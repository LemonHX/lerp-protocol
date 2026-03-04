//! Encrypted bi-directional stream ↔ TCP forwarding.
//!
//! Each WebTransport bi-directional stream corresponds to one local TCP
//! connection. Data is encrypted with ChaCha20-Poly1305 using session keys
//! from the E2E handshake.
//!
//! Wire framing (per direction):
//! ```text
//! [4-byte LE ciphertext_length][ciphertext (includes 16-byte Poly1305 tag)]
//! ```
//!
//! Framing lets the receiver know exactly how many bytes to read for each
//! tagged block, making the protocol self-delimiting inside the stream.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wtransport::{RecvStream, SendStream};

use crate::
    crypto::{RecvCipher, SendCipher, SessionKeys};

const MAX_FRAME: usize = 64 * 1024; // 64 KiB per encrypted chunk

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Forward traffic between an E2E-encrypted WebTransport bi-stream and a
/// local TCP stream.
///
/// Both directions run concurrently; the function returns when either side
/// closes its half.
pub async fn run_bistream(
    wt_send: SendStream,
    wt_recv: RecvStream,
    tcp: TcpStream,
    keys: &SessionKeys,
) {
    let peer = tcp.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into());
    tracing::debug!(tcp_peer = %peer, "forward: bistream started");
    let (tcp_read, tcp_write) = tcp.into_split();

    let send_cipher = SendCipher::new(&keys.send_key);
    let recv_cipher = RecvCipher::new(&keys.recv_key);

    // TCP → WebTransport  (encrypt)
    let tcp_to_wt = tcp_to_webtransport(tcp_read, wt_send, send_cipher);
    // WebTransport → TCP  (decrypt)
    let wt_to_tcp = webtransport_to_tcp(wt_recv, tcp_write, recv_cipher);

    tokio::join!(tcp_to_wt, wt_to_tcp);
    tracing::debug!(tcp_peer = %peer, "forward: bistream closed");
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Read from TCP, encrypt each chunk, write framed ciphertext to WebTransport.
async fn tcp_to_webtransport(
    mut tcp_r: tokio::net::tcp::OwnedReadHalf,
    mut wt_s: SendStream,
    mut cipher: SendCipher,
) {
    let mut buf = vec![0u8; MAX_FRAME];
    let mut total_bytes: u64 = 0;
    loop {
        let n = match tcp_r.read(&mut buf).await {
            Ok(0) => { tracing::debug!(total_bytes, "forward: TCP→WT closed (EOF)"); break; }
            Err(e) => { tracing::debug!(%e, total_bytes, "forward: TCP→WT read error"); break; }
            Ok(n) => n,
        };
        total_bytes += n as u64;
        tracing::trace!(n, total_bytes, "forward: TCP→WT frame");
        let frame = match cipher.seal_frame(&buf[..n]) {
            Ok(f) => f,
            Err(e) => { tracing::warn!(%e, "forward: seal_frame error"); break; }
        };
        if let Err(e) = wt_s.write_all(&frame).await {
            tracing::debug!(%e, total_bytes, "forward: TCP→WT write error");
            break;
        }
    }
    let _ = wt_s.finish().await;
}

/// Read framed ciphertext from WebTransport, decrypt, write plaintext to TCP.
async fn webtransport_to_tcp(
    mut wt_r: RecvStream,
    mut tcp_w: tokio::net::tcp::OwnedWriteHalf,
    mut cipher: RecvCipher,
) {
    let mut total_bytes: u64 = 0;
    loop {
        // Read 4-byte length header.
        let mut len_buf = [0u8; 4];
        if let Err(e) = wt_r.read_exact(&mut len_buf).await {
            tracing::debug!(%e, total_bytes, "forward: WT→TCP header read error");
            break;
        }
        let ct_len = u32::from_le_bytes(len_buf) as usize;
        if ct_len == 0 || ct_len > MAX_FRAME + 16 {
            tracing::warn!(ct_len, "forward: invalid frame length");
            break;
        }
        // Read ciphertext.
        let mut ct = vec![0u8; ct_len];
        if let Err(e) = wt_r.read_exact(&mut ct).await {
            tracing::debug!(%e, total_bytes, "forward: WT→TCP body read error");
            break;
        }
        // Decrypt.
        let pt = match cipher.open(&ct) {
            Ok(p) => p,
            Err(e) => { tracing::warn!(%e, "forward: decryption error"); break; }
        };
        total_bytes += pt.len() as u64;
        tracing::trace!(pt_len = pt.len(), total_bytes, "forward: WT→TCP frame");
        // Write plaintext to local TCP.
        if let Err(e) = tcp_w.write_all(&pt).await {
            tracing::debug!(%e, total_bytes, "forward: WT→TCP write error");
            break;
        }
    }
}
