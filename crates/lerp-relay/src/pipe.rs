//! Bidirectional transparent byte pipe between two WebTransport connections.
//!
//! The relay forwards three things between connection A and connection B:
//!   * Bidirectional streams opened by either side
//!   * Unidirectional streams opened by either side
//!   * WebTransport datagrams
//!
//! All forwarding is transparent — no bytes are inspected.

use tokio::io;
use wtransport::Connection;
use wtransport::RecvStream;
use wtransport::SendStream;
use wtransport::VarInt;

/// Run a transparent bidirectional pipe between `conn_a` and `conn_b` until either side closes.
pub async fn run(conn_a: Connection, conn_b: Connection) {
    tracing::debug!(
        a = conn_a.stable_id(),
        b = conn_b.stable_id(),
        "pipe started"
    );

    // Forward streams and datagrams in both directions concurrently.
    // Stop as soon as either connection closes (or an unrecoverable error).
    tokio::select! {
        _ = forward_all(conn_a.clone(), conn_b.clone()) => {}
        _ = conn_a.closed() => {}
        _ = conn_b.closed() => {}
    }

    tracing::debug!(
        a = conn_a.stable_id(),
        b = conn_b.stable_id(),
        "pipe ended — closing both connections"
    );

    conn_a.close(VarInt::from_u32(0), b"peer disconnected");
    conn_b.close(VarInt::from_u32(0), b"peer disconnected");
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Drive all forwarder loops concurrently; returns when any direction stops.
async fn forward_all(a: Connection, b: Connection) {
    tokio::join!(
        forward_bi_streams(a.clone(), b.clone()),
        forward_bi_streams(b.clone(), a.clone()),
        forward_uni_streams(a.clone(), b.clone()),
        forward_uni_streams(b.clone(), a.clone()),
        forward_datagrams(a.clone(), b.clone()),
        forward_datagrams(b.clone(), a.clone()),
    );
}

/// Accept bidirectional streams from `from`, open matching streams on `to`, and pipe bytes.
async fn forward_bi_streams(from: Connection, to: Connection) {
    loop {
        match from.accept_bi().await {
            Ok((from_send, from_recv)) => {
                let to = to.clone();
                tokio::spawn(async move {
                    pipe_bi(from_send, from_recv, to).await;
                });
            }
            Err(e) => {
                tracing::debug!("accept_bi ended: {e}");
                break;
            }
        }
    }
}

/// Accept unidirectional streams from `from`, open matching streams on `to`, and pipe bytes.
async fn forward_uni_streams(from: Connection, to: Connection) {
    loop {
        match from.accept_uni().await {
            Ok(from_recv) => {
                let to = to.clone();
                tokio::spawn(async move {
                    pipe_uni(from_recv, to).await;
                });
            }
            Err(e) => {
                tracing::debug!("accept_uni ended: {e}");
                break;
            }
        }
    }
}

/// Forward datagrams from `from` to `to`.
async fn forward_datagrams(from: Connection, to: Connection) {
    loop {
        match from.receive_datagram().await {
            Ok(dgram) => {
                let payload = dgram.payload().to_vec();
                if let Err(e) = to.send_datagram(payload) {
                    tracing::debug!("send_datagram error: {e}");
                    break;
                }
            }
            Err(e) => {
                tracing::debug!("receive_datagram ended: {e}");
                break;
            }
        }
    }
}

/// Pipe a single bidirectional stream: open matching stream on `to_conn`, copy bytes both ways.
async fn pipe_bi(from_send: SendStream, from_recv: RecvStream, to_conn: Connection) {
    let opening = match to_conn.open_bi().await {
        Ok(o) => o,
        Err(e) => {
            tracing::debug!("open_bi failed: {e}");
            return;
        }
    };
    let (to_send, to_recv) = match opening.await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::debug!("open_bi init failed: {e}");
            return;
        }
    };

    let mut from_send = from_send;
    let mut from_recv = from_recv;
    let mut to_send = to_send;
    let mut to_recv = to_recv;

    // Copy in both directions simultaneously.
    let _ = tokio::join!(
        io::copy(&mut from_recv, &mut to_send),
        io::copy(&mut to_recv, &mut from_send),
    );
}

/// Pipe a single unidirectional stream: open matching send stream on `to_conn`, copy bytes.
async fn pipe_uni(from_recv: RecvStream, to_conn: Connection) {
    let opening = match to_conn.open_uni().await {
        Ok(o) => o,
        Err(e) => {
            tracing::debug!("open_uni failed: {e}");
            return;
        }
    };
    let to_send = match opening.await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("open_uni init failed: {e}");
            return;
        }
    };

    let mut from_recv = from_recv;
    let mut to_send = to_send;
    let _ = io::copy(&mut from_recv, &mut to_send).await;
}

