//! LPP Hello / HelloAck handshake.
//!
//! Spec §09: after WebTransport connection is established,
//!
//! 1. Initiator sends `Hello` on a new uni-stream.
//! 2. Responder reads `Hello`, verifies signature, sends `HelloAck` on a new uni-stream.
//! 3. Initiator reads `HelloAck`, verifies signature.
//! 4. Both sides compute the X25519 shared secret → derive ChaCha20-Poly1305 session keys.
//!
//! Control messages travel on uni-directional streams: one message per stream,
//! stream FIN signals end-of-message.

use std::collections::HashMap;

use tokio::io::AsyncReadExt;
use wtransport::Connection;

use lerp_proto::{
    identity::{verify_signature, EndpointId, EphemeralEcdh, SecretKey},
    lpp::{self, Close, Hello, HelloAck, LppMessage, LPP_VERSION},
};

use crate::{
    crypto::SessionKeys,
    error::DaemonError,
};

// ---------------------------------------------------------------------------
// Result type returned to callers
// ---------------------------------------------------------------------------

pub struct HandshakeResult {
    /// The peer's verified EndpointId.
    pub peer_eid: EndpointId,
    /// E2E session keys derived from the ECDH exchange.
    pub session_keys: SessionKeys,
    /// Negotiated LPP version (min of both sides' `ver`).
    #[allow(dead_code)]
    pub negotiated_ver: u8,
    /// Forwarded ticket `app_fields` metadata (only present when we are the responder).
    pub meta: Option<HashMap<String, rmpv::Value>>,
}

// ---------------------------------------------------------------------------
// Initiator (connector / client)
// ---------------------------------------------------------------------------

/// Perform the initiator side of the E2E handshake.
///
/// Sends `Hello`, waits for `HelloAck`, verifies peer identity, derives keys.
///
/// `expected_peer_eid` — the EndpointId from the ticket; the handshake fails
/// if the peer answers with a different identity.
pub async fn initiator_handshake(
    conn: &Connection,
    our_sk: &SecretKey,
    expected_peer_eid: &EndpointId,
    meta: Option<HashMap<String, rmpv::Value>>,
) -> Result<HandshakeResult, DaemonError> {
    let ecdh = EphemeralEcdh::generate();
    let ecdh_pub = ecdh.public_key_bytes();
    let sig = our_sk.sign(&ecdh_pub);
    let our_eid_b32 = our_sk.endpoint_id().to_base32();

    // ─── Send Hello ───────────────────────────────────────────────────────
    tracing::debug!(our_eid = %our_eid_b32, expected_peer = %expected_peer_eid.to_base32(), "handshake[init]: sending Hello");
    let hello_bytes = lpp::encode(&LppMessage::Hello(Hello {
        ver: LPP_VERSION,
        eid: our_eid_b32,
        ecdh: ecdh_pub.to_vec(),
        sig: sig.to_vec(),
        meta,
    }))
    .map_err(|e| DaemonError::Handshake(e.to_string()))?;

    send_uni(conn, &hello_bytes).await?;
    tracing::debug!("handshake[init]: Hello sent, waiting for HelloAck");

    // ─── Receive HelloAck ─────────────────────────────────────────────────
    let ack_bytes = recv_uni(conn).await?;
    tracing::debug!(bytes = ack_bytes.len(), "handshake[init]: received response");
    let ack_msg = lpp::decode(&ack_bytes).map_err(|e| DaemonError::Handshake(e.to_string()))?;

    let ack = match ack_msg {
        LppMessage::HelloAck(a) => a,
        LppMessage::Close(c) => {
            tracing::warn!(reason = %c.reason, "handshake[init]: peer rejected connection");
            return Err(DaemonError::Handshake(format!("peer sent Close: {}", c.reason)))
        }
        _ => {
            return Err(DaemonError::Handshake(
                "unexpected message type during handshake".into(),
            ))
        }
    };

    // ─── Verify peer identity ─────────────────────────────────────────────
    let peer_eid = EndpointId::from_base32(&ack.eid)
        .map_err(|e| DaemonError::Handshake(e.to_string()))?;

    if &peer_eid != expected_peer_eid {
        return Err(DaemonError::Handshake(format!(
            "eid mismatch: expected {}, got {}",
            expected_peer_eid.to_base32(),
            ack.eid
        )));
    }

    let peer_ecdh_pub: [u8; 32] = ack
        .ecdh
        .try_into()
        .map_err(|_| DaemonError::Handshake("peer ECDH key has wrong length".into()))?;

    verify_signature(&peer_eid, &peer_ecdh_pub, &ack.sig)
        .map_err(|e| DaemonError::Handshake(e.to_string()))?;
    tracing::debug!(peer = %peer_eid.to_base32(), ver = ack.ver, "handshake[init]: signature OK, deriving session keys");

    // ─── Derive session keys ──────────────────────────────────────────────
    let shared = ecdh.complete(&peer_ecdh_pub);
    let session_keys = SessionKeys::derive(shared.as_bytes(), &ecdh_pub, &peer_ecdh_pub)?
;    tracing::info!(peer = %peer_eid.to_base32(), "handshake[init]: complete");

    Ok(HandshakeResult {
        peer_eid,
        session_keys,
        negotiated_ver: ack.ver.min(LPP_VERSION),
        meta: None,
    })
}

// ---------------------------------------------------------------------------
// Responder (server / accept)
// ---------------------------------------------------------------------------

/// Perform the responder side of the E2E handshake.
///
/// Waits for `Hello`, verifies initiator identity, sends `HelloAck`, derives keys.
pub async fn responder_handshake(
    conn: &Connection,
    our_sk: &SecretKey,
) -> Result<HandshakeResult, DaemonError> {
    // ─── Receive Hello ────────────────────────────────────────────────────
    tracing::debug!("handshake[resp]: waiting for Hello");
    let hello_bytes = recv_uni(conn).await?;
    tracing::debug!(bytes = hello_bytes.len(), "handshake[resp]: received Hello");
    let hello_msg =
        lpp::decode(&hello_bytes).map_err(|e| DaemonError::Handshake(e.to_string()))?;

    let hello = match hello_msg {
        LppMessage::Hello(h) => h,
        _ => {
            return Err(DaemonError::Handshake(
                "expected Hello as first message".into(),
            ))
        }
    };

    // ─── Verify initiator's identity ──────────────────────────────────────
    let peer_eid = EndpointId::from_base32(&hello.eid)
        .map_err(|e| DaemonError::Handshake(e.to_string()))?;
    tracing::info!(peer = %peer_eid.to_base32(), ver = hello.ver, "handshake[resp]: received Hello from peer");

    let peer_ecdh_pub: [u8; 32] = hello
        .ecdh
        .try_into()
        .map_err(|_| DaemonError::Handshake("peer ECDH key has wrong length".into()))?;

    verify_signature(&peer_eid, &peer_ecdh_pub, &hello.sig)
        .map_err(|e| DaemonError::Handshake(e.to_string()))?;
    tracing::debug!(peer = %peer_eid.to_base32(), "handshake[resp]: signature OK");

    // ─── Version negotiation ──────────────────────────────────────────────
    let negotiated_ver = hello.ver.min(LPP_VERSION);

    if negotiated_ver != LPP_VERSION && hello.ver > LPP_VERSION {
        // Peer is newer; we tell them our max.
        tracing::warn!(
            peer = %peer_eid.to_base32(),
            peer_ver = hello.ver,
            our_ver = LPP_VERSION,
            "handshake: version mismatch, sending HelloAck with our max version"
        );
    }

    // ─── Send HelloAck ────────────────────────────────────────────────────
    let ecdh = EphemeralEcdh::generate();
    let ecdh_pub = ecdh.public_key_bytes();
    let sig = our_sk.sign(&ecdh_pub);

    tracing::debug!(peer = %peer_eid.to_base32(), "handshake[resp]: sending HelloAck");
    let ack_bytes = lpp::encode(&LppMessage::HelloAck(HelloAck {
        ver: negotiated_ver,
        eid: our_sk.endpoint_id().to_base32(),
        ecdh: ecdh_pub.to_vec(),
        sig: sig.to_vec(),
    }))
    .map_err(|e| DaemonError::Handshake(e.to_string()))?;

    send_uni(conn, &ack_bytes).await?;
    tracing::debug!(peer = %peer_eid.to_base32(), "handshake[resp]: HelloAck sent, deriving session keys");

    // ─── Derive session keys ──────────────────────────────────────────────
    let shared = ecdh.complete(&peer_ecdh_pub);
    let session_keys = SessionKeys::derive(shared.as_bytes(), &ecdh_pub, &peer_ecdh_pub)?;
    tracing::info!(peer = %peer_eid.to_base32(), "handshake[resp]: complete");;

    Ok(HandshakeResult {
        peer_eid,
        session_keys,
        negotiated_ver,
        meta: hello.meta,
    })
}

// ---------------------------------------------------------------------------
// Graceful rejection helper
// ---------------------------------------------------------------------------

/// Send a `Close` message to the peer and return the supplied error.
pub async fn send_rejection(
    conn: &Connection,
    reason: &str,
) -> Result<(), DaemonError> {
    let bytes = lpp::encode(&LppMessage::Close(Close { reason: reason.to_string() }))
        .map_err(|e| DaemonError::Handshake(e.to_string()))?;
    send_uni(conn, &bytes).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Low-level uni-stream I/O
// ---------------------------------------------------------------------------

/// Open a new uni-directional stream, write `bytes`, and close the stream.
pub async fn send_uni(conn: &Connection, bytes: &[u8]) -> Result<(), DaemonError> {

    let opening = conn
        .open_uni()
        .await
        .map_err(|e| DaemonError::WebTransport(e.to_string()))?;

    let mut stream = opening
        .await
        .map_err(|e| DaemonError::WebTransport(e.to_string()))?;

    stream
        .write_all(bytes)
        .await
        .map_err(|e| DaemonError::WebTransport(e.to_string()))?;
    stream
        .finish()
        .await
        .map_err(|e| DaemonError::WebTransport(e.to_string()))?;

    Ok(())
}

/// Accept an inbound uni-directional stream and read all bytes until EOF.
pub async fn recv_uni(conn: &Connection) -> Result<Vec<u8>, DaemonError> {
    let mut stream = conn
        .accept_uni()
        .await
        .map_err(|e| DaemonError::WebTransport(e.to_string()))?;

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| DaemonError::WebTransport(e.to_string()))?;

    Ok(buf)
}
