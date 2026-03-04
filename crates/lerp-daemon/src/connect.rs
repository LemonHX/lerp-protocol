//! Connect mode: parse a lerp ticket, connect to the relay as the initiator,
//! perform the E2E handshake, then listen for local TCP connections and tunnel
//! each one through a new bi-stream on the WebTransport connection.
//!
//! Spec §07: "lerp-client 连接 relay，握手后监听本地端口，将本地 TCP 流量透明
//! 隧道到远端 lerp-daemon"

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use wtransport::{ClientConfig, Connection, Endpoint};

use lerp_proto::{identity::{EndpointId, SecretKey}, routing, ticket::Ticket};

use crate::{error::DaemonError, forward, handshake};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Serve a single `[[connect]]` config entry forever.
///
/// Opens a local TCP listener on `entry.local_port`, connects to the relay
/// described in the ticket, performs the LPP handshake as the initiator, and
/// for each local TCP client opens a new bi-stream over the existing
/// WebTransport connection.
///
/// On relay disconnect the function reconnects and re-does the handshake
/// automatically.
pub async fn run_connect_entry(entry: ConnectCfg) {
    loop {
        match connect_once(&entry).await {
            Ok(()) => {
                tracing::info!(port = entry.local_port, "connect: disconnected, reconnecting");
            }
            Err(e) => {
                tracing::warn!(
                    port = entry.local_port,
                    "connect: error ({e}), reconnecting in 5s"
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// All config needed to run a connect entry (pre-parsed, cheap to clone).
#[derive(Clone)]
pub struct ConnectCfg {
    /// The raw base64url-encoded ticket string from config.
    pub ticket_b64: String,
    /// Local TCP port to listen on.
    pub local_port: u16,
    /// Optional meta fields to send in the Hello message.
    pub meta: Option<std::collections::HashMap<String, rmpv::Value>>,
}

// ---------------------------------------------------------------------------
// Single connection attempt
// ---------------------------------------------------------------------------

async fn connect_once(cfg: &ConnectCfg) -> Result<(), DaemonError> {
    // ── Decode ticket ────────────────────────────────────────────────────
    let ticket = Ticket::decode(&cfg.ticket_b64)
        .map_err(|e| DaemonError::Ticket(format!("invalid ticket: {e}")))?;

    let peer_eid = EndpointId::from_base32(&ticket.lerp_eid)
        .map_err(|e| DaemonError::Ticket(format!("bad peer eid in ticket: {e}")))?;

    let relay_host = ticket
        .lerp_rly
        .as_deref()
        .ok_or_else(|| DaemonError::Ticket("ticket has no relay host".into()))?;

    let relay_secret: [u8; 32] = ticket
        .lerp_sec
        .ok_or_else(|| DaemonError::Ticket("ticket has no relay secret".into()))?;

    // ── Build SNI for the target peer's routing token ─────────────────────
    let bucket = routing::current_time_bucket();
    let token = routing::derive_routing_token(&peer_eid, &relay_secret, bucket);
    let sni = routing::build_sni(&token, relay_host);
    let url = format!("https://{sni}/lerp");

    tracing::info!(
        port = cfg.local_port,
        peer = %peer_eid.to_base32(),
        relay = relay_host,
        %url,
        bucket,
        "connect: dialing relay"
    );

    // ── Connect to relay ──────────────────────────────────────────────────
    let conn = dial_relay(&url).await?;

    tracing::info!(
        port = cfg.local_port,
        peer = %peer_eid.to_base32(),
        "connect: relay connected, running handshake"
    );

    // ── LPP handshake (initiator side) ────────────────────────────────────
    // Use an ephemeral in-memory key for connect mode — forward secrecy between
    // sessions, no key material written to disk.
    let our_sk = Arc::new(SecretKey::generate());

    let hs = handshake::initiator_handshake(
        &conn,
        &our_sk,
        &peer_eid,
        cfg.meta.clone(),
    )
    .await?;

    tracing::info!(
        port = cfg.local_port,
        peer = %hs.peer_eid.to_base32(),
        "connect: handshake complete, listening on 127.0.0.1:{}",
        cfg.local_port
    );

    // ── Local TCP listener ────────────────────────────────────────────────
    let listener = TcpListener::bind(("127.0.0.1", cfg.local_port))
        .await
        .map_err(DaemonError::Io)?;

    let keys = Arc::new(hs.session_keys);
    let conn = Arc::new(conn);

    loop {
        let (tcp, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("connect: tcp accept error: {e}");
                continue;
            }
        };

        tracing::debug!("connect: local connection from {peer_addr}");

        let keys = Arc::clone(&keys);
        let conn = Arc::clone(&conn);

        tokio::spawn(async move {
            match open_bistream(&conn).await {
                Ok((send, recv)) => {
                    forward::run_bistream(send, recv, tcp, &keys).await;
                }
                Err(e) => {
                    tracing::warn!("connect: failed to open bi-stream: {e}");
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Relay dial helper
// ---------------------------------------------------------------------------

async fn dial_relay(url: &str) -> Result<Connection, DaemonError> {
    tracing::debug!(%url, "dial_relay: building QUIC client config");
    let config = ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build();

    let endpoint = Endpoint::client(config)
        .map_err(|e| DaemonError::WebTransport(format!("endpoint create failed: {e}")))?;

    tracing::debug!(%url, "dial_relay: sending WebTransport CONNECT");
    let session = endpoint
        .connect(url)
        .await
        .map_err(|e| DaemonError::WebTransport(format!("CONNECT to {url} failed: {e}")))?;

    tracing::info!(%url, "dial_relay: connection established");
    Ok(session)
}

// ---------------------------------------------------------------------------
// Open a bi-directional stream
// ---------------------------------------------------------------------------

async fn open_bistream(
    conn: &Connection,
) -> Result<
    (
        wtransport::stream::SendStream,
        wtransport::stream::RecvStream,
    ),
    DaemonError,
> {
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| DaemonError::WebTransport(e.to_string()))?
        .await
        .map_err(|e| DaemonError::WebTransport(e.to_string()))?;

    Ok((send, recv))
}
