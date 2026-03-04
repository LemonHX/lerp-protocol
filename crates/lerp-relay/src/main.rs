//! lerp-relay: a stateless WebTransport relay for the lerp protocol.
//!
//! Reads configuration from environment variables (see [`config::RelayConfig`] for details),
//! then listens for incoming WebTransport connections, resolves their EndpointId from the SNI
//! blind routing token, pairs two connections sharing the same EndpointId, and transparently
//! forwards bytes between them.

mod config;
mod error;
mod pipe;
mod router;

use std::sync::Arc;

use tracing::info;
use tracing::warn;
use wtransport::endpoint::IncomingSession;
use wtransport::endpoint::SessionRequest;
use wtransport::Connection;
use wtransport::Endpoint;
use wtransport::Identity;
use wtransport::ServerConfig;
use wtransport::VarInt;

use lerp_proto::{
    lpp::{self, LppMessage, Qad},
    routing,
};

use config::RelayConfig;
use error::RelayError;
use router::PairOutcome;
use router::PendingTable;

#[tokio::main]
async fn main() {
    // Load .env file if present (silently ignored when absent).
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if let Err(e) = run().await {
        tracing::error!("fatal error: {e}");
        eprintln!("Exiting!");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = RelayConfig::from_env()?;

    info!(bind = %cfg.bind_addr, "loading TLS identity");
    let identity = Identity::load_pemfiles(&cfg.cert_path, &cfg.key_path)
        .await
        .map_err(|e| format!("failed to load TLS cert/key: {e}"))?;

    let server_cfg = ServerConfig::builder()
        .with_bind_address(cfg.bind_addr)
        .with_identity(identity)
        .keep_alive_interval(Some(std::time::Duration::from_secs(10)))
        .build();

    let endpoint = Endpoint::server(server_cfg)?;
    let table = PendingTable::new(cfg.pair_timeout);

    let relay_secret = cfg.relay_secret;

    info!(bind = %cfg.bind_addr, "lerp-relay listening");

    loop {
        let incoming = endpoint.accept().await;
        let table = Arc::clone(&table);

        tokio::spawn(async move {
            if let Err(e) = handle_incoming(incoming, table, relay_secret).await {
                warn!("connection error: {e}");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

async fn handle_incoming(
    incoming: IncomingSession,
    table: Arc<PendingTable>,
    relay_secret: [u8; 32],
) -> Result<(), RelayError> {
    // Complete TLS + QUIC handshake → HTTP/3 CONNECT request.
    let request: SessionRequest = incoming.await?;

    // The `:authority` header contains the SNI hostname, e.g. "TOKEN52.relay.example.com".
    // parse_sni_token extracts the first DNS label and base32-decodes it to 32 bytes.
    let authority = request.authority();
    tracing::info!(authority, "incoming session");
    let token_bytes = routing::parse_sni_token(authority).map_err(|e| {
        RelayError::InvalidSni(format!("{authority}: {e}"))
    })?;

    // Resolve EndpointId: try current window, then previous (spec § 04-relay step 4-5).
    let cur_bucket = routing::current_time_bucket();
    let prev_bucket = routing::previous_time_bucket();

    let eid_cur = routing::recover_endpoint_id(&token_bytes, &relay_secret, cur_bucket);
    let eid_prev = routing::recover_endpoint_id(&token_bytes, &relay_secret, prev_bucket);

    // Prefer whichever candidate already has a waiting peer connection (spec step 5).
    // has_pending is sync — no await needed (DashMap is a sync read).
    let eid = if table.has_pending(&eid_cur) {
        tracing::debug!("routing: current bucket has pending peer");
        eid_cur
    } else if table.has_pending(&eid_prev) {
        tracing::debug!("routing: previous bucket has pending peer");
        eid_prev
    } else {
        // No pending peer yet: default to current bucket.
        eid_cur
    };

    tracing::debug!(eid = %eid.to_base32(), bucket = cur_bucket, "resolved EndpointId from SNI");

    // Accept the WebTransport session (sends HTTP 200 to client).
    let conn = request.accept().await?;

    // Relay-side observed address discovery (QAD): tell endpoint what source
    // socket address relay sees for this connection.
    send_qad_notice(&conn);

    tracing::info!(
        eid = %eid.to_base32(),
        peer = %conn.remote_address(),
        "connection accepted, attempting to pair"
    );

    // Pair with a waiting peer — or wait — or time out.
    match table.pair(eid.clone(), conn.clone()).await? {
        PairOutcome::Initiator { our_conn, peer_conn } => {
            tracing::info!(eid = %eid.to_base32(), "paired — starting pipe");
            pipe::run(our_conn, peer_conn).await;
        }

        PairOutcome::Waiter => {
            // Our clone is already in the table; the peer's task owns the pipe.
            tracing::info!(eid = %eid.to_base32(), "parked — paired by peer");
        }

        PairOutcome::Timeout => {
            tracing::warn!(eid = %eid.to_base32(), "pairing timeout — closing");
            conn.close(VarInt::from_u32(1), b"pair timeout");
        }
    }

    Ok(())
}

fn send_qad_notice(conn: &Connection) {
    let observed = conn.remote_address().to_string();
    let payload = match lpp::encode(&LppMessage::Qad(Qad {
        addr: observed.clone(),
    })) {
        Ok(p) => p,
        Err(e) => {
            warn!("qad encode failed: {e}");
            return;
        }
    };

    if let Err(e) = conn.send_datagram(payload) {
        warn!(%observed, "failed to send QAD datagram: {e}");
    } else {
        tracing::debug!(%observed, "sent QAD datagram");
    }
}
