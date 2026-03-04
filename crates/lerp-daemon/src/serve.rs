//! Serve mode: connect to relay with our own EndpointId as routing target,
//! wait for an initiator to pair, perform the LPP E2E handshake, and forward
//! each incoming bi-stream to a local TCP address.
//!
//! Spec §06: "lerp-daemon 监听来自 relay 的连接，建立 E2E 加密信道后，将流量
//! 透明转发到 localhost:<port>"
//!
//! # On-connect hook
//!
//! If `on_connect_hook` is configured, the daemon runs the specified program
//! with the peer's identity and metadata on stdin (JSON).  The program must
//! write `{"accept":true}` or `{"accept":false,"reason":"..."}` on stdout.
//! A non-zero exit code is treated as rejection.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use wtransport::{ClientConfig, Connection, Endpoint};

use lerp_proto::{identity::SecretKey, routing};

use crate::{
    error::DaemonError,
    forward,
    handshake::{self, send_rejection},
};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Serve a single `[[serve]]` config entry forever.
///
/// Connects to the relay, waits for a peer to pair, performs the E2E
/// handshake, optionally runs the on_connect hook, then forwards streams
/// to the configured local TCP address.
///
/// On disconnect or error, reconnects and retries automatically.
pub async fn run_serve_entry(entry: ServeCfg) {
    loop {
        match serve_once(&entry).await {
            Ok(()) => {
                tracing::info!(eid = %entry.eid_b32, "serve: peer disconnected, reconnecting");
            }
            Err(e) => {
                tracing::warn!(eid = %entry.eid_b32, "serve: error ({e}), reconnecting in 5s");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// All config needed to run a serve entry (pre-parsed, cheap to clone).
#[derive(Clone)]
pub struct ServeCfg {
    pub sk: Arc<SecretKey>,
    pub eid_b32: String,
    pub relay_host: String,
    pub relay_secret: [u8; 32],
    pub forward_addr: String,
    pub on_connect_hook: Option<String>,
}

// ---------------------------------------------------------------------------
// Single connection attempt
// ---------------------------------------------------------------------------

async fn serve_once(cfg: &ServeCfg) -> Result<(), DaemonError> {
    // Build the SNI routing token for our own endpoint_id (so the relay can
    // pair a remote initiator that targets us).
    let bucket = routing::current_time_bucket();
    let eid = cfg.sk.endpoint_id();
    let token = routing::derive_routing_token(&eid, &cfg.relay_secret, bucket);
    let sni = routing::build_sni(&token, &cfg.relay_host);
    let url = format!("https://{sni}/lerp");

    tracing::info!(
        eid = %cfg.eid_b32,
        relay = %cfg.relay_host,
        %url,
        bucket,
        "serve: dialing relay"
    );

    let conn = dial_relay(&url).await?;

    tracing::info!(eid = %cfg.eid_b32, "serve: relay connected, waiting for peer to pair");

    // The relay will wait until an initiator connects with the same SNI token.
    // Once paired, we execute the LPP handshake as the responder.
    let hs = handshake::responder_handshake(&conn, &cfg.sk).await?;

    tracing::info!(
        eid = %cfg.eid_b32,
        peer = %hs.peer_eid.to_base32(),
        "serve: handshake complete"
    );

    // ── on_connect hook ───────────────────────────────────────────────────
    if let Some(hook) = &cfg.on_connect_hook {
        let accepted =
            run_hook(hook, &hs.peer_eid.to_base32(), &hs.meta).await?;
        if !accepted {
            tracing::warn!(
                peer = %hs.peer_eid.to_base32(),
                "serve: rejected by on_connect hook"
            );
            send_rejection(&conn, "rejected").await?;
            return Err(DaemonError::Rejected("hook rejected connection".into()));
        }
    }

    tracing::info!(
        eid = %cfg.eid_b32,
        peer = %hs.peer_eid.to_base32(),
        forward = %cfg.forward_addr,
        "serve: accepting streams"
    );

    // ── Forward bi-streams to local TCP ───────────────────────────────────
    let keys = Arc::new(hs.session_keys);
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let forward_addr = cfg.forward_addr.clone();
                let keys = Arc::clone(&keys);
                tokio::spawn(async move {
                    match TcpStream::connect(&forward_addr).await {
                        Ok(tcp) => {
                            forward::run_bistream(send, recv, tcp, &keys).await;
                        }
                        Err(e) => {
                            tracing::warn!("serve: failed to connect to {forward_addr}: {e}");
                        }
                    }
                });
            }
            Err(e) => {
                tracing::debug!("serve: accept_bi ended: {e}");
                return Ok(());
            }
        }
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
    let conn = endpoint
        .connect(url)
        .await
        .map_err(|e| DaemonError::WebTransport(format!("CONNECT to {url} failed: {e}")))?;

    tracing::info!(%url, "dial_relay: connection established");
    Ok(conn)
}

// ---------------------------------------------------------------------------
// on_connect hook runner
// ---------------------------------------------------------------------------

/// Execute the hook script.  Returns `true` if the connection should be
/// accepted.
async fn run_hook(
    hook_path: &str,
    peer_eid: &str,
    meta: &Option<std::collections::HashMap<String, rmpv::Value>>,
) -> Result<bool, DaemonError> {
    use tokio::process::Command;

    let meta_json = match meta {
        Some(m) => serde_json::to_value(
            m.iter()
                .map(|(k, v)| (k.clone(), rmpv_to_json(v)))
                .collect::<serde_json::Map<_, _>>(),
        )
        .unwrap_or(serde_json::Value::Object(Default::default())),
        None => serde_json::Value::Object(Default::default()),
    };

    let payload = serde_json::json!({
        "peer_eid": peer_eid,
        "meta": meta_json,
    });
    let payload_str = serde_json::to_string(&payload)
        .map_err(|e| DaemonError::Hook(e.to_string()))?;

    let mut child = Command::new(hook_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| DaemonError::Hook(format!("failed to start hook {hook_path}: {e}")))?;

    // Write payload to hook stdin.
    if let Some(stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        let mut stdin = stdin;
        let _ = stdin.write_all(payload_str.as_bytes()).await;
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| DaemonError::Hook(e.to_string()))?;

    if !output.status.success() {
        return Ok(false);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .map_err(|e| DaemonError::Hook(format!("hook stdout is not valid JSON: {e}")))?;

    Ok(v.get("accept").and_then(|a| a.as_bool()).unwrap_or(false))
}

/// Best-effort rmpv::Value → serde_json::Value conversion for hook input.
fn rmpv_to_json(v: &rmpv::Value) -> serde_json::Value {
    match v {
        rmpv::Value::Nil => serde_json::Value::Null,
        rmpv::Value::Boolean(b) => serde_json::Value::Bool(*b),
        rmpv::Value::Integer(i) => {
            serde_json::Value::Number(serde_json::Number::from(i.as_i64().unwrap_or(0)))
        }
        rmpv::Value::F32(f) => serde_json::json!(*f),
        rmpv::Value::F64(f) => serde_json::json!(*f),
        rmpv::Value::String(s) => {
            serde_json::Value::String(s.as_str().unwrap_or("").to_string())
        }
        rmpv::Value::Binary(b) => {
            serde_json::Value::String(data_encoding::BASE64URL_NOPAD.encode(b))
        }
        rmpv::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(rmpv_to_json).collect())
        }
        rmpv::Value::Map(m) => serde_json::Value::Object(
            m.iter()
                .map(|(k, v)| (rmpv_to_json(k).to_string(), rmpv_to_json(v)))
                .collect(),
        ),
        rmpv::Value::Ext(_, _) => serde_json::Value::Null,
    }
}
