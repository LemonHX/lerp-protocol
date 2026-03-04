//! IPC control socket for the lerp daemon.
//!
//! On Unix  : Unix domain socket at `~/.lerp/daemon.sock`
//! On Windows: Named pipe   `\\.\pipe\lerp-daemon`
//!
//! Protocol: newline-delimited JSON.  Each request is one JSON line; the
//! daemon replies with one JSON line.
//!
//! # Request / Response
//!
//! ```json
//! // Create a new endpoint identity
//! {"type":"new-endpoint"}
//! → {"ok":true,"eid":"<base32>"}
//!
//! // List all stored endpoint ids
//! {"type":"list-endpoints"}
//! → {"ok":true,"endpoints":["<base32>", ...]}
//!
//! // Generate a ticket for an endpoint
//! {"type":"ticket","eid":"<base32>","relay":"relay.example.com:443",
//!  "relay_sec_hex":"<64 hex chars>","app_fields":{...}}
//! → {"ok":true,"ticket":"<base64url>"}
//!
//! // Query current connection status
//! {"type":"status"}
//! → {"ok":true,"connections":[...]}
//!
//! // Error response (any request)
//! → {"ok":false,"error":"<message>"}
//! ```

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use lerp_proto::ticket::Ticket;

use crate::{config::ipc_socket_path, error::DaemonError, keystore};

// ---------------------------------------------------------------------------
// JSON request/response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum IpcRequest {
    NewEndpoint,
    ListEndpoints,
    Ticket {
        eid: String,
        relay: Option<String>,
        relay_sec_hex: Option<String>,
        #[serde(flatten)]
        app_fields: serde_json::Map<String, serde_json::Value>,
    },
    Status,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum IpcResponse {
    Ok(serde_json::Value),
    Err { ok: bool, error: String },
}

impl IpcResponse {
    fn ok(val: serde_json::Value) -> Self {
        let mut obj = match val {
            serde_json::Value::Object(m) => m,
            _ => Default::default(),
        };
        obj.insert("ok".into(), serde_json::Value::Bool(true));
        Self::Ok(serde_json::Value::Object(obj))
    }

    fn err(msg: impl ToString) -> Self {
        Self::Err {
            ok: false,
            error: msg.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Platform-specific listener
// ---------------------------------------------------------------------------

/// Run the IPC server forever.  Accepts connections and dispatches requests.
pub async fn run_ipc_server() -> Result<(), DaemonError> {
    let path = ipc_socket_path()?;

    #[cfg(unix)]
    {
        use tokio::net::UnixListener;
        // Remove stale socket file.
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).map_err(DaemonError::Io)?;
        tracing::info!("IPC listening on {}", path.display());
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(handle_unix_connection(stream));
                }
                Err(e) => {
                    tracing::warn!("IPC accept error: {e}");
                }
            }
        }
    }

    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};
        // The pipe name is stored in `path` as a PathBuf.
        let pipe_name = path.to_string_lossy().into_owned();
        tracing::info!("IPC listening on {pipe_name}");
        loop {
            let server = ServerOptions::new()
                .first_pipe_instance(false)
                .pipe_mode(PipeMode::Byte)
                .create(&pipe_name)
                .map_err(DaemonError::Io)?;
            server.connect().await.map_err(DaemonError::Io)?;
            tokio::spawn(handle_windows_pipe(server, pipe_name.clone()));
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        tracing::warn!("IPC not supported on this platform");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Connection handlers
// ---------------------------------------------------------------------------

#[cfg(unix)]
async fn handle_unix_connection(stream: tokio::net::UnixStream) {
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut lines = BufReader::new(read_half).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let resp = dispatch_request(&line).await;
        let mut out =
            serde_json::to_string(&resp).unwrap_or_else(|_| r#"{"ok":false,"error":"internal"}"#.into());
        out.push('\n');
        if write_half.write_all(out.as_bytes()).await.is_err() {
            break;
        }
    }
}

#[cfg(windows)]
async fn handle_windows_pipe(
    pipe: tokio::net::windows::named_pipe::NamedPipeServer,
    _pipe_name: String,
) {
    let (read_half, mut write_half) = tokio::io::split(pipe);
    let mut lines = BufReader::new(read_half).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let resp = dispatch_request(&line).await;
        let mut out =
            serde_json::to_string(&resp).unwrap_or_else(|_| r#"{"ok":false,"error":"internal"}"#.into());
        out.push('\n');
        if write_half.write_all(out.as_bytes()).await.is_err() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Request dispatcher
// ---------------------------------------------------------------------------

async fn dispatch_request(line: &str) -> IpcResponse {
    let req: IpcRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => return IpcResponse::err(format!("bad request JSON: {e}")),
    };

    match req {
        IpcRequest::NewEndpoint => handle_new_endpoint().await,
        IpcRequest::ListEndpoints => handle_list_endpoints().await,
        IpcRequest::Ticket {
            eid,
            relay,
            relay_sec_hex,
            app_fields,
        } => handle_ticket(eid, relay, relay_sec_hex, app_fields).await,
        IpcRequest::Status => handle_status().await,
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_new_endpoint() -> IpcResponse {
    match keystore::generate() {
        Ok((_sk, eid)) => IpcResponse::ok(serde_json::json!({ "eid": eid.to_base32() })),
        Err(e) => IpcResponse::err(e),
    }
}

async fn handle_list_endpoints() -> IpcResponse {
    match keystore::list_endpoints() {
        Ok(eids) => {
            let arr: Vec<serde_json::Value> = eids
                .iter()
                .map(|e| serde_json::Value::String(e.to_base32()))
                .collect();
            IpcResponse::ok(serde_json::json!({ "endpoints": arr }))
        }
        Err(e) => IpcResponse::err(e),
    }
}

async fn handle_ticket(
    eid_b32: String,
    relay: Option<String>,
    relay_sec_hex: Option<String>,
    app_fields: serde_json::Map<String, serde_json::Value>,
) -> IpcResponse {
    // Load the signing key.
    let (_sk, eid) = match keystore::load_by_b32(&eid_b32) {
        Ok(v) => v,
        Err(e) => return IpcResponse::err(e),
    };

    // Decode relay secret if provided.
    let relay_secret: Option<[u8; 32]> = match relay_sec_hex.as_deref() {
        Some(hex) => {
            match data_encoding::HEXLOWER_PERMISSIVE.decode(hex.as_bytes()) {
                Ok(bytes) => {
                    if bytes.len() != 32 {
                        return IpcResponse::err("relay_sec_hex must be 32 bytes (64 hex chars)");
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                }
                Err(e) => return IpcResponse::err(format!("invalid relay_sec_hex: {e}")),
            }
        }
        None => None,
    };

    // Convert app_fields to msgpack-compatible map.
    let mut meta_map = std::collections::HashMap::new();
    for (k, v) in &app_fields {
        meta_map.insert(k.clone(), json_to_rmpv(v));
    }

    // Build and encode the ticket.
    let mut ticket = Ticket::new(&eid);
    if let Some(host) = relay {
        if let Some(secret) = relay_secret {
            ticket = ticket.with_relay(host, secret);
        } else {
            ticket.lerp_rly = Some(host);
        }
    }
    ticket.app_fields = meta_map;

    match ticket.encode() {
        Ok(encoded) => IpcResponse::ok(serde_json::json!({ "ticket": encoded })),
        Err(e) => IpcResponse::err(format!("ticket encode failed: {e}")),
    }
}

async fn handle_status() -> IpcResponse {
    // Future: query shared state for active connections.
    IpcResponse::ok(serde_json::json!({ "connections": [] }))
}

// ---------------------------------------------------------------------------
// IPC client helper (used by CLI to query the running daemon)
// ---------------------------------------------------------------------------

/// Send a single request to the running daemon and return its response.
pub async fn send_request(req: &IpcRequest) -> Result<serde_json::Value, DaemonError> {
    let path = ipc_socket_path()?;
    let line = serde_json::to_string(req).map_err(|e| DaemonError::Ipc(e.to_string()))?;

    #[cfg(unix)]
    {
        use tokio::net::UnixStream;
        let stream = UnixStream::connect(&path)
            .await
            .map_err(|e| DaemonError::Ipc(format!("cannot connect to daemon: {e}")))?;
        let (read_half, mut write_half) = tokio::io::split(stream);
        write_half
            .write_all(format!("{line}\n").as_bytes())
            .await
            .map_err(DaemonError::Io)?;
        let mut resp_line = String::new();
        BufReader::new(read_half)
            .read_line(&mut resp_line)
            .await
            .map_err(DaemonError::Io)?;
        serde_json::from_str(resp_line.trim())
            .map_err(|e| DaemonError::Ipc(format!("bad daemon response: {e}")))
    }

    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        let pipe_name = path.to_string_lossy().into_owned();
        let pipe = ClientOptions::new()
            .open(&pipe_name)
            .map_err(|e| DaemonError::Ipc(format!("cannot connect to daemon: {e}")))?;
        let (read_half, mut write_half) = tokio::io::split(pipe);
        write_half
            .write_all(format!("{line}\n").as_bytes())
            .await
            .map_err(DaemonError::Io)?;
        let mut resp_line = String::new();
        BufReader::new(read_half)
            .read_line(&mut resp_line)
            .await
            .map_err(DaemonError::Io)?;
        serde_json::from_str(resp_line.trim())
            .map_err(|e| DaemonError::Ipc(format!("bad daemon response: {e}")))
    }

    #[cfg(not(any(unix, windows)))]
    {
        Err(DaemonError::Ipc("IPC not supported on this platform".into()))
    }
}

// ---------------------------------------------------------------------------
// serde_json → rmpv::Value conversion
// ---------------------------------------------------------------------------

fn json_to_rmpv(v: &serde_json::Value) -> rmpv::Value {
    match v {
        serde_json::Value::Null => rmpv::Value::Nil,
        serde_json::Value::Bool(b) => rmpv::Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                rmpv::Value::Integer(rmpv::Integer::from(i))
            } else if let Some(f) = n.as_f64() {
                rmpv::Value::F64(f)
            } else {
                rmpv::Value::Nil
            }
        }
        serde_json::Value::String(s) => {
            rmpv::Value::String(rmpv::Utf8String::from(s.as_str()))
        }
        serde_json::Value::Array(arr) => {
            rmpv::Value::Array(arr.iter().map(json_to_rmpv).collect())
        }
        serde_json::Value::Object(m) => rmpv::Value::Map(
            m.iter()
                .map(|(k, v)| {
                    (
                        rmpv::Value::String(rmpv::Utf8String::from(k.as_str())),
                        json_to_rmpv(v),
                    )
                })
                .collect(),
        ),
    }
}
