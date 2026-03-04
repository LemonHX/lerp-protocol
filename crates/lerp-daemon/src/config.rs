//! lerp-daemon configuration.
//!
//! Config file location: `~/.lerp/config.toml`
//!
//! ```toml
//! [daemon]
//! quic_port = 51820  # optional; omit for auto
//!
//! [[serve]]
//! eid           = "A3F9B2C1..."   # our endpoint_id (base32)
//! forward       = "localhost:8080" # TCP target
//! relay         = "relay.example.com"
//! relay_sec_hex = "0000...64hex"  # relay secret (hex-encoded 32 bytes)
//! on_connect_hook = "/usr/local/bin/lerp-auth"  # optional
//!
//! [[connect]]
//! ticket     = "<base64url>"  # lerp ticket from peer
//! local_port = 5678           # local TCP port to listen on
//! ```

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::DaemonError;

// ---------------------------------------------------------------------------
// Top-level
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Config {
    #[serde(default)]
    pub daemon: DaemonSection,

    #[serde(default)]
    pub serve: Vec<ServeEntry>,

    #[serde(default)]
    pub connect: Vec<ConnectEntry>,
}

// ---------------------------------------------------------------------------
// [daemon] section
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DaemonSection {
    /// Fixed QUIC port for the embedded WebTransport server (P2P).
    /// If `None`, the OS picks a random ephemeral port.
    pub quic_port: Option<u16>,
}

// ---------------------------------------------------------------------------
// [[serve]] entries
// ---------------------------------------------------------------------------

/// A "serve" entry: accept connections intended for `eid` and forward them
/// to a local TCP address.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServeEntry {
    /// Our endpoint_id (base32).
    pub eid: String,

    /// Local TCP address to forward incoming connections to (e.g. `"localhost:8080"`).
    pub forward: String,

    /// Relay hostname (e.g. `"relay.example.com"`).
    /// Required unless the peer connects directly (P2P only).
    pub relay: Option<String>,

    /// Relay secret, hex-encoded 32 bytes.
    /// Must be set when `relay` is set.
    pub relay_sec_hex: Option<String>,

    /// Optional path to an on_connect hook script that authorises incoming connections.
    /// The script receives JSON on stdin and must write `{"accept":true}` or
    /// `{"accept":false,"reason":"..."}` on stdout.
    pub on_connect_hook: Option<String>,
}

impl ServeEntry {
    /// Decode the hex relay secret into 32 bytes.
    pub fn relay_secret(&self) -> Result<Option<[u8; 32]>, DaemonError> {
        let Some(ref hex) = self.relay_sec_hex else {
            return Ok(None);
        };
        let bytes = data_encoding::HEXLOWER_PERMISSIVE
            .decode(hex.trim().as_bytes())
            .map_err(|e| DaemonError::Config(format!("relay_sec_hex is invalid hex: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| DaemonError::Config("relay_sec_hex must decode to 32 bytes".into()))?;
        Ok(Some(arr))
    }
}

// ---------------------------------------------------------------------------
// [[connect]] entries
// ---------------------------------------------------------------------------

/// A "connect" entry: use a ticket to reach a remote endpoint and expose it
/// as a local TCP listener.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConnectEntry {
    /// lerp ticket (base64url).
    pub ticket: String,

    /// Local TCP port to listen on.  Incoming connections are forwarded
    /// through the E2E-encrypted relay path to the ticket's target endpoint.
    pub local_port: u16,
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

/// Returns `~/.lerp/`
pub fn lerp_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".lerp")
}

/// Returns `~/.lerp/keys/`
pub fn keys_dir() -> PathBuf {
    lerp_dir().join("keys")
}

/// Returns `~/.lerp/config.toml`
pub fn config_path() -> PathBuf {
    lerp_dir().join("config.toml")
}

/// Unix socket path (`~/.lerp/daemon.sock`) or Windows named-pipe name.
#[cfg(unix)]
pub fn ipc_path() -> PathBuf {
    lerp_dir().join("daemon.sock")
}

/// Named pipe name on Windows: `\\.\pipe\lerp-daemon`.
#[cfg(windows)]
pub fn ipc_pipe_name() -> String {
    r"\\.\pipe\lerp-daemon".to_string()
}

/// Unified IPC path: socket path on Unix, named-pipe path on Windows.
/// Returns a `PathBuf` whose `Display` gives the correct path/name on every
/// supported platform.
pub fn ipc_socket_path() -> Result<PathBuf, crate::error::DaemonError> {
    #[cfg(unix)]
    {
        Ok(ipc_path())
    }
    #[cfg(windows)]
    {
        Ok(PathBuf::from(ipc_pipe_name()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(crate::error::DaemonError::Ipc(
            "IPC not supported on this platform".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

impl Config {
    /// Load from an explicit path, or fall back to `~/.lerp/config.toml`.
    pub fn load_from(path: Option<std::path::PathBuf>) -> Result<Self, DaemonError> {
        let path = path.unwrap_or_else(config_path);
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path)?;
        toml::from_str(&text).map_err(|e| DaemonError::Config(e.to_string()))
    }

    /// Write the current config to `~/.lerp/config.toml`.
    #[allow(dead_code)]
    pub fn save(&self) -> Result<(), DaemonError> {
        let dir = lerp_dir();
        std::fs::create_dir_all(&dir)?;
        let text =
            toml::to_string_pretty(self).map_err(|e| DaemonError::Config(e.to_string()))?;
        std::fs::write(config_path(), text)?;
        Ok(())
    }
}
