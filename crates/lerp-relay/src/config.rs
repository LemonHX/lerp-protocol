//! Relay runtime configuration, loaded from environment variables.
//!
//! | Variable              | Required | Default        | Description                               |
//! |-----------------------|----------|----------------|-------------------------------------------|
//! | `RELAY_SECRET`        | yes      | —              | Hex-encoded 32-byte relay secret          |
//! | `RELAY_CERT`          | yes      | —              | Path to TLS certificate PEM               |
//! | `RELAY_KEY`           | yes      | —              | Path to TLS private-key PEM               |
//! | `RELAY_BIND`          | no       | 0.0.0.0:443    | Socket address to listen on               |
//! | `RELAY_PAIR_TIMEOUT`  | no       | 30             | Seconds to wait for a peer connection     |

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use data_encoding::HEXLOWER_PERMISSIVE;

use crate::error::RelayError;

/// Runtime configuration for the relay.
#[derive(Debug)]
pub struct RelayConfig {
    /// 32-byte secret used to derive the blind routing tokens.
    pub relay_secret: [u8; 32],
    /// Local socket address to bind the WebTransport server on.
    pub bind_addr: SocketAddr,
    /// Path to TLS certificate PEM file (wildcard cert recommended).
    pub cert_path: PathBuf,
    /// Path to TLS private key PEM file.
    pub key_path: PathBuf,
    /// How long to suspend a connection while waiting for its peer.
    pub pair_timeout: Duration,
}

impl RelayConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, RelayError> {
        // --- RELAY_SECRET ---
        let secret_hex = std::env::var("RELAY_SECRET").map_err(|_| {
            RelayError::Config(
                "RELAY_SECRET environment variable is required (hex-encoded 32 bytes)".into(),
            )
        })?;
        let secret_bytes = HEXLOWER_PERMISSIVE
            .decode(secret_hex.trim().as_bytes())
            .map_err(|e| RelayError::Config(format!("RELAY_SECRET is not valid hex: {e}")))?;
        let relay_secret: [u8; 32] = secret_bytes.try_into().map_err(|_| {
            RelayError::Config("RELAY_SECRET must decode to exactly 32 bytes".into())
        })?;

        // --- RELAY_CERT / RELAY_KEY ---
        let cert_path: PathBuf = std::env::var("RELAY_CERT")
            .map_err(|_| RelayError::Config("RELAY_CERT environment variable is required".into()))?
            .into();
        let key_path: PathBuf = std::env::var("RELAY_KEY")
            .map_err(|_| RelayError::Config("RELAY_KEY environment variable is required".into()))?
            .into();

        // --- RELAY_BIND ---
        let bind_addr: SocketAddr = std::env::var("RELAY_BIND")
            .unwrap_or_else(|_| "0.0.0.0:443".into())
            .parse()
            .map_err(|e| RelayError::Config(format!("RELAY_BIND is not a valid socket address: {e}")))?;

        // --- RELAY_PAIR_TIMEOUT ---
        let pair_timeout_secs: u64 = std::env::var("RELAY_PAIR_TIMEOUT")
            .unwrap_or_else(|_| "30".into())
            .parse()
            .map_err(|e| RelayError::Config(format!("RELAY_PAIR_TIMEOUT must be an integer: {e}")))?;

        Ok(Self {
            relay_secret,
            bind_addr,
            cert_path,
            key_path,
            pair_timeout: Duration::from_secs(pair_timeout_secs),
        })
    }
}
