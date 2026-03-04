//! Unified error type for lerp-daemon.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("lerp-proto error: {0}")]
    Proto(#[from] lerp_proto::error::LerpError),

    #[error("WebTransport error: {0}")]
    WebTransport(String),

    #[error("handshake failed: {0}")]
    Handshake(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("key error: {0}")]
    Key(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("connection rejected by hook: {0}")]
    Rejected(String),

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("hook error: {0}")]
    Hook(String),

    #[error("ticket error: {0}")]
    Ticket(String),
}

impl From<wtransport::error::ConnectionError> for DaemonError {
    fn from(e: wtransport::error::ConnectionError) -> Self {
        Self::WebTransport(e.to_string())
    }
}
