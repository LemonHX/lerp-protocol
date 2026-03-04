//! Error types for lerp-relay.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("invalid SNI: {0}")]
    InvalidSni(String),

    #[error("lerp-proto error: {0}")]
    Proto(#[from] lerp_proto::error::LerpError),

    #[error("WebTransport connection error: {0}")]
    Connection(#[from] wtransport::error::ConnectionError),

    #[error("WebTransport send datagram error: {0}")]
    SendDatagram(#[from] wtransport::error::SendDatagramError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("config error: {0}")]
    Config(String),
}
