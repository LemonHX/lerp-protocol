use thiserror::Error;

#[derive(Debug, Error)]
pub enum LerpError {
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid ticket: {0}")]
    InvalidTicket(String),

    #[error("invalid endpoint id: {0}")]
    InvalidEndpointId(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("unknown LPP message type: {0}")]
    UnknownMessageType(String),

    #[error("LPP version incompatible: remote={remote}, local_max={local_max}")]
    VersionIncompatible { remote: u8, local_max: u8 },

    #[error("missing required field: {0}")]
    MissingField(String),
}
