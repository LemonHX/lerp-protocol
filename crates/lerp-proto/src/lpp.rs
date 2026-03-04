//! lerp Peer Protocol (LPP) message types.
//!
//! All control messages travel over **uni-directional** WebTransport streams
//! (one message per stream, stream close = end of message).
//!
//! Ping / Pong use WebTransport **datagrams**.
//!
//! Every message is a msgpack **map** with a `"t"` key identifying the type.

use serde::{Deserialize, Serialize};

use crate::error::LerpError;

/// Maximum supported LPP version.
pub const LPP_VERSION: u8 = 0;

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// All LPP control messages.
///
/// Serialization uses rmp-serde in named (map) mode so the wire format
/// matches the spec's msgpack map layout.
#[derive(Debug, Clone, PartialEq)]
pub enum LppMessage {
    /// `"H"` – initiator sends first, starts E2E handshake.
    Hello(Hello),
    /// `"HA"` – responder's reply, completes identity exchange.
    HelloAck(HelloAck),
    /// `"AO"` – direct-connect candidate addresses (daemon profile only).
    AddrOffer(AddrOffer),
    /// `"PS"` – one UDP probe succeeded (daemon profile only).
    ProbeSuccess(ProbeSuccess),
    /// `"DU"` – initiator signals direct upgrade (daemon profile only).
    DirectUpgrade,
    /// `"DA"` – responder acknowledges direct upgrade (daemon profile only).
    DirectAck,
    /// `"QAD"` – relay-observed address discovery response.
    ///
    /// Relay→daemon control message carrying the daemon's externally observed
    /// socket address (`ip:port`) as seen by relay.
    Qad(Qad),
    /// `"PI"` – keepalive ping (datagram).
    Ping(Ping),
    /// `"PO"` – keepalive pong (datagram).
    Pong(Pong),
    /// `"CL"` – graceful close.
    Close(Close),
}

// ---------------------------------------------------------------------------
// Individual message structs
// ---------------------------------------------------------------------------

/// `Hello` message (`"H"`).
///
/// Sent by the connection initiator immediately after the WebTransport
/// connection is established.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    /// Maximum LPP version the sender supports.
    pub ver: u8,
    /// Sender's endpoint_id (base32-encoded Ed25519 public key).
    pub eid: String,
    /// Ephemeral X25519 public key (32 bytes).
    #[serde(with = "serde_bytes")]
    pub ecdh: Vec<u8>,
    /// Ed25519 signature over the `ecdh` bytes.
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    /// Optional application-defined metadata forwarded from the initiator's
    /// ticket `app_fields`.  lerp passes this through opaquely; the receiver
    /// reads it in the `on_connect` callback.  Absent when initiator has no
    /// app fields.  **Not E2E-encrypted** — protected only by relay TLS.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub meta: Option<std::collections::HashMap<String, rmpv::Value>>,
}

/// `HelloAck` message (`"HA"`).
///
/// Sent by the responder after verifying `Hello`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelloAck {
    /// Negotiated LPP version (min of both peers' `ver` fields).
    pub ver: u8,
    /// Responder's endpoint_id (base32-encoded Ed25519 public key).
    pub eid: String,
    /// Ephemeral X25519 public key (32 bytes).
    #[serde(with = "serde_bytes")]
    pub ecdh: Vec<u8>,
    /// Ed25519 signature over the `ecdh` bytes.
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// `AddrOffer` message (`"AO"`).
///
/// Daemon-only. Carries the sender's direct-connect candidate addresses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AddrOffer {
    /// Candidate addresses in `host:port` / `[ipv6]:port` format.
    pub addrs: Vec<String>,
}

/// `ProbeSuccess` message (`"PS"`).
///
/// Daemon-only. Announces that a UDP probe to one of the peer's candidates
/// succeeded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeSuccess {
    /// The peer's candidate address that was successfully probed.
    pub addr: String,
}

/// `QAD` message (`"QAD"`).
///
/// Sent by relay to each endpoint after relay-side accept, carrying the
/// externally observed source socket address.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Qad {
    /// Externally observed source socket address, e.g. `"203.0.113.2:54321"`.
    pub addr: String,
}

/// `Ping` datagram (`"PI"`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ping {
    pub seq: u64,
}

/// `Pong` datagram (`"PO"`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pong {
    pub seq: u64,
}

/// `Close` message (`"CL"`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Close {
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Well-known close reasons
// ---------------------------------------------------------------------------

impl Close {
    pub const SHUTDOWN: &'static str = "shutdown";
    pub const UNSUPPORTED_MSG: &'static str = "unsupported_message";
    pub const VERSION_INCOMPATIBLE: &'static str = "version_incompatible";
    pub const AUTH_FAILED: &'static str = "auth_failed";

    pub fn shutdown() -> Self {
        Self { reason: Self::SHUTDOWN.into() }
    }
    pub fn unsupported_message() -> Self {
        Self { reason: Self::UNSUPPORTED_MSG.into() }
    }
    pub fn auth_failed() -> Self {
        Self { reason: Self::AUTH_FAILED.into() }
    }
}

// ---------------------------------------------------------------------------
// Serialize / deserialize LppMessage to/from msgpack bytes
// ---------------------------------------------------------------------------

/// Encode an [`LppMessage`] as msgpack bytes (map-based, named fields).
///
/// The `"t"` type tag is always the first key in the map.
pub fn encode(msg: &LppMessage) -> Result<Vec<u8>, LerpError> {
    match msg {
        LppMessage::Hello(m) => encode_tagged("H", m),
        LppMessage::HelloAck(m) => encode_tagged("HA", m),
        LppMessage::AddrOffer(m) => encode_tagged("AO", m),
        LppMessage::ProbeSuccess(m) => encode_tagged("PS", m),
        LppMessage::DirectUpgrade => encode_tag_only("DU"),
        LppMessage::DirectAck => encode_tag_only("DA"),
        LppMessage::Qad(m) => encode_tagged("QAD", m),
        LppMessage::Ping(m) => encode_tagged("PI", m),
        LppMessage::Pong(m) => encode_tagged("PO", m),
        LppMessage::Close(m) => encode_tagged("CL", m),
    }
}

/// Decode an [`LppMessage`] from msgpack bytes.
pub fn decode(bytes: &[u8]) -> Result<LppMessage, LerpError> {
    // First pass: read only the "t" discriminant.
    #[derive(Deserialize)]
    struct TypeTag {
        t: String,
    }

    let tag: TypeTag = rmp_serde::from_slice(bytes)
        .map_err(|e| LerpError::Serialization(e.to_string()))?;

    // Second pass: deserialize the full message (unknown fields like "t" are ignored).
    match tag.t.as_str() {
        "H" => Ok(LppMessage::Hello(des(bytes)?)),
        "HA" => Ok(LppMessage::HelloAck(des(bytes)?)),
        "AO" => Ok(LppMessage::AddrOffer(des(bytes)?)),
        "PS" => Ok(LppMessage::ProbeSuccess(des(bytes)?)),
        "DU" => Ok(LppMessage::DirectUpgrade),
        "DA" => Ok(LppMessage::DirectAck),
        "QAD" => Ok(LppMessage::Qad(des(bytes)?)),
        "PI" => Ok(LppMessage::Ping(des(bytes)?)),
        "PO" => Ok(LppMessage::Pong(des(bytes)?)),
        "CL" => Ok(LppMessage::Close(des(bytes)?)),
        other => Err(LerpError::UnknownMessageType(other.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Generic serde wrapper that prepends a `"t"` type-tag key to any struct.
///
/// Because `inner` is `#[serde(flatten)]`-ed, rmp_serde writes a single map
/// whose first key is `"t"` followed by all fields of `T`.  No manual rmpv
/// map construction needed.
#[derive(Serialize)]
struct Tagged<'a, T: Serialize> {
    t: &'a str,
    #[serde(flatten)]
    inner: &'a T,
}

/// Tag-only message wrapper (DirectUpgrade / DirectAck).
#[derive(Serialize)]
struct TagOnly<'a> {
    t: &'a str,
}

fn encode_tagged<T: Serialize>(tag: &str, payload: &T) -> Result<Vec<u8>, LerpError> {
    rmp_serde::to_vec_named(&Tagged { t: tag, inner: payload })
        .map_err(|e| LerpError::Serialization(e.to_string()))
}

fn encode_tag_only(tag: &str) -> Result<Vec<u8>, LerpError> {
    rmp_serde::to_vec_named(&TagOnly { t: tag })
        .map_err(|e| LerpError::Serialization(e.to_string()))
}

/// Deserialize a typed struct from msgpack bytes (unknown fields like `"t"` are ignored).
fn des<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, LerpError> {
    rmp_serde::from_slice(bytes).map_err(|e| LerpError::Serialization(e.to_string()))
}
