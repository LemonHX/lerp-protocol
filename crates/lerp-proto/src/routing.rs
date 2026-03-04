//! Blind routing token derivation for relay SNI routing.
//!
//! Spec §04-relay: routing_token = endpoint_id XOR BLAKE3(relay_secret || time_bucket)[:32]

use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;

use crate::{error::LerpError, identity::EndpointId};

/// Default time window in seconds (10 minutes).
pub const WINDOW_SECONDS: u64 = 600;

/// Length of a relay secret in bytes.
pub const RELAY_SECRET_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Time bucket
// ---------------------------------------------------------------------------

/// Returns `floor(unix_timestamp_seconds / WINDOW_SECONDS)`.
pub fn current_time_bucket() -> u64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs();
    secs / WINDOW_SECONDS
}

/// Returns the previous time bucket (current - 1), used to tolerate clock skew.
pub fn previous_time_bucket() -> u64 {
    current_time_bucket().saturating_sub(1)
}

// ---------------------------------------------------------------------------
// BLAKE3 key-stream derivation
// ---------------------------------------------------------------------------

fn derive_keystream(relay_secret: &[u8; RELAY_SECRET_LEN], time_bucket: u64) -> [u8; 32] {
    // input = relay_secret (32 bytes) || time_bucket (8 bytes, little-endian)
    let mut input = [0u8; RELAY_SECRET_LEN + 8];
    input[..RELAY_SECRET_LEN].copy_from_slice(relay_secret);
    input[RELAY_SECRET_LEN..].copy_from_slice(&time_bucket.to_le_bytes());
    *blake3::hash(&input).as_bytes()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Derive the 32-byte routing token for a given endpoint and time bucket.
///
/// `routing_token = endpoint_id XOR BLAKE3(relay_secret || time_bucket)[:32]`
pub fn derive_routing_token(
    endpoint_id: &EndpointId,
    relay_secret: &[u8; RELAY_SECRET_LEN],
    time_bucket: u64,
) -> [u8; 32] {
    let ks = derive_keystream(relay_secret, time_bucket);
    let mut token = [0u8; 32];
    for i in 0..32 {
        token[i] = endpoint_id.as_bytes()[i] ^ ks[i];
    }
    token
}

/// Recover the endpoint_id from a routing token.
///
/// `endpoint_id = routing_token XOR BLAKE3(relay_secret || time_bucket)[:32]`
pub fn recover_endpoint_id(
    routing_token: &[u8; 32],
    relay_secret: &[u8; RELAY_SECRET_LEN],
    time_bucket: u64,
) -> EndpointId {
    let ks = derive_keystream(relay_secret, time_bucket);
    let mut eid = [0u8; 32];
    for i in 0..32 {
        eid[i] = routing_token[i] ^ ks[i];
    }
    EndpointId(eid)
}

/// Build the full SNI string: `<base32(routing_token)>.<relay_host>`
///
/// The base32 subdomain is 52 characters, well within the DNS label limit of
/// 63 characters.
pub fn build_sni(routing_token: &[u8; 32], relay_host: &str) -> String {
    format!("{}.{}", BASE32_NOPAD.encode(routing_token), relay_host)
}

/// Parse the 32-byte routing token from an SNI string.
///
/// Expects format `<base32_52_chars>.<rest>`.
pub fn parse_sni_token(sni: &str) -> Result<[u8; 32], LerpError> {
    let subdomain = sni
        .split('.')
        .next()
        .ok_or_else(|| LerpError::InvalidEncoding("invalid SNI format".into()))?;

    let bytes = BASE32_NOPAD
        .decode(subdomain.to_uppercase().as_bytes())
        .map_err(|e| LerpError::InvalidEncoding(e.to_string()))?;

    bytes
        .try_into()
        .map_err(|_| LerpError::InvalidEncoding("routing token must be 32 bytes".into()))
}

/// High-level helper: recover the endpoint_id from an SNI string.
///
/// The relay calls this for **both** `current_time_bucket()` and
/// `previous_time_bucket()`, then selects the one that matches an awaiting
/// connection.
pub fn sni_to_endpoint_id(
    sni: &str,
    relay_secret: &[u8; RELAY_SECRET_LEN],
    time_bucket: u64,
) -> Result<EndpointId, LerpError> {
    let token = parse_sni_token(sni)?;
    Ok(recover_endpoint_id(&token, relay_secret, time_bucket))
}

/// Convenience: derive the SNI for the **current** time bucket.
pub fn endpoint_to_sni(
    endpoint_id: &EndpointId,
    relay_secret: &[u8; RELAY_SECRET_LEN],
    relay_host: &str,
) -> String {
    let token = derive_routing_token(endpoint_id, relay_secret, current_time_bucket());
    build_sni(&token, relay_host)
}
