//! `lerp-proto` – shared protocol types and utilities for the lerp network.
//!
//! ## Module layout
//!
//! | Module | Contents |
//! |---|---|
//! | [`error`] | [`LerpError`] – unified error type |
//! | [`identity`] | [`EndpointId`], [`SecretKey`], [`EphemeralEcdh`], signature helpers |
//! | [`routing`] | Blind routing-token derivation and SNI helpers |
//! | [`ticket`] | [`Ticket`] encode / decode (msgpack + BLAKE3 checksum + base64url) |
//! | [`lpp`] | LPP message types and msgpack codec ([`LppMessage`], [`lpp::encode`], [`lpp::decode`]) |

pub mod error;
pub mod identity;
pub mod lpp;
pub mod routing;
pub mod ticket;

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// Convenient top-level re-exports
// ---------------------------------------------------------------------------

pub use error::LerpError;
pub use identity::{EndpointId, EphemeralEcdh, SecretKey};
pub use lpp::LppMessage;
pub use routing::{
    build_sni, current_time_bucket, derive_routing_token, endpoint_to_sni, parse_sni_token,
    previous_time_bucket, recover_endpoint_id, sni_to_endpoint_id,
};
pub use ticket::{Ticket, LERP_VERSION};
