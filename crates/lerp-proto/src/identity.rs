//! Identity primitives: Ed25519 keypair, EndpointId, and ECDH ephemeral keys.

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, SharedSecret};

use crate::error::LerpError;

/// Length of an EndpointId / Ed25519 public key in bytes.
pub const ENDPOINT_ID_LEN: usize = 32;
/// Length of the base32 (no padding) string representation.
pub const ENDPOINT_ID_BASE32_LEN: usize = 52;

// ---------------------------------------------------------------------------
// EndpointId
// ---------------------------------------------------------------------------

/// An endpoint's globally unique identity: the raw bytes of its Ed25519 public key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EndpointId(pub [u8; ENDPOINT_ID_LEN]);

impl EndpointId {
    pub fn from_bytes(bytes: [u8; ENDPOINT_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; ENDPOINT_ID_LEN] {
        &self.0
    }

    /// Encodes as RFC 4648 base32 without padding (52 chars).
    pub fn to_base32(&self) -> String {
        BASE32_NOPAD.encode(&self.0)
    }

    /// Decodes from RFC 4648 base32 (no padding).
    pub fn from_base32(s: &str) -> Result<Self, LerpError> {
        let bytes = BASE32_NOPAD
            .decode(s.to_uppercase().as_bytes())
            .map_err(|e| LerpError::InvalidEndpointId(e.to_string()))?;

        let arr: [u8; ENDPOINT_ID_LEN] = bytes
            .try_into()
            .map_err(|_| LerpError::InvalidEndpointId(
                format!("expected {} bytes", ENDPOINT_ID_LEN),
            ))?;
        Ok(Self(arr))
    }

    /// Returns the underlying ed25519 verifying key.
    pub fn to_verifying_key(&self) -> Result<VerifyingKey, LerpError> {
        VerifyingKey::from_bytes(&self.0)
            .map_err(|e| LerpError::InvalidEndpointId(e.to_string()))
    }
}

impl std::fmt::Display for EndpointId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base32())
    }
}

// ---------------------------------------------------------------------------
// SecretKey (Ed25519 signing key)
// ---------------------------------------------------------------------------

/// The Ed25519 signing key for an endpoint.
///
/// The raw 32-byte private scalar is stored locally and **never** leaves the
/// host machine.
pub struct SecretKey(SigningKey);

impl SecretKey {
    /// Generate a fresh random keypair.
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    /// Restore from raw 32-byte Ed25519 seed bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    /// Export the raw 32-byte seed (for local persistence).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Derive the corresponding [`EndpointId`].
    pub fn endpoint_id(&self) -> EndpointId {
        EndpointId(self.0.verifying_key().to_bytes())
    }

    /// Sign arbitrary bytes, returning a 64-byte signature.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/// Verify an Ed25519 signature.
///
/// - `endpoint_id`: the signer's public key
/// - `msg`:         the message that was signed
/// - `sig_bytes`:   64-byte raw signature
pub fn verify_signature(
    endpoint_id: &EndpointId,
    msg: &[u8],
    sig_bytes: &[u8],
) -> Result<(), LerpError> {
    let vk = endpoint_id.to_verifying_key()?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| LerpError::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(msg, &sig).map_err(|_| LerpError::InvalidSignature)
}

// ---------------------------------------------------------------------------
// Ephemeral X25519 ECDH (used in Hello / HelloAck)
// ---------------------------------------------------------------------------

/// An ephemeral X25519 key pair for use in a single LPP handshake.
///
/// Drop this after computing the shared secret — it is consumed by
/// [`EphemeralEcdh::complete`].
pub struct EphemeralEcdh {
    secret: EphemeralSecret,
    public: X25519PublicKey,
}

impl EphemeralEcdh {
    /// Generate a new ephemeral key pair.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// The public key bytes to send in `Hello` / `HelloAck` (`ecdh` field).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Perform Diffie-Hellman with the peer's public key bytes and return the
    /// 32-byte shared secret.
    pub fn complete(self, peer_pub_bytes: &[u8; 32]) -> SharedSecret {
        let peer_pub = X25519PublicKey::from(*peer_pub_bytes);
        self.secret.diffie_hellman(&peer_pub)
    }
}
