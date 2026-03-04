//! End-to-end session encryption for lerp daemon connections.
//!
//! After the Hello/HelloAck exchange:
//!
//! 1. Both sides have the ECDH shared secret (32 bytes from X25519).
//! 2. Two directional keys are derived via HKDF-SHA256 with distinct labels.
//! 3. Each QUIC bi-directional stream's data is framed as:
//!    `[4-byte LE ciphertext length][ChaCha20-Poly1305 ciphertext (includes 16-byte tag)]`
//!    A monotonically increasing per-stream sequence counter forms the nonce.
//!
//! The key assignment is deterministic regardless of connection order by
//! sorting the two peers' ephemeral ECDH public keys lexicographically.
//! The peer whose pubkey sorts *lower* is "side A"; the other is "side B".
//! Side A's send key is `lerp-v0-a-to-b`; side B's send key is `lerp-v0-b-to-a`.

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::DaemonError;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const FRAME_HDR: usize = 4; // 4-byte LE length prefix

// ---------------------------------------------------------------------------
// Session key derivation
// ---------------------------------------------------------------------------

/// Session keys derived from an ECDH shared secret.
pub struct SessionKeys {
    /// Key to use when *encrypting* outgoing stream data.
    pub send_key: [u8; KEY_LEN],
    /// Key to use when *decrypting* incoming stream data.
    pub recv_key: [u8; KEY_LEN],
}

impl SessionKeys {
    /// Derive send/recv keys from the ECDH shared secret.
    ///
    /// `our_ecdh_pub` and `peer_ecdh_pub` are each 32-byte X25519 public keys.
    /// The direction assignment is deterministic: the side whose pubkey sorts
    /// lexicographically lower gets label `"lerp-v0-a-to-b"` as its send key.
    pub fn derive(
        shared_secret: &[u8; 32],
        our_ecdh_pub: &[u8; 32],
        peer_ecdh_pub: &[u8; 32],
    ) -> Result<Self, DaemonError> {
        let hk = Hkdf::<Sha256>::new(None, shared_secret);

        let mut key_a_to_b = [0u8; KEY_LEN];
        let mut key_b_to_a = [0u8; KEY_LEN];

        hk.expand(b"lerp-v0-a-to-b", &mut key_a_to_b)
            .map_err(|e| DaemonError::Crypto(e.to_string()))?;
        hk.expand(b"lerp-v0-b-to-a", &mut key_b_to_a)
            .map_err(|e| DaemonError::Crypto(e.to_string()))?;

        // "A" is the peer whose ECDH pubkey is lexicographically smaller.
        let (send_key, recv_key) = if our_ecdh_pub < peer_ecdh_pub {
            // We are "A": our outgoing = a-to-b, their outgoing = b-to-a
            (key_a_to_b, key_b_to_a)
        } else {
            // We are "B": our outgoing = b-to-a, their outgoing = a-to-b
            (key_b_to_a, key_a_to_b)
        };

        Ok(Self { send_key, recv_key })
    }
}

// ---------------------------------------------------------------------------
// Per-stream ciphers
// ---------------------------------------------------------------------------

/// Encrypts outgoing stream data for one stream direction.
pub struct SendCipher {
    cipher: ChaCha20Poly1305,
    seq: u64,
}

impl SendCipher {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        Self { cipher: ChaCha20Poly1305::new(key.into()), seq: 0 }
    }

    /// Encrypt `plaintext` and return a fully-framed wire chunk:
    /// `[4-byte LE length of ciphertext][ciphertext]`
    ///
    /// The ciphertext already includes the 16-byte Poly1305 tag.
    pub fn seal_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, DaemonError> {
        let nonce_bytes = make_nonce(self.seq);
        let ct = self
            .cipher
            .encrypt(&nonce_bytes.into(), plaintext)
            .map_err(|e| DaemonError::Crypto(e.to_string()))?;
        self.seq += 1;

        let mut frame = Vec::with_capacity(FRAME_HDR + ct.len());
        frame.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        frame.extend_from_slice(&ct);
        Ok(frame)
    }
}

/// Decrypts incoming stream data for one stream direction.
pub struct RecvCipher {
    cipher: ChaCha20Poly1305,
    seq: u64,
}

impl RecvCipher {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        Self { cipher: ChaCha20Poly1305::new(key.into()), seq: 0 }
    }

    /// Decrypt one ciphertext block (without the 4-byte length header).
    pub fn open(&mut self, ct: &[u8]) -> Result<Vec<u8>, DaemonError> {
        if ct.len() < TAG_LEN {
            return Err(DaemonError::Crypto("ciphertext too short".into()));
        }
        let nonce_bytes = make_nonce(self.seq);
        let pt = self
            .cipher
            .decrypt(&nonce_bytes.into(), ct)
            .map_err(|_| DaemonError::Crypto("decryption failed (bad tag)".into()))?;
        self.seq += 1;
        Ok(pt)
    }
}

// ---------------------------------------------------------------------------
// Nonce construction
// ---------------------------------------------------------------------------

/// Build a 12-byte nonce from a 64-bit counter: bytes 0-3 = 0, bytes 4-11 = seq LE.
fn make_nonce(seq: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[4..].copy_from_slice(&seq.to_le_bytes());
    n
}
