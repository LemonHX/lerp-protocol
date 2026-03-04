//! Ed25519 key storage under `~/.lerp/keys/<eid_base32>.key`.
//!
//! Each key file contains the raw 32-byte Ed25519 seed (private scalar).
//! File permissions are set to 0600 on Unix.

use std::path::PathBuf;

use lerp_proto::identity::{EndpointId, SecretKey};

use crate::config::keys_dir;
use crate::error::DaemonError;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a fresh Ed25519 keypair and persist it.
pub fn generate() -> Result<(SecretKey, EndpointId), DaemonError> {
    let sk = SecretKey::generate();
    let eid = sk.endpoint_id();
    persist(&sk, &eid)?;
    Ok((sk, eid))
}

/// Load a secret key by its EndpointId.
pub fn load(eid: &EndpointId) -> Result<SecretKey, DaemonError> {
    let path = key_path(eid);
    let bytes = std::fs::read(&path).map_err(|e| {
        DaemonError::Key(format!("cannot read key {}: {e}", eid.to_base32()))
    })?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DaemonError::Key("key file must be exactly 32 bytes".into()))?;
    Ok(SecretKey::from_bytes(&arr))
}

/// Load a secret key by its base32 string representation.
pub fn load_by_b32(eid_b32: &str) -> Result<(SecretKey, EndpointId), DaemonError> {
    let eid = EndpointId::from_base32(eid_b32)?;
    let sk = load(&eid)?;
    Ok((sk, eid))
}

/// List all EndpointIds that have keys stored on disk.
pub fn list_endpoints() -> Result<Vec<EndpointId>, DaemonError> {
    let dir = keys_dir();
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut eids = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(b32) = name.strip_suffix(".key") {
            if let Ok(eid) = EndpointId::from_base32(b32) {
                eids.push(eid);
            }
        }
    }
    Ok(eids)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn key_path(eid: &EndpointId) -> PathBuf {
    keys_dir().join(format!("{}.key", eid.to_base32()))
}

fn persist(sk: &SecretKey, eid: &EndpointId) -> Result<(), DaemonError> {
    let path = key_path(eid);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, sk.to_bytes())?;

    // Restrict permissions to owner-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}
