use crate::identity::{verify_signature, EndpointId, EphemeralEcdh, SecretKey, ENDPOINT_ID_LEN};

// ---------------------------------------------------------------------------
// SecretKey
// ---------------------------------------------------------------------------

#[test]
fn secret_key_generate_is_unique() {
    let a = SecretKey::generate();
    let b = SecretKey::generate();
    assert_ne!(a.endpoint_id(), b.endpoint_id());
}

#[test]
fn secret_key_roundtrip_bytes() {
    let key = SecretKey::generate();
    let bytes = key.to_bytes();
    let restored = SecretKey::from_bytes(&bytes);
    assert_eq!(key.endpoint_id(), restored.endpoint_id());
}

#[test]
fn secret_key_verifying_key_matches_endpoint_id() {
    let key = SecretKey::generate();
    let eid = key.endpoint_id();
    let vk = key.verifying_key();
    assert_eq!(vk.to_bytes(), *eid.as_bytes());
}

// ---------------------------------------------------------------------------
// EndpointId
// ---------------------------------------------------------------------------

#[test]
fn endpoint_id_from_bytes_roundtrip() {
    let bytes = [0x42u8; ENDPOINT_ID_LEN];
    let eid = EndpointId::from_bytes(bytes);
    assert_eq!(eid.as_bytes(), &bytes);
}

#[test]
fn endpoint_id_base32_roundtrip() {
    let key = SecretKey::generate();
    let eid = key.endpoint_id();
    let s = eid.to_base32();
    assert_eq!(s.len(), 52, "base32 must be 52 chars");
    let decoded = EndpointId::from_base32(&s).unwrap();
    assert_eq!(eid, decoded);
}

#[test]
fn endpoint_id_base32_case_insensitive() {
    let key = SecretKey::generate();
    let eid = key.endpoint_id();
    let lower = eid.to_base32().to_lowercase();
    let upper = eid.to_base32().to_uppercase();
    assert_eq!(
        EndpointId::from_base32(&lower).unwrap(),
        EndpointId::from_base32(&upper).unwrap(),
    );
}

#[test]
fn endpoint_id_from_base32_invalid_chars() {
    // Base32 alphabet doesn't include '0','1','8','9'
    let result = EndpointId::from_base32("00000000000000000000000000000000000000000000000000!!");
    assert!(result.is_err());
}

#[test]
fn endpoint_id_from_base32_too_short() {
    // Valid base32 chars but decodes to wrong byte length
    let result = EndpointId::from_base32("AAAA");
    assert!(result.is_err());
}

#[test]
fn endpoint_id_display_equals_base32() {
    let key = SecretKey::generate();
    let eid = key.endpoint_id();
    assert_eq!(format!("{eid}"), eid.to_base32());
}

#[test]
fn endpoint_id_ordering() {
    let a = EndpointId::from_bytes([0x00; 32]);
    let b = EndpointId::from_bytes([0xff; 32]);
    assert!(a < b);
}

// ---------------------------------------------------------------------------
// verify_signature
// ---------------------------------------------------------------------------

#[test]
fn verify_signature_happy_path() {
    let key = SecretKey::generate();
    let eid = key.endpoint_id();
    let msg = b"hello lerp";
    let sig = key.sign(msg);
    verify_signature(&eid, msg, &sig).unwrap();
}

#[test]
fn verify_signature_wrong_message() {
    let key = SecretKey::generate();
    let eid = key.endpoint_id();
    let sig = key.sign(b"original");
    assert!(verify_signature(&eid, b"tampered", &sig).is_err());
}

#[test]
fn verify_signature_wrong_key() {
    let signer = SecretKey::generate();
    let other = SecretKey::generate();
    let msg = b"hello";
    let sig = signer.sign(msg);
    // Verify against a different endpoint_id → must fail
    assert!(verify_signature(&other.endpoint_id(), msg, &sig).is_err());
}

#[test]
fn verify_signature_short_sig() {
    let key = SecretKey::generate();
    let eid = key.endpoint_id();
    // 63 bytes instead of 64 → must fail before even calling dalek
    let short = [0u8; 63];
    assert!(verify_signature(&eid, b"msg", &short).is_err());
}

// ---------------------------------------------------------------------------
// EphemeralEcdh
// ---------------------------------------------------------------------------

#[test]
fn ephemeral_ecdh_shared_secret_matches() {
    let alice = EphemeralEcdh::generate();
    let bob = EphemeralEcdh::generate();

    let alice_pub = alice.public_key_bytes();
    let bob_pub = bob.public_key_bytes();

    let alice_ss = alice.complete(&bob_pub);
    let bob_ss = bob.complete(&alice_pub);

    assert_eq!(alice_ss.as_bytes(), bob_ss.as_bytes());
}

#[test]
fn ephemeral_ecdh_public_keys_differ() {
    let a = EphemeralEcdh::generate();
    let b = EphemeralEcdh::generate();
    assert_ne!(a.public_key_bytes(), b.public_key_bytes());
}
