use rmpv::Value;

use crate::{
    identity::SecretKey,
    ticket::{Ticket, CHECKSUM_LEN, LERP_VERSION},
};

fn make_ticket() -> (SecretKey, Ticket) {
    let key = SecretKey::generate();
    let ticket = Ticket::new(&key.endpoint_id());
    (key, ticket)
}

fn relay_secret() -> [u8; 32] {
    [0xBEu8; 32]
}

// ---------------------------------------------------------------------------
// Constructors & accessors
// ---------------------------------------------------------------------------

#[test]
fn new_ticket_defaults() {
    let (key, ticket) = make_ticket();
    assert_eq!(ticket.lerp_ver, LERP_VERSION);
    assert_eq!(ticket.lerp_eid, key.endpoint_id().to_base32());
    assert!(ticket.lerp_rly.is_none());
    assert!(ticket.lerp_sec.is_none());
    assert!(ticket.lerp_dir.is_none());
    assert!(ticket.app_fields.is_empty());
    assert!(!ticket.has_relay());
    assert!(ticket.relay_secret().is_none());
}

#[test]
fn with_relay_sets_fields() {
    let (_, ticket) = make_ticket();
    let sec = relay_secret();
    let t = ticket.with_relay("relay.example.com".into(), sec);
    assert_eq!(t.lerp_rly.as_deref(), Some("relay.example.com"));
    assert_eq!(t.lerp_sec, Some(sec));
    assert!(t.has_relay());
    assert_eq!(t.relay_secret(), Some(&sec));
}

#[test]
fn with_direct_sets_addrs() {
    let (_, ticket) = make_ticket();
    let addrs = vec!["1.2.3.4:5000".into(), "[::1]:5000".into()];
    let t = ticket.with_direct(addrs.clone());
    assert_eq!(t.lerp_dir, Some(addrs));
}

#[test]
fn with_app_field_inserts_kv() {
    let (_, ticket) = make_ticket();
    let t = ticket.with_app_field("invite_code", Value::String("XYZ".into()));
    assert!(t.app_fields.contains_key("invite_code"));
}

#[test]
fn endpoint_id_accessor_matches_eid() {
    let (key, ticket) = make_ticket();
    assert_eq!(ticket.endpoint_id().unwrap(), key.endpoint_id());
}

// ---------------------------------------------------------------------------
// Encode → Decode roundtrips
// ---------------------------------------------------------------------------

#[test]
fn minimal_ticket_roundtrip() {
    let (_, ticket) = make_ticket();
    let s = ticket.encode().unwrap();
    let decoded = Ticket::decode(&s).unwrap();
    assert_eq!(decoded.lerp_ver, ticket.lerp_ver);
    assert_eq!(decoded.lerp_eid, ticket.lerp_eid);
    assert!(decoded.lerp_rly.is_none());
    assert!(decoded.lerp_sec.is_none());
}

#[test]
fn ticket_with_relay_roundtrip() {
    let (_, ticket) = make_ticket();
    let sec = relay_secret();
    let t = ticket.with_relay("r.example.com".into(), sec);
    let s = t.encode().unwrap();
    let d = Ticket::decode(&s).unwrap();
    assert_eq!(d.lerp_rly.as_deref(), Some("r.example.com"));
    assert_eq!(d.lerp_sec, Some(sec));
}

#[test]
fn ticket_with_direct_roundtrip() {
    let (_, ticket) = make_ticket();
    let addrs = vec!["10.0.0.1:7777".into()];
    let t = ticket.with_direct(addrs.clone());
    let s = t.encode().unwrap();
    let d = Ticket::decode(&s).unwrap();
    assert_eq!(d.lerp_dir, Some(addrs));
}

#[test]
fn ticket_with_app_fields_roundtrip() {
    let (_, ticket) = make_ticket();
    let t = ticket
        .with_app_field("user_id", Value::String("alice".into()))
        .with_app_field("version", Value::Integer(2.into()));
    let s = t.encode().unwrap();
    let d = Ticket::decode(&s).unwrap();
    assert!(d.app_fields.contains_key("user_id"));
    assert!(d.app_fields.contains_key("version"));
}

#[test]
fn full_ticket_roundtrip() {
    let (_, ticket) = make_ticket();
    let sec = relay_secret();
    let t = ticket
        .with_relay("relay.lerp.io".into(), sec)
        .with_direct(vec!["192.168.1.1:9000".into()])
        .with_app_field("role", Value::String("admin".into()));
    let s = t.encode().unwrap();
    let d = Ticket::decode(&s).unwrap();
    assert_eq!(d.lerp_rly.as_deref(), Some("relay.lerp.io"));
    assert_eq!(d.lerp_sec, Some(sec));
    assert_eq!(d.lerp_dir.unwrap(), vec!["192.168.1.1:9000"]);
    assert!(d.app_fields.contains_key("role"));
}

// ---------------------------------------------------------------------------
// Decode error cases
// ---------------------------------------------------------------------------

#[test]
fn decode_invalid_base64url() {
    assert!(Ticket::decode("!!!not-base64url!!!").is_err());
}

#[test]
fn decode_too_short() {
    // Less than CHECKSUM_LEN bytes encoded
    use data_encoding::BASE64URL_NOPAD;
    let short = BASE64URL_NOPAD.encode(&[0u8; CHECKSUM_LEN - 1]);
    assert!(Ticket::decode(&short).is_err());
}

#[test]
fn decode_checksum_mismatch() {
    let (_, ticket) = make_ticket();
    let mut wire = {
        use data_encoding::BASE64URL_NOPAD;
        BASE64URL_NOPAD.decode(ticket.encode().unwrap().as_bytes()).unwrap()
    };
    // Flip a checksum byte
    wire[0] ^= 0xFF;
    use data_encoding::BASE64URL_NOPAD;
    let corrupted = BASE64URL_NOPAD.encode(&wire);
    assert!(Ticket::decode(&corrupted).is_err());
}

#[test]
fn decode_relay_without_secret_rejected() {
    // Manually construct a ticket where lerp_rly is set but lerp_sec is absent.
    // Easiest: encode a valid ticket, then tamper the msgpack to remove lerp_sec.
    // Instead we just build the struct directly and bypass encode's validation,
    // using rmp_serde directly to craft the wire bytes.
    use data_encoding::BASE64URL_NOPAD;

    let key = SecretKey::generate();
    let mut ticket = Ticket::new(&key.endpoint_id());
    // Set rly but leave sec = None (invalid combination)
    ticket.lerp_rly = Some("relay.example.com".into());
    // ticket.lerp_sec stays None

    // Bypass encode() by calling to_msgpack via rmp_serde directly
    let payload = rmp_serde::to_vec_named(&ticket).unwrap();
    let binding = blake3::hash(&payload);
    let checksum = &binding.as_bytes()[..CHECKSUM_LEN];
    let mut wire = Vec::new();
    wire.extend_from_slice(checksum);
    wire.extend_from_slice(&payload);
    let s = BASE64URL_NOPAD.encode(&wire);

    assert!(Ticket::decode(&s).is_err());
}

#[test]
fn decode_different_version_still_succeeds() {
    // A ticket with a different lerp_ver should decode (with a warning), not error.
    let (_, mut ticket) = make_ticket();
    ticket.lerp_ver = "9.9.9".into();
    let payload = rmp_serde::to_vec_named(&ticket).unwrap();
    let binding = blake3::hash(&payload);
    let checksum = &binding.as_bytes()[..CHECKSUM_LEN];
    let mut wire = Vec::new();
    wire.extend_from_slice(checksum);
    wire.extend_from_slice(&payload);
    use data_encoding::BASE64URL_NOPAD;
    let s = BASE64URL_NOPAD.encode(&wire);
    // Should succeed (just warns)
    assert!(Ticket::decode(&s).is_ok());
}
