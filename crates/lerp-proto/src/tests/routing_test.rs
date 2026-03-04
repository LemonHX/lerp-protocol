use crate::{
    identity::SecretKey,
    routing::{
        build_sni, current_time_bucket, derive_routing_token, endpoint_to_sni, parse_sni_token,
        previous_time_bucket, recover_endpoint_id, sni_to_endpoint_id, RELAY_SECRET_LEN,
        WINDOW_SECONDS,
    },
};

fn make_secret() -> [u8; RELAY_SECRET_LEN] {
    let mut s = [0u8; RELAY_SECRET_LEN];
    s[0] = 0xDE;
    s[1] = 0xAD;
    s
}

// ---------------------------------------------------------------------------
// time_bucket
// ---------------------------------------------------------------------------

#[test]
fn current_time_bucket_is_reasonable() {
    // Unix epoch / WINDOW_SECONDS — must be well above ~2015 and below ~2100
    let bucket = current_time_bucket();
    assert!(bucket > 1_420_000_000 / WINDOW_SECONDS); // > 2015
    assert!(bucket < 4_102_444_800 / WINDOW_SECONDS); // < 2100
}

#[test]
fn previous_bucket_is_one_less() {
    let cur = current_time_bucket();
    let prev = previous_time_bucket();
    // Either equal (if cur == 0, which is impossible in practice) or cur - 1
    assert!(prev == cur.saturating_sub(1));
}

// ---------------------------------------------------------------------------
// derive / recover roundtrip
// ---------------------------------------------------------------------------

#[test]
fn routing_token_roundtrip_same_bucket() {
    let key = SecretKey::generate();
    let eid = key.endpoint_id();
    let secret = make_secret();
    let bucket = 42u64;

    let token = derive_routing_token(&eid, &secret, bucket);
    let recovered = recover_endpoint_id(&token, &secret, bucket);
    assert_eq!(eid, recovered);
}

#[test]
fn different_buckets_produce_different_tokens() {
    let key = SecretKey::generate();
    let eid = key.endpoint_id();
    let secret = make_secret();

    let t0 = derive_routing_token(&eid, &secret, 0);
    let t1 = derive_routing_token(&eid, &secret, 1);
    assert_ne!(t0, t1);
}

#[test]
fn different_secrets_produce_different_tokens() {
    let key = SecretKey::generate();
    let eid = key.endpoint_id();
    let secret_a = [0xAAu8; RELAY_SECRET_LEN];
    let secret_b = [0xBBu8; RELAY_SECRET_LEN];

    let ta = derive_routing_token(&eid, &secret_a, 0);
    let tb = derive_routing_token(&eid, &secret_b, 0);
    assert_ne!(ta, tb);
}

// ---------------------------------------------------------------------------
// build_sni / parse_sni_token
// ---------------------------------------------------------------------------

#[test]
fn build_and_parse_sni_roundtrip() {
    let token = [0xABu8; 32];
    let sni = build_sni(&token, "relay.example.com");

    // Subdomain must be 52 chars
    let subdomain = sni.split('.').next().unwrap();
    assert_eq!(subdomain.len(), 52);

    let parsed = parse_sni_token(&sni).unwrap();
    assert_eq!(parsed, token);
}

#[test]
fn parse_sni_invalid_base32() {
    assert!(parse_sni_token("!!!.relay.example.com").is_err());
}

#[test]
fn parse_sni_wrong_byte_length() {
    // "AAAA" decodes to 3 bytes, not 32
    assert!(parse_sni_token("AAAA.relay.example.com").is_err());
}

// ---------------------------------------------------------------------------
// sni_to_endpoint_id
// ---------------------------------------------------------------------------

#[test]
fn sni_to_endpoint_id_roundtrip() {
    let key = SecretKey::generate();
    let eid = key.endpoint_id();
    let secret = make_secret();
    let bucket = current_time_bucket();

    let token = derive_routing_token(&eid, &secret, bucket);
    let sni = build_sni(&token, "relay.example.com");

    let recovered = sni_to_endpoint_id(&sni, &secret, bucket).unwrap();
    assert_eq!(eid, recovered);
}

#[test]
fn sni_to_endpoint_id_invalid_sni() {
    let secret = make_secret();
    assert!(sni_to_endpoint_id("!!!bad", &secret, 0).is_err());
}

// ---------------------------------------------------------------------------
// endpoint_to_sni (convenience helper)
// ---------------------------------------------------------------------------

#[test]
fn endpoint_to_sni_recoverable_with_current_bucket() {
    let key = SecretKey::generate();
    let eid = key.endpoint_id();
    let secret = make_secret();

    let sni = endpoint_to_sni(&eid, &secret, "relay.example.com");
    let recovered = sni_to_endpoint_id(&sni, &secret, current_time_bucket()).unwrap();
    assert_eq!(eid, recovered);
}

#[test]
fn endpoint_to_sni_format() {
    let key = SecretKey::generate();
    let eid = key.endpoint_id();
    let secret = make_secret();
    let sni = endpoint_to_sni(&eid, &secret, "r.example.com");
    assert!(sni.ends_with(".r.example.com"), "sni={sni}");
    let subdomain = sni.split('.').next().unwrap();
    assert_eq!(subdomain.len(), 52);
}
