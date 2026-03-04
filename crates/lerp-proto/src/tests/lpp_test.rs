use std::collections::HashMap;

use crate::{
    identity::SecretKey,
    lpp::{
        self, AddrOffer, Close, Hello, HelloAck, Ping, Pong, ProbeSuccess, LPP_VERSION,
    },
    LppMessage,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hello_no_meta() -> Hello {
    let key = SecretKey::generate();
    let eid = key.endpoint_id().to_base32();
    let ecdh = vec![0u8; 32];
    let sig = key.sign(&ecdh).to_vec();
    Hello { ver: LPP_VERSION, eid, ecdh, sig, meta: None }
}

fn hello_with_meta() -> Hello {
    let mut h = hello_no_meta();
    let mut map = HashMap::new();
    map.insert("invite".to_string(), rmpv::Value::String("CODE123".into()));
    h.meta = Some(map);
    h
}

// ---------------------------------------------------------------------------
// encode / decode roundtrips for every variant
// ---------------------------------------------------------------------------

fn roundtrip(msg: &LppMessage) -> LppMessage {
    let bytes = lpp::encode(msg).expect("encode");
    lpp::decode(&bytes).expect("decode")
}

#[test]
fn hello_roundtrip_no_meta() {
    let h = hello_no_meta();
    let msg = LppMessage::Hello(h.clone());
    assert_eq!(roundtrip(&msg), msg);
}

#[test]
fn hello_roundtrip_with_meta() {
    let h = hello_with_meta();
    let msg = LppMessage::Hello(h);
    let out = roundtrip(&msg);
    if let LppMessage::Hello(decoded) = out {
        let meta = decoded.meta.unwrap();
        assert!(meta.contains_key("invite"));
    } else {
        panic!("expected Hello");
    }
}

#[test]
fn hello_ack_roundtrip() {
    let key = SecretKey::generate();
    let eid = key.endpoint_id().to_base32();
    let ecdh = vec![1u8; 32];
    let sig = key.sign(&ecdh).to_vec();
    let msg = LppMessage::HelloAck(HelloAck { ver: LPP_VERSION, eid, ecdh, sig });
    assert_eq!(roundtrip(&msg), msg);
}

#[test]
fn addr_offer_roundtrip() {
    let msg = LppMessage::AddrOffer(AddrOffer {
        addrs: vec!["1.2.3.4:1234".into(), "[::1]:5678".into()],
    });
    assert_eq!(roundtrip(&msg), msg);
}

#[test]
fn addr_offer_empty_addrs() {
    let msg = LppMessage::AddrOffer(AddrOffer { addrs: vec![] });
    assert_eq!(roundtrip(&msg), msg);
}

#[test]
fn probe_success_roundtrip() {
    let msg = LppMessage::ProbeSuccess(ProbeSuccess { addr: "10.0.0.1:9999".into() });
    assert_eq!(roundtrip(&msg), msg);
}

#[test]
fn direct_upgrade_roundtrip() {
    assert_eq!(roundtrip(&LppMessage::DirectUpgrade), LppMessage::DirectUpgrade);
}

#[test]
fn direct_ack_roundtrip() {
    assert_eq!(roundtrip(&LppMessage::DirectAck), LppMessage::DirectAck);
}

#[test]
fn ping_roundtrip() {
    let msg = LppMessage::Ping(Ping { seq: 42 });
    assert_eq!(roundtrip(&msg), msg);
}

#[test]
fn pong_roundtrip() {
    let msg = LppMessage::Pong(Pong { seq: 42 });
    assert_eq!(roundtrip(&msg), msg);
}

#[test]
fn close_roundtrip() {
    let msg = LppMessage::Close(Close { reason: "shutdown".into() });
    assert_eq!(roundtrip(&msg), msg);
}

// ---------------------------------------------------------------------------
// Close constructors
// ---------------------------------------------------------------------------

#[test]
fn close_shutdown_constructor() {
    let c = Close::shutdown();
    assert_eq!(c.reason, Close::SHUTDOWN);
}

#[test]
fn close_unsupported_message_constructor() {
    let c = Close::unsupported_message();
    assert_eq!(c.reason, Close::UNSUPPORTED_MSG);
}

#[test]
fn close_auth_failed_constructor() {
    let c = Close::auth_failed();
    assert_eq!(c.reason, Close::AUTH_FAILED);
}

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

#[test]
fn decode_unknown_type_tag() {
    // Manually encode a map with "t" = "ZZ"
    let fake: HashMap<&str, &str> = [("t", "ZZ")].into_iter().collect();
    let bytes = rmp_serde::to_vec_named(&fake).unwrap();
    let err = lpp::decode(&bytes).unwrap_err();
    assert!(matches!(err, crate::LerpError::UnknownMessageType(_)));
}

#[test]
fn decode_empty_bytes() {
    assert!(lpp::decode(&[]).is_err());
}

#[test]
fn decode_not_a_map() {
    // Encode a plain string, not a map
    let bytes = rmp_serde::to_vec(&"hello").unwrap();
    assert!(lpp::decode(&bytes).is_err());
}

#[test]
fn decode_map_missing_t_field() {
    let map: HashMap<&str, u8> = [("ver", 0u8)].into_iter().collect();
    let bytes = rmp_serde::to_vec_named(&map).unwrap();
    assert!(lpp::decode(&bytes).is_err());
}

// ---------------------------------------------------------------------------
// Seq numbers preserved
// ---------------------------------------------------------------------------

#[test]
fn ping_seq_preserved() {
    let msg = LppMessage::Ping(Ping { seq: u64::MAX });
    if let LppMessage::Ping(p) = roundtrip(&msg) {
        assert_eq!(p.seq, u64::MAX);
    } else {
        panic!("expected Ping");
    }
}

#[test]
fn pong_seq_preserved() {
    let msg = LppMessage::Pong(Pong { seq: 0 });
    if let LppMessage::Pong(p) = roundtrip(&msg) {
        assert_eq!(p.seq, 0);
    } else {
        panic!("expected Pong");
    }
}
