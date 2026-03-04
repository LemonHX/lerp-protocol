use crate::error::LerpError;

// Each variant's Display output should be non-empty and contain a useful hint.

#[test]
fn invalid_encoding_display() {
    let e = LerpError::InvalidEncoding("bad base32".into());
    assert!(e.to_string().contains("bad base32"));
}

#[test]
fn invalid_signature_display() {
    let e = LerpError::InvalidSignature;
    assert!(!e.to_string().is_empty());
}

#[test]
fn invalid_ticket_display() {
    let e = LerpError::InvalidTicket("corrupt".into());
    assert!(e.to_string().contains("corrupt"));
}

#[test]
fn invalid_endpoint_id_display() {
    let e = LerpError::InvalidEndpointId("short".into());
    assert!(e.to_string().contains("short"));
}

#[test]
fn serialization_display() {
    let e = LerpError::Serialization("unexpected eof".into());
    assert!(e.to_string().contains("unexpected eof"));
}

#[test]
fn unknown_message_type_display() {
    let e = LerpError::UnknownMessageType("XX".into());
    assert!(e.to_string().contains("XX"));
}

#[test]
fn version_incompatible_display() {
    let e = LerpError::VersionIncompatible { remote: 5, local_max: 0 };
    let s = e.to_string();
    assert!(s.contains('5') && s.contains('0'));
}

#[test]
fn missing_field_display() {
    let e = LerpError::MissingField("lerp_ver".into());
    assert!(e.to_string().contains("lerp_ver"));
}
