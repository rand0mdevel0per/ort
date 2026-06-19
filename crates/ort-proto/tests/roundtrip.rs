//! Frame encode/decode round-trip and framing tests.

use ort_proto::{encode_framed, parse_len, Frame, KemPayload, ProtoError};

fn sample_payload() -> KemPayload {
    KemPayload {
        ciphertext: vec![1u8; 1088],
        src_ip: [2u8; 16],
        ts_millis: 0x0102030405060708,
        nonce: [3u8; 32],
        client_sig: vec![4u8; 3309],
        enc_data: vec![6u8; 500],
    }
}

fn roundtrip(f: &Frame) {
    let body = f.encode();
    let decoded = Frame::decode(&body).expect("decode");
    assert_eq!(*f, decoded);
}

#[test]
fn all_frame_variants_roundtrip() {
    roundtrip(&Frame::ClientHelloOneRtt {
        suite_id: 0x0001,
        client_pk: vec![9u8; 1952],
    });
    roundtrip(&Frame::ClientHelloZeroRtt {
        suite_id: 0x0001,
        client_pk: vec![9u8; 1952],
        payload: sample_payload(),
    });
    roundtrip(&Frame::ClientData {
        client_pk: vec![9u8; 1952],
        payload: sample_payload(),
    });
    roundtrip(&Frame::ServerHello {
        suite_id: 0x0001,
        server_pk: vec![7u8; 1184],
        certificate: vec![8u8; 700],
        server_ts: 42,
    });
    roundtrip(&Frame::ServerAck {
        ek_hash: vec![1u8; 64],
    });
    roundtrip(&Frame::DataRecord {
        dir: 1,
        ciphertext: vec![0xAB; 16384],
    });
    roundtrip(&Frame::Close);
}

#[test]
fn empty_certificate_roundtrips() {
    roundtrip(&Frame::ServerHello {
        suite_id: 0x0001,
        server_pk: vec![7u8; 1184],
        certificate: vec![],
        server_ts: 0,
    });
}

#[test]
fn truncated_is_rejected() {
    let body = Frame::ServerAck {
        ek_hash: vec![1u8; 64],
    }
    .encode();
    assert!(matches!(
        Frame::decode(&body[..body.len() - 5]),
        Err(ProtoError::Truncated)
    ));
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut body = Frame::Close.encode();
    body.push(0xFF);
    assert!(matches!(Frame::decode(&body), Err(ProtoError::TrailingBytes(1))));
}

#[test]
fn unknown_frame_type_is_rejected() {
    assert!(matches!(
        Frame::decode(&[0xEE]),
        Err(ProtoError::UnknownFrameType(0xEE))
    ));
}

#[test]
fn outer_framing_length() {
    let body = Frame::Close.encode();
    let framed = encode_framed(&body);
    let mut prefix = [0u8; 4];
    prefix.copy_from_slice(&framed[..4]);
    assert_eq!(parse_len(prefix).unwrap(), body.len());
    assert_eq!(&framed[4..], &body[..]);
}

#[test]
fn oversize_length_rejected() {
    let prefix = (ort_proto::MAX_FRAME as u32 + 1).to_be_bytes();
    assert!(matches!(parse_len(prefix), Err(ProtoError::FrameTooLarge(_))));
}
