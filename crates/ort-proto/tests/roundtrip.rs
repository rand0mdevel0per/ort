//! Frame encode/decode round-trip and framing tests.

use ort_proto::{encode_framed, parse_len, Frame, KemPayload, ProtoError, SuiteOffer};

fn sample_payload(n_offers: usize) -> KemPayload {
    let offers = (0..n_offers)
        .map(|i| SuiteOffer {
            suite_id: 0x0001 + i as u16,
            ciphertext: vec![i as u8; 1088],
            nonce: [3u8; 32],
            enc_data: vec![6u8; 500],
        })
        .collect();
    KemPayload {
        offers,
        src_ip: [2u8; 16],
        ts_millis: 0x0102030405060708,
        client_sig: vec![4u8; 3309],
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
        client_pk: vec![9u8; 1952],
        sig_alg: 0x0001,
        available_suites: vec![0x0001, 0x0002],
    });
    roundtrip(&Frame::ClientHelloZeroRtt {
        client_pk: vec![9u8; 1952],
        client_kem_pk: vec![7u8; 1184],
        sig_alg: 0x0001,
        payload: sample_payload(2),
    });
    roundtrip(&Frame::ClientData {
        client_pk: vec![9u8; 1952],
        sig_alg: 0x0002,
        payload: sample_payload(1),
    });
    roundtrip(&Frame::ServerHello {
        accepted_suite: 0x0001,
        server_pk: vec![7u8; 1184],
        server_pk_signature: vec![6u8; 64],
        certificate: vec![8u8; 700],
        observed_ip: [9u8; 16],
        server_ts: 42,
    });
    roundtrip(&Frame::ServerAck {
        accepted_suite: 0x0002,
        ek_hash: [1u8; 64],
    });
    roundtrip(&Frame::ServerReject { reason: 1 });
    roundtrip(&Frame::ServerRefuse0RTT {
        accepted_suite: 0x0001,
        server_ct: vec![0xAB; 1088],
        nonce: [0x42; 32],
        server_signature: vec![0xCD; 64],
    });
    roundtrip(&Frame::DataRecord {
        from_server: true,
        ciphertext: vec![0xAB; 16384],
    });
    roundtrip(&Frame::DataRecord {
        from_server: false,
        ciphertext: vec![0x12; 3],
    });
    roundtrip(&Frame::Close);
}

#[test]
fn empty_certificate_roundtrips() {
    roundtrip(&Frame::ServerHello {
        accepted_suite: 0x0001,
        server_pk: vec![7u8; 1184],
        server_pk_signature: vec![],
        certificate: vec![],
        observed_ip: [0u8; 16],
        server_ts: 0,
    });
}

#[test]
fn invalid_data_record_dir_rejected() {
    // hand-craft a DataRecord with dir=16
    let mut body = vec![0x07u8, 16];
    body.extend_from_slice(&0u32.to_be_bytes());
    assert!(matches!(
        Frame::decode(&body),
        Err(ProtoError::InvalidValue(_))
    ));
}

#[test]
fn zero_offers_rejected() {
    // ClientHelloZeroRtt with zero offers must fail.
    let mut body = vec![0x02u8]; // ClientHelloZeroRtt tag
    body.extend_from_slice(&1u32.to_be_bytes()); // client_pk len=1
    body.push(0xAA);
    body.extend_from_slice(&1u32.to_be_bytes()); // client_kem_pk len=1
    body.push(0xBB);
    body.extend_from_slice(&0x0001u16.to_be_bytes()); // sig_alg
    body.extend_from_slice(&0u16.to_be_bytes()); // 0 offers
    assert!(matches!(Frame::decode(&body), Err(ProtoError::Empty(_))));
}

#[test]
fn truncated_is_rejected() {
    let body = Frame::ServerAck {
        accepted_suite: 1,
        ek_hash: [1u8; 64],
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
    assert!(matches!(
        Frame::decode(&body),
        Err(ProtoError::TrailingBytes(1))
    ));
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
    let framed = encode_framed(&body).unwrap();
    let mut prefix = [0u8; 4];
    prefix.copy_from_slice(&framed[..4]);
    assert_eq!(parse_len(prefix).unwrap(), body.len());
    assert_eq!(&framed[4..], &body[..]);
}

#[test]
fn oversize_length_rejected() {
    let prefix = (ort_proto::MAX_FRAME as u32 + 1).to_be_bytes();
    assert!(matches!(
        parse_len(prefix),
        Err(ProtoError::FrameTooLarge(_))
    ));
}
