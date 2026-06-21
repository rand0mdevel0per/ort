//! Protocol robustness tests: malformed frames, truncated data, boundary values.
//! All should fail gracefully with proper Error types, no panics.

use ort_proto::{Frame, ProtoError};

#[test]
fn decode_empty_buffer() {
    assert!(matches!(Frame::decode(&[]), Err(ProtoError::Truncated)));
}

#[test]
fn decode_invalid_tag() {
    // Tag 0xFF is not a valid frame type
    let buf = vec![0xFF, 0, 0, 0, 0];
    assert!(matches!(
        Frame::decode(&buf),
        Err(ProtoError::UnknownFrameType(_))
    ));
}

#[test]
fn decode_truncated_client_hello_one_rtt() {
    // ClientHelloOneRtt tag but incomplete payload
    let buf = vec![0x01, 0, 0, 0]; // missing client_pk length
    assert!(matches!(Frame::decode(&buf), Err(ProtoError::Truncated)));
}

#[test]
fn decode_oversized_client_pk() {
    // ClientHelloOneRtt with absurdly large client_pk length (exceeds MAX_FRAME)
    let mut buf = vec![0x01]; // ClientHelloOneRtt tag
    buf.extend_from_slice(&(u32::MAX).to_be_bytes()); // 4GB client_pk
    // Should fail with FrameTooLarge or Truncated
    let result = Frame::decode(&buf);
    assert!(result.is_err());
}

#[test]
fn decode_zero_length_vec_accepted() {
    // ServerHello with empty certificate should decode successfully
    let mut buf = vec![0x04]; // ServerHello tag
    buf.extend_from_slice(&0x0001u16.to_be_bytes()); // accepted_suite
    buf.extend_from_slice(&10u32.to_be_bytes()); // server_pk len
    buf.extend(&vec![0xAB; 10]); // server_pk
    buf.extend_from_slice(&0u32.to_be_bytes()); // server_pk_signature len = 0
    buf.extend_from_slice(&0u32.to_be_bytes()); // certificate len = 0
    buf.extend_from_slice(&[127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // observed_ip
    buf.extend_from_slice(&1000u64.to_be_bytes()); // server_ts
    let frame = Frame::decode(&buf).expect("empty certificate should be valid");
    match frame {
        Frame::ServerHello { certificate, .. } => assert!(certificate.is_empty()),
        _ => panic!("wrong frame type"),
    }
}

#[test]
fn decode_truncated_in_middle_of_vec() {
    // ServerHello claims 100 bytes certificate but only provides 10
    let mut buf = vec![0x04]; // ServerHello
    buf.extend_from_slice(&0x0001u16.to_be_bytes());
    buf.extend_from_slice(&10u32.to_be_bytes());
    buf.extend(&vec![0xAB; 10]);
    buf.extend_from_slice(&100u32.to_be_bytes()); // claims 100
    buf.extend(&vec![0xCD; 10]); // only provides 10
    assert!(matches!(Frame::decode(&buf), Err(ProtoError::Truncated)));
}

#[test]
fn decode_data_record_max_size() {
    // DataRecord with maximum plausible ciphertext (16MB)
    let max_ct_len = 16 * 1024 * 1024;
    let mut buf = vec![0x07]; // DataRecord tag
    buf.push(1); // from_server = true
    buf.extend_from_slice(&(max_ct_len as u32).to_be_bytes());
    buf.extend(vec![0xFF; max_ct_len]);
    let frame = Frame::decode(&buf).expect("16MB ciphertext should decode");
    match frame {
        Frame::DataRecord { ciphertext, .. } => assert_eq!(ciphertext.len(), max_ct_len),
        _ => panic!("wrong frame type"),
    }
}

#[test]
fn encode_decode_roundtrip_with_empty_vecs() {
    let frame = Frame::ClientHelloZeroRtt {
        client_pk: vec![],
        client_kem_pk: vec![],
        sig_alg: 0x0001,
        payload: ort_proto::KemPayload {
            offers: vec![],
            src_ip: [0; 16],
            ts_millis: 0,
            client_sig: vec![],
        },
    };
    let encoded = frame.encode();
    // Empty offers should be rejected at decode time
    let decoded = Frame::decode(&encoded);
    assert!(decoded.is_err(), "empty offers should be rejected by codec");
}

#[test]
fn decode_all_zero_bytes() {
    // All zeros: tag=0 (ClientHelloOneRtt) with zero lengths
    let buf = vec![0u8; 20];
    // Should fail gracefully, not panic
    let _ = Frame::decode(&buf);
}

#[test]
fn decode_random_bytes() {
    // Pure random bytes should not panic
    use rand::Rng;
    let mut rng = rand::thread_rng();
    for _ in 0..100 {
        let len: usize = rng.random::<u8>() as usize % 500 + 1;
        let buf: Vec<u8> = (0..len).map(|_| rng.random()).collect();
        let _ = Frame::decode(&buf); // should not panic
    }
}

#[test]
fn encode_decode_preserves_all_fields() {
    let frame = Frame::ServerHello {
        accepted_suite: 0x1234,
        server_pk: vec![0xAB; 1184],
        server_pk_signature: vec![0xEF; 64],
        certificate: vec![0xCD; 700],
        observed_ip: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        server_ts: 9876543210,
    };
    let encoded = frame.encode();
    let decoded = Frame::decode(&encoded).expect("roundtrip failed");
    match decoded {
        Frame::ServerHello {
            accepted_suite,
            server_pk,
            server_pk_signature,
            certificate,
            observed_ip,
            server_ts,
        } => {
            assert_eq!(accepted_suite, 0x1234);
            assert_eq!(server_pk.len(), 1184);
            assert_eq!(server_pk_signature.len(), 64);
            assert_eq!(certificate.len(), 700);
            assert_eq!(observed_ip[0], 10);
            assert_eq!(server_ts, 9876543210);
        }
        _ => panic!("wrong frame type"),
    }
}

#[test]
fn decode_close_frame() {
    let buf = vec![0x08]; // Close tag
    let frame = Frame::decode(&buf).expect("Close should decode from single byte");
    assert!(matches!(frame, Frame::Close));
}

#[test]
fn decode_server_reject() {
    let buf = vec![0x06, 42]; // ServerReject with reason=42
    let frame = Frame::decode(&buf).expect("ServerReject should decode");
    match frame {
        Frame::ServerReject { reason } => assert_eq!(reason, 42),
        _ => panic!("wrong frame type"),
    }
}
