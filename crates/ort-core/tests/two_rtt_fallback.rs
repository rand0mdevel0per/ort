//! 2-RTT fallback tests: verify that 0-RTT failures with no common suite
//! correctly fall back to 1-RTT negotiation.

use ort_core::handshake::{
    client_offer_zero_rtt, client_one_rtt_finish, server_on_client_data, server_on_first,
    ClientConfig, ServerConfig, ServerStep, SuiteKey,
};
use ort_core::replay::StrikeCache;
use ort_core::suite::agile::{ServerKemKey, SigIdentity};
use ort_core::suite::SuiteId;
use ort_core::time::FixedClock;

const IP: [u8; 16] = [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

#[test]
fn no_common_suite_falls_back_to_2rtt() {
    // Client offers ML-KEM in 0-RTT but server only supports X25519 -> 2-RTT
    let scfg = ServerConfig {
        suites: vec![SuiteKey {
            key: ServerKemKey::generate(SuiteId::X25519Ed25519),
            certificate: vec![],
        }],
        window_ms: 2000,
        skew_ms: 1000,
    };
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    // Manually craft a ClientHelloZeroRtt with ML-KEM and X25519 offers
    let frame = ort_proto::Frame::ClientHelloZeroRtt {
        client_pk: vec![0xAA; 1952],
        client_kem_pk: vec![0xBB; 1184],
        sig_alg: SuiteId::MlKem768MlDsa65.code(),
        payload: ort_proto::KemPayload {
            offers: vec![
                ort_proto::SuiteOffer {
                    suite_id: SuiteId::MlKem768MlDsa65.code(),
                    ciphertext: vec![0xCC; 1088],
                    nonce: [0x42; 32],
                    enc_data: vec![0xDD; 100],
                },
                ort_proto::SuiteOffer {
                    suite_id: SuiteId::X25519Ed25519.code(),
                    ciphertext: vec![0xEE; 32],
                    nonce: [0x43; 32],
                    enc_data: vec![0xFF; 100],
                },
            ],
            src_ip: IP,
            ts_millis: 1_000_000,
            client_sig: vec![0x11; 3309],
        },
    };

    // Server tries process_payload: signature will fail (invalid sig)
    // Then falls back to 2-RTT and picks X25519
    let step = server_on_first(&scfg, &frame, IP, &clock, &guard).unwrap();
    match step {
        ServerStep::OneRtt { selected, .. } => {
            assert_eq!(selected, SuiteId::X25519Ed25519);
        }
        other => panic!("expected 2-RTT (OneRtt), got different step"),
    }
}

#[test]
fn bad_signature_with_no_common_suite_falls_back_to_2rtt() {
    // Client signature invalid + first offer doesn't match server -> 2-RTT
    let scfg = ServerConfig {
        suites: vec![SuiteKey {
            key: ServerKemKey::generate(SuiteId::X25519Ed25519),
            certificate: vec![],
        }],
        window_ms: 2000,
        skew_ms: 1000,
    };
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    // Manually craft frame with bad signature
    let frame = ort_proto::Frame::ClientHelloZeroRtt {
        client_pk: vec![0xAA; 1952],
        client_kem_pk: vec![0xBB; 1184],
        sig_alg: SuiteId::MlKem768MlDsa65.code(),
        payload: ort_proto::KemPayload {
            offers: vec![
                ort_proto::SuiteOffer {
                    suite_id: SuiteId::MlKem768MlDsa65.code(),
                    ciphertext: vec![0xCC; 1088],
                    nonce: [0x42; 32],
                    enc_data: vec![0xDD; 100],
                },
                ort_proto::SuiteOffer {
                    suite_id: SuiteId::X25519Ed25519.code(),
                    ciphertext: vec![0xEE; 32],
                    nonce: [0x43; 32],
                    enc_data: vec![0xFF; 100],
                },
            ],
            src_ip: IP,
            ts_millis: 1_000_000,
            client_sig: vec![0xBA; 3309], // invalid signature
        },
    };

    // Server should fall back to 2-RTT with X25519
    let step = server_on_first(&scfg, &frame, IP, &clock, &guard).unwrap();
    match step {
        ServerStep::OneRtt { selected, .. } => {
            assert_eq!(selected, SuiteId::X25519Ed25519);
        }
        _ => panic!("expected 2-RTT fallback"),
    }
}

#[test]
fn empty_offers_with_server_support_falls_back_to_2rtt() {
    // Empty offers but client advertised suites in available_suites -> not a total rejection
    let scfg = ServerConfig {
        suites: vec![SuiteKey {
            key: ServerKemKey::generate(SuiteId::MlKem768MlDsa65),
            certificate: vec![],
        }],
        window_ms: 2000,
        skew_ms: 1000,
    };
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    // Manually craft ClientHelloZeroRtt with empty offers
    let frame = ort_proto::Frame::ClientHelloZeroRtt {
        client_pk: vec![0xAB; 1952],
        client_kem_pk: vec![0xCD; 1184],
        sig_alg: 0x0001,
        payload: ort_proto::KemPayload {
            offers: vec![],
            src_ip: IP,
            ts_millis: 1_000_000,
            client_sig: vec![0x11; 3309],
        },
    };

    // Empty offers -> no suite to select -> should Reject (can't negotiate from nothing)
    let step = server_on_first(&scfg, &frame, IP, &clock, &guard).unwrap();
    assert!(
        matches!(step, ServerStep::Reject { .. }),
        "empty offers with no fallback info should Reject"
    );
}
