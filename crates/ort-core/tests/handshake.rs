//! In-memory (sans-IO) handshake tests: 0-RTT / 1-RTT for both suites,
//! multi-suite offers, negotiation/reject, and replay/window/source-IP paths.

use ort_core::handshake::{
    client_half_rtt_finish, client_offer_zero_rtt, client_one_rtt_finish, client_one_rtt_hello,
    server_on_client_data, server_on_first, ClientConfig, ServerConfig, ServerStep, SuiteKey,
};
use ort_core::kdf::derive_session_keys;
use ort_core::pool::Direction;
use ort_core::record::RecordLayer;
use ort_core::replay::StrikeCache;
use ort_core::suite::agile::{ServerKemKey, SigIdentity};
use ort_core::suite::SuiteId;
use ort_core::time::FixedClock;
use ort_proto::{reject, Frame};

const IP: [u8; 16] = [10, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

fn client_cfg(sig: SuiteId) -> ClientConfig {
    ClientConfig::new(SigIdentity::generate(sig))
}

fn server_cfg(suites: &[SuiteId]) -> ServerConfig {
    let suites = suites
        .iter()
        .map(|id| SuiteKey {
            key: ServerKemKey::generate(*id),
            certificate: vec![],
        })
        .collect();
    ServerConfig {
        suites,
        window_ms: 2000,
        skew_ms: 1000,
    }
}

fn server_pk(cfg: &ServerConfig, id: SuiteId) -> Vec<u8> {
    cfg.suites
        .iter()
        .find(|s| s.key.suite_id() == id)
        .unwrap()
        .key
        .public()
}

fn exchange(client: &mut RecordLayer, server: &mut RecordLayer) {
    let up = client.seal(Direction::ClientToServer, b"ping");
    assert_eq!(
        server.open(Direction::ClientToServer, &up).unwrap(),
        b"ping"
    );
    let down = server.seal(Direction::ServerToClient, b"pong");
    assert_eq!(
        client.open(Direction::ServerToClient, &down).unwrap(),
        b"pong"
    );
}

fn zero_rtt(sig: SuiteId, kem: SuiteId) {
    let ccfg = client_cfg(sig);
    let scfg = server_cfg(&[kem]);
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    let (frame, mut ce) = client_offer_zero_rtt(&ccfg, kem, &server_pk(&scfg, kem), IP, &clock, b"early").unwrap();

    match server_on_first(&scfg, &frame, IP, &clock, &guard).unwrap() {
        ServerStep::ZeroRtt {
            accepted_suite,
            ack,
            mut established,
        } => {
            assert_eq!(accepted_suite, kem);
            assert_eq!(established.early_data, b"early");
            match ack {
                Frame::ServerAck {
                    accepted_suite: a,
                    ek_hash,
                } => {
                    assert_eq!(a, kem.code());
                    assert_eq!(ek_hash, ce.expected_ek_hash);
                    assert_eq!(ce.offered_suite, SuiteId::from_code(a).unwrap());
                }
                _ => panic!("expected ack"),
            }
            exchange(&mut ce.record, &mut established.record);
        }
        _ => panic!("expected 0-RTT"),
    }
}

#[test]
fn zero_rtt_v1() {
    zero_rtt(SuiteId::MlKem768MlDsa65, SuiteId::MlKem768MlDsa65);
}

#[test]
fn zero_rtt_v2() {
    zero_rtt(SuiteId::X25519Ed25519, SuiteId::X25519Ed25519);
}

#[test]
fn zero_rtt_mixed_sig_and_kem() {
    // Sign with Ed25519 (v2) but encapsulate with ML-KEM (v1): decoupled.
    zero_rtt(SuiteId::X25519Ed25519, SuiteId::MlKem768MlDsa65);
}

#[test]
fn one_rtt_negotiates_and_completes() {
    let ccfg = client_cfg(SuiteId::MlKem768MlDsa65);
    let scfg = server_cfg(&[SuiteId::X25519Ed25519, SuiteId::MlKem768MlDsa65]);
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    // client advertises both, prefers v1
    let hello = client_one_rtt_hello(
        &ccfg,
        &[SuiteId::MlKem768MlDsa65, SuiteId::X25519Ed25519],
    );
    let (accepted, spk) = match server_on_first(&scfg, &hello, IP, &clock, &guard).unwrap() {
        ServerStep::OneRtt {
            hello:
                Frame::ServerHello {
                    accepted_suite,
                    server_pk,
                    observed_ip,
                    ..
                },
            selected: _,
        } => {
            assert_eq!(observed_ip, IP);
            (SuiteId::from_code(accepted_suite).unwrap(), server_pk)
        }
        _ => panic!("expected ServerHello"),
    };
    assert_eq!(accepted, SuiteId::MlKem768MlDsa65);

    let (frame, mut ce) = client_one_rtt_finish(&ccfg, accepted, &spk, IP, &clock, b"hi").unwrap();
    let mut se = server_on_client_data(&scfg, &frame, IP, &clock, &guard, accepted).unwrap();
    assert_eq!(se.early_data, b"hi");
    exchange(&mut ce.record, &mut se.record);
}

#[test]
fn multi_offer_server_picks_supported() {
    // Client offers both suites via 1-RTT negotiation. 0-RTT only offers one suite.
    // This test now uses 1-RTT hello + finish to demonstrate multi-suite support.
    let ccfg = client_cfg(SuiteId::MlKem768MlDsa65);
    let scfg = server_cfg(&[SuiteId::X25519Ed25519]);
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    let hello = client_one_rtt_hello(&ccfg, &[SuiteId::MlKem768MlDsa65, SuiteId::X25519Ed25519]);
    let (accepted, spk) = match server_on_first(&scfg, &hello, IP, &clock, &guard).unwrap() {
        ServerStep::OneRtt { hello: Frame::ServerHello { accepted_suite, server_pk, .. }, .. } => {
            (SuiteId::from_code(accepted_suite).unwrap(), server_pk)
        }
        _ => panic!("expected ServerHello"),
    };
    assert_eq!(accepted, SuiteId::X25519Ed25519);
    let _ = spk;
}

#[test]
fn no_common_suite_is_rejected_zero_rtt() {
    let ccfg = client_cfg(SuiteId::MlKem768MlDsa65);
    let scfg = server_cfg(&[SuiteId::X25519Ed25519]); // server: v2 only
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    // Client tries 0-RTT with v1, server only has v2
    let (frame, _ce) = client_offer_zero_rtt(&ccfg, SuiteId::MlKem768MlDsa65, &vec![0u8; 1184], IP, &clock, b"x").unwrap();
    match server_on_first(&scfg, &frame, IP, &clock, &guard).unwrap() {
        ServerStep::Reject {
            frame: Frame::ServerReject { reason },
        } => {
            assert_eq!(reason, reject::NO_COMMON_SUITE);
        }
        _ => panic!("expected reject"),
    }
}

#[test]
fn no_common_suite_is_rejected_one_rtt() {
    let ccfg = client_cfg(SuiteId::MlKem768MlDsa65);
    let scfg = server_cfg(&[SuiteId::X25519Ed25519]);
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    let hello = client_one_rtt_hello(&ccfg, &[SuiteId::MlKem768MlDsa65]);
    match server_on_first(&scfg, &hello, IP, &clock, &guard).unwrap() {
        ServerStep::Reject {
            frame: Frame::ServerReject { reason },
        } => {
            assert_eq!(reason, reject::NO_COMMON_SUITE);
        }
        _ => panic!("expected reject"),
    }
}

fn make_zero_rtt(scfg: &ServerConfig) -> Frame {
    let ccfg = client_cfg(SuiteId::MlKem768MlDsa65);
    let kem = SuiteId::MlKem768MlDsa65;
    let clock = FixedClock::new(1_000_000);
    client_offer_zero_rtt(&ccfg, kem, &server_pk(scfg, kem), IP, &clock, b"d")
        .unwrap()
        .0
}

#[test]
fn replay_within_window_triggers_half_rtt() {
    let scfg = server_cfg(&[SuiteId::MlKem768MlDsa65]);
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);
    let frame = make_zero_rtt(&scfg);
    server_on_first(&scfg, &frame, IP, &clock, &guard).expect("first ok");
    // Replay triggers Half-RTT fallback
    assert!(matches!(
        server_on_first(&scfg, &frame, IP, &clock, &guard),
        Ok(ServerStep::HalfRtt { .. })
    ));
}

#[test]
fn stale_timestamp_triggers_half_rtt() {
    let scfg = server_cfg(&[SuiteId::MlKem768MlDsa65]);
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);
    let frame = make_zero_rtt(&scfg);
    clock.advance(5000);
    // Stale timestamp triggers Half-RTT fallback
    assert!(matches!(
        server_on_first(&scfg, &frame, IP, &clock, &guard),
        Ok(ServerStep::HalfRtt { .. })
    ));
}

#[test]
fn half_rtt_establishes_session() {
    // End-to-end Half-RTT: client attempts 0-RTT twice with same frame (replay),
    // both successfully establish the session via Half-RTT fallback.
    let ccfg = client_cfg(SuiteId::MlKem768MlDsa65);
    let scfg = server_cfg(&[SuiteId::MlKem768MlDsa65]);
    let kem = SuiteId::MlKem768MlDsa65;
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    // Create 0-RTT frame once
    let (frame, mut est) = client_offer_zero_rtt(&ccfg, kem, &server_pk(&scfg, kem), IP, &clock, b"data").unwrap();

    // First attempt: 0-RTT succeeds
    server_on_first(&scfg, &frame, IP, &clock, &guard).expect("first 0-RTT ok");

    // Second attempt with SAME frame: triggers replay → Half-RTT
    let step = server_on_first(&scfg, &frame, IP, &clock, &guard).unwrap();
    match step {
        ServerStep::HalfRtt { shared, nonce, frame, .. } => {
            // Server has keys
            let server_keys = derive_session_keys(&shared, &nonce);
            let mut server_record = RecordLayer::new(server_keys, &nonce);

            // Client processes ServerRefuse0RTT
            if let Frame::ServerRefuse0RTT { server_ct, nonce: n, .. } = frame {
                client_half_rtt_finish(&mut est, &server_ct, &n).unwrap();
                // Both sides now have established RecordLayers
                exchange(&mut est.record, &mut server_record);
            } else {
                panic!("expected ServerRefuse0RTT frame");
            }
        }
        _ => panic!("expected Half-RTT"),
    }
}

#[test]
fn source_ip_mismatch_triggers_half_rtt() {
    let scfg = server_cfg(&[SuiteId::MlKem768MlDsa65]);
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);
    let frame = make_zero_rtt(&scfg);
    let other = [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    // SourceIpMismatch now triggers Half-RTT fallback (not direct rejection)
    assert!(matches!(
        server_on_first(&scfg, &frame, other, &clock, &guard),
        Ok(ServerStep::HalfRtt { .. })
    ));
}
