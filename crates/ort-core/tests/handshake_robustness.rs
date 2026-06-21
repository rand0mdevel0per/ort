//! Handshake robustness: invalid state transitions, malformed payloads,
//! boundary conditions. All should fail gracefully without panics.

use ort_core::handshake::{
    client_offer_zero_rtt, client_one_rtt_finish, client_one_rtt_hello, server_on_client_data,
    server_on_first, ClientConfig, ServerConfig, SuiteKey,
};
use ort_core::replay::StrikeCache;
use ort_core::suite::agile::{ServerKemKey, SigIdentity};
use ort_core::suite::SuiteId;
use ort_core::time::FixedClock;
use ort_core::Error;
use ort_proto::Frame;

const IP: [u8; 16] = [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

fn client_cfg() -> ClientConfig {
    ClientConfig::new(SigIdentity::generate(SuiteId::MlKem768MlDsa65))
}

fn server_cfg() -> ServerConfig {
    ServerConfig {
        suites: vec![SuiteKey {
            key: ServerKemKey::generate(SuiteId::MlKem768MlDsa65),
            certificate: vec![],
        }],
        window_ms: 2000,
        skew_ms: 1000,
    }
}

#[test]
fn server_on_first_rejects_data_record() {
    let scfg = server_cfg();
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    // DataRecord is not valid as first frame
    let frame = Frame::DataRecord {
        from_server: false,
        ciphertext: vec![0xAB; 100],
    };
    assert!(matches!(
        server_on_first(&scfg, &frame, IP, &clock, &guard),
        Err(Error::UnexpectedMessage(_))
    ));
}

#[test]
fn server_on_first_rejects_server_ack() {
    let scfg = server_cfg();
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    // ServerAck is a server-to-client frame, not valid as first
    let frame = Frame::ServerAck {
        accepted_suite: 0x0001,
        ek_hash: [0u8; 64],
    };
    assert!(matches!(
        server_on_first(&scfg, &frame, IP, &clock, &guard),
        Err(Error::UnexpectedMessage(_))
    ));
}

#[test]
fn server_on_client_data_rejects_client_hello() {
    let scfg = server_cfg();
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    // ClientHelloOneRtt is not valid for server_on_client_data
    let ccfg = client_cfg();
    let hello = client_one_rtt_hello(&ccfg, &[SuiteId::MlKem768MlDsa65]);
    assert!(matches!(
        server_on_client_data(&scfg, &hello, IP, &clock, &guard, SuiteId::MlKem768MlDsa65),
        Err(Error::UnexpectedMessage(_))
    ));
}

#[test]
fn source_ip_mismatch_triggers_half_rtt() {
    let ccfg = client_cfg();
    let scfg = server_cfg();
    let spk = scfg.suites[0].key.public();
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    let (frame, _est) = client_offer_zero_rtt(
        &ccfg,
        SuiteId::MlKem768MlDsa65,
        &spk,
        IP,
        &clock,
        b"data",
    )
    .unwrap();

    // Send with different IP -> triggers Half-RTT fallback
    let other_ip = [10, 0, 0, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(matches!(
        server_on_first(&scfg, &frame, other_ip, &clock, &guard),
        Ok(ort_core::handshake::ServerStep::HalfRtt { .. })
    ));
}

#[test]
fn tampered_signature_rejected() {
    let ccfg = client_cfg();
    let scfg = server_cfg();
    let spk = scfg.suites[0].key.public();
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    let (frame, _est) = client_offer_zero_rtt(
        &ccfg,
        SuiteId::MlKem768MlDsa65,
        &spk,
        IP,
        &clock,
        b"data",
    )
    .unwrap();

    // Tamper with the signature
    let tampered = match frame {
        Frame::ClientHelloZeroRtt {
            client_pk,
            client_kem_pk,
            sig_alg,
            mut payload,
        } => {
            if !payload.client_sig.is_empty() {
                payload.client_sig[0] ^= 0xFF;
            }
            Frame::ClientHelloZeroRtt {
                client_pk,
                client_kem_pk,
                sig_alg,
                payload,
            }
        }
        _ => panic!("expected ClientHelloZeroRtt"),
    };

    // BadSignature MUST be rejected (auth bypass risk)
    assert!(matches!(
        server_on_first(&scfg, &tampered, IP, &clock, &guard),
        Err(Error::BadSignature)
    ));
}

#[test]
fn empty_client_pk_handled() {
    let scfg = server_cfg();
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    // ClientHelloZeroRtt with empty client_pk
    let frame = Frame::ClientHelloZeroRtt {
        client_pk: vec![],
        client_kem_pk: vec![0xAB; 1184],
        sig_alg: 0x0001,
        payload: ort_proto::KemPayload {
            offers: vec![ort_proto::SuiteOffer {
                suite_id: 0x0001,
                ciphertext: vec![0xCD; 1088],
                nonce: [0x42; 32],
                enc_data: vec![0x99; 100],
            }],
            src_ip: IP,
            ts_millis: 1_000_000,
            client_sig: vec![0x11; 3309],
        },
    };

    // Should fail at signature verification (empty pk is invalid)
    let result = server_on_first(&scfg, &frame, IP, &clock, &guard);
    assert!(result.is_err());
}

#[test]
fn empty_offers_rejected() {
    let scfg = server_cfg();
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    let frame = Frame::ClientHelloZeroRtt {
        client_pk: vec![0xAB; 1952],
        client_kem_pk: vec![0xCD; 1184],
        sig_alg: 0x0001,
        payload: ort_proto::KemPayload {
            offers: vec![], // empty
            src_ip: IP,
            ts_millis: 1_000_000,
            client_sig: vec![0x11; 3309],
        },
    };

    // Should fail: either BadSignature (empty offers hash) or NoCommonSuite
    let result = server_on_first(&scfg, &frame, IP, &clock, &guard);
    assert!(result.is_err() || matches!(result, Ok(ort_core::handshake::ServerStep::Reject { .. })),
            "empty offers MUST be rejected");
}

#[test]
fn unsupported_suite_rejected() {
    let ccfg = client_cfg();
    let scfg = server_cfg();
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    // Client hello with suite that server doesn't support
    let hello = client_one_rtt_hello(&ccfg, &[SuiteId::X25519Ed25519]);

    // Server only supports ML-KEM, should reject
    let result = server_on_first(&scfg, &hello, IP, &clock, &guard);
    // Should return Reject step with NO_COMMON_SUITE
    match result {
        Ok(ort_core::handshake::ServerStep::Reject { .. }) => {},
        _ => panic!("expected Reject"),
    }
}

#[test]
fn far_future_timestamp_rejected() {
    let ccfg = client_cfg();
    let scfg = server_cfg();
    let spk = scfg.suites[0].key.public();
    let guard = StrikeCache::new(2000);

    // Client at time 1M, server at time 0 with 1s skew tolerance
    let client_clock = FixedClock::new(1_000_000);
    let server_clock = FixedClock::new(0);

    let (frame, _est) = client_offer_zero_rtt(
        &ccfg,
        SuiteId::MlKem768MlDsa65,
        &spk,
        IP,
        &client_clock,
        b"data",
    )
    .unwrap();

    // Timestamp is 1M ms in the future, well beyond 1s skew tolerance
    // Should trigger Half-RTT (StaleTimestamp), not full rejection
    let result = server_on_first(&scfg, &frame, IP, &server_clock, &guard);
    match result {
        Ok(ort_core::handshake::ServerStep::HalfRtt { .. }) => {}, // Half-RTT fallback
        Err(_) => {}, // or direct error, both acceptable
        _ => panic!("expected Half-RTT or error"),
    }
}

#[test]
fn malformed_ciphertext_rejected() {
    let ccfg = client_cfg();
    let scfg = server_cfg();
    let spk = scfg.suites[0].key.public();
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    let (frame, _est) = client_offer_zero_rtt(
        &ccfg,
        SuiteId::MlKem768MlDsa65,
        &spk,
        IP,
        &clock,
        b"data",
    )
    .unwrap();

    // Replace ciphertext with wrong-sized one
    let malformed = match frame {
        Frame::ClientHelloZeroRtt {
            client_pk,
            client_kem_pk,
            sig_alg,
            mut payload,
        } => {
            if !payload.offers.is_empty() {
                payload.offers[0].ciphertext = vec![0xFF; 10]; // wrong size
            }
            Frame::ClientHelloZeroRtt {
                client_pk,
                client_kem_pk,
                sig_alg,
                payload,
            }
        }
        _ => panic!("expected ClientHelloZeroRtt"),
    };

    // Malformed ciphertext: can trigger Half-RTT or get rejected
    let result = server_on_first(&scfg, &malformed, IP, &clock, &guard);
    // Should not panic; can be Half-RTT (sig valid) or Reject/Err (depending on when ct is checked)
    assert!(
        result.is_err()
        || matches!(result, Ok(ort_core::handshake::ServerStep::Reject { .. }))
        || matches!(result, Ok(ort_core::handshake::ServerStep::HalfRtt { .. })),
        "malformed ciphertext must be handled gracefully"
    );
}

#[test]
fn wrong_suite_in_client_data_rejected() {
    let ccfg = client_cfg();
    let scfg = server_cfg();
    let spk = scfg.suites[0].key.public();
    let clock = FixedClock::new(1_000_000);
    let guard = StrikeCache::new(2000);

    // Build ClientData for wrong suite
    let (frame, _est) = client_one_rtt_finish(
        &ccfg,
        SuiteId::MlKem768MlDsa65,
        &spk,
        IP,
        &clock,
        b"data",
    )
    .unwrap();

    // Server expects X25519 but client sent ML-KEM
    let result = server_on_client_data(
        &scfg,
        &frame,
        IP,
        &clock,
        &guard,
        SuiteId::X25519Ed25519,
    );
    // Should reject (no matching suite)
    assert!(result.is_err());
}
