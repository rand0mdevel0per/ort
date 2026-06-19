//! In-memory (sans-IO) handshake tests for both 0-RTT and 1-RTT, plus the
//! replay/window/source-IP rejection paths.

use ort_core::handshake::{
    client_one_rtt_finish, client_one_rtt_hello, client_zero_rtt, server_on_client_data,
    server_on_first, ClientConfig, ClientEstablished, ServerConfig, ServerEstablished, ServerStep,
};
use ort_core::pool::Direction;
use ort_core::record::RecordLayer;
use ort_core::replay::StrikeCache;
use ort_core::suite::v1::V1;
use ort_core::suite::CipherSuite;
use ort_core::time::FixedClock;
use ort_proto::Frame;

const IP: [u8; 16] = [10, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// Extract the error from a server step result (ServerStep isn't `Debug`).
fn step_err(r: ort_core::Result<ServerStep<V1>>) -> ort_core::Error {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

fn client_cfg() -> ClientConfig<V1> {
    let sig_secret = V1::sig_generate();
    let client_pk = V1::sig_public(&sig_secret);
    ClientConfig {
        sig_secret,
        client_pk,
    }
}

fn server_cfg() -> ServerConfig<V1> {
    let kem_secret = V1::kem_generate();
    let server_pk = V1::kem_public(&kem_secret);
    ServerConfig {
        kem_secret,
        server_pk,
        certificate: vec![],
        window_ms: 2000,
        skew_ms: 250,
    }
}

/// Exchange application data both ways to confirm the two record layers agree.
fn exchange(client: &mut RecordLayer<V1>, server: &mut RecordLayer<V1>) {
    // client -> server
    let up = client.seal(Direction::ClientToServer, b"ping from client");
    assert_eq!(server.open(Direction::ClientToServer, &up).unwrap(), b"ping from client");
    // server -> client
    let down = server.seal(Direction::ServerToClient, b"pong from server");
    assert_eq!(client.open(Direction::ServerToClient, &down).unwrap(), b"pong from server");
    // a second round to confirm counters advance in lock-step
    let up2 = client.seal(Direction::ClientToServer, b"second");
    assert_eq!(server.open(Direction::ClientToServer, &up2).unwrap(), b"second");
}

#[test]
fn zero_rtt_end_to_end() {
    let ccfg = client_cfg();
    let scfg = server_cfg();
    let clock = FixedClock::new(1_000_000);
    let mut strike = StrikeCache::new(scfg.window_ms);

    let (frame, mut client_est): (Frame, ClientEstablished<V1>) =
        client_zero_rtt(&ccfg, &scfg.server_pk, IP, &clock, b"early hello").unwrap();

    let step = server_on_first(&scfg, &frame, IP, &clock, &mut strike).unwrap();
    let (ack, mut server_est) = match step {
        ServerStep::ZeroRtt { ack, established } => (ack, established),
        _ => panic!("expected 0-RTT"),
    };
    assert_eq!(server_est.early_data, b"early hello");

    // client validates the ServerAck key confirmation
    match ack {
        Frame::ServerAck { ek_hash } => assert_eq!(ek_hash, client_est.expected_ek_hash.to_vec()),
        _ => panic!("expected ack"),
    }

    exchange(&mut client_est.record, &mut server_est.record);
}

#[test]
fn one_rtt_end_to_end() {
    let ccfg = client_cfg();
    let scfg = server_cfg();
    let clock = FixedClock::new(1_000_000);
    let mut strike = StrikeCache::new(scfg.window_ms);

    // step 1: bare hello
    let hello = client_one_rtt_hello(&ccfg);
    let step = server_on_first(&scfg, &hello, IP, &clock, &mut strike).unwrap();
    let server_pk = match step {
        ServerStep::OneRtt { hello: Frame::ServerHello { server_pk, .. } } => server_pk,
        _ => panic!("expected 1-RTT ServerHello"),
    };

    // step 2: client sends data flight
    let (frame, mut client_est) =
        client_one_rtt_finish(&ccfg, &server_pk, IP, &clock, b"first payload").unwrap();
    let mut server_est: ServerEstablished<V1> =
        server_on_client_data(&scfg, &frame, IP, &clock, &mut strike).unwrap();
    assert_eq!(server_est.early_data, b"first payload");

    exchange(&mut client_est.record, &mut server_est.record);
}

#[test]
fn zero_rtt_empty_early_data() {
    let ccfg = client_cfg();
    let scfg = server_cfg();
    let clock = FixedClock::new(1_000_000);
    let mut strike = StrikeCache::new(scfg.window_ms);

    let (frame, _est) = client_zero_rtt(&ccfg, &scfg.server_pk, IP, &clock, b"").unwrap();
    let step = server_on_first(&scfg, &frame, IP, &clock, &mut strike).unwrap();
    if let ServerStep::ZeroRtt { established, .. } = step {
        assert!(established.early_data.is_empty());
    } else {
        panic!("expected 0-RTT");
    }
}

#[test]
fn replay_within_window_is_rejected() {
    let ccfg = client_cfg();
    let scfg = server_cfg();
    let clock = FixedClock::new(1_000_000);
    let mut strike = StrikeCache::new(scfg.window_ms);

    let (frame, _est) = client_zero_rtt(&ccfg, &scfg.server_pk, IP, &clock, b"data").unwrap();
    server_on_first(&scfg, &frame, IP, &clock, &mut strike).expect("first accepted");
    let err = step_err(server_on_first(&scfg, &frame, IP, &clock, &mut strike));
    assert!(matches!(err, ort_core::Error::Replayed), "got {err:?}");
}

#[test]
fn stale_timestamp_is_rejected() {
    let ccfg = client_cfg();
    let scfg = server_cfg();
    let clock = FixedClock::new(1_000_000);
    let mut strike = StrikeCache::new(scfg.window_ms);

    let (frame, _est) = client_zero_rtt(&ccfg, &scfg.server_pk, IP, &clock, b"data").unwrap();
    // advance the server clock well past the 2s window
    clock.advance(5_000);
    let err = step_err(server_on_first(&scfg, &frame, IP, &clock, &mut strike));
    assert!(matches!(err, ort_core::Error::StaleTimestamp), "got {err:?}");
}

#[test]
fn source_ip_mismatch_is_rejected() {
    let ccfg = client_cfg();
    let scfg = server_cfg();
    let clock = FixedClock::new(1_000_000);
    let mut strike = StrikeCache::new(scfg.window_ms);

    let (frame, _est) = client_zero_rtt(&ccfg, &scfg.server_pk, IP, &clock, b"data").unwrap();
    let other_ip = [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let err = step_err(server_on_first(&scfg, &frame, other_ip, &clock, &mut strike));
    assert!(matches!(err, ort_core::Error::SourceIpMismatch), "got {err:?}");
}

#[test]
fn tampered_early_data_fails_signature() {
    let ccfg = client_cfg();
    let scfg = server_cfg();
    let clock = FixedClock::new(1_000_000);
    let mut strike = StrikeCache::new(scfg.window_ms);

    let (frame, _est) = client_zero_rtt(&ccfg, &scfg.server_pk, IP, &clock, b"data").unwrap();
    // tamper the early data inside the frame
    let tampered = match frame {
        Frame::ClientHelloZeroRtt {
            suite_id,
            client_pk,
            mut payload,
        } => {
            payload.enc_data[0] ^= 0xFF;
            Frame::ClientHelloZeroRtt {
                suite_id,
                client_pk,
                payload,
            }
        }
        _ => unreachable!(),
    };
    let err = step_err(server_on_first(&scfg, &tampered, IP, &clock, &mut strike));
    assert!(matches!(err, ort_core::Error::BadSignature), "got {err:?}");
}

#[test]
fn wrong_server_pk_breaks_decapsulation() {
    // A client that encapsulates against the wrong server key yields a shared
    // secret the server cannot reproduce -> early-data AEAD open fails.
    let ccfg = client_cfg();
    let scfg = server_cfg();
    let other = server_cfg(); // different KEM keypair
    let clock = FixedClock::new(1_000_000);
    let mut strike = StrikeCache::new(scfg.window_ms);

    let (frame, _est) = client_zero_rtt(&ccfg, &other.server_pk, IP, &clock, b"data").unwrap();
    let err = step_err(server_on_first(&scfg, &frame, IP, &clock, &mut strike));
    assert!(matches!(err, ort_core::Error::AeadFailure), "got {err:?}");
}
