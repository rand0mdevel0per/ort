//! Handshake benchmarks: 0-RTT, Half-RTT, 1-RTT, and 2-RTT modes.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ort_core::handshake::{
    client_half_rtt_finish, client_offer_zero_rtt, client_one_rtt_finish, client_one_rtt_hello,
    server_on_client_data, server_on_first, ClientConfig, ServerConfig, ServerStep, SuiteKey,
};
use ort_core::replay::StrikeCache;
use ort_core::suite::agile::{ServerKemKey, SigIdentity};
use ort_core::suite::SuiteId;
use ort_core::time::FixedClock;
use ort_proto::Frame;

const IP: [u8; 16] = [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

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

fn bench_zero_rtt(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");

    for suite in [SuiteId::MlKem768MlDsa65, SuiteId::X25519Ed25519] {
        let suite_name = match suite {
            SuiteId::MlKem768MlDsa65 => "PQC",
            SuiteId::X25519Ed25519 => "ECDH",
            _ => unreachable!(),
        };

        let ccfg = client_cfg(suite);
        let scfg = server_cfg(&[suite]);
        let spk = server_pk(&scfg, suite);
        let clock = FixedClock::new(1_000_000);
        let guard = StrikeCache::new(2000);

        group.bench_function(BenchmarkId::new("0-RTT", suite_name), |b| {
            b.iter(|| {
                let (frame, _est) =
                    client_offer_zero_rtt(&ccfg, suite, &spk, IP, &clock, b"early").unwrap();
                let step = server_on_first(&scfg, &frame, IP, &clock, &guard).unwrap();
                black_box(step);
            });
        });
    }

    group.finish();
}

fn bench_half_rtt(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");

    for suite in [SuiteId::MlKem768MlDsa65, SuiteId::X25519Ed25519] {
        let suite_name = match suite {
            SuiteId::MlKem768MlDsa65 => "PQC",
            SuiteId::X25519Ed25519 => "ECDH",
            _ => unreachable!(),
        };

        let ccfg = client_cfg(suite);
        let scfg = server_cfg(&[suite]);
        let spk = server_pk(&scfg, suite);
        let clock = FixedClock::new(1_000_000);
        let guard = StrikeCache::new(2000);

        // Pre-populate guard to trigger Half-RTT
        let (frame, _) = client_offer_zero_rtt(&ccfg, suite, &spk, IP, &clock, b"x").unwrap();
        server_on_first(&scfg, &frame, IP, &clock, &guard).unwrap();

        group.bench_function(BenchmarkId::new("Half-RTT", suite_name), |b| {
            b.iter(|| {
                // Replay triggers Half-RTT fallback
                let (frame, mut est) =
                    client_offer_zero_rtt(&ccfg, suite, &spk, IP, &clock, b"x").unwrap();
                let step = server_on_first(&scfg, &frame, IP, &clock, &guard).unwrap();
                if let ServerStep::HalfRtt { frame, .. } = step {
                    if let Frame::ServerRefuse0RTT {
                        server_ct, nonce, ..
                    } = frame
                    {
                        client_half_rtt_finish(&mut est, &server_ct, &nonce).unwrap();
                    }
                }
                black_box(est);
            });
        });
    }

    group.finish();
}

fn bench_one_rtt(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");

    for suite in [SuiteId::MlKem768MlDsa65, SuiteId::X25519Ed25519] {
        let suite_name = match suite {
            SuiteId::MlKem768MlDsa65 => "PQC",
            SuiteId::X25519Ed25519 => "ECDH",
            _ => unreachable!(),
        };

        let ccfg = client_cfg(suite);
        let scfg = server_cfg(&[suite]);
        let clock = FixedClock::new(1_000_000);
        let guard = StrikeCache::new(2000);

        group.bench_function(BenchmarkId::new("1-RTT", suite_name), |b| {
            b.iter(|| {
                // Client hello
                let hello = client_one_rtt_hello(&ccfg, &[suite]);
                let step = server_on_first(&scfg, &hello, IP, &clock, &guard).unwrap();
                let (selected, spk) = match step {
                    ServerStep::OneRtt {
                        hello: Frame::ServerHello { server_pk, .. },
                        selected,
                    } => (selected, server_pk),
                    _ => panic!("expected 1-RTT"),
                };
                // Client data
                let (frame, _est) =
                    client_one_rtt_finish(&ccfg, selected, &spk, IP, &clock, b"data").unwrap();
                let _established =
                    server_on_client_data(&scfg, &frame, IP, &clock, &guard, selected).unwrap();
                black_box(_established);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_zero_rtt, bench_half_rtt, bench_one_rtt);
criterion_main!(benches);
