//! Cryptographic primitive benchmarks: KEM and signature operations for both
//! PQC (ML-KEM-768 + ML-DSA-65) and ECDH (X25519 + Ed25519) suites.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ort_core::suite::agile::{self, ServerKemKey, SigIdentity};
use ort_core::suite::{fresh_r, SuiteId};

fn bench_kem_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("kem");

    for suite in [SuiteId::MlKem768MlDsa65, SuiteId::X25519Ed25519] {
        let suite_name = match suite {
            SuiteId::MlKem768MlDsa65 => "PQC",
            SuiteId::X25519Ed25519 => "ECDH",
            _ => unreachable!(),
        };

        // KEM key generation
        group.bench_function(BenchmarkId::new("keygen", suite_name), |b| {
            b.iter(|| {
                black_box(ServerKemKey::generate(suite));
            });
        });

        // KEM encapsulate
        let server_key = ServerKemKey::generate(suite);
        let server_pk = server_key.public();
        group.bench_function(BenchmarkId::new("encapsulate", suite_name), |b| {
            b.iter(|| {
                let r = fresh_r().unwrap();
                black_box(agile::kem_encapsulate(suite, &server_pk, &r).unwrap());
            });
        });

        // KEM decapsulate
        let r = fresh_r().unwrap();
        let (ct, _shared) = agile::kem_encapsulate(suite, &server_pk, &r).unwrap();
        group.bench_function(BenchmarkId::new("decapsulate", suite_name), |b| {
            b.iter(|| {
                black_box(server_key.decapsulate(&ct).unwrap());
            });
        });
    }

    group.finish();
}

fn bench_sig_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature");

    for suite in [SuiteId::MlKem768MlDsa65, SuiteId::X25519Ed25519] {
        let suite_name = match suite {
            SuiteId::MlKem768MlDsa65 => "PQC",
            SuiteId::X25519Ed25519 => "ECDH",
            _ => unreachable!(),
        };

        // Signature key generation
        group.bench_function(BenchmarkId::new("keygen", suite_name), |b| {
            b.iter(|| {
                black_box(SigIdentity::generate(suite));
            });
        });

        // Sign
        let identity = SigIdentity::generate(suite);
        let msg = b"ORT client binding signature";
        group.bench_function(BenchmarkId::new("sign", suite_name), |b| {
            b.iter(|| {
                black_box(identity.sign(msg));
            });
        });

        // Verify
        let sig = identity.sign(msg);
        let vk = identity.public();
        group.bench_function(BenchmarkId::new("verify", suite_name), |b| {
            b.iter(|| {
                black_box(agile::sig_verify(suite, &vk, msg, &sig).unwrap());
            });
        });
    }

    group.finish();
}

fn bench_record_seal_open(c: &mut Criterion) {
    use ort_core::kdf::derive_session_keys;
    use ort_core::pool::Direction;
    use ort_core::record::RecordLayer;

    let mut group = c.benchmark_group("record");

    // Test various payload sizes
    for size in [1024, 16384, 262144, 1048576] {
        let payload = vec![0xAB; size];
        let nonce = [0x42; 32];
        let shared = [0x99; 32];
        let keys = derive_session_keys(&shared, &nonce);
        let mut record = RecordLayer::new(keys, &nonce);

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(BenchmarkId::new("seal", format!("{}KB", size / 1024)), |b| {
            b.iter(|| {
                black_box(record.seal(Direction::ClientToServer, &payload));
            });
        });

        let sealed = record.seal(Direction::ClientToServer, &payload);
        group.bench_function(BenchmarkId::new("open", format!("{}KB", size / 1024)), |b| {
            b.iter(|| {
                black_box(record.open(Direction::ClientToServer, &sealed).unwrap());
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_kem_ops, bench_sig_ops, bench_record_seal_open);
criterion_main!(benches);
