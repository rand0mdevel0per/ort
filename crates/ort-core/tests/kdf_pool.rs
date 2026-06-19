//! Key-schedule and entropy-pool tests, including the GCM nonce-uniqueness
//! invariant and a pinned key-schedule vector locking the wire contract.

use ort_core::kdf::derive_session_keys;
use ort_core::pool::{Direction, EntropyPool};
use ort_core::suite::v1::V1;
use std::collections::HashSet;

#[test]
fn key_schedule_pinned_vector() {
    // Fixed inputs -> fixed outputs. If this changes, the wire format changed.
    let k_sk = [0x11u8; 32];
    let ciphertext = [0x22u8; 64];
    let keys = derive_session_keys::<V1>(&k_sk, &ciphertext);
    assert_eq!(
        hex::encode(keys.enc_key),
        "6294f046bcd8e8287a98e9ca7ee7acf65c9789ea8de1119e9d3bf6740b0d91ec"
    );
    assert_eq!(
        hex::encode(keys.pool_key),
        "fcd5962a74d99e7a48efc3b982d5159d8f7d3e91993cea6c74257db8118ecbe5"
    );
}

#[test]
fn key_schedule_deterministic_and_ct_sensitive() {
    let k_sk = [0x11u8; 32];
    let ct1 = [0x22u8; 64];
    let ct2 = [0x23u8; 64];

    let a = derive_session_keys::<V1>(&k_sk, &ct1);
    let b = derive_session_keys::<V1>(&k_sk, &ct1);
    let c = derive_session_keys::<V1>(&k_sk, &ct2);

    assert_eq!(a.enc_key, b.enc_key);
    assert_eq!(a.pool_key, b.pool_key);
    assert_ne!(a.enc_key, c.enc_key, "different ciphertext => different key");
    assert_ne!(a.enc_key, a.pool_key, "enc/pool keys are distinct");
}

#[test]
fn nonce_uniqueness_within_session() {
    let pool_key = [0x42u8; 32];
    let cm_nonce = [0x7fu8; 32];
    let mut pool = EntropyPool::new(&pool_key, &cm_nonce);

    let mut seen = HashSet::new();
    for _ in 0..10_000 {
        assert!(seen.insert(pool.next_nonce(Direction::ClientToServer)), "c2s nonce repeated");
    }
    // s2c stream must be disjoint from c2s.
    for _ in 0..10_000 {
        assert!(seen.insert(pool.next_nonce(Direction::ServerToClient)), "s2c collided with c2s");
    }
}

#[test]
fn pools_synchronize_across_peers() {
    // Two pools built from the same key/nonce (the two peers) must produce the
    // same nonce streams per direction, including after absorbing identical
    // wire ciphertext.
    let pool_key = [0x42u8; 32];
    let cm_nonce = [0x7fu8; 32];
    let mut a = EntropyPool::new(&pool_key, &cm_nonce);
    let mut b = EntropyPool::new(&pool_key, &cm_nonce);

    for i in 0..100u32 {
        let na = a.next_nonce(Direction::ClientToServer);
        let nb = b.next_nonce(Direction::ClientToServer);
        assert_eq!(na, nb, "peers must agree on nonce {i}");
        let fake_ct = [i as u8; 48];
        a.absorb(Direction::ClientToServer, &fake_ct);
        b.absorb(Direction::ClientToServer, &fake_ct);
    }
}

#[test]
fn distinct_sessions_have_disjoint_nonces() {
    // The GCM-safety invariant: even if two sessions happened to reuse the same
    // enc_key (e.g. forced), differing ConnMeta nonce / pool_key yield disjoint
    // nonce streams.
    let pk1 = [0x42u8; 32];
    let pk2 = [0x42u8; 32];
    let n1 = [0x01u8; 32];
    let n2 = [0x02u8; 32];
    let mut s1 = EntropyPool::new(&pk1, &n1);
    let mut s2 = EntropyPool::new(&pk2, &n2);

    let set1: HashSet<_> = (0..2000).map(|_| s1.next_nonce(Direction::ClientToServer)).collect();
    let set2: HashSet<_> = (0..2000).map(|_| s2.next_nonce(Direction::ClientToServer)).collect();
    assert!(set1.is_disjoint(&set2), "sessions with different nonce seeds must not share nonces");
}
