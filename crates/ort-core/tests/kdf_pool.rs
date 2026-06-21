//! Key-schedule (direct KDF from shared secret) and entropy-pool tests.

use ort_core::kdf::derive_session_keys;
use ort_core::pool::{Direction, EntropyPool};
use std::collections::HashSet;

#[test]
fn session_keys_deterministic_and_nonce_sensitive() {
    let shared = [0x11u8; 32];
    let n1 = [0x22u8; 32];
    let n2 = [0x23u8; 32];
    let a = derive_session_keys(&shared, &n1);
    let b = derive_session_keys(&shared, &n1);
    let c = derive_session_keys(&shared, &n2);
    assert_eq!(a.enc_key, b.enc_key);
    assert_ne!(a.enc_key, c.enc_key);
    assert_ne!(a.enc_key, a.pool_key);
}

#[test]
fn different_shared_secrets_yield_different_keys() {
    let shared1 = [0x42u8; 32];
    let shared2 = [0x43u8; 32];
    let nonce = [0x77u8; 32];
    let keys1 = derive_session_keys(&shared1, &nonce);
    let keys2 = derive_session_keys(&shared2, &nonce);
    assert_ne!(keys1.enc_key, keys2.enc_key);
    assert_ne!(keys1.pool_key, keys2.pool_key);
}

#[test]
fn nonce_uniqueness_within_session() {
    let mut pool = EntropyPool::new(&[0x42u8; 32], &[0x7fu8; 32]);
    let mut seen = HashSet::new();
    for _ in 0..10_000 {
        assert!(seen.insert(pool.next_nonce(Direction::ClientToServer)));
    }
    for _ in 0..10_000 {
        assert!(seen.insert(pool.next_nonce(Direction::ServerToClient)));
    }
}

#[test]
fn pools_synchronize_across_peers() {
    let mut a = EntropyPool::new(&[0x42u8; 32], &[0x7fu8; 32]);
    let mut b = EntropyPool::new(&[0x42u8; 32], &[0x7fu8; 32]);
    for i in 0..100u32 {
        assert_eq!(
            a.next_nonce(Direction::ClientToServer),
            b.next_nonce(Direction::ClientToServer)
        );
        let ct = [i as u8; 48];
        a.absorb(Direction::ClientToServer, &ct);
        b.absorb(Direction::ClientToServer, &ct);
    }
}

#[test]
fn distinct_sessions_have_disjoint_nonces() {
    let mut s1 = EntropyPool::new(&[0x42u8; 32], &[0x01u8; 32]);
    let mut s2 = EntropyPool::new(&[0x42u8; 32], &[0x02u8; 32]);
    let set1: HashSet<_> = (0..2000)
        .map(|_| s1.next_nonce(Direction::ClientToServer))
        .collect();
    let set2: HashSet<_> = (0..2000)
        .map(|_| s2.next_nonce(Direction::ClientToServer))
        .collect();
    assert!(set1.is_disjoint(&set2));
}
