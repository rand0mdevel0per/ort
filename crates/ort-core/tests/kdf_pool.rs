//! Key-schedule (DEK derivation + enc_sk wrapping) and entropy-pool tests.

use ort_core::kdf::{derive_session_keys, unwrap_enc_sk, wrap_enc_sk};
use ort_core::pool::{Direction, EntropyPool};
use std::collections::HashSet;

#[test]
fn session_keys_deterministic_and_nonce_sensitive() {
    let enc_sk = [0x11u8; 32];
    let n1 = [0x22u8; 32];
    let n2 = [0x23u8; 32];
    let a = derive_session_keys(&enc_sk, &n1);
    let b = derive_session_keys(&enc_sk, &n1);
    let c = derive_session_keys(&enc_sk, &n2);
    assert_eq!(a.enc_key, b.enc_key);
    assert_ne!(a.enc_key, c.enc_key);
    assert_ne!(a.enc_key, a.pool_key);
}

#[test]
fn enc_sk_wrap_roundtrip() {
    let shared = [0x42u8; 32];
    let ct = vec![0x55u8; 1088];
    let enc_sk = [0x77u8; 32];
    let wrapped = wrap_enc_sk(&shared, &ct, 0x0001, &enc_sk);
    let got = unwrap_enc_sk(&shared, &ct, 0x0001, &wrapped).unwrap();
    assert_eq!(&got[..], &enc_sk);

    // wrong shared secret fails authentication
    assert!(unwrap_enc_sk(&[0u8; 32], &ct, 0x0001, &wrapped).is_err());
    // wrong suite-id AAD fails
    assert!(unwrap_enc_sk(&shared, &ct, 0x0002, &wrapped).is_err());
    // wrong ciphertext binding fails
    assert!(unwrap_enc_sk(&shared, &vec![0u8; 1088], 0x0001, &wrapped).is_err());
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
