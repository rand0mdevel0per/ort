//! ConnMeta binding signature + replay window/strike-cache tests.

use ort_core::connmeta::{sign_client_binding, verify_client_binding, ConnMeta};
use ort_core::replay::{replay_tag, ReplayGuard, StrikeCache};
use ort_core::suite::agile::SigIdentity;
use ort_core::suite::SuiteId;
use ort_core::time::check_window;

fn meta(ts: u64) -> ConnMeta {
    ConnMeta {
        src_ip: [0; 16],
        ts_millis: ts,
        nonce: [0xAB; 32],
    }
}

#[test]
fn binding_sign_verify_both_suites() {
    for id in [SuiteId::V1MlKem768MlDsa65, SuiteId::V2X25519Ed25519] {
        let identity = SigIdentity::generate(id);
        let client_pk = identity.public();
        let cm = meta(1000);
        let oh = [9u8; 32];
        let enc = vec![2u8; 128];
        let sig = sign_client_binding(&identity, &cm, &client_pk, &oh, &enc);
        verify_client_binding(id, &client_pk, &cm, &oh, &enc, &sig).unwrap();
        // tampered offers hash / enc_data / wrong sig_alg all fail
        assert!(verify_client_binding(id, &client_pk, &cm, &[8u8; 32], &enc, &sig).is_err());
        assert!(verify_client_binding(id, &client_pk, &cm, &oh, b"x", &sig).is_err());
    }
}

#[test]
fn window_accepts_and_rejects() {
    let (w, s) = (2000, 250);
    assert!(check_window(10_000, 9_000, w, s).is_ok());
    assert!(check_window(10_000, 8_000, w, s).is_ok()); // edge
    assert!(check_window(10_000, 7_999, w, s).is_err());
    assert!(check_window(10_000, 10_200, w, s).is_ok()); // small future skew
    assert!(check_window(10_000, 10_500, w, s).is_err());
}

#[test]
fn strike_cache_dedups_and_evicts() {
    let cache = StrikeCache::new(2000);
    let tag = replay_tag(&[0xAB; 32], &[1, 2, 3]);
    cache.check_and_insert(tag, 1000).unwrap();
    assert!(cache.check_and_insert(tag, 1000).is_err());
    assert!(cache.check_and_insert(tag, 2999).is_err());
    cache.check_and_insert(tag, 3001).unwrap(); // evicted, accepted again
}

#[test]
fn strike_cache_stays_bounded() {
    let cache = StrikeCache::new(2000);
    for i in 0..1000u32 {
        cache
            .check_and_insert(replay_tag(&[0; 32], &i.to_be_bytes()), 0)
            .unwrap();
    }
    assert_eq!(cache.len(), 1000);
    cache
        .check_and_insert(replay_tag(&[9; 32], b"fresh"), 5000)
        .unwrap();
    assert_eq!(cache.len(), 1);
}
