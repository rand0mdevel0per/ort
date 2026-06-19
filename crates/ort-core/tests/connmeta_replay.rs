//! ConnMeta signing, replay-window and strike-cache tests.

use ort_core::connmeta::{sign_client_binding, verify_client_binding, ConnMeta};
use ort_core::replay::{replay_tag, StrikeCache};
use ort_core::suite::v1::V1;
use ort_core::suite::CipherSuite;
use ort_core::time::check_window;

fn sample_meta(ts: u64) -> ConnMeta {
    ConnMeta {
        src_ip: [0; 16],
        ts_millis: ts,
        nonce: [0xAB; 32],
    }
}

#[test]
fn client_binding_sign_verify() {
    let sk = V1::sig_generate();
    let client_pk = V1::sig_public(&sk);
    let cm = sample_meta(1000);
    let ct = vec![1u8; V1::KEM_CT_LEN];
    let enc = vec![2u8; 128];

    let sig = sign_client_binding::<V1>(&sk, &cm, &client_pk, &ct, &enc);
    verify_client_binding::<V1>(&client_pk, &cm, &ct, &enc, &sig).expect("valid binding verifies");
}

#[test]
fn client_binding_rejects_swapped_ciphertext() {
    let sk = V1::sig_generate();
    let client_pk = V1::sig_public(&sk);
    let cm = sample_meta(1000);
    let ct = vec![1u8; V1::KEM_CT_LEN];
    let enc = vec![2u8; 128];
    let sig = sign_client_binding::<V1>(&sk, &cm, &client_pk, &ct, &enc);

    // swap the KEM ciphertext -> signature must fail
    let mut ct2 = ct.clone();
    ct2[0] ^= 0xFF;
    assert!(verify_client_binding::<V1>(&client_pk, &cm, &ct2, &enc, &sig).is_err());

    // swap the early data -> signature must fail
    let mut enc2 = enc.clone();
    enc2[0] ^= 0xFF;
    assert!(verify_client_binding::<V1>(&client_pk, &cm, &ct, &enc2, &sig).is_err());

    // tamper the timestamp -> signature must fail
    let cm2 = sample_meta(1001);
    assert!(verify_client_binding::<V1>(&client_pk, &cm2, &ct, &enc, &sig).is_err());
}

#[test]
fn window_accepts_and_rejects() {
    let window = 2000;
    let skew = 250;
    // within window
    assert!(check_window(10_000, 9_000, window, skew).is_ok());
    assert!(check_window(10_000, 10_000, window, skew).is_ok());
    // exactly at window edge (now - ts == window) is accepted
    assert!(check_window(10_000, 8_000, window, skew).is_ok());
    // just past window
    assert!(check_window(10_000, 7_999, window, skew).is_err());
    // small future skew allowed
    assert!(check_window(10_000, 10_200, window, skew).is_ok());
    // too far in the future
    assert!(check_window(10_000, 10_500, window, skew).is_err());
}

#[test]
fn strike_cache_dedups_within_window() {
    let mut cache = StrikeCache::new(2000);
    let tag = replay_tag::<V1>(&[0xAB; 32], &[1, 2, 3]);

    // first time: accepted
    cache.check_and_insert(tag, 1000).unwrap();
    // immediate replay: rejected
    assert!(cache.check_and_insert(tag, 1000).is_err());
    // still within window: rejected
    assert!(cache.check_and_insert(tag, 2999).is_err());
    // past the window: the old entry is evicted, so it is accepted again
    cache.check_and_insert(tag, 3001).unwrap();
}

#[test]
fn strike_cache_evicts_and_stays_bounded() {
    let mut cache = StrikeCache::new(2000);
    // insert 1000 distinct tags at t=0
    for i in 0..1000u32 {
        let tag = replay_tag::<V1>(&[0; 32], &i.to_be_bytes());
        cache.check_and_insert(tag, 0).unwrap();
    }
    assert_eq!(cache.len(), 1000);
    // a later insert past the window evicts all of them
    let fresh = replay_tag::<V1>(&[9; 32], b"fresh");
    cache.check_and_insert(fresh, 5000).unwrap();
    assert_eq!(cache.len(), 1, "stale entries evicted, cache bounded");
}

#[test]
fn replay_tag_distinguishes_nonce_and_data() {
    let a = replay_tag::<V1>(&[1; 32], b"data");
    let b = replay_tag::<V1>(&[2; 32], b"data");
    let c = replay_tag::<V1>(&[1; 32], b"DATA");
    assert_ne!(a, b);
    assert_ne!(a, c);
}
