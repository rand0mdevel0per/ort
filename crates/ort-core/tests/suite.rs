//! KEM round-trip and signature tests for both cipher suites.

use ort_core::suite::agile::{self, ServerKemKey, SigIdentity};
use ort_core::suite::{classical::V2, fresh_r, v1::V1, CipherSuite, SuiteId};

fn kem_roundtrip(id: SuiteId, ek_len: usize, ct_len: usize) {
    let secret = ServerKemKey::generate(id);
    let ek = secret.public();
    assert_eq!(ek.len(), ek_len, "ek length for {id:?}");

    let r = fresh_r().unwrap();
    let (ct, shared_c) = agile::kem_encapsulate(id, &ek, &r).unwrap();
    assert_eq!(ct.len(), ct_len, "ct length for {id:?}");

    let shared_s = secret.decapsulate(&ct).unwrap();
    assert_eq!(shared_c, shared_s, "shared secret mismatch for {id:?}");

    // determinism in r
    let (ct2, s2) = agile::kem_encapsulate(id, &ek, &r).unwrap();
    assert_eq!((ct, shared_c), (ct2, s2));
    // fresh r differs
    let (ct3, s3) = agile::kem_encapsulate(id, &ek, &fresh_r().unwrap()).unwrap();
    assert_ne!(s3, shared_c);
    let _ = ct3;
}

#[test]
fn v1_kem_roundtrip() {
    kem_roundtrip(SuiteId::V1MlKem768MlDsa65, V1::KEM_EK_LEN, V1::KEM_CT_LEN);
}

#[test]
fn v2_kem_roundtrip() {
    kem_roundtrip(SuiteId::V2X25519Ed25519, V2::KEM_EK_LEN, V2::KEM_CT_LEN);
}

fn sig_roundtrip(id: SuiteId, vk_len: usize, sig_len: usize) {
    let identity = SigIdentity::generate(id);
    let vk = identity.public();
    assert_eq!(vk.len(), vk_len);
    let msg = b"bind this handshake";
    let sig = identity.sign(msg);
    assert_eq!(sig.len(), sig_len);
    agile::sig_verify(id, &vk, msg, &sig).unwrap();
    assert!(agile::sig_verify(id, &vk, b"other", &sig).is_err());
    let mut bad = sig.clone();
    bad[0] ^= 1;
    assert!(agile::sig_verify(id, &vk, msg, &bad).is_err());
}

#[test]
fn v1_sig_roundtrip() {
    sig_roundtrip(SuiteId::V1MlKem768MlDsa65, V1::SIG_VK_LEN, V1::SIG_LEN);
}

#[test]
fn v2_sig_roundtrip() {
    sig_roundtrip(SuiteId::V2X25519Ed25519, V2::SIG_VK_LEN, V2::SIG_LEN);
}

#[test]
fn kem_seed_roundtrip_both() {
    for id in [SuiteId::V1MlKem768MlDsa65, SuiteId::V2X25519Ed25519] {
        let s = ServerKemKey::generate(id);
        let seed = s.to_seed();
        let r = ServerKemKey::from_seed(id, &seed).unwrap();
        assert_eq!(s.public(), r.public(), "{id:?}");
    }
}

#[test]
fn sig_seed_roundtrip_both() {
    for id in [SuiteId::V1MlKem768MlDsa65, SuiteId::V2X25519Ed25519] {
        let s = SigIdentity::generate(id);
        let seed = s.to_seed();
        let r = SigIdentity::from_seed(id, &seed).unwrap();
        assert_eq!(s.public(), r.public(), "{id:?}");
    }
}

#[test]
fn v1_implicit_rejection() {
    let secret = ServerKemKey::generate(SuiteId::V1MlKem768MlDsa65);
    let bogus = vec![0xABu8; V1::KEM_CT_LEN];
    let shared = secret.decapsulate(&bogus).unwrap();
    let (_ct, real) = agile::kem_encapsulate(
        SuiteId::V1MlKem768MlDsa65,
        &secret.public(),
        &fresh_r().unwrap(),
    )
    .unwrap();
    assert_ne!(shared, real);
}
