//! v1 cipher-suite round-trip and known-answer tests.

use ort_core::suite::v1::V1;
use ort_core::suite::{fresh_r, CipherSuite};

#[test]
fn kem_roundtrip_and_sizes() {
    let secret = V1::kem_generate();
    let ek = V1::kem_public(&secret);
    assert_eq!(ek.len(), V1::KEM_EK_LEN, "ek length");

    let r = fresh_r();
    let (ct, shared_c) = V1::kem_encapsulate(&ek, &r).unwrap();
    assert_eq!(ct.len(), V1::KEM_CT_LEN, "ct length");

    let shared_s = V1::kem_decapsulate(&secret, &ct).unwrap();
    assert_eq!(shared_c, shared_s, "client/server shared secret must match");
}

#[test]
fn kem_deterministic_in_r() {
    let secret = V1::kem_generate();
    let ek = V1::kem_public(&secret);
    let r = fresh_r();

    let (ct1, s1) = V1::kem_encapsulate(&ek, &r).unwrap();
    let (ct2, s2) = V1::kem_encapsulate(&ek, &r).unwrap();
    assert_eq!(ct1, ct2, "same r => same ciphertext");
    assert_eq!(s1, s2, "same r => same shared");

    let r2 = fresh_r();
    let (ct3, s3) = V1::kem_encapsulate(&ek, &r2).unwrap();
    assert_ne!(ct1, ct3, "different r => different ciphertext");
    assert_ne!(s1, s3, "different r => different shared (overwhelmingly likely)");
}

#[test]
fn kem_secret_seed_roundtrip() {
    let secret = V1::kem_generate();
    let seed = V1::kem_secret_to_bytes(&secret);
    assert_eq!(seed.len(), 64, "ml-kem dk seed is 64 bytes");
    let restored = V1::kem_secret_from_bytes(&seed).unwrap();
    assert_eq!(
        V1::kem_public(&secret),
        V1::kem_public(&restored),
        "restored secret yields same public key"
    );
}

#[test]
fn kem_bad_ciphertext_implicit_rejection() {
    // ML-KEM implicit rejection: a garbage ct of the right length decapsulates
    // to a pseudo-random secret that will not match the encapsulator's.
    let secret = V1::kem_generate();
    let bogus = vec![0xABu8; V1::KEM_CT_LEN];
    let shared = V1::kem_decapsulate(&secret, &bogus).unwrap();
    let ek = V1::kem_public(&secret);
    let (_ct, real) = V1::kem_encapsulate(&ek, &fresh_r()).unwrap();
    assert_ne!(shared, real);
    // Wrong length must error.
    assert!(V1::kem_decapsulate(&secret, &[0u8; 10]).is_err());
}

#[test]
fn sig_sign_verify_and_sizes() {
    let sk = V1::sig_generate();
    let vk = V1::sig_public(&sk);
    assert_eq!(vk.len(), V1::SIG_VK_LEN, "vk length");

    let msg = b"the quick brown fox";
    let sig = V1::sig_sign(&sk, msg);
    assert_eq!(sig.len(), V1::SIG_LEN, "sig length");

    V1::sig_verify(&vk, msg, &sig).expect("valid signature verifies");
    assert!(V1::sig_verify(&vk, b"tampered", &sig).is_err(), "wrong msg fails");

    let mut bad = sig.clone();
    bad[0] ^= 0x01;
    assert!(V1::sig_verify(&vk, msg, &bad).is_err(), "tampered sig fails");
}

#[test]
fn sig_seed_roundtrip() {
    let sk = V1::sig_generate();
    let seed = V1::sig_secret_to_bytes(&sk);
    assert_eq!(seed.len(), 32, "ml-dsa seed is 32 bytes");
    let restored = V1::sig_secret_from_bytes(&seed).unwrap();
    assert_eq!(V1::sig_public(&sk), V1::sig_public(&restored));
}

#[test]
fn aead_roundtrip_and_tamper() {
    let key = [7u8; 32];
    let nonce = [3u8; 12];
    let aad = b"associated";
    let pt = b"secret payload";

    let ct = V1::aead_seal(&key, &nonce, aad, pt);
    assert_eq!(ct.len(), pt.len() + 16, "ct includes 16-byte tag");

    let opened = V1::aead_open(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(opened, pt);

    // tamper ciphertext
    let mut bad = ct.clone();
    bad[0] ^= 0x01;
    assert!(V1::aead_open(&key, &nonce, aad, &bad).is_err());
    // wrong aad
    assert!(V1::aead_open(&key, &nonce, b"other", &ct).is_err());
    // wrong nonce
    assert!(V1::aead_open(&key, &[9u8; 12], aad, &ct).is_err());
}

#[test]
fn hkdf_deterministic_and_salt_sensitive() {
    let ikm = [1u8; 32];
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let mut c = [0u8; 32];
    V1::hkdf(&ikm, b"salt-1", b"info", &mut a);
    V1::hkdf(&ikm, b"salt-1", b"info", &mut b);
    V1::hkdf(&ikm, b"salt-2", b"info", &mut c);
    assert_eq!(a, b, "deterministic");
    assert_ne!(a, c, "salt changes output");
}

#[test]
fn blake3_known_answer() {
    // BLAKE3 of the empty input (256-bit).
    let h = V1::hash256(b"");
    assert_eq!(
        hex::encode(h),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
    // 512-bit output starts with the same 256-bit prefix (XOF extension).
    let h512 = V1::hash512(b"");
    assert_eq!(&h512[..32], &h[..]);
}
