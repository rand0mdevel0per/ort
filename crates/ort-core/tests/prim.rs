//! Fixed symmetric primitive KATs (AES-256-GCM, HKDF-SHA256, BLAKE3).

use ort_core::prim;

#[test]
fn aead_roundtrip_and_tamper() {
    let key = [7u8; 32];
    let nonce = [3u8; 12];
    let aad = b"associated";
    let pt = b"secret payload";

    let ct = prim::aead_seal(&key, &nonce, aad, pt);
    assert_eq!(ct.len(), pt.len() + 16);
    assert_eq!(prim::aead_open(&key, &nonce, aad, &ct).unwrap(), pt);

    let mut bad = ct.clone();
    bad[0] ^= 1;
    assert!(prim::aead_open(&key, &nonce, aad, &bad).is_err());
    assert!(prim::aead_open(&key, &nonce, b"other", &ct).is_err());
    assert!(prim::aead_open(&key, &[9u8; 12], aad, &ct).is_err());
}

#[test]
fn hkdf_deterministic_and_salt_sensitive() {
    let ikm = [1u8; 32];
    let (mut a, mut b, mut c) = ([0u8; 32], [0u8; 32], [0u8; 32]);
    prim::hkdf(&ikm, b"salt-1", b"info", &mut a);
    prim::hkdf(&ikm, b"salt-1", b"info", &mut b);
    prim::hkdf(&ikm, b"salt-2", b"info", &mut c);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn blake3_known_answer() {
    let h = prim::hash256(b"");
    assert_eq!(
        hex::encode(h),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
    assert_eq!(&prim::hash512(b"")[..32], &h[..]);
}
