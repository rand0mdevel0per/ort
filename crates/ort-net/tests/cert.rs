//! Strict certificate verification: signature and validity.

use ort_net::cert::ServerVerifier;
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};

/// Build a self-signed cert (standard X.509, no custom extensions).
fn make_cert() -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let params = CertificateParams::new(vec!["ortd".to_string()]).unwrap();
    params.self_signed(&key).unwrap().der().as_ref().to_vec()
}

#[test]
fn strict_accepts_valid_certificate() {
    let cert = make_cert();
    let v = ServerVerifier::Strict { ca: None };
    v.verify(&cert).expect("valid cert accepted");
}

#[test]
fn strict_rejects_missing_certificate() {
    let v = ServerVerifier::Strict { ca: None };
    assert!(v.verify(&[]).is_err());
}

#[test]
fn strict_rejects_tampered_certificate() {
    let mut cert = make_cert();
    // Flip a byte in the middle (likely in the TBS) to break the signature.
    let mid = cert.len() / 2;
    cert[mid] ^= 0xFF;
    let v = ServerVerifier::Strict { ca: None };
    assert!(
        v.verify(&cert).is_err(),
        "tampered cert must be rejected"
    );
}

#[test]
fn tofu_accepts_anything() {
    let v = ServerVerifier::TrustOnFirstUse;
    v.verify(&[]).unwrap();
}
