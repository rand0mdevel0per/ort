//! Strict certificate verification: ServerPK binding, signature and validity.

use ort_net::cert::ServerVerifier;
use ort_net::SERVERPK_OID_U64;
use rcgen::{CertificateParams, CustomExtension, KeyPair, PKCS_ED25519};

/// Build a self-signed cert binding `server_pk` via the custom extension.
fn make_cert(server_pk: &[u8]) -> Vec<u8> {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut params = CertificateParams::new(vec!["ortd".to_string()]).unwrap();
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(SERVERPK_OID_U64, server_pk.to_vec()));
    params.self_signed(&key).unwrap().der().as_ref().to_vec()
}

#[test]
fn strict_accepts_matching_binding() {
    let server_pk = vec![0xAB; 1184];
    let cert = make_cert(&server_pk);
    let v = ServerVerifier::Strict { ca: None };
    v.verify(&server_pk, &cert).expect("matching binding accepted");
}

#[test]
fn strict_rejects_mismatched_binding() {
    let server_pk = vec![0xAB; 1184];
    let other_pk = vec![0xCD; 1184];
    let cert = make_cert(&server_pk);
    let v = ServerVerifier::Strict { ca: None };
    assert!(v.verify(&other_pk, &cert).is_err(), "mismatched key must be rejected");
}

#[test]
fn strict_rejects_missing_certificate() {
    let v = ServerVerifier::Strict { ca: None };
    assert!(v.verify(&[1, 2, 3], &[]).is_err());
}

#[test]
fn strict_rejects_tampered_certificate() {
    let server_pk = vec![0xAB; 1184];
    let mut cert = make_cert(&server_pk);
    // Flip a byte in the middle (likely in the TBS) to break the signature.
    let mid = cert.len() / 2;
    cert[mid] ^= 0xFF;
    let v = ServerVerifier::Strict { ca: None };
    assert!(v.verify(&server_pk, &cert).is_err(), "tampered cert must be rejected");
}

#[test]
fn tofu_accepts_anything() {
    let v = ServerVerifier::TrustOnFirstUse;
    v.verify(&[1, 2, 3], &[]).unwrap();
}
