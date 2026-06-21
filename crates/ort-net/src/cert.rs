//! Server public-key verification policy.
//!
//! The server's certificate is a standard X.509 certificate. The server proves
//! ownership of KEM public keys by signing them with the certificate's private key.
//! Strict verification parses the certificate, checks its validity and signature
//! (self-signed, or against a pinned CA). `--no-strict-cert` trusts on first use (TOFU)
//! and relies on caller-side pinning.

use crate::error::OrtError;
use x509_parser::prelude::*;

/// How the client decides to trust a server's KEM public key.
#[derive(Debug, Clone)]
pub enum ServerVerifier {
    /// Trust the `server_pk` from ServerHello without chain validation
    /// (`--no-strict-cert`). TOFU pinning is layered on by the caller.
    TrustOnFirstUse,
    /// Validate the presented certificate and its ServerPK binding. If `ca` is
    /// `Some`, the certificate must be signed by that CA; otherwise the
    /// certificate must be validly self-signed.
    Strict {
        /// Optional DER-encoded CA certificate to anchor trust to.
        ca: Option<Vec<u8>>,
    },
}

impl ServerVerifier {
    /// Verify that the `certificate` is valid (DER; empty if none).
    pub fn verify(&self, certificate: &[u8]) -> Result<(), OrtError> {
        let ca = match self {
            ServerVerifier::TrustOnFirstUse => return Ok(()),
            ServerVerifier::Strict { ca } => ca,
        };

        if certificate.is_empty() {
            return Err(OrtError::Cert("server presented no certificate".into()));
        }
        let (_, cert) = parse_x509_certificate(certificate)
            .map_err(|e| OrtError::Cert(format!("parse certificate: {e}")))?;

        if !cert.validity().is_valid() {
            return Err(OrtError::Cert(
                "certificate expired or not yet valid".into(),
            ));
        }

        match ca {
            Some(ca_der) => {
                let (_, ca_cert) = parse_x509_certificate(ca_der)
                    .map_err(|e| OrtError::Cert(format!("parse CA: {e}")))?;
                cert.verify_signature(Some(ca_cert.public_key()))
                    .map_err(|e| OrtError::Cert(format!("certificate not signed by CA: {e}")))?;
            }
            None => {
                cert.verify_signature(None)
                    .map_err(|e| OrtError::Cert(format!("invalid self-signature: {e}")))?;
            }
        }

        Ok(())
    }
}

/// Extract the server's signing public key from a DER certificate for Half-RTT
/// signature verification. Returns (verifying_key_bytes, suite_id).
pub fn extract_signing_key(certificate: &[u8]) -> Result<(Vec<u8>, ort_core::suite::SuiteId), OrtError> {
    if certificate.is_empty() {
        return Err(OrtError::Cert("certificate is empty".into()));
    }

    let (_, cert) = parse_x509_certificate(certificate)
        .map_err(|e| OrtError::Cert(format!("parse certificate: {e}")))?;

    // Extract the public key from the certificate's SubjectPublicKeyInfo
    let spki = cert.public_key();
    let pk_bytes = spki.subject_public_key.data.to_vec();

    // Determine the signature suite based on the algorithm OID
    let alg_oid = &spki.algorithm.algorithm;
    let suite = if alg_oid.to_id_string() == "1.3.101.112" {
        // Ed25519
        ort_core::suite::SuiteId::X25519Ed25519
    } else if alg_oid.to_id_string() == "2.16.840.1.101.3.4.3.17" {
        // ML-DSA-65 (FIPS 204)
        ort_core::suite::SuiteId::MlKem768MlDsa65
    } else {
        return Err(OrtError::Cert(format!(
            "unsupported certificate signature algorithm: {}",
            alg_oid
        )));
    };

    Ok((pk_bytes, suite))
}
