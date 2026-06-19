//! Server public-key verification policy.
//!
//! The server's ML-KEM public key is bound into an X.509 certificate via a
//! private custom extension. Strict verification parses that certificate,
//! checks its validity and signature (self-signed, or against a pinned CA), and
//! requires the embedded key to equal the `server_pk` presented in ServerHello —
//! closing the MITM key-substitution gap. `--no-strict-cert` instead trusts the
//! key on first use (TOFU) and relies on caller-side pinning.

use crate::error::OrtError;
use x509_parser::prelude::*;

/// Private-enterprise OID carrying the bound ML-KEM ServerPK (numeric form).
/// (58271 is an unregistered placeholder PEN — documented in SPEC.md.)
pub const SERVERPK_OID_U64: &[u64] = &[1, 3, 6, 1, 4, 1, 58271, 1, 1];
/// The same OID in dotted-string form, for matching parsed extensions.
pub const SERVERPK_OID_STR: &str = "1.3.6.1.4.1.58271.1.1";

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

fn extract_bound_server_pk(cert: &X509Certificate<'_>) -> Option<Vec<u8>> {
    cert.extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == SERVERPK_OID_STR)
        .map(|e| e.value.to_vec())
}

impl ServerVerifier {
    /// Verify that `server_pk` is acceptable given the presented `certificate`
    /// (DER; empty if none).
    pub fn verify(&self, server_pk: &[u8], certificate: &[u8]) -> Result<(), OrtError> {
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
            return Err(OrtError::Cert("certificate expired or not yet valid".into()));
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

        let bound = extract_bound_server_pk(&cert)
            .ok_or_else(|| OrtError::Cert("certificate has no ServerPK extension".into()))?;
        if bound != server_pk {
            return Err(OrtError::Cert(
                "ServerHello public key does not match certificate binding".into(),
            ));
        }
        Ok(())
    }
}
