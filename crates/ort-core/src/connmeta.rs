//! ConnMeta — the per-connection metadata the client signs to bind a handshake
//! to a source IP, a timestamp and a fresh nonce (anti-replay), plus helpers to
//! build/verify the client signature over the full ClientHello binding string.

use crate::suite::CipherSuite;
use crate::{Error, Result};

/// Domain-separation label for the client binding signature.
pub const CLIENT_BINDING_LABEL: &[u8] = b"ORT-v1 connmeta";

/// Per-connection metadata, signed by the client with its ML-DSA key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnMeta {
    /// Client source IP as 16 bytes (IPv6, or IPv4-mapped `::ffff:a.b.c.d`).
    pub src_ip: [u8; 16],
    /// Client timestamp in milliseconds since the Unix epoch.
    pub ts_millis: u64,
    /// Fresh per-connection random nonce.
    pub nonce: [u8; 32],
}

impl ConnMeta {
    /// Canonical byte encoding (56 bytes): `src_ip(16) || ts_be(8) || nonce(32)`.
    pub fn canonical(&self) -> [u8; 56] {
        let mut out = [0u8; 56];
        out[..16].copy_from_slice(&self.src_ip);
        out[16..24].copy_from_slice(&self.ts_millis.to_be_bytes());
        out[24..].copy_from_slice(&self.nonce);
        out
    }
}

/// Build the message the client signs:
/// `LABEL || canonical(ConnMeta) || client_pk || H(ciphertext) || H(enc_data)`.
///
/// Binding the KEM ciphertext and the early-data ciphertext means neither can
/// be swapped without invalidating the signature.
pub fn client_binding_msg<S: CipherSuite>(
    cm: &ConnMeta,
    client_pk: &[u8],
    ciphertext: &[u8],
    enc_data: &[u8],
) -> Vec<u8> {
    let ct_hash = S::hash256(ciphertext);
    let ed_hash = S::hash256(enc_data);
    let mut msg = Vec::with_capacity(
        CLIENT_BINDING_LABEL.len() + 56 + client_pk.len() + ct_hash.len() + ed_hash.len(),
    );
    msg.extend_from_slice(CLIENT_BINDING_LABEL);
    msg.extend_from_slice(&cm.canonical());
    msg.extend_from_slice(client_pk);
    msg.extend_from_slice(&ct_hash);
    msg.extend_from_slice(&ed_hash);
    msg
}

/// Sign the client binding with the client's signing secret.
pub fn sign_client_binding<S: CipherSuite>(
    sk: &S::SigSecret,
    cm: &ConnMeta,
    client_pk: &[u8],
    ciphertext: &[u8],
    enc_data: &[u8],
) -> Vec<u8> {
    let msg = client_binding_msg::<S>(cm, client_pk, ciphertext, enc_data);
    S::sig_sign(sk, &msg)
}

/// Verify the client binding signature. `client_pk` is both the signed-over
/// identity and the verifying key (clients are unrestricted; the signature only
/// authenticates *this* handshake).
pub fn verify_client_binding<S: CipherSuite>(
    client_pk: &[u8],
    cm: &ConnMeta,
    ciphertext: &[u8],
    enc_data: &[u8],
    sig: &[u8],
) -> Result<()> {
    let msg = client_binding_msg::<S>(cm, client_pk, ciphertext, enc_data);
    S::sig_verify(client_pk, &msg, sig).map_err(|_| Error::BadSignature)
}
