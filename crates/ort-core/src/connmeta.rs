//! ConnMeta — per-connection metadata the client signs to bind a handshake to
//! a source IP, timestamp and fresh nonce (anti-replay), plus helpers to
//! build/verify the binding signature. The signed message also commits to the
//! protocol version, the signature algorithm and all KEM offers (via their
//! hash), so neither the version, the chosen suites nor the ciphertexts/early
//! data can be altered.

use crate::suite::agile::{self, SigIdentity};
use crate::suite::SuiteId;
use crate::{prim, Result};

/// Current ORT protocol version (bound into every client signature).
pub const PROTOCOL_VERSION: u16 = 1;

/// Domain-separation label for the client binding signature.
pub const CLIENT_BINDING_LABEL: &[u8] = b"ORT-v1 connmeta";

/// Per-connection metadata, signed by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnMeta {
    /// Client source IP as 16 bytes (IPv6, or IPv4-mapped). For 1-RTT this is
    /// the server-observed IP echoed from ServerHello (NAT-safe).
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
/// `LABEL || version || sig_alg || canonical(cm) || client_pk || offers_hash || H(enc_data)`.
pub fn client_binding_msg(
    version: u16,
    sig_alg: SuiteId,
    cm: &ConnMeta,
    client_pk: &[u8],
    offers_hash: &[u8; 32],
    enc_data: &[u8],
) -> Vec<u8> {
    let ed_hash = prim::hash256(enc_data);
    let mut msg = Vec::with_capacity(CLIENT_BINDING_LABEL.len() + 4 + 56 + client_pk.len() + 64);
    msg.extend_from_slice(CLIENT_BINDING_LABEL);
    msg.extend_from_slice(&version.to_be_bytes());
    msg.extend_from_slice(&sig_alg.code().to_be_bytes());
    msg.extend_from_slice(&cm.canonical());
    msg.extend_from_slice(client_pk);
    msg.extend_from_slice(offers_hash);
    msg.extend_from_slice(&ed_hash);
    msg
}

/// Sign the client binding with the client's signing identity (its suite id is
/// used as `sig_alg`).
pub fn sign_client_binding(
    identity: &SigIdentity,
    cm: &ConnMeta,
    client_pk: &[u8],
    offers_hash: &[u8; 32],
    enc_data: &[u8],
) -> Vec<u8> {
    let msg = client_binding_msg(
        PROTOCOL_VERSION,
        identity.suite_id(),
        cm,
        client_pk,
        offers_hash,
        enc_data,
    );
    identity.sign(&msg)
}

/// Verify the client binding signature under `sig_alg` with `client_pk`.
pub fn verify_client_binding(
    sig_alg: SuiteId,
    client_pk: &[u8],
    cm: &ConnMeta,
    offers_hash: &[u8; 32],
    enc_data: &[u8],
    sig: &[u8],
) -> Result<()> {
    let msg = client_binding_msg(
        PROTOCOL_VERSION,
        sig_alg,
        cm,
        client_pk,
        offers_hash,
        enc_data,
    );
    agile::sig_verify(sig_alg, client_pk, &msg, sig)
}
