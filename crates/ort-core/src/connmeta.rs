//! ConnMeta — connection-level metadata the client signs, plus helpers to
//! build/verify the binding signature. The signed message commits to the
//! protocol version, the signature algorithm, the source IP, the timestamp,
//! hashes of both the client signing key and the ephemeral KEM key, and all KEM
//! offers (via `offers_hash`) — so none of these can be altered. Using BLAKE3
//! hashes instead of full keys keeps ConnMeta compact and fixed-size.

use crate::suite::agile::{self, SigIdentity};
use crate::suite::SuiteId;
use crate::{prim, Result};

/// Current ORT protocol version (bound into every client signature).
pub const PROTOCOL_VERSION: u16 = 1;

/// Domain-separation label for the client binding signature.
pub const CLIENT_BINDING_LABEL: &[u8] = b"ORT-v1 connmeta";

/// Connection-level metadata, signed by the client. Per-offer nonces live in
/// each [`ort_proto::SuiteOffer`] and are covered by `offers_hash`. Client keys
/// are bound via their BLAKE3 hashes for compactness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnMeta {
    /// Client source IP as 16 bytes (IPv6, or IPv4-mapped). For 1-RTT this is
    /// the server-observed IP echoed from ServerHello (NAT-safe).
    pub src_ip: [u8; 16],
    /// Client timestamp in milliseconds since the Unix epoch.
    pub ts_millis: u64,
    /// BLAKE3-256 hash of the client's signing public key.
    pub sig_pk_hash: [u8; 32],
    /// BLAKE3-256 hash of the client's ephemeral KEM public key (for Half-RTT).
    pub kem_pk_hash: [u8; 32],
}

impl ConnMeta {
    /// Canonical byte encoding (88 bytes): `src_ip(16) || ts_be(8) || sig_pk_hash(32) || kem_pk_hash(32)`.
    pub fn canonical(&self) -> [u8; 88] {
        let mut out = [0u8; 88];
        out[..16].copy_from_slice(&self.src_ip);
        out[16..24].copy_from_slice(&self.ts_millis.to_be_bytes());
        out[24..56].copy_from_slice(&self.sig_pk_hash);
        out[56..88].copy_from_slice(&self.kem_pk_hash);
        out
    }

    /// Replay-cache tag: `BLAKE3-256(src_ip || ts || offer_nonce)`. Small and
    /// independent of the (potentially large) early data.
    pub fn replay_tag(&self, offer_nonce: &[u8; 32]) -> [u8; 32] {
        let mut buf = [0u8; 24 + 32];
        buf[..16].copy_from_slice(&self.src_ip);
        buf[16..24].copy_from_slice(&self.ts_millis.to_be_bytes());
        buf[24..].copy_from_slice(offer_nonce);
        prim::hash256(&buf)
    }
}

/// Build the message the client signs. Instead of signing ConnMeta directly, we
/// sign its BLAKE3-256 hash for efficiency (ConnMeta is 88 bytes).
/// `LABEL || version || sig_alg || BLAKE3(connmeta_canonical) || offers_hash`.
pub fn client_binding_msg(
    version: u16,
    sig_alg: SuiteId,
    cm: &ConnMeta,
    offers_hash: &[u8; 32],
) -> Vec<u8> {
    let cm_hash = prim::hash256(&cm.canonical());
    let mut msg = Vec::with_capacity(CLIENT_BINDING_LABEL.len() + 4 + 32 + 32);
    msg.extend_from_slice(CLIENT_BINDING_LABEL);
    msg.extend_from_slice(&version.to_be_bytes());
    msg.extend_from_slice(&sig_alg.code().to_be_bytes());
    msg.extend_from_slice(&cm_hash);
    msg.extend_from_slice(offers_hash);
    msg
}

/// Sign the client binding with the client's signing identity (its suite id is
/// used as `sig_alg`).
pub fn sign_client_binding(
    identity: &SigIdentity,
    cm: &ConnMeta,
    offers_hash: &[u8; 32],
) -> Vec<u8> {
    let msg = client_binding_msg(PROTOCOL_VERSION, identity.suite_id(), cm, offers_hash);
    identity.sign(&msg)
}

/// Verify the client binding signature under `sig_alg`.
pub fn verify_client_binding(
    sig_alg: SuiteId,
    client_pk: &[u8],
    cm: &ConnMeta,
    offers_hash: &[u8; 32],
    sig: &[u8],
) -> Result<()> {
    let msg = client_binding_msg(PROTOCOL_VERSION, sig_alg, cm, offers_hash);
    agile::sig_verify(sig_alg, client_pk, &msg, sig)
}
