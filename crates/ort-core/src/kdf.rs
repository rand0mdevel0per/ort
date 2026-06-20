//! Key schedule.
//!
//! A fresh random **session key** `enc_sk` (the DEK) is generated per
//! connection and encrypts the application data. For each offered suite the
//! client wraps a copy of `enc_sk` under a key derived from that suite's KEM
//! shared secret, so the server can adopt whichever offered suite it supports
//! and recover the same `enc_sk`. Because `enc_sk` is random per connection,
//! the derived record keys are unique — no cross-session `(key, nonce)` reuse.

use crate::prim;
use crate::{Error, Result};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// HKDF `info` label for the AEAD record key.
pub const INFO_ENC_KEY: &[u8] = b"ORT-v1 enc-key";
/// HKDF `info` label for the entropy-pool key.
pub const INFO_POOL_KEY: &[u8] = b"ORT-v1 pool-key";
/// HKDF `info` label for the per-suite `enc_sk` wrapping key.
pub const INFO_WRAP_KEY: &[u8] = b"ORT-v1 wrap-key";
/// Fixed nonce for the single-use `enc_sk` wrap (the wrap key is used once).
const WRAP_NONCE: [u8; prim::NONCE_LEN] = [0u8; prim::NONCE_LEN];

/// The secrets that drive a single ORT session's record layer.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// AES-256-GCM record key.
    pub enc_key: [u8; 32],
    /// Seed key for the per-session entropy pool / nonce sequencer.
    pub pool_key: [u8; 32],
}

impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionKeys(..redacted..)")
    }
}

/// Generate a fresh random session key (`enc_sk`).
pub fn generate_enc_sk() -> Result<Zeroizing<[u8; 32]>> {
    let mut sk = Zeroizing::new([0u8; 32]);
    crate::suite::fill_random(&mut sk[..])?;
    Ok(sk)
}

/// Derive the record-layer keys from the session key `enc_sk`, salted by the
/// per-connection ConnMeta nonce.
pub fn derive_session_keys(enc_sk: &[u8; 32], nonce: &[u8; 32]) -> SessionKeys {
    let mut enc_key = [0u8; 32];
    prim::hkdf(enc_sk, nonce, INFO_ENC_KEY, &mut enc_key);
    let mut pool_key = [0u8; 32];
    prim::hkdf(enc_sk, nonce, INFO_POOL_KEY, &mut pool_key);
    SessionKeys { enc_key, pool_key }
}

/// Derive the wrapping key for `enc_sk` from a suite's KEM shared secret,
/// bound to that suite's ciphertext.
fn wrap_key(shared: &[u8; 32], ciphertext: &[u8]) -> Zeroizing<[u8; 32]> {
    let salt = prim::hash256(ciphertext);
    let mut k = Zeroizing::new([0u8; 32]);
    prim::hkdf(shared, &salt, INFO_WRAP_KEY, &mut k[..]);
    k
}

/// Seal a copy of `enc_sk` for one suite, AAD-bound to the suite id.
pub fn wrap_enc_sk(
    shared: &[u8; 32],
    ciphertext: &[u8],
    suite_id: u16,
    enc_sk: &[u8; 32],
) -> Vec<u8> {
    let k = wrap_key(shared, ciphertext);
    prim::aead_seal(&k, &WRAP_NONCE, &suite_id.to_be_bytes(), enc_sk)
}

/// Recover `enc_sk` from a wrapped copy using a suite's KEM shared secret.
pub fn unwrap_enc_sk(
    shared: &[u8; 32],
    ciphertext: &[u8],
    suite_id: u16,
    wrapped: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let k = wrap_key(shared, ciphertext);
    let pt = prim::aead_open(&k, &WRAP_NONCE, &suite_id.to_be_bytes(), wrapped)?;
    let arr: [u8; 32] = pt
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed("wrapped enc_sk length"))?;
    Ok(Zeroizing::new(arr))
}
