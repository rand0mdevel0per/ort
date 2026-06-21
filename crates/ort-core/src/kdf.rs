//! Key schedule.
//!
//! Each connection (and each per-suite offer) derives its session keys directly
//! from that suite's KEM shared secret `k_sk` and a fresh per-offer `nonce`:
//! `enc_sk = HKDF(k_sk, salt = nonce)`. There is no key shared across suites
//! (each offer's keys come only from its own KEM secret), and `k_sk` is fresh
//! per connection (the client uses a fresh encapsulation seed), so the derived
//! record keys are unique — no cross-session `(key, nonce)` reuse.

use crate::prim;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HKDF `info` label for the AEAD record key.
pub const INFO_ENC_KEY: &[u8] = b"ORT-v1 enc-key";
/// HKDF `info` label for the entropy-pool key.
pub const INFO_POOL_KEY: &[u8] = b"ORT-v1 pool-key";

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

/// Derive the record-layer keys from the KEM shared secret `k_sk`, salted by the
/// per-offer `nonce`.
pub fn derive_session_keys(k_sk: &[u8; 32], nonce: &[u8; 32]) -> SessionKeys {
    let mut enc_key = [0u8; 32];
    prim::hkdf(k_sk, nonce, INFO_ENC_KEY, &mut enc_key);
    let mut pool_key = [0u8; 32];
    prim::hkdf(k_sk, nonce, INFO_POOL_KEY, &mut pool_key);
    SessionKeys { enc_key, pool_key }
}
