//! Key schedule: derive per-session keys from the KEM shared secret.
//!
//! Because the shared secret `k_sk` is fresh every connection (the client uses
//! a fresh encapsulation seed `r`), the derived `enc_key`/`pool_key` are unique
//! per session — there is no cross-session `(key, nonce)` reuse to worry about.

use crate::suite::CipherSuite;
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

/// Derive the session keys from the KEM shared secret and the on-wire
/// ciphertext (which both peers see, and which binds the derivation to this
/// specific encapsulation).
pub fn derive_session_keys<S: CipherSuite>(k_sk: &[u8; 32], ciphertext: &[u8]) -> SessionKeys {
    let salt = S::hash256(ciphertext);
    let mut enc_key = [0u8; 32];
    S::hkdf(k_sk, &salt, INFO_ENC_KEY, &mut enc_key);
    let mut pool_key = [0u8; 32];
    S::hkdf(k_sk, &salt, INFO_POOL_KEY, &mut pool_key);
    SessionKeys { enc_key, pool_key }
}
