//! AEAD record layer: seals/opens application records using the session key
//! and pool-derived nonces. Directions are independent so both peers stay in
//! lock-step regardless of interleaving.

use crate::kdf::SessionKeys;
use crate::pool::{Direction, EntropyPool};
use crate::suite::CipherSuite;
use crate::Result;
use core::marker::PhantomData;

/// AAD domain label (10 bytes) bound into every record.
pub const RECORD_AAD_LABEL: &[u8; 10] = b"ORT-v1 rec";

/// AAD = `label(10) || dir(1) || counter_be(8)` — binds direction and sequence
/// so reordered or cross-direction records fail authentication.
fn record_aad(dir: Direction, counter: u64) -> [u8; 19] {
    let mut aad = [0u8; 19];
    aad[..10].copy_from_slice(RECORD_AAD_LABEL);
    aad[10] = dir as u8;
    aad[11..].copy_from_slice(&counter.to_be_bytes());
    aad
}

/// Stateful AEAD record layer for one established session.
pub struct RecordLayer<S: CipherSuite> {
    keys: SessionKeys,
    pool: EntropyPool,
    _suite: PhantomData<S>,
}

impl<S: CipherSuite> RecordLayer<S> {
    /// Build the record layer from derived session keys and the ConnMeta nonce.
    pub fn new(keys: SessionKeys, connmeta_nonce: &[u8; 32]) -> Self {
        let pool = EntropyPool::new(&keys.pool_key, connmeta_nonce);
        RecordLayer {
            keys,
            pool,
            _suite: PhantomData,
        }
    }

    /// Seal `plaintext` for `dir`, returning `ciphertext || tag`.
    pub fn seal(&mut self, dir: Direction, plaintext: &[u8]) -> Vec<u8> {
        let counter = self.pool.counter(dir);
        let nonce = self.pool.next_nonce(dir);
        let aad = record_aad(dir, counter);
        let ct = S::aead_seal(&self.keys.enc_key, &nonce, &aad, plaintext);
        self.pool.absorb(dir, &ct);
        ct
    }

    /// Open a `ciphertext || tag` record for `dir`.
    pub fn open(&mut self, dir: Direction, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let counter = self.pool.counter(dir);
        let nonce = self.pool.next_nonce(dir);
        let aad = record_aad(dir, counter);
        let pt = S::aead_open(&self.keys.enc_key, &nonce, &aad, ciphertext)?;
        self.pool.absorb(dir, ciphertext);
        Ok(pt)
    }

    /// BLAKE3-512 of the AEAD key, used for 0-RTT key confirmation (ServerAck).
    pub fn enc_key_hash(&self) -> [u8; 64] {
        S::hash512(&self.keys.enc_key)
    }
}
