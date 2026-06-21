//! AEAD record layer: seals/opens application records using the session key
//! and pool-derived nonces. Directions are independent so both peers stay in
//! lock-step regardless of interleaving. Suite-independent (fixed AES-256-GCM +
//! BLAKE3), so an established session is identical whatever suite was used.

use crate::kdf::SessionKeys;
use crate::pool::{DirChannel, Direction, EntropyPool};
use crate::prim::{self, NONCE_LEN};
use crate::Result;
use zeroize::Zeroizing;

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
pub struct RecordLayer {
    keys: SessionKeys,
    pool: EntropyPool,
}

impl RecordLayer {
    /// Build the record layer from derived session keys and the ConnMeta nonce.
    pub fn new(keys: SessionKeys, connmeta_nonce: &[u8; 32]) -> Self {
        let pool = EntropyPool::new(&keys.pool_key, connmeta_nonce);
        RecordLayer { keys, pool }
    }

    /// Seal `plaintext` for `dir`, returning `ciphertext || tag`.
    pub fn seal(&mut self, dir: Direction, plaintext: &[u8]) -> Vec<u8> {
        let counter = self.pool.counter(dir);
        let nonce = self.pool.next_nonce(dir);
        let aad = record_aad(dir, counter);
        let ct = prim::aead_seal(&self.keys.enc_key, &nonce, &aad, plaintext);
        self.pool.absorb(dir, &ct);
        ct
    }

    /// Open a `ciphertext || tag` record for `dir`.
    pub fn open(&mut self, dir: Direction, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let counter = self.pool.counter(dir);
        let nonce = self.pool.next_nonce(dir);
        let aad = record_aad(dir, counter);
        let pt = prim::aead_open(&self.keys.enc_key, &nonce, &aad, ciphertext)?;
        self.pool.absorb(dir, ciphertext);
        Ok(pt)
    }

    /// BLAKE3-512 of the AEAD key, used for 0-RTT key confirmation (ServerAck).
    pub fn enc_key_hash(&self) -> [u8; 64] {
        prim::hash512(&self.keys.enc_key)
    }

    /// Split into independent send/receive halves so the two directions can be
    /// driven by separate tasks with no shared lock (true full duplex).
    /// `send_dir` is the direction this peer seals into.
    pub fn split(self, send_dir: Direction) -> (RecordSender, RecordReceiver) {
        let enc_key = Zeroizing::new(self.keys.enc_key);
        let (c2s, s2c) = self.pool.split();
        let (send_chan, recv_chan) = match send_dir {
            Direction::ClientToServer => (c2s, s2c),
            Direction::ServerToClient => (s2c, c2s),
        };
        (
            RecordSender {
                enc_key: enc_key.clone(),
                chan: send_chan,
            },
            RecordReceiver {
                enc_key,
                chan: recv_chan,
            },
        )
    }
}

/// The sending half of a split record layer (one direction). The key is held in
/// a `Zeroizing` wrapper so it is wiped when the half is dropped.
pub struct RecordSender {
    enc_key: Zeroizing<[u8; 32]>,
    chan: DirChannel,
}

impl RecordSender {
    /// Seal `plaintext`, returning `ciphertext || tag`.
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let counter = self.chan.counter();
        let nonce = self.chan.next_nonce();
        let aad = record_aad(self.chan.direction(), counter);
        let ct = prim::aead_seal(&self.enc_key, &nonce, &aad, plaintext);
        self.chan.absorb(&ct);
        ct
    }

    /// The direction this half seals into.
    pub fn direction(&self) -> Direction {
        self.chan.direction()
    }
}

/// The receiving half of a split record layer (one direction). The key is held
/// in a `Zeroizing` wrapper so it is wiped when the half is dropped.
pub struct RecordReceiver {
    enc_key: Zeroizing<[u8; 32]>,
    chan: DirChannel,
}

impl RecordReceiver {
    /// Open a `ciphertext || tag` record.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let counter = self.chan.counter();
        let nonce = self.chan.next_nonce();
        let aad = record_aad(self.chan.direction(), counter);
        let pt = prim::aead_open(&self.enc_key, &nonce, &aad, ciphertext)?;
        self.chan.absorb(ciphertext);
        Ok(pt)
    }

    /// The direction this half opens from.
    pub fn direction(&self) -> Direction {
        self.chan.direction()
    }
}

// Keep NONCE_LEN referenced for documentation of the record nonce size.
const _: () = assert!(NONCE_LEN == 12);
