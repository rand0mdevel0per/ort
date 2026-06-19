//! Per-session entropy pool and nonce sequencer.
//!
//! Each direction owns an independent BLAKE3-keyed pool so the two directions
//! never desynchronize regardless of how their records interleave on the wire.
//! A nonce is `XOF(pool_state || counter)`; the monotonic per-direction counter
//! guarantees uniqueness within a session, and after every record the
//! ciphertext (plus any exchanged random blob) is absorbed back into the pool
//! so subsequent nonces are unpredictable to an observer while staying
//! identical on both peers (they absorb the same wire bytes in the same order).

use crate::suite::NONCE_LEN;
use zeroize::ZeroizeOnDrop;

/// Direction of a record stream. Selects an independent sub-pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    /// Client → server.
    ClientToServer = 0,
    /// Server → client.
    ServerToClient = 1,
}

impl Direction {
    /// The opposite direction.
    pub fn flip(self) -> Direction {
        match self {
            Direction::ClientToServer => Direction::ServerToClient,
            Direction::ServerToClient => Direction::ClientToServer,
        }
    }

    fn label(self) -> &'static [u8] {
        match self {
            Direction::ClientToServer => b"ORT-v1 pool c2s",
            Direction::ServerToClient => b"ORT-v1 pool s2c",
        }
    }
}

/// One direction's keyed pool + monotonic counter.
struct DirPool {
    state: blake3::Hasher,
    counter: u64,
}

impl DirPool {
    fn new(pool_key: &[u8; 32], dir: Direction, seed: &[u8]) -> Self {
        let mut state = blake3::Hasher::new_keyed(pool_key);
        state.update(dir.label());
        state.update(seed);
        DirPool { state, counter: 0 }
    }

    fn next_nonce(&mut self) -> [u8; NONCE_LEN] {
        let mut h = self.state.clone();
        h.update(&self.counter.to_be_bytes());
        let mut nonce = [0u8; NONCE_LEN];
        h.finalize_xof().fill(&mut nonce);
        self.counter += 1;
        nonce
    }

    fn absorb(&mut self, data: &[u8]) {
        self.state.update(b"ORT-v1 absorb");
        self.state.update(data);
    }
}

/// The full per-session entropy pool: one sub-pool per direction.
pub struct EntropyPool {
    c2s: DirPool,
    s2c: DirPool,
}

impl ZeroizeOnDrop for EntropyPool {}

impl EntropyPool {
    /// Create a pool from the session `pool_key` and the ConnMeta nonce (which
    /// is fresh per connection, mixing extra per-session uniqueness in).
    pub fn new(pool_key: &[u8; 32], connmeta_nonce: &[u8; 32]) -> Self {
        EntropyPool {
            c2s: DirPool::new(pool_key, Direction::ClientToServer, connmeta_nonce),
            s2c: DirPool::new(pool_key, Direction::ServerToClient, connmeta_nonce),
        }
    }

    fn dir(&mut self, dir: Direction) -> &mut DirPool {
        match dir {
            Direction::ClientToServer => &mut self.c2s,
            Direction::ServerToClient => &mut self.s2c,
        }
    }

    /// Next nonce for `dir`. Advances that direction's counter.
    pub fn next_nonce(&mut self, dir: Direction) -> [u8; NONCE_LEN] {
        self.dir(dir).next_nonce()
    }

    /// Mix a record's ciphertext (and optional exchanged random) back into the
    /// pool for `dir`. Must be called identically on both peers after each
    /// record so the streams stay in lock-step.
    pub fn absorb(&mut self, dir: Direction, ciphertext: &[u8]) {
        self.dir(dir).absorb(ciphertext);
    }

    /// The current counter for a direction (number of nonces drawn so far).
    pub fn counter(&self, dir: Direction) -> u64 {
        match dir {
            Direction::ClientToServer => self.c2s.counter,
            Direction::ServerToClient => self.s2c.counter,
        }
    }
}
