//! Per-session entropy pool and nonce sequencer.
//!
//! Each direction owns an independent BLAKE3-keyed pool so the two directions
//! never desynchronize regardless of how their records interleave on the wire.
//! A nonce is `XOF(pool_state || counter)`; the monotonic per-direction counter
//! guarantees uniqueness within a session, and after every record the
//! ciphertext (plus any exchanged random blob) is absorbed back into the pool
//! so subsequent nonces are unpredictable to an observer while staying
//! identical on both peers (they absorb the same wire bytes in the same order).

use crate::prim::NONCE_LEN;
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

/// One direction's keyed pool + monotonic counter. Can stand alone so the
/// record layer can be split into independent send/receive halves.
pub struct DirChannel {
    state: blake3::Hasher,
    counter: u64,
    dir: Direction,
}

impl DirChannel {
    fn new(pool_key: &[u8; 32], dir: Direction, seed: &[u8]) -> Self {
        let mut state = blake3::Hasher::new_keyed(pool_key);
        state.update(dir.label());
        state.update(seed);
        DirChannel {
            state,
            counter: 0,
            dir,
        }
    }

    /// This channel's direction.
    pub fn direction(&self) -> Direction {
        self.dir
    }

    /// Next nonce; advances the counter.
    pub fn next_nonce(&mut self) -> [u8; NONCE_LEN] {
        let mut h = self.state.clone();
        h.update(&self.counter.to_be_bytes());
        let mut nonce = [0u8; NONCE_LEN];
        h.finalize_xof().fill(&mut nonce);
        self.counter += 1;
        nonce
    }

    /// Current counter (number of nonces drawn so far).
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Mix wire bytes back into the pool.
    pub fn absorb(&mut self, data: &[u8]) {
        self.state.update(b"ORT-v1 absorb");
        self.state.update(data);
    }
}

/// The full per-session entropy pool: one channel per direction.
pub struct EntropyPool {
    c2s: DirChannel,
    s2c: DirChannel,
}

impl ZeroizeOnDrop for EntropyPool {}

impl EntropyPool {
    /// Create a pool from the session `pool_key` and the ConnMeta nonce (which
    /// is fresh per connection, mixing extra per-session uniqueness in).
    pub fn new(pool_key: &[u8; 32], connmeta_nonce: &[u8; 32]) -> Self {
        EntropyPool {
            c2s: DirChannel::new(pool_key, Direction::ClientToServer, connmeta_nonce),
            s2c: DirChannel::new(pool_key, Direction::ServerToClient, connmeta_nonce),
        }
    }

    fn dir(&mut self, dir: Direction) -> &mut DirChannel {
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

    /// Split into the two per-direction channels `(client→server, server→client)`.
    pub fn split(self) -> (DirChannel, DirChannel) {
        (self.c2s, self.s2c)
    }
}
