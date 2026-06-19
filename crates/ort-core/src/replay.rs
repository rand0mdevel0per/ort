//! A bounded, self-evicting strike cache that rejects replayed 0-RTT
//! ClientHellos within the anti-replay window.
//!
//! The cache stores `BLAKE3-256(nonce || enc_data)` for each accepted
//! ClientHello together with its arrival time, and evicts entries older than
//! the window. Combined with the signed-timestamp window check and the source
//! IP binding, this closes in-window replay. It is the server's only mutable
//! state and is bounded by the number of concurrent handshakes within one
//! window.

use crate::suite::CipherSuite;
use crate::{Error, Result};
use std::collections::HashMap;

/// Compute the replay-cache tag for a ClientHello.
pub fn replay_tag<S: CipherSuite>(nonce: &[u8; 32], enc_data: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + enc_data.len());
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(enc_data);
    S::hash256(&buf)
}

/// A time-windowed set of seen ClientHello tags.
#[derive(Debug)]
pub struct StrikeCache {
    window_ms: u64,
    entries: HashMap<[u8; 32], u64>,
    last_evict: u64,
}

impl StrikeCache {
    /// Create a cache that remembers tags for `window_ms` milliseconds.
    pub fn new(window_ms: u64) -> Self {
        StrikeCache {
            window_ms,
            entries: HashMap::new(),
            last_evict: 0,
        }
    }

    /// Drop entries older than the window relative to `now_ms`.
    pub fn evict(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        self.entries.retain(|_, &mut seen| seen >= cutoff);
        self.last_evict = now_ms;
    }

    /// Check a tag and, if unseen, record it. Returns `Err(Replayed)` if the
    /// tag was already present within the window.
    pub fn check_and_insert(&mut self, tag: [u8; 32], now_ms: u64) -> Result<()> {
        self.evict(now_ms);
        if self.entries.contains_key(&tag) {
            return Err(Error::Replayed);
        }
        self.entries.insert(tag, now_ms);
        Ok(())
    }

    /// Current number of cached entries (for tests/metrics).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
