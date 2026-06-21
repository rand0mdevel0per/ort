//! High-concurrency replay guard for the server's global anti-replay hotspot.
//!
//! The cache is **sharded**: tags are partitioned across many independent
//! shards (by a prefix of the tag), each a small `Mutex<HashMap>`. A shard lock
//! is held only for the O(1) membership check + insert (and an occasional
//! bounded eviction sweep) — never across any cryptographic work — so under
//! load threads contend only when they hit the same shard. Each shard evicts
//! entries older than the window via `HashMap::retain`, run at most once per
//! half-window, which keeps the cache bounded to roughly one window of traffic.
//! (This avoids the FIFO-reordering / unbounded-growth pitfalls of a naive
//! queue-based evictor.)

use ort_core::replay::ReplayGuard;
use ort_core::{Error, Result};
use std::collections::HashMap;
use std::sync::Mutex;

const SHARDS: usize = 64;

struct Shard {
    entries: HashMap<[u8; 32], u64>,
    last_evict: u64,
}

/// Sharded, self-evicting strike cache.
pub struct ConcurrentStrikeCache {
    window_ms: u64,
    shards: Vec<Mutex<Shard>>,
}

impl ConcurrentStrikeCache {
    /// Create a cache remembering tags for `window_ms` milliseconds.
    pub fn new(window_ms: u64) -> Self {
        let shards = (0..SHARDS)
            .map(|_| Mutex::new(Shard { entries: HashMap::new(), last_evict: 0 }))
            .collect();
        ConcurrentStrikeCache { window_ms, shards }
    }

    fn shard_for(&self, tag: &[u8; 32]) -> &Mutex<Shard> {
        // Top two bytes give a stable, well-distributed shard index.
        let idx = ((tag[0] as usize) << 8 | tag[1] as usize) % SHARDS;
        &self.shards[idx]
    }

    /// Approximate total membership (for tests/metrics).
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap().entries.len()).sum()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ReplayGuard for ConcurrentStrikeCache {
    fn check_and_insert(&self, tag: [u8; 32], now_ms: u64) -> Result<()> {
        let mut shard = self.shard_for(&tag).lock().unwrap();
        // Evict at most once per half-window to bound amortized cost.
        if now_ms.saturating_sub(shard.last_evict) > self.window_ms / 2 {
            let cutoff = now_ms.saturating_sub(self.window_ms);
            shard.entries.retain(|_, &mut seen| seen >= cutoff);
            shard.last_evict = now_ms;
        }
        if shard.entries.contains_key(&tag) {
            return Err(Error::Replayed);
        }
        shard.entries.insert(tag, now_ms);
        Ok(())
    }
}
