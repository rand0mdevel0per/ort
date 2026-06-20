//! A lock-free-ish, high-concurrency replay guard for the server's global
//! anti-replay hotspot.
//!
//! Membership is a sharded [`DashSet`] (atomic check-and-insert); insertion
//! order is recorded in a lock-free [`SegQueue`] of `(tag, ts)`. Each operation
//! first drains the front of the queue of entries older than the window,
//! removing them from the set, so the cache self-bounds to roughly the number
//! of handshakes within one window. No lock is held across the caller's
//! cryptographic work — `check_and_insert` returns immediately.

use crossbeam_queue::SegQueue;
use dashmap::DashSet;
use ort_core::replay::ReplayGuard;
use ort_core::{Error, Result};

/// Concurrent strike cache.
pub struct ConcurrentStrikeCache {
    window_ms: u64,
    seen: DashSet<[u8; 32]>,
    order: SegQueue<([u8; 32], u64)>,
}

impl ConcurrentStrikeCache {
    /// Create a cache remembering tags for `window_ms` milliseconds.
    pub fn new(window_ms: u64) -> Self {
        ConcurrentStrikeCache {
            window_ms,
            seen: DashSet::new(),
            order: SegQueue::new(),
        }
    }

    fn evict(&self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        // Drain expired entries from the front. Entries are pushed in arrival
        // order, so the front is the oldest. If we pop a not-yet-expired entry
        // (possible only under clock non-monotonicity), push it back.
        while let Some((tag, ts)) = self.order.pop() {
            if ts < cutoff {
                self.seen.remove(&tag);
            } else {
                self.order.push((tag, ts));
                break;
            }
        }
    }

    /// Current membership size (approximate, for metrics/tests).
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl ReplayGuard for ConcurrentStrikeCache {
    fn check_and_insert(&self, tag: [u8; 32], now_ms: u64) -> Result<()> {
        self.evict(now_ms);
        // Atomic membership test+insert: `insert` returns false if already present.
        if !self.seen.insert(tag) {
            return Err(Error::Replayed);
        }
        self.order.push((tag, now_ms));
        Ok(())
    }
}
