//! Anti-replay: a [`ReplayGuard`] rejects replayed ClientHellos within the
//! acceptance window. The handshake depends only on the trait; `ort-net`
//! provides a sharded high-concurrency implementation, while this module's
//! [`StrikeCache`] is a simple mutex-backed version used in tests. The cache
//! tag is `ConnMeta::replay_tag` — `BLAKE3-256(src_ip || ts || offer_nonce)`,
//! small and independent of the early data.

use crate::{Error, Result};
use std::collections::HashMap;
use std::sync::Mutex;

/// A windowed replay guard. Implementations must be safe to share across tasks
/// (`&self`), perform an atomic check-and-insert, and not hold any lock across
/// the caller's subsequent cryptographic work.
pub trait ReplayGuard: Send + Sync {
    /// Record `tag` at `now_ms`; return [`Error::Replayed`] if already present
    /// within the window. Evicts expired entries.
    fn check_and_insert(&self, tag: [u8; 32], now_ms: u64) -> Result<()>;
}

struct Inner {
    entries: HashMap<[u8; 32], u64>,
}

/// Simple mutex-backed strike cache (used in tests; `ort-net` has a lock-free one).
pub struct StrikeCache {
    window_ms: u64,
    inner: Mutex<Inner>,
}

impl StrikeCache {
    /// Create a cache remembering tags for `window_ms` milliseconds.
    pub fn new(window_ms: u64) -> Self {
        StrikeCache {
            window_ms,
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
            }),
        }
    }

    /// Current entry count (for tests).
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ReplayGuard for StrikeCache {
    fn check_and_insert(&self, tag: [u8; 32], now_ms: u64) -> Result<()> {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        let mut g = self.inner.lock().unwrap();
        g.entries.retain(|_, &mut seen| seen >= cutoff);
        if g.entries.contains_key(&tag) {
            return Err(Error::Replayed);
        }
        g.entries.insert(tag, now_ms);
        Ok(())
    }
}
