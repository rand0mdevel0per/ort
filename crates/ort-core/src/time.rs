//! Time abstraction so the handshake's replay window can be tested
//! deterministically with a mock clock.

use crate::{Error, Result};

/// A source of wall-clock time in milliseconds since the Unix epoch.
pub trait Clock {
    /// Current time in milliseconds since the Unix epoch.
    fn now_millis(&self) -> u64;
}

/// Real system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// A fixed/mock clock for tests. Time only advances when explicitly set.
#[derive(Debug, Clone)]
pub struct FixedClock(std::sync::Arc<std::sync::atomic::AtomicU64>);

impl FixedClock {
    /// Create a clock pinned at `millis`.
    pub fn new(millis: u64) -> Self {
        FixedClock(std::sync::Arc::new(std::sync::atomic::AtomicU64::new(millis)))
    }
    /// Set the current time.
    pub fn set(&self, millis: u64) {
        self.0.store(millis, std::sync::atomic::Ordering::SeqCst);
    }
    /// Advance the clock by `delta` milliseconds.
    pub fn advance(&self, delta: u64) {
        self.0.fetch_add(delta, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now_millis(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Validate a ConnMeta timestamp against the anti-replay window.
///
/// Accepts `ts` if it is no more than `skew_ms` in the future (clock skew
/// tolerance) and no more than `window_ms` in the past.
pub fn check_window(now_ms: u64, ts_ms: u64, window_ms: u64, skew_ms: u64) -> Result<()> {
    if ts_ms > now_ms.saturating_add(skew_ms) {
        return Err(Error::StaleTimestamp); // too far in the future
    }
    if now_ms.saturating_sub(ts_ms) > window_ms {
        return Err(Error::StaleTimestamp); // too old
    }
    Ok(())
}
