//! Host clock backend: explicit-tick time for deterministic runs,
//! plus a wall-clock helper for live Pi tooling.
//!
//! The deterministic path never reads the OS clock: time only moves
//! via [`HostClock::advance`], so native and WASM runs with the same
//! script agree tick-for-tick (`SCOPE.md` §2).

use std::time::{SystemTime, UNIX_EPOCH};

/// Explicit-tick host clock: current time in microseconds.
///
/// Starts at zero (or a caller-supplied epoch) and moves only via
/// [`HostClock::advance`]. Saturates instead of wrapping, matching
/// the sim [`rounddance_sim::VirtualClock`] contract.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct HostClock {
    now_us: u64,
}

impl HostClock {
    /// Clock starting at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self { now_us: 0 }
    }

    /// Clock starting at `now_us` (e.g. a persisted resume mark).
    #[must_use]
    pub const fn at(now_us: u64) -> Self {
        Self { now_us }
    }

    /// Current time in microseconds.
    #[must_use]
    pub const fn now_us(self) -> u64 {
        self.now_us
    }

    /// Move time forward; saturates instead of wrapping.
    pub fn advance(&mut self, delta_us: u64) {
        self.now_us = self.now_us.saturating_add(delta_us);
    }
}

/// Live wall-clock readout in microseconds since the Unix epoch.
///
/// Returns `None` when the OS clock is unavailable or before the
/// epoch. Live tooling only — deterministic runs (and the WASM
/// replay leg) must use [`HostClock`], never this.
#[must_use]
pub fn wall_now_us() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_micros().min(u128::from(u64::MAX)) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_only_moves_explicitly() {
        let mut c = HostClock::new();
        assert_eq!(c.now_us(), 0);
        c.advance(150);
        assert_eq!(c.now_us(), 150);
        c.advance(u64::MAX);
        assert_eq!(c.now_us(), u64::MAX, "saturates, never wraps");
    }

    #[test]
    fn wall_clock_is_sane_when_available() {
        if let Some(now) = wall_now_us() {
            // Past 2026-01-01 in microseconds.
            assert!(now > 1_767_225_600_000_000);
        }
    }
}
