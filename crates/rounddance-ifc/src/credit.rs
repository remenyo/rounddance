//! Backpressure: credit-based bounded send queues.
//!
//! Every IFC sender owns a fixed number of outstanding-transaction
//! slots (like [`MacDataSap`](https://github.com/remenyo/rounddance)
//! `tx_queue_free`). `send` fails with [`IfcError::QueueFull`] instead
//! of blocking or growing memory; the peer returns one credit per
//! completed transaction. Poll-based: no callbacks, no locks.

use crate::IfcError;

/// Fixed-slot credit window. `const N`: outstanding slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Credits<const N: usize> {
    used: usize,
}

impl<const N: usize> Credits<N> {
    /// Empty window (all `N` credits free).
    #[must_use]
    pub const fn new() -> Self {
        Self { used: 0 }
    }

    /// Take one credit for a new transaction.
    pub fn take(&mut self) -> Result<(), IfcError> {
        if self.used >= N {
            return Err(IfcError::QueueFull);
        }
        self.used += 1;
        Ok(())
    }

    /// Return one credit when a transaction completes. Unknown/extra
    /// completions are ignored (idempotent — never underflows).
    pub fn give(&mut self) {
        self.used = self.used.saturating_sub(1);
    }

    /// Free slots right now.
    #[must_use]
    pub const fn free(&self) -> usize {
        N - self.used
    }

    /// Total slots (constant per provisioning).
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// True when [`Credits::take`] would fail.
    #[must_use]
    pub const fn full(&self) -> bool {
        self.used >= N
    }

    /// Forget all outstanding transactions (link reset). Fresh state
    /// after reconnect starts here, plus the peer's `RESUME` seq check.
    pub fn reset(&mut self) {
        self.used = 0;
    }
}

impl<const N: usize> Default for Credits<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Versioned exportable link state (migration skeleton, `semantics.md`).
/// `next_seq` values are per-direction counters; import MUST reject a
/// snapshot whose counters moved backwards (see `security-handoff`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkSnapshot {
    /// Snapshot format version (1 for this skeleton).
    pub format: u8,
    /// Next transmit sequence number.
    pub next_tx_seq: u16,
    /// Highest received sequence number.
    pub last_rx_seq: u16,
    /// Outstanding (unconfirmed) transaction count.
    pub outstanding: u16,
}

impl LinkSnapshot {
    /// Capture from live counters.
    #[must_use]
    pub const fn capture(next_tx_seq: u16, last_rx_seq: u16, outstanding: u16) -> Self {
        Self {
            format: 1,
            next_tx_seq,
            last_rx_seq,
            outstanding,
        }
    }

    /// Validate against the *current* live counters before applying:
    /// counters must not move backwards. Returns the snapshot on
    /// success, [`IfcError::BadFrame`] on rollback.
    pub fn check_against(&self, live_tx: u16, live_rx: u16) -> Result<Self, IfcError> {
        if self.format != 1 {
            return Err(IfcError::VersionMismatch);
        }
        // Counter rollback check with wrap-aware comparison: a snapshot
        // is "backwards" when it lies more than half the u16 range
        // behind the live value (same rule as the reconnect path).
        if wrapping_behind(self.next_tx_seq, live_tx) || wrapping_behind(self.last_rx_seq, live_rx)
        {
            return Err(IfcError::BadFrame);
        }
        Ok(*self)
    }
}

/// True when `a` is strictly behind `b` on the wrapping u16 ring.
#[must_use]
pub const fn wrapping_behind(a: u16, b: u16) -> bool {
    a != b && b.wrapping_sub(a) < 0x8000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credit_window_exhausts_and_recovers() {
        let mut c = Credits::<2>::new();
        c.take().unwrap();
        c.take().unwrap();
        assert_eq!(c.take(), Err(IfcError::QueueFull));
        assert!(c.full());
        c.give();
        assert_eq!(c.free(), 1);
        c.take().unwrap();
    }

    #[test]
    fn give_is_idempotent() {
        let mut c = Credits::<1>::new();
        c.give();
        c.give();
        assert_eq!(c.free(), 1);
    }

    #[test]
    fn snapshot_rejects_rollback() {
        let live = LinkSnapshot::capture(100, 90, 0);
        let ok = LinkSnapshot::capture(100, 90, 0);
        assert!(ok.check_against(live.next_tx_seq, live.last_rx_seq).is_ok());
        let stale = LinkSnapshot::capture(50, 90, 0);
        assert_eq!(
            stale.check_against(live.next_tx_seq, live.last_rx_seq),
            Err(IfcError::BadFrame)
        );
    }
}
