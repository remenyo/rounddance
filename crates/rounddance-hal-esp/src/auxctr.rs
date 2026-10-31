//! Auxiliary frame-counter space with NVM persistence hooks (Phase 4).
//!
//! A reboot restarts a RAM-only counter at its base while live peers
//! still hold the pre-reboot high-water in their replay tables: every
//! post-reboot frame then misclassifies as replay and the join wedges
//! until the peer reboots too (observed class after B-008
//! crash-reboots). The fix persists a chunk high-water in NVS; this
//! module owns the chunk arithmetic, the firmware owns the NVS bytes.
//!
//! Protocol (the firmware MUST follow this order per secured frame):
//! `poll_checkpoint` → persist if `Some` → `take` → seal + transmit.
//! Every radiated counter's chunk is therefore persisted before its
//! frame goes on air; a crash can only lose counters from frames that
//! were never transmitted (safe to reuse). `take` saturates at
//! [`u32::MAX`] instead of wrapping: a stuck counter is a loud,
//! fail-obvious outage, while a wrap is silent replay-acceptance.
//!
//! `no_std`, no allocation, no atomics (caller serializes access).

/// Values per persisted chunk: one NVS write per this many secured
/// frames worst case (fewer when idle). Small enough to bound reuse
/// after a crash-before-persist, large enough to spare NVS wear.
pub const AUX_CHUNK: u32 = 64;

/// Monotonic auxiliary counter with persist-before-use checkpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuxCounter {
    next: u32,
    /// Highest chunk index reported to the firmware yet (`None` when
    /// nothing was reported this boot).
    reported: Option<u32>,
}

impl AuxCounter {
    /// Start at `base` (deployment floor, e.g. the lab
    /// `TRANSPORT_AUX_BASE`); the base chunk is due for persistence
    /// on the first poll so a crash before any write still resumes
    /// above it.
    #[must_use]
    pub const fn fresh(base: u32) -> Self {
        Self {
            next: base,
            reported: None,
        }
    }

    /// Resume after a reboot: `saved_chunk` is the highest chunk the
    /// firmware persisted (its NVS read, or `None` on a fresh part).
    /// Restarts strictly above every counter whose chunk was
    /// persisted; floors at `base` so a stale/lagging NVS never
    /// rewinds below the deployment floor.
    #[must_use]
    pub const fn resume(saved_chunk: Option<u32>, base: u32) -> Self {
        let next = match saved_chunk {
            // Next chunk after the persisted one (saturating: the
            // counter space is effectively inexhaustible, and
            // saturating beats wrapping).
            Some(s) => s.saturating_add(1).saturating_mul(AUX_CHUNK),
            None => base,
        };
        let next = if next < base { base } else { next };
        Self {
            next,
            reported: None,
        }
    }

    /// Take the next counter value (saturates at [`u32::MAX`], never
    /// wraps — see module docs).
    #[must_use]
    pub fn take(&mut self) -> u32 {
        let v = self.next;
        self.next = self.next.saturating_add(1);
        v
    }

    /// Chunk index covering [`take`](Self::take)'s next value, once
    /// per chunk: persist the returned chunk BEFORE transmitting any
    /// frame sealed under a counter from it. Returns `None` when the
    /// current chunk was already reported.
    pub fn poll_checkpoint(&mut self) -> Option<u32> {
        let c = self.next / AUX_CHUNK;
        if self.reported == Some(c) {
            None
        } else {
            self.reported = Some(c);
            Some(c)
        }
    }
}
