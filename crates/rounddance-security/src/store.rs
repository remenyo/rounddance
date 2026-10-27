//! Pluggable non-volatile counter store with rollback protection.
//!
//! Paraphrase-level model of the persistence hook behind doc
//! `05-3474-23` R23.2 chapter 4 frame counters. All wording here is
//! paraphrase (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped), MINTED-pending-confirm,
//! anchored at §4.3.4 (p0425-L10232-L10236: counters survive factory
//! reset, reset only as specified).
//!
//! # Rollback-protection rule (normative)
//!
//! Counter values MUST be strictly monotonic across reboots: no value
//! handed out before a reboot SHALL be handed out again after it.
//! Backends meet this as follows:
//!
//! * The core checkpoints the next-to-use counter every `watermark`
//!   handed-out values via [`NvmStore::save_outgoing`].
//! * On boot the core resumes at `persisted + stride`, where `stride`
//!   is at least the watermark ([`COUNTER_STRIDE`]). The skipped
//!   stride covers values that may have been used after the last
//!   checkpoint but before the power loss, so they can never repeat.
//! * The store SHALL reject a save that moves the persisted value
//!   backwards; the core SHALL reject a resume below its last
//!   persisted mark.
//! * RAM backends ([`RamStore`]) keep the same API for host/sim use but
//!   provide NO cross-reboot protection: values handed out after the
//!   last save are lost on reset. Flash backends per target close this
//!   gap; they plug the same trait.
//!
//! Requirement `05-3474-23-434-01`.

/// Checkpoint stride: resume advances the persisted value by at least
/// this many counter steps, covering the worst-case gap between the
/// last checkpoint and a power loss.
///
/// Requirement `05-3474-23-434-01`.
pub const COUNTER_STRIDE: u32 = 1024;

/// Failures from the persistence backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// Backend refused the write (media full, worn, or busy).
    Io,
    /// Stored image failed validation (torn write, bad magic).
    Corrupt,
}

/// Snapshot of what the NVM backend holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistedState {
    /// Last checkpointed next-to-use outgoing counter.
    pub outgoing_next: u32,
}

impl PersistedState {
    /// Blank image (factory state): counters start at zero.
    #[must_use]
    pub const fn blank() -> Self {
        Self { outgoing_next: 0 }
    }

    /// Resume value after boot: persisted mark plus the rollback
    /// stride, saturating at the top of the range.
    ///
    /// Requirement `05-3474-23-434-01`.
    #[must_use]
    pub const fn resume_next(&self) -> u32 {
        self.outgoing_next.saturating_add(COUNTER_STRIDE)
    }
}

/// Non-volatile counter store. Implementations are per target
/// (flash on ESP, file-backed on host tooling); [`RamStore`] is the
/// default for sim and unit tests.
///
/// Requirement `05-3474-23-434-01`.
pub trait NvmStore {
    /// Read the current snapshot. `Corrupt` when the image fails
    /// validation; the caller then falls back to factory state plus a
    /// fresh key (never to a guessed lower counter).
    fn load(&self) -> Result<PersistedState, StoreError>;

    /// Checkpoint the next-to-use outgoing counter. SHALL reject a
    /// value below the last saved one (monotonic backend guard).
    fn save_outgoing(&mut self, next: u32) -> Result<(), StoreError>;
}

/// RAM-backed store: same API, no cross-reboot protection. Suitable
/// for sim, host tests, and targets whose real backend is not yet
/// wired; NOT suitable for production devices (documented gap, not a
/// silent fallback).
///
/// Requirement `05-3474-23-434-01`.
#[derive(Debug, Clone, Copy)]
pub struct RamStore {
    state: PersistedState,
    valid: bool,
    writes: u32,
    fail_next: bool,
}

impl RamStore {
    /// Blank store (reads as factory state until first save).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: PersistedState::blank(),
            valid: false,
            writes: 0,
            fail_next: false,
        }
    }

    /// Number of successful saves so far (budget accounting hook).
    #[must_use]
    pub const fn writes(&self) -> u32 {
        self.writes
    }

    /// Arm a one-shot write failure (fault-injection for tests).
    pub const fn arm_failure(&mut self) {
        self.fail_next = true;
    }
}

impl Default for RamStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NvmStore for RamStore {
    fn load(&self) -> Result<PersistedState, StoreError> {
        if self.valid {
            Ok(self.state)
        } else {
            Ok(PersistedState::blank())
        }
    }

    fn save_outgoing(&mut self, next: u32) -> Result<(), StoreError> {
        if self.fail_next {
            self.fail_next = false;
            return Err(StoreError::Io);
        }
        if self.valid && next < self.state.outgoing_next {
            return Err(StoreError::Corrupt);
        }
        self.state.outgoing_next = next;
        self.valid = true;
        self.writes += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_skips_stride() {
        let s = PersistedState {
            outgoing_next: 5000,
        };
        assert_eq!(s.resume_next(), 5000 + COUNTER_STRIDE);
        let top = PersistedState {
            outgoing_next: u32::MAX,
        };
        assert_eq!(top.resume_next(), u32::MAX);
    }

    #[test]
    fn ram_store_monotonic_and_blank() {
        let mut store = RamStore::new();
        assert_eq!(store.load().unwrap(), PersistedState::blank());
        store.save_outgoing(1024).unwrap();
        assert_eq!(store.load().unwrap().outgoing_next, 1024);
        // Backwards save is rejected, state unchanged.
        assert_eq!(store.save_outgoing(100), Err(StoreError::Corrupt));
        assert_eq!(store.load().unwrap().outgoing_next, 1024);
        store.arm_failure();
        assert_eq!(store.save_outgoing(2048), Err(StoreError::Io));
        assert_eq!(store.writes(), 1);
    }
}
