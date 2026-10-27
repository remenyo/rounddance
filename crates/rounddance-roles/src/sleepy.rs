//! Sleepy end device: duty-cycled poll, parent agreement, sleep/wake.
//!
//! The sleepy child negotiates its poll interval with the parent
//! (parent poll agreement): the parent holds indirect data across
//! sleeps and only ages the child out after a longer silence. Wake
//! and sleep advance on caller ticks with an injected clock — time
//! is never read here, so sim virtual time drives duty cycling
//! deterministically.
//!
//! Paraphrase-level model of the R23.2 sleepy/polling family
//! (§3.6.1.2: receiver-on versus duty-cycled polling, parent
//! agreement on the poll rate; repo-minted `05-3474-23-3612-*`,
//! MINTED-pending-confirm). All wording here is paraphrase (D1,
//! `SCOPE.md` §2).

/// Shortest admitted poll interval, caller ms.
///
/// Requirement `05-3474-23-3612-10` (MINTED-pending-confirm).
pub const MIN_POLL_INTERVAL_MS: u64 = 100;

/// Longest admitted poll interval, caller ms.
///
/// Requirement `05-3474-23-3612-10` (MINTED-pending-confirm).
pub const MAX_POLL_INTERVAL_MS: u64 = 60_000;

/// Failures from the sleepy machine.
///
/// Requirement `05-3474-23-3612-10` (MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SleepyError {
    /// Operation not allowed in the current state.
    BadState,
    /// Requested poll interval outside
    /// [`MIN_POLL_INTERVAL_MS`]..=[`MAX_POLL_INTERVAL_MS`].
    BadInterval,
}

/// Sleep/wake phase.
///
/// Requirement `05-3474-23-3612-10` (MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SleepState {
    /// Not on any network.
    Unjoined,
    /// Awake and able to exchange (poll window open).
    Awake,
    /// Radio off; next wake at the scheduled caller-ms time.
    Asleep,
    /// Parent declared lost; rejoin in progress.
    Rejoining,
}

/// Agreed duty-cycle parameters shared with the parent.
///
/// Requirement `05-3474-23-3612-10` (MINTED-pending-confirm): the
/// poll interval is agreed with the parent so it can size its
/// indirect hold and aging window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SleepyConfig {
    /// Poll interval in caller ms.
    pub poll_interval_ms: u64,
}

impl SleepyConfig {
    /// Validate an interval against the admitted range.
    pub fn new(poll_interval_ms: u64) -> Result<Self, SleepyError> {
        if !(MIN_POLL_INTERVAL_MS..=MAX_POLL_INTERVAL_MS).contains(&poll_interval_ms) {
            return Err(SleepyError::BadInterval);
        }
        Ok(Self { poll_interval_ms })
    }
}

/// Sleepy end device: wakes on schedule, polls, sleeps again.
///
/// The caller advances time with [`SleepyEndDeviceMachine::tick`];
/// when `wake_due` reports true the caller powers the radio, issues
/// the poll, reports the outcome, and the machine re-arms sleep.
///
/// Requirement `05-3474-23-3612-10` (MINTED-pending-confirm).
pub struct SleepyEndDeviceMachine {
    state: SleepState,
    parent_short: u16,
    config: SleepyConfig,
    next_wake_ms: u64,
    missed: u32,
    polls: u32,
}

impl SleepyEndDeviceMachine {
    /// New sleepy device under `config`, unjoined.
    #[must_use]
    pub const fn new(config: SleepyConfig) -> Self {
        Self {
            state: SleepState::Unjoined,
            parent_short: 0xFFFF,
            config,
            next_wake_ms: 0,
            missed: 0,
            polls: 0,
        }
    }

    /// Current sleep/wake phase.
    #[must_use]
    pub const fn state(&self) -> SleepState {
        self.state
    }

    /// Current parent short address (`0xFFFF` = none).
    #[must_use]
    pub const fn parent(&self) -> u16 {
        self.parent_short
    }

    /// Agreed poll interval in caller ms.
    #[must_use]
    pub const fn poll_interval_ms(&self) -> u64 {
        self.config.poll_interval_ms
    }

    /// Total polls issued (lifetime counter).
    #[must_use]
    pub const fn polls(&self) -> u32 {
        self.polls
    }

    /// Join via `parent_short` at `now_ms`: wakes immediately to
    /// poll.
    pub fn join(&mut self, parent_short: u16, now_ms: u64) -> Result<(), SleepyError> {
        if self.state != SleepState::Unjoined {
            return Err(SleepyError::BadState);
        }
        self.parent_short = parent_short;
        self.state = SleepState::Awake;
        self.next_wake_ms = now_ms;
        Ok(())
    }

    /// True when a wake is due at `now_ms` (caller should power the
    /// radio and poll).
    #[must_use]
    pub fn wake_due(&self, now_ms: u64) -> bool {
        matches!(self.state, SleepState::Asleep) && now_ms >= self.next_wake_ms
    }

    /// Wake the radio (caller powers it first).
    pub fn wake(&mut self) -> Result<(), SleepyError> {
        if self.state != SleepState::Asleep {
            return Err(SleepyError::BadState);
        }
        self.state = SleepState::Awake;
        Ok(())
    }

    /// Report one poll round, then re-arm sleep at
    /// `now_ms + poll_interval`. Three consecutive misses declare
    /// the parent lost (same bound as [`crate::enddevice`]).
    ///
    /// Requirement `05-3474-23-3612-10` + `05-3474-23-3613-02`
    /// (MINTED-pending-confirm).
    pub fn polled(&mut self, acked: bool, now_ms: u64) -> Result<SleepState, SleepyError> {
        if self.state != SleepState::Awake {
            return Err(SleepyError::BadState);
        }
        self.polls += 1;
        if acked {
            self.missed = 0;
            self.state = SleepState::Asleep;
            self.next_wake_ms = now_ms.saturating_add(self.config.poll_interval_ms);
        } else {
            self.missed += 1;
            if self.missed >= 3 {
                self.state = SleepState::Rejoining;
                self.missed = 0;
            } else {
                self.state = SleepState::Asleep;
                self.next_wake_ms = now_ms.saturating_add(self.config.poll_interval_ms);
            }
        }
        Ok(self.state)
    }

    /// Advance the schedule without radio activity: an asleep device
    /// whose wake already passed stays flagged via [`Self::wake_due`].
    pub fn tick(&mut self, _now_ms: u64) -> SleepState {
        self.state
    }

    /// Rejoin outcome: success (optionally via a new parent)
    /// resumes the awake-then-sleep cycle at `now_ms`.
    ///
    /// Requirement `05-3474-23-3613-03` (MINTED-pending-confirm).
    pub fn rejoin_done(
        &mut self,
        success: bool,
        new_parent: Option<u16>,
        now_ms: u64,
    ) -> SleepState {
        if self.state == SleepState::Rejoining {
            if success {
                if let Some(parent) = new_parent {
                    self.parent_short = parent;
                }
                self.state = SleepState::Awake;
                self.next_wake_ms = now_ms;
            } else {
                self.state = SleepState::Unjoined;
            }
        }
        self.state
    }

    /// Leave the network cleanly from any joined phase.
    ///
    /// Requirement `05-3474-23-3616-01` (MINTED-pending-confirm).
    pub fn leave(&mut self) -> Result<(), SleepyError> {
        match self.state {
            SleepState::Awake | SleepState::Asleep => {
                self.state = SleepState::Unjoined;
                Ok(())
            }
            SleepState::Unjoined | SleepState::Rejoining => Err(SleepyError::BadState),
        }
    }
}
