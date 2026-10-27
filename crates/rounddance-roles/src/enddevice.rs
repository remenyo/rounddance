//! End-device role: poll parent, rejoin on loss, leave cleanly.
//!
//! Thin orchestration: rejoin sequencing stays in
//! `rounddance-commission` (`RejoinMachine`); this machine binds the
//! outcome to end-device duty — periodic polling, parent-loss
//! detection, and leave.
//!
//! Paraphrase-level model of the R23.2 end-device family (§3.6.1.2
//! polling, §3.6.1.3 rejoin, §3.6.1.6 leave; repo-minted
//! `05-3474-23-3612-*` / `05-3474-23-3613-*` / `05-3474-23-3616-*`,
//! MINTED-pending-confirm). All wording here is paraphrase (D1,
//! `SCOPE.md` §2).

/// Poll period of a non-sleepy end device, caller ms.
///
/// Requirement `05-3474-23-3612-09` (MINTED-pending-confirm).
pub const END_DEVICE_POLL_MS: u64 = 1_000;

/// Missed polls that declare the parent lost.
///
/// Requirement `05-3474-23-3613-02` (MINTED-pending-confirm).
pub const END_DEVICE_MAX_MISSED: u32 = 3;

/// Failures from the end-device machine.
///
/// Requirement `05-3474-23-3612-09` (MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndDeviceError {
    /// Operation not allowed in the current state.
    BadState,
}

/// End-device lifecycle.
///
/// Requirement `05-3474-23-3612-09` (MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndDeviceState {
    /// Not on any network.
    Unjoined,
    /// Join in progress (delegated to commission).
    Joining,
    /// On-network: polling the parent.
    Polling,
    /// Parent declared lost; rejoin in progress.
    Rejoining,
    /// Left the network cleanly.
    Left,
}

/// What one poll achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOutcome {
    /// Parent answered (data or empty ack).
    Acked,
    /// No answer; consecutive misses accumulate toward loss.
    Missed,
}

/// End device: polls its parent, declares loss after consecutive
/// misses, rejoins, and leaves cleanly.
///
/// Requirement `05-3474-23-3612-09` (MINTED-pending-confirm).
pub struct EndDeviceMachine {
    state: EndDeviceState,
    parent_short: u16,
    missed: u32,
    polls: u32,
}

impl EndDeviceMachine {
    /// New unjoined end device.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: EndDeviceState::Unjoined,
            parent_short: 0xFFFF,
            missed: 0,
            polls: 0,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> EndDeviceState {
        self.state
    }

    /// Short address of the current parent (`0xFFFF` = none).
    #[must_use]
    pub const fn parent(&self) -> u16 {
        self.parent_short
    }

    /// Total polls issued (lifetime counter).
    #[must_use]
    pub const fn polls(&self) -> u32 {
        self.polls
    }

    /// Begin joining via `parent_short`.
    pub fn begin_join(&mut self, parent_short: u16) -> Result<(), EndDeviceError> {
        if self.state != EndDeviceState::Unjoined {
            return Err(EndDeviceError::BadState);
        }
        self.parent_short = parent_short;
        self.state = EndDeviceState::Joining;
        Ok(())
    }

    /// Join outcome: success starts polling.
    pub fn join_done(&mut self, success: bool) -> EndDeviceState {
        if self.state == EndDeviceState::Joining {
            self.state = if success {
                EndDeviceState::Polling
            } else {
                EndDeviceState::Unjoined
            };
        }
        self.state
    }

    /// Record one poll round: `acked` resets the miss counter, a
    /// miss increments it, and [`END_DEVICE_MAX_MISSED`] consecutive
    /// misses move the machine to rejoin.
    ///
    /// Requirement `05-3474-23-3612-09` + `05-3474-23-3613-02`
    /// (MINTED-pending-confirm).
    pub fn poll(&mut self, acked: bool) -> Result<PollOutcome, EndDeviceError> {
        if self.state != EndDeviceState::Polling {
            return Err(EndDeviceError::BadState);
        }
        self.polls += 1;
        if acked {
            self.missed = 0;
            Ok(PollOutcome::Acked)
        } else {
            self.missed += 1;
            if self.missed >= END_DEVICE_MAX_MISSED {
                self.state = EndDeviceState::Rejoining;
                self.missed = 0;
            }
            Ok(PollOutcome::Missed)
        }
    }

    /// Rejoin outcome: success (optionally via a new parent)
    /// resumes polling; failure returns to unjoined.
    ///
    /// Requirement `05-3474-23-3613-02` + `05-3474-23-3613-03`
    /// (MINTED-pending-confirm).
    pub fn rejoin_done(&mut self, success: bool, new_parent: Option<u16>) -> EndDeviceState {
        if self.state == EndDeviceState::Rejoining {
            if success {
                if let Some(parent) = new_parent {
                    self.parent_short = parent;
                }
                self.state = EndDeviceState::Polling;
            } else {
                self.state = EndDeviceState::Unjoined;
            }
        }
        self.state
    }

    /// Leave the network cleanly (caller emits the leave primitive).
    ///
    /// Requirement `05-3474-23-3616-01` (MINTED-pending-confirm).
    pub fn leave(&mut self) -> Result<(), EndDeviceError> {
        if self.state != EndDeviceState::Polling {
            return Err(EndDeviceError::BadState);
        }
        self.state = EndDeviceState::Left;
        Ok(())
    }
}

impl Default for EndDeviceMachine {
    fn default() -> Self {
        Self::new()
    }
}
