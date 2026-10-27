//! Acknowledged-transmission retry machine and duplicate rejection,
//! both driven by an injected tick clock (no wall clock).
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2 §§2.2.8.4.2–
//! 2.2.8.4.4 plus Table 2-23 constants (§2.2.7.1). All wording here is
//! paraphrase.
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped) pending seed
//! extraction of chapter 2.

use crate::status::ApsStatus;

/// Retries allowed after a failed transmission attempt (Table 2-23
/// `apscMaxFrameRetries`, §2.2.7.1).
///
/// Requirement `05-3474-23-2271-01`.
pub const MAX_FRAME_RETRIES: u8 = 3;

/// Minimum duplicate-rejection table capacity tracking (Table 2-23
/// `apscMinDuplicateRejectionTableSize`, §2.2.7.1). The default table
/// below holds more; it never holds fewer than this.
///
/// Requirement `05-3474-23-2271-01`.
pub const MIN_DUP_TABLE_SIZE: usize = 1;

/// Default duplicate-rejection table capacity (declared budget, at
/// least [`MIN_DUP_TABLE_SIZE`]).
///
/// Requirement `05-3474-23-22842-02`.
pub const DUP_TABLE_SIZE: usize = 4;

/// What the sender expects back in the acknowledgement (§2.2.8.4.4:
/// same cluster identifier and APS counter, source endpoint equal to
/// the destination endpoint of the original frame).
///
/// Requirement `05-3474-23-22844-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckExpect {
    /// Cluster identifier of the transmitted frame.
    pub cluster_id: u16,
    /// APS counter of the transmitted frame.
    pub counter: u8,
    /// Destination endpoint of the transmitted frame; the ack's source
    /// endpoint must equal it.
    pub dst_endpoint: u8,
}

impl AckExpect {
    /// Check one incoming acknowledgement's addressing fields against
    /// the expectation.
    #[must_use]
    pub const fn matches(&self, cluster_id: u16, counter: u8, src_endpoint: u8) -> bool {
        self.cluster_id == cluster_id
            && self.counter == counter
            && self.dst_endpoint == src_endpoint
    }
}

/// One received acknowledgement, already frame-decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckInfo {
    /// Cluster identifier carried in the ack.
    pub cluster_id: u16,
    /// APS counter carried in the ack.
    pub counter: u8,
    /// Source endpoint carried in the ack.
    pub src_endpoint: u8,
}

/// Retry session verdict after an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryVerdict {
    /// Still waiting: acknowledgement outstanding, deadline unreached.
    Waiting,
    /// The frame went on air (again): caller must (re)transmit now and
    /// restart the wait. The first `poll_transmit` call also reports
    /// this so the initial transmission is scheduled the same way.
    Transmit,
    /// Matching acknowledgement received: done, report success upward.
    Acked,
    /// Retries exhausted: done, confirm carries `NO_ACK`.
    Failed(ApsStatus),
}

/// Acknowledged-transmission retry state machine (§2.2.8.4.4): wait up
/// to the configured ack-wait ticks, retransmit on timeout up to
/// [`MAX_FRAME_RETRIES`] times, then fail with `NO_ACK`.
///
/// The session borrows no clock: every method takes the caller's tick
/// `now`. Durations are opaque ticks so sim virtual time, millis, or
/// MAC symbols all work; the Table 2-23 1.6-second nominal value is a
/// caller-side conversion, not encoded here.
///
/// SAP note (§2.2.8.4.1): the APS layer keeps route discovery enabled
/// on every network-layer request it issues; the `DiscoverRoute`
/// parameter lives one layer down (see the sim transport test, which
/// issues `DiscoverRoute::Enable` under every APDU).
///
/// Requirement `05-3474-23-22844-01` (`05-3474-23-22841-03` for the SAP note).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetrySession {
    expect: AckExpect,
    ack_wait_ticks: u64,
    attempts: u8,
    deadline: u64,
    done: bool,
    failed: bool,
    initial: bool,
}

impl RetrySession {
    /// New session: nothing sent yet; `now` is the current tick and
    /// `ack_wait_ticks` the per-attempt wait.
    #[must_use]
    pub const fn new(expect: AckExpect, now: u64, ack_wait_ticks: u64) -> Self {
        Self {
            expect,
            ack_wait_ticks,
            attempts: 0,
            deadline: now.saturating_add(ack_wait_ticks),
            done: false,
            failed: false,
            initial: true,
        }
    }

    /// Schedule the pending (re)transmission. Reports
    /// [`RetryVerdict::Transmit`] once per attempt, including the
    /// first: the caller transmits, then waits for `on_ack`/`on_tick`.
    pub fn poll_transmit(&mut self) -> RetryVerdict {
        if self.done {
            return if self.failed {
                RetryVerdict::Failed(ApsStatus::NoAck)
            } else {
                RetryVerdict::Acked
            };
        }
        if self.initial {
            self.initial = false;
            return RetryVerdict::Transmit;
        }
        RetryVerdict::Waiting
    }

    /// Handle one incoming acknowledgement.
    pub fn on_ack(&mut self, ack: AckInfo) -> RetryVerdict {
        if self.done {
            return if self.failed {
                RetryVerdict::Failed(ApsStatus::NoAck)
            } else {
                RetryVerdict::Acked
            };
        }
        if self
            .expect
            .matches(ack.cluster_id, ack.counter, ack.src_endpoint)
        {
            self.done = true;
            RetryVerdict::Acked
        } else {
            // Wrong cluster, counter, or endpoint: the attempt is
            // treated as failed (§2.2.8.4.4) but the session keeps
            // waiting until the deadline rather than failing early.
            RetryVerdict::Waiting
        }
    }

    /// Handle a clock advance: timeout → retransmit or fail.
    pub fn on_tick(&mut self, now: u64) -> RetryVerdict {
        if self.done {
            return if self.failed {
                RetryVerdict::Failed(ApsStatus::NoAck)
            } else {
                RetryVerdict::Acked
            };
        }
        if now < self.deadline {
            return RetryVerdict::Waiting;
        }
        if self.attempts >= MAX_FRAME_RETRIES {
            self.done = true;
            self.failed = true;
            return RetryVerdict::Failed(ApsStatus::NoAck);
        }
        self.attempts += 1;
        self.deadline = now.saturating_add(self.ack_wait_ticks);
        RetryVerdict::Transmit
    }

    /// Retransmissions used so far (0 = original attempt outstanding).
    #[must_use]
    pub const fn attempts(&self) -> u8 {
        self.attempts
    }
}

/// Duplicate-rejection table (§2.2.8.4.2): source address + APS counter
/// pairs already delivered upward. Capacity is the declared
/// [`DUP_TABLE_SIZE`] budget (at least the one-entry minimum).
///
/// Requirement `05-3474-23-22842-02`.
#[derive(Clone, Copy, Debug)]
pub struct DupRejectTable {
    entries: [(u16, u8); DUP_TABLE_SIZE],
    len: usize,
    next: usize,
}

impl Default for DupRejectTable {
    fn default() -> Self {
        Self::new()
    }
}

impl DupRejectTable {
    /// Empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [(0u16, 0u8); DUP_TABLE_SIZE],
            len: 0,
            next: 0,
        }
    }

    /// Observe one delivered frame. Returns `true` when the
    /// source/counter pair was already recorded (duplicate: deliver
    /// once only); otherwise records it and returns `false`.
    pub fn observe(&mut self, src: u16, counter: u8) -> bool {
        for i in 0..self.len {
            if self.entries[i] == (src, counter) {
                return true;
            }
        }
        self.entries[self.next] = (src, counter);
        self.next = (self.next + 1) % DUP_TABLE_SIZE;
        self.len = (self.len + 1).min(DUP_TABLE_SIZE);
        false
    }

    /// Entries currently held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the table holds nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}
