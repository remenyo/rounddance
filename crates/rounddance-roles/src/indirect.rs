//! Indirect-data queue: hold frames for sleepy children.
//!
//! Paraphrase-level model of the R23.2 indirect-transmission family
//! (§3.6.1.2: a parent holds data for a polling child until the
//! child polls or the hold lapses). All wording here is paraphrase
//! (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped), MINTED-pending-confirm.

/// Bound on held indirect frames per parent (declared budget).
///
/// Requirement `05-3474-23-3612-04` (MINTED-pending-confirm).
pub const MAX_INDIRECT_QUEUE: usize = 16;

/// Largest single held payload in octets (declared budget).
///
/// Requirement `05-3474-23-3612-04` (MINTED-pending-confirm).
pub const MAX_INDIRECT_PAYLOAD: usize = 128;

/// Hold lifetime of an undelivered frame, caller ms.
///
/// Requirement `05-3474-23-3612-04` (MINTED-pending-confirm).
pub const INDIRECT_HOLD_MS: u64 = 7_500;

/// Failures from indirect-queue management.
///
/// Requirement `05-3474-23-3612-04` (MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndirectError {
    /// Queue is full; the frame must be refused, never silently dropped.
    QueueFull,
    /// Payload exceeds [`MAX_INDIRECT_PAYLOAD`].
    PayloadTooLarge,
    /// No frame is held for this child.
    NothingPending,
}

/// One held frame: destination child + payload + enqueue time.
///
/// Requirement `05-3474-23-3612-04` (MINTED-pending-confirm).
#[derive(Debug, Clone, Copy)]
pub struct PendingFrame {
    child_short: u16,
    len: u8,
    payload: [u8; MAX_INDIRECT_PAYLOAD],
    enqueued_ms: u64,
}

impl PendingFrame {
    /// Destination child short address.
    #[must_use]
    pub const fn child_short(&self) -> u16 {
        self.child_short
    }

    /// Held payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload[..usize::from(self.len)]
    }

    /// Caller-ms timestamp of enqueue.
    #[must_use]
    pub const fn enqueued_ms(&self) -> u64 {
        self.enqueued_ms
    }
}

/// Bounded hold for sleepy-child frames, drained by polls.
///
/// Requirement `05-3474-23-3612-04` (MINTED-pending-confirm).
#[derive(Debug, Clone)]
pub struct IndirectQueue {
    frames: [Option<PendingFrame>; MAX_INDIRECT_QUEUE],
    len: usize,
    hold_ms: u64,
}

impl Default for IndirectQueue {
    fn default() -> Self {
        Self::new(INDIRECT_HOLD_MS)
    }
}

impl IndirectQueue {
    /// Empty queue with `hold_ms` lifetime per frame.
    #[must_use]
    pub const fn new(hold_ms: u64) -> Self {
        Self {
            frames: [None; MAX_INDIRECT_QUEUE],
            len: 0,
            hold_ms,
        }
    }

    /// Number of held frames.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True when nothing is held.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True when a frame is held for `child_short`.
    ///
    /// Requirement `05-3474-23-3612-05` (MINTED-pending-confirm): a
    /// poll delivers pending data instead of an empty ack.
    #[must_use]
    pub fn has_pending(&self, child_short: u16) -> bool {
        self.frames
            .iter()
            .any(|slot| matches!(slot, Some(frame) if frame.child_short == child_short))
    }

    /// Hold `payload` for `child_short`; refuses oversize payloads
    /// and a full queue.
    ///
    /// Requirement `05-3474-23-3612-04` (MINTED-pending-confirm).
    pub fn enqueue(
        &mut self,
        child_short: u16,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<(), IndirectError> {
        if payload.len() > MAX_INDIRECT_PAYLOAD {
            return Err(IndirectError::PayloadTooLarge);
        }
        if self.len >= MAX_INDIRECT_QUEUE {
            return Err(IndirectError::QueueFull);
        }
        for slot in self.frames.iter_mut() {
            if slot.is_none() {
                let mut bytes = [0u8; MAX_INDIRECT_PAYLOAD];
                bytes[..payload.len()].copy_from_slice(payload);
                *slot = Some(PendingFrame {
                    child_short,
                    len: payload.len() as u8,
                    payload: bytes,
                    enqueued_ms: now_ms,
                });
                self.len += 1;
                return Ok(());
            }
        }
        Err(IndirectError::QueueFull)
    }

    /// Deliver the oldest frame held for `child_short` (poll hit).
    ///
    /// Requirement `05-3474-23-3612-05` (MINTED-pending-confirm).
    pub fn poll_deliver(&mut self, child_short: u16) -> Result<PendingFrame, IndirectError> {
        let mut best: Option<usize> = None;
        for (i, slot) in self.frames.iter().enumerate() {
            if let Some(frame) = slot {
                if frame.child_short == child_short
                    && best.is_none_or(|b| frame.enqueued_ms < self.frames[b].unwrap().enqueued_ms)
                {
                    best = Some(i);
                }
            }
        }
        match best {
            Some(i) => {
                let frame = self.frames[i].take().unwrap();
                self.len -= 1;
                Ok(frame)
            }
            None => Err(IndirectError::NothingPending),
        }
    }

    /// Drop frames whose hold lapsed; returns the number expired.
    ///
    /// Requirement `05-3474-23-3612-04` (MINTED-pending-confirm).
    pub fn expire(&mut self, now_ms: u64) -> usize {
        let mut dropped = 0;
        for slot in self.frames.iter_mut() {
            if let Some(frame) = slot {
                if now_ms.saturating_sub(frame.enqueued_ms) >= self.hold_ms {
                    *slot = None;
                    dropped += 1;
                }
            }
        }
        self.len -= dropped;
        dropped
    }
}
