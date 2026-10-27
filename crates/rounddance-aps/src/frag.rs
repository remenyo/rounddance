//! Fragmentation transmission planning, block splitting, and
//! reassembly with an injected tick clock (no wall clock).
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2 §§2.2.8.4.5.1–
//! 2.2.8.4.5.4 plus the Fig 2-2 transmit decision tree (mined from the
//! PDF page render; numeric statuses from Table 2-29, §2.2.9). All
//! wording here is paraphrase.
//!
//! # Budgets (D5: bounded + fallible + accountable)
//!
//! * [`MAX_RX_TRANSACTIONS`]: concurrent inbound fragmented
//!   transactions held.
//! * [`MAX_BLOCKS_PER_RX`]: blocks per inbound transaction (bitmask
//!   budget); larger announced totals are rejected fallibly.
//! * [`MAX_ASDU_OCTETS`]: reassembly buffer per transaction — at least
//!   the Table 2-28 128-octet minimum.
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped) pending seed
//! extraction of chapter 2.
//!
//! Interop note (§2.2.8.4.5): a window size of 1 is the only
//! guaranteed-interoperable window; larger windows are manufacturer
//! extensions. This stack's reassembly accepts multi-block windows
//! within a declared block budget, so window-1 peers interoperate.
//!
//! Requirement `05-3474-23-22845-02`.

use crate::status::ApsStatus;

/// Concurrent inbound fragmented transactions held.
///
/// Requirement `05-3474-23-22845-06`.
pub const MAX_RX_TRANSACTIONS: usize = 2;

/// Blocks tracked per inbound transaction (one bit each).
///
/// Requirement `05-3474-23-22845-06`.
pub const MAX_BLOCKS_PER_RX: usize = 32;

/// Reassembly buffer per transaction: covers the Table 2-28 128-octet
/// minimum with headroom for larger negotiated transfers.
///
/// Requirement `05-3474-23-22845-04`.
pub const MAX_ASDU_OCTETS: usize = 512;

/// What the fragmentation-parameter discovery learned about one peer
/// (§2.2.8.4.5.1: node-descriptor query + cache).
///
/// Requirement `05-3474-23-22845-03`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerFragCaps {
    /// Descriptor answer on file (cache hit or fresh response).
    pub known: bool,
    /// Peer advertised fragmented-reception support.
    pub can_fragment: bool,
    /// Peer's maximum incoming transfer size in octets.
    pub max_rx_asdu: usize,
}

impl PeerFragCaps {
    /// No discovery result yet: every gate below reports unknown.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            known: false,
            can_fragment: false,
            max_rx_asdu: 0,
        }
    }
}

/// Transmit plan from the Fig 2-2 decision tree: single frame, a
/// fragmented run, or a confirm status that aborts the request.
///
/// Requirement `05-3474-23-22411-05` (oversize broadcast gate),
/// `05-3474-23-22411-06` (local-support gate),
/// `05-3474-23-22411-07` (discovery gates),
/// `05-3474-23-22411-08` (receiver-buffer gate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxPlan {
    /// Fits one frame: transmit unfragmented.
    Single,
    /// Fragment into this many blocks of at most `block_payload_max`.
    Fragmented {
        /// Total block count (first block announces it).
        block_count: u8,
    },
    /// Abort before touching the medium; confirm carries the status.
    Fail(ApsStatus),
}

/// Walk the Fig 2-2 transmit gates for an ASDU of `asdu_len` octets.
///
/// Callers guarantee the §2.2.8.4.1 precondition: only devices
/// currently part of a network hand frames to this planner
/// (unassociated callers must be rejected before this point, as the
/// NLDE guard does one layer down).
///
/// * Fits `single_capacity` → [`TxPlan::Single`].
/// * Oversize broadcast (fragmentation is broadcast-forbidden,
///   §2.2.8.4.5) → `AsduTooLong`.
/// * Local fragmentation unsupported → `AsduTooLong`.
/// * Peer capabilities unknown → `UnknownFragmentSupport`.
/// * Peer cannot fragment → `PeerCannotFragment`.
/// * ASDU larger than the peer's advertised maximum → `AsduTooLong`.
/// * Otherwise → [`TxPlan::Fragmented`] with a `ceil` block count; a
///   count that overflows the one-octet block-number field also
///   reports `AsduTooLong`.
#[must_use]
pub fn plan_transmit(
    asdu_len: usize,
    single_capacity: usize,
    broadcast: bool,
    local_frag: bool,
    peer: PeerFragCaps,
    block_payload_max: usize,
) -> TxPlan {
    if asdu_len <= single_capacity {
        return TxPlan::Single;
    }
    if broadcast {
        return TxPlan::Fail(ApsStatus::AsduTooLong);
    }
    if !local_frag {
        return TxPlan::Fail(ApsStatus::AsduTooLong);
    }
    if !peer.known {
        return TxPlan::Fail(ApsStatus::UnknownFragmentSupport);
    }
    if !peer.can_fragment {
        return TxPlan::Fail(ApsStatus::PeerCannotFragment);
    }
    if asdu_len > peer.max_rx_asdu {
        return TxPlan::Fail(ApsStatus::AsduTooLong);
    }
    if block_payload_max == 0 {
        return TxPlan::Fail(ApsStatus::IllegalRequest);
    }
    let count = asdu_len.div_ceil(block_payload_max);
    if !(2..=255).contains(&count) {
        return TxPlan::Fail(ApsStatus::AsduTooLong);
    }
    TxPlan::Fragmented {
        block_count: count as u8,
    }
}

/// One side of a fragmented transmission: the ASDU sliced into
/// `count` blocks of at most `block_max` payload octets
/// (§2.2.8.4.5.3: every block shares the APS counter; block 0
/// announces the total, block `k ≥ 1` carries number `k`).
///
/// Requirement `05-3474-23-22845-05`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxBlocks<'a> {
    asdu: &'a [u8],
    block_max: usize,
    count: u8,
}

impl<'a> TxBlocks<'a> {
    /// Slice `asdu` into blocks; fails when no positive block size is
    /// configured or the count overflows one octet.
    pub fn new(asdu: &'a [u8], block_max: usize) -> Result<Self, FragError> {
        if block_max == 0 {
            return Err(FragError::BadBlockSize);
        }
        let count = asdu.len().div_ceil(block_max);
        if count > 255 {
            return Err(FragError::PayloadTooLarge);
        }
        Ok(Self {
            asdu,
            block_max,
            count: count as u8,
        })
    }

    /// Total block count (announced in the first block).
    #[must_use]
    pub const fn count(&self) -> u8 {
        self.count
    }

    /// Block `index` (0-based): fragmentation marker, wire block
    /// number, and payload slice.
    ///
    /// # Panics
    ///
    /// Panics when `index >= count` — the caller enumerates
    /// `0..count`, so this is a programming error, not input data.
    #[must_use]
    pub fn block(&self, index: u8) -> (crate::frame::Fragmentation, u8, &'a [u8]) {
        use crate::frame::Fragmentation as F;
        let i = usize::from(index);
        assert!(i < usize::from(self.count));
        let start = i * self.block_max;
        let end = (start + self.block_max).min(self.asdu.len());
        let (frag, number) = if index == 0 {
            (F::First, self.count)
        } else {
            (F::Subsequent, index)
        };
        (frag, number, &self.asdu[start..end])
    }
}

/// Outcome of feeding one received fragment to the reassembler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedOutcome {
    /// Stored; more blocks (or the timeout) pending.
    InProgress,
    /// Repeated block of the in-progress transaction, or a new
    /// transaction matching an in-progress source/counter pair
    /// (§2.2.8.4.5.4 duplicate rule): dropped, nothing stored.
    Duplicate,
    /// Transaction complete: `len` reassembled octets are ready in
    /// [`Reassembler::assembled`].
    Complete {
        /// Reassembled ASDU length.
        len: usize,
    },
}

/// Largest single-block payload staged per block index: one fragment
/// rides one APDU in one 15.4 frame, so this comfortably covers any
/// on-air block. Larger blocks are rejected fallibly.
///
/// Requirement `05-3474-23-22845-06`.
pub const MAX_BLOCK_PAYLOAD: usize = 128;

/// One inbound transaction slot: per-block staging plus lengths, so
/// out-of-order arrival needs no relocation — compaction happens once
/// every block is in.
#[derive(Clone, Copy, Debug)]
struct RxSlot {
    active: bool,
    src: u16,
    counter: u8,
    total: Option<u8>,
    received_mask: u32,
    lens: [u16; MAX_BLOCKS_PER_RX],
    stage: [[u8; MAX_BLOCK_PAYLOAD]; MAX_BLOCKS_PER_RX],
    last_progress: u64,
}

impl RxSlot {
    const fn empty() -> Self {
        Self {
            active: false,
            src: 0,
            counter: 0,
            total: None,
            received_mask: 0,
            lens: [0u16; MAX_BLOCKS_PER_RX],
            stage: [[0u8; MAX_BLOCK_PAYLOAD]; MAX_BLOCKS_PER_RX],
            last_progress: 0,
        }
    }
}

/// Fragment reassembly over a bounded slot pool with an injected tick
/// clock (§2.2.8.4.5.4: window from 0, per-window acknowledgement,
/// indication once every block arrived, timeout on a stalled window).
///
/// Requirement `05-3474-23-22845-06`.
#[derive(Clone, Debug)]
pub struct Reassembler {
    slots: [RxSlot; MAX_RX_TRANSACTIONS],
    done_len: Option<usize>,
    done_buf: [u8; MAX_ASDU_OCTETS],
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    /// Empty reassembler; no transactions in progress.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [RxSlot::empty(), RxSlot::empty()],
            done_len: None,
            done_buf: [0u8; MAX_ASDU_OCTETS],
        }
    }

    /// Feed one received fragment (already frame-decoded): source NWK
    /// address, shared APS counter, extended-header marker/number, and
    /// the block payload. `now` is the caller's tick clock.
    pub fn feed(
        &mut self,
        src: u16,
        counter: u8,
        frag: crate::frame::Fragmentation,
        block_number: u8,
        payload: &[u8],
        now: u64,
    ) -> Result<FeedOutcome, FragError> {
        use crate::frame::Fragmentation as F;
        if frag == F::Unfragmented {
            return Err(FragError::NotFragmented);
        }
        // Block index on the wire: first block is index 0 and
        // announces the total; later blocks carry their own index.
        let (index, announces_total) = match frag {
            F::First => (0u8, Some(block_number)),
            F::Subsequent => {
                if block_number == 0 || usize::from(block_number) >= MAX_BLOCKS_PER_RX {
                    return Err(FragError::BlockOutOfRange);
                }
                (block_number, None)
            }
            F::Unfragmented => return Err(FragError::NotFragmented),
        };
        if payload.len() > MAX_ASDU_OCTETS {
            return Err(FragError::PayloadTooLarge);
        }

        // Find the live slot for this source/counter pair.
        let found = self
            .slots
            .iter()
            .position(|s| s.active && s.src == src && s.counter == counter);
        let idx = match found {
            Some(idx) => idx,
            // New transaction: claim a free slot.
            None => self
                .slots
                .iter()
                .position(|s| !s.active)
                .ok_or(FragError::NoSlot)?,
        };
        if self.slots[idx].active
            && (self.slots[idx].src != src || self.slots[idx].counter != counter)
        {
            return Err(FragError::NoSlot);
        }
        // The slot borrow ends before the completion copy below.
        let completed: Option<usize> = {
            let slot = &mut self.slots[idx];
            if !slot.active {
                slot.active = true;
                slot.src = src;
                slot.counter = counter;
                slot.total = None;
                slot.received_mask = 0;
                slot.last_progress = now;
            }
            // A first block for a live transaction is the
            // duplicate-transaction case (§2.2.8.4.5.4) — unless block
            // 0 itself is still missing, in which case this IS the late
            // opener (out-of-order arrival is legal) and is stored.
            if frag == F::First && (slot.received_mask & 1) != 0 {
                return Ok(FeedOutcome::Duplicate);
            }
            if let Some(total) = announces_total {
                if total == 0 || usize::from(total) > MAX_BLOCKS_PER_RX {
                    slot.active = false;
                    slot.received_mask = 0;
                    return Err(FragError::BadBlockCount);
                }
                match slot.total {
                    Some(known) if known != total => {
                        // Conflicting totals for one transaction: drop it.
                        slot.active = false;
                        slot.received_mask = 0;
                        return Err(FragError::ConflictingTotal);
                    }
                    _ => slot.total = Some(total),
                }
            }
            if let Some(total) = slot.total {
                if index >= total {
                    return Err(FragError::BlockOutOfRange);
                }
            }
            let bit = 1u32 << index;
            if slot.received_mask & bit != 0 {
                return Ok(FeedOutcome::Duplicate);
            }
            if payload.len() > MAX_BLOCK_PAYLOAD {
                return Err(FragError::PayloadTooLarge);
            }
            slot.stage[usize::from(index)][..payload.len()].copy_from_slice(payload);
            slot.lens[usize::from(index)] = payload.len() as u16;
            slot.received_mask |= bit;
            slot.last_progress = now;
            match slot.total {
                Some(total)
                    if slot.received_mask & complete_mask(total) == complete_mask(total) =>
                {
                    // Compact in block order into the scratch length.
                    let mut len = 0usize;
                    for i in 0..usize::from(total) {
                        len += usize::from(slot.lens[i]);
                    }
                    Some(len)
                }
                _ => None,
            }
        };
        match completed {
            Some(len) if len <= MAX_ASDU_OCTETS => {
                // Compact staged blocks in order into the done buffer.
                let mut off = 0usize;
                let total = usize::from(self.slots[idx].total.unwrap_or(0));
                for i in 0..total {
                    let blen = usize::from(self.slots[idx].lens[i]);
                    self.done_buf[off..off + blen]
                        .copy_from_slice(&self.slots[idx].stage[i][..blen]);
                    off += blen;
                }
                self.done_len = Some(len);
                self.slots[idx].active = false;
                self.slots[idx].received_mask = 0;
                Ok(FeedOutcome::Complete { len })
            }
            Some(_) => {
                self.slots[idx].active = false;
                self.slots[idx].received_mask = 0;
                Err(FragError::PayloadTooLarge)
            }
            None => Ok(FeedOutcome::InProgress),
        }
    }

    /// Last completed ASDU, if any (cleared by `take_assembled`).
    #[must_use]
    pub fn assembled(&self) -> Option<&[u8]> {
        self.done_len.map(|len| &self.done_buf[..len])
    }

    /// Move the completed ASDU out into a caller-visible copy.
    /// Returns `None` when no transaction has completed since the last
    /// take.
    #[must_use]
    pub fn take_assembled(&mut self) -> Option<([u8; MAX_ASDU_OCTETS], usize)> {
        let len = self.done_len.take()?;
        Some((self.done_buf, len))
    }

    /// Drop transactions stalled longer than `timeout_ticks` since
    /// their last progress (§2.2.8.4.5.4: window timeout). Returns the
    /// number of reaped transactions.
    pub fn reap_expired(&mut self, now: u64, timeout_ticks: u64) -> usize {
        let mut reaped = 0;
        for slot in &mut self.slots {
            if slot.active && now.saturating_sub(slot.last_progress) > timeout_ticks {
                slot.active = false;
                slot.received_mask = 0;
                reaped += 1;
            }
        }
        reaped
    }

    /// Number of transactions currently held.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.slots.iter().filter(|s| s.active).count()
    }
}

/// Bitmask with the low `total` bits set: the "every block received"
/// pattern for a transaction of `total` blocks (1..=32).
fn complete_mask(total: u8) -> u32 {
    if total >= 32 {
        u32::MAX
    } else {
        (1u32 << total) - 1
    }
}

/// Window-stall timeout from the acknowledgement parameters
/// (§2.2.8.4.5.4: no forward progress within one ack-wait plus one
/// ack-wait per allowed retry).
///
/// Requirement `05-3474-23-22845-06`.
#[must_use]
pub const fn rx_timeout_ticks(ack_wait_ticks: u64, max_retries: u64) -> u64 {
    ack_wait_ticks.saturating_add(ack_wait_ticks.saturating_mul(max_retries))
}

/// Fallible fragmentation errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FragError {
    /// Unfragmented frame handed to the reassembly path.
    NotFragmented,
    /// Zero block size configured for splitting.
    BadBlockSize,
    /// First block announced a zero or over-budget total.
    BadBlockCount,
    /// Block index outside the announced transaction.
    BlockOutOfRange,
    /// Conflicting totals announced for one transaction.
    ConflictingTotal,
    /// Block would overflow the reassembly budget.
    PayloadTooLarge,
    /// No free transaction slot (receiver busy — report
    /// `DefragDeferred` on the confirm path).
    NoSlot,
}

impl core::fmt::Display for FragError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFragmented => write!(f, "frame is not fragmented"),
            Self::BadBlockSize => write!(f, "zero block size"),
            Self::BadBlockCount => write!(f, "bad total block count"),
            Self::BlockOutOfRange => write!(f, "block outside transaction window"),
            Self::ConflictingTotal => write!(f, "conflicting block totals"),
            Self::PayloadTooLarge => write!(f, "fragment exceeds reassembly budget"),
            Self::NoSlot => write!(f, "no free reassembly slot"),
        }
    }
}

impl core::error::Error for FragError {}
