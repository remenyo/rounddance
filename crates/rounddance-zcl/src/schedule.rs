//! Metering snapshot schedules (cluster 0x0702): ScheduleSnapshot
//! command codecs, the bounded schedule table, and timetable-driven
//! take support for the snapshot store.
//!
//! Paraphrase-level model of doc `07-5123-08` §10.4.3.3.1.5 (client
//! ScheduleSnapshot: issuer + fragment index/total + concatenated
//! schedule entries) and §10.4.2.3.1.5 (server ScheduleSnapshotResponse:
//! issuer + per-schedule confirmation pairs). All wording here is
//! paraphrase (D1).
//!
//! Requirement IDs below are repo-minted (`07-5123-08-1046-*`, dots
//! stripped), MINTED-pending-confirm.
//!
//! Out of scope on purpose (rarer shapes stay bounded-opaque —
//! `metering::ServerBehavior` answers `UnsupCommand` for them, never
//! silent misbehavior): multi-entry fragmentation beyond the bounded
//! assembler below is rejected, not grown.

use crate::snapshot;
use crate::{Error, ZclStatus};

/// Client generated (server receives): ScheduleSnapshot (timetable
/// setup for snapshot takes).
///
/// Requirement `07-5123-08-1046-01` (MINTED-pending-confirm).
pub const CMD_SCHEDULE_SNAPSHOT: u8 = 0x04;
/// Server generated: ScheduleSnapshotResponse (issuer plus one
/// confirmation pair per scheduled entry).
///
/// Requirement `07-5123-08-1046-01` (MINTED-pending-confirm).
pub const CMD_SCHEDULE_SNAPSHOT_RESPONSE: u8 = 0x04;

/// Schedule entry wire length: id + start + bitmap + type + cause.
///
/// Requirement `07-5123-08-1046-01` (MINTED-pending-confirm).
pub const SCHEDULE_ENTRY_LEN: usize = 13;
/// Largest schedule backlog held (bounded; a full table answers
/// insufficient-space, never grows).
///
/// Requirement `07-5123-08-1046-02` (MINTED-pending-confirm).
pub const MAX_SCHEDULES: usize = 4;
/// Largest confirmation pairs carried in one response here.
///
/// Requirement `07-5123-08-1046-01` (MINTED-pending-confirm).
pub const MAX_SCHEDULE_CONFIRM: usize = 4;
/// Largest fragment assembly held while a multi-fragment schedule
/// command arrives (four entries' worth; larger totals are refused).
///
/// Requirement `07-5123-08-1046-01` (MINTED-pending-confirm).
pub const MAX_SCHEDULE_ASSEMBLY: usize = MAX_SCHEDULE_CONFIRM * SCHEDULE_ENTRY_LEN;
/// Largest fragment count accepted for one schedule command.
///
/// Requirement `07-5123-08-1046-01` (MINTED-pending-confirm).
pub const MAX_SCHEDULE_FRAGMENTS: u8 = 4;

/// Smallest timetable id the device files (ids address 1..=254).
///
/// Requirement `07-5123-08-1046-02` (MINTED-pending-confirm).
pub const SCHEDULE_ID_MIN: u8 = 1;
/// Largest timetable id the device files.
///
/// Requirement `07-5123-08-1046-02` (MINTED-pending-confirm).
pub const SCHEDULE_ID_MAX: u8 = 254;

/// Confirmation: the schedule entry was filed.
pub const SCHEDULE_CONF_ACCEPTED: u8 = 0x00;
/// Confirmation: the requested sub-payload shape is not carried here.
pub const SCHEDULE_CONF_TYPE_NOT_SUPPORTED: u8 = 0x01;
/// Confirmation: the requested cause is not carried here.
pub const SCHEDULE_CONF_CAUSE_NOT_SUPPORTED: u8 = 0x02;
/// Confirmation: the entry is structurally unusable (out-of-range id
/// or a zero/reserved timetable bitmap).
pub const SCHEDULE_CONF_NOT_CURRENTLY_AVAILABLE: u8 = 0x03;
/// Confirmation: timetables are switched off on this device.
pub const SCHEDULE_CONF_NOT_SUPPORTED_BY_DEVICE: u8 = 0x04;
/// Confirmation: the bounded table is full.
pub const SCHEDULE_CONF_INSUFFICIENT_SPACE: u8 = 0x05;

/// Timetable frequency unit: one day per count step.
///
/// Requirement `07-5123-08-1046-03` (MINTED-pending-confirm).
pub const FREQ_DAY: u8 = 0;
/// Timetable frequency unit: one week per count step.
pub const FREQ_WEEK: u8 = 1;
/// Timetable frequency unit: one 30-day month per count step.
pub const FREQ_MONTH: u8 = 2;

/// One timetable entry: when snapshots fire and what they carry.
///
/// Requirement `07-5123-08-1046-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduleEntry {
    /// Timetable id (1..=254).
    pub id: u8,
    /// First fire time (caller seconds).
    pub start: u32,
    /// Timetable bitmap: low 20 bits count, bits 20-21 unit,
    /// bits 22-23 phase hint.
    pub bitmap: u32,
    /// Sub-payload shape selector (as in `snapshot`).
    pub payload_type: u8,
    /// Cause map stamped on fired snapshots.
    pub cause: u32,
}

/// Decode one 13-octet timetable entry.
pub fn decode_schedule_entry(buf: &[u8]) -> Result<ScheduleEntry, Error> {
    if buf.len() != SCHEDULE_ENTRY_LEN {
        return Err(Error::Truncated);
    }
    let mut bitmap = [0u8; 4];
    bitmap[..3].copy_from_slice(&buf[5..8]);
    Ok(ScheduleEntry {
        id: buf[0],
        start: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
        bitmap: u32::from_le_bytes(bitmap),
        payload_type: buf[8],
        cause: u32::from_le_bytes([buf[9], buf[10], buf[11], buf[12]]),
    })
}

/// Encode one 13-octet timetable entry into `out`.
pub fn encode_schedule_entry(entry: &ScheduleEntry, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < SCHEDULE_ENTRY_LEN {
        return Err(Error::BufferTooSmall);
    }
    out[0] = entry.id;
    out[1..5].copy_from_slice(&entry.start.to_le_bytes());
    let raw = entry.bitmap.to_le_bytes();
    out[5..8].copy_from_slice(&raw[..3]);
    out[8] = entry.payload_type;
    out[9..13].copy_from_slice(&entry.cause.to_le_bytes());
    Ok(SCHEDULE_ENTRY_LEN)
}

/// Fire-count field of a timetable bitmap (low 20 bits).
///
/// Requirement `07-5123-08-1046-03` (MINTED-pending-confirm).
#[must_use]
pub const fn schedule_count(bitmap: u32) -> u32 {
    bitmap & 0x000F_FFFF
}

/// Frequency unit field of a timetable bitmap (bits 20-21).
///
/// Requirement `07-5123-08-1046-03` (MINTED-pending-confirm).
#[must_use]
pub const fn schedule_freq(bitmap: u32) -> u8 {
    ((bitmap >> 20) & 0x03) as u8
}

/// Phase-hint field of a timetable bitmap (bits 22-23).
///
/// Requirement `07-5123-08-1046-03` (MINTED-pending-confirm).
#[must_use]
pub const fn schedule_wildcard(bitmap: u32) -> u8 {
    ((bitmap >> 22) & 0x03) as u8
}

/// Period between fires in seconds, or 0 when the bitmap selects no
/// usable cadence (zero count or the reserved unit). Weeks count 7
/// days and months 30 days; the phase hint rides along for queries
/// but firing stays periodic from `start` (documented limitation).
///
/// Requirement `07-5123-08-1046-03` (MINTED-pending-confirm).
#[must_use]
pub const fn schedule_period_s(bitmap: u32) -> u64 {
    const DAY_S: u64 = 86_400;
    let count = schedule_count(bitmap) as u64;
    if count == 0 {
        return 0;
    }
    match schedule_freq(bitmap) {
        FREQ_DAY => count.saturating_mul(DAY_S),
        FREQ_WEEK => count.saturating_mul(7 * DAY_S),
        FREQ_MONTH => count.saturating_mul(30 * DAY_S),
        _ => 0,
    }
}

/// Whether the bitmap can ever fire.
#[must_use]
pub const fn schedule_bitmap_usable(bitmap: u32) -> bool {
    schedule_period_s(bitmap) != 0
}

/// One filed timetable plus the issuer that filed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FiledSchedule {
    entry: ScheduleEntry,
    issuer: u32,
    next_due: u32,
}

/// Bounded timetable store: id-addressed entries with issuer
/// serialisation and next-due cursors.
///
/// Requirement `07-5123-08-1046-02` (MINTED-pending-confirm): newer
/// issuer information replaces older information for the same id; a
/// stale re-file answers accepted but changes nothing; ids outside
/// 1..=254, unknown sub-payload shapes, and unsupported causes are
/// refused per entry without touching the table.
#[derive(Clone, Copy, Debug)]
pub struct ScheduleTable {
    entries: [Option<FiledSchedule>; MAX_SCHEDULES],
    len: u8,
    supported: bool,
}

impl Default for ScheduleTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ScheduleTable {
    /// Empty timetable store (timetables switched on).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_SCHEDULES],
            len: 0,
            supported: true,
        }
    }

    /// Filed entry count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// No entries filed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Switch timetable support off (every intake then confirms
    /// not-supported-by-device).
    pub const fn set_supported(&mut self, supported: bool) {
        self.supported = supported;
    }

    /// File one entry, answering its confirmation code.
    pub fn intake(&mut self, issuer: u32, entry: &ScheduleEntry) -> u8 {
        if !self.supported {
            return SCHEDULE_CONF_NOT_SUPPORTED_BY_DEVICE;
        }
        if entry.id < SCHEDULE_ID_MIN || entry.id > SCHEDULE_ID_MAX {
            return SCHEDULE_CONF_NOT_CURRENTLY_AVAILABLE;
        }
        if !snapshot::payload_type_known(entry.payload_type) {
            return SCHEDULE_CONF_TYPE_NOT_SUPPORTED;
        }
        if !snapshot::SnapshotStore::cause_supported(entry.cause) {
            return SCHEDULE_CONF_CAUSE_NOT_SUPPORTED;
        }
        if !schedule_bitmap_usable(entry.bitmap) {
            return SCHEDULE_CONF_NOT_CURRENTLY_AVAILABLE;
        }
        let mut i = 0;
        while i < self.len as usize {
            if let Some(filed) = self.entries[i] {
                if filed.entry.id == entry.id {
                    if issuer < filed.issuer {
                        // Stale re-file: accepted, table unchanged.
                        return SCHEDULE_CONF_ACCEPTED;
                    }
                    self.entries[i] = Some(FiledSchedule {
                        entry: *entry,
                        issuer,
                        next_due: entry.start,
                    });
                    return SCHEDULE_CONF_ACCEPTED;
                }
            }
            i += 1;
        }
        if self.len as usize >= MAX_SCHEDULES {
            return SCHEDULE_CONF_INSUFFICIENT_SPACE;
        }
        self.entries[self.len as usize] = Some(FiledSchedule {
            entry: *entry,
            issuer,
            next_due: entry.start,
        });
        self.len += 1;
        SCHEDULE_CONF_ACCEPTED
    }

    /// Snapshot causes + sub-payload shapes due at `now` (each entry
    /// at most once per call); cursors advance past `now` so a later
    /// call never re-fires the same grid point. Returns the count
    /// written into `out`.
    pub fn collect_due(&mut self, now: u32, out: &mut [(u32, u8)]) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < self.len as usize {
            if let Some(mut filed) = self.entries[i] {
                let period = schedule_period_s(filed.entry.bitmap);
                if period != 0 && now >= filed.next_due && n < out.len() {
                    out[n] = (filed.entry.cause, filed.entry.payload_type);
                    n += 1;
                    // Catch the cursor up past `now` (a long sleep
                    // fires once here; missed grids stay missed and
                    // documented as such).
                    let mut due = filed.next_due as u64;
                    let target = now as u64;
                    while due <= target {
                        due = due.saturating_add(period);
                        if due > u32::MAX as u64 {
                            break;
                        }
                    }
                    filed.next_due = due.min(u32::MAX as u64) as u32;
                    self.entries[i] = Some(filed);
                }
            }
            i += 1;
        }
        n
    }
}

/// Bounded reassembly for a fragmented ScheduleSnapshot command:
/// index 0 opens (or re-opens) the assembly, later fragments must
/// continue the same issuer in order, and the closing fragment drains
/// the entry list.
///
/// Requirement `07-5123-08-1046-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug)]
pub struct ScheduleAssembler {
    issuer: u32,
    next_index: u8,
    buf: [u8; MAX_SCHEDULE_ASSEMBLY],
    len: u8,
    armed: bool,
}

impl Default for ScheduleAssembler {
    fn default() -> Self {
        Self::new()
    }
}

/// Assembler intake verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Assembly {
    /// More fragments still expected.
    Incomplete,
    /// The full entry body arrived (`len` significant bytes).
    Complete {
        /// Issuer of the assembled command.
        issuer: u32,
        /// Assembled entry-body length.
        len: u8,
    },
}

impl ScheduleAssembler {
    /// Idle assembler.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            issuer: 0,
            next_index: 0,
            buf: [0u8; MAX_SCHEDULE_ASSEMBLY],
            len: 0,
            armed: false,
        }
    }

    /// Assembled entry bytes (valid after `Complete`).
    #[must_use]
    pub const fn assembled(&self) -> &[u8] {
        self.buf.split_at(self.len as usize).0
    }

    /// Feed one fragment; validates order, size, and entry framing.
    pub fn feed(
        &mut self,
        issuer: u32,
        index: u8,
        total: u8,
        body: &[u8],
    ) -> Result<Assembly, ZclStatus> {
        if total == 0 || total > MAX_SCHEDULE_FRAGMENTS {
            return Err(ZclStatus::MalformedCommand);
        }
        if index >= total {
            return Err(ZclStatus::MalformedCommand);
        }
        if body.len() > MAX_SCHEDULE_ASSEMBLY || !body.len().is_multiple_of(SCHEDULE_ENTRY_LEN) {
            return Err(ZclStatus::MalformedCommand);
        }
        if index == 0 {
            self.issuer = issuer;
            self.next_index = 0;
            self.len = 0;
            self.armed = true;
        } else {
            if !self.armed || issuer != self.issuer || index != self.next_index {
                return Err(ZclStatus::MalformedCommand);
            }
        }
        if self.len as usize + body.len() > MAX_SCHEDULE_ASSEMBLY {
            self.armed = false;
            return Err(ZclStatus::MalformedCommand);
        }
        self.buf[self.len as usize..self.len as usize + body.len()].copy_from_slice(body);
        self.len += body.len() as u8;
        self.next_index = index + 1;
        if index + 1 == total {
            self.armed = false;
            Ok(Assembly::Complete {
                issuer: self.issuer,
                len: self.len,
            })
        } else {
            Ok(Assembly::Incomplete)
        }
    }
}

/// Encode a ScheduleSnapshotResponse body (issuer plus confirmation
/// pairs) into `out`.
pub fn encode_schedule_response(
    issuer: u32,
    confirmations: &[(u8, u8)],
    out: &mut [u8],
) -> Result<usize, Error> {
    if confirmations.len() > MAX_SCHEDULE_CONFIRM {
        return Err(Error::InvalidValue(confirmations.len() as u8));
    }
    let need = 4 + 2 * confirmations.len();
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    out[..4].copy_from_slice(&issuer.to_le_bytes());
    let mut i = 0;
    while i < confirmations.len() {
        out[4 + 2 * i] = confirmations[i].0;
        out[4 + 2 * i + 1] = confirmations[i].1;
        i += 1;
    }
    Ok(need)
}

/// Decoded ScheduleSnapshotResponse body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedScheduleResponse {
    /// Issuer echoed from the command this answers.
    pub issuer: u32,
    /// (schedule id, confirmation) pairs.
    pub confirmations: [(u8, u8); MAX_SCHEDULE_CONFIRM],
    /// Significant pairs.
    pub count: u8,
}

/// Decode a ScheduleSnapshotResponse body.
pub fn decode_schedule_response(buf: &[u8]) -> Result<DecodedScheduleResponse, Error> {
    if buf.len() < 4 || !(buf.len() - 4).is_multiple_of(2) {
        return Err(Error::Truncated);
    }
    let count = (buf.len() - 4) / 2;
    if count > MAX_SCHEDULE_CONFIRM {
        return Err(Error::InvalidValue(count as u8));
    }
    let mut confirmations = [(0u8, 0u8); MAX_SCHEDULE_CONFIRM];
    let mut i = 0;
    while i < count {
        confirmations[i] = (buf[4 + 2 * i], buf[4 + 2 * i + 1]);
        i += 1;
    }
    Ok(DecodedScheduleResponse {
        issuer: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        confirmations,
        count: count as u8,
    })
}
