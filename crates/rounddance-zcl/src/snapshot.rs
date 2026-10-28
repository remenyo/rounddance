//! Metering snapshots (cluster 0x0702): take/get command codecs,
//! the bounded snapshot store, and the publish-snapshot payload
//! codec.
//!
//! Paraphrase-level model of doc `07-5123-08` §10.4.2.3.1.5/6/7
//! (server-generated schedule/take/publish responses) and
//! §10.4.3.3.1.5/6/7 (client-generated schedule/take/get commands),
//! plus doc `17-05019-012` §10.4.2.3.1.7/§10.4.3.3.1.7 (snapshot
//! retrieval answers one snapshot or `NOT_FOUND`). All wording here
//! is paraphrase (D1).
//!
//! Requirement IDs below reuse `17-05019-012-423-02` (corpus-mined)
//! or are repo-minted (`07-5123-08-1045-*`, dots stripped),
//! MINTED-pending-confirm. Schedule commands and sampled-data
//! commands stay explicitly follow-up, not silent scope: only
//! take/get/response/publish are implemented here.

use crate::{Error, ZclStatus};

/// Server generated: TakeSnapshotResponse (taken id + verdict).
///
/// Requirement `07-5123-08-1045-01` (MINTED-pending-confirm).
pub const CMD_TAKE_SNAPSHOT_RESPONSE: u8 = 0x05;
/// Server generated: PublishSnapshot (one snapshot plus its
/// sub-payload).
///
/// Requirement `07-5123-08-1045-02` (MINTED-pending-confirm).
pub const CMD_PUBLISH_SNAPSHOT: u8 = 0x06;
/// Client generated (server receives): TakeSnapshot (cause map).
///
/// Requirement `07-5123-08-1045-01` (MINTED-pending-confirm).
pub const CMD_TAKE_SNAPSHOT: u8 = 0x05;
/// Client generated (server receives): GetSnapshot (time window +
/// offset + cause filter).
///
/// Requirement `07-5123-08-1045-02` (MINTED-pending-confirm).
pub const CMD_GET_SNAPSHOT: u8 = 0x06;

/// Snapshot-cause bit: tariff-information change. Takes before/after
/// pairs around the change.
///
/// Requirement `07-5123-08-1045-03` (MINTED-pending-confirm).
pub const CAUSE_TARIFF_CHANGE_BIT: u32 = 3;
/// Snapshot-cause bit the server additionally sets for snapshots
/// taken on a TakeSnapshot command.
///
/// Requirement `07-5123-08-1045-03` (MINTED-pending-confirm).
pub const CAUSE_MANUAL_BIT: u32 = 10;
/// Snapshot-cause bit for timetable-driven snapshots.
///
/// Requirement `07-5123-08-1045-03` (MINTED-pending-confirm).
pub const CAUSE_SCHEDULED_BIT: u32 = 16;
/// Cause value selecting every snapshot regardless of cause.
///
/// Requirement `17-05019-012-423-02` (corpus-mined).
pub const CAUSE_ALL: u32 = 0xFFFF_FFFF;
/// Cause bits this build accepts (defined bits only); anything
/// higher answers cause-not-supported and stores nothing.
///
/// Requirement `07-5123-08-1045-03` (MINTED-pending-confirm).
pub const SUPPORTED_CAUSES: u32 = 0x0003_FFFF;

/// TakeSnapshotResponse verdict: the snapshot was taken.
pub const CONFIRM_ACCEPTED: u8 = 0x00;
/// TakeSnapshotResponse verdict: the cause is not supported.
pub const CONFIRM_CAUSE_NOT_SUPPORTED: u8 = 0x01;

/// Snapshot payload types carried here (charging-scheme selector).
///
/// Requirement `07-5123-08-1045-02` (MINTED-pending-confirm).
pub const PAYLOAD_TOU_DELIVERED: u8 = 0x00;
/// TOU received set.
pub const PAYLOAD_TOU_RECEIVED: u8 = 0x01;
/// Block/tier delivered set.
pub const PAYLOAD_BLOCK_DELIVERED: u8 = 0x02;
/// Block/tier received set.
pub const PAYLOAD_BLOCK_RECEIVED: u8 = 0x03;
/// TOU delivered without billing fields.
pub const PAYLOAD_TOU_DELIVERED_NO_BILLING: u8 = 0x04;
/// TOU received without billing fields.
pub const PAYLOAD_TOU_RECEIVED_NO_BILLING: u8 = 0x05;
/// Block/tier delivered without billing fields.
pub const PAYLOAD_BLOCK_DELIVERED_NO_BILLING: u8 = 0x06;
/// Block/tier received without billing fields.
pub const PAYLOAD_BLOCK_RECEIVED_NO_BILLING: u8 = 0x07;
/// Snapshot data currently unavailable.
pub const PAYLOAD_UNAVAILABLE: u8 = 0x80;

/// Largest snapshot backlog held (bounded ring; full stores evict
/// the oldest snapshot).
///
/// Requirement `07-5123-08-1045-04` (MINTED-pending-confirm).
pub const MAX_SNAPSHOTS: usize = 8;
/// Largest sub-payload carried per snapshot (bounds the publish
/// body: 16-octet header + sub-payload fits the 64-octet event
/// reply path when the typed builder stays within
/// [`MAX_SNAPSHOT_TIERS`] tiers).
///
/// Requirement `07-5123-08-1045-02` (MINTED-pending-confirm).
pub const MAX_SNAPSHOT_SUB: usize = 48;
/// Largest tier-summation tail the typed TOU builder encodes.
///
/// Requirement `07-5123-08-1045-02` (MINTED-pending-confirm).
pub const MAX_SNAPSHOT_TIERS: usize = 4;

/// TakeSnapshot request: the cause map for the snapshot to take.
///
/// Requirement `07-5123-08-1045-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakeSnapshot {
    /// Cause map (the server additionally sets the manual bit).
    pub cause: u32,
}

/// Decode a TakeSnapshot body: exactly 4 octets (cause map32).
pub fn decode_take_snapshot(buf: &[u8]) -> Result<TakeSnapshot, Error> {
    if buf.len() != 4 {
        return Err(Error::Truncated);
    }
    Ok(TakeSnapshot {
        cause: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
    })
}

/// Encode a TakeSnapshot body into `out` (4 octets).
pub fn encode_take_snapshot(req: &TakeSnapshot, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 4 {
        return Err(Error::BufferTooSmall);
    }
    out[..4].copy_from_slice(&req.cause.to_le_bytes());
    Ok(4)
}

/// TakeSnapshotResponse: the taken snapshot id plus the verdict.
///
/// Requirement `07-5123-08-1045-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakeSnapshotResponse {
    /// Snapshot id allocated by the taker.
    pub snapshot_id: u32,
    /// Verdict (`CONFIRM_*`).
    pub confirmation: u8,
}

/// Decode a TakeSnapshotResponse body: exactly 5 octets.
pub fn decode_take_snapshot_response(buf: &[u8]) -> Result<TakeSnapshotResponse, Error> {
    if buf.len() != 5 {
        return Err(Error::Truncated);
    }
    Ok(TakeSnapshotResponse {
        snapshot_id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        confirmation: buf[4],
    })
}

/// Encode a TakeSnapshotResponse body into `out` (5 octets).
pub fn encode_take_snapshot_response(
    rsp: &TakeSnapshotResponse,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < 5 {
        return Err(Error::BufferTooSmall);
    }
    out[..4].copy_from_slice(&rsp.snapshot_id.to_le_bytes());
    out[4] = rsp.confirmation;
    Ok(5)
}

/// GetSnapshot query: time window plus which snapshot to return.
///
/// Requirement `17-05019-012-423-02` (corpus-mined).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetSnapshot {
    /// Earliest snapshot timestamp to return (inclusive).
    pub earliest: u32,
    /// Latest snapshot timestamp to return (exclusive).
    pub latest: u32,
    /// Which matching snapshot to return (0 = first match).
    pub offset: u8,
    /// Cause filter (`CAUSE_ALL` selects everything).
    pub cause: u32,
}

/// Decode a GetSnapshot body: exactly 13 octets.
pub fn decode_get_snapshot(buf: &[u8]) -> Result<GetSnapshot, Error> {
    if buf.len() != 13 {
        return Err(Error::Truncated);
    }
    Ok(GetSnapshot {
        earliest: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        latest: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        offset: buf[8],
        cause: u32::from_le_bytes([buf[9], buf[10], buf[11], buf[12]]),
    })
}

/// Encode a GetSnapshot body into `out` (13 octets).
pub fn encode_get_snapshot(req: &GetSnapshot, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 13 {
        return Err(Error::BufferTooSmall);
    }
    out[..4].copy_from_slice(&req.earliest.to_le_bytes());
    out[4..8].copy_from_slice(&req.latest.to_le_bytes());
    out[8] = req.offset;
    out[9..13].copy_from_slice(&req.cause.to_le_bytes());
    Ok(13)
}

/// PublishSnapshot leading fields (the 16-octet fixed header).
///
/// Requirement `07-5123-08-1045-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishSnapshot {
    /// Snapshot id allocated by the taker.
    pub snapshot_id: u32,
    /// Timestamp the snapshot was taken.
    pub snapshot_time: u32,
    /// Snapshots matching the selecting GetSnapshot.
    pub total_found: u8,
    /// Fragment index of this command.
    pub command_index: u8,
    /// Fragment count of this snapshot delivery.
    pub total_commands: u8,
    /// Cause map of the taken snapshot.
    pub cause: u32,
    /// Sub-payload shape selector.
    pub payload_type: u8,
}

/// Fixed PublishSnapshot header length.
pub const PUBLISH_HEADER_LEN: usize = 16;

/// Encode a PublishSnapshot body (header plus sub-payload) into
/// `out`; returns the total octets.
pub fn encode_publish_snapshot(
    hdr: &PublishSnapshot,
    sub: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if sub.len() > MAX_SNAPSHOT_SUB {
        return Err(Error::InvalidValue(sub.len() as u8));
    }
    let need = PUBLISH_HEADER_LEN + sub.len();
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    out[..4].copy_from_slice(&hdr.snapshot_id.to_le_bytes());
    out[4..8].copy_from_slice(&hdr.snapshot_time.to_le_bytes());
    out[8] = hdr.total_found;
    out[9] = hdr.command_index;
    out[10] = hdr.total_commands;
    out[11..15].copy_from_slice(&hdr.cause.to_le_bytes());
    out[15] = hdr.payload_type;
    out[PUBLISH_HEADER_LEN..need].copy_from_slice(sub);
    Ok(need)
}

/// Decoded PublishSnapshot body: header plus a bounded sub-payload
/// copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedPublish {
    /// Leading fields.
    pub header: PublishSnapshot,
    /// Sub-payload bytes.
    pub sub: [u8; MAX_SNAPSHOT_SUB],
    /// Significant sub-payload octets.
    pub sub_len: u8,
}

impl DecodedPublish {
    /// Sub-payload slice.
    #[must_use]
    pub const fn sub_payload(&self) -> &[u8] {
        self.sub.split_at(self.sub_len as usize).0
    }
}

/// Decode a PublishSnapshot body: 16-octet header plus at most
/// [`MAX_SNAPSHOT_SUB`] sub-payload octets.
pub fn decode_publish_snapshot(buf: &[u8]) -> Result<DecodedPublish, Error> {
    if buf.len() < PUBLISH_HEADER_LEN {
        return Err(Error::Truncated);
    }
    let sub_len = buf.len() - PUBLISH_HEADER_LEN;
    if sub_len > MAX_SNAPSHOT_SUB {
        return Err(Error::InvalidValue(sub_len as u8));
    }
    let mut sub = [0u8; MAX_SNAPSHOT_SUB];
    sub[..sub_len].copy_from_slice(&buf[PUBLISH_HEADER_LEN..]);
    Ok(DecodedPublish {
        header: PublishSnapshot {
            snapshot_id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            snapshot_time: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            total_found: buf[8],
            command_index: buf[9],
            total_commands: buf[10],
            cause: u32::from_le_bytes([buf[11], buf[12], buf[13], buf[14]]),
            payload_type: buf[15],
        },
        sub,
        sub_len: sub_len as u8,
    })
}

/// Build a minimal TOU sub-payload (summation + billing pair +
/// trailing digit + tier tail) into `out`.
///
/// The typed layout here carries the delivered/received summation
/// (uint48), the bill-to-date value and stamp, the projected bill
/// value and stamp, the trailing-digit map, the tier count, and one
/// uint48 per tier — newest information first, tiers in index
/// order. Tiers beyond [`MAX_SNAPSHOT_TIERS`] are a field error
/// (bounded, never grown).
///
/// Requirement `07-5123-08-1045-02` (MINTED-pending-confirm).
#[allow(clippy::too_many_arguments)]
pub fn encode_tou_sub_payload(
    summation: u64,
    bill_to_date: u32,
    bill_stamp: u32,
    projected_bill: u32,
    projected_stamp: u32,
    trailing_digit: u8,
    tiers: &[u64],
    out: &mut [u8],
) -> Result<usize, Error> {
    if tiers.len() > MAX_SNAPSHOT_TIERS {
        return Err(Error::InvalidValue(tiers.len() as u8));
    }
    let need = 6 + 4 + 4 + 4 + 4 + 1 + 1 + 6 * tiers.len();
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    let sum48 = (summation & 0x0000_ffff_ffff_ffff).to_le_bytes();
    out[..6].copy_from_slice(&sum48[..6]);
    out[6..10].copy_from_slice(&bill_to_date.to_le_bytes());
    out[10..14].copy_from_slice(&bill_stamp.to_le_bytes());
    out[14..18].copy_from_slice(&projected_bill.to_le_bytes());
    out[18..22].copy_from_slice(&projected_stamp.to_le_bytes());
    out[22] = trailing_digit;
    out[23] = tiers.len() as u8;
    let mut i = 0;
    while i < tiers.len() {
        let t48 = (tiers[i] & 0x0000_ffff_ffff_ffff).to_le_bytes();
        out[24 + 6 * i..30 + 6 * i].copy_from_slice(&t48[..6]);
        i += 1;
    }
    Ok(need)
}

/// One stored snapshot: identity plus a bounded sub-payload copy.
///
/// Requirement `07-5123-08-1045-04` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// Snapshot id allocated at take time.
    pub id: u32,
    /// Timestamp the snapshot was taken.
    pub time: u32,
    /// Cause map (manual bit already folded in for takes).
    pub cause: u32,
    /// Sub-payload shape selector.
    pub payload_type: u8,
    /// Sub-payload bytes.
    pub sub: [u8; MAX_SNAPSHOT_SUB],
    /// Significant sub-payload octets.
    pub sub_len: u8,
}

impl Snapshot {
    /// Sub-payload slice.
    #[must_use]
    pub const fn sub_payload(&self) -> &[u8] {
        self.sub.split_at(self.sub_len as usize).0
    }
}

/// Bounded snapshot store: insertion-ordered ring with take and
/// filtered single-answer retrieval.
///
/// Requirement `07-5123-08-1045-04` (MINTED-pending-confirm): takes
/// allocate consecutive ids and evict the oldest snapshot when
/// full; tariff-change takes land as before/after pairs (see
/// [`SnapshotStore::take_pair`]).
///
/// Requirement `17-05019-012-423-02` (corpus-mined): a query
/// answers the single matching snapshot (offset selects the nth
/// match in take order); no match answers `NOT_FOUND`.
#[derive(Clone, Copy, Debug)]
pub struct SnapshotStore {
    entries: [Option<Snapshot>; MAX_SNAPSHOTS],
    len: u8,
    next_id: u32,
}

impl Default for SnapshotStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotStore {
    /// Empty store; first snapshot takes id 0.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_SNAPSHOTS],
            len: 0,
            next_id: 0,
        }
    }

    /// Stored snapshot count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// No snapshots stored.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether `cause` is acceptable (defined bits only).
    #[must_use]
    pub const fn cause_supported(cause: u32) -> bool {
        cause & !SUPPORTED_CAUSES == 0
    }

    /// Take one snapshot: unsupported causes answer
    /// cause-not-supported and store nothing; accepted takes store
    /// (evicting the oldest when full) and return the fresh id plus
    /// the accepted verdict.
    pub fn take(&mut self, time: u32, cause: u32, payload_type: u8, sub: &[u8]) -> (u32, u8) {
        if !Self::cause_supported(cause) {
            return (0, CONFIRM_CAUSE_NOT_SUPPORTED);
        }
        if sub.len() > MAX_SNAPSHOT_SUB {
            return (0, CONFIRM_CAUSE_NOT_SUPPORTED);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let mut bytes = [0u8; MAX_SNAPSHOT_SUB];
        bytes[..sub.len()].copy_from_slice(sub);
        let snap = Snapshot {
            id,
            time,
            cause,
            payload_type,
            sub: bytes,
            sub_len: sub.len() as u8,
        };
        if self.len as usize >= MAX_SNAPSHOTS {
            // Evict the oldest (slot 0) and shift down.
            let mut i = 0;
            while i + 1 < MAX_SNAPSHOTS {
                self.entries[i] = self.entries[i + 1];
                i += 1;
            }
            self.entries[MAX_SNAPSHOTS - 1] = Some(snap);
        } else {
            self.entries[self.len as usize] = Some(snap);
            self.len += 1;
        }
        (id, CONFIRM_ACCEPTED)
    }

    /// Take a tariff-change before/after pair: two consecutive takes
    /// sharing the cause, each with its own sub-payload. Returns
    /// both ids (or the refusal verdict twice when the cause is
    /// unsupported).
    pub fn take_pair(
        &mut self,
        time: u32,
        cause: u32,
        payload_type: u8,
        before: &[u8],
        after: &[u8],
    ) -> ([u32; 2], u8) {
        let (first, conf) = self.take(time, cause, payload_type, before);
        if conf != CONFIRM_ACCEPTED {
            return ([0, 0], conf);
        }
        let (second, _) = self.take(time, cause, payload_type, after);
        ([first, second], CONFIRM_ACCEPTED)
    }

    /// Snapshots matching a GetSnapshot filter (the `total_found`
    /// field of a PublishSnapshot answer).
    pub fn match_count(&self, earliest: u32, latest: u32, cause: u32) -> u8 {
        let mut n = 0u8;
        let mut i = 0;
        while i < self.len as usize {
            if let Some(snap) = self.entries[i] {
                let time_hit = snap.time >= earliest && snap.time < latest;
                let cause_hit = cause == CAUSE_ALL || (snap.cause & cause) != 0;
                if time_hit && cause_hit {
                    n = n.saturating_add(1);
                }
            }
            i += 1;
        }
        n
    }

    /// Answer a GetSnapshot query: the offset-th snapshot in take
    /// order whose timestamp falls in `[earliest, latest)` and whose
    /// cause overlaps the filter (`CAUSE_ALL` takes everything).
    /// No match answers `NOT_FOUND`.
    pub fn query(
        &self,
        earliest: u32,
        latest: u32,
        offset: u8,
        cause: u32,
    ) -> Result<Snapshot, ZclStatus> {
        let mut skip = offset as usize;
        let mut i = 0;
        while i < self.len as usize {
            if let Some(snap) = self.entries[i] {
                let time_hit = snap.time >= earliest && snap.time < latest;
                let cause_hit = cause == CAUSE_ALL || (snap.cause & cause) != 0;
                if time_hit && cause_hit {
                    if skip == 0 {
                        return Ok(snap);
                    }
                    skip -= 1;
                }
            }
            i += 1;
        }
        Err(ZclStatus::NotFound)
    }
}
