//! Daily Schedule cluster (0x070D): server definition, schedule
//! codecs, and the bounded schedule/day-profile store.
//!
//! Paraphrase-level model of doc `17-05035-016` §10.15 (overview
//! anchors p0007-L56-L81, revision anchor p0008-L102-L103,
//! identifiers anchor p0008-L104-L106, attribute sets anchors
//! p0009-L108-L130, peak-status anchors p0011-L144-L176,
//! server-command table anchor p0013-L177-L180, PublishSchedule
//! payload anchor p0013-L192-L194 + details p0013-L195-L202 +
//! p0014-L203-L223, PublishDayProfile anchors p0015-L241-L244 +
//! p0016-L245-L264 + Linky entries p0016-L265-L276, cancel
//! anchors p0017-L278-L308, received-command table anchor
//! p0018-L309-L313, GetSchedule anchors p0018-L314-L336,
//! GetDayProfile anchors p0019-L337-L347, cancellation-fetch
//! anchors p0019-L348-L358). All wording here is paraphrase (D1).
//!
//! Requirement IDs below are repo-minted
//! (`17-05035-016-1015-<seq>`, dots stripped),
//! MINTED-pending-confirm.

use crate::attrs::{access, AttrDef, AttrStore, ATTR_CLUSTER_REVISION};
use crate::behavior::{AppEvent, Behavior, Ctx, HandleOutcome};
use crate::cluster::{ClusterDef, ClusterRole, CmdDef};
use crate::frame::{Direction, FrameControl, FrameType, Header};
use crate::types::{DataType, Value};
use crate::{Error, ZclStatus};

/// Cluster identifier.
///
/// Requirement `17-05035-016-1015-01` (MINTED-pending-confirm).
pub const CLUSTER_ID: u16 = 0x070D;
/// Implemented specification revision (rev table tip: initial).
///
/// Requirement `17-05035-016-1015-02` (MINTED-pending-confirm).
pub const REVISION: u16 = 1;

/// Auxiliary switch label 1..8.
pub const ATTR_AUX_LABEL_BASE: u16 = 0x0000;
/// Current auxiliary-switch bitmap (bit n = switch n+1 on).
pub const ATTR_AUX_STATE: u16 = 0x0100;
/// Register tier active in the current day-profile entry.
pub const ATTR_CURRENT_TIER: u16 = 0x0101;
/// Name of the register tier active now.
pub const ATTR_CURRENT_TIER_LABEL: u16 = 0x0102;
/// Day-color / peak-planning bitmap (Linky).
pub const ATTR_PEAK_STATUS: u16 = 0x0103;
/// Start of the planned peak period (UTC, unset = all-ones).
pub const ATTR_PEAK_START: u16 = 0x0104;
/// End of the planned peak period (UTC, unset = all-ones).
pub const ATTR_PEAK_END: u16 = 0x0105;
/// Name of the tariff active now.
pub const ATTR_CURRENT_TARIFF_LABEL: u16 = 0x0106;

/// Switch label count carried by this cluster.
pub const AUX_LABEL_COUNT: usize = 8;
/// Longest auxiliary-switch label body (octets).
pub const MAX_AUX_LABEL: usize = 23;
/// Longest tier-label body (octets).
pub const MAX_TIER_LABEL: usize = 17;
/// Longest tariff-label body (octets).
pub const MAX_TARIFF_LABEL: usize = 25;
/// Longest schedule-name body (octets).
pub const MAX_SCHEDULE_NAME: usize = 12;
/// Schedules retained (current plus next, per the overview).
pub const MAX_SCHEDULES: usize = 2;
/// Day-profile entries retained per profile here.
pub const MAX_DAY_ENTRIES: usize = 24;
/// Day-profile fragments assembled per command here.
pub const MAX_DAY_FRAGMENTS: u8 = 4;

/// Server received: fetch schedules.
pub const CMD_GET_SCHEDULE: u8 = 0x00;
/// Server received: fetch a day profile.
pub const CMD_GET_DAY_PROFILE: u8 = 0x01;
/// Server received: fetch a pending cancellation.
pub const CMD_GET_SCHEDULE_CANCELLATION: u8 = 0x05;
/// Server generated: publish one schedule.
pub const CMD_PUBLISH_SCHEDULE: u8 = 0x00;
/// Server generated: publish day-profile entries.
pub const CMD_PUBLISH_DAY_PROFILE: u8 = 0x01;
/// Server generated: withdraw one schedule instance.
pub const CMD_CANCEL_SCHEDULE: u8 = 0x05;
/// Server generated: withdraw every schedule.
pub const CMD_CANCEL_ALL_SCHEDULES: u8 = 0x06;

/// Schedule type: the Linky day-entry shape.
pub const SCHED_TYPE_LINKY: u8 = 0x00;
/// Schedule type wildcard used by fetch commands (any type).
pub const SCHED_TYPE_ANY: u8 = 0xff;
/// Time reference: entries count in UTC.
pub const TIME_REF_UTC: u8 = 0x00;
/// Time reference: entries count in zone standard time.
pub const TIME_REF_STANDARD: u8 = 0x01;
/// Time reference: entries count in local wall time.
pub const TIME_REF_LOCAL: u8 = 0x02;
/// Provider wildcard (matches every provider).
pub const PROVIDER_ANY: u32 = 0xffff_ffff;
/// Issuer wildcard (matches every issuer event).
pub const ISSUER_ANY: u32 = 0xffff_ffff;
/// Timestamp meaning "no peak bound set".
pub const PEAK_UNSET: u32 = 0xffff_ffff;
/// Start value meaning "run now" on publish.
pub const START_NOW: u32 = 0x0000_0000;

/// Peak color: low tariff day.
pub const COLOR_BLUE: u8 = 0x01;
/// Peak color: medium tariff day.
pub const COLOR_WHITE: u8 = 0x02;
/// Peak color: high tariff day.
pub const COLOR_RED: u8 = 0x03;

/// Current-day color field (bits 0-1) of the peak bitmap.
#[must_use]
pub const fn day_color(status: u8) -> u8 {
    status & 0x03
}

/// Next-day color field (bits 2-3) of the peak bitmap.
#[must_use]
pub const fn next_day_color(status: u8) -> u8 {
    (status >> 2) & 0x03
}

/// Peak-notice field (bits 4-5) of the peak bitmap.
#[must_use]
pub const fn peak_notice(status: u8) -> u8 {
    (status >> 4) & 0x03
}

/// On-peak field (bits 6-7) of the peak bitmap.
#[must_use]
pub const fn on_peak(status: u8) -> u8 {
    (status >> 6) & 0x03
}

/// Whether a color field names a defined day color.
#[must_use]
pub const fn color_known(color: u8) -> bool {
    matches!(color, COLOR_BLUE | COLOR_WHITE | COLOR_RED)
}

/// Whether the time reference names a defined interpretation.
#[must_use]
pub const fn time_ref_known(time_ref: u8) -> bool {
    matches!(time_ref, TIME_REF_UTC | TIME_REF_STANDARD | TIME_REF_LOCAL)
}

/// Highest register tier this model files (matches the tier table
/// range carried alongside the attribute set).
pub const MAX_TIER: u8 = 48;

/// One Linky day-profile entry: minutes after midnight, the tier in
/// force from then on, and the auxiliary-switch bitmap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DayEntry {
    /// Start time, minutes after midnight.
    pub start_min: u16,
    /// Register tier in force from `start_min`.
    pub tier: u8,
    /// Auxiliary-switch bitmap in force from `start_min`.
    pub aux: u8,
}

/// Entry wire length (start + tier + switch bitmap).
pub const DAY_ENTRY_LEN: usize = 4;

/// Decode one 4-octet day-profile entry.
pub fn decode_day_entry(buf: &[u8]) -> Result<DayEntry, Error> {
    if buf.len() != DAY_ENTRY_LEN {
        return Err(Error::Truncated);
    }
    let start_min = u16::from_le_bytes([buf[0], buf[1]]);
    if start_min >= 1440 {
        return Err(Error::InvalidValue(buf[1]));
    }
    if buf[2] > MAX_TIER {
        return Err(Error::InvalidValue(buf[2]));
    }
    Ok(DayEntry {
        start_min,
        tier: buf[2],
        aux: buf[3],
    })
}

/// Encode one day-profile entry.
pub fn encode_day_entry(entry: &DayEntry, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < DAY_ENTRY_LEN {
        return Err(Error::BufferTooSmall);
    }
    if entry.start_min >= 1440 {
        return Err(Error::InvalidValue((entry.start_min >> 8) as u8));
    }
    if entry.tier > MAX_TIER {
        return Err(Error::InvalidValue(entry.tier));
    }
    out[0..2].copy_from_slice(&entry.start_min.to_le_bytes());
    out[2] = entry.tier;
    out[3] = entry.aux;
    Ok(DAY_ENTRY_LEN)
}

/// One published schedule instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    /// Commodity provider.
    pub provider: u32,
    /// Provider-side event serial (newer wins).
    pub issuer: u32,
    /// Supplier schedule identifier.
    pub schedule_id: u32,
    /// Day-profile reference.
    pub day_id: u16,
    /// Moment the schedule takes effect (UTC).
    pub start: u32,
    /// Entry shape selector (Linky here).
    pub sched_type: u8,
    /// How entry times are interpreted.
    pub time_ref: u8,
    /// Schedule name body length.
    pub name_len: u8,
    /// Schedule name body (UTF-8).
    pub name: [u8; MAX_SCHEDULE_NAME],
}

impl Schedule {
    /// Name bytes significant in `name`.
    #[must_use]
    pub const fn name_bytes(&self) -> &[u8] {
        self.name.split_at(self.name_len as usize).0
    }
}

/// PublishSchedule fixed prefix length (before the name string).
pub const PUBLISH_SCHEDULE_PREFIX: usize = 20;

/// Encode a PublishSchedule body.
pub fn encode_publish_schedule(sched: &Schedule, out: &mut [u8]) -> Result<usize, Error> {
    if sched.sched_type != SCHED_TYPE_LINKY {
        return Err(Error::InvalidValue(sched.sched_type));
    }
    if !time_ref_known(sched.time_ref) {
        return Err(Error::InvalidValue(sched.time_ref));
    }
    if sched.name_len as usize > MAX_SCHEDULE_NAME {
        return Err(Error::InvalidValue(sched.name_len));
    }
    let need = PUBLISH_SCHEDULE_PREFIX + 1 + sched.name_len as usize;
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&sched.provider.to_le_bytes());
    out[4..8].copy_from_slice(&sched.issuer.to_le_bytes());
    out[8..12].copy_from_slice(&sched.schedule_id.to_le_bytes());
    out[12..14].copy_from_slice(&sched.day_id.to_le_bytes());
    out[14..18].copy_from_slice(&sched.start.to_le_bytes());
    out[18] = sched.sched_type;
    out[19] = sched.time_ref;
    out[20] = sched.name_len;
    out[21..21 + sched.name_len as usize].copy_from_slice(&sched.name[..sched.name_len as usize]);
    Ok(need)
}

/// Decode a PublishSchedule body.
pub fn decode_publish_schedule(buf: &[u8]) -> Result<Schedule, Error> {
    if buf.len() < PUBLISH_SCHEDULE_PREFIX + 1 {
        return Err(Error::Truncated);
    }
    let name_len = buf[20] as usize;
    if name_len > MAX_SCHEDULE_NAME || buf.len() != PUBLISH_SCHEDULE_PREFIX + 1 + name_len {
        return Err(Error::InvalidValue(buf[20]));
    }
    if buf[18] != SCHED_TYPE_LINKY {
        return Err(Error::InvalidValue(buf[18]));
    }
    if !time_ref_known(buf[19]) {
        return Err(Error::InvalidValue(buf[19]));
    }
    let mut name = [0u8; MAX_SCHEDULE_NAME];
    name[..name_len].copy_from_slice(&buf[21..21 + name_len]);
    Ok(Schedule {
        provider: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        issuer: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        schedule_id: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        day_id: u16::from_le_bytes([buf[12], buf[13]]),
        start: u32::from_le_bytes([buf[14], buf[15], buf[16], buf[17]]),
        sched_type: buf[18],
        time_ref: buf[19],
        name_len: buf[20],
        name,
    })
}

/// PublishDayProfile fixed prefix length (before the entry list).
pub const PUBLISH_DAY_PREFIX: usize = 15;

/// Decoded PublishDayProfile body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedDayProfile {
    /// Commodity provider.
    pub provider: u32,
    /// Provider-side event serial.
    pub issuer: u32,
    /// Day-profile reference.
    pub day_id: u16,
    /// Entries in the whole profile (all fragments).
    pub total_entries: u8,
    /// This fragment's index.
    pub cmd_index: u8,
    /// Fragment count for the whole profile.
    pub total_cmds: u8,
    /// Entry shape selector.
    pub sched_type: u8,
    /// Entries carried by this fragment.
    pub entries: [DayEntry; MAX_DAY_ENTRIES],
    /// Significant entries in `entries`.
    pub count: u8,
}

/// Encode a PublishDayProfile fragment body.
#[allow(clippy::too_many_arguments)]
pub fn encode_publish_day_profile(
    provider: u32,
    issuer: u32,
    day_id: u16,
    total_entries: u8,
    cmd_index: u8,
    total_cmds: u8,
    sched_type: u8,
    entries: &[DayEntry],
    out: &mut [u8],
) -> Result<usize, Error> {
    if sched_type != SCHED_TYPE_LINKY {
        return Err(Error::InvalidValue(sched_type));
    }
    if total_cmds == 0 || total_cmds > MAX_DAY_FRAGMENTS || cmd_index >= total_cmds {
        return Err(Error::InvalidValue(cmd_index));
    }
    if entries.len() > MAX_DAY_ENTRIES {
        return Err(Error::InvalidValue(entries.len() as u8));
    }
    let need = PUBLISH_DAY_PREFIX + DAY_ENTRY_LEN * entries.len();
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&provider.to_le_bytes());
    out[4..8].copy_from_slice(&issuer.to_le_bytes());
    out[8..10].copy_from_slice(&day_id.to_le_bytes());
    out[10] = total_entries;
    out[11] = cmd_index;
    out[12] = total_cmds;
    out[13] = sched_type;
    out[14] = entries.len() as u8;
    let mut i = 0;
    while i < entries.len() {
        encode_day_entry(
            &entries[i],
            &mut out[PUBLISH_DAY_PREFIX + DAY_ENTRY_LEN * i..],
        )?;
        i += 1;
    }
    Ok(need)
}

/// Decode a PublishDayProfile fragment body.
pub fn decode_publish_day_profile(buf: &[u8]) -> Result<DecodedDayProfile, Error> {
    if buf.len() < PUBLISH_DAY_PREFIX {
        return Err(Error::Truncated);
    }
    // The trailing prefix octet mirrors the entry body length.
    let body_count = buf[PUBLISH_DAY_PREFIX - 1] as usize;
    if buf.len() != PUBLISH_DAY_PREFIX + DAY_ENTRY_LEN * body_count {
        return Err(Error::Truncated);
    }
    if body_count > MAX_DAY_ENTRIES {
        return Err(Error::InvalidValue(body_count as u8));
    }
    if buf[13] != SCHED_TYPE_LINKY {
        return Err(Error::InvalidValue(buf[13]));
    }
    if buf[12] == 0 || buf[12] > MAX_DAY_FRAGMENTS || buf[11] >= buf[12] {
        return Err(Error::InvalidValue(buf[11]));
    }
    let mut entries = [DayEntry {
        start_min: 0,
        tier: 0,
        aux: 0,
    }; MAX_DAY_ENTRIES];
    let mut i = 0;
    while i < body_count {
        entries[i] = decode_day_entry(
            &buf[PUBLISH_DAY_PREFIX + DAY_ENTRY_LEN * i
                ..PUBLISH_DAY_PREFIX + DAY_ENTRY_LEN * (i + 1)],
        )?;
        i += 1;
    }
    Ok(DecodedDayProfile {
        provider: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        issuer: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        day_id: u16::from_le_bytes([buf[8], buf[9]]),
        total_entries: buf[10],
        cmd_index: buf[11],
        total_cmds: buf[12],
        sched_type: buf[13],
        entries,
        count: body_count as u8,
    })
}

/// CancelSchedule body length (provider + schedule + type).
pub const CANCEL_SCHEDULE_LEN: usize = 9;

/// One filed cancellation (single-schedule or all-schedules).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cancellation {
    /// Commodity provider the cancellation applies to.
    pub provider: u32,
    /// Schedule withdrawn (`u32::MAX` marks every schedule).
    pub schedule_id: u32,
    /// Entry shape withdrawn.
    pub sched_type: u8,
    /// True for the withdraw-everything form.
    pub all: bool,
}

/// Encode a CancelSchedule body.
pub fn encode_cancel_schedule(cancel: &Cancellation, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < CANCEL_SCHEDULE_LEN {
        return Err(Error::BufferTooSmall);
    }
    if cancel.all {
        return Err(Error::InvalidValue(0xff));
    }
    out[0..4].copy_from_slice(&cancel.provider.to_le_bytes());
    out[4..8].copy_from_slice(&cancel.schedule_id.to_le_bytes());
    out[8] = cancel.sched_type;
    Ok(CANCEL_SCHEDULE_LEN)
}

/// Decode a CancelSchedule body.
pub fn decode_cancel_schedule(buf: &[u8]) -> Result<Cancellation, Error> {
    if buf.len() != CANCEL_SCHEDULE_LEN {
        return Err(Error::Truncated);
    }
    if buf[8] != SCHED_TYPE_LINKY {
        return Err(Error::InvalidValue(buf[8]));
    }
    Ok(Cancellation {
        provider: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        schedule_id: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        sched_type: buf[8],
        all: false,
    })
}

/// GetSchedule body length.
pub const GET_SCHEDULE_LEN: usize = 14;

/// Fetch filter carried by GetSchedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduleQuery {
    /// Provider filter (`PROVIDER_ANY` matches all).
    pub provider: u32,
    /// Earliest start accepted in replies.
    pub earliest_start: u32,
    /// Minimum issuer accepted in replies.
    pub min_issuer: u32,
    /// Reply cap (0 means every match).
    pub max_count: u8,
    /// Type filter (`SCHED_TYPE_ANY` matches all).
    pub sched_type: u8,
}

/// Decode a GetSchedule body.
pub fn decode_get_schedule(buf: &[u8]) -> Result<ScheduleQuery, Error> {
    if buf.len() != GET_SCHEDULE_LEN {
        return Err(Error::Truncated);
    }
    Ok(ScheduleQuery {
        provider: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        earliest_start: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        min_issuer: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        max_count: buf[12],
        sched_type: buf[13],
    })
}

/// Encode a GetSchedule body.
pub fn encode_get_schedule(query: &ScheduleQuery, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < GET_SCHEDULE_LEN {
        return Err(Error::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&query.provider.to_le_bytes());
    out[4..8].copy_from_slice(&query.earliest_start.to_le_bytes());
    out[8..12].copy_from_slice(&query.min_issuer.to_le_bytes());
    out[12] = query.max_count;
    out[13] = query.sched_type;
    Ok(GET_SCHEDULE_LEN)
}

/// GetDayProfile body length (provider + day id).
pub const GET_DAY_PROFILE_LEN: usize = 6;

/// Decode a GetDayProfile body.
pub fn decode_get_day_profile(buf: &[u8]) -> Result<(u32, u16), Error> {
    if buf.len() != GET_DAY_PROFILE_LEN {
        return Err(Error::Truncated);
    }
    Ok((
        u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        u16::from_le_bytes([buf[4], buf[5]]),
    ))
}

/// Encode a GetDayProfile body.
pub fn encode_get_day_profile(provider: u32, day_id: u16, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < GET_DAY_PROFILE_LEN {
        return Err(Error::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&provider.to_le_bytes());
    out[4..6].copy_from_slice(&day_id.to_le_bytes());
    Ok(GET_DAY_PROFILE_LEN)
}

/// One stored day profile: the entry list behind a day id.
#[derive(Clone, Copy, Debug)]
pub struct DayProfile {
    /// Commodity provider.
    pub provider: u32,
    /// Provider-side event serial of the filed fragments.
    pub issuer: u32,
    /// Day-profile reference.
    pub day_id: u16,
    /// Filed entries, ascending by start.
    pub entries: [DayEntry; MAX_DAY_ENTRIES],
    /// Significant entries in `entries`.
    pub count: u8,
}

/// Bounded schedule/day-profile store: at most two schedule
/// instances (current plus next) with their day profiles, newer
/// issuer serials replacing older information for the same period.
///
/// Requirement `17-05035-016-1015-03` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug)]
pub struct ScheduleStore {
    schedules: [Option<Schedule>; MAX_SCHEDULES],
    len: u8,
    profiles: [Option<DayProfile>; MAX_SCHEDULES],
    profile_len: u8,
    pending_cancel: Option<Cancellation>,
}

impl Default for ScheduleStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ScheduleStore {
    /// Empty store with no pending cancellation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            schedules: [None; MAX_SCHEDULES],
            len: 0,
            profiles: [None; MAX_SCHEDULES],
            profile_len: 0,
            pending_cancel: None,
        }
    }

    /// Filed schedule count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// No schedules filed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Last cancellation still awaiting fetch, if any.
    #[must_use]
    pub const fn pending_cancel(&self) -> Option<Cancellation> {
        self.pending_cancel
    }

    /// File one schedule: same-id refiles keep the newer issuer
    /// only; other-type instances are untouched; a full store
    /// refuses with insufficient-space.
    pub fn file_schedule(&mut self, sched: &Schedule) -> Result<(), ZclStatus> {
        if sched.sched_type != SCHED_TYPE_LINKY || !time_ref_known(sched.time_ref) {
            return Err(ZclStatus::InvalidField);
        }
        let mut i = 0;
        while i < self.len as usize {
            if let Some(filed) = self.schedules[i] {
                if filed.provider == sched.provider && filed.schedule_id == sched.schedule_id {
                    if sched.issuer < filed.issuer {
                        return Ok(());
                    }
                    self.schedules[i] = Some(*sched);
                    return Ok(());
                }
            }
            i += 1;
        }
        if self.len as usize >= MAX_SCHEDULES {
            return Err(ZclStatus::InsufficientSpace);
        }
        self.schedules[self.len as usize] = Some(*sched);
        self.len += 1;
        Ok(())
    }

    /// File one day profile: entries must arrive ascending with the
    /// first at midnight; the newer issuer wins per day id.
    pub fn file_profile(&mut self, profile: &DayProfile) -> Result<(), ZclStatus> {
        if profile.count as usize > MAX_DAY_ENTRIES {
            return Err(ZclStatus::InvalidField);
        }
        let mut i = 0;
        while i < profile.count as usize {
            if i == 0 && profile.entries[0].start_min != 0 {
                return Err(ZclStatus::InvalidField);
            }
            if i > 0 && profile.entries[i].start_min <= profile.entries[i - 1].start_min {
                return Err(ZclStatus::InvalidField);
            }
            i += 1;
        }
        let mut j = 0;
        while j < self.profile_len as usize {
            if let Some(filed) = self.profiles[j] {
                if filed.provider == profile.provider && filed.day_id == profile.day_id {
                    if profile.issuer < filed.issuer {
                        return Ok(());
                    }
                    self.profiles[j] = Some(*profile);
                    return Ok(());
                }
            }
            j += 1;
        }
        if self.profile_len as usize >= MAX_SCHEDULES {
            return Err(ZclStatus::InsufficientSpace);
        }
        self.profiles[self.profile_len as usize] = Some(*profile);
        self.profile_len += 1;
        Ok(())
    }

    /// Schedule currently in force at `now_utc` (latest start at or
    /// before now), if any.
    #[must_use]
    pub fn active_at(&self, now_utc: u32) -> Option<Schedule> {
        let mut best: Option<Schedule> = None;
        let mut i = 0;
        while i < self.len as usize {
            if let Some(filed) = self.schedules[i] {
                if filed.start <= now_utc {
                    let newer = match best {
                        Some(cur) => filed.start >= cur.start,
                        None => true,
                    };
                    if newer {
                        best = Some(filed);
                    }
                }
            }
            i += 1;
        }
        best
    }

    /// Tier and switch bitmap in force at `now_utc` under the active
    /// schedule's day profile (minutes counted inside the UTC day).
    pub fn evaluate(&self, now_utc: u32) -> Option<(u8, u8)> {
        let sched = self.active_at(now_utc)?;
        let mut i = 0;
        while i < self.profile_len as usize {
            if let Some(profile) = self.profiles[i] {
                if (profile.provider == sched.provider || profile.provider == PROVIDER_ANY)
                    && profile.day_id == sched.day_id
                    && profile.count > 0
                {
                    let minute = (now_utc % 86_400) / 60;
                    let mut tier = profile.entries[0].tier;
                    let mut aux = profile.entries[0].aux;
                    let mut k = 0;
                    while k < profile.count as usize {
                        if (profile.entries[k].start_min as u32) <= minute {
                            tier = profile.entries[k].tier;
                            aux = profile.entries[k].aux;
                        }
                        k += 1;
                    }
                    return Some((tier, aux));
                }
            }
            i += 1;
        }
        None
    }

    /// Withdraw one schedule instance (plus its day profile when the
    /// provider and day id line up) and remember the cancellation
    /// for fetch; unknown ids answer not-found.
    pub fn cancel(&mut self, cancel: &Cancellation) -> Result<(), ZclStatus> {
        let mut found = false;
        let mut i = 0;
        while i < self.len as usize {
            if let Some(filed) = self.schedules[i] {
                if filed.provider == cancel.provider
                    && filed.schedule_id == cancel.schedule_id
                    && (cancel.sched_type == SCHED_TYPE_ANY
                        || filed.sched_type == cancel.sched_type)
                {
                    self.schedules[i] = None;
                    found = true;
                }
            }
            i += 1;
        }
        if !found {
            return Err(ZclStatus::NotFound);
        }
        // Compact the surviving schedules down.
        let mut w = 0;
        let mut r = 0;
        while r < self.len as usize {
            if let Some(filed) = self.schedules[r] {
                self.schedules[w] = Some(filed);
                w += 1;
            }
            r += 1;
        }
        #[allow(clippy::cast_possible_truncation)]
        let kept = w.min(MAX_SCHEDULES) as u8;
        let mut c = kept as usize;
        while c < self.len as usize {
            self.schedules[c] = None;
            c += 1;
        }
        self.len = kept;
        self.pending_cancel = Some(*cancel);
        Ok(())
    }

    /// Withdraw every schedule and profile; the fetch queue then
    /// reports the withdraw-everything marker.
    pub fn cancel_all(&mut self, provider: u32) {
        let mut i = 0;
        while i < MAX_SCHEDULES {
            self.schedules[i] = None;
            self.profiles[i] = None;
            i += 1;
        }
        self.len = 0;
        self.profile_len = 0;
        self.pending_cancel = Some(Cancellation {
            provider,
            schedule_id: u32::MAX,
            sched_type: SCHED_TYPE_LINKY,
            all: true,
        });
    }
}

/// Scheduled tier/switch application target: the attributes the
/// behavior refreshes from [`ScheduleStore::evaluate`].
pub const EVAL_ATTRS: [u16; 2] = [ATTR_AUX_STATE, ATTR_CURRENT_TIER];

/// Server attribute table, ascending.
///
/// Requirement `17-05035-016-1015-04` (MINTED-pending-confirm).
pub static SERVER_ATTRS: &[AttrDef] = &[
    AttrDef {
        id: 0x0000,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: 0x0001,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: 0x0002,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: 0x0003,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: 0x0004,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: 0x0005,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: 0x0006,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: 0x0007,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_AUX_STATE,
        datatype: DataType::Map(1).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_CURRENT_TIER,
        datatype: DataType::Enum8.as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_CURRENT_TIER_LABEL,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_PEAK_STATUS,
        datatype: DataType::Map(1).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_PEAK_START,
        datatype: DataType::Time(0xe2).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_PEAK_END,
        datatype: DataType::Time(0xe2).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_CURRENT_TARIFF_LABEL,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_CLUSTER_REVISION,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ,
        reportable: false,
    },
];

/// Server received commands, ascending.
pub static SERVER_RX: &[CmdDef] = &[
    CmdDef {
        id: CMD_GET_SCHEDULE,
        name: "get-schedule",
    },
    CmdDef {
        id: CMD_GET_DAY_PROFILE,
        name: "get-day-profile",
    },
    CmdDef {
        id: CMD_GET_SCHEDULE_CANCELLATION,
        name: "get-schedule-cancellation",
    },
];

/// Server generated commands, ascending.
pub static SERVER_TX: &[CmdDef] = &[
    CmdDef {
        id: CMD_PUBLISH_SCHEDULE,
        name: "publish-schedule",
    },
    CmdDef {
        id: CMD_PUBLISH_DAY_PROFILE,
        name: "publish-day-profile",
    },
    CmdDef {
        id: CMD_CANCEL_SCHEDULE,
        name: "cancel-schedule",
    },
    CmdDef {
        id: CMD_CANCEL_ALL_SCHEDULES,
        name: "cancel-all-schedules",
    },
];

/// Server definition.
pub struct ServerDef;
impl ClusterDef for ServerDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "daily-schedule-server"
    }
    fn revision(&self) -> u16 {
        REVISION
    }
    fn role(&self) -> ClusterRole {
        ClusterRole::Server
    }
    fn attributes(&self) -> &'static [AttrDef] {
        SERVER_ATTRS
    }
    fn received_commands(&self) -> &'static [CmdDef] {
        SERVER_RX
    }
    fn generated_commands(&self) -> &'static [CmdDef] {
        SERVER_TX
    }
}

/// Client definition (no attributes; generates the fetch commands).
pub struct ClientDef;
impl ClusterDef for ClientDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "daily-schedule-client"
    }
    fn revision(&self) -> u16 {
        REVISION
    }
    fn role(&self) -> ClusterRole {
        ClusterRole::Client
    }
    fn attributes(&self) -> &'static [AttrDef] {
        &[]
    }
    fn received_commands(&self) -> &'static [CmdDef] {
        SERVER_TX
    }
    fn generated_commands(&self) -> &'static [CmdDef] {
        SERVER_RX
    }
}

fn octet_str(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.len() > crate::types::MAX_STR_LEN {
        return Err(Error::StringTooLong);
    }
    let mut buf = [0u8; crate::types::MAX_STR_LEN];
    buf[..bytes.len()].copy_from_slice(bytes);
    #[allow(clippy::cast_possible_truncation)]
    let len = bytes.len() as u8;
    Ok(Value::OctetStr { len, bytes: buf })
}

/// Build a fresh server store with table defaults.
pub fn server_store() -> Result<AttrStore, Error> {
    let mut store = AttrStore::new(None);
    let labels = [
        "Auxiliary 1",
        "Auxiliary 2",
        "Auxiliary 3",
        "Auxiliary 4",
        "Auxiliary 5",
        "Auxiliary 6",
        "Auxiliary 7",
        "Auxiliary 8",
    ];
    let mut i = 0;
    while i < AUX_LABEL_COUNT {
        store.add(SERVER_ATTRS[i], octet_str(labels[i].as_bytes())?)?;
        i += 1;
    }
    store.add(
        SERVER_ATTRS[8],
        Value::Map {
            width: 1,
            bytes: [0; 8],
        },
    )?;
    store.add(SERVER_ATTRS[9], Value::Enum8(0))?;
    store.add(SERVER_ATTRS[10], octet_str(&[])?)?;
    store.add(
        SERVER_ATTRS[11],
        Value::Map {
            width: 1,
            bytes: [0; 8],
        },
    )?;
    store.add(
        SERVER_ATTRS[12],
        Value::Time {
            tag: 0xe2,
            v: PEAK_UNSET,
        },
    )?;
    store.add(
        SERVER_ATTRS[13],
        Value::Time {
            tag: 0xe2,
            v: PEAK_UNSET,
        },
    )?;
    store.add(SERVER_ATTRS[14], octet_str(&[])?)?;
    store.add_globals(REVISION)?;
    Ok(store)
}

/// Server behavior: answers the three fetch commands from the
/// [`ScheduleStore`] and refreshes the live tier/switch attributes.
///
/// Requirement `17-05035-016-1015-05` (MINTED-pending-confirm).
pub struct ServerBehavior {
    store: ScheduleStore,
}

impl Default for ServerBehavior {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBehavior {
    /// Behavior over a fresh schedule store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            store: ScheduleStore::new(),
        }
    }

    /// Mutable schedule store behind the behavior.
    pub const fn schedules(&mut self) -> &mut ScheduleStore {
        &mut self.store
    }

    /// Refresh the live tier/switch attributes from the profile in
    /// force at `now_utc`; returns the applied pair, if any.
    pub fn refresh_live(&mut self, ctx: &mut Ctx<'_>, now_utc: u32) -> Option<(u8, u8)> {
        let (tier, aux) = self.store.evaluate(now_utc)?;
        let _ = ctx.store.set_local(
            ATTR_AUX_STATE,
            Value::Map {
                width: 1,
                bytes: [aux, 0, 0, 0, 0, 0, 0, 0],
            },
        );
        let _ = ctx.store.set_local(ATTR_CURRENT_TIER, Value::Enum8(tier));
        ctx.events.push(AppEvent::AttributeChanged {
            cluster: CLUSTER_ID,
            attr: ATTR_AUX_STATE,
        });
        ctx.events.push(AppEvent::AttributeChanged {
            cluster: CLUSTER_ID,
            attr: ATTR_CURRENT_TIER,
        });
        Some((tier, aux))
    }
}

impl Behavior for ServerBehavior {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }

    fn handle_cluster_command(
        &mut self,
        ctx: &mut Ctx<'_>,
        _header: &Header,
        command_id: u8,
        payload: &[u8],
    ) -> Result<HandleOutcome, ZclStatus> {
        match command_id {
            CMD_GET_SCHEDULE => {
                let query =
                    decode_get_schedule(payload).map_err(|_| ZclStatus::MalformedCommand)?;
                // First match in ascending start order answers
                // inline; the rest ride along as outbound events.
                let mut matches: [Schedule; MAX_SCHEDULES] = [schedule_sentinel(); MAX_SCHEDULES];
                let mut n = 0;
                let mut i = 0;
                while i < self.store.len() {
                    if let Some(filed) = self.store.schedules[i] {
                        let provider_ok =
                            query.provider == PROVIDER_ANY || filed.provider == query.provider;
                        let issuer_ok =
                            query.min_issuer == ISSUER_ANY || filed.issuer >= query.min_issuer;
                        let start_ok = filed.start >= query.earliest_start;
                        let type_ok = query.sched_type == SCHED_TYPE_ANY
                            || filed.sched_type == query.sched_type;
                        if provider_ok && issuer_ok && start_ok && type_ok && n < MAX_SCHEDULES {
                            // Keep ascending by start (insertion).
                            let mut k = n;
                            while k > 0 && matches[k - 1].start > filed.start {
                                matches[k] = matches[k - 1];
                                k -= 1;
                            }
                            matches[k] = filed;
                            n += 1;
                        }
                    }
                    i += 1;
                }
                if query.max_count != 0 && (n as u8) > query.max_count {
                    n = query.max_count as usize;
                }
                if n == 0 {
                    return Err(ZclStatus::NotFound);
                }
                let mut first = [0u8; PUBLISH_SCHEDULE_PREFIX + 1 + MAX_SCHEDULE_NAME];
                let flen = encode_publish_schedule(&matches[0], &mut first)
                    .map_err(|_| ZclStatus::Failure)?;
                let mut j = 1;
                while j < n {
                    let mut rest = [0u8; PUBLISH_SCHEDULE_PREFIX + 1 + MAX_SCHEDULE_NAME];
                    if let Ok(rlen) = encode_publish_schedule(&matches[j], &mut rest) {
                        let mut body = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
                        body[..rlen].copy_from_slice(&rest[..rlen]);
                        #[allow(clippy::cast_possible_truncation)]
                        let len = rlen as u8;
                        ctx.events.push(AppEvent::OutboundCommand {
                            cluster: CLUSTER_ID,
                            cmd: CMD_PUBLISH_SCHEDULE,
                            tsn: 0,
                            len,
                            payload: body,
                        });
                    }
                    j += 1;
                }
                HandleOutcome::reply(CMD_PUBLISH_SCHEDULE, &first[..flen])
                    .map_err(|_| ZclStatus::Failure)
            }
            CMD_GET_DAY_PROFILE => {
                let (provider, day_id) =
                    decode_get_day_profile(payload).map_err(|_| ZclStatus::MalformedCommand)?;
                let mut i = 0;
                while i < self.store.profile_len as usize {
                    if let Some(profile) = self.store.profiles[i] {
                        if (provider == PROVIDER_ANY || profile.provider == provider)
                            && profile.day_id == day_id
                        {
                            let mut body =
                                [0u8; PUBLISH_DAY_PREFIX + DAY_ENTRY_LEN * MAX_DAY_ENTRIES];
                            let blen = encode_publish_day_profile(
                                profile.provider,
                                profile.issuer,
                                profile.day_id,
                                profile.count,
                                0,
                                1,
                                SCHED_TYPE_LINKY,
                                &profile.entries[..profile.count as usize],
                                &mut body,
                            )
                            .map_err(|_| ZclStatus::Failure)?;
                            return HandleOutcome::reply(CMD_PUBLISH_DAY_PROFILE, &body[..blen])
                                .map_err(|_| ZclStatus::Failure);
                        }
                    }
                    i += 1;
                }
                Err(ZclStatus::NotFound)
            }
            CMD_GET_SCHEDULE_CANCELLATION => {
                if !payload.is_empty() {
                    return Err(ZclStatus::MalformedCommand);
                }
                match self.store.pending_cancel {
                    Some(cancel) if !cancel.all => {
                        let mut body = [0u8; CANCEL_SCHEDULE_LEN];
                        encode_cancel_schedule(&cancel, &mut body)
                            .map_err(|_| ZclStatus::Failure)?;
                        HandleOutcome::reply(CMD_CANCEL_SCHEDULE, &body)
                            .map_err(|_| ZclStatus::Failure)
                    }
                    Some(_) => Ok(HandleOutcome::no_reply()),
                    None => Err(ZclStatus::NotFound),
                }
            }
            _ => Err(ZclStatus::UnsupCommand),
        }
    }
}

const fn schedule_sentinel() -> Schedule {
    Schedule {
        provider: 0,
        issuer: 0,
        schedule_id: 0,
        day_id: 0,
        start: u32::MAX,
        sched_type: SCHED_TYPE_LINKY,
        time_ref: TIME_REF_UTC,
        name_len: 0,
        name: [0; MAX_SCHEDULE_NAME],
    }
}

/// Client-side fetch builders (client-to-server frames).
pub mod client {
    use super::*;

    fn frame(tsn: u8, cmd: u8, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let header = Header {
            control: FrameControl {
                frame_type: FrameType::ClusterSpecific,
                manufacturer_specific: false,
                direction: Direction::ToServer,
                disable_default_response: false,
            },
            manufacturer_code: None,
            tsn,
            command_id: cmd,
        };
        let hn = header.encode_into(out)?;
        if out.len() - hn < payload.len() {
            return Err(Error::BufferTooSmall);
        }
        out[hn..hn + payload.len()].copy_from_slice(payload);
        Ok(hn + payload.len())
    }

    /// Encode a GetSchedule fetch.
    pub fn get_schedule(tsn: u8, query: &ScheduleQuery, out: &mut [u8]) -> Result<usize, Error> {
        let mut payload = [0u8; GET_SCHEDULE_LEN];
        encode_get_schedule(query, &mut payload)?;
        frame(tsn, CMD_GET_SCHEDULE, &payload, out)
    }

    /// Encode a GetDayProfile fetch.
    pub fn get_day_profile(
        tsn: u8,
        provider: u32,
        day_id: u16,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut payload = [0u8; GET_DAY_PROFILE_LEN];
        encode_get_day_profile(provider, day_id, &mut payload)?;
        frame(tsn, CMD_GET_DAY_PROFILE, &payload, out)
    }

    /// Encode a GetScheduleCancellation fetch (empty body).
    pub fn get_cancellation(tsn: u8, out: &mut [u8]) -> Result<usize, Error> {
        frame(tsn, CMD_GET_SCHEDULE_CANCELLATION, &[], out)
    }
}
