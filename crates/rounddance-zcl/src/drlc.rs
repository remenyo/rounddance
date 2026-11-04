//! Demand Response and Load Control cluster (0x0701): server plus
//! client definitions, event codecs, and the bounded event table
//! shared by both sides.
//!
//! Paraphrase-level model of doc `07-5123-08` section 10.3. The
//! overview, revision record, cluster identifier, server storage
//! rule, and the empty server attribute set sit at extraction
//! anchors p0684-L15570-L15581, p0685-L15582-L15599, and
//! p0693-L15838-L15842. The Load Control Event shape (payload table,
//! issuer, device class, utility group, start, duration, criticality,
//! offsets, setpoints, load, duty, event control, generation and
//! response rules) sits at anchors p0686-L15604-L15617,
//! p0687-L15619-L15645, p0688-L15646-L15678, p0689-L15679-L15739,
//! p0690-L15739-L15757. Cancel and cancel-all (payloads, control,
//! effects) sit at anchors p0691-L15758-L15803 and
//! p0692-L15806-L15832. Client attributes, command tables, report
//! and fetch shapes sit at anchors p0694-L15852-L15901,
//! p0695-L15897-L15924, p0696-L15902-L15924, and
//! p0698-L15941-L15989. Doc `07-5356-22` section D.2 carries the same
//! cluster in the Smart Energy profile. All wording here is
//! paraphrase (D1).
//!
//! Requirement IDs below are repo-minted (`07-5123-08-103-<seq>`,
//! dots stripped), MINTED-pending-confirm.
//!
//! NOTE for the lib.rs hookup (main agent merges this to avoid
//! `mod` conflicts): add exactly one line to
//! `crates/rounddance-zcl/src/lib.rs` in the module block:
//!
//! ```text
//! pub mod drlc;
//! ```

use crate::attrs::{access, AttrDef, AttrStore};
use crate::behavior::{AppEvent, Behavior, Ctx, HandleOutcome};
use crate::cluster::{ClusterDef, ClusterRole, CmdDef};
use crate::frame::Header;
use crate::types::{DataType, Value};
use crate::{Error, ZclStatus};

/// Cluster identifier.
///
/// Requirement `07-5123-08-103-01` (MINTED-pending-confirm).
pub const CLUSTER_ID: u16 = 0x0701;
/// Implemented specification revision (rev table tip).
///
/// Requirement `07-5123-08-103-01` (MINTED-pending-confirm).
pub const REVISION: u16 = 2;

/// Server generated: Load Control Event.
pub const CMD_LOAD_CONTROL_EVENT: u8 = 0x00;
/// Server generated: Cancel Load Control Event.
pub const CMD_CANCEL_EVENT: u8 = 0x01;
/// Server generated: Cancel All Load Control Events.
pub const CMD_CANCEL_ALL_EVENTS: u8 = 0x02;
/// Client generated: Report Event Status.
pub const CMD_REPORT_EVENT_STATUS: u8 = 0x00;
/// Client generated: Get Scheduled Events.
pub const CMD_GET_SCHEDULED_EVENTS: u8 = 0x01;

/// Client attribute: utility enrollment group (0x00 = all groups).
pub const ATTR_UTILITY_ENROLLMENT_GROUP: u16 = 0x0000;
/// Client attribute: start-randomization window, minutes (0x00-0x3C).
pub const ATTR_START_RANDOMIZATION_MINUTES: u16 = 0x0001;
/// Client attribute: duration-randomization window, minutes.
pub const ATTR_DURATION_RANDOMIZATION_MINUTES: u16 = 0x0002;
/// Client attribute: device-class filter treated as a 16-bit bitmap.
pub const ATTR_DEVICE_CLASS_VALUE: u16 = 0x0003;

/// Default start-randomization window, minutes.
pub const DEFAULT_START_RANDOMIZATION_MINUTES: u8 = 0x1e;
/// Randomization windows are never larger than this, minutes.
pub const MAX_RANDOMIZATION_MINUTES: u8 = 0x3c;

/// Start-time value meaning "now".
pub const START_NOW: u32 = 0x0000_0000;
/// Longest event duration, minutes (one day).
pub const MAX_DURATION_MINUTES: u16 = 1440;
/// Issuer-event value meaning "no minimum" in Get Scheduled Events.
pub const ISSUER_ANY: u32 = 0xffff_ffff;

/// Temperature-offset value meaning "not used".
pub const OFFSET_UNUSED: u8 = 0xff;
/// Temperature-setpoint value meaning "not used".
pub const SETPOINT_UNUSED: u16 = 0x8000;
/// Load-adjustment value meaning "not used".
pub const AVG_LOAD_UNUSED: u8 = 0x80;
/// Duty-cycle value meaning "not used".
pub const DUTY_UNUSED: u8 = 0xff;

/// Event-control bit: randomize the start time.
pub const EVENT_CTRL_RANDOMIZE_START: u8 = 0x01;
/// Event-control bit: randomize the duration.
pub const EVENT_CTRL_RANDOMIZE_DURATION: u8 = 0x02;

/// Cancel-control bit: end with randomization (else immediately).
pub const CANCEL_CTRL_USE_RANDOMIZATION: u8 = 0x01;

/// Criticality: voluntary conservation appeal.
pub const CRITICALITY_GREEN: u8 = 0x01;
/// Criticality: highest voluntary tier.
pub const CRITICALITY_VOLUNTARY_MAX: u8 = 0x06;
/// Criticality: emergency (mandatory).
pub const CRITICALITY_EMERGENCY: u8 = 0x07;
/// Criticality: planned outage (mandatory).
pub const CRITICALITY_PLANNED_OUTAGE: u8 = 0x08;
/// Criticality: service disconnect (mandatory).
pub const CRITICALITY_SERVICE_DISCONNECT: u8 = 0x09;
/// First utility-defined criticality level.
pub const CRITICALITY_UTILITY_MIN: u8 = 0x0a;
/// Last utility-defined criticality level.
pub const CRITICALITY_UTILITY_MAX: u8 = 0x0f;

/// Participation class: voluntary.
pub const PARTICIPATION_VOLUNTARY: u8 = 0;
/// Participation class: mandatory.
pub const PARTICIPATION_MANDATORY: u8 = 1;
/// Participation class: utility-defined.
pub const PARTICIPATION_UTILITY: u8 = 2;

/// Report status: command received.
pub const STATUS_RECEIVED: u8 = 0x01;
/// Report status: event started.
pub const STATUS_STARTED: u8 = 0x02;
/// Report status: event completed.
pub const STATUS_COMPLETED: u8 = 0x03;
/// Report status: user opted out.
pub const STATUS_OPT_OUT: u8 = 0x04;
/// Report status: user opted in.
pub const STATUS_OPT_IN: u8 = 0x05;
/// Report status: event cancelled.
pub const STATUS_CANCELLED: u8 = 0x06;
/// Report status: event superseded.
pub const STATUS_SUPERSEDED: u8 = 0x07;
/// Report status: partially completed with opt-out.
pub const STATUS_PARTIAL_OPT_OUT: u8 = 0x08;
/// Report status: partially completed with opt-in.
pub const STATUS_PARTIAL_OPT_IN: u8 = 0x09;
/// Report status: completed without participation (prior opt-out).
pub const STATUS_COMPLETED_NO_PARTICIPATION: u8 = 0x0a;
/// Report status: rejected, bad cancel (default).
pub const STATUS_REJECTED_CANCEL: u8 = 0xf8;
/// Report status: rejected, bad cancel effective time.
pub const STATUS_REJECTED_CANCEL_TIME: u8 = 0xf9;
/// Report status: rejected, event already expired.
pub const STATUS_REJECTED_EXPIRED: u8 = 0xfb;
/// Report status: rejected, cancel names an unknown event.
pub const STATUS_REJECTED_UNDEFINED: u8 = 0xfd;
/// Report status: command rejected.
pub const STATUS_REJECTED: u8 = 0xfe;

/// Signature type: no signature (tail is fill).
pub const SIGNATURE_NONE: u8 = 0x00;
/// Signature type: ECDSA (tail is the joined signature).
pub const SIGNATURE_ECDSA: u8 = 0x01;
/// Fill octet for an unused signature tail.
pub const SIGNATURE_FILL: u8 = 0xff;
/// Largest signature tail carried here (bounded opaque).
pub const MAX_SIGNATURE: usize = 48;

/// Smallest client-side event backlog (devices hold three or more).
pub const MIN_EVENT_SLOTS: usize = 3;
/// Event backlog slots held here (at least the required three).
pub const MAX_EVENTS: usize = 4;

/// Whether a criticality level names a defined tier (voluntary
/// 1..6, mandatory 7..9, utility 0x0A..=0x0F).
///
/// Requirement `07-5123-08-103-02` (MINTED-pending-confirm).
#[must_use]
pub const fn criticality_known(level: u8) -> bool {
    level >= CRITICALITY_GREEN && level <= CRITICALITY_UTILITY_MAX
}

/// Participation class for a defined criticality level (`None` for
/// reserved levels).
///
/// Requirement `07-5123-08-103-02` (MINTED-pending-confirm).
#[must_use]
pub const fn criticality_participation(level: u8) -> Option<u8> {
    if level >= CRITICALITY_GREEN && level <= CRITICALITY_VOLUNTARY_MAX {
        Some(PARTICIPATION_VOLUNTARY)
    } else if level >= CRITICALITY_EMERGENCY && level <= CRITICALITY_SERVICE_DISCONNECT {
        Some(PARTICIPATION_MANDATORY)
    } else if level >= CRITICALITY_UTILITY_MIN && level <= CRITICALITY_UTILITY_MAX {
        Some(PARTICIPATION_UTILITY)
    } else {
        None
    }
}

/// Whether a report status names a defined outcome.
///
/// Requirement `07-5123-08-103-03` (MINTED-pending-confirm).
#[must_use]
pub const fn report_status_known(status: u8) -> bool {
    matches!(
        status,
        STATUS_RECEIVED
            | STATUS_STARTED
            | STATUS_COMPLETED
            | STATUS_OPT_OUT
            | STATUS_OPT_IN
            | STATUS_CANCELLED
            | STATUS_SUPERSEDED
            | STATUS_PARTIAL_OPT_OUT
            | STATUS_PARTIAL_OPT_IN
            | STATUS_COMPLETED_NO_PARTICIPATION
            | STATUS_REJECTED_CANCEL
            | STATUS_REJECTED_CANCEL_TIME
            | STATUS_REJECTED_EXPIRED
            | STATUS_REJECTED_UNDEFINED
            | STATUS_REJECTED
    )
}

/// Whether two enrollment groups overlap (0x00 on either side
/// addresses every group).
///
/// Requirement `07-5123-08-103-04` (MINTED-pending-confirm).
#[must_use]
pub const fn groups_overlap(a: u8, b: u8) -> bool {
    a == 0 || b == 0 || a == b
}

/// Whether two device-class maps overlap (any shared bit).
///
/// Requirement `07-5123-08-103-04` (MINTED-pending-confirm).
#[must_use]
pub const fn classes_overlap(a: u16, b: u16) -> bool {
    a & b != 0
}

/// Apply randomization choices to a start/duration pair: a set start
/// bit delays the start by the chosen start minutes, a set duration
/// bit extends the duration by the chosen duration minutes. The
/// random choice itself is application policy above this layer; the
/// caller passes the already-chosen minute values.
///
/// Requirement `07-5123-08-103-05` (MINTED-pending-confirm).
#[must_use]
pub const fn apply_randomization(
    start: u32,
    duration_min: u16,
    control: u8,
    start_choice_min: u8,
    duration_choice_min: u8,
) -> (u32, u16) {
    let shifted = if control & EVENT_CTRL_RANDOMIZE_START != 0 {
        start.saturating_add(start_choice_min as u32 * 60)
    } else {
        start
    };
    let extended = if control & EVENT_CTRL_RANDOMIZE_DURATION != 0 {
        duration_min.saturating_add(duration_choice_min as u16)
    } else {
        duration_min
    };
    (shifted, extended)
}

/// One Load Control Event: the 14-octet mandatory prefix plus the
/// eight optional octets (carried always; unused ones hold the
/// documented ignore sentinels) plus the event-control octet.
///
/// Requirement `07-5123-08-103-06` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadControlEvent {
    /// Provider-side event identifier (supersession order).
    pub issuer_event_id: u32,
    /// Target device-class bitmap.
    pub device_class: u16,
    /// Target enrollment group (0x00 = all groups).
    pub group: u8,
    /// Scheduled start (`START_NOW` = immediately).
    pub start_time: u32,
    /// Duration, minutes (at most [`MAX_DURATION_MINUTES`]).
    pub duration_min: u16,
    /// Criticality tier.
    pub criticality: u8,
    /// Cooling offset, 0.1 C steps (`OFFSET_UNUSED` = not used).
    pub cooling_offset: u8,
    /// Heating offset, 0.1 C steps (`OFFSET_UNUSED` = not used).
    pub heating_offset: u8,
    /// Cooling setpoint, 0.01 C steps (`SETPOINT_UNUSED` = unused).
    pub cooling_setpoint: u16,
    /// Heating setpoint, 0.01 C steps (`SETPOINT_UNUSED` = unused).
    pub heating_setpoint: u16,
    /// Load adjustment, percent (`AVG_LOAD_UNUSED` = not used).
    pub avg_load_adjustment: u8,
    /// Duty cycle, percent (`DUTY_UNUSED` = not used).
    pub duty_cycle: u8,
    /// Control map (randomization bits).
    pub event_control: u8,
}

/// Wire length of a Load Control Event body.
pub const LOAD_CONTROL_EVENT_LEN: usize = 23;

/// Decode a Load Control Event body (exactly 23 octets).
pub fn decode_load_control_event(buf: &[u8]) -> Result<LoadControlEvent, Error> {
    if buf.len() != LOAD_CONTROL_EVENT_LEN {
        return Err(Error::Truncated);
    }
    let duration_min = u16::from_le_bytes([buf[11], buf[12]]);
    if duration_min > MAX_DURATION_MINUTES {
        return Err(Error::InvalidValue(buf[12]));
    }
    if !criticality_known(buf[13]) {
        return Err(Error::InvalidValue(buf[13]));
    }
    Ok(LoadControlEvent {
        issuer_event_id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        device_class: u16::from_le_bytes([buf[4], buf[5]]),
        group: buf[6],
        start_time: u32::from_le_bytes([buf[7], buf[8], buf[9], buf[10]]),
        duration_min,
        criticality: buf[13],
        cooling_offset: buf[14],
        heating_offset: buf[15],
        cooling_setpoint: u16::from_le_bytes([buf[16], buf[17]]),
        heating_setpoint: u16::from_le_bytes([buf[18], buf[19]]),
        avg_load_adjustment: buf[20],
        duty_cycle: buf[21],
        event_control: buf[22],
    })
}

/// Encode a Load Control Event body into `out` (23 octets).
pub fn encode_load_control_event(ev: &LoadControlEvent, out: &mut [u8]) -> Result<usize, Error> {
    if ev.duration_min > MAX_DURATION_MINUTES {
        return Err(Error::InvalidValue(0));
    }
    if !criticality_known(ev.criticality) {
        return Err(Error::InvalidValue(ev.criticality));
    }
    if out.len() < LOAD_CONTROL_EVENT_LEN {
        return Err(Error::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&ev.issuer_event_id.to_le_bytes());
    out[4..6].copy_from_slice(&ev.device_class.to_le_bytes());
    out[6] = ev.group;
    out[7..11].copy_from_slice(&ev.start_time.to_le_bytes());
    out[11..13].copy_from_slice(&ev.duration_min.to_le_bytes());
    out[13] = ev.criticality;
    out[14] = ev.cooling_offset;
    out[15] = ev.heating_offset;
    out[16..18].copy_from_slice(&ev.cooling_setpoint.to_le_bytes());
    out[18..20].copy_from_slice(&ev.heating_setpoint.to_le_bytes());
    out[20] = ev.avg_load_adjustment;
    out[21] = ev.duty_cycle;
    out[22] = ev.event_control;
    Ok(LOAD_CONTROL_EVENT_LEN)
}

/// Cancel Load Control Event body: the event to drop plus the
/// control/effective-time tail. The effective-time field is
/// deprecated and always carries zero on the wire here; arrival
/// takes immediate effect.
///
/// Requirement `07-5123-08-103-07` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CancelEvent {
    /// Event identifier to cancel.
    pub issuer_event_id: u32,
    /// Device-class map (should repeat the event's map).
    pub device_class: u16,
    /// Enrollment group (should repeat the event's group).
    pub group: u8,
    /// Cancel control (randomization bit).
    pub cancel_control: u8,
}

/// Wire length of a Cancel Load Control Event body.
pub const CANCEL_EVENT_LEN: usize = 12;

/// Decode a Cancel Load Control Event body (exactly 12 octets; any
/// effective-time value is accepted on receipt).
pub fn decode_cancel_event(buf: &[u8]) -> Result<CancelEvent, Error> {
    if buf.len() != CANCEL_EVENT_LEN {
        return Err(Error::Truncated);
    }
    Ok(CancelEvent {
        issuer_event_id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        device_class: u16::from_le_bytes([buf[4], buf[5]]),
        group: buf[6],
        cancel_control: buf[7],
    })
}

/// Encode a Cancel Load Control Event body (12 octets, zeroed
/// effective-time tail).
pub fn encode_cancel_event(ev: &CancelEvent, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < CANCEL_EVENT_LEN {
        return Err(Error::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&ev.issuer_event_id.to_le_bytes());
    out[4..6].copy_from_slice(&ev.device_class.to_le_bytes());
    out[6] = ev.group;
    out[7] = ev.cancel_control;
    out[8..12].copy_from_slice(&0u32.to_le_bytes());
    Ok(CANCEL_EVENT_LEN)
}

/// Report Event Status body: the 17-octet fixed prefix, a signature
/// type, and a bounded opaque signature tail (fill when unused).
///
/// Requirement `07-5123-08-103-08` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportEventStatus {
    /// Event the report belongs to.
    pub issuer_event_id: u32,
    /// Report outcome.
    pub event_status: u8,
    /// Time the outcome occurred (never zero on the wire).
    pub event_status_time: u32,
    /// Criticality actually applied.
    pub criticality_applied: u8,
    /// Cooling setpoint applied (`SETPOINT_UNUSED` = unused).
    pub cooling_setpoint_applied: u16,
    /// Heating setpoint applied (`SETPOINT_UNUSED` = unused).
    pub heating_setpoint_applied: u16,
    /// Load adjustment applied (`AVG_LOAD_UNUSED` = unused).
    pub avg_load_applied: u8,
    /// Duty cycle applied (`DUTY_UNUSED` = unused).
    pub duty_cycle_applied: u8,
    /// Control map echoed from the event.
    pub event_control: u8,
    /// Signature algorithm (`SIGNATURE_*`).
    pub signature_type: u8,
    /// Signature tail length.
    pub signature_len: u8,
    /// Signature tail bytes (fill when [`SIGNATURE_NONE`]).
    pub signature: [u8; MAX_SIGNATURE],
}

/// Fixed prefix length of a Report Event Status body.
pub const REPORT_STATUS_PREFIX_LEN: usize = 18;

/// Decode a Report Event Status body: 18-octet prefix plus a bounded
/// opaque signature tail.
pub fn decode_report_event_status(buf: &[u8]) -> Result<ReportEventStatus, Error> {
    if buf.len() < REPORT_STATUS_PREFIX_LEN {
        return Err(Error::Truncated);
    }
    let tail = buf.len() - REPORT_STATUS_PREFIX_LEN;
    if tail > MAX_SIGNATURE {
        return Err(Error::InvalidValue(buf[REPORT_STATUS_PREFIX_LEN - 1]));
    }
    if !report_status_known(buf[4]) {
        return Err(Error::InvalidValue(buf[4]));
    }
    if !criticality_known(buf[9]) {
        return Err(Error::InvalidValue(buf[9]));
    }
    let status_time = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
    if status_time == 0 {
        return Err(Error::InvalidValue(0));
    }
    let mut signature = [0u8; MAX_SIGNATURE];
    signature[..tail].copy_from_slice(&buf[REPORT_STATUS_PREFIX_LEN..]);
    #[allow(clippy::cast_possible_truncation)]
    let signature_len = tail as u8;
    Ok(ReportEventStatus {
        issuer_event_id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        event_status: buf[4],
        event_status_time: status_time,
        criticality_applied: buf[9],
        cooling_setpoint_applied: u16::from_le_bytes([buf[10], buf[11]]),
        heating_setpoint_applied: u16::from_le_bytes([buf[12], buf[13]]),
        avg_load_applied: buf[14],
        duty_cycle_applied: buf[15],
        event_control: buf[16],
        signature_type: buf[17],
        signature_len,
        signature,
    })
}

/// Encode a Report Event Status body into `out`.
pub fn encode_report_event_status(rsp: &ReportEventStatus, out: &mut [u8]) -> Result<usize, Error> {
    if !report_status_known(rsp.event_status) {
        return Err(Error::InvalidValue(rsp.event_status));
    }
    if !criticality_known(rsp.criticality_applied) {
        return Err(Error::InvalidValue(rsp.criticality_applied));
    }
    if rsp.event_status_time == 0 {
        return Err(Error::InvalidValue(0));
    }
    let tail = rsp.signature_len as usize;
    if tail > MAX_SIGNATURE {
        return Err(Error::InvalidValue(rsp.signature_len));
    }
    let need = REPORT_STATUS_PREFIX_LEN + tail;
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&rsp.issuer_event_id.to_le_bytes());
    out[4] = rsp.event_status;
    out[5..9].copy_from_slice(&rsp.event_status_time.to_le_bytes());
    out[9] = rsp.criticality_applied;
    out[10..12].copy_from_slice(&rsp.cooling_setpoint_applied.to_le_bytes());
    out[12..14].copy_from_slice(&rsp.heating_setpoint_applied.to_le_bytes());
    out[14] = rsp.avg_load_applied;
    out[15] = rsp.duty_cycle_applied;
    out[16] = rsp.event_control;
    out[17] = rsp.signature_type;
    out[REPORT_STATUS_PREFIX_LEN..need].copy_from_slice(&rsp.signature[..tail]);
    Ok(need)
}

/// Build an unsigned report for `event` with `status`: the unused
/// signature tail goes out as fill, per the no-signature rule.
pub fn unsigned_report(event: &LoadControlEvent, status: u8, now: u32) -> ReportEventStatus {
    ReportEventStatus {
        issuer_event_id: event.issuer_event_id,
        event_status: status,
        event_status_time: if now == 0 { 1 } else { now },
        criticality_applied: event.criticality,
        cooling_setpoint_applied: event.cooling_setpoint,
        heating_setpoint_applied: event.heating_setpoint,
        avg_load_applied: event.avg_load_adjustment,
        duty_cycle_applied: event.duty_cycle,
        event_control: event.event_control,
        signature_type: SIGNATURE_NONE,
        signature_len: MAX_SIGNATURE as u8,
        signature: [SIGNATURE_FILL; MAX_SIGNATURE],
    }
}

/// Get Scheduled Events query: minimum start plus a page cap plus an
/// optional same-start issuer floor.
///
/// Requirement `07-5123-08-103-09` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetScheduledEvents {
    /// Minimum event start to answer.
    pub start_time: u32,
    /// Maximum answers (`0` = no limit).
    pub max_events: u8,
    /// Same-start issuer floor (`None` = no floor).
    pub min_issuer: Option<u32>,
}

/// Decode a Get Scheduled Events body (5 octets, or 9 with the
/// optional issuer floor; `ISSUER_ANY` means no floor).
pub fn decode_get_scheduled(buf: &[u8]) -> Result<GetScheduledEvents, Error> {
    if buf.len() != 5 && buf.len() != 9 {
        return Err(Error::Truncated);
    }
    let issuer = if buf.len() == 9 {
        let v = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
        if v == ISSUER_ANY {
            None
        } else {
            Some(v)
        }
    } else {
        None
    };
    Ok(GetScheduledEvents {
        start_time: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        max_events: buf[4],
        min_issuer: issuer,
    })
}

/// Encode a Get Scheduled Events body into `out` (5 or 9 octets).
pub fn encode_get_scheduled(req: &GetScheduledEvents, out: &mut [u8]) -> Result<usize, Error> {
    let need = if req.min_issuer.is_some() { 9 } else { 5 };
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&req.start_time.to_le_bytes());
    out[4] = req.max_events;
    if let Some(issuer) = req.min_issuer {
        out[5..9].copy_from_slice(&issuer.to_le_bytes());
    }
    Ok(need)
}

/// Bounded event backlog shared by both sides (servers hold two or
/// more, clients three or more; this table holds four).
///
/// Requirement `07-5123-08-103-10` (MINTED-pending-confirm): newer
/// issuer ids supersede overlapping older events; cancel removes the
/// named event; answers sort by start, then issuer id.
#[derive(Clone, Copy, Debug)]
pub struct EventTable {
    events: [Option<LoadControlEvent>; MAX_EVENTS],
}

impl Default for EventTable {
    fn default() -> Self {
        Self::new()
    }
}

impl EventTable {
    /// Empty backlog.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: [None; MAX_EVENTS],
        }
    }

    /// Event count held.
    #[must_use]
    pub fn len(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < MAX_EVENTS {
            if self.events[i].is_some() {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// Whether the backlog is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether `ev` contends with `old` for one slot (shared class
    /// and group targeting).
    fn contends(old: &LoadControlEvent, ev: &LoadControlEvent) -> bool {
        classes_overlap(old.device_class, ev.device_class) && groups_overlap(old.group, ev.group)
    }

    /// Insert an event: a contending older-or-equal issuer id is
    /// dropped; a contending newer event drops the newcomer. A full
    /// table evicts the oldest issuer id.
    pub fn insert(&mut self, ev: LoadControlEvent) {
        let mut i = 0;
        while i < MAX_EVENTS {
            match self.events[i] {
                Some(old) if Self::contends(&old, &ev) => {
                    if ev.issuer_event_id > old.issuer_event_id {
                        self.events[i] = None;
                    } else {
                        return;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        let mut j = 0;
        while j < MAX_EVENTS {
            if self.events[j].is_none() {
                self.events[j] = Some(ev);
                return;
            }
            j += 1;
        }
        let mut oldest = 0;
        let mut k = 1;
        while k < MAX_EVENTS {
            let a = self.events[oldest]
                .map(|e| e.issuer_event_id)
                .unwrap_or(u32::MAX);
            let b = self.events[k]
                .map(|e| e.issuer_event_id)
                .unwrap_or(u32::MAX);
            if b < a {
                oldest = k;
            }
            k += 1;
        }
        self.events[oldest] = Some(ev);
    }

    /// Remove the event with `issuer` (cancel effect). Returns
    /// whether anything was removed.
    pub fn cancel(&mut self, issuer: u32) -> bool {
        let mut hit = false;
        let mut i = 0;
        while i < MAX_EVENTS {
            if matches!(self.events[i], Some(ev) if ev.issuer_event_id == issuer) {
                self.events[i] = None;
                hit = true;
            }
            i += 1;
        }
        hit
    }

    /// Drop every event (cancel-all effect).
    pub fn cancel_all(&mut self) {
        self.events = [None; MAX_EVENTS];
    }

    /// Events at or after `start` matching the same-start issuer
    /// floor, ascending by (start, issuer id), at most `max`
    /// (`0` = no limit).
    pub fn scheduled_since(
        &self,
        start: u32,
        max: u8,
        min_issuer: Option<u32>,
        out: &mut [LoadControlEvent],
    ) -> usize {
        let mut hits: [Option<LoadControlEvent>; MAX_EVENTS] = [None; MAX_EVENTS];
        let mut n = 0;
        let mut i = 0;
        while i < MAX_EVENTS {
            if let Some(ev) = self.events[i] {
                let start_hit = ev.start_time >= start || ev.start_time == START_NOW;
                let issuer_hit = match min_issuer {
                    Some(floor) if ev.start_time == start => ev.issuer_event_id >= floor,
                    _ => true,
                };
                if start_hit && issuer_hit {
                    hits[n] = Some(ev);
                    n += 1;
                }
            }
            i += 1;
        }
        let mut a = 0;
        while a < n {
            let mut b = a + 1;
            while b < n {
                let ea = hits[a].map(|e| (e.start_time, e.issuer_event_id));
                let eb = hits[b].map(|e| (e.start_time, e.issuer_event_id));
                if eb < ea {
                    hits.swap(a, b);
                }
                b += 1;
            }
            a += 1;
        }
        let limit = if max == 0 { n } else { (max as usize).min(n) };
        let take = limit.min(out.len());
        let mut k = 0;
        while k < take {
            if let Some(ev) = hits[k] {
                out[k] = ev;
            }
            k += 1;
        }
        take
    }
}

/// Server attribute table: this cluster defines no server attributes
/// (the global revision still rides in the store).
pub static SERVER_ATTRS: &[AttrDef] = &[];

/// Client attribute table, ascending.
pub static CLIENT_ATTRS: &[AttrDef] = &[
    AttrDef {
        id: ATTR_UTILITY_ENROLLMENT_GROUP,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_START_RANDOMIZATION_MINUTES,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_DURATION_RANDOMIZATION_MINUTES,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_DEVICE_CLASS_VALUE,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
];

/// Server received commands, ascending.
pub static SERVER_RX: &[CmdDef] = &[
    CmdDef {
        id: CMD_REPORT_EVENT_STATUS,
        name: "report-event-status",
    },
    CmdDef {
        id: CMD_GET_SCHEDULED_EVENTS,
        name: "get-scheduled-events",
    },
];

/// Server generated commands, ascending.
pub static SERVER_TX: &[CmdDef] = &[
    CmdDef {
        id: CMD_LOAD_CONTROL_EVENT,
        name: "load-control-event",
    },
    CmdDef {
        id: CMD_CANCEL_EVENT,
        name: "cancel-load-control-event",
    },
    CmdDef {
        id: CMD_CANCEL_ALL_EVENTS,
        name: "cancel-all-load-control-events",
    },
];

/// Server definition.
pub struct ServerDef;
impl ClusterDef for ServerDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "drlc-server"
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

/// Client definition.
pub struct ClientDef;
impl ClusterDef for ClientDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "drlc-client"
    }
    fn revision(&self) -> u16 {
        REVISION
    }
    fn role(&self) -> ClusterRole {
        ClusterRole::Client
    }
    fn attributes(&self) -> &'static [AttrDef] {
        CLIENT_ATTRS
    }
    fn received_commands(&self) -> &'static [CmdDef] {
        SERVER_TX
    }
    fn generated_commands(&self) -> &'static [CmdDef] {
        SERVER_RX
    }
}

/// Build a fresh server store (globals only; no server attributes).
pub fn server_store() -> Result<AttrStore, Error> {
    let mut store = AttrStore::new(None);
    store.add_globals(REVISION)?;
    Ok(store)
}

/// Build a fresh client store with table defaults for
/// `device_class`.
pub fn client_store(device_class: u16) -> Result<AttrStore, Error> {
    let mut store = AttrStore::new(None);
    store.add(CLIENT_ATTRS[0], Value::UInt { width: 1, v: 0 })?;
    store.add(
        CLIENT_ATTRS[1],
        Value::UInt {
            width: 1,
            v: u64::from(DEFAULT_START_RANDOMIZATION_MINUTES),
        },
    )?;
    store.add(CLIENT_ATTRS[2], Value::UInt { width: 1, v: 0 })?;
    store.add(
        CLIENT_ATTRS[3],
        Value::UInt {
            width: 2,
            v: u64::from(device_class),
        },
    )?;
    store.add_globals(REVISION)?;
    Ok(store)
}

/// Read the client enrollment group from a store (0x00 when absent).
pub fn group_of(store: &AttrStore) -> u8 {
    match store.get(ATTR_UTILITY_ENROLLMENT_GROUP) {
        Some(Value::UInt { v, .. }) => (v & 0xff) as u8,
        _ => 0,
    }
}

/// Read the client device-class filter from a store.
pub fn class_of(store: &AttrStore) -> u16 {
    match store.get(ATTR_DEVICE_CLASS_VALUE) {
        Some(Value::UInt { v, .. }) => (v & 0xffff) as u16,
        _ => 0,
    }
}

/// Client behavior: filter incoming events by class/group, keep the
/// bounded backlog, and emit status reports.
///
/// Requirement `07-5123-08-103-11` (MINTED-pending-confirm).
pub struct ClientBehavior {
    table: EventTable,
}

impl Default for ClientBehavior {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBehavior {
    /// Fresh behavior: empty backlog.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            table: EventTable::new(),
        }
    }

    /// Borrow the backlog.
    pub const fn table(&self) -> &EventTable {
        &self.table
    }

    /// Whether an event targets this client (shared class bit and
    /// overlapping group); non-targets are ignored with `SUCCESS`
    /// and never stored.
    #[must_use]
    pub fn targets(&self, ctx: &Ctx<'_>, ev: &LoadControlEvent) -> bool {
        classes_overlap(class_of(ctx.store), ev.device_class)
            && groups_overlap(group_of(ctx.store), ev.group)
    }

    /// Emit an unsigned status report for `ev` through the event
    /// queue.
    fn emit_report(&self, ctx: &mut Ctx<'_>, ev: &LoadControlEvent, status: u8) {
        let rsp = unsigned_report(ev, status, ctx.now_s as u32);
        let mut body = [0u8; REPORT_STATUS_PREFIX_LEN];
        if encode_report_event_status(&rsp, &mut body).is_ok() {
            let mut payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
            payload[..REPORT_STATUS_PREFIX_LEN].copy_from_slice(&body);
            ctx.events.push(AppEvent::OutboundCommand {
                cluster: CLUSTER_ID,
                cmd: CMD_REPORT_EVENT_STATUS,
                tsn: 0,
                len: REPORT_STATUS_PREFIX_LEN as u8,
                payload,
            });
        }
    }

    /// Handle an incoming Load Control Event: ignore non-targets,
    /// store targets, report receipt.
    pub fn handle_event(
        &mut self,
        ctx: &mut Ctx<'_>,
        ev: &LoadControlEvent,
    ) -> Result<HandleOutcome, ZclStatus> {
        if !self.targets(ctx, ev) {
            return Ok(HandleOutcome::no_reply());
        }
        self.table.insert(*ev);
        self.emit_report(ctx, ev, STATUS_RECEIVED);
        Ok(HandleOutcome::no_reply())
    }

    /// Handle an incoming cancel: drop the named event and report
    /// the outcome (unknown events report undefined-cancel).
    pub fn handle_cancel(
        &mut self,
        ctx: &mut Ctx<'_>,
        cancel: &CancelEvent,
    ) -> Result<HandleOutcome, ZclStatus> {
        if self.table.cancel(cancel.issuer_event_id) {
            let probe = LoadControlEvent {
                issuer_event_id: cancel.issuer_event_id,
                device_class: cancel.device_class,
                group: cancel.group,
                start_time: START_NOW,
                duration_min: 0,
                criticality: CRITICALITY_GREEN,
                cooling_offset: OFFSET_UNUSED,
                heating_offset: OFFSET_UNUSED,
                cooling_setpoint: SETPOINT_UNUSED,
                heating_setpoint: SETPOINT_UNUSED,
                avg_load_adjustment: AVG_LOAD_UNUSED,
                duty_cycle: DUTY_UNUSED,
                event_control: 0,
            };
            self.emit_report(ctx, &probe, STATUS_CANCELLED);
            Ok(HandleOutcome::no_reply())
        } else {
            Err(ZclStatus::NotFound)
        }
    }

    /// Handle an incoming cancel-all: drop everything.
    pub fn handle_cancel_all(&mut self, ctx: &mut Ctx<'_>) -> Result<HandleOutcome, ZclStatus> {
        self.table.cancel_all();
        ctx.events.push(AppEvent::StateChanged {
            cluster: CLUSTER_ID,
            from: 1,
            to: 0,
        });
        Ok(HandleOutcome::no_reply())
    }
}

impl Behavior for ClientBehavior {
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
            CMD_LOAD_CONTROL_EVENT => {
                let ev =
                    decode_load_control_event(payload).map_err(|_| ZclStatus::MalformedCommand)?;
                self.handle_event(ctx, &ev)
            }
            CMD_CANCEL_EVENT => {
                let cancel =
                    decode_cancel_event(payload).map_err(|_| ZclStatus::MalformedCommand)?;
                self.handle_cancel(ctx, &cancel)
            }
            CMD_CANCEL_ALL_EVENTS => {
                if payload.len() != 1 {
                    return Err(ZclStatus::MalformedCommand);
                }
                self.handle_cancel_all(ctx)
            }
            _ => Err(ZclStatus::UnsupCommand),
        }
    }
}

/// Server behavior: backlog-backed Get Scheduled Events answers.
///
/// Requirement `07-5123-08-103-12` (MINTED-pending-confirm): answers
/// sort by start, then issuer id; an empty answer is `NOT_FOUND`.
pub struct ServerBehavior {
    table: EventTable,
}

impl Default for ServerBehavior {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBehavior {
    /// Fresh behavior: empty backlog.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            table: EventTable::new(),
        }
    }

    /// Borrow the backlog.
    pub const fn table(&self) -> &EventTable {
        &self.table
    }

    /// Mutable backlog (tests/sim preload it).
    pub fn table_mut(&mut self) -> &mut EventTable {
        &mut self.table
    }

    /// Answer a Get Scheduled Events query by emitting one
    /// LoadControlEvent per match. Returns the emitted count.
    pub fn answer_scheduled(
        &self,
        ctx: &mut Ctx<'_>,
        req: &GetScheduledEvents,
    ) -> Result<usize, ZclStatus> {
        let mut hits = [LoadControlEvent {
            issuer_event_id: 0,
            device_class: 0,
            group: 0,
            start_time: 0,
            duration_min: 0,
            criticality: CRITICALITY_GREEN,
            cooling_offset: OFFSET_UNUSED,
            heating_offset: OFFSET_UNUSED,
            cooling_setpoint: SETPOINT_UNUSED,
            heating_setpoint: SETPOINT_UNUSED,
            avg_load_adjustment: AVG_LOAD_UNUSED,
            duty_cycle: DUTY_UNUSED,
            event_control: 0,
        }; MAX_EVENTS];
        let n =
            self.table
                .scheduled_since(req.start_time, req.max_events, req.min_issuer, &mut hits);
        if n == 0 {
            return Err(ZclStatus::NotFound);
        }
        let mut i = 0;
        while i < n {
            let mut body = [0u8; LOAD_CONTROL_EVENT_LEN];
            encode_load_control_event(&hits[i], &mut body)
                .map_err(|_| ZclStatus::InsufficientSpace)?;
            let mut payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
            payload[..LOAD_CONTROL_EVENT_LEN].copy_from_slice(&body);
            ctx.events.push(AppEvent::OutboundCommand {
                cluster: CLUSTER_ID,
                cmd: CMD_LOAD_CONTROL_EVENT,
                tsn: 0,
                len: LOAD_CONTROL_EVENT_LEN as u8,
                payload,
            });
            i += 1;
        }
        Ok(n)
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
            CMD_GET_SCHEDULED_EVENTS => {
                let req = decode_get_scheduled(payload).map_err(|_| ZclStatus::MalformedCommand)?;
                self.answer_scheduled(ctx, &req)?;
                Ok(HandleOutcome::no_reply())
            }
            CMD_REPORT_EVENT_STATUS => {
                decode_report_event_status(payload).map_err(|_| ZclStatus::MalformedCommand)?;
                Ok(HandleOutcome::no_reply())
            }
            _ => Err(ZclStatus::UnsupCommand),
        }
    }
}
