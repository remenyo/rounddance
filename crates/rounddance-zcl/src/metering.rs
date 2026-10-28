//! Simple Metering cluster (0x0702): server definition, reading
//! behavior, and consumption-profile (GetProfile) handling.
//!
//! Paraphrase-level model of doc `07-5123-08` §10.4 (attribute sets +
//! Tables 10-56/10-57/10-71, anchors p0714-L16287-L16294 +
//! p0714-L16299-L16302 + p0715-L16303-L16308 + p0732-L16680-L16688,
//! formatting prose p0735-L16701-L16731, demand row p0741 line 28,
//! server commands p0772-L17383-L17386 + p0775-L17431-L17450,
//! client commands p0799-L18066-L18070 + p0800-L18072-L18097 +
//! p0801-L18123-L18132, response status p0773-L17387-L17397).
//! All wording here is paraphrase (D1).
//!
//! Requirement IDs below are repo-minted (`07-5123-08-<clause>-<seq>`,
//! dots stripped), MINTED-pending-confirm, except the corpus-reused
//! mirror/snapshot rows named in `mirror.rs` / `snapshot.rs`. The
//! mirror-table state, the mirror setup commands, the
//! take/get-snapshot commands, and the schedule/sampling/supply
//! commands live in their modules; this file wires them into the
//! server behavior. Only the notification-scheme machinery
//! (`ConfigureMirror` et al.) and non-TOU publish shapes stay
//! bounded-opaque follow-up, never silent scope.

use crate::attrs::{access, AttrDef, AttrStore, ATTR_CLUSTER_REVISION};
use crate::behavior::{AppEvent, Behavior, Ctx, EventQueue, HandleOutcome};
use crate::cluster::{ClusterDef, ClusterRole, CmdDef};
use crate::frame::Header;
use crate::mirror::{self, MirrorClient};
use crate::sampling::{self, SampleEngine};
use crate::schedule::{self, ScheduleAssembler, ScheduleTable};
use crate::snapshot::{self, SnapshotStore};
use crate::supply::{self, SupplyMachine};
use crate::types::{DataType, Value};
use crate::{Error, ZclStatus};

/// Cluster identifier.
///
/// Requirement `07-5123-08-1041-01` (MINTED-pending-confirm).
pub const CLUSTER_ID: u16 = 0x0702;
/// Implemented specification revision (rev table tip).
///
/// Requirement `07-5123-08-1041-02` (MINTED-pending-confirm).
pub const REVISION: u16 = 2;

/// Reading information set: lifetime delivered summation (uint48).
pub const ATTR_SUMMATION_DELIVERED: u16 = 0x0000;
/// Reading information set: lifetime received summation (uint48).
pub const ATTR_SUMMATION_RECEIVED: u16 = 0x0001;
/// Reading information set: instantaneous demand (int24).
pub const ATTR_INSTANTANEOUS_DEMAND: u16 = 0x0400;
/// Reading information set: current-day delivered consumption (uint24).
pub const ATTR_DAY_CONSUMPTION_DELIVERED: u16 = 0x0401;
/// Formatting set: unit of measure (enum8, mandatory).
pub const ATTR_UNIT_OF_MEASURE: u16 = 0x0300;
/// Formatting set: scaling multiplier (uint24, paired with divisor).
pub const ATTR_MULTIPLIER: u16 = 0x0301;
/// Formatting set: scaling divisor (uint24, paired with multiplier).
pub const ATTR_DIVISOR: u16 = 0x0302;
/// Formatting set: summation digit layout (map8, mandatory).
pub const ATTR_SUMMATION_FORMATTING: u16 = 0x0303;
/// Formatting set: demand digit layout (map8).
pub const ATTR_DEMAND_FORMATTING: u16 = 0x0304;
/// Formatting set: metering device type (map8, mandatory).
pub const ATTR_METERING_DEVICE_TYPE: u16 = 0x0306;
/// Formatting set: meter serial number (octet string, 25 max here).
pub const ATTR_METER_SERIAL: u16 = 0x0308;

/// Server received: GetProfile (interval channel + end time + count).
pub const CMD_GET_PROFILE: u8 = 0x00;
/// Server received: RequestFastPollMode (period seconds + duration min).
pub const CMD_REQUEST_FAST_POLL: u8 = 0x03;
/// Server generated: GetProfileResponse (end time + status + intervals).
pub const CMD_GET_PROFILE_RESPONSE: u8 = 0x00;
/// Server generated: RequestFastPollModeResponse (period + end time).
pub const CMD_FAST_POLL_RESPONSE: u8 = 0x03;

/// GetProfile interval channels carried here (consumption pair).
pub const CHANNEL_DELIVERED: u8 = 0x00;
/// Consumption-received channel.
pub const CHANNEL_RECEIVED: u8 = 0x01;

/// GetProfileResponse status: success.
pub const PROFILE_STATUS_SUCCESS: u8 = 0x00;
/// GetProfileResponse status: undefined interval channel requested.
pub const PROFILE_STATUS_BAD_CHANNEL: u8 = 0x01;
/// GetProfileResponse status: no intervals available for the request.
pub const PROFILE_STATUS_NO_INTERVALS: u8 = 0x05;

/// Largest interval backlog the profile buffer holds (bounded).
pub const MAX_INTERVALS: usize = 24;
/// Largest interval payload one response encodes here.
pub const MAX_RESPONSE_INTERVALS: usize = 8;

/// Server attribute table, ascending.
///
/// Requirement `07-5123-08-1042-01` (reading set, mandatory
/// summation) + `07-5123-08-1042-02` (formatting set)
/// (both MINTED-pending-confirm).
pub static SERVER_ATTRS: &[AttrDef] = &[
    AttrDef {
        id: ATTR_SUMMATION_DELIVERED,
        datatype: DataType::UInt(6).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_SUMMATION_RECEIVED,
        datatype: DataType::UInt(6).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_UNIT_OF_MEASURE,
        datatype: DataType::Enum8.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_MULTIPLIER,
        datatype: DataType::UInt(3).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_DIVISOR,
        datatype: DataType::UInt(3).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_SUMMATION_FORMATTING,
        datatype: DataType::Map(1).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_DEMAND_FORMATTING,
        datatype: DataType::Map(1).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_METERING_DEVICE_TYPE,
        datatype: DataType::Map(1).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_METER_SERIAL,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_INSTANTANEOUS_DEMAND,
        datatype: DataType::Int(3).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_DAY_CONSUMPTION_DELIVERED,
        datatype: DataType::UInt(3).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_CLUSTER_REVISION,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ,
        reportable: false,
    },
];

/// Server received commands, ascending: the client-driven reads
/// plus the ESI-side answers (`RequestMirrorResponse`,
/// `MirrorRemoved`) and notification flags, which the meter's
/// server receives from the ESI client.
pub static SERVER_RX: &[CmdDef] = &[
    CmdDef {
        id: CMD_GET_PROFILE,
        name: "get-profile",
    },
    CmdDef {
        id: mirror::CMD_REQUEST_MIRROR_RESPONSE,
        name: "request-mirror-response",
    },
    CmdDef {
        id: mirror::CMD_MIRROR_REMOVED,
        name: "mirror-removed",
    },
    CmdDef {
        id: CMD_REQUEST_FAST_POLL,
        name: "request-fast-poll",
    },
    CmdDef {
        id: schedule::CMD_SCHEDULE_SNAPSHOT,
        name: "schedule-snapshot",
    },
    CmdDef {
        id: snapshot::CMD_TAKE_SNAPSHOT,
        name: "take-snapshot",
    },
    CmdDef {
        id: snapshot::CMD_GET_SNAPSHOT,
        name: "get-snapshot",
    },
    CmdDef {
        id: sampling::CMD_START_SAMPLING,
        name: "start-sampling",
    },
    CmdDef {
        id: sampling::CMD_GET_SAMPLED_DATA,
        name: "get-sampled-data",
    },
    CmdDef {
        id: mirror::CMD_MIRROR_REPORT_ATTR_RESPONSE,
        name: "mirror-report-attribute-response",
    },
    CmdDef {
        id: supply::CMD_RESET_LOAD_LIMIT,
        name: "reset-load-limit",
    },
    CmdDef {
        id: supply::CMD_CHANGE_SUPPLY,
        name: "change-supply",
    },
    CmdDef {
        id: supply::CMD_LOCAL_CHANGE_SUPPLY,
        name: "local-change-supply",
    },
    CmdDef {
        id: supply::CMD_SET_SUPPLY_STATUS,
        name: "set-supply-status",
    },
    CmdDef {
        id: supply::CMD_SET_UNCONTROLLED_FLOW,
        name: "set-uncontrolled-flow-threshold",
    },
];

/// Server generated commands, ascending: the meter's answers plus
/// the mirror-setup requests the meter's server sends toward the ESI.
pub static SERVER_TX: &[CmdDef] = &[
    CmdDef {
        id: CMD_GET_PROFILE_RESPONSE,
        name: "get-profile-response",
    },
    CmdDef {
        id: mirror::CMD_REQUEST_MIRROR,
        name: "request-mirror",
    },
    CmdDef {
        id: mirror::CMD_REMOVE_MIRROR,
        name: "remove-mirror",
    },
    CmdDef {
        id: CMD_FAST_POLL_RESPONSE,
        name: "fast-poll-response",
    },
    CmdDef {
        id: schedule::CMD_SCHEDULE_SNAPSHOT_RESPONSE,
        name: "schedule-snapshot-response",
    },
    CmdDef {
        id: snapshot::CMD_TAKE_SNAPSHOT_RESPONSE,
        name: "take-snapshot-response",
    },
    CmdDef {
        id: snapshot::CMD_PUBLISH_SNAPSHOT,
        name: "publish-snapshot",
    },
    CmdDef {
        id: sampling::CMD_GET_SAMPLED_DATA_RESPONSE,
        name: "get-sampled-data-response",
    },
    CmdDef {
        id: supply::CMD_SUPPLY_STATUS_RESPONSE,
        name: "supply-status-response",
    },
    CmdDef {
        id: sampling::CMD_START_SAMPLING_RESPONSE,
        name: "start-sampling-response",
    },
];

/// Server definition.
pub struct ServerDef;
impl ClusterDef for ServerDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "metering-server"
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

/// Build a fresh server store: zeroed readings, unitary scale
/// (multiplier = divisor = 1), blank formatting.
///
/// Requirement `07-5123-08-1042-01/02` (MINTED-pending-confirm).
pub fn server_store() -> Result<AttrStore, Error> {
    let mut store = AttrStore::new(None);
    store.add(SERVER_ATTRS[0], Value::UInt { width: 6, v: 0 })?;
    store.add(SERVER_ATTRS[1], Value::UInt { width: 6, v: 0 })?;
    store.add(SERVER_ATTRS[2], Value::Enum8(0))?;
    store.add(SERVER_ATTRS[3], Value::UInt { width: 3, v: 1 })?;
    store.add(SERVER_ATTRS[4], Value::UInt { width: 3, v: 1 })?;
    store.add(
        SERVER_ATTRS[5],
        Value::Map {
            width: 1,
            bytes: [0; 8],
        },
    )?;
    store.add(
        SERVER_ATTRS[6],
        Value::Map {
            width: 1,
            bytes: [0; 8],
        },
    )?;
    store.add(
        SERVER_ATTRS[7],
        Value::Map {
            width: 1,
            bytes: [0; 8],
        },
    )?;
    store.add(
        SERVER_ATTRS[8],
        Value::OctetStr {
            len: 0,
            bytes: [0; crate::types::MAX_STR_LEN],
        },
    )?;
    store.add(SERVER_ATTRS[9], Value::Int { width: 3, v: 0 })?;
    store.add(SERVER_ATTRS[10], Value::UInt { width: 3, v: 0 })?;
    store.add_globals(REVISION)?;
    Ok(store)
}

/// Read a `uint48` reading as `u64`.
fn get_u48(store: &AttrStore, attr: u16) -> u64 {
    match store.get(attr) {
        Some(Value::UInt { v, .. }) => v,
        _ => 0,
    }
}

/// Read a `uint24` scale attribute; missing means 1 (absent scale is
/// unitary here, matching the paired-scale rule: a zero divisor must
/// never divide).
fn get_scale(store: &AttrStore, attr: u16) -> u64 {
    match store.get(attr) {
        Some(Value::UInt { v, .. }) => v,
        _ => 1,
    }
}

/// Apply the multiplier/divisor pair to a raw count, saturating.
///
/// Requirement `07-5123-08-1042-03` (MINTED-pending-confirm): the
/// pair scales every summation/consumption/demand reading into the
/// unit of measure. A zero divisor is treated as unitary (fallible
/// codecs never divide by zero); a zero multiplier yields zero.
#[must_use]
pub fn scaled_value(raw: u64, multiplier: u64, divisor: u64) -> u64 {
    let div = if divisor == 0 { 1 } else { divisor };
    raw.saturating_mul(multiplier) / div
}

/// Scaled delivered summation from the live store.
pub fn scaled_summation(store: &AttrStore) -> u64 {
    scaled_value(
        get_u48(store, ATTR_SUMMATION_DELIVERED),
        get_scale(store, ATTR_MULTIPLIER),
        get_scale(store, ATTR_DIVISOR),
    )
}

/// Split a digit-layout octet into (right-of-point, left-of-point,
/// suppress-leading-zeros).
///
/// Requirement `07-5123-08-1042-04` (MINTED-pending-confirm).
#[must_use]
pub const fn split_formatting(layout: u8) -> (u8, u8, bool) {
    (layout & 0x07, (layout >> 3) & 0x0f, layout & 0x80 != 0)
}

/// Decoded GetProfile request.
///
/// Requirement `07-5123-08-1043-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetProfileRequest {
    /// Interval channel (0 = delivered, 1 = received here).
    pub channel: u8,
    /// End time selecting the newest block at or before it (0 asks
    /// for the most recent block).
    pub end_time: u32,
    /// Number of intervals requested.
    pub periods: u8,
}

/// Decode a GetProfile request body (1 + 4 + 1 octets).
pub fn decode_get_profile(buf: &[u8]) -> Result<GetProfileRequest, Error> {
    if buf.len() != 6 {
        return Err(Error::Truncated);
    }
    Ok(GetProfileRequest {
        channel: buf[0],
        end_time: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
        periods: buf[5],
    })
}

/// Encode a GetProfile request body into `out` (6 octets).
pub fn encode_get_profile(req: &GetProfileRequest, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 6 {
        return Err(Error::BufferTooSmall);
    }
    out[0] = req.channel;
    out[1..5].copy_from_slice(&req.end_time.to_le_bytes());
    out[5] = req.periods;
    Ok(6)
}

/// Bounded consumption-profile backlog: newest-first interval ring
/// plus the end time of the newest interval.
///
/// Requirement `07-5123-08-1043-02` (MINTED-pending-confirm): the
/// meter keeps capturable interval blocks the client pages through
/// with end-time-anchored requests.
#[derive(Clone, Copy, Debug)]
pub struct ProfileBuffer {
    intervals: [u32; MAX_INTERVALS],
    len: u8,
    newest_end_time: u32,
    period_enum: u8,
}

impl Default for ProfileBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl ProfileBuffer {
    /// Empty backlog with `period_s` seconds per interval.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            intervals: [0; MAX_INTERVALS],
            len: 0,
            newest_end_time: 0,
            period_enum: 3,
        }
    }

    /// Record one interval (24-bit value); oldest drops when full.
    pub fn record(&mut self, value: u32, end_time: u32) {
        let v = value & 0x00ff_ffff;
        if self.len as usize >= MAX_INTERVALS {
            let mut i = MAX_INTERVALS - 1;
            while i > 0 {
                self.intervals[i] = self.intervals[i - 1];
                i -= 1;
            }
            self.intervals[0] = v;
        } else {
            let mut i = self.len as usize;
            while i > 0 {
                self.intervals[i] = self.intervals[i - 1];
                i -= 1;
            }
            self.intervals[0] = v;
            self.len += 1;
        }
        self.newest_end_time = end_time;
    }

    /// Interval count held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the backlog is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Answer a GetProfile request: status + response body in `out`.
    /// Unknown channels answer `BAD_CHANNEL`; an empty backlog or a
    /// request for more than held answers `NO_INTERVALS`; otherwise
    /// the newest-first slice is encoded as little-endian uint24s.
    pub fn answer(&self, req: &GetProfileRequest, out: &mut [u8]) -> Result<usize, ZclStatus> {
        if req.channel != CHANNEL_DELIVERED && req.channel != CHANNEL_RECEIVED {
            return Err(ZclStatus::InvalidField);
        }
        if self.is_empty() || req.periods == 0 {
            return Err(ZclStatus::NotFound);
        }
        let n = (req.periods as usize)
            .min(self.len as usize)
            .min(MAX_RESPONSE_INTERVALS);
        // 4 (end time) + 1 (status) + 1 (period enum) + 1 (count) + 3*n.
        let need = 7 + 3 * n;
        if out.len() < need {
            return Err(ZclStatus::InsufficientSpace);
        }
        out[0..4].copy_from_slice(&self.newest_end_time.to_le_bytes());
        out[4] = PROFILE_STATUS_SUCCESS;
        out[5] = self.period_enum;
        out[6] = n as u8;
        let mut i = 0;
        while i < n {
            let v = self.intervals[i] & 0x00ff_ffff;
            out[7 + 3 * i..10 + 3 * i].copy_from_slice(&v.to_le_bytes()[..3]);
            i += 1;
        }
        Ok(need)
    }
}

/// Server behavior: reading updates plus GetProfile / fast-poll /
/// mirror-setup / snapshot / schedule / sampling / supply command
/// handling.
pub struct ServerBehavior {
    profile: ProfileBuffer,
    fast_poll_until_s: u64,
    mirror: MirrorClient,
    snapshots: SnapshotStore,
    schedules: ScheduleTable,
    assembler: ScheduleAssembler,
    samples: SampleEngine,
    supply: SupplyMachine,
}

impl Default for ServerBehavior {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBehavior {
    /// Fresh behavior: empty profile, no fast poll, no mirror
    /// grant, no snapshots, schedules, sessions, or supply orders.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            profile: ProfileBuffer::new(),
            fast_poll_until_s: 0,
            mirror: MirrorClient::new(),
            snapshots: SnapshotStore::new(),
            schedules: ScheduleTable::new(),
            assembler: ScheduleAssembler::new(),
            samples: SampleEngine::new(),
            supply: SupplyMachine::new(),
        }
    }

    /// Borrow the profile backlog (tests/sim fill it).
    pub const fn profile(&self) -> &ProfileBuffer {
        &self.profile
    }

    /// Mutable profile backlog.
    pub fn profile_mut(&mut self) -> &mut ProfileBuffer {
        &mut self.profile
    }

    /// Borrow the meter-side mirror record (granted endpoint plus
    /// latest waiting-command flags).
    pub const fn mirror_client(&self) -> &MirrorClient {
        &self.mirror
    }

    /// Mutable meter-side mirror record.
    pub fn mirror_client_mut(&mut self) -> &mut MirrorClient {
        &mut self.mirror
    }

    /// Borrow the snapshot store.
    pub const fn snapshots(&self) -> &SnapshotStore {
        &self.snapshots
    }

    /// Mutable snapshot store (tests/sim pre-load snapshots).
    pub fn snapshots_mut(&mut self) -> &mut SnapshotStore {
        &mut self.snapshots
    }

    /// Borrow the snapshot timetable.
    pub const fn schedules(&self) -> &ScheduleTable {
        &self.schedules
    }

    /// Mutable timetable (tests/sim pre-file schedules).
    pub fn schedules_mut(&mut self) -> &mut ScheduleTable {
        &mut self.schedules
    }

    /// Borrow the sampling engine.
    pub const fn samples(&self) -> &SampleEngine {
        &self.samples
    }

    /// Mutable sampling engine (tests/sim push captures).
    pub fn samples_mut(&mut self) -> &mut SampleEngine {
        &mut self.samples
    }

    /// Borrow the supply machine.
    pub const fn supply(&self) -> &SupplyMachine {
        &self.supply
    }

    /// Mutable supply machine (tests/sim narrow policy + drive
    /// meter events).
    pub fn supply_mut(&mut self) -> &mut SupplyMachine {
        &mut self.supply
    }

    /// Take one snapshot around the live delivered summation (the
    /// tariff-change pair rule included); shared by command-driven
    /// and timetable-driven takes.
    fn take_live(&mut self, store: &AttrStore, time: u32, cause: u32) -> (u32, u8) {
        let summation = get_u48(store, ATTR_SUMMATION_DELIVERED);
        let mut sub = [0u8; snapshot::MAX_SNAPSHOT_SUB];
        let sub_len =
            match snapshot::encode_tou_sub_payload(summation, 0, 0, 0, 0, 0, &[], &mut sub) {
                Ok(n) => n,
                Err(_) => return (0, snapshot::CONFIRM_CAUSE_NOT_SUPPORTED),
            };
        if cause & (1u32 << snapshot::CAUSE_TARIFF_CHANGE_BIT) != 0 {
            let (ids, conf) = self.snapshots.take_pair(
                time,
                cause,
                snapshot::PAYLOAD_TOU_DELIVERED,
                &sub[..sub_len],
                &sub[..sub_len],
            );
            (ids[0], conf)
        } else {
            self.snapshots.take(
                time,
                cause,
                snapshot::PAYLOAD_TOU_DELIVERED,
                &sub[..sub_len],
            )
        }
    }

    /// Caller-second tick for the timetable/sampling/supply paths:
    /// fires due timetable entries into the snapshot store (with the
    /// scheduled bit folded in), opens due sampling sessions, and
    /// executes a due delayed supply command (queueing its
    /// acknowledgement when requested). Behaviors never read a
    /// clock; the caller passes `now`.
    ///
    /// Requirement `07-5123-08-1046-02` (timetable firing) +
    /// `07-5123-08-1047-04` (session opening) +
    /// `17-05019-012-423-03` (delayed execution)
    /// (MINTED-pending-confirm where noted).
    pub fn tick_metering(&mut self, store: &AttrStore, events: &mut EventQueue, now: u32) {
        // Timetable fires: this build carries the delivered-TOU
        // shape, which the intake gate already enforces.
        let mut due = [(0u32, 0u8); schedule::MAX_SCHEDULES];
        let n = self.schedules.collect_due(now, &mut due);
        let mut i = 0;
        while i < n {
            let cause = due[i].0 | (1u32 << snapshot::CAUSE_SCHEDULED_BIT);
            let _ = self.take_live(store, now, cause);
            i += 1;
        }
        // Sampling sessions whose start time arrived.
        let opened = self.samples.tick(now);
        if opened > 0 {
            events.push(AppEvent::StateChanged {
                cluster: CLUSTER_ID,
                from: 4,
                to: opened,
            });
        }
        // Delayed supply execution.
        let old = self.supply.status();
        if let Some((rsp, ack)) = self.supply.tick(now) {
            events.push(AppEvent::StateChanged {
                cluster: CLUSTER_ID,
                from: old,
                to: rsp.status,
            });
            if ack {
                let mut body = [0u8; 13];
                if supply::encode_supply_status_response(&rsp, &mut body).is_ok() {
                    let mut payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
                    payload[..13].copy_from_slice(&body);
                    events.push(AppEvent::OutboundCommand {
                        cluster: CLUSTER_ID,
                        cmd: supply::CMD_SUPPLY_STATUS_RESPONSE,
                        tsn: 0,
                        len: 13,
                        payload,
                    });
                }
            }
        }
    }

    /// Queue an outbound `RequestMirror` (empty body) for the
    /// application to send toward the ESI.
    ///
    /// Requirement `07-5123-08-1044-01` (MINTED-pending-confirm).
    pub fn request_mirror(&mut self, ctx: &mut Ctx<'_>) {
        let payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
        ctx.events.push(AppEvent::OutboundCommand {
            cluster: CLUSTER_ID,
            cmd: mirror::CMD_REQUEST_MIRROR,
            tsn: 0,
            len: 0,
            payload,
        });
    }

    /// Queue an outbound `RemoveMirror` (empty body) for the
    /// application to send toward the ESI.
    ///
    /// Requirement `07-5123-08-1044-01` (MINTED-pending-confirm).
    pub fn remove_mirror(&mut self, ctx: &mut Ctx<'_>) {
        let payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
        ctx.events.push(AppEvent::OutboundCommand {
            cluster: CLUSTER_ID,
            cmd: mirror::CMD_REMOVE_MIRROR,
            tsn: 0,
            len: 0,
            payload,
        });
    }

    /// Add a raw meter count to the delivered summation (saturating
    /// at 48 bits) and mirror it into the day consumption. Internal
    /// measurement updates use the local path: the summation
    /// attributes are read-only to peers.
    ///
    /// Requirement `07-5123-08-1042-01` (MINTED-pending-confirm).
    pub fn add_consumption(&self, store: &mut AttrStore, raw: u64) {
        let cur = get_u48(store, ATTR_SUMMATION_DELIVERED);
        // Clamp (not mask): saturation sticks at the 48-bit ceiling
        // instead of wrapping into the low bits.
        let next = cur.saturating_add(raw).min(0x0000_ffff_ffff_ffff);
        let _ = store.set_local(ATTR_SUMMATION_DELIVERED, Value::UInt { width: 6, v: next });
        let day = match store.get(ATTR_DAY_CONSUMPTION_DELIVERED) {
            Some(Value::UInt { v, .. }) => v,
            _ => 0,
        };
        let _ = store.set_local(
            ATTR_DAY_CONSUMPTION_DELIVERED,
            Value::UInt {
                width: 3,
                v: day.saturating_add(raw).min(0x00ff_ffff),
            },
        );
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
            CMD_GET_PROFILE => {
                let req = decode_get_profile(payload).map_err(|_| ZclStatus::MalformedCommand)?;
                let mut body = [0u8; 7 + 3 * MAX_RESPONSE_INTERVALS];
                match self.profile.answer(&req, &mut body) {
                    Ok(n) => {
                        let mut payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
                        payload[..n].copy_from_slice(&body[..n]);
                        ctx.events.push(AppEvent::OutboundCommand {
                            cluster: CLUSTER_ID,
                            cmd: CMD_GET_PROFILE_RESPONSE,
                            tsn: 0,
                            len: n as u8,
                            payload,
                        });
                        Ok(HandleOutcome::no_reply())
                    }
                    Err(ZclStatus::InvalidField) => Err(ZclStatus::InvalidField),
                    Err(_) => Err(ZclStatus::NotFound),
                }
            }
            CMD_REQUEST_FAST_POLL => {
                if payload.len() != 2 {
                    return Err(ZclStatus::MalformedCommand);
                }
                let period = payload[0].max(1);
                let duration_min = payload[1];
                self.fast_poll_until_s = ctx.now_s + (duration_min as u64).saturating_mul(60);
                ctx.events.push(AppEvent::StateChanged {
                    cluster: CLUSTER_ID,
                    from: 0,
                    to: 1,
                });
                let mut payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
                payload[0] = period;
                payload[1..5].copy_from_slice(&(self.fast_poll_until_s as u32).to_le_bytes());
                ctx.events.push(AppEvent::OutboundCommand {
                    cluster: CLUSTER_ID,
                    cmd: CMD_FAST_POLL_RESPONSE,
                    tsn: 0,
                    len: 5,
                    payload,
                });
                Ok(HandleOutcome::no_reply())
            }
            mirror::CMD_REQUEST_MIRROR_RESPONSE => {
                let endpoint = mirror::decode_mirror_endpoint(payload)
                    .map_err(|_| ZclStatus::MalformedCommand)?;
                self.mirror.on_response(endpoint)?;
                let (from, to) = if endpoint == mirror::ENDPOINT_REFUSED {
                    (1, 0)
                } else {
                    (0, 1)
                };
                ctx.events.push(AppEvent::StateChanged {
                    cluster: CLUSTER_ID,
                    from,
                    to,
                });
                Ok(HandleOutcome::no_reply())
            }
            mirror::CMD_MIRROR_REMOVED => {
                let endpoint = mirror::decode_mirror_endpoint(payload)
                    .map_err(|_| ZclStatus::MalformedCommand)?;
                self.mirror.on_removed(endpoint);
                ctx.events.push(AppEvent::StateChanged {
                    cluster: CLUSTER_ID,
                    from: 1,
                    to: 0,
                });
                Ok(HandleOutcome::no_reply())
            }
            mirror::CMD_MIRROR_REPORT_ATTR_RESPONSE => {
                let mut report = mirror::MirrorReport::new(0);
                mirror::decode_mirror_report(payload, &mut report)
                    .map_err(|_| ZclStatus::MalformedCommand)?;
                let count = self.mirror.on_report(&report);
                ctx.events.push(AppEvent::StateChanged {
                    cluster: CLUSTER_ID,
                    from: 2,
                    to: count.min(255) as u8,
                });
                Ok(HandleOutcome::no_reply())
            }
            snapshot::CMD_TAKE_SNAPSHOT => {
                let req = snapshot::decode_take_snapshot(payload)
                    .map_err(|_| ZclStatus::MalformedCommand)?;
                // Command-driven takes additionally carry the manual
                // bit on top of the requested cause.
                let cause = req.cause | (1u32 << snapshot::CAUSE_MANUAL_BIT);
                // Caller seconds seed the snapshot clock; the low 32
                // bits are the on-wire timestamp.
                #[allow(clippy::cast_possible_truncation)]
                let now = ctx.now_s as u32;
                // A tariff-change take lands as a before/after pair;
                // the response carries the first id.
                let (id, confirmation) = self.take_live(ctx.store, now, cause);
                let mut body = [0u8; 5];
                snapshot::encode_take_snapshot_response(
                    &snapshot::TakeSnapshotResponse {
                        snapshot_id: id,
                        confirmation,
                    },
                    &mut body,
                )
                .map_err(|_| ZclStatus::InsufficientSpace)?;
                HandleOutcome::reply(snapshot::CMD_TAKE_SNAPSHOT_RESPONSE, &body)
                    .map_err(|_| ZclStatus::InsufficientSpace)
            }
            snapshot::CMD_GET_SNAPSHOT => {
                let req = snapshot::decode_get_snapshot(payload)
                    .map_err(|_| ZclStatus::MalformedCommand)?;
                match self
                    .snapshots
                    .query(req.earliest, req.latest, req.offset, req.cause)
                {
                    Ok(snap) => {
                        let total = self
                            .snapshots
                            .match_count(req.earliest, req.latest, req.cause);
                        let hdr = snapshot::PublishSnapshot {
                            snapshot_id: snap.id,
                            snapshot_time: snap.time,
                            total_found: total,
                            command_index: 0,
                            total_commands: 1,
                            cause: snap.cause,
                            payload_type: snap.payload_type,
                        };
                        let mut body = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
                        let n =
                            snapshot::encode_publish_snapshot(&hdr, snap.sub_payload(), &mut body)
                                .map_err(|_| ZclStatus::InsufficientSpace)?;
                        HandleOutcome::reply(snapshot::CMD_PUBLISH_SNAPSHOT, &body[..n])
                            .map_err(|_| ZclStatus::InsufficientSpace)
                    }
                    Err(_) => Err(ZclStatus::NotFound),
                }
            }
            schedule::CMD_SCHEDULE_SNAPSHOT => {
                if payload.len() < 6 {
                    return Err(ZclStatus::MalformedCommand);
                }
                let issuer = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let index = payload[4];
                let total = payload[5];
                let body = &payload[6..];
                match self.assembler.feed(issuer, index, total, body) {
                    Err(e) => Err(e),
                    Ok(schedule::Assembly::Incomplete) => Ok(HandleOutcome::no_reply()),
                    Ok(schedule::Assembly::Complete { issuer, len }) => {
                        let mut confirmations = [(0u8, 0u8); schedule::MAX_SCHEDULE_CONFIRM];
                        let mut count = 0usize;
                        let mut off = 0;
                        while off + schedule::SCHEDULE_ENTRY_LEN <= len as usize
                            && count < schedule::MAX_SCHEDULE_CONFIRM
                        {
                            let entry = schedule::decode_schedule_entry(
                                &self.assembler.assembled()
                                    [off..off + schedule::SCHEDULE_ENTRY_LEN],
                            )
                            .map_err(|_| ZclStatus::MalformedCommand)?;
                            // This build fires the delivered-TOU
                            // shape; anything else is a typed refusal.
                            let conf = if entry.payload_type != snapshot::PAYLOAD_TOU_DELIVERED {
                                schedule::SCHEDULE_CONF_TYPE_NOT_SUPPORTED
                            } else {
                                self.schedules.intake(issuer, &entry)
                            };
                            confirmations[count] = (entry.id, conf);
                            count += 1;
                            off += schedule::SCHEDULE_ENTRY_LEN;
                        }
                        if off != len as usize {
                            return Err(ZclStatus::MalformedCommand);
                        }
                        let mut rsp = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
                        let n = schedule::encode_schedule_response(
                            issuer,
                            &confirmations[..count],
                            &mut rsp,
                        )
                        .map_err(|_| ZclStatus::InsufficientSpace)?;
                        HandleOutcome::reply(schedule::CMD_SCHEDULE_SNAPSHOT_RESPONSE, &rsp[..n])
                            .map_err(|_| ZclStatus::InsufficientSpace)
                    }
                }
            }
            sampling::CMD_START_SAMPLING => {
                let req = sampling::decode_start_sampling(payload)
                    .map_err(|_| ZclStatus::MalformedCommand)?;
                #[allow(clippy::cast_possible_truncation)]
                let now = ctx.now_s as u32;
                match self.samples.open(&req, now) {
                    sampling::OpenVerdict::Opened(id) => {
                        let mut body = [0u8; 2];
                        sampling::encode_start_response(id, &mut body)
                            .map_err(|_| ZclStatus::InsufficientSpace)?;
                        HandleOutcome::reply(sampling::CMD_START_SAMPLING_RESPONSE, &body)
                            .map_err(|_| ZclStatus::InsufficientSpace)
                    }
                    sampling::OpenVerdict::Full => {
                        let mut body = [0u8; 2];
                        sampling::encode_start_response(sampling::SAMPLE_ID_NONE, &mut body)
                            .map_err(|_| ZclStatus::InsufficientSpace)?;
                        HandleOutcome::reply(sampling::CMD_START_SAMPLING_RESPONSE, &body)
                            .map_err(|_| ZclStatus::InsufficientSpace)
                    }
                    sampling::OpenVerdict::Stale | sampling::OpenVerdict::Cancelled => {
                        Ok(HandleOutcome::no_reply())
                    }
                    sampling::OpenVerdict::Unusable => Err(ZclStatus::InvalidField),
                }
            }
            sampling::CMD_GET_SAMPLED_DATA => {
                let req = sampling::decode_get_sampled_data(payload)
                    .map_err(|_| ZclStatus::MalformedCommand)?;
                let mut values = [0u32; sampling::MAX_SAMPLES_PER_RESPONSE];
                match self.samples.query(&req, &mut values) {
                    Err(e) => Err(e),
                    Ok((start, sample_type, interval_s, count)) => {
                        let mut body = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
                        let n = sampling::encode_sampled_data_response(
                            req.sample_id,
                            start,
                            sample_type,
                            interval_s,
                            &values[..count as usize],
                            &mut body,
                        )
                        .map_err(|_| ZclStatus::InsufficientSpace)?;
                        HandleOutcome::reply(sampling::CMD_GET_SAMPLED_DATA_RESPONSE, &body[..n])
                            .map_err(|_| ZclStatus::InsufficientSpace)
                    }
                }
            }
            supply::CMD_CHANGE_SUPPLY => {
                let req = supply::decode_change_supply(payload)
                    .map_err(|_| ZclStatus::MalformedCommand)?;
                #[allow(clippy::cast_possible_truncation)]
                let now = ctx.now_s as u32;
                match self.supply.apply_change(&req, now) {
                    Err(e) => Err(e),
                    Ok(supply::SupplyOutcome::Delayed) => Ok(HandleOutcome::no_reply()),
                    Ok(supply::SupplyOutcome::Cancelled) => Ok(HandleOutcome::no_reply()),
                    Ok(supply::SupplyOutcome::Applied { ack }) => {
                        let new = self.supply.status();
                        ctx.events.push(AppEvent::StateChanged {
                            cluster: CLUSTER_ID,
                            from: new,
                            to: new,
                        });
                        if ack {
                            let rsp = supply::SupplyStatusResponse {
                                provider: req.provider,
                                issuer: req.issuer,
                                impl_time: req.impl_time,
                                status: new,
                            };
                            let mut body = [0u8; 13];
                            supply::encode_supply_status_response(&rsp, &mut body)
                                .map_err(|_| ZclStatus::InsufficientSpace)?;
                            HandleOutcome::reply(supply::CMD_SUPPLY_STATUS_RESPONSE, &body)
                                .map_err(|_| ZclStatus::InsufficientSpace)
                        } else {
                            Ok(HandleOutcome::no_reply())
                        }
                    }
                }
            }
            supply::CMD_LOCAL_CHANGE_SUPPLY => {
                let proposed = supply::decode_local_change_supply(payload)
                    .map_err(|_| ZclStatus::MalformedCommand)?;
                let old = self.supply.status();
                self.supply.apply_local(proposed)?;
                ctx.events.push(AppEvent::StateChanged {
                    cluster: CLUSTER_ID,
                    from: old,
                    to: proposed,
                });
                Ok(HandleOutcome::no_reply())
            }
            supply::CMD_SET_SUPPLY_STATUS => {
                let req = supply::decode_set_supply_status(payload)
                    .map_err(|_| ZclStatus::MalformedCommand)?;
                let _ = self.supply.apply_set_status(&req)?;
                Ok(HandleOutcome::no_reply())
            }
            supply::CMD_SET_UNCONTROLLED_FLOW => {
                let cfg = supply::decode_flow_threshold(payload)
                    .map_err(|_| ZclStatus::MalformedCommand)?;
                self.supply.apply_flow(&cfg);
                Ok(HandleOutcome::no_reply())
            }
            supply::CMD_RESET_LOAD_LIMIT => {
                let (provider, issuer) = supply::decode_reset_load_limit(payload)
                    .map_err(|_| ZclStatus::MalformedCommand)?;
                self.supply.reset_load_limit(provider, issuer);
                Ok(HandleOutcome::no_reply())
            }
            _ => Err(ZclStatus::UnsupCommand),
        }
    }
}
