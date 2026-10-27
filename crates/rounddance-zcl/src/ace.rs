//! IAS ACE (Ancillary Control Equipment) server cluster (0x0501):
//! arm/bypass/panic handling, zone-table queries, and panel fan-out.
//!
//! Paraphrase-level model of doc `07-5123-08` §8.3 (received table
//! anchor p0536-L12218-L12221, arm payload p0537-L12223-L12225 +
//! mode values p0537-L12226-L12228 + code rules p0537-L12229-L12237 +
//! arm effect p0538-L12241-L12245, bypass payload
//! p0538-L12252-L12255 + bypass effect p0538-L12261-L12264,
//! emergency/fire/panic p0538-L12264-L12265, zone-ID-map query
//! p0538-L12266-L12268, zone-information query p0539-L12273-L12276 +
//! effect p0539-L12277-L12278, panel-status query
//! p0539-L12280-L12282, zone-status query p0540-L12305-L12308 +
//! mask rules p0540-L12313-L12333, generated table
//! p0541-L12340-L12341, arm-response payload p0541-L12344-L12345 +
//! notification values p0541-L12347-L12348 + p0542-L12349,
//! zone-ID-map response p0542-L12351-L12353, zone-information
//! response p0542-L12359-L12361 + unallocated rule
//! p0542-L12363-L12365, zone-status-changed p0543-L12378-L12380 +
//! audible values p0543-L12391-L12393, panel-status-changed
//! p0544-L12414-L12416 + panel values p0544-L12418-L12419 +
//! p0545 + per-second arming updates p0544-L12409-L12412, alarm
//! values p0545-L12427-L12429, seconds-remaining
//! p0546-L12431-L12435, panel-status response p0546-L12441-L12442,
//! bypassed-list payload p0547-L12460-L12462 + disarm reset
//! p0547-L12472-L12474, bypass-response p0547-L12480-L12481 +
//! result values p0548-L12489-L12490, zone-status response
//! p0548-L12495-L12496). All wording here is paraphrase (D1).
//!
//! Requirement IDs `07-5123-08-832-01..04` corpus-mined and reused;
//! `07-5123-08-831-01`, `07-5123-08-833-01/02`,
//! `07-5123-08-834-01` repo-minted, MINTED-pending-confirm.

use crate::attrs::{AttrDef, AttrStore, ATTR_CLUSTER_REVISION};
use crate::behavior::{AppEvent, Behavior, Ctx, EventQueue, HandleOutcome};
use crate::cluster::{ClusterDef, ClusterRole, CmdDef};
use crate::frame::{Direction, FrameControl, FrameType, Header};
use crate::types::DataType;
use crate::{Error, ZclStatus};

/// Cluster identifier.
///
/// Requirement `07-5123-08-831-01` (MINTED-pending-confirm).
pub const CLUSTER_ID: u16 = 0x0501;
/// Implemented specification revision (rev table tip).
///
/// Requirement `07-5123-08-831-01` (MINTED-pending-confirm).
pub const REVISION: u16 = 2;

/// Received: Arm (mode + code + zone id).
pub const CMD_ARM: u8 = 0x00;
/// Received: Bypass (count + zone ids + code).
pub const CMD_BYPASS: u8 = 0x01;
/// Received: Emergency (no payload).
pub const CMD_EMERGENCY: u8 = 0x02;
/// Received: Fire (no payload).
pub const CMD_FIRE: u8 = 0x03;
/// Received: Panic (no payload).
pub const CMD_PANIC: u8 = 0x04;
/// Received: Get Zone ID Map (no payload).
pub const CMD_GET_ZONE_ID_MAP: u8 = 0x05;
/// Received: Get Zone Information (zone id).
pub const CMD_GET_ZONE_INFO: u8 = 0x06;
/// Received: Get Panel Status (no payload).
pub const CMD_GET_PANEL_STATUS: u8 = 0x07;
/// Received: Get Bypassed Zone List (no payload).
pub const CMD_GET_BYPASSED_LIST: u8 = 0x08;
/// Received: Get Zone Status (start + max + mask flag + mask).
pub const CMD_GET_ZONE_STATUS: u8 = 0x09;

/// Generated: Arm Response (notification).
pub const CMD_ARM_RESPONSE: u8 = 0x00;
/// Generated: Get Zone ID Map Response (16 section bitmaps).
pub const CMD_ZONE_ID_MAP_RESPONSE: u8 = 0x01;
/// Generated: Get Zone Information Response.
pub const CMD_ZONE_INFO_RESPONSE: u8 = 0x02;
/// Generated: Zone Status Changed.
pub const CMD_ZONE_STATUS_CHANGED: u8 = 0x03;
/// Generated: Panel Status Changed.
pub const CMD_PANEL_STATUS_CHANGED: u8 = 0x04;
/// Generated: Get Panel Status Response.
pub const CMD_PANEL_STATUS_RESPONSE: u8 = 0x05;
/// Generated: Set Bypassed Zone List.
pub const CMD_SET_BYPASSED_LIST: u8 = 0x06;
/// Generated: Bypass Response.
pub const CMD_BYPASS_RESPONSE: u8 = 0x07;
/// Generated: Get Zone Status Response.
pub const CMD_ZONE_STATUS_RESPONSE: u8 = 0x08;

/// Arm mode: disarm.
pub const ARM_DISARM: u8 = 0x00;
/// Arm mode: arm day/home zones only.
pub const ARM_DAY_HOME: u8 = 0x01;
/// Arm mode: arm night/sleep zones only.
pub const ARM_NIGHT_SLEEP: u8 = 0x02;
/// Arm mode: arm all zones.
pub const ARM_ALL: u8 = 0x03;

/// Arm notification: all zones disarmed.
pub const ARM_NOTIFY_DISARMED: u8 = 0x00;
/// Arm notification: only day/home zones armed.
pub const ARM_NOTIFY_DAY: u8 = 0x01;
/// Arm notification: only night/sleep zones armed.
pub const ARM_NOTIFY_NIGHT: u8 = 0x02;
/// Arm notification: all zones armed.
pub const ARM_NOTIFY_ALL: u8 = 0x03;
/// Arm notification: invalid arm/disarm code.
pub const ARM_NOTIFY_BAD_CODE: u8 = 0x04;
/// Arm notification: not ready to arm.
pub const ARM_NOTIFY_NOT_READY: u8 = 0x05;
/// Arm notification: already disarmed.
pub const ARM_NOTIFY_ALREADY_DISARMED: u8 = 0x06;

/// Panel status: disarmed and ready.
pub const PANEL_DISARMED: u8 = 0x00;
/// Panel status: armed stay.
pub const PANEL_ARMED_STAY: u8 = 0x01;
/// Panel status: armed night.
pub const PANEL_ARMED_NIGHT: u8 = 0x02;
/// Panel status: armed away.
pub const PANEL_ARMED_AWAY: u8 = 0x03;
/// Panel status: exit delay.
pub const PANEL_EXIT_DELAY: u8 = 0x04;
/// Panel status: entry delay.
pub const PANEL_ENTRY_DELAY: u8 = 0x05;
/// Panel status: not ready to arm.
pub const PANEL_NOT_READY: u8 = 0x06;
/// Panel status: in alarm.
pub const PANEL_IN_ALARM: u8 = 0x07;
/// Panel status: arming stay.
pub const PANEL_ARMING_STAY: u8 = 0x08;
/// Panel status: arming night.
pub const PANEL_ARMING_NIGHT: u8 = 0x09;
/// Panel status: arming away.
pub const PANEL_ARMING_AWAY: u8 = 0x0a;

/// Alarm status: no alarm.
pub const ALARM_NONE: u8 = 0x00;
/// Alarm status: burglar.
pub const ALARM_BURGLAR: u8 = 0x01;
/// Alarm status: fire.
pub const ALARM_FIRE: u8 = 0x02;
/// Alarm status: emergency.
pub const ALARM_EMERGENCY: u8 = 0x03;
/// Alarm status: police panic.
pub const ALARM_POLICE_PANIC: u8 = 0x04;
/// Alarm status: fire panic.
pub const ALARM_FIRE_PANIC: u8 = 0x05;
/// Alarm status: emergency (medical) panic.
pub const ALARM_MEDICAL_PANIC: u8 = 0x06;

/// Audible notification: mute.
pub const AUDIBLE_MUTE: u8 = 0x00;
/// Audible notification: default sound.
pub const AUDIBLE_DEFAULT: u8 = 0x01;

/// Bypass result: zone bypassed.
pub const BYPASS_OK: u8 = 0x00;
/// Bypass result: zone not bypassed.
pub const BYPASS_FAILED: u8 = 0x01;
/// Bypass result: bypass not allowed by policy.
pub const BYPASS_NOT_ALLOWED: u8 = 0x02;
/// Bypass result: zone id outside the valid range.
pub const BYPASS_INVALID_ID: u8 = 0x03;
/// Bypass result: valid range, but no record held.
pub const BYPASS_UNKNOWN_ID: u8 = 0x04;
/// Bypass result: arm/disarm code rejected.
pub const BYPASS_BAD_CODE: u8 = 0x05;

/// Zone id meaning "no zone programmed".
pub const ZONE_ID_NONE: u8 = 0xff;
/// Largest zone table this server keeps (bounded).
pub const MAX_ZONES: usize = 16;
/// Longest zone label carried here (paraphrase of the 16..24
/// guidance: capped at 24, never grown).
pub const MAX_ZONE_LABEL: usize = 24;
/// Longest arm/disarm code accepted here (bounded; the text sets
/// no hard maximum, so overlong codes are refused, never grown).
pub const MAX_CODE_LEN: usize = 16;
/// Most zone ids one Bypass command may name here.
pub const MAX_BYPASS_IDS: usize = 16;
/// Most (id, status) pairs one status response carries here
/// (3 + 20 * 3 = 63 octets, inside the 64-octet event budget).
pub const MAX_STATUS_PAIRS: usize = 20;

/// Server attribute table: revision globals only (no
/// cluster-specific attributes here).
///
/// Requirement `07-5123-08-831-01` (MINTED-pending-confirm).
pub static SERVER_ATTRS: &[AttrDef] = &[AttrDef {
    id: ATTR_CLUSTER_REVISION,
    datatype: DataType::UInt(2).as_u8(),
    access: crate::attrs::access::READ,
    reportable: false,
}];

/// Server received commands, ascending.
pub static SERVER_RX: &[CmdDef] = &[
    CmdDef {
        id: CMD_ARM,
        name: "arm",
    },
    CmdDef {
        id: CMD_BYPASS,
        name: "bypass",
    },
    CmdDef {
        id: CMD_EMERGENCY,
        name: "emergency",
    },
    CmdDef {
        id: CMD_FIRE,
        name: "fire",
    },
    CmdDef {
        id: CMD_PANIC,
        name: "panic",
    },
    CmdDef {
        id: CMD_GET_ZONE_ID_MAP,
        name: "get-zone-id-map",
    },
    CmdDef {
        id: CMD_GET_ZONE_INFO,
        name: "get-zone-information",
    },
    CmdDef {
        id: CMD_GET_PANEL_STATUS,
        name: "get-panel-status",
    },
    CmdDef {
        id: CMD_GET_BYPASSED_LIST,
        name: "get-bypassed-zone-list",
    },
    CmdDef {
        id: CMD_GET_ZONE_STATUS,
        name: "get-zone-status",
    },
];

/// Server generated commands, ascending.
pub static SERVER_TX: &[CmdDef] = &[
    CmdDef {
        id: CMD_ARM_RESPONSE,
        name: "arm-response",
    },
    CmdDef {
        id: CMD_ZONE_ID_MAP_RESPONSE,
        name: "get-zone-id-map-response",
    },
    CmdDef {
        id: CMD_ZONE_INFO_RESPONSE,
        name: "get-zone-information-response",
    },
    CmdDef {
        id: CMD_ZONE_STATUS_CHANGED,
        name: "zone-status-changed",
    },
    CmdDef {
        id: CMD_PANEL_STATUS_CHANGED,
        name: "panel-status-changed",
    },
    CmdDef {
        id: CMD_PANEL_STATUS_RESPONSE,
        name: "get-panel-status-response",
    },
    CmdDef {
        id: CMD_SET_BYPASSED_LIST,
        name: "set-bypassed-zone-list",
    },
    CmdDef {
        id: CMD_BYPASS_RESPONSE,
        name: "bypass-response",
    },
    CmdDef {
        id: CMD_ZONE_STATUS_RESPONSE,
        name: "get-zone-status-response",
    },
];

/// Server definition.
pub struct ServerDef;
impl ClusterDef for ServerDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "ias-ace-server"
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

/// Build a fresh server store (revision globals only).
///
/// Requirement `07-5123-08-831-01` (MINTED-pending-confirm).
pub fn server_store() -> Result<AttrStore, Error> {
    let mut store = AttrStore::new(None);
    store.add_globals(REVISION)?;
    Ok(store)
}

/// One CIE zone-table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZoneEntry {
    /// Whether this slot holds a zone.
    pub used: bool,
    /// Zone type (0xffff = unallocated marker on the wire).
    pub zone_type: u16,
    /// Zone IEEE address (all-0xff = unallocated on the wire).
    pub ieee: [u8; 8],
    /// Zone label length.
    pub label_len: u8,
    /// Zone label bytes (UTF-8).
    pub label: [u8; MAX_ZONE_LABEL],
    /// Live ZoneStatus value.
    pub status: u16,
    /// Whether the zone is currently bypassed.
    pub bypassed: bool,
    /// Whether the bypass survives a disarm (user-programmed).
    pub permanent: bool,
}

impl ZoneEntry {
    /// Empty slot.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            used: false,
            zone_type: 0xffff,
            ieee: [0xff; 8],
            label_len: 0,
            label: [0; MAX_ZONE_LABEL],
            status: 0,
            bypassed: false,
            permanent: false,
        }
    }
}

/// Decoded Arm command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmRequest<'a> {
    /// Arm mode (`ARM_*`).
    pub mode: u8,
    /// Arm/disarm code bytes (UTF-8, possibly empty).
    pub code: &'a [u8],
    /// Target zone id (`ZONE_ID_NONE` = none programmed).
    pub zone_id: u8,
}

/// Decode an Arm body (mode + length-prefixed code + zone id).
///
/// Requirement `07-5123-08-833-01` (MINTED-pending-confirm).
pub fn decode_arm(buf: &[u8]) -> Result<ArmRequest<'_>, Error> {
    if buf.len() < 3 {
        return Err(Error::Truncated);
    }
    let len = buf[1] as usize;
    if len > MAX_CODE_LEN || buf.len() != 3 + len {
        return Err(Error::MalformedList);
    }
    Ok(ArmRequest {
        mode: buf[0],
        code: &buf[2..2 + len],
        zone_id: buf[2 + len],
    })
}

/// Encode an Arm body into `out`.
pub fn encode_arm(mode: u8, code: &[u8], zone_id: u8, out: &mut [u8]) -> Result<usize, Error> {
    if code.len() > MAX_CODE_LEN || out.len() < 3 + code.len() {
        return Err(Error::BufferTooSmall);
    }
    out[0] = mode;
    out[1] = code.len() as u8;
    out[2..2 + code.len()].copy_from_slice(code);
    out[2 + code.len()] = zone_id;
    Ok(3 + code.len())
}

/// Decoded Bypass command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BypassRequest<'a> {
    /// Zone ids to bypass.
    pub zones: &'a [u8],
    /// Arm/disarm code bytes.
    pub code: &'a [u8],
}

/// Decode a Bypass body (count + ids + length-prefixed code).
///
/// Requirement `07-5123-08-833-01` (MINTED-pending-confirm).
pub fn decode_bypass(buf: &[u8]) -> Result<BypassRequest<'_>, Error> {
    if buf.is_empty() {
        return Err(Error::Truncated);
    }
    let count = buf[0] as usize;
    if count > MAX_BYPASS_IDS || buf.len() < 1 + count + 1 {
        return Err(Error::MalformedList);
    }
    let len = buf[1 + count] as usize;
    if len > MAX_CODE_LEN || buf.len() != 2 + count + len {
        return Err(Error::MalformedList);
    }
    Ok(BypassRequest {
        zones: &buf[1..1 + count],
        code: &buf[2 + count..2 + count + len],
    })
}

/// Decoded Get Zone Status command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZoneStatusQuery {
    /// First zone id to report.
    pub start: u8,
    /// Maximum pairs to return.
    pub max: u8,
    /// Mask flag (false = return every zone).
    pub mask_flag: bool,
    /// Status mask (ANDed per zone when the flag is set).
    pub mask: u16,
}

/// Decode a Get Zone Status body (1 + 1 + 1 + 2 octets).
///
/// Requirement `07-5123-08-833-02` (MINTED-pending-confirm).
pub fn decode_zone_status_query(buf: &[u8]) -> Result<ZoneStatusQuery, Error> {
    if buf.len() != 5 {
        return Err(Error::Truncated);
    }
    let flag = match buf[2] {
        0x00 => false,
        0x01 => true,
        v => return Err(Error::InvalidValue(v)),
    };
    Ok(ZoneStatusQuery {
        start: buf[0],
        max: buf[1],
        mask_flag: flag,
        mask: u16::from_le_bytes([buf[3], buf[4]]),
    })
}

/// Encode a Get Zone Status body.
pub fn encode_zone_status_query(q: &ZoneStatusQuery, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 5 {
        return Err(Error::BufferTooSmall);
    }
    out[0] = q.start;
    out[1] = q.max;
    out[2] = u8::from(q.mask_flag);
    out[3..5].copy_from_slice(&q.mask.to_le_bytes());
    Ok(5)
}

/// Whether `code` is acceptable: UTF-8 (per the code rule) and
/// matching the configured expectation (empty expectation accepts
/// anything, including the zero-length no-code form).
///
/// Requirement `07-5123-08-832-02` (corpus-mined).
#[must_use]
pub fn code_accepted(code: &[u8], expected: &[u8]) -> bool {
    if core::str::from_utf8(code).is_err() {
        return false;
    }
    if expected.is_empty() {
        return true;
    }
    code == expected
}

/// Server behavior: panel state, zone table, bypass list, and
/// query/response fan-out.
///
/// Requirements `07-5123-08-832-01` (every arm attempt closes
/// with an arm-response verdict), `07-5123-08-832-03`
/// (mask-filtered zone-status queries), `07-5123-08-832-04`
/// (panel transitions emit panel-status-changed; disarm clears
/// non-permanent bypasses), all corpus-mined.
pub struct ServerBehavior {
    panel: u8,
    alarm: u8,
    seconds_left: u8,
    delay_target: u8,
    not_ready: bool,
    code_len: u8,
    code: [u8; MAX_CODE_LEN],
    zones: [ZoneEntry; MAX_ZONES],
}

impl Default for ServerBehavior {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBehavior {
    /// Fresh behavior: disarmed, no alarm, empty zone table, no
    /// code required.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            panel: PANEL_DISARMED,
            alarm: ALARM_NONE,
            seconds_left: 0,
            delay_target: PANEL_DISARMED,
            not_ready: false,
            code_len: 0,
            code: [0; MAX_CODE_LEN],
            zones: [ZoneEntry::empty(); MAX_ZONES],
        }
    }

    /// Current panel status.
    #[must_use]
    pub const fn panel(&self) -> u8 {
        self.panel
    }

    /// Current alarm status.
    #[must_use]
    pub const fn alarm(&self) -> u8 {
        self.alarm
    }

    /// Mark the panel not-ready (manufacturer readiness rule);
    /// arm attempts then refuse with `ARM_NOTIFY_NOT_READY`.
    pub const fn set_not_ready(&mut self, not_ready: bool) {
        self.not_ready = not_ready;
    }

    /// Install the expected arm/disarm code (empty = none
    /// required). Overlong codes are refused, never truncated.
    pub fn set_code(&mut self, code: &[u8]) -> Result<(), Error> {
        if code.len() > MAX_CODE_LEN || core::str::from_utf8(code).is_err() {
            return Err(Error::StringTooLong);
        }
        self.code[..code.len()].copy_from_slice(code);
        self.code_len = code.len() as u8;
        Ok(())
    }

    fn expected_code(&self) -> &[u8] {
        &self.code[..self.code_len as usize]
    }

    /// Enroll (or replace) a zone-table entry. `id` above the
    /// table bound is refused.
    pub fn enroll_zone(
        &mut self,
        id: u8,
        zone_type: u16,
        ieee: [u8; 8],
        label: &[u8],
        permanent_bypass: bool,
    ) -> Result<(), Error> {
        if id as usize >= MAX_ZONES {
            return Err(Error::InvalidValue(id));
        }
        if label.len() > MAX_ZONE_LABEL || core::str::from_utf8(label).is_err() {
            return Err(Error::StringTooLong);
        }
        let mut entry = ZoneEntry::empty();
        entry.used = true;
        entry.zone_type = zone_type;
        entry.ieee = ieee;
        entry.label[..label.len()].copy_from_slice(label);
        entry.label_len = label.len() as u8;
        entry.permanent = permanent_bypass;
        entry.bypassed = permanent_bypass;
        self.zones[id as usize] = entry;
        Ok(())
    }

    /// Read a zone-table entry.
    #[must_use]
    pub fn zone(&self, id: u8) -> Option<ZoneEntry> {
        if id as usize >= MAX_ZONES {
            return None;
        }
        let e = self.zones[id as usize];
        e.used.then_some(e)
    }

    /// Update a zone's live status (e.g. from its Status Change
    /// Notification relayed by the application).
    pub fn set_zone_status(&mut self, id: u8, status: u16) -> Result<(), Error> {
        if id as usize >= MAX_ZONES || !self.zones[id as usize].used {
            return Err(Error::InvalidValue(id));
        }
        self.zones[id as usize].status = status;
        Ok(())
    }

    /// Count of currently bypassed zones.
    #[must_use]
    pub fn bypassed_count(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < MAX_ZONES {
            if self.zones[i].used && self.zones[i].bypassed {
                n += 1;
            }
            i += 1;
        }
        n
    }

    fn emit_panel_changed(&self, events: &mut EventQueue, tsn: u8) {
        let mut payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
        payload[0] = self.panel;
        payload[1] = self.seconds_left;
        payload[2] = AUDIBLE_DEFAULT;
        payload[3] = self.alarm;
        events.push(AppEvent::OutboundCommand {
            cluster: CLUSTER_ID,
            cmd: CMD_PANEL_STATUS_CHANGED,
            tsn,
            len: 4,
            payload,
        });
    }

    fn emit_arm_response(&self, events: &mut EventQueue, tsn: u8, notification: u8) {
        let mut payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
        payload[0] = notification;
        events.push(AppEvent::OutboundCommand {
            cluster: CLUSTER_ID,
            cmd: CMD_ARM_RESPONSE,
            tsn,
            len: 1,
            payload,
        });
    }

    fn emit_bypassed_list(&self, events: &mut EventQueue, tsn: u8) {
        let mut payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
        let mut n = 0usize;
        let mut i = 0;
        while i < MAX_ZONES && n < MAX_BYPASS_IDS {
            if self.zones[i].used && self.zones[i].bypassed {
                payload[1 + n] = i as u8;
                n += 1;
            }
            i += 1;
        }
        payload[0] = n as u8;
        events.push(AppEvent::OutboundCommand {
            cluster: CLUSTER_ID,
            cmd: CMD_SET_BYPASSED_LIST,
            tsn,
            len: (1 + n) as u8,
            payload,
        });
    }

    fn apply_disarm(&mut self, events: &mut EventQueue, tsn: u8) {
        // Disarm clears every non-permanent bypass (832-04);
        // permanent (user-programmed) bypasses stay.
        let mut i = 0;
        while i < MAX_ZONES {
            if self.zones[i].used && self.zones[i].bypassed && !self.zones[i].permanent {
                self.zones[i].bypassed = false;
            }
            i += 1;
        }
        self.panel = PANEL_DISARMED;
        self.alarm = ALARM_NONE;
        self.seconds_left = 0;
        self.emit_panel_changed(events, tsn);
        self.emit_bypassed_list(events, tsn);
        events.push(AppEvent::StateChanged {
            cluster: CLUSTER_ID,
            from: 1,
            to: 0,
        });
    }

    fn apply_arm(&mut self, events: &mut EventQueue, tsn: u8, mode: u8) -> u8 {
        if self.not_ready {
            self.emit_arm_response(events, tsn, ARM_NOTIFY_NOT_READY);
            return ARM_NOTIFY_NOT_READY;
        }
        let (panel, notify) = match mode {
            ARM_DAY_HOME => (PANEL_ARMED_STAY, ARM_NOTIFY_DAY),
            ARM_NIGHT_SLEEP => (PANEL_ARMED_NIGHT, ARM_NOTIFY_NIGHT),
            ARM_ALL => (PANEL_ARMED_AWAY, ARM_NOTIFY_ALL),
            _ => {
                self.emit_arm_response(events, tsn, ARM_NOTIFY_NOT_READY);
                return ARM_NOTIFY_NOT_READY;
            }
        };
        self.panel = panel;
        self.emit_panel_changed(events, tsn);
        self.emit_arm_response(events, tsn, notify);
        events.push(AppEvent::StateChanged {
            cluster: CLUSTER_ID,
            from: 0,
            to: 1,
        });
        notify
    }

    fn apply_bypass(
        &mut self,
        events: &mut EventQueue,
        tsn: u8,
        req: &BypassRequest<'_>,
    ) -> Result<(), Error> {
        if !code_accepted(req.code, self.expected_code()) {
            let mut payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
            payload[0] = req.zones.len() as u8;
            let mut i = 0;
            while i < req.zones.len() {
                payload[1 + i] = BYPASS_BAD_CODE;
                i += 1;
            }
            let len = 1 + req.zones.len();
            events.push(AppEvent::OutboundCommand {
                cluster: CLUSTER_ID,
                cmd: CMD_BYPASS_RESPONSE,
                tsn,
                len: len as u8,
                payload,
            });
            return Ok(());
        }
        let mut payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
        payload[0] = req.zones.len() as u8;
        let mut i = 0;
        while i < req.zones.len() {
            let id = req.zones[i];
            payload[1 + i] = if id as usize >= MAX_ZONES {
                BYPASS_INVALID_ID
            } else if !self.zones[id as usize].used {
                BYPASS_UNKNOWN_ID
            } else {
                self.zones[id as usize].bypassed = true;
                BYPASS_OK
            };
            i += 1;
        }
        let len = 1 + req.zones.len();
        events.push(AppEvent::OutboundCommand {
            cluster: CLUSTER_ID,
            cmd: CMD_BYPASS_RESPONSE,
            tsn,
            len: len as u8,
            payload,
        });
        Ok(())
    }

    fn answer_zone_status(
        &self,
        events: &mut EventQueue,
        tsn: u8,
        q: &ZoneStatusQuery,
    ) -> Result<(), Error> {
        // Mask-flag clear returns every zone; set returns only
        // zones whose status ANDed with the mask is nonzero
        // (832-03).
        let mut payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
        let mut pairs: [(u8, u16); MAX_STATUS_PAIRS] = [(0, 0); MAX_STATUS_PAIRS];
        let mut n = 0usize;
        let mut id = q.start as usize;
        let mut complete = true;
        while id < MAX_ZONES {
            if self.zones[id].used {
                let st = self.zones[id].status;
                if !q.mask_flag || st & q.mask != 0 {
                    if n < q.max as usize && n < MAX_STATUS_PAIRS {
                        pairs[n] = (id as u8, st);
                        n += 1;
                    } else {
                        complete = false;
                        break;
                    }
                }
            }
            id += 1;
        }
        if id < MAX_ZONES {
            // Loop exited early on capacity: more zones remain.
            complete = false;
        }
        payload[0] = u8::from(complete);
        payload[1] = n as u8;
        let mut i = 0;
        while i < n {
            payload[2 + i * 3] = pairs[i].0;
            payload[3 + i * 3..5 + i * 3].copy_from_slice(&pairs[i].1.to_le_bytes());
            i += 1;
        }
        let len = 2 + n * 3;
        events.push(AppEvent::OutboundCommand {
            cluster: CLUSTER_ID,
            cmd: CMD_ZONE_STATUS_RESPONSE,
            tsn,
            len: len as u8,
            payload,
        });
        Ok(())
    }

    /// Application-side zone-status fan-out: records the zone's
    /// new status and emits the Zone Status Changed command.
    ///
    /// Requirement `07-5123-08-834-01` (MINTED-pending-confirm).
    pub fn report_zone_status(
        &mut self,
        events: &mut EventQueue,
        tsn: u8,
        id: u8,
        status: u16,
        audible: u8,
    ) -> Result<(), Error> {
        self.set_zone_status(id, status)
            .map_err(|_| Error::InvalidValue(id))?;
        let e = self.zones[id as usize];
        let mut payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
        payload[0] = id;
        payload[1..3].copy_from_slice(&status.to_le_bytes());
        payload[3] = audible;
        payload[4] = e.label_len;
        payload[5..5 + e.label_len as usize].copy_from_slice(&e.label[..e.label_len as usize]);
        let len = 5 + e.label_len as usize;
        events.push(AppEvent::OutboundCommand {
            cluster: CLUSTER_ID,
            cmd: CMD_ZONE_STATUS_CHANGED,
            tsn,
            len: len as u8,
            payload,
        });
        Ok(())
    }

    /// Enter an exit/entry delay with `seconds` on the clock and
    /// the armed (exit) or alarm (entry) state it resolves to.
    pub fn start_delay(&mut self, events: &mut EventQueue, tsn: u8, delay: u8, seconds: u8) {
        self.panel = delay;
        self.seconds_left = seconds;
        self.delay_target = if delay == PANEL_ENTRY_DELAY {
            PANEL_IN_ALARM
        } else {
            PANEL_ARMED_AWAY
        };
        self.emit_panel_changed(events, tsn);
    }
}

impl Behavior for ServerBehavior {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }

    fn handle_cluster_command(
        &mut self,
        ctx: &mut Ctx<'_>,
        header: &Header,
        command_id: u8,
        payload: &[u8],
    ) -> Result<HandleOutcome, ZclStatus> {
        match command_id {
            CMD_ARM => {
                let req = decode_arm(payload).map_err(|_| ZclStatus::MalformedCommand)?;
                if core::str::from_utf8(req.code).is_err() {
                    return Err(ZclStatus::InvalidField);
                }
                if req.mode == ARM_DISARM {
                    if self.panel == PANEL_DISARMED {
                        self.emit_arm_response(ctx.events, header.tsn, ARM_NOTIFY_ALREADY_DISARMED);
                    } else {
                        self.apply_disarm(ctx.events, header.tsn);
                        self.emit_arm_response(ctx.events, header.tsn, ARM_NOTIFY_DISARMED);
                    }
                    return Ok(HandleOutcome::no_reply());
                }
                if !matches!(req.mode, ARM_DAY_HOME | ARM_NIGHT_SLEEP | ARM_ALL) {
                    return Err(ZclStatus::InvalidField);
                }
                if !code_accepted(req.code, self.expected_code()) {
                    self.emit_arm_response(ctx.events, header.tsn, ARM_NOTIFY_BAD_CODE);
                    return Ok(HandleOutcome::no_reply());
                }
                self.apply_arm(ctx.events, header.tsn, req.mode);
                Ok(HandleOutcome::no_reply())
            }
            CMD_BYPASS => {
                let req = decode_bypass(payload).map_err(|_| ZclStatus::MalformedCommand)?;
                self.apply_bypass(ctx.events, header.tsn, &req)
                    .map_err(|_| ZclStatus::InsufficientSpace)?;
                Ok(HandleOutcome::no_reply())
            }
            CMD_EMERGENCY | CMD_FIRE | CMD_PANIC => {
                if !payload.is_empty() {
                    return Err(ZclStatus::MalformedCommand);
                }
                self.alarm = match command_id {
                    CMD_EMERGENCY => ALARM_EMERGENCY,
                    CMD_FIRE => ALARM_FIRE,
                    _ => ALARM_POLICE_PANIC,
                };
                self.panel = PANEL_IN_ALARM;
                self.seconds_left = 0;
                self.emit_panel_changed(ctx.events, header.tsn);
                ctx.events.push(AppEvent::StateChanged {
                    cluster: CLUSTER_ID,
                    from: 0,
                    to: 2,
                });
                Ok(HandleOutcome::no_reply())
            }
            CMD_GET_ZONE_ID_MAP => {
                if !payload.is_empty() {
                    return Err(ZclStatus::MalformedCommand);
                }
                let mut body = [0u8; 32];
                let mut i = 0;
                while i < MAX_ZONES {
                    if self.zones[i].used {
                        let section = i / 16;
                        let bit = i % 16;
                        let at = section * 2 + bit / 8;
                        body[at] |= 1 << (bit % 8);
                    }
                    i += 1;
                }
                let mut event_payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
                event_payload[..32].copy_from_slice(&body);
                ctx.events.push(AppEvent::OutboundCommand {
                    cluster: CLUSTER_ID,
                    cmd: CMD_ZONE_ID_MAP_RESPONSE,
                    tsn: header.tsn,
                    len: 32,
                    payload: event_payload,
                });
                Ok(HandleOutcome::no_reply())
            }
            CMD_GET_ZONE_INFO => {
                if payload.len() != 1 {
                    return Err(ZclStatus::MalformedCommand);
                }
                let id = payload[0];
                let mut body = [0u8; 12 + MAX_ZONE_LABEL];
                body[0] = id;
                let mut len = 12;
                if let Some(e) = self.zone(id) {
                    body[1..3].copy_from_slice(&e.zone_type.to_le_bytes());
                    body[3..11].copy_from_slice(&e.ieee);
                    body[11] = e.label_len;
                    body[12..12 + e.label_len as usize]
                        .copy_from_slice(&e.label[..e.label_len as usize]);
                    len = 12 + e.label_len as usize;
                } else {
                    // Unallocated marker: type 0xffff, address all-1,
                    // zero-length label (paraphrase of the rule).
                    body[1..3].copy_from_slice(&0xffffu16.to_le_bytes());
                    body[3..11].copy_from_slice(&[0xff; 8]);
                    body[11] = 0;
                }
                let mut event_payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
                event_payload[..len].copy_from_slice(&body[..len]);
                ctx.events.push(AppEvent::OutboundCommand {
                    cluster: CLUSTER_ID,
                    cmd: CMD_ZONE_INFO_RESPONSE,
                    tsn: header.tsn,
                    len: len as u8,
                    payload: event_payload,
                });
                Ok(HandleOutcome::no_reply())
            }
            CMD_GET_PANEL_STATUS => {
                if !payload.is_empty() {
                    return Err(ZclStatus::MalformedCommand);
                }
                let mut event_payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
                event_payload[0] = self.panel;
                event_payload[1] = self.seconds_left;
                event_payload[2] = AUDIBLE_DEFAULT;
                event_payload[3] = self.alarm;
                ctx.events.push(AppEvent::OutboundCommand {
                    cluster: CLUSTER_ID,
                    cmd: CMD_PANEL_STATUS_RESPONSE,
                    tsn: header.tsn,
                    len: 4,
                    payload: event_payload,
                });
                Ok(HandleOutcome::no_reply())
            }
            CMD_GET_BYPASSED_LIST => {
                if !payload.is_empty() {
                    return Err(ZclStatus::MalformedCommand);
                }
                self.emit_bypassed_list(ctx.events, header.tsn);
                Ok(HandleOutcome::no_reply())
            }
            CMD_GET_ZONE_STATUS => {
                let q =
                    decode_zone_status_query(payload).map_err(|_| ZclStatus::MalformedCommand)?;
                self.answer_zone_status(ctx.events, header.tsn, &q)
                    .map_err(|_| ZclStatus::InsufficientSpace)?;
                Ok(HandleOutcome::no_reply())
            }
            _ => Err(ZclStatus::UnsupCommand),
        }
    }
}

/// Advance exit/entry-delay timers by `elapsed_s` caller seconds;
/// expiry resolves to the armed (exit) or alarm (entry) state with
/// a panel-status-changed emission. Arming states re-emit every
/// tick while counting down.
///
/// Requirement `07-5123-08-834-01` (MINTED-pending-confirm).
pub fn tick_1s(behavior: &mut ServerBehavior, events: &mut EventQueue, tsn: u8, elapsed_s: u8) {
    if behavior.panel != PANEL_EXIT_DELAY && behavior.panel != PANEL_ENTRY_DELAY {
        return;
    }
    if elapsed_s >= behavior.seconds_left {
        behavior.seconds_left = 0;
        behavior.panel = behavior.delay_target;
        if behavior.panel == PANEL_IN_ALARM {
            behavior.alarm = ALARM_BURGLAR;
        }
        behavior.emit_panel_changed(events, tsn);
    } else {
        behavior.seconds_left -= elapsed_s;
        behavior.emit_panel_changed(events, tsn);
    }
}

/// Client-side (panel-query) command builders.
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

    /// Encode an Arm command.
    pub fn arm(
        tsn: u8,
        mode: u8,
        code: &[u8],
        zone_id: u8,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut body = [0u8; 3 + MAX_CODE_LEN];
        let n = encode_arm(mode, code, zone_id, &mut body)?;
        frame(tsn, CMD_ARM, &body[..n], out)
    }

    /// Encode a Get Zone Status command.
    pub fn get_zone_status(tsn: u8, q: &ZoneStatusQuery, out: &mut [u8]) -> Result<usize, Error> {
        let mut body = [0u8; 5];
        let n = encode_zone_status_query(q, &mut body)?;
        frame(tsn, CMD_GET_ZONE_STATUS, &body[..n], out)
    }
}
