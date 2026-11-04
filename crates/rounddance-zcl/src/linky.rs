//! Linky Metering extension (cluster 0x0702, Linky-specific
//! rows): attribute table, mode/disconnect codecs, and day-maximum
//! demand tracking.
//!
//! Paraphrase-level model of doc `17-05019-012` §10.4.2.2 (status
//! set anchors p0019-L316-L376, disconnect-reason anchor
//! p0023-L463-L467, Linky-mode anchor p0023-L468-L470, SiteID
//! anchor p0027-L596-L601, serial-number anchor p0027-L602-L604,
//! formatting anchor p0024-L556-L561, current-meter-id anchor
//! p0025-L452-L453, day-maximum anchors p0025-L862-L872,
//! period-count anchor p0026-L904, reactive-energy anchors
//! p0028-L1280-L1289, plus the attribute-row lines for 0x0206,
//! 0x0307, 0x0308, 0x030E, 0x045D, 0x045E, 0x0500, and
//! 0x0D05–0x0D08). This module extends (not replaces) the generic
//! metering model in `metering`; `CLUSTER_ID` is shared.
//! All wording here is paraphrase (D1).
//!
//! Requirement IDs below are repo-minted
//! (`17-05019-012-104-<seq>`, dots stripped),
//! MINTED-pending-confirm.

use crate::attrs::{access, AttrDef};
use crate::types::DataType;
use crate::{Error, ZclStatus};

/// Shared metering cluster identifier (see `metering`).
pub const CLUSTER_ID: u16 = crate::metering::CLUSTER_ID;

/// Meter status flags.
pub const ATTR_STATUS: u16 = 0x0200;
/// Extended meter status flags (64-bit).
pub const ATTR_EXTENDED_STATUS: u16 = 0x0204;
/// Current meter identifier string.
pub const ATTR_CURRENT_METER_ID: u16 = 0x0206;
/// Why the supply is disconnected (enumeration).
pub const ATTR_DISCONNECT_REASON: u16 = 0x0208;
/// Simple/advanced operating mode flags (Linky).
pub const ATTR_LINKY_MODE: u16 = 0x0209;
/// Active register tier for delivered energy.
pub const ATTR_ACTIVE_TIER_DELIVERED: u16 = 0x0020;
/// Tier count in use (0 = blocks only, 1..=48 = tiers).
pub const ATTR_TIERS_IN_USE: u16 = 0x0023;
/// Meter point location string.
pub const ATTR_SITE_ID: u16 = 0x0307;
/// Meter serial-number string.
pub const ATTR_METER_SERIAL: u16 = 0x0308;
/// Communication-module serial-number string.
pub const ATTR_MODULE_SERIAL: u16 = 0x030e;
/// Current-day maximum delivered demand.
pub const ATTR_DAY_MAX_DELIVERED: u16 = 0x045d;
/// Time of the current-day maximum delivered demand.
pub const ATTR_DAY_MAX_DELIVERED_TIME: u16 = 0x045e;
/// Current-day maximum received demand.
pub const ATTR_DAY_MAX_RECEIVED: u16 = 0x045f;
/// Time of the current-day maximum received demand.
pub const ATTR_DAY_MAX_RECEIVED_TIME: u16 = 0x0460;
/// Previous-day maximum delivered demand.
pub const ATTR_PREV_DAY_MAX_DELIVERED: u16 = 0x0461;
/// Time of the previous-day maximum delivered demand.
pub const ATTR_PREV_DAY_MAX_DELIVERED_TIME: u16 = 0x0462;
/// Previous-day maximum received demand.
pub const ATTR_PREV_DAY_MAX_RECEIVED: u16 = 0x0463;
/// Time of the previous-day maximum received demand.
pub const ATTR_PREV_DAY_MAX_RECEIVED_TIME: u16 = 0x0464;
/// Interval backlog depth behind profile replies.
pub const ATTR_MAX_PERIODS_DELIVERED: u16 = 0x0500;
/// Reactive-energy summation, quadrant 1.
pub const ATTR_REACTIVE_Q1: u16 = 0x0d05;
/// Reactive-energy summation, quadrant 2.
pub const ATTR_REACTIVE_Q2: u16 = 0x0d06;
/// Reactive-energy summation, quadrant 3.
pub const ATTR_REACTIVE_Q3: u16 = 0x0d07;
/// Reactive-energy summation, quadrant 4.
pub const ATTR_REACTIVE_Q4: u16 = 0x0d08;

/// Longest meter-identifier body (octets).
pub const MAX_METER_ID: usize = 32;
/// Longest site-identifier body (octets).
pub const MAX_SITE_ID: usize = 33;
/// Longest serial-number body (octets).
pub const MAX_SERIAL: usize = 25;
/// Highest tier count admitted (blocks-only 0 through 48 tiers).
pub const MAX_TIERS: u8 = 48;

/// Linky mode: advanced-operation flag (bit 0 set).
pub const MODE_ADVANCED_BIT: u8 = 0x01;

/// Whether the mode octet selects advanced operation.
#[must_use]
pub const fn mode_is_advanced(mode: u8) -> bool {
    mode & MODE_ADVANCED_BIT != 0
}

/// Whether the mode octet is well-formed (reserved bits clear).
///
/// Requirement `17-05019-012-104-01` (MINTED-pending-confirm).
#[must_use]
pub const fn mode_well_formed(mode: u8) -> bool {
    mode & !MODE_ADVANCED_BIT == 0
}

/// Disconnect reason: supply connected (normal operation).
pub const DISCONNECT_NONE: u8 = 0x00;
/// Disconnect reason: over-power trip.
pub const DISCONNECT_OVER_POWER: u8 = 0x01;
/// Disconnect reason: over-voltage trip.
pub const DISCONNECT_OVER_VOLTAGE: u8 = 0x02;
/// Disconnect reason: remote load-control curtailment.
pub const DISCONNECT_LOAD_CONTROL: u8 = 0x03;
/// Disconnect reason: other remote command.
pub const DISCONNECT_REMOTE: u8 = 0x04;
/// Disconnect reason: thermal trip above rated current.
pub const DISCONNECT_OVERHEAT: u8 = 0x05;

/// Whether a disconnect reason names a defined cause.
#[must_use]
pub const fn disconnect_reason_known(reason: u8) -> bool {
    matches!(
        reason,
        DISCONNECT_NONE
            | DISCONNECT_OVER_POWER
            | DISCONNECT_OVER_VOLTAGE
            | DISCONNECT_LOAD_CONTROL
            | DISCONNECT_REMOTE
            | DISCONNECT_OVERHEAT
    )
}

/// Whether a tier count is admissible (blocks-only or 1..=48).
#[must_use]
pub const fn tiers_in_use_valid(count: u8) -> bool {
    count <= MAX_TIERS
}

/// Linky extension attribute table, ascending. Complements (never
/// repeats) the generic `metering::SERVER_ATTRS` rows.
///
/// Requirement `17-05019-012-104-02` (MINTED-pending-confirm).
pub static LINKY_ATTRS: &[AttrDef] = &[
    AttrDef {
        id: ATTR_ACTIVE_TIER_DELIVERED,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_TIERS_IN_USE,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_STATUS,
        datatype: DataType::Map(1).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_EXTENDED_STATUS,
        datatype: DataType::Map(8).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_CURRENT_METER_ID,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_DISCONNECT_REASON,
        datatype: DataType::Enum8.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_LINKY_MODE,
        datatype: DataType::Map(1).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_SITE_ID,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_METER_SERIAL,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_MODULE_SERIAL,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_DAY_MAX_DELIVERED,
        datatype: DataType::UInt(6).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_DAY_MAX_DELIVERED_TIME,
        datatype: DataType::Time(0xe2).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_DAY_MAX_RECEIVED,
        datatype: DataType::UInt(6).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_DAY_MAX_RECEIVED_TIME,
        datatype: DataType::Time(0xe2).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_PREV_DAY_MAX_DELIVERED,
        datatype: DataType::UInt(6).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_PREV_DAY_MAX_DELIVERED_TIME,
        datatype: DataType::Time(0xe2).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_PREV_DAY_MAX_RECEIVED,
        datatype: DataType::UInt(6).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_PREV_DAY_MAX_RECEIVED_TIME,
        datatype: DataType::Time(0xe2).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_MAX_PERIODS_DELIVERED,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_REACTIVE_Q1,
        datatype: DataType::UInt(6).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_REACTIVE_Q2,
        datatype: DataType::UInt(6).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_REACTIVE_Q3,
        datatype: DataType::UInt(6).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_REACTIVE_Q4,
        datatype: DataType::UInt(6).as_u8(),
        access: access::READ,
        reportable: false,
    },
];

/// Look up a Linky extension row by identifier.
#[must_use]
pub fn attr_def(id: u16) -> Option<AttrDef> {
    LINKY_ATTRS.iter().find(|a| a.id == id).copied()
}

/// One day-maximum record: the largest demand seen plus the moment
/// it was seen (caller seconds, UTC).
///
/// Requirement `17-05019-012-104-03` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DayMax {
    /// Largest demand observed this window.
    pub value: u64,
    /// Moment the largest demand was observed.
    pub at_utc: u32,
    /// Whether any observation has been filed yet.
    pub valid: bool,
}

impl DayMax {
    /// Empty record (no observation yet).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            value: 0,
            at_utc: 0,
            valid: false,
        }
    }

    /// File one demand observation; a strictly larger value
    /// replaces the record (ties keep the earlier moment).
    pub const fn observe(&mut self, demand: u64, at_utc: u32) {
        if !self.valid || demand > self.value {
            self.value = demand;
            self.at_utc = at_utc;
            self.valid = true;
        }
    }

    /// Clear the record at a day boundary.
    pub const fn reset(&mut self) {
        self.value = 0;
        self.at_utc = 0;
        self.valid = false;
    }
}

impl Default for DayMax {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a Linky mode octet (advanced flag plus reserved-zero
/// bits) — reserved bits are always written clear.
pub fn encode_linky_mode(advanced: bool, out: &mut [u8]) -> Result<usize, Error> {
    if out.is_empty() {
        return Err(Error::BufferTooSmall);
    }
    out[0] = if advanced { MODE_ADVANCED_BIT } else { 0 };
    Ok(1)
}

/// Decode a Linky mode octet: exactly one octet, reserved bits must
/// read clear.
pub fn decode_linky_mode(buf: &[u8]) -> Result<bool, Error> {
    if buf.len() != 1 {
        return Err(Error::Truncated);
    }
    if !mode_well_formed(buf[0]) {
        return Err(Error::InvalidValue(buf[0]));
    }
    Ok(mode_is_advanced(buf[0]))
}

/// Decode a disconnect-reason octet into its status mapping.
pub fn decode_disconnect_reason(buf: &[u8]) -> Result<u8, ZclStatus> {
    if buf.len() != 1 {
        return Err(ZclStatus::MalformedCommand);
    }
    if !disconnect_reason_known(buf[0]) {
        return Err(ZclStatus::InvalidField);
    }
    Ok(buf[0])
}
