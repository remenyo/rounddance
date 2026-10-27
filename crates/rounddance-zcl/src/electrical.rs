//! Electrical Measurement cluster (0x0B04): server definition with
//! scaled-measurement helpers.
//!
//! Paraphrase-level model of doc `07-5123-08` §4.9 (cluster +
//! formatting rule, anchors p0339-L8117-L8124, attribute sets
//! p0339-L8125-L8132, basic info p0340-L8133-L8139, DC formatting
//! p0342-L8170-L8171, multiplier/divisor prose p0342-L8172-L8195,
//! AC non-phase-specific p0343-L8196-L8197 + p0344-L8198-L8215,
//! AC formatting p0344-L8237-L8239 + p0345-L8240-L8245,
//! phase-A measurements p0346-L8262-L8263 + table rows,
//! AC formatting table p0349-L8330). All wording is paraphrase (D1).
//!
//! Requirement IDs below are repo-minted (`07-5123-08-<clause>-<seq>`,
//! dots stripped), MINTED-pending-confirm.

use crate::attrs::{access, AttrDef, AttrStore, ATTR_CLUSTER_REVISION};
use crate::cluster::{ClusterDef, ClusterRole, CmdDef};
use crate::types::{DataType, Value};
use crate::Error;

/// Cluster identifier.
///
/// Requirement `07-5123-08-491-01` (MINTED-pending-confirm).
pub const CLUSTER_ID: u16 = 0x0B04;
/// Implemented specification revision (rev table tip).
///
/// Requirement `07-5123-08-491-02` (MINTED-pending-confirm).
pub const REVISION: u16 = 2;

/// Basic information: measurement capability bitmap (map32, mandatory).
pub const ATTR_MEASUREMENT_TYPE: u16 = 0x0000;
/// AC non-phase-specific: line frequency (uint16, 0xffff = unknown).
pub const ATTR_AC_FREQUENCY: u16 = 0x0300;
/// AC non-phase-specific: net active power, signed (int24).
pub const ATTR_TOTAL_ACTIVE_POWER: u16 = 0x0304;
/// AC non-phase-specific formatting: frequency multiplier.
pub const ATTR_AC_FREQUENCY_MULTIPLIER: u16 = 0x0400;
/// AC non-phase-specific formatting: frequency divisor.
pub const ATTR_AC_FREQUENCY_DIVISOR: u16 = 0x0401;
/// AC non-phase-specific formatting: power multiplier (uint32).
pub const ATTR_POWER_MULTIPLIER: u16 = 0x0402;
/// AC non-phase-specific formatting: power divisor (uint32).
pub const ATTR_POWER_DIVISOR: u16 = 0x0403;
/// Phase A: RMS voltage (uint16, 0xffff = unknown).
pub const ATTR_RMS_VOLTAGE: u16 = 0x0505;
/// Phase A: RMS current (uint16, 0xffff = unknown).
pub const ATTR_RMS_CURRENT: u16 = 0x0508;
/// Phase A: active power, signed (int16, 0x8000 = unknown).
pub const ATTR_ACTIVE_POWER: u16 = 0x050B;
/// Phase A formatting: voltage multiplier.
pub const ATTR_AC_VOLTAGE_MULTIPLIER: u16 = 0x0600;
/// Phase A formatting: voltage divisor.
pub const ATTR_AC_VOLTAGE_DIVISOR: u16 = 0x0601;
/// Phase A formatting: current multiplier.
pub const ATTR_AC_CURRENT_MULTIPLIER: u16 = 0x0602;
/// Phase A formatting: current divisor.
pub const ATTR_AC_CURRENT_DIVISOR: u16 = 0x0603;
/// Phase A formatting: power multiplier.
pub const ATTR_AC_POWER_MULTIPLIER: u16 = 0x0604;
/// Phase A formatting: power divisor.
pub const ATTR_AC_POWER_DIVISOR: u16 = 0x0605;

/// Sentinel: unmeasurable frequency / RMS quantity.
pub const UNKNOWN_U16: u16 = 0xffff;
/// Sentinel: unmeasurable phase-A active power.
pub const UNKNOWN_I16: i16 = -0x8000;

/// Server attribute table, ascending.
///
/// Requirement `07-5123-08-492-01` (MINTED-pending-confirm).
pub static SERVER_ATTRS: &[AttrDef] = &[
    AttrDef {
        id: ATTR_MEASUREMENT_TYPE,
        datatype: DataType::Map(4).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_AC_FREQUENCY,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_TOTAL_ACTIVE_POWER,
        datatype: DataType::Int(3).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_AC_FREQUENCY_MULTIPLIER,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_AC_FREQUENCY_DIVISOR,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_POWER_MULTIPLIER,
        datatype: DataType::UInt(4).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_POWER_DIVISOR,
        datatype: DataType::UInt(4).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_RMS_VOLTAGE,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_RMS_CURRENT,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_ACTIVE_POWER,
        datatype: DataType::Int(2).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_AC_VOLTAGE_MULTIPLIER,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_AC_VOLTAGE_DIVISOR,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_AC_CURRENT_MULTIPLIER,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_AC_CURRENT_DIVISOR,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_AC_POWER_MULTIPLIER,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_AC_POWER_DIVISOR,
        datatype: DataType::UInt(2).as_u8(),
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

/// No cluster-specific commands on either side; readings travel via
/// the foundation read/report mechanism.
pub static SERVER_RX: &[CmdDef] = &[];
/// No generated cluster-specific commands.
pub static SERVER_TX: &[CmdDef] = &[];

/// Server definition.
pub struct ServerDef;
impl ClusterDef for ServerDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "electrical-server"
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

/// Build a fresh server store: unknown sentinels on the live
/// readings, unitary scale pairs, zeroed capability bitmap.
///
/// Requirements `07-5123-08-492-01/02` (MINTED-pending-confirm).
pub fn server_store() -> Result<AttrStore, Error> {
    let mut store = AttrStore::new(None);
    store.add(
        SERVER_ATTRS[0],
        Value::Map {
            width: 4,
            bytes: [0; 8],
        },
    )?;
    store.add(
        SERVER_ATTRS[1],
        Value::UInt {
            width: 2,
            v: UNKNOWN_U16 as u64,
        },
    )?;
    store.add(SERVER_ATTRS[2], Value::Int { width: 3, v: 0 })?;
    let mut i = 3;
    while i < 7 {
        let width = if SERVER_ATTRS[i].id == ATTR_POWER_MULTIPLIER
            || SERVER_ATTRS[i].id == ATTR_POWER_DIVISOR
        {
            4
        } else {
            2
        };
        store.add(SERVER_ATTRS[i], Value::UInt { width, v: 1 })?;
        i += 1;
    }
    store.add(
        SERVER_ATTRS[7],
        Value::UInt {
            width: 2,
            v: UNKNOWN_U16 as u64,
        },
    )?;
    store.add(
        SERVER_ATTRS[8],
        Value::UInt {
            width: 2,
            v: UNKNOWN_U16 as u64,
        },
    )?;
    store.add(
        SERVER_ATTRS[9],
        Value::Int {
            width: 2,
            v: UNKNOWN_I16 as i64,
        },
    )?;
    let mut j = 10;
    while j < 16 {
        store.add(SERVER_ATTRS[j], Value::UInt { width: 2, v: 1 })?;
        j += 1;
    }
    store.add_globals(REVISION)?;
    Ok(store)
}

/// Apply an unsigned multiplier/divisor pair, saturating. A zero
/// divisor (or a zero multiplier/divisor pair meaning "absent") is
/// treated as unitary so raw values pass through instead of trapping.
///
/// Requirement `07-5123-08-492-02` (MINTED-pending-confirm): when a
/// multiplier or divisor is present its counterpart is implemented
/// too, and the pair scales the raw measurement into the stated
/// unit. `0x0000` is never a legal scale value, so it is folded to
/// the unitary factor here.
#[must_use]
pub fn scaled_u64(raw: u64, multiplier: u64, divisor: u64) -> u64 {
    let mult = if multiplier == 0 { 1 } else { multiplier };
    let div = if divisor == 0 { 1 } else { divisor };
    raw.saturating_mul(mult) / div
}

/// Apply a signed multiplier/divisor pair, saturating.
#[must_use]
pub fn scaled_i64(raw: i64, multiplier: u64, divisor: u64) -> i64 {
    let mult = if multiplier == 0 {
        1
    } else {
        multiplier as i64
    };
    let div = if divisor == 0 { 1 } else { divisor as i64 };
    raw.saturating_mul(mult) / div
}

/// Read a `uint16` scale factor; missing or zero means unitary.
fn get_mult(store: &AttrStore, attr: u16) -> u64 {
    match store.get(attr) {
        Some(Value::UInt { v, .. }) => v,
        _ => 1,
    }
}

/// Scaled RMS voltage in the configured unit, or `None` when the
/// raw reading is the unknown sentinel.
pub fn scaled_rms_voltage(store: &AttrStore) -> Option<u64> {
    match store.get(ATTR_RMS_VOLTAGE) {
        Some(Value::UInt { v, .. }) if v != UNKNOWN_U16 as u64 => Some(scaled_u64(
            v,
            get_mult(store, ATTR_AC_VOLTAGE_MULTIPLIER),
            get_mult(store, ATTR_AC_VOLTAGE_DIVISOR),
        )),
        _ => None,
    }
}

/// Scaled RMS current in the configured unit, or `None` when unknown.
pub fn scaled_rms_current(store: &AttrStore) -> Option<u64> {
    match store.get(ATTR_RMS_CURRENT) {
        Some(Value::UInt { v, .. }) if v != UNKNOWN_U16 as u64 => Some(scaled_u64(
            v,
            get_mult(store, ATTR_AC_CURRENT_MULTIPLIER),
            get_mult(store, ATTR_AC_CURRENT_DIVISOR),
        )),
        _ => None,
    }
}

/// Scaled phase-A active power, or `None` when the raw reading is
/// the unknown sentinel. Sign convention: positive means delivered
/// to the premises, negative means received from it.
///
/// Requirement `07-5123-08-492-03` (MINTED-pending-confirm).
pub fn scaled_active_power(store: &AttrStore) -> Option<i64> {
    match store.get(ATTR_ACTIVE_POWER) {
        Some(Value::Int { v, .. }) if v != UNKNOWN_I16 as i64 => Some(scaled_i64(
            v,
            get_mult(store, ATTR_AC_POWER_MULTIPLIER),
            get_mult(store, ATTR_AC_POWER_DIVISOR),
        )),
        _ => None,
    }
}
