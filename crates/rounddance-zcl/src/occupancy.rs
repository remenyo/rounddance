//! Occupancy Sensing cluster (0x0406): server definition and
//! motion-driven behavior.
//!
//! Paraphrase-level model of doc `07-5123-08` §4.8 (cluster Table
//! 4-3 anchor p0317-L7650-L7652, sensor set Table 4-21 anchor
//! p0335-L8028-L8030, Occupancy bit anchor p0335-L8031-L8033, type
//! Table 4-22 anchor p0335-L8035-L8038, bitmap Table 4-23 anchor
//! p0335-L8039-L8042, alignment Table 4-24 anchor
//! p0336-L8043-L8046, PIR set Table 4-25 anchor p0336-L8047-L8049 +
//! delay prose p0336-L8050-L8055, ultrasonic set Table 4-26 anchor
//! p0337-L8062-L8064, contact set Table 4-27 anchor
//! p0337-L8078-L8081) and of doc `15-0014-05` §13 (occupancy sensor
//! device anchors p0053-L735-L749, required attributes
//! p0054-L750-L754). All wording here is paraphrase (D1).
//!
//! Requirement IDs below are repo-minted (`07-5123-08-48-<seq>` and
//! `15-0014-05-13-<seq>`, dots stripped), MINTED-pending-confirm.

use crate::attrs::{access, AttrDef, AttrStore, ATTR_CLUSTER_REVISION};
use crate::behavior::{AppEvent, Behavior, Ctx, HandleOutcome};
use crate::cluster::{ClusterDef, ClusterRole, CmdDef};
use crate::frame::Header;
use crate::types::{DataType, Value};
use crate::{Error, ZclStatus};

/// Cluster identifier.
///
/// Requirement `07-5123-08-48-01` (MINTED-pending-confirm).
pub const CLUSTER_ID: u16 = 0x0406;
/// Implemented revision for the attribute set modeled here.
///
/// Requirement `07-5123-08-48-02` (MINTED-pending-confirm).
pub const REVISION: u16 = 1;

/// Occupancy flags (bit 0 = occupied, all other bits reserved).
pub const ATTR_OCCUPANCY: u16 = 0x0000;
/// Sensor technology selector (PIR / ultrasonic / both / contact).
pub const ATTR_SENSOR_TYPE: u16 = 0x0001;
/// Implemented-technology bitmap (bit 0 PIR, bit 1 ultrasonic,
/// bit 2 physical contact).
pub const ATTR_SENSOR_BITMAP: u16 = 0x0002;
/// PIR hold time after last motion, seconds (occupied to clear).
pub const ATTR_PIR_OCC_TO_UNOCC_DELAY: u16 = 0x0010;
/// PIR settle time before reporting occupied, seconds.
pub const ATTR_PIR_UNOCC_TO_OCC_DELAY: u16 = 0x0011;
/// Motion sightings required inside the settle window.
pub const ATTR_PIR_UNOCC_TO_OCC_THRESHOLD: u16 = 0x0012;
/// Ultrasonic hold time after last motion, seconds.
pub const ATTR_US_OCC_TO_UNOCC_DELAY: u16 = 0x0020;
/// Ultrasonic settle time before reporting occupied, seconds.
pub const ATTR_US_UNOCC_TO_OCC_DELAY: u16 = 0x0021;
/// Motion sightings required inside the ultrasonic settle window.
pub const ATTR_US_UNOCC_TO_OCC_THRESHOLD: u16 = 0x0022;
/// Contact hold time after release, seconds.
pub const ATTR_CONTACT_OCC_TO_UNOCC_DELAY: u16 = 0x0030;
/// Contact settle time before reporting occupied, seconds.
pub const ATTR_CONTACT_UNOCC_TO_OCC_DELAY: u16 = 0x0031;
/// Events required inside the contact settle window.
pub const ATTR_CONTACT_UNOCC_TO_OCC_THRESHOLD: u16 = 0x0032;

/// Occupied flag position inside [`ATTR_OCCUPANCY`].
pub const OCCUPIED_BIT: u8 = 0x01;

/// Sensor type: passive infrared.
pub const SENSOR_PIR: u8 = 0x00;
/// Sensor type: ultrasonic.
pub const SENSOR_ULTRASONIC: u8 = 0x01;
/// Sensor type: PIR plus ultrasonic.
pub const SENSOR_PIR_AND_US: u8 = 0x02;
/// Sensor type: physical contact.
pub const SENSOR_CONTACT: u8 = 0x03;

/// Bitmap bit: PIR implemented.
pub const BITMAP_PIR: u8 = 0x01;
/// Bitmap bit: ultrasonic implemented.
pub const BITMAP_ULTRASONIC: u8 = 0x02;
/// Bitmap bit: physical contact implemented.
pub const BITMAP_CONTACT: u8 = 0x04;

/// Server attribute table, ascending.
///
/// Requirement `07-5123-08-48-03` (MINTED-pending-confirm);
/// occupancy-sensor device rows per `15-0014-05-13-01`.
pub static SERVER_ATTRS: &[AttrDef] = &[
    AttrDef {
        id: ATTR_OCCUPANCY,
        datatype: DataType::Map(1).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_SENSOR_TYPE,
        datatype: DataType::Enum8.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_SENSOR_BITMAP,
        datatype: DataType::Map(1).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_PIR_OCC_TO_UNOCC_DELAY,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_PIR_UNOCC_TO_OCC_DELAY,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_PIR_UNOCC_TO_OCC_THRESHOLD,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_US_OCC_TO_UNOCC_DELAY,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_US_UNOCC_TO_OCC_DELAY,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_US_UNOCC_TO_OCC_THRESHOLD,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_CONTACT_OCC_TO_UNOCC_DELAY,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_CONTACT_UNOCC_TO_OCC_DELAY,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_CONTACT_UNOCC_TO_OCC_THRESHOLD,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_CLUSTER_REVISION,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ,
        reportable: false,
    },
];

/// Server definition (the cluster carries no cluster-specific
/// commands; occupancy travels in attribute reports).
pub struct ServerDef;
impl ClusterDef for ServerDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "occupancy-server"
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
        &[]
    }
    fn generated_commands(&self) -> &'static [CmdDef] {
        &[]
    }
}

/// Whether the occupancy flags report an occupied space.
#[must_use]
pub const fn is_occupied(flags: u8) -> bool {
    flags & OCCUPIED_BIT != 0
}

/// Whether a sensor-type value names a defined technology.
#[must_use]
pub const fn sensor_type_known(sensor_type: u8) -> bool {
    matches!(
        sensor_type,
        SENSOR_PIR | SENSOR_ULTRASONIC | SENSOR_PIR_AND_US | SENSOR_CONTACT
    )
}

/// Whether the type selector and the implementation bitmap agree
/// (the seven admissible pairs of the alignment table).
///
/// Requirement `07-5123-08-48-04` (MINTED-pending-confirm).
#[must_use]
pub const fn type_bitmap_aligned(sensor_type: u8, bitmap: u8) -> bool {
    // Low three bitmap bits select implemented technologies; the
    // table fixes which selector goes with each combination.
    let bits = bitmap & 0x07;
    match sensor_type {
        SENSOR_PIR => bits == 0x01 || bits == 0x05,
        SENSOR_ULTRASONIC => bits == 0x02 || bits == 0x06,
        SENSOR_PIR_AND_US => bits == 0x03 || bits == 0x07,
        // Contact-only has no dedicated selector value; contact
        // always rides along with one of the three above.
        SENSOR_CONTACT => bits == 0x04,
        _ => false,
    }
}

/// Current occupancy flags held in a server store.
#[must_use]
pub fn occupancy_of(store: &AttrStore) -> u8 {
    match store.get(ATTR_OCCUPANCY) {
        Some(Value::Map { bytes, .. }) => bytes[0],
        _ => 0,
    }
}

/// Build a fresh server store with table defaults.
pub fn server_store() -> Result<AttrStore, Error> {
    let mut store = AttrStore::new(None);
    store.add(
        SERVER_ATTRS[0],
        Value::Map {
            width: 1,
            bytes: [0; 8],
        },
    )?;
    store.add(SERVER_ATTRS[1], Value::Enum8(SENSOR_PIR))?;
    store.add(
        SERVER_ATTRS[2],
        Value::Map {
            width: 1,
            bytes: [BITMAP_PIR, 0, 0, 0, 0, 0, 0, 0],
        },
    )?;
    let mut i = 3;
    while i < SERVER_ATTRS.len() - 1 {
        let width = if SERVER_ATTRS[i].id & 0x00ff == 0x0012
            || SERVER_ATTRS[i].id & 0x00ff == 0x0022
            || SERVER_ATTRS[i].id & 0x00ff == 0x0032
        {
            1
        } else {
            2
        };
        let v = if width == 1 { 1 } else { 0 };
        store.add(SERVER_ATTRS[i], Value::UInt { width, v })?;
        i += 1;
    }
    store.add_globals(REVISION)?;
    Ok(store)
}

/// Server behavior: motion sightings drive the occupied flag; the
/// configured hold time clears it again via [`tick_s`].
///
/// Requirement `07-5123-08-48-05` (MINTED-pending-confirm).
pub struct ServerBehavior {
    hold_s: u32,
}

impl Default for ServerBehavior {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBehavior {
    /// Idle behavior (space reads clear until motion arrives).
    #[must_use]
    pub const fn new() -> Self {
        Self { hold_s: 0 }
    }

    fn emit(store: &mut AttrStore, events: &mut crate::behavior::EventQueue, flags: u8) {
        let mut bytes = [0u8; 8];
        bytes[0] = flags & OCCUPIED_BIT;
        let _ = store.set_local(ATTR_OCCUPANCY, Value::Map { width: 1, bytes });
        events.push(AppEvent::AttributeChanged {
            cluster: CLUSTER_ID,
            attr: ATTR_OCCUPANCY,
        });
    }

    fn hold_config(store: &AttrStore) -> u32 {
        match store.get(ATTR_PIR_OCC_TO_UNOCC_DELAY) {
            Some(Value::UInt { v, .. }) => v.min(0xfffe) as u32,
            _ => 0,
        }
    }

    /// Record one motion sighting: the space reads occupied and the
    /// hold timer reloads from the PIR hold attribute.
    pub fn motion_detected(&mut self, ctx: &mut Ctx<'_>) {
        self.hold_s = Self::hold_config(ctx.store);
        Self::emit(ctx.store, ctx.events, OCCUPIED_BIT);
    }

    /// Advance the hold timer by `dt_s` caller seconds; expiry
    /// clears the occupied flag.
    pub fn tick_s(&mut self, ctx: &mut Ctx<'_>, dt_s: u32) {
        if !is_occupied(occupancy_of(ctx.store)) || self.hold_s == 0 {
            return;
        }
        if dt_s >= self.hold_s {
            self.hold_s = 0;
            Self::emit(ctx.store, ctx.events, 0);
        } else {
            self.hold_s -= dt_s;
        }
    }
}

impl Behavior for ServerBehavior {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }

    fn handle_cluster_command(
        &mut self,
        _ctx: &mut Ctx<'_>,
        _header: &Header,
        _command_id: u8,
        _payload: &[u8],
    ) -> Result<HandleOutcome, ZclStatus> {
        // No cluster-specific commands exist on this cluster.
        Err(ZclStatus::UnsupCommand)
    }
}
