//! Aliro Reader bridge (local model): advertisement feature
//! flags, notification/event codecs, operation-source handling, and
//! a reader-state behavior.
//!
//! Paraphrase-level model of doc `26-42802-001` (advertisement
//! payload Table 11-2 anchor p0108-L12-L33 + flow-bit anchors
//! p0108-L43 + p0109-L43-L47, notification anchors
//! p0109-L15-L24, event attribute Table 11-15 anchors
//! p0125-L18-L27, general-error Table 11-16 anchors
//! p0125-L30-L42, status Table 11-14 anchors p0122-L40-L45,
//! status-changed Table 11-19 anchors p0127-L36-L45,
//! operation-source Table 11-20 anchor p0128-L15-L48,
//! protocol-completed Table 11-21 anchor p0129-L12-L14,
//! capability Table 11-22 anchors p0129-L21-L40).
//! All wording here is paraphrase (D1).
//!
//! This cluster identifier is locally administered for the bridge
//! and is NOT a CSA-assigned ZCL cluster number: Aliro itself runs
//! over its own transports, and this module only carries the
//! reader-side state/events in ZCL idioms so gateways can expose
//! them through the attribute/command machinery.
//!
//! Requirement IDs below are repo-minted
//! (`26-42802-001-11-<seq>`, dots stripped),
//! MINTED-pending-confirm.

use crate::attrs::{access, AttrDef, AttrStore, ATTR_CLUSTER_REVISION};
use crate::behavior::{AppEvent, Behavior, Ctx, HandleOutcome};
use crate::cluster::{ClusterDef, ClusterRole, CmdDef};
use crate::frame::Header;
use crate::types::{DataType, Value};
use crate::{Error, ZclStatus};

/// Locally-administered bridge cluster identifier (NOT assigned).
///
/// Requirement `26-42802-001-11-01` (MINTED-pending-confirm).
pub const CLUSTER_ID: u16 = 0xfc00;
/// Implemented model revision.
pub const REVISION: u16 = 1;

/// Advertisement feature flags (BLE+UWB flow + BLE-only flow).
pub const ATTR_ADV_FEATURES: u16 = 0x0000;
/// Reader notification class (no-error / error / low-battery / touch).
pub const ATTR_NOTIFICATION: u16 = 0x0001;
/// Advertisement format version carried by the reader.
pub const ATTR_ADV_VERSION: u16 = 0x0002;
/// Cause behind the latest state change.
pub const ATTR_OPERATION_SOURCE: u16 = 0x0003;
/// Latest request verdict (accept / reject).
pub const ATTR_READER_STATUS: u16 = 0x0004;

/// Feature bit: BLE + UWB flow supported.
pub const FEATURE_BLE_UWB: u8 = 0x80;
/// Feature bit: BLE-only flow supported.
pub const FEATURE_BLE_ONLY: u8 = 0x40;
/// Mask of the advertisement-version field.
pub const ADV_VERSION_MASK: u8 = 0x07;
/// Mask of the notification field.
pub const NOTIFICATION_MASK: u8 = 0x18;
/// Shift of the notification field.
pub const NOTIFICATION_SHIFT: u8 = 3;

/// Notification: reader nominal.
pub const NOTIFY_NO_ERROR: u8 = 0x00;
/// Notification: unspecified reader fault.
pub const NOTIFY_UNKNOWN_ERROR: u8 = 0x01;
/// Notification: reader battery low.
pub const NOTIFY_LOW_BATTERY: u8 = 0x02;
/// Notification: physical interaction sensed.
pub const NOTIFY_SENSOR_TRIGGERED: u8 = 0x03;

/// Whether a notification value names a defined class.
#[must_use]
pub const fn notification_known(notification: u8) -> bool {
    matches!(
        notification,
        NOTIFY_NO_ERROR | NOTIFY_UNKNOWN_ERROR | NOTIFY_LOW_BATTERY | NOTIFY_SENSOR_TRIGGERED
    )
}

/// Operation source: unspecified.
pub const SOURCE_UNSPECIFIED: u8 = 0;
/// Operation source: manual behavior at the reader.
pub const SOURCE_MANUAL: u8 = 1;
/// Operation source: reader automation.
pub const SOURCE_AUTO: u8 = 2;
/// Operation source: reader schedule.
pub const SOURCE_SCHEDULE: u8 = 3;
/// Operation source: user device over BLE + UWB.
pub const SOURCE_BLE_UWB_DEVICE: u8 = 4;
/// Operation source: user device over NFC.
pub const SOURCE_NFC_DEVICE: u8 = 5;
/// Operation source: user device over BLE-only flow.
pub const SOURCE_BLE_ONLY_DEVICE: u8 = 6;
/// Operation source: companion ecosystem.
pub const SOURCE_MATTER: u8 = 7;

/// Whether an operation source names a defined origin.
#[must_use]
pub const fn source_known(source: u8) -> bool {
    source <= SOURCE_MATTER
}

/// Request verdict: accepted.
pub const STATUS_ACCEPT: u8 = 0x00;
/// Request verdict: rejected.
pub const STATUS_REJECT: u8 = 0x01;

/// Whether a request verdict names a defined outcome.
#[must_use]
pub const fn status_known(status: u8) -> bool {
    matches!(status, STATUS_ACCEPT | STATUS_REJECT)
}

/// Event attribute: reader busy marker (empty body).
pub const EVENT_ATTR_BUSY: u8 = 0;
/// Event attribute: general error with a reason octet.
pub const EVENT_ATTR_GENERAL_ERROR: u8 = 1;
/// Event attribute: opaque reader-descriptor blob.
pub const EVENT_ATTR_READER_DESCRIPTOR: u8 = 2;

/// Error reason: no further detail.
pub const ERROR_UNKNOWN: u8 = 0;
/// Error reason: reader resources exhausted.
pub const ERROR_RESOURCE_UNAVAILABLE: u8 = 1;
/// Error reason: unsupported message or shape.
pub const ERROR_WRONG_PARAMETERS: u8 = 2;
/// Error reason: session key for the ranging session missing.
pub const ERROR_URSK_UNAVAILABLE: u8 = 3;

/// Largest reader-descriptor blob carried here.
pub const MAX_DESCRIPTOR: usize = 32;

/// Whether an error reason names a defined cause.
#[must_use]
pub const fn error_reason_known(reason: u8) -> bool {
    matches!(
        reason,
        ERROR_UNKNOWN
            | ERROR_RESOURCE_UNAVAILABLE
            | ERROR_WRONG_PARAMETERS
            | ERROR_URSK_UNAVAILABLE
    )
}

/// Pack advertisement feature octet: flow bits plus notification
/// class plus advertisement version.
pub fn encode_adv_features(
    ble_uwb: bool,
    ble_only: bool,
    notification: u8,
    version: u8,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.is_empty() {
        return Err(Error::BufferTooSmall);
    }
    if !notification_known(notification) {
        return Err(Error::InvalidValue(notification));
    }
    if version & !ADV_VERSION_MASK != 0 {
        return Err(Error::InvalidValue(version));
    }
    let mut flags = (notification << NOTIFICATION_SHIFT) & NOTIFICATION_MASK;
    flags |= version & ADV_VERSION_MASK;
    if ble_uwb {
        flags |= FEATURE_BLE_UWB;
    }
    if ble_only {
        flags |= FEATURE_BLE_ONLY;
    }
    out[0] = flags;
    Ok(1)
}

/// Unpack an advertisement feature octet into (ble_uwb, ble_only,
/// notification, version). The field masks admit only defined
/// notification classes, so every octet unpacks.
#[must_use]
pub const fn decode_adv_features(flags: u8) -> (bool, bool, u8, u8) {
    let notification = (flags & NOTIFICATION_MASK) >> NOTIFICATION_SHIFT;
    (
        flags & FEATURE_BLE_UWB != 0,
        flags & FEATURE_BLE_ONLY != 0,
        notification,
        flags & ADV_VERSION_MASK,
    )
}

/// One decoded event attribute (busy / general-error /
/// reader-descriptor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventAttr {
    /// Attribute selector.
    pub id: u8,
    /// Reason octet (general-error only).
    pub reason: u8,
    /// Descriptor length (reader-descriptor only).
    pub len: u8,
    /// Descriptor body (reader-descriptor only).
    pub descriptor: [u8; MAX_DESCRIPTOR],
}

/// Encode one event attribute body (id + length + value).
pub fn encode_event_attr(attr: &EventAttr, out: &mut [u8]) -> Result<usize, Error> {
    let need = match attr.id {
        EVENT_ATTR_BUSY => 2,
        EVENT_ATTR_GENERAL_ERROR => 3,
        EVENT_ATTR_READER_DESCRIPTOR => 2 + attr.len as usize,
        other => return Err(Error::InvalidValue(other)),
    };
    if attr.len as usize > MAX_DESCRIPTOR {
        return Err(Error::InvalidValue(attr.len));
    }
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    out[0] = attr.id;
    match attr.id {
        EVENT_ATTR_BUSY => {
            out[1] = 0;
        }
        EVENT_ATTR_GENERAL_ERROR => {
            if !error_reason_known(attr.reason) {
                return Err(Error::InvalidValue(attr.reason));
            }
            out[1] = 1;
            out[2] = attr.reason;
        }
        _ => {
            out[1] = attr.len;
            out[2..2 + attr.len as usize].copy_from_slice(&attr.descriptor[..attr.len as usize]);
        }
    }
    Ok(need)
}

/// Decode one event attribute body.
pub fn decode_event_attr(buf: &[u8]) -> Result<EventAttr, Error> {
    if buf.len() < 2 {
        return Err(Error::Truncated);
    }
    match buf[0] {
        EVENT_ATTR_BUSY => {
            if buf[1] != 0 || buf.len() != 2 {
                return Err(Error::InvalidValue(buf[1]));
            }
            Ok(EventAttr {
                id: buf[0],
                reason: 0,
                len: 0,
                descriptor: [0; MAX_DESCRIPTOR],
            })
        }
        EVENT_ATTR_GENERAL_ERROR => {
            if buf[1] != 1 || buf.len() != 3 {
                return Err(Error::Truncated);
            }
            if !error_reason_known(buf[2]) {
                return Err(Error::InvalidValue(buf[2]));
            }
            Ok(EventAttr {
                id: buf[0],
                reason: buf[2],
                len: 0,
                descriptor: [0; MAX_DESCRIPTOR],
            })
        }
        EVENT_ATTR_READER_DESCRIPTOR => {
            let len = buf[1] as usize;
            if len > MAX_DESCRIPTOR || buf.len() != 2 + len {
                return Err(Error::InvalidValue(buf[1]));
            }
            let mut descriptor = [0u8; MAX_DESCRIPTOR];
            descriptor[..len].copy_from_slice(&buf[2..2 + len]);
            #[allow(clippy::cast_possible_truncation)]
            let len_u8 = len as u8;
            Ok(EventAttr {
                id: buf[0],
                reason: 0,
                len: len_u8,
                descriptor,
            })
        }
        other => Err(Error::InvalidValue(other)),
    }
}

/// Server attribute table, ascending.
///
/// Requirement `26-42802-001-11-02` (MINTED-pending-confirm).
pub static SERVER_ATTRS: &[AttrDef] = &[
    AttrDef {
        id: ATTR_ADV_FEATURES,
        datatype: DataType::Map(1).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_NOTIFICATION,
        datatype: DataType::Enum8.as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_ADV_VERSION,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_OPERATION_SOURCE,
        datatype: DataType::Enum8.as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_READER_STATUS,
        datatype: DataType::Enum8.as_u8(),
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

/// Server definition (the reader bridge reports; it takes no
/// cluster-specific commands).
pub struct ServerDef;
impl ClusterDef for ServerDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "aliro-reader-server"
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

/// Build a fresh bridge store with idle defaults.
pub fn server_store() -> Result<AttrStore, Error> {
    let mut store = AttrStore::new(None);
    store.add(
        SERVER_ATTRS[0],
        Value::Map {
            width: 1,
            bytes: [0; 8],
        },
    )?;
    store.add(SERVER_ATTRS[1], Value::Enum8(NOTIFY_NO_ERROR))?;
    store.add(SERVER_ATTRS[2], Value::UInt { width: 1, v: 0 })?;
    store.add(SERVER_ATTRS[3], Value::Enum8(SOURCE_UNSPECIFIED))?;
    store.add(SERVER_ATTRS[4], Value::Enum8(STATUS_ACCEPT))?;
    store.add_globals(REVISION)?;
    Ok(store)
}

/// Reader-state behavior: busy marking, state-change publication
/// with an operation source, and notification-class updates.
///
/// Requirement `26-42802-001-11-03` (MINTED-pending-confirm).
pub struct ReaderBehavior {
    busy: bool,
}

impl Default for ReaderBehavior {
    fn default() -> Self {
        Self::new()
    }
}

impl ReaderBehavior {
    /// Idle reader (accepting, no pending operation).
    #[must_use]
    pub const fn new() -> Self {
        Self { busy: false }
    }

    /// Whether the reader is marked busy.
    #[must_use]
    pub const fn is_busy(&self) -> bool {
        self.busy
    }

    /// Mark the reader busy (further operations queue behind it).
    pub fn mark_busy(&mut self, ctx: &mut Ctx<'_>) {
        self.busy = true;
        ctx.events.push(AppEvent::StateChanged {
            cluster: CLUSTER_ID,
            from: 0,
            to: 1,
        });
    }

    /// Publish a state change with its operation source and verdict;
    /// clears the busy marker.
    pub fn state_changed(
        &mut self,
        ctx: &mut Ctx<'_>,
        source: u8,
        status: u8,
    ) -> Result<(), ZclStatus> {
        if !source_known(source) {
            return Err(ZclStatus::InvalidField);
        }
        if !status_known(status) {
            return Err(ZclStatus::InvalidField);
        }
        let from = u8::from(self.busy);
        self.busy = false;
        ctx.store
            .set_local(ATTR_OPERATION_SOURCE, Value::Enum8(source))
            .map_err(|_| ZclStatus::Failure)?;
        ctx.store
            .set_local(ATTR_READER_STATUS, Value::Enum8(status))
            .map_err(|_| ZclStatus::Failure)?;
        ctx.events.push(AppEvent::AttributeChanged {
            cluster: CLUSTER_ID,
            attr: ATTR_OPERATION_SOURCE,
        });
        ctx.events.push(AppEvent::StateChanged {
            cluster: CLUSTER_ID,
            from,
            to: 2,
        });
        Ok(())
    }

    /// Update the notification class (no-error / fault /
    /// low-battery / touch).
    pub fn set_notification(
        &mut self,
        ctx: &mut Ctx<'_>,
        notification: u8,
    ) -> Result<(), ZclStatus> {
        if !notification_known(notification) {
            return Err(ZclStatus::InvalidField);
        }
        ctx.store
            .set_local(ATTR_NOTIFICATION, Value::Enum8(notification))
            .map_err(|_| ZclStatus::Failure)?;
        ctx.events.push(AppEvent::AttributeChanged {
            cluster: CLUSTER_ID,
            attr: ATTR_NOTIFICATION,
        });
        Ok(())
    }
}

impl Behavior for ReaderBehavior {
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
        // The bridge takes no cluster-specific commands.
        Err(ZclStatus::UnsupCommand)
    }
}
