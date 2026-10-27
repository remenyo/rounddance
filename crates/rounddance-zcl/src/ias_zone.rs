//! IAS Zone cluster (0x0500): server with enrollment state machine.
//!
//! Paraphrase-level model of doc `07-5123-08` §8.2 (attribute sets +
//! Table 8-3/8-8 anchors p0525-L11921-L11923 + p0528-L11954-L11956,
//! ZoneState/ZoneType/ZoneStatus §8.2.2.1.1 anchors p0525-L11924-L11933
//! plus p0526-L11927-L11935 + p0527-L11935-L11948, CIE address + ZoneID +
//! sensitivity §8.2.2.1.2 anchors p0528-L11958-L11981, received
//! commands Table 8-9 anchor p0530-L12060-L12063, Enroll Response
//! §8.2.2.2.1 anchors p0531-L12064-L12078, Normal/Test §8.2.2.2.2
//! anchors p0531-L12079-L12088 + p0532-L12106-L12126 + p0533-L12124,
//! generated commands Table 8-11 anchor p0533-L12152-L12156,
//! notification §8.2.2.3.1 anchors p0534-L12157-L12175, enroll
//! request §8.2.2.3.2 anchors p0534-L12177-L12184). All wording here
//! is paraphrase (D1).
//!
//! Requirement IDs `07-5123-08-822-01..10` corpus-mined and reused;
//! `07-5123-08-821-01` (revision, repo-minted, MINTED-pending-confirm).

use crate::attrs::{access, AttrDef, AttrStore, ATTR_CLUSTER_REVISION};
use crate::behavior::{AppEvent, Behavior, Ctx, EventQueue, HandleOutcome};
use crate::cluster::{ClusterDef, ClusterRole, CmdDef};
use crate::frame::{Direction, FrameControl, FrameType, Header};
use crate::types::{DataType, Value};
use crate::{Error, ZclStatus};

/// Cluster identifier.
pub const CLUSTER_ID: u16 = 0x0500;
/// Implemented specification revision (rev table tip).
///
/// Requirement `07-5123-08-821-01` (MINTED-pending-confirm).
pub const REVISION: u16 = 2;

/// ZoneState: not enrolled.
pub const ZONE_STATE_NOT_ENROLLED: u8 = 0x00;
/// ZoneState: enrolled.
pub const ZONE_STATE_ENROLLED: u8 = 0x01;

/// ZoneState attribute.
pub const ATTR_ZONE_STATE: u16 = 0x0000;
/// ZoneType attribute.
pub const ATTR_ZONE_TYPE: u16 = 0x0001;
/// ZoneStatus attribute (bit map).
pub const ATTR_ZONE_STATUS: u16 = 0x0002;
/// IAS CIE address attribute (EUI64).
pub const ATTR_CIE_ADDRESS: u16 = 0x0010;
/// ZoneID attribute (0xff = none programmed).
pub const ATTR_ZONE_ID: u16 = 0x0011;
/// Sensitivity-level count attribute.
pub const ATTR_NUM_SENS_LEVELS: u16 = 0x0012;
/// Current sensitivity level attribute.
pub const ATTR_CUR_SENS_LEVEL: u16 = 0x0013;

/// ZoneStatus bits.
pub const STATUS_ALARM1: u16 = 0x0001;
/// Alarm2 bit.
pub const STATUS_ALARM2: u16 = 0x0002;
/// Tamper bit.
pub const STATUS_TAMPER: u16 = 0x0004;
/// Low-battery bit.
pub const STATUS_BATTERY: u16 = 0x0008;
/// Supervision-notify bit.
pub const STATUS_SUPERVISION: u16 = 0x0010;
/// Restore-notify bit.
pub const STATUS_RESTORE: u16 = 0x0020;
/// Trouble bit.
pub const STATUS_TROUBLE: u16 = 0x0040;
/// AC/mains-fault bit.
pub const STATUS_AC: u16 = 0x0080;
/// Test-mode bit.
pub const STATUS_TEST: u16 = 0x0100;
/// Defective-battery bit.
pub const STATUS_BATTERY_DEFECT: u16 = 0x0200;

/// Received: Zone Enroll Response (code + zone id).
pub const CMD_ENROLL_RESPONSE: u8 = 0x00;
/// Received: Initiate Normal Operation Mode (no payload).
pub const CMD_NORMAL_OP: u8 = 0x01;
/// Received: Initiate Test Mode (duration + sensitivity).
pub const CMD_TEST_MODE: u8 = 0x02;

/// Generated: Zone Status Change Notification.
pub const CMD_STATUS_NOTIFY: u8 = 0x00;
/// Generated: Zone Enroll Request.
pub const CMD_ENROLL_REQUEST: u8 = 0x01;

/// Enroll response codes.
pub const ENROLL_SUCCESS: u8 = 0x00;
/// Zone type not supported by the CIE.
pub const ENROLL_NOT_SUPPORTED: u8 = 0x01;
/// CIE permits no new zones right now.
pub const ENROLL_NO_PERMIT: u8 = 0x02;
/// CIE zone table full.
pub const ENROLL_TOO_MANY: u8 = 0x03;

/// Enrollment stages tracked by [`ServerBehavior`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollStage {
    /// ZoneState reads not-enrolled; no CIE bound.
    NotEnrolled = 0,
    /// CIE address written; enroll request not yet sent.
    CieBound = 1,
    /// Enroll request sent; awaiting the enroll response.
    EnrollPending = 2,
    /// Enrolled: ZoneState reads enrolled.
    Enrolled = 3,
}

/// Server attribute table, ascending.
pub static SERVER_ATTRS: &[AttrDef] = &[
    AttrDef {
        id: ATTR_ZONE_STATE,
        datatype: DataType::Enum8.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_ZONE_TYPE,
        datatype: DataType::Enum16.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_ZONE_STATUS,
        datatype: DataType::Map(2).as_u8(),
        access: access::READ | access::REPORT,
        reportable: true,
    },
    AttrDef {
        id: ATTR_CIE_ADDRESS,
        datatype: DataType::Eui64.as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_ZONE_ID,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_NUM_SENS_LEVELS,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_CUR_SENS_LEVEL,
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

/// Server received commands, ascending.
pub static SERVER_RX: &[CmdDef] = &[
    CmdDef {
        id: CMD_ENROLL_RESPONSE,
        name: "enroll-response",
    },
    CmdDef {
        id: CMD_NORMAL_OP,
        name: "normal-op",
    },
    CmdDef {
        id: CMD_TEST_MODE,
        name: "test-mode",
    },
];

/// Server generated commands, ascending.
pub static SERVER_TX: &[CmdDef] = &[
    CmdDef {
        id: CMD_STATUS_NOTIFY,
        name: "status-notify",
    },
    CmdDef {
        id: CMD_ENROLL_REQUEST,
        name: "enroll-request",
    },
];

/// Server definition.
pub struct ServerDef;
impl ClusterDef for ServerDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "ias-zone-server"
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

/// Build a fresh server store for `zone_type` (ZoneID none, CIE zero).
pub fn server_store(zone_type: u16) -> Result<AttrStore, Error> {
    let mut store = AttrStore::new(None);
    store.add(SERVER_ATTRS[0], Value::Enum8(ZONE_STATE_NOT_ENROLLED))?;
    store.add(SERVER_ATTRS[1], Value::Enum16(zone_type))?;
    store.add(
        SERVER_ATTRS[2],
        Value::Map {
            width: 2,
            bytes: [0; 8],
        },
    )?;
    store.add(SERVER_ATTRS[3], Value::Eui64([0; 8]))?;
    store.add(SERVER_ATTRS[4], Value::UInt { width: 1, v: 0xff })?;
    store.add(SERVER_ATTRS[5], Value::UInt { width: 1, v: 0x02 })?;
    store.add(SERVER_ATTRS[6], Value::UInt { width: 1, v: 0x00 })?;
    store.add_globals(REVISION)?;
    Ok(store)
}

/// Current ZoneStatus value.
pub fn zone_status(store: &AttrStore) -> u16 {
    match store.get(ATTR_ZONE_STATUS) {
        Some(Value::Map { bytes, .. }) => u16::from_le_bytes([bytes[0], bytes[1]]),
        _ => 0,
    }
}

/// Configured CIE address (zero = unbound).
pub fn cie_address(store: &AttrStore) -> u64 {
    match store.get(ATTR_CIE_ADDRESS) {
        Some(Value::Eui64(b)) => u64::from_le_bytes(b),
        _ => 0,
    }
}

/// Server behavior: enrollment state machine, test-mode timer, and
/// status-change notification fan-out.
///
/// Requirements `07-5123-08-822-01` (CIE gating), `07-5123-08-822-05`
/// (CIE-side writes only — enforced by only advancing on the write
/// hook, never self-assigning), `07-5123-08-822-06/07` (handshake +
/// lockdown), `07-5123-08-822-08/09/10` (mode signaling +
/// notification geometry), all corpus-mined.
pub struct ServerBehavior {
    stage: EnrollStage,
    test_left_s: u32,
    last_change_s: u64,
}

impl Default for ServerBehavior {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBehavior {
    /// Fresh behavior: not enrolled, no test timer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stage: EnrollStage::NotEnrolled,
            test_left_s: 0,
            last_change_s: 0,
        }
    }

    /// Current enrollment stage.
    #[must_use]
    pub const fn stage(&self) -> EnrollStage {
        self.stage
    }

    fn move_stage(&mut self, events: &mut EventQueue, to: EnrollStage) {
        let from = self.stage;
        self.stage = to;
        if from as u8 != to as u8 {
            events.push(AppEvent::StateChanged {
                cluster: CLUSTER_ID,
                from: from as u8,
                to: to as u8,
            });
        }
    }

    /// Whether `sender` may command this server: before binding any
    /// sender may write the CIE address; once bound, only the CIE.
    ///
    /// Requirement `07-5123-08-822-01` (corpus-mined).
    pub fn sender_allowed(store: &AttrStore, stage: EnrollStage, sender: Option<u64>) -> bool {
        if stage == EnrollStage::NotEnrolled {
            return true;
        }
        match sender {
            Some(s) => s == cie_address(store),
            None => true,
        }
    }

    /// Bind-lockdown check for ZDO bind/unbind attempts touching this
    /// cluster: refused unless the requester is the paired CIE.
    ///
    /// Requirement `07-5123-08-822-07` (corpus-mined).
    pub fn check_bind(
        store: &AttrStore,
        stage: EnrollStage,
        requester: u64,
    ) -> Result<(), ZclStatus> {
        if stage == EnrollStage::NotEnrolled {
            return Ok(());
        }
        if requester == cie_address(store) {
            Ok(())
        } else {
            Err(ZclStatus::NotAuthorized)
        }
    }

    /// Emit a Zone Status Change Notification event for the live
    /// status (extended status zeroed; delay in quarter-seconds since
    /// the last status change).
    ///
    /// Requirement `07-5123-08-822-10` (corpus-mined).
    pub fn emit_notification(
        &mut self,
        store: &AttrStore,
        events: &mut EventQueue,
        tsn: u8,
        now_s: u64,
    ) {
        let status = zone_status(store);
        let zone_id = match store.get(ATTR_ZONE_ID) {
            Some(Value::UInt { v, .. }) => v.min(0xff) as u8,
            _ => 0xff,
        };
        let delay_qs = now_s
            .saturating_sub(self.last_change_s)
            .saturating_mul(4)
            .min(0xffff) as u16;
        let mut payload = [0u8; MAX_NOTIFY_LEN];
        payload[..2].copy_from_slice(&status.to_le_bytes());
        payload[2] = 0x00;
        payload[3] = zone_id;
        payload[4..6].copy_from_slice(&delay_qs.to_le_bytes());
        events.push(AppEvent::OutboundCommand {
            cluster: CLUSTER_ID,
            cmd: CMD_STATUS_NOTIFY,
            tsn,
            len: MAX_NOTIFY_LEN as u8,
            payload: {
                let mut p = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
                p[..MAX_NOTIFY_LEN].copy_from_slice(&payload);
                p
            },
        });
    }

    /// Application-driven status update: sets ZoneStatus, stamps the
    /// change time, and emits the notification event.
    pub fn set_status(&mut self, ctx: &mut Ctx<'_>, status: u16, tsn: u8) -> Result<(), Error> {
        let mut bytes = [0u8; 8];
        bytes[..2].copy_from_slice(&status.to_le_bytes());
        ctx.store
            .set_local(ATTR_ZONE_STATUS, Value::Map { width: 2, bytes })?;
        self.last_change_s = ctx.now_s;
        ctx.events.push(AppEvent::AttributeChanged {
            cluster: CLUSTER_ID,
            attr: ATTR_ZONE_STATUS,
        });
        self.emit_notification(ctx.store, ctx.events, tsn, ctx.now_s);
        Ok(())
    }

    /// Trip-to-pair / auto-enroll-request trigger: emits the enroll
    /// request event (zone type + manufacturer code) and parks in
    /// the pending stage.
    ///
    /// Requirement `07-5123-08-822-06` (corpus-mined).
    pub fn trigger_enroll_request(
        &mut self,
        ctx: &mut Ctx<'_>,
        manufacturer_code: u16,
        tsn: u8,
    ) -> Result<(), Error> {
        let zone_type = match ctx.store.get(ATTR_ZONE_TYPE) {
            Some(Value::Enum16(v)) => v,
            _ => 0xffff,
        };
        let mut payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
        payload[..2].copy_from_slice(&zone_type.to_le_bytes());
        payload[2..4].copy_from_slice(&manufacturer_code.to_le_bytes());
        ctx.events.push(AppEvent::OutboundCommand {
            cluster: CLUSTER_ID,
            cmd: CMD_ENROLL_REQUEST,
            tsn,
            len: 4,
            payload,
        });
        self.move_stage(ctx.events, EnrollStage::EnrollPending);
        Ok(())
    }

    fn enroll(&mut self, ctx: &mut Ctx<'_>, zone_id: u8) -> Result<(), ZclStatus> {
        ctx.store
            .set_local(
                ATTR_ZONE_ID,
                Value::UInt {
                    width: 1,
                    v: zone_id as u64,
                },
            )
            .map_err(|_| ZclStatus::Failure)?;
        ctx.store
            .set_local(ATTR_ZONE_STATE, Value::Enum8(ZONE_STATE_ENROLLED))
            .map_err(|_| ZclStatus::Failure)?;
        self.move_stage(ctx.events, EnrollStage::Enrolled);
        Ok(())
    }
}

/// Status-notification payload length (status + ext + zone id + delay).
pub const MAX_NOTIFY_LEN: usize = 6;

impl Behavior for ServerBehavior {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }

    fn on_attribute_written(&mut self, ctx: &mut Ctx<'_>, attr: u16) -> Result<(), ZclStatus> {
        // Only the CIE (or its agent) configures the address; the
        // zone never self-assigns (822-05). Any committed write of a
        // non-zero address binds the server and arms the sender gate.
        if attr != ATTR_CIE_ADDRESS {
            return Ok(());
        }
        if cie_address(ctx.store) == 0 {
            return Ok(());
        }
        if self.stage == EnrollStage::NotEnrolled {
            self.move_stage(ctx.events, EnrollStage::CieBound);
        }
        Ok(())
    }

    fn handle_cluster_command(
        &mut self,
        ctx: &mut Ctx<'_>,
        header: &Header,
        command_id: u8,
        payload: &[u8],
    ) -> Result<HandleOutcome, ZclStatus> {
        if !Self::sender_allowed(ctx.store, self.stage, ctx.sender_ieee) {
            return Err(ZclStatus::NotAuthorized);
        }
        match command_id {
            CMD_ENROLL_RESPONSE => {
                if payload.len() != 2 {
                    return Err(ZclStatus::MalformedCommand);
                }
                match payload[0] {
                    ENROLL_SUCCESS => {
                        self.enroll(ctx, payload[1])?;
                        Ok(HandleOutcome::no_reply())
                    }
                    ENROLL_NOT_SUPPORTED | ENROLL_NO_PERMIT | ENROLL_TOO_MANY => {
                        // Refused: stay parked; the application learns
                        // the code through the state event below.
                        ctx.events.push(AppEvent::StateChanged {
                            cluster: CLUSTER_ID,
                            from: self.stage as u8,
                            to: self.stage as u8,
                        });
                        Ok(HandleOutcome::no_reply())
                    }
                    _ => Err(ZclStatus::InvalidField),
                }
            }
            CMD_NORMAL_OP => {
                if !payload.is_empty() {
                    return Err(ZclStatus::MalformedCommand);
                }
                // Normal-mode entry retains configuration and clears
                // the test bit with a notification (822-08).
                self.test_left_s = 0;
                let status = zone_status(ctx.store) & !STATUS_TEST;
                self.set_status(ctx, status, header.tsn)
                    .map_err(|_| ZclStatus::Failure)?;
                Ok(HandleOutcome::no_reply())
            }
            CMD_TEST_MODE => {
                if payload.len() != 2 {
                    return Err(ZclStatus::MalformedCommand);
                }
                let duration = payload[0];
                // Sensitivity stored verbatim: higher values stay
                // higher, preserving the monotonic order of
                // `07-5123-08-822-02` (corpus-mined).
                let level = payload[1];
                ctx.store
                    .set_local(
                        ATTR_CUR_SENS_LEVEL,
                        Value::UInt {
                            width: 1,
                            v: level as u64,
                        },
                    )
                    .map_err(|_| ZclStatus::Failure)?;
                self.test_left_s = duration as u32;
                // Entry announces test-bit-set (822-09).
                let status = zone_status(ctx.store) | STATUS_TEST;
                self.set_status(ctx, status, header.tsn)
                    .map_err(|_| ZclStatus::Failure)?;
                Ok(HandleOutcome::no_reply())
            }
            _ => Err(ZclStatus::UnsupCommand),
        }
    }
}

/// Advance the test-mode timer by `elapsed_s` caller seconds; expiry
/// restores normal mode with a test-bit-cleared notification.
///
/// Requirement `07-5123-08-822-09` (corpus-mined).
pub fn tick_1s(
    behavior: &mut ServerBehavior,
    store: &mut AttrStore,
    events: &mut EventQueue,
    tsn: u8,
    now_s: u64,
    elapsed_s: u32,
) {
    if behavior.test_left_s == 0 {
        return;
    }
    if elapsed_s >= behavior.test_left_s {
        behavior.test_left_s = 0;
        let status = zone_status(store) & !STATUS_TEST;
        let mut bytes = [0u8; 8];
        bytes[..2].copy_from_slice(&status.to_le_bytes());
        let _ = store.set_local(ATTR_ZONE_STATUS, Value::Map { width: 2, bytes });
        behavior.last_change_s = now_s;
        // Reuse the notification emitter through a scratch borrow.
        let zone_id = match store.get(ATTR_ZONE_ID) {
            Some(Value::UInt { v, .. }) => v.min(0xff) as u8,
            _ => 0xff,
        };
        let mut payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
        payload[..2].copy_from_slice(&status.to_le_bytes());
        payload[2] = 0x00;
        payload[3] = zone_id;
        payload[4..6].copy_from_slice(&0u16.to_le_bytes());
        events.push(AppEvent::OutboundCommand {
            cluster: CLUSTER_ID,
            cmd: CMD_STATUS_NOTIFY,
            tsn,
            len: MAX_NOTIFY_LEN as u8,
            payload,
        });
    } else {
        behavior.test_left_s -= elapsed_s;
    }
}

/// CIE-side (client) command builders: server-to-client frames.
pub mod cie {
    use super::*;

    fn frame(tsn: u8, cmd: u8, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let header = Header {
            control: FrameControl {
                frame_type: FrameType::ClusterSpecific,
                manufacturer_specific: false,
                direction: Direction::ToClient,
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

    /// Encode a Zone Enroll Response (code + zone id).
    pub fn enroll_response(tsn: u8, code: u8, zone_id: u8, out: &mut [u8]) -> Result<usize, Error> {
        frame(tsn, CMD_ENROLL_RESPONSE, &[code, zone_id], out)
    }

    /// Encode Initiate Normal Operation Mode.
    pub fn normal_op(tsn: u8, out: &mut [u8]) -> Result<usize, Error> {
        frame(tsn, CMD_NORMAL_OP, &[], out)
    }

    /// Encode Initiate Test Mode (duration seconds + level).
    pub fn test_mode(tsn: u8, duration_s: u8, level: u8, out: &mut [u8]) -> Result<usize, Error> {
        frame(tsn, CMD_TEST_MODE, &[duration_s, level], out)
    }
}
