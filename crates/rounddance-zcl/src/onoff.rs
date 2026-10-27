//! On/Off cluster (0x0006): client + server definition and behavior.
//!
//! Paraphrase-level model of doc `07-5123-08` §3.8 (attributes Table
//! 3-45 anchor p0172-L5064-L5066, OnOff/GlobalSceneControl §3.8.2.2.1–
//! 2.2.2 anchors p0173-L5067-L5080, OnTime/OffWaitTime §3.8.2.2.3–2.2.4
//! anchors p0173-L5083-L5091, StartUpOnOff §3.8.2.2.5 anchor
//! p0174-L5092-L5096, command IDs Table 3-47 anchor p0174-L5098-L5100,
//! Off/On/Toggle effects §3.8.2.3.1–3.3 anchors p0175-L5101-L5119, Off
//! With Effect §3.8.2.3.4 anchors p0175-L5120-L5129 +
//! p0176-L5130-L5141, Recall Global Scene §3.8.2.3.5 anchor
//! p0176-L5142-L5152, Timed Off §3.8.2.3.6 anchors p0176-L5154-L5178 +
//! p0177-L5179-L5194). All wording here is paraphrase (D1).
//!
//! Requirement IDs `07-5123-08-382-01/02` + `07-5123-08-383-01..04`
//! (repo-minted, MINTED-pending-confirm); `07-5123-08-381-01`
//! (revision, repo-minted).

use crate::attrs::{access, AttrDef, AttrStore, ATTR_CLUSTER_REVISION};
use crate::behavior::{AppEvent, Behavior, Ctx, HandleOutcome};
use crate::cluster::{ClusterDef, ClusterRole, CmdDef};
use crate::frame::{Direction, FrameControl, FrameType, Header};
use crate::types::{DataType, Value};
use crate::{Error, ZclStatus};

/// Cluster identifier.
pub const CLUSTER_ID: u16 = 0x0006;
/// Implemented specification revision (rev table tip).
///
/// Requirement `07-5123-08-381-01` (MINTED-pending-confirm).
pub const REVISION: u16 = 2;

/// OnOff attribute: 0 = off, 1 = on.
pub const ATTR_ONOFF: u16 = 0x0000;
/// GlobalSceneControl attribute.
pub const ATTR_GLOBAL_SCENE: u16 = 0x4000;
/// OnTime attribute (1/10 s guarded-on timer).
pub const ATTR_ONTIME: u16 = 0x4001;
/// OffWaitTime attribute (1/10 s guarded-off timer).
pub const ATTR_OFFWAIT: u16 = 0x4002;
/// StartUpOnOff attribute.
pub const ATTR_STARTUP: u16 = 0x4003;

/// Off command (no payload).
pub const CMD_OFF: u8 = 0x00;
/// On command (no payload).
pub const CMD_ON: u8 = 0x01;
/// Toggle command (no payload).
pub const CMD_TOGGLE: u8 = 0x02;
/// Off With Effect command (effect + variant).
pub const CMD_OFF_EFFECT: u8 = 0x40;
/// On With Recall Global Scene command (no payload).
pub const CMD_ON_RECALL_SCENE: u8 = 0x41;
/// On With Timed Off command (control + on-time + off-wait).
pub const CMD_ON_TIMED_OFF: u8 = 0x42;

/// Effect identifiers for Off With Effect.
pub const EFFECT_DELAYED_OFF: u8 = 0x00;
/// Dying-light effect.
pub const EFFECT_DYING_LIGHT: u8 = 0x01;

/// StartUpOnOff values.
pub const STARTUP_OFF: u8 = 0x00;
/// Start up on.
pub const STARTUP_ON: u8 = 0x01;
/// Start up toggled from the previous value.
pub const STARTUP_TOGGLE: u8 = 0x02;
/// Start up at the previous value.
pub const STARTUP_PREVIOUS: u8 = 0xff;

/// Server attribute table, ascending.
///
/// Requirement `07-5123-08-382-01` (MINTED-pending-confirm).
pub static SERVER_ATTRS: &[AttrDef] = &[
    AttrDef {
        id: ATTR_ONOFF,
        datatype: DataType::Bool.as_u8(),
        access: access::READ | access::REPORT | access::SCENE,
        reportable: true,
    },
    AttrDef {
        id: ATTR_GLOBAL_SCENE,
        datatype: DataType::Bool.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_ONTIME,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_OFFWAIT,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_STARTUP,
        datatype: DataType::Enum8.as_u8(),
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
///
/// Requirement `07-5123-08-383-01` (MINTED-pending-confirm).
pub static SERVER_RX: &[CmdDef] = &[
    CmdDef {
        id: CMD_OFF,
        name: "off",
    },
    CmdDef {
        id: CMD_ON,
        name: "on",
    },
    CmdDef {
        id: CMD_TOGGLE,
        name: "toggle",
    },
    CmdDef {
        id: CMD_OFF_EFFECT,
        name: "off-with-effect",
    },
    CmdDef {
        id: CMD_ON_RECALL_SCENE,
        name: "on-with-recall-scene",
    },
    CmdDef {
        id: CMD_ON_TIMED_OFF,
        name: "on-with-timed-off",
    },
];

/// Server definition.
pub struct ServerDef;
impl ClusterDef for ServerDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "on-off-server"
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
        &[]
    }
}

/// Client definition (no attributes; generates the server commands).
pub struct ClientDef;
impl ClusterDef for ClientDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "on-off-client"
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
        &[]
    }
    fn generated_commands(&self) -> &'static [CmdDef] {
        SERVER_RX
    }
}

/// Build a fresh server store with table defaults.
pub fn server_store() -> Result<AttrStore, Error> {
    let mut store = AttrStore::new(None);
    store.add(SERVER_ATTRS[0], Value::Bool(false))?;
    store.add(SERVER_ATTRS[1], Value::Bool(true))?;
    store.add(SERVER_ATTRS[2], Value::UInt { width: 2, v: 0 })?;
    store.add(SERVER_ATTRS[3], Value::UInt { width: 2, v: 0 })?;
    // StartUpOnOff default: previous value (0xff). The attribute
    // table's default cell carries a manufacturer-specific marker, so
    // this follows the power-up value table instead (0xff = previous).
    store.add(SERVER_ATTRS[4], Value::Enum8(STARTUP_PREVIOUS))?;
    store.add_globals(REVISION)?;
    Ok(store)
}

/// Current OnOff value from a server store.
pub fn onoff(store: &AttrStore) -> bool {
    matches!(store.get(ATTR_ONOFF), Some(Value::Bool(true)))
}

/// Server behavior: applies command effects to the store and emits
/// application callbacks for scene store/recall (scene storage itself
/// is the application's job).
///
/// Requirements `07-5123-08-383-01..04` (MINTED-pending-confirm).
pub struct ServerBehavior;

impl ServerBehavior {
    fn set_onoff(ctx: &mut Ctx<'_>, on: bool) -> Result<(), Error> {
        ctx.store.set_local(ATTR_ONOFF, Value::Bool(on))?;
        ctx.events.push(AppEvent::AttributeChanged {
            cluster: CLUSTER_ID,
            attr: ATTR_ONOFF,
        });
        Ok(())
    }

    fn set_u16(ctx: &mut Ctx<'_>, attr: u16, v: u16) -> Result<(), Error> {
        ctx.store.set_local(
            attr,
            Value::UInt {
                width: 2,
                v: v as u64,
            },
        )?;
        ctx.events.push(AppEvent::AttributeChanged {
            cluster: CLUSTER_ID,
            attr,
        });
        Ok(())
    }

    fn get_u16(ctx: &Ctx<'_>, attr: u16) -> u16 {
        match ctx.store.get(attr) {
            Some(Value::UInt { v, .. }) => v.min(0xffff) as u16,
            _ => 0,
        }
    }

    fn effect_off(ctx: &mut Ctx<'_>) -> Result<HandleOutcome, ZclStatus> {
        Self::set_onoff(ctx, false).map_err(|_| ZclStatus::Failure)?;
        Self::set_u16(ctx, ATTR_ONTIME, 0).map_err(|_| ZclStatus::Failure)?;
        Ok(HandleOutcome::no_reply())
    }

    fn effect_on(ctx: &mut Ctx<'_>) -> Result<HandleOutcome, ZclStatus> {
        Self::set_onoff(ctx, true).map_err(|_| ZclStatus::Failure)?;
        if Self::get_u16(ctx, ATTR_ONTIME) == 0 {
            Self::set_u16(ctx, ATTR_OFFWAIT, 0).map_err(|_| ZclStatus::Failure)?;
        }
        Ok(HandleOutcome::no_reply())
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
            CMD_OFF => {
                if !payload.is_empty() {
                    return Err(ZclStatus::MalformedCommand);
                }
                Self::effect_off(ctx)
            }
            CMD_ON => {
                if !payload.is_empty() {
                    return Err(ZclStatus::MalformedCommand);
                }
                Self::effect_on(ctx)
            }
            CMD_TOGGLE => {
                if !payload.is_empty() {
                    return Err(ZclStatus::MalformedCommand);
                }
                if onoff(ctx.store) {
                    Self::effect_off(ctx)
                } else {
                    Self::effect_on(ctx)
                }
            }
            CMD_OFF_EFFECT => {
                if payload.len() != 2 {
                    return Err(ZclStatus::MalformedCommand);
                }
                if payload[0] != EFFECT_DELAYED_OFF && payload[0] != EFFECT_DYING_LIGHT {
                    return Err(ZclStatus::InvalidField);
                }
                // Unknown variants fall back to the default variant;
                // the application learns the request through the event.
                // Scene-control update per `07-5123-08-382-02`.
                let global_scene =
                    matches!(ctx.store.get(ATTR_GLOBAL_SCENE), Some(Value::Bool(true)));
                if global_scene {
                    ctx.events.push(AppEvent::StateChanged {
                        cluster: CLUSTER_ID,
                        from: 1,
                        to: 0,
                    });
                    ctx.store
                        .set_local(ATTR_GLOBAL_SCENE, Value::Bool(false))
                        .map_err(|_| ZclStatus::Failure)?;
                }
                Self::effect_off(ctx)
            }
            // Requirement `07-5123-08-383-03` (MINTED-pending-confirm).
            CMD_ON_RECALL_SCENE => {
                if !payload.is_empty() {
                    return Err(ZclStatus::MalformedCommand);
                }
                let global_scene =
                    matches!(ctx.store.get(ATTR_GLOBAL_SCENE), Some(Value::Bool(true)));
                // A set control flag means the live state already is
                // the scene: discard without effect.
                if global_scene {
                    return Ok(HandleOutcome::no_reply());
                }
                ctx.events.push(AppEvent::StateChanged {
                    cluster: CLUSTER_ID,
                    from: 0,
                    to: 1,
                });
                ctx.store
                    .set_local(ATTR_GLOBAL_SCENE, Value::Bool(true))
                    .map_err(|_| ZclStatus::Failure)?;
                Self::effect_on(ctx)
            }
            CMD_ON_TIMED_OFF => {
                if payload.len() != 5 {
                    return Err(ZclStatus::MalformedCommand);
                }
                let accept_only_when_on = payload[0] & 0x01 != 0;
                if payload[0] & 0xfe != 0 {
                    return Err(ZclStatus::InvalidField);
                }
                let on_time = u16::from_le_bytes([payload[1], payload[2]]);
                let off_wait = u16::from_le_bytes([payload[3], payload[4]]);
                if on_time == 0xffff || off_wait == 0xffff {
                    return Err(ZclStatus::InvalidValue);
                }
                if accept_only_when_on && !onoff(ctx.store) {
                    return Ok(HandleOutcome::no_reply());
                }
                let cur_off = Self::get_u16(ctx, ATTR_OFFWAIT);
                if cur_off > 0 && !onoff(ctx.store) {
                    Self::set_u16(ctx, ATTR_OFFWAIT, cur_off.min(off_wait))
                        .map_err(|_| ZclStatus::Failure)?;
                    return Ok(HandleOutcome::no_reply());
                }
                let cur_on = Self::get_u16(ctx, ATTR_ONTIME);
                Self::set_u16(ctx, ATTR_ONTIME, cur_on.max(on_time))
                    .map_err(|_| ZclStatus::Failure)?;
                Self::set_u16(ctx, ATTR_OFFWAIT, off_wait).map_err(|_| ZclStatus::Failure)?;
                Self::set_onoff(ctx, true).map_err(|_| ZclStatus::Failure)?;
                Ok(HandleOutcome::no_reply())
            }
            _ => Err(ZclStatus::UnsupCommand),
        }
    }
}

/// Advance the 1/10 s OnTime/OffWaitTime countdown. Both timers at
/// `0xffff` hold their state; an OnTime reaching zero turns the
/// device off.
pub fn tick_100ms(store: &mut AttrStore, events: &mut crate::behavior::EventQueue) {
    let on = onoff(store);
    let get = |attr| match store.get(attr) {
        Some(Value::UInt { v, .. }) => v.min(0xffff) as u16,
        _ => 0,
    };
    let set = |store: &mut AttrStore, attr, v: u16| {
        let _ = store.set_local(
            attr,
            Value::UInt {
                width: 2,
                v: v as u64,
            },
        );
    };
    if on {
        let on_time = get(ATTR_ONTIME);
        if on_time != 0 && on_time != 0xffff {
            let next = on_time - 1;
            set(store, ATTR_ONTIME, next);
            if next == 0 {
                set(store, ATTR_OFFWAIT, 0);
                let _ = store.set_local(ATTR_ONOFF, Value::Bool(false));
                events.push(AppEvent::AttributeChanged {
                    cluster: CLUSTER_ID,
                    attr: ATTR_ONOFF,
                });
            }
        }
    } else {
        let off_wait = get(ATTR_OFFWAIT);
        if off_wait != 0 && off_wait != 0xffff {
            set(store, ATTR_OFFWAIT, off_wait - 1);
        }
    }
}

/// Apply power-up behavior from StartUpOnOff, reflecting the result
/// in OnOff. `previous` is the pre-outage OnOff value.
pub fn apply_startup(store: &mut AttrStore, previous: bool) -> Result<(), Error> {
    let mode = match store.get(ATTR_STARTUP) {
        Some(Value::Enum8(v)) => v,
        _ => STARTUP_PREVIOUS,
    };
    let next = match mode {
        STARTUP_OFF => false,
        STARTUP_ON => true,
        STARTUP_TOGGLE => !previous,
        STARTUP_PREVIOUS => previous,
        _ => return Err(Error::InvalidValue(mode)),
    };
    store.set_local(ATTR_ONOFF, Value::Bool(next))
}

/// Client-side command builders: client-to-server cluster-specific
/// frames with a fresh transaction number.
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

    /// Encode an Off command.
    pub fn off(tsn: u8, out: &mut [u8]) -> Result<usize, Error> {
        frame(tsn, CMD_OFF, &[], out)
    }

    /// Encode an On command.
    pub fn on(tsn: u8, out: &mut [u8]) -> Result<usize, Error> {
        frame(tsn, CMD_ON, &[], out)
    }

    /// Encode a Toggle command.
    pub fn toggle(tsn: u8, out: &mut [u8]) -> Result<usize, Error> {
        frame(tsn, CMD_TOGGLE, &[], out)
    }

    /// Encode an Off With Effect command.
    pub fn off_with_effect(
        tsn: u8,
        effect: u8,
        variant: u8,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        frame(tsn, CMD_OFF_EFFECT, &[effect, variant], out)
    }

    /// Encode an On With Timed Off command.
    pub fn on_with_timed_off(
        tsn: u8,
        accept_only_when_on: bool,
        on_time: u16,
        off_wait: u16,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let payload = [
            u8::from(accept_only_when_on),
            (on_time & 0xff) as u8,
            (on_time >> 8) as u8,
            (off_wait & 0xff) as u8,
            (off_wait >> 8) as u8,
        ];
        frame(tsn, CMD_ON_TIMED_OFF, &payload, out)
    }
}
