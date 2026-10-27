//! Level Control cluster (0x0008): server basics.
//!
//! Paraphrase-level model of doc `07-5123-08` §3.10 (attribute Table
//! 3-56 anchor p0184-L5320-L5322, Options/ExecuteIfOff §3.10.2.2.8
//! anchors p0185-L5342-L5357, On/Off coupling Table 3-55 anchor
//! p0183-L5296-L5301, with/without-On/Off sets §3.10.2.1.2 anchor
//! p0183-L5302-L5312, command IDs Table 3-59 anchor p0187-L5388-L5390,
//! Move-to-Level/Move/Step/Stop payloads + effects anchors
//! p0187-L5391-L5412 + p0188-L5413-L5432 + p0189-L5434-L5448 +
//! p0190-L5449-L5465). All wording here is paraphrase (D1).
//!
//! Requirement IDs `07-5123-08-3102-01..04` (repo-minted,
//! MINTED-pending-confirm); `07-5123-08-3101-01` (revision,
//! repo-minted); `07-5123-08-425-01` (range guard, corpus-mined).

use crate::attrs::{access, AttrDef, AttrStore, ATTR_CLUSTER_REVISION};
use crate::behavior::{AppEvent, Behavior, Ctx, HandleOutcome};
use crate::cluster::{ClusterDef, ClusterRole, CmdDef};
use crate::frame::{Direction, FrameControl, FrameType, Header};
use crate::types::{DataType, Value};
use crate::{Error, ZclStatus};

/// Cluster identifier (base level control).
pub const CLUSTER_ID: u16 = 0x0008;
/// Implemented specification revision (rev table tip).
///
/// Requirement `07-5123-08-3101-01` (MINTED-pending-confirm).
pub const REVISION: u16 = 3;

/// CurrentLevel attribute.
pub const ATTR_CURRENT_LEVEL: u16 = 0x0000;
/// RemainingTime attribute (1/10 s).
pub const ATTR_REMAINING: u16 = 0x0001;
/// MinLevel attribute.
pub const ATTR_MIN_LEVEL: u16 = 0x0002;
/// MaxLevel attribute.
pub const ATTR_MAX_LEVEL: u16 = 0x0003;
/// Options attribute (bit 0 = ExecuteIfOff).
pub const ATTR_OPTIONS: u16 = 0x000f;
/// OnOffTransitionTime attribute (1/10 s).
pub const ATTR_ONOFF_TRANSITION: u16 = 0x0010;
/// OnLevel attribute (0xff = not defined).
pub const ATTR_ON_LEVEL: u16 = 0x0011;
/// OnTransitionTime attribute (0xffff = fall back).
pub const ATTR_ON_TRANSITION: u16 = 0x0012;
/// OffTransitionTime attribute (0xffff = fall back).
pub const ATTR_OFF_TRANSITION: u16 = 0x0013;
/// DefaultMoveRate attribute (0xff = as fast as able).
pub const ATTR_MOVE_RATE: u16 = 0x0014;
/// StartUpCurrentLevel attribute (0xff = previous).
pub const ATTR_STARTUP_LEVEL: u16 = 0x4000;

/// ExecuteIfOff options bit: with it clear, without-On/Off commands
/// do not run while the sibling OnOff attribute reads off.
pub const OPTIONS_EXECUTE_IF_OFF: u8 = 0x01;

/// Move to Level (option-less and with-On/Off share the payload).
pub const CMD_MOVE_TO_LEVEL: u8 = 0x00;
/// Move (continuous).
pub const CMD_MOVE: u8 = 0x01;
/// Step.
pub const CMD_STEP: u8 = 0x02;
/// Stop (either set; the commands are identical).
pub const CMD_STOP: u8 = 0x03;
/// Move to Level with On/Off.
pub const CMD_MOVE_TO_LEVEL_ONOFF: u8 = 0x04;
/// Move with On/Off.
pub const CMD_MOVE_ONOFF: u8 = 0x05;
/// Step with On/Off.
pub const CMD_STEP_ONOFF: u8 = 0x06;
/// Stop twin for the with-On/Off set.
pub const CMD_STOP_ONOFF: u8 = 0x07;

/// Move/step direction up.
pub const DIR_UP: u8 = 0x00;
/// Move/step direction down.
pub const DIR_DOWN: u8 = 0x01;

/// Server attribute table, ascending.
///
/// Requirement `07-5123-08-3102-01` (MINTED-pending-confirm). The
/// extracted table's default cells for CurrentLevel, DefaultMoveRate,
/// and StartUpCurrentLevel are taken as listed (0xff-class), with the
/// CurrentLevel choice noted in [`server_store`].
pub static SERVER_ATTRS: &[AttrDef] = &[
    AttrDef {
        id: ATTR_CURRENT_LEVEL,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ | access::REPORT | access::SCENE,
        reportable: true,
    },
    AttrDef {
        id: ATTR_REMAINING,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_MIN_LEVEL,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_MAX_LEVEL,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_OPTIONS,
        datatype: DataType::Map(1).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_ONOFF_TRANSITION,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_ON_LEVEL,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_ON_TRANSITION,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_OFF_TRANSITION,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_MOVE_RATE,
        datatype: DataType::UInt(1).as_u8(),
        access: access::READ | access::WRITE,
        reportable: false,
    },
    AttrDef {
        id: ATTR_STARTUP_LEVEL,
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
///
/// Requirement `07-5123-08-3102-04` (MINTED-pending-confirm).
pub static SERVER_RX: &[CmdDef] = &[
    CmdDef {
        id: CMD_MOVE_TO_LEVEL,
        name: "move-to-level",
    },
    CmdDef {
        id: CMD_MOVE,
        name: "move",
    },
    CmdDef {
        id: CMD_STEP,
        name: "step",
    },
    CmdDef {
        id: CMD_STOP,
        name: "stop",
    },
    CmdDef {
        id: CMD_MOVE_TO_LEVEL_ONOFF,
        name: "move-to-level-with-onoff",
    },
    CmdDef {
        id: CMD_MOVE_ONOFF,
        name: "move-with-onoff",
    },
    CmdDef {
        id: CMD_STEP_ONOFF,
        name: "step-with-onoff",
    },
    CmdDef {
        id: CMD_STOP_ONOFF,
        name: "stop-with-onoff",
    },
];

/// Server definition.
pub struct ServerDef;
impl ClusterDef for ServerDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "level-server"
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

/// Range guard: CurrentLevel/OnLevel writes outside the live
/// physical envelope are refused with the level left unchanged.
///
/// Requirement `07-5123-08-425-01` (corpus-mined).
pub fn level_guard(store: &AttrStore, attr: u16, value: &Value) -> Option<ZclStatus> {
    let level = match (attr, value) {
        (ATTR_CURRENT_LEVEL, Value::UInt { v, .. }) => *v,
        (ATTR_ON_LEVEL, Value::UInt { v, .. }) if *v != 0xff => *v,
        _ => return None,
    };
    let min = match store.get(ATTR_MIN_LEVEL) {
        Some(Value::UInt { v, .. }) => v.min(0xff),
        _ => 0,
    };
    let max = match store.get(ATTR_MAX_LEVEL) {
        Some(Value::UInt { v, .. }) => v.min(0xff),
        _ => 0xff,
    };
    if level < min || level > max {
        Some(ZclStatus::InvalidValue)
    } else {
        None
    }
}

/// Build a fresh server store with table defaults.
pub fn server_store() -> Result<AttrStore, Error> {
    let mut store = AttrStore::new(Some(|attr, value| {
        // Guard closure without store access cannot read the live
        // envelope; envelope checks run in the behavior instead (see
        // `ServerBehavior`). This hook accepts everything.
        let _ = (attr, value);
        None
    }));
    store.add(SERVER_ATTRS[0], Value::UInt { width: 1, v: 0xff })?;
    store.add(SERVER_ATTRS[1], Value::UInt { width: 2, v: 0 })?;
    store.add(SERVER_ATTRS[2], Value::UInt { width: 1, v: 0 })?;
    store.add(SERVER_ATTRS[3], Value::UInt { width: 1, v: 0xff })?;
    store.add(
        SERVER_ATTRS[4],
        Value::Map {
            width: 1,
            bytes: [0; 8],
        },
    )?;
    store.add(SERVER_ATTRS[5], Value::UInt { width: 2, v: 0 })?;
    store.add(SERVER_ATTRS[6], Value::UInt { width: 1, v: 0xff })?;
    store.add(
        SERVER_ATTRS[7],
        Value::UInt {
            width: 2,
            v: 0xffff,
        },
    )?;
    store.add(
        SERVER_ATTRS[8],
        Value::UInt {
            width: 2,
            v: 0xffff,
        },
    )?;
    store.add(SERVER_ATTRS[9], Value::UInt { width: 1, v: 0xff })?;
    store.add(SERVER_ATTRS[10], Value::UInt { width: 1, v: 0xff })?;
    store.add_globals(REVISION)?;
    Ok(store)
}

/// Server behavior: immediate level application with RemainingTime
/// bookkeeping (fading itself is device-specific and out of scope for
/// server basics). With-On/Off commands publish the coupled OnOff
/// request through [`ServerBehavior::take_onoff_request`], which the
/// application applies to the sibling On/Off cluster.
///
/// Requirements `07-5123-08-3102-02/03/04` (MINTED-pending-confirm).
pub struct ServerBehavior {
    pending_onoff: Option<bool>,
}

impl Default for ServerBehavior {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBehavior {
    /// Fresh behavior with no pending coupling request.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pending_onoff: None,
        }
    }

    /// Take the pending sibling-OnOff request, if a with-On/Off
    /// command produced one.
    pub fn take_onoff_request(&mut self) -> Option<bool> {
        self.pending_onoff.take()
    }

    fn level(store: &AttrStore) -> u8 {
        match store.get(ATTR_CURRENT_LEVEL) {
            Some(Value::UInt { v, .. }) => v.min(0xff) as u8,
            _ => 0,
        }
    }

    fn envelope(store: &AttrStore) -> (u8, u8) {
        let min = match store.get(ATTR_MIN_LEVEL) {
            Some(Value::UInt { v, .. }) => v.min(0xff) as u8,
            _ => 0,
        };
        let max = match store.get(ATTR_MAX_LEVEL) {
            Some(Value::UInt { v, .. }) => v.min(0xff) as u8,
            _ => 0xff,
        };
        (min, max)
    }

    fn apply_level(ctx: &mut Ctx<'_>, level: u8, remaining_100ms: u16) -> Result<(), ZclStatus> {
        ctx.store
            .set_local(
                ATTR_CURRENT_LEVEL,
                Value::UInt {
                    width: 1,
                    v: level as u64,
                },
            )
            .map_err(|_| ZclStatus::Failure)?;
        ctx.store
            .set_local(
                ATTR_REMAINING,
                Value::UInt {
                    width: 2,
                    v: remaining_100ms as u64,
                },
            )
            .map_err(|_| ZclStatus::Failure)?;
        ctx.events.push(AppEvent::AttributeChanged {
            cluster: CLUSTER_ID,
            attr: ATTR_CURRENT_LEVEL,
        });
        Ok(())
    }

    /// Temporary Options bitmap from the attribute plus the
    /// command's mask/override pair (absent pair defaults to 0/0 for
    /// legacy frames).
    fn temp_options(ctx: &Ctx<'_>, mask: u8, over: u8) -> u8 {
        let base = match ctx.store.get(ATTR_OPTIONS) {
            Some(Value::Map { bytes, .. }) => bytes[0],
            _ => 0,
        };
        (base & !mask) | (over & mask)
    }

    /// ExecuteIfOff gate: without-On/Off commands stop before any
    /// effect while the sibling reads off and the bit is clear.
    ///
    /// Requirement `07-5123-08-3102-02` (MINTED-pending-confirm).
    fn gated(ctx: &Ctx<'_>, with_onoff: bool, options: u8) -> bool {
        !with_onoff && ctx.peer_onoff == Some(false) && options & OPTIONS_EXECUTE_IF_OFF == 0
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
        let with_onoff = matches!(
            command_id,
            CMD_MOVE_TO_LEVEL_ONOFF | CMD_MOVE_ONOFF | CMD_STEP_ONOFF | CMD_STOP_ONOFF
        );
        match command_id {
            CMD_MOVE_TO_LEVEL | CMD_MOVE_TO_LEVEL_ONOFF => {
                if payload.len() != 3 && payload.len() != 5 {
                    return Err(ZclStatus::MalformedCommand);
                }
                let level = payload[0];
                let trans = u16::from_le_bytes([payload[1], payload[2]]);
                let (mask, over) = if payload.len() == 5 {
                    (payload[3], payload[4])
                } else {
                    (0, 0)
                };
                if Self::gated(ctx, with_onoff, Self::temp_options(ctx, mask, over)) {
                    return Ok(HandleOutcome::no_reply());
                }
                let (min, max) = Self::envelope(ctx.store);
                if level < min || level > max {
                    return Err(ZclStatus::InvalidValue);
                }
                // A 0xffff transition falls back to device speed;
                // basics apply immediately either way.
                Self::apply_level(ctx, level, if trans == 0xffff { 0 } else { trans })?;
                if with_onoff {
                    self.pending_onoff = Some(level > min);
                }
                Ok(HandleOutcome::no_reply())
            }
            CMD_MOVE | CMD_MOVE_ONOFF => {
                if payload.len() != 2 && payload.len() != 4 {
                    return Err(ZclStatus::MalformedCommand);
                }
                let mode = payload[0];
                if mode != DIR_UP && mode != DIR_DOWN {
                    return Err(ZclStatus::InvalidField);
                }
                let (mask, over) = if payload.len() == 4 {
                    (payload[2], payload[3])
                } else {
                    (0, 0)
                };
                if Self::gated(ctx, with_onoff, Self::temp_options(ctx, mask, over)) {
                    return Ok(HandleOutcome::no_reply());
                }
                let (min, max) = Self::envelope(ctx.store);
                // Basics run continuous moves to the bound at once.
                let target = if mode == DIR_UP { max } else { min };
                Self::apply_level(ctx, target, 0)?;
                if with_onoff {
                    self.pending_onoff = Some(target > min);
                }
                Ok(HandleOutcome::no_reply())
            }
            CMD_STEP | CMD_STEP_ONOFF => {
                if payload.len() != 4 && payload.len() != 6 {
                    return Err(ZclStatus::MalformedCommand);
                }
                let mode = payload[0];
                if mode != DIR_UP && mode != DIR_DOWN {
                    return Err(ZclStatus::InvalidField);
                }
                let size = payload[1];
                let trans = u16::from_le_bytes([payload[2], payload[3]]);
                let (mask, over) = if payload.len() == 6 {
                    (payload[4], payload[5])
                } else {
                    (0, 0)
                };
                if Self::gated(ctx, with_onoff, Self::temp_options(ctx, mask, over)) {
                    return Ok(HandleOutcome::no_reply());
                }
                let (min, max) = Self::envelope(ctx.store);
                let cur = Self::level(ctx.store);
                let target = if mode == DIR_UP {
                    cur.saturating_add(size).min(max)
                } else {
                    cur.saturating_sub(size).max(min)
                };
                Self::apply_level(ctx, target, if trans == 0xffff { 0 } else { trans })?;
                if with_onoff {
                    self.pending_onoff = Some(target > min);
                }
                Ok(HandleOutcome::no_reply())
            }
            CMD_STOP | CMD_STOP_ONOFF => {
                if !payload.is_empty() && payload.len() != 2 {
                    return Err(ZclStatus::MalformedCommand);
                }
                let (mask, over) = if payload.len() == 2 {
                    (payload[0], payload[1])
                } else {
                    (0, 0)
                };
                if Self::gated(ctx, with_onoff, Self::temp_options(ctx, mask, over)) {
                    return Ok(HandleOutcome::no_reply());
                }
                // Any in-process move ends; the level holds and the
                // remaining time clears.
                Self::apply_level(ctx, Self::level(ctx.store), 0)?;
                Ok(HandleOutcome::no_reply())
            }
            _ => Err(ZclStatus::UnsupCommand),
        }
    }
}

/// Count down RemainingTime in 1/10 s steps (floor zero).
pub fn tick_100ms(store: &mut AttrStore) {
    if let Some(Value::UInt { v, .. }) = store.get(ATTR_REMAINING) {
        if v > 0 && v <= 0xffff {
            let _ = store.set_local(ATTR_REMAINING, Value::UInt { width: 2, v: v - 1 });
        }
    }
}

/// Client-side command builders (client-to-server frames).
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

    /// Encode Move to Level (mask/override appended when `Some`).
    pub fn move_to_level(
        tsn: u8,
        with_onoff: bool,
        level: u8,
        trans_100ms: u16,
        options: Option<(u8, u8)>,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let cmd = if with_onoff {
            CMD_MOVE_TO_LEVEL_ONOFF
        } else {
            CMD_MOVE_TO_LEVEL
        };
        let mut payload = [0u8; 5];
        payload[0] = level;
        payload[1..3].copy_from_slice(&trans_100ms.to_le_bytes());
        let len = match options {
            Some((mask, over)) => {
                payload[3] = mask;
                payload[4] = over;
                5
            }
            None => 3,
        };
        frame(tsn, cmd, &payload[..len], out)
    }

    /// Encode Move.
    pub fn move_cmd(
        tsn: u8,
        with_onoff: bool,
        mode: u8,
        rate: u8,
        options: Option<(u8, u8)>,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let cmd = if with_onoff { CMD_MOVE_ONOFF } else { CMD_MOVE };
        let mut payload = [0u8; 4];
        payload[0] = mode;
        payload[1] = rate;
        let len = match options {
            Some((mask, over)) => {
                payload[2] = mask;
                payload[3] = over;
                4
            }
            None => 2,
        };
        frame(tsn, cmd, &payload[..len], out)
    }

    /// Encode Step.
    pub fn step(
        tsn: u8,
        with_onoff: bool,
        mode: u8,
        size: u8,
        trans_100ms: u16,
        options: Option<(u8, u8)>,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let cmd = if with_onoff { CMD_STEP_ONOFF } else { CMD_STEP };
        let mut payload = [0u8; 6];
        payload[0] = mode;
        payload[1] = size;
        payload[2..4].copy_from_slice(&trans_100ms.to_le_bytes());
        let len = match options {
            Some((mask, over)) => {
                payload[4] = mask;
                payload[5] = over;
                6
            }
            None => 4,
        };
        frame(tsn, cmd, &payload[..len], out)
    }
}
