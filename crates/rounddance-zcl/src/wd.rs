//! IAS WD (Warning Device) server cluster (0x0502): siren/strobe
//! warnings with preemption, duty-cycle quantization, and squawk.
//!
//! Paraphrase-level model of doc `07-5123-08` §8.4 (cluster id +
//! MaxDuration anchor p0550-L12525-L12532, received table
//! p0550-L12534-L12536, preemption p0551-L12540-L12541, warning
//! payload p0551-L12543-L12547, warning modes p0551-L12551,
//! strobe values p0551-L12555-L12556, siren levels
//! p0552-L12557-L12560, duration rule p0552-L12561-L12562, duty
//! cycle p0552-L12564-L12570, strobe levels p0552-L12571-L12575,
//! squawk (no effect while active) p0552-L12576-L12577, squawk
//! payload p0553-L12580, squawk mode p0553-L12582-L12585, squawk
//! strobe p0553-L12586-L12589, squawk levels p0553-L12590-L12593,
//! no generated commands p0553-L12594-L12595). All wording here is
//! paraphrase (D1).
//!
//! Requirement IDs `07-5123-08-842-01..03` corpus-mined and reused;
//! `07-5123-08-841-01` repo-minted, MINTED-pending-confirm.

use crate::attrs::{access, AttrDef, AttrStore, ATTR_CLUSTER_REVISION};
use crate::behavior::{AppEvent, Behavior, Ctx, EventQueue, HandleOutcome};
use crate::cluster::{ClusterDef, ClusterRole, CmdDef};
use crate::frame::Header;
use crate::types::{DataType, Value};
use crate::{Error, ZclStatus};

/// Cluster identifier.
///
/// Requirement `07-5123-08-841-01` (MINTED-pending-confirm).
pub const CLUSTER_ID: u16 = 0x0502;
/// Implemented specification revision (rev table tip).
///
/// Requirement `07-5123-08-841-01` (MINTED-pending-confirm).
pub const REVISION: u16 = 2;

/// MaxDuration attribute: siren cap in seconds (default 240).
pub const ATTR_MAX_DURATION: u16 = 0x0000;
/// Default MaxDuration value.
pub const DEFAULT_MAX_DURATION: u16 = 240;

/// Received: Start Warning.
pub const CMD_START_WARNING: u8 = 0x00;
/// Received: Squawk.
pub const CMD_SQUAWK: u8 = 0x01;

/// Warning mode: stop (no warning).
pub const WARN_STOP: u8 = 0x00;
/// Warning mode: burglar.
pub const WARN_BURGLAR: u8 = 0x01;
/// Warning mode: fire.
pub const WARN_FIRE: u8 = 0x02;
/// Warning mode: emergency.
pub const WARN_EMERGENCY: u8 = 0x03;
/// Warning mode: police panic.
pub const WARN_POLICE_PANIC: u8 = 0x04;
/// Warning mode: fire panic.
pub const WARN_FIRE_PANIC: u8 = 0x05;
/// Warning mode: emergency (medical) panic.
pub const WARN_MEDICAL_PANIC: u8 = 0x06;

/// Strobe: none.
pub const STROBE_NONE: u8 = 0x00;
/// Strobe: in parallel with the warning.
pub const STROBE_PARALLEL: u8 = 0x01;

/// Squawk mode: system-armed notification sound.
pub const SQUAWK_ARMED: u8 = 0x00;
/// Squawk mode: system-disarmed notification sound.
pub const SQUAWK_DISARMED: u8 = 0x01;

/// Siren intensities carried here (every named level; the
/// at-least-one-level rule holds by construction).
///
/// Requirement `07-5123-08-842-02` (corpus-mined).
pub const SIREN_LEVELS: [u8; 4] = [0, 1, 2, 3];
/// Strobe intensities carried here (every named level).
///
/// Requirement `07-5123-08-842-02` (corpus-mined).
pub const STROBE_LEVELS: [u8; 4] = [0, 1, 2, 3];

/// Server attribute table, ascending.
pub static SERVER_ATTRS: &[AttrDef] = &[
    AttrDef {
        id: ATTR_MAX_DURATION,
        datatype: DataType::UInt(2).as_u8(),
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
        id: CMD_START_WARNING,
        name: "start-warning",
    },
    CmdDef {
        id: CMD_SQUAWK,
        name: "squawk",
    },
];

/// Server generated commands: none.
pub static SERVER_TX: &[CmdDef] = &[];

/// Server definition.
pub struct ServerDef;
impl ClusterDef for ServerDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "ias-wd-server"
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

/// Build a fresh server store (default MaxDuration).
///
/// Requirement `07-5123-08-841-01` (MINTED-pending-confirm).
pub fn server_store() -> Result<AttrStore, Error> {
    let mut store = AttrStore::new(None);
    store.add(
        SERVER_ATTRS[0],
        Value::UInt {
            width: 2,
            v: DEFAULT_MAX_DURATION as u64,
        },
    )?;
    store.add_globals(REVISION)?;
    Ok(store)
}

/// Live MaxDuration cap (missing attribute reads as default).
pub fn max_duration(store: &AttrStore) -> u16 {
    match store.get(ATTR_MAX_DURATION) {
        Some(Value::UInt { v, .. }) => v.min(0xffff) as u16,
        _ => DEFAULT_MAX_DURATION,
    }
}

/// Decoded Start Warning command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartWarning {
    /// Warning mode (4-bit, `WARN_*`).
    pub mode: u8,
    /// Strobe selector (2-bit, `STROBE_*`).
    pub strobe: u8,
    /// Siren intensity (2-bit).
    pub siren: u8,
    /// Requested duration in seconds (ignored for stop/stop).
    pub duration_s: u16,
    /// Strobe duty cycle, percent (quantized on apply).
    pub duty: u8,
    /// Strobe intensity (`STROBE_LEVELS` member).
    pub level: u8,
}

/// Split the combined flags octet into (mode, strobe, siren).
#[must_use]
pub const fn split_flags(flags: u8) -> (u8, u8, u8) {
    (flags & 0x0f, (flags >> 4) & 0x03, (flags >> 6) & 0x03)
}

/// Pack (mode, strobe, siren) into the combined flags octet.
#[must_use]
pub const fn pack_flags(mode: u8, strobe: u8, siren: u8) -> u8 {
    (mode & 0x0f) | ((strobe & 0x03) << 4) | ((siren & 0x03) << 6)
}

/// Decode a Start Warning body (5 octets).
///
/// Requirement `07-5123-08-841-01` (MINTED-pending-confirm).
pub fn decode_start_warning(buf: &[u8]) -> Result<StartWarning, Error> {
    if buf.len() != 5 {
        return Err(Error::Truncated);
    }
    let (mode, strobe, siren) = split_flags(buf[0]);
    if mode > WARN_MEDICAL_PANIC || strobe > STROBE_PARALLEL {
        return Err(Error::InvalidValue(buf[0]));
    }
    if !SIREN_LEVELS.contains(&siren) || !STROBE_LEVELS.contains(&buf[4]) {
        return Err(Error::InvalidValue(buf[4]));
    }
    Ok(StartWarning {
        mode,
        strobe,
        siren,
        duration_s: u16::from_le_bytes([buf[1], buf[2]]),
        duty: buf[3],
        level: buf[4],
    })
}

/// Encode a Start Warning body (5 octets).
pub fn encode_start_warning(w: &StartWarning, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 5 {
        return Err(Error::BufferTooSmall);
    }
    out[0] = pack_flags(w.mode, w.strobe, w.siren);
    out[1..3].copy_from_slice(&w.duration_s.to_le_bytes());
    out[3] = w.duty;
    out[4] = w.level;
    Ok(5)
}

/// Decoded Squawk command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Squawk {
    /// Squawk mode (4-bit, `SQUAWK_*`).
    pub mode: u8,
    /// Whether the strobe blinks in parallel.
    pub strobe: bool,
    /// Squawk intensity (2-bit).
    pub level: u8,
}

/// Decode a Squawk body (1 octet).
///
/// Requirement `07-5123-08-841-01` (MINTED-pending-confirm).
pub fn decode_squawk(buf: &[u8]) -> Result<Squawk, Error> {
    if buf.len() != 1 {
        return Err(Error::Truncated);
    }
    let mode = buf[0] & 0x0f;
    if mode > SQUAWK_DISARMED {
        return Err(Error::InvalidValue(buf[0]));
    }
    if buf[0] & 0x10 != 0 {
        // Reserved bit set: not a squawk this build sounds.
        return Err(Error::InvalidValue(buf[0]));
    }
    Ok(Squawk {
        mode,
        strobe: buf[0] & 0x20 != 0,
        level: (buf[0] >> 6) & 0x03,
    })
}

/// Encode a Squawk body (1 octet).
pub fn encode_squawk(s: &Squawk, out: &mut [u8]) -> Result<usize, Error> {
    if out.is_empty() {
        return Err(Error::BufferTooSmall);
    }
    out[0] = (s.mode & 0x0f) | (u8::from(s.strobe) << 5) | ((s.level & 0x03) << 6);
    Ok(1)
}

/// Round an arbitrary duty value to the nearest valid step
/// (0–100 in steps of 10; ties round up).
///
/// Requirement `07-5123-08-842-03` (corpus-mined).
#[must_use]
pub const fn quantize_duty(duty: u8) -> u8 {
    let q = (duty as u16 + 5) / 10;
    if q > 10 {
        100
    } else {
        (q * 10) as u8
    }
}

/// Currently sounding warning, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActiveWarning {
    /// Warning mode in effect.
    pub mode: u8,
    /// Strobe selector in effect.
    pub strobe: u8,
    /// Siren intensity in effect.
    pub siren: u8,
    /// Seconds left on the clock.
    pub remaining_s: u16,
    /// Quantized strobe duty cycle.
    pub duty: u8,
    /// Strobe intensity in effect.
    pub level: u8,
}

/// Server behavior: warning preemption, duration clamp, squawk
/// gating, and expiry.
///
/// Requirement `07-5123-08-842-01` (a new start always ends any
/// still-current effect, corpus-mined).
pub struct ServerBehavior {
    active: Option<ActiveWarning>,
    squawks: u32,
}

impl Default for ServerBehavior {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBehavior {
    /// Fresh behavior: silent.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            active: None,
            squawks: 0,
        }
    }

    /// Currently sounding warning, if any.
    #[must_use]
    pub const fn active(&self) -> Option<ActiveWarning> {
        self.active
    }

    /// Squawks sounded since reset (diagnostic counter).
    #[must_use]
    pub const fn squawks(&self) -> u32 {
        self.squawks
    }

    fn stop(&mut self, events: &mut EventQueue) {
        self.active = None;
        events.push(AppEvent::StateChanged {
            cluster: CLUSTER_ID,
            from: 1,
            to: 0,
        });
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
            CMD_START_WARNING => {
                let w = decode_start_warning(payload).map_err(|_| ZclStatus::MalformedCommand)?;
                if w.mode == WARN_STOP && w.strobe == STROBE_NONE {
                    // Stop/stop: duration ignored, siren silenced.
                    self.stop(ctx.events);
                    return Ok(HandleOutcome::no_reply());
                }
                // Any new start preempts the still-current effect.
                let cap = max_duration(ctx.store);
                let duration = if cap == 0 {
                    w.duration_s
                } else {
                    w.duration_s.min(cap)
                };
                self.active = Some(ActiveWarning {
                    mode: w.mode,
                    strobe: w.strobe,
                    siren: w.siren,
                    remaining_s: duration,
                    duty: quantize_duty(w.duty),
                    level: w.level,
                });
                ctx.events.push(AppEvent::StateChanged {
                    cluster: CLUSTER_ID,
                    from: 0,
                    to: 1,
                });
                Ok(HandleOutcome::no_reply())
            }
            CMD_SQUAWK => {
                let s = decode_squawk(payload).map_err(|_| ZclStatus::MalformedCommand)?;
                if self.active.is_some() {
                    // Squawks never interrupt a live warning.
                    return Ok(HandleOutcome::no_reply());
                }
                let _ = s;
                self.squawks = self.squawks.saturating_add(1);
                ctx.events.push(AppEvent::StateChanged {
                    cluster: CLUSTER_ID,
                    from: 0,
                    to: 3,
                });
                Ok(HandleOutcome::no_reply())
            }
            _ => Err(ZclStatus::UnsupCommand),
        }
    }
}

/// Advance the warning clock by `elapsed_s` caller seconds; expiry
/// silences the device.
///
/// Requirement `07-5123-08-842-01` (durations run out on their
/// own, corpus-mined reading of the duration rule).
pub fn tick_1s(behavior: &mut ServerBehavior, events: &mut EventQueue, elapsed_s: u16) {
    let Some(active) = behavior.active else {
        return;
    };
    if elapsed_s >= active.remaining_s {
        behavior.stop(events);
    } else {
        behavior.active = Some(ActiveWarning {
            remaining_s: active.remaining_s - elapsed_s,
            ..active
        });
    }
}
