//! NCP half-host role: the PC drives a chip that runs the full
//! Zigbee stack plus the application endpoint.
//!
//! Where the RCP role keeps every Zigbee layer on the PC and the
//! chip is a bare 15.4 radio, the NCP role inverts the split: the
//! chip owns formation, joining, NWK/APS/ZDO/security/ZCL and the
//! lamp, while the PC commissions (form, permit, admit) and drives
//! the application (toggle, attribute reads) over the same serial
//! wire. This module is the PC side of that split ([`NcpHost`]) plus
//! a scripted chip-side model for tests ([`NcpDevice`]).
//!
//! # Envelope
//!
//! NCP frames reuse the RCP transport envelope byte-for-byte
//! ([`crate::frame`]: `SYNC | LEN | KIND | SEQ | payload | CRC16`)
//! with a disjoint KIND namespace, so one UART decoder serves both
//! roles and the universal PC runner probes the role by asking for a
//! version first (an RCP answers `0x85`, an NCP answers `0xA0`+…).
//! Fixed-shape payloads, not CBOR/`rounddance-ifc`: the firmware
//! side stays as small as the RCP one (bounded, no heap, no
//! allocator), and every class below fits the 128-octet envelope
//! with room to spare. That choice is deliberate and documented,
//! not an oversight — the ifc envelope stays available if the NCP
//! surface ever outgrows fixed shapes.
//!
//! Host→NCP (`0x20`–`0x25`): reset, form, permit, admit, toggle,
//! get-state. NCP→host (`0xA0`–`0xA4`): ready, status, joined,
//! attribute report, error. All sets are fire-and-forget at this
//! layer (idempotent by construction); the PC runner applies its
//! own wall-clock budget above and re-asks with `GetState`.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-RCP-NCP-01` (NCP frame classes), `RD-RCP-NCP-02` (host +
//! device models).

use crate::frame::{self, Decoder, Frame, FrameError, Outcome};
use crate::uart::Uart;
use core::fmt;

// Host → NCP command classes.
pub const N_RESET: u8 = 0x20;
pub const N_FORM: u8 = 0x21;
pub const N_PERMIT: u8 = 0x22;
pub const N_ADMIT: u8 = 0x23;
pub const N_TOGGLE: u8 = 0x24;
pub const N_GET_STATE: u8 = 0x25;

// NCP → host event classes.
pub const N_READY: u8 = 0xA0;
pub const N_STATUS: u8 = 0xA1;
pub const N_JOINED: u8 = 0xA2;
pub const N_ATTR: u8 = 0xA3;
pub const N_ERROR: u8 = 0xA4;

/// NCP reset modes (`N_RESET` payload byte 0).
pub const N_RESET_WARM: u8 = 0x00;
/// NCP reset modes (`N_RESET` payload byte 0).
pub const N_RESET_COLD: u8 = 0x01;

/// NCP state octet (`N_STATUS` payload byte 0).
pub const N_STATE_IDLE: u8 = 0x00;
/// NCP state octet (`N_STATUS` payload byte 0).
pub const N_STATE_FORMED: u8 = 0x01;
/// NCP state octet (`N_STATUS` payload byte 0).
pub const N_STATE_PERMIT_OPEN: u8 = 0x02;

/// NCP error codes (`N_ERROR` payload).
pub const N_BAD_COMMAND: u8 = 0x01;
/// NCP error codes (`N_ERROR` payload).
pub const N_BAD_CHANNEL: u8 = 0x02;
/// NCP error codes (`N_ERROR` payload).
pub const N_NOT_READY: u8 = 0x03;
/// NCP error codes (`N_ERROR` payload).
pub const N_NO_SUCH_DEVICE: u8 = 0x04;
/// NCP error codes (`N_ERROR` payload).
pub const N_TABLE_FULL: u8 = 0x05;

/// NCP firmware version the scripted device reports.
pub const NCP_FW_VERSION: u8 = 0x01;

/// Largest NCP device table (admitted EUI→short pairs).
pub const NCP_MAX_DEVICES: usize = 8;
/// Pending-event queue depth on both models.
pub const NCP_QUEUE_DEPTH: usize = 8;

/// NCP codec errors: every decoder is fallible, oversize or unknown
/// input is an error, never a truncation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NcpError {
    /// Frame layer rejected the transfer.
    Frame(FrameError),
    /// Unknown class octet.
    UnknownKind(u8),
    /// Payload shorter than the class minimum.
    Truncated,
    /// Payload longer than the class allows.
    TooLong,
    /// Enumerated value outside its range.
    BadValue,
    /// UART FIFO full (backpressure, never silent loss).
    UartFull,
    /// Event queue full (upper layer must drain).
    QueueFull,
    /// Channel outside 11–26.
    InvalidChannel,
}

impl fmt::Display for NcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(e) => write!(f, "NCP frame error: {e}"),
            Self::UnknownKind(k) => write!(f, "unknown NCP class {k:#04x}"),
            Self::Truncated => f.write_str("NCP payload shorter than its class minimum"),
            Self::TooLong => f.write_str("NCP payload longer than its class allows"),
            Self::BadValue => f.write_str("NCP enumerated value out of range"),
            Self::UartFull => f.write_str("NCP UART FIFO full"),
            Self::QueueFull => f.write_str("NCP event queue full"),
            Self::InvalidChannel => f.write_str("NCP channel outside 11-26"),
        }
    }
}

impl core::error::Error for NcpError {}

impl From<FrameError> for NcpError {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

impl From<crate::RcpError> for NcpError {
    fn from(_: crate::RcpError) -> Self {
        Self::UartFull
    }
}

/// Host → NCP command (owned, bounded, no heap).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NcpCommand {
    /// Reset the NCP; `cold` also clears its network state.
    Reset {
        /// True = cold (clear network state), false = warm.
        cold: bool,
    },
    /// Form a network on `channel`/`pan` at `power_dbm`.
    Form {
        /// 802.15.4 channel 11–26 (checked by the device).
        channel: u8,
        /// PAN identifier.
        pan: u16,
        /// TX power in dBm (standing +10 dBm cap enforced both sides).
        power_dbm: i8,
    },
    /// Open the permit-joining window for `window_secs` seconds.
    Permit {
        /// Window length in seconds.
        window_secs: u16,
    },
    /// Admit one joiner identity (the chip answers its assoc-req).
    Admit {
        /// Joiner EUI-64 (display order, as provisioned).
        eui: [u8; 8],
        /// Short address to assign.
        short: u16,
    },
    /// Toggle the lamp on `short` (the chip runs the ZCL exchange).
    Toggle {
        /// Destination short address.
        short: u16,
    },
    /// Ask for the current [`NcpEvent::Status`].
    GetState,
}

impl NcpCommand {
    /// Class octet.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Reset { .. } => N_RESET,
            Self::Form { .. } => N_FORM,
            Self::Permit { .. } => N_PERMIT,
            Self::Admit { .. } => N_ADMIT,
            Self::Toggle { .. } => N_TOGGLE,
            Self::GetState => N_GET_STATE,
        }
    }

    /// Encode with sequence `seq` into `out`; returns bytes written.
    pub fn encode(&self, seq: u8, out: &mut [u8]) -> Result<usize, NcpError> {
        let mut payload = [0u8; 16];
        let len = match self {
            Self::Reset { cold } => {
                payload[0] = if *cold { N_RESET_COLD } else { N_RESET_WARM };
                1
            }
            Self::Form {
                channel,
                pan,
                power_dbm,
            } => {
                payload[0] = *channel;
                payload[1..3].copy_from_slice(&pan.to_le_bytes());
                payload[3] = *power_dbm as u8;
                4
            }
            Self::Permit { window_secs } => {
                payload[0..2].copy_from_slice(&window_secs.to_le_bytes());
                2
            }
            Self::Admit { eui, short } => {
                payload[0..8].copy_from_slice(eui);
                payload[8..10].copy_from_slice(&short.to_le_bytes());
                10
            }
            Self::Toggle { short } => {
                payload[0..2].copy_from_slice(&short.to_le_bytes());
                2
            }
            Self::GetState => 0,
        };
        Ok(frame::encode(self.kind(), seq, &payload[..len], out)?)
    }

    /// Decode a host→NCP frame (device side + host loopback checks).
    pub fn decode(frame: &Frame) -> Result<Self, NcpError> {
        let p = frame.payload_bytes();
        match frame.kind {
            N_RESET => {
                if p.len() != 1 {
                    return Err(NcpError::Truncated);
                }
                match p[0] {
                    N_RESET_WARM => Ok(Self::Reset { cold: false }),
                    N_RESET_COLD => Ok(Self::Reset { cold: true }),
                    _ => Err(NcpError::BadValue),
                }
            }
            N_FORM => {
                if p.len() != 4 {
                    return Err(NcpError::Truncated);
                }
                Ok(Self::Form {
                    channel: p[0],
                    pan: u16::from_le_bytes([p[1], p[2]]),
                    power_dbm: p[3] as i8,
                })
            }
            N_PERMIT => {
                if p.len() != 2 {
                    return Err(NcpError::Truncated);
                }
                Ok(Self::Permit {
                    window_secs: u16::from_le_bytes([p[0], p[1]]),
                })
            }
            N_ADMIT => {
                if p.len() != 10 {
                    return Err(NcpError::Truncated);
                }
                let mut eui = [0u8; 8];
                eui.copy_from_slice(&p[..8]);
                Ok(Self::Admit {
                    eui,
                    short: u16::from_le_bytes([p[8], p[9]]),
                })
            }
            N_TOGGLE => {
                if p.len() != 2 {
                    return Err(NcpError::Truncated);
                }
                Ok(Self::Toggle {
                    short: u16::from_le_bytes([p[0], p[1]]),
                })
            }
            N_GET_STATE => {
                if !p.is_empty() {
                    return Err(NcpError::TooLong);
                }
                Ok(Self::GetState)
            }
            k => Err(NcpError::UnknownKind(k)),
        }
    }
}

/// NCP → host event (owned, bounded, no heap).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NcpEvent {
    /// NCP (re)started and ready.
    Ready {
        /// Firmware version octet.
        fw_version: u8,
    },
    /// Current network state (answers every mutating command and
    /// [`NcpCommand::GetState`]).
    Status {
        /// One of `N_STATE_*`.
        state: u8,
        /// Admitted devices known so far.
        joined: u8,
    },
    /// A device joined (admit accepted its assoc + announce parsed).
    Joined {
        /// Assigned short address.
        short: u16,
        /// Joiner EUI-64.
        eui: [u8; 8],
    },
    /// Attribute report (answers [`NcpCommand::Toggle`]: the lamp
    /// value after the chip ran the ZCL exchange).
    Attr {
        /// Source short address.
        short: u16,
        /// Cluster identifier.
        cluster: u16,
        /// Reported value octet (On/Off: 0/1).
        value: u8,
    },
    /// Chip-side rejection (see `N_*` codes).
    Error {
        /// Error code.
        code: u8,
    },
}

impl NcpEvent {
    /// Class octet.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Ready { .. } => N_READY,
            Self::Status { .. } => N_STATUS,
            Self::Joined { .. } => N_JOINED,
            Self::Attr { .. } => N_ATTR,
            Self::Error { .. } => N_ERROR,
        }
    }

    /// Encode with event sequence `seq` into `out`.
    pub fn encode(&self, seq: u8, out: &mut [u8]) -> Result<usize, NcpError> {
        let mut payload = [0u8; 16];
        let len = match self {
            Self::Ready { fw_version } => {
                payload[0] = *fw_version;
                1
            }
            Self::Status { state, joined } => {
                payload[0] = *state;
                payload[1] = *joined;
                2
            }
            Self::Joined { short, eui } => {
                payload[0..2].copy_from_slice(&short.to_le_bytes());
                payload[2..10].copy_from_slice(eui);
                10
            }
            Self::Attr {
                short,
                cluster,
                value,
            } => {
                payload[0..2].copy_from_slice(&short.to_le_bytes());
                payload[2..4].copy_from_slice(&cluster.to_le_bytes());
                payload[4] = *value;
                5
            }
            Self::Error { code } => {
                payload[0] = *code;
                1
            }
        };
        Ok(frame::encode(self.kind(), seq, &payload[..len], out)?)
    }

    /// Decode an NCP→host frame.
    pub fn decode(frame: &Frame) -> Result<Self, NcpError> {
        let p = frame.payload_bytes();
        match frame.kind {
            N_READY => {
                if p.len() != 1 {
                    return Err(NcpError::Truncated);
                }
                Ok(Self::Ready { fw_version: p[0] })
            }
            N_STATUS => {
                if p.len() != 2 {
                    return Err(NcpError::Truncated);
                }
                Ok(Self::Status {
                    state: p[0],
                    joined: p[1],
                })
            }
            N_JOINED => {
                if p.len() != 10 {
                    return Err(NcpError::Truncated);
                }
                let mut eui = [0u8; 8];
                eui.copy_from_slice(&p[2..10]);
                Ok(Self::Joined {
                    short: u16::from_le_bytes([p[0], p[1]]),
                    eui,
                })
            }
            N_ATTR => {
                if p.len() != 5 {
                    return Err(NcpError::Truncated);
                }
                Ok(Self::Attr {
                    short: u16::from_le_bytes([p[0], p[1]]),
                    cluster: u16::from_le_bytes([p[2], p[3]]),
                    value: p[4],
                })
            }
            N_ERROR => {
                if p.len() != 1 {
                    return Err(NcpError::Truncated);
                }
                Ok(Self::Error { code: p[0] })
            }
            k => Err(NcpError::UnknownKind(k)),
        }
    }
}

/// PC-side NCP driver: fire-and-forget commands over any [`Uart`],
/// polled events, injected clock for pacing (no wall clock, no
/// allocator — scripted runs replay exactly).
pub struct NcpHost<U: Uart> {
    uart: U,
    now_us: u64,
    next_seq: u8,
    decoder: Decoder,
    events: [Option<NcpEvent>; NCP_QUEUE_DEPTH],
    events_len: usize,
    dropped: u32,
}

impl<U: Uart> NcpHost<U> {
    /// New host: no I/O performed. Call [`NcpHost::reset`] to open
    /// the handshake before use.
    #[must_use]
    pub fn new(uart: U) -> Self {
        Self {
            uart,
            now_us: 0,
            next_seq: 0,
            decoder: Decoder::new(),
            events: [None, None, None, None, None, None, None, None],
            events_len: 0,
            dropped: 0,
        }
    }

    /// Injected-clock time in microseconds.
    #[must_use]
    pub const fn now_us(&self) -> u64 {
        self.now_us
    }

    /// Move the injected clock forward (saturates, never wraps).
    pub fn advance(&mut self, delta_us: u64) {
        self.now_us = self.now_us.saturating_add(delta_us);
    }

    /// Borrow the UART (test harnesses move bytes through this).
    pub const fn uart(&self) -> &U {
        &self.uart
    }

    /// Mutably borrow the UART.
    pub fn uart_mut(&mut self) -> &mut U {
        &mut self.uart
    }

    /// Malformed runs dropped so far (diagnostic).
    #[must_use]
    pub const fn dropped(&self) -> u32 {
        self.dropped
    }

    fn send(&mut self, cmd: &NcpCommand) -> Result<(), NcpError> {
        let mut wire = [0u8; 64];
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        match cmd.encode(seq, &mut wire) {
            Ok(n) => self
                .uart
                .write_bytes(&wire[..n])
                .map_err(|_| NcpError::UartFull),
            Err(e) => Err(e),
        }
    }

    /// Open the handshake (answers with [`NcpEvent::Ready`]).
    pub fn reset(&mut self, cold: bool) -> Result<(), NcpError> {
        self.send(&NcpCommand::Reset { cold })
    }

    /// Form the chip's network.
    pub fn form(&mut self, channel: u8, pan: u16, power_dbm: i8) -> Result<(), NcpError> {
        self.send(&NcpCommand::Form {
            channel,
            pan,
            power_dbm,
        })
    }

    /// Open the chip's permit window.
    pub fn permit(&mut self, window_secs: u16) -> Result<(), NcpError> {
        self.send(&NcpCommand::Permit { window_secs })
    }

    /// Admit one joiner identity.
    pub fn admit(&mut self, eui: [u8; 8], short: u16) -> Result<(), NcpError> {
        self.send(&NcpCommand::Admit { eui, short })
    }

    /// Toggle the lamp on `short` (answered by [`NcpEvent::Attr`]).
    pub fn toggle(&mut self, short: u16) -> Result<(), NcpError> {
        self.send(&NcpCommand::Toggle { short })
    }

    /// Ask for the current status.
    pub fn get_state(&mut self) -> Result<(), NcpError> {
        self.send(&NcpCommand::GetState)
    }

    /// Pump inbound bytes into the event queue. Call after moving
    /// peer bytes and after advancing the clock.
    pub fn poll(&mut self) {
        while let Some(b) = self.uart.read_byte() {
            match self.decoder.push_byte(b) {
                Some(Outcome::Frame(f)) => match NcpEvent::decode(&f) {
                    Ok(ev) => {
                        if self.events_len < self.events.len() {
                            self.events[self.events_len] = Some(ev);
                            self.events_len += 1;
                        } else {
                            self.dropped = self.dropped.saturating_add(1);
                        }
                    }
                    Err(_) => self.dropped = self.dropped.saturating_add(1),
                },
                Some(Outcome::Dropped(_)) => self.dropped = self.dropped.saturating_add(1),
                None => {}
            }
        }
    }

    /// Take the oldest pending event, if any.
    pub fn poll_event(&mut self) -> Option<NcpEvent> {
        if self.events_len == 0 {
            return None;
        }
        let out = self.events[0].take();
        self.events.rotate_left(1);
        self.events_len -= 1;
        out
    }

    /// Pending event count.
    #[must_use]
    pub const fn pending(&self) -> usize {
        self.events_len
    }
}

/// Scripted NCP firmware model: the chip side of the wire for
/// tests. Applies commands to a small network-state model (formed,
/// permit, admitted devices, one lamp per device) and answers
/// exactly where the half-host firmware would: [`NcpEvent::Ready`]
/// after reset, [`NcpEvent::Status`] after every mutating command,
/// [`NcpEvent::Joined`] on admit, [`NcpEvent::Attr`] on toggle. A
/// contract pin, not firmware: timing is immediate and every fault
/// the host must survive is scriptable (bad commands, unknown
/// devices, full tables).
pub struct NcpDevice {
    decoder: Decoder,
    inbound: crate::uart::LoopPipe<512>,
    outbound: crate::uart::LoopPipe<512>,
    event_seq: u8,
    formed: bool,
    channel: Option<u8>,
    pan: Option<u16>,
    permit_open: bool,
    devices: [Option<([u8; 8], u16)>; NCP_MAX_DEVICES],
    lamps: [bool; NCP_MAX_DEVICES],
}

impl NcpDevice {
    /// Fresh chip: unformed, no devices, lamp off everywhere.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            decoder: Decoder::new(),
            inbound: crate::uart::LoopPipe::new(),
            outbound: crate::uart::LoopPipe::new(),
            event_seq: 0,
            formed: false,
            channel: None,
            pan: None,
            permit_open: false,
            devices: [None; NCP_MAX_DEVICES],
            lamps: [false; NCP_MAX_DEVICES],
        }
    }

    /// True once [`NcpCommand::Form`] was accepted.
    #[must_use]
    pub const fn formed(&self) -> bool {
        self.formed
    }

    /// Lamp value for `short`, if admitted.
    #[must_use]
    pub fn lamp(&self, short: u16) -> Option<bool> {
        self.devices
            .iter()
            .position(|d| matches!(d, Some((_, s)) if *s == short))
            .map(|i| self.lamps[i])
    }

    /// Feed host-side bytes into the chip (the harness moves them
    /// from the host UART's outbound FIFO).
    pub fn push_host_bytes(&mut self, bytes: &[u8]) {
        for b in bytes {
            if !self.inbound.push(*b) {
                break;
            }
        }
    }

    /// Drain chip-side bytes toward the host; returns bytes moved.
    pub fn take_ncp_bytes(&mut self, out: &mut [u8]) -> usize {
        let mut n = 0;
        while n < out.len() {
            match self.outbound.pop() {
                Some(b) => {
                    out[n] = b;
                    n += 1;
                }
                None => break,
            }
        }
        n
    }

    fn emit(&mut self, ev: &NcpEvent) {
        let mut wire = [0u8; 64];
        let seq = self.event_seq;
        self.event_seq = self.event_seq.wrapping_add(1);
        let n = ev.encode(seq, &mut wire).unwrap_or(0);
        for b in &wire[..n] {
            if !self.outbound.push(*b) {
                break;
            }
        }
    }

    fn status(&mut self) {
        let state = if !self.formed {
            N_STATE_IDLE
        } else if self.permit_open {
            N_STATE_PERMIT_OPEN
        } else {
            N_STATE_FORMED
        };
        let joined = self.devices.iter().filter(|d| d.is_some()).count() as u8;
        self.emit(&NcpEvent::Status { state, joined });
    }

    fn handle(&mut self, frame: &Frame) {
        let cmd = match NcpCommand::decode(frame) {
            Ok(c) => c,
            Err(_) => {
                self.emit(&NcpEvent::Error {
                    code: N_BAD_COMMAND,
                });
                return;
            }
        };
        match cmd {
            NcpCommand::Reset { cold } => {
                if cold {
                    self.formed = false;
                    self.channel = None;
                    self.pan = None;
                    self.permit_open = false;
                    self.devices = [None; NCP_MAX_DEVICES];
                    self.lamps = [false; NCP_MAX_DEVICES];
                }
                self.emit(&NcpEvent::Ready {
                    fw_version: NCP_FW_VERSION,
                });
            }
            NcpCommand::Form {
                channel,
                pan,
                power_dbm,
            } => {
                if !(11..=26).contains(&channel) {
                    self.emit(&NcpEvent::Error {
                        code: N_BAD_CHANNEL,
                    });
                    return;
                }
                if power_dbm > crate::MAX_TX_POWER_DBM {
                    self.emit(&NcpEvent::Error {
                        code: N_BAD_COMMAND,
                    });
                    return;
                }
                self.formed = true;
                self.channel = Some(channel);
                self.pan = Some(pan);
                self.status();
            }
            NcpCommand::Permit { .. } => {
                if !self.formed {
                    self.emit(&NcpEvent::Error { code: N_NOT_READY });
                    return;
                }
                self.permit_open = true;
                self.status();
            }
            NcpCommand::Admit { eui, short } => {
                if !self.formed {
                    self.emit(&NcpEvent::Error { code: N_NOT_READY });
                    return;
                }
                if self.devices.contains(&Some((eui, short))) {
                    self.emit(&NcpEvent::Joined { short, eui });
                    return;
                }
                match self.devices.iter_mut().find(|d| d.is_none()) {
                    Some(slot) => {
                        *slot = Some((eui, short));
                        self.emit(&NcpEvent::Joined { short, eui });
                    }
                    None => self.emit(&NcpEvent::Error { code: N_TABLE_FULL }),
                }
            }
            NcpCommand::Toggle { short } => {
                match self
                    .devices
                    .iter()
                    .position(|d| matches!(d, Some((_, s)) if *s == short))
                {
                    Some(i) => {
                        self.lamps[i] = !self.lamps[i];
                        let value = u8::from(self.lamps[i]);
                        self.emit(&NcpEvent::Attr {
                            short,
                            cluster: 0x0006,
                            value,
                        });
                    }
                    None => self.emit(&NcpEvent::Error {
                        code: N_NO_SUCH_DEVICE,
                    }),
                }
            }
            NcpCommand::GetState => self.status(),
        }
    }

    /// Process all queued host bytes and emit due events.
    pub fn poll(&mut self) {
        while let Some(b) = self.inbound.pop() {
            match self.decoder.push_byte(b) {
                Some(Outcome::Frame(f)) => self.handle(&f),
                Some(Outcome::Dropped(_)) => self.emit(&NcpEvent::Error {
                    code: N_BAD_COMMAND,
                }),
                None => {}
            }
        }
    }
}

impl Default for NcpDevice {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::MAX_FRAME_BYTES;

    fn roundtrip_cmd(cmd: &NcpCommand) {
        let mut wire = [0u8; MAX_FRAME_BYTES];
        let n = cmd.encode(0x33, &mut wire).unwrap();
        let mut dec = Decoder::new();
        let mut out = None;
        for b in &wire[..n] {
            if let Some(o) = dec.push_byte(*b) {
                out = Some(o);
            }
        }
        match out {
            Some(Outcome::Frame(f)) => {
                assert_eq!(f.kind, cmd.kind());
                assert_eq!(f.seq, 0x33);
                assert_eq!(&NcpCommand::decode(&f).unwrap(), cmd);
            }
            other => panic!("expected frame, got {other:?}"),
        }
    }

    fn roundtrip_ev(ev: &NcpEvent) {
        let mut wire = [0u8; MAX_FRAME_BYTES];
        let n = ev.encode(0x07, &mut wire).unwrap();
        let mut dec = Decoder::new();
        let mut out = None;
        for b in &wire[..n] {
            if let Some(o) = dec.push_byte(*b) {
                out = Some(o);
            }
        }
        match out {
            Some(Outcome::Frame(f)) => assert_eq!(&NcpEvent::decode(&f).unwrap(), ev),
            other => panic!("expected frame, got {other:?}"),
        }
    }

    #[test]
    fn all_classes_round_trip() {
        roundtrip_cmd(&NcpCommand::Reset { cold: true });
        roundtrip_cmd(&NcpCommand::Reset { cold: false });
        roundtrip_cmd(&NcpCommand::Form {
            channel: 15,
            pan: 0x1a2b,
            power_dbm: 10,
        });
        roundtrip_cmd(&NcpCommand::Permit { window_secs: 60 });
        roundtrip_cmd(&NcpCommand::Admit {
            eui: [1, 2, 3, 4, 5, 6, 7, 8],
            short: 0x0001,
        });
        roundtrip_cmd(&NcpCommand::Toggle { short: 0x0001 });
        roundtrip_cmd(&NcpCommand::GetState);
        roundtrip_ev(&NcpEvent::Ready { fw_version: 1 });
        roundtrip_ev(&NcpEvent::Status {
            state: N_STATE_PERMIT_OPEN,
            joined: 2,
        });
        roundtrip_ev(&NcpEvent::Joined {
            short: 0x0001,
            eui: [8, 7, 6, 5, 4, 3, 2, 1],
        });
        roundtrip_ev(&NcpEvent::Attr {
            short: 0x0001,
            cluster: 0x0006,
            value: 1,
        });
        roundtrip_ev(&NcpEvent::Error {
            code: N_NO_SUCH_DEVICE,
        });
    }

    #[test]
    fn malformed_rejected() {
        let mut wire = [0u8; MAX_FRAME_BYTES];
        let n = frame::encode(N_FORM, 0, &[15], &mut wire).unwrap();
        let mut dec = Decoder::new();
        let mut frame = None;
        for b in &wire[..n] {
            if let Some(Outcome::Frame(f)) = dec.push_byte(*b) {
                frame = Some(f);
            }
        }
        assert_eq!(
            NcpCommand::decode(&frame.unwrap()),
            Err(NcpError::Truncated)
        );
        let n = frame::encode(0x2F, 0, &[], &mut wire).unwrap();
        let mut dec = Decoder::new();
        let mut frame = None;
        for b in &wire[..n] {
            if let Some(Outcome::Frame(f)) = dec.push_byte(*b) {
                frame = Some(f);
            }
        }
        assert_eq!(
            NcpCommand::decode(&frame.unwrap()),
            Err(NcpError::UnknownKind(0x2F))
        );
    }

    #[test]
    fn device_guards_and_toggle() {
        use crate::uart::HostSide;
        let mut host = NcpHost::new(HostSide::new());
        let mut dev = NcpDevice::new();
        let mut buf = [0u8; 256];
        let mut pump = |host: &mut NcpHost<HostSide>, dev: &mut NcpDevice| {
            let mut n = 0;
            while let Some(b) = host.uart_mut().outbound.pop() {
                if n >= buf.len() {
                    break;
                }
                buf[n] = b;
                n += 1;
            }
            dev.push_host_bytes(&buf[..n]);
            dev.poll();
            let m = dev.take_ncp_bytes(&mut buf);
            for b in &buf[..m] {
                assert!(host.uart_mut().inbound.push(*b));
            }
            host.poll();
        };
        // Permit before form is refused, never latched.
        host.permit(60).unwrap();
        pump(&mut host, &mut dev);
        assert_eq!(
            host.poll_event().unwrap(),
            NcpEvent::Error { code: N_NOT_READY }
        );
        assert!(!dev.formed());
        // Bad channel refused, then form lands.
        host.form(30, 0x1a2b, 10).unwrap();
        pump(&mut host, &mut dev);
        assert_eq!(
            host.poll_event().unwrap(),
            NcpEvent::Error {
                code: N_BAD_CHANNEL
            }
        );
        host.form(15, 0x1a2b, 10).unwrap();
        pump(&mut host, &mut dev);
        assert_eq!(
            host.poll_event().unwrap(),
            NcpEvent::Status {
                state: N_STATE_FORMED,
                joined: 0
            }
        );
        assert!(dev.formed());
        // Unknown toggle refused; admit → joined; toggle flips 0→1→0.
        host.toggle(0x0001).unwrap();
        pump(&mut host, &mut dev);
        assert_eq!(
            host.poll_event().unwrap(),
            NcpEvent::Error {
                code: N_NO_SUCH_DEVICE
            }
        );
        let eui = [1, 2, 3, 4, 5, 6, 7, 8];
        host.admit(eui, 0x0001).unwrap();
        pump(&mut host, &mut dev);
        assert_eq!(
            host.poll_event().unwrap(),
            NcpEvent::Joined { short: 1, eui }
        );
        host.toggle(0x0001).unwrap();
        pump(&mut host, &mut dev);
        assert_eq!(
            host.poll_event().unwrap(),
            NcpEvent::Attr {
                short: 1,
                cluster: 0x0006,
                value: 1,
            }
        );
        assert_eq!(dev.lamp(0x0001), Some(true));
        host.toggle(0x0001).unwrap();
        pump(&mut host, &mut dev);
        assert_eq!(
            host.poll_event().unwrap(),
            NcpEvent::Attr {
                short: 1,
                cluster: 0x0006,
                value: 0,
            }
        );
        assert_eq!(dev.lamp(0x0001), Some(false));
    }
}
