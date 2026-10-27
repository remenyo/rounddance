//! RCP command/response classes over [`crate::frame`].
//!
//! Host (S3) → RCP (H2) commands (`0x01`–`0x08`): reset, channel,
//! TX power, PAN/short/extended addressing, 15.4 TX, energy scan.
//! RCP → host events (`0x80`–`0x84`): ready, TX confirm, received
//! frame, energy result, error. Every class has a fixed minimal
//! payload shape; oversize or unknown input is an error, never a
//! truncation.
//!
//! Wire IDs are rounddance constructions (no spec corpus covers the
//! S3+H2 UART), documented in `docs/otbr/protocol.md`.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-RCP-03` (command classes), `RD-RCP-04` (event classes).

use crate::frame::{self, Frame, FrameError, MAX_RCP_PAYLOAD};
use core::fmt;

/// Largest 15.4 PSDU a TX/RX event carries.
pub const MAX_PSDU: usize = 127;

// Host → RCP command classes.
pub const K_RESET: u8 = 0x01;
pub const K_SET_CHANNEL: u8 = 0x02;
pub const K_SET_TX_POWER: u8 = 0x03;
pub const K_SET_PAN_ID: u8 = 0x04;
pub const K_SET_SHORT_ADDR: u8 = 0x05;
pub const K_SET_EXT_ADDR: u8 = 0x06;
pub const K_TX_FRAME: u8 = 0x07;
pub const K_ENERGY_SCAN: u8 = 0x08;

// RCP → host event classes.
pub const K_READY: u8 = 0x80;
pub const K_TX_CONFIRM: u8 = 0x81;
pub const K_RX_FRAME: u8 = 0x82;
pub const K_ENERGY_RESULT: u8 = 0x83;
pub const K_ERROR: u8 = 0x84;

/// TX-frame flags octet: bit 0 selects the inter-PAN path (same bit
/// on RX events marks which queue the frame arrived on).
pub const FLAG_INTER_PAN: u8 = 1 << 0;

/// Peer error codes (`K_ERROR` payload).
pub const E_BAD_COMMAND: u8 = 0x01;
pub const E_BAD_CHANNEL: u8 = 0x02;
pub const E_POWER_CAPPED: u8 = 0x03;
pub const E_NOT_READY: u8 = 0x04;

/// Reset modes (`K_RESET` payload byte 0).
pub const RESET_WARM: u8 = 0x00;
pub const RESET_COLD: u8 = 0x01;

/// Over-air TX outcome reported by the RCP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxOutcome {
    /// Frame radiated (ACK status, if any, is a MAC-layer concern).
    Delivered = 0,
    /// Medium stayed busy past the RCP's CSMA budget.
    ChannelBusy = 1,
    /// No acknowledgement / no confirm within the RCP budget.
    NoAck = 2,
}

impl TxOutcome {
    /// Decode a status octet; unknown values are [`CmdError::BadValue`].
    pub fn from_u8(v: u8) -> Result<Self, CmdError> {
        match v {
            0 => Ok(Self::Delivered),
            1 => Ok(Self::ChannelBusy),
            2 => Ok(Self::NoAck),
            _ => Err(CmdError::BadValue),
        }
    }

    /// Status octet.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Command/event codec errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmdError {
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
}

impl fmt::Display for CmdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(e) => write!(f, "RCP frame error: {e}"),
            Self::UnknownKind(k) => write!(f, "unknown RCP class {k:#04x}"),
            Self::Truncated => f.write_str("RCP payload shorter than its class minimum"),
            Self::TooLong => f.write_str("RCP payload longer than its class allows"),
            Self::BadValue => f.write_str("RCP enumerated value out of range"),
        }
    }
}

impl core::error::Error for CmdError {}

impl From<FrameError> for CmdError {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

/// Host → RCP command (owned, bounded, no heap).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Reset the RCP; `cold` also clears its addressing state.
    Reset {
        /// True = cold (clear addressing), false = warm.
        cold: bool,
    },
    /// Tune to a 2.4 GHz 802.15.4 channel (11–26, checked by driver).
    SetChannel {
        /// Channel number.
        channel: u8,
    },
    /// TX power in dBm (standing +10 dBm cap enforced by driver).
    SetTxPower {
        /// Requested power.
        dbm: i8,
    },
    /// PAN identifier for subsequent frames.
    SetPanId {
        /// PAN ID.
        pan: u16,
    },
    /// Short address for subsequent frames.
    SetShortAddr {
        /// Short address.
        addr: u16,
    },
    /// Extended (IEEE) address for subsequent frames.
    SetExtAddr {
        /// Extended address.
        addr: u64,
    },
    /// Radiate one 15.4 PSDU (SAP MSDU in the v0 mapping).
    TxFrame {
        /// True = inter-PAN path.
        inter_pan: bool,
        /// Live PSDU length.
        len: u8,
        /// PSDU bytes (first `len` live).
        psdu: [u8; MAX_PSDU],
    },
    /// Energy-detect scan on one channel.
    EnergyScan {
        /// Channel number.
        channel: u8,
    },
}

impl Command {
    /// Class octet.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Reset { .. } => K_RESET,
            Self::SetChannel { .. } => K_SET_CHANNEL,
            Self::SetTxPower { .. } => K_SET_TX_POWER,
            Self::SetPanId { .. } => K_SET_PAN_ID,
            Self::SetShortAddr { .. } => K_SET_SHORT_ADDR,
            Self::SetExtAddr { .. } => K_SET_EXT_ADDR,
            Self::TxFrame { .. } => K_TX_FRAME,
            Self::EnergyScan { .. } => K_ENERGY_SCAN,
        }
    }

    /// Encode with sequence `seq` into `out`; returns bytes written.
    pub fn encode(&self, seq: u8, out: &mut [u8]) -> Result<usize, CmdError> {
        let mut payload = [0u8; MAX_RCP_PAYLOAD];
        let len = match self {
            Self::Reset { cold } => {
                payload[0] = if *cold { RESET_COLD } else { RESET_WARM };
                1
            }
            Self::SetChannel { channel } => {
                payload[0] = *channel;
                1
            }
            Self::SetTxPower { dbm } => {
                payload[0] = *dbm as u8;
                1
            }
            Self::SetPanId { pan } => {
                payload[0..2].copy_from_slice(&pan.to_le_bytes());
                2
            }
            Self::SetShortAddr { addr } => {
                payload[0..2].copy_from_slice(&addr.to_le_bytes());
                2
            }
            Self::SetExtAddr { addr } => {
                payload[0..8].copy_from_slice(&addr.to_le_bytes());
                8
            }
            Self::TxFrame {
                inter_pan,
                len,
                psdu,
            } => {
                if *len as usize > MAX_PSDU {
                    return Err(CmdError::TooLong);
                }
                payload[0] = if *inter_pan { FLAG_INTER_PAN } else { 0 };
                payload[1..1 + *len as usize].copy_from_slice(&psdu[..*len as usize]);
                1 + *len as usize
            }
            Self::EnergyScan { channel } => {
                payload[0] = *channel;
                1
            }
        };
        Ok(frame::encode(self.kind(), seq, &payload[..len], out)?)
    }

    /// Decode a host→RCP frame (peer side + driver loopback checks).
    pub fn decode(frame: &Frame) -> Result<Self, CmdError> {
        let p = frame.payload_bytes();
        match frame.kind {
            K_RESET => {
                if p.len() != 1 {
                    return Err(CmdError::Truncated);
                }
                match p[0] {
                    RESET_WARM => Ok(Self::Reset { cold: false }),
                    RESET_COLD => Ok(Self::Reset { cold: true }),
                    _ => Err(CmdError::BadValue),
                }
            }
            K_SET_CHANNEL => {
                if p.len() != 1 {
                    return Err(CmdError::Truncated);
                }
                Ok(Self::SetChannel { channel: p[0] })
            }
            K_SET_TX_POWER => {
                if p.len() != 1 {
                    return Err(CmdError::Truncated);
                }
                Ok(Self::SetTxPower { dbm: p[0] as i8 })
            }
            K_SET_PAN_ID => {
                if p.len() != 2 {
                    return Err(CmdError::Truncated);
                }
                Ok(Self::SetPanId {
                    pan: u16::from_le_bytes([p[0], p[1]]),
                })
            }
            K_SET_SHORT_ADDR => {
                if p.len() != 2 {
                    return Err(CmdError::Truncated);
                }
                Ok(Self::SetShortAddr {
                    addr: u16::from_le_bytes([p[0], p[1]]),
                })
            }
            K_SET_EXT_ADDR => {
                if p.len() != 8 {
                    return Err(CmdError::Truncated);
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&p[..8]);
                Ok(Self::SetExtAddr {
                    addr: u64::from_le_bytes(b),
                })
            }
            K_TX_FRAME => {
                if p.is_empty() {
                    return Err(CmdError::Truncated);
                }
                if p.len() - 1 > MAX_PSDU {
                    return Err(CmdError::TooLong);
                }
                let mut psdu = [0u8; MAX_PSDU];
                psdu[..p.len() - 1].copy_from_slice(&p[1..]);
                Ok(Self::TxFrame {
                    inter_pan: p[0] & FLAG_INTER_PAN != 0,
                    len: (p.len() - 1) as u8,
                    psdu,
                })
            }
            K_ENERGY_SCAN => {
                if p.len() != 1 {
                    return Err(CmdError::Truncated);
                }
                Ok(Self::EnergyScan { channel: p[0] })
            }
            k => Err(CmdError::UnknownKind(k)),
        }
    }
}

/// RCP → host event (owned, bounded, no heap).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// RCP (re)started and ready; answers a reset handshake.
    Ready {
        /// Firmware version octet.
        fw_version: u8,
    },
    /// One TX transaction finished; `seq` echoes the command.
    TxConfirm {
        /// Echoed command sequence.
        seq: u8,
        /// Outcome.
        status: TxOutcome,
    },
    /// One frame arrived off air.
    RxFrame {
        /// True = inter-PAN path.
        inter_pan: bool,
        /// RSSI in dBm.
        rssi: i8,
        /// Link quality 0–255.
        lqi: u8,
        /// Live PSDU length.
        len: u8,
        /// PSDU bytes (first `len` live).
        psdu: [u8; MAX_PSDU],
    },
    /// Energy-scan result.
    EnergyResult {
        /// Scanned channel.
        channel: u8,
        /// Energy 0–255 (higher = more energy).
        energy: u8,
    },
    /// Peer-side rejection (see `E_*` codes).
    Error {
        /// Error code.
        code: u8,
    },
}

impl Event {
    /// Class octet.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Ready { .. } => K_READY,
            Self::TxConfirm { .. } => K_TX_CONFIRM,
            Self::RxFrame { .. } => K_RX_FRAME,
            Self::EnergyResult { .. } => K_ENERGY_RESULT,
            Self::Error { .. } => K_ERROR,
        }
    }

    /// Encode with event sequence `seq` into `out`.
    pub fn encode(&self, seq: u8, out: &mut [u8]) -> Result<usize, CmdError> {
        let mut payload = [0u8; MAX_RCP_PAYLOAD];
        let len = match self {
            Self::Ready { fw_version } => {
                payload[0] = *fw_version;
                1
            }
            Self::TxConfirm { seq, status } => {
                payload[0] = *seq;
                payload[1] = status.as_u8();
                2
            }
            Self::RxFrame {
                inter_pan,
                rssi,
                lqi,
                len,
                psdu,
            } => {
                if *len as usize > MAX_PSDU {
                    return Err(CmdError::TooLong);
                }
                payload[0] = if *inter_pan { FLAG_INTER_PAN } else { 0 };
                payload[1] = *rssi as u8;
                payload[2] = *lqi;
                payload[3..3 + *len as usize].copy_from_slice(&psdu[..*len as usize]);
                3 + *len as usize
            }
            Self::EnergyResult { channel, energy } => {
                payload[0] = *channel;
                payload[1] = *energy;
                2
            }
            Self::Error { code } => {
                payload[0] = *code;
                1
            }
        };
        Ok(frame::encode(self.kind(), seq, &payload[..len], out)?)
    }

    /// Decode an RCP→host frame.
    pub fn decode(frame: &Frame) -> Result<Self, CmdError> {
        let p = frame.payload_bytes();
        match frame.kind {
            K_READY => {
                if p.len() != 1 {
                    return Err(CmdError::Truncated);
                }
                Ok(Self::Ready { fw_version: p[0] })
            }
            K_TX_CONFIRM => {
                if p.len() != 2 {
                    return Err(CmdError::Truncated);
                }
                Ok(Self::TxConfirm {
                    seq: p[0],
                    status: TxOutcome::from_u8(p[1])?,
                })
            }
            K_RX_FRAME => {
                if p.len() < 3 {
                    return Err(CmdError::Truncated);
                }
                if p.len() - 3 > MAX_PSDU {
                    return Err(CmdError::TooLong);
                }
                let mut psdu = [0u8; MAX_PSDU];
                psdu[..p.len() - 3].copy_from_slice(&p[3..]);
                Ok(Self::RxFrame {
                    inter_pan: p[0] & FLAG_INTER_PAN != 0,
                    rssi: p[1] as i8,
                    lqi: p[2],
                    len: (p.len() - 3) as u8,
                    psdu,
                })
            }
            K_ENERGY_RESULT => {
                if p.len() != 2 {
                    return Err(CmdError::Truncated);
                }
                Ok(Self::EnergyResult {
                    channel: p[0],
                    energy: p[1],
                })
            }
            K_ERROR => {
                if p.len() != 1 {
                    return Err(CmdError::Truncated);
                }
                Ok(Self::Error { code: p[0] })
            }
            k => Err(CmdError::UnknownKind(k)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(cmd: &Command) {
        let mut wire = [0u8; 256];
        let n = cmd.encode(0x33, &mut wire).unwrap();
        let mut dec = crate::frame::Decoder::new();
        let mut out = None;
        for b in &wire[..n] {
            if let Some(o) = dec.push_byte(*b) {
                out = Some(o);
            }
        }
        match out {
            Some(crate::frame::Outcome::Frame(f)) => {
                assert_eq!(f.kind, cmd.kind());
                assert_eq!(f.seq, 0x33);
                assert_eq!(&Command::decode(&f).unwrap(), cmd);
            }
            other => panic!("expected frame, got {other:?}"),
        }
    }

    fn roundtrip_event(ev: &Event) {
        let mut wire = [0u8; 256];
        let n = ev.encode(0x07, &mut wire).unwrap();
        let mut dec = crate::frame::Decoder::new();
        let mut out = None;
        for b in &wire[..n] {
            if let Some(o) = dec.push_byte(*b) {
                out = Some(o);
            }
        }
        match out {
            Some(crate::frame::Outcome::Frame(f)) => {
                assert_eq!(&Event::decode(&f).unwrap(), ev);
            }
            other => panic!("expected frame, got {other:?}"),
        }
    }

    #[test]
    fn command_vectors() {
        roundtrip(&Command::Reset { cold: true });
        roundtrip(&Command::Reset { cold: false });
        roundtrip(&Command::SetChannel { channel: 15 });
        roundtrip(&Command::SetTxPower { dbm: -3 });
        roundtrip(&Command::SetPanId { pan: 0x1a2b });
        roundtrip(&Command::SetShortAddr { addr: 0x0001 });
        roundtrip(&Command::SetExtAddr {
            addr: 0x0200_0000_0000_0002,
        });
        let mut psdu = [0u8; MAX_PSDU];
        psdu[0] = 0xDE;
        psdu[1] = 0xAD;
        roundtrip(&Command::TxFrame {
            inter_pan: false,
            len: 2,
            psdu,
        });
        roundtrip(&Command::TxFrame {
            inter_pan: true,
            len: 0,
            psdu: [0u8; MAX_PSDU],
        });
        roundtrip(&Command::EnergyScan { channel: 26 });
    }

    #[test]
    fn event_vectors() {
        roundtrip_event(&Event::Ready { fw_version: 1 });
        roundtrip_event(&Event::TxConfirm {
            seq: 0x41,
            status: TxOutcome::Delivered,
        });
        roundtrip_event(&Event::TxConfirm {
            seq: 0x42,
            status: TxOutcome::ChannelBusy,
        });
        let mut psdu = [0u8; MAX_PSDU];
        psdu[..3].copy_from_slice(&[1, 2, 3]);
        roundtrip_event(&Event::RxFrame {
            inter_pan: false,
            rssi: -50,
            lqi: 200,
            len: 3,
            psdu,
        });
        roundtrip_event(&Event::EnergyResult {
            channel: 15,
            energy: 116,
        });
        roundtrip_event(&Event::Error {
            code: E_POWER_CAPPED,
        });
    }

    #[test]
    fn malformed_command_rejected() {
        let mut wire = [0u8; 256];
        // Reset with an empty payload.
        let n = crate::frame::encode(K_RESET, 0, &[], &mut wire).unwrap();
        let mut dec = crate::frame::Decoder::new();
        let mut frame = None;
        for b in &wire[..n] {
            if let Some(crate::frame::Outcome::Frame(f)) = dec.push_byte(*b) {
                frame = Some(f);
            }
        }
        assert_eq!(Command::decode(&frame.unwrap()), Err(CmdError::Truncated));
        // Unknown class.
        let n = crate::frame::encode(0x5A, 0, &[1], &mut wire).unwrap();
        let mut dec = crate::frame::Decoder::new();
        let mut frame = None;
        for b in &wire[..n] {
            if let Some(crate::frame::Outcome::Frame(f)) = dec.push_byte(*b) {
                frame = Some(f);
            }
        }
        assert_eq!(
            Command::decode(&frame.unwrap()),
            Err(CmdError::UnknownKind(0x5A))
        );
        // Bad TX status value.
        let n = crate::frame::encode(K_TX_CONFIRM, 0, &[9, 7], &mut wire).unwrap();
        let mut dec = crate::frame::Decoder::new();
        let mut frame = None;
        for b in &wire[..n] {
            if let Some(crate::frame::Outcome::Frame(f)) = dec.push_byte(*b) {
                frame = Some(f);
            }
        }
        assert_eq!(Event::decode(&frame.unwrap()), Err(CmdError::BadValue));
    }
}
