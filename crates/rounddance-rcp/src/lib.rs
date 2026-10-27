//! S3+H2 OTBR path: the Zigbee stack runs on the S3 host, the H2 is
//! a bare 15.4 RCP across a UART.
//!
//! This crate is the host side of that split: UART transport framing
//! ([`frame`]), the RCP command/response classes ([`cmd`]), the UART
//! seam ([`uart`]), the host-side driver implementing the MAC SAP
//! traits ([`driver`]), and a scripted H2-firmware model for tests
//! ([`peer`]).
//!
//! # Documented topology (lab wiring, no hardware touched here)
//!
//! ```text
//! S3 host (stack)                  H2 (15.4 RCP firmware)
//!   GPIO18 (TX)  ──────────────────►  GPIO23 (RX)
//!   GPIO17 (RX)  ◄──────────────────  GPIO24 (TX)
//!   GPIO7        ──────────────────►  EN (reset hold)
//!   GPIO8        ──────────────────►  GPIO9 (BOOT select)
//! ```
//!
//! * UART: 460800 baud, 8N1, raw RCP frames (see [`frame`]).
//! * Roles: the S3 owns PAN formation, addressing, retries, and all
//!   Zigbee layers; the H2 owns the 15.4 PHY (CSMA, auto-ACK,
//!   energy detect, frame radiate/receive) and nothing above it.
//! * The v0 mapping is deliberately thin: SAP MSDUs ride as RCP
//!   payloads verbatim. MAC header build/parse (cf.
//!   `rounddance-hal-esp`'s adapter) and multi-channel retune are
//!   deferred follow-ups, recorded in `docs/otbr/protocol.md`.
//!
//! # Crate choice (not an `otbr` submodule)
//!
//! No OpenThread/OTBR stack is ported here — the S3 runs the
//! rounddance stack, and the H2 firmware is out of scope for this
//! crate (the [`peer`] model pins the wire contract both sides
//! implement). What this crate owns is a radio-transport adapter,
//! the same seam shape as `rounddance-hal-esp`'s `Driver`, so it is
//! named for the seam (`rcp`), not for a stack it does not contain.
//!
//! # Design rules
//!
//! * `no_std`, `#![forbid(unsafe_code)]`, bounded + fallible +
//!   accountable (D5, `SCOPE.md` §2): fixed arrays, explicit queue
//!   depths, [`RcpError`] instead of panics or silent truncation.
//! * Poll-based throughout (no callbacks, no locks): the driver and
//!   the peer both advance through explicit `poll` calls on an
//!   injected clock, so sim runs stay decision-deterministic
//!   (`SCOPE.md` §8).
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-RCP-01`…`RD-RCP-11` (`REQUIREMENTS.md` wave-18 section).
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

use core::fmt;

pub mod cmd;
pub mod driver;
pub mod frame;
pub mod peer;
pub mod uart;

pub use cmd::{CmdError, Command, Event, TxOutcome};
pub use driver::{RcpDriver, RcpStats, TraceEvent, CMD_TIMEOUT_US, MAX_RETRIES, TX_SLOTS};
pub use frame::{Decoder, DropReason, Frame, FrameError, Outcome};
pub use peer::EmulatedRcp;
pub use uart::{HostSide, LoopPipe, Uart};

/// Standing lab TX-power ceiling in dBm (wave-11 policy: +10 dBm on
/// ALL units until human clears it). Both the driver
/// ([`driver::RcpDriver::set_tx_power`]) and the emulated firmware
/// ([`peer::EmulatedRcp`]) enforce it.
pub const MAX_TX_POWER_DBM: i8 = 10;

/// H2 RCP firmware version the emulated peer reports.
pub const RCP_FW_VERSION: u8 = 0x01;

/// S3-side UART wiring (documented topology; board code owns these).
pub const S3_UART_TX_GPIO: u8 = 18;
/// S3-side UART wiring (documented topology; board code owns these).
pub const S3_UART_RX_GPIO: u8 = 17;
/// S3-side UART wiring (documented topology; board code owns these).
pub const S3_RESET_GPIO: u8 = 7;
/// S3-side UART wiring (documented topology; board code owns these).
pub const S3_BOOT_GPIO: u8 = 8;
/// H2-side UART wiring (documented topology; firmware owns these).
pub const H2_UART_RX_GPIO: u8 = 23;
/// H2-side UART wiring (documented topology; firmware owns these).
pub const H2_UART_TX_GPIO: u8 = 24;
/// H2-side UART wiring (documented topology; firmware owns these).
pub const H2_BOOT_GPIO: u8 = 9;
/// RCP UART baud rate (documented topology).
pub const RCP_UART_BAUD: u32 = 460_800;

/// Crate-level errors (transport + provisioning, outside the SAP
/// taxonomy the driver maps into [`rounddance_mac_sap::MacError`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RcpError {
    /// Frame layer rejected the transfer.
    Frame(FrameError),
    /// Command/event codec rejected the payload.
    Cmd(CmdError),
    /// Scripted FIFO full (backpressure, never silent loss).
    UartFull,
    /// Requested power exceeds [`MAX_TX_POWER_DBM`]; nothing sent.
    PowerCapExceeded {
        /// The rejected request in dBm.
        requested: i8,
    },
    /// Channel outside 11–26.
    InvalidChannel,
}

impl fmt::Display for RcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(e) => write!(f, "RCP frame error: {e}"),
            Self::Cmd(e) => write!(f, "RCP codec error: {e}"),
            Self::UartFull => f.write_str("RCP UART FIFO full"),
            Self::PowerCapExceeded { requested } => {
                write!(
                    f,
                    "tx power {requested} dBm exceeds +{MAX_TX_POWER_DBM} dBm cap"
                )
            }
            Self::InvalidChannel => f.write_str("RCP channel outside 11-26"),
        }
    }
}

impl core::error::Error for RcpError {}

impl From<FrameError> for RcpError {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

impl From<CmdError> for RcpError {
    fn from(e: CmdError) -> Self {
        Self::Cmd(e)
    }
}

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-rcp"
}
