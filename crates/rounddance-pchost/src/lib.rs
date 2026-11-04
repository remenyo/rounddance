//! PC host runner: the radio/half-host roles the PC plays against
//! RCP or NCP firmware over a serial UART.
//!
//! This is a **host-only `std` tool crate** (like `lab-arbitrator`):
//! it never builds for `no_std` or `wasm32-unknown-unknown`, and the
//! CI wasm job excludes it for exactly that reason. The protocol
//! crates it drives (`rounddance-rcp`, `rounddance-hal-esp`, …)
//! stay `no_std` + `forbid(unsafe_code)`; the only `unsafe` here is
//! confined to [`serial`] (raw POSIX serial + DTR), each block with
//! a `SAFETY` comment on the `hal-esp` precedent.
//!
//! # Roles
//!
//! * **RCP radio role** ([`PcRunner`]): the PC owns the full Zigbee
//!   stack (`CoordinatorApp` / `JoinerApp` over
//!   [`RcpDriver`]) and the chip is a
//!   bare 15.4 radio. [`SerialUart`] is the
//!   production UART; tests run the same runner over `HostSide` +
//!   `EmulatedRcp`.
//! * **NCP half-host role** ([`NcpRunner`]): the chip owns the stack
//!   and the application endpoint; the PC commissions (form, permit,
//!   admit) and drives the lamp (toggle, attribute reports) through
//!   [`NcpHost`].
//!
//! # Target universality
//!
//! The same runner speaks identical classes to H2, C6, and S31 RCP
//! firmware: [`PcRunner::probe_info`] reports the firmware's version,
//! capabilities, EUI, and radio-target name (from the `CAPS_TARGET_*`
//! bit, if set — a generic/scripted peer names nothing and still
//! works). Standalone images (`rd-coord`, `rd-router`, `rd-joiner`,
//! `rd-coord-s31`) keep booting when the PC is detached; nothing
//! here changes them.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-RCP-NCP-03` (PC runner + probe), `RD-RCP-NCP-04` (NCP drive).
//!
//! The only `unsafe` in this crate is confined to [`serial`]
//! (POSIX serial + DTR ioctls), each block carrying a `SAFETY`
//! comment on the `hal-esp` precedent; everything else is safe.
#![deny(unsafe_code)]

use rounddance_mac_sap::{Channel, MacMgmtSap as _};
use rounddance_rcp::{NcpEvent, NcpHost, RcpDriver, RcpError, Uart, VersionInfo, CMD_TIMEOUT_US};

pub mod serial;

pub use serial::SerialUart;

/// What [`PcRunner::probe_info`] learned from the firmware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeInfo {
    /// Firmware version octet.
    pub fw_version: u8,
    /// Wire-protocol version octet.
    pub proto_version: u8,
    /// Capability bitmask.
    pub caps: u16,
    /// 15.4 EUI-64 of the radio.
    pub eui: [u8; 8],
    /// Radio-target name from the `CAPS_TARGET_*` bit, if exactly one
    /// is set (`None` = generic/scripted peer — still fully usable).
    pub target: Option<&'static str>,
}

impl From<VersionInfo> for ProbeInfo {
    fn from(v: VersionInfo) -> Self {
        Self {
            fw_version: v.fw_version,
            proto_version: v.proto_version,
            caps: v.caps,
            eui: v.eui,
            target: rounddance_rcp::cmd::caps_target_name(v.caps),
        }
    }
}

/// PC-side errors: transport plus runner policy (bounded, no heap).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunnerError {
    /// RCP transport/codec fault.
    Rcp(RcpError),
    /// NCP codec/transport fault.
    Ncp(rounddance_rcp::NcpError),
    /// MAC SAP refusal (backpressure, addressing, shape).
    Mac(rounddance_mac_sap::MacError),
    /// Handshake budget exhausted (peer never answered `Ready`).
    NotReady,
    /// Probe answered with an unexpected target (`--target` gate).
    WrongTarget,
    /// Wall-clock budget exhausted while waiting for an event.
    Timeout,
}

impl core::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rcp(e) => write!(f, "RCP fault: {e}"),
            Self::Ncp(e) => write!(f, "NCP fault: {e}"),
            Self::Mac(e) => write!(f, "MAC refusal: {e}"),
            Self::NotReady => f.write_str("RCP peer never answered Ready"),
            Self::WrongTarget => f.write_str("firmware target is not the expected one"),
            Self::Timeout => f.write_str("wall-clock budget exhausted"),
        }
    }
}

impl std::error::Error for RunnerError {}

impl From<RcpError> for RunnerError {
    fn from(e: RcpError) -> Self {
        Self::Rcp(e)
    }
}

impl From<rounddance_rcp::NcpError> for RunnerError {
    fn from(e: rounddance_rcp::NcpError) -> Self {
        Self::Ncp(e)
    }
}

impl From<rounddance_mac_sap::MacError> for RunnerError {
    fn from(e: rounddance_mac_sap::MacError) -> Self {
        Self::Mac(e)
    }
}

use core::fmt::Write as _;

/// Log one air frame as `<prefix> <hex…>` (same discipline as
/// `hal-esp`'s `log_air`: full bytes, bounded 512-octet line).
pub fn log_air(prefix: &str, bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut line = [0u8; 512];
    let mut n = 0usize;
    for &b in prefix.as_bytes() {
        if n >= line.len() {
            break;
        }
        line[n] = b;
        n += 1;
    }
    for &b in bytes {
        if n + 3 > line.len() {
            break;
        }
        line[n] = b' ';
        line[n + 1] = HEX[(b >> 4) as usize];
        line[n + 2] = HEX[(b & 0x0f) as usize];
        n += 3;
    }
    let mut s = String::new();
    let _ = write!(
        s,
        "{}",
        core::str::from_utf8(&line[..n]).unwrap_or("<non-utf8>")
    );
    s
}

/// PC-side RCP radio role: owns an [`RcpDriver`] over any [`Uart`],
/// advances it on a wall clock, and exposes the probe + provision
/// steps the `rd-pchost` binary and the integration tests share.
///
/// The type is generic over the UART so the exact same runner runs
/// against [`SerialUart`] on hardware and
/// `HostSide` + `EmulatedRcp` in tests: `U` moves the bytes, the
/// caller pumps the far end (the OS on hardware, the harness in
/// tests).
pub struct PcRunner<U: Uart> {
    driver: RcpDriver<U>,
    wall_last: Option<std::time::Instant>,
}

impl<U: Uart> PcRunner<U> {
    /// New runner: unprovisioned, no I/O performed.
    pub fn new(uart: U) -> Self {
        Self {
            driver: RcpDriver::new(uart),
            wall_last: None,
        }
    }

    /// Borrow the RCP driver (SAP calls + app wiring go through
    /// this).
    pub fn driver(&self) -> &RcpDriver<U> {
        &self.driver
    }

    /// Mutably borrow the RCP driver.
    pub fn driver_mut(&mut self) -> &mut RcpDriver<U> {
        &mut self.driver
    }

    /// Move the injected clock forward by wall elapsed time since
    /// the last call (first call arms the clock and advances zero).
    /// The driver never reads the wall clock itself — this is the
    /// only place wall time enters, keeping scripted runs exact.
    pub fn advance_wall(&mut self) {
        let now = std::time::Instant::now();
        if let Some(last) = self.wall_last {
            let dt = now.saturating_duration_since(last);
            self.driver
                .advance(dt.as_micros().min(u128::from(u64::MAX)) as u64);
        }
        self.wall_last = Some(now);
    }

    /// Manual advance (tests + paced scripts): move the injected
    /// clock by `delta_us` and poll once.
    pub fn advance(&mut self, delta_us: u64) {
        self.driver.advance(delta_us);
        self.driver.poll();
    }

    /// Ask the firmware for its version/caps/EUI (the report lands
    /// in [`RcpDriver::last_version`] on the next poll).
    pub fn query_version(&mut self) {
        self.driver.query_version();
    }

    /// Latest probe report, if one has arrived.
    #[must_use]
    pub fn probe_info(&self) -> Option<ProbeInfo> {
        self.driver.last_version().map(ProbeInfo::from)
    }

    /// Provision the radio path: channel, PAN, short, extended
    /// address, TX power, and the filtered + HW auto-ACK receive
    /// mode (the association posture — the Trust Center only
    /// transports after an ACKed association response).
    pub fn provision(
        &mut self,
        channel: u8,
        pan: u16,
        short: u16,
        ext: u64,
        power_dbm: i8,
    ) -> Result<(), RunnerError> {
        let ch = Channel::new(channel).map_err(|_| RunnerError::Timeout)?;
        self.driver.set_channel(ch).map_err(RunnerError::Mac)?;
        self.driver.set_pan_id(pan);
        self.driver.set_short_addr(short);
        self.driver.set_extended_addr(ext);
        self.driver.set_tx_power(power_dbm)?;
        self.driver.set_promiscuous_mode(false);
        Ok(())
    }

    /// True once a `Ready` has arrived and no handshake is open.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.driver.ready()
    }
}

/// PC-side NCP half-host role: owns an [`NcpHost`] over any
/// [`Uart`], advances it on a wall clock, and exposes the
/// commission + drive steps the binary and tests share.
pub struct NcpRunner<U: Uart> {
    host: NcpHost<U>,
    wall_last: Option<std::time::Instant>,
}

impl<U: Uart> NcpRunner<U> {
    /// New runner: no I/O performed.
    pub fn new(uart: U) -> Self {
        Self {
            host: NcpHost::new(uart),
            wall_last: None,
        }
    }

    /// Borrow the NCP host.
    pub fn host(&self) -> &NcpHost<U> {
        &self.host
    }

    /// Mutably borrow the NCP host.
    pub fn host_mut(&mut self) -> &mut NcpHost<U> {
        &mut self.host
    }

    /// Wall-clock advance (same discipline as
    /// [`PcRunner::advance_wall`]).
    pub fn advance_wall(&mut self) {
        let now = std::time::Instant::now();
        if let Some(last) = self.wall_last {
            let dt = now.saturating_duration_since(last);
            self.host
                .advance(dt.as_micros().min(u128::from(u64::MAX)) as u64);
        }
        self.wall_last = Some(now);
        self.host.poll();
    }

    /// Manual advance (tests): move the clock and poll once.
    pub fn advance(&mut self, delta_us: u64) {
        self.host.advance(delta_us);
        self.host.poll();
    }

    /// Commission the chip's network in one call: reset (cold) →
    /// form → permit. Each step only *sends*; the caller pumps the
    /// far end between steps (harness) or lets the OS move bytes
    /// (hardware), then drains [`NcpRunner::events`].
    pub fn commission(
        &mut self,
        channel: u8,
        pan: u16,
        power_dbm: i8,
        window_secs: u16,
    ) -> Result<(), RunnerError> {
        self.host.reset(true)?;
        self.host.form(channel, pan, power_dbm)?;
        self.host.permit(window_secs)?;
        Ok(())
    }

    /// Drain all pending NCP events (oldest first).
    pub fn events(&mut self) -> Vec<NcpEvent> {
        let mut out = Vec::new();
        while let Some(ev) = self.host.poll_event() {
            out.push(ev);
        }
        out
    }
}

/// Wall-clock wait helper for the binary: until `ready` or
/// `budget_ms` elapses, `advance_wall` + `poll` every 2 ms.
/// `pump` moves far-end bytes where the harness owns the medium
/// (no-op on a real serial port — the OS moves them).
pub fn wait_ready<U: Uart>(
    runner: &mut PcRunner<U>,
    budget_ms: u64,
    mut pump: impl FnMut(),
) -> Result<(), RunnerError> {
    let start = std::time::Instant::now();
    while !runner.ready() {
        if start.elapsed().as_millis() as u64 > budget_ms {
            return Err(RunnerError::NotReady);
        }
        pump();
        runner.advance_wall();
        runner.driver_mut().poll();
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    Ok(())
}

/// Wall-clock wait for a version report (same discipline as
/// [`wait_ready`).
pub fn wait_version<U: Uart>(
    runner: &mut PcRunner<U>,
    budget_ms: u64,
    mut pump: impl FnMut(),
) -> Result<ProbeInfo, RunnerError> {
    runner.query_version();
    let start = std::time::Instant::now();
    loop {
        pump();
        runner.advance_wall();
        runner.driver_mut().poll();
        if let Some(info) = runner.probe_info() {
            return Ok(info);
        }
        if start.elapsed().as_millis() as u64 > budget_ms {
            return Err(RunnerError::Timeout);
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// Unused-import guard: `CMD_TIMEOUT_US` documents the single-flight
/// budget the wall loops above are paced against.
#[allow(dead_code)]
const _CMD_BUDGET_US: u64 = CMD_TIMEOUT_US;
