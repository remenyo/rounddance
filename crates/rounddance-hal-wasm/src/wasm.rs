//! Guest-side radio: [`WasmDriver`] adapts any [`HostOps`] to the
//! MAC-SAP [`rounddance_hal_esp::Driver`] seam.
//!
//! On-device the host is [`crate::ffi::FfiHost`]; host tests
//! use [`MockHost`](crate::mock::MockHost). Either way
//! [`EspAdapter`](rounddance_hal_esp::EspAdapter) and everything above
//! it — `CoordinatorApp`, `JoinerApp`, `RouterDevice` — run
//! unmodified inside the guest.
//!
//! Requirement `RD-WASM-RT-04` (MINTED-pending-confirm).

use crate::ffi::FfiHost;
use crate::host::HostOps;
use rounddance_hal_esp::{Driver, DriverError, PendingMode, RxFrame, TxEvent};

/// The 15.4 radio as seen from the WASM guest: every radio effect is
/// one host call through `H`.
pub struct WasmDriver<H: HostOps = FfiHost> {
    host: H,
}

impl<H: HostOps> WasmDriver<H> {
    /// Wrap a host endpoint (real imports or scripted mock).
    #[must_use]
    pub const fn new(host: H) -> Self {
        Self { host }
    }

    /// Borrow the host endpoint.
    #[must_use]
    pub const fn host(&self) -> &H {
        &self.host
    }

    /// Mutably borrow the host endpoint.
    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }
}

impl<H: HostOps> Driver for WasmDriver<H> {
    fn is_ready(&self) -> bool {
        self.host.is_ready()
    }
    fn init(&mut self) -> Result<(), DriverError> {
        self.host.init()
    }
    fn deinit(&mut self) -> Result<(), DriverError> {
        self.host.deinit()
    }
    fn set_channel(&mut self, channel: u8) -> Result<(), DriverError> {
        self.host.set_channel(channel)
    }
    fn set_tx_power(&mut self, dbm: i8) -> Result<(), DriverError> {
        self.host.set_tx_power(dbm)
    }
    fn set_addrs(&mut self, pan: u16, short: u16, ext: &[u8; 8]) -> Result<(), DriverError> {
        self.host.set_addrs(pan, short, ext)
    }
    fn set_promiscuous(&mut self, enable: bool) -> Result<(), DriverError> {
        self.host.set_promiscuous(enable)
    }
    fn start_rx(&mut self) -> Result<(), DriverError> {
        self.host.start_rx()
    }
    fn set_coordinator(&mut self, enable: bool) -> Result<(), DriverError> {
        self.host.set_coordinator(enable)
    }
    fn set_pending_mode(&mut self, mode: PendingMode) -> Result<(), DriverError> {
        self.host.set_pending_mode(mode)
    }
    fn pending_short_add(&mut self, short: u16) -> Result<(), DriverError> {
        self.host.pending_short_add(short)
    }
    fn pending_short_clear(&mut self, short: u16) -> Result<(), DriverError> {
        self.host.pending_short_clear(short)
    }
    fn pending_shorts_reset(&mut self) -> Result<(), DriverError> {
        self.host.pending_shorts_reset()
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), DriverError> {
        self.host.transmit(frame)
    }
    fn poll_tx(&mut self) -> Option<TxEvent> {
        self.host.poll_tx()
    }
    fn poll_rx(&mut self) -> Option<RxFrame> {
        self.host.poll_rx()
    }
    fn energy_scan(&mut self, channel: u8) -> Result<i8, DriverError> {
        self.host.energy_scan(channel)
    }
}
