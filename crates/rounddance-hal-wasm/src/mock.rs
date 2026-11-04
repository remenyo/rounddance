//! Scriptable host for host tests: [`MockHost`] over [`MockDriver`].
//!
//! The guest's host calls bottom out here instead of in a WASM
//! runtime, with the same record-then-script discipline as
//! [`rounddance_hal_esp::MockDriver`]: script TX
//! outcomes, inject RX frames, canned ED values — so guest-side
//! behavior (including the full join → toggle exchange) is proven on
//! host with zero native code.
//!
//! Requirement `RD-WASM-RT-03` (MINTED-pending-confirm).

use crate::host::HostOps;
use rounddance_hal_esp::{Driver, DriverError, MockDriver, PendingMode, RxFrame, TxEvent};

/// Scriptable [`HostOps`]: delegates to an inner [`MockDriver`].
#[derive(Clone, Debug)]
pub struct MockHost {
    inner: MockDriver,
}

impl MockHost {
    /// Permissive mock: init succeeds, TX auto-completes `Done`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: MockDriver::new(),
        }
    }

    /// Borrow the inner driver (recordings: channels, power, air
    /// frames, source-match table).
    #[must_use]
    pub fn driver(&self) -> &MockDriver {
        &self.inner
    }

    /// Mutably borrow the inner driver (scripting + injection).
    #[must_use]
    pub fn driver_mut(&mut self) -> &mut MockDriver {
        &mut self.inner
    }

    /// Script the next TX-submit outcomes in order.
    pub fn script_submit(&mut self, outcomes: &[Result<(), DriverError>]) {
        self.inner.script_submit(outcomes);
    }

    /// Script the next TX events in order (disables auto-complete).
    pub fn script_events(&mut self, events: &[TxEvent]) {
        self.inner.script_events(events);
    }

    /// Inject RX frames, drained in order.
    pub fn inject_rx(&mut self, frames: &[RxFrame]) {
        self.inner.inject_rx(frames);
    }

    /// Set the canned energy-scan result; `fail` makes scans error.
    pub fn set_ed(&mut self, dbm: i8, fail: bool) {
        self.inner.set_ed(dbm, fail);
    }
}

impl Default for MockHost {
    fn default() -> Self {
        Self::new()
    }
}

impl HostOps for MockHost {
    fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }
    fn init(&mut self) -> Result<(), DriverError> {
        self.inner.init()
    }
    fn deinit(&mut self) -> Result<(), DriverError> {
        self.inner.deinit()
    }
    fn set_channel(&mut self, channel: u8) -> Result<(), DriverError> {
        self.inner.set_channel(channel)
    }
    fn set_tx_power(&mut self, dbm: i8) -> Result<(), DriverError> {
        self.inner.set_tx_power(dbm)
    }
    fn set_addrs(&mut self, pan: u16, short: u16, ext: &[u8; 8]) -> Result<(), DriverError> {
        self.inner.set_addrs(pan, short, ext)
    }
    fn set_promiscuous(&mut self, enable: bool) -> Result<(), DriverError> {
        self.inner.set_promiscuous(enable)
    }
    fn start_rx(&mut self) -> Result<(), DriverError> {
        self.inner.start_rx()
    }
    fn set_coordinator(&mut self, enable: bool) -> Result<(), DriverError> {
        self.inner.set_coordinator(enable)
    }
    fn set_pending_mode(&mut self, mode: PendingMode) -> Result<(), DriverError> {
        self.inner.set_pending_mode(mode)
    }
    fn pending_short_add(&mut self, short: u16) -> Result<(), DriverError> {
        self.inner.pending_short_add(short)
    }
    fn pending_short_clear(&mut self, short: u16) -> Result<(), DriverError> {
        self.inner.pending_short_clear(short)
    }
    fn pending_shorts_reset(&mut self) -> Result<(), DriverError> {
        self.inner.pending_shorts_reset()
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), DriverError> {
        self.inner.transmit(frame)
    }
    fn poll_tx(&mut self) -> Option<TxEvent> {
        self.inner.poll_tx()
    }
    fn poll_rx(&mut self) -> Option<RxFrame> {
        self.inner.poll_rx()
    }
    fn energy_scan(&mut self, channel: u8) -> Result<i8, DriverError> {
        self.inner.energy_scan(channel)
    }
}
