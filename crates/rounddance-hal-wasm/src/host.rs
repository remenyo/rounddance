//! Guest-side host contract: the testable form of the WASM import ABI.
//!
//! [`HostOps`] mirrors the [`Driver`](rounddance_hal_esp::Driver)
//! surface one-for-one so [`WasmDriver`](crate::wasm::WasmDriver) is a
//! thin adapter. [`ffi::FfiHost`](crate::ffi::FfiHost) implements it
//! over the real guest imports on-device;
//! [`mock::MockHost`](crate::mock::MockHost) scripts it on host.
//! All types are the shared `hal-esp` ones: there is exactly one
//! failure taxonomy and one frame geometry across native and guest.
//!
//! Requirement `RD-WASM-RT-01` (MINTED-pending-confirm).

use rounddance_hal_esp::{DriverError, PendingMode, RxFrame, TxEvent};

/// What the native runner must provide. Every method is non-blocking
/// except `energy_scan` (bounded wait) and `init`/`deinit`, matching
/// the [`Driver`](rounddance_hal_esp::Driver) contract this trait
/// mirrors: transmit is single-flight with reports via `poll_tx`,
/// reception never calls back into the guest.
pub trait HostOps {
    /// True when the radio is initialised and usable.
    fn is_ready(&self) -> bool;

    /// NVS-first initialisation, then radio enable + sane defaults
    /// (filtering on, RX-when-idle on, receiver running).
    ///
    /// # Errors
    ///
    /// [`DriverError::HwFault`] when enable fails.
    fn init(&mut self) -> Result<(), DriverError>;

    /// Shut the radio down; the guest must `init` again before use.
    ///
    /// # Errors
    ///
    /// [`DriverError::HwFault`] when disable fails.
    fn deinit(&mut self) -> Result<(), DriverError>;

    /// Tune to a 2.4 GHz channel number (11–26).
    ///
    /// # Errors
    ///
    /// [`DriverError::NotReady`] when down,
    /// [`DriverError::InvalidParam`] for out-of-range input,
    /// [`DriverError::HwFault`] on radio error.
    fn set_channel(&mut self, channel: u8) -> Result<(), DriverError>;

    /// Program TX power in dBm (the adapter caps before calling).
    ///
    /// # Errors
    ///
    /// As for [`HostOps::set_channel`].
    fn set_tx_power(&mut self, dbm: i8) -> Result<(), DriverError>;

    /// Program PAN id + short + extended addresses (filtering state).
    ///
    /// # Errors
    ///
    /// As for [`HostOps::set_channel`].
    fn set_addrs(&mut self, pan: u16, short: u16, ext: &[u8; 8]) -> Result<(), DriverError>;

    /// Enable/disable promiscuous (unfiltered) receive.
    ///
    /// # Errors
    ///
    /// As for [`HostOps::set_channel`].
    fn set_promiscuous(&mut self, enable: bool) -> Result<(), DriverError>;

    /// Start the receiver (enter receive state after enable).
    ///
    /// # Errors
    ///
    /// [`DriverError::NotReady`] when down, [`DriverError::HwFault`]
    /// on radio error.
    fn start_rx(&mut self) -> Result<(), DriverError>;

    /// Declare this node a PAN coordinator.
    ///
    /// # Errors
    ///
    /// As for [`HostOps::set_channel`].
    fn set_coordinator(&mut self, enable: bool) -> Result<(), DriverError>;

    /// Program the auto frame-pending mode for ACKs.
    ///
    /// # Errors
    ///
    /// As for [`HostOps::set_channel`].
    fn set_pending_mode(&mut self, mode: PendingMode) -> Result<(), DriverError>;

    /// Add a short address to the source-matching (pending) table.
    ///
    /// # Errors
    ///
    /// As for [`HostOps::set_channel`].
    fn pending_short_add(&mut self, short: u16) -> Result<(), DriverError>;

    /// Remove a short address from the source-matching table.
    ///
    /// # Errors
    ///
    /// As for [`HostOps::set_channel`].
    fn pending_short_clear(&mut self, short: u16) -> Result<(), DriverError>;

    /// Empty the short-address source-matching table.
    ///
    /// # Errors
    ///
    /// As for [`HostOps::set_channel`].
    fn pending_shorts_reset(&mut self) -> Result<(), DriverError>;

    /// Submit one Len+2 frame for transmission (CCA-gated). Returns
    /// immediately; the fate arrives via [`HostOps::poll_tx`].
    ///
    /// # Errors
    ///
    /// [`DriverError::NotReady`] when down, [`DriverError::Busy`]
    /// when a transmit is already in flight,
    /// [`DriverError::InvalidParam`] for an empty/oversize frame,
    /// [`DriverError::HwFault`] on radio error.
    fn transmit(&mut self, frame: &[u8]) -> Result<(), DriverError>;

    /// Take the oldest pending transmit report, if any.
    fn poll_tx(&mut self) -> Option<TxEvent>;

    /// Take the oldest pending received frame, if any.
    fn poll_rx(&mut self) -> Option<RxFrame>;

    /// Energy-detect scan on `channel`; higher value = more energy.
    ///
    /// # Errors
    ///
    /// As for [`HostOps::set_channel`], plus
    /// [`DriverError::Unsupported`] where the radio lacks scan
    /// hardware.
    fn energy_scan(&mut self, channel: u8) -> Result<i8, DriverError>;
}
