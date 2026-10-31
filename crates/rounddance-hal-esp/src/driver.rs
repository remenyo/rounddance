//! [`Driver`] seam: the injectable 15.4 radio the adapter drives.
//!
//! The adapter ([`EspAdapter`](crate::adapter::EspAdapter)) never touches
//! hardware or IDF symbols directly — every radio effect goes through
//! this trait. Production provides
//! [`EspIdfDriver`](crate::esp::EspIdfDriver) (`esp` feature); host
//! tests and WASM provide [`MockDriver`](crate::mock::MockDriver).
//!
//! The trait mirrors the proven spike surface: init/deinit, channel +
//! TX-power programming, one single-flight transmit with TX-DONE /
//! TX-failed events, an RX pump (ISR flags + `handle_done`, never
//! callbacks into the adapter), and energy-detect scan.

use core::fmt;

/// Largest on-air 15.4 frame this seam carries: 1 length octet + up to
/// 127 PSDU octets (the hardware appends/checks the 2 FCS octets, which
/// the Len+2 convention accounts for).
pub const MAX_AIR_FRAME: usize = 128;

/// Largest PSDU (length-octet payload) the seam accepts.
pub const MAX_PSDU: usize = 127;

/// Driver-level failure taxonomy. Variants are observable radio states
/// only — never allocator state (D5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverError {
    /// Radio not initialised (`init` not called or `deinit` since).
    NotReady,
    /// A transmit is already in flight (single-flight driver).
    Busy,
    /// Hardware fault reported by the driver call.
    HwFault,
    /// Feature the radio/HAL lacks.
    Unsupported,
    /// Out-of-range parameter (channel, power, length).
    InvalidParam,
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NotReady => "radio not initialised",
            Self::Busy => "transmit already in flight",
            Self::HwFault => "radio hardware fault",
            Self::Unsupported => "unsupported by this radio",
            Self::InvalidParam => "invalid radio parameter",
        };
        f.write_str(s)
    }
}

impl core::error::Error for DriverError {}

/// Auto frame-pending mode for ACKs (Zigbee indirect-transmission
/// convention). The on-target driver maps these 1:1 onto
/// `esp_ieee802154_pending_mode_t` (same order, checked against the
/// header).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingMode {
    /// Frame-pending bit always set in the ACK to a Data Request.
    Disable,
    /// Pending bit set when the source matches, in Data-Request ACKs.
    Enable,
    /// Pending bit set when the source matches, in all ACK frames.
    Enhanced,
    /// Zigbee convention: pending cleared to 0 only when the source
    /// is a short address present in the table, in Data-Request ACKs.
    Zigbee,
}

/// Why a transmit failed, mirroring the driver's TX-error enum
/// (`esp_ieee802154_tx_error_t`; see `ffi` for the value mapping).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxFail {
    /// Medium stayed busy past the CSMA budget.
    CcaBusy,
    /// No ACK arrived within the retry budget.
    NoAck,
    /// Transaction aborted.
    Aborted,
    /// Rejected by the coexistence system.
    CoexReject,
    /// Invalid security configuration.
    Security,
    /// Invalid ACK frame received.
    InvalidAck,
}

/// One transmit report from the driver's event pump.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxEvent {
    /// Frame went out (and was ACKed, when ACK was requested — the
    /// hardware handles ACK tracking, the driver reports once).
    Done,
    /// Frame did not go out / was not ACKed, with the reason.
    Failed(TxFail),
}

/// One received frame handed out of the driver's RX pump.
///
/// `bytes[..len]` is the full on-air frame starting at the length
/// octet (Len+2 semantics: `bytes[0]` counts the trailing 2 HW-FCS
/// octets). The pump has already released the driver buffer
/// (`receive_handle_done`), so this frame is owned by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxFrame {
    /// On-air bytes starting at the length octet.
    pub bytes: [u8; MAX_AIR_FRAME],
    /// Live length of `bytes` (always `>= 1`, the length octet).
    pub len: usize,
    /// Arrival channel number (11–26).
    pub channel: u8,
    /// Reception RSSI in dBm (radio convention).
    pub rssi: i8,
    /// Reception LQI (0–255 scale per radio convention).
    pub lqi: u8,
}

impl RxFrame {
    /// Build a frame from on-air bytes; empty input is rejected.
    pub fn from_slice(bytes: &[u8], channel: u8, rssi: i8, lqi: u8) -> Result<Self, DriverError> {
        if bytes.is_empty() || bytes.len() > MAX_AIR_FRAME {
            return Err(DriverError::InvalidParam);
        }
        let mut buf = [0u8; MAX_AIR_FRAME];
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: buf,
            len: bytes.len(),
            channel,
            rssi,
            lqi,
        })
    }

    /// Live on-air bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Injectable 15.4 radio.
///
/// All methods are non-blocking except `energy_scan` (bounded wait) and
/// `init`/`deinit`. Transmit is single-flight: at most one frame is
/// outstanding in the driver; its fate arrives via [`Driver::poll_tx`].
/// Reception never calls back into the adapter: frames wait in the pump
/// ([`Driver::poll_rx`]), whose real implementation releases each driver
/// buffer (`receive_handle_done`) before returning.
pub trait Driver {
    /// True when the radio is initialised and usable.
    fn is_ready(&self) -> bool;

    /// NVS-first initialisation, then driver enable + sane defaults
    /// (filtering on, RX-when-idle on, receiver running). See the crate
    /// docs for the invariant list.
    ///
    /// # Errors
    ///
    /// [`DriverError::HwFault`] when enable fails.
    fn init(&mut self) -> Result<(), DriverError>;

    /// Shut the driver down; the adapter must `init` again before use.
    ///
    /// # Errors
    ///
    /// [`DriverError::HwFault`] when disable fails.
    fn deinit(&mut self) -> Result<(), DriverError>;

    /// Tune to a 2.4 GHz channel number (11–26, checked by the adapter).
    ///
    /// # Errors
    ///
    /// [`DriverError::NotReady`] when down, [`DriverError::InvalidParam`]
    /// for out-of-range input, [`DriverError::HwFault`] on driver error.
    fn set_channel(&mut self, channel: u8) -> Result<(), DriverError>;

    /// Program TX power in dBm. The adapter enforces the standing cap
    /// BEFORE calling here; range checking below the cap is the
    /// driver's job.
    ///
    /// # Errors
    ///
    /// As for [`Driver::set_channel`].
    fn set_tx_power(&mut self, dbm: i8) -> Result<(), DriverError>;

    /// Program PAN id + short + extended addresses (filtering state).
    ///
    /// # Errors
    ///
    /// As for [`Driver::set_channel`].
    fn set_addrs(&mut self, pan: u16, short: u16, ext: &[u8; 8]) -> Result<(), DriverError>;

    /// Enable/disable promiscuous (unfiltered) receive. The adapter
    /// programs `false` at init; `true` is a sniffer/test escape hatch.
    ///
    /// # Errors
    ///
    /// As for [`Driver::set_channel`].
    fn set_promiscuous(&mut self, enable: bool) -> Result<(), DriverError>;

    /// Start the receiver (enter receive state after enable).
    ///
    /// # Errors
    ///
    /// [`DriverError::NotReady`] when down, [`DriverError::HwFault`] on
    /// driver error.
    fn start_rx(&mut self) -> Result<(), DriverError>;

    /// Declare this node a PAN coordinator (affects frame handling,
    /// e.g. association and pending-data behavior).
    ///
    /// # Errors
    ///
    /// As for [`Driver::set_channel`].
    fn set_coordinator(&mut self, enable: bool) -> Result<(), DriverError>;

    /// Program the auto frame-pending mode for ACKs (Zigbee indirect
    /// convention lives here: [`PendingMode::Zigbee`]).
    ///
    /// # Errors
    ///
    /// As for [`Driver::set_channel`].
    fn set_pending_mode(&mut self, mode: PendingMode) -> Result<(), DriverError>;

    /// Add a short address to the source-matching (pending) table.
    /// Under [`PendingMode::Zigbee`], a listed short gets its
    /// Data-Request ACK pending bit cleared (no data queued); shorts
    /// with queued indirect messages stay OUT of the table.
    ///
    /// # Errors
    ///
    /// As for [`Driver::set_channel`].
    fn pending_short_add(&mut self, short: u16) -> Result<(), DriverError>;

    /// Remove a short address from the source-matching table.
    ///
    /// # Errors
    ///
    /// As for [`Driver::set_channel`].
    fn pending_short_clear(&mut self, short: u16) -> Result<(), DriverError>;

    /// Empty the short-address source-matching table.
    ///
    /// # Errors
    ///
    /// As for [`Driver::set_channel`].
    fn pending_shorts_reset(&mut self) -> Result<(), DriverError>;

    /// Submit one Len+2 frame for transmission (CCA-gated). Returns
    /// immediately; the fate arrives via [`Driver::poll_tx`].
    ///
    /// # Errors
    ///
    /// [`DriverError::NotReady`] when down, [`DriverError::Busy`] when a
    /// transmit is already in flight, [`DriverError::InvalidParam`] for
    /// an empty/oversize frame, [`DriverError::HwFault`] on driver error.
    fn transmit(&mut self, frame: &[u8]) -> Result<(), DriverError>;

    /// Take the oldest pending transmit report, if any.
    fn poll_tx(&mut self) -> Option<TxEvent>;

    /// Take the oldest pending received frame, if any. Returning a
    /// frame implies its driver buffer was released.
    fn poll_rx(&mut self) -> Option<RxFrame>;

    /// Energy-detect scan on `channel`; higher value = more energy.
    /// Bounded wait (the real driver wraps the async ED-done event).
    ///
    /// # Errors
    ///
    /// As for [`Driver::set_channel`], plus [`DriverError::Unsupported`]
    /// where the radio lacks scan hardware.
    fn energy_scan(&mut self, channel: u8) -> Result<i8, DriverError>;
}
