//! Abstract 802.15.4 MAC boundary (service access point).
//!
//! The SAP split lets the host path and the C6-standalone path share the
//! core from day one (D3, see `SCOPE.md` §3): upper layers (NWK and above)
//! talk only to the traits in this crate, while per-target adapters
//! (host HAL, ESP HAL, sim harness) implement them.
//!
//! # Design
//!
//! * Data path ([`MacDataSap`]): request / cancel / poll-confirm /
//!   poll-indication, plus queue-depth accessors for backpressure.
//! * Management path ([`MacMgmtSap`]): reset, addressing, channel
//!   selection, energy scan. Combined with [`HasCapabilities`] so upper
//!   layers can discover what the radio/HAL actually provides.
//! * Combined convenience boundary: [`MacSap`].
//! * All frame storage is [`BoundedOctets`]: fixed-capacity, no heap,
//!   fallible pushes — per the D5 alloc rule (bounded + fallible +
//!   accountable, `SCOPE.md` §2). This crate has no allocator dependency.
//! * Poll-based (no callbacks, no locks): cooperative and multithreaded
//!   schedulers both stay feasible; deterministic single-threaded sim use
//!   just calls `step`-style polls in virtual-time order.
//!
//! # Spec-area citations
//!
//! Every public item names the 802.15.4 service area it serves via the
//! primitive family (MCPS-DATA for the data path, MLME for management).
//! The paraphrased-requirements corpus (`requirements-seed.md`) currently
//! carries **no 802.15.4 MAC clause entries**, so per-item requirement IDs
//! are marked `coverage pending`; they will be filled when MAC extraction
//! lands, per `REQUIREMENTS.md` traceability. No spec text is reproduced
//! here (D1, `SCOPE.md` §2).
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

use core::fmt;

/// Maximum 802.15.4 PHY packet (PSDU) size in octets.
///
/// Spec area: 802.15.4 PHY packet structure; requirements-seed:
/// coverage pending. Upper layers must fit MAC header + MSDU within this.
pub const MAX_PHY_PSDU_LEN: usize = 127;

/// Maximum MAC payload (MSDU) this SAP accepts in one request.
///
/// Spec area: 802.15.4 data service (MCPS-DATA.request size limit);
/// requirements-seed: coverage pending. Kept below [`MAX_PHY_PSDU_LEN`]
/// to leave room for the largest MAC header/footer the adapters emit.
pub const MAX_MSDU_LEN: usize = 116;

/// Fixed-capacity octet buffer, `heapless`-style but dependency-free.
///
/// Spec area: crate-local alloc accounting (D5 bounded + fallible +
/// accountable, `SCOPE.md` §2); requirements-seed: N-A (harness detail).
/// Pushes beyond capacity fail with [`MacError::FrameTooLong`] instead of
/// truncating, so oversize frames are always visible to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundedOctets<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> BoundedOctets<N> {
    /// Empty buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    /// Buffer holding a copy of `bytes`, or [`MacError::FrameTooLong`].
    pub fn from_slice(bytes: &[u8]) -> Result<Self, MacError> {
        let mut out = Self::new();
        out.extend_from_slice(bytes)?;
        Ok(out)
    }

    /// Append one octet, or [`MacError::FrameTooLong`] when full.
    pub fn push(&mut self, byte: u8) -> Result<(), MacError> {
        if self.len >= N {
            return Err(MacError::FrameTooLong);
        }
        self.buf[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    /// Append `bytes`, or [`MacError::FrameTooLong`] (prefix kept).
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), MacError> {
        if self.len + bytes.len() > N {
            return Err(MacError::FrameTooLong);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }

    /// Live payload bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Payload length in octets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// True when no payload bytes are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Total capacity in octets.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Discard all payload bytes.
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl<const N: usize> Default for BoundedOctets<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// One MAC payload worth of bytes.
pub type FramePayload = BoundedOctets<MAX_MSDU_LEN>;

/// 16-bit short address.
pub type ShortAddr = u16;
/// 64-bit extended (IEEE) address.
pub type ExtAddr = u64;
/// 16-bit PAN identifier.
pub type PanId = u16;

/// MAC address mode + value.
///
/// Spec area: 802.15.4 addressing (MCPS-DATA address modes);
/// requirements-seed: coverage pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrMode {
    /// No address present (e.g. some management frames).
    None,
    /// 16-bit short address.
    Short(ShortAddr),
    /// 64-bit extended address.
    Extended(ExtAddr),
}

/// Destination (or source) selector: PAN scope + address.
///
/// Spec area: 802.15.4 addressing / PAN association (MCPS-DATA,
/// MLME-ASSOCIATE family); requirements-seed: coverage pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacAddress {
    /// PAN context, when the frame carries one.
    pub pan: Option<PanId>,
    /// Address mode + value.
    pub addr: AddrMode,
}

impl MacAddress {
    /// Short-address endpoint inside `pan`.
    #[must_use]
    pub const fn short(pan: PanId, addr: ShortAddr) -> Self {
        Self {
            pan: Some(pan),
            addr: AddrMode::Short(addr),
        }
    }

    /// Extended-address endpoint inside `pan`.
    #[must_use]
    pub const fn extended(pan: PanId, addr: ExtAddr) -> Self {
        Self {
            pan: Some(pan),
            addr: AddrMode::Extended(addr),
        }
    }
}

/// 2.4 GHz 802.15.4 channel (11–26).
///
/// Spec area: 802.15.4 channelization / MLME-SCAN channel mask;
/// requirements-seed: coverage pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channel(u8);

impl Channel {
    /// Lowest valid 2.4 GHz channel number.
    pub const MIN: u8 = 11;
    /// Highest valid 2.4 GHz channel number.
    pub const MAX: u8 = 26;

    /// Checked constructor; out-of-range input is [`MacError::InvalidChannel`].
    pub const fn new(number: u8) -> Result<Self, MacError> {
        if number < Self::MIN || number > Self::MAX {
            return Err(MacError::InvalidChannel);
        }
        Ok(Self(number))
    }

    /// Raw channel number.
    #[must_use]
    pub const fn number(self) -> u8 {
        self.0
    }
}

/// Per-frame transmit options (bitmask).
///
/// Spec area: 802.15.4 data service options (MCPS-DATA.request option
/// family: acknowledged vs unacknowledged transmission);
/// requirements-seed: coverage pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxOptions(u8);

impl TxOptions {
    /// No options set.
    pub const NONE: Self = Self(0);
    /// Request MAC-level acknowledgement of this frame.
    pub const ACK: Self = Self(1 << 0);

    /// Raw option bits (for adapters mapping to HAL flags).
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// True when the [`TxOptions::ACK`] bit is set.
    #[must_use]
    pub const fn wants_ack(self) -> bool {
        self.0 & Self::ACK.0 != 0
    }
}

/// Opaque handle binding a confirm (or cancel) to its request.
///
/// Spec area: 802.15.4 data service handle (`msduHandle`);
/// requirements-seed: coverage pending. Handles are adapter-scoped and
/// never reused while their transaction is outstanding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TxHandle(pub u32);

/// Outcome of one transmit transaction.
///
/// Spec area: 802.15.4 data confirm status (MCPS-DATA.confirm);
/// requirements-seed: coverage pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxStatus {
    /// Frame delivered (and acknowledged, when ACK was requested).
    Delivered,
    /// No acknowledgement arrived within the adapter's retry budget.
    NoAck,
    /// Medium stayed busy past the adapter's CSMA budget.
    ChannelBusy,
    /// Transaction was cancelled via [`MacDataSap::data_cancel`].
    Cancelled,
}

/// Error taxonomy for the whole SAP boundary.
///
/// Spec area: 802.15.4 confirm/status families (MCPS-DATA.confirm,
/// MLME confirm primitives); requirements-seed: coverage pending.
/// Variants are observable radio/stack states only — never allocator
/// state (D5: no protocol decision depends on allocator state).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacError {
    /// Transmit queue has no free slot (backpressure signal).
    QueueFull,
    /// Payload exceeds [`MAX_MSDU_LEN`] or the adapter MTU.
    FrameTooLong,
    /// Destination/source address is malformed for this context.
    InvalidAddress,
    /// Channel number outside the supported range.
    InvalidChannel,
    /// No acknowledgement within the retry budget.
    NoAck,
    /// Medium busy past the CSMA budget.
    ChannelBusy,
    /// Radio not ready (down, uncalibrated, wrong state).
    NotReady,
    /// Handle unknown or transaction already finished.
    UnknownHandle,
    /// Radio/HAL lacks this feature (see [`HasCapabilities`]).
    Unsupported,
    /// Hardware fault reported by the adapter.
    RadioFault,
}

impl fmt::Display for MacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::QueueFull => "transmit queue full",
            Self::FrameTooLong => "frame exceeds maximum length",
            Self::InvalidAddress => "invalid MAC address",
            Self::InvalidChannel => "invalid channel",
            Self::NoAck => "no acknowledgement received",
            Self::ChannelBusy => "channel busy",
            Self::NotReady => "radio not ready",
            Self::UnknownHandle => "unknown transmit handle",
            Self::Unsupported => "feature unsupported by this radio",
            Self::RadioFault => "radio hardware fault",
        };
        f.write_str(s)
    }
}

impl core::error::Error for MacError {}

/// One upper-layer transmit request.
///
/// Spec area: 802.15.4 data request (MCPS-DATA.request);
/// requirements-seed: coverage pending.
///
/// # Example
///
/// ```
/// use rounddance_mac_sap::{FramePayload, MacAddress, TxOptions, TxRequest};
///
/// let req = TxRequest {
///     dst: MacAddress::short(0x1a2b, 0x0000),
///     msdu: FramePayload::from_slice(&[0x01, 0x02, 0x03]).unwrap(),
///     options: TxOptions::ACK,
/// };
/// assert_eq!(req.msdu.len(), 3);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxRequest {
    /// Destination of the frame.
    pub dst: MacAddress,
    /// Payload bytes (bounded, no heap).
    pub msdu: FramePayload,
    /// Transmit options (e.g. ACK requested).
    pub options: TxOptions,
}

/// One transmit confirm delivered back to the upper layer.
///
/// Spec area: 802.15.4 data confirm (MCPS-DATA.confirm);
/// requirements-seed: coverage pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxConfirm {
    /// Handle copied from the matching request.
    pub handle: TxHandle,
    /// Transaction outcome.
    pub status: TxStatus,
    /// Adapter timestamp of completion in microseconds, when the
    /// radio/HAL provides frame timestamps (see [`MacCapabilities`]).
    pub timestamp_us: Option<u64>,
}

/// One received frame delivered to the upper layer.
///
/// Spec area: 802.15.4 data indication (MCPS-DATA.indication);
/// requirements-seed: coverage pending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RxIndication {
    /// Source of the frame.
    pub src: MacAddress,
    /// Link quality at reception (0–255 scale per radio convention).
    pub lqi: u8,
    /// Adapter timestamp of reception in microseconds, when the
    /// radio/HAL provides frame timestamps (see [`MacCapabilities`]).
    pub timestamp_us: Option<u64>,
    /// Payload bytes (bounded, no heap).
    pub msdu: FramePayload,
}

/// What the radio/HAL underneath actually provides.
///
/// Spec area: 802.15.4 capability discovery (upper layers must adapt to
/// radios with/without hardware ACK, CSMA, energy scan, timestamps —
/// host, ESP, and sim adapters differ); requirements-seed: coverage
/// pending. Every adapter reports honestly; upper layers branch on these
/// flags instead of probing behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacCapabilities {
    /// Radio acknowledges frames in hardware (else the adapter
    /// synthesizes ACK handling above the HAL).
    pub hw_auto_ack: bool,
    /// Radio performs CSMA-CA in hardware.
    pub hw_csma_ca: bool,
    /// Radio retries unacknowledged frames in hardware.
    pub hw_retries: bool,
    /// Adapter supports energy-detect scans
    /// ([`MacMgmtSap::energy_scan`]); otherwise it fails with
    /// [`MacError::Unsupported`].
    pub energy_scan: bool,
    /// Confirms/indications carry real timestamps; otherwise
    /// `timestamp_us` is `None`.
    pub frame_timestamping: bool,
    /// Adapter can enter promiscuous receive mode.
    pub promiscuous_mode: bool,
}

/// Capability-discovery hook every adapter implements.
///
/// Spec area: capability discovery (see [`MacCapabilities`]).
pub trait HasCapabilities {
    /// Report what this radio/HAL provides.
    fn capabilities(&self) -> MacCapabilities;
}

/// Upper-layer view of the MAC data service.
///
/// Spec area: 802.15.4 data service
/// (MCPS-DATA.request / .confirm / .indication family);
/// requirements-seed: coverage pending.
///
/// Cancel/backpressure contract: `data_request` fails with
/// [`MacError::QueueFull`] instead of blocking or growing memory, so the
/// upper layer always sees backpressure explicitly; `data_cancel` revokes
/// an outstanding transaction and surfaces as [`TxStatus::Cancelled`].
pub trait MacDataSap {
    /// Queue one frame for transmission; the matching [`TxConfirm`]
    /// arrives via [`MacDataSap::poll_confirm`].
    ///
    /// # Errors
    ///
    /// [`MacError::QueueFull`] under backpressure, [`MacError::FrameTooLong`]
    /// for oversize payloads, [`MacError::InvalidAddress`] for malformed
    /// destinations, [`MacError::NotReady`] when the radio is down.
    fn data_request(&mut self, req: TxRequest) -> Result<TxHandle, MacError>;

    /// Revoke an outstanding transaction. A revoked transaction that has
    /// not yet completed reports [`TxStatus::Cancelled`]; an already
    /// finished or unknown handle reports [`MacError::UnknownHandle`].
    fn data_cancel(&mut self, handle: TxHandle) -> Result<(), MacError>;

    /// Take the oldest pending transmit confirm, if any.
    fn poll_confirm(&mut self) -> Option<TxConfirm>;

    /// Take the oldest pending received frame, if any.
    fn poll_indication(&mut self) -> Option<RxIndication>;

    /// Free transmit slots right now (backpressure readout).
    fn tx_queue_free(&self) -> usize;

    /// Total transmit slots (constant per adapter provisioning; radio
    /// parameters are preallocated, never resized mid-transaction — D5).
    fn tx_queue_capacity(&self) -> usize;

    /// True when [`MacDataSap::data_request`] would fail with
    /// [`MacError::QueueFull`]. Provided; adapters need not override.
    fn tx_queue_full(&self) -> bool {
        self.tx_queue_free() == 0
    }
}

/// Upper-layer view of the MAC management service.
///
/// Spec area: 802.15.4 management service (MLME-RESET / MLME-SET /
/// MLME-SCAN families); requirements-seed: coverage pending.
pub trait MacMgmtSap: HasCapabilities {
    /// Reset the MAC. `cold = true` also clears addressing state set via
    /// the `set_*` methods; `cold = false` keeps it.
    fn reset(&mut self, cold: bool);

    /// Tune to `channel`.
    ///
    /// # Errors
    ///
    /// [`MacError::InvalidChannel`] for out-of-range input (defensive;
    /// [`Channel::new`] already rejects those), [`MacError::NotReady`]
    /// when the radio is down.
    fn set_channel(&mut self, channel: Channel) -> Result<(), MacError>;

    /// Set the short address used in subsequent frames.
    fn set_short_addr(&mut self, addr: ShortAddr);

    /// Set the extended (IEEE) address used in subsequent frames.
    fn set_extended_addr(&mut self, addr: ExtAddr);

    /// Set the PAN identifier used in subsequent frames.
    fn set_pan_id(&mut self, pan: PanId);

    /// Energy-detect scan on `channel`; higher value = more energy.
    /// Radios without scan hardware report [`MacError::Unsupported`]
    /// (see [`MacCapabilities::energy_scan`]).
    fn energy_scan(&mut self, channel: Channel) -> Result<u8, MacError>;
}

/// Whole MAC boundary: data + management in one bound.
///
/// Spec area: SAP binding shared by host, ESP, and sim adapters (D3).
/// Blanket-implemented for every type that provides both halves.
pub trait MacSap: MacDataSap + MacMgmtSap {}

impl<T: MacDataSap + MacMgmtSap> MacSap for T {}

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-mac-sap"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
    }

    #[test]
    fn buffer_accepts_up_to_capacity() {
        let mut b = FramePayload::new();
        for i in 0..MAX_MSDU_LEN {
            b.push(i as u8).unwrap();
        }
        assert_eq!(b.len(), MAX_MSDU_LEN);
        assert_eq!(b.push(0), Err(MacError::FrameTooLong));
        assert!(!b.is_empty());
        assert_eq!(b.capacity(), MAX_MSDU_LEN);
    }

    #[test]
    fn from_slice_rejects_oversize() {
        let big = [0xAA; MAX_MSDU_LEN + 1];
        assert_eq!(FramePayload::from_slice(&big), Err(MacError::FrameTooLong));
        let ok = [0xAA; MAX_MSDU_LEN];
        let b = FramePayload::from_slice(&ok).unwrap();
        assert_eq!(b.as_slice(), ok);
    }

    #[test]
    fn extend_rejects_overflow_and_keeps_prefix() {
        let mut b = FramePayload::from_slice(&[1, 2, 3]).unwrap();
        let big = [9u8; MAX_MSDU_LEN];
        assert_eq!(b.extend_from_slice(&big), Err(MacError::FrameTooLong));
        assert_eq!(b.as_slice(), &[1, 2, 3]);
        b.clear();
        assert!(b.is_empty());
    }

    #[test]
    fn channel_range_checked() {
        assert!(Channel::new(10).is_err());
        assert_eq!(Channel::new(11).unwrap().number(), 11);
        assert_eq!(Channel::new(26).unwrap().number(), 26);
        assert_eq!(Channel::new(27), Err(MacError::InvalidChannel));
    }

    #[test]
    fn tx_options_bits() {
        assert!(!TxOptions::NONE.wants_ack());
        assert!(TxOptions::ACK.wants_ack());
        assert_eq!(TxOptions::ACK.bits(), 1);
    }

    #[test]
    fn error_display_is_human_readable() {
        assert_eq!(format!("{}", MacError::QueueFull), "transmit queue full");
        assert_eq!(
            format!("{}", MacError::Unsupported),
            "feature unsupported by this radio"
        );
        // Every variant must render non-empty (backpressure signals included).
        for e in [
            MacError::QueueFull,
            MacError::FrameTooLong,
            MacError::InvalidAddress,
            MacError::InvalidChannel,
            MacError::NoAck,
            MacError::ChannelBusy,
            MacError::NotReady,
            MacError::UnknownHandle,
            MacError::Unsupported,
            MacError::RadioFault,
        ] {
            assert!(!format!("{e}").is_empty());
        }
    }

    #[test]
    fn address_constructors_scope_pan() {
        let a = MacAddress::short(0x1a2b, 0x0000);
        assert_eq!(a.pan, Some(0x1a2b));
        assert_eq!(a.addr, AddrMode::Short(0x0000));
        let b = MacAddress::extended(0x1a2b, 0x0012_4b00_1a2b_3c4d);
        assert!(matches!(b.addr, AddrMode::Extended(_)));
    }
}
