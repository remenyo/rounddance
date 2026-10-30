//! [`EspAdapter`]: the MAC SAP over an injectable [`Driver`].
//!
//! Queueing, failure mapping, cap enforcement, and the inter-PAN path
//! all live here and are fully exercised over
//! [`MockDriver`](crate::mock::MockDriver) — the on-target driver only
//! needs to satisfy the [`Driver`] trait for the same behavior to hold
//! on hardware.
//!
//! # Frame shapes (v0)
//!
//! PAN data frames: `Len | FC 2 | seq | dst_pan | dst | src | MSDU`,
//! short-short intra-PAN (`FC = 0x8841`, `+0x20` AR bit when ACK is
//! requested), `Len` = header + MSDU + 2 (Len+2 rule: the 2 trailing
//! hardware-FCS octets the radio appends/checks itself).
//!
//! Inter-PAN frames: `Len | FC 2 | seq | dst_pan=0xFFFF | dst=0xFFFF |
//! src_pan | src | MSDU`, unacknowledged broadcast. RX routing is by
//! destination PAN: frames for our PAN go to the PAN indication queue,
//! everything else to the inter-PAN queue.

use crate::driver::{Driver, DriverError, RxFrame, TxEvent, TxFail, MAX_AIR_FRAME, MAX_PSDU};
use crate::mac_cmd::{self, Incoming as MacIncoming};
use core::array::from_fn;
use core::fmt;
use rounddance_mac_sap::{
    AddrMode, Channel, ExtAddr, FramePayload, HasCapabilities, InterPanIndication, MacAddress,
    MacCapabilities, MacDataSap, MacError, MacInterPanSap, MacMgmtSap, PanId, RxIndication,
    ShortAddr, TxConfirm, TxHandle, TxRequest, TxStatus, MAX_MSDU_LEN,
};

/// Standing lab TX-power ceiling in dBm (wave-11 policy: +10 dBm on ALL
/// units until human clears it). [`EspAdapter::set_tx_power`] rejects
/// anything hotter BEFORE it reaches the driver.
pub const MAX_TX_POWER_DBM: i8 = 10;

/// Default TX power programmed at [`EspAdapter::init`] (the cap value —
/// explicit, recorded by every driver).
pub const DEFAULT_TX_POWER_DBM: i8 = MAX_TX_POWER_DBM;

/// Default channel programmed at [`EspAdapter::init`] when none was set.
pub const DEFAULT_CHANNEL: u8 = 15;

/// Outstanding PAN transactions (preallocated, never resized — D5).
const TX_SLOTS: usize = 4;
/// Pending-confirm queue depth.
const CONFIRM_DEPTH: usize = 8;
/// Per-path pending-indication queue depth.
const INDICATION_DEPTH: usize = 8;

/// Pending MAC-command indication queue depth.
const MAC_QUEUE_DEPTH: usize = 8;

/// Adapter-level errors (outside the SAP error taxonomy: construction /
/// provisioning failures, not per-frame states).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EspError {
    /// Requested power exceeds [`MAX_TX_POWER_DBM`]; the driver was not
    /// touched. Lab policy until human clears it.
    PowerCapExceeded {
        /// The rejected request in dBm.
        requested: i8,
    },
    /// The driver reported a failure.
    Driver(DriverError),
    /// Operation needs `init` first.
    NotInitialized,
}

impl fmt::Display for EspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PowerCapExceeded { requested } => {
                write!(
                    f,
                    "tx power {requested} dBm exceeds +{MAX_TX_POWER_DBM} dBm cap"
                )
            }
            Self::Driver(e) => write!(f, "driver fault: {e}"),
            Self::NotInitialized => f.write_str("adapter not initialised"),
        }
    }
}

impl core::error::Error for EspError {}

/// One queued PAN transaction.
#[derive(Clone, Copy, Debug)]
struct PanSlot {
    handle: TxHandle,
    frame: [u8; MAX_AIR_FRAME],
    len: usize,
}

/// One queued inter-PAN transaction.
#[derive(Clone, Copy, Debug)]
struct InterPanSlot {
    handle: TxHandle,
    frame: [u8; MAX_AIR_FRAME],
    len: usize,
}

/// Which path the in-flight driver transaction belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Submitted {
    Pan(usize),
    InterPan,
}

/// Build a PAN data air frame (Len+2, short-short intra-PAN).
///
/// Layout: `Len | FC0 | FC1=0x88 | seq | pan LE | dst LE | src LE |
/// msdu`. `FC0 = 0x41`, plus the AR bit when `ack` is set.
///
/// # Errors
///
/// [`MacError::FrameTooLong`] when header + MSDU + FCS exceeds the PSDU.
pub fn build_data_frame(
    seq: u8,
    pan: PanId,
    dst: ShortAddr,
    src: ShortAddr,
    msdu: &[u8],
    ack: bool,
) -> Result<([u8; MAX_AIR_FRAME], usize), MacError> {
    const MHR: usize = 9;
    if msdu.len() > MAX_MSDU_LEN || MHR + msdu.len() + 2 > 127 {
        return Err(MacError::FrameTooLong);
    }
    let mut frame = [0u8; MAX_AIR_FRAME];
    frame[0] = (MHR + msdu.len() + 2) as u8;
    frame[1] = if ack { 0x61 } else { 0x41 };
    frame[2] = 0x88;
    frame[3] = seq;
    frame[4..6].copy_from_slice(&pan.to_le_bytes());
    frame[6..8].copy_from_slice(&dst.to_le_bytes());
    frame[8..10].copy_from_slice(&src.to_le_bytes());
    frame[10..10 + msdu.len()].copy_from_slice(msdu);
    Ok((frame, 10 + msdu.len()))
}

/// Build an inter-PAN air frame (Len+2, unacknowledged broadcast).
///
/// Layout: `Len | FC0=0x01 | FC1=0x88 | seq | 0xFFFF | 0xFFFF | src_pan
/// LE | src LE | msdu`.
///
/// # Errors
///
/// [`MacError::FrameTooLong`] when header + MSDU + FCS exceeds the PSDU.
pub fn build_inter_pan_frame(
    seq: u8,
    src_pan: PanId,
    src: ShortAddr,
    msdu: &[u8],
) -> Result<([u8; MAX_AIR_FRAME], usize), MacError> {
    const MHR: usize = 11;
    if msdu.len() > MAX_MSDU_LEN || MHR + msdu.len() + 2 > 127 {
        return Err(MacError::FrameTooLong);
    }
    let mut frame = [0u8; MAX_AIR_FRAME];
    frame[0] = (MHR + msdu.len() + 2) as u8;
    frame[1] = 0x01;
    frame[2] = 0x88;
    frame[3] = seq;
    frame[4..6].copy_from_slice(&0xFFFFu16.to_le_bytes());
    frame[6..8].copy_from_slice(&0xFFFFu16.to_le_bytes());
    frame[8..10].copy_from_slice(&src_pan.to_le_bytes());
    frame[10..12].copy_from_slice(&src.to_le_bytes());
    frame[12..12 + msdu.len()].copy_from_slice(msdu);
    Ok((frame, 12 + msdu.len()))
}

/// Parsed PAN data frame: source plus MSDU bounds into the air frame.
struct ParsedData {
    src: MacAddress,
    dst_pan: PanId,
    msdu_start: usize,
    msdu_end: usize,
}

/// Parse our short-short intra-PAN shape; anything else is `None`
/// (v0 limitation, documented: beacons / extended-address frames are
/// dropped and counted, not delivered).
fn parse_data_frame(buf: &[u8]) -> Option<ParsedData> {
    if buf.len() < 10 || buf[1] != 0x41 && buf[1] != 0x61 || buf[2] != 0x88 {
        return None;
    }
    let len = buf[0] as usize;
    if len < 9 + 2 {
        return None;
    }
    let msdu_end = 1 + (len - 2);
    if buf.len() < msdu_end {
        return None;
    }
    let msdu_start = 10;
    if msdu_end < msdu_start || msdu_end - msdu_start > MAX_MSDU_LEN {
        return None;
    }
    let pan = u16::from_le_bytes([buf[4], buf[5]]);
    let src = u16::from_le_bytes([buf[8], buf[9]]);
    Some(ParsedData {
        src: MacAddress::short(pan, src),
        dst_pan: pan,
        msdu_start,
        msdu_end,
    })
}

/// Parsed inter-PAN frame: arrival channel is attached by the caller.
struct ParsedInterPan {
    msdu_start: usize,
    msdu_end: usize,
}

/// Parse our inter-PAN broadcast shape; anything else is `None`.
fn parse_inter_pan_frame(buf: &[u8]) -> Option<ParsedInterPan> {
    if buf.len() < 12 || buf[1] != 0x01 || buf[2] != 0x88 {
        return None;
    }
    let len = buf[0] as usize;
    if len < 11 + 2 {
        return None;
    }
    let msdu_end = 1 + (len - 2);
    if buf.len() < msdu_end {
        return None;
    }
    let msdu_start = 12;
    if msdu_end < msdu_start || msdu_end - msdu_start > MAX_MSDU_LEN {
        return None;
    }
    Some(ParsedInterPan {
        msdu_start,
        msdu_end,
    })
}

fn map_tx_event(ev: TxEvent) -> TxStatus {
    match ev {
        TxEvent::Done => TxStatus::Delivered,
        TxEvent::Failed(TxFail::CcaBusy) => TxStatus::ChannelBusy,
        TxEvent::Failed(TxFail::NoAck) => TxStatus::NoAck,
        // Remaining driver failures (abort / coexist / security /
        // invalid-ACK) share one operational truth: the frame was not
        // delivered. `NoAck` is the only non-delivery SAP status, so it
        // carries them; the per-reason split is visible in driver logs.
        TxEvent::Failed(_) => TxStatus::NoAck,
    }
}

fn map_mgmt_err(e: DriverError) -> MacError {
    match e {
        DriverError::NotReady => MacError::NotReady,
        DriverError::Busy => MacError::QueueFull,
        DriverError::HwFault => MacError::RadioFault,
        DriverError::Unsupported => MacError::Unsupported,
        DriverError::InvalidParam => MacError::RadioFault,
    }
}

/// One received MAC-command PSDU (beacon-request / assoc-request /
/// long data poll) with per-frame meters.
///
/// The PSDU is the exact on-air command bytes (`Len`-stripped, tail
/// meters excluded); upper layers feed it to
/// [`mac_cmd::classify`](crate::mac_cmd::classify) / [`CoordinatorApp`](crate::app::CoordinatorApp).
#[derive(Clone, Copy, Debug)]
pub struct MacIndication {
    psdu: [u8; MAX_PSDU],
    len: usize,
    channel: u8,
    rssi: i8,
    lqi: u8,
}

impl MacIndication {
    /// Exact on-air command PSDU bytes.
    #[must_use]
    pub fn psdu(&self) -> &[u8] {
        &self.psdu[..self.len]
    }

    /// Arrival channel number (11-26).
    #[must_use]
    pub fn channel_number(&self) -> u8 {
        self.channel
    }

    /// Reception RSSI in dBm.
    #[must_use]
    pub fn rssi(&self) -> i8 {
        self.rssi
    }

    /// Reception LQI.
    #[must_use]
    pub fn lqi(&self) -> u8 {
        self.lqi
    }
}

/// The MAC SAP over an injectable [`Driver`].
///
/// Bounded and fallible throughout: 4 TX slots, 8-deep confirm /
/// indication queues, no heap. All driver interaction funnels through
/// [`EspAdapter::pump`], which the `poll_*` methods call — upper layers
/// keep polling; there are no callbacks.
pub struct EspAdapter<D: Driver> {
    driver: D,
    inited: bool,
    channel: u8,
    pan: PanId,
    short: ShortAddr,
    ext: [u8; 8],
    power_dbm: i8,
    seq: u8,
    next_handle: u32,
    pan_slots: [Option<PanSlot>; TX_SLOTS],
    interpan_slot: Option<InterPanSlot>,
    submitted: Option<(TxHandle, Submitted)>,
    confirms: [Option<TxConfirm>; CONFIRM_DEPTH],
    confirms_len: usize,
    indications: [Option<RxIndication>; INDICATION_DEPTH],
    indications_len: usize,
    interpan_confirms: [Option<TxConfirm>; CONFIRM_DEPTH],
    interpan_confirms_len: usize,
    interpan_indications: [Option<InterPanIndication>; INDICATION_DEPTH],
    interpan_indications_len: usize,
    mac_queue: [Option<MacIndication>; MAC_QUEUE_DEPTH],
    mac_len: usize,
    /// Submit-time driver faults that left the frame queued
    /// (backpressure with an explanation — see `pump`).
    submit_faults: u32,
    /// RX frames dropped (unparseable, not-for-us, or full queue).
    rx_dropped: u32,
}

impl<D: Driver> EspAdapter<D> {
    /// Wrap `driver`. Provisioning (`set_channel` / addresses / power)
    /// may precede [`EspAdapter::init`]; init programs it all into the
    /// driver in the NVS-first order.
    #[must_use]
    pub fn new(driver: D) -> Self {
        Self {
            driver,
            inited: false,
            channel: DEFAULT_CHANNEL,
            pan: 0xFFFF,
            short: 0xFFFF,
            ext: [0; 8],
            power_dbm: DEFAULT_TX_POWER_DBM,
            seq: 0,
            next_handle: 0,
            pan_slots: [None; TX_SLOTS],
            interpan_slot: None,
            submitted: None,
            confirms: [None; CONFIRM_DEPTH],
            confirms_len: 0,
            indications: from_fn(|_| None),
            indications_len: 0,
            interpan_confirms: [None; CONFIRM_DEPTH],
            interpan_confirms_len: 0,
            interpan_indications: from_fn(|_| None),
            interpan_indications_len: 0,
            mac_queue: [None; MAC_QUEUE_DEPTH],
            mac_len: 0,
            submit_faults: 0,
            rx_dropped: 0,
        }
    }

    /// Borrow the underlying driver (firmware / diagnostics escape).
    #[must_use]
    pub fn driver(&self) -> &D {
        &self.driver
    }

    /// Mutably borrow the underlying driver.
    #[must_use]
    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    /// Count of submit-time driver faults absorbed as backpressure.
    #[must_use]
    pub fn submit_faults(&self) -> u32 {
        self.submit_faults
    }

    /// Count of RX frames dropped (unparseable / full queue).
    #[must_use]
    pub fn rx_dropped(&self) -> u32 {
        self.rx_dropped
    }

    /// Initialise the radio: NVS-first `init`, then stored channel /
    /// power / addresses, filtering ON (promiscuous OFF), RX-when-idle,
    /// receiver running.
    ///
    /// # Errors
    ///
    /// [`EspError::Driver`] when the driver fails.
    pub fn init(&mut self) -> Result<(), EspError> {
        self.driver.init().map_err(EspError::Driver)?;
        self.apply_provisioning().map_err(EspError::Driver)?;
        self.inited = true;
        Ok(())
    }

    fn apply_provisioning(&mut self) -> Result<(), DriverError> {
        self.driver.set_channel(self.channel)?;
        self.driver.set_tx_power(self.power_dbm)?;
        self.driver.set_addrs(self.pan, self.short, &self.ext)?;
        // The driver defaults promiscuous to TRUE: explicitly enable
        // filtering (wave-2b hard constraint).
        self.driver.set_promiscuous(false)?;
        self.driver.start_rx()?;
        Ok(())
    }

    /// Program TX power in dBm. Requests above [`MAX_TX_POWER_DBM`]
    /// are rejected BEFORE reaching the driver (standing lab cap).
    ///
    /// # Errors
    ///
    /// [`EspError::PowerCapExceeded`] for anything hotter than the cap,
    /// [`EspError::Driver`] when the live driver rejects the value.
    pub fn set_tx_power(&mut self, dbm: i8) -> Result<(), EspError> {
        if dbm > MAX_TX_POWER_DBM {
            return Err(EspError::PowerCapExceeded { requested: dbm });
        }
        if self.inited {
            self.driver.set_tx_power(dbm).map_err(EspError::Driver)?;
        }
        self.power_dbm = dbm;
        Ok(())
    }

    /// Currently programmed TX power in dBm.
    #[must_use]
    pub fn tx_power(&self) -> i8 {
        self.power_dbm
    }

    /// Take the next sequence number (shared across PAN / inter-PAN).
    fn take_seq(&mut self) -> u8 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    /// Take the next transmit handle.
    fn take_handle(&mut self) -> TxHandle {
        let h = TxHandle(self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1);
        h
    }

    /// Push, dropping the oldest when full would overflow would lose a
    /// confirm — instead the caller must guarantee space. Confirms are
    /// 8-deep against 4 slots + 1 inter-PAN, so overflow is unreachable
    /// unless the upper layer never polls; debug-assert that contract.
    fn push_confirm(&mut self, c: TxConfirm) {
        if self.confirms_len < CONFIRM_DEPTH {
            self.confirms[self.confirms_len] = Some(c);
            self.confirms_len += 1;
        }
        debug_assert!(
            self.confirms_len <= CONFIRM_DEPTH,
            "confirm queue overflow: poll_confirm starved"
        );
    }

    fn push_indication(&mut self, ind: RxIndication) {
        if self.indications_len < INDICATION_DEPTH {
            self.indications[self.indications_len] = Some(ind);
            self.indications_len += 1;
        } else {
            self.rx_dropped += 1;
        }
    }

    fn push_interpan_confirm(&mut self, c: TxConfirm) {
        if self.interpan_confirms_len < CONFIRM_DEPTH {
            self.interpan_confirms[self.interpan_confirms_len] = Some(c);
            self.interpan_confirms_len += 1;
        }
        debug_assert!(
            self.interpan_confirms_len <= CONFIRM_DEPTH,
            "inter-PAN confirm queue overflow"
        );
    }

    fn push_interpan_indication(&mut self, ind: InterPanIndication) {
        if self.interpan_indications_len < INDICATION_DEPTH {
            self.interpan_indications[self.interpan_indications_len] = Some(ind);
            self.interpan_indications_len += 1;
        } else {
            self.rx_dropped += 1;
        }
    }

    fn push_mac_indication(&mut self, ind: MacIndication) {
        if self.mac_len < MAC_QUEUE_DEPTH {
            self.mac_queue[self.mac_len] = Some(ind);
            self.mac_len += 1;
        } else {
            self.rx_dropped += 1;
        }
    }

    fn complete_submitted(&mut self, status: TxStatus, stamp: Option<u64>) {
        if let Some((handle, kind)) = self.submitted.take() {
            // Free the queue slot: one slot = one outstanding
            // transaction, queued or in-air (capacity counts both).
            match kind {
                Submitted::Pan(i) => self.pan_slots[i] = None,
                Submitted::InterPan => self.interpan_slot = None,
            }
            let c = TxConfirm {
                handle,
                status,
                timestamp_us: stamp,
            };
            match kind {
                Submitted::Pan(_) => self.push_confirm(c),
                Submitted::InterPan => self.push_interpan_confirm(c),
            }
        }
    }

    /// Oldest queued (not yet submitted) transaction across both paths.
    /// The in-air transaction is skipped: the driver is single-flight.
    fn oldest_queued(&self) -> Option<(TxHandle, Submitted)> {
        let air = self.submitted.map(|(h, _)| h);
        let mut best: Option<(TxHandle, Submitted)> = None;
        let mut consider = |handle: TxHandle, kind: Submitted| {
            if air == Some(handle) {
                return;
            }
            let take = match best {
                None => true,
                Some((h, _)) => handle.0 < h.0,
            };
            if take {
                best = Some((handle, kind));
            }
        };
        for (i, slot) in self.pan_slots.iter().enumerate() {
            if let Some(s) = slot {
                consider(s.handle, Submitted::Pan(i));
            }
        }
        if let Some(s) = &self.interpan_slot {
            consider(s.handle, Submitted::InterPan);
        }
        best
    }

    /// Advance driver state: complete finished TX, drain RX, submit the
    /// oldest queued frame while the driver is idle.
    pub fn pump(&mut self) {
        // 1. Transmit reports.
        if let Some(ev) = self.driver.poll_tx() {
            self.complete_submitted(map_tx_event(ev), None);
        }
        // 2. Received frames.
        while let Some(rx) = self.driver.poll_rx() {
            self.dispatch_rx(&rx);
        }
        // 3. Submit oldest queued while the driver is idle.
        if self.submitted.is_none() {
            if let Some((_, kind)) = self.oldest_queued() {
                let (frame, len) = match kind {
                    Submitted::Pan(i) => {
                        let s = self.pan_slots[i].as_ref().expect("queued slot");
                        (s.frame, s.len)
                    }
                    Submitted::InterPan => {
                        let s = self.interpan_slot.as_ref().expect("queued inter-PAN");
                        (s.frame, s.len)
                    }
                };
                match self.driver.transmit(&frame[..len]) {
                    Ok(()) => {
                        // Slots free at completion, not at submit: the
                        // slot still identifies the transaction for
                        // `data_cancel` and capacity accounting.
                        let handle = match kind {
                            Submitted::Pan(i) => {
                                self.pan_slots[i].as_ref().expect("queued slot").handle
                            }
                            Submitted::InterPan => {
                                self.interpan_slot
                                    .as_ref()
                                    .expect("queued inter-PAN")
                                    .handle
                            }
                        };
                        self.submitted = Some((handle, kind));
                    }
                    // Single-flight race: leave queued, retry next pump.
                    Err(DriverError::Busy) => {}
                    // Persistent fault: leave queued (visible
                    // backpressure) and count it — the upper layer sees
                    // `tx_queue_full` plus `submit_faults`, never a
                    // silently lost transaction.
                    Err(_) => {
                        self.submit_faults = self.submit_faults.saturating_add(1);
                    }
                }
            }
        }
    }

    /// Route one RX frame to the PAN or inter-PAN indication queue.
    fn dispatch_rx(&mut self, rx: &RxFrame) {
        let buf = rx.as_slice();
        // Prefer the inter-PAN shape first: its FC0 (0x01) never equals
        // our PAN FC0 (0x41/0x61), so the two never alias.
        if let Some(p) = parse_inter_pan_frame(buf) {
            let payload = &buf[p.msdu_start..p.msdu_end];
            if let Ok(msdu) = FramePayload::from_slice(payload) {
                if let Ok(channel) = Channel::new(rx.channel) {
                    self.push_interpan_indication(InterPanIndication { channel, msdu });
                    return;
                }
            }
            self.rx_dropped += 1;
            return;
        }
        if let Some(p) = parse_data_frame(buf) {
            // Our PAN (or unset 0xFFFF provisioning) → PAN queue;
            // anything addressed elsewhere (touchlink scan traffic on a
            // foreign PAN) → inter-PAN queue with its arrival channel.
            let payload = &buf[p.msdu_start..p.msdu_end];
            let Ok(msdu) = FramePayload::from_slice(payload) else {
                self.rx_dropped += 1;
                return;
            };
            if p.dst_pan == self.pan {
                self.push_indication(RxIndication {
                    src: p.src,
                    lqi: rx.lqi,
                    timestamp_us: None,
                    msdu,
                });
            } else if let Ok(channel) = Channel::new(rx.channel) {
                self.push_interpan_indication(InterPanIndication { channel, msdu });
            } else {
                self.rx_dropped += 1;
            }
            return;
        }
        // MAC-command leg (coordinator RX): strip Len+2, classify the
        // PSDU, surface matches on the MAC queue. Non-command bytes
        // and overfull queues count as dropped, as before.
        if !buf.is_empty() {
            let len = buf[0] as usize;
            if len >= 2 {
                let psdu_len = len - 2;
                if psdu_len > 0 && psdu_len <= MAX_PSDU && buf.len() > psdu_len {
                    let psdu = &buf[1..1 + psdu_len];
                    if !matches!(mac_cmd::classify(psdu), MacIncoming::Other) {
                        let mut raw = [0u8; MAX_PSDU];
                        raw[..psdu_len].copy_from_slice(psdu);
                        self.push_mac_indication(MacIndication {
                            psdu: raw,
                            len: psdu_len,
                            channel: rx.channel,
                            rssi: rx.rssi,
                            lqi: rx.lqi,
                        });
                        return;
                    }
                }
            }
        }
        self.rx_dropped += 1;
    }

    /// Drop all queued state (warm reset helper).
    fn drain_all(&mut self) {
        self.pan_slots = [None; TX_SLOTS];
        self.interpan_slot = None;
        self.submitted = None;
        self.confirms = [None; CONFIRM_DEPTH];
        self.confirms_len = 0;
        self.indications = from_fn(|_| None);
        self.indications_len = 0;
        self.interpan_confirms = [None; CONFIRM_DEPTH];
        self.interpan_confirms_len = 0;
        self.interpan_indications = from_fn(|_| None);
        self.interpan_indications_len = 0;
        self.mac_queue = [None; MAC_QUEUE_DEPTH];
        self.mac_len = 0;
    }
}

impl<D: Driver> HasCapabilities for EspAdapter<D> {
    fn capabilities(&self) -> MacCapabilities {
        MacCapabilities {
            // Hardware ACK + CSMA; the driver reports each transaction
            // once — no HAL retry (upper layers own retry).
            hw_auto_ack: true,
            hw_csma_ca: true,
            hw_retries: false,
            energy_scan: true,
            // v0: no SFD timestamps wired through; confirms carry None.
            frame_timestamping: false,
            // Filtering is programmable (promiscuous escape hatch).
            promiscuous_mode: true,
        }
    }
}

impl<D: Driver> MacDataSap for EspAdapter<D> {
    fn data_request(&mut self, req: TxRequest) -> Result<TxHandle, MacError> {
        if !self.inited {
            return Err(MacError::NotReady);
        }
        if req.msdu.len() > MAX_MSDU_LEN {
            return Err(MacError::FrameTooLong);
        }
        let dst = match req.dst.addr {
            AddrMode::Short(a) => a,
            // Well-formed but beyond the v0 short-only builder.
            AddrMode::Extended(_) => return Err(MacError::Unsupported),
            AddrMode::None => return Err(MacError::InvalidAddress),
        };
        let free = self.pan_slots.iter().position(|s| s.is_none());
        let Some(idx) = free else {
            return Err(MacError::QueueFull);
        };
        let handle = self.take_handle();
        let seq = self.take_seq();
        let (frame, len) = build_data_frame(
            seq,
            self.pan,
            dst,
            self.short,
            req.msdu.as_slice(),
            req.options.wants_ack(),
        )?;
        self.pan_slots[idx] = Some(PanSlot { handle, frame, len });
        self.pump();
        Ok(handle)
    }

    fn data_cancel(&mut self, handle: TxHandle) -> Result<(), MacError> {
        // Accepted by the driver (in-air): cannot be recalled, runs to
        // completion. Anything still queued below is revocable.
        if self.submitted.is_some_and(|(h, _)| h == handle) {
            return Ok(());
        }
        for slot in self.pan_slots.iter_mut() {
            if slot.is_some_and(|s| s.handle == handle) {
                *slot = None;
                self.push_confirm(TxConfirm {
                    handle,
                    status: TxStatus::Cancelled,
                    timestamp_us: None,
                });
                return Ok(());
            }
        }
        Err(MacError::UnknownHandle)
    }

    fn poll_confirm(&mut self) -> Option<TxConfirm> {
        self.pump();
        if self.confirms_len == 0 {
            return None;
        }
        let c = self.confirms[0].take();
        self.confirms.rotate_left(1);
        self.confirms_len -= 1;
        c
    }

    fn poll_indication(&mut self) -> Option<RxIndication> {
        self.pump();
        if self.indications_len == 0 {
            return None;
        }
        let ind = self.indications[0].take();
        self.indications.rotate_left(1);
        self.indications_len -= 1;
        ind
    }

    fn tx_queue_free(&self) -> usize {
        self.pan_slots.iter().filter(|s| s.is_none()).count()
    }

    fn tx_queue_capacity(&self) -> usize {
        TX_SLOTS
    }
}

impl<D: Driver> MacMgmtSap for EspAdapter<D> {
    fn reset(&mut self, cold: bool) {
        self.drain_all();
        if cold {
            self.channel = DEFAULT_CHANNEL;
            self.pan = 0xFFFF;
            self.short = 0xFFFF;
            self.ext = [0; 8];
            // De-init the driver even if it errors: post-cold-reset the
            // adapter is down until `init` regardless.
            let _ = self.driver.deinit();
            self.inited = false;
        }
    }

    fn set_channel(&mut self, channel: Channel) -> Result<(), MacError> {
        if !self.inited {
            return Err(MacError::NotReady);
        }
        self.driver
            .set_channel(channel.number())
            .map_err(map_mgmt_err)?;
        self.channel = channel.number();
        Ok(())
    }

    fn set_short_addr(&mut self, addr: ShortAddr) {
        self.short = addr;
        if self.inited {
            let _ = self.driver.set_addrs(self.pan, self.short, &self.ext);
        }
    }

    fn set_extended_addr(&mut self, addr: ExtAddr) {
        self.ext = addr.to_le_bytes();
        if self.inited {
            let _ = self.driver.set_addrs(self.pan, self.short, &self.ext);
        }
    }

    fn set_pan_id(&mut self, pan: PanId) {
        self.pan = pan;
        if self.inited {
            let _ = self.driver.set_addrs(self.pan, self.short, &self.ext);
        }
    }

    fn energy_scan(&mut self, channel: Channel) -> Result<u8, MacError> {
        if !self.inited {
            return Err(MacError::NotReady);
        }
        self.driver
            .energy_scan(channel.number())
            .map(|dbm| dbm as u8)
            .map_err(map_mgmt_err)
    }
}

impl<D: Driver> MacInterPanSap for EspAdapter<D> {
    fn interpan_request(
        &mut self,
        channel: Channel,
        msdu: &FramePayload,
    ) -> Result<TxHandle, MacError> {
        if !self.inited {
            return Err(MacError::NotReady);
        }
        if msdu.len() > MAX_MSDU_LEN {
            return Err(MacError::FrameTooLong);
        }
        if self.interpan_slot.is_some() {
            return Err(MacError::QueueFull);
        }
        // Inter-PAN is per-channel: retune for this transaction.
        self.driver
            .set_channel(channel.number())
            .map_err(map_mgmt_err)?;
        let handle = self.take_handle();
        let seq = self.take_seq();
        let (frame, len) = build_inter_pan_frame(seq, self.pan, self.short, msdu.as_slice())?;
        self.interpan_slot = Some(InterPanSlot { handle, frame, len });
        self.pump();
        Ok(handle)
    }

    fn poll_interpan_confirm(&mut self) -> Option<TxConfirm> {
        self.pump();
        if self.interpan_confirms_len == 0 {
            return None;
        }
        let c = self.interpan_confirms[0].take();
        self.interpan_confirms.rotate_left(1);
        self.interpan_confirms_len -= 1;
        c
    }

    fn poll_interpan_indication(&mut self) -> Option<InterPanIndication> {
        self.pump();
        if self.interpan_indications_len == 0 {
            return None;
        }
        let ind = self.interpan_indications[0].take();
        self.interpan_indications.rotate_left(1);
        self.interpan_indications_len -= 1;
        ind
    }
}

impl<D: Driver> EspAdapter<D> {
    /// Swap the inter-PAN channel back after a scan burst (firmware
    /// convenience: inter-PAN retunes per request).
    pub fn restore_channel(&mut self) -> Result<(), MacError> {
        if !self.inited {
            return Err(MacError::NotReady);
        }
        // Channel::new cannot fail here: stored channels always came
        // from a checked `Channel` or the default constant.
        let ch = Channel::new(self.channel).map_err(|_| MacError::RadioFault)?;
        self.set_channel(ch)
    }

    /// Enable/disable promiscuous (unfiltered) receive. The coordinator
    /// enables this after init: broadcast beacon-requests never pass
    /// the hardware filter. Forwards to the driver when live.
    ///
    /// # Errors
    ///
    /// [`MacError::NotReady`] when the radio is down.
    pub fn set_promiscuous(&mut self, enable: bool) -> Result<(), MacError> {
        if !self.inited {
            return Err(MacError::NotReady);
        }
        self.driver.set_promiscuous(enable).map_err(map_mgmt_err)
    }

    /// Queue one raw MAC-command PSDU for transmission (Len+2 wrapped,
    /// single-flight through the same slots as data, so command and
    /// data TX share backpressure). Confirms arrive via the normal
    /// `poll_confirm` queue. The caller owns the MAC sequence inside
    /// the PSDU (the adapter does not rewrite it).
    ///
    /// # Errors
    ///
    /// [`MacError::NotReady`] when down, [`MacError::FrameTooLong`]
    /// for an empty/oversize PSDU, [`MacError::QueueFull`] when no TX
    /// slot is free.
    pub fn transmit_mac(&mut self, psdu: &[u8]) -> Result<TxHandle, MacError> {
        if !self.inited {
            return Err(MacError::NotReady);
        }
        if psdu.is_empty() || psdu.len() > MAX_PSDU {
            return Err(MacError::FrameTooLong);
        }
        let free = self.pan_slots.iter().position(|s| s.is_none());
        let Some(idx) = free else {
            return Err(MacError::QueueFull);
        };
        let handle = self.take_handle();
        let mut frame = [0u8; MAX_AIR_FRAME];
        frame[0] = (psdu.len() + 2) as u8;
        frame[1..1 + psdu.len()].copy_from_slice(psdu);
        let len = 1 + psdu.len();
        self.pan_slots[idx] = Some(PanSlot { handle, frame, len });
        self.pump();
        Ok(handle)
    }

    /// Take the oldest pending MAC-command indication, if any.
    pub fn poll_mac_indication(&mut self) -> Option<MacIndication> {
        self.pump();
        if self.mac_len == 0 {
            return None;
        }
        let ind = self.mac_queue[0].take();
        self.mac_queue.rotate_left(1);
        self.mac_len -= 1;
        ind
    }

    /// Pending MAC-command indication count.
    #[must_use]
    pub fn mac_pending(&self) -> usize {
        self.mac_len
    }
}
