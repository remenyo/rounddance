//! Host-side RCP driver: the MAC SAP traits over a scripted UART.
//!
//! [`RcpDriver`] owns the S3 side of the OTBR split. Upper layers
//! (NWK and above) see [`MacDataSap`], [`MacMgmtSap`], and
//! [`MacInterPanSap`]; underneath, every transaction becomes RCP
//! command/event frames on an injected [`Uart`] and an injected
//! microsecond clock. Nothing here reads wall-clock time or the
//! allocator, so a scripted run replays exactly.
//!
//! # Transaction discipline
//!
//! * Management commands (reset, channel, power, addressing) are
//!   fire-and-confirm-optional: they encode and write immediately,
//!   update the driver's provision cache, and re-emit from that
//!   cache after every reset handshake. The peer answers TX and
//!   scans explicitly; pure sets carry no ack (idempotent by
//!   construction).
//! * TX is single-flight over a 4-slot shared pool (PAN +
//!   inter-PAN): requests submit eagerly while the flight is free
//!   (and `poll` submits whatever queued once a confirm lands),
//!   matches the confirm by sequence, and on `CMD_TIMEOUT_US` without an answer
//!   resends with a fresh sequence up to `MAX_RETRIES` times, then
//!   confirms `NoAck`. `data_request` during a reset handshake fails
//!   `NotReady` — queued frames wait out the handshake, they are
//!   never silently dropped.
//! * Energy scans are split-phase: [`MacMgmtSap::energy_scan`]
//!   (re)arms a scan unless one is already pending and reports the
//!   most recent completed result for that channel, or `NotReady`
//!   when none has completed yet. Poll between calls.
//! * Desync recovery: `DESYNC_THRESHOLD` consecutive dropped runs
//!   (bad length or CRC) open a reset handshake — `Reset`, await
//!   `Ready`, replay the provision cache, resume. The queued TX pool
//!   survives the handshake.
//! * v0 scope notes: SAP MSDUs ride as RCP payloads verbatim (no MAC
//!   header build/parse yet — cf. `rounddance-hal-esp`'s adapter),
//!   RX indications carry `AddrMode::None` sources for the same
//!   reason, confirms carry no timestamps, and inter-PAN requests
//!   ride the peer's tuned channel (per-request retune is a
//!   follow-up). All recorded in `docs/otbr/protocol.md`.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-RCP-05` (SAP mapping), `RD-RCP-06` (timeout/retry),
//! `RD-RCP-07` (desync→resync), `RD-RCP-08` (reset handshake).

use crate::cmd::{Command, Event, TxOutcome, MAX_PSDU};
use crate::frame::{Decoder, Outcome};
use crate::uart::Uart;
use crate::{RcpError, MAX_TX_POWER_DBM};
#[cfg(test)]
use rounddance_mac_sap::TxOptions;
use rounddance_mac_sap::{
    AddrMode, Channel, ExtAddr, FramePayload, HasCapabilities, InterPanIndication, MacAddress,
    MacCapabilities, MacDataSap, MacError, MacInterPanSap, MacMgmtSap, PanId, RxIndication,
    ShortAddr, TxConfirm, TxHandle, TxRequest, TxStatus,
};

/// Command timeout in microseconds on the injected clock.
pub const CMD_TIMEOUT_US: u64 = 20_000;
/// TX resends after the first attempt before confirming `NoAck`.
pub const MAX_RETRIES: u8 = 3;
/// Consecutive dropped UART runs that open a reset handshake.
pub const DESYNC_THRESHOLD: u32 = 4;
/// Shared outstanding-TX pool (PAN + inter-PAN).
pub const TX_SLOTS: usize = 4;
/// Per-queue confirm depth.
pub const CONFIRM_DEPTH: usize = 8;
/// Per-queue indication depth.
pub const INDICATION_DEPTH: usize = 8;
/// Driver event-trace depth (linear fill, then stops + counts).
pub const TRACE_DEPTH: usize = 64;

/// One observable driver event (injected-clock ordered by position).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceEvent {
    /// `data_request` queued a PAN handle.
    TxQueued(u32),
    /// TX submitted with frame sequence.
    TxSent(u8),
    /// Timeout resend with fresh frame sequence.
    TxRetry(u8),
    /// Confirm delivered to the upper queue for a handle.
    TxConfirmed(u32),
    /// Transaction failed to the upper queue for a handle.
    TxFailed(u32),
    /// Management command written (class octet).
    MgmtSent(u8),
    /// Reset command written.
    ResetSent,
    /// `Ready` seen (firmware version).
    ReadySeen(u8),
    /// Provision cache replayed after a handshake.
    Reprovisioned,
    /// Desync meter tripped a reset handshake.
    ResyncReset,
    /// UART run dropped (length or CRC).
    FrameDropped,
    /// Peer error event (code).
    PeerError(u8),
    /// RX event queued (length).
    RxPushed(u8),
    /// Scan command written (channel).
    ScanSent(u8),
    /// Scan result cached (channel).
    ScanResult(u8),
    /// Pending scan timed out.
    ScanTimeout,
}

/// Driver diagnostics (all counters saturate, never wrap).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RcpStats {
    /// TX frames submitted (first attempts).
    pub tx_sent: u32,
    /// Timeout resends.
    pub tx_retries: u32,
    /// Transactions confirmed (any outcome).
    pub tx_confirmed: u32,
    /// Transactions failed after the retry budget.
    pub tx_failed: u32,
    /// Scan results cached.
    pub scans: u32,
    /// Pending scans timed out.
    pub scan_timeouts: u32,
    /// RX events queued.
    pub rx_frames: u32,
    /// RX events dropped (indication queue full).
    pub rx_overruns: u32,
    /// UART runs dropped (length or CRC).
    pub drops: u32,
    /// Desync-triggered reset handshakes.
    pub resyncs: u32,
    /// Reset commands written.
    pub resets: u32,
    /// Reset-handshake retried after its own timeout.
    pub reset_retries: u32,
    /// Peer error events seen.
    pub peer_errors: u32,
    /// Confirms for unknown sequences ignored.
    pub stray_confirms: u32,
    /// Confirms dropped (upper queue full).
    pub confirm_overruns: u32,
    /// UART writes refused (FIFO full).
    pub uart_drops: u32,
    /// Trace events lost after [`TRACE_DEPTH`].
    pub trace_overflows: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotState {
    Queued,
    Sent { seq: u8, deadline: u64, retries: u8 },
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    handle: TxHandle,
    inter_pan: bool,
    cancelled: bool,
    len: u8,
    psdu: [u8; MAX_PSDU],
    state: SlotState,
}

/// Host-side RCP driver over any [`Uart`].
pub struct RcpDriver<U: Uart> {
    uart: U,
    now_us: u64,
    next_seq: u8,
    next_handle: u32,
    slots: [Option<Slot>; TX_SLOTS],
    confirms: [Option<TxConfirm>; CONFIRM_DEPTH],
    confirms_len: usize,
    indications: [Option<RxIndication>; INDICATION_DEPTH],
    indications_len: usize,
    interpan_confirms: [Option<TxConfirm>; TX_SLOTS],
    interpan_confirms_len: usize,
    interpan_indications: [Option<InterPanIndication>; TX_SLOTS],
    interpan_indications_len: usize,
    decoder: Decoder,
    resetting: bool,
    reset_cold: bool,
    reset_deadline: u64,
    synced: bool,
    channel: Option<Channel>,
    power_dbm: Option<i8>,
    pan: Option<PanId>,
    short: Option<ShortAddr>,
    ext: Option<ExtAddr>,
    pending_scan: Option<PendingScan>,
    cached_energy: Option<CachedEnergy>,
    trace: [Option<TraceEvent>; TRACE_DEPTH],
    trace_len: usize,
    stats: RcpStats,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingScan {
    channel: u8,
    deadline: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CachedEnergy {
    channel: u8,
    energy: u8,
}

impl<U: Uart> RcpDriver<U> {
    /// New driver: unprovisioned, no I/O performed. Call
    /// [`MacMgmtSap::reset`] to open the reset handshake before use.
    #[must_use]
    pub fn new(uart: U) -> Self {
        Self {
            uart,
            now_us: 0,
            next_seq: 0,
            next_handle: 0,
            slots: [None; TX_SLOTS],
            confirms: [None; CONFIRM_DEPTH],
            confirms_len: 0,
            indications: core::array::from_fn(|_| None),
            indications_len: 0,
            interpan_confirms: [None; TX_SLOTS],
            interpan_confirms_len: 0,
            interpan_indications: core::array::from_fn(|_| None),
            interpan_indications_len: 0,
            decoder: Decoder::new(),
            resetting: false,
            reset_cold: true,
            reset_deadline: 0,
            synced: false,
            channel: None,
            power_dbm: None,
            pan: None,
            short: None,
            ext: None,
            pending_scan: None,
            cached_energy: None,
            trace: [None; TRACE_DEPTH],
            trace_len: 0,
            stats: RcpStats {
                tx_sent: 0,
                tx_retries: 0,
                tx_confirmed: 0,
                tx_failed: 0,
                scans: 0,
                scan_timeouts: 0,
                rx_frames: 0,
                rx_overruns: 0,
                drops: 0,
                resyncs: 0,
                resets: 0,
                reset_retries: 0,
                peer_errors: 0,
                stray_confirms: 0,
                confirm_overruns: 0,
                uart_drops: 0,
                trace_overflows: 0,
            },
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

    /// True once a `Ready` has arrived and no handshake is open.
    #[must_use]
    pub const fn ready(&self) -> bool {
        self.synced && !self.resetting
    }

    /// Diagnostics snapshot.
    #[must_use]
    pub const fn stats(&self) -> RcpStats {
        self.stats
    }

    /// Recorded trace length (capped at [`TRACE_DEPTH`]).
    #[must_use]
    pub const fn trace_len(&self) -> usize {
        self.trace_len
    }

    /// Trace event at position `i`, if recorded.
    #[must_use]
    pub fn trace_at(&self, i: usize) -> Option<TraceEvent> {
        if i < self.trace_len {
            self.trace[i]
        } else {
            None
        }
    }

    fn trace(&mut self, ev: TraceEvent) {
        if self.trace_len < TRACE_DEPTH {
            self.trace[self.trace_len] = Some(ev);
            self.trace_len += 1;
        } else {
            self.stats.trace_overflows = self.stats.trace_overflows.saturating_add(1);
        }
    }

    fn bump(stat: &mut u32) {
        *stat = stat.saturating_add(1);
    }

    fn send_cmd(&mut self, cmd: &Command) {
        let mut wire = [0u8; 256];
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        match cmd.encode(seq, &mut wire) {
            Ok(n) => match self.uart.write_bytes(&wire[..n]) {
                Ok(()) => {
                    self.trace(TraceEvent::MgmtSent(cmd.kind()));
                }
                Err(_) => {
                    Self::bump(&mut self.stats.uart_drops);
                }
            },
            Err(_) => {
                // `TxFrame` length is bounded by `FramePayload` at the
                // SAP edge, so encode failure here is unreachable for
                // driver-built commands; management shapes are fixed.
                Self::bump(&mut self.stats.uart_drops);
            }
        }
    }

    fn start_reset(&mut self, cold: bool) {
        self.resetting = true;
        self.reset_cold = cold;
        self.reset_deadline = self.now_us.saturating_add(CMD_TIMEOUT_US);
        Self::bump(&mut self.stats.resets);
        self.trace(TraceEvent::ResetSent);
        self.send_cmd(&Command::Reset { cold });
    }

    fn reprovision(&mut self) {
        if let Some(ch) = self.channel {
            self.send_cmd(&Command::SetChannel {
                channel: ch.number(),
            });
        }
        if let Some(dbm) = self.power_dbm {
            self.send_cmd(&Command::SetTxPower { dbm });
        }
        if let Some(pan) = self.pan {
            self.send_cmd(&Command::SetPanId { pan });
        }
        if let Some(addr) = self.short {
            self.send_cmd(&Command::SetShortAddr { addr });
        }
        if let Some(addr) = self.ext {
            self.send_cmd(&Command::SetExtAddr { addr });
        }
        self.trace(TraceEvent::Reprovisioned);
    }

    fn note_drop(&mut self) {
        Self::bump(&mut self.stats.drops);
        self.trace(TraceEvent::FrameDropped);
        if !self.resetting && self.decoder.consecutive_bad() >= DESYNC_THRESHOLD {
            Self::bump(&mut self.stats.resyncs);
            self.trace(TraceEvent::ResyncReset);
            self.start_reset(false);
        }
    }

    fn push_confirm(&mut self, inter_pan: bool, confirm: TxConfirm) {
        if inter_pan {
            if self.interpan_confirms_len < self.interpan_confirms.len() {
                self.interpan_confirms[self.interpan_confirms_len] = Some(confirm);
                self.interpan_confirms_len += 1;
            } else {
                Self::bump(&mut self.stats.confirm_overruns);
            }
        } else if self.confirms_len < self.confirms.len() {
            self.confirms[self.confirms_len] = Some(confirm);
            self.confirms_len += 1;
        } else {
            Self::bump(&mut self.stats.confirm_overruns);
        }
    }

    fn fail_slot(&mut self, idx: usize, status: TxStatus) {
        if let Some(slot) = self.slots[idx].take() {
            let status = if slot.cancelled {
                TxStatus::Cancelled
            } else {
                status
            };
            if status == TxStatus::Delivered {
                self.trace(TraceEvent::TxConfirmed(slot.handle.0));
            } else {
                self.trace(TraceEvent::TxFailed(slot.handle.0));
            }
            Self::bump(&mut self.stats.tx_confirmed);
            self.push_confirm(
                slot.inter_pan,
                TxConfirm {
                    handle: slot.handle,
                    status,
                    timestamp_us: None,
                },
            );
        }
    }

    fn dispatch(&mut self, ev: Event) {
        match ev {
            Event::Ready { fw_version } => {
                self.synced = true;
                self.trace(TraceEvent::ReadySeen(fw_version));
                if self.resetting {
                    self.resetting = false;
                    self.reprovision();
                }
            }
            Event::TxConfirm { seq, status } => {
                let mut found = None;
                for (i, slot) in self.slots.iter().enumerate() {
                    if let Some(s) = slot {
                        if matches!(s.state, SlotState::Sent { seq: q, .. } if q == seq) {
                            found = Some(i);
                            break;
                        }
                    }
                }
                match found {
                    Some(i) => {
                        let mapped = match status {
                            TxOutcome::Delivered => TxStatus::Delivered,
                            TxOutcome::ChannelBusy => TxStatus::ChannelBusy,
                            TxOutcome::NoAck => TxStatus::NoAck,
                        };
                        self.fail_slot(i, mapped);
                    }
                    None => {
                        Self::bump(&mut self.stats.stray_confirms);
                    }
                }
            }
            Event::RxFrame {
                inter_pan,
                lqi,
                len,
                psdu,
                ..
            } => {
                Self::bump(&mut self.stats.rx_frames);
                self.trace(TraceEvent::RxPushed(len));
                let msdu = match FramePayload::from_slice(&psdu[..len as usize]) {
                    Ok(m) => m,
                    Err(_) => {
                        // Peer-bounded at 127, SAP-bounded at 116: an
                        // over-long air frame cannot queue; count it.
                        Self::bump(&mut self.stats.rx_overruns);
                        return;
                    }
                };
                if inter_pan {
                    // Arrival channel is the peer's tuned channel; the
                    // 15 fallback below is statically legal (11..=26)
                    // and only applies before provisioning.
                    let ch = match self.channel {
                        Some(c) => c,
                        None => match Channel::new(15) {
                            Ok(c) => c,
                            Err(_) => unreachable!("15 is a legal 802.15.4 channel"),
                        },
                    };
                    let ind = InterPanIndication { channel: ch, msdu };
                    if self.interpan_indications_len < self.interpan_indications.len() {
                        self.interpan_indications[self.interpan_indications_len] = Some(ind);
                        self.interpan_indications_len += 1;
                    } else {
                        Self::bump(&mut self.stats.rx_overruns);
                    }
                } else {
                    let ind = RxIndication {
                        // v0: no MAC header parse yet — source is
                        // unparsed, payload is the whole PSDU.
                        src: MacAddress {
                            pan: self.pan,
                            addr: AddrMode::None,
                        },
                        lqi,
                        timestamp_us: None,
                        msdu,
                    };
                    if self.indications_len < self.indications.len() {
                        self.indications[self.indications_len] = Some(ind);
                        self.indications_len += 1;
                    } else {
                        Self::bump(&mut self.stats.rx_overruns);
                    }
                }
            }
            Event::EnergyResult { channel, energy } => {
                Self::bump(&mut self.stats.scans);
                self.cached_energy = Some(CachedEnergy { channel, energy });
                if matches!(self.pending_scan, Some(p) if p.channel == channel) {
                    self.pending_scan = None;
                    self.trace(TraceEvent::ScanResult(channel));
                }
            }
            Event::Error { code } => {
                Self::bump(&mut self.stats.peer_errors);
                self.trace(TraceEvent::PeerError(code));
            }
        }
    }

    fn try_submit(&mut self) {
        if self.resetting {
            return;
        }
        for slot in self.slots.iter() {
            if matches!(slot, Some(s) if matches!(s.state, SlotState::Sent { .. })) {
                return;
            }
        }
        let mut idx = None;
        for (i, slot) in self.slots.iter().enumerate() {
            if matches!(slot, Some(s) if s.state == SlotState::Queued) {
                idx = Some(i);
                break;
            }
        }
        let i = match idx {
            Some(i) => i,
            None => return,
        };
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let slot = self.slots[i].as_mut().expect("slot selected above");
        let mut wire = [0u8; 256];
        let cmd = Command::TxFrame {
            inter_pan: slot.inter_pan,
            len: slot.len,
            psdu: slot.psdu,
        };
        match cmd.encode(seq, &mut wire) {
            Ok(n) => match self.uart.write_bytes(&wire[..n]) {
                Ok(()) => {
                    slot.state = SlotState::Sent {
                        seq,
                        deadline: self.now_us.saturating_add(CMD_TIMEOUT_US),
                        retries: 0,
                    };
                    Self::bump(&mut self.stats.tx_sent);
                    self.trace(TraceEvent::TxSent(seq));
                }
                Err(_) => {
                    Self::bump(&mut self.stats.uart_drops);
                }
            },
            Err(_) => {
                Self::bump(&mut self.stats.uart_drops);
            }
        }
    }

    fn check_timeouts(&mut self) {
        if self.resetting && self.now_us >= self.reset_deadline {
            self.reset_deadline = self.now_us.saturating_add(CMD_TIMEOUT_US);
            Self::bump(&mut self.stats.reset_retries);
            self.trace(TraceEvent::ResetSent);
            let cold = self.reset_cold;
            self.send_cmd(&Command::Reset { cold });
        }
        let mut timed_out = None;
        for (i, slot) in self.slots.iter().enumerate() {
            if let Some(s) = slot {
                if let SlotState::Sent {
                    seq,
                    deadline,
                    retries,
                } = s.state
                {
                    if self.now_us >= deadline {
                        timed_out = Some((i, seq, retries));
                        break;
                    }
                }
            }
        }
        if let Some((i, _seq, retries)) = timed_out {
            if retries >= MAX_RETRIES {
                Self::bump(&mut self.stats.tx_failed);
                self.fail_slot(i, TxStatus::NoAck);
            } else {
                let seq = self.next_seq;
                self.next_seq = self.next_seq.wrapping_add(1);
                let slot = self.slots[i].as_mut().expect("slot timed out above");
                let mut wire = [0u8; 256];
                let cmd = Command::TxFrame {
                    inter_pan: slot.inter_pan,
                    len: slot.len,
                    psdu: slot.psdu,
                };
                let sent = match cmd.encode(seq, &mut wire) {
                    Ok(n) => self.uart.write_bytes(&wire[..n]).is_ok(),
                    Err(_) => false,
                };
                if sent {
                    slot.state = SlotState::Sent {
                        seq,
                        deadline: self.now_us.saturating_add(CMD_TIMEOUT_US),
                        retries: retries + 1,
                    };
                    Self::bump(&mut self.stats.tx_retries);
                    self.trace(TraceEvent::TxRetry(seq));
                } else {
                    Self::bump(&mut self.stats.uart_drops);
                    // Re-arm the deadline so the retry is re-attempted
                    // on the next poll, never silently lost.
                    slot.state = SlotState::Sent {
                        seq: _seq,
                        deadline: self.now_us.saturating_add(CMD_TIMEOUT_US),
                        retries,
                    };
                }
            }
        }
        if let Some(p) = self.pending_scan {
            if self.now_us >= p.deadline {
                self.pending_scan = None;
                Self::bump(&mut self.stats.scan_timeouts);
                self.trace(TraceEvent::ScanTimeout);
            }
        }
    }

    /// Pump inbound bytes, fire timeouts, submit queued TX. Call
    /// after advancing the clock or delivering peer bytes.
    pub fn poll(&mut self) {
        while let Some(b) = self.uart.read_byte() {
            match self.decoder.push_byte(b) {
                Some(Outcome::Frame(f)) => match Event::decode(&f) {
                    Ok(ev) => self.dispatch(ev),
                    Err(_) => self.note_drop(),
                },
                Some(Outcome::Dropped(_)) => self.note_drop(),
                None => {}
            }
        }
        self.check_timeouts();
        self.try_submit();
    }

    /// Set TX power in dBm; hotter than [`MAX_TX_POWER_DBM`] is
    /// refused before anything reaches the UART.
    pub fn set_tx_power(&mut self, dbm: i8) -> Result<(), RcpError> {
        if dbm > MAX_TX_POWER_DBM {
            return Err(RcpError::PowerCapExceeded { requested: dbm });
        }
        self.power_dbm = Some(dbm);
        self.send_cmd(&Command::SetTxPower { dbm });
        Ok(())
    }

    fn queue_tx(&mut self, inter_pan: bool, msdu: &FramePayload) -> Result<TxHandle, MacError> {
        if self.resetting {
            return Err(MacError::NotReady);
        }
        if msdu.len() > MAX_PSDU {
            return Err(MacError::FrameTooLong);
        }
        let mut free = None;
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.is_none() {
                free = Some(i);
                break;
            }
        }
        let i = match free {
            Some(i) => i,
            None => return Err(MacError::QueueFull),
        };
        let handle = TxHandle(self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1);
        let mut psdu = [0u8; MAX_PSDU];
        psdu[..msdu.len()].copy_from_slice(msdu.as_slice());
        self.slots[i] = Some(Slot {
            handle,
            inter_pan,
            cancelled: false,
            len: msdu.len() as u8,
            psdu,
            state: SlotState::Queued,
        });
        self.trace(TraceEvent::TxQueued(handle.0));
        // Submit eagerly when the single flight is free so one
        // request + one link round-trip already completes; `poll`
        // re-attempts whenever a confirm frees the flight.
        self.try_submit();
        Ok(handle)
    }

    fn shift_confirms(&mut self) -> Option<TxConfirm> {
        if self.confirms_len == 0 {
            return None;
        }
        let out = self.confirms[0].take();
        for i in 1..self.confirms.len() {
            self.confirms[i - 1] = self.confirms[i].take();
        }
        self.confirms_len -= 1;
        out
    }

    fn shift_indications(&mut self) -> Option<RxIndication> {
        if self.indications_len == 0 {
            return None;
        }
        let out = self.indications[0].take();
        for i in 1..self.indications.len() {
            self.indications[i - 1] = self.indications[i].take();
        }
        self.indications_len -= 1;
        out
    }

    fn shift_interpan_confirms(&mut self) -> Option<TxConfirm> {
        if self.interpan_confirms_len == 0 {
            return None;
        }
        let out = self.interpan_confirms[0].take();
        for i in 1..self.interpan_confirms.len() {
            self.interpan_confirms[i - 1] = self.interpan_confirms[i].take();
        }
        self.interpan_confirms_len -= 1;
        out
    }

    fn shift_interpan_indications(&mut self) -> Option<InterPanIndication> {
        if self.interpan_indications_len == 0 {
            return None;
        }
        let out = self.interpan_indications[0].take();
        for i in 1..self.interpan_indications.len() {
            self.interpan_indications[i - 1] = self.interpan_indications[i].take();
        }
        self.interpan_indications_len -= 1;
        out
    }
}

impl<U: Uart> HasCapabilities for RcpDriver<U> {
    fn capabilities(&self) -> MacCapabilities {
        MacCapabilities {
            // The H2 radio owns CSMA + auto-ACK in hardware; the RCP
            // reports each transaction once (no HAL retry).
            hw_auto_ack: true,
            hw_csma_ca: true,
            hw_retries: false,
            energy_scan: true,
            // v0 carries no timestamps yet.
            frame_timestamping: false,
            promiscuous_mode: false,
        }
    }
}

impl<U: Uart> MacDataSap for RcpDriver<U> {
    fn data_request(&mut self, req: TxRequest) -> Result<TxHandle, MacError> {
        if matches!(req.dst.addr, AddrMode::None) {
            return Err(MacError::InvalidAddress);
        }
        self.queue_tx(false, &req.msdu)
    }

    fn data_cancel(&mut self, handle: TxHandle) -> Result<(), MacError> {
        for slot in self.slots.iter_mut() {
            if let Some(s) = slot {
                if s.handle == handle && !s.inter_pan {
                    match s.state {
                        SlotState::Queued => {
                            let dropped = slot.take().expect("slot matched above");
                            self.trace(TraceEvent::TxFailed(dropped.handle.0));
                            Self::bump(&mut self.stats.tx_confirmed);
                            self.push_confirm(
                                false,
                                TxConfirm {
                                    handle,
                                    status: TxStatus::Cancelled,
                                    timestamp_us: None,
                                },
                            );
                            return Ok(());
                        }
                        SlotState::Sent { .. } => {
                            // Already radiated: the confirm will
                            // report Cancelled when it lands.
                            s.cancelled = true;
                            return Ok(());
                        }
                    }
                }
            }
        }
        Err(MacError::UnknownHandle)
    }

    fn poll_confirm(&mut self) -> Option<TxConfirm> {
        self.shift_confirms()
    }

    fn poll_indication(&mut self) -> Option<RxIndication> {
        self.shift_indications()
    }

    fn tx_queue_free(&self) -> usize {
        self.slots.iter().filter(|s| s.is_none()).count()
    }

    fn tx_queue_capacity(&self) -> usize {
        TX_SLOTS
    }
}

impl<U: Uart> MacMgmtSap for RcpDriver<U> {
    fn reset(&mut self, cold: bool) {
        self.slots = [None; TX_SLOTS];
        self.confirms = [None; CONFIRM_DEPTH];
        self.confirms_len = 0;
        self.indications = core::array::from_fn(|_| None);
        self.indications_len = 0;
        self.interpan_confirms = [None; TX_SLOTS];
        self.interpan_confirms_len = 0;
        self.interpan_indications = core::array::from_fn(|_| None);
        self.interpan_indications_len = 0;
        self.pending_scan = None;
        if cold {
            self.channel = None;
            self.power_dbm = None;
            self.pan = None;
            self.short = None;
            self.ext = None;
            self.cached_energy = None;
        }
        self.start_reset(cold);
    }

    fn set_channel(&mut self, channel: Channel) -> Result<(), MacError> {
        self.channel = Some(channel);
        self.send_cmd(&Command::SetChannel {
            channel: channel.number(),
        });
        Ok(())
    }

    fn set_short_addr(&mut self, addr: ShortAddr) {
        self.short = Some(addr);
        self.send_cmd(&Command::SetShortAddr { addr });
    }

    fn set_extended_addr(&mut self, addr: ExtAddr) {
        self.ext = Some(addr);
        self.send_cmd(&Command::SetExtAddr { addr });
    }

    fn set_pan_id(&mut self, pan: PanId) {
        self.pan = Some(pan);
        self.send_cmd(&Command::SetPanId { pan });
    }

    fn energy_scan(&mut self, channel: Channel) -> Result<u8, MacError> {
        if self.pending_scan.is_none() {
            self.send_cmd(&Command::EnergyScan {
                channel: channel.number(),
            });
            self.trace(TraceEvent::ScanSent(channel.number()));
            self.pending_scan = Some(PendingScan {
                channel: channel.number(),
                deadline: self.now_us.saturating_add(CMD_TIMEOUT_US),
            });
        }
        match self.cached_energy {
            Some(c) if c.channel == channel.number() => Ok(c.energy),
            _ => Err(MacError::NotReady),
        }
    }
}

impl<U: Uart> MacInterPanSap for RcpDriver<U> {
    fn interpan_request(
        &mut self,
        _channel: Channel,
        msdu: &FramePayload,
    ) -> Result<TxHandle, MacError> {
        // v0 rides the peer's tuned channel (per-request retune is a
        // follow-up); the path bit, not the channel, selects routing.
        self.queue_tx(true, msdu)
    }

    fn poll_interpan_confirm(&mut self) -> Option<TxConfirm> {
        self.shift_interpan_confirms()
    }

    fn poll_interpan_indication(&mut self) -> Option<InterPanIndication> {
        self.shift_interpan_indications()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::EmulatedRcp;
    use crate::uart::HostSide;
    use std::vec::Vec;

    fn pair() -> (RcpDriver<HostSide>, EmulatedRcp) {
        (RcpDriver::new(HostSide::new()), EmulatedRcp::new())
    }

    /// Move every byte: driver → peer, peer reacts, peer → driver,
    /// driver reacts. The only timing in the system.
    fn pump(driver: &mut RcpDriver<HostSide>, peer: &mut EmulatedRcp) {
        let mut buf = [0u8; 512];
        let mut n = 0;
        while let Some(b) = driver.uart_mut().outbound.pop() {
            if n >= buf.len() {
                break;
            }
            buf[n] = b;
            n += 1;
        }
        peer.push_host_bytes(&buf[..n]);
        peer.poll();
        let m = peer.take_rcp_bytes(&mut buf);
        for b in &buf[..m] {
            assert!(driver.uart_mut().inbound.push(*b), "test FIFO fits");
        }
        driver.poll();
    }

    fn form(driver: &mut RcpDriver<HostSide>, peer: &mut EmulatedRcp) {
        driver.reset(true);
        pump(&mut *driver, &mut *peer);
        assert!(driver.ready(), "reset handshake completes");
        driver.set_channel(Channel::new(15).unwrap()).unwrap();
        driver.set_pan_id(0x1a2b);
        driver.set_short_addr(0x0000);
        driver.set_tx_power(10).unwrap();
        pump(&mut *driver, &mut *peer);
    }

    #[test]
    fn form_handshake_and_provisioning() {
        let (mut driver, mut peer) = pair();
        assert!(!driver.ready());
        form(&mut driver, &mut peer);
        assert_eq!(peer.channel(), Some(15));
        assert_eq!(peer.pan(), Some(0x1a2b));
        assert_eq!(peer.short(), Some(0x0000));
        assert_eq!(peer.tx_power_dbm(), 10);
        assert_eq!(driver.stats().resets, 1);
        assert_eq!(driver.stats().drops, 0);
        // Power cap enforced before the UART.
        assert_eq!(
            driver.set_tx_power(20),
            Err(RcpError::PowerCapExceeded { requested: 20 })
        );
        assert_eq!(peer.tx_power_dbm(), 10);
    }

    #[test]
    fn tx_confirm_round_trip_and_cancel() {
        let (mut driver, mut peer) = pair();
        form(&mut driver, &mut peer);
        let h = driver
            .data_request(TxRequest {
                dst: MacAddress::short(0x1a2b, 0x0002),
                msdu: FramePayload::from_slice(&[0xDE, 0xAD]).unwrap(),
                options: TxOptions::ACK,
            })
            .unwrap();
        assert_eq!(driver.tx_queue_free(), TX_SLOTS - 1);
        pump(&mut driver, &mut peer);
        let c = driver.poll_confirm().unwrap();
        assert_eq!((c.handle, c.status), (h, TxStatus::Delivered));
        let tx = peer.take_tx().unwrap();
        assert_eq!(&tx.psdu[..tx.len as usize], &[0xDE, 0xAD]);

        // Cancelling a queued frame reports Cancelled: hold the
        // single flight with A, queue B behind it, cancel B.
        let ha = driver
            .data_request(TxRequest {
                dst: MacAddress::short(0x1a2b, 0x0002),
                msdu: FramePayload::from_slice(&[1]).unwrap(),
                options: TxOptions::ACK,
            })
            .unwrap();
        let hb = driver
            .data_request(TxRequest {
                dst: MacAddress::short(0x1a2b, 0x0002),
                msdu: FramePayload::from_slice(&[2]).unwrap(),
                options: TxOptions::ACK,
            })
            .unwrap();
        driver.data_cancel(hb).unwrap();
        let cancelled = driver.poll_confirm().unwrap();
        assert_eq!(
            (cancelled.handle, cancelled.status),
            (hb, TxStatus::Cancelled)
        );
        assert_eq!(driver.data_cancel(hb), Err(MacError::UnknownHandle));
        // A still flies and confirms normally.
        pump(&mut driver, &mut peer);
        let ca = driver.poll_confirm().unwrap();
        assert_eq!((ca.handle, ca.status), (ha, TxStatus::Delivered));
    }

    #[test]
    fn timeout_retries_then_fails_noack() {
        let (mut driver, mut peer) = pair();
        form(&mut driver, &mut peer);
        peer.drop_confirms = 255; // nothing ever confirmed
        let h = driver
            .data_request(TxRequest {
                dst: MacAddress::short(0x1a2b, 0x0002),
                msdu: FramePayload::from_slice(&[5, 6]).unwrap(),
                options: TxOptions::ACK,
            })
            .unwrap();
        pump(&mut driver, &mut peer); // first submit, confirm dropped
        assert_eq!(driver.poll_confirm(), None);
        for _ in 0..MAX_RETRIES {
            driver.advance(CMD_TIMEOUT_US);
            pump(&mut driver, &mut peer); // each poll resends (peer drops again)
        }
        driver.advance(CMD_TIMEOUT_US);
        pump(&mut driver, &mut peer); // budget exhausted
        let c = driver.poll_confirm().unwrap();
        assert_eq!((c.handle, c.status), (h, TxStatus::NoAck));
        assert_eq!(
            driver.stats().tx_retries,
            u32::from(MAX_RETRIES),
            "one resend per timeout"
        );
        assert_eq!(driver.stats().tx_failed, 1);
        assert_eq!(peer.stats.tx_received, 1 + u32::from(MAX_RETRIES));
    }

    #[test]
    fn desync_opens_reset_and_reprovisions() {
        let (mut driver, mut peer) = pair();
        form(&mut driver, &mut peer);
        // Corrupt the next responses and prepend garbage: every run
        // drops on the host until the meter trips.
        peer.corrupt_next = 255;
        peer.garbage_next = 255;
        for _ in 0..DESYNC_THRESHOLD {
            // Best-effort queue: once the meter trips, the open
            // handshake refuses new frames with NotReady (by design).
            let _ = driver.data_request(TxRequest {
                dst: MacAddress::short(0x1a2b, 0x0002),
                msdu: FramePayload::from_slice(&[9]).unwrap(),
                options: TxOptions::ACK,
            });
            // Drain the queued TX without confirming: each corrupt
            // response (plus its garbage prefix) counts drops.
            pump(&mut driver, &mut peer);
            driver.advance(CMD_TIMEOUT_US);
        }
        assert!(
            driver.stats().drops >= DESYNC_THRESHOLD,
            "drops counted: {}",
            driver.stats().drops
        );
        assert_eq!(driver.stats().resyncs, 1);
        // Heal the peer; the handshake must complete and the
        // provision cache must land back on the firmware.
        peer.corrupt_next = 0;
        peer.garbage_next = 0;
        peer.drop_confirms = 0;
        for _ in 0..4 {
            pump(&mut driver, &mut peer);
            driver.advance(1_000);
        }
        assert!(driver.ready(), "handshake re-completes after heal");
        assert_eq!(peer.channel(), Some(15), "provision cache replayed");
        assert_eq!(peer.pan(), Some(0x1a2b));
    }

    #[test]
    fn scan_split_phase_and_timeout() {
        let (mut driver, mut peer) = pair();
        form(&mut driver, &mut peer);
        let ch = Channel::new(15).unwrap();
        assert_eq!(driver.energy_scan(ch), Err(MacError::NotReady));
        pump(&mut driver, &mut peer);
        assert_eq!(
            driver.energy_scan(ch),
            Ok(15u8.wrapping_mul(7).wrapping_add(11))
        );
        // A scan nobody answers times out instead of sticking: arm a
        // scan on a new channel, then advance past its deadline
        // without ever delivering the peer's answer.
        let ch20 = Channel::new(20).unwrap();
        assert_eq!(driver.energy_scan(ch20), Err(MacError::NotReady));
        driver.advance(CMD_TIMEOUT_US);
        driver.poll();
        assert_eq!(driver.stats().scan_timeouts, 1);
    }

    #[test]
    fn interpan_path_confirms_separately() {
        let (mut driver, mut peer) = pair();
        form(&mut driver, &mut peer);
        let h = driver
            .interpan_request(
                Channel::new(15).unwrap(),
                &FramePayload::from_slice(&[0xAA]).unwrap(),
            )
            .unwrap();
        pump(&mut driver, &mut peer);
        assert_eq!(driver.poll_confirm(), None, "PAN queue stays empty");
        let c = driver.poll_interpan_confirm().unwrap();
        assert_eq!((c.handle, c.status), (h, TxStatus::Delivered));
        let tx = peer.take_tx().unwrap();
        assert!(tx.inter_pan);
    }

    #[test]
    fn trace_is_deterministic_across_runs() {
        fn run() -> Vec<TraceEvent> {
            let (mut driver, mut peer) = pair();
            form(&mut driver, &mut peer);
            let _ = driver
                .data_request(TxRequest {
                    dst: MacAddress::short(0x1a2b, 0x0002),
                    msdu: FramePayload::from_slice(&[1, 2, 3]).unwrap(),
                    options: TxOptions::ACK,
                })
                .unwrap();
            pump(&mut driver, &mut peer);
            let _ = driver.poll_confirm().unwrap();
            (0..driver.trace_len())
                .map(|i| driver.trace_at(i).unwrap())
                .collect()
        }
        assert_eq!(run(), run());
    }
}
