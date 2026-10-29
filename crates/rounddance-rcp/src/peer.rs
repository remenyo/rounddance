//! Scripted H2-firmware model: the RCP side of the wire for tests.
//!
//! [`EmulatedRcp`] speaks [`crate::cmd`] over two FIFOs, applies
//! commands to a small radio-state model (channel, TX power, PAN,
//! addresses), and answers exactly where the real firmware would:
//! [`Event::Ready`](crate::Event::Ready) after reset, [`Event`]
//! confirms per TX, [`Event::EnergyResult`](crate::Event::EnergyResult)
//! per scan. It is a contract pin, not a firmware: timing is
//! immediate (the test harness moves the bytes), and every fault the
//! driver must survive is scriptable — dropped confirms (timeout),
//! corrupted responses (CRC desync), raw garbage (framing desync),
//! forced error events, and queued inbound air frames.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-RCP-09` (power-cap mirror), `RD-RCP-10` (scripted faults),
//! `RD-RCP-12` (promiscuous/filtered mirror), `RD-RCP-13`
//! (version answers), `RD-RCP-14` (SHORT-SNOOP latch).

use crate::cmd::{
    Command, Event, TxOutcome, E_BAD_CHANNEL, E_BAD_COMMAND, E_POWER_CAPPED, MAX_PSDU,
};
use crate::frame::{Decoder, Outcome};
use crate::uart::{LoopPipe, LINK_BYTES};
use crate::{MAX_TX_POWER_DBM, RCP_CAPS, RCP_FW_VERSION, RCP_PROTO_VERSION};

/// Energy reported for a channel: pure function of the channel, so
/// scans never perturb any deterministic stream (same convention as
/// the sim harness).
#[must_use]
pub const fn channel_energy(channel: u8) -> u8 {
    channel.wrapping_mul(7).wrapping_add(11)
}

/// One radiated frame, as the test medium sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Radiated {
    /// True = inter-PAN path.
    pub inter_pan: bool,
    /// Live PSDU length.
    pub len: u8,
    /// PSDU bytes (first `len` live).
    pub psdu: [u8; MAX_PSDU],
}

/// Peer diagnostics (all counters saturate, never wrap).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerStats {
    /// Reset commands honoured.
    pub resets: u32,
    /// TX commands received.
    pub tx_received: u32,
    /// TX confirms emitted.
    pub confirms_sent: u32,
    /// Confirms deliberately dropped by script.
    pub confirms_dropped: u32,
    /// Scan commands answered.
    pub scans: u32,
    /// Inbound air frames emitted as RX events.
    pub rx_emitted: u32,
    /// Malformed command frames rejected with [`E_BAD_COMMAND`].
    pub bad_commands: u32,
    /// Association-response shorts latched by the SHORT-SNOOP.
    pub short_snoops: u32,
}

/// The emulated H2 RCP firmware.
pub struct EmulatedRcp {
    inbound: LoopPipe<LINK_BYTES>,
    outbound: LoopPipe<LINK_BYTES>,
    decoder: Decoder,
    channel: Option<u8>,
    tx_power_dbm: i8,
    pan: Option<u16>,
    short: Option<u16>,
    ext: Option<u64>,
    promiscuous: bool,
    eui: [u8; 8],
    /// Scripted dead-H2 fault: while set, [`EmulatedRcp::poll`] is a
    /// no-op — no Ready, no confirms, no RX — modelling the
    /// download-parked / powered-down unit. Revive by clearing it
    /// (or by swapping in a fresh peer, modelling a reboot).
    pub dead: bool,
    event_seq: u8,
    /// Next `n` TX commands radiate but get no confirm (timeout path).
    pub drop_confirms: u8,
    /// Status the next confirms carry.
    pub confirm_status: TxOutcome,
    /// Next `n` emitted responses get a flipped octet (CRC desync).
    pub corrupt_next: u8,
    /// Garbage runs prepended before the next `n` responses.
    pub garbage_next: u8,
    /// Error event emitted on the next [`EmulatedRcp::poll`], if set.
    pub error_next: Option<u8>,
    tx_log: [Option<Radiated>; 8],
    pending_rx: [Option<PendingRx>; 8],
    /// Diagnostics.
    pub stats: PeerStats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingRx {
    inter_pan: bool,
    rssi: i8,
    lqi: u8,
    len: u8,
    psdu: [u8; MAX_PSDU],
}

impl EmulatedRcp {
    /// Fresh firmware: unprovisioned, TX power 0 dBm, ready pending
    /// the first reset handshake.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inbound: LoopPipe::new(),
            outbound: LoopPipe::new(),
            decoder: Decoder::new(),
            channel: None,
            tx_power_dbm: 0,
            pan: None,
            short: None,
            ext: None,
            promiscuous: true,
            eui: [0u8; 8],
            dead: false,
            event_seq: 0,
            drop_confirms: 0,
            confirm_status: TxOutcome::Delivered,
            corrupt_next: 0,
            garbage_next: 0,
            error_next: None,
            tx_log: [None, None, None, None, None, None, None, None],
            pending_rx: [None, None, None, None, None, None, None, None],
            stats: PeerStats {
                resets: 0,
                tx_received: 0,
                confirms_sent: 0,
                confirms_dropped: 0,
                scans: 0,
                rx_emitted: 0,
                bad_commands: 0,
                short_snoops: 0,
            },
        }
    }

    /// Programmed channel, if any.
    #[must_use]
    pub const fn channel(&self) -> Option<u8> {
        self.channel
    }

    /// Programmed TX power in dBm.
    #[must_use]
    pub const fn tx_power_dbm(&self) -> i8 {
        self.tx_power_dbm
    }

    /// Programmed PAN, if any.
    #[must_use]
    pub const fn pan(&self) -> Option<u16> {
        self.pan
    }

    /// Programmed short address, if any.
    #[must_use]
    pub const fn short(&self) -> Option<u16> {
        self.short
    }

    /// Programmed extended address, if any.
    #[must_use]
    pub const fn ext(&self) -> Option<u64> {
        self.ext
    }

    /// Receive mode: true = promiscuous (all frames, no HW ACK —
    /// the firmware boot default), false = filtered + HW auto-ACK.
    #[must_use]
    pub const fn promiscuous(&self) -> bool {
        self.promiscuous
    }

    /// 15.4 EUI-64 reported by the version handshake.
    #[must_use]
    pub const fn eui(&self) -> [u8; 8] {
        self.eui
    }

    /// Set the EUI-64 reported by the version handshake.
    pub fn set_eui(&mut self, eui: [u8; 8]) {
        self.eui = eui;
    }

    /// Latch the assigned short from our own association response
    /// before any slower path runs. The transport follows the
    /// response within milliseconds, so the filtered-address check
    /// only still matches when the short is already latched here —
    /// the host's confirm (see
    /// [`crate::driver::RcpDriver::note_assoc_response`]) is the
    /// idempotent second copy.
    fn snoop_assoc_short(&mut self, psdu: &[u8]) {
        let pan = match self.pan {
            Some(p) => p,
            None => return,
        };
        let ext = match self.ext {
            Some(e) => e,
            None => return,
        };
        if psdu.len() < 13 {
            return;
        }
        let fcf = u16::from_le_bytes([psdu[0], psdu[1]]);
        if fcf & 0x07 != 0x03 {
            return;
        }
        if (fcf >> 10) & 0x03 != 0x03 {
            return;
        }
        if u16::from_le_bytes([psdu[3], psdu[4]]) != pan {
            return;
        }
        let mut dst = [0u8; 8];
        dst.copy_from_slice(&psdu[5..13]);
        if u64::from_le_bytes(dst) != ext {
            return;
        }
        let moff = match (fcf >> 14) & 0x03 {
            0x02 => 15,
            0x03 => 21,
            _ => return,
        };
        if psdu.len() < moff + 4 {
            return;
        }
        if psdu[moff] != 0x02 || psdu[moff + 3] != 0x00 {
            return;
        }
        let short = u16::from_le_bytes([psdu[moff + 1], psdu[moff + 2]]);
        if short != 0xFFFF && Some(short) != self.short {
            self.short = Some(short);
            self.stats.short_snoops = self.stats.short_snoops.saturating_add(1);
        }
    }

    /// Feed host-side bytes into the peer (test harness moves them
    /// from the driver's outbound FIFO). Full FIFO refuses the tail;
    /// the refused count is returned (never silent loss).
    pub fn push_host_bytes(&mut self, bytes: &[u8]) -> usize {
        let mut refused = 0;
        for b in bytes {
            if !self.inbound.push(*b) {
                refused += 1;
            }
        }
        refused
    }

    /// Drain peer-side bytes toward the host; returns bytes moved.
    pub fn take_rcp_bytes(&mut self, out: &mut [u8]) -> usize {
        let mut n = 0;
        while n < out.len() {
            match self.outbound.pop() {
                Some(b) => {
                    out[n] = b;
                    n += 1;
                }
                None => break,
            }
        }
        n
    }

    /// Queue one inbound air frame for emission as an RX event on the
    /// next [`EmulatedRcp::poll`]; `false` when the RX queue is full.
    /// The SHORT-SNOOP runs first, so an association response latches
    /// its short even when the RX queue is full.
    pub fn queue_rx(&mut self, psdu: &[u8], rssi: i8, lqi: u8, inter_pan: bool) -> bool {
        if psdu.len() > MAX_PSDU {
            return false;
        }
        self.snoop_assoc_short(psdu);
        let mut buf = [0u8; MAX_PSDU];
        buf[..psdu.len()].copy_from_slice(psdu);
        let rx = PendingRx {
            inter_pan,
            rssi,
            lqi,
            len: psdu.len() as u8,
            psdu: buf,
        };
        for slot in self.pending_rx.iter_mut() {
            if slot.is_none() {
                *slot = Some(rx);
                return true;
            }
        }
        false
    }

    /// Take the oldest radiated frame, if any (test medium moves it
    /// to the far peer's RX queue).
    pub fn take_tx(&mut self) -> Option<Radiated> {
        for slot in self.tx_log.iter_mut() {
            if slot.is_some() {
                return slot.take();
            }
        }
        None
    }

    /// True when a radiated frame is waiting.
    #[must_use]
    pub fn has_tx(&self) -> bool {
        self.tx_log.iter().any(Option::is_some)
    }

    fn emit_raw(&mut self, bytes: &[u8]) {
        // Bounded FIFOs: on overflow the tail is refused and counted
        // by the harness via push/take accounting, never panics.
        for b in bytes {
            if !self.outbound.push(*b) {
                break;
            }
        }
    }

    fn emit(&mut self, ev: &Event) {
        let mut wire = [0u8; 256];
        let seq = self.event_seq;
        self.event_seq = self.event_seq.wrapping_add(1);
        let n = ev.encode(seq, &mut wire).unwrap_or(0);
        if n == 0 {
            return;
        }
        if self.garbage_next > 0 {
            self.garbage_next -= 1;
            // A SYNC-led run with an illegal LEN: forces one
            // BadLen drop on the host, then the real frame parses.
            self.emit_raw(&[0x00, 0xA5, 0x01, 0xFF]);
        }
        if self.corrupt_next > 0 {
            self.corrupt_next -= 1;
            let mut corrupt = [0u8; 256];
            corrupt[..n].copy_from_slice(&wire[..n]);
            corrupt[n - 1] ^= 0xFF;
            self.emit_raw(&corrupt[..n]);
        } else {
            self.emit_raw(&wire[..n]);
        }
    }

    fn emit_error(&mut self, code: u8) {
        self.emit(&Event::Error { code });
    }

    fn log_tx(&mut self, inter_pan: bool, len: u8, psdu: &[u8; MAX_PSDU]) {
        let radiated = Radiated {
            inter_pan,
            len,
            psdu: *psdu,
        };
        for slot in self.tx_log.iter_mut() {
            if slot.is_none() {
                *slot = Some(radiated);
                return;
            }
        }
        // Log full: oldest entry is evicted (radiated frames are
        // also visible in driver-side traces; the log is a test aid).
        for i in 1..self.tx_log.len() {
            self.tx_log[i - 1] = self.tx_log[i].take();
        }
        self.tx_log[self.tx_log.len() - 1] = Some(radiated);
    }

    fn handle(&mut self, frame: &crate::frame::Frame) {
        let cmd = match Command::decode(frame) {
            Ok(c) => c,
            Err(_) => {
                self.stats.bad_commands = self.stats.bad_commands.saturating_add(1);
                self.emit_error(E_BAD_COMMAND);
                return;
            }
        };
        match cmd {
            Command::Reset { cold } => {
                if cold {
                    self.channel = None;
                    self.pan = None;
                    self.short = None;
                    self.ext = None;
                }
                self.stats.resets = self.stats.resets.saturating_add(1);
                self.emit(&Event::Ready {
                    fw_version: RCP_FW_VERSION,
                });
            }
            Command::SetChannel { channel } => {
                if !(11..=26).contains(&channel) {
                    self.emit_error(E_BAD_CHANNEL);
                } else {
                    self.channel = Some(channel);
                }
            }
            Command::SetTxPower { dbm } => {
                if dbm > MAX_TX_POWER_DBM {
                    // Standing lab policy, mirrored in firmware: hotter
                    // requests are refused, never applied.
                    self.emit_error(E_POWER_CAPPED);
                } else {
                    self.tx_power_dbm = dbm;
                }
            }
            Command::SetPanId { pan } => {
                self.pan = Some(pan);
            }
            Command::SetShortAddr { addr } => {
                self.short = Some(addr);
            }
            Command::SetExtAddr { addr } => {
                self.ext = Some(addr);
            }
            Command::TxFrame {
                inter_pan,
                len,
                psdu,
            } => {
                self.stats.tx_received = self.stats.tx_received.saturating_add(1);
                self.log_tx(inter_pan, len, &psdu);
                if self.drop_confirms > 0 {
                    self.drop_confirms -= 1;
                    self.stats.confirms_dropped = self.stats.confirms_dropped.saturating_add(1);
                } else {
                    self.stats.confirms_sent = self.stats.confirms_sent.saturating_add(1);
                    self.emit(&Event::TxConfirm {
                        seq: frame.seq,
                        status: self.confirm_status,
                    });
                }
            }
            Command::EnergyScan { channel } => {
                self.stats.scans = self.stats.scans.saturating_add(1);
                self.emit(&Event::EnergyResult {
                    channel,
                    energy: channel_energy(channel),
                });
            }
            Command::GetVersion => {
                self.emit(&Event::Version {
                    fw_version: RCP_FW_VERSION,
                    proto_version: RCP_PROTO_VERSION,
                    caps: RCP_CAPS,
                    eui: self.eui,
                });
            }
            Command::SetPromiscuous { promiscuous } => {
                self.promiscuous = promiscuous;
            }
        }
    }

    /// Process all queued host bytes and emit due responses, queued
    /// RX events, and any forced error event. A [`EmulatedRcp::dead`]
    /// peer does nothing at all.
    pub fn poll(&mut self) {
        if self.dead {
            return;
        }
        while let Some(b) = self.inbound.pop() {
            match self.decoder.push_byte(b) {
                Some(Outcome::Frame(f)) => self.handle(&f),
                Some(Outcome::Dropped(_)) => {
                    self.stats.bad_commands = self.stats.bad_commands.saturating_add(1);
                    self.emit_error(E_BAD_COMMAND);
                }
                None => {}
            }
        }
        if let Some(code) = self.error_next.take() {
            self.emit_error(code);
        }
        for i in 0..self.pending_rx.len() {
            let rx = self.pending_rx[i].take();
            if let Some(rx) = rx {
                self.stats.rx_emitted = self.stats.rx_emitted.saturating_add(1);
                self.emit(&Event::RxFrame {
                    inter_pan: rx.inter_pan,
                    rssi: rx.rssi,
                    lqi: rx.lqi,
                    len: rx.len,
                    psdu: rx.psdu,
                });
            }
        }
    }
}

impl Default for EmulatedRcp {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn drive(peer: &mut EmulatedRcp, cmd: &Command, seq: u8) {
        let mut wire = [0u8; 256];
        let n = cmd.encode(seq, &mut wire).unwrap();
        assert_eq!(peer.push_host_bytes(&wire[..n]), 0);
        peer.poll();
    }

    fn collect(peer: &mut EmulatedRcp) -> Vec<Event> {
        let mut raw = [0u8; 1024];
        let n = peer.take_rcp_bytes(&mut raw);
        let mut dec = Decoder::new();
        let mut evs = Vec::new();
        for b in &raw[..n] {
            if let Some(Outcome::Frame(f)) = dec.push_byte(*b) {
                evs.push(Event::decode(&f).unwrap());
            }
        }
        evs
    }

    #[test]
    fn reset_provision_tx_scan_cycle() {
        let mut peer = EmulatedRcp::new();
        drive(&mut peer, &Command::Reset { cold: true }, 1);
        assert_eq!(
            collect(&mut peer),
            [Event::Ready {
                fw_version: RCP_FW_VERSION
            }]
        );
        drive(&mut peer, &Command::SetChannel { channel: 15 }, 2);
        drive(&mut peer, &Command::SetPanId { pan: 0x1a2b }, 3);
        drive(&mut peer, &Command::SetShortAddr { addr: 7 }, 4);
        drive(
            &mut peer,
            &Command::SetExtAddr {
                addr: 0x0200_0000_0000_0002,
            },
            5,
        );
        drive(&mut peer, &Command::SetTxPower { dbm: 10 }, 6);
        assert!(collect(&mut peer).is_empty(), "sets are ack-less");
        assert_eq!(peer.channel(), Some(15));
        assert_eq!(peer.pan(), Some(0x1a2b));
        assert_eq!(peer.short(), Some(7));
        assert_eq!(peer.tx_power_dbm(), 10);

        let mut psdu = [0u8; MAX_PSDU];
        psdu[..2].copy_from_slice(&[0xDE, 0xAD]);
        drive(
            &mut peer,
            &Command::TxFrame {
                inter_pan: false,
                len: 2,
                psdu,
            },
            0x41,
        );
        assert_eq!(
            collect(&mut peer),
            [Event::TxConfirm {
                seq: 0x41,
                status: TxOutcome::Delivered
            }]
        );
        let tx = peer.take_tx().unwrap();
        assert_eq!(&tx.psdu[..2], &[0xDE, 0xAD]);

        drive(&mut peer, &Command::EnergyScan { channel: 15 }, 9);
        assert_eq!(
            collect(&mut peer),
            [Event::EnergyResult {
                channel: 15,
                energy: channel_energy(15)
            }]
        );
    }

    #[test]
    fn guards_reject_out_of_policy() {
        let mut peer = EmulatedRcp::new();
        drive(&mut peer, &Command::SetChannel { channel: 30 }, 1);
        assert_eq!(
            collect(&mut peer),
            [Event::Error {
                code: E_BAD_CHANNEL
            }]
        );
        assert_eq!(peer.channel(), None);
        drive(&mut peer, &Command::SetTxPower { dbm: 20 }, 2);
        assert_eq!(
            collect(&mut peer),
            [Event::Error {
                code: E_POWER_CAPPED
            }]
        );
        assert_eq!(peer.tx_power_dbm(), 0, "hot request never applied");
    }

    const SNOOP_EXT: u64 = 0xAC87_65FF_FE43_2112;

    fn assoc_rsp_psdu(pan: u16, ext: u64, assigned: u16, status: u8) -> [u8; 19] {
        // MAC command, long dest, short source: FCF 0x8C03, seq,
        // dst pan + dst ext, src short, then the assoc-rsp body
        // (id 0x02, assigned short, status).
        let mut psdu = [0u8; 19];
        psdu[0..2].copy_from_slice(&0x8C03u16.to_le_bytes());
        psdu[2] = 0x55;
        psdu[3..5].copy_from_slice(&pan.to_le_bytes());
        psdu[5..13].copy_from_slice(&ext.to_le_bytes());
        psdu[13..15].copy_from_slice(&0x0000u16.to_le_bytes());
        psdu[15] = 0x02;
        psdu[16..18].copy_from_slice(&assigned.to_le_bytes());
        psdu[18] = status;
        psdu
    }

    #[test]
    fn version_promiscuous_and_dead_fault() {
        let mut peer = EmulatedRcp::new();
        assert!(peer.promiscuous(), "firmware boots promiscuous");
        drive(
            &mut peer,
            &Command::SetPromiscuous { promiscuous: false },
            1,
        );
        assert!(collect(&mut peer).is_empty(), "mode set is ack-less");
        assert!(!peer.promiscuous(), "filtered + HW auto-ACK");
        drive(&mut peer, &Command::SetPromiscuous { promiscuous: true }, 2);
        assert!(peer.promiscuous());
        let eui = [0x74, 0x4D, 0xBD, 0xFF, 0xFE, 0x61, 0x7A, 0xFA];
        peer.set_eui(eui);
        drive(&mut peer, &Command::GetVersion, 3);
        assert_eq!(
            collect(&mut peer),
            [Event::Version {
                fw_version: RCP_FW_VERSION,
                proto_version: RCP_PROTO_VERSION,
                caps: RCP_CAPS,
                eui,
            }]
        );
        peer.dead = true;
        drive(&mut peer, &Command::Reset { cold: false }, 4);
        assert!(collect(&mut peer).is_empty(), "dead peer answers nothing");
    }

    #[test]
    fn short_snoop_latches_assoc_short() {
        let mut peer = EmulatedRcp::new();
        drive(&mut peer, &Command::SetPanId { pan: 0x3761 }, 1);
        drive(&mut peer, &Command::SetExtAddr { addr: SNOOP_EXT }, 2);
        assert!(collect(&mut peer).is_empty());
        assert_eq!(peer.short(), None);
        // Wrong PAN: ignored.
        let foreign = assoc_rsp_psdu(0x1234, SNOOP_EXT, 0x1204, 0x00);
        assert!(peer.queue_rx(&foreign, -50, 200, false));
        assert_eq!(peer.short(), None);
        // Denied status: ignored.
        let denied = assoc_rsp_psdu(0x3761, SNOOP_EXT, 0x1204, 0x01);
        assert!(peer.queue_rx(&denied, -50, 200, false));
        assert_eq!(peer.short(), None);
        // Success: latched at queue time, before any poll.
        let rsp = assoc_rsp_psdu(0x3761, SNOOP_EXT, 0x1204, 0x00);
        assert!(peer.queue_rx(&rsp, -50, 200, false));
        assert_eq!(peer.short(), Some(0x1204), "snooped pre-emit");
        assert_eq!(peer.stats.short_snoops, 1);
        // Still emitted as a normal RX event for the host.
        peer.poll();
        let evs = collect(&mut peer);
        assert_eq!(evs.len(), 3, "all three queued frames emit");
        assert!(matches!(evs[2], Event::RxFrame { len: 19, .. }));
    }

    #[test]
    fn rx_queue_emits_events() {
        let mut peer = EmulatedRcp::new();
        assert!(peer.queue_rx(&[9, 8, 7], -60, 180, false));
        peer.poll();
        assert_eq!(
            collect(&mut peer),
            [Event::RxFrame {
                inter_pan: false,
                rssi: -60,
                lqi: 180,
                len: 3,
                psdu: {
                    let mut p = [0u8; MAX_PSDU];
                    p[..3].copy_from_slice(&[9, 8, 7]);
                    p
                },
            }]
        );
    }
}
