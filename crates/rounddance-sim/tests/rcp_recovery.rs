//! w53 RCP recovery timelines, decision-for-decision.
//!
//! A deterministic RCP session — one [`RcpDriver`] host plus one
//! [`EmulatedRcp`] firmware across a scripted UART — replaying the
//! two wave-53 reset outcomes against the injected clock:
//!
//! * j9: mid-live H2 reboot → `RECOVERED` in bounded time, the
//!   session completes (provision cache replayed, queued TX
//!   delivered, no hang);
//! * j8: dead H2 → clean `driver-fail (unrecovered)`: new frames
//!   refuse `NotReady`, the preserved queue waits, nothing wedges.
//!
//! The same file pins the drain-vs-join RX ownership fix (w53 §4c):
//! while a join ladder runs, the ladder owns RX and the ambient
//! idle drain is parked; only with no ladder running may the idle
//! path consume indications. No hardware, no wall clock — the only
//! timing is the drivers' injected clocks, so each disturbed run
//! replays exactly.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-RCP-15` (host-side recovery state machine), `RD-RCP-16`
//! (drain-vs-join RX ownership); reused `RD-RCP-06`
//! (timeout/retry) and `RD-RCP-08` (reset handshake) legs.

use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap as _, MacMgmtSap as _, TxOptions, TxRequest,
    TxStatus,
};
use rounddance_rcp::{
    EmulatedRcp, HostSide, RcpDriver, RcpStats, RecoveryState, TraceEvent, CMD_TIMEOUT_US,
};

const PAN: u16 = 0x3761;
const SHORT: u16 = 0x1204;
const PEER_SHORT: u16 = 0x0000;
const PEER_IEEE: u64 = 0xAC87_65FF_FE43_2112;
const EUI: [u8; 8] = [0x74, 0x4D, 0xBD, 0xFF, 0xFE, 0x61, 0x7A, 0xFA];

/// One deterministic RCP session: host driver + firmware peer + the
/// byte pump between them, plus the ladder/idle RX ownership flag.
struct RcpSession {
    driver: RcpDriver<HostSide>,
    peer: EmulatedRcp,
    ladder_running: bool,
    decisions: Vec<&'static str>,
}

impl RcpSession {
    fn new() -> Self {
        Self {
            driver: RcpDriver::new(HostSide::new()),
            peer: EmulatedRcp::new(),
            ladder_running: false,
            decisions: Vec::new(),
        }
    }

    fn decide(&mut self, d: &'static str) {
        self.decisions.push(d);
    }

    /// One link round-trip: driver → peer → driver.
    fn pump(&mut self) {
        let mut buf = [0u8; 512];
        let mut n = 0;
        while let Some(b) = self.driver.uart_mut().outbound.pop() {
            if n >= buf.len() {
                break;
            }
            buf[n] = b;
            n += 1;
        }
        self.peer.push_host_bytes(&buf[..n]);
        self.peer.poll();
        let m = self.peer.take_rcp_bytes(&mut buf);
        for b in &buf[..m] {
            assert!(self.driver.uart_mut().inbound.push(*b), "test FIFO fits");
        }
        self.driver.poll();
    }

    fn advance(&mut self, delta_us: u64) {
        self.driver.advance(delta_us);
    }

    /// Bring-up: reset handshake + version/caps handshake +
    /// provisioning + filtered + HW auto-ACK (the pre-assoc mode).
    fn form(&mut self) {
        self.driver.reset(true);
        self.pump();
        assert!(self.driver.ready(), "reset handshake completes");
        self.driver.query_version();
        self.pump();
        let v = self.driver.last_version().expect("version latched");
        assert_eq!(v.eui, self.peer.eui(), "EUI matches the peer");
        self.decide("version-ok");
        self.driver.set_channel(Channel::new(25).unwrap()).unwrap();
        self.driver.set_pan_id(PAN);
        self.driver.set_short_addr(SHORT);
        self.driver.set_extended_addr(PEER_IEEE);
        self.driver.set_tx_power(10).unwrap();
        self.driver.set_promiscuous_mode(false);
        self.pump();
        self.pump();
        assert!(!self.peer.promiscuous(), "filtered pre-assoc mode");
        self.decide("formed-filtered");
    }

    fn send(&mut self, byte: u8) -> TxStatus {
        let h = self
            .driver
            .data_request(TxRequest {
                dst: MacAddress::short(PAN, PEER_SHORT),
                msdu: FramePayload::from_slice(&[byte]).unwrap(),
                options: TxOptions::ACK,
            })
            .expect("queue has room");
        self.pump();
        let c = self.driver.poll_confirm().expect("peer confirms");
        assert_eq!(c.handle, h);
        c.status
    }

    /// Ambient idle drain: consumes pending RX indications ONLY when
    /// no ladder runs. Returns frames consumed.
    fn idle_drain(&mut self) -> usize {
        if self.ladder_running {
            return 0;
        }
        let mut n = 0;
        while self.driver.poll_indication().is_some() {
            n += 1;
        }
        n
    }

    /// Ladder-owned RX: the join step takes its own frame.
    fn ladder_take(&mut self) -> Option<Vec<u8>> {
        assert!(self.ladder_running, "ladder owns RX while it runs");
        self.driver
            .poll_indication()
            .map(|ind| ind.msdu.as_slice().to_vec())
    }

    fn trace(&self) -> Vec<TraceEvent> {
        (0..self.driver.trace_len())
            .map(|i| self.driver.trace_at(i).unwrap())
            .collect()
    }

    fn stats(&self) -> RcpStats {
        self.driver.stats()
    }
}

// j9: a live frame delivers, the H2 reboots mid-session, recovery
// replays provisioning and the session completes.
fn reboot_recovery_run() -> (Vec<&'static str>, Vec<TraceEvent>, RcpStats) {
    let mut s = RcpSession::new();
    s.peer.set_eui(EUI);
    s.form();
    assert_eq!(s.send(0xA1), TxStatus::Delivered);
    s.decide("confirm-delivered");
    // The H2 reboots: fresh unprovisioned firmware, queue preserved
    // on the host.
    s.peer = EmulatedRcp::new();
    s.peer.set_eui(EUI);
    s.driver.start_recovery();
    assert_eq!(s.driver.recovery_state(), RecoveryState::Recovering);
    s.decide("recover-start");
    s.pump();
    s.pump();
    assert_eq!(s.driver.recovery_state(), RecoveryState::Recovered);
    assert!(s.driver.ready());
    assert_eq!(s.peer.channel(), Some(25), "channel replayed");
    assert_eq!(s.peer.pan(), Some(PAN), "PAN replayed");
    assert_eq!(s.peer.short(), Some(SHORT), "short replayed");
    assert_eq!(s.peer.ext(), Some(PEER_IEEE), "ext replayed");
    assert!(!s.peer.promiscuous(), "filtered mode replayed");
    s.decide("recovered");
    // The session completes: TX, RX, and a leave-shaped frame all
    // cross the healed path.
    assert_eq!(s.send(0xA2), TxStatus::Delivered);
    s.decide("post-heal-delivered");
    assert_eq!(s.send(0xA3), TxStatus::Delivered);
    s.decide("leave-confirmed");
    (s.decisions.clone(), s.trace(), s.stats())
}

#[test]
fn rcp_reboot_recovers_and_replays_j9() {
    let (d1, t1, s1) = reboot_recovery_run();
    assert_eq!(
        d1,
        [
            "version-ok",
            "formed-filtered",
            "confirm-delivered",
            "recover-start",
            "recovered",
            "post-heal-delivered",
            "leave-confirmed",
        ]
    );
    assert_eq!(s1.recoveries, 1);
    assert_eq!(s1.recovery_failures, 0);
    let (d2, t2, s2) = reboot_recovery_run();
    assert_eq!((d1, t1, s1), (d2, t2, s2), "j9 timeline replays exactly");
}

// j8: the H2 dies mid-session → clean driver-fail, no hang; the
// path heals afterwards without wedging.
#[test]
fn rcp_dead_peer_fails_clean_then_heals_j8() {
    let mut s = RcpSession::new();
    s.peer.set_eui(EUI);
    s.form();
    assert_eq!(s.send(0xB1), TxStatus::Delivered, "join leg pre-fault");
    s.peer.dead = true;
    s.driver.start_recovery();
    s.decide("recover-start");
    for _ in 0..4 {
        s.advance(CMD_TIMEOUT_US);
        s.pump();
    }
    assert_eq!(s.driver.recovery_state(), RecoveryState::Failed);
    s.decide("driver-fail-unrecovered");
    assert_eq!(
        s.driver.data_request(TxRequest {
            dst: MacAddress::short(PAN, PEER_SHORT),
            msdu: FramePayload::from_slice(&[0xB2]).unwrap(),
            options: TxOptions::ACK,
        }),
        Err(rounddance_mac_sap::MacError::NotReady),
        "session aborts without hang"
    );
    assert_eq!(s.stats().recovery_failures, 1);
    // The firmware is restored (fresh unit); recovery replays the
    // cache and the preserved queue drains.
    s.peer = EmulatedRcp::new();
    s.peer.set_eui(EUI);
    s.driver.start_recovery();
    s.pump();
    s.pump();
    assert_eq!(s.driver.recovery_state(), RecoveryState::Recovered);
    assert!(s.driver.ready());
    assert_eq!(s.send(0xB3), TxStatus::Delivered, "path heals");
    s.decide("healed-after-restore");
    assert_eq!(
        s.decisions,
        [
            "version-ok",
            "formed-filtered",
            "recover-start",
            "driver-fail-unrecovered",
            "healed-after-restore",
        ]
    );
}

// w53 §4c: the ambient idle drain stole the join's own RX (the
// Timeout-Rsp). While a ladder runs, the drain is parked and the
// join frame survives for the ladder; with no ladder running the
// drain consumes ambient frames as before (j6: timeout_rsp=1).
#[test]
fn rcp_idle_drain_parks_during_ladder() {
    let mut s = RcpSession::new();
    s.peer.set_eui(EUI);
    s.form();
    s.ladder_running = true;
    assert!(s.peer.queue_rx(&[0xC1, 0xC2], -50, 200, false));
    s.pump();
    assert_eq!(s.idle_drain(), 0, "drain parked: join RX not stolen");
    let frame = s.ladder_take().expect("ladder owns its RX");
    assert_eq!(frame, [0xC1, 0xC2], "join frame survives for the ladder");
    // No ladder running: ambient RX drains as before.
    s.ladder_running = false;
    assert!(s.peer.queue_rx(&[0xD1], -60, 180, false));
    s.pump();
    assert_eq!(s.idle_drain(), 1, "idle path still consumes ambient");
    assert!(s.driver.poll_indication().is_none());
}
