//! Deterministic simulation harness skeleton.
//!
//! Same core + virtualized effects: virtual time, seeded replay, scripted
//! media/faults. Decision determinism — same seed + event script yields the
//! same emitted frames and state transitions, verified by trace comparison
//! (`SCOPE.md` §2, §8) — not byte-identical memory.
//!
//! # Determinism rules
//!
//! * The only clock is [`VirtualClock`]: `u64` microseconds, advanced
//!   explicitly by the scenario or the medium. Wall-clock time is never
//!   read.
//! * The only randomness is [`SeededRng`]: SplitMix64, `no_std`-compatible
//!   algorithm (this harness itself may use `std`, but the RNG uses only
//!   core integer ops so the same stream replays on ESP/WASM later).
//! * [`ScriptedRadio`] implements the MAC SAP traits
//!   ([`MacDataSap`](rounddance_mac_sap::MacDataSap) and
//!   [`MacMgmtSap`](rounddance_mac_sap::MacMgmtSap)) behind a scripted
//!   medium: each queued frame is delivered, dropped, or delayed per the
//!   script, with every decision appended to a virtual-time-stamped trace.
//!   Replaying the same seed + script yields the identical trace.
//!
//! # Spec-area citations
//!
//! Harness detail per `SCOPE.md` §8 (sim runs: virtual time, seeded
//! replay, scripted media/faults); requirements-seed: N-A (no sim
//! clauses; harness verifies requirements, it is not one).

#![forbid(unsafe_code)]

use rounddance_mac_sap::{
    Channel, ExtAddr, HasCapabilities, MacAddress, MacCapabilities, MacDataSap, MacError,
    MacMgmtSap, PanId, RxIndication, ShortAddr, TxConfirm, TxHandle, TxRequest, TxStatus,
};
use std::collections::VecDeque;

/// Simulation seed; the whole run's randomness derives from this value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seed(pub u64);

/// Virtual clock: explicit microsecond time, never wall-clock.
///
/// Spec area: `SCOPE.md` §8 virtual time. Time only moves via
/// [`VirtualClock::advance`], so event order is fully script-determined.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtualClock {
    now_us: u64,
}

impl VirtualClock {
    /// Clock starting at `now_us` microseconds.
    #[must_use]
    pub const fn new(now_us: u64) -> Self {
        Self { now_us }
    }

    /// Current virtual time in microseconds.
    #[must_use]
    pub const fn now_us(self) -> u64 {
        self.now_us
    }

    /// Move time forward; saturates instead of wrapping so a runaway
    /// script degrades to a stuck clock rather than time travel.
    pub fn advance(&mut self, delta_us: u64) {
        self.now_us = self.now_us.saturating_add(delta_us);
    }
}

/// Seeded RNG (SplitMix64): the only randomness in a sim run.
///
/// `no_std`-compatible by construction — core integer ops only — so the
/// same [`Seed`] replays the identical stream on host, ESP, and WASM.
/// Reference constants are the published SplitMix64 ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    /// RNG seeded from `seed`.
    #[must_use]
    pub const fn new(seed: Seed) -> Self {
        Self { state: seed.0 }
    }

    /// Next `u64` of the stream.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform value in `0..n` (`n == 0` yields `0`).
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        // Rejection-free modulo bias is acceptable for scripted faults
        // (never a security decision); determinism is what matters.
        self.next_u64() % n
    }

    /// True with probability `percent` (0 = never, 100 = always).
    pub fn chance(&mut self, percent: u8) -> bool {
        if percent >= 100 {
            return true;
        }
        self.below(100) < u64::from(percent)
    }
}

/// One scripted medium behavior applied to a queued frame, in order.
///
/// Spec area: `SCOPE.md` §8 scripted media/faults. When the script is
/// exhausted, further frames [`ScriptAction::Deliver`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptAction {
    /// Deliver to the loopback inbox and confirm [`TxStatus::Delivered`].
    Deliver,
    /// Drop on the medium; confirm [`TxStatus::NoAck`].
    Drop,
    /// Drop with `percent` probability drawn from [`SeededRng`]
    /// (deterministic per seed); otherwise deliver.
    MaybeDrop {
        /// Drop probability, 0–100.
        percent: u8,
    },
    /// Advance the virtual clock by `base_us` plus a seeded jitter in
    /// `0..=jitter_us`, then deliver.
    Delay {
        /// Fixed delay component in microseconds.
        base_us: u64,
        /// Seeded jitter bound in microseconds.
        jitter_us: u64,
    },
}

/// Frame waiting in the scripted medium.
#[derive(Clone, Debug)]
struct QueuedTx {
    handle: TxHandle,
    req: TxRequest,
    enqueued_us: u64,
}

/// Scripted-media stub implementing the MAC SAP traits.
///
/// A single node with loopback delivery: `data_request` enqueues,
/// [`ScriptedRadio::step`] pushes one frame through the next
/// [`ScriptAction`], and confirms/indications wait in FIFOs for the
/// poll accessors. Every state change appends a `t=<us>` trace line, so
/// two runs with the same seed + script produce byte-identical traces
/// (see [`round_trip_trace`]).
pub struct ScriptedRadio {
    clock: VirtualClock,
    rng: SeededRng,
    script: Vec<ScriptAction>,
    cursor: usize,
    next_handle: u32,
    queued: VecDeque<QueuedTx>,
    confirms: VecDeque<TxConfirm>,
    inbox: VecDeque<RxIndication>,
    trace: Vec<String>,
    caps: MacCapabilities,
    channel: Option<Channel>,
    pan: Option<PanId>,
    short_addr: Option<ShortAddr>,
    ext_addr: Option<ExtAddr>,
    capacity: usize,
}

impl ScriptedRadio {
    /// Fixed transmit queue depth for the skeleton (preallocated,
    /// never resized mid-run — D5, `SCOPE.md` §2).
    pub const QUEUE_CAPACITY: usize = 8;

    /// New stub node: clock at zero, `script` as the medium program.
    #[must_use]
    pub fn new(seed: Seed, script: Vec<ScriptAction>) -> Self {
        Self {
            clock: VirtualClock::new(0),
            rng: SeededRng::new(seed),
            script,
            cursor: 0,
            next_handle: 0,
            queued: VecDeque::new(),
            confirms: VecDeque::new(),
            inbox: VecDeque::new(),
            trace: Vec::new(),
            caps: MacCapabilities {
                hw_auto_ack: false,
                hw_csma_ca: false,
                hw_retries: false,
                energy_scan: true,
                frame_timestamping: true,
                promiscuous_mode: false,
            },
            channel: None,
            pan: None,
            short_addr: None,
            ext_addr: None,
            capacity: Self::QUEUE_CAPACITY,
        }
    }

    /// Current virtual time in microseconds.
    #[must_use]
    pub fn now_us(&self) -> u64 {
        self.clock.now_us()
    }

    /// Full event trace of this run (virtual-time-stamped lines).
    #[must_use]
    pub fn trace_lines(&self) -> &[String] {
        &self.trace
    }

    fn emit(&mut self, what: impl Into<String>) {
        self.trace
            .push(format!("t={} {}", self.clock.now_us(), what.into()));
    }

    /// Push the oldest queued frame through the next script action.
    /// Returns false when the queue was empty.
    pub fn step(&mut self) -> bool {
        let Some(q) = self.queued.pop_front() else {
            return false;
        };
        let action = self
            .script
            .get(self.cursor)
            .copied()
            .unwrap_or(ScriptAction::Deliver);
        self.cursor += 1;
        let handle = q.handle;
        match action {
            ScriptAction::Deliver => self.deliver(q, TxStatus::Delivered, "deliver"),
            ScriptAction::Drop => {
                self.emit(format!("drop handle={} len={}", handle.0, q.req.msdu.len()));
                self.confirms.push_back(TxConfirm {
                    handle,
                    status: TxStatus::NoAck,
                    timestamp_us: Some(self.clock.now_us()),
                });
                self.emit(format!("confirm handle={} status=NoAck", handle.0));
            }
            ScriptAction::MaybeDrop { percent } => {
                if self.rng.chance(percent) {
                    self.emit(format!(
                        "drop handle={} len={} p={percent}",
                        handle.0,
                        q.req.msdu.len()
                    ));
                    self.confirms.push_back(TxConfirm {
                        handle,
                        status: TxStatus::NoAck,
                        timestamp_us: Some(self.clock.now_us()),
                    });
                    self.emit(format!("confirm handle={} status=NoAck", handle.0));
                } else {
                    self.deliver(q, TxStatus::Delivered, "deliver");
                }
            }
            ScriptAction::Delay { base_us, jitter_us } => {
                let jitter = self.rng.below(jitter_us.saturating_add(1));
                self.clock.advance(base_us.saturating_add(jitter));
                self.deliver(q, TxStatus::Delivered, "delayed-deliver");
            }
        }
        true
    }

    fn deliver(&mut self, q: QueuedTx, status: TxStatus, verb: &str) {
        let handle = q.handle;
        let len = q.req.msdu.len();
        let queued_us = self.clock.now_us().saturating_sub(q.enqueued_us);
        self.emit(format!(
            "{verb} handle={} len={len} queued_us={queued_us}",
            handle.0
        ));
        self.inbox.push_back(RxIndication {
            src: MacAddress::short(self.pan.unwrap_or(0), self.short_addr.unwrap_or(0)),
            lqi: 200,
            timestamp_us: Some(self.clock.now_us()),
            msdu: q.req.msdu,
        });
        self.emit(format!("rx len={len}"));
        self.confirms.push_back(TxConfirm {
            handle,
            status,
            timestamp_us: Some(self.clock.now_us()),
        });
        self.emit(format!("confirm handle={} status=Delivered", handle.0));
    }

    /// Step until no frame is queued or `max_steps` is reached.
    pub fn run_until_idle(&mut self, max_steps: usize) {
        for _ in 0..max_steps {
            if !self.step() {
                break;
            }
        }
    }
}

impl HasCapabilities for ScriptedRadio {
    fn capabilities(&self) -> MacCapabilities {
        self.caps
    }
}

impl MacDataSap for ScriptedRadio {
    fn data_request(&mut self, req: TxRequest) -> Result<TxHandle, MacError> {
        if req.msdu.len() > rounddance_mac_sap::MAX_MSDU_LEN {
            return Err(MacError::FrameTooLong);
        }
        if matches!(req.dst.addr, rounddance_mac_sap::AddrMode::None) {
            return Err(MacError::InvalidAddress);
        }
        if self.queued.len() >= self.capacity {
            return Err(MacError::QueueFull);
        }
        let handle = TxHandle(self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1);
        self.emit(format!("tx handle={} len={}", handle.0, req.msdu.len()));
        self.queued.push_back(QueuedTx {
            handle,
            req,
            enqueued_us: self.clock.now_us(),
        });
        Ok(handle)
    }

    fn data_cancel(&mut self, handle: TxHandle) -> Result<(), MacError> {
        let Some(pos) = self.queued.iter().position(|q| q.handle == handle) else {
            return Err(MacError::UnknownHandle);
        };
        self.queued.remove(pos);
        self.emit(format!("cancel handle={}", handle.0));
        self.confirms.push_back(TxConfirm {
            handle,
            status: TxStatus::Cancelled,
            timestamp_us: Some(self.clock.now_us()),
        });
        self.emit(format!("confirm handle={} status=Cancelled", handle.0));
        Ok(())
    }

    fn poll_confirm(&mut self) -> Option<TxConfirm> {
        self.confirms.pop_front()
    }

    fn poll_indication(&mut self) -> Option<RxIndication> {
        self.inbox.pop_front()
    }

    fn tx_queue_free(&self) -> usize {
        self.capacity - self.queued.len()
    }

    fn tx_queue_capacity(&self) -> usize {
        self.capacity
    }
}

impl MacMgmtSap for ScriptedRadio {
    fn reset(&mut self, cold: bool) {
        self.queued.clear();
        self.confirms.clear();
        self.inbox.clear();
        if cold {
            self.channel = None;
            self.pan = None;
            self.short_addr = None;
            self.ext_addr = None;
        }
        self.emit(format!("reset cold={cold}"));
    }

    fn set_channel(&mut self, channel: Channel) -> Result<(), MacError> {
        self.channel = Some(channel);
        self.emit(format!("set-channel {}", channel.number()));
        Ok(())
    }

    fn set_short_addr(&mut self, addr: ShortAddr) {
        self.short_addr = Some(addr);
        self.emit(format!("set-short-addr {addr:#06x}"));
    }

    fn set_extended_addr(&mut self, addr: ExtAddr) {
        self.ext_addr = Some(addr);
        self.emit("set-extended-addr");
    }

    fn set_pan_id(&mut self, pan: PanId) {
        self.pan = Some(pan);
        self.emit(format!("set-pan-id {pan:#06x}"));
    }

    fn energy_scan(&mut self, channel: Channel) -> Result<u8, MacError> {
        // Deterministic dummy: pure function of the channel, no RNG
        // draw, so scans never perturb the fault-decision stream.
        Ok(channel.number().wrapping_mul(7).wrapping_add(11))
    }
}

/// Single-node send/receive round-trip scenario.
///
/// Brings a [`ScriptedRadio`] up (channel 15, PAN `0x1a2b`, short address
/// `0x0001`), sends `payload` with ACK requested, drains the medium, and
/// returns the virtual-time-stamped trace. Replaying with the same seed +
/// script yields the identical trace — the decision-determinism check.
///
/// # Example
///
/// ```
/// use rounddance_sim::{ScriptAction, round_trip_trace};
///
/// let trace = round_trip_trace(42, &[ScriptAction::Deliver], &[0x01, 0x02]);
/// assert!(trace.iter().any(|l| l.contains("confirm handle=0 status=Delivered")));
/// assert!(trace.iter().any(|l| l.contains("rx len=2")));
/// ```
pub fn round_trip_trace(seed: u64, script: &[ScriptAction], payload: &[u8]) -> Vec<String> {
    use rounddance_mac_sap::{FramePayload, TxOptions};

    let mut radio = ScriptedRadio::new(Seed(seed), script.to_vec());
    radio.reset(true);
    radio
        .set_channel(Channel::new(15).expect("15 is valid"))
        .expect("stub ready");
    radio.set_pan_id(0x1a2b);
    radio.set_short_addr(0x0001);
    let req = TxRequest {
        dst: MacAddress::short(0x1a2b, 0x0002),
        msdu: FramePayload::from_slice(payload).expect("scenario payload fits"),
        options: TxOptions::ACK,
    };
    radio.data_request(req).expect("queue has room");
    radio.run_until_idle(16);
    let confirm = radio.poll_confirm().expect("script always confirms");
    assert_eq!(
        confirm.status,
        TxStatus::Delivered,
        "scenario script must deliver"
    );
    assert!(
        radio.poll_indication().is_some(),
        "delivery implies an rx indication"
    );
    radio.trace_lines().to_vec()
}

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-sim"
}

#[cfg(test)]
mod tests {
    use super::*;
    use rounddance_mac_sap::{FramePayload, TxOptions};

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
        assert_eq!(Seed(42), Seed(42));
    }

    #[test]
    fn clock_only_moves_explicitly() {
        let mut c = VirtualClock::new(100);
        assert_eq!(c.now_us(), 100);
        c.advance(50);
        assert_eq!(c.now_us(), 150);
        c.advance(u64::MAX);
        assert_eq!(c.now_us(), u64::MAX, "saturates, never wraps");
    }

    #[test]
    fn rng_replays_per_seed() {
        let mut a = SeededRng::new(Seed(7));
        let mut b = SeededRng::new(Seed(7));
        for _ in 0..16 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut c = SeededRng::new(Seed(8));
        assert_ne!(a.next_u64(), c.next_u64(), "distinct seeds diverge");
        // chance() boundaries are exact, no sampling involved.
        let mut r = SeededRng::new(Seed(1));
        assert!(r.chance(100));
        assert!(!r.chance(0));
        assert_eq!(r.below(0), 0);
    }

    #[test]
    fn replay_twice_identical_trace() {
        let script = vec![
            ScriptAction::Delay {
                base_us: 320,
                jitter_us: 100,
            },
            ScriptAction::MaybeDrop { percent: 50 },
            ScriptAction::Deliver,
            ScriptAction::Drop,
        ];
        let payload = [0x01, 0x02, 0x03, 0x04];
        let first = round_trip_trace(0x1234_5678, &script, &payload);
        let second = round_trip_trace(0x1234_5678, &script, &payload);
        assert!(!first.is_empty());
        assert_eq!(first, second, "same seed + script must replay identically");
    }

    #[test]
    fn script_changes_trace() {
        let payload = [0xAA];
        let delivered = round_trip_trace(99, &[ScriptAction::Deliver], &payload);
        // A dropping script never yields the Delivered confirm path.
        let mut radio = ScriptedRadio::new(Seed(99), vec![ScriptAction::Drop]);
        radio.reset(true);
        let req = TxRequest {
            dst: MacAddress::short(0x1a2b, 0x0002),
            msdu: FramePayload::from_slice(&payload).expect("fits"),
            options: TxOptions::ACK,
        };
        radio.data_request(req).expect("room");
        radio.run_until_idle(8);
        let confirm = radio.poll_confirm().expect("drop still confirms");
        assert_eq!(confirm.status, TxStatus::NoAck);
        assert!(
            radio.poll_indication().is_none(),
            "dropped frame never arrives"
        );
        let dropped_trace = radio.trace_lines().to_vec();
        assert_ne!(delivered, dropped_trace);
    }

    #[test]
    fn backpressure_and_cancel_hooks() {
        let mut radio = ScriptedRadio::new(Seed(0), vec![]);
        assert_eq!(radio.tx_queue_capacity(), ScriptedRadio::QUEUE_CAPACITY);
        assert!(!radio.tx_queue_full());
        let mut handles = Vec::new();
        for _ in 0..ScriptedRadio::QUEUE_CAPACITY {
            let req = TxRequest {
                dst: MacAddress::short(0x1a2b, 0x0002),
                msdu: FramePayload::from_slice(&[0x00]).expect("fits"),
                options: TxOptions::NONE,
            };
            handles.push(radio.data_request(req).expect("room"));
        }
        assert!(radio.tx_queue_full());
        assert_eq!(radio.tx_queue_free(), 0);
        let req = TxRequest {
            dst: MacAddress::short(0x1a2b, 0x0002),
            msdu: FramePayload::from_slice(&[0x00]).expect("fits"),
            options: TxOptions::NONE,
        };
        assert_eq!(radio.data_request(req), Err(MacError::QueueFull));
        // Cancel frees the slot and reports Cancelled.
        radio.data_cancel(handles[0]).expect("outstanding handle");
        assert!(!radio.tx_queue_full());
        assert_eq!(radio.data_cancel(handles[0]), Err(MacError::UnknownHandle));
        let confirm = radio.poll_confirm().expect("cancel confirms");
        assert_eq!(confirm.status, TxStatus::Cancelled);
    }

    #[test]
    fn mgmt_reports_capabilities_and_scans() {
        let mut radio = ScriptedRadio::new(Seed(3), vec![]);
        let caps = radio.capabilities();
        assert!(caps.energy_scan);
        assert!(caps.frame_timestamping);
        assert!(!caps.hw_auto_ack, "stub synthesizes ACKs above the HAL");
        let e15 = radio.energy_scan(Channel::new(15).unwrap()).expect("scan");
        let e15b = radio.energy_scan(Channel::new(15).unwrap()).expect("scan");
        assert_eq!(e15, e15b, "scan is a pure function of channel");
    }
}
