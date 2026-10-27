//! Host loopback radio pair: two MAC SAP endpoints joined by a
//! shared tick-clocked medium.
//!
//! [`HostMedium::pair`] returns two [`HostRadio`] endpoints (node A
//! and node B) that share one medium: a frame queued on A is
//! delivered to B's inbox (and confirmed to A) when the harness
//! calls [`HostMedium::pump`]. Every medium step advances the
//! shared tick clock by a fixed quantum plus seeded jitter and
//! appends a trace line, so same-seed runs agree tick-for-tick on
//! native and WASM.
//!
//! Capability report is honest: no hardware ACK / CSMA / retries
//! (the harness confirms above the HAL), no energy scan (there is
//! no real front end), frame timestamps from the tick clock.

use rounddance_mac_sap::{
    AddrMode, Channel, ExtAddr, HasCapabilities, MacAddress, MacCapabilities, MacDataSap, MacError,
    MacMgmtSap, PanId, RxIndication, ShortAddr, TxConfirm, TxHandle, TxRequest, TxStatus,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

/// Which endpoint of the pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeId {
    /// First endpoint.
    A,
    /// Second endpoint.
    B,
}

impl NodeId {
    /// The other endpoint.
    #[must_use]
    pub const fn peer(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// One frame in flight on the shared medium.
#[derive(Clone, Debug)]
struct InFlight {
    handle: TxHandle,
    from: NodeId,
    req: TxRequest,
    enqueued_us: u64,
}

#[derive(Debug)]
struct MediumInner {
    clock_us: u64,
    jitter_state: u64,
    in_flight: VecDeque<InFlight>,
    inbox_a: VecDeque<RxIndication>,
    inbox_b: VecDeque<RxIndication>,
    confirms_a: VecDeque<TxConfirm>,
    confirms_b: VecDeque<TxConfirm>,
    trace: Vec<String>,
    drop_next: bool,
}

/// Shared tick-clocked medium behind a [`HostRadio`] pair.
///
/// `Clone` shares the medium (radios hold a handle to it); all
/// state advances only through explicit [`HostMedium::pump`] /
/// [`HostMedium::pump_idle`] calls.
#[derive(Clone, Debug)]
pub struct HostMedium {
    inner: Rc<RefCell<MediumInner>>,
}

impl HostMedium {
    /// Fixed per-pump clock quantum in microseconds.
    pub const PUMP_QUANTUM_US: u64 = 64;
    /// Seeded jitter bound added to each pump quantum (`0..=32`).
    pub const PUMP_JITTER_US: u64 = 32;
    /// In-flight frame budget for the whole medium.
    pub const MEDIUM_CAPACITY: usize = 16;

    /// New idle medium with the given jitter seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            inner: Rc::new(RefCell::new(MediumInner {
                clock_us: 0,
                jitter_state: seed,
                in_flight: VecDeque::new(),
                inbox_a: VecDeque::new(),
                inbox_b: VecDeque::new(),
                confirms_a: VecDeque::new(),
                confirms_b: VecDeque::new(),
                trace: Vec::new(),
                drop_next: false,
            })),
        }
    }

    /// Connected endpoint pair `(a, b)` sharing one medium.
    #[must_use]
    pub fn pair(seed: u64) -> (HostRadio, HostRadio) {
        let medium = Self::new(seed);
        (
            HostRadio::attach(medium.clone(), NodeId::A),
            HostRadio::attach(medium, NodeId::B),
        )
    }

    /// Current medium time in microseconds.
    #[must_use]
    pub fn now_us(&self) -> u64 {
        self.inner.borrow().clock_us
    }

    /// Medium trace lines (tx / deliver / confirm events).
    #[must_use]
    pub fn trace_lines(&self) -> Vec<String> {
        self.inner.borrow().trace.clone()
    }

    /// Drop the next pumped frame (fault injection; confirms NoAck).
    /// Clears after one use.
    pub fn drop_next(&self) {
        self.inner.borrow_mut().drop_next = true;
    }

    fn jitter_next(state: &mut u64) -> u64 {
        // SplitMix64, same constants as sim/host entropy: the pump
        // jitter stream matches `HostEntropy` draws from the seed.
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        (z ^ (z >> 31)) % (Self::PUMP_JITTER_US + 1)
    }

    fn tick(&self) {
        let mut m = self.inner.borrow_mut();
        let jitter = Self::jitter_next(&mut m.jitter_state);
        m.clock_us = m.clock_us.saturating_add(Self::PUMP_QUANTUM_US + jitter);
    }

    /// Advance the clock one quantum with no traffic (idle tick).
    pub fn pump_idle(&self) {
        self.tick();
        let now = self.now_us();
        self.inner
            .borrow_mut()
            .trace
            .push(format!("t={now} medium idle"));
    }

    /// Move one in-flight frame to its destination. Returns false
    /// when no frame is in flight.
    pub fn pump(&self) -> bool {
        let frame = self.inner.borrow_mut().in_flight.pop_front();
        let Some(frame) = frame else {
            return false;
        };
        self.tick();
        let now = self.now_us();
        let handle = frame.handle;
        let len = frame.req.msdu.len();
        let from = frame.from;
        // Fault injection: the frame dies on the medium.
        if self.inner.borrow().drop_next {
            self.inner.borrow_mut().drop_next = false;
            self.inner
                .borrow_mut()
                .trace
                .push(format!("t={now} medium drop handle={} len={len}", handle.0));
            let confirm = TxConfirm {
                handle,
                status: TxStatus::NoAck,
                timestamp_us: Some(now),
            };
            match from {
                NodeId::A => self.inner.borrow_mut().confirms_a.push_back(confirm),
                NodeId::B => self.inner.borrow_mut().confirms_b.push_back(confirm),
            }
            self.inner
                .borrow_mut()
                .trace
                .push(format!("t={now} confirm handle={} status=NoAck", handle.0));
            return true;
        }
        let queued_us = now.saturating_sub(frame.enqueued_us);
        self.inner.borrow_mut().trace.push(format!(
            "t={now} medium deliver handle={} {from:?}->peer len={len} queued_us={queued_us}",
            handle.0,
        ));
        // Cross-delivery: the confirm returns to the sender, the
        // indication lands on the peer.
        let indication = RxIndication {
            src: MacAddress::short(0, 0),
            lqi: 200,
            timestamp_us: Some(now),
            msdu: frame.req.msdu,
        };
        match from {
            NodeId::A => self.inner.borrow_mut().inbox_b.push_back(indication),
            NodeId::B => self.inner.borrow_mut().inbox_a.push_back(indication),
        }
        self.inner
            .borrow_mut()
            .trace
            .push(format!("t={now} rx at={:?} len={len}", from.peer()));
        let confirm = TxConfirm {
            handle,
            status: TxStatus::Delivered,
            timestamp_us: Some(now),
        };
        match from {
            NodeId::A => self.inner.borrow_mut().confirms_a.push_back(confirm),
            NodeId::B => self.inner.borrow_mut().confirms_b.push_back(confirm),
        }
        self.inner.borrow_mut().trace.push(format!(
            "t={now} confirm handle={} status=Delivered",
            handle.0
        ));
        true
    }

    /// Pump until no frame is in flight or `max_steps` is reached.
    pub fn run_until_idle(&self, max_steps: usize) {
        for _ in 0..max_steps {
            if !self.pump() {
                break;
            }
        }
    }
}

/// One endpoint of a [`HostMedium`] pair.
///
/// Implements the full MAC SAP (`data` + `mgmt` + capabilities) so
/// upper layers run unmodified against host hardware.
#[derive(Clone, Debug)]
pub struct HostRadio {
    medium: HostMedium,
    node: NodeId,
    next_handle: u32,
    channel: Option<Channel>,
    pan: Option<PanId>,
    short_addr: Option<ShortAddr>,
    ext_addr: Option<ExtAddr>,
}

impl HostRadio {
    /// Per-node outstanding-frame budget (backpressure threshold).
    pub const QUEUE_CAPACITY: usize = 8;

    fn attach(medium: HostMedium, node: NodeId) -> Self {
        Self {
            medium,
            node,
            next_handle: 0,
            channel: None,
            pan: None,
            short_addr: None,
            ext_addr: None,
        }
    }

    /// Which endpoint of the pair this is.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Shared medium handle (for the harness pump loop).
    #[must_use]
    pub fn medium(&self) -> &HostMedium {
        &self.medium
    }

    fn outstanding(&self) -> usize {
        self.medium
            .inner
            .borrow()
            .in_flight
            .iter()
            .filter(|f| f.from == self.node)
            .count()
    }
}

impl HasCapabilities for HostRadio {
    fn capabilities(&self) -> MacCapabilities {
        MacCapabilities {
            hw_auto_ack: false,
            hw_csma_ca: false,
            hw_retries: false,
            energy_scan: false,
            frame_timestamping: true,
            promiscuous_mode: false,
        }
    }
}

impl MacDataSap for HostRadio {
    fn data_request(&mut self, req: TxRequest) -> Result<TxHandle, MacError> {
        if req.msdu.len() > rounddance_mac_sap::MAX_MSDU_LEN {
            return Err(MacError::FrameTooLong);
        }
        if matches!(req.dst.addr, AddrMode::None) {
            return Err(MacError::InvalidAddress);
        }
        if self.outstanding() >= Self::QUEUE_CAPACITY
            || self.medium.inner.borrow().in_flight.len() >= HostMedium::MEDIUM_CAPACITY
        {
            return Err(MacError::QueueFull);
        }
        let handle = TxHandle(self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1);
        let now = self.medium.now_us();
        let len = req.msdu.len();
        self.medium
            .inner
            .borrow_mut()
            .in_flight
            .push_back(InFlight {
                handle,
                from: self.node,
                req,
                enqueued_us: now,
            });
        self.medium.inner.borrow_mut().trace.push(format!(
            "t={now} tx handle={} node={:?} len={len}",
            handle.0, self.node
        ));
        Ok(handle)
    }

    fn data_cancel(&mut self, handle: TxHandle) -> Result<(), MacError> {
        let mut m = self.medium.inner.borrow_mut();
        let Some(pos) = m
            .in_flight
            .iter()
            .position(|f| f.from == self.node && f.handle == handle)
        else {
            return Err(MacError::UnknownHandle);
        };
        m.in_flight.remove(pos);
        let now = m.clock_us;
        let confirms = match self.node {
            NodeId::A => &mut m.confirms_a,
            NodeId::B => &mut m.confirms_b,
        };
        confirms.push_back(TxConfirm {
            handle,
            status: TxStatus::Cancelled,
            timestamp_us: Some(now),
        });
        Ok(())
    }

    fn poll_confirm(&mut self) -> Option<TxConfirm> {
        match self.node {
            NodeId::A => self.medium.inner.borrow_mut().confirms_a.pop_front(),
            NodeId::B => self.medium.inner.borrow_mut().confirms_b.pop_front(),
        }
    }

    fn poll_indication(&mut self) -> Option<RxIndication> {
        match self.node {
            NodeId::A => self.medium.inner.borrow_mut().inbox_a.pop_front(),
            NodeId::B => self.medium.inner.borrow_mut().inbox_b.pop_front(),
        }
    }

    fn tx_queue_free(&self) -> usize {
        Self::QUEUE_CAPACITY.saturating_sub(self.outstanding())
    }

    fn tx_queue_capacity(&self) -> usize {
        Self::QUEUE_CAPACITY
    }
}

impl MacMgmtSap for HostRadio {
    fn reset(&mut self, cold: bool) {
        if cold {
            self.channel = None;
            self.pan = None;
            self.short_addr = None;
            self.ext_addr = None;
        }
    }

    fn set_channel(&mut self, channel: Channel) -> Result<(), MacError> {
        self.channel = Some(channel);
        Ok(())
    }

    fn set_short_addr(&mut self, addr: ShortAddr) {
        self.short_addr = Some(addr);
    }

    fn set_extended_addr(&mut self, addr: ExtAddr) {
        self.ext_addr = Some(addr);
    }

    fn set_pan_id(&mut self, pan: PanId) {
        self.pan = Some(pan);
    }

    fn energy_scan(&mut self, _channel: Channel) -> Result<u8, MacError> {
        // Honest report: the loopback medium has no front end, so no
        // scan hardware (see `capabilities`).
        Err(MacError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rounddance_mac_sap::{FramePayload, TxOptions};

    fn addressed(msdu: &[u8]) -> TxRequest {
        TxRequest {
            dst: MacAddress::short(0x1a2b, 0x0002),
            msdu: FramePayload::from_slice(msdu).unwrap(),
            options: TxOptions::ACK,
        }
    }

    #[test]
    fn pair_cross_delivers_a_to_b() {
        let (mut a, mut b) = HostMedium::pair(0x1234);
        a.reset(true);
        b.reset(true);
        a.set_channel(Channel::new(15).unwrap()).unwrap();
        b.set_channel(Channel::new(15).unwrap()).unwrap();
        a.data_request(addressed(&[0xDE, 0xAD])).unwrap();
        a.medium().run_until_idle(8);
        assert_eq!(a.poll_confirm().unwrap().status, TxStatus::Delivered);
        let rx = b.poll_indication().unwrap();
        assert_eq!(rx.msdu.as_slice(), &[0xDE, 0xAD]);
        assert!(a.poll_indication().is_none(), "sender gets no loopback");
    }

    #[test]
    fn pair_cross_delivers_b_to_a() {
        let (mut a, mut b) = HostMedium::pair(77);
        b.data_request(addressed(&[0x01])).unwrap();
        b.medium().run_until_idle(8);
        assert_eq!(b.poll_confirm().unwrap().status, TxStatus::Delivered);
        assert_eq!(a.poll_indication().unwrap().msdu.as_slice(), &[0x01]);
        assert!(b.poll_indication().is_none());
    }

    #[test]
    fn queue_full_is_backpressure_and_cancel_frees() {
        let (mut a, _) = HostMedium::pair(0);
        let mut handles = Vec::new();
        for _ in 0..HostRadio::QUEUE_CAPACITY {
            handles.push(a.data_request(addressed(&[0x00])).unwrap());
        }
        assert!(a.tx_queue_full());
        assert_eq!(a.data_request(addressed(&[0x00])), Err(MacError::QueueFull));
        a.data_cancel(handles[0]).unwrap();
        assert!(!a.tx_queue_full());
        assert_eq!(a.data_cancel(handles[0]), Err(MacError::UnknownHandle));
        assert_eq!(a.poll_confirm().unwrap().status, TxStatus::Cancelled);
    }

    #[test]
    fn honest_capabilities_no_scan() {
        let (mut a, _) = HostMedium::pair(0);
        let caps = a.capabilities();
        assert!(!caps.hw_auto_ack);
        assert!(!caps.energy_scan);
        assert!(caps.frame_timestamping);
        assert_eq!(
            a.energy_scan(Channel::new(15).unwrap()),
            Err(MacError::Unsupported)
        );
    }

    #[test]
    fn drop_next_confirms_noack_without_indication() {
        let (mut a, mut b) = HostMedium::pair(9);
        a.data_request(addressed(&[0xFF])).unwrap();
        a.medium().drop_next();
        a.medium().run_until_idle(8);
        assert_eq!(a.poll_confirm().unwrap().status, TxStatus::NoAck);
        assert!(b.poll_indication().is_none());
    }

    #[test]
    fn replays_agree_tick_for_tick() {
        let run = |seed: u64| {
            let (mut a, mut b) = HostMedium::pair(seed);
            a.data_request(addressed(&[0x01, 0x02])).unwrap();
            b.data_request(addressed(&[0x03])).unwrap();
            a.medium().run_until_idle(8);
            (a.medium().trace_lines(), a.medium().now_us())
        };
        assert_eq!(run(0xBEEF), run(0xBEEF));
        assert_ne!(run(0xBEEF), run(0xCAFE));
    }
}
