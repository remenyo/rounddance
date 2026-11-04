//! Line-coverage closure for doc `05-3474-23` R23.2 chapters 2–3,
//! MAC-below-NWK surface: the SAP traits the NWK data entity relies
//! on (addressing, channel selection, bounded payloads, backpressure,
//! energy scan for network discovery).
//!
//! The NWK layer reaches the radio only through this boundary
//! (§3.2.2.1 MAC interfaces share one PAN ID; §3.4 MAC source
//! addressing carries the sender address and PAN ID). Each test pins
//! one contract of that boundary. Comments cite the supporting gap
//! anchors (D1: document number, revision, clause and line only).

use rounddance_mac_sap::{
    AddrMode, BoundedOctets, Channel, ExtAddr, FramePayload, HasCapabilities, MacAddress,
    MacCapabilities, MacDataSap, MacError, MacMgmtSap, PanId, RxIndication, ShortAddr, TxConfirm,
    TxHandle, TxOptions, TxRequest, TxStatus, MAX_MSDU_LEN, MAX_PHY_PSDU_LEN,
};

// 05-3474-23-3221-01: the MAC boundary exposes 2.4 GHz channels
// 11–26; out-of-range selection is refused before touching the
// radio. Anchors: p0246-L5783-L5797, p0246-L5791-L5798.
#[test]
fn channel_selection_checked_05_3474_23_3221_01() {
    assert_eq!(Channel::MIN, 11);
    assert_eq!(Channel::MAX, 26);
    for n in 11..=26u8 {
        assert_eq!(Channel::new(n).unwrap().number(), n);
    }
    assert_eq!(Channel::new(0), Err(MacError::InvalidChannel));
    assert_eq!(Channel::new(10), Err(MacError::InvalidChannel));
    assert_eq!(Channel::new(27), Err(MacError::InvalidChannel));
}

// 05-3474-23-331-05: MAC payloads fit one PHY packet — the SAP MSDU
// bound leaves room for the largest MAC header/footer; oversize
// NWK payloads are refused, never truncated.
// Anchors: p0304-L7190-L7197, p0058-L1510-L1514.
#[test]
fn bounded_payload_never_truncates_05_3474_23_331_05() {
    const {
        assert!(MAX_MSDU_LEN < MAX_PHY_PSDU_LEN);
    }
    let exact = [0x5Au8; MAX_MSDU_LEN];
    assert!(FramePayload::from_slice(&exact).is_ok());
    let over = [0x5Au8; MAX_MSDU_LEN + 1];
    assert_eq!(FramePayload::from_slice(&over), Err(MacError::FrameTooLong));
    // A partial payload keeps its prefix when an extension overflows.
    let mut buf = BoundedOctets::<8>::from_slice(&[1, 2, 3]).unwrap();
    assert_eq!(
        buf.extend_from_slice(&[4, 5, 6, 7, 8, 9]),
        Err(MacError::FrameTooLong)
    );
    assert_eq!(buf.as_slice(), &[1, 2, 3]);
}

// 05-3474-23-3211-04: transmit options and addressing — acknowledged
// vs unacknowledged service, short vs extended addresses scoped by
// PAN ID, opaque handles binding confirms to requests.
// Anchors: p0246-L5783-L5788, p0304-L7194-L7197.
#[test]
fn addressing_and_options_05_3474_23_3211_04() {
    let pan: PanId = 0x1A2B;
    let short: ShortAddr = 0x0000;
    let ext: ExtAddr = 0x0012_4B00_1A2B_3C4D;
    let a = MacAddress::short(pan, short);
    assert_eq!(a.pan, Some(pan));
    assert_eq!(a.addr, AddrMode::Short(short));
    let b = MacAddress::extended(pan, ext);
    assert_eq!(b.pan, Some(pan));
    assert_eq!(b.addr, AddrMode::Extended(ext));
    assert!(!TxOptions::NONE.wants_ack());
    assert!(TxOptions::ACK.wants_ack());
    assert_ne!(TxHandle(1), TxHandle(2));
    // Every taxonomy variant renders a log-safe message.
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

/// Minimal in-test MAC stub: bounded queue, scripted confirms.
struct StubMac {
    capacity: usize,
    queued: usize,
    next: u32,
    confirms: [Option<TxConfirm>; 4],
    energy_ok: bool,
}

impl StubMac {
    fn new(capacity: usize, energy_ok: bool) -> Self {
        Self {
            capacity,
            queued: 0,
            next: 0,
            confirms: [None, None, None, None],
            energy_ok,
        }
    }

    fn caps() -> MacCapabilities {
        MacCapabilities {
            hw_auto_ack: false,
            hw_csma_ca: true,
            hw_retries: false,
            energy_scan: true,
            frame_timestamping: false,
            promiscuous_mode: false,
        }
    }
}

impl HasCapabilities for StubMac {
    fn capabilities(&self) -> MacCapabilities {
        Self::caps()
    }
}

impl MacDataSap for StubMac {
    fn data_request(&mut self, req: TxRequest) -> Result<TxHandle, MacError> {
        if req.msdu.len() > MAX_MSDU_LEN {
            return Err(MacError::FrameTooLong);
        }
        if self.queued >= self.capacity {
            return Err(MacError::QueueFull);
        }
        let h = TxHandle(self.next);
        self.next += 1;
        self.queued += 1;
        for slot in self.confirms.iter_mut() {
            if slot.is_none() {
                *slot = Some(TxConfirm {
                    handle: h,
                    status: TxStatus::Delivered,
                    timestamp_us: None,
                });
                break;
            }
        }
        Ok(h)
    }

    fn data_cancel(&mut self, handle: TxHandle) -> Result<(), MacError> {
        for slot in self.confirms.iter_mut() {
            if matches!(slot, Some(c) if c.handle == handle) {
                *slot = Some(TxConfirm {
                    handle,
                    status: TxStatus::Cancelled,
                    timestamp_us: None,
                });
                self.queued = self.queued.saturating_sub(1);
                return Ok(());
            }
        }
        Err(MacError::UnknownHandle)
    }

    fn poll_confirm(&mut self) -> Option<TxConfirm> {
        for slot in self.confirms.iter_mut() {
            if slot.is_some() {
                return slot.take();
            }
        }
        None
    }

    fn poll_indication(&mut self) -> Option<RxIndication> {
        None
    }

    fn tx_queue_free(&self) -> usize {
        self.capacity.saturating_sub(self.queued)
    }

    fn tx_queue_capacity(&self) -> usize {
        self.capacity
    }
}

impl MacMgmtSap for StubMac {
    fn reset(&mut self, cold: bool) {
        self.queued = 0;
        self.confirms = [None, None, None, None];
        if cold {
            self.next = 0;
        }
    }

    fn set_channel(&mut self, channel: Channel) -> Result<(), MacError> {
        let _ = channel;
        Ok(())
    }

    fn set_short_addr(&mut self, _addr: ShortAddr) {}

    fn set_extended_addr(&mut self, _addr: ExtAddr) {}

    fn set_pan_id(&mut self, _pan: PanId) {}

    fn energy_scan(&mut self, channel: Channel) -> Result<u8, MacError> {
        if !self.energy_ok {
            return Err(MacError::Unsupported);
        }
        let _ = channel;
        Ok(0x2A)
    }
}

// 05-3474-23-3221-02: backpressure and cancellation — the queue depth
// is observable, full queues refuse with QueueFull, and cancellation
// surfaces as Cancelled; reset restores the budget.
// Anchors: p0246-L5783-L5788, p0251-L5912-L5918.
#[test]
fn backpressure_and_cancel_05_3474_23_3221_02() {
    let mut mac = StubMac::new(2, true);
    assert_eq!(mac.tx_queue_capacity(), 2);
    assert_eq!(mac.tx_queue_free(), 2);
    assert!(!mac.tx_queue_full());
    let mk = || TxRequest {
        dst: MacAddress::short(0x1A2B, 0x0001),
        msdu: FramePayload::from_slice(&[0x01]).unwrap(),
        options: TxOptions::ACK,
    };
    let h0 = mac.data_request(mk()).unwrap();
    let h1 = mac.data_request(mk()).unwrap();
    assert!(mac.tx_queue_full());
    assert_eq!(mac.data_request(mk()), Err(MacError::QueueFull));
    // Cancel revokes the transaction visibly.
    assert_eq!(mac.data_cancel(TxHandle(999)), Err(MacError::UnknownHandle));
    mac.data_cancel(h0).unwrap();
    let mut saw_cancelled = false;
    while let Some(c) = mac.poll_confirm() {
        if c.handle == h0 {
            assert_eq!(c.status, TxStatus::Cancelled);
            saw_cancelled = true;
        }
    }
    assert!(saw_cancelled);
    let _ = h1;
    // Reset restores the budget; cold reset restarts handle numbering.
    mac.reset(true);
    assert_eq!(mac.tx_queue_free(), 2);
    assert_eq!(mac.data_request(mk()).unwrap(), TxHandle(0));
}

// 05-3474-23-3221-03: management plane — channel tune, addressing,
// and the energy scan the NWK discovery procedure uses to pick
// channels; radios without scan hardware report Unsupported.
// Anchors: p0251-L5912-L5918, p0246-L5791-L5798.
#[test]
fn mgmt_plane_and_scan_05_3474_23_3221_03() {
    let mut mac = StubMac::new(4, true);
    mac.set_channel(Channel::new(15).unwrap()).unwrap();
    mac.set_short_addr(0x0001);
    mac.set_extended_addr(0x0012_4B00_1A2B_3C4D);
    mac.set_pan_id(0x1A2B);
    assert_eq!(mac.energy_scan(Channel::new(15).unwrap()).unwrap(), 0x2A);
    let caps = mac.capabilities();
    assert!(caps.energy_scan);
    assert!(!caps.frame_timestamping);
    let mut noscan = StubMac::new(4, false);
    assert_eq!(
        noscan.energy_scan(Channel::new(11).unwrap()),
        Err(MacError::Unsupported)
    );
}
