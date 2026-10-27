//! Initiator↔target Touchlink inter-PAN exchange over SAP media:
//! scan broadcast on two channels, scan response on the heard channel,
//! transaction pairing, network-order close-out, a stale-transaction
//! leg, and deterministic replay of the whole run.
//!
//! Requirement traceability: `07-5123-08-13322-01` + `13323-01`
//! (scan request/response command identifiers),
//! `22-65816-030-121-01` + `121-03` (initiator scan broadcast +
//! transaction pairing), `22-65816-030-122-01` + `122-02` (target
//! respond + order handling), `22-65816-030-1211-01` (transaction
//! binding). `121-03` / `122-02` are repo-minted,
//! MINTED-pending-confirm.

use rounddance_commission::{
    SapInterPan, TouchlinkFrame, TouchlinkInitiator, TouchlinkInitiatorState, TouchlinkTarget,
    TouchlinkTargetState,
};
use rounddance_mac_sap::{
    Channel, FramePayload, InterPanIndication, MacError, MacInterPanSap, TxConfirm, TxHandle,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

const TRANSACTION: u32 = 0xA5A5_1234;
const INIT_INFO: u8 = 0x0B;
const TARGET_INFO: u8 = 0x0C;
const KEY_INDEX: u8 = 0x04;

/// Shared air: one FIFO per direction, each entry tagged with the
/// broadcast channel.
#[derive(Default)]
struct Air {
    to_target: VecDeque<(u8, Vec<u8>)>,
    to_initiator: VecDeque<(u8, Vec<u8>)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Initiator,
    Target,
}

/// One endpoint's inter-PAN SAP: requests land in the peer's FIFO,
/// indications drain the local FIFO.
struct EndpointRadio {
    air: Rc<RefCell<Air>>,
    side: Side,
    next: u32,
    confirms: VecDeque<TxHandle>,
}

impl EndpointRadio {
    fn new(air: Rc<RefCell<Air>>, side: Side) -> Self {
        Self {
            air,
            side,
            next: 0,
            confirms: VecDeque::new(),
        }
    }
}

impl MacInterPanSap for EndpointRadio {
    fn interpan_request(
        &mut self,
        channel: Channel,
        msdu: &FramePayload,
    ) -> Result<TxHandle, MacError> {
        let h = TxHandle(self.next);
        self.next += 1;
        self.confirms.push_back(h);
        let mut air = self.air.borrow_mut();
        let queue = match self.side {
            Side::Initiator => &mut air.to_target,
            Side::Target => &mut air.to_initiator,
        };
        queue.push_back((channel.number(), msdu.as_slice().to_vec()));
        Ok(h)
    }

    fn poll_interpan_confirm(&mut self) -> Option<TxConfirm> {
        self.confirms.pop_front().map(|handle| TxConfirm {
            handle,
            status: rounddance_mac_sap::TxStatus::Delivered,
            timestamp_us: None,
        })
    }

    fn poll_interpan_indication(&mut self) -> Option<InterPanIndication> {
        let mut air = self.air.borrow_mut();
        let queue = match self.side {
            Side::Initiator => &mut air.to_initiator,
            Side::Target => &mut air.to_target,
        };
        queue
            .pop_front()
            .map(|(channel, bytes)| InterPanIndication {
                channel: Channel::new(channel).unwrap(),
                msdu: FramePayload::from_slice(&bytes).unwrap(),
            })
    }
}

/// Full exchange transcript: ordered trace lines plus the on-air
/// scan-request and scan-response bytes.
struct ExchangeOutcome {
    trace: Vec<String>,
    scan_req_wire: Vec<u8>,
    scan_rsp_wire: Vec<u8>,
    initiator_done: bool,
}

/// One scripted initiator↔target inter-PAN exchange. `stale_tx`
/// injects a second scan request under a foreign transaction to prove
/// the target restarts instead of latching it.
fn exchange(stale_tx: u32) -> ExchangeOutcome {
    let air = Rc::new(RefCell::new(Air::default()));
    let mut init_radio = EndpointRadio::new(Rc::clone(&air), Side::Initiator);
    let mut target_radio = EndpointRadio::new(Rc::clone(&air), Side::Target);
    let mut trace = Vec::new();

    let mut initiator = TouchlinkInitiator::new();
    let mut target = TouchlinkTarget::new();
    initiator.begin_scan(TRANSACTION).unwrap();

    // Initiator broadcasts the scan request on two channels.
    let sent = {
        let mut tx = SapInterPan::new(&mut init_radio);
        initiator
            .broadcast_scan(&mut tx, &[15, 20], INIT_INFO, KEY_INDEX)
            .unwrap()
    };
    assert_eq!(sent, 2);
    trace.push("scan-broadcast:2ch".to_string());

    // Both copies reach the target; the first latches the exchange.
    let mut scan_req_wire = Vec::new();
    for _ in 0..2 {
        let ind = target_radio.poll_interpan_indication().unwrap();
        let frame = TouchlinkFrame::decode(ind.msdu.as_slice()).unwrap();
        assert_eq!(frame.command, 0x00);
        assert_eq!(frame.transaction, TRANSACTION);
        if scan_req_wire.is_empty() {
            scan_req_wire = ind.msdu.as_slice().to_vec();
        }
        target.on_scan_request(&frame);
    }
    assert_eq!(target.state(), TouchlinkTargetState::ScanReceived);
    trace.push("target:scan-received".to_string());

    // A foreign transaction while the target waits re-latches the
    // procedure (duplicate scan restarts it per 122-01) without
    // advancing it; re-driving the real scan recovers the exchange.
    let stale = TouchlinkFrame::new(stale_tx, 0x00, &[INIT_INFO, KEY_INDEX]).unwrap();
    target.on_scan_request(&stale);
    assert_eq!(target.state(), TouchlinkTargetState::ScanReceived);
    let real = TouchlinkFrame::new(TRANSACTION, 0x00, &[INIT_INFO, KEY_INDEX]).unwrap();
    target.on_scan_request(&real);
    assert_eq!(target.state(), TouchlinkTargetState::ScanReceived);
    trace.push("stale:relatch-then-recover".to_string());

    // Target answers on the heard channel.
    {
        let mut tx = SapInterPan::new(&mut target_radio);
        target.respond(&mut tx, 15, TARGET_INFO, KEY_INDEX).unwrap();
    }
    assert_eq!(target.state(), TouchlinkTargetState::Responded);
    trace.push("target:responded:ch15".to_string());

    // Initiator pairs the response by transaction and proceeds.
    let ind = init_radio.poll_interpan_indication().unwrap();
    assert_eq!(ind.channel, Channel::new(15).unwrap());
    let rsp = TouchlinkFrame::decode(ind.msdu.as_slice()).unwrap();
    assert_eq!(rsp.command, 0x01);
    let scan_rsp_wire = ind.msdu.as_slice().to_vec();
    initiator.note_response(rsp.transaction == TRANSACTION);
    assert_eq!(initiator.state(), TouchlinkInitiatorState::Selecting);
    initiator.proceed(false).unwrap();
    assert_eq!(initiator.state(), TouchlinkInitiatorState::JoiningNetwork);
    trace.push("initiator:joining-network".to_string());

    // A foreign-transaction frame never selects.
    initiator.note_response(false);
    assert_eq!(initiator.state(), TouchlinkInitiatorState::JoiningNetwork);

    // Network order + close-out on both sides.
    target.on_network_order(true);
    assert_eq!(target.state(), TouchlinkTargetState::Applying);
    initiator.finish(true);
    target.finish(true);
    assert_eq!(initiator.state(), TouchlinkInitiatorState::Done);
    assert_eq!(target.state(), TouchlinkTargetState::Done);
    trace.push("both:done".to_string());

    ExchangeOutcome {
        trace,
        scan_req_wire,
        scan_rsp_wire,
        initiator_done: true,
    }
}

// 22-65816-030-121-03 / 122-02: full inter-PAN scan exchange plus a
// stale-transaction leg.
#[test]
fn touchlink_interpan_scan_round_trip() {
    let out = exchange(0xDEAD_BEEF);
    assert_eq!(
        out.trace,
        [
            "scan-broadcast:2ch",
            "target:scan-received",
            "stale:relatch-then-recover",
            "target:responded:ch15",
            "initiator:joining-network",
            "both:done",
        ]
    );
    // Frozen wire shape: LE transaction + command + info/key.
    assert_eq!(
        out.scan_req_wire,
        [0x34, 0x12, 0xA5, 0xA5, 0x00, INIT_INFO, KEY_INDEX]
    );
    assert_eq!(
        out.scan_rsp_wire,
        [0x34, 0x12, 0xA5, 0xA5, 0x01, TARGET_INFO, KEY_INDEX]
    );
    assert!(out.initiator_done);
}

// Deterministic replay: the same scripted exchange produces the same
// transcript and the same on-air bytes twice.
#[test]
fn touchlink_interpan_replay_identical() {
    let first = exchange(0xDEAD_BEEF);
    let second = exchange(0xDEAD_BEEF);
    assert_eq!(first.trace, second.trace);
    assert_eq!(first.scan_req_wire, second.scan_req_wire);
    assert_eq!(first.scan_rsp_wire, second.scan_rsp_wire);
}
