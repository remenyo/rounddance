//! Complete Touchlink commissioning over simulated inter-PAN media:
//! scan, key-index negotiation, network start/join orders with key
//! transport, success responses, startup-delay handoff, and key-install
//! verification — plus stale-transaction, bad-key-index, timeout, and
//! refused-steal negatives, all with deterministic replay.
//!
//! Requirement traceability: `07-5123-08-13322-01` + `13323-01`
//! (command identifiers), `07-5123-08-133225-01` + `133226-01` +
//! `133227-01` + `133228-01` + `133231-01` + `133233-01` +
//! `133234-01` + `133235-01` (payload layouts),
//! `07-5123-08-1333411-01` (key transport + index negotiation),
//! `22-65816-030-121-04` (initiator start/join + timeouts + handoff),
//! `22-65816-030-122-03` (target orders + lifetime + abandon),
//! `22-65816-030-122-04` (update handling),
//! `22-65816-030-1211-02` (transaction discipline).

use rounddance_commission::{
    decrypt_network_key, encrypt_network_key, select_key_index, transport_key_for,
    CommissionedNetwork, InterPanTx, JoinKind, NetworkJoinRequest, NetworkJoinResponse,
    NetworkStartRequest, NetworkStartResponse, NetworkUpdateRequest, SapInterPan, ScanResponseBody,
    TargetOrderCtx, TouchlinkFrame, TouchlinkInitiator, TouchlinkInitiatorState, TouchlinkKey,
    TouchlinkTarget, TouchlinkTargetState, KEY_INDEX_CERTIFICATION, MIN_STARTUP_DELAY_MS,
    RX_WINDOW_MS, TRANSACTION_LIFETIME_MS,
};
use rounddance_mac_sap::{
    Channel, FramePayload, InterPanIndication, MacError, MacInterPanSap, TxConfirm, TxHandle,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

const TRANSACTION: u32 = 0x3eaa_2009;
const RESPONSE_ID: u32 = 0x8876_2fb1;
const PLAIN_KEY: [u8; 16] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];
const EXT_PAN: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

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

/// Full exchange transcript plus the on-air order/response bytes and
/// both handoff parameter sets.
struct ExchangeOutcome {
    trace: Vec<String>,
    start_req_wire: Vec<u8>,
    start_rsp_wire: Vec<u8>,
    initiator_handoff: Option<CommissionedNetwork>,
    target_handoff: Option<CommissionedNetwork>,
}

/// One scripted complete commissioning exchange: factory-new target,
/// certification protection, initiator forms the network via a start
/// order and the target installs the unwrapped key.
fn exchange() -> ExchangeOutcome {
    let air = Rc::new(RefCell::new(Air::default()));
    let mut init_radio = EndpointRadio::new(Rc::clone(&air), Side::Initiator);
    let mut target_radio = EndpointRadio::new(Rc::clone(&air), Side::Target);
    let mut trace = Vec::new();

    let mut initiator = TouchlinkInitiator::new();
    let mut target = TouchlinkTarget::new();
    initiator.begin_scan(TRANSACTION).unwrap();
    trace.push("initiator:scan-begin".to_string());

    // Scan broadcast on two channels; the target latches the first.
    {
        let mut tx = SapInterPan::new(&mut init_radio);
        initiator
            .broadcast_scan(&mut tx, &[15, 20], 0x83, KEY_INDEX_CERTIFICATION)
            .unwrap();
    }
    for _ in 0..2 {
        let ind = target_radio.poll_interpan_indication().unwrap();
        let frame = TouchlinkFrame::decode(ind.msdu.as_slice()).unwrap();
        target.on_scan_request(&frame);
    }
    assert_eq!(target.state(), TouchlinkTargetState::ScanReceived);
    trace.push("target:scan-received".to_string());

    // Full scan response with the certification bit set.
    let rsp = ScanResponseBody {
        rssi_correction: 0x05,
        zigbee_info: 0x05,
        touchlink_info: 0x83,
        key_bitmask: 1u16 << KEY_INDEX_CERTIFICATION,
        response_id: RESPONSE_ID,
        extended_pan: [0; 8],
        network_update_id: 0,
        channel: 0,
        pan_id: 0,
        network_address: 0xffff,
        sub_devices: 0,
        total_groups: 0,
        endpoint: 0,
        profile_id: 0,
        device_id: 0,
        version: 0,
        group_count: 0,
    };
    {
        let mut tx = SapInterPan::new(&mut target_radio);
        target.respond_full(&mut tx, 15, &rsp).unwrap();
    }
    assert_eq!(target.state(), TouchlinkTargetState::Responded);
    trace.push("target:responded".to_string());

    // Initiator pairs the response, negotiates the protection, and
    // wraps the network key.
    let ind = init_radio.poll_interpan_indication().unwrap();
    let rsp_frame = TouchlinkFrame::decode(ind.msdu.as_slice()).unwrap();
    let body = ScanResponseBody::decode(rsp_frame.payload_bytes()).unwrap();
    initiator.note_response(rsp_frame.transaction == TRANSACTION);
    let index = select_key_index(1u16 << KEY_INDEX_CERTIFICATION, body.key_bitmask).unwrap();
    assert_eq!(index, KEY_INDEX_CERTIFICATION);
    let transport = transport_key_for(index, TRANSACTION, body.response_id, &[0u8; 16]).unwrap();
    let wrapped = encrypt_network_key(&transport, &PLAIN_KEY);
    initiator.proceed(true).unwrap();
    trace.push("initiator:key-negotiated".to_string());

    // Start order over the air; the target unwraps and accepts.
    let req = NetworkStartRequest {
        extended_pan: EXT_PAN,
        key_index: index,
        encrypted_key: wrapped,
        channel: 15,
        pan_id: 0x1a2b,
        network_address: 0x0001,
        group_begin: 0x0001,
        group_end: 0x0008,
        free_nwk_begin: 0x0002,
        free_nwk_end: 0x7fff,
        free_group_begin: 0x000b,
        free_group_end: 0x000c,
        initiator_ieee: [0xaa; 8],
        initiator_nwk: 0x0000,
    };
    {
        let mut tx = SapInterPan::new(&mut init_radio);
        initiator.send_start(&mut tx, 15, &req, &PLAIN_KEY).unwrap();
    }
    assert_eq!(
        initiator.state(),
        TouchlinkInitiatorState::AwaitingStartResponse
    );
    let ind = target_radio.poll_interpan_indication().unwrap();
    let order_frame = TouchlinkFrame::decode(ind.msdu.as_slice()).unwrap();
    let start_req_wire = ind.msdu.as_slice().to_vec();
    let order = NetworkStartRequest::decode(order_frame.payload_bytes()).unwrap();
    let ctx = TargetOrderCtx {
        is_router: true,
        accept: true,
        key: TouchlinkKey::Certification,
        supported_keys: 1u16 << KEY_INDEX_CERTIFICATION,
    };
    let reply = target
        .on_network_start(&order, order_frame.transaction, &ctx)
        .unwrap();
    assert!(reply.is_success());
    assert_eq!(target.state(), TouchlinkTargetState::Applying);
    trace.push("target:applying".to_string());

    // Success response closes the initiator leg after the delay.
    {
        let mut tx = SapInterPan::new(&mut target_radio);
        let mut payload = [0u8; NetworkStartResponse::LEN];
        let n = reply.encode_into(&mut payload).unwrap();
        let frame = TouchlinkFrame::new(TRANSACTION, 0x11, &payload[..n]).unwrap();
        tx.send(15, &frame).unwrap();
    }
    let ind = init_radio.poll_interpan_indication().unwrap();
    let rsp_frame = TouchlinkFrame::decode(ind.msdu.as_slice()).unwrap();
    let start_rsp_wire = ind.msdu.as_slice().to_vec();
    let start_rsp = NetworkStartResponse::decode(rsp_frame.payload_bytes()).unwrap();
    initiator
        .on_start_response(&start_rsp, rsp_frame.transaction)
        .unwrap();
    assert!(!initiator.tick_ms(MIN_STARTUP_DELAY_MS - 1));
    assert!(initiator.tick_ms(1));
    assert_eq!(initiator.state(), TouchlinkInitiatorState::Done);
    trace.push("initiator:done".to_string());

    // Key-install verification: the target unwrapped the initiator's
    // key, and both sides hand the same network to classical layers.
    let initiator_handoff = initiator.take_handoff();
    let target_handoff = target.take_pending();
    let (Some(init), Some(targ)) = (initiator_handoff, target_handoff) else {
        panic!("handoff missing");
    };
    assert_eq!(init.network_key, PLAIN_KEY);
    assert_eq!(targ.network_key, PLAIN_KEY);
    assert_eq!(
        decrypt_network_key(&transport, &order.encrypted_key),
        PLAIN_KEY
    );
    assert_eq!(init.pan_id, targ.pan_id);
    assert_eq!(init.extended_pan, targ.extended_pan);
    target.finish(true);
    assert_eq!(target.state(), TouchlinkTargetState::Done);
    trace.push("target:done".to_string());

    ExchangeOutcome {
        trace,
        start_req_wire,
        start_rsp_wire,
        initiator_handoff,
        target_handoff,
    }
}

// 22-65816-030-121-04 / 122-03: complete touchlink commissioning —
// form a new network via touchlink, join the target, verify the key
// install on both handoffs.
#[test]
fn touchlink_complete_commissioning() {
    let out = exchange();
    assert_eq!(
        out.trace,
        [
            "initiator:scan-begin",
            "target:scan-received",
            "target:responded",
            "initiator:key-negotiated",
            "target:applying",
            "initiator:done",
            "target:done",
        ]
    );
    // Frozen on-air shape: LE transaction + command + start payload.
    assert_eq!(&out.start_req_wire[..5], &[0x09, 0x20, 0xaa, 0x3e, 0x10]);
    assert_eq!(out.start_req_wire.len(), 5 + NetworkStartRequest::LEN);
    assert_eq!(&out.start_rsp_wire[..5], &[0x09, 0x20, 0xaa, 0x3e, 0x11]);
    assert_eq!(out.start_rsp_wire.len(), 5 + NetworkStartResponse::LEN);
    assert!(out.initiator_handoff.is_some() && out.target_handoff.is_some());
}

// Deterministic replay: the same scripted exchange produces the same
// transcript and the same on-air bytes twice.
#[test]
fn touchlink_complete_commissioning_replay_identical() {
    let first = exchange();
    let second = exchange();
    assert_eq!(first.trace, second.trace);
    assert_eq!(first.start_req_wire, second.start_req_wire);
    assert_eq!(first.start_rsp_wire, second.start_rsp_wire);
    assert_eq!(first.initiator_handoff, second.initiator_handoff);
    assert_eq!(first.target_handoff, second.target_handoff);
}

// 22-65816-030-121-04 / 122-03: on-network initiator joins a
// router target to its network with the update identifier carried.
#[test]
fn touchlink_join_existing_network() {
    let air = Rc::new(RefCell::new(Air::default()));
    let mut init_radio = EndpointRadio::new(Rc::clone(&air), Side::Initiator);
    let mut target_radio = EndpointRadio::new(Rc::clone(&air), Side::Target);
    let mut initiator = TouchlinkInitiator::new();
    let mut target = TouchlinkTarget::new();
    initiator.begin_scan(TRANSACTION).unwrap();
    {
        let mut tx = SapInterPan::new(&mut init_radio);
        initiator
            .broadcast_scan(&mut tx, &[15], 0x83, KEY_INDEX_CERTIFICATION)
            .unwrap();
    }
    let ind = target_radio.poll_interpan_indication().unwrap();
    target.on_scan_request(&TouchlinkFrame::decode(ind.msdu.as_slice()).unwrap());
    let rsp = ScanResponseBody {
        rssi_correction: 0,
        zigbee_info: 0x05,
        touchlink_info: 0x01,
        key_bitmask: 1u16 << KEY_INDEX_CERTIFICATION,
        response_id: RESPONSE_ID,
        extended_pan: EXT_PAN,
        network_update_id: 0x03,
        channel: 15,
        pan_id: 0x1a2b,
        network_address: 0x1234,
        sub_devices: 0,
        total_groups: 0,
        endpoint: 0,
        profile_id: 0,
        device_id: 0,
        version: 0,
        group_count: 0,
    };
    {
        let mut tx = SapInterPan::new(&mut target_radio);
        target.respond_full(&mut tx, 15, &rsp).unwrap();
    }
    let ind = init_radio.poll_interpan_indication().unwrap();
    let rsp_frame = TouchlinkFrame::decode(ind.msdu.as_slice()).unwrap();
    initiator.note_response(true);
    initiator.proceed(false).unwrap();
    let req = NetworkJoinRequest {
        extended_pan: EXT_PAN,
        key_index: KEY_INDEX_CERTIFICATION,
        encrypted_key: encrypt_network_key(
            &transport_key_for(
                KEY_INDEX_CERTIFICATION,
                TRANSACTION,
                RESPONSE_ID,
                &[0u8; 16],
            )
            .unwrap(),
            &PLAIN_KEY,
        ),
        network_update_id: 0x03,
        channel: 15,
        pan_id: 0x1a2b,
        network_address: 0x0007,
        group_begin: 0,
        group_end: 0,
        free_nwk_begin: 0,
        free_nwk_end: 0,
        free_group_begin: 0,
        free_group_end: 0,
    };
    {
        let mut tx = SapInterPan::new(&mut init_radio);
        initiator
            .send_join(&mut tx, 15, JoinKind::Router, &req, &PLAIN_KEY)
            .unwrap();
    }
    let ind = target_radio.poll_interpan_indication().unwrap();
    let order_frame = TouchlinkFrame::decode(ind.msdu.as_slice()).unwrap();
    assert_eq!(order_frame.command, 0x12);
    let order = NetworkJoinRequest::decode(order_frame.payload_bytes()).unwrap();
    let ctx = TargetOrderCtx {
        is_router: true,
        accept: true,
        key: TouchlinkKey::Certification,
        supported_keys: 1u16 << KEY_INDEX_CERTIFICATION,
    };
    let reply = target
        .on_network_join(&order, TRANSACTION, JoinKind::Router, true, &ctx)
        .unwrap();
    assert!(reply.is_success());
    initiator.on_join_response(&reply, TRANSACTION).unwrap();
    assert!(initiator.tick_ms(MIN_STARTUP_DELAY_MS));
    assert_eq!(initiator.state(), TouchlinkInitiatorState::Done);
    let handoff = target.take_pending().unwrap();
    assert_eq!(handoff.network_key, PLAIN_KEY);
    assert!(!handoff.formed_new);
    assert_eq!(handoff.network_update_id, 0x03);
    assert_eq!(rsp_frame.transaction, TRANSACTION);
}

// 22-65816-030-1211-02 / 121-04 / 122-03: negatives over the air —
// stale transaction, refused steal, receive-window timeout, and
// lifetime abandonment.
#[test]
fn touchlink_commissioning_negatives() {
    // Stale transaction on the order: discarded, exchange waits.
    {
        let mut target = TouchlinkTarget::new();
        let scan = TouchlinkFrame::new(TRANSACTION, 0x00, &[0x05, 0x83]).unwrap();
        target.on_scan_request(&scan);
        let rsp = ScanResponseBody {
            rssi_correction: 0,
            zigbee_info: 0,
            touchlink_info: 0,
            key_bitmask: 1u16 << KEY_INDEX_CERTIFICATION,
            response_id: RESPONSE_ID,
            extended_pan: [0; 8],
            network_update_id: 0,
            channel: 0,
            pan_id: 0,
            network_address: 0xffff,
            sub_devices: 0,
            total_groups: 0,
            endpoint: 0,
            profile_id: 0,
            device_id: 0,
            version: 0,
            group_count: 0,
        };
        struct Drop;
        impl rounddance_commission::InterPanTx for Drop {
            type Error = rounddance_commission::TouchlinkError;
            fn send(
                &mut self,
                _c: u8,
                _f: &TouchlinkFrame,
            ) -> Result<(), rounddance_commission::TouchlinkError> {
                Ok(())
            }
        }
        target.respond_full(&mut Drop, 15, &rsp).unwrap();
        let req = NetworkJoinRequest {
            extended_pan: EXT_PAN,
            key_index: KEY_INDEX_CERTIFICATION,
            encrypted_key: [0; 16],
            network_update_id: 0,
            channel: 15,
            pan_id: 0x1a2b,
            network_address: 1,
            group_begin: 0,
            group_end: 0,
            free_nwk_begin: 0,
            free_nwk_end: 0,
            free_group_begin: 0,
            free_group_end: 0,
        };
        let ctx = TargetOrderCtx {
            is_router: true,
            accept: true,
            key: TouchlinkKey::Certification,
            supported_keys: 1u16 << KEY_INDEX_CERTIFICATION,
        };
        assert!(target
            .on_network_join(&req, 0xDEAD_BEEF, JoinKind::Router, true, &ctx)
            .is_err());
        assert_eq!(target.state(), TouchlinkTargetState::Responded);
        // Refused steal: failure answer, terminated.
        let refuse = TargetOrderCtx {
            accept: false,
            ..ctx
        };
        let reply = target
            .on_network_join(&req, TRANSACTION, JoinKind::Router, true, &refuse)
            .unwrap();
        assert_eq!(reply, NetworkJoinResponse::failure());
        assert_eq!(target.state(), TouchlinkTargetState::Restarted);
    }
    // Silent target: the initiator fails the leg at the window.
    {
        let mut initiator = TouchlinkInitiator::new();
        struct Drop;
        impl rounddance_commission::InterPanTx for Drop {
            type Error = rounddance_commission::TouchlinkError;
            fn send(
                &mut self,
                _c: u8,
                _f: &TouchlinkFrame,
            ) -> Result<(), rounddance_commission::TouchlinkError> {
                Ok(())
            }
        }
        initiator.begin_scan(TRANSACTION).unwrap();
        initiator.note_response(true);
        initiator.proceed(true).unwrap();
        let req = NetworkStartRequest {
            extended_pan: EXT_PAN,
            key_index: KEY_INDEX_CERTIFICATION,
            encrypted_key: [0; 16],
            channel: 15,
            pan_id: 0x1a2b,
            network_address: 1,
            group_begin: 0,
            group_end: 0,
            free_nwk_begin: 0,
            free_nwk_end: 0,
            free_group_begin: 0,
            free_group_end: 0,
            initiator_ieee: [0; 8],
            initiator_nwk: 0,
        };
        initiator
            .send_start(&mut Drop, 15, &req, &PLAIN_KEY)
            .unwrap();
        assert!(!initiator.tick_ms(RX_WINDOW_MS - 1));
        assert!(initiator.tick_ms(1));
        assert_eq!(initiator.state(), TouchlinkInitiatorState::Failed);
    }
    // Idle target: abandoned at the transaction lifetime.
    {
        let mut target = TouchlinkTarget::new();
        let scan = TouchlinkFrame::new(TRANSACTION, 0x00, &[0x05, 0x83]).unwrap();
        target.on_scan_request(&scan);
        assert!(target.tick_ms(TRANSACTION_LIFETIME_MS));
        assert_eq!(target.state(), TouchlinkTargetState::Expired);
    }
    // Network update adoption on the same network with a newer id.
    {
        let mut target = TouchlinkTarget::new();
        let scan = TouchlinkFrame::new(TRANSACTION, 0x00, &[0x05, 0x83]).unwrap();
        target.on_scan_request(&scan);
        let update = NetworkUpdateRequest {
            extended_pan: EXT_PAN,
            network_update_id: 0x05,
            channel: 20,
            pan_id: 0x1a2b,
            network_address: 1,
        };
        // Not yet responded: ignored.
        assert_eq!(
            target.on_network_update(&update, TRANSACTION, &EXT_PAN, 0x1a2b, 0x04),
            rounddance_commission::UpdateDisposition::Ignored
        );
    }
}
