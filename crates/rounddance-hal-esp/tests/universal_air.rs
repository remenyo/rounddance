//! Universal air-shuttle: S31 coordinator → C6 router → C6 end-device.
//!
//! Sim air-proof (mock-to-mock) that the portable core is target
//! agnostic and the C6 router forwards live secured frames:
//! * S31 [`BoardConfig`] drives the same [`CoordinatorApp`]
//!   form → permit → admit path as C6 (same bytes, different board);
//! * [`RouterDevice`] joins Active, admits the joiner child, installs
//!   the 0x0000 route, and forwards the coordinator toggle NPDU to the
//!   joiner and the Default Response back;
//! * the end-device lamp flips and the coordinator verifies DefRsp.
//!
//! MAC air frames shuttle adapter→adapter like `c6_standalone.rs`;
//! the router fairness queue carries the NPDU between shuttles.

use rounddance_commission::{BeaconSurveyEntry, InstallCode, JoinerState};
use rounddance_hal_esp::{
    app::{
        CoordinatorApp, JoinerApp, JoinerNwkOutcome, NwkRxOutcome, APP_CHANNEL, APP_PAN,
        COORD_SHORT, JOINER_SHORT,
    },
    board::{BoardConfig, EspTarget},
    driver::RxFrame,
    EspAdapter, MockDriver, RouterDevice, SerialLog,
};
use rounddance_mac_sap::{
    FramePayload, MacAddress, MacDataSap, MacMgmtSap, TxOptions, TxRequest, TxStatus,
};
use rounddance_roles::{AgingPolicy, AppEndpoint, CommandError, MAX_APP_PAYLOAD};
use rounddance_zcl::onoff;

static JOINER_DEF: onoff::ServerDef = onoff::ServerDef;

#[derive(Default)]
struct VecLog {
    lines: Vec<String>,
}
impl SerialLog for VecLog {
    fn log(&mut self, line: &str) {
        self.lines.push(line.to_string());
    }
}

struct Lamp {
    id: u8,
    on: bool,
}
impl AppEndpoint for Lamp {
    fn endpoint_id(&self) -> u8 {
        self.id
    }
    fn profile_id(&self) -> u16 {
        0x0104
    }
    fn handle_command(
        &mut self,
        payload: &[u8],
        response: &mut [u8],
    ) -> Result<usize, CommandError> {
        if payload == [0x01] {
            self.on = true;
            response[0] = 0x06;
            Ok(1)
        } else {
            Err(CommandError::BadCommand)
        }
    }
}

/// Shuttle one MSDU from `tx` adapter to `rx` adapter over mock air.
fn shuttle(
    tx: &mut EspAdapter<MockDriver>,
    rx: &mut EspAdapter<MockDriver>,
    air_log: &mut Vec<Vec<u8>>,
    dst: u16,
    msdu: &[u8],
) -> Vec<u8> {
    tx.data_request(TxRequest {
        dst: MacAddress::short(APP_PAN, dst),
        msdu: FramePayload::from_slice(msdu).unwrap(),
        options: TxOptions::ACK,
    })
    .unwrap();
    let mut tries = 0;
    loop {
        if let Some(c) = tx.poll_confirm() {
            assert_eq!(c.status, TxStatus::Delivered);
            break;
        }
        tries += 1;
        assert!(tries < 8, "confirm never arrived");
    }
    let d = tx.driver();
    let air = d.tx_frame(d.tx_count() - 1).unwrap().to_vec();
    air_log.push(air.clone());
    let frame = RxFrame::from_slice(&air, APP_CHANNEL, -40, 200).unwrap();
    rx.driver_mut().inject_rx(&[frame]);
    let mut tries = 0;
    loop {
        if let Some(ind) = rx.poll_indication() {
            return ind.msdu.as_slice().to_vec();
        }
        tries += 1;
        assert!(tries < 8, "indication never arrived");
    }
}

#[test]
fn s31_coordinator_c6_router_c6_enddevice_air() {
    // S31 provisioning drives the identical coordinator core.
    let s31 =
        BoardConfig::s31_coordinator([0x02, 0x11, 0x22, 0x33, 0x44, 0x55], APP_PAN, APP_CHANNEL);
    assert_eq!(s31.target, EspTarget::S31);
    assert_eq!(s31.target.idf_target(), "esp32s31");
    assert!(s31.target.supports_standalone_coordinator());
    assert!(!s31.target.needs_xiao_c6_antenna_select());
    assert!(s31.identity.role().is_some());

    let mut coord_adapter = EspAdapter::new(MockDriver::new());
    coord_adapter.set_pan_id(APP_PAN);
    coord_adapter.set_short_addr(COORD_SHORT);
    coord_adapter.set_extended_addr(rounddance_hal_esp::app::tc_ieee());
    coord_adapter.init().unwrap();

    let mut router_adapter = EspAdapter::new(MockDriver::new());
    router_adapter.set_pan_id(APP_PAN);
    router_adapter.set_short_addr(0x0004);
    router_adapter.set_extended_addr(0x4455_6677_8899_0011);
    router_adapter.init().unwrap();

    let mut joiner_adapter = EspAdapter::new(MockDriver::new());
    joiner_adapter.set_pan_id(APP_PAN);
    joiner_adapter.set_short_addr(0xFFFF);
    joiner_adapter.set_extended_addr(rounddance_hal_esp::app::joiner_ieee());
    joiner_adapter.init().unwrap();

    let mut coord_log = VecLog::default();
    let mut joiner_log = VecLog::default();
    let mut coord = CoordinatorApp::new();
    let mut joiner = JoinerApp::new(&JOINER_DEF).unwrap();
    let mut router = RouterDevice::new(AgingPolicy::default(), 60_000);
    let mut air: Vec<Vec<u8>> = Vec::new();

    // Coordinator forms (S31 board, portable core).
    coord.begin_formation(&mut coord_log).unwrap();
    coord.formation_done(&mut coord_log, true);
    coord.open_permit(&mut coord_log, 60_000).unwrap();
    coord.admit_joiner(&mut coord_log, 0).unwrap();

    // Router joins as a router and learns the uplink route.
    router.begin_join().unwrap();
    assert_eq!(
        router.join_done(true),
        rounddance_roles::RouterState::Active
    );
    router
        .admit_child(JOINER_SHORT, 0x1122_3344_5566_7788, false, 0)
        .unwrap();
    router
        .install_route(COORD_SHORT, COORD_SHORT, 1, 0)
        .unwrap();
    assert_eq!(router.next_hop(COORD_SHORT, 1), Some(COORD_SHORT));
    // Route discovery seam exercises without a storm.
    let rreq = router.start_discovery(0x0005, 0x0004, 2).unwrap();
    assert!(router
        .note_discovery_reply(rreq, 0x0005, 0x0004, 1, 3)
        .unwrap());

    // End-device join (install-code MMO, same as c6_standalone).
    let mut wire = [0u8; 18];
    let n = InstallCode::with_crc(&[0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23], &mut wire)
        .unwrap();
    let code = InstallCode::from_slice(&wire[..n]).unwrap();
    let mut initial_key = [0u8; 16];
    let attrs = coord.exchange_join_key(&code, &mut initial_key).unwrap();
    assert_eq!(attrs, rounddance_commission::KeyAttributes::SYMMETRIC);
    joiner.begin_scan(&mut joiner_log).unwrap();
    for _ in 0..2 {
        joiner
            .ingest_beacon(BeaconSurveyEntry {
                pan_id: APP_PAN,
                channel: APP_CHANNEL,
                lqi: 220,
                rssi: -40,
                permit_joining: true,
                router_capacity: true,
                end_device_capacity: true,
                protocol_version: 2,
            })
            .unwrap();
    }
    assert_eq!(joiner.finish_scan(&mut joiner_log), Some(APP_PAN));
    joiner.assoc_confirm(&mut joiner_log, true);
    joiner_adapter.set_short_addr(JOINER_SHORT);
    {
        use rounddance_commission::{
            build_transport_key_frame, ha_transport_key, TransportKeyParams,
        };
        const JW: [u8; 8] = [0xa4, 0x97, 0x85, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
        const TCW: [u8; 8] = [0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
        const KEY: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let tkey = ha_transport_key().unwrap();
        let tp = TransportKeyParams {
            dst_pan: APP_PAN,
            dst_short: JOINER_SHORT,
            dst_eui: JW,
            src_eui: TCW,
            mac_seq: 0x5a,
            nwk_seq: 0x21,
            nwk_radius: 0x1e,
            aps_ctr: 0x51,
            auxctr: 0x0000_1000,
            seq_no: 0x00,
            netkey: KEY,
            transport_key: tkey,
        };
        let mut tf = [0u8; 128];
        let tn = build_transport_key_frame(&tp, &mut tf).unwrap();
        match joiner.on_nwk_joiner(&tf[9..tn]) {
            JoinerNwkOutcome::TransportAccepted { .. } => {}
            other => panic!("transport not accepted: {other:?}"),
        }
    }
    joiner.verify_confirm(&mut joiner_log);
    assert_eq!(joiner.state(), JoinerState::Announced);
    joiner.close_out(&mut joiner_log);
    assert_eq!(joiner.state(), JoinerState::Joined);

    // Toggle: coordinator seals, router forwards, joiner applies.
    use rounddance_security::{KeySet, NetworkKey};
    const KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    let keys = KeySet::new(NetworkKey::new(KEY, 0));
    let mut scratch = [0u8; 160];
    let _ = coord.take_node_desc_req(&mut scratch, JOINER_SHORT, &KEY);
    coord.new_toggle();
    let mut toggle_buf = [0u8; 160];
    let tlen = coord
        .build_toggle_request(&mut coord_log, &KEY, &mut toggle_buf)
        .unwrap();
    let toggle_msdu = toggle_buf[9..tlen].to_vec();

    // MAC hop 1: coordinator → router over the adapters.
    let at_router = shuttle(
        &mut coord_adapter,
        &mut router_adapter,
        &mut air,
        0x0004,
        &toggle_msdu,
    );
    assert_eq!(at_router, toggle_msdu);
    // NWK hop: router forwards toward the joiner short.
    router
        .forward(JOINER_SHORT, &at_router)
        .expect("router forward");
    assert_eq!(router.route_pending(), 1);
    let mut lamp = Lamp { id: 1, on: false };
    router.register_endpoint(&lamp).expect("register");
    let mut fwd_out = [(0u16, [0u8; MAX_APP_PAYLOAD], 0usize); 8];
    let mut eps: [&mut Lamp; 1] = [&mut lamp];
    let (f, _) = router.tick(&mut eps, |e| e.endpoint_id(), &mut fwd_out, 4);
    assert_eq!(f, 1);
    assert_eq!(fwd_out[0].0, JOINER_SHORT);
    assert_eq!(&fwd_out[0].1[..fwd_out[0].2], &at_router[..]);
    assert_eq!(router.forwarded(), 1);

    // MAC hop 2: router → joiner.
    let at_joiner = shuttle(
        &mut router_adapter,
        &mut joiner_adapter,
        &mut air,
        JOINER_SHORT,
        &fwd_out[0].1[..fwd_out[0].2],
    );
    match joiner.on_nwk_joiner(&at_joiner) {
        JoinerNwkOutcome::Data { cluster, profile } => {
            assert_eq!((cluster, profile), (0x0006, 0x0104))
        }
        other => panic!("toggle not Data: {other:?}"),
    }
    let mut resp_buf = [0u8; 160];
    let rlen = joiner
        .answer_toggle(&mut joiner_log, &at_joiner, &mut resp_buf)
        .unwrap();
    assert!(joiner.lamp());
    let defrsp_msdu = resp_buf[9..rlen].to_vec();

    // Return path through the router.
    router
        .forward(COORD_SHORT, &defrsp_msdu)
        .expect("return forward");
    let mut fwd_back = [(0u16, [0u8; MAX_APP_PAYLOAD], 0usize); 8];
    let (f2, _) = router.tick(&mut eps, |e| e.endpoint_id(), &mut fwd_back, 5);
    assert_eq!(f2, 1);
    let at_coord = shuttle(
        &mut joiner_adapter,
        &mut coord_adapter,
        &mut air,
        COORD_SHORT,
        &fwd_back[0].1[..fwd_back[0].2],
    );
    match coord.on_nwk_data(&at_coord, &keys, 9_000) {
        NwkRxOutcome::Data { cluster, profile } => assert_eq!((cluster, profile), (0x0006, 0x0104)),
        other => panic!("defrsp not Data: {other:?}"),
    }
    assert!(coord
        .verify_defrsp(&mut coord_log, &keys, &at_coord)
        .unwrap());
    assert_eq!(coord.defrsp_ok, 1);
    assert_eq!(router.forwarded(), 2);
}

/// Confirm-driven retry (the fw radiate loop shape): a NoAck confirm
/// re-pends the frame and the retry radiates identical MSDU bytes
/// (fresh MAC sequence only). Proves the loss path the C6 router and
/// S31 coordinator loops rely on when the band is congested.
#[test]
fn router_confirm_retry_radiates_identical_msdu() {
    use rounddance_hal_esp::{MockDriver, TxEvent, TxFail};
    let mut adapter = EspAdapter::new(MockDriver::new());
    adapter.set_pan_id(APP_PAN);
    adapter.set_short_addr(COORD_SHORT);
    adapter.set_extended_addr(0x0102_0304_0506_0708);
    adapter.init().unwrap();
    adapter.driver_mut().hold_auto_complete();
    adapter
        .driver_mut()
        .script_events(&[TxEvent::Failed(TxFail::NoAck), TxEvent::Done]);

    let msdu = [0x0Au8, 0x0B, 0x0C, 0x0D];
    let retry_budget = 4u8;
    let mut tries = 0u8;
    let mut radiated = false;
    while tries < retry_budget && !radiated {
        let _h = adapter
            .data_request(TxRequest {
                dst: MacAddress::short(APP_PAN, JOINER_SHORT),
                msdu: FramePayload::from_slice(&msdu).unwrap(),
                options: TxOptions::ACK,
            })
            .unwrap();
        if let Some(c) = adapter.poll_confirm() {
            tries += 1;
            if c.status == TxStatus::Delivered {
                radiated = true;
            }
        } else {
            break;
        }
    }
    assert!(radiated, "retry must eventually deliver");
    assert_eq!(tries, 2, "one NoAck then one Delivered");
    let d = adapter.driver();
    assert_eq!(d.tx_count(), 2);
    let first = d.tx_frame(0).unwrap().to_vec();
    let second = d.tx_frame(1).unwrap().to_vec();
    // Same MSDU on air both times; only the MAC sequence differs.
    assert_eq!(&first[10..], &second[10..]);
    assert_eq!(&first[10..], &msdu);
    assert_ne!(first[3], second[3], "fresh MAC sequence per attempt");
}

/// C6 router uplink join over the MAC SAP, then router duties.
///
/// Closes the "unconditional `join_done(true)`" gap: the router's own
/// uplink runs the real install-code join (scan → assoc-req/rsp over
/// MAC PSDUs → transport-key open → annce → joined) through a
/// `JoinerApp` uplink identity, and `RouterDevice` activates only on
/// the observed `Joined` state. Post-join the router serves a sleepy
/// child (hold → poll → deliver), forwards by installed route, and
/// hosts its endpoint — all under the fairness tick.
#[test]
fn c6_router_joins_over_mac_then_serves_children() {
    use rounddance_commission::{build_transport_key_frame, ha_transport_key, TransportKeyParams};
    let mut coord_log = VecLog::default();
    let mut uplink_log = VecLog::default();
    let mut coord = CoordinatorApp::new();
    static UPLINK_DEF: onoff::ServerDef = onoff::ServerDef;
    let mut uplink = JoinerApp::new(&UPLINK_DEF).unwrap();
    let mut router = RouterDevice::new(AgingPolicy::default(), 60_000);

    // Coordinator admits the router uplink as an extra short.
    coord.begin_formation(&mut coord_log).unwrap();
    coord.formation_done(&mut coord_log, true);
    coord.open_permit(&mut coord_log, 60_000).unwrap();
    const ROUTER_SHORT: u16 = 0x0004;
    coord
        .admit_extra(
            &mut coord_log,
            rounddance_hal_esp::app::JOINER_EUI,
            ROUTER_SHORT,
        )
        .unwrap();
    let mut wire = [0u8; 18];
    let n = InstallCode::with_crc(&[0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23], &mut wire)
        .unwrap();
    let code = InstallCode::from_slice(&wire[..n]).unwrap();
    let mut initial_key = [0u8; 16];
    let _ = coord.exchange_join_key(&code, &mut initial_key).unwrap();

    // Uplink scan → candidate.
    uplink.begin_scan(&mut uplink_log).unwrap();
    for _ in 0..2 {
        uplink
            .ingest_beacon(BeaconSurveyEntry {
                pan_id: APP_PAN,
                channel: APP_CHANNEL,
                lqi: 220,
                rssi: -40,
                permit_joining: true,
                router_capacity: true,
                end_device_capacity: true,
                protocol_version: 2,
            })
            .unwrap();
    }
    assert_eq!(uplink.finish_scan(&mut uplink_log), Some(APP_PAN));

    // Assoc-req over a MAC PSDU; coordinator latches + pends RSP.
    let mut areq = [0u8; 32];
    let an = uplink
        .take_assoc_req(&mut areq, APP_PAN, COORD_SHORT)
        .unwrap();
    let _ = coord.on_mac_psdu(&areq[..an]);
    assert!(coord.assoc_pending());
    let mut arsp = [0u8; 32];
    let rn = coord.take_assoc_rsp(&mut arsp).unwrap();
    assert!(rn > 0);
    let _ = uplink.on_mac_psdu(&mut uplink_log, &arsp[..rn], APP_CHANNEL, -40, 200);
    assert_eq!(uplink.assoc_short(), Some(ROUTER_SHORT));

    // Transport-key open → announced → joined.
    const KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    {
        const JW: [u8; 8] = [0xa4, 0x97, 0x85, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
        const TCW: [u8; 8] = [0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
        let tkey = ha_transport_key().unwrap();
        let tp = TransportKeyParams {
            dst_pan: APP_PAN,
            dst_short: ROUTER_SHORT,
            dst_eui: JW,
            src_eui: TCW,
            mac_seq: 0x5a,
            nwk_seq: 0x21,
            nwk_radius: 0x1e,
            aps_ctr: 0x51,
            auxctr: 0x0000_1000,
            seq_no: 0x00,
            netkey: KEY,
            transport_key: tkey,
        };
        let mut tf = [0u8; 128];
        let tn = build_transport_key_frame(&tp, &mut tf).unwrap();
        match uplink.on_nwk_joiner(&tf[9..tn]) {
            JoinerNwkOutcome::TransportAccepted { .. } => {}
            other => panic!("router uplink transport refused: {other:?}"),
        }
    }
    uplink.verify_confirm(&mut uplink_log);
    uplink.close_out(&mut uplink_log);
    assert_eq!(uplink.state(), JoinerState::Joined);

    // Activation is gated on the observed join — never unconditional.
    router.begin_join().unwrap();
    assert_eq!(
        router.join_done(uplink.state() == JoinerState::Joined),
        rounddance_roles::RouterState::Active
    );

    // Router duties under the adopted short: sleepy child hold →
    // poll → deliver, installed-route forward, local endpoint.
    router
        .admit_child(0x0005, 0xAABB_CCDD_EEFF_0011, true, 0)
        .unwrap();
    router
        .install_route(COORD_SHORT, COORD_SHORT, 1, 0)
        .unwrap();
    assert_eq!(router.next_hop(COORD_SHORT, 1), Some(COORD_SHORT));
    let held = [0x55u8, 0x66];
    router.hold_for_child(0x0005, &held, 2).unwrap();
    let served = router.serve_poll(0x0005, 3).unwrap().expect("held frame");
    assert_eq!(served.payload(), &held);
    assert!(router.serve_poll(0x0005, 4).unwrap().is_none());

    router.forward(COORD_SHORT, &[0x09, 0x08]).unwrap();
    let mut lamp = Lamp { id: 1, on: false };
    router.register_endpoint(&lamp).unwrap();
    router.deliver_to_endpoint(1, &[0x01]).unwrap();
    let mut fwd_out = [(0u16, [0u8; MAX_APP_PAYLOAD], 0usize); 8];
    let mut eps: [&mut Lamp; 1] = [&mut lamp];
    let (f, a) = router.tick(&mut eps, |e| e.endpoint_id(), &mut fwd_out, 5);
    assert_eq!((f, a), (1, 1));
    assert_eq!(fwd_out[0].0, COORD_SHORT);
    assert!(lamp.on);
}
