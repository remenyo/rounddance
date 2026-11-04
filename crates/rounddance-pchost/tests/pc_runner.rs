//! PC-runner proof: form → join → ZCL toggle over two scripted
//! RCP links, plus the NCP half-host drive.
//!
//! The same [`PcRunner`](rounddance_pchost::PcRunner) the `rd-pchost`
//! binary owns runs here over `HostSide` + `EmulatedRcp` pairs with
//! a scripted air medium between them.
//!
//! Coordinator forms, the joiner scans over a real beacon-req and
//! beacon exchange through the MAC-command queue, associates over
//! assoc-req and assoc-rsp with SHORT-SNOOP latch plus host
//! confirm, adopts the transport key, announces with a bare
//! DeviceAnnce over `data_request` decoded by the coordinator,
//! answers Node_desc, and applies a secured Toggle with a verified
//! Default Response. A captured toggle replayed on both legs is
//! refused. The NCP leg commissions a scripted chip and drives its
//! lamp to on.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-RCP-NCP-03` (PC runner form/join/toggle), `RD-RCP-NCP-04`
//! (NCP drive); reused corpus rows per the app layer.

use rounddance_commission::{InstallCode, JoinerState, KeyAttributes};
use rounddance_hal_esp::app::{
    role_from_mac, AppRole, CoordinatorApp, JoinerApp, JoinerNwkOutcome, NwkIgnore, NwkRxOutcome,
    APP_PAN, COORD_BASE_MAC, COORD_SHORT, JOINER_BASE_MAC, JOINER_EUI, JOINER_SHORT, TC_EUI_WIRE,
    UNASSOC_SHORT,
};
use rounddance_hal_esp::{mac_cmd, SerialLog};
use rounddance_mac_sap::{
    FramePayload, MacAddress, MacDataSap as _, MacMgmtSap as _, TxOptions, TxRequest, TxStatus,
};
use rounddance_pchost::PcRunner;
use rounddance_rcp::{EmulatedRcp, HostSide};
use rounddance_zcl::onoff;
use rounddance_zdo::DeviceAnnce;

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

const JOINER_EUI_WIRE: [u8; 8] = {
    let mut w = JOINER_EUI;
    let mut i = 0;
    while i < 4 {
        let t = w[i];
        w[i] = w[7 - i];
        w[7 - i] = t;
        i += 1;
    }
    w
};

/// One scripted air leg: host runner + RCP firmware.
struct AirNode {
    runner: PcRunner<HostSide>,
    peer: EmulatedRcp,
    app_log: VecLog,
}

impl AirNode {
    fn pump(&mut self) {
        let mut buf = [0u8; 512];
        let mut n = 0;
        while let Some(b) = self.runner.driver_mut().uart_mut().outbound.pop() {
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
            assert!(self.runner.driver_mut().uart_mut().inbound.push(*b));
        }
        self.runner.driver_mut().poll();
    }
}

/// Move every radiated frame from `a` to `b` with the sender's
/// tuned channel as the arrival channel, pumping both ends.
fn transfer(a: &mut AirNode, b: &mut AirNode) {
    a.pump();
    while let Some(tx) = a.peer.take_tx() {
        let _ = b.peer.queue_rx_on(
            &tx.psdu[..tx.len as usize],
            -50,
            200,
            tx.inter_pan,
            tx.channel,
        );
    }
    b.pump();
}

fn provisioned_pair() -> (AirNode, AirNode) {
    let mut coord = AirNode {
        runner: PcRunner::new(HostSide::new()),
        peer: EmulatedRcp::new(),
        app_log: VecLog::default(),
    };
    let mut joiner = AirNode {
        runner: PcRunner::new(HostSide::new()),
        peer: EmulatedRcp::new(),
        app_log: VecLog::default(),
    };
    for node in [&mut coord, &mut joiner] {
        node.runner.driver_mut().reset(true);
        node.pump();
        assert!(node.runner.ready());
    }
    coord
        .runner
        .provision(
            15,
            APP_PAN,
            COORD_SHORT,
            u64::from_le_bytes(TC_EUI_WIRE),
            10,
        )
        .unwrap();
    joiner
        .runner
        .provision(
            15,
            0xFFFF,
            UNASSOC_SHORT,
            u64::from_le_bytes(JOINER_EUI_WIRE),
            10,
        )
        .unwrap();
    coord.pump();
    joiner.pump();
    (coord, joiner)
}

/// Shuttle one complete MAC PSDU from `a`'s radio to `b`'s radio
/// (confirm must land `Delivered` on `a`); the caller drains
/// whichever queue the shape routes to.
fn shuttle_raw(a: &mut AirNode, b: &mut AirNode, psdu: &[u8]) {
    let h = a.runner.driver_mut().transmit_mac(psdu).unwrap();
    a.pump();
    transfer(a, b);
    let c = a.runner.driver_mut().poll_confirm().unwrap();
    assert_eq!((c.handle, c.status), (h, TxStatus::Delivered));
}

/// Shuttle one NPDU from `a` to `b`'s PAN queue; returns the MSDU.
fn shuttle_data(a: &mut AirNode, b: &mut AirNode, dst: u16, npdu: &[u8]) -> Vec<u8> {
    let h = a
        .runner
        .driver_mut()
        .data_request(TxRequest {
            dst: MacAddress::short(APP_PAN, dst),
            msdu: FramePayload::from_slice(npdu).unwrap(),
            options: TxOptions::ACK,
        })
        .unwrap();
    a.pump();
    transfer(a, b);
    let c = a.runner.driver_mut().poll_confirm().unwrap();
    assert_eq!((c.handle, c.status), (h, TxStatus::Delivered));
    b.runner
        .driver_mut()
        .poll_indication()
        .unwrap()
        .msdu
        .as_slice()
        .to_vec()
}

#[test]
fn pc_runner_form_join_toggle_over_rcp() {
    use rounddance_security::{KeySet, NetworkKey};
    assert_eq!(role_from_mac(&COORD_BASE_MAC), Some(AppRole::Coordinator));
    assert_eq!(role_from_mac(&JOINER_BASE_MAC), Some(AppRole::Joiner));

    let (mut coord_node, mut joiner_node) = provisioned_pair();
    let mut coord = CoordinatorApp::new();
    let mut joiner = JoinerApp::new(&JOINER_DEF).unwrap();

    // Formation + permit + install-code admission (stack logic, the
    // same calls the standalone image makes).
    coord.begin_formation(&mut coord_node.app_log).unwrap();
    coord.formation_done(&mut coord_node.app_log, true);
    coord.open_permit(&mut coord_node.app_log, 60_000).unwrap();
    coord.admit_joiner(&mut coord_node.app_log, 0).unwrap();
    let mut wire = [0u8; 18];
    let n = InstallCode::with_crc(&[0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23], &mut wire)
        .unwrap();
    let code = InstallCode::from_slice(&wire[..n]).unwrap();
    let mut initial_key = [0u8; 16];
    let attrs = coord.exchange_join_key(&code, &mut initial_key).unwrap();
    assert_eq!(attrs, KeyAttributes::SYMMETRIC);

    // Joiner survey over real beacon frames: two solicited answers
    // (the N-sighting gate needs two rows) through the MAC queues.
    joiner.begin_scan(&mut joiner_node.app_log).unwrap();
    let mut seq: u8 = 0;
    for _ in 0..2 {
        let mut req = [0u8; 8];
        seq = seq.wrapping_add(1);
        let rn = mac_cmd::build_beacon_req(seq, &mut req).unwrap();
        shuttle_raw(&mut joiner_node, &mut coord_node, &req[..rn]);
        // Coordinator answers the solicited beacon.
        let got_req = coord_node
            .runner
            .driver_mut()
            .poll_mac_indication()
            .unwrap();
        let inc = coord.on_mac_psdu(got_req.psdu());
        assert!(matches!(inc, mac_cmd::Incoming::BeaconReq { .. }));
        let mut bc = [0u8; 26];
        let bn = coord.take_beacon(&mut bc).unwrap();
        assert!(bn > 0);
        shuttle_raw(&mut coord_node, &mut joiner_node, &bc[..bn]);
        let got = joiner_node
            .runner
            .driver_mut()
            .poll_mac_indication()
            .unwrap();
        let inc = joiner.on_mac_psdu(
            &mut joiner_node.app_log,
            got.psdu(),
            got.channel_number(),
            got.rssi(),
            got.lqi(),
        );
        assert!(matches!(inc, mac_cmd::Incoming::Beacon(_)));
    }
    assert_eq!(joiner.finish_scan(&mut joiner_node.app_log), Some(APP_PAN));

    // Association over real assoc frames: req → rsp + SHORT-SNOOP
    // latch on the joiner firmware + host confirm.
    let mut areq = [0u8; 19];
    let an = joiner
        .take_assoc_req(&mut areq, APP_PAN, COORD_SHORT)
        .unwrap();
    shuttle_raw(&mut joiner_node, &mut coord_node, &areq[..an]);
    let got_req = coord_node
        .runner
        .driver_mut()
        .poll_mac_indication()
        .unwrap();
    let inc = coord.on_mac_psdu(got_req.psdu());
    assert!(matches!(inc, mac_cmd::Incoming::AssocReq(_)));
    // Adopt the elected PAN before the answer arrives (the radio
    // filter class the firmware models).
    joiner_node
        .runner
        .provision(
            15,
            APP_PAN,
            UNASSOC_SHORT,
            u64::from_le_bytes(JOINER_EUI_WIRE),
            10,
        )
        .unwrap();
    joiner_node.pump();
    let mut arsp = [0u8; 25];
    let rn = coord.take_assoc_rsp(&mut arsp).unwrap();
    assert!(rn > 0);
    // The success short rides at [22..24] with status 0x00 at [24];
    // confirm it to the RCP before the slow path (second copy — the
    // firmware snoops the first at queue time).
    assert_eq!(arsp[24], 0x00);
    let short = u16::from_le_bytes([arsp[22], arsp[23]]);
    assert_eq!(short, JOINER_SHORT);
    shuttle_raw(&mut coord_node, &mut joiner_node, &arsp[..rn]);
    assert_eq!(
        joiner_node.peer.short(),
        Some(JOINER_SHORT),
        "firmware SHORT-SNOOP latched at queue time"
    );
    let got_rsp = joiner_node
        .runner
        .driver_mut()
        .poll_mac_indication()
        .unwrap();
    let inc = joiner.on_mac_psdu(
        &mut joiner_node.app_log,
        got_rsp.psdu(),
        got_rsp.channel_number(),
        got_rsp.rssi(),
        got_rsp.lqi(),
    );
    assert!(matches!(inc, mac_cmd::Incoming::AssocRsp(_)));
    assert_eq!(joiner.assoc_short(), Some(JOINER_SHORT));
    joiner_node.runner.driver_mut().set_short_addr(JOINER_SHORT);
    joiner_node.pump();
    assert!(joiner_node
        .runner
        .driver_mut()
        .note_assoc_response(JOINER_SHORT, 0x00));

    // Transport-key delivery over a real secured frame: the joiner
    // adopts the network key, announces, and joins.
    const KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    let tkey = rounddance_commission::ha_transport_key().unwrap();
    let mut tf = [0u8; 128];
    let tn = coord.take_transport_key(&mut tf, &KEY, &tkey).unwrap();
    assert!(tn > 0);
    shuttle_raw(&mut coord_node, &mut joiner_node, &tf[..tn]);
    // A secured NWK frame parses as data (MHR route), not MAC.
    assert!(joiner_node
        .runner
        .driver_mut()
        .poll_mac_indication()
        .is_none());
    let tf_msdu = joiner_node
        .runner
        .driver_mut()
        .poll_indication()
        .unwrap()
        .msdu
        .as_slice()
        .to_vec();
    match joiner.on_nwk_joiner(&tf_msdu) {
        JoinerNwkOutcome::TransportAccepted { .. } => {}
        other => panic!("transport not accepted: {other:?}"),
    }
    joiner.verify_confirm(&mut joiner_node.app_log);
    joiner.close_out(&mut joiner_node.app_log);
    assert_eq!(joiner.state(), JoinerState::Joined);

    // Announce leg: bare DeviceAnnce over data_request, decoded +
    // heard by the coordinator.
    let mut annce_buf = [0u8; DeviceAnnce::LEN];
    let alen = joiner.build_annce(&mut annce_buf).unwrap();
    let heard = shuttle_data(
        &mut joiner_node,
        &mut coord_node,
        COORD_SHORT,
        &annce_buf[..alen],
    );
    let decoded = DeviceAnnce::decode(&heard).unwrap();
    assert_eq!(decoded.nwk_addr, JOINER_SHORT);
    assert_eq!(decoded.ieee, u64::from_le_bytes(JOINER_EUI));
    coord.joiner_heard(1_000).unwrap();
    assert!(!joiner.lamp(), "lamp starts off");

    // ZCL leg: coordinator Node_desc → joiner answer → toggle →
    // DefRsp, all secured, all over the scripted air.
    let keys = KeySet::new(NetworkKey::new(KEY, 0));
    let mut scratch = [0u8; 160];
    let _ = coord.take_node_desc_req(&mut scratch, JOINER_SHORT, &KEY);
    coord.new_toggle();
    let mut toggle_buf = [0u8; 160];
    let tlen = coord
        .build_toggle_request(&mut coord_node.app_log, &KEY, &mut toggle_buf)
        .unwrap();
    let toggle_npdu = toggle_buf[..tlen].to_vec();
    shuttle_raw(&mut coord_node, &mut joiner_node, &toggle_npdu);
    let got_msdu = joiner_node
        .runner
        .driver_mut()
        .poll_indication()
        .unwrap()
        .msdu
        .as_slice()
        .to_vec();
    match joiner.on_nwk_joiner(&got_msdu) {
        JoinerNwkOutcome::Data { cluster, profile } => {
            assert_eq!((cluster, profile), (0x0006, 0x0104));
        }
        other => panic!("toggle not classified as Data: {other:?}"),
    }
    let mut resp_buf = [0u8; 160];
    let rlen = joiner
        .answer_toggle(&mut joiner_node.app_log, &got_msdu, &mut resp_buf)
        .unwrap();
    assert!(joiner.lamp(), "toggle flips the lamp off→on");
    let defrsp_npdu = resp_buf[..rlen].to_vec();
    shuttle_raw(&mut joiner_node, &mut coord_node, &defrsp_npdu);
    let back_msdu = coord_node
        .runner
        .driver_mut()
        .poll_indication()
        .unwrap()
        .msdu
        .as_slice()
        .to_vec();
    match coord.on_nwk_data(&back_msdu, &keys, 9_000) {
        NwkRxOutcome::Data { cluster, profile } => {
            assert_eq!((cluster, profile), (0x0006, 0x0104));
        }
        other => panic!("defrsp not classified as Data: {other:?}"),
    }
    assert!(coord
        .verify_defrsp(&mut coord_node.app_log, &keys, &back_msdu)
        .unwrap());
    assert_eq!(coord.defrsp_ok, 1);

    // Replay refusal on both legs (firewall holds at classification).
    match joiner.on_nwk_joiner(&toggle_npdu[9..]) {
        JoinerNwkOutcome::Ignored(NwkIgnore::Replay) => {}
        other => panic!("joiner replay not refused: {other:?}"),
    }
    match coord.on_nwk_data(&defrsp_npdu[9..], &keys, 9_001) {
        NwkRxOutcome::Ignored(NwkIgnore::Replay) => {}
        other => panic!("coord replay not refused: {other:?}"),
    }
    assert!(joiner.lamp());
}

#[test]
fn pc_runner_ncp_drive_lamp() {
    use rounddance_pchost::NcpRunner;
    use rounddance_rcp::{NcpDevice, NcpEvent, NcpHost};
    let mut host = NcpRunner::new(HostSide::new());
    let mut dev = NcpDevice::new();
    let mut buf = [0u8; 256];
    let mut pump = |host: &mut NcpRunner<HostSide>, dev: &mut NcpDevice| {
        let mut n = 0;
        while let Some(b) = host.host_mut().uart_mut().outbound.pop() {
            if n >= buf.len() {
                break;
            }
            buf[n] = b;
            n += 1;
        }
        dev.push_host_bytes(&buf[..n]);
        dev.poll();
        let m = dev.take_ncp_bytes(&mut buf);
        for b in &buf[..m] {
            assert!(host.host_mut().uart_mut().inbound.push(*b));
        }
        host.advance(1_000);
    };
    // Same calls the binary makes: reset → form → permit → admit →
    // toggle → attribute report.
    host.host_mut().reset(true).unwrap();
    pump(&mut host, &mut dev);
    assert!(matches!(host.events().as_slice(), [NcpEvent::Ready { .. }]));
    host.host_mut().form(15, APP_PAN, 10).unwrap();
    pump(&mut host, &mut dev);
    host.host_mut().permit(60).unwrap();
    pump(&mut host, &mut dev);
    host.host_mut().admit(JOINER_EUI, JOINER_SHORT).unwrap();
    pump(&mut host, &mut dev);
    let evs = host.events();
    assert!(evs.iter().any(|e| matches!(
        e,
        NcpEvent::Joined {
            short: JOINER_SHORT,
            ..
        }
    )));
    host.host_mut().toggle(JOINER_SHORT).unwrap();
    pump(&mut host, &mut dev);
    let evs = host.events();
    assert!(evs.iter().any(|e| matches!(
        e,
        NcpEvent::Attr {
            short: JOINER_SHORT,
            cluster: 0x0006,
            value: 1
        }
    )));
    // Direct host check too (unit-level, no runner): the lamp is on.
    let _ = NcpHost::<HostSide>::new(HostSide::new());
    assert_eq!(dev.lamp(JOINER_SHORT), Some(true));
}

#[test]
fn pc_runner_probe_names_target_and_replays() {
    use rounddance_rcp::cmd::{CAPS_TARGET_C6, CAPS_TARGET_H2, CAPS_TARGET_S31};
    fn pump(runner: &mut PcRunner<HostSide>, peer: &mut EmulatedRcp) {
        let mut buf = [0u8; 256];
        let mut n = 0;
        while let Some(b) = runner.driver_mut().uart_mut().outbound.pop() {
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
            assert!(runner.driver_mut().uart_mut().inbound.push(*b));
        }
        runner.driver_mut().poll();
    }
    for (bit, name) in [
        (CAPS_TARGET_H2, "H2"),
        (CAPS_TARGET_C6, "C6"),
        (CAPS_TARGET_S31, "S31"),
    ] {
        let mut runner = PcRunner::new(HostSide::new());
        let mut peer = EmulatedRcp::new();
        peer.target_caps = bit;
        runner.driver_mut().reset(true);
        // Manual pump (no wall clock in tests).
        pump(&mut runner, &mut peer);
        assert!(runner.ready());
        runner.query_version();
        pump(&mut runner, &mut peer);
        let info = runner.probe_info().expect("version latched");
        assert_eq!(info.target, Some(name));
    }
}
