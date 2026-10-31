//! C6-standalone full-stack proof: form → join → ZCL toggle over
//! [`MockDriver`](rounddance_hal_esp::MockDriver).
//!
//! The app logic runs against two [`EspAdapter`]s (coordinator +
//! joiner) with air frames shuttled mock-to-mock, mirroring the
//! wave-23 OTA run deterministically: same network identity, same
//! role-by-MAC selection, same log discipline, same exchange order
//! (formation → permit → admit → install-code join → DeviceAnnce →
//! secured ZCL Toggle → Default Response, plus the wave-23
//! unsecured-vendor-frame tolerance and replay refusal).

use rounddance_commission::{BeaconSurveyEntry, InstallCode, JoinerState, UNSECURED_VENDOR_CMD};
use rounddance_hal_esp::{
    app::{
        role_from_mac, AppRole, CoordinatorApp, JoinerApp, APP_CHANNEL, APP_PAN, COORD_BASE_MAC,
        COORD_SHORT, EXT_PAN_ID, JOINER_BASE_MAC, JOINER_SHORT, MAC_CAPS, UNASSOC_SHORT,
        ZCL_ENDPOINT,
    },
    driver::RxFrame,
    EspAdapter, MockDriver, SerialLog,
};
use rounddance_mac_sap::{
    FramePayload, MacAddress, MacDataSap, MacMgmtSap, TxOptions, TxRequest, TxStatus,
};
use rounddance_zcl::onoff;
use rounddance_zdo::DeviceAnnce;

static JOINER_DEF: onoff::ServerDef = onoff::ServerDef;

/// Collecting serial log for assertions.
#[derive(Default)]
struct VecLog {
    lines: Vec<String>,
}

impl SerialLog for VecLog {
    fn log(&mut self, line: &str) {
        self.lines.push(line.to_string());
    }
}

impl VecLog {
    fn has(&self, needle: &str) -> bool {
        self.lines.iter().any(|l| l.contains(needle))
    }
}

/// One full-stack run: both adapters, both apps, shuttled air.
struct FullStack {
    coord_adapter: EspAdapter<MockDriver>,
    joiner_adapter: EspAdapter<MockDriver>,
    coord: CoordinatorApp,
    joiner: JoinerApp<'static>,
    coord_log: VecLog,
    joiner_log: VecLog,
    /// MAC air frames shuttled, in order (for the determinism pin).
    air: Vec<Vec<u8>>,
}

impl FullStack {
    fn new() -> Self {
        // Role selection refuses before any radio is touched (full
        // base-MAC compare on the verified lab pair).
        assert_eq!(role_from_mac(&COORD_BASE_MAC), Some(AppRole::Coordinator));
        assert_eq!(role_from_mac(&JOINER_BASE_MAC), Some(AppRole::Joiner));

        let mut coord_adapter = EspAdapter::new(MockDriver::new());
        coord_adapter.set_pan_id(APP_PAN);
        coord_adapter.set_short_addr(COORD_SHORT);
        coord_adapter.set_extended_addr(rounddance_hal_esp::app::tc_ieee());
        coord_adapter.init().unwrap();

        let mut joiner_adapter = EspAdapter::new(MockDriver::new());
        joiner_adapter.set_pan_id(APP_PAN);
        joiner_adapter.set_short_addr(UNASSOC_SHORT);
        joiner_adapter.set_extended_addr(rounddance_hal_esp::app::joiner_ieee());
        joiner_adapter.init().unwrap();

        Self {
            coord_adapter,
            joiner_adapter,
            coord: CoordinatorApp::new(),
            joiner: JoinerApp::new(&JOINER_DEF).unwrap(),
            coord_log: VecLog::default(),
            joiner_log: VecLog::default(),
            air: Vec::new(),
        }
    }

    /// Send one NPDU over `tx`, shuttle the MAC air frame into `rx`,
    /// and return the received MSDU.
    fn shuttle(&mut self, from_joiner: bool, dst: u16, npdu: &[u8]) -> Vec<u8> {
        let (tx, rx) = if from_joiner {
            (&mut self.joiner_adapter, &mut self.coord_adapter)
        } else {
            (&mut self.coord_adapter, &mut self.joiner_adapter)
        };
        tx.data_request(TxRequest {
            dst: MacAddress::short(APP_PAN, dst),
            msdu: FramePayload::from_slice(npdu).unwrap(),
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
        self.air.push(air.clone());
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

    /// Run the whole exchange; returns (toggle NPDU, defrsp NPDU).
    fn run(&mut self) -> (Vec<u8>, Vec<u8>) {
        // Formation: scan → conflict check → centralized primitive →
        // confirm, then the permit window opens on the allow-list.
        self.coord.begin_formation(&mut self.coord_log).unwrap();
        self.coord.formation_done(&mut self.coord_log, true);
        self.coord.open_permit(&mut self.coord_log, 60_000).unwrap();
        self.coord.admit_joiner(&mut self.coord_log, 0).unwrap();

        // Install-code join with the real MMO KDF (never a mock).
        let mut wire = [0u8; 18];
        let n = InstallCode::with_crc(&[0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23], &mut wire)
            .unwrap();
        let code = InstallCode::from_slice(&wire[..n]).unwrap();
        let mut initial_key = [0u8; 16];
        let attrs = self
            .coord
            .exchange_join_key(&code, &mut initial_key)
            .unwrap();
        assert_eq!(attrs, rounddance_commission::KeyAttributes::SYMMETRIC);

        // Joiner: survey → candidate → assoc → vendor-frame tolerance
        // (wave-23 captured 0x30) → key → verify → announced.
        self.joiner.begin_scan(&mut self.joiner_log).unwrap();
        self.joiner
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
        assert_eq!(self.joiner.finish_scan(&mut self.joiner_log), Some(APP_PAN));
        self.joiner.assoc_confirm(&mut self.joiner_log, true);
        // Association assigns the short address, as on device.
        self.joiner_adapter.set_short_addr(JOINER_SHORT);
        self.joiner.tolerate_unsecured(UNSECURED_VENDOR_CMD);
        assert_eq!(self.joiner.unsecured_tolerated, 1);
        self.joiner.key_transport(&mut self.joiner_log, true);
        self.joiner.verify_confirm(&mut self.joiner_log);
        assert_eq!(
            self.joiner.state(),
            rounddance_commission::JoinerState::Announced
        );

        // Announce leg over the adapters (ZDO DeviceAnnce).
        let mut annce_buf = [0u8; DeviceAnnce::LEN];
        let alen = self.joiner.build_annce(&mut annce_buf).unwrap();
        assert_eq!(alen, DeviceAnnce::LEN);
        let heard = self.shuttle(true, COORD_SHORT, &annce_buf[..alen]);
        let decoded = DeviceAnnce::decode(&heard).unwrap();
        assert_eq!(decoded.nwk_addr, JOINER_SHORT);
        assert_eq!(decoded.ieee, rounddance_hal_esp::app::joiner_ieee());
        self.coord.joiner_heard(1).unwrap();
        self.joiner.close_out(&mut self.joiner_log);
        assert_eq!(
            self.joiner.state(),
            rounddance_commission::JoinerState::Joined
        );
        assert!(!self.joiner.lamp(), "lamp starts off");

        // ZCL leg: coordinator serves Toggle, joiner applies it on
        // the live server behavior and answers Default Response.
        let mut toggle_buf = [0u8; 128];
        let tlen = self
            .coord
            .build_toggle_request(&mut self.coord_log, &mut toggle_buf)
            .unwrap();
        let toggle_npdu = toggle_buf[..tlen].to_vec();
        let got = self.shuttle(false, JOINER_SHORT, &toggle_npdu);
        assert_eq!(got, toggle_npdu);
        let mut resp_buf = [0u8; 128];
        let rlen = self
            .joiner
            .handle_toggle(&mut self.joiner_log, &got, &mut resp_buf)
            .unwrap();
        assert!(self.joiner.lamp(), "toggle flips the lamp off→on");
        let defrsp_npdu = resp_buf[..rlen].to_vec();
        let got_back = self.shuttle(true, COORD_SHORT, &defrsp_npdu);
        assert_eq!(got_back, defrsp_npdu);
        assert!(self
            .coord
            .handle_defrsp(&mut self.coord_log, &got_back)
            .unwrap());
        assert_eq!(self.coord.defrsp_ok, 1);

        (toggle_npdu, defrsp_npdu)
    }
}

/// The full exchange completes: join states, lamp flip, verified
/// Default Response, and the serial-log discipline lines.
#[test]
fn c6_standalone_form_join_toggle() {
    let mut stack = FullStack::new();
    let (toggle, defrsp) = stack.run();
    assert!(!toggle.is_empty());
    assert!(!defrsp.is_empty());
    assert_ne!(toggle, defrsp);
    assert_eq!(stack.coord.toggles_sent, 1);
    assert_eq!(stack.joiner.defrsp_sent, 1);
    assert!(stack.joiner.lamp());

    for needle in [
        "C6APP FORMED",
        "C6APP PERMIT open",
        "C6APP ADMIT",
        "C6APP JOINED announced",
        "C6APP JOIN-COMPLETE",
        "C6APP TX-TOGGLE",
        "C6APP TX-DEFRSP",
        "C6APP DEFRSP ok",
    ] {
        assert!(
            stack.coord_log.has(needle) || stack.joiner_log.has(needle),
            "missing log line: {needle}"
        );
    }
    // Endpoint identity is on the wire: HA profile endpoints both
    // legs carry the app endpoint.
    assert_eq!(ZCL_ENDPOINT, 0x01);
    assert_eq!(MAC_CAPS, 0x8c);
}

/// Replayed toggle bytes are refused (replay table), on both legs.
#[test]
fn c6_standalone_replay_is_refused() {
    let mut stack = FullStack::new();
    let (toggle, defrsp) = stack.run();
    let mut out = [0u8; 128];
    assert_eq!(
        stack
            .joiner
            .handle_toggle(&mut stack.joiner_log, &toggle, &mut out)
            .unwrap_err(),
        rounddance_hal_esp::app::AppError::Replay
    );
    assert_eq!(
        stack
            .coord
            .handle_defrsp(&mut stack.coord_log, &defrsp)
            .unwrap_err(),
        rounddance_hal_esp::app::AppError::Replay
    );
    // The lamp stays where the single real toggle left it.
    assert!(stack.joiner.lamp());
}

/// Decision determinism: two fresh runs radiate identical bytes and
/// log identical lines.
#[test]
fn c6_standalone_replays_deterministically() {
    let mut first = FullStack::new();
    first.run();
    let mut second = FullStack::new();
    second.run();
    assert_eq!(first.air, second.air);
    assert_eq!(first.coord_log.lines, second.coord_log.lines);
    assert_eq!(first.joiner_log.lines, second.joiner_log.lines);
}

/// Units outside the proven pair refuse before touching the radio.
#[test]
fn c6_standalone_unknown_unit_refuses_role() {
    assert_eq!(role_from_mac(&[0xa0, 0xf2, 0x62, 0xff, 0xfe, 0x00]), None);
    assert_eq!(role_from_mac(&[0xa0, 0xf2, 0x62, 0xff, 0xfe, 0x86]), None);
    assert_eq!(role_from_mac(&COORD_BASE_MAC), Some(AppRole::Coordinator));
    assert_eq!(role_from_mac(&JOINER_BASE_MAC), Some(AppRole::Joiner));
}

/// Phase 3 leg 1: joiner-side MAC dispatch. A live-shaped beacon
/// (MG21 capture bytes) feeds the survey through `on_mac_psdu` and
/// elects the candidate; the coordinator's long-source assoc-rsp
/// hands off short + status; `take_assoc_req` builds the join
/// request for the elected PAN.
#[test]
fn joiner_on_mac_psdu_scans_and_hands_off_assoc() {
    use rounddance_hal_esp::mac_cmd::Incoming;

    static DEF: rounddance_zcl::onoff::ServerDef = rounddance_zcl::onoff::ServerDef;
    let mut joiner_log = VecLog::default();
    let mut joiner = JoinerApp::new(&DEF).unwrap();
    joiner.begin_scan(&mut joiner_log).unwrap();
    // Live-shaped beacon (our OTA shape, permit open): ch15.
    let mut bc = [0u8; 26];
    bc[..14].copy_from_slice(&[
        0x00, 0x80, 0x5a, 0x01, 0xc6, 0x00, 0x00, 0xff, 0xcf, 0x00, 0x00, 0x00, 0x22, 0x8c,
    ]);
    bc[14..22].copy_from_slice(&EXT_PAN_ID);
    bc[22..25].copy_from_slice(&[0xff, 0xff, 0xff]);
    let inc = joiner.on_mac_psdu(&mut joiner_log, &bc, APP_CHANNEL, -60, 220);
    assert!(matches!(inc, Incoming::Beacon(_)));
    // Collection only: no election until the window closes.
    assert_eq!(joiner.candidate_pan(), None);
    assert!(!joiner_log.has("C6APP SURVEY"));
    // Repeat beacons accumulate without faulting the machine.
    let inc2 = joiner.on_mac_psdu(&mut joiner_log, &bc, APP_CHANNEL, -62, 220);
    assert!(matches!(inc2, Incoming::Beacon(_)));
    // Window closes: best row elected, joiner advances.
    assert_eq!(joiner.finish_scan(&mut joiner_log), Some(APP_PAN));
    assert!(joiner_log.has("C6APP SURVEY"));
    assert_eq!(joiner.state(), JoinerState::AwaitingCandidate);
    assert_eq!(joiner.candidate_pan(), Some(APP_PAN));
    // Rescan-after-election must not fault the machine: a fresh scan
    // re-elects while already AwaitingCandidate; the second
    // on_candidate is correctly suppressed, not a BadState failure.
    // (Must run before assoc_confirm moves the machine on.)
    joiner.begin_scan(&mut joiner_log).unwrap();
    let inc3 = joiner.on_mac_psdu(&mut joiner_log, &bc, APP_CHANNEL, -61, 221);
    assert!(matches!(inc3, Incoming::Beacon(_)));
    assert_eq!(joiner.finish_scan(&mut joiner_log), Some(APP_PAN));
    assert_eq!(joiner.state(), JoinerState::AwaitingCandidate);
    assert_eq!(joiner.candidate_pan(), Some(APP_PAN));
    // Rescan-after-election must not fault the machine: a fresh scan
    // re-elects while already AwaitingCandidate; the second
    // on_candidate is correctly suppressed, not a BadState failure.
    // (Must run before assoc_confirm moves the machine on.)
    joiner.begin_scan(&mut joiner_log).unwrap();
    let inc3 = joiner.on_mac_psdu(&mut joiner_log, &bc, APP_CHANNEL, -61, 221);
    assert!(matches!(inc3, Incoming::Beacon(_)));
    assert_eq!(joiner.finish_scan(&mut joiner_log), Some(APP_PAN));
    assert_eq!(joiner.state(), JoinerState::AwaitingCandidate);
    assert_eq!(joiner.candidate_pan(), Some(APP_PAN));
    // Long-source assoc-rsp assigning 0xC5C1 (MG21's allocation):
    // handoff stores the short and confirms success.
    assert_eq!(joiner.assoc_short(), None);
    let mut rsp = [0u8; 25];
    rsp[..5].copy_from_slice(&[0x63, 0xcc, 0x02, 0x01, 0xc6]);
    rsp[5..13].copy_from_slice(&rounddance_hal_esp::app::JOINER_EUI);
    rsp[13..21].copy_from_slice(&rounddance_hal_esp::app::TC_EUI_WIRE);
    rsp[21..25].copy_from_slice(&[0x02, 0xc1, 0xc5, 0x00]);
    let rlen = 25;
    let inc = joiner.on_mac_psdu(&mut joiner_log, &rsp[..rlen], 25, -60, 200);
    assert!(matches!(inc, Incoming::AssocRsp(_)));
    assert_eq!(joiner.assoc_short(), Some(0xC5C1));
    assert!(joiner_log.has("C6APP ASSOC ok"));
    // Assoc-req targets the elected PAN with our EUI in wire
    // order (LSB-first, as the NCP-verified handshake shape
    // requires), coordinator short.
    let mut out = [0u8; 19];
    let n = joiner.take_assoc_req(&mut out, APP_PAN).unwrap();
    assert_eq!(n, 19);
    assert_eq!(
        &out[..9],
        &[0x23, 0xc8, out[2], 0x01, 0xc6, 0x00, 0x00, 0xff, 0xff]
    );
    let mut wire = rounddance_hal_esp::app::JOINER_EUI;
    wire.reverse();
    assert_eq!(&out[9..17], &wire);
    assert_eq!(&out[17..19], &[0x01, 0x8c]);
}
