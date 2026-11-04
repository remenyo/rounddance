//! Guest full exchange: form → join → toggle over two guest adapters.
//!
//! The same install-code join plus secured ZCL toggle the C6
//! `MockDriver` legs prove, now running entirely inside the guest
//! ABI: [`CoordinatorApp`] and [`JoinerApp`] compose over
//! `EspAdapter<WasmDriver<MockHost>>` with no app changes —
//! mock-to-mock air shuttled host-side through the `MockHost`
//! doubles. This is the S31-coordinator/C6-router/C6-end-device
//! conversation the native runner will host on air.
use rounddance_commission::{BeaconSurveyEntry, InstallCode, JoinerState};
use rounddance_hal_esp::{
    app::{
        CoordinatorApp, JoinerApp, JoinerNwkOutcome, NwkRxOutcome, APP_CHANNEL, APP_PAN,
        COORD_SHORT, JOINER_SHORT,
    },
    driver::RxFrame,
    EspAdapter, SerialLog,
};
use rounddance_hal_wasm::{MockHost, WasmDriver};
use rounddance_mac_sap::{
    FramePayload, MacAddress, MacDataSap, MacMgmtSap, TxOptions, TxRequest, TxStatus,
};
use rounddance_zcl::onoff;

static JOINER_DEF: onoff::ServerDef = onoff::ServerDef;

type GuestAdapter = EspAdapter<WasmDriver<MockHost>>;

#[derive(Default)]
struct VecLog {
    lines: Vec<String>,
}
impl SerialLog for VecLog {
    fn log(&mut self, line: &str) {
        self.lines.push(line.to_string());
    }
}

fn guest(pan: u16, short: u16, ext: u64) -> GuestAdapter {
    let mut a = EspAdapter::new(WasmDriver::new(MockHost::new()));
    a.set_pan_id(pan);
    a.set_short_addr(short);
    a.set_extended_addr(ext);
    a.set_tx_power(10).unwrap();
    a.init().unwrap();
    a
}

/// Shuttle one MSDU guest-adapter → guest-adapter over mock-host air.
fn shuttle(tx: &mut GuestAdapter, rx: &mut GuestAdapter, dst: u16, msdu: &[u8]) -> Vec<u8> {
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
    let d = tx.driver().host().driver();
    let air = d.tx_frame(d.tx_count() - 1).unwrap().to_vec();
    let frame = RxFrame::from_slice(&air, APP_CHANNEL, -40, 200).unwrap();
    rx.driver_mut().host_mut().driver_mut().inject_rx(&[frame]);
    let mut tries = 0;
    loop {
        if let Some(ind) = rx.poll_indication() {
            return ind.msdu.as_slice().to_vec();
        }
        tries += 1;
        assert!(tries < 8, "indication never arrived");
    }
}

/// The guest runs the whole first transaction with no app changes:
///
/// form → permit → admit → install-code join → secured toggle →
/// verified Default Response, lamp off → on.
#[test]
fn guest_runs_join_then_toggle() {
    let mut coord_adapter = guest(APP_PAN, COORD_SHORT, rounddance_hal_esp::app::tc_ieee());
    let mut joiner_adapter = guest(APP_PAN, 0xFFFF, rounddance_hal_esp::app::joiner_ieee());
    let mut coord_log = VecLog::default();
    let mut joiner_log = VecLog::default();
    let mut coord = CoordinatorApp::new();
    let mut joiner = JoinerApp::new(&JOINER_DEF).unwrap();

    coord.begin_formation(&mut coord_log).unwrap();
    coord.formation_done(&mut coord_log, true);
    coord.open_permit(&mut coord_log, 60_000).unwrap();
    coord.admit_joiner(&mut coord_log, 0).unwrap();

    // Install-code join with the real MMO KDF (never a mock).
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
    joiner.close_out(&mut joiner_log);
    assert_eq!(joiner.state(), JoinerState::Joined);
    assert!(!joiner.lamp());

    // Toggle leg over the guest adapters, then the verified answer.
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
    let got = shuttle(
        &mut coord_adapter,
        &mut joiner_adapter,
        JOINER_SHORT,
        &toggle_buf[9..tlen],
    );
    match joiner.on_nwk_joiner(&got) {
        JoinerNwkOutcome::Data { cluster, profile } => {
            assert_eq!((cluster, profile), (0x0006, 0x0104))
        }
        other => panic!("toggle not Data: {other:?}"),
    }
    let mut resp_buf = [0u8; 160];
    let rlen = joiner
        .answer_toggle(&mut joiner_log, &got, &mut resp_buf)
        .unwrap();
    assert!(joiner.lamp(), "toggle flips the lamp off→on");
    let got_back = shuttle(
        &mut joiner_adapter,
        &mut coord_adapter,
        COORD_SHORT,
        &resp_buf[9..rlen],
    );
    match coord.on_nwk_data(&got_back, &keys, 9_000) {
        NwkRxOutcome::Data { cluster, profile } => {
            assert_eq!((cluster, profile), (0x0006, 0x0104))
        }
        other => panic!("defrsp not Data: {other:?}"),
    }
    assert!(coord
        .verify_defrsp(&mut coord_log, &keys, &got_back)
        .unwrap());
    assert_eq!(coord.defrsp_ok, 1);
    assert_eq!(coord.toggles_sent, 1);
    assert_eq!(joiner.defrsp_sent, 1);
}
