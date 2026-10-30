//! Coordinator radiate path: role gate + MAC command routing + assoc answers.
//!
//! Pins the MVP-fix wiring head-side: [`app::role_from_mac`] admits only
//! the real lab pair, [`EspAdapter`] routes MAC-command PSDUs into the
//! MAC queue (no more drops), [`transmit_mac`] wraps Len+2, and
//! [`CoordinatorApp`] answers beacons/assocs through [`CoordAssoc`]
//! with gratuitous pacing. Byte-exact pins reuse the OTA-proven
//! scratch vectors (same source as `mac_assoc.rs`).

use rounddance_hal_esp::adapter::build_data_frame;
use rounddance_hal_esp::app::{
    self, AppRole, CoordinatorApp, COORD_BASE_MAC, JOINER_BASE_MAC, JOINER_EUI, TC_EUI,
};
use rounddance_hal_esp::driver::RxFrame;
use rounddance_hal_esp::mac_cmd::{CoordAssoc, GRATUITOUS_BEACON_INTERVAL_MS, MAC_ASSOC_RSP};
use rounddance_hal_esp::{EspAdapter, MockDriver};
use rounddance_mac_sap::{MacDataSap, MacMgmtSap};

const PAN: u16 = app::APP_PAN;
const COORD: u16 = app::COORD_SHORT;
const EXT_PAN: [u8; 8] = app::EXT_PAN_ID;

fn ota_beacon_req() -> [u8; 8] {
    [0x03, 0x08, 0xaa, 0xff, 0xff, 0xff, 0xff, 0x07]
}

fn ota_assoc_req() -> [u8; 19] {
    let mut b = [0u8; 19];
    b[..9].copy_from_slice(&[0x23, 0xc8, 0xcc, 0x01, 0xc6, 0x00, 0x00, 0xff, 0xff]);
    b[9..17].copy_from_slice(&JOINER_EUI);
    b[17..19].copy_from_slice(&[0x01, 0x8c]);
    b
}

fn len2_frame(psdu: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(1 + psdu.len());
    f.push((psdu.len() + 2) as u8);
    f.extend_from_slice(psdu);
    f
}

fn formed_app() -> CoordinatorApp {
    // Mirrors c6_standalone harness setup (formation, no permit).
    let mut app = CoordinatorApp::new();
    let mut log = app::NullLog;
    app.begin_formation(&mut log).unwrap();
    app.formation_done(&mut log, true);
    app
}

#[test]
fn role_gate_matches_real_lab_units() {
    // Full-MAC gate (MVP fix): 7F68 coordinates, 97A4 joins.
    assert_eq!(
        app::role_from_mac(&COORD_BASE_MAC),
        Some(AppRole::Coordinator)
    );
    assert_eq!(app::role_from_mac(&JOINER_BASE_MAC), Some(AppRole::Joiner));
    // No lab octet slips through: C5, S3, zeros, broadcast.
    for mac in [
        [0x30, 0xed, 0xa0, 0xe4, 0x1a, 0x30],
        [0xcc, 0x8d, 0xa2, 0x29, 0xa4, 0x6c],
        [0x00; 6],
        [0xff; 6],
    ] {
        assert_eq!(app::role_from_mac(&mac), None);
    }
    // EUI expansion rule shared with the OTA units.
    assert_eq!(
        app::eui_from_mac(&COORD_BASE_MAC),
        [0xa0, 0xf2, 0x62, 0xff, 0xfe, 0x86, 0x7f, 0x68]
    );
    // Integer helpers agree with the EUI tables (u64 vs u64).
    assert_eq!(app::tc_ieee(), u64::from_le_bytes(TC_EUI));
    assert_eq!(app::joiner_ieee(), u64::from_le_bytes(JOINER_EUI));
}

#[test]
fn adapter_routes_beacon_req_to_mac_queue() {
    let mut a = EspAdapter::new(MockDriver::new());
    a.set_pan_id(PAN);
    a.set_short_addr(COORD);
    a.init().unwrap();
    let air = ota_beacon_req();
    let wire = len2_frame(&air);
    a.driver_mut()
        .inject_rx(&[RxFrame::from_slice(&wire, 15, -40, 200).unwrap()]);
    assert!(a.poll_indication().is_none());
    let ind = a.poll_mac_indication().expect("beacon-req routes");
    assert_eq!(ind.psdu(), &air);
    assert_eq!(a.rx_dropped(), 0);
}

#[test]
fn adapter_transmit_mac_wraps_len_plus_two() {
    let mut a = EspAdapter::new(MockDriver::new());
    // NotReady before init.
    assert!(a.transmit_mac(&[0x01, 0x02]).is_err());
    a.set_pan_id(PAN);
    a.set_short_addr(COORD);
    a.init().unwrap();
    // Empty PSDU refuses.
    assert!(a.transmit_mac(&[]).is_err());
    // Valid PSDU accepted (single-flight slot).
    assert!(a.transmit_mac(&ota_beacon_req()).is_ok());
    // Shared builder wraps Len+2 exactly.
    let msdu = [0xaa, 0xbb, 0xcc];
    let (frame, len) = build_data_frame(0x5a, PAN, COORD, 0x0001, &msdu, false).expect("fits");
    assert_eq!(len, 10 + msdu.len());
    assert_eq!(frame[0] as usize, 9 + msdu.len() + 2);
    assert_eq!(frame[3], 0x5a);
}

#[test]
fn app_permit_allow_wiring_drives_assoc_answers() {
    let mut app = formed_app();
    let mut log = app::NullLog;
    let assoc = ota_assoc_req();
    let mut out = [0u8; 32];
    // Closed window: no answer.
    app.on_mac_psdu(&assoc);
    assert_eq!(app.take_assoc_rsp(&mut out).unwrap(), 0);
    // Open + admit: exact 19-octet assoc-rsp, command 0x02.
    app.open_permit(&mut log, 600_000).unwrap();
    app.admit_joiner(&mut log, 0).unwrap();
    app.on_mac_psdu(&assoc);
    let n = app.take_assoc_rsp(&mut out).unwrap();
    assert_eq!(n, 19);
    assert_eq!(out[15], MAC_ASSOC_RSP);
    assert_eq!(u16::from_le_bytes([out[16], out[17]]), app::JOINER_SHORT);
    assert_eq!(out[18], 0x00);
    // Foreign EUI: denied (no pending answer latched).
    let mut foreign = assoc;
    foreign[9..17].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]);
    app.on_mac_psdu(&foreign);
    assert_eq!(app.take_assoc_rsp(&mut out).unwrap(), 0);
}

#[test]
fn pacing_gratuitous_due_after_interval_only_when_unassociated() {
    use rounddance_hal_esp::mac_cmd::gratuitous_due;
    let iv = GRATUITOUS_BEACON_INTERVAL_MS;
    assert!(!gratuitous_due(1_000, 1_000 + iv - 1, iv));
    assert!(gratuitous_due(1_000, 1_000 + iv, iv));
    assert!(gratuitous_due(1_000, 1_000 + iv + 1, iv));
    // Wrapping clock: 6001 ms elapsed across u64::MAX.
    assert!(gratuitous_due(u64::MAX - 5000, 1000, iv));
    assert!(!gratuitous_due(u64::MAX - 100, 100, iv));
    // Fresh coordinator is unassociated: gratuitous path is armed.
    let app = formed_app();
    assert!(!app.is_associated());
}

#[test]
fn end_to_end_adapter_app_beacon_answer_radiates() {
    let mut a = EspAdapter::new(MockDriver::new());
    a.set_pan_id(PAN);
    a.set_short_addr(COORD);
    a.init().unwrap();
    let mut app = formed_app();
    let mut log = app::NullLog;
    app.open_permit(&mut log, 600_000).unwrap();
    let air = ota_beacon_req();
    let wire = len2_frame(&air);
    a.driver_mut()
        .inject_rx(&[RxFrame::from_slice(&wire, 15, -40, 200).unwrap()]);
    let ind = a.poll_mac_indication().expect("routes");
    app.on_mac_psdu(ind.psdu());
    let mut out = [0u8; 32];
    let n = app.take_beacon(&mut out).unwrap();
    assert_eq!(n, 26);
    // The 26-octet answer fits the TX path exactly (Len+2 wrap).
    assert!(a.transmit_mac(&out[..n]).is_ok());
}

#[test]
fn coord_assoc_still_gates_permit_allow_deny_directly() {
    use rounddance_hal_esp::mac_cmd::parse_assoc_req;
    let mut assoc = CoordAssoc::new();
    let mut out = [0u8; 32];
    // Idle: nothing radiated.
    assert_eq!(assoc.take_beacon(0x01, &EXT_PAN, &mut out).unwrap(), 0);
    let req = parse_assoc_req(&ota_assoc_req()).expect("parses");
    assert_eq!(req.dst_pan, PAN);
    assert_eq!(req.dst_short, COORD);
    // Permit closed: assoc ignored.
    assert!(!assoc.permit());
    assert!(!assoc.on_assoc_req(&req));
    // Provision identity, open permit, no allow: still denied.
    assoc.provision(PAN, COORD);
    assoc.set_permit(true);
    assert!(!assoc.on_assoc_req(&req));
    assert_eq!(
        assoc.take_assoc_rsp(0x02, 0x0001, 0x00, &mut out).unwrap(),
        0
    );
    // Allow the joiner: exact 19-octet answer, command 0x02.
    assoc.allow(JOINER_EUI).unwrap();
    assert!(assoc.on_assoc_req(&req));
    let n = assoc.take_assoc_rsp(0x02, 0x0001, 0x00, &mut out).unwrap();
    assert_eq!(n, 19);
    assert_eq!(out[15], MAC_ASSOC_RSP);
    // Beacon leg stays independent of assoc state.
    assert_eq!(assoc.take_beacon(0x5a, &EXT_PAN, &mut out).unwrap(), 0);
}

/// Rung-3 air-order regression: the MG24 NCP radiates its EUI LSB-first
/// (`6d 49 11 fe ff 13 8d 34`), the byte-reverse of the NCP-reported
/// display order (`34:8d:13:ff:fe:11:49:6d`). The allow-list must admit
/// either orientation of an explicitly admitted EUI — a byte-exact
/// check deafened the coordinator to all 4 real assoc-reqs.
///
/// Captured verbatim from `~/hwscratch/w89-rung3-admit/` (ch15, 90 s):
/// `23 c8 49 01 c6 00 00 ff ff 6d4911feff138d34 01 8c`.
#[test]
fn admit_extra_answers_air_order_mg24_assoc_req() {
    let mut air = [0u8; 19];
    air[..9].copy_from_slice(&[0x23, 0xc8, 0x49, 0x01, 0xc6, 0x00, 0x00, 0xff, 0xff]);
    air[9..17].copy_from_slice(&[0x6d, 0x49, 0x11, 0xfe, 0xff, 0x13, 0x8d, 0x34]);
    air[17..19].copy_from_slice(&[0x01, 0x8c]);
    let mut app = formed_app();
    let mut log = app::NullLog;
    // Unadmitted: silent, both orientations.
    app.on_mac_psdu(&air);
    let mut out = [0u8; 32];
    assert_eq!(app.take_assoc_rsp(&mut out).unwrap(), 0);
    // Admit by display order, answer the air order.
    app.open_permit(&mut log, 600_000).unwrap();
    app.admit_extra(&mut log, app::MG24_EUI, app::MG24_SHORT)
        .unwrap();
    app.on_mac_psdu(&air);
    let n = app.take_assoc_rsp(&mut out).unwrap();
    assert_eq!(n, 19);
    assert_eq!(out[15], MAC_ASSOC_RSP);
    assert_eq!(u16::from_le_bytes([out[16], out[17]]), app::MG24_SHORT);
    // A never-admitted EUI stays silent in both orientations.
    let mut app2 = formed_app();
    let mut foreign = air;
    foreign[9..17].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    app2.open_permit(&mut log, 600_000).unwrap();
    app2.on_mac_psdu(&foreign);
    assert_eq!(app2.take_assoc_rsp(&mut out).unwrap(), 0);
}
