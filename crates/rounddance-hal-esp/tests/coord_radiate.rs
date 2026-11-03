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
use rounddance_nwk::{FrameControl as NwkFc, FrameType as NwkType, NwkHeader};
use rounddance_security::{
    ccm_star_seal_into, AuxHeader, KeyIdMode, KeyIdentifier, SecurityControl,
};

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
    // Open + admit: exact 25-octet assoc-rsp, command 0x02.
    app.open_permit(&mut log, 600_000).unwrap();
    app.admit_joiner(&mut log, 0).unwrap();
    app.on_mac_psdu(&assoc);
    let n = app.take_assoc_rsp(&mut out).unwrap();
    assert_eq!(n, 25);
    assert_eq!(out[21], MAC_ASSOC_RSP);
    assert_eq!(u16::from_le_bytes([out[22], out[23]]), app::JOINER_SHORT);
    assert_eq!(out[24], 0x00);
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
    assoc.provision(PAN, COORD, &TC_EUI);
    assoc.set_permit(true);
    assert!(!assoc.on_assoc_req(&req));
    assert_eq!(
        assoc.take_assoc_rsp(0x02, 0x0001, 0x00, &mut out).unwrap(),
        0
    );
    // Allow the joiner: exact 25-octet answer, command 0x02.
    assoc.allow(JOINER_EUI).unwrap();
    assert!(assoc.on_assoc_req(&req));
    let n = assoc.take_assoc_rsp(0x02, 0x0001, 0x00, &mut out).unwrap();
    assert_eq!(n, 25);
    assert_eq!(out[21], MAC_ASSOC_RSP);
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
    assert_eq!(n, 25);
    assert_eq!(out[21], MAC_ASSOC_RSP);
    assert_eq!(u16::from_le_bytes([out[22], out[23]]), app::MG24_SHORT);
    // Source is the wire-order coordinator EUI (MG21 parity).
    assert_eq!(&out[13..21], &app::TC_EUI_WIRE);
    // A never-admitted EUI stays silent in both orientations.
    let mut app2 = formed_app();
    let mut foreign = air;
    foreign[9..17].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    app2.open_permit(&mut log, 600_000).unwrap();
    app2.on_mac_psdu(&foreign);
    assert_eq!(app2.take_assoc_rsp(&mut out).unwrap(), 0);
}

/// Short-addressed data-request poll carry (adapter gap): an associated
/// device polls with its assigned short (`FC 63 88`, 10 B, command
/// `0x04`). `classify` must route it (not `Other`, which the adapter
/// drops into `rx_dropped`), and the app must re-arm the pending
/// association answer for the short's EUI — the post-association
/// sibling of the long pre-association poll fetch edge.
#[test]
fn short_poll_rearms_assoc_answer_through_adapter() {
    use rounddance_hal_esp::mac_cmd::{
        build_data_poll_short, classify, parse_data_poll_short, Incoming as MacIncoming,
    };
    // Codec round-trip: FC 63 88 | seq | dst pan | dst short | src short | 0x04.
    let mut air = [0u8; 10];
    assert_eq!(
        build_data_poll_short(0x05, PAN, COORD, app::JOINER_SHORT, &mut air).unwrap(),
        10
    );
    assert_eq!(
        air,
        [0x63, 0x88, 0x05, 0x01, 0xc6, 0x00, 0x00, 0x01, 0x00, 0x04]
    );
    let poll = parse_data_poll_short(&air).expect("short poll parses");
    assert_eq!((poll.seq, poll.src_short), (0x05, app::JOINER_SHORT));
    assert!(matches!(classify(&air), MacIncoming::ShortPoll(_)));
    // Malformed short polls stay out of the MAC queue.
    assert!(parse_data_poll_short(&air[..9]).is_none());
    let mut bad = air;
    bad[9] = 0x09;
    assert!(parse_data_poll_short(&bad).is_none());
    assert!(matches!(classify(&bad), MacIncoming::Other));

    // Adapter carries it to the MAC queue (pre-fix: dropped, rx_dropped 1).
    let mut a = EspAdapter::new(MockDriver::new());
    a.set_pan_id(PAN);
    a.set_short_addr(COORD);
    a.init().unwrap();
    let wire = len2_frame(&air);
    a.driver_mut()
        .inject_rx(&[RxFrame::from_slice(&wire, 15, -40, 200).unwrap()]);
    assert!(a.poll_indication().is_none());
    let ind = a.poll_mac_indication().expect("short poll routes");
    assert_eq!(ind.psdu(), &air);
    assert_eq!(a.rx_dropped(), 0);

    // App re-arms the association answer for the short's EUI.
    let mut app = formed_app();
    let mut log = app::NullLog;
    let mut out = [0u8; 32];
    app.open_permit(&mut log, 600_000).unwrap();
    app.admit_joiner(&mut log, 0).unwrap();
    app.on_mac_psdu(&ota_assoc_req());
    assert_eq!(app.take_assoc_rsp(&mut out).unwrap(), 25);
    assert!(!app.assoc_pending());
    app.on_mac_psdu(&air);
    assert!(app.assoc_pending(), "short poll re-arms");
    let n = app.take_assoc_rsp(&mut out).unwrap();
    assert_eq!(n, 25);
    assert_eq!(u16::from_le_bytes([out[22], out[23]]), app::JOINER_SHORT);
    // Unknown short re-arms nothing.
    app.on_mac_psdu(&ota_assoc_req());
    assert_eq!(app.take_assoc_rsp(&mut out).unwrap(), 25);
    let mut stranger = air;
    stranger[7..9].copy_from_slice(&0x00feu16.to_le_bytes());
    app.on_mac_psdu(&stranger);
    assert!(!app.assoc_pending());
}

/// Addressed-mode contract (w92 rung-3): the coordinator runs with
/// hardware filtering ON (promiscuous OFF) and programmed PAN/short.
/// Broadcast beacon-requests AND unicast association requests must
/// both dispatch to the MAC queue with zero drops — filtering must
/// not cost either RX path. (Promiscuous previously carried both,
/// but suppresses HW auto-ACK, which broke association on air: 8
/// unacked `23 c8` retries, zero ACKs in joinwin6. This test pins the
/// dispatch half; the ACK half is proven on air post-fix.)
#[test]
fn addressed_mode_routes_broadcast_and_unicast() {
    let mut a = EspAdapter::new(MockDriver::new());
    a.set_pan_id(PAN);
    a.set_short_addr(COORD);
    a.init().unwrap();
    // Filtering stays ON: the addressed-mode invariant.
    assert_eq!(a.driver().promiscuous(), Some(false));
    let bcn = ota_beacon_req();
    let asc = ota_assoc_req();
    a.driver_mut().inject_rx(&[
        RxFrame::from_slice(&len2_frame(&bcn), 15, -40, 200).unwrap(),
        RxFrame::from_slice(&len2_frame(&asc), 15, -35, 210).unwrap(),
    ]);
    let first = a.poll_mac_indication().expect("beacon-req routes");
    assert_eq!(first.psdu(), &bcn);
    let second = a.poll_mac_indication().expect("assoc-req routes");
    assert_eq!(second.psdu(), &asc);
    assert_eq!(a.rx_dropped(), 0);
}

/// TX-loss re-arm (w92 f1 class): an acked assoc-req whose built
/// response could not be queued (single-flight busy) must be
/// re-pended, not silently dropped — the joiner's only answer.
#[test]
fn rearm_assoc_repends_after_consumed_take() {
    let mut app = formed_app();
    let mut log = app::NullLog;
    app.open_permit(&mut log, 600_000).unwrap();
    app.admit_joiner(&mut log, 0).unwrap();
    // Nothing latched: re-arm is a no-op.
    app.rearm_assoc();
    assert!(!app.assoc_pending());
    // Admitted assoc latches + pends; take consumes.
    app.on_mac_psdu(&ota_assoc_req());
    assert!(app.assoc_pending());
    let mut out = [0u8; 32];
    assert_eq!(app.take_assoc_rsp(&mut out).unwrap(), 25);
    assert!(!app.assoc_pending());
    // TX loss: re-arm re-pends the same answer.
    app.rearm_assoc();
    assert!(app.assoc_pending());
    let n = app.take_assoc_rsp(&mut out).unwrap();
    assert_eq!(n, 25);
    assert_eq!(out[21], MAC_ASSOC_RSP);
    assert!(!app.assoc_pending());
}

/// Trust-Center key transport (B-006 gate): after an admitted assoc,
/// the app owes the 0x05 transport-key frame; the built PSDU carries
/// the ecosystem layout (MAC `61 88`, unsecured NWK header, APS
/// `0x21`, aux `0x30` + monotonic counter + TC source) and its sealed
/// tail opens with the HA-derived key to the exact 35-octet command
/// (`05 01 <netkey> 00 <joiner> <tc>`).
#[test]
fn transport_key_builds_and_opens_with_ha_key() {
    use rounddance_commission::TRANSPORT_FRAME_LEN;
    use rounddance_nwk::decode as nwk_decode;
    use rounddance_security::{ccm_star_open_into, derive_key_transport_key, CCM_TAG_LEN};

    const TEST_NETKEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    let mut app = formed_app();
    let mut log = app::NullLog;
    assert!(!app.transport_pending());
    app.open_permit(&mut log, 600_000).unwrap();
    app.admit_extra(&mut log, app::MG24_EUI, app::MG24_SHORT)
        .unwrap();
    // MG24 air-order assoc-req latches + pends assoc AND transport.
    let mut air = [0u8; 19];
    air[..9].copy_from_slice(&[0x23, 0xc8, 0x49, 0x01, 0xc6, 0x00, 0x00, 0xff, 0xff]);
    air[9..17].copy_from_slice(&[0x6d, 0x49, 0x11, 0xfe, 0xff, 0x13, 0x8d, 0x34]);
    air[17..19].copy_from_slice(&[0x01, 0x8c]);
    app.on_mac_psdu(&air);
    assert!(app.assoc_pending());
    assert!(app.transport_pending());
    // Build the transport frame (bigger buffer than the 32 B MAC one).
    let tkey = derive_key_transport_key(&rounddance_commission::HA_LINK_KEY).unwrap();
    let mut out = [0u8; 128];
    let n = app
        .take_transport_key(&mut out, &TEST_NETKEY, &tkey)
        .unwrap();
    assert_eq!(n, TRANSPORT_FRAME_LEN);
    assert!(!app.transport_pending());
    let f = &out[..n];
    // MAC data header to the assigned short.
    assert_eq!(
        &f[..9],
        &[0x61, 0x88, f[2], 0x01, 0xc6, 0x02, 0x00, 0x00, 0x00]
    );
    // NWK unsecured data header decodes via the repo codec.
    let dec = nwk_decode(&f[9..]).expect("nwk decodes");
    assert_eq!((dec.header.dst_addr, dec.header.src_addr), (0x0002, 0x0000));
    assert!(!dec.header.control.security);
    // APS command header + on-air aux (level zeroed, key-transport,
    // extended nonce) + TC source.
    let aps = dec.payload;
    assert_eq!(&aps[..2], &[0x21, aps[1]]);
    assert_eq!(aps[2], 0x30);
    assert_eq!(&aps[3..7], &0x00001000u32.to_le_bytes());
    // Aux source rides LSB-first (wire order), like the MG21 reference.
    let mut tc_wire = app::TC_EUI;
    tc_wire.reverse();
    assert_eq!(&aps[7..15], &tc_wire);
    // Sealed tail opens with the HA-derived key to the exact command.
    let ct = &aps[15..];
    assert_eq!(ct.len(), 35 + CCM_TAG_LEN);
    let (ct_body, tag) = ct.split_at(35);
    let mut tag4 = [0u8; 4];
    tag4.copy_from_slice(tag);
    let mut aad = [0u8; 15];
    aad[..2].copy_from_slice(&aps[..2]);
    aad[2] = 0x35;
    aad[3..7].copy_from_slice(&aps[3..7]);
    aad[7..15].copy_from_slice(&aps[7..15]);
    let mut nonce = [0u8; 13];
    nonce[..8].copy_from_slice(&aps[7..15]); // wire-order source, as sealed
    nonce[8..12].copy_from_slice(&aps[3..7]);
    nonce[12] = 0x35;
    let mut pt = [0u8; 35];
    assert_eq!(
        ccm_star_open_into(&tkey, &nonce, &aad, ct_body, &tag4, &mut pt),
        Ok(35)
    );
    let mut expect = [0u8; 35];
    expect[0] = 0x05;
    expect[1] = 0x01;
    expect[2..18].copy_from_slice(&TEST_NETKEY);
    expect[18] = 0x00;
    // EUIs ride LSB-first (wire order): dst as latched from the air,
    // src as the LE bytes of the coordinator EUI (w93 MG21 reference).
    expect[19..27].copy_from_slice(&[0x6du8, 0x49, 0x11, 0xfe, 0xff, 0x13, 0x8d, 0x34]);
    expect[27..35].copy_from_slice(&[0x68u8, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0]);
    assert_eq!(pt, expect);
    // TX loss re-pends (mirror of the assoc re-arm).
    app.rearm_transport();
    assert!(app.transport_pending());
}

/// Short-poll gating (w96 residue): once the transport frame has been
/// built for the latched joiner, stray polls no longer re-pend stale
/// answers; a fresh association re-opens the cycle. Explicit TX-loss
/// re-arm stays unconditional.
#[test]
fn short_poll_gated_after_transport_sent() {
    use rounddance_commission::{ha_transport_key, TRANSPORT_FRAME_LEN};

    const TEST_NETKEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    let tkey = ha_transport_key().unwrap();
    let mut app = formed_app();
    let mut log = app::NullLog;
    app.open_permit(&mut log, 600_000).unwrap();
    app.admit_joiner(&mut log, 0).unwrap();
    app.on_mac_psdu(&ota_assoc_req());
    assert!(app.assoc_pending());
    // Pre-transport polls still re-arm (join flow intact).
    app.on_mac_psdu(&ota_assoc_req());
    let mut out = [0u8; 128];
    assert_eq!(app.take_assoc_rsp(&mut out).unwrap(), 25);
    let air = build_short_poll(app::JOINER_SHORT, 0x05);
    app.on_mac_psdu(&air);
    assert!(app.assoc_pending(), "pre-transport poll re-arms");
    assert_eq!(app.take_assoc_rsp(&mut out).unwrap(), 25);
    // Build the transport: the joiner moved past association.
    let n = app
        .take_transport_key(&mut out, &TEST_NETKEY, &tkey)
        .unwrap();
    assert_eq!(n, TRANSPORT_FRAME_LEN);
    assert!(!app.transport_pending());
    // Stray polls no longer re-pend anything...
    app.on_mac_psdu(&air);
    assert!(!app.assoc_pending());
    assert!(!app.transport_pending());
    // ...but explicit TX-loss re-arm still works...
    app.rearm_assoc();
    assert!(app.assoc_pending());
    app.rearm_transport();
    assert!(app.transport_pending());
    // ...and a fresh association re-opens the whole cycle.
    app.on_mac_psdu(&ota_assoc_req());
    let mut out2 = [0u8; 32];
    assert_eq!(app.take_assoc_rsp(&mut out2).unwrap(), 25);
    let n2 = app
        .take_transport_key(&mut out, &TEST_NETKEY, &tkey)
        .unwrap();
    assert_eq!(n2, TRANSPORT_FRAME_LEN);
}

/// 10-octet short data-request poll via the codec under test.
fn build_short_poll(src_short: u16, seq: u8) -> [u8; 10] {
    use rounddance_hal_esp::mac_cmd::build_data_poll_short;
    let mut b = [0u8; 10];
    build_data_poll_short(seq, PAN, COORD, src_short, &mut b).unwrap();
    b
}

/// Aux (APS security) frame counter riding inside a built
/// transport-key frame: MAC header is 9 B, then the NWK codec splits
/// off the APS payload whose bytes 3..7 are the counter (LE).
fn transport_auxctr_of(frame: &[u8]) -> u32 {
    use rounddance_nwk::decode as nwk_decode;
    let dec = nwk_decode(&frame[9..]).expect("nwk decodes");
    let aps = dec.payload;
    u32::from_le_bytes([aps[3], aps[4], aps[5], aps[6]])
}

const TEST_NETKEY_EDGE: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// `take_transport_key` with nothing pending returns `Ok(0)` and must
/// not touch the aux counter: the counter observed in the frame built
/// after an idle take is exactly one past the previous frame (not two
/// — an idle take consumes no counter value).
#[test]
fn take_transport_key_idle_returns_zero_without_touching_auxctr() {
    use rounddance_commission::{ha_transport_key, TRANSPORT_FRAME_LEN};

    let tkey = ha_transport_key().unwrap();
    let mut app = formed_app();
    let mut log = app::NullLog;
    let mut out = [0u8; 128];
    // Fresh app: nothing pending, idle take is `Ok(0)`.
    assert!(!app.transport_pending());
    assert_eq!(
        app.take_transport_key(&mut out, &TEST_NETKEY_EDGE, &tkey)
            .unwrap(),
        0
    );
    assert!(!app.transport_pending());
    // Latch an association and build frame 1; record its aux counter.
    app.open_permit(&mut log, 600_000).unwrap();
    app.admit_joiner(&mut log, 0).unwrap();
    app.on_mac_psdu(&ota_assoc_req());
    assert!(app.transport_pending());
    let n1 = app
        .take_transport_key(&mut out, &TEST_NETKEY_EDGE, &tkey)
        .unwrap();
    assert_eq!(n1, TRANSPORT_FRAME_LEN);
    let aux1 = transport_auxctr_of(&out[..n1]);
    // Idle take between two builds: still `Ok(0)`, still not pending.
    assert!(!app.transport_pending());
    assert_eq!(
        app.take_transport_key(&mut out, &TEST_NETKEY_EDGE, &tkey)
            .unwrap(),
        0
    );
    assert!(!app.transport_pending());
    // Re-arm + rebuild: exactly one counter step since frame 1, so the
    // idle take consumed nothing.
    app.rearm_transport();
    assert!(app.transport_pending());
    let n2 = app
        .take_transport_key(&mut out, &TEST_NETKEY_EDGE, &tkey)
        .unwrap();
    assert_eq!(n2, TRANSPORT_FRAME_LEN);
    assert_eq!(transport_auxctr_of(&out[..n2]), aux1.wrapping_add(1));
}

/// `rearm_assoc` / `rearm_transport` with nothing latched are pure
/// no-ops: neither pending flag is set by the re-arm itself.
#[test]
fn rearm_with_nothing_latched_is_noop() {
    let mut app = formed_app();
    assert!(!app.is_associated());
    assert!(!app.assoc_pending());
    assert!(!app.transport_pending());
    app.rearm_assoc();
    app.rearm_transport();
    assert!(!app.assoc_pending());
    assert!(!app.transport_pending());
}

/// Transport build failure (undersized buffer) keeps `transport_pending`
/// set so firmware can retry with a bigger buffer; the retry then
/// succeeds and clears the flag.
#[test]
fn transport_build_failure_keeps_pending_for_retry() {
    use rounddance_commission::{ha_transport_key, TRANSPORT_FRAME_LEN};
    use rounddance_hal_esp::mac_cmd::MacCmdError;

    let tkey = ha_transport_key().unwrap();
    let mut app = formed_app();
    let mut log = app::NullLog;
    app.open_permit(&mut log, 600_000).unwrap();
    app.admit_joiner(&mut log, 0).unwrap();
    app.on_mac_psdu(&ota_assoc_req());
    assert!(app.transport_pending());
    // One octet short of the 71-octet frame: build refusal.
    let mut small = [0u8; TRANSPORT_FRAME_LEN - 1];
    assert_eq!(
        app.take_transport_key(&mut small, &TEST_NETKEY_EDGE, &tkey),
        Err(MacCmdError::BufferTooSmall)
    );
    // Still owed: the retry path rebuilds the full frame.
    assert!(app.transport_pending());
    let mut out = [0u8; 128];
    let n = app
        .take_transport_key(&mut out, &TEST_NETKEY_EDGE, &tkey)
        .unwrap();
    assert_eq!(n, TRANSPORT_FRAME_LEN);
    assert!(!app.transport_pending());
}

/// Phase 1 leg 1b (indirect queue): bounded per-short payload store —
/// enqueue/has/take roundtrip, table-full + oversize refusals, take
/// semantics (absent → Ok(0), short buffer keeps the entry),
/// same-short replace without consuming a slot.
#[test]
fn indirect_queue_enqueue_take_table() {
    use rounddance_hal_esp::mac_cmd::MacCmdError;
    let mut app = formed_app();
    assert!(!app.has_indirect(0x0002));
    let mut out = [0u8; 96];
    assert_eq!(app.indirect_take(0x0002, &mut out), Ok(0));
    // Roundtrip.
    app.indirect_enqueue(0x0002, &[0x01, 0x02, 0x03]).unwrap();
    assert!(app.has_indirect(0x0002));
    assert!(!app.has_indirect(0x0003));
    assert_eq!(app.indirect_take(0x0002, &mut out), Ok(3));
    assert_eq!(&out[..3], &[0x01, 0x02, 0x03]);
    assert!(!app.has_indirect(0x0002));
    // Oversize refused.
    let big = [0xAAu8; 97];
    assert_eq!(
        app.indirect_enqueue(0x0002, &big),
        Err(MacCmdError::BufferTooSmall)
    );
    assert!(!app.has_indirect(0x0002));
    // Fill to capacity (4 slots).
    for s in [0x0002u16, 0x0003, 0x0004, 0x0005] {
        app.indirect_enqueue(s, &[0x09]).unwrap();
    }
    assert_eq!(
        app.indirect_enqueue(0x0006, &[0x09]),
        Err(MacCmdError::TableFull)
    );
    // Same-short replace: no new slot, payload updated.
    app.indirect_enqueue(0x0002, &[0x07, 0x08]).unwrap();
    assert_eq!(app.indirect_take(0x0002, &mut out), Ok(2));
    assert_eq!(&out[..2], &[0x07, 0x08]);
    // Short take buffer: refusal, entry retained.
    let mut tiny = [0u8; 1];
    app.indirect_enqueue(0x0002, &[0x0A, 0x0B]).unwrap();
    assert_eq!(
        app.indirect_take(0x0002, &mut tiny),
        Err(MacCmdError::BufferTooSmall)
    );
    assert!(app.has_indirect(0x0002));
    assert_eq!(app.indirect_take(0x0002, &mut out), Ok(2));
}

/// Phase 1 RX leg: secured NWK RX open + Device_annce handling.
/// Synthetic frames (synthetic key, repo codecs): the live annce
/// class (APS broadcast + ep 0x00, refused by `decode_data`) must
/// still classify as Annce; a secured unicast NWK command reports
/// its id; tamper/replay/truncation are counted Ignored, never
/// silent.
const KEY: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const EUI: [u8; 8] = [0x6d, 0x49, 0x11, 0xfe, 0xff, 0x13, 0x8d, 0x34];
const TC: [u8; 8] = [0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0];

#[allow(clippy::too_many_arguments)]
fn sealed_nwk(
    pt: &[u8],
    ftype: NwkType,
    dst: u16,
    src: u16,
    dst_ieee: Option<u64>,
    src_ieee: Option<u64>,
    seq: u8,
    auxctr: u32,
    key: &[u8; 16],
    src_eui: [u8; 8],
) -> Vec<u8> {
    let ctl = NwkFc {
        frame_type: ftype,
        protocol_version: 0x02,
        discover_route: rounddance_nwk::DiscoverRoute::Suppress,
        multicast: false,
        security: true,
        source_route: false,
        dst_ieee: dst_ieee.is_some(),
        src_ieee: src_ieee.is_some(),
        end_device_initiator: false,
    };
    let hdr = NwkHeader {
        control: ctl,
        dst_addr: dst,
        src_addr: src,
        radius: 0x1e,
        seq,
        dst_ieee,
        src_ieee,
        source_route: None,
    };
    let mut hdr_buf = [0u8; 32];
    let hlen = hdr.encode_into(&[], &mut hdr_buf).unwrap();
    let aux = AuxHeader {
        control: SecurityControl::new(0, KeyIdMode::Index, true).unwrap(),
        frame_counter: auxctr,
        ext_source: Some(src_eui),
        key_id: KeyIdentifier::Index(0),
    };
    let mut aux_buf = [0u8; 14];
    let alen = aux.encode_into(&mut aux_buf).unwrap();
    assert_eq!(alen, 14);
    let restored = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::Index, true).unwrap(),
        frame_counter: auxctr,
        ext_source: Some(src_eui),
        key_id: KeyIdentifier::Index(0),
    };
    let mut rbuf = [0u8; 14];
    let rlen = restored.encode_into(&mut rbuf).unwrap();
    let mut aad = [0u8; 48];
    aad[..hlen].copy_from_slice(&hdr_buf[..hlen]);
    aad[hlen..hlen + rlen].copy_from_slice(&rbuf[..rlen]);
    let aad = &aad[..hlen + rlen];
    let mut nonce = [0u8; 13];
    nonce[..8].copy_from_slice(&src_eui);
    nonce[8..12].copy_from_slice(&auxctr.to_le_bytes());
    nonce[12] = 0x2d;
    let mut tail = [0u8; 128];
    let tlen = ccm_star_seal_into(key, &nonce, aad, pt, &mut tail).unwrap();
    let mut frame = Vec::with_capacity(hlen + alen + tlen);
    frame.extend_from_slice(&hdr_buf[..hlen]);
    frame.extend_from_slice(&aux_buf[..alen]);
    frame.extend_from_slice(&tail[..tlen]);
    frame
}

/// Open a joiner-received NWK-secured tail with the adopted key:
/// returns (aux counter, plaintext). Mirrors the app's
/// `open_network_data` construction (nonce/AAD per the w45 battery).
fn open_joiner_tail(
    key: &[u8; 16],
    ct: &[u8],
    tag: &[u8],
    nwk_hdr: &[u8],
    src_eui: &[u8; 8],
    auxctr: u32,
) -> (u32, Vec<u8>) {
    use rounddance_security::{ccm_star_open_into, CCM_TAG_LEN};
    assert_eq!(tag.len(), CCM_TAG_LEN);
    let mut tag4 = [0u8; CCM_TAG_LEN];
    tag4.copy_from_slice(tag);
    let mut aad = [0u8; 64];
    let mut restored = [0u8; 16];
    restored[0] = 0x2d;
    restored[1..5].copy_from_slice(&auxctr.to_le_bytes());
    restored[5..13].copy_from_slice(src_eui);
    restored[13] = 0x00;
    aad[..nwk_hdr.len()].copy_from_slice(nwk_hdr);
    aad[nwk_hdr.len()..nwk_hdr.len() + 14].copy_from_slice(&restored[..14]);
    let mut nonce = [0u8; 13];
    nonce[..8].copy_from_slice(src_eui);
    nonce[8..12].copy_from_slice(&auxctr.to_le_bytes());
    nonce[12] = 0x2d;
    let mut pt = vec![0u8; ct.len()];
    let n = ccm_star_open_into(key, &nonce, &aad[..nwk_hdr.len() + 14], ct, &tag4, &mut pt)
        .expect("test tail opens");
    pt.truncate(n);
    (auxctr, pt)
}

#[test]
fn nwk_rx_opens_secured_and_handles_annce() {
    use rounddance_security::{KeySet, NetworkKey};

    // Live annce class: APS broadcast + ep 0x00 + 0x0013/0x0000.
    let mut aps = vec![
        0x08, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0xec, 0x81, 0x02, 0x00,
    ];
    aps.extend_from_slice(&EUI);
    aps.push(0x8c);
    let frame = sealed_nwk(
        &aps,
        NwkType::Data,
        0xfffd,
        0x0002,
        None,
        Some(u64::from_le_bytes(EUI)),
        0xf7,
        0,
        &KEY,
        EUI,
    );
    let keys = KeySet::new(NetworkKey::new(KEY, 0));
    let mut app = formed_app();
    // Admit first: the annce confirm path marks a known child.
    let mut log = app::NullLog;
    app.open_permit(&mut log, 600_000).unwrap();
    app.admit_extra(&mut log, EUI, 0x0002).unwrap();
    let before = app.nwk_rx_classified;
    let out = app.on_nwk_data(&frame, &keys, 1_000);
    match out {
        app::NwkRxOutcome::Annce {
            short,
            eui,
            capability,
        } => {
            assert_eq!(short, 0x0002);
            assert_eq!(eui, EUI);
            assert_eq!(capability, 0x8c);
        }
        other => panic!("expected Annce, got {:?}", other),
    }
    assert_eq!(app.nwk_rx_classified, before + 1);
    // Secured unicast NWK command (live 0x0B class): id reported.
    let cmd = sealed_nwk(
        &[0x0b, 0x08, 0x00],
        NwkType::Command,
        0x0000,
        0x0002,
        Some(u64::from_le_bytes(TC)),
        Some(u64::from_le_bytes(EUI)),
        0xf8,
        1,
        &KEY,
        EUI,
    );
    match app.on_nwk_data(&cmd, &keys, 1_000) {
        app::NwkRxOutcome::NwkCommand { id } => assert_eq!(id, 0x0b),
        other => panic!("expected NwkCommand, got {:?}", other),
    }
    // Tampered tail: MIC failure, counted, never silent.
    let mut bad = cmd.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    let ignored_before = app.nwk_rx_ignored;
    assert!(matches!(
        app.on_nwk_data(&bad, &keys, 1_000),
        app::NwkRxOutcome::Ignored(_)
    ));
    assert_eq!(app.nwk_rx_ignored, ignored_before + 1);
    // Replay: the annce frame again is stale now.
    assert!(matches!(
        app.on_nwk_data(&frame, &keys, 2_000),
        app::NwkRxOutcome::Ignored(_)
    ));
    // Truncated + unsecured command (no key needed for the id;
    // FCF 0x0009: command, no security, no extended addresses).
    assert!(matches!(
        app.on_nwk_data(&[0x08, 0x12], &keys, 3_000),
        app::NwkRxOutcome::Ignored(_)
    ));
    let open_cmd = vec![
        0x09, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xf8, 0x02, 0xaa, 0xbb,
    ];
    match app.on_nwk_data(&open_cmd, &keys, 3_000) {
        app::NwkRxOutcome::NwkCommand { id } => assert_eq!(id, 0x02),
        other => panic!("expected open NwkCommand, got {:?}", other),
    }
}

/// Phase 1 response leg: coordinator-initiated Node_desc_req.
/// Sealed NWK-data + open APS unicast (ep 0, 0x0002/0x0000) + ZDO
/// request; the built frame decrypts to the exact APS/ZDO plaintext
/// and our own RX path classifies it as Data{0x0002, 0}.
#[test]
fn node_desc_req_builds_sealed_and_classifies() {
    use rounddance_hal_esp::app::NwkRxOutcome;
    use rounddance_security::{ccm_star_open_into, KeySet, NetworkKey};

    const KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const TCW: [u8; 8] = [0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
    let mut app = formed_app();
    let mut out = [0u8; 160];
    let n = app.take_node_desc_req(&mut out, 0x0002, &KEY).unwrap();
    assert!(n <= out.len() && n > 30);
    let f = &out[..n];
    // MAC data header to the joined short.
    assert_eq!(
        &f[..9],
        &[0x61, 0x88, f[2], 0x01, 0xc6, 0x02, 0x00, 0x00, 0x00]
    );
    // NWK secured data header, no extended addresses:
    // FCF 08 02, dst 02 00, src 00 00, radius 1e, seq (fresh app: 00).
    assert_eq!(&f[9..15], &[0x08, 0x02, 0x02, 0x00, 0x00, 0x00]);
    assert_eq!(f[15], 0x1e);
    assert_eq!(f[16], 0x00);
    // Aux: on-air level zero, Index key, extended nonce (our source).
    assert_eq!(f[17], 0x28);
    assert_eq!(&f[22..30], &TCW);
    assert_eq!(f[30], 0x00);
    // Decrypt the tail with the key: APS unicast ep 0 + ZDO request.
    let ct_end = n - 4;
    let mut tag = [0u8; 4];
    tag.copy_from_slice(&f[ct_end..n]);
    let mut raux = [0u8; 14];
    raux[0] = 0x2d;
    raux[1..5].copy_from_slice(&f[18..22]);
    raux[5..13].copy_from_slice(&TCW);
    raux[13] = 0x00;
    let mut aad = [0u8; 22];
    aad[..8].copy_from_slice(&f[9..17]);
    aad[8..22].copy_from_slice(&raux);
    let mut nonce = [0u8; 13];
    nonce[..8].copy_from_slice(&TCW);
    nonce[8..12].copy_from_slice(&f[18..22]);
    nonce[12] = 0x2d;
    let mut pt = [0u8; 96];
    let m = ccm_star_open_into(&KEY, &nonce, &aad, &f[31..ct_end], &tag, &mut pt).unwrap();
    let pt = &pt[..m];
    assert_eq!(&pt[..2], &[0x00, 0x00]);
    assert_eq!(u16::from_le_bytes([pt[2], pt[3]]), 0x0002);
    assert_eq!(u16::from_le_bytes([pt[4], pt[5]]), 0x0000);
    assert_eq!(pt[6], 0x00);
    // ZDO Node_desc_req: TSN + short of interest.
    assert_eq!(pt[8..11], [pt[7], 0x02, 0x00]);
    // Loopback: our own RX path classifies the request shape
    // (MAC header stripped, as the driver/adapter path delivers).
    let keys = KeySet::new(NetworkKey::new(KEY, 0));
    let mut app2 = formed_app();
    match app2.on_nwk_data(&f[9..], &keys, 5_000) {
        NwkRxOutcome::Data { cluster, profile } => {
            assert_eq!((cluster, profile), (0x0002, 0x0000));
        }
        other => panic!("expected Data, got {:?}", other),
    }
    // Short buffer refused.
    let mut tiny = [0u8; 16];
    assert!(app.take_node_desc_req(&mut tiny, 0x0002, &KEY).is_err());
}

/// Phase 1 response matching: a ZDO response whose cluster + TSN
/// close an open transaction classifies as ZdoResponse (pending
/// entry consumed); stray TSNs stay Data with the entry retained;
/// an empty response payload is counted Ignored; the 9th open
/// transaction is refused.
#[test]
fn zdo_response_matches_open_transaction() {
    use rounddance_hal_esp::app::NwkRxOutcome;
    use rounddance_security::{KeySet, NetworkKey};

    const KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const EUI: [u8; 8] = [0x6d, 0x49, 0x11, 0xfe, 0xff, 0x13, 0x8d, 0x34];
    const TC: [u8; 8] = [0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
    let keys = KeySet::new(NetworkKey::new(KEY, 0));
    let mut app = formed_app();
    assert_eq!(app.zdo_pending_open(), 0);
    // Open one transaction: fresh app hands out TSN 0.
    let mut out = [0u8; 160];
    app.take_node_desc_req(&mut out, 0x0002, &KEY).unwrap();
    assert_eq!(app.zdo_pending_open(), 1);
    // Synthetic Node_desc_rsp (cluster 0x8002, TSN 0, status + body).
    let mut zdo = vec![0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
    let mut aps = vec![0x00, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00, 0x09];
    aps.append(&mut zdo);
    let rsp = sealed_nwk(
        &aps,
        NwkType::Data,
        0x0000,
        0x0002,
        Some(u64::from_le_bytes(TC)),
        Some(u64::from_le_bytes(EUI)),
        0x42,
        7,
        &KEY,
        EUI,
    );
    match app.on_nwk_data(&rsp, &keys, 9_000) {
        NwkRxOutcome::ZdoResponse {
            cluster,
            tsn,
            status,
            req_cluster,
        } => {
            assert_eq!(cluster, 0x8002);
            assert_eq!(tsn, 0x00);
            assert_eq!(status, Some(0x00));
            assert_eq!(req_cluster, 0x0002);
        }
        other => panic!("expected ZdoResponse, got {:?}", other),
    }
    assert_eq!(app.zdo_pending_open(), 0);
    // Stray TSN: no open entry → counted Data, nothing consumed.
    let aps2 = vec![0x00, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00, 0x09, 0x07, 0x00];
    let stray = sealed_nwk(
        &aps2,
        NwkType::Data,
        0x0000,
        0x0002,
        Some(u64::from_le_bytes(TC)),
        Some(u64::from_le_bytes(EUI)),
        0x43,
        8,
        &KEY,
        EUI,
    );
    let before = app.nwk_rx_classified;
    match app.on_nwk_data(&stray, &keys, 9_001) {
        NwkRxOutcome::Data { cluster, profile } => {
            assert_eq!((cluster, profile), (0x8002, 0x0000));
        }
        other => panic!("expected Data, got {:?}", other),
    }
    assert_eq!(app.nwk_rx_classified, before + 1);
    // Empty response payload: counted Ignored.
    let aps3 = vec![0x00, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00, 0x09];
    let empty = sealed_nwk(
        &aps3,
        NwkType::Data,
        0x0000,
        0x0002,
        Some(u64::from_le_bytes(TC)),
        Some(u64::from_le_bytes(EUI)),
        0x44,
        9,
        &KEY,
        EUI,
    );
    assert!(matches!(
        app.on_nwk_data(&empty, &keys, 9_002),
        NwkRxOutcome::Ignored(_)
    ));
    // Table fills at 8 opens; the 9th take is refused outright.
    let mut app2 = formed_app();
    for _ in 0..8 {
        app2.take_node_desc_req(&mut out, 0x0002, &KEY).unwrap();
    }
    assert_eq!(app2.zdo_pending_open(), 8);
    assert!(app2.take_node_desc_req(&mut out, 0x0002, &KEY).is_err());
}

/// b007 regression: a factory-reset NCP restarts its NWK aux counter
/// at 0 on rejoin; delivering a fresh transport key must reset that
/// source's replay state, or its post-join frames misclassify as
/// replays for the rest of the boot.
#[test]
fn transport_key_resets_replay_for_rejoin() {
    use rounddance_commission::ha_transport_key;
    use rounddance_hal_esp::app::NwkRxOutcome;
    use rounddance_security::{KeySet, NetworkKey};

    const KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const EUI: [u8; 8] = [0x6d, 0x49, 0x11, 0xfe, 0xff, 0x13, 0x8d, 0x34];
    let keys = KeySet::new(NetworkKey::new(KEY, 0));
    let tkey = ha_transport_key().unwrap();
    let mut app = formed_app();
    let mut log = app::NullLog;
    app.open_permit(&mut log, 600_000).unwrap();
    app.admit_extra(&mut log, EUI, 0x0002).unwrap();
    // Air-order assoc-req for EUI (19 B MAC command shape).
    let mut req = [0u8; 19];
    req[..9].copy_from_slice(&[0x23, 0xc8, 0x49, 0x01, 0xc6, 0x00, 0x00, 0xff, 0xff]);
    req[9..17].copy_from_slice(&EUI);
    req[17..19].copy_from_slice(&[0x01, 0x8c]);
    let join_once = |app: &mut app::CoordinatorApp, out: &mut [u8]| {
        app.on_mac_psdu(&req);
        assert!(app.assoc_pending());
        assert_eq!(app.take_assoc_rsp(out).unwrap(), 25);
        let n = app.take_transport_key(out, &KEY, &tkey).unwrap();
        assert_eq!(n, 71);
    };
    let mut out = [0u8; 128];
    join_once(&mut app, &mut out);
    // Live annce shape (auxctr 0), sealed.
    let mut aps = vec![
        0x08, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0xec, 0x81, 0x02, 0x00,
    ];
    aps.extend_from_slice(&EUI);
    aps.push(0x8c);
    let frame = sealed_nwk(
        &aps,
        NwkType::Data,
        0xfffd,
        0x0002,
        None,
        Some(u64::from_le_bytes(EUI)),
        0xf7,
        0,
        &KEY,
        EUI,
    );
    match app.on_nwk_data(&frame, &keys, 1_000) {
        NwkRxOutcome::Annce { short: 0x0002, .. } => {}
        other => panic!("expected Annce, got {:?}", other),
    }
    // Same frame again: replay, entry retained.
    assert!(matches!(
        app.on_nwk_data(&frame, &keys, 2_000),
        NwkRxOutcome::Ignored(_)
    ));
    // Rejoin after factory reset (same EUI, counter restarted):
    // fresh transport resets the source's replay state.
    join_once(&mut app, &mut out);
    match app.on_nwk_data(&frame, &keys, 3_000) {
        NwkRxOutcome::Annce { short: 0x0002, .. } => {}
        other => panic!("expected Annce after rejoin, got {:?}", other),
    }
}

/// Phase 3 leg 2: joiner transport open + annce + node_desc answer.
/// Byte-exact transport frames come from the committed builder; the
/// joiner adopts the key, answers its own annce, and replies to a
/// secured Node_desc_req. Tamper/replay/wrong-state are counted,
/// and a duplicate delivery is idempotent (never a wedge).
#[test]
fn joiner_transport_open_adopts_key_and_answers() {
    use rounddance_commission::{
        build_secured_nwk_frame, build_transport_key_frame, ha_transport_key, SecuredNwkParams,
        TransportKeyParams,
    };
    use rounddance_hal_esp::app::{JoinerNwkOutcome, NwkIgnore};

    const KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const TCW: [u8; 8] = [0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
    // Joiner's own wire-order EUI (the transport destination must name us).
    const JW: [u8; 8] = [0xa4, 0x97, 0x85, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
    static DEF: rounddance_zcl::onoff::ServerDef = rounddance_zcl::onoff::ServerDef;
    let mut log = app::NullLog;
    let mut joiner = app::JoinerApp::new(&DEF).unwrap();
    joiner.begin_scan(&mut log).unwrap();
    joiner
        .ingest_beacon(rounddance_commission::BeaconSurveyEntry {
            pan_id: 0xC601,
            channel: 15,
            lqi: 200,
            rssi: -40,
            permit_joining: true,
            router_capacity: true,
            end_device_capacity: true,
            protocol_version: 2,
        })
        .unwrap();
    // Doubled: N-sighting gate needs >=2 rows (Phase 4 election
    // hardening).
    joiner
        .ingest_beacon(rounddance_commission::BeaconSurveyEntry {
            pan_id: 0xC601,
            channel: 15,
            lqi: 200,
            rssi: -40,
            permit_joining: true,
            router_capacity: true,
            end_device_capacity: true,
            protocol_version: 2,
        })
        .unwrap();
    assert_eq!(joiner.finish_scan(&mut log), Some(0xC601));
    // Assoc-rsp handoff assigns the short (long-source, status 0).
    let mut rsp = [0u8; 25];
    rsp[..5].copy_from_slice(&[0x63, 0xcc, 0x02, 0x01, 0xc6]);
    rsp[5..13].copy_from_slice(&JW);
    rsp[13..21].copy_from_slice(&TCW);
    rsp[21..25].copy_from_slice(&[0x02, 0x02, 0x00, 0x00]);
    let inc = joiner.on_mac_psdu(&mut log, &rsp, 15, -40, 200);
    assert!(matches!(
        inc,
        rounddance_hal_esp::mac_cmd::Incoming::AssocRsp(_)
    ));
    assert_eq!(joiner.assoc_short(), Some(0x0002));
    let tkey = ha_transport_key().unwrap();
    // Byte-exact proactive transport-key delivery for our EUI.
    let tp = TransportKeyParams {
        dst_pan: 0xC601,
        dst_short: 0x0002,
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
    // MAC header stripped, as the driver/adapter path delivers.
    let tf = &tf[9..tn];
    // Wrong state first (fresh joiner, pre-assoc): counted, no latch.
    let mut fresh = app::JoinerApp::new(&DEF).unwrap();
    assert!(matches!(
        fresh.on_nwk_joiner(tf),
        JoinerNwkOutcome::Ignored(NwkIgnore::WrongState)
    ));
    assert_eq!(fresh.adopted_netkey(), None);
    // The real open: adopts + advances to KeyWait.
    match joiner.on_nwk_joiner(tf) {
        JoinerNwkOutcome::TransportAccepted { auxctr } => assert_eq!(auxctr, 0x0000_1000),
        other => panic!("expected TransportAccepted, got {:?}", other),
    }
    assert_eq!(joiner.adopted_netkey(), Some((KEY, 0x00)));
    // Duplicate delivery (coordinator retransmit): idempotent.
    match joiner.on_nwk_joiner(tf) {
        JoinerNwkOutcome::TransportAccepted { auxctr } => assert_eq!(auxctr, 0x0000_1000),
        other => panic!("expected idempotent accept, got {:?}", other),
    }
    // Tampered tail: MIC failure, key untouched.
    let mut bad = tf.to_vec();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert!(matches!(
        joiner.on_nwk_joiner(&bad),
        JoinerNwkOutcome::Ignored(NwkIgnore::MicFailed)
    ));
    // Annce: NWK-secured broadcast carrying our Device_annce.
    // MAC 41 88 broadcast; NWK dst 0xFFFD src = assigned short.
    let mut out = [0u8; 160];
    let n = joiner.take_annce(&mut out).unwrap();
    let f = &out[..n];
    assert_eq!(&f[..3], &[0x41, 0x88, f[2]]);
    assert_eq!(&f[3..9], &[0x01, 0xc6, 0xff, 0xff, 0x02, 0x00]);
    assert_eq!(&f[9..11], &[0x08, 0x02]);
    assert_eq!(&f[11..13], &[0xfd, 0xff]);
    assert_eq!(&f[13..15], &[0x02, 0x00]);
    assert_eq!(f[15], 0x1e);
    assert_eq!(f[17], 0x28);
    assert_eq!(&f[18..22], &0x0000_2000u32.to_le_bytes());
    assert_eq!(&f[22..30], &JW);
    assert_eq!(f[30], 0x00);
    // Decrypt the tail: APS broadcast ep 0 + ZDO Device_annce.
    let (actr, apt) = open_joiner_tail(
        &KEY,
        &f[31..n - 4],
        &f[n - 4..n],
        &f[9..17],
        &JW,
        0x0000_2000,
    );
    assert_eq!(
        &apt[..8],
        &[0x08, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, apt[7]]
    );
    assert_eq!(&apt[8..11], &[apt[7], 0x02, 0x00]);
    assert_eq!(&apt[11..19], &JW);
    assert_eq!(apt[19], 0x8c);
    assert_eq!(actr, 0x0000_2000);
    // Secured Node_desc_req to us (unicast, ep 0, cluster 0x0002).
    let mut rq = [0u8; 8 + 3];
    rq[..8].copy_from_slice(&[0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07]);
    rq[8..11].copy_from_slice(&[0x09, 0x02, 0x00]);
    let rp = SecuredNwkParams {
        dst_pan: 0xC601,
        dst_short: 0x0002,
        src_short: 0x0000,
        broadcast: false,
        src_eui: TCW,
        mac_seq: 0x11,
        nwk_seq: 0x22,
        nwk_radius: 0x1e,
        auxctr: 0x0000_2000,
        netkey: KEY,
    };
    let mut rf = [0u8; 160];
    let rn = build_secured_nwk_frame(&rq, &rp, &mut rf).unwrap();
    // No adopted key yet: secured frame refused, no latch.
    let mut joiner2 = app::JoinerApp::new(&DEF).unwrap();
    joiner2.begin_scan(&mut log).unwrap();
    let _ = joiner2.finish_scan(&mut log);
    assert!(matches!(
        joiner2.on_nwk_joiner(&rf[9..rn]),
        JoinerNwkOutcome::Ignored(NwkIgnore::UnknownKey)
    ));
    match joiner.on_nwk_joiner(&rf[9..rn]) {
        JoinerNwkOutcome::NodeDescReq {
            src_short,
            tsn,
            subject,
        } => {
            assert_eq!((src_short, tsn, subject), (0x0000, 0x09, 0x0002));
        }
        other => panic!("expected NodeDescReq, got {:?}", other),
    }
    // The answer decrypts to a Node_desc_rsp echoing TSN + subject.
    let mut ro = [0u8; 160];
    let ro_n = joiner
        .take_node_desc_rsp(&mut ro, 0x0000, 0x09, 0x0002)
        .unwrap();
    let rof = &ro[..ro_n];
    assert_eq!(
        &rof[..9],
        &[0x61, 0x88, rof[2], 0x01, 0xc6, 0x00, 0x00, 0x02, 0x00]
    );
    assert_eq!(&rof[9..11], &[0x08, 0x02]);
    assert_eq!(&rof[11..13], &[0x00, 0x00]);
    assert_eq!(&rof[13..15], &[0x02, 0x00]);
    assert_eq!(rof[15], 0x1e);
    // auxctr advanced past the annce (0x2000 -> 0x2001), src is us.
    assert_eq!(rof[17], 0x28);
    assert_eq!(&rof[18..22], &0x0000_2001u32.to_le_bytes());
    assert_eq!(&rof[22..30], &JW);
    assert_eq!(rof[30], 0x00);
    // Decrypt: APS unicast ep 0, cluster 0x8002, ZDO Node_desc_rsp.
    let (ractr, rpt) = open_joiner_tail(
        &KEY,
        &rof[31..ro_n - 4],
        &rof[ro_n - 4..ro_n],
        &rof[9..17],
        &JW,
        0x0000_2001,
    );
    assert_eq!(ractr, 0x0000_2001);
    assert_eq!(
        &rpt[..8],
        &[0x00, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00, rpt[7]]
    );
    let rsp = rounddance_zdo::zdp::NodeDescRsp::decode(&rpt[8..]).expect("rsp decodes");
    assert_eq!(rsp.tsn, 0x09);
    assert!(rsp.status.is_success());
    assert_eq!(rsp.nwk_of_interest, 0x0002);
    assert!(rsp.descriptor.is_some());
}

/// Phase 5 MG21-as-joiner: the MG21 stick (EUI
/// `04:e3:e5:ff:fe:f4:75:5f`, live-probed) radiates its EUI LSB-first
/// like every Ember NCP, so admission must accept the air order and
/// answer short 0x0003. Unadmitted until the fw allow-list names it.
#[test]
fn admit_extra_answers_mg21_as_joiner() {
    let mut air = [0u8; 19];
    air[..9].copy_from_slice(&[0x23, 0xc8, 0x4a, 0x01, 0xc6, 0x00, 0x00, 0xff, 0xff]);
    // True LSB-first air order: the FULL byte-reverse of display
    // order (middle `ff:fe` becomes `fe:ff` on air, as rung-3 proved
    // for the MG24: `6d:49:11:fe:ff:13:8d:34`).
    air[9..17].copy_from_slice(&[0x5f, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04]);
    air[17..19].copy_from_slice(&[0x01, 0x8c]);
    let mut app = formed_app();
    let mut log = app::NullLog;
    // Unadmitted: silent.
    app.on_mac_psdu(&air);
    let mut out = [0u8; 32];
    assert_eq!(app.take_assoc_rsp(&mut out).unwrap(), 0);
    // Admit by display order, answer the air order with 0x0003.
    app.open_permit(&mut log, 600_000).unwrap();
    app.admit_extra(&mut log, app::MG21_EUI, app::MG21_SHORT)
        .unwrap();
    app.on_mac_psdu(&air);
    let n = app.take_assoc_rsp(&mut out).unwrap();
    assert_eq!(n, 25);
    assert_eq!(out[21], MAC_ASSOC_RSP);
    assert_eq!(u16::from_le_bytes([out[22], out[23]]), app::MG21_SHORT);
    assert_eq!(&out[13..21], &app::TC_EUI_WIRE);
}

/// Phase 4 node_desc retry contract: consecutive takes (as the
/// confirm-driven retry emits) open DISTINCT matchable transactions —
/// a response to any one closes only its own entry, and the others
/// stay open for their own answers. (The retry loop itself lives in
/// fw, unharnessed; this pins the app behavior it depends on.)
#[test]
fn node_desc_retries_open_independently_matchable_transactions() {
    use rounddance_hal_esp::app::NwkRxOutcome;
    use rounddance_security::{KeySet, NetworkKey};

    const KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    let keys = KeySet::new(NetworkKey::new(KEY, 0));
    let mut app = formed_app();
    let mut out = [0u8; 160];
    // Two takes (initial + one retry): distinct TSNs, two entries.
    app.take_node_desc_req(&mut out, 0x0002, &KEY).unwrap();
    app.take_node_desc_req(&mut out, 0x0002, &KEY).unwrap();
    assert_eq!(app.zdo_pending_open(), 2);
    // A response echoing the FIRST tsn closes only it.
    let mut zdo = vec![0x00, 0x00];
    let mut aps = vec![0x00, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00, 0x09];
    aps.append(&mut zdo);
    let rsp = sealed_nwk(
        &aps,
        NwkType::Data,
        0x0000,
        0x0002,
        None,
        None,
        0x42,
        7,
        &KEY,
        [0u8; 8],
    );
    match app.on_nwk_data(&rsp, &keys, 9_000) {
        NwkRxOutcome::ZdoResponse { tsn, .. } => assert_eq!(tsn, 0x00),
        other => panic!("expected ZdoResponse, got {:?}", other),
    }
    assert_eq!(app.zdo_pending_open(), 1);
    // The SECOND tsn still matches afterwards.
    let mut zdo2 = vec![0x01, 0x00];
    let mut aps2 = vec![0x00, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00, 0x09];
    aps2.append(&mut zdo2);
    let rsp2 = sealed_nwk(
        &aps2,
        NwkType::Data,
        0x0000,
        0x0002,
        None,
        None,
        0x43,
        8,
        &KEY,
        [0u8; 8],
    );
    match app.on_nwk_data(&rsp2, &keys, 9_001) {
        NwkRxOutcome::ZdoResponse { tsn, .. } => assert_eq!(tsn, 0x01),
        other => panic!("expected ZdoResponse, got {:?}", other),
    }
    assert_eq!(app.zdo_pending_open(), 0);
}

/// Phase 4 RSP-retry contract: rebuilding a Node_desc_rsp for the
/// same request (same echoed TSN, as the confirm-driven retry does)
/// must never re-emit identical secured bytes — each take consumes a
/// fresh aux counter, so a confirm-lost first copy cannot make the
/// coordinator trip its own replay check on the duplicate.
#[test]
fn node_desc_rsp_rebuilds_advance_auxctr() {
    const KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const JW: [u8; 8] = [0xa4, 0x97, 0x85, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
    static DEF: rounddance_zcl::onoff::ServerDef = rounddance_zcl::onoff::ServerDef;
    let mut log = app::NullLog;
    let mut joiner = app::JoinerApp::new(&DEF).unwrap();
    joiner.begin_scan(&mut log).unwrap();
    joiner
        .ingest_beacon(rounddance_commission::BeaconSurveyEntry {
            pan_id: 0xC601,
            channel: 15,
            lqi: 200,
            rssi: -40,
            permit_joining: true,
            router_capacity: true,
            end_device_capacity: true,
            protocol_version: 2,
        })
        .unwrap();
    // Doubled: N-sighting gate needs >=2 rows (Phase 4 election
    // hardening).
    joiner
        .ingest_beacon(rounddance_commission::BeaconSurveyEntry {
            pan_id: 0xC601,
            channel: 15,
            lqi: 200,
            rssi: -40,
            permit_joining: true,
            router_capacity: true,
            end_device_capacity: true,
            protocol_version: 2,
        })
        .unwrap();
    assert_eq!(joiner.finish_scan(&mut log), Some(0xC601));
    let mut rsp = [0u8; 25];
    rsp[..5].copy_from_slice(&[0x63, 0xcc, 0x02, 0x01, 0xc6]);
    rsp[5..13].copy_from_slice(&JW);
    rsp[13..21].copy_from_slice(&rounddance_hal_esp::app::TC_EUI_WIRE);
    rsp[21..25].copy_from_slice(&[0x02, 0x02, 0x00, 0x00]);
    let _ = joiner.on_mac_psdu(&mut log, &rsp[..25], 15, -40, 200);
    // Adopt the key through a synthetic transport (same shape the
    // leg-2 test feeds).
    let tkey = rounddance_commission::ha_transport_key().unwrap();
    let tp = rounddance_commission::TransportKeyParams {
        dst_pan: 0xC601,
        dst_short: 0x0002,
        dst_eui: JW,
        src_eui: [0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0],
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
    let tn = rounddance_commission::build_transport_key_frame(&tp, &mut tf).unwrap();
    let _ = joiner.on_nwk_joiner(&tf[9..tn]);
    assert!(joiner.adopted_netkey().is_some());
    // Same request answered twice (the retry path): strictly
    // increasing aux counters, both independently openable.
    let mut out = [0u8; 160];
    let n1 = joiner
        .take_node_desc_rsp(&mut out, 0x0000, 0x09, 0x0002)
        .unwrap();
    let f1 = out[..n1].to_vec();
    let n2 = joiner
        .take_node_desc_rsp(&mut out, 0x0000, 0x09, 0x0002)
        .unwrap();
    let f2 = out[..n2].to_vec();
    // Aux counter lives at MAC(9) + NWK(8) + 1.
    let c1 = u32::from_le_bytes(f1[9 + 8 + 1..9 + 8 + 5].try_into().unwrap());
    let c2 = u32::from_le_bytes(f2[9 + 8 + 1..9 + 8 + 5].try_into().unwrap());
    assert_eq!(c2, c1.wrapping_add(1));
    assert_ne!(f1, f2);
    for (f, c) in [&f1, &f2].iter().zip([c1, c2]) {
        let (actr, pt) = open_joiner_tail(
            &KEY,
            &f[31..f.len() - 4],
            &f[f.len() - 4..],
            &f[9..17],
            &JW,
            c,
        );
        assert_eq!(actr, c);
        let rsp = rounddance_zdo::zdp::NodeDescRsp::decode(&pt[8..]).expect("rsp decodes");
        assert_eq!((rsp.tsn, rsp.nwk_of_interest), (0x09, 0x0002));
    }
}

/// Phase 4 joiner-NVS-aux contract: without a resume a rebooted
/// joiner restarts at `JOINER_AUX_BASE` (reusing counters a live TC
/// still holds in its replay window — the exact rewind the coord
/// NVS leg closed on the other side); `resume_auxctr` with the
/// persisted chunk restarts strictly above every radiated counter.
/// The fw NVS wiring (this leg) calls `resume_auxctr` at boot and
/// `aux_checkpoint` after every secured build; this test pins the
/// app behavior that wiring depends on.
#[test]
fn joiner_aux_resume_skips_rewind() {
    use rounddance_hal_esp::app::{AUX_CHUNK, JOINER_AUX_BASE};
    const KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const JW: [u8; 8] = [0xa4, 0x97, 0x85, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
    static DEF: rounddance_zcl::onoff::ServerDef = rounddance_zcl::onoff::ServerDef;
    fn keyed_joiner() -> app::JoinerApp<'static> {
        let mut log = app::NullLog;
        let mut joiner = app::JoinerApp::new(&DEF).unwrap();
        joiner.begin_scan(&mut log).unwrap();
        joiner
            .ingest_beacon(rounddance_commission::BeaconSurveyEntry {
                pan_id: 0xC601,
                channel: 15,
                lqi: 200,
                rssi: -40,
                permit_joining: true,
                router_capacity: true,
                end_device_capacity: true,
                protocol_version: 2,
            })
            .unwrap();
        // Doubled: N-sighting gate needs >=2 rows (Phase 4 election
        // hardening).
        joiner
            .ingest_beacon(rounddance_commission::BeaconSurveyEntry {
                pan_id: 0xC601,
                channel: 15,
                lqi: 200,
                rssi: -40,
                permit_joining: true,
                router_capacity: true,
                end_device_capacity: true,
                protocol_version: 2,
            })
            .unwrap();
        assert_eq!(joiner.finish_scan(&mut log), Some(0xC601));
        let mut rsp = [0u8; 25];
        rsp[..5].copy_from_slice(&[0x63, 0xcc, 0x02, 0x01, 0xc6]);
        rsp[5..13].copy_from_slice(&JW);
        rsp[13..21].copy_from_slice(&rounddance_hal_esp::app::TC_EUI_WIRE);
        rsp[21..25].copy_from_slice(&[0x02, 0x02, 0x00, 0x00]);
        let _ = joiner.on_mac_psdu(&mut log, &rsp[..25], 15, -40, 200);
        let tkey = rounddance_commission::ha_transport_key().unwrap();
        let tp = rounddance_commission::TransportKeyParams {
            dst_pan: 0xC601,
            dst_short: 0x0002,
            dst_eui: JW,
            src_eui: [0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0],
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
        let tn = rounddance_commission::build_transport_key_frame(&tp, &mut tf).unwrap();
        let _ = joiner.on_nwk_joiner(&tf[9..tn]);
        assert!(joiner.adopted_netkey().is_some());
        joiner
    }
    fn annce_auxctr(joiner: &mut app::JoinerApp<'static>) -> u32 {
        let mut out = [0u8; 160];
        let n = joiner.take_annce(&mut out).unwrap();
        assert!(n > 0, "annce needs adopted short+key");
        u32::from_le_bytes(out[9 + 8 + 1..9 + 8 + 5].try_into().unwrap())
    }
    // First boot: base chunk, base counter.
    let mut a = keyed_joiner();
    assert_eq!(a.aux_checkpoint(), Some(JOINER_AUX_BASE / AUX_CHUNK));
    let c1 = annce_auxctr(&mut a);
    assert_eq!(c1, JOINER_AUX_BASE);
    // Reboot WITHOUT resume: same counter reused (the rewind this
    // leg's fw wiring closes on device).
    let mut b = keyed_joiner();
    assert_eq!(annce_auxctr(&mut b), c1);
    // Reboot WITH resume of the radiated chunk: strictly above.
    // (The checkpoint now reports the NEW chunk — persist-before-use:
    // the fw persists it before sealing any frame under it.)
    let mut c = keyed_joiner();
    c.resume_auxctr(Some(c1 / AUX_CHUNK));
    assert_eq!(c.aux_checkpoint(), Some(c1 / AUX_CHUNK + 1));
    let c3 = annce_auxctr(&mut c);
    assert!(c3 > c1, "resumed {c3:#x} must exceed radiated {c1:#x}");
    assert_eq!(c3, (c1 / AUX_CHUNK + 1) * AUX_CHUNK);
}

/// Phase 4 join-rate policy: a storm of NEW-EUI associations is
/// throttled (bounded accepts per window) while re-assocs from the
/// latched EUI always pass (legit retry/rejoin must never break).
/// Reproduce-then-fix: without the policy the 5th new EUI is
/// accepted and nothing is counted.
#[test]
fn assoc_rate_policy_throttles_new_eui_storm() {
    // Five distinct display-order EUIs; air order is the full
    // reverse (rung-3/MG21 lesson: middle ff:fe -> fe:ff on air).
    const EUIS: [[u8; 8]; 5] = [
        [0x01, 0x02, 0x03, 0xff, 0xfe, 0x06, 0x07, 0x08],
        [0x11, 0x12, 0x13, 0xff, 0xfe, 0x16, 0x17, 0x18],
        [0x21, 0x22, 0x23, 0xff, 0xfe, 0x26, 0x27, 0x28],
        [0x31, 0x32, 0x33, 0xff, 0xfe, 0x36, 0x37, 0x38],
        [0x41, 0x42, 0x43, 0xff, 0xfe, 0x46, 0x47, 0x48],
    ];
    fn air_for(eui: &[u8; 8], seq: u8) -> [u8; 19] {
        let mut air = [0u8; 19];
        air[..9].copy_from_slice(&[0x23, 0xc8, seq, 0x01, 0xc6, 0x00, 0x00, 0xff, 0xff]);
        let mut wire = *eui;
        wire.reverse();
        air[9..17].copy_from_slice(&wire);
        air[17..19].copy_from_slice(&[0x01, 0x8c]);
        air
    }
    let mut app = formed_app();
    let mut log = app::NullLog;
    app.open_permit(&mut log, 600_000).unwrap();
    for (i, eui) in EUIS.iter().enumerate() {
        app.admit_extra(&mut log, *eui, 0x0010 + i as u16).unwrap();
    }
    app.tick(0, 0);
    let mut out = [0u8; 32];
    // Budget is 4 new accepts per 60 s window: first four pass.
    for (i, eui) in EUIS[..4].iter().enumerate() {
        let air = air_for(eui, i as u8);
        app.on_mac_psdu(&air);
        assert_eq!(
            app.take_assoc_rsp(&mut out).unwrap(),
            25,
            "new EUI {i} accepted"
        );
    }
    assert_eq!(app.assoc_throttled(), 0);
    // Fifth new EUI inside the window: throttled, nothing pended.
    let air = air_for(&EUIS[4], 0x40);
    app.on_mac_psdu(&air);
    assert_eq!(
        app.take_assoc_rsp(&mut out).unwrap(),
        0,
        "5th new EUI throttled"
    );
    assert_eq!(app.assoc_throttled(), 1);
    assert_eq!(app.assoc_denied(), 0);
    // Window rolls: the same EUI is admitted on retry.
    app.tick(61_000, 61_000);
    let air = air_for(&EUIS[4], 0x41);
    app.on_mac_psdu(&air);
    assert_eq!(
        app.take_assoc_rsp(&mut out).unwrap(),
        25,
        "post-window accept"
    );
    assert_eq!(app.assoc_throttled(), 1);
}

/// Re-assocs from the latched EUI never consume budget (the joiner
/// retries assoc-req every 2 s on RSP loss and rejoins after every
/// reboot; throttling those would wedge the legit path).
#[test]
fn reassoc_from_latched_eui_ignores_budget() {
    const EUIS: [[u8; 8]; 4] = [
        [0x51, 0x52, 0x53, 0xff, 0xfe, 0x56, 0x57, 0x58],
        [0x61, 0x62, 0x63, 0xff, 0xfe, 0x66, 0x67, 0x68],
        [0x71, 0x72, 0x73, 0xff, 0xfe, 0x76, 0x77, 0x78],
        [0x81, 0x82, 0x83, 0xff, 0xfe, 0x86, 0x87, 0x88],
    ];
    fn air_for(eui: &[u8; 8], seq: u8) -> [u8; 19] {
        let mut air = [0u8; 19];
        air[..9].copy_from_slice(&[0x23, 0xc8, seq, 0x01, 0xc6, 0x00, 0x00, 0xff, 0xff]);
        let mut wire = *eui;
        wire.reverse();
        air[9..17].copy_from_slice(&wire);
        air[17..19].copy_from_slice(&[0x01, 0x8c]);
        air
    }
    let mut app = formed_app();
    let mut log = app::NullLog;
    app.open_permit(&mut log, 600_000).unwrap();
    for (i, eui) in EUIS.iter().enumerate() {
        app.admit_extra(&mut log, *eui, 0x0020 + i as u16).unwrap();
    }
    app.tick(0, 0);
    let mut out = [0u8; 32];
    for (i, eui) in EUIS.iter().enumerate() {
        let air = air_for(eui, i as u8);
        app.on_mac_psdu(&air);
        assert_eq!(app.take_assoc_rsp(&mut out).unwrap(), 25);
    }
    // Budget exhausted (4/4); the latched (last) EUI retries freely.
    for s in 0x10..0x13u8 {
        let air = air_for(&EUIS[3], s);
        app.on_mac_psdu(&air);
        assert_eq!(
            app.take_assoc_rsp(&mut out).unwrap(),
            25,
            "latched re-assoc passes"
        );
    }
    assert_eq!(app.assoc_throttled(), 0);
    assert_eq!(app.assoc_denied(), 0);
}

/// Denied associations (unlisted EUI, closed window) are counted as
/// denied — never throttled, never answered. Previously silent.
#[test]
fn denied_assoc_counted_not_throttled() {
    const LISTED: [u8; 8] = [0x91, 0x92, 0x93, 0xff, 0xfe, 0x96, 0x97, 0x98];
    const STRANGER: [u8; 8] = [0xa1, 0xa2, 0xa3, 0xff, 0xfe, 0xa6, 0xa7, 0xa8];
    fn air_for(eui: &[u8; 8], seq: u8) -> [u8; 19] {
        let mut air = [0u8; 19];
        air[..9].copy_from_slice(&[0x23, 0xc8, seq, 0x01, 0xc6, 0x00, 0x00, 0xff, 0xff]);
        let mut wire = *eui;
        wire.reverse();
        air[9..17].copy_from_slice(&wire);
        air[17..19].copy_from_slice(&[0x01, 0x8c]);
        air
    }
    let mut app = formed_app();
    let mut log = app::NullLog;
    app.open_permit(&mut log, 600_000).unwrap();
    app.admit_extra(&mut log, LISTED, 0x0030).unwrap();
    app.tick(0, 0);
    let mut out = [0u8; 32];
    // Stranger under open permit: denied, counted, silent.
    app.on_mac_psdu(&air_for(&STRANGER, 0x01));
    assert_eq!(app.take_assoc_rsp(&mut out).unwrap(), 0);
    assert_eq!(app.assoc_denied(), 1);
    assert_eq!(app.assoc_throttled(), 0);
    // Listed EUI after the window closes: denied the same way.
    app.tick(601_000, 601_000);
    assert!(!app.permit_open());
    app.on_mac_psdu(&air_for(&LISTED, 0x02));
    assert_eq!(app.take_assoc_rsp(&mut out).unwrap(), 0);
    assert_eq!(app.assoc_denied(), 2);
    assert_eq!(app.assoc_throttled(), 0);
}

/// Phase 4 ZCL-toggle leg, fw-path contract: the joiner's RX-NWK
/// classification consumes the replay check, so answering the same
/// bytes with the checking path would refuse the first legitimate
/// Toggle as a replay. `answer_toggle` skips the re-check
/// (documented pre-classification contract) and flips the lamp
/// exactly once per toggle intent: a confirm-lost duplicate
/// (same ZCL TSN, fresh aux counter) re-seals WITHOUT re-flipping.
#[test]
fn toggle_answer_skips_recheck_and_flips_once() {
    use rounddance_hal_esp::app::JoinerNwkOutcome;
    const KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const JW: [u8; 8] = [0xa4, 0x97, 0x85, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
    static DEF: rounddance_zcl::onoff::ServerDef = rounddance_zcl::onoff::ServerDef;
    let mut log = app::NullLog;
    // Keyed joiner: scan (two sightings: N-sighting gate) ->
    // assoc-rsp -> transport open.
    let mut joiner = app::JoinerApp::new(&DEF).unwrap();
    joiner.begin_scan(&mut log).unwrap();
    for _ in 0..2 {
        joiner
            .ingest_beacon(rounddance_commission::BeaconSurveyEntry {
                pan_id: 0xC601,
                channel: 15,
                lqi: 200,
                rssi: -40,
                permit_joining: true,
                router_capacity: true,
                end_device_capacity: true,
                protocol_version: 2,
            })
            .unwrap();
    }
    assert_eq!(joiner.finish_scan(&mut log), Some(0xC601));
    let mut rsp = [0u8; 25];
    rsp[..5].copy_from_slice(&[0x63, 0xcc, 0x02, 0x01, 0xc6]);
    rsp[5..13].copy_from_slice(&JW);
    rsp[13..21].copy_from_slice(&rounddance_hal_esp::app::TC_EUI_WIRE);
    rsp[21..25].copy_from_slice(&[0x02, 0x02, 0x00, 0x00]);
    let _ = joiner.on_mac_psdu(&mut log, &rsp[..25], 15, -40, 200);
    let tkey = rounddance_commission::ha_transport_key().unwrap();
    let tp = rounddance_commission::TransportKeyParams {
        dst_pan: 0xC601,
        dst_short: 0x0002,
        dst_eui: JW,
        src_eui: [0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0],
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
    let tn = rounddance_commission::build_transport_key_frame(&tp, &mut tf).unwrap();
    let _ = joiner.on_nwk_joiner(&tf[9..tn]);
    assert!(joiner.adopted_netkey().is_some());
    assert!(!joiner.lamp());
    // Coordinator builds the toggle; joiner classifies it (this
    // consumes the replay check for these bytes).
    let mut coord = formed_app();
    // Advance the coordinator counter past the synthetic transport
    // auxctr, exactly as the air order does (transport, then a
    // node_desc_req, then the toggle): otherwise the first toggle
    // would tie the recorded counter and classify as a replay.
    let mut scratch_req = [0u8; 160];
    let _ = coord.take_node_desc_req(&mut scratch_req, 0x0002, &KEY);
    let mut tf2 = [0u8; 160];
    coord.new_toggle();
    let tn2 = coord
        .build_toggle_request(&mut log, &KEY, &mut tf2)
        .unwrap();
    match joiner.on_nwk_joiner(&tf2[9..tn2]) {
        JoinerNwkOutcome::Data { cluster, profile } => {
            assert_eq!((cluster, profile), (0x0006, 0x0104))
        }
        other => panic!("expected toggle Data, got {other:?}"),
    }
    // A fresh delivery flips the lamp exactly once (checked below).
    // The answer path skips the re-check: flips exactly once...
    let mut out = [0u8; 160];
    let n1 = joiner
        .answer_toggle(&mut log, &tf2[9..tn2], &mut out)
        .unwrap();
    assert!(n1 > 0);
    assert!(joiner.lamp());
    let f1 = out[..n1].to_vec();
    // ...and a confirm-lost duplicate re-seals (fresh counter, never
    // identical bytes) WITHOUT flipping again.
    let n2 = joiner
        .answer_toggle(&mut log, &tf2[9..tn2], &mut out)
        .unwrap();
    assert!(joiner.lamp());
    let f2 = out[..n2].to_vec();
    assert_ne!(f1, f2);
    // Both answers open under the run key with strictly advancing
    // aux counters from the NVM-backed space (first secured joiner
    // frames of this boot: 0x2000, 0x2001), APS unicast ep1 +
    // On/Off + HA, DefRsp echoing the toggle TSN with success.
    for (f, n, c) in [(&f1, n1, 0x0000_2000u32), (&f2, n2, 0x0000_2001u32)] {
        assert_eq!(&f[0..2], &[0x61, 0x88]);
        let (actr, apt) = open_joiner_tail(&KEY, &f[31..n - 4], &f[n - 4..], &f[9..17], &JW, c);
        assert_eq!(actr, c);
        let aps = rounddance_aps::decode_data(&apt).unwrap();
        assert_eq!(
            (aps.header.cluster_id, aps.header.profile_id),
            (0x0006, 0x0104)
        );
        let (zhdr, zbody) = rounddance_zcl::frame::Header::decode(aps.payload).unwrap();
        assert_eq!(zhdr.command_id, 0x0b);
        let rsp = rounddance_zcl::general::DefaultRsp::decode(zbody).unwrap();
        assert_eq!(rsp.cmd, rounddance_zcl::onoff::CMD_TOGGLE);
        assert!(matches!(
            rsp.status,
            rounddance_zcl::status::ZclStatus::Success
        ));
    }
}

/// Phase 4 ZCL-toggle leg, coordinator side: a DefRsp verified after
/// classification must not trip the replay re-check either, and a
/// tunneled-then-answered exchange verifies end to end.
#[test]
fn defrsp_verify_skips_recheck_and_counts() {
    use rounddance_hal_esp::app::{JoinerNwkOutcome, NwkIgnore, NwkRxOutcome};
    use rounddance_security::{KeySet, NetworkKey};
    const KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const JW: [u8; 8] = [0xa4, 0x97, 0x85, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
    static DEF: rounddance_zcl::onoff::ServerDef = rounddance_zcl::onoff::ServerDef;
    let mut log = app::NullLog;
    // Same keyed joiner as the toggle test above.
    let mut joiner = app::JoinerApp::new(&DEF).unwrap();
    joiner.begin_scan(&mut log).unwrap();
    for _ in 0..2 {
        joiner
            .ingest_beacon(rounddance_commission::BeaconSurveyEntry {
                pan_id: 0xC601,
                channel: 15,
                lqi: 200,
                rssi: -40,
                permit_joining: true,
                router_capacity: true,
                end_device_capacity: true,
                protocol_version: 2,
            })
            .unwrap();
    }
    assert_eq!(joiner.finish_scan(&mut log), Some(0xC601));
    let mut rsp = [0u8; 25];
    rsp[..5].copy_from_slice(&[0x63, 0xcc, 0x02, 0x01, 0xc6]);
    rsp[5..13].copy_from_slice(&JW);
    rsp[13..21].copy_from_slice(&rounddance_hal_esp::app::TC_EUI_WIRE);
    rsp[21..25].copy_from_slice(&[0x02, 0x02, 0x00, 0x00]);
    let _ = joiner.on_mac_psdu(&mut log, &rsp[..25], 15, -40, 200);
    let tkey = rounddance_commission::ha_transport_key().unwrap();
    let tp = rounddance_commission::TransportKeyParams {
        dst_pan: 0xC601,
        dst_short: 0x0002,
        dst_eui: JW,
        src_eui: [0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0],
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
    let tn = rounddance_commission::build_transport_key_frame(&tp, &mut tf).unwrap();
    let _ = joiner.on_nwk_joiner(&tf[9..tn]);
    let mut coord = formed_app();
    let keys = KeySet::new(NetworkKey::new(KEY, 0));
    // Advance the coordinator counter past the synthetic transport
    // auxctr, exactly as the air order does (transport, then a
    // node_desc_req, then the toggle): otherwise the first toggle
    // would tie the recorded counter and classify as a replay.
    let mut scratch_req = [0u8; 160];
    let _ = coord.take_node_desc_req(&mut scratch_req, 0x0002, &KEY);
    let mut tf2 = [0u8; 160];
    coord.new_toggle();
    let tn2 = coord
        .build_toggle_request(&mut log, &KEY, &mut tf2)
        .unwrap();
    match joiner.on_nwk_joiner(&tf2[9..tn2]) {
        JoinerNwkOutcome::Data { cluster, profile } => {
            assert_eq!((cluster, profile), (0x0006, 0x0104))
        }
        other => panic!("expected toggle Data, got {other:?}"),
    }
    let mut ans = [0u8; 160];
    let an = joiner
        .answer_toggle(&mut log, &tf2[9..tn2], &mut ans)
        .unwrap();
    // Coordinator classifies the answer (consumes its replay check),
    // then verifies without re-checking.
    match coord.on_nwk_data(&ans[9..an], &keys, 9_000) {
        NwkRxOutcome::Data { cluster, profile } => {
            assert_eq!((cluster, profile), (0x0006, 0x0104))
        }
        other => panic!("expected DefRsp Data, got {other:?}"),
    }
    assert!(coord.verify_defrsp(&mut log, &keys, &ans[9..an]).unwrap());
    assert_eq!(coord.defrsp_ok, 1);
    // Duplicate delivery is refused at classification (never
    // re-answered): the replay firewall holds on both ends.
    match joiner.on_nwk_joiner(&tf2[9..tn2]) {
        JoinerNwkOutcome::Ignored(NwkIgnore::Replay) => {}
        other => panic!("expected Replay ignore, got {other:?}"),
    }
}
