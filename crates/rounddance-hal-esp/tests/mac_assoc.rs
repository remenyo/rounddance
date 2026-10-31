//! MAC beacon/association leg over a scripted radio (G-01).
//!
//! Byte-exact pins are the OTA-proven scratch builders (`rd-c6join`
//! `src/main.rs` self-test pins): beacon(0x5a), assoc-rsp(0x02),
//! beacon-req(0xaa), assoc-req(0xcc). The coordinator responder legs
//! mirror `rd-c6join` `src/main.rs` RX/TX pacing (pend_beacon /
//! pend_assoc, allow-list + permit gating, poll re-arm).

use rounddance_hal_esp::mac_cmd::{
    self, AssocReq, BeaconInfo, CoordAssoc, BEACON_LEN, MAC_ASSOC_REQ, MAC_ASSOC_RSP,
    MAC_BEACON_REQ, MAC_CAPS, MAC_DATA_REQ, SUPERFRAME_ASSOC_PERMIT,
};
use rounddance_hal_esp::{app, driver::RxFrame, EspAdapter, MockDriver};
use rounddance_mac_sap::{MacDataSap, MacMgmtSap};

const JOINER_EUI: [u8; 8] = app::JOINER_EUI;
const EXT_PAN: [u8; 8] = app::EXT_PAN_ID;
const PAN: u16 = app::APP_PAN;
const COORD: u16 = app::COORD_SHORT;
const JOINER_SHORT: u16 = app::JOINER_SHORT;

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

fn ota_poll_long() -> [u8; 18] {
    let mut b = [0u8; 18];
    b[..9].copy_from_slice(&[0x23, 0xc8, 0x01, 0x01, 0xc6, 0x00, 0x00, 0xff, 0xff]);
    b[9..17].copy_from_slice(&JOINER_EUI);
    b[17] = 0x04;
    b
}

fn ota_beacon() -> [u8; 26] {
    let mut b = [0u8; 26];
    b[..14].copy_from_slice(&[
        0x00, 0x80, 0x5a, 0x01, 0xc6, 0x00, 0x00, 0xff, 0xcf, 0x00, 0x00, 0x00, 0x22, 0x8c,
    ]);
    b[14..22].copy_from_slice(&EXT_PAN);
    // Beacon-payload TxOffset FFFFFF (nonbeacon-network marker) + update id 00.
    b[22..25].copy_from_slice(&[0xff, 0xff, 0xff]);
    b
}

fn ota_assoc_rsp() -> [u8; 25] {
    let mut b = [0u8; 25];
    b[..5].copy_from_slice(&[0x63, 0xcc, 0x02, 0x01, 0xc6]);
    b[5..13].copy_from_slice(&JOINER_EUI);
    b[13..21].copy_from_slice(&app::TC_EUI_WIRE);
    b[21..25].copy_from_slice(&[0x02, 0x01, 0x00, 0x00]);
    b
}

#[test]
fn builders_match_ota_pins() {
    let mut out = [0u8; 32];
    assert_eq!(mac_cmd::build_beacon_req(0xaa, &mut out).unwrap(), 8);
    assert_eq!(&out[..8], &ota_beacon_req());
    assert_eq!(
        mac_cmd::build_assoc_req(0xcc, PAN, COORD, &JOINER_EUI, MAC_CAPS, &mut out).unwrap(),
        19
    );
    assert_eq!(&out[..19], &ota_assoc_req());
    assert_eq!(
        mac_cmd::build_data_poll_long(0x01, PAN, COORD, &JOINER_EUI, &mut out).unwrap(),
        18
    );
    assert_eq!(&out[..18], &ota_poll_long());
    assert_eq!(
        mac_cmd::build_beacon(
            0x5a,
            PAN,
            COORD,
            SUPERFRAME_ASSOC_PERMIT,
            &EXT_PAN,
            &mut out
        )
        .unwrap(),
        BEACON_LEN
    );
    assert_eq!(&out[..26], &ota_beacon());
    assert_eq!(
        mac_cmd::build_assoc_rsp(
            0x02,
            PAN,
            &JOINER_EUI,
            &app::TC_EUI_WIRE,
            JOINER_SHORT,
            0x00,
            &mut out
        )
        .unwrap(),
        25
    );
    assert_eq!(&out[..25], &ota_assoc_rsp());
}

#[test]
fn builders_reject_small_buffers() {
    let mut tiny = [0u8; 4];
    assert!(mac_cmd::build_beacon_req(0xaa, &mut tiny).is_err());
    assert!(mac_cmd::build_assoc_req(0xcc, PAN, COORD, &JOINER_EUI, MAC_CAPS, &mut tiny).is_err());
    assert!(mac_cmd::build_beacon(
        0x5a,
        PAN,
        COORD,
        SUPERFRAME_ASSOC_PERMIT,
        &EXT_PAN,
        &mut tiny
    )
    .is_err());
    assert!(mac_cmd::build_assoc_rsp(
        0x02,
        PAN,
        &JOINER_EUI,
        &app::TC_EUI_WIRE,
        JOINER_SHORT,
        0x00,
        &mut tiny
    )
    .is_err());
}

#[test]
fn parsers_round_trip_ota_vectors() {
    let req = mac_cmd::parse_beacon_req(&ota_beacon_req()).expect("beacon-req parses");
    assert_eq!(req.seq, 0xaa);
    assert_eq!(MAC_BEACON_REQ, 0x07);

    let areq = mac_cmd::parse_assoc_req(&ota_assoc_req()).expect("assoc-req parses");
    assert_eq!(
        areq,
        AssocReq {
            seq: 0xcc,
            dst_pan: PAN,
            dst_short: COORD,
            src_eui: JOINER_EUI,
            caps: MAC_CAPS,
        }
    );
    assert_eq!(MAC_ASSOC_REQ, 0x01);
    assert_eq!(MAC_DATA_REQ, 0x04);

    let poll = mac_cmd::parse_data_poll_long(&ota_poll_long()).expect("poll parses");
    assert_eq!(poll.seq, 0x01);
    assert_eq!(poll.src_eui, JOINER_EUI);

    let bi: BeaconInfo = mac_cmd::parse_beacon(&ota_beacon()).expect("beacon parses");
    assert_eq!(bi.seq, 0x5a);
    assert_eq!(bi.src_pan, PAN);
    assert_eq!(bi.src_short, COORD);
    assert!(bi.assoc_permit, "OTA superframe 0xCFFF permits");
    assert_eq!(bi.superframe, SUPERFRAME_ASSOC_PERMIT);
    let payload = &ota_beacon()[bi.payload_off..];
    assert!(mac_cmd::beacon_payload_is_ours(payload, &EXT_PAN));
    assert!(!mac_cmd::beacon_payload_is_ours(payload, &[0u8; 8]));

    let rsp = mac_cmd::parse_assoc_rsp(&ota_assoc_rsp()).expect("assoc-rsp parses");
    assert_eq!(rsp.seq, 0x02);
    assert_eq!(rsp.dst_eui, JOINER_EUI);
    assert_eq!(rsp.src_eui, app::TC_EUI_WIRE);
    assert_eq!(rsp.short, JOINER_SHORT);
    assert_eq!(rsp.status, 0x00);
    assert_eq!(MAC_ASSOC_RSP, 0x02);
}

#[test]
fn parsers_reject_malformed_without_panic() {
    let empty: [u8; 0] = [];
    assert!(mac_cmd::parse_beacon_req(&empty).is_none());
    assert!(mac_cmd::parse_assoc_req(&empty).is_none());
    assert!(mac_cmd::parse_data_poll_long(&empty).is_none());
    assert!(mac_cmd::parse_beacon(&empty).is_none());
    assert!(mac_cmd::parse_assoc_rsp(&empty).is_none());
    // Single header byte: no indexing panic.
    assert!(mac_cmd::parse_beacon_req(&[0x03]).is_none());
    assert!(mac_cmd::parse_beacon(&[0x00]).is_none());
    // Truncated tails.
    assert!(mac_cmd::parse_beacon_req(&ota_beacon_req()[..7]).is_none());
    assert!(mac_cmd::parse_assoc_req(&ota_assoc_req()[..18]).is_none());
    assert!(mac_cmd::parse_assoc_rsp(&ota_assoc_rsp()[..24]).is_none());
    assert!(mac_cmd::parse_beacon(&ota_beacon()[..11]).is_none());
    // Wrong command id in an otherwise valid shape.
    let mut bad = ota_assoc_req();
    bad[17] = 0x09;
    assert!(mac_cmd::parse_assoc_req(&bad).is_none());
    let mut bad = ota_beacon_req();
    bad[7] = 0x09;
    assert!(mac_cmd::parse_beacon_req(&bad).is_none());
    // Cross-shape: beacon bytes are not an assoc response.
    assert!(mac_cmd::parse_assoc_rsp(&ota_beacon()).is_none());
    assert!(mac_cmd::parse_beacon(&ota_assoc_rsp()).is_none());
    // Classifier routes each OTA shape, unknowns fall to Other.
    assert!(matches!(
        mac_cmd::classify(&ota_beacon_req()),
        mac_cmd::Incoming::BeaconReq { seq: 0xaa }
    ));
    assert!(matches!(
        mac_cmd::classify(&ota_assoc_req()),
        mac_cmd::Incoming::AssocReq { .. }
    ));
    assert!(matches!(
        mac_cmd::classify(&ota_poll_long()),
        mac_cmd::Incoming::DataPoll { .. }
    ));
    assert!(matches!(
        mac_cmd::classify(&ota_beacon()),
        mac_cmd::Incoming::Other
    ));
    assert!(matches!(
        mac_cmd::classify(&[0x41, 0x88, 0x00]),
        mac_cmd::Incoming::Other
    ));
}

#[test]
fn coordinator_answers_beacon_req_while_serving() {
    let mut coord = CoordAssoc::new();
    coord.provision(PAN, COORD, &app::TC_EUI_WIRE);
    let mut out = [0u8; 32];
    // Nothing pending: idle, no bytes radiated.
    assert_eq!(coord.take_beacon(0x01, &EXT_PAN, &mut out).unwrap(), 0);
    // Beacon requests pend regardless of the permit window (the flag
    // inside the superframe, not the answer, carries the window).
    coord.on_beacon_req();
    coord.on_beacon_req();
    assert_eq!(coord.pending_beacon(), 2);
    assert_eq!(coord.take_beacon(0x5a, &EXT_PAN, &mut out).unwrap(), 26);
    assert_eq!(&out[..26], &ota_beacon());
    assert_eq!(coord.pending_beacon(), 1);
}

#[test]
fn coordinator_assoc_needs_permit_and_allow_list() {
    let mut coord = CoordAssoc::new();
    coord.provision(PAN, COORD, &app::TC_EUI_WIRE);
    let areq = mac_cmd::parse_assoc_req(&ota_assoc_req()).unwrap();
    let mut out = [0u8; 32];
    // Closed window: no latch, no pending, no response bytes.
    assert!(!coord.on_assoc_req(&areq));
    assert!(!coord.assoc_pending());
    assert_eq!(
        coord
            .take_assoc_rsp(0x02, JOINER_SHORT, 0x00, &mut out)
            .unwrap(),
        0
    );
    // Open window but foreign EUI: denied like the scratch ASSOC-DENY leg.
    coord.set_permit(true);
    let foreign = AssocReq {
        src_eui: [0u8; 8],
        ..areq
    };
    assert!(!coord.on_assoc_req(&foreign));
    assert!(!coord.assoc_pending());
    // Open window + allow-listed EUI: latch + pend, response is OTA-exact.
    coord.allow(JOINER_EUI).unwrap();
    assert!(coord.on_assoc_req(&areq));
    assert!(coord.assoc_pending());
    assert_eq!(coord.device_eui(), Some(JOINER_EUI));
    assert_eq!(
        coord
            .take_assoc_rsp(0x02, JOINER_SHORT, 0x00, &mut out)
            .unwrap(),
        25
    );
    assert_eq!(&out[..25], &ota_assoc_rsp());
    assert!(!coord.assoc_pending(), "one response per request");
    // Long poll from the latched EUI re-arms the response (fetch edge).
    let poll = mac_cmd::parse_data_poll_long(&ota_poll_long()).unwrap();
    assert!(coord.on_data_poll(&poll));
    assert!(coord.assoc_pending());
    // Poll from a stranger re-arms nothing.
    let mut stranger = ota_poll_long();
    stranger[9] = 0x00;
    let stranger = mac_cmd::parse_data_poll_long(&stranger).unwrap();
    coord
        .take_assoc_rsp(0x03, JOINER_SHORT, 0x00, &mut out)
        .unwrap();
    assert!(!coord.on_data_poll(&stranger));
    assert!(!coord.assoc_pending());
}

#[test]
fn coordinator_ignores_foreign_pan_assoc() {
    let mut coord = CoordAssoc::new();
    coord.provision(PAN, COORD, &app::TC_EUI_WIRE);
    coord.set_permit(true);
    coord.allow(JOINER_EUI).unwrap();
    let mut foreign_pan = ota_assoc_req();
    foreign_pan[3..5].copy_from_slice(&0x1234u16.to_le_bytes());
    let req = mac_cmd::parse_assoc_req(&foreign_pan).unwrap();
    assert!(!coord.on_assoc_req(&req), "not addressed to our PAN");
    assert!(!coord.assoc_pending());
}

#[test]
fn joiner_handoff_values_from_air() {
    // The exact values the joiner app consumes: beacon permit flag +
    // assoc-rsp short/status, feeding the existing survey/confirm calls.
    let bi = mac_cmd::parse_beacon(&ota_beacon()).unwrap();
    assert!(bi.assoc_permit);
    assert_eq!((bi.src_pan, bi.src_short), (PAN, COORD));
    let rsp = mac_cmd::parse_assoc_rsp(&ota_assoc_rsp()).unwrap();
    assert_eq!(rsp.dst_eui, JOINER_EUI);
    assert_eq!((rsp.short, rsp.status), (JOINER_SHORT, 0x00));

    // assoc_confirm(true) advances the existing join machine, as the
    // c6_standalone leg does post-survey (app.rs assoc_confirm path).
    // The survey entry carries the parsed PAN + permit flag; remaining
    // fields are the lab pins the c6_standalone leg uses (full
    // beacon→entry capacity/version mapping is rung-2 work).
    static DEF: rounddance_zcl::onoff::ServerDef = rounddance_zcl::onoff::ServerDef;
    let mut joiner = app::JoinerApp::new(&DEF).unwrap();
    joiner.begin_scan(&mut NullLog).unwrap();
    let state = joiner
        .survey(
            &mut NullLog,
            rounddance_commission::BeaconSurveyEntry {
                pan_id: bi.src_pan,
                channel: 15,
                lqi: 200,
                rssi: -40,
                permit_joining: bi.assoc_permit,
                router_capacity: true,
                end_device_capacity: true,
                protocol_version: 2,
            },
        )
        .unwrap();
    assert_eq!(
        state,
        rounddance_commission::SteeringState::CandidateSelected
    );
    joiner.assoc_confirm(&mut NullLog, rsp.status == 0x00);
    assert_eq!(
        joiner.state(),
        rounddance_commission::JoinerState::Authenticating
    );
}

#[test]
fn adapter_routes_command_frames_to_mac_queue_closed_gap() {
    // Closed rung-2 gap (MVP FIX): EspAdapter routes MAC-command
    // PSDUs (beacon-req here) to the MAC queue instead of dropping
    // them; data indications stay empty and `rx_dropped` stays 0.
    let mut a = EspAdapter::new(MockDriver::new());
    a.set_pan_id(PAN);
    a.set_short_addr(COORD);
    a.init().unwrap();
    let air = ota_beacon_req();
    let mut len2 = [0u8; 9];
    len2[0] = (air.len() + 2) as u8;
    len2[1..].copy_from_slice(&air);
    a.driver_mut()
        .inject_rx(&[RxFrame::from_slice(&len2, 15, -40, 200).unwrap()]);
    assert!(a.poll_indication().is_none());
    let ind = a.poll_mac_indication().expect("beacon-req routes");
    assert_eq!(ind.psdu(), &air);
    assert_eq!(a.rx_dropped(), 0);
}

struct NullLog;
impl app::SerialLog for NullLog {
    fn log(&mut self, _line: &str) {}
}

/// Pre-w93 legacy short-source association-response shape (`FC 63 8c`,
/// 19 B: coordinator SHORT as source). Real Ember NCPs never emit this
/// layout on air (w93 MG21 capture is `FC 63 cc`, 25 B, long source);
/// the long-source-only parser must refuse it with `None` (recorded
/// here), and it must not classify as anything routable either.
fn ota_assoc_rsp_legacy_short_source() -> [u8; 19] {
    let mut b = [0u8; 19];
    b[..3].copy_from_slice(&[0x63, 0x8c, 0x02]);
    b[3..5].copy_from_slice(&PAN.to_le_bytes());
    b[5..13].copy_from_slice(&JOINER_EUI);
    b[13..15].copy_from_slice(&COORD.to_le_bytes());
    b[15] = MAC_ASSOC_RSP;
    b[16..18].copy_from_slice(&JOINER_SHORT.to_le_bytes());
    b[18] = 0x00;
    b
}

#[test]
fn parse_rejects_legacy_short_source_rsp() {
    // Same seq/PAN/dst-EUI/short/status as the OTA vector, only the
    // source addressing differs (short `8c` vs long `cc`).
    let legacy = ota_assoc_rsp_legacy_short_source();
    assert_eq!(legacy.len(), 19);
    assert_eq!(legacy[1], 0x8c);
    assert_eq!(legacy[2], ota_assoc_rsp()[2]);
    // Recorded refusal: exactly `None`, never a partial `AssocRsp`.
    assert_eq!(mac_cmd::parse_assoc_rsp(&legacy), None);
    assert!(mac_cmd::parse_assoc_rsp(&legacy).is_none());
    assert!(matches!(
        mac_cmd::classify(&legacy),
        mac_cmd::Incoming::Other
    ));
    // Positive control: the 25 B long-source twin parses.
    assert!(mac_cmd::parse_assoc_rsp(&ota_assoc_rsp()).is_some());
}

/// Truncated long-source RSPs (24 B off-by-one, 0 B empty) and
/// wrong-command variants of the exact 25 B shape: all refuse with
/// `None`, no indexing panic on the empty slice.
#[test]
fn parse_rejects_truncated_and_wrong_cmd_rsp() {
    let full = ota_assoc_rsp();
    // 24 B: one octet short of ASSOC_RSP_LEN.
    assert_eq!(mac_cmd::parse_assoc_rsp(&full[..24]), None);
    // 0 B: empty slice.
    let empty: [u8; 0] = [];
    assert_eq!(mac_cmd::parse_assoc_rsp(&empty), None);
    assert_eq!(mac_cmd::parse_assoc_rsp(&full[..0]), None);
    // Oversize is equally refused (exact-length match).
    let mut long = [0u8; 26];
    long[..25].copy_from_slice(&full);
    assert_eq!(mac_cmd::parse_assoc_rsp(&long), None);
    // Wrong command id in an otherwise valid 25 B shape.
    let mut bad_cmd = full;
    bad_cmd[21] = 0x09;
    assert_eq!(mac_cmd::parse_assoc_rsp(&bad_cmd), None);
    // Wrong second FC byte (`8c` short-source marker smuggled into a
    // 25 B frame) and wrong first FC byte.
    let mut bad_fc = full;
    bad_fc[1] = 0x8c;
    assert_eq!(mac_cmd::parse_assoc_rsp(&bad_fc), None);
    let mut bad_fc0 = full;
    bad_fc0[0] = 0x62;
    assert_eq!(mac_cmd::parse_assoc_rsp(&bad_fc0), None);
}

/// `build_assoc_rsp` boundary: every undersized buffer (0 B, 24 B)
/// fails with exactly `BufferTooSmall`; the 25 B boundary succeeds
/// with the OTA-exact bytes.
#[test]
fn build_assoc_rsp_rejects_undersized_buffers_at_boundary() {
    use mac_cmd::{MacCmdError, ASSOC_RSP_LEN};
    assert_eq!(ASSOC_RSP_LEN, 25);
    let mut exact = [0u8; 25];
    let mut one_short = [0u8; 24];
    let mut empty = [0u8; 0];
    assert_eq!(
        mac_cmd::build_assoc_rsp(
            0x02,
            PAN,
            &JOINER_EUI,
            &app::TC_EUI_WIRE,
            JOINER_SHORT,
            0x00,
            &mut empty
        ),
        Err(MacCmdError::BufferTooSmall)
    );
    assert_eq!(
        mac_cmd::build_assoc_rsp(
            0x02,
            PAN,
            &JOINER_EUI,
            &app::TC_EUI_WIRE,
            JOINER_SHORT,
            0x00,
            &mut one_short
        ),
        Err(MacCmdError::BufferTooSmall)
    );
    assert_eq!(
        mac_cmd::build_assoc_rsp(
            0x02,
            PAN,
            &JOINER_EUI,
            &app::TC_EUI_WIRE,
            JOINER_SHORT,
            0x00,
            &mut exact
        ),
        Ok(25)
    );
    assert_eq!(&exact, &ota_assoc_rsp());
}

/// w93 MG21 reference (live Ember NCP, ch20): the wire-proven
/// association-response shape — `FC 63 cc` (both addrs long),
/// coordinator EUI as source. The old short-source `... 8c` layout
/// never appears on air from a real NCP; MG24 accepts this form and
/// joins (NETWORK_UP, short 0xC5C1). Captured verbatim in
/// `~/hwscratch/w93/sniff_mg21ref.txt` (footer stripped).
#[test]
fn parse_mg21_reference_assoc_rsp_long_source() {
    let raw = "63cc9d61376d4911feff138d345f75f4feffe5e30402c1c500";
    let psdu: Vec<u8> = (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(psdu.len(), 25);
    let rsp = mac_cmd::parse_assoc_rsp(&psdu).expect("MG21 RSP parses");
    assert_eq!(rsp.seq, 0x9d);
    assert_eq!(
        rsp.dst_eui,
        [0x6d, 0x49, 0x11, 0xfe, 0xff, 0x13, 0x8d, 0x34]
    );
    assert_eq!(
        rsp.src_eui,
        [0x5f, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04]
    );
    assert_eq!(rsp.short, 0xc5c1);
    assert_eq!(rsp.status, 0x00);
}
