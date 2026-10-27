//! On/Off command + attribute report over the scripted medium: a
//! client Toggle rides an APS data APDU (HA profile) inside an NWK
//! data NPDU from node A to node B; B applies it to a live On/Off
//! server behavior and answers with a Report Attributes command, and
//! the whole exchange replays deterministically.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `07-5123-08-383-01` (toggle effect), `07-5123-08-2511-01`
//! (report generation), `SCOPE.md` §8 (decision determinism).

use rounddance_aps::{DataDest, DataHeader, DeliveryMode, FrameControl};
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap as _, MacMgmtSap as _, TxOptions, TxRequest,
    TxStatus,
};
use rounddance_nwk::{build_data_header, decode as nwk_decode, DiscoverRoute, NldeDataRequest};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};
use rounddance_zcl::behavior::{Ctx, EventQueue};
use rounddance_zcl::frame::Header;
use rounddance_zcl::{general, onoff, DispatchOutcome, Endpoint, ReportingEngine};

const PAN: u16 = 0x1a2b;
const NODE_A: u16 = 0x0001;
const NODE_B: u16 = 0x0002;
const HA_PROFILE: u16 = 0x0104;
const ENDPOINT: u8 = 0x01;

/// Wrap ZCL octets in an APS data APDU on the application endpoint pair.
fn encoded_zcl_apdu(cluster: u16, counter: u8, zcl: &[u8]) -> Vec<u8> {
    let header = DataHeader {
        control: FrameControl {
            ack_request: true,
            ..FrameControl::data(DeliveryMode::Unicast)
        },
        dest: DataDest::Unicast {
            dst_endpoint: ENDPOINT,
        },
        cluster_id: cluster,
        profile_id: HA_PROFILE,
        src_endpoint: ENDPOINT,
        counter,
        ext: None,
    };
    let mut out = vec![0u8; header.header_len() + zcl.len()];
    let n = header.encode_into(zcl, &mut out).unwrap();
    out.truncate(n);
    out
}

/// Wrap an APDU in an NWK data NPDU from `src` to `dst`.
fn encoded_npdu(src: u16, dst: u16, apdu: &[u8]) -> Vec<u8> {
    let req = NldeDataRequest {
        dst_addr: dst,
        use_alias: false,
        alias_src: 0,
        alias_seq: 0,
        radius_param: 3,
        discover_route: DiscoverRoute::Enable,
        generated_seq: 0x42,
        local_short_addr: src,
        max_depth: 5,
        associated: true,
    };
    let header = build_data_header(&req).unwrap();
    let mut out = vec![0u8; header.header_len() + apdu.len()];
    let n = header.encode_into(apdu, &mut out).unwrap();
    out.truncate(n);
    out
}

/// One medium trip: queue `npdu` on a loopback radio and return the
/// delivered on-air copy plus the radio's trace.
fn medium_trip(seed: u64, node: u16, dst: u16, npdu: &[u8]) -> (Vec<String>, Vec<u8>) {
    let mut radio = ScriptedRadio::new(Seed(seed), vec![ScriptAction::Deliver]);
    radio.reset(true);
    radio.set_channel(Channel::new(15).unwrap()).unwrap();
    radio.set_pan_id(PAN);
    radio.set_short_addr(node);
    radio
        .data_request(TxRequest {
            dst: MacAddress::short(PAN, dst),
            msdu: FramePayload::from_slice(npdu).expect("NPDU fits one MSDU"),
            options: TxOptions::ACK,
        })
        .expect("queue has room");
    radio.run_until_idle(16);
    let confirm = radio.poll_confirm().expect("script always confirms");
    assert_eq!(confirm.status, TxStatus::Delivered);
    let rx = radio
        .poll_indication()
        .expect("delivery implies indication");
    (radio.trace_lines().to_vec(), rx.msdu.as_slice().to_vec())
}

// 07-5123-08-383-01 + 07-5123-08-2511-01: Toggle from A flips B's
// OnOff; B's Report Attributes carries the new value back to A.
#[test]
fn zcl_onoff_toggle_and_report_two_node() {
    let tsn = 0x61;
    // A builds a client Toggle for B.
    let mut toggle = [0u8; 16];
    let toggle_len = onoff::client::toggle(tsn, &mut toggle).unwrap();
    assert_eq!(&toggle[..toggle_len], &[0x01, tsn, onoff::CMD_TOGGLE]);
    let apdu = encoded_zcl_apdu(onoff::CLUSTER_ID, 0x09, &toggle[..toggle_len]);
    let sent = encoded_npdu(NODE_A, NODE_B, &apdu);

    // A -> medium; B picks up the on-air copy.
    let (_, on_air) = medium_trip(0x21c0, NODE_A, NODE_B, &sent);
    assert_eq!(on_air, sent);
    let npdu = nwk_decode(&on_air).unwrap();
    assert_eq!(npdu.header.dst_addr, NODE_B);
    let aps = rounddance_aps::decode_data(npdu.payload).unwrap();
    assert_eq!(aps.header.cluster_id, onoff::CLUSTER_ID);
    assert_eq!(aps.header.profile_id, HA_PROFILE);
    let (header, payload) = Header::decode(aps.payload).unwrap();
    assert_eq!(header.tsn, tsn);
    assert_eq!(header.command_id, onoff::CMD_TOGGLE);

    // B dispatches the Toggle against a live server (starts off).
    let def = onoff::ServerDef;
    let mut endpoint = Endpoint::new();
    endpoint.add(&def).unwrap();
    let mut store = onoff::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = onoff::ServerBehavior;
    let mut zcl_out = [0u8; 128];
    let mut ctx = Ctx {
        store: &mut store,
        reporting: &mut eng,
        events: &mut events,
        now_s: 0,
        peer_onoff: None,
        sender_ieee: None,
    };
    match rounddance_zcl::dispatch(
        &endpoint,
        Some(&mut beh),
        &mut ctx,
        &header,
        payload,
        onoff::CLUSTER_ID,
        None,
        &[],
        &mut zcl_out,
    )
    .unwrap()
    {
        DispatchOutcome::Silent => {}
        DispatchOutcome::Respond(_) => panic!("toggle sends no reply"),
    }
    assert!(onoff::onoff(&store));

    // B reports the new OnOff value back to A.
    let rep_header = Header::reply_to(&header, general::cmd::REPORT);
    let mut zcl = [0u8; 32];
    let hn = rep_header.encode_into(&mut zcl).unwrap();
    let records = [general::ReportRecord {
        id: onoff::ATTR_ONOFF,
        dtype: rounddance_zcl::DataType::Bool.as_u8(),
        value: rounddance_zcl::Value::Bool(true),
    }];
    let bn = general::encode_report(&records, &mut zcl[hn..]).unwrap();
    let rsp_apdu = encoded_zcl_apdu(onoff::CLUSTER_ID, 0x0a, &zcl[..hn + bn]);
    let rsp_sent = encoded_npdu(NODE_B, NODE_A, &rsp_apdu);

    // B -> medium; A picks up the report.
    let (_, rsp_air) = medium_trip(0x21c1, NODE_B, NODE_A, &rsp_sent);
    let rsp_npdu = nwk_decode(&rsp_air).unwrap();
    assert_eq!(rsp_npdu.header.dst_addr, NODE_A);
    let rsp_aps = rounddance_aps::decode_data(rsp_npdu.payload).unwrap();
    assert_eq!(rsp_aps.header.cluster_id, onoff::CLUSTER_ID);
    let (rep_back, rep_payload) = Header::decode(rsp_aps.payload).unwrap();
    assert_eq!(rep_back.tsn, tsn);
    assert_eq!(rep_back.command_id, general::cmd::REPORT);
    let mut recs = [general::ReportRecord {
        id: 0,
        dtype: 0,
        value: rounddance_zcl::Value::NoData,
    }; 4];
    assert_eq!(general::decode_report(rep_payload, &mut recs).unwrap(), 1);
    assert_eq!(recs[0].id, onoff::ATTR_ONOFF);
    assert_eq!(recs[0].value, rounddance_zcl::Value::Bool(true));
}

// Decision determinism: the same seed + frame bytes yield identical
// traces and identical delivered octets across runs.
#[test]
fn zcl_transaction_replays_deterministically() {
    let tsn = 0x61;
    let mut toggle = [0u8; 16];
    let toggle_len = onoff::client::toggle(tsn, &mut toggle).unwrap();
    let apdu = encoded_zcl_apdu(onoff::CLUSTER_ID, 0x09, &toggle[..toggle_len]);
    let sent = encoded_npdu(NODE_A, NODE_B, &apdu);

    let scripted = |seed: u64| {
        let mut radio = ScriptedRadio::new(
            Seed(seed),
            vec![
                ScriptAction::Delay {
                    base_us: 320,
                    jitter_us: 100,
                },
                ScriptAction::Deliver,
            ],
        );
        radio.reset(true);
        radio.set_channel(Channel::new(15).unwrap()).unwrap();
        radio.set_pan_id(PAN);
        radio.set_short_addr(NODE_A);
        radio
            .data_request(TxRequest {
                dst: MacAddress::short(PAN, NODE_B),
                msdu: FramePayload::from_slice(&sent).expect("NPDU fits one MSDU"),
                options: TxOptions::ACK,
            })
            .expect("queue has room");
        radio.run_until_idle(16);
        let rx = radio
            .poll_indication()
            .expect("delivery implies indication");
        (radio.trace_lines().to_vec(), rx.msdu.as_slice().to_vec())
    };

    let (trace_a, air_a) = scripted(0x21c2);
    let (trace_b, air_b) = scripted(0x21c2);
    assert_eq!(trace_a, trace_b);
    assert_eq!(air_a, air_b);
    assert_eq!(air_a, sent);
}
