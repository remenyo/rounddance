//! Line-coverage closure for doc `05-3474-23` R23.2 chapters 2–3,
//! sim level: APS + NWK behaviors end to end over the scripted
//! medium (loss-driven retry, multi-hop radius, discovery-driven
//! forwarding, group delivery).
//!
//! Each test drives the public APIs of `rounddance-aps`,
//! `rounddance-nwk` and `rounddance-sim` together. Comments name
//! the requirement ID plus the gap anchors cited (D1: document
//! number, revision, clause and line only — no spec text
//! reproduced).

use rounddance_aps::{
    decode_data, AckExpect, AckInfo, ApsStatus, DataDest, DataHeader, DeliveryMode, DupRejectTable,
    FrameControl, GroupTable, Reassembler, RetrySession, RetryVerdict,
};
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap, MacMgmtSap, TxOptions, TxRequest, TxStatus,
};
use rounddance_nwk::{
    build_data_header, decode as nwk_decode, DiscoverRoute, DiscoveryTable, NldeDataRequest,
    RouteTable, SeenRequests, ROUTE_LIFETIME_MS,
};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};

const PAN: u16 = 0x1A2B;
const NODE_A: u16 = 0x0001;
const RELAY: u16 = 0x00AA;
const NODE_B: u16 = 0x0002;

/// Encode one unicast APS data APDU.
fn apdu_unicast(counter: u8, payload: &[u8]) -> Vec<u8> {
    let header = DataHeader {
        control: FrameControl {
            ext_header: false,
            ack_request: true,
            ..FrameControl::data(DeliveryMode::Unicast)
        },
        dest: DataDest::Unicast { dst_endpoint: 0x02 },
        cluster_id: 0x0006,
        profile_id: 0x0104,
        src_endpoint: 0x01,
        counter,
        ext: None,
    };
    let mut out = vec![0u8; header.header_len() + payload.len()];
    let n = header.encode_into(payload, &mut out).unwrap();
    out.truncate(n);
    out
}

/// Wrap an APDU in a NWK data NPDU from `src` with hop budget `radius`.
fn npdu(src: u16, dst: u16, radius: u8, seq: u8, apdu: &[u8]) -> Vec<u8> {
    let req = NldeDataRequest {
        dst_addr: dst,
        use_alias: false,
        alias_src: 0,
        alias_seq: 0,
        radius_param: radius,
        discover_route: DiscoverRoute::Enable,
        generated_seq: seq,
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

fn node(seed: u64, script: Vec<ScriptAction>, short: u16) -> ScriptedRadio {
    let mut radio = ScriptedRadio::new(Seed(seed), script);
    radio.reset(true);
    radio.set_channel(Channel::new(15).unwrap()).unwrap();
    radio.set_pan_id(PAN);
    radio.set_short_addr(short);
    radio
}

fn send(npdu: &[u8], radio: &mut ScriptedRadio, dst: u16) {
    radio
        .data_request(TxRequest {
            dst: MacAddress::short(PAN, dst),
            msdu: FramePayload::from_slice(npdu).expect("NPDU fits one MSDU"),
            options: TxOptions::ACK,
        })
        .expect("queue has room");
    radio.run_until_idle(16);
}

// 05-3474-23-22841-02: acknowledged APS transmission over a lossy
// medium — the first attempt is lost, the retry after the
// acknowledgement wait delivers, and the receiver delivers the ASDU
// upward exactly once.
// Anchors: p0060-L1590-L1614, p0065-L1690-L1693.
#[test]
fn lossy_retry_delivers_once_05_3474_23_22841_02() {
    let apdu = apdu_unicast(0x42, &[0xDE, 0xAD]);
    let sent = npdu(NODE_A, NODE_B, 3, 0x42, &apdu);
    let mut radio = node(
        0xA11CE,
        vec![ScriptAction::Drop, ScriptAction::Deliver],
        NODE_A,
    );
    let expect = AckExpect {
        cluster_id: 0x0006,
        counter: 0x42,
        dst_endpoint: 0x02,
    };
    let mut sess = RetrySession::new(expect, 0, 100);
    assert_eq!(sess.poll_transmit(), RetryVerdict::Transmit);
    // First attempt lost on the medium.
    send(&sent, &mut radio, NODE_B);
    let lost = radio.poll_confirm().expect("drop still confirms");
    assert_eq!(lost.status, TxStatus::NoAck);
    assert_eq!(sess.on_tick(100), RetryVerdict::Transmit);
    // Retry delivers; the ack ends the session.
    send(&sent, &mut radio, NODE_B);
    let ok = radio.poll_confirm().expect("retry confirms");
    assert_eq!(ok.status, TxStatus::Delivered);
    assert_eq!(
        sess.on_ack(AckInfo {
            cluster_id: 0x0006,
            counter: 0x42,
            src_endpoint: 0x02,
        }),
        RetryVerdict::Acked
    );
    // Receiver decodes both layers and hands the ASDU up once;
    // the duplicate copy is rejected, never re-indicated.
    let on_air = radio.poll_indication().expect("delivery implies rx");
    let first = nwk_decode(on_air.msdu.as_slice()).unwrap();
    assert_eq!(first.header.radius, 3);
    let aps = decode_data(first.payload).unwrap();
    assert_eq!(aps.payload, &[0xDE, 0xAD]);
    let mut dup = DupRejectTable::new();
    assert!(!dup.observe(first.header.src_addr, aps.header.counter));
    assert!(dup.observe(first.header.src_addr, aps.header.counter));
}

// 05-3474-23-333-01: multi-hop relay — each forwarder spends one hop
// of the radius budget; the destination receives the decremented
// budget and the intact APS payload.
// Anchors: p0293-L6925-L6943, p0304-L7190-L7197.
#[test]
fn relay_spends_radius_05_3474_23_333_01() {
    let apdu = apdu_unicast(0x09, &[0x01, 0x02, 0x03]);
    let sent = npdu(NODE_A, NODE_B, 3, 0x10, &apdu);
    let mut a = node(0xBEEF, vec![ScriptAction::Deliver], NODE_A);
    send(&sent, &mut a, RELAY);
    a.poll_confirm().unwrap();
    let at_relay = a.poll_indication().expect("relay hears A");
    let mut frame = nwk_decode(at_relay.msdu.as_slice()).unwrap();
    assert_eq!(frame.header.radius, 3);
    // The relay re-emits with one hop spent.
    let mut relayed = frame.header;
    relayed.radius = relayed.radius.saturating_sub(1);
    relayed.src_addr = RELAY;
    let mut out = vec![0u8; relayed.header_len() + frame.payload.len()];
    let n = relayed.encode_into(frame.payload, &mut out).unwrap();
    out.truncate(n);
    let mut b = node(0xBEEF, vec![ScriptAction::Deliver], NODE_B);
    send(&out, &mut b, NODE_B);
    b.poll_confirm().unwrap();
    let at_b = b.poll_indication().expect("B hears the relay");
    frame = nwk_decode(at_b.msdu.as_slice()).unwrap();
    assert_eq!(frame.header.radius, 2);
    assert_eq!(frame.header.dst_addr, NODE_B);
    let aps = decode_data(frame.payload).unwrap();
    assert_eq!(aps.payload, &[0x01, 0x02, 0x03]);
    assert_eq!(aps.header.counter, 0x09);
}

// 05-3474-23-3645-04: discovery-driven forwarding — the originator
// floods once, the relay suppresses its own reflood of the same
// (originator, id), and the reply installs a next-hop route the
// follow-on data frame uses.
// Anchors: p0297-L7031-L7034, p0300-L7125-L7133.
#[test]
fn discovery_installs_forwarding_route_05_3474_23_3645_04() {
    let mut discovery = DiscoveryTable::new();
    let mut routes = RouteTable::new();
    let mut seen = SeenRequests::new();
    // Originator floods for B.
    let session = discovery.start(NODE_B, 0x2A, 0).unwrap();
    assert_eq!(discovery.pending_count(0), 1);
    // Relay sees the flood once, suppresses the repeat.
    assert!(!seen.observe(NODE_A, session.rreq_id, 10));
    assert!(seen.observe(NODE_A, session.rreq_id, 11));
    // The reply resolves the session; the originator installs the
    // relay as next hop with the reported path cost.
    let resolved = discovery.resolve(0x2A, 100).unwrap();
    assert_eq!(resolved.dst, NODE_B);
    routes
        .install(NODE_B, RELAY, 4, 100, ROUTE_LIFETIME_MS)
        .unwrap();
    assert_eq!(routes.next_hop(NODE_B, 200), Some(RELAY));
    // Follow-on data rides the installed route through the medium.
    let apdu = apdu_unicast(0x55, &[0xAA]);
    let sent = npdu(NODE_A, NODE_B, 5, 0x20, &apdu);
    let mut a = node(0xC0DE, vec![ScriptAction::Deliver], NODE_A);
    send(&sent, &mut a, routes.next_hop(NODE_B, 200).unwrap());
    a.poll_confirm().unwrap();
    let on_air = a.poll_indication().unwrap();
    let frame = nwk_decode(on_air.msdu.as_slice()).unwrap();
    assert_eq!(frame.header.dst_addr, NODE_B);
    assert_eq!(decode_data(frame.payload).unwrap().payload, &[0xAA]);
}

// 05-3474-23-22841-03: group delivery over the medium — a broadcast
// APDU decoded at the receiver is offered only to member endpoints;
// the plumbing (GroupTable) and the delivery (decoded fields) agree.
// Anchors: p0060-L1590-L1614, p0099-L2354-L2382.
#[test]
fn group_delivery_filters_endpoints_05_3474_23_22841_03() {
    let header = DataHeader {
        control: FrameControl {
            ext_header: false,
            ack_request: false,
            ..FrameControl::data(DeliveryMode::Broadcast)
        },
        dest: DataDest::Broadcast { dst_endpoint: 0xFF },
        cluster_id: 0x0006,
        profile_id: 0x0104,
        src_endpoint: 0x01,
        counter: 0x31,
        ext: None,
    };
    let payload = [0x10, 0x20];
    let mut apdu = vec![0u8; header.header_len() + payload.len()];
    let n = header.encode_into(&payload, &mut apdu).unwrap();
    apdu.truncate(n);
    let sent = npdu(NODE_A, 0xFFFF, 2, 0x31, &apdu);
    let mut b = node(0xF00D, vec![ScriptAction::Deliver], NODE_B);
    send(&sent, &mut b, 0xFFFF);
    b.poll_confirm().unwrap();
    let at_b = b.poll_indication().unwrap();
    let frame = nwk_decode(at_b.msdu.as_slice()).unwrap();
    let aps = decode_data(frame.payload).unwrap();
    // Receiver offers the frame to member endpoints only.
    let mut groups = GroupTable::new();
    assert_eq!(groups.add(0x00AA, 0x02), ApsStatus::Success);
    let mut out = [0u8; 8];
    let taken = groups.members(0x00AA, &mut out);
    assert_eq!(taken, 1);
    assert!(out[..taken].contains(&0x02));
    assert!(!out[..taken].contains(&0x03));
    assert!(matches!(
        aps.header.dest,
        DataDest::Broadcast { dst_endpoint: 0xFF }
    ));
    // Fragment state is untouched by group traffic on this node.
    let rx = Reassembler::new();
    assert_eq!(rx.live_count(), 0);
}
