//! ZDP transaction over the scripted medium: a `Node_Desc_req` rides
//! an APS data APDU (ZDP profile, endpoint 0x00) inside an NWK data
//! NPDU from node A to node B; B answers with `Node_Desc_rsp`, and the
//! whole exchange replays deterministically.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `05-3474-23-24311-03` (request),
//! `05-3474-23-24423-01` + `05-3474-23-2323-01` (response + descriptor),
//! `SCOPE.md` §8 (decision determinism).

use rounddance_aps::{DataDest, DataHeader, DeliveryMode, FrameControl};
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap as _, MacMgmtSap as _, TxOptions, TxRequest,
    TxStatus,
};
use rounddance_nwk::{build_data_header, decode as nwk_decode, DiscoverRoute, NldeDataRequest};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};
use rounddance_zdo::*;

const PAN: u16 = 0x1a2b;
const NODE_A: u16 = 0x0001;
const NODE_B: u16 = 0x0002;
const ZDP_PROFILE: u16 = 0x0000;

/// Wrap ZDP octets in an APS data APDU on the ZDO endpoint pair.
fn encoded_zdp_apdu(cluster: u16, counter: u8, zdp: &[u8]) -> Vec<u8> {
    let header = DataHeader {
        control: FrameControl {
            ack_request: true,
            ..FrameControl::data(DeliveryMode::Unicast)
        },
        dest: DataDest::Unicast { dst_endpoint: 0x00 },
        cluster_id: cluster,
        profile_id: ZDP_PROFILE,
        src_endpoint: 0x00,
        counter,
        ext: None,
    };
    let mut out = vec![0u8; header.header_len() + zdp.len()];
    let n = header.encode_into(zdp, &mut out).unwrap();
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

fn node_b_descriptor() -> NodeDescriptor {
    NodeDescriptor {
        flags0: 0x01, // router
        aps_flags: 0x00,
        freq_band: 0x04,
        mac_cap: 0x8E,
        mfr_code: 0x1234,
        max_buf: 82,
        max_in_transfer: 82,
        server_mask: 0x0000,
        max_out_transfer: 82,
        desc_cap: 0x00,
    }
}

// 05-3474-23-24311-03 + 05-3474-23-24423-01: Node_Desc_req from A is
// decoded by B; B's Node_Desc_rsp echoes tsn + interest address and
// carries B's descriptor, decoded by A.
#[test]
fn zdo_node_desc_transaction_two_node() {
    let tsn = 0x51;
    // A builds the request for B's network address.
    let req = NodeDescReq {
        tsn,
        nwk_of_interest: NODE_B,
    };
    let mut req_bytes = [0u8; 8];
    let req_len = req.encode_into(&mut req_bytes).unwrap();
    let apdu = encoded_zdp_apdu(CLUSTER_NODE_DESC_REQ, 0x07, &req_bytes[..req_len]);
    let sent = encoded_npdu(NODE_A, NODE_B, &apdu);

    // A -> medium; B picks up the on-air copy.
    let (_, on_air) = medium_trip(0x2D0, NODE_A, NODE_B, &sent);
    assert_eq!(on_air, sent);
    let npdu = nwk_decode(&on_air).unwrap();
    assert_eq!(npdu.header.dst_addr, NODE_B);
    let aps = rounddance_aps::decode_data(npdu.payload).unwrap();
    assert_eq!(aps.header.cluster_id, CLUSTER_NODE_DESC_REQ);
    assert_eq!(aps.header.profile_id, ZDP_PROFILE);
    let seen_req = NodeDescReq::decode(aps.payload).unwrap();
    assert_eq!(seen_req.tsn, tsn);
    assert_eq!(seen_req.nwk_of_interest, NODE_B);

    // B answers from its local descriptor.
    let rsp = NodeDescRsp {
        tsn: seen_req.tsn,
        status: ZdpStatus::Success,
        nwk_of_interest: seen_req.nwk_of_interest,
        descriptor: Some(node_b_descriptor()),
        tlvs: &[],
    };
    let mut rsp_bytes = [0u8; 32];
    let rsp_len = rsp.encode_into(&mut rsp_bytes).unwrap();
    let rsp_apdu = encoded_zdp_apdu(
        CLUSTER_NODE_DESC_REQ | RESPONSE_BIT,
        0x08,
        &rsp_bytes[..rsp_len],
    );
    assert_eq!(
        rounddance_zdo::response_cluster(CLUSTER_NODE_DESC_REQ),
        Some(CLUSTER_NODE_DESC_REQ | RESPONSE_BIT)
    );
    let rsp_sent = encoded_npdu(NODE_B, NODE_A, &rsp_apdu);

    // B -> medium; A picks up the answer.
    let (_, rsp_air) = medium_trip(0x2D1, NODE_B, NODE_A, &rsp_sent);
    let rsp_npdu = nwk_decode(&rsp_air).unwrap();
    assert_eq!(rsp_npdu.header.dst_addr, NODE_A);
    let rsp_aps = rounddance_aps::decode_data(rsp_npdu.payload).unwrap();
    assert_eq!(
        rsp_aps.header.cluster_id,
        CLUSTER_NODE_DESC_REQ | RESPONSE_BIT
    );
    let seen_rsp = NodeDescRsp::decode(rsp_aps.payload).unwrap();
    assert_eq!(seen_rsp.tsn, tsn);
    assert!(seen_rsp.status.is_success());
    assert_eq!(seen_rsp.nwk_of_interest, NODE_B);
    assert_eq!(seen_rsp.descriptor.unwrap(), node_b_descriptor());
}

// Decision determinism: the same seed + request bytes yield identical
// traces and identical delivered octets across runs.
#[test]
fn zdo_transaction_replays_deterministically() {
    let req = NodeDescReq {
        tsn: 0x51,
        nwk_of_interest: NODE_B,
    };
    let mut req_bytes = [0u8; 8];
    let req_len = req.encode_into(&mut req_bytes).unwrap();
    let apdu = encoded_zdp_apdu(CLUSTER_NODE_DESC_REQ, 0x07, &req_bytes[..req_len]);
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
                msdu: FramePayload::from_slice(&sent).expect("fits"),
                options: TxOptions::ACK,
            })
            .expect("room");
        radio.run_until_idle(16);
        let rx = radio
            .poll_indication()
            .expect("delivery")
            .msdu
            .as_slice()
            .to_vec();
        (radio.trace_lines().to_vec(), rx)
    };
    let (first_trace, first_rx) = scripted(0xBEAD);
    let (second_trace, second_rx) = scripted(0xBEAD);
    assert_eq!(first_trace, second_trace);
    assert_eq!(first_rx, second_rx);
    assert_eq!(first_rx, sent);
}
