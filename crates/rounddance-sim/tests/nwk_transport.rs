//! NWK frame transport over the scripted medium.
//!
//! Encoded NWK frames ride as MAC MSDUs through `ScriptedRadio`:
//! single-node loopback and a two-node handoff (A's delivered bytes are
//! copied onto the medium for B, modeling one broadcast hop). Decoded
//! fields are asserted on receipt, and the whole scenario replays
//! deterministically.
//!
//! Requirement traceability: `05-3474-23-3213-01` (inbound indication
//! path), `05-3474-23-3211-03/04/05` (header construction under test),
//! `05-3474-23-366-01` (broadcast delivery).

use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap, MacMgmtSap, TxOptions, TxRequest, TxStatus,
};
use rounddance_nwk::{build_data_header, decode, DiscoverRoute, NldeDataRequest};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};

const PAN: u16 = 0x1a2b;
const NODE_A: u16 = 0x0001;
const NODE_B: u16 = 0x0002;

/// Build a data NPDU for `dst` and encode it with `payload`; returns the
/// exact on-air octets.
fn encoded_npdu(dst: u16, payload: &[u8]) -> Vec<u8> {
    let req = NldeDataRequest {
        dst_addr: dst,
        use_alias: false,
        alias_src: 0,
        alias_seq: 0,
        radius_param: 3,
        discover_route: DiscoverRoute::Enable,
        generated_seq: 0x42,
        local_short_addr: NODE_A,
        max_depth: 5,
        associated: true,
    };
    let header = build_data_header(&req).unwrap();
    let mut out = vec![0u8; header.header_len() + payload.len()];
    let n = header.encode_into(payload, &mut out).unwrap();
    out.truncate(n);
    out
}

fn loopback_deliver(seed: u64, msdu: &[u8], script: Vec<ScriptAction>) -> (Vec<String>, Vec<u8>) {
    let mut radio = ScriptedRadio::new(Seed(seed), script);
    radio.reset(true);
    radio.set_channel(Channel::new(15).unwrap()).unwrap();
    radio.set_pan_id(PAN);
    radio.set_short_addr(NODE_A);
    let req = TxRequest {
        dst: MacAddress::short(PAN, NODE_B),
        msdu: FramePayload::from_slice(msdu).expect("NPDU fits one MSDU"),
        options: TxOptions::ACK,
    };
    radio.data_request(req).expect("queue has room");
    radio.run_until_idle(16);
    let confirm = radio.poll_confirm().expect("script always confirms");
    assert_eq!(confirm.status, TxStatus::Delivered);
    let rx = radio
        .poll_indication()
        .expect("delivery implies indication");
    (radio.trace_lines().to_vec(), rx.msdu.as_slice().to_vec())
}

// 05-3474-23-3213-01: single-node loopback — encoded frame goes through
// the scripted medium and decodes to identical fields.
#[test]
fn nwk_loopback_decodes_identical_fields() {
    let payload = [0xAA, 0xBB, 0x01, 0x02];
    let sent = encoded_npdu(NODE_B, &payload);
    let (trace, received) = loopback_deliver(
        0x1234,
        &sent,
        vec![ScriptAction::Delay {
            base_us: 320,
            jitter_us: 100,
        }],
    );
    assert_eq!(received, sent, "medium preserves octets");
    let decoded = decode(&received).unwrap();
    assert_eq!(decoded.header.dst_addr, NODE_B);
    assert_eq!(decoded.header.src_addr, NODE_A);
    assert_eq!(decoded.header.radius, 3);
    assert_eq!(decoded.header.seq, 0x42);
    assert_eq!(decoded.header.control.discover_route, DiscoverRoute::Enable);
    assert_eq!(decoded.payload, payload.as_slice());
    assert!(
        trace
            .iter()
            .any(|l| l.contains("confirm handle=0 status=Delivered")),
        "trace records delivery"
    );
}

// 05-3474-23-366-01: two-node handoff — A's broadcast NPDU is copied off
// A's loopback inbox onto B's radio; B decodes identical fields.
#[test]
fn nwk_two_node_broadcast_handoff() {
    let payload = [0x01, 0x02, 0x03];
    let sent = encoded_npdu(0xFFFF, &payload);

    let mut node_a = ScriptedRadio::new(Seed(7), vec![ScriptAction::Deliver]);
    node_a.reset(true);
    node_a.set_pan_id(PAN);
    node_a.set_short_addr(NODE_A);
    node_a
        .data_request(TxRequest {
            dst: MacAddress::short(PAN, 0xFFFF),
            msdu: FramePayload::from_slice(&sent).expect("fits"),
            options: TxOptions::NONE,
        })
        .expect("room");
    node_a.run_until_idle(8);
    let on_air = node_a.poll_indication().expect("A loopback = on-air copy");

    // The medium hands the identical octets to B.
    let mut node_b = ScriptedRadio::new(Seed(7), vec![ScriptAction::Deliver]);
    node_b.reset(true);
    node_b.set_pan_id(PAN);
    node_b.set_short_addr(NODE_B);
    node_b
        .data_request(TxRequest {
            dst: MacAddress::short(PAN, NODE_B),
            msdu: FramePayload::from_slice(on_air.msdu.as_slice()).expect("fits"),
            options: TxOptions::NONE,
        })
        .expect("room");
    node_b.run_until_idle(8);
    let at_b = node_b.poll_indication().expect("B receives the copy");
    assert_eq!(at_b.msdu.as_slice(), sent.as_slice());

    let decoded = decode(at_b.msdu.as_slice()).unwrap();
    assert_eq!(decoded.header.dst_addr, 0xFFFF);
    assert_eq!(decoded.header.src_addr, NODE_A);
    assert_eq!(decoded.payload, payload.as_slice());
    assert!(
        rounddance_nwk::indication_for_local(decoded.header.dst_addr, NODE_B, true),
        "broadcast accepted by non-destination node"
    );
}

// Decision determinism: the same seed + script + NPDU yields identical
// traces across runs.
#[test]
fn nwk_scenario_replays_deterministically() {
    let sent = encoded_npdu(NODE_B, &[0xDE, 0xAD, 0xBE, 0xEF]);
    let script = || {
        vec![
            ScriptAction::Delay {
                base_us: 320,
                jitter_us: 100,
            },
            ScriptAction::MaybeDrop { percent: 50 },
            ScriptAction::Deliver,
        ]
    };
    let (first_trace, first_rx) = loopback_deliver(0xBEEF, &sent, script());
    let (second_trace, second_rx) = loopback_deliver(0xBEEF, &sent, script());
    assert_eq!(first_trace, second_trace);
    assert_eq!(first_rx, second_rx);
    assert_eq!(
        decode(&second_rx).unwrap().payload,
        &[0xDE, 0xAD, 0xBE, 0xEF]
    );
}

// 05-3474-23-3213-01 + 05-3474-23-3211-03/04/05 + 05-3474-23-366-01
// (matrix): NWK loopback transport is timing-independent. Four seeds
// incl. the 0/u64::MAX edges — per-seed double runs replay the
// identical trace + wire, and every seed preserves the exact octets
// end to end with identical decoded fields (same timing-vs-decision
// split as the secured-transport matrix: Delay jitter moves
// `queued_us` timestamps, never the header/payload decision — the
// naive cross-seed trace pin fails on those timestamps only). The
// jitter-only script matches the loopback functional precedent; the
// MaybeDrop leg stays per-seed-only under
// `nwk_scenario_replays_deterministically` because drop decisions
// diverge cross-seed by design.
#[test]
fn nwk_transport_matrix_seeds_share_wire_and_fields() {
    use DiscoverRoute::Enable;
    const SEEDS: [u64; 4] = [0x0000, 0x1234, 0xBEEF, u64::MAX];
    const PAYLOAD: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
    let script = || {
        vec![ScriptAction::Delay {
            base_us: 320,
            jitter_us: 100,
        }]
    };
    for &seed in &SEEDS {
        let sent = encoded_npdu(NODE_B, PAYLOAD);
        let (trace_a, rx_a) = loopback_deliver(seed, &sent, script());
        let (trace_b, rx_b) = loopback_deliver(seed, &sent, script());
        assert_eq!(trace_a, trace_b, "per-seed trace replay, seed {seed:#x}");
        assert_eq!(rx_a, rx_b, "per-seed wire replay, seed {seed:#x}");
        assert_eq!(rx_a, sent, "medium preserves octets, seed {seed:#x}");
        assert!(
            trace_a
                .iter()
                .any(|l| l.contains("confirm handle=0 status=Delivered")),
            "trace records delivery, seed {seed:#x}"
        );
        let decoded = decode(&rx_a).unwrap();
        assert_eq!(
            decoded.header.dst_addr, NODE_B,
            "nwk dst pin, seed {seed:#x}"
        );
        assert_eq!(
            decoded.header.src_addr, NODE_A,
            "nwk src pin, seed {seed:#x}"
        );
        assert_eq!(decoded.header.radius, 3, "nwk radius pin, seed {seed:#x}");
        assert_eq!(decoded.header.seq, 0x42, "nwk seq pin, seed {seed:#x}");
        assert_eq!(
            decoded.header.control.discover_route, Enable,
            "nwk discover-route pin, seed {seed:#x}"
        );
        assert_eq!(
            decoded.payload, PAYLOAD,
            "cross-seed payload pin, seed {seed:#x}"
        );
    }
}
