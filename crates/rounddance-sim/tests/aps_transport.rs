//! APS payload transport over the NWK codec and the scripted medium.
//!
//! An encoded APS data APDU rides as the NWK payload through
//! `ScriptedRadio`: single-node loopback, a two-node handoff (A's
//! delivered bytes are copied onto the medium for B, modeling one
//! broadcast hop), a fragmented ASDU end-to-end (blocks carried as
//! successive NWK payloads, reassembled on receipt), and deterministic
//! replay of the whole scenario.
//!
//! Requirement traceability: `05-3474-23-22511-16` (data APDU codec),
//! `05-3474-23-22845-05/06` (fragment split/reassembly),
//! `05-3474-23-3211-03/04/05` (NWK header under test),
//! `05-3474-23-22842-02` (duplicate rejection on replayed blocks).

use rounddance_aps::{
    decode_data, plan_transmit, DataDest, DataHeader, ExtHeader, FeedOutcome, Fragmentation,
    FrameControl, PeerFragCaps, Reassembler, TxBlocks, TxPlan,
};
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap, MacMgmtSap, TxOptions, TxRequest, TxStatus,
};
use rounddance_nwk::{build_data_header, decode as nwk_decode, DiscoverRoute, NldeDataRequest};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};

const PAN: u16 = 0x1a2b;
const NODE_A: u16 = 0x0001;
const NODE_B: u16 = 0x0002;

/// Encode one APS data APDU with `payload`; returns the exact on-air
/// octets (unicast A:ep1 -> B:ep2, cluster 0x0006, profile 0x0104).
fn encoded_apdu(counter: u8, ext: Option<ExtHeader>, payload: &[u8]) -> Vec<u8> {
    let header = DataHeader {
        control: FrameControl {
            ext_header: ext.is_some(),
            ack_request: true,
            ..FrameControl::data(rounddance_aps::DeliveryMode::Unicast)
        },
        dest: DataDest::Unicast { dst_endpoint: 0x02 },
        cluster_id: 0x0006,
        profile_id: 0x0104,
        src_endpoint: 0x01,
        counter,
        ext,
    };
    let mut out = vec![0u8; header.header_len() + payload.len()];
    let n = header.encode_into(payload, &mut out).unwrap();
    out.truncate(n);
    out
}

/// Wrap an APDU in a NWK data NPDU; returns the exact on-air octets.
fn encoded_npdu(dst: u16, apdu: &[u8]) -> Vec<u8> {
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
    let mut out = vec![0u8; header.header_len() + apdu.len()];
    let n = header.encode_into(apdu, &mut out).unwrap();
    out.truncate(n);
    out
}

fn loopback_deliver(seed: u64, npdu: &[u8], script: Vec<ScriptAction>) -> (Vec<String>, Vec<u8>) {
    let mut radio = ScriptedRadio::new(Seed(seed), script);
    radio.reset(true);
    radio.set_channel(Channel::new(15).unwrap()).unwrap();
    radio.set_pan_id(PAN);
    radio.set_short_addr(NODE_A);
    let req = TxRequest {
        dst: MacAddress::short(PAN, NODE_B),
        msdu: FramePayload::from_slice(npdu).expect("NPDU fits one MSDU"),
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

// 05-3474-23-22511-16: single-node loopback — the APS APDU inside the
// NWK payload decodes to identical fields on receipt.
#[test]
fn aps_loopback_decodes_identical_fields() {
    let apdu = encoded_apdu(0x42, None, &[0xAA, 0xBB, 0x01, 0x02]);
    let sent = encoded_npdu(NODE_B, &apdu);
    let (trace, received) = loopback_deliver(
        0x1234,
        &sent,
        vec![ScriptAction::Delay {
            base_us: 320,
            jitter_us: 100,
        }],
    );
    assert_eq!(received, sent, "medium preserves octets");
    let npdu = nwk_decode(&received).unwrap();
    assert_eq!(npdu.header.dst_addr, NODE_B);
    let aps = decode_data(npdu.payload).unwrap();
    assert_eq!(aps.header.dest, DataDest::Unicast { dst_endpoint: 0x02 });
    assert_eq!(aps.header.cluster_id, 0x0006);
    assert_eq!(aps.header.profile_id, 0x0104);
    assert_eq!(aps.header.src_endpoint, 0x01);
    assert_eq!(aps.header.counter, 0x42);
    assert_eq!(aps.payload, &[0xAA, 0xBB, 0x01, 0x02]);
    assert!(
        trace
            .iter()
            .any(|l| l.contains("confirm handle=0 status=Delivered")),
        "trace records delivery"
    );
}

// 05-3474-23-22845-05/06: fragmented ASDU end-to-end — the plan splits
// the ASDU, every block rides its own NPDU through the medium, and the
// receiver reassembles the exact octets out of order.
#[test]
fn aps_fragmented_asdu_reassembles_end_to_end() {
    let asdu: Vec<u8> = (0..=119u8).collect();
    let plan = plan_transmit(
        asdu.len(),
        64,
        false,
        true,
        PeerFragCaps {
            known: true,
            can_fragment: true,
            max_rx_asdu: 200,
        },
        32,
    );
    let TxPlan::Fragmented { block_count } = plan else {
        panic!("120-octet ASDU must fragment, got {plan:?}");
    };
    assert_eq!(block_count, 4);

    // Each block rides its own loopback trip through the medium.
    let tx = TxBlocks::new(&asdu, 32).unwrap();
    let mut carried: Vec<Vec<u8>> = Vec::new();
    for i in 0..block_count {
        let (frag, number, payload) = tx.block(i);
        let ext = match frag {
            Fragmentation::First => ExtHeader::first(number),
            Fragmentation::Subsequent => ExtHeader::subsequent(number),
            Fragmentation::Unfragmented => unreachable!(),
        };
        let apdu = encoded_apdu(0x77, Some(ext), payload);
        let sent = encoded_npdu(NODE_B, &apdu);
        let (_, received) =
            loopback_deliver(0x500 + u64::from(i), &sent, vec![ScriptAction::Deliver]);
        carried.push(received);
    }

    // Receiver decodes both layers and feeds reassembly last-to-first
    // (blocks may arrive in any order).
    let mut rx = Reassembler::new();
    let mut done = None;
    for npdu_bytes in carried.iter().rev() {
        let npdu = nwk_decode(npdu_bytes).unwrap();
        let aps = decode_data(npdu.payload).unwrap();
        let ext = aps.header.ext.expect("fragmented frames carry ext");
        let outcome = rx
            .feed(
                npdu.header.src_addr,
                aps.header.counter,
                ext.frag,
                ext.block_number.unwrap(),
                aps.payload,
                1000,
            )
            .unwrap();
        match outcome {
            FeedOutcome::Complete { len } => done = Some(len),
            FeedOutcome::InProgress => {}
            FeedOutcome::Duplicate => panic!("no repeats fed"),
        }
    }
    assert_eq!(done, Some(asdu.len()));
    assert_eq!(rx.assembled(), Some(asdu.as_slice()));

    // 05-3474-23-22842-02: replaying a block of a live transaction
    // is a duplicate, not a second delivery.
    let mut rx2 = Reassembler::new();
    let replay = nwk_decode(&carried[3]).unwrap();
    let replay_aps = decode_data(replay.payload).unwrap();
    let replay_ext = replay_aps.header.ext.unwrap();
    let feed_replay = |rx: &mut Reassembler, now: u64| {
        rx.feed(
            replay.header.src_addr,
            replay_aps.header.counter,
            replay_ext.frag,
            replay_ext.block_number.unwrap(),
            replay_aps.payload,
            now,
        )
    };
    assert_eq!(feed_replay(&mut rx2, 1), Ok(FeedOutcome::InProgress));
    assert_eq!(feed_replay(&mut rx2, 2), Ok(FeedOutcome::Duplicate));
}

// Two-node handoff: A's broadcast APDU is copied off A's loopback
// inbox onto B's radio; B decodes identical fields.
#[test]
fn aps_two_node_broadcast_handoff() {
    let mut control = FrameControl::data(rounddance_aps::DeliveryMode::Broadcast);
    control.ack_request = false;
    let header = DataHeader {
        control,
        dest: DataDest::Broadcast { dst_endpoint: 0xFF },
        cluster_id: 0x0006,
        profile_id: 0x0104,
        src_endpoint: 0x01,
        counter: 0x09,
        ext: None,
    };
    let payload = [0x01, 0x02, 0x03];
    let mut apdu = vec![0u8; header.header_len() + payload.len()];
    let n = header.encode_into(&payload, &mut apdu).unwrap();
    apdu.truncate(n);
    let sent = encoded_npdu(0xFFFF, &apdu);

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

    let npdu = nwk_decode(at_b.msdu.as_slice()).unwrap();
    assert_eq!(npdu.header.dst_addr, 0xFFFF);
    let aps = decode_data(npdu.payload).unwrap();
    assert_eq!(aps.header.dest, DataDest::Broadcast { dst_endpoint: 0xFF });
    assert_eq!(aps.payload, payload.as_slice());
}

// Decision determinism: the same seed + script + APDU yields identical
// traces across runs.
#[test]
fn aps_scenario_replays_deterministically() {
    let apdu = encoded_apdu(0x42, None, &[0xDE, 0xAD, 0xBE, 0xEF]);
    let sent = encoded_npdu(NODE_B, &apdu);
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
    let npdu = nwk_decode(&second_rx).unwrap();
    assert_eq!(
        decode_data(npdu.payload).unwrap().payload,
        &[0xDE, 0xAD, 0xBE, 0xEF]
    );
}
