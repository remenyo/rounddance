//! Price block-period loop over the scripted medium: a meter
//! recovers its block schedule after a reset (Get Block Period(s)
//! → PublishBlockPeriod answers) and fetches its block thresholds
//! (GetBlockThresholds → PublishBlockThresholds) — twice, with
//! byte-identical traces.
//!
//! Requirement traceability (corpus-mined 102-01/02/03 + 104-02
//! reused; codec/table/store rows repo-minted,
//! MINTED-pending-confirm): `07-5123-08-1023-01/02`
//! (block-period + threshold queries with NOT_FOUND when empty),
//! `07-5123-08-1025-01/02` (block codec + backlog with
//! supersession + cancel), `07-5123-08-1026-01` (threshold codec
//! + newest-wins store), `SCOPE.md` §8 (decision determinism).

use rounddance_aps::{DataDest, DataHeader, DeliveryMode, FrameControl as ApsFrameControl};
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap as _, MacMgmtSap as _, TxOptions, TxRequest,
    TxStatus,
};
use rounddance_nwk::{build_data_header, decode as nwk_decode, DiscoverRoute, NldeDataRequest};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};
use rounddance_zcl::behavior::{AppEvent, Behavior, Ctx, EventQueue};
use rounddance_zcl::frame::{Direction, FrameControl, FrameType, Header};
use rounddance_zcl::{price, ReportingEngine};

const PAN: u16 = 0x1a2b;
const NODE_METER: u16 = 0x0001;
const NODE_TC: u16 = 0x0002;
/// Smart Energy profile identifier on the APDUs here.
const SE_PROFILE: u16 = 0x0109;
const ENDPOINT: u8 = 0x01;

/// Wrap ZCL octets in an APS data APDU.
fn encoded_zcl_apdu(cluster: u16, counter: u8, zcl: &[u8]) -> Vec<u8> {
    let header = DataHeader {
        control: ApsFrameControl {
            ack_request: true,
            ..ApsFrameControl::data(DeliveryMode::Unicast)
        },
        dest: DataDest::Unicast {
            dst_endpoint: ENDPOINT,
        },
        cluster_id: cluster,
        profile_id: SE_PROFILE,
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

/// One medium trip: queue `zcl` (full ZCL frame) from `src` to
/// `dst` on a fresh scripted radio and return the delivered ZCL
/// octets.
fn trip(seed: u64, src: u16, dst: u16, cluster: u16, counter: u8, zcl: &[u8]) -> Vec<u8> {
    let apdu = encoded_zcl_apdu(cluster, counter, zcl);
    let npdu = encoded_npdu(src, dst, &apdu);
    let mut radio = ScriptedRadio::new(Seed(seed), vec![ScriptAction::Deliver]);
    radio.reset(true);
    radio.set_channel(Channel::new(15).unwrap()).unwrap();
    radio.set_pan_id(PAN);
    radio.set_short_addr(src);
    radio
        .data_request(TxRequest {
            dst: MacAddress::short(PAN, dst),
            msdu: FramePayload::from_slice(&npdu).expect("NPDU fits one MSDU"),
            options: TxOptions::ACK,
        })
        .expect("queue has room");
    radio.run_until_idle(16);
    let confirm = radio.poll_confirm().expect("script always confirms");
    assert_eq!(confirm.status, TxStatus::Delivered);
    let rx = radio
        .poll_indication()
        .expect("delivery implies indication");
    let on_air = rx.msdu.as_slice().to_vec();
    let parsed = nwk_decode(&on_air).unwrap();
    assert_eq!(parsed.header.dst_addr, dst);
    let aps = rounddance_aps::decode_data(parsed.payload).unwrap();
    assert_eq!(aps.header.cluster_id, cluster);
    aps.payload.to_vec()
}

/// Wrap a cluster command payload in a ZCL frame.
fn zcl_frame(tsn: u8, to_server: bool, cmd: u8, payload: &[u8]) -> Vec<u8> {
    let header = Header {
        control: FrameControl {
            frame_type: FrameType::ClusterSpecific,
            manufacturer_specific: false,
            direction: if to_server {
                Direction::ToServer
            } else {
                Direction::ToClient
            },
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn,
        command_id: cmd,
    };
    let mut out = vec![0u8; 8 + payload.len()];
    let n = header.encode_into(&mut out).unwrap();
    out[n..n + payload.len()].copy_from_slice(payload);
    out.truncate(n + payload.len());
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn period(provider: u32, issuer: u32, start: u32, duration: u32) -> price::BlockPeriod {
    price::BlockPeriod {
        provider_id: provider,
        issuer_event_id: issuer,
        start_time: start,
        duration,
        control: 0x01,
        duration_type: 0x20,
        tariff_type: 0x00,
        tariff_resolution: 0x00,
    }
}

/// Run the whole block loop once; returns the hex trace plus the
/// meter-observed period and first threshold.
fn run_loop(seed: u64) -> (Vec<String>, price::BlockPeriod, u64) {
    let mut trace = Vec::new();
    let mut counter = 0u8;
    let mut tsn = 0x70u8;

    let mut fly = |from: u16, to: u16, frame: Vec<u8>| -> Vec<u8> {
        trace.push(format!("{from:04x}>{to:04x}:{}", hex(&frame)));
        counter = counter.wrapping_add(1);
        trip(seed, from, to, price::CLUSTER_ID, counter, &frame)
    };

    // Trust-center price server: two block periods (current +
    // upcoming) plus one threshold set.
    let mut tc_store = price::server_store().unwrap();
    let mut tc_beh = price::ServerBehavior::new();
    tc_beh
        .blocks_mut()
        .insert(period(0x1122_3344, 10, 0x1000_0000, 60));
    tc_beh
        .blocks_mut()
        .insert(period(0x1122_3344, 11, 0x1000_0e10, 60));
    let twire: [u8; 32] = [
        0x44, 0x33, 0x22, 0x11, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x55, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x22, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00,
        0x00, 0x00,
    ];
    let tmsg = price::decode_publish_block_thresholds(&twire).unwrap();
    tc_beh.thresholds_insert(&tmsg);
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();

    // 1. Meter recovers after reset: Get Block Period(s), no cap.
    let air = fly(
        NODE_METER,
        NODE_TC,
        zcl_frame(
            tsn,
            true,
            price::CMD_GET_BLOCK_PERIODS,
            &[0x00, 0x00, 0x00, 0x00, 0x00],
        ),
    );
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    assert_eq!(h.command_id, price::CMD_GET_BLOCK_PERIODS);
    {
        let mut ctx = Ctx {
            store: &mut tc_store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 0x1000_0000,
            peer_onoff: None,
            sender_ieee: None,
        };
        <price::ServerBehavior as Behavior>::handle_cluster_command(
            &mut tc_beh,
            &mut ctx,
            &h,
            h.command_id,
            p,
        )
        .unwrap();
    }
    // Both periods answer, current first.
    let mut answers = Vec::new();
    while let Some(ev) = events.pop() {
        if let AppEvent::OutboundCommand {
            cmd, len, payload, ..
        } = ev
        {
            assert_eq!(cmd, price::CMD_PUBLISH_BLOCK_PERIOD);
            answers.push(payload[..len as usize].to_vec());
        }
    }
    assert_eq!(answers.len(), 2);
    let first = price::decode_publish_block_period(&answers[0]).unwrap();
    let second = price::decode_publish_block_period(&answers[1]).unwrap();
    assert_eq!(first.issuer_event_id, 10);
    assert_eq!(second.issuer_event_id, 11);
    // Each answer flies back to the meter and decodes cleanly.
    for body in &answers {
        let back = fly(
            NODE_TC,
            NODE_METER,
            zcl_frame(tsn, false, price::CMD_PUBLISH_BLOCK_PERIOD, body),
        );
        tsn = tsn.wrapping_add(1);
        let (h2, p2) = Header::decode(&back).unwrap();
        assert_eq!(h2.command_id, price::CMD_PUBLISH_BLOCK_PERIOD);
        price::decode_publish_block_period(p2).unwrap();
    }

    // 2. Meter fetches thresholds for its tariff.
    let air = fly(
        NODE_METER,
        NODE_TC,
        zcl_frame(
            tsn,
            true,
            price::CMD_GET_BLOCK_THRESHOLDS,
            &[0x55, 0x00, 0x00, 0x00],
        ),
    );
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    {
        let mut ctx = Ctx {
            store: &mut tc_store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 0x1000_0000,
            peer_onoff: None,
            sender_ieee: None,
        };
        <price::ServerBehavior as Behavior>::handle_cluster_command(
            &mut tc_beh,
            &mut ctx,
            &h,
            h.command_id,
            p,
        )
        .unwrap();
    }
    let threshold_body = match events.pop().unwrap() {
        AppEvent::OutboundCommand {
            cmd, len, payload, ..
        } => {
            assert_eq!(cmd, price::CMD_PUBLISH_BLOCK_THRESHOLDS);
            payload[..len as usize].to_vec()
        }
        _ => panic!("expected threshold answer"),
    };
    let back = fly(
        NODE_TC,
        NODE_METER,
        zcl_frame(
            tsn,
            false,
            price::CMD_PUBLISH_BLOCK_THRESHOLDS,
            &threshold_body,
        ),
    );
    let (h2, p2) = Header::decode(&back).unwrap();
    assert_eq!(h2.command_id, price::CMD_PUBLISH_BLOCK_THRESHOLDS);
    let got = price::decode_publish_block_thresholds(p2).unwrap();
    assert_eq!(got.sets[0].values[0], 1000);
    // Scaled against the meter's multiplier/divisor pair.
    let scaled = price::scaled_threshold(got.sets[0].values[0], 1, 1000);

    (trace, first, scaled)
}

// Block schedule recovery runs twice with a byte-identical trace.
#[test]
fn se_block_loop_replays_identically() {
    let (t1, first1, scaled1) = run_loop(0xb10c);
    let (t2, first2, scaled2) = run_loop(0xb10c);
    assert_eq!(t1, t2);
    assert!(!t1.is_empty());
    assert_eq!(first1, first2);
    assert_eq!(first1.issuer_event_id, 10);
    assert_eq!(scaled1, scaled2);
    assert_eq!(scaled1, 1);
}
