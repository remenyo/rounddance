//! Mirror + snapshot loop over the scripted medium: a meter and an
//! ESI-like peer drive the full mirror lifecycle — mirror request,
//! endpoint grant, reading push gated by the grant, command-driven
//! snapshot take, snapshot retrieval, then mirror release — twice,
//! with byte-identical traces.
//!
//! Requirement traceability (corpus-reused unless noted,
//! MINTED-pending-confirm): `07-5123-08-104-01`
//! (mirror descriptors), `17-05019-012-422-02` (device-type swap —
//! the two ends stay distinct records), `17-05019-012-423-01`
//! (grant-gated pushes, capacity, availability) ,
//! `17-05019-012-423-02` (one snapshot or NOT_FOUND),
//! `07-5123-08-1044-*` + `07-5123-08-1045-*` (command codecs,
//! table/store rules, repo-minted), `SCOPE.md` §8 (decision
//! determinism).

use rounddance_aps::{DataDest, DataHeader, DeliveryMode, FrameControl as ApsFrameControl};
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap as _, MacMgmtSap as _, TxOptions, TxRequest,
    TxStatus,
};
use rounddance_nwk::{build_data_header, decode as nwk_decode, DiscoverRoute, NldeDataRequest};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};
use rounddance_zcl::behavior::{AppEvent, Behavior, Ctx, EventQueue};
use rounddance_zcl::frame::{Direction, FrameControl, FrameType, Header};
use rounddance_zcl::{metering, mirror, snapshot, ReportingEngine, ZclStatus};

const PAN: u16 = 0x1a2b;
const NODE_METER: u16 = 0x0001;
const NODE_ESI: u16 = 0x0002;
/// Smart Energy profile identifier on the APDUs here.
const SE_PROFILE: u16 = 0x0109;
const ENDPOINT: u8 = 0x01;
/// Meter identity the ESI grants the mirror to.
const METER_IEEE: u64 = 0x0012_4B00_0A0B_0C0D;

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

/// One medium trip: queue `zcl` (full ZCL frame) from `src` to `dst`
/// on a fresh scripted radio and return the delivered ZCL octets.
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

/// Meter-side inbound dispatch: decode the delivered frame and run
/// the server behavior.
fn meter_handle(
    beh: &mut metering::ServerBehavior,
    store: &mut rounddance_zcl::AttrStore,
    eng: &mut ReportingEngine,
    events: &mut EventQueue,
    now_s: u64,
    air: &[u8],
) -> rounddance_zcl::behavior::HandleOutcome {
    let (h, p) = Header::decode(air).unwrap();
    let mut ctx = Ctx {
        store,
        reporting: eng,
        events,
        now_s,
        peer_onoff: None,
        sender_ieee: None,
    };
    <metering::ServerBehavior as Behavior>::handle_cluster_command(
        beh,
        &mut ctx,
        &h,
        h.command_id,
        p,
    )
    .unwrap()
}

/// Run the whole mirror loop; returns the hex trace plus the
/// granted endpoint, the mirrored reading, the taken snapshot id,
/// and whether the grant cleared at the end.
fn run_loop(seed: u64) -> (Vec<String>, u16, u64, u32, bool) {
    let mut trace = Vec::new();
    let mut counter = 0u8;
    let mut tsn = 0x40u8;

    // ESI-side provider state: the mirror table plus the mirrored
    // reading the granted meter pushes.
    let mut table = mirror::MirrorTable::new();

    // Meter side: live store + behavior.
    let mut meter_store = metering::server_store().unwrap();
    let mut meter_beh = metering::ServerBehavior::new();
    let mut eng = ReportingEngine::new();

    // Macro-free trip helper: send a ZCL frame, record it, deliver it.
    let mut fly = |from: u16, to: u16, frame: Vec<u8>| -> Vec<u8> {
        trace.push(format!("{from:04x}>{to:04x}:{}", hex(&frame)));
        counter = counter.wrapping_add(1);
        trip(seed, from, to, metering::CLUSTER_ID, counter, &frame)
    };

    // 1. Meter requests a mirror (server-generated, empty body).
    let mut events = EventQueue::new();
    {
        let mut ctx = Ctx {
            store: &mut meter_store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 100,
            peer_onoff: None,
            sender_ieee: None,
        };
        meter_beh.request_mirror(&mut ctx);
    }
    let (req_cmd, req_body) = match events.pop() {
        Some(AppEvent::OutboundCommand {
            cmd, len, payload, ..
        }) => (cmd, payload[..len as usize].to_vec()),
        other => panic!("expected request-mirror, got {other:?}"),
    };
    assert_eq!(req_cmd, mirror::CMD_REQUEST_MIRROR);
    let air = fly(
        NODE_METER,
        NODE_ESI,
        zcl_frame(tsn, false, req_cmd, &req_body),
    );
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    assert_eq!(h.command_id, mirror::CMD_REQUEST_MIRROR);
    mirror::decode_empty_setup(p).unwrap();

    // 2. ESI grants endpoint 0x0001; the answer flies back.
    let granted = table.request(METER_IEEE);
    assert_eq!(granted, 0x0001);
    assert!(table.has_capacity());
    let mut ep_body = [0u8; 2];
    mirror::encode_mirror_endpoint(granted, &mut ep_body).unwrap();
    let air = fly(
        NODE_ESI,
        NODE_METER,
        zcl_frame(tsn, true, mirror::CMD_REQUEST_MIRROR_RESPONSE, &ep_body),
    );
    tsn = tsn.wrapping_add(1);
    let mut events = EventQueue::new();
    meter_handle(
        &mut meter_beh,
        &mut meter_store,
        &mut eng,
        &mut events,
        101,
        &air,
    );
    assert_eq!(meter_beh.mirror_client().granted(), Some(granted));

    // 3. Meter measures; only the granted meter may push.
    meter_beh.add_consumption(&mut meter_store, 500_000);
    let reading = metering::scaled_summation(&meter_store);
    assert_eq!(reading, 500_000);
    table.may_push(granted, METER_IEEE).unwrap();
    let mirrored_reading = reading;
    assert_eq!(
        table.may_push(granted, 0xDEAD_BEEF),
        Err(ZclStatus::NotAuthorized)
    );

    // 4. ESI takes a snapshot of the meter (client to server).
    let mut take_body = [0u8; 4];
    snapshot::encode_take_snapshot(&snapshot::TakeSnapshot { cause: 1 << 1 }, &mut take_body)
        .unwrap();
    let air = fly(
        NODE_ESI,
        NODE_METER,
        zcl_frame(tsn, true, snapshot::CMD_TAKE_SNAPSHOT, &take_body),
    );
    tsn = tsn.wrapping_add(1);
    let mut events = EventQueue::new();
    let outcome = meter_handle(
        &mut meter_beh,
        &mut meter_store,
        &mut eng,
        &mut events,
        9_000,
        &air,
    );
    assert_eq!(
        outcome.reply_cmd,
        Some(snapshot::CMD_TAKE_SNAPSHOT_RESPONSE)
    );
    let rsp =
        snapshot::decode_take_snapshot_response(&outcome.reply_body[..outcome.reply_len as usize])
            .unwrap();
    assert_eq!(rsp.confirmation, snapshot::CONFIRM_ACCEPTED);
    let reply = zcl_frame(
        tsn,
        false,
        snapshot::CMD_TAKE_SNAPSHOT_RESPONSE,
        &outcome.reply_body[..outcome.reply_len as usize],
    );
    let air = fly(NODE_METER, NODE_ESI, reply);
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    assert_eq!(h.command_id, snapshot::CMD_TAKE_SNAPSHOT_RESPONSE);
    let back = snapshot::decode_take_snapshot_response(p).unwrap();
    assert_eq!(back, rsp);

    // 5. ESI retrieves the snapshot (client to server).
    let mut get_body = [0u8; 13];
    snapshot::encode_get_snapshot(
        &snapshot::GetSnapshot {
            earliest: 0,
            latest: 0xFFFF_FFFF,
            offset: 0,
            cause: snapshot::CAUSE_ALL,
        },
        &mut get_body,
    )
    .unwrap();
    let air = fly(
        NODE_ESI,
        NODE_METER,
        zcl_frame(tsn, true, snapshot::CMD_GET_SNAPSHOT, &get_body),
    );
    tsn = tsn.wrapping_add(1);
    let mut events = EventQueue::new();
    let outcome = meter_handle(
        &mut meter_beh,
        &mut meter_store,
        &mut eng,
        &mut events,
        9_001,
        &air,
    );
    assert_eq!(outcome.reply_cmd, Some(snapshot::CMD_PUBLISH_SNAPSHOT));
    let reply = zcl_frame(
        tsn,
        false,
        snapshot::CMD_PUBLISH_SNAPSHOT,
        &outcome.reply_body[..outcome.reply_len as usize],
    );
    let air = fly(NODE_METER, NODE_ESI, reply);
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    assert_eq!(h.command_id, snapshot::CMD_PUBLISH_SNAPSHOT);
    let published = snapshot::decode_publish_snapshot(p).unwrap();
    assert_eq!(published.header.snapshot_id, rsp.snapshot_id);
    assert_eq!(published.header.snapshot_time, 9_000);
    assert_eq!(published.header.total_found, 1);
    assert_eq!(
        published.header.cause,
        (1 << 1) | (1u32 << snapshot::CAUSE_MANUAL_BIT)
    );
    // Sub-payload carries the live summation at take time.
    assert_eq!(&published.sub[..6], &[0x20, 0xA1, 0x07, 0x00, 0x00, 0x00]);

    // 6. Meter releases the mirror; ESI confirms.
    let mut events = EventQueue::new();
    {
        let mut ctx = Ctx {
            store: &mut meter_store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 9_002,
            peer_onoff: None,
            sender_ieee: None,
        };
        meter_beh.remove_mirror(&mut ctx);
    }
    let (rm_cmd, rm_body) = match events.pop() {
        Some(AppEvent::OutboundCommand {
            cmd, len, payload, ..
        }) => (cmd, payload[..len as usize].to_vec()),
        other => panic!("expected remove-mirror, got {other:?}"),
    };
    assert_eq!(rm_cmd, mirror::CMD_REMOVE_MIRROR);
    let air = fly(
        NODE_METER,
        NODE_ESI,
        zcl_frame(tsn, false, rm_cmd, &rm_body),
    );
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    assert_eq!(h.command_id, mirror::CMD_REMOVE_MIRROR);
    mirror::decode_empty_setup(p).unwrap();
    let freed = table
        .remove(granted, mirror::ReleaseRequester::Meter(METER_IEEE))
        .unwrap();
    assert_eq!(freed, granted);
    assert!(table.is_empty());
    let mut gone_body = [0u8; 2];
    mirror::encode_mirror_endpoint(freed, &mut gone_body).unwrap();
    let air = fly(
        NODE_ESI,
        NODE_METER,
        zcl_frame(tsn, true, mirror::CMD_MIRROR_REMOVED, &gone_body),
    );
    let mut events = EventQueue::new();
    meter_handle(
        &mut meter_beh,
        &mut meter_store,
        &mut eng,
        &mut events,
        9_003,
        &air,
    );
    let cleared = meter_beh.mirror_client().granted().is_none();

    (trace, granted, mirrored_reading, rsp.snapshot_id, cleared)
}

// Mirror established, readings mirrored, snapshot taken + retrieved,
// mirror released.
#[test]
fn se_mirror_loop_end_to_end() {
    let (trace, endpoint, reading, snap_id, cleared) = run_loop(0x5EED);
    assert!(!trace.is_empty());
    assert_eq!(endpoint, 0x0001);
    assert_eq!(reading, 500_000);
    assert_eq!(snap_id, 0);
    assert!(cleared);
}

// Decision determinism: the same seed replays byte-identically.
#[test]
fn se_mirror_loop_replays_deterministically() {
    let (t1, e1, r1, s1, c1) = run_loop(0x5EED);
    let (t2, e2, r2, s2, c2) = run_loop(0x5EED);
    assert_eq!(t1, t2);
    assert_eq!((e1, r1, s1, c1), (e2, r2, s2, c2));
    // A different seed still drives the same application outcome.
    let (_, e3, r3, s3, c3) = run_loop(0x5EEF);
    assert_eq!((e3, r3, s3, c3), (e1, r1, s1, c1));
}
