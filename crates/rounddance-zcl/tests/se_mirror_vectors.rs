//! Wire vectors for metering mirrors + snapshots (cluster 0x0702).
//!
//! Each test names the requirement ID it verifies. Byte strings are
//! hand-computed from the paraphrased layouts in `mirror.rs` /
//! `snapshot.rs` (docs `07-5123-08` §10.4 and `17-05019-012`
//! §10.4) — never copied from spec text (D1, `SCOPE.md` §2).
//! Corpus-mined IDs are reused verbatim; repo-minted IDs are
//! MINTED-pending-confirm.

use rounddance_zcl::behavior::{Behavior, Ctx, EventQueue};
use rounddance_zcl::frame::{Direction, FrameControl, FrameType, Header};
use rounddance_zcl::{metering, mirror, snapshot, ReportingEngine, ZclStatus};

// ---- mirror codecs -------------------------------------------------

// 07-5123-08-1044-04: endpoint carriers are 2-octet LE values.
#[test]
fn vector_mirror_endpoint_codec_07_5123_08_1044_04() {
    let mut out = [0u8; 4];
    assert_eq!(mirror::encode_mirror_endpoint(0x0005, &mut out), Ok(2));
    assert_eq!(&out[..2], &[0x05, 0x00]);
    assert_eq!(mirror::decode_mirror_endpoint(&out[..2]), Ok(0x0005));
    assert_eq!(
        mirror::decode_mirror_endpoint(&mirror::ENDPOINT_REFUSED.to_le_bytes()),
        Ok(0xFFFF)
    );
    assert!(mirror::decode_mirror_endpoint(&out[..1]).is_err());
    assert!(mirror::decode_mirror_endpoint(&out[..3]).is_err());
    assert!(mirror::encode_mirror_endpoint(0x0001, &mut out[..1]).is_err());
    assert!(mirror::endpoint_is_grantable(0x0001));
    assert!(mirror::endpoint_is_grantable(0x00F0));
    assert!(!mirror::endpoint_is_grantable(0x0000));
    assert!(!mirror::endpoint_is_grantable(0x00F1));
    assert!(!mirror::endpoint_is_grantable(0xFFFF));
}

// 07-5123-08-1044-01: setup commands carry empty bodies.
#[test]
fn vector_empty_setup_codec_07_5123_08_1044_01() {
    let mut out = [0xAAu8; 2];
    assert_eq!(mirror::encode_empty_setup(&mut out), Ok(0));
    assert!(mirror::decode_empty_setup(&[]).is_ok());
    assert!(mirror::decode_empty_setup(&[0x00]).is_err());
}

// 07-5123-08-1044-03: report body is scheme + LE flag words.
#[test]
fn vector_mirror_report_codec_07_5123_08_1044_03() {
    let report = mirror::MirrorReport {
        scheme: 0x02,
        flags: {
            let mut f = [0u32; mirror::MAX_NOTIFICATION_FLAGS];
            f[0] = 0x0000_0005;
            f[1] = 0xAABB_CCDD;
            f
        },
        count: 2,
    };
    let mut out = [0u8; 16];
    assert_eq!(mirror::encode_mirror_report(&report, &mut out), Ok(9));
    assert_eq!(
        &out[..9],
        &[0x02, 0x05, 0x00, 0x00, 0x00, 0xDD, 0xCC, 0xBB, 0xAA]
    );
    let mut back = mirror::MirrorReport::new(0xFF);
    mirror::decode_mirror_report(&out[..9], &mut back).unwrap();
    assert_eq!(back.scheme, 0x02);
    assert_eq!(back.count, 2);
    assert_eq!(back.flags[0], 0x0000_0005);
    assert_eq!(back.flags[1], 0xAABB_CCDD);
    // Empty body and ragged tails are rejected.
    let mut junk = mirror::MirrorReport::new(0);
    assert!(mirror::decode_mirror_report(&[], &mut junk).is_err());
    assert!(mirror::decode_mirror_report(&[0x01, 0x02, 0x03], &mut junk).is_err());
    // More than the bounded maximum is a field error, never grown.
    let mut big = [0u8; 1 + 4 * (mirror::MAX_NOTIFICATION_FLAGS + 1)];
    big[0] = 0x01;
    assert!(mirror::decode_mirror_report(&big, &mut junk).is_err());
    let mut small = [0u8; 2];
    assert!(mirror::encode_mirror_report(&report, &mut small).is_err());
}

// ---- mirror table --------------------------------------------------

// 07-5123-08-1044-05: grants are idempotent; a full table refuses.
#[test]
fn vector_mirror_table_grants_07_5123_08_1044_05() {
    let mut table = mirror::MirrorTable::new();
    assert!(table.is_empty());
    assert!(table.has_capacity());
    let first = table.request(0x1111_2222_3333_4444);
    assert_eq!(first, 0x0001);
    assert_eq!(table.len(), 1);
    // Same meter re-requests: same endpoint, no duplicate slot.
    assert_eq!(table.request(0x1111_2222_3333_4444), 0x0001);
    assert_eq!(table.len(), 1);
    assert_eq!(table.endpoint_for(0x1111_2222_3333_4444), Some(0x0001));
    let e2 = table.request(0xAAAA);
    let e3 = table.request(0xBBBB);
    let e4 = table.request(0xCCCC);
    assert_eq!((e2, e3, e4), (0x0002, 0x0003, 0x0004));
    assert!(!table.has_capacity());
    assert_eq!(table.request(0xDDDD), mirror::ENDPOINT_REFUSED);
    assert_eq!(table.len(), mirror::MAX_MIRRORS);
}

// 07-5123-08-1044-05: removal rules (unknown / wrong meter / ESI).
#[test]
fn vector_mirror_table_remove_07_5123_08_1044_05() {
    use mirror::ReleaseRequester::{Esi, Meter};
    let mut table = mirror::MirrorTable::new();
    let ep = table.request(0x1111);
    assert_eq!(table.remove(0x00F0, Esi), Err(ZclStatus::NotFound));
    assert_eq!(
        table.remove(ep, Meter(0x2222)),
        Err(ZclStatus::NotAuthorized)
    );
    assert_eq!(table.remove(ep, Meter(0x1111)), Ok(ep));
    assert_eq!(table.len(), 0);
    // ESI-side release needs no meter identity.
    let ep2 = table.request(0x3333);
    assert_eq!(ep2, 0x0002);
    assert_eq!(table.remove(ep2, Esi), Ok(ep2));
    assert!(table.is_empty());
}

// 17-05019-012-423-01: only the granted meter may push.
#[test]
fn vector_mirror_push_gate_17_05019_012_423_01() {
    let mut table = mirror::MirrorTable::new();
    let ep = table.request(0x1111);
    assert!(table.may_push(ep, 0x1111).is_ok());
    assert_eq!(table.may_push(ep, 0x2222), Err(ZclStatus::NotAuthorized));
    assert_eq!(table.may_push(0x00F0, 0x1111), Err(ZclStatus::NotFound));
}

// 17-05019-012-423-01: supported-but-empty vs unsupported split.
#[test]
fn vector_mirror_readiness_17_05019_012_423_01() {
    use mirror::AttrReadiness as R;
    assert_eq!(R::classify(true, true), R::Ready);
    assert_eq!(R::classify(true, false), R::Empty);
    assert_eq!(R::classify(false, false), R::Unsupported);
    assert_eq!(R::classify(false, true), R::Unsupported);
    assert_eq!(R::Ready.status(), ZclStatus::Success);
    // Empty maps to NOT_FOUND (corpus term ATTRIBUTE_UNAVAILABLE —
    // the closest receipt-side status in this crate's set).
    assert_eq!(R::Empty.status(), ZclStatus::NotFound);
    assert_eq!(R::Unsupported.status(), ZclStatus::UnsupportedAttribute);
}

// ---- meter-side mirror record --------------------------------------

// 07-5123-08-1044-02: grant / refusal / removal record keeping.
#[test]
fn vector_mirror_client_record_07_5123_08_1044_02() {
    let mut client = mirror::MirrorClient::new();
    assert_eq!(client.granted(), None);
    client.on_response(0x0007).unwrap();
    assert_eq!(client.granted(), Some(0x0007));
    // Refusal clears the grant.
    client.on_response(mirror::ENDPOINT_REFUSED).unwrap();
    assert_eq!(client.granted(), None);
    // Reserved values are field errors, never grants.
    assert_eq!(client.on_response(0x00F1), Err(ZclStatus::InvalidField));
    assert_eq!(client.granted(), None);
    client.on_response(0x0003).unwrap();
    // Another endpoint's removal is ignored; ours clears.
    client.on_removed(0x0004);
    assert_eq!(client.granted(), Some(0x0003));
    client.on_removed(0x0003);
    assert_eq!(client.granted(), None);
}

// 07-5123-08-1044-03: waiting-flag intake.
#[test]
fn vector_mirror_client_report_07_5123_08_1044_03() {
    let mut client = mirror::MirrorClient::new();
    let mut flags = [0u32; mirror::MAX_NOTIFICATION_FLAGS];
    flags[0] = 0x0000_0011;
    flags[2] = 0x2200_0000;
    let report = mirror::MirrorReport {
        scheme: 0x01,
        flags,
        count: 3,
    };
    assert_eq!(client.on_report(&report), 3);
    assert_eq!(client.report().scheme, 0x01);
    assert_eq!(client.report().flags[2], 0x2200_0000);
}

// ---- meter behavior wiring -----------------------------------------

/// Handler context over a fresh metering store.
fn ctx_for<'a>(
    store: &'a mut rounddance_zcl::AttrStore,
    eng: &'a mut ReportingEngine,
    events: &'a mut EventQueue,
    now_s: u64,
) -> Ctx<'a> {
    Ctx {
        store,
        reporting: eng,
        events,
        now_s,
        peer_onoff: None,
        sender_ieee: None,
    }
}

fn hdr(cmd: u8) -> Header {
    Header {
        control: FrameControl {
            frame_type: FrameType::ClusterSpecific,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x20,
        command_id: cmd,
    }
}

// 07-5123-08-1044-01: the meter emits empty setup commands.
#[test]
fn vector_meter_setup_outbound_07_5123_08_1044_01() {
    use rounddance_zcl::behavior::AppEvent;
    let mut store = metering::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = metering::ServerBehavior::new();
    beh.request_mirror(&mut ctx_for(&mut store, &mut eng, &mut events, 0));
    beh.remove_mirror(&mut ctx_for(&mut store, &mut eng, &mut events, 0));
    match events.pop() {
        Some(AppEvent::OutboundCommand { cmd, len, .. }) => {
            assert_eq!(cmd, mirror::CMD_REQUEST_MIRROR);
            assert_eq!(len, 0);
        }
        other => panic!("expected request-mirror, got {other:?}"),
    }
    match events.pop() {
        Some(AppEvent::OutboundCommand { cmd, len, .. }) => {
            assert_eq!(cmd, mirror::CMD_REMOVE_MIRROR);
            assert_eq!(len, 0);
        }
        other => panic!("expected remove-mirror, got {other:?}"),
    }
    // Empty setup bodies decode on the ESI side.
    assert!(mirror::decode_empty_setup(&[]).is_ok());
}

// 07-5123-08-1044-02: the meter records grants and removals.
#[test]
fn vector_meter_grant_intake_07_5123_08_1044_02() {
    use rounddance_zcl::behavior::AppEvent;
    let mut store = metering::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = metering::ServerBehavior::new();
    let ep = 0x0009u16.to_le_bytes();
    let outcome = <metering::ServerBehavior as Behavior>::handle_cluster_command(
        &mut beh,
        &mut ctx_for(&mut store, &mut eng, &mut events, 0),
        &hdr(mirror::CMD_REQUEST_MIRROR_RESPONSE),
        mirror::CMD_REQUEST_MIRROR_RESPONSE,
        &ep,
    )
    .unwrap();
    assert!(outcome.reply_cmd.is_none());
    assert_eq!(beh.mirror_client().granted(), Some(0x0009));
    match events.pop() {
        Some(AppEvent::StateChanged { from, to, .. }) => assert_eq!((from, to), (0, 1)),
        other => panic!("expected grant state change, got {other:?}"),
    }
    // Malformed bodies never latch a grant.
    let bad = <metering::ServerBehavior as Behavior>::handle_cluster_command(
        &mut beh,
        &mut ctx_for(&mut store, &mut eng, &mut events, 0),
        &hdr(mirror::CMD_REQUEST_MIRROR_RESPONSE),
        mirror::CMD_REQUEST_MIRROR_RESPONSE,
        &[0x09],
    );
    assert_eq!(bad, Err(ZclStatus::MalformedCommand));
    assert_eq!(beh.mirror_client().granted(), Some(0x0009));
    // Removal clears the grant.
    <metering::ServerBehavior as Behavior>::handle_cluster_command(
        &mut beh,
        &mut ctx_for(&mut store, &mut eng, &mut events, 0),
        &hdr(mirror::CMD_MIRROR_REMOVED),
        mirror::CMD_MIRROR_REMOVED,
        &ep,
    )
    .unwrap();
    assert_eq!(beh.mirror_client().granted(), None);
}

// 07-5123-08-1044-03: waiting flags land in the meter record.
#[test]
fn vector_meter_report_intake_07_5123_08_1044_03() {
    use rounddance_zcl::behavior::AppEvent;
    let mut store = metering::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = metering::ServerBehavior::new();
    let body = [0x01, 0x11, 0x00, 0x00, 0x00];
    <metering::ServerBehavior as Behavior>::handle_cluster_command(
        &mut beh,
        &mut ctx_for(&mut store, &mut eng, &mut events, 0),
        &hdr(mirror::CMD_MIRROR_REPORT_ATTR_RESPONSE),
        mirror::CMD_MIRROR_REPORT_ATTR_RESPONSE,
        &body,
    )
    .unwrap();
    assert_eq!(beh.mirror_client().report().scheme, 0x01);
    assert_eq!(beh.mirror_client().report().count, 1);
    match events.pop() {
        Some(AppEvent::StateChanged { from, to, .. }) => assert_eq!((from, to), (2, 1)),
        other => panic!("expected flag state change, got {other:?}"),
    }
    let bad = <metering::ServerBehavior as Behavior>::handle_cluster_command(
        &mut beh,
        &mut ctx_for(&mut store, &mut eng, &mut events, 0),
        &hdr(mirror::CMD_MIRROR_REPORT_ATTR_RESPONSE),
        mirror::CMD_MIRROR_REPORT_ATTR_RESPONSE,
        &[0x01, 0x02],
    );
    assert_eq!(bad, Err(ZclStatus::MalformedCommand));
}

// ---- snapshot codecs -----------------------------------------------

// 07-5123-08-1045-01: TakeSnapshot is a 4-octet cause map.
#[test]
fn vector_take_snapshot_codec_07_5123_08_1045_01() {
    let req = snapshot::TakeSnapshot { cause: 0x0000_0401 };
    let mut out = [0u8; 6];
    assert_eq!(snapshot::encode_take_snapshot(&req, &mut out), Ok(4));
    assert_eq!(&out[..4], &[0x01, 0x04, 0x00, 0x00]);
    assert_eq!(snapshot::decode_take_snapshot(&out[..4]).unwrap(), req);
    assert!(snapshot::decode_take_snapshot(&out[..3]).is_err());
    assert!(snapshot::decode_take_snapshot(&out[..5]).is_err());
    assert!(snapshot::encode_take_snapshot(&req, &mut out[..3]).is_err());
    // Response is id + verdict.
    let rsp = snapshot::TakeSnapshotResponse {
        snapshot_id: 0x1234_5678,
        confirmation: snapshot::CONFIRM_ACCEPTED,
    };
    let mut body = [0u8; 6];
    assert_eq!(
        snapshot::encode_take_snapshot_response(&rsp, &mut body),
        Ok(5)
    );
    assert_eq!(&body[..5], &[0x78, 0x56, 0x34, 0x12, 0x00]);
    assert_eq!(
        snapshot::decode_take_snapshot_response(&body[..5]).unwrap(),
        rsp
    );
    assert!(snapshot::decode_take_snapshot_response(&body[..4]).is_err());
}

// 17-05019-012-423-02: GetSnapshot is window + offset + cause.
#[test]
fn vector_get_snapshot_codec_17_05019_012_423_02() {
    let req = snapshot::GetSnapshot {
        earliest: 0x1111_1111,
        latest: 0x2222_2222,
        offset: 0x03,
        cause: snapshot::CAUSE_ALL,
    };
    let mut out = [0u8; 16];
    assert_eq!(snapshot::encode_get_snapshot(&req, &mut out), Ok(13));
    assert_eq!(
        &out[..13],
        &[0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x03, 0xFF, 0xFF, 0xFF, 0xFF]
    );
    assert_eq!(snapshot::decode_get_snapshot(&out[..13]).unwrap(), req);
    assert!(snapshot::decode_get_snapshot(&out[..12]).is_err());
    assert!(snapshot::decode_get_snapshot(&out[..14]).is_err());
    assert!(snapshot::encode_get_snapshot(&req, &mut out[..12]).is_err());
}

// 07-5123-08-1045-02: publish header + bounded sub-payload.
#[test]
fn vector_publish_snapshot_codec_07_5123_08_1045_02() {
    let hdr = snapshot::PublishSnapshot {
        snapshot_id: 0x0102_0304,
        snapshot_time: 0x0506_0708,
        total_found: 2,
        command_index: 0,
        total_commands: 1,
        cause: 0x0000_0401,
        payload_type: snapshot::PAYLOAD_TOU_DELIVERED,
    };
    let sub = [0xAAu8, 0xBB, 0xCC];
    let mut out = [0u8; 32];
    assert_eq!(
        snapshot::encode_publish_snapshot(&hdr, &sub, &mut out),
        Ok(19)
    );
    assert_eq!(
        &out[..16],
        &[
            0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x02, 0x00, 0x01, 0x01, 0x04, 0x00,
            0x00, 0x00
        ]
    );
    assert_eq!(&out[16..19], &[0xAA, 0xBB, 0xCC]);
    let back = snapshot::decode_publish_snapshot(&out[..19]).unwrap();
    assert_eq!(back.header, hdr);
    assert_eq!(back.sub_len, 3);
    assert_eq!(&back.sub[..3], &sub);
    assert!(snapshot::decode_publish_snapshot(&out[..15]).is_err());
    let mut too_big = [0u8; snapshot::MAX_SNAPSHOT_SUB + 1];
    too_big[0] = 0x01;
    assert!(snapshot::encode_publish_snapshot(&hdr, &too_big, &mut [0u8; 128]).is_err());
}

// 07-5123-08-1045-02: typed TOU sub-payload exact bytes.
#[test]
fn vector_tou_sub_payload_07_5123_08_1045_02() {
    let mut out = [0u8; 64];
    let n = snapshot::encode_tou_sub_payload(
        0x0102_0304_0506,
        0x1122_3344,
        0x5566_7788,
        0x99AA_BBCC,
        0xDDEE_FF00,
        0x40,
        &[0x0000_0000_0007, 0x0809_0A0B_0C0D],
        &mut out,
    )
    .unwrap();
    assert_eq!(n, 36);
    assert_eq!(
        &out[..36],
        &[
            0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // summation uint48
            0x44, 0x33, 0x22, 0x11, // bill to date
            0x88, 0x77, 0x66, 0x55, // bill stamp
            0xCC, 0xBB, 0xAA, 0x99, // projected bill
            0x00, 0xFF, 0xEE, 0xDD, // projected stamp
            0x40, // trailing digit
            0x02, // tier count
            0x07, 0x00, 0x00, 0x00, 0x00, 0x00, // tier 1
            0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, // tier 2
        ]
    );
    // Tier tails beyond the bound are refused, never truncated.
    let many = [0u64; snapshot::MAX_SNAPSHOT_TIERS + 1];
    assert!(snapshot::encode_tou_sub_payload(0, 0, 0, 0, 0, 0, &many, &mut out).is_err());
    assert!(snapshot::encode_tou_sub_payload(0, 0, 0, 0, 0, 0, &[], &mut out[..23]).is_err());
}

// ---- snapshot store ------------------------------------------------

// 07-5123-08-1045-04 + 17-05019-012-423-02: take, window, offset,
// cause filter, NOT_FOUND, eviction.
#[test]
fn vector_snapshot_store_take_query_07_5123_08_1045_04() {
    let mut store = snapshot::SnapshotStore::new();
    assert!(store.is_empty());
    let sub_a = [0xA1u8];
    let sub_b = [0xB2u8];
    let (id0, conf0) = store.take(1000, 1 << snapshot::CAUSE_MANUAL_BIT, 0, &sub_a);
    assert_eq!((id0, conf0), (0, snapshot::CONFIRM_ACCEPTED));
    let (id1, conf1) = store.take(2000, 1 << snapshot::CAUSE_SCHEDULED_BIT, 0, &sub_b);
    assert_eq!((id1, conf1), (1, snapshot::CONFIRM_ACCEPTED));
    assert_eq!(store.len(), 2);
    // First match in take order; offset selects the next.
    let first = store.query(0, 3000, 0, snapshot::CAUSE_ALL).unwrap();
    assert_eq!((first.id, first.sub_len), (0, 1));
    let second = store.query(0, 3000, 1, snapshot::CAUSE_ALL).unwrap();
    assert_eq!(second.id, 1);
    assert!(store.query(0, 3000, 2, snapshot::CAUSE_ALL).is_err());
    // Window edges: [earliest, latest).
    assert_eq!(store.query(0, 3000, 0, snapshot::CAUSE_ALL).unwrap().id, 0);
    assert_eq!(
        store.query(2000, 3000, 0, snapshot::CAUSE_ALL).unwrap().id,
        1
    );
    assert!(store.query(2001, 3000, 0, snapshot::CAUSE_ALL).is_err());
    assert!(store.query(0, 1000, 0, snapshot::CAUSE_ALL).is_err());
    // Cause filter overlaps; unknown causes miss.
    assert_eq!(
        store
            .query(0, 3000, 0, 1 << snapshot::CAUSE_SCHEDULED_BIT)
            .unwrap()
            .id,
        1
    );
    assert_eq!(
        store.query(0, 3000, 0, 1 << snapshot::CAUSE_TARIFF_CHANGE_BIT),
        Err(ZclStatus::NotFound)
    );
    // Unsupported cause bits store nothing.
    let (bad_id, bad_conf) = store.take(3000, 1 << 20, 0, &sub_a);
    assert_eq!(bad_conf, snapshot::CONFIRM_CAUSE_NOT_SUPPORTED);
    assert_eq!(bad_id, 0);
    assert_eq!(store.len(), 2);
    // Fill past capacity: oldest evicted, ids stay consecutive.
    let mut i = 0;
    while i < snapshot::MAX_SNAPSHOTS {
        store.take(4000 + i as u32, 1, 0, &sub_a);
        i += 1;
    }
    assert_eq!(store.len(), snapshot::MAX_SNAPSHOTS);
    let oldest = store.query(0, 5000, 0, snapshot::CAUSE_ALL).unwrap();
    assert!(oldest.id > 1);
    assert_eq!(
        store.match_count(0, 5000, snapshot::CAUSE_ALL) as usize,
        snapshot::MAX_SNAPSHOTS
    );
}

// 07-5123-08-1045-03: tariff-change takes land as before/after pairs.
#[test]
fn vector_snapshot_take_pair_07_5123_08_1045_03() {
    let mut store = snapshot::SnapshotStore::new();
    let cause = (1 << snapshot::CAUSE_TARIFF_CHANGE_BIT) | (1 << snapshot::CAUSE_MANUAL_BIT);
    let (ids, conf) = store.take_pair(
        5000,
        cause,
        snapshot::PAYLOAD_TOU_DELIVERED,
        &[0x01],
        &[0x02],
    );
    assert_eq!(conf, snapshot::CONFIRM_ACCEPTED);
    assert_eq!(ids, [0, 1]);
    assert_eq!(store.len(), 2);
    assert_eq!(
        store
            .query(0, 6000, 0, snapshot::CAUSE_ALL)
            .unwrap()
            .sub_payload(),
        &[0x01]
    );
    assert_eq!(
        store
            .query(0, 6000, 1, snapshot::CAUSE_ALL)
            .unwrap()
            .sub_payload(),
        &[0x02]
    );
    // Unsupported pair causes refuse without storing.
    let (bad_ids, bad_conf) = store.take_pair(6000, 1 << 31, 0, &[0x01], &[0x02]);
    assert_eq!(bad_conf, snapshot::CONFIRM_CAUSE_NOT_SUPPORTED);
    assert_eq!(bad_ids, [0, 0]);
    assert_eq!(store.len(), 2);
}

// ---- meter behavior snapshot legs ----------------------------------

// 07-5123-08-1045-01: TakeSnapshot receipt takes, stamps the manual
// bit, and answers id + accepted.
#[test]
fn vector_meter_take_snapshot_07_5123_08_1045_01() {
    let mut store = metering::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = metering::ServerBehavior::new();
    beh.add_consumption(&mut store, 0x0102_0304_0506);
    let mut req = [0u8; 4];
    snapshot::encode_take_snapshot(&snapshot::TakeSnapshot { cause: 1 << 1 }, &mut req).unwrap();
    let outcome = <metering::ServerBehavior as Behavior>::handle_cluster_command(
        &mut beh,
        &mut ctx_for(&mut store, &mut eng, &mut events, 9_000),
        &hdr(snapshot::CMD_TAKE_SNAPSHOT),
        snapshot::CMD_TAKE_SNAPSHOT,
        &req,
    )
    .unwrap();
    assert_eq!(
        outcome.reply_cmd,
        Some(snapshot::CMD_TAKE_SNAPSHOT_RESPONSE)
    );
    let rsp =
        snapshot::decode_take_snapshot_response(&outcome.reply_body[..outcome.reply_len as usize])
            .unwrap();
    assert_eq!(
        rsp,
        snapshot::TakeSnapshotResponse {
            snapshot_id: 0,
            confirmation: snapshot::CONFIRM_ACCEPTED,
        }
    );
    // Manual bit folded in; stored sub-payload carries the live sum.
    let snap = beh
        .snapshots()
        .query(0, 10_000, 0, snapshot::CAUSE_ALL)
        .unwrap();
    assert_eq!(snap.time, 9_000);
    assert_eq!(snap.cause, (1 << 1) | (1 << snapshot::CAUSE_MANUAL_BIT));
    assert_eq!(
        &snap.sub_payload()[..6],
        &[0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
    );
    // Malformed bodies are refused without taking.
    let bad = <metering::ServerBehavior as Behavior>::handle_cluster_command(
        &mut beh,
        &mut ctx_for(&mut store, &mut eng, &mut events, 9_001),
        &hdr(snapshot::CMD_TAKE_SNAPSHOT),
        snapshot::CMD_TAKE_SNAPSHOT,
        &req[..3],
    );
    assert_eq!(bad, Err(ZclStatus::MalformedCommand));
    assert_eq!(beh.snapshots().len(), 1);
}

// 07-5123-08-1045-01: unsupported take causes answer refusal.
#[test]
fn vector_meter_take_unsupported_07_5123_08_1045_01() {
    let mut store = metering::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = metering::ServerBehavior::new();
    let mut req = [0u8; 4];
    snapshot::encode_take_snapshot(&snapshot::TakeSnapshot { cause: 1 << 20 }, &mut req).unwrap();
    let outcome = <metering::ServerBehavior as Behavior>::handle_cluster_command(
        &mut beh,
        &mut ctx_for(&mut store, &mut eng, &mut events, 9_000),
        &hdr(snapshot::CMD_TAKE_SNAPSHOT),
        snapshot::CMD_TAKE_SNAPSHOT,
        &req,
    )
    .unwrap();
    let rsp =
        snapshot::decode_take_snapshot_response(&outcome.reply_body[..outcome.reply_len as usize])
            .unwrap();
    assert_eq!(rsp.confirmation, snapshot::CONFIRM_CAUSE_NOT_SUPPORTED);
    assert!(beh.snapshots().is_empty());
}

// 17-05019-012-423-02: GetSnapshot answers one snapshot or NOT_FOUND.
#[test]
fn vector_meter_get_snapshot_17_05019_012_423_02() {
    let mut store = metering::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = metering::ServerBehavior::new();
    // Empty store answers NOT_FOUND, never an empty publish.
    let mut req = [0u8; 13];
    snapshot::encode_get_snapshot(
        &snapshot::GetSnapshot {
            earliest: 0,
            latest: 0xFFFF_FFFF,
            offset: 0,
            cause: snapshot::CAUSE_ALL,
        },
        &mut req,
    )
    .unwrap();
    let miss = <metering::ServerBehavior as Behavior>::handle_cluster_command(
        &mut beh,
        &mut ctx_for(&mut store, &mut eng, &mut events, 0),
        &hdr(snapshot::CMD_GET_SNAPSHOT),
        snapshot::CMD_GET_SNAPSHOT,
        &req,
    );
    assert_eq!(miss, Err(ZclStatus::NotFound));
    // Take two, then fetch the second by offset.
    beh.snapshots_mut().take(1000, 1 << 1, 0, &[0xAA]);
    beh.snapshots_mut().take(2000, 1 << 1, 0, &[0xBB]);
    snapshot::encode_get_snapshot(
        &snapshot::GetSnapshot {
            earliest: 0,
            latest: 0xFFFF_FFFF,
            offset: 1,
            cause: snapshot::CAUSE_ALL,
        },
        &mut req,
    )
    .unwrap();
    let outcome = <metering::ServerBehavior as Behavior>::handle_cluster_command(
        &mut beh,
        &mut ctx_for(&mut store, &mut eng, &mut events, 0),
        &hdr(snapshot::CMD_GET_SNAPSHOT),
        snapshot::CMD_GET_SNAPSHOT,
        &req,
    )
    .unwrap();
    assert_eq!(outcome.reply_cmd, Some(snapshot::CMD_PUBLISH_SNAPSHOT));
    let decoded =
        snapshot::decode_publish_snapshot(&outcome.reply_body[..outcome.reply_len as usize])
            .unwrap();
    assert_eq!(decoded.header.snapshot_id, 1);
    assert_eq!(decoded.header.snapshot_time, 2000);
    assert_eq!(decoded.header.total_found, 2);
    assert_eq!(decoded.header.command_index, 0);
    assert_eq!(decoded.header.total_commands, 1);
    assert_eq!(decoded.sub_len, 1);
    assert_eq!(decoded.sub[0], 0xBB);
}
