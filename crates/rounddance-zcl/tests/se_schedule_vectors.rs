//! Wire vectors for metering schedule/sampling/supply (cluster
//! 0x0702): timetable codecs + table rules, sampled-data codecs +
//! session engine rules, and supply codecs + machine rules, each
//! wired through `metering::ServerBehavior`.
//!
//! Each test names the requirement ID it verifies. Byte strings are
//! hand-computed from the paraphrased layouts in `schedule.rs` /
//! `sampling.rs` / `supply.rs` (docs `07-5123-08` §10.4 and
//! `17-05019-012` §10.4) — never copied from spec text (D1,
//! `SCOPE.md` §2). Corpus-mined `17-05019-012-423-03` is reused
//! verbatim; repo-minted IDs are MINTED-pending-confirm.

use rounddance_zcl::behavior::{Behavior, Ctx, EventQueue};
use rounddance_zcl::frame::{Direction, FrameControl, FrameType, Header};
use rounddance_zcl::{metering, sampling, schedule, snapshot, supply, ReportingEngine, ZclStatus};

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

fn drive(
    beh: &mut metering::ServerBehavior,
    store: &mut rounddance_zcl::AttrStore,
    eng: &mut ReportingEngine,
    events: &mut EventQueue,
    now_s: u64,
    cmd: u8,
    payload: &[u8],
) -> Result<rounddance_zcl::behavior::HandleOutcome, ZclStatus> {
    <metering::ServerBehavior as Behavior>::handle_cluster_command(
        beh,
        &mut ctx_for(store, eng, events, now_s),
        &hdr(cmd),
        cmd,
        payload,
    )
}

// ---- schedule codecs ------------------------------------------------

// 07-5123-08-1046-01: timetable entries are 13-octet records.
#[test]
fn vector_schedule_entry_codec_07_5123_08_1046_01() {
    let entry = schedule::ScheduleEntry {
        id: 7,
        start: 0x1234_5678,
        bitmap: 0x0080_0005,
        payload_type: snapshot::PAYLOAD_TOU_DELIVERED,
        cause: 0x0001_0000,
    };
    let mut out = [0u8; 16];
    assert_eq!(schedule::encode_schedule_entry(&entry, &mut out), Ok(13));
    assert_eq!(
        &out[..13],
        &[0x07, 0x78, 0x56, 0x34, 0x12, 0x05, 0x00, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00]
    );
    assert_eq!(schedule::decode_schedule_entry(&out[..13]), Ok(entry));
    // Ragged and short bodies are rejected; small buffers refuse.
    assert!(schedule::decode_schedule_entry(&out[..12]).is_err());
    assert!(schedule::decode_schedule_entry(&out[..14]).is_err());
    let mut small = [0u8; 12];
    assert!(schedule::encode_schedule_entry(&entry, &mut small).is_err());
}

// 07-5123-08-1046-03: bitmap fields split into count/unit/phase.
#[test]
fn vector_schedule_bitmap_07_5123_08_1046_03() {
    assert_eq!(schedule::schedule_count(0x0080_0005), 5);
    assert_eq!(schedule::schedule_freq(0x0080_0005), schedule::FREQ_DAY);
    assert_eq!(schedule::schedule_wildcard(0x0080_0005), 2);
    assert_eq!(schedule::schedule_period_s(0x0080_0005), 5 * 86_400);
    assert_eq!(schedule::schedule_period_s(3 | (1 << 20)), 3 * 7 * 86_400);
    assert_eq!(schedule::schedule_period_s(2 | (2 << 20)), 2 * 30 * 86_400);
    // Zero counts and the reserved unit never fire.
    assert_eq!(schedule::schedule_period_s(0), 0);
    assert!(!schedule::schedule_bitmap_usable(0));
    assert!(!schedule::schedule_bitmap_usable(4 | (3 << 20)));
    assert!(schedule::schedule_bitmap_usable(1));
    // Wire-known sub-payload selectors pass; others do not.
    assert!(snapshot::payload_type_known(
        snapshot::PAYLOAD_TOU_DELIVERED
    ));
    assert!(snapshot::payload_type_known(
        snapshot::PAYLOAD_BLOCK_RECEIVED_NO_BILLING
    ));
    assert!(snapshot::payload_type_known(snapshot::PAYLOAD_UNAVAILABLE));
    assert!(!snapshot::payload_type_known(0x08));
    assert!(!snapshot::payload_type_known(0x7F));
}

// 07-5123-08-1046-01: responses echo the issuer with confirmations.
#[test]
fn vector_schedule_response_codec_07_5123_08_1046_01() {
    let mut out = [0u8; 16];
    let pairs = [
        (3u8, schedule::SCHEDULE_CONF_ACCEPTED),
        (4, schedule::SCHEDULE_CONF_TYPE_NOT_SUPPORTED),
    ];
    assert_eq!(
        schedule::encode_schedule_response(0xAABB_CCDD, &pairs, &mut out),
        Ok(8)
    );
    assert_eq!(&out[..8], &[0xDD, 0xCC, 0xBB, 0xAA, 0x03, 0x00, 0x04, 0x01]);
    let back = schedule::decode_schedule_response(&out[..8]).unwrap();
    assert_eq!(back.issuer, 0xAABB_CCDD);
    assert_eq!(back.count, 2);
    assert_eq!(back.confirmations[0], (3, 0x00));
    assert_eq!(back.confirmations[1], (4, 0x01));
    // Ragged tails and over-bound pair counts are rejected.
    assert!(schedule::decode_schedule_response(&out[..7]).is_err());
    assert!(schedule::decode_schedule_response(&out[..5]).is_err());
    let mut big = [0u8; 4 + 2 * (schedule::MAX_SCHEDULE_CONFIRM + 1)];
    big[..4].copy_from_slice(&[1, 2, 3, 4]);
    assert!(schedule::decode_schedule_response(&big).is_err());
    let many = [(1u8, 0u8); schedule::MAX_SCHEDULE_CONFIRM + 1];
    assert!(schedule::encode_schedule_response(1, &many, &mut out).is_err());
}

// ---- schedule table -------------------------------------------------

// 07-5123-08-1046-02: intake files, replaces, and refuses per entry.
#[test]
fn vector_schedule_table_intake_07_5123_08_1046_02() {
    let mut table = schedule::ScheduleTable::new();
    assert!(table.is_empty());
    let entry = schedule::ScheduleEntry {
        id: 2,
        start: 1_000,
        bitmap: 1,
        payload_type: snapshot::PAYLOAD_TOU_DELIVERED,
        cause: 1 << snapshot::CAUSE_SCHEDULED_BIT,
    };
    assert_eq!(table.intake(10, &entry), schedule::SCHEDULE_CONF_ACCEPTED);
    assert_eq!(table.len(), 1);
    // Newer issuer replaces; stale re-file answers accepted but keeps
    // the older filing.
    let mut newer = entry;
    newer.start = 2_000;
    assert_eq!(table.intake(11, &newer), schedule::SCHEDULE_CONF_ACCEPTED);
    assert_eq!(table.len(), 1);
    let mut older = entry;
    older.start = 500;
    assert_eq!(table.intake(9, &older), schedule::SCHEDULE_CONF_ACCEPTED);
    assert_eq!(table.len(), 1);
    // Out-of-range ids are unusable, never filed.
    let mut bad_id = entry;
    bad_id.id = 0;
    assert_eq!(
        table.intake(12, &bad_id),
        schedule::SCHEDULE_CONF_NOT_CURRENTLY_AVAILABLE
    );
    bad_id.id = 255;
    assert_eq!(
        table.intake(12, &bad_id),
        schedule::SCHEDULE_CONF_NOT_CURRENTLY_AVAILABLE
    );
    // Unknown sub-payload shapes are refused per entry.
    let mut bad_type = entry;
    bad_type.id = 3;
    bad_type.payload_type = 0x42;
    assert_eq!(
        table.intake(12, &bad_type),
        schedule::SCHEDULE_CONF_TYPE_NOT_SUPPORTED
    );
    // Unsupported causes are refused (bit 20 sits outside the mask).
    let mut bad_cause = entry;
    bad_cause.id = 3;
    bad_cause.cause = 1 << 20;
    assert_eq!(
        table.intake(12, &bad_cause),
        schedule::SCHEDULE_CONF_CAUSE_NOT_SUPPORTED
    );
    // Unusable timetables (zero count) are refused.
    let mut bad_bitmap = entry;
    bad_bitmap.id = 3;
    bad_bitmap.bitmap = 0;
    assert_eq!(
        table.intake(12, &bad_bitmap),
        schedule::SCHEDULE_CONF_NOT_CURRENTLY_AVAILABLE
    );
    assert_eq!(table.len(), 1);
    // Fill the table; one more is insufficient space.
    let mut i = 3u8;
    while i <= 5 {
        let mut e = entry;
        e.id = i;
        assert_eq!(table.intake(20, &e), schedule::SCHEDULE_CONF_ACCEPTED);
        i += 1;
    }
    assert_eq!(table.len(), schedule::MAX_SCHEDULES);
    let mut full = entry;
    full.id = 9;
    assert_eq!(
        table.intake(21, &full),
        schedule::SCHEDULE_CONF_INSUFFICIENT_SPACE
    );
    // A switched-off device refuses everything per entry.
    let mut off = schedule::ScheduleTable::new();
    off.set_supported(false);
    assert_eq!(
        off.intake(1, &entry),
        schedule::SCHEDULE_CONF_NOT_SUPPORTED_BY_DEVICE
    );
    assert!(off.is_empty());
}

// 07-5123-08-1046-02: due entries fire once per grid point.
#[test]
fn vector_schedule_table_due_07_5123_08_1046_02() {
    let mut table = schedule::ScheduleTable::new();
    let entry = schedule::ScheduleEntry {
        id: 1,
        start: 100,
        bitmap: 1, // daily here means one 86_400 s step.
        payload_type: snapshot::PAYLOAD_TOU_DELIVERED,
        cause: 0x00,
    };
    assert_eq!(table.intake(1, &entry), schedule::SCHEDULE_CONF_ACCEPTED);
    let mut out = [(0u32, 0u8); schedule::MAX_SCHEDULES];
    assert_eq!(table.collect_due(99, &mut out), 0);
    assert_eq!(table.collect_due(100, &mut out), 1);
    assert_eq!(out[0], (0x00, snapshot::PAYLOAD_TOU_DELIVERED));
    // Same grid point never re-fires; the next grid point does.
    assert_eq!(table.collect_due(100, &mut out), 0);
    assert_eq!(table.collect_due(100 + 86_400, &mut out), 1);
    assert_eq!(table.collect_due(100 + 86_400, &mut out), 0);
}

// 07-5123-08-1046-01: fragmented intake assembles in order.
#[test]
fn vector_schedule_assembler_07_5123_08_1046_01() {
    let entry = schedule::ScheduleEntry {
        id: 5,
        start: 300,
        bitmap: 2,
        payload_type: snapshot::PAYLOAD_TOU_DELIVERED,
        cause: 0x04,
    };
    let mut wire = [0u8; schedule::SCHEDULE_ENTRY_LEN];
    schedule::encode_schedule_entry(&entry, &mut wire).unwrap();
    // Single-fragment command completes at once.
    let mut asm = schedule::ScheduleAssembler::new();
    assert_eq!(
        asm.feed(7, 0, 1, &wire),
        Ok(schedule::Assembly::Complete { issuer: 7, len: 13 })
    );
    assert_eq!(asm.assembled(), &wire);
    assert_eq!(schedule::decode_schedule_entry(asm.assembled()), Ok(entry));
    // Two fragments assemble in order; out-of-order is malformed.
    let mut asm2 = schedule::ScheduleAssembler::new();
    let mut two = [0u8; 2 * schedule::SCHEDULE_ENTRY_LEN];
    two[..13].copy_from_slice(&wire);
    two[13..].copy_from_slice(&wire);
    assert_eq!(
        asm2.feed(9, 0, 2, &two[..13]),
        Ok(schedule::Assembly::Incomplete)
    );
    // A repeated fragment 0 restarts the assembly (retransmission);
    // a wrong-issuer continuation is malformed.
    assert_eq!(
        asm2.feed(9, 0, 2, &two[..13]),
        Ok(schedule::Assembly::Incomplete)
    );
    assert_eq!(
        asm2.feed(77, 1, 2, &two[13..]),
        Err(ZclStatus::MalformedCommand)
    );
    let mut asm3 = schedule::ScheduleAssembler::new();
    assert_eq!(
        asm3.feed(9, 0, 2, &two[..13]),
        Ok(schedule::Assembly::Incomplete)
    );
    assert_eq!(
        asm3.feed(9, 1, 2, &two[13..]),
        Ok(schedule::Assembly::Complete { issuer: 9, len: 26 })
    );
    // Degenerate shapes: zero totals, over-bound totals, past-end
    // indexes, and ragged bodies.
    let mut asm4 = schedule::ScheduleAssembler::new();
    assert_eq!(asm4.feed(1, 0, 0, &wire), Err(ZclStatus::MalformedCommand));
    assert_eq!(asm4.feed(1, 0, 5, &wire), Err(ZclStatus::MalformedCommand));
    assert_eq!(asm4.feed(1, 1, 1, &wire), Err(ZclStatus::MalformedCommand));
    assert_eq!(
        asm4.feed(1, 0, 1, &wire[..7]),
        Err(ZclStatus::MalformedCommand)
    );
}

// ---- sampling codecs ------------------------------------------------

// 07-5123-08-1047-01: StartSampling bodies are 13 octets.
#[test]
fn vector_start_sampling_codec_07_5123_08_1047_01() {
    let req = sampling::StartSampling {
        issuer: 0x0102_0304,
        start: 0,
        sample_type: sampling::SAMPLE_DEMAND,
        interval_s: 60,
        max_samples: 10,
    };
    let mut out = [0u8; 16];
    assert_eq!(sampling::encode_start_sampling(&req, &mut out), Ok(13));
    assert_eq!(
        &out[..13],
        &[0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x3C, 0x00, 0x0A, 0x00]
    );
    assert_eq!(sampling::decode_start_sampling(&out[..13]), Ok(req));
    assert!(sampling::decode_start_sampling(&out[..12]).is_err());
    assert!(sampling::decode_start_sampling(&out[..14]).is_err());
    let mut small = [0u8; 12];
    assert!(sampling::encode_start_sampling(&req, &mut small).is_err());
    // Sample-type gate: 0..=4 capture, the rest do not.
    assert!(sampling::sample_type_known(sampling::SAMPLE_DELIVERED));
    assert!(sampling::sample_type_known(sampling::SAMPLE_DEMAND));
    assert!(!sampling::sample_type_known(5));
    // Start responses carry the allocated id (or the failure sentinel).
    let mut rsp = [0u8; 2];
    assert_eq!(sampling::encode_start_response(3, &mut rsp), Ok(2));
    assert_eq!(&rsp, &[0x03, 0x00]);
    assert_eq!(sampling::decode_start_response(&rsp), Ok(3));
    assert!(sampling::decode_start_response(&rsp[..1]).is_err());
}

// 07-5123-08-1047-02: GetSampledData queries are 9 octets; responses
// carry the header plus the 24-bit series.
#[test]
fn vector_sampled_data_codec_07_5123_08_1047_02() {
    let req = sampling::GetSampledData {
        sample_id: 1,
        earliest: 1_000,
        sample_type: sampling::SAMPLE_DEMAND,
        count: 2,
    };
    let mut out = [0u8; 10];
    assert_eq!(sampling::encode_get_sampled_data(&req, &mut out), Ok(9));
    assert_eq!(
        &out[..9],
        &[0x01, 0x00, 0xE8, 0x03, 0x00, 0x00, 0x04, 0x02, 0x00]
    );
    assert_eq!(sampling::decode_get_sampled_data(&out[..9]), Ok(req));
    assert!(sampling::decode_get_sampled_data(&out[..8]).is_err());
    let mut rsp = [0u8; 32];
    let samples = [0x0012_3456u32, sampling::SAMPLE_INVALID];
    let n = sampling::encode_sampled_data_response(
        1,
        1_000,
        sampling::SAMPLE_DEMAND,
        60,
        &samples,
        &mut rsp,
    )
    .unwrap();
    assert_eq!(n, 11 + 6);
    assert_eq!(
        &rsp[..17],
        &[
            0x01, 0x00, 0xE8, 0x03, 0x00, 0x00, 0x04, 0x3C, 0x00, 0x02, 0x00, 0x56, 0x34, 0x12,
            0xFF, 0xFF, 0xFF
        ]
    );
    let back = sampling::decode_sampled_data_response(&rsp[..n]).unwrap();
    assert_eq!(back.sample_id, 1);
    assert_eq!(back.start, 1_000);
    assert_eq!(back.sample_type, sampling::SAMPLE_DEMAND);
    assert_eq!(back.interval_s, 60);
    assert_eq!(back.sample_values(), &samples);
    // Ragged tails, count lies, and over-bound series are rejected.
    assert!(sampling::decode_sampled_data_response(&rsp[..16]).is_err());
    let mut lied = [0u8; 17];
    lied.copy_from_slice(&rsp[..17]);
    lied[9] = 3;
    assert!(sampling::decode_sampled_data_response(&lied).is_err());
}

// ---- sampling engine ------------------------------------------------

// 07-5123-08-1047-04: sessions open, fill, and read back by window.
#[test]
fn vector_sample_engine_sessions_07_5123_08_1047_04() {
    let mut eng = sampling::SampleEngine::new();
    assert!(eng.is_empty());
    let open = sampling::StartSampling {
        issuer: 5,
        start: 0,
        sample_type: sampling::SAMPLE_DELIVERED,
        interval_s: 30,
        max_samples: 4,
    };
    assert_eq!(eng.open(&open, 100), sampling::OpenVerdict::Opened(1));
    // Stale issuers never open.
    let mut stale = open;
    stale.issuer = 5;
    assert_eq!(eng.open(&stale, 100), sampling::OpenVerdict::Stale);
    let second = sampling::StartSampling { issuer: 6, ..open };
    assert_eq!(eng.open(&second, 100), sampling::OpenVerdict::Opened(2));
    // A full engine answers the failure sentinel on open.
    let third = sampling::StartSampling { issuer: 7, ..open };
    assert_eq!(eng.open(&third, 100), sampling::OpenVerdict::Full);
    // Unusable shapes fail before capacity is consulted: unknown
    // type, zero interval, zero count.
    let mut bad = sampling::StartSampling { issuer: 8, ..open };
    bad.sample_type = 9;
    assert_eq!(eng.open(&bad, 100), sampling::OpenVerdict::Unusable);
    bad.sample_type = sampling::SAMPLE_DELIVERED;
    bad.interval_s = 0;
    assert_eq!(eng.open(&bad, 100), sampling::OpenVerdict::Unusable);
    bad.interval_s = 30;
    bad.max_samples = 0;
    assert_eq!(eng.open(&bad, 100), sampling::OpenVerdict::Unusable);
    // Pushes land chronologically; the session closes at capacity.
    assert!(eng.push(1, 10, 100));
    assert!(eng.push(1, 20, 130));
    assert!(eng.push(1, 30, 160));
    assert!(eng.push(1, 40, 190));
    assert!(!eng.push(1, 50, 220));
    let mut values = [0u32; sampling::MAX_SAMPLES_PER_RESPONSE];
    let q = sampling::GetSampledData {
        sample_id: 1,
        earliest: 0,
        sample_type: sampling::SAMPLE_DELIVERED,
        count: 10,
    };
    let (start, stype, interval, count) = eng.query(&q, &mut values).unwrap();
    assert_eq!(
        (start, stype, interval, count),
        (100, sampling::SAMPLE_DELIVERED, 30, 4)
    );
    assert_eq!(&values[..4], &[10, 20, 30, 40]);
    // Windows filter from the earliest stamp; empty windows miss.
    let win = sampling::GetSampledData {
        earliest: 150,
        count: 10,
        ..q
    };
    let (start2, _, _, count2) = eng.query(&win, &mut values).unwrap();
    assert_eq!((start2, count2), (160, 2));
    assert_eq!(&values[..2], &[30, 40]);
    let miss = sampling::GetSampledData { earliest: 999, ..q };
    assert_eq!(eng.query(&miss, &mut values), Err(ZclStatus::NotFound));
    // Type mismatches and unknown ids fail typed.
    let wrong = sampling::GetSampledData {
        sample_type: sampling::SAMPLE_RECEIVED,
        ..q
    };
    assert_eq!(eng.query(&wrong, &mut values), Err(ZclStatus::InvalidField));
    let unknown = sampling::GetSampledData { sample_id: 99, ..q };
    assert_eq!(eng.query(&unknown, &mut values), Err(ZclStatus::NotFound));
    // Cancelling frees the slot for a newer issuer.
    assert_eq!(
        eng.open(
            &sampling::StartSampling {
                issuer: 6,
                start: sampling::START_CANCEL,
                ..open
            },
            200
        ),
        sampling::OpenVerdict::Cancelled
    );
    let fourth = sampling::StartSampling { issuer: 9, ..open };
    assert_eq!(eng.open(&fourth, 200), sampling::OpenVerdict::Opened(3));
    assert_eq!(eng.len(), 2);
}

// 07-5123-08-1047-04: future-dated sessions open on the tick.
#[test]
fn vector_sample_engine_tick_07_5123_08_1047_04() {
    let mut eng = sampling::SampleEngine::new();
    let future = sampling::StartSampling {
        issuer: 3,
        start: 1_000,
        sample_type: sampling::SAMPLE_RECEIVED,
        interval_s: 15,
        max_samples: 2,
    };
    assert_eq!(eng.open(&future, 100), sampling::OpenVerdict::Opened(1));
    assert!(!eng.push(1, 7, 100));
    assert_eq!(eng.tick(999), 0);
    assert!(!eng.push(1, 7, 999));
    assert_eq!(eng.tick(1_000), 1);
    assert!(eng.push(1, 7, 1_000));
    assert_eq!(eng.tick(2_000), 0);
}

// ---- supply codecs --------------------------------------------------

// 07-5123-08-1048-01: ChangeSupply bodies are 18 octets.
#[test]
fn vector_change_supply_codec_07_5123_08_1048_01() {
    let req = supply::ChangeSupply {
        provider: 0x1111_1111,
        issuer: 0x2222_2222,
        request_time: 0x3333_3333,
        impl_time: supply::IMPL_IMMEDIATE,
        proposed: supply::SUPPLY_ON,
        control: supply::CONTROL_ACK_REQUIRED,
    };
    let mut out = [0u8; 20];
    assert_eq!(supply::encode_change_supply(&req, &mut out), Ok(18));
    assert_eq!(
        &out[..18],
        &[
            0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x33, 0x33, 0x33, 0x33, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x01
        ]
    );
    assert_eq!(supply::decode_change_supply(&out[..18]), Ok(req));
    assert!(supply::decode_change_supply(&out[..17]).is_err());
    assert!(supply::decode_change_supply(&out[..19]).is_err());
    let mut small = [0u8; 17];
    assert!(supply::encode_change_supply(&req, &mut small).is_err());
    // Status gate: the three named states pass, the rest do not.
    assert!(supply::supply_status_known(supply::SUPPLY_OFF));
    assert!(supply::supply_status_known(supply::SUPPLY_ARMED));
    assert!(supply::supply_status_known(supply::SUPPLY_ON));
    assert!(!supply::supply_status_known(0x03));
    // Response bodies echo provider/issuer/time/status in 13 octets.
    let rsp = supply::SupplyStatusResponse {
        provider: 0x1111_1111,
        issuer: 0x2222_2222,
        impl_time: 500,
        status: supply::SUPPLY_OFF,
    };
    let mut rout = [0u8; 13];
    assert_eq!(
        supply::encode_supply_status_response(&rsp, &mut rout),
        Ok(13)
    );
    assert_eq!(
        &rout,
        &[0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0xF4, 0x01, 0x00, 0x00, 0x00]
    );
    assert_eq!(supply::decode_supply_status_response(&rout), Ok(rsp));
    assert!(supply::decode_supply_status_response(&rout[..12]).is_err());
}

// 07-5123-08-1048-02/05: local-change and load-limit bodies.
#[test]
fn vector_local_and_reset_codec_07_5123_08_1048_02() {
    let mut out = [0u8; 2];
    assert_eq!(
        supply::encode_local_change_supply(supply::SUPPLY_ARMED, &mut out),
        Ok(1)
    );
    assert_eq!(&out[..1], &[0x01]);
    assert_eq!(
        supply::decode_local_change_supply(&out[..1]),
        Ok(supply::SUPPLY_ARMED)
    );
    assert!(supply::decode_local_change_supply(&[]).is_err());
    assert!(supply::decode_local_change_supply(&out).is_err());
    let mut empty: [u8; 0] = [];
    assert!(supply::encode_local_change_supply(supply::SUPPLY_ON, &mut empty).is_err());
    let mut rout = [0u8; 8];
    assert_eq!(
        supply::encode_reset_load_limit(0x0A0A_0A0A, 0x0B0B_0B0B, &mut rout),
        Ok(8)
    );
    assert_eq!(&rout, &[0x0A, 0x0A, 0x0A, 0x0A, 0x0B, 0x0B, 0x0B, 0x0B]);
    assert_eq!(
        supply::decode_reset_load_limit(&rout),
        Ok((0x0A0A_0A0A, 0x0B0B_0B0B))
    );
    assert!(supply::decode_reset_load_limit(&rout[..7]).is_err());
}

// 07-5123-08-1048-03: event-state tables are 8 octets.
#[test]
fn vector_set_supply_status_codec_07_5123_08_1048_03() {
    let req = supply::SetSupplyStatus {
        issuer: 44,
        tamper: supply::SUPPLY_OFF,
        depletion: supply::SUPPLY_ARMED,
        uncontrolled: supply::SUPPLY_UNCHANGED,
        load_limit: supply::SUPPLY_ON,
    };
    let mut out = [0u8; 8];
    assert_eq!(supply::encode_set_supply_status(&req, &mut out), Ok(8));
    assert_eq!(&out, &[44, 0, 0, 0, 0x00, 0x01, 0x03, 0x02]);
    assert_eq!(supply::decode_set_supply_status(&out), Ok(req));
    assert!(supply::decode_set_supply_status(&out[..7]).is_err());
    assert!(supply::event_state_known(supply::SUPPLY_UNCHANGED));
    assert!(!supply::event_state_known(0x04));
}

// 07-5123-08-1048-04: flow-guard bodies are 18 octets with nonzero scales.
#[test]
fn vector_flow_threshold_codec_07_5123_08_1048_04() {
    let cfg = supply::FlowThreshold {
        provider: 1,
        issuer: 2,
        threshold: 100,
        unit: 3,
        multiplier: 2,
        divisor: 4,
        stabilization: 5,
        measurement: 60,
    };
    let mut out = [0u8; 18];
    assert_eq!(supply::encode_flow_threshold(&cfg, &mut out), Ok(18));
    assert_eq!(
        &out,
        &[
            0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x03, 0x02, 0x00, 0x04,
            0x00, 0x05, 0x3C, 0x00
        ]
    );
    assert_eq!(supply::decode_flow_threshold(&out), Ok(cfg));
    // Zero scales are field errors both directions.
    let mut zero_mult = cfg;
    zero_mult.multiplier = 0;
    assert!(supply::encode_flow_threshold(&zero_mult, &mut out).is_err());
    let mut zeroed = out;
    zeroed[11] = 0;
    zeroed[12] = 0;
    assert!(supply::decode_flow_threshold(&zeroed).is_err());
    let mut zero_div = out;
    zero_div[13] = 0;
    zero_div[14] = 0;
    assert!(supply::decode_flow_threshold(&zero_div).is_err());
}

// ---- supply machine -------------------------------------------------

// 17-05019-012-423-03 + 07-5123-08-1048-01: delayed commands
// serialize; immediate never auto-cancels; cancels are exact.
#[test]
fn vector_supply_machine_ordering_17_05019_012_423_03() {
    let mut m = supply::SupplyMachine::new();
    assert_eq!(m.status(), supply::SUPPLY_ON);
    assert_eq!(m.pending(), None);
    // Immediate applies at once with the ack flag carried out.
    let now = supply::ChangeSupply {
        provider: 1,
        issuer: 1,
        request_time: 100,
        impl_time: supply::IMPL_IMMEDIATE,
        proposed: supply::SUPPLY_OFF,
        control: supply::CONTROL_ACK_REQUIRED,
    };
    assert_eq!(
        m.apply_change(&now, 200),
        Ok(supply::SupplyOutcome::Applied { ack: true })
    );
    assert_eq!(m.status(), supply::SUPPLY_OFF);
    // Delayed files without acting; a newer delayed overrides it.
    let later = supply::ChangeSupply {
        impl_time: 1_000,
        proposed: supply::SUPPLY_ON,
        issuer: 2,
        control: 0,
        ..now
    };
    assert_eq!(
        m.apply_change(&later, 200),
        Ok(supply::SupplyOutcome::Delayed)
    );
    assert_eq!(m.status(), supply::SUPPLY_OFF);
    assert_eq!(m.pending(), Some((1, 2, 1_000, supply::SUPPLY_ON)));
    let override_ = supply::ChangeSupply { issuer: 3, ..later };
    assert_eq!(
        m.apply_change(&override_, 200),
        Ok(supply::SupplyOutcome::Delayed)
    );
    assert_eq!(m.pending(), Some((1, 3, 1_000, supply::SUPPLY_ON)));
    // An immediate command does NOT cancel the pending delayed one.
    let imm = supply::ChangeSupply { issuer: 4, ..now };
    assert_eq!(
        m.apply_change(&imm, 200),
        Ok(supply::SupplyOutcome::Applied { ack: true })
    );
    assert_eq!(m.pending(), Some((1, 3, 1_000, supply::SUPPLY_ON)));
    // Ticks before the time do nothing; the due tick applies once.
    assert_eq!(m.tick(999), None);
    let (rsp, ack) = m.tick(1_000).unwrap();
    assert!(!ack);
    assert_eq!(
        rsp,
        supply::SupplyStatusResponse {
            provider: 1,
            issuer: 3,
            impl_time: 1_000,
            status: supply::SUPPLY_ON,
        }
    );
    assert_eq!(m.status(), supply::SUPPLY_ON);
    assert_eq!(m.pending(), None);
    assert_eq!(m.tick(1_001), None);
    // Exact-match cancels clear the pending time without touching
    // the status; mismatches fail.
    let delayed = supply::ChangeSupply { issuer: 5, ..later };
    assert_eq!(
        m.apply_change(&delayed, 200),
        Ok(supply::SupplyOutcome::Delayed)
    );
    let cancel = supply::ChangeSupply {
        impl_time: supply::IMPL_CANCEL,
        ..delayed
    };
    assert_eq!(
        m.apply_change(&cancel, 300),
        Ok(supply::SupplyOutcome::Cancelled)
    );
    assert_eq!(m.pending(), None);
    assert_eq!(m.status(), supply::SUPPLY_ON);
    let wrong = supply::ChangeSupply {
        issuer: 6,
        ..cancel
    };
    assert_eq!(m.apply_change(&wrong, 300), Err(ZclStatus::InvalidValue));
    let uncancelled = supply::ChangeSupply {
        issuer: 7,
        ..cancel
    };
    let _ = uncancelled;
    // Past-dated nonzero times fail; bad states fail.
    let past = supply::ChangeSupply {
        impl_time: 150,
        issuer: 8,
        ..now
    };
    assert_eq!(m.apply_change(&past, 200), Err(ZclStatus::InvalidValue));
    let bad_state = supply::ChangeSupply {
        proposed: 0x09,
        issuer: 9,
        ..now
    };
    assert_eq!(
        m.apply_change(&bad_state, 200),
        Err(ZclStatus::InvalidField)
    );
    // Policy gates: unauthorized origins and incapable devices.
    m.set_authorized(false);
    assert_eq!(m.apply_change(&now, 200), Err(ZclStatus::NotAuthorized));
    m.set_authorized(true);
    m.set_capable(false);
    assert_eq!(m.apply_change(&now, 200), Err(ZclStatus::UnsupCommand));
    assert_eq!(
        m.apply_local(supply::SUPPLY_ON),
        Err(ZclStatus::UnsupCommand)
    );
    m.set_capable(true);
}

// 07-5123-08-1048-02/03: local changes apply without answers;
// event tables select per-event states.
#[test]
fn vector_supply_local_and_events_07_5123_08_1048_02() {
    let mut m = supply::SupplyMachine::new();
    assert!(m.apply_local(supply::SUPPLY_ARMED).is_ok());
    assert_eq!(m.status(), supply::SUPPLY_ARMED);
    assert!(m.apply_local(supply::SUPPLY_ON).is_ok());
    assert_eq!(m.apply_local(0x00), Err(ZclStatus::InvalidField));
    assert_eq!(m.apply_local(0x05), Err(ZclStatus::InvalidField));
    let table = supply::SetSupplyStatus {
        issuer: 10,
        tamper: supply::SUPPLY_OFF,
        depletion: supply::SUPPLY_UNCHANGED,
        uncontrolled: supply::SUPPLY_ARMED,
        load_limit: supply::SUPPLY_ON,
    };
    assert_eq!(m.apply_set_status(&table), Ok(true));
    // Stale tables are ignored.
    let mut stale = table;
    stale.issuer = 9;
    assert_eq!(m.apply_set_status(&stale), Ok(false));
    // Out-of-range directives are field errors.
    let mut bad = table;
    bad.issuer = 11;
    bad.tamper = 0x04;
    assert_eq!(m.apply_set_status(&bad), Err(ZclStatus::InvalidField));
    // Events apply their entries; unchanged leaves the status alone.
    assert_eq!(
        m.apply_event(supply::SupplyEvent::Tamper),
        Some(supply::SUPPLY_OFF)
    );
    assert_eq!(m.status(), supply::SUPPLY_OFF);
    assert_eq!(m.apply_event(supply::SupplyEvent::Depletion), None);
    assert_eq!(m.status(), supply::SUPPLY_OFF);
    assert_eq!(
        m.apply_event(supply::SupplyEvent::UncontrolledFlow),
        Some(supply::SUPPLY_ARMED)
    );
    assert_eq!(
        m.apply_event(supply::SupplyEvent::LoadLimit),
        Some(supply::SUPPLY_ON)
    );
}

// 07-5123-08-1048-04/05: guard math and reset ordering.
#[test]
fn vector_supply_guard_and_reset_07_5123_08_1048_04() {
    let mut m = supply::SupplyMachine::new();
    assert_eq!(m.flow_trip_value(), None);
    let cfg = supply::FlowThreshold {
        provider: 1,
        issuer: 3,
        threshold: 100,
        unit: 0,
        multiplier: 2,
        divisor: 4,
        stabilization: 1,
        measurement: 10,
    };
    assert!(m.apply_flow(&cfg));
    assert_eq!(m.flow(), Some(cfg));
    assert_eq!(m.flow_trip_value(), Some(50));
    // Stale guards are ignored.
    let mut stale = cfg;
    stale.issuer = 2;
    assert!(!m.apply_flow(&stale));
    assert_eq!(m.flow(), Some(cfg));
    // A zero threshold disables the trip value without clearing config.
    let mut disabled = cfg;
    disabled.issuer = 4;
    disabled.threshold = 0;
    assert!(m.apply_flow(&disabled));
    assert_eq!(m.flow_trip_value(), Some(0));
    // Load-limit resets are issuer-ordered and zero the counter.
    m.note_load(17);
    assert_eq!(m.load_limit_count(), 17);
    assert!(!m.reset_load_limit(1, 0));
    assert_eq!(m.load_limit_count(), 17);
    assert!(m.reset_load_limit(1, 5));
    assert_eq!(m.load_limit_count(), 0);
    assert!(!m.reset_load_limit(1, 5));
}

// ---- metering behavior wiring ---------------------------------------

// 07-5123-08-1046-01/02: the meter files timetables and fires them.
#[test]
fn vector_meter_schedule_take_fire_07_5123_08_1046_01() {
    let mut store = metering::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = metering::ServerBehavior::new();
    beh.add_consumption(&mut store, 0x00AA_BBCC);
    let entry = schedule::ScheduleEntry {
        id: 1,
        start: 5_000,
        bitmap: 1,
        payload_type: snapshot::PAYLOAD_TOU_DELIVERED,
        cause: 0x00,
    };
    let mut entry_wire = [0u8; schedule::SCHEDULE_ENTRY_LEN];
    schedule::encode_schedule_entry(&entry, &mut entry_wire).unwrap();
    let mut cmd = [0u8; 6 + schedule::SCHEDULE_ENTRY_LEN];
    cmd[..4].copy_from_slice(&9u32.to_le_bytes());
    cmd[4] = 0;
    cmd[5] = 1;
    cmd[6..].copy_from_slice(&entry_wire);
    let outcome = drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        100,
        schedule::CMD_SCHEDULE_SNAPSHOT,
        &cmd,
    )
    .unwrap();
    assert_eq!(
        outcome.reply_cmd,
        Some(schedule::CMD_SCHEDULE_SNAPSHOT_RESPONSE)
    );
    let back =
        schedule::decode_schedule_response(&outcome.reply_body[..outcome.reply_len as usize])
            .unwrap();
    assert_eq!(back.issuer, 9);
    assert_eq!(back.count, 1);
    assert_eq!(back.confirmations[0], (1, schedule::SCHEDULE_CONF_ACCEPTED));
    assert_eq!(beh.schedules().len(), 1);
    // Ticks before the start fire nothing; the due tick files a
    // snapshot stamped with the scheduled bit.
    beh.tick_metering(&store, &mut events, 4_999);
    assert!(beh.snapshots().is_empty());
    beh.tick_metering(&store, &mut events, 5_000);
    assert_eq!(beh.snapshots().len(), 1);
    let snap = beh
        .snapshots()
        .query(0, 6_000, 0, 1 << snapshot::CAUSE_SCHEDULED_BIT)
        .unwrap();
    assert_eq!(snap.time, 5_000);
    assert_eq!(&snap.sub_payload()[..3], &[0xCC, 0xBB, 0xAA]);
    // A non-TOU filing confirms type-not-supported without filing.
    let mut other = entry;
    other.id = 2;
    other.payload_type = snapshot::PAYLOAD_BLOCK_DELIVERED;
    let mut other_wire = [0u8; schedule::SCHEDULE_ENTRY_LEN];
    schedule::encode_schedule_entry(&other, &mut other_wire).unwrap();
    let mut cmd2 = [0u8; 6 + schedule::SCHEDULE_ENTRY_LEN];
    cmd2[..4].copy_from_slice(&10u32.to_le_bytes());
    cmd2[5] = 1;
    cmd2[6..].copy_from_slice(&other_wire);
    let outcome2 = drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        101,
        schedule::CMD_SCHEDULE_SNAPSHOT,
        &cmd2,
    )
    .unwrap();
    let back2 =
        schedule::decode_schedule_response(&outcome2.reply_body[..outcome2.reply_len as usize])
            .unwrap();
    assert_eq!(
        back2.confirmations[0],
        (2, schedule::SCHEDULE_CONF_TYPE_NOT_SUPPORTED)
    );
    assert_eq!(beh.schedules().len(), 1);
}

// 07-5123-08-1047-01/02: sampling sessions run through the behavior.
#[test]
fn vector_meter_sampled_data_07_5123_08_1047_01() {
    let mut store = metering::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = metering::ServerBehavior::new();
    let mut req_wire = [0u8; 13];
    sampling::encode_start_sampling(
        &sampling::StartSampling {
            issuer: 1,
            start: 0,
            sample_type: sampling::SAMPLE_DELIVERED,
            interval_s: 30,
            max_samples: 3,
        },
        &mut req_wire,
    )
    .unwrap();
    let outcome = drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        700,
        sampling::CMD_START_SAMPLING,
        &req_wire,
    )
    .unwrap();
    assert_eq!(
        outcome.reply_cmd,
        Some(sampling::CMD_START_SAMPLING_RESPONSE)
    );
    assert_eq!(
        sampling::decode_start_response(&outcome.reply_body[..outcome.reply_len as usize]),
        Ok(1)
    );
    // Empty sessions answer NOT_FOUND; pushed captures read back.
    let mut get_wire = [0u8; 9];
    sampling::encode_get_sampled_data(
        &sampling::GetSampledData {
            sample_id: 1,
            earliest: 0,
            sample_type: sampling::SAMPLE_DELIVERED,
            count: 3,
        },
        &mut get_wire,
    )
    .unwrap();
    assert_eq!(
        drive(
            &mut beh,
            &mut store,
            &mut eng,
            &mut events,
            701,
            sampling::CMD_GET_SAMPLED_DATA,
            &get_wire
        ),
        Err(ZclStatus::NotFound)
    );
    assert!(beh.samples_mut().push(1, 100, 700));
    assert!(beh.samples_mut().push(1, 200, 730));
    let outcome = drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        760,
        sampling::CMD_GET_SAMPLED_DATA,
        &get_wire,
    )
    .unwrap();
    assert_eq!(
        outcome.reply_cmd,
        Some(sampling::CMD_GET_SAMPLED_DATA_RESPONSE)
    );
    let back =
        sampling::decode_sampled_data_response(&outcome.reply_body[..outcome.reply_len as usize])
            .unwrap();
    assert_eq!(back.sample_id, 1);
    assert_eq!(back.start, 700);
    assert_eq!(back.sample_values(), &[100, 200]);
    // Stale opens are ignored silently (no reply, no session).
    let mut stale_wire = [0u8; 13];
    sampling::encode_start_sampling(
        &sampling::StartSampling {
            issuer: 1,
            start: 0,
            sample_type: sampling::SAMPLE_DELIVERED,
            interval_s: 30,
            max_samples: 3,
        },
        &mut stale_wire,
    )
    .unwrap();
    let outcome = drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        761,
        sampling::CMD_START_SAMPLING,
        &stale_wire,
    )
    .unwrap();
    assert_eq!(outcome.reply_cmd, None);
    assert_eq!(beh.samples().len(), 1);
}

// 07-5123-08-1048-01 + 17-05019-012-423-03: supply orders run through
// the behavior with typed refusals and delayed acknowledgements.
#[test]
fn vector_meter_supply_orders_07_5123_08_1048_01() {
    use rounddance_zcl::behavior::AppEvent;
    let mut store = metering::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = metering::ServerBehavior::new();
    // Immediate with ack: status flips, response answers.
    let mut cmd = [0u8; 18];
    supply::encode_change_supply(
        &supply::ChangeSupply {
            provider: 1,
            issuer: 1,
            request_time: 100,
            impl_time: supply::IMPL_IMMEDIATE,
            proposed: supply::SUPPLY_OFF,
            control: supply::CONTROL_ACK_REQUIRED,
        },
        &mut cmd,
    )
    .unwrap();
    let outcome = drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        200,
        supply::CMD_CHANGE_SUPPLY,
        &cmd,
    )
    .unwrap();
    assert_eq!(outcome.reply_cmd, Some(supply::CMD_SUPPLY_STATUS_RESPONSE));
    let rsp =
        supply::decode_supply_status_response(&outcome.reply_body[..outcome.reply_len as usize])
            .unwrap();
    assert_eq!(rsp.status, supply::SUPPLY_OFF);
    assert_eq!(beh.supply().status(), supply::SUPPLY_OFF);
    // Delayed: no reply now; the tick applies it and queues the ack.
    let mut delayed = [0u8; 18];
    supply::encode_change_supply(
        &supply::ChangeSupply {
            provider: 1,
            issuer: 2,
            request_time: 200,
            impl_time: 5_000,
            proposed: supply::SUPPLY_ON,
            control: supply::CONTROL_ACK_REQUIRED,
        },
        &mut delayed,
    )
    .unwrap();
    let outcome = drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        201,
        supply::CMD_CHANGE_SUPPLY,
        &delayed,
    )
    .unwrap();
    assert_eq!(outcome.reply_cmd, None);
    assert_eq!(beh.supply().status(), supply::SUPPLY_OFF);
    beh.tick_metering(&store, &mut events, 5_000);
    assert_eq!(beh.supply().status(), supply::SUPPLY_ON);
    let mut saw_ack = false;
    let mut saw_change = false;
    while let Some(ev) = events.pop() {
        match ev {
            AppEvent::OutboundCommand { cmd, len, .. } => {
                if cmd == supply::CMD_SUPPLY_STATUS_RESPONSE {
                    assert_eq!(len, 13);
                    saw_ack = true;
                }
            }
            AppEvent::StateChanged { from, to, .. }
                if from == supply::SUPPLY_OFF && to == supply::SUPPLY_ON =>
            {
                saw_change = true;
            }
            AppEvent::StateChanged { .. } => {}
            _ => {}
        }
    }
    assert!(saw_ack && saw_change);
    // Unauthorized origins are refused without acting.
    beh.supply_mut().set_authorized(false);
    assert_eq!(
        drive(
            &mut beh,
            &mut store,
            &mut eng,
            &mut events,
            202,
            supply::CMD_CHANGE_SUPPLY,
            &cmd
        ),
        Err(ZclStatus::NotAuthorized)
    );
    beh.supply_mut().set_authorized(true);
    // Local changes apply with a state event and never a reply.
    let mut local = [0u8; 1];
    supply::encode_local_change_supply(supply::SUPPLY_ARMED, &mut local).unwrap();
    let outcome = drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        203,
        supply::CMD_LOCAL_CHANGE_SUPPLY,
        &local,
    )
    .unwrap();
    assert_eq!(outcome.reply_cmd, None);
    assert_eq!(beh.supply().status(), supply::SUPPLY_ARMED);
    // Config commands file silently.
    let mut set = [0u8; 8];
    supply::encode_set_supply_status(
        &supply::SetSupplyStatus {
            issuer: 3,
            tamper: supply::SUPPLY_OFF,
            depletion: supply::SUPPLY_UNCHANGED,
            uncontrolled: supply::SUPPLY_UNCHANGED,
            load_limit: supply::SUPPLY_UNCHANGED,
        },
        &mut set,
    )
    .unwrap();
    assert!(drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        204,
        supply::CMD_SET_SUPPLY_STATUS,
        &set
    )
    .unwrap()
    .reply_cmd
    .is_none());
    let mut flow = [0u8; 18];
    supply::encode_flow_threshold(
        &supply::FlowThreshold {
            provider: 1,
            issuer: 4,
            threshold: 50,
            unit: 0,
            multiplier: 1,
            divisor: 2,
            stabilization: 1,
            measurement: 5,
        },
        &mut flow,
    )
    .unwrap();
    assert!(drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        205,
        supply::CMD_SET_UNCONTROLLED_FLOW,
        &flow
    )
    .unwrap()
    .reply_cmd
    .is_none());
    assert_eq!(beh.supply().flow_trip_value(), Some(25));
    let mut reset = [0u8; 8];
    supply::encode_reset_load_limit(1, 6, &mut reset).unwrap();
    assert!(drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        206,
        supply::CMD_RESET_LOAD_LIMIT,
        &reset
    )
    .unwrap()
    .reply_cmd
    .is_none());
}
