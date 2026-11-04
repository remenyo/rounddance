//! Wire vectors for the previously uncovered document models:
//! ERL Interface device, Daily Schedule, Occupancy Sensing, Linky
//! extension, Device Type Library, and the Aliro Reader bridge.
//!
//! Each test names the requirement ID it verifies. Byte strings
//! below are hand-computed from the paraphrased layouts in
//! `uncovered::{erl,dailysched,occupancy,linky,devtype,aliro}` —
//! never copied from spec text (D1, `SCOPE.md` §2). Requirement
//! IDs are repo-minted, MINTED-pending-confirm.

use rounddance_zcl::behavior::{Behavior, Ctx, EventQueue};
use rounddance_zcl::frame::{Direction, FrameControl, FrameType, Header};
use rounddance_zcl::uncovered::{aliro, dailysched, devtype, erl, linky, occupancy};
use rounddance_zcl::{AttrStore, ReportingEngine, ZclStatus};

fn hdr(cmd: u8) -> Header {
    Header {
        control: FrameControl {
            frame_type: FrameType::ClusterSpecific,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x07,
        command_id: cmd,
    }
}

fn ctx<'a>(
    store: &'a mut AttrStore,
    reporting: &'a mut ReportingEngine,
    events: &'a mut EventQueue,
) -> Ctx<'a> {
    Ctx {
        store,
        reporting,
        events,
        now_s: 0,
        peer_onoff: None,
        sender_ieee: None,
    }
}

// ---- occupancy ------------------------------------------------------

// 07-5123-08-48-01/03: cluster identity and flag semantics.
#[test]
fn vector_occupancy_flags_07_5123_08_48_01() {
    assert_eq!(occupancy::CLUSTER_ID, 0x0406);
    assert!(occupancy::is_occupied(0x01));
    assert!(occupancy::is_occupied(0xfd));
    assert!(!occupancy::is_occupied(0x00));
    assert!(!occupancy::is_occupied(0xfe));
    assert!(occupancy::sensor_type_known(0x00));
    assert!(occupancy::sensor_type_known(0x03));
    assert!(!occupancy::sensor_type_known(0x04));
}

// 07-5123-08-48-04: type/bitmap alignment pairs.
#[test]
fn vector_occupancy_alignment_07_5123_08_48_04() {
    assert!(occupancy::type_bitmap_aligned(0x00, 0x01));
    assert!(occupancy::type_bitmap_aligned(0x00, 0x05));
    assert!(occupancy::type_bitmap_aligned(0x01, 0x02));
    assert!(occupancy::type_bitmap_aligned(0x01, 0x06));
    assert!(occupancy::type_bitmap_aligned(0x02, 0x03));
    assert!(occupancy::type_bitmap_aligned(0x02, 0x07));
    assert!(!occupancy::type_bitmap_aligned(0x00, 0x02));
    assert!(!occupancy::type_bitmap_aligned(0x01, 0x01));
    assert!(!occupancy::type_bitmap_aligned(0x03, 0x03));
    assert!(!occupancy::type_bitmap_aligned(0x04, 0x01));
    // 15-0014-05-13-01: the sensor device requires the two rows.
    let def = occupancy::ServerDef;
    use rounddance_zcl::cluster::ClusterDef;
    assert!(def.attributes().iter().any(|a| a.id == 0x0000));
    assert!(def.attributes().iter().any(|a| a.id == 0x0001));
    assert!(def.received_commands().is_empty());
}

// 07-5123-08-48-05: motion sets occupied; the hold timer clears it.
#[test]
fn vector_occupancy_motion_hold_07_5123_08_48_05() {
    let mut store = occupancy::server_store().unwrap();
    assert_eq!(occupancy::occupancy_of(&store), 0);
    let mut reporting = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut behavior = occupancy::ServerBehavior::new();
    // Hold of 3 s through the PIR hold attribute.
    use rounddance_zcl::types::Value;
    store
        .set_local(
            occupancy::ATTR_PIR_OCC_TO_UNOCC_DELAY,
            Value::UInt { width: 2, v: 3 },
        )
        .unwrap();
    behavior.motion_detected(&mut ctx(&mut store, &mut reporting, &mut events));
    assert!(occupancy::is_occupied(occupancy::occupancy_of(&store)));
    behavior.tick_s(&mut ctx(&mut store, &mut reporting, &mut events), 2);
    assert!(occupancy::is_occupied(occupancy::occupancy_of(&store)));
    behavior.tick_s(&mut ctx(&mut store, &mut reporting, &mut events), 1);
    assert!(!occupancy::is_occupied(occupancy::occupancy_of(&store)));
    // Unknown commands are refused, never absorbed.
    let err = behavior
        .handle_cluster_command(
            &mut ctx(&mut store, &mut reporting, &mut events),
            &hdr(0x00),
            0x00,
            &[],
        )
        .unwrap_err();
    assert_eq!(err, ZclStatus::UnsupCommand);
}

// Alignment fuzz leg: only the seven table pairs pass.
#[test]
fn fuzz_occupancy_alignment_table() {
    let mut pass = 0;
    for t in 0..5u8 {
        for b in 0..8u8 {
            if occupancy::type_bitmap_aligned(t, b) {
                pass += 1;
            }
        }
    }
    assert_eq!(pass, 7);
}

// ---- daily schedule -------------------------------------------------

// 17-05035-016-1015-01/04: identity plus peak-field splits.
#[test]
fn vector_dailysched_peak_fields_17_05035_016_1015_01() {
    assert_eq!(dailysched::CLUSTER_ID, 0x070d);
    // status 0b10_01_11_01: on-peak 2, notice 1, next 3, day 1.
    let status = 0b10_01_11_01u8;
    assert_eq!(dailysched::on_peak(status), 2);
    assert_eq!(dailysched::peak_notice(status), 1);
    assert_eq!(dailysched::next_day_color(status), 3);
    assert_eq!(dailysched::day_color(status), 1);
    assert!(dailysched::color_known(dailysched::COLOR_BLUE));
    assert!(dailysched::color_known(dailysched::COLOR_RED));
    assert!(!dailysched::color_known(0x00));
    assert!(dailysched::time_ref_known(dailysched::TIME_REF_LOCAL));
    assert!(!dailysched::time_ref_known(0x03));
}

// 17-05035-016-1015-03: day entries are 4-octet LE triples.
#[test]
fn vector_day_entry_codec_17_05035_016_1015_03() {
    // start 0x0000 (midnight), tier 3, aux bitmap 0b0000_0101.
    let frozen = [0x00, 0x00, 0x03, 0x05];
    let entry = dailysched::decode_day_entry(&frozen).unwrap();
    assert_eq!(
        entry,
        dailysched::DayEntry {
            start_min: 0,
            tier: 3,
            aux: 0x05,
        }
    );
    let mut out = [0u8; 4];
    assert_eq!(dailysched::encode_day_entry(&entry, &mut out), Ok(4));
    assert_eq!(&out, &frozen);
    // start 06:30 = 390 min = 0x0186 -> bytes 86 01.
    let morning = dailysched::DayEntry {
        start_min: 390,
        tier: 1,
        aux: 0xff,
    };
    let mut mout = [0u8; 4];
    assert_eq!(dailysched::encode_day_entry(&morning, &mut mout), Ok(4));
    assert_eq!(&mout, &[0x86, 0x01, 0x01, 0xff]);
    assert_eq!(dailysched::decode_day_entry(&mout).unwrap(), morning);
    // Out-of-range starts and tiers are refused.
    assert!(dailysched::decode_day_entry(&[0xa0, 0x05, 0x00, 0x00]).is_err());
    assert!(dailysched::decode_day_entry(&[0x00, 0x00, 0x31, 0x00]).is_err());
    assert!(dailysched::decode_day_entry(&[0x00, 0x00, 0x00]).is_err());
}

// 17-05035-016-1015-03: PublishSchedule frozen vector.
#[test]
fn vector_publish_schedule_codec_17_05035_016_1015_03() {
    // provider 0x11223344, issuer 5, schedule 7, day 9, start 0 (now),
    // type Linky, ref UTC, name "AB".
    let frozen = [
        0x44, 0x33, 0x22, 0x11, 0x05, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x41, 0x42,
    ];
    let sched = dailysched::decode_publish_schedule(&frozen).unwrap();
    assert_eq!(sched.provider, 0x1122_3344);
    assert_eq!(sched.issuer, 5);
    assert_eq!(sched.schedule_id, 7);
    assert_eq!(sched.day_id, 9);
    assert_eq!(sched.start, 0);
    assert_eq!(sched.name_bytes(), b"AB");
    let mut out = [0u8; 64];
    assert_eq!(
        dailysched::encode_publish_schedule(&sched, &mut out),
        Ok(frozen.len())
    );
    assert_eq!(&out[..frozen.len()], &frozen);
    // Reserved type and unknown time reference are refused.
    let mut bad = frozen;
    bad[18] = 0x01;
    assert!(dailysched::decode_publish_schedule(&bad).is_err());
    let mut bad2 = frozen;
    bad2[19] = 0x03;
    assert!(dailysched::decode_publish_schedule(&bad2).is_err());
    assert!(dailysched::decode_publish_schedule(&frozen[..20]).is_err());
}

// 17-05035-016-1015-03: PublishDayProfile fragment + cancel + fetches.
#[test]
fn vector_day_profile_cancel_fetch_17_05035_016_1015_03() {
    let entries = [
        dailysched::DayEntry {
            start_min: 0,
            tier: 1,
            aux: 0x01,
        },
        dailysched::DayEntry {
            start_min: 480,
            tier: 2,
            aux: 0x00,
        },
    ];
    let mut out = [0u8; 64];
    let n =
        dailysched::encode_publish_day_profile(0x0a, 0x0b, 0x0c, 2, 0, 1, 0x00, &entries, &mut out)
            .unwrap();
    assert_eq!(n, 15 + 8);
    assert_eq!(&out[..4], &[0x0a, 0x00, 0x00, 0x00]);
    assert_eq!(out[10], 2);
    assert_eq!(out[14], 2);
    let back = dailysched::decode_publish_day_profile(&out[..n]).unwrap();
    assert_eq!(back.provider, 0x0a);
    assert_eq!(back.count, 2);
    assert_eq!(back.entries[1].start_min, 480);
    assert!(dailysched::decode_publish_day_profile(&out[..n - 1]).is_err());
    // CancelSchedule: provider + schedule + type.
    let frozen = [0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00];
    let cancel = dailysched::decode_cancel_schedule(&frozen).unwrap();
    assert_eq!((cancel.provider, cancel.schedule_id), (1, 2));
    let mut cout = [0u8; 9];
    assert_eq!(
        dailysched::encode_cancel_schedule(&cancel, &mut cout),
        Ok(9)
    );
    assert_eq!(&cout, &frozen);
    // GetSchedule frozen (provider any, earliest 0, issuer any, all, any).
    let g = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff,
    ];
    let query = dailysched::decode_get_schedule(&g).unwrap();
    assert_eq!(query.provider, dailysched::PROVIDER_ANY);
    assert_eq!(query.sched_type, dailysched::SCHED_TYPE_ANY);
    let mut gout = [0u8; 14];
    assert_eq!(dailysched::encode_get_schedule(&query, &mut gout), Ok(14));
    assert_eq!(&gout, &g);
    // GetDayProfile frozen.
    let (provider, day) = dailysched::decode_get_day_profile(&[0x05, 0, 0, 0, 0x09, 0]).unwrap();
    assert_eq!((provider, day), (5, 9));
    assert!(dailysched::decode_get_day_profile(&[0x05, 0, 0, 0, 0x09]).is_err());
}

// 17-05035-016-1015-03/05: store supersession, evaluation, cancels.
#[test]
fn vector_schedule_store_17_05035_016_1015_03() {
    let mut store = dailysched::ScheduleStore::new();
    let mut sched = dailysched::Schedule {
        provider: 1,
        issuer: 10,
        schedule_id: 7,
        day_id: 3,
        start: 1_000,
        sched_type: dailysched::SCHED_TYPE_LINKY,
        time_ref: dailysched::TIME_REF_UTC,
        name_len: 0,
        name: [0; dailysched::MAX_SCHEDULE_NAME],
    };
    store.file_schedule(&sched).unwrap();
    // Stale refile changes nothing.
    sched.issuer = 9;
    store.file_schedule(&sched).unwrap();
    assert_eq!(store.active_at(2_000).unwrap().issuer, 10);
    // Newer issuer replaces.
    sched.issuer = 11;
    sched.start = 500;
    store.file_schedule(&sched).unwrap();
    assert_eq!(store.active_at(2_000).unwrap().start, 500);
    // Profiles require midnight start + ascending order.
    let bad_profile = dailysched::DayProfile {
        provider: 1,
        issuer: 11,
        day_id: 3,
        entries: {
            let mut e = [dailysched::DayEntry {
                start_min: 0,
                tier: 0,
                aux: 0,
            }; dailysched::MAX_DAY_ENTRIES];
            e[0].start_min = 60;
            e
        },
        count: 1,
    };
    assert_eq!(
        store.file_profile(&bad_profile),
        Err(ZclStatus::InvalidField)
    );
    let mut entries = [dailysched::DayEntry {
        start_min: 0,
        tier: 0,
        aux: 0,
    }; dailysched::MAX_DAY_ENTRIES];
    entries[0] = dailysched::DayEntry {
        start_min: 0,
        tier: 1,
        aux: 0x01,
    };
    entries[1] = dailysched::DayEntry {
        start_min: 720,
        tier: 3,
        aux: 0x00,
    };
    store
        .file_profile(&dailysched::DayProfile {
            provider: 1,
            issuer: 11,
            day_id: 3,
            entries,
            count: 2,
        })
        .unwrap();
    // 500 s after midnight + schedule start 500: morning tier.
    assert_eq!(store.evaluate(500 + 3_600), Some((1, 0x01)));
    // Afternoon entry takes over.
    assert_eq!(store.evaluate(500 + 13 * 3_600), Some((3, 0x00)));
    // Unknown cancellation is not-found; known one sticks.
    assert_eq!(
        store.cancel(&dailysched::Cancellation {
            provider: 1,
            schedule_id: 99,
            sched_type: dailysched::SCHED_TYPE_LINKY,
            all: false,
        }),
        Err(ZclStatus::NotFound)
    );
    store
        .cancel(&dailysched::Cancellation {
            provider: 1,
            schedule_id: 7,
            sched_type: dailysched::SCHED_TYPE_LINKY,
            all: false,
        })
        .unwrap();
    assert!(store.is_empty());
    assert!(store.pending_cancel().is_some());
    store.cancel_all(1);
    assert!(store.pending_cancel().unwrap().all);
}

// 17-05035-016-1015-05: fetch commands answered from the store.
#[test]
fn vector_schedule_behavior_17_05035_016_1015_05() {
    let mut attr_store = dailysched::server_store().unwrap();
    let mut reporting = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut behavior = dailysched::ServerBehavior::new();
    // Empty store: fetches answer not-found.
    let q = dailysched::ScheduleQuery {
        provider: dailysched::PROVIDER_ANY,
        earliest_start: 0,
        min_issuer: dailysched::ISSUER_ANY,
        max_count: 0,
        sched_type: dailysched::SCHED_TYPE_ANY,
    };
    let mut qbuf = [0u8; 14];
    dailysched::encode_get_schedule(&q, &mut qbuf).unwrap();
    let err = behavior
        .handle_cluster_command(
            &mut ctx(&mut attr_store, &mut reporting, &mut events),
            &hdr(0x00),
            0x00,
            &qbuf,
        )
        .unwrap_err();
    assert_eq!(err, ZclStatus::NotFound);
    let err = behavior
        .handle_cluster_command(
            &mut ctx(&mut attr_store, &mut reporting, &mut events),
            &hdr(0x05),
            0x05,
            &[],
        )
        .unwrap_err();
    assert_eq!(err, ZclStatus::NotFound);
    // File one schedule + profile, then fetch both.
    behavior
        .schedules()
        .file_schedule(&dailysched::Schedule {
            provider: 2,
            issuer: 1,
            schedule_id: 4,
            day_id: 6,
            start: 0,
            sched_type: dailysched::SCHED_TYPE_LINKY,
            time_ref: dailysched::TIME_REF_UTC,
            name_len: 1,
            name: {
                let mut n = [0u8; dailysched::MAX_SCHEDULE_NAME];
                n[0] = b'Q';
                n
            },
        })
        .unwrap();
    let outcome = behavior
        .handle_cluster_command(
            &mut ctx(&mut attr_store, &mut reporting, &mut events),
            &hdr(0x00),
            0x00,
            &qbuf,
        )
        .unwrap();
    assert_eq!(outcome.reply_cmd, Some(0x00));
    let sched =
        dailysched::decode_publish_schedule(&outcome.reply_body[..outcome.reply_len as usize])
            .unwrap();
    assert_eq!(sched.schedule_id, 4);
    let mut entries = [dailysched::DayEntry {
        start_min: 0,
        tier: 0,
        aux: 0,
    }; dailysched::MAX_DAY_ENTRIES];
    entries[0] = dailysched::DayEntry {
        start_min: 0,
        tier: 2,
        aux: 0x02,
    };
    behavior
        .schedules()
        .file_profile(&dailysched::DayProfile {
            provider: 2,
            issuer: 1,
            day_id: 6,
            entries,
            count: 1,
        })
        .unwrap();
    let mut dbuf = [0u8; 6];
    dailysched::encode_get_day_profile(2, 6, &mut dbuf).unwrap();
    let outcome = behavior
        .handle_cluster_command(
            &mut ctx(&mut attr_store, &mut reporting, &mut events),
            &hdr(0x01),
            0x01,
            &dbuf,
        )
        .unwrap();
    assert_eq!(outcome.reply_cmd, Some(0x01));
    // Live refresh applies the profile pair to the attributes.
    let applied = behavior.refresh_live(
        &mut ctx(&mut attr_store, &mut reporting, &mut events),
        3_600,
    );
    assert_eq!(applied, Some((2, 0x02)));
    // Client builders frame the fetches toward the server.
    let mut frame = [0u8; 32];
    let n = dailysched::client::get_schedule(0x0a, &q, &mut frame).unwrap();
    assert_eq!(frame[0] & 0x01, 0x01);
    assert_eq!(frame[1], 0x0a);
    assert_eq!(frame[2], 0x00);
    assert_eq!(n, 3 + 14);
    let n = dailysched::client::get_cancellation(0x0b, &mut frame).unwrap();
    assert_eq!((n, frame[1], frame[2]), (3, 0x0b, 0x05));
}

// PublishSchedule roundtrip fuzz leg (deterministic name sweep).
#[test]
fn fuzz_publish_schedule_roundtrip() {
    for i in 0..64u8 {
        let len = (i % 13) as usize;
        let mut name = [0u8; dailysched::MAX_SCHEDULE_NAME];
        for (k, b) in name.iter_mut().enumerate().take(len) {
            *b = i.wrapping_add(k as u8);
        }
        #[allow(clippy::cast_possible_truncation)]
        let sched = dailysched::Schedule {
            provider: u32::from(i),
            issuer: u32::from(i) * 7,
            schedule_id: u32::from(i),
            day_id: u16::from(i),
            start: u32::from(i) * 1_000,
            sched_type: dailysched::SCHED_TYPE_LINKY,
            time_ref: i % 3,
            name_len: len as u8,
            name,
        };
        let mut out = [0u8; 64];
        let n = dailysched::encode_publish_schedule(&sched, &mut out).unwrap();
        assert_eq!(
            dailysched::decode_publish_schedule(&out[..n]).unwrap(),
            sched
        );
    }
}

// One trivially reusable sim loop: a full UTC day stepped in
// 15-minute grids flips the tier at the profile boundary.
#[test]
fn sim_dailysched_day_boundary() {
    let mut store = dailysched::ScheduleStore::new();
    store
        .file_schedule(&dailysched::Schedule {
            provider: 1,
            issuer: 1,
            schedule_id: 1,
            day_id: 1,
            start: 0,
            sched_type: dailysched::SCHED_TYPE_LINKY,
            time_ref: dailysched::TIME_REF_UTC,
            name_len: 0,
            name: [0; dailysched::MAX_SCHEDULE_NAME],
        })
        .unwrap();
    let mut entries = [dailysched::DayEntry {
        start_min: 0,
        tier: 0,
        aux: 0,
    }; dailysched::MAX_DAY_ENTRIES];
    entries[0] = dailysched::DayEntry {
        start_min: 0,
        tier: 1,
        aux: 0,
    };
    entries[1] = dailysched::DayEntry {
        start_min: 360,
        tier: 3,
        aux: 0x01,
    };
    store
        .file_profile(&dailysched::DayProfile {
            provider: 1,
            issuer: 1,
            day_id: 1,
            entries,
            count: 2,
        })
        .unwrap();
    let mut flips = 0;
    let mut prev = 1u8;
    let mut t = 0u32;
    while t < 86_400 {
        let (tier, _) = store.evaluate(t).unwrap();
        if tier != prev {
            flips += 1;
            prev = tier;
        }
        t += 900;
    }
    assert_eq!((flips, prev), (1, 3));
}

// ---- ERL ------------------------------------------------------------

// 17-05031-011-4-01/03: device identity and mandatory cluster sets.
#[test]
fn vector_erl_identity_17_05031_011_4_01() {
    assert_eq!(erl::DEVICE_ID, 0x0509);
    assert_eq!(erl::REVISION, 1);
    assert!(erl::SERVER_MANDATORY.contains(&0x0702));
    assert!(erl::SERVER_MANDATORY.contains(&0x070d));
    assert!(erl::SERVER_MANDATORY.contains(&0x0b04));
    assert!(erl::SERVER_MANDATORY.contains(&0x0000));
    assert_eq!(erl::CLIENT_MANDATORY, &[0x0003, 0x000a]);
    assert!(erl::covers(erl::SERVER_MANDATORY, erl::SERVER_MANDATORY));
    assert!(!erl::covers(
        &erl::SERVER_MANDATORY[1..],
        erl::SERVER_MANDATORY
    ));
    assert!(erl::conforms(erl::SERVER_MANDATORY, erl::CLIENT_MANDATORY));
    assert!(!erl::conforms(erl::SERVER_MANDATORY, &[0x0003]));
    assert!(!erl::conforms(&[0x0000], erl::CLIENT_MANDATORY));
}

// 17-05031-011-4-04/05: attribute and command table spot checks.
#[test]
fn vector_erl_tables_17_05031_011_4_04() {
    let row = erl::find_attr(0x0b04, 0x050b).unwrap();
    assert!(row.reportable);
    let row = erl::find_attr(0x0000, 0x0000).unwrap();
    assert!(!row.reportable);
    assert!(erl::find_attr(0x0702, 0x0209).unwrap().reportable);
    assert!(erl::find_attr(0x070d, 0x0100).unwrap().reportable);
    assert!(erl::find_attr(0x070d, 0x0102).is_some());
    assert!(erl::find_attr(0x1234, 0x0000).is_none());
    assert!(erl::COMMANDS_RX.contains(&erl::CmdReq {
        cluster: 0x070d,
        cmd: 0x05
    }));
    assert!(erl::COMMANDS_RX.contains(&erl::CmdReq {
        cluster: 0x0702,
        cmd: 0x08
    }));
    assert_eq!(erl::COMMANDS_RX.len(), 11);
    assert_eq!(erl::COMMANDS_TX.len(), 9);
    // Metering GetSampledData response follows the sampled-data request.
    let tx = erl::COMMANDS_TX
        .iter()
        .find(|c| c.cluster == 0x0702 && c.cmd == 0x07)
        .unwrap();
    assert_eq!(tx.on_receipt_of, 0x08);
    // CancelAllSchedules is unsolicited.
    let tx = erl::COMMANDS_TX
        .iter()
        .find(|c| c.cluster == 0x070d && c.cmd == 0x06)
        .unwrap();
    assert_eq!(tx.on_receipt_of, 0xff);
}

// Attribute-table roundtrip fuzz leg: every row is findable.
#[test]
fn fuzz_erl_attr_table_roundtrip() {
    for row in erl::REQUIRED_ATTRS {
        assert_eq!(erl::find_attr(row.cluster, row.attr), Some(*row));
    }
    assert!(!erl::REQUIRED_ATTRS.is_empty());
}

// ---- linky ----------------------------------------------------------

// 17-05019-012-104-01: mode octet codec.
#[test]
fn vector_linky_mode_17_05019_012_104_01() {
    let mut out = [0u8; 1];
    assert_eq!(linky::encode_linky_mode(false, &mut out), Ok(1));
    assert_eq!(out, [0x00]);
    assert_eq!(linky::encode_linky_mode(true, &mut out), Ok(1));
    assert_eq!(out, [0x01]);
    assert_eq!(linky::decode_linky_mode(&[0x00]), Ok(false));
    assert_eq!(linky::decode_linky_mode(&[0x01]), Ok(true));
    assert!(linky::decode_linky_mode(&[0x02]).is_err());
    assert!(linky::decode_linky_mode(&[]).is_err());
    assert!(linky::decode_linky_mode(&[0x01, 0x00]).is_err());
    assert!(linky::encode_linky_mode(true, &mut []).is_err());
    assert!(linky::mode_is_advanced(0x01));
    assert!(!linky::mode_is_advanced(0x00));
    assert!(linky::mode_well_formed(0x00));
    assert!(!linky::mode_well_formed(0x80));
}

// 17-05019-012-104-02/03: reason codes, tier rules, day-max track.
#[test]
fn vector_linky_reason_tier_daymax_17_05019_012_104_02() {
    assert!(linky::disconnect_reason_known(0x00));
    assert!(linky::disconnect_reason_known(0x05));
    assert!(!linky::disconnect_reason_known(0x06));
    assert_eq!(linky::decode_disconnect_reason(&[0x03]), Ok(0x03));
    assert_eq!(
        linky::decode_disconnect_reason(&[0x09]),
        Err(ZclStatus::InvalidField)
    );
    assert!(linky::decode_disconnect_reason(&[]).is_err());
    assert!(linky::tiers_in_use_valid(0));
    assert!(linky::tiers_in_use_valid(48));
    assert!(!linky::tiers_in_use_valid(49));
    assert_eq!(linky::CLUSTER_ID, 0x0702);
    assert!(linky::attr_def(0x0209).is_some());
    assert!(linky::attr_def(0x0d08).is_some());
    assert!(linky::attr_def(0x0000).is_none());
    // Table stays ascending.
    let mut prev = 0u16;
    for a in linky::LINKY_ATTRS {
        assert!(a.id > prev);
        prev = a.id;
    }
    // Day-max keeps the largest observation (ties keep first).
    let mut day = linky::DayMax::new();
    assert!(!day.valid);
    day.observe(100, 1_000);
    day.observe(90, 2_000);
    assert_eq!((day.value, day.at_utc), (100, 1_000));
    day.observe(100, 3_000);
    assert_eq!(day.at_utc, 1_000);
    day.observe(140, 4_000);
    assert_eq!((day.value, day.at_utc), (140, 4_000));
    day.reset();
    assert!(!day.valid);
    day.observe(5, 6);
    assert_eq!((day.value, day.at_utc), (5, 6));
}

// Day-max fuzz leg: the record always equals the prefix maximum.
#[test]
fn fuzz_linky_daymax_prefix_max() {
    let mut day = linky::DayMax::new();
    let mut best = 0u64;
    let mut i = 0u64;
    while i < 200 {
        // Deterministic pseudo-random sequence, no RNG dependency.
        let demand = (i * 37 + 11) % 151;
        if demand > best {
            best = demand;
        }
        day.observe(demand, i as u32);
        assert_eq!(day.value, best);
        i += 1;
    }
}

// ---- device type library --------------------------------------------

// 23-02016-002-14-01/02: Door Lock descriptor and coverage.
#[test]
fn vector_devtype_door_lock_23_02016_002_14_01() {
    assert_eq!(devtype::DOOR_LOCK_ID, 0x000a);
    assert_eq!(devtype::DOOR_LOCK.id, 0x000a);
    assert_eq!(devtype::DOOR_LOCK.revision, 1);
    assert!(devtype::DOOR_LOCK.conforms(&[0x0000, 0x0003, 0x0101, 0x000a], &[]));
    assert!(!devtype::DOOR_LOCK.conforms(&[0x0000, 0x0003], &[]));
    assert_eq!(devtype::find_device(0x000a).unwrap().id, 0x000a);
    assert!(devtype::find_device(0x9999).is_none());
}

// 23-02016-002-14-03/04/05: restriction plus table contents.
#[test]
fn vector_devtype_restriction_tables_23_02016_002_14_03() {
    assert!(devtype::door_lock_restricted(&[0x0000, 0x0004]));
    assert!(devtype::door_lock_restricted(&[0x0005]));
    assert!(!devtype::door_lock_restricted(&[0x0000, 0x0003, 0x0101]));
    assert!(devtype::DOOR_LOCK_ATTRS.contains(&(0x0101, 0x0000)));
    assert!(devtype::DOOR_LOCK_ATTRS.contains(&(0x0101, 0x0002)));
    assert!(devtype::DOOR_LOCK_COMMANDS_RX.contains(&(0x0101, 0x01)));
    assert!(devtype::DOOR_LOCK_COMMANDS_TX.contains(&(0x0101, 0x01, 0x01)));
}

// Coverage fuzz leg: dropping any single mandatory cluster breaks it.
#[test]
fn fuzz_devtype_coverage_subsets() {
    let full = [0x0000u16, 0x0003, 0x0101, 0x000a];
    assert!(devtype::DOOR_LOCK.servers_covered(&full));
    for drop in 0..3usize {
        let mut sub = full;
        sub[drop] = 0xffff;
        let mandatory = &sub[..3];
        // Only the three mandatory entries matter for the negative leg.
        let _ = mandatory;
    }
    for required in devtype::DOOR_LOCK_SERVER_MANDATORY {
        let pared: Vec<u16> = full.iter().copied().filter(|c| c != required).collect();
        assert!(!devtype::DOOR_LOCK.servers_covered(&pared));
    }
}

// ---- aliro ----------------------------------------------------------

// 26-42802-001-11-01/02: feature octet codec.
#[test]
fn vector_aliro_adv_features_26_42802_001_11_01() {
    let mut out = [0u8; 1];
    // UWB + touch + version 5 -> 0x80 | 0x18 | 0x05 = 0x9D.
    assert_eq!(
        aliro::encode_adv_features(true, false, 0x03, 0x05, &mut out),
        Ok(1)
    );
    assert_eq!(out, [0x9d]);
    assert_eq!(aliro::decode_adv_features(0x9d), (true, false, 0x03, 0x05));
    // Both flows + no error + version 0 -> 0xC0.
    assert_eq!(
        aliro::encode_adv_features(true, true, 0x00, 0x00, &mut out),
        Ok(1)
    );
    assert_eq!(out, [0xc0]);
    assert_eq!(aliro::decode_adv_features(0xc0), (true, true, 0x00, 0x00));
    // Field masks admit only defined classes: every octet unpacks.
    assert_eq!(aliro::decode_adv_features(0x20), (false, false, 0x00, 0x00));
    // Undefined notification and version overflow are refused.
    assert!(aliro::encode_adv_features(true, true, 0x04, 0x00, &mut out).is_err());
    assert!(aliro::encode_adv_features(true, true, 0x00, 0x08, &mut out).is_err());
    assert!(aliro::encode_adv_features(true, true, 0x00, 0x00, &mut []).is_err());
    assert!(aliro::source_known(aliro::SOURCE_MATTER));
    assert!(!aliro::source_known(0x08));
    assert!(aliro::status_known(aliro::STATUS_REJECT));
    assert!(!aliro::status_known(0x02));
}

// 26-42802-001-11-02: event attribute codec.
#[test]
fn vector_aliro_event_attr_26_42802_001_11_02() {
    // Busy marker: id 0 + zero length.
    let busy = aliro::EventAttr {
        id: 0,
        reason: 0,
        len: 0,
        descriptor: [0; aliro::MAX_DESCRIPTOR],
    };
    let mut out = [0u8; 40];
    assert_eq!(aliro::encode_event_attr(&busy, &mut out), Ok(2));
    assert_eq!(&out[..2], &[0x00, 0x00]);
    assert_eq!(aliro::decode_event_attr(&out[..2]).unwrap(), busy);
    // General error: id 1 + length 1 + reason 2.
    let err_attr = aliro::EventAttr {
        id: 1,
        reason: 2,
        len: 0,
        descriptor: [0; aliro::MAX_DESCRIPTOR],
    };
    assert_eq!(aliro::encode_event_attr(&err_attr, &mut out), Ok(3));
    assert_eq!(&out[..3], &[0x01, 0x01, 0x02]);
    assert_eq!(aliro::decode_event_attr(&out[..3]).unwrap(), err_attr);
    assert!(aliro::decode_event_attr(&[0x01, 0x01, 0x04]).is_err());
    // Reader descriptor: id 2 + length + body.
    let mut desc = [0u8; aliro::MAX_DESCRIPTOR];
    desc[0] = 0xb5;
    desc[1] = 0x02;
    let rd = aliro::EventAttr {
        id: 2,
        reason: 0,
        len: 2,
        descriptor: desc,
    };
    assert_eq!(aliro::encode_event_attr(&rd, &mut out), Ok(4));
    assert_eq!(&out[..4], &[0x02, 0x02, 0xb5, 0x02]);
    assert_eq!(aliro::decode_event_attr(&out[..4]).unwrap(), rd);
    assert!(aliro::decode_event_attr(&[0x02, 0x02, 0xb5]).is_err());
    assert!(aliro::decode_event_attr(&[0x07, 0x00]).is_err());
    assert!(aliro::error_reason_known(aliro::ERROR_URSK_UNAVAILABLE));
    assert!(!aliro::error_reason_known(0x04));
}

// 26-42802-001-11-03: reader-state behavior.
#[test]
fn vector_aliro_reader_behavior_26_42802_001_11_03() {
    let mut store = aliro::server_store().unwrap();
    let mut reporting = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut behavior = aliro::ReaderBehavior::new();
    assert!(!behavior.is_busy());
    behavior.mark_busy(&mut ctx(&mut store, &mut reporting, &mut events));
    assert!(behavior.is_busy());
    behavior
        .state_changed(
            &mut ctx(&mut store, &mut reporting, &mut events),
            aliro::SOURCE_NFC_DEVICE,
            aliro::STATUS_ACCEPT,
        )
        .unwrap();
    assert!(!behavior.is_busy());
    use rounddance_zcl::types::Value;
    assert_eq!(
        store.get(aliro::ATTR_OPERATION_SOURCE),
        Some(Value::Enum8(aliro::SOURCE_NFC_DEVICE))
    );
    assert_eq!(
        behavior.state_changed(
            &mut ctx(&mut store, &mut reporting, &mut events),
            0x08,
            aliro::STATUS_ACCEPT,
        ),
        Err(ZclStatus::InvalidField)
    );
    assert_eq!(
        behavior.state_changed(
            &mut ctx(&mut store, &mut reporting, &mut events),
            aliro::SOURCE_AUTO,
            0x02,
        ),
        Err(ZclStatus::InvalidField)
    );
    behavior
        .set_notification(
            &mut ctx(&mut store, &mut reporting, &mut events),
            aliro::NOTIFY_LOW_BATTERY,
        )
        .unwrap();
    assert_eq!(
        store.get(aliro::ATTR_NOTIFICATION),
        Some(Value::Enum8(aliro::NOTIFY_LOW_BATTERY))
    );
    assert_eq!(
        behavior.set_notification(&mut ctx(&mut store, &mut reporting, &mut events), 0x04,),
        Err(ZclStatus::InvalidField)
    );
    // The bridge takes no cluster-specific commands.
    let err = behavior
        .handle_cluster_command(
            &mut ctx(&mut store, &mut reporting, &mut events),
            &hdr(0x00),
            0x00,
            &[],
        )
        .unwrap_err();
    assert_eq!(err, ZclStatus::UnsupCommand);
}

// Advertisement roundtrip fuzz leg: every valid combination survives.
#[test]
fn fuzz_aliro_adv_roundtrip() {
    for flows in 0..4u8 {
        for notif in 0..4u8 {
            for ver in 0..8u8 {
                let mut out = [0u8; 1];
                aliro::encode_adv_features(
                    flows & 0x02 != 0,
                    flows & 0x01 != 0,
                    notif,
                    ver,
                    &mut out,
                )
                .unwrap();
                assert_eq!(
                    aliro::decode_adv_features(out[0]),
                    (flows & 0x02 != 0, flows & 0x01 != 0, notif, ver)
                );
            }
        }
    }
}
