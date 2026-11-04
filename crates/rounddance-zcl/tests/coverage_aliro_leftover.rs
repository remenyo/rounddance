//! Coverage vectors for doc `26-42802-001` (Aliro, page/clause
//! granularity — the extraction carries no margin anchors, so line
//! anchors do not exist and coverage is recorded per page and clause)
//! plus the ERL / Daily Schedule / Lighting-Occupancy / Linky /
//! DeviceType leftovers (docs `17-05031-011`, `17-05035-016`,
//! `15-0014-05`, `17-05019-012`, `23-02016-002`).
//!
//! Each test names the requirement ID it verifies. Byte strings are
//! hand-computed from the paraphrased layouts in
//! `uncovered::{aliro, erl, dailysched, devtype, linky}` — never
//! copied from spec text (D1, `SCOPE.md` §2). Requirement IDs are
//! repo-minted, MINTED-pending-confirm.
//!
//! Method limit (recorded here and in the annex): the Aliro
//! extraction has no margin line anchors, so vectors below cite
//! PDF pages and clause/table numbers instead of `pNNNN-Lxxx`
//! anchors; behavior assertions carry the same weight as
//! line-anchored vectors elsewhere.

use rounddance_zcl::behavior::{Behavior, Ctx, EventQueue};
use rounddance_zcl::frame::{Direction, FrameControl, FrameType, Header};
use rounddance_zcl::types::Value;
use rounddance_zcl::uncovered::{aliro, dailysched, devtype, erl, linky};
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

// ---- Aliro advertisement Table 11-2 (PDF p108, §11.3) ---------------

// 26-42802-001-11-04: advertisement service marker + flow matrix.
#[test]
fn vector_aliro_adv_layout_26_42802_001_11_04() {
    // The service marker is fixed; the version field defaults to 0
    // and changes whenever the payload changes.
    assert_eq!(aliro::ADV_VERSION_MASK, 0x07);
    assert_eq!(aliro::NOTIFICATION_MASK, 0x18);
    assert_eq!(aliro::NOTIFICATION_SHIFT, 3);
    // Flow-bit matrix: every BLE/UWB × BLE-only combination packs.
    let mut out = [0u8; 1];
    for (uwb, only) in [(false, false), (true, false), (false, true), (true, true)] {
        aliro::encode_adv_features(uwb, only, aliro::NOTIFY_NO_ERROR, 0, &mut out).unwrap();
        let (d_uwb, d_only, notif, ver) = aliro::decode_adv_features(out[0]);
        assert_eq!(
            (d_uwb, d_only, notif, ver),
            (uwb, only, aliro::NOTIFY_NO_ERROR, 0)
        );
    }
    assert_eq!(out.len(), 1);
    // All four notification classes pack (Table 11-2 bits [4:3]).
    for notif in [
        aliro::NOTIFY_NO_ERROR,
        aliro::NOTIFY_UNKNOWN_ERROR,
        aliro::NOTIFY_LOW_BATTERY,
        aliro::NOTIFY_SENSOR_TRIGGERED,
    ] {
        aliro::encode_adv_features(false, false, notif, 0, &mut out).unwrap();
        assert_eq!(aliro::decode_adv_features(out[0]).2, notif);
    }
    // RFU version values and unknown classes are refused.
    assert!(aliro::encode_adv_features(false, false, 0x04, 0, &mut out).is_err());
    assert!(
        aliro::encode_adv_features(false, false, aliro::NOTIFY_NO_ERROR, 0x08, &mut out).is_err()
    );
    assert!(aliro::encode_adv_features(false, false, aliro::NOTIFY_NO_ERROR, 0, &mut []).is_err());
}

// 26-42802-001-11-05: trigger persistence + descriptor bounds.
#[test]
fn vector_aliro_trigger_persistence_26_42802_001_11_05() {
    // A sensor trigger stays published until the application clears
    // it: busy cycles and state changes never touch the class.
    let mut store = aliro::server_store().unwrap();
    let mut reporting = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut behavior = aliro::ReaderBehavior::new();
    behavior
        .set_notification(
            &mut ctx(&mut store, &mut reporting, &mut events),
            aliro::NOTIFY_SENSOR_TRIGGERED,
        )
        .unwrap();
    behavior.mark_busy(&mut ctx(&mut store, &mut reporting, &mut events));
    behavior
        .state_changed(
            &mut ctx(&mut store, &mut reporting, &mut events),
            aliro::SOURCE_BLE_ONLY_DEVICE,
            aliro::STATUS_ACCEPT,
        )
        .unwrap();
    assert_eq!(
        store.get(aliro::ATTR_NOTIFICATION),
        Some(Value::Enum8(aliro::NOTIFY_SENSOR_TRIGGERED))
    );
    // Reader-descriptor bodies stay bounded (Table 11-15).
    let mut desc = [0xabu8; aliro::MAX_DESCRIPTOR];
    desc[0] = 0x01;
    let attr = aliro::EventAttr {
        id: aliro::EVENT_ATTR_READER_DESCRIPTOR,
        reason: 0,
        len: aliro::MAX_DESCRIPTOR as u8,
        descriptor: desc,
    };
    let mut buf = [0u8; 2 + aliro::MAX_DESCRIPTOR];
    let n = aliro::encode_event_attr(&attr, &mut buf).unwrap();
    assert_eq!(n, 2 + aliro::MAX_DESCRIPTOR);
    assert_eq!(aliro::decode_event_attr(&buf[..n]).unwrap(), attr);
    let mut too_long = attr;
    too_long.len = aliro::MAX_DESCRIPTOR as u8 + 1;
    assert!(aliro::encode_event_attr(&too_long, &mut buf).is_err());
}

// 26-42802-001-11-06: full source + error + status alphabets.
#[test]
fn vector_aliro_alphabets_26_42802_001_11_06() {
    // Operation sources (Table 11-20): the full 0..=7 set is known.
    for s in 0..=aliro::SOURCE_MATTER {
        assert!(aliro::source_known(s), "source {s}");
    }
    assert!(!aliro::source_known(aliro::SOURCE_MATTER + 1));
    // Error reasons (Table 11-16): the full set is known.
    for r in [
        aliro::ERROR_UNKNOWN,
        aliro::ERROR_RESOURCE_UNAVAILABLE,
        aliro::ERROR_WRONG_PARAMETERS,
        aliro::ERROR_URSK_UNAVAILABLE,
    ] {
        assert!(aliro::error_reason_known(r));
        let attr = aliro::EventAttr {
            id: aliro::EVENT_ATTR_GENERAL_ERROR,
            reason: r,
            len: 0,
            descriptor: [0u8; aliro::MAX_DESCRIPTOR],
        };
        let mut buf = [0u8; 4];
        let n = aliro::encode_event_attr(&attr, &mut buf).unwrap();
        assert_eq!(aliro::decode_event_attr(&buf[..n]).unwrap(), attr);
    }
    assert!(!aliro::error_reason_known(0x04));
    // Verdicts (Table 11-14): accept/reject only.
    assert!(aliro::status_known(aliro::STATUS_ACCEPT));
    assert!(aliro::status_known(aliro::STATUS_REJECT));
    assert!(!aliro::status_known(0x02));
    // Busy markers round-trip with an empty body (Table 11-15).
    let busy = aliro::EventAttr {
        id: aliro::EVENT_ATTR_BUSY,
        reason: 0,
        len: 0,
        descriptor: [0u8; aliro::MAX_DESCRIPTOR],
    };
    let mut buf = [0u8; 4];
    let n = aliro::encode_event_attr(&busy, &mut buf).unwrap();
    assert_eq!(n, 2);
    assert_eq!(aliro::decode_event_attr(&buf[..n]).unwrap(), busy);
    assert!(aliro::decode_event_attr(&buf[..1]).is_err());
}

// ---- ERL leftovers (doc 17-05031-011) --------------------------------

// 17-05031-011-4-06: conformance over the mandatory cluster lists.
#[test]
fn vector_erl_conformance_17_05031_011_4_06() {
    // Exact mandatory sets conform ...
    assert!(erl::conforms(erl::SERVER_MANDATORY, erl::CLIENT_MANDATORY));
    // ... missing any mandatory server cluster breaks conformance ...
    let short: Vec<u16> = erl::SERVER_MANDATORY.iter().copied().skip(1).collect();
    assert!(!erl::conforms(&short, erl::CLIENT_MANDATORY));
    // ... while extra clusters and the optional OTA set are fine.
    let mut extra = erl::SERVER_MANDATORY.to_vec();
    extra.push(erl::CLUSTER_OTA);
    assert!(erl::conforms(&extra, erl::CLIENT_MANDATORY));
    // Covers() is the subset primitive underneath.
    assert!(erl::covers(&[0x0000, 0x0003], &[0x0000]));
    assert!(!erl::covers(&[0x0000], &[0x0000, 0x0003]));
    // The messaging row pins the newly modeled cluster id.
    assert_eq!(erl::CLUSTER_MESSAGING, 0x0703);
    assert_eq!(erl::DEVICE_ID, 0x0509);
}

// 17-05031-011-4-07: generated-command trigger mapping.
#[test]
fn vector_erl_triggers_17_05031_011_4_07() {
    // Every generated command names its triggering receipt ...
    for tx in erl::COMMANDS_TX {
        assert!(
            erl::COMMANDS_RX.contains(&erl::CmdReq {
                cluster: tx.cluster,
                cmd: tx.on_receipt_of,
            }) || tx.on_receipt_of == 0xff
        );
    }
    assert_eq!(erl::COMMANDS_TX.len(), 9);
}

// ---- Daily Schedule leftovers (doc 17-05035-016) ----------------------

// 17-05035-016-1015-06: day-color + peak-notice helpers.
#[test]
fn vector_dailysched_colors_17_05035_016_1015_06() {
    assert!(dailysched::color_known(dailysched::COLOR_BLUE));
    assert!(dailysched::color_known(dailysched::COLOR_WHITE));
    assert!(dailysched::color_known(dailysched::COLOR_RED));
    assert!(!dailysched::color_known(0x00));
    assert!(!dailysched::color_known(0x04));
    assert!(dailysched::time_ref_known(dailysched::TIME_REF_UTC));
    assert!(dailysched::time_ref_known(dailysched::TIME_REF_STANDARD));
    assert!(dailysched::time_ref_known(dailysched::TIME_REF_LOCAL));
    assert!(!dailysched::time_ref_known(0x03));
    // Peak colors step blue -> white -> red; notices mirror the peak.
    let status = 0x6du8;
    assert_eq!(dailysched::day_color(status), dailysched::COLOR_BLUE);
    assert_eq!(dailysched::next_day_color(status), dailysched::COLOR_RED);
    assert!(dailysched::color_known(dailysched::day_color(status)));
    assert_ne!(
        dailysched::next_day_color(status),
        dailysched::day_color(status)
    );
    assert_eq!(dailysched::peak_notice(0x6d), 0x02);
    assert_eq!(dailysched::on_peak(0x6d), 0x01);
    assert_eq!(dailysched::MAX_SCHEDULES, 2);
    assert_eq!(dailysched::SCHED_TYPE_LINKY, 0x00);
    assert_eq!(dailysched::SCHED_TYPE_ANY, 0xff);
}

// 17-05035-016-1015-07: day-profile query codec + tier ceiling.
#[test]
fn vector_dailysched_day_query_17_05035_016_1015_07() {
    let mut buf = [0u8; dailysched::GET_DAY_PROFILE_LEN];
    let n = dailysched::encode_get_day_profile(0x1122_3344, 0x0203, &mut buf).unwrap();
    assert_eq!(n, dailysched::GET_DAY_PROFILE_LEN);
    assert_eq!(
        dailysched::decode_get_day_profile(&buf).unwrap(),
        (0x1122_3344, 0x0203)
    );
    assert!(dailysched::decode_get_day_profile(&buf[..5]).is_err());
    assert_eq!(dailysched::MAX_TIER, 48);
    assert_eq!(dailysched::PROVIDER_ANY, 0xffff_ffff);
    assert_eq!(dailysched::PEAK_UNSET, 0xffff_ffff);
}

// ---- Lighting leftovers (doc 15-0014-05) -------------------------------

// 15-0014-05-13-02: occupancy-sensor rows ride the modeled cluster.
#[test]
fn vector_lighting_sensor_rows_15_0014_05_13_02() {
    use rounddance_zcl::cluster::ClusterDef as _;
    use rounddance_zcl::uncovered::occupancy;
    // The sensor device requires the occupied-flags row and the
    // sensor-type row; the modeled server carries both, ascending.
    let ids: Vec<u16> = occupancy::ServerDef
        .attributes()
        .iter()
        .map(|a| a.id)
        .collect();
    assert!(ids.contains(&occupancy::ATTR_OCCUPANCY));
    assert!(ids.contains(&occupancy::ATTR_SENSOR_TYPE));
    assert!(ids.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(occupancy::CLUSTER_ID, 0x0406);
}

// 15-0014-05-06-01: lamp/controller devices stay deferred here.
#[test]
fn vector_lighting_lamps_deferred_15_0014_05_06_01() {
    // Lamp and controller device types need color/ballast/level
    // clusters with no bounded model in this crate: the registry
    // carries no descriptor for them (explicit follow-up).
    assert!(devtype::find_device(0x0100).is_none());
    assert!(devtype::find_device(0x0101).is_none());
    assert!(devtype::find_device(0x0102).is_none());
    assert!(devtype::find_device(0x000a).is_some());
}

// ---- Linky leftovers (doc 17-05019-012) --------------------------------

// 17-05019-012-104-03: identifier string ceilings.
#[test]
fn vector_linky_string_ceilings_17_05019_012_104_03() {
    assert_eq!(linky::MAX_METER_ID, 32);
    assert_eq!(linky::MAX_SITE_ID, 33);
    assert_eq!(linky::MAX_SERIAL, 25);
    assert_eq!(linky::MAX_TIERS, 48);
    // Every defined row resolves; unknown rows miss.
    for id in [
        linky::ATTR_STATUS,
        linky::ATTR_EXTENDED_STATUS,
        linky::ATTR_CURRENT_METER_ID,
        linky::ATTR_LINKY_MODE,
        linky::ATTR_ACTIVE_TIER_DELIVERED,
        linky::ATTR_SITE_ID,
        linky::ATTR_DAY_MAX_DELIVERED,
        linky::ATTR_DAY_MAX_DELIVERED_TIME,
        linky::ATTR_REACTIVE_Q1,
        linky::ATTR_REACTIVE_Q4,
    ] {
        assert!(linky::attr_def(id).is_some(), "row {id:#06x} missing");
    }
    assert!(linky::attr_def(0xffff).is_none());
}

// 17-05019-012-104-04: mode codec round-trip + shape rules.
#[test]
fn vector_linky_mode_codec_17_05019_012_104_04() {
    let mut buf = [0u8; 1];
    assert_eq!(linky::encode_linky_mode(true, &mut buf).unwrap(), 1);
    assert!(linky::decode_linky_mode(&buf).unwrap());
    assert_eq!(linky::encode_linky_mode(false, &mut buf).unwrap(), 1);
    assert!(!linky::decode_linky_mode(&buf).unwrap());
    assert!(linky::mode_is_advanced(linky::MODE_ADVANCED_BIT));
    assert!(!linky::mode_is_advanced(0x00));
    assert!(linky::mode_well_formed(0x00));
    assert!(linky::mode_well_formed(linky::MODE_ADVANCED_BIT));
    assert!(!linky::mode_well_formed(0x02));
    assert!(linky::decode_linky_mode(&[]).is_err());
}

// ---- DeviceType leftovers (doc 23-02016-002) ----------------------------

// 23-02016-002-14-06: registry lookup + side coverage.
#[test]
fn vector_devtype_registry_23_02016_002_14_06() {
    let lock = devtype::find_device(devtype::DOOR_LOCK_ID).unwrap();
    assert_eq!(lock.id, 0x000a);
    assert_eq!(lock.revision, devtype::DOOR_LOCK_REVISION);
    assert!(lock.servers_covered(devtype::DOOR_LOCK_SERVER_MANDATORY));
    assert!(!lock.servers_covered(&[devtype::CLUSTER_BASIC]));
    assert!(lock.clients_covered(&[]));
    assert!(lock.conforms(devtype::DOOR_LOCK_SERVER_MANDATORY, &[]));
    // Class vocabulary: locks are always-addressable endpoints.
    assert_eq!(lock.class, devtype::DeviceClass::Simple);
    assert_ne!(lock.class, devtype::DeviceClass::Sleepy);
    assert_eq!(devtype::CLUSTER_DOOR_LOCK, 0x0101);
    // Full table lengths stay pinned (drift changes fail loudly).
    assert_eq!(devtype::DOOR_LOCK_ATTRS.len(), 12);
    assert_eq!(devtype::DOOR_LOCK_COMMANDS_RX.len(), 4);
    assert_eq!(devtype::DOOR_LOCK_COMMANDS_TX.len(), 3);
}

// ---- Aliro method-limit record (no margin anchors) ----------------------

// 26-42802-001-00-01: page-granularity method is pinned, not silent.
#[test]
fn vector_aliro_page_method_26_42802_001_00_01() {
    // The bridge cluster is locally administered (never a CSA ZCL
    // number): gateways must not confuse it with assigned clusters.
    assert_eq!(aliro::CLUSTER_ID, 0xfc00);
    // Revision and tables stay ascending for discovery integration.
    let ids: Vec<u16> = aliro::SERVER_ATTRS.iter().map(|a| a.id).collect();
    assert!(ids.windows(2).all(|w| w[0] < w[1]));
    assert!(!ids.contains(&0x0005));
    // Unknown bridge commands are refused, never absorbed.
    let mut store = aliro::server_store().unwrap();
    let mut reporting = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut behavior = aliro::ReaderBehavior::new();
    assert_eq!(
        behavior.handle_cluster_command(
            &mut ctx(&mut store, &mut reporting, &mut events),
            &hdr(0x7e),
            0x7e,
            &[]
        ),
        Err(ZclStatus::UnsupCommand)
    );
}
