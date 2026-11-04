//! Coverage vectors for ZCL cluster clauses (doc `07-5123-08`,
//! chapters 3/4/8/10): the newly modeled Demand Response and Load
//! Control (0x0701) and Messaging (0x0703) clusters plus opaque pins
//! for the deferred bodies (tunneling, prepayment, non-TOU shapes).
//!
//! The two new modules ship as `src/drlc.rs` / `src/messaging.rs` and
//! are used through the `rounddance_zcl::{drlc, messaging}` re-exports.
//!
//! Each test names the requirement ID it verifies. Byte strings are
//! hand-computed from the paraphrased layouts in the two modules —
//! never copied from spec text (D1, `SCOPE.md` §2). Requirement IDs
//! are repo-minted, MINTED-pending-confirm.

pub use rounddance_zcl::attrs;
pub use rounddance_zcl::behavior;
pub use rounddance_zcl::cluster;
pub use rounddance_zcl::frame;
pub use rounddance_zcl::types;
pub use rounddance_zcl::Error;
pub use rounddance_zcl::ZclStatus;

use rounddance_zcl::{drlc, messaging};

use rounddance_zcl::behavior::{Behavior, Ctx, EventQueue};
use rounddance_zcl::cluster::ClusterDef;
use rounddance_zcl::frame::{Direction, FrameControl, FrameType, Header};
use rounddance_zcl::uncovered::occupancy;
use rounddance_zcl::{electrical, metering, snapshot, supply, AttrStore, ReportingEngine};

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
        now_s: 1000,
        peer_onoff: None,
        sender_ieee: None,
    }
}

fn ev(issuer: u32, class: u16, group: u8, start: u32, duration: u16) -> drlc::LoadControlEvent {
    drlc::LoadControlEvent {
        issuer_event_id: issuer,
        device_class: class,
        group,
        start_time: start,
        duration_min: duration,
        criticality: drlc::CRITICALITY_EMERGENCY,
        cooling_offset: drlc::OFFSET_UNUSED,
        heating_offset: drlc::OFFSET_UNUSED,
        cooling_setpoint: drlc::SETPOINT_UNUSED,
        heating_setpoint: drlc::SETPOINT_UNUSED,
        avg_load_adjustment: drlc::AVG_LOAD_UNUSED,
        duty_cycle: drlc::DUTY_UNUSED,
        event_control: 0,
    }
}

// ---- DRLC identity (anchors p0685-L15582-L15585) -------------------

// 07-5123-08-103-01: cluster identity and revision.
#[test]
fn vector_drlc_identity_07_5123_08_103_01() {
    assert_eq!(drlc::CLUSTER_ID, 0x0701);
    assert_eq!(drlc::REVISION, 2);
    assert_eq!(drlc::ServerDef.cluster_id(), 0x0701);
    assert_eq!(drlc::ClientDef.cluster_id(), 0x0701);
    // The server side defines no attributes; the client side defines
    // the four filter/randomization attributes, ascending.
    assert!(drlc::ServerDef.attributes().is_empty());
    let ids: Vec<u16> = drlc::ClientDef.attributes().iter().map(|a| a.id).collect();
    assert_eq!(ids, vec![0x0000, 0x0001, 0x0002, 0x0003]);
    // Command sets ascend on both sides.
    let rx: Vec<u8> = drlc::ServerDef
        .received_commands()
        .iter()
        .map(|c| c.id)
        .collect();
    let tx: Vec<u8> = drlc::ServerDef
        .generated_commands()
        .iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(rx, vec![0x00, 0x01]);
    assert_eq!(tx, vec![0x00, 0x01, 0x02]);
    assert!(drlc::server_store().is_ok());
    let store = drlc::client_store(0x0001).unwrap();
    assert_eq!(drlc::class_of(&store), 0x0001);
    assert_eq!(drlc::group_of(&store), 0);
}

// ---- DRLC codecs (anchors p0686-p0692) ------------------------------

// 07-5123-08-103-02/06: event codec round-trip + tier rules.
#[test]
fn vector_drlc_event_codec_07_5123_08_103_06() {
    let event = ev(0x1122_3344, 0x0005, 0x02, 0x5566_7788, 60);
    let mut buf = [0u8; drlc::LOAD_CONTROL_EVENT_LEN];
    let n = drlc::encode_load_control_event(&event, &mut buf).unwrap();
    assert_eq!(n, drlc::LOAD_CONTROL_EVENT_LEN);
    assert_eq!(&buf[0..4], &[0x44, 0x33, 0x22, 0x11]);
    assert_eq!(&buf[4..6], &[0x05, 0x00]);
    assert_eq!(buf[6], 0x02);
    let back = drlc::decode_load_control_event(&buf).unwrap();
    assert_eq!(back, event);
    // Overlong durations and reserved tiers are refused.
    let mut bad = event;
    bad.duration_min = drlc::MAX_DURATION_MINUTES + 1;
    assert!(drlc::encode_load_control_event(&bad, &mut buf).is_err());
    assert!(drlc::decode_load_control_event(&buf[..22]).is_err());
    assert!(drlc::criticality_known(drlc::CRITICALITY_GREEN));
    assert!(drlc::criticality_known(
        drlc::CRITICALITY_SERVICE_DISCONNECT
    ));
    assert!(drlc::criticality_known(0x0c));
    assert!(!drlc::criticality_known(0x00));
    assert!(!drlc::criticality_known(0x10));
    assert_eq!(
        drlc::criticality_participation(drlc::CRITICALITY_GREEN),
        Some(drlc::PARTICIPATION_VOLUNTARY)
    );
    assert_eq!(
        drlc::criticality_participation(drlc::CRITICALITY_EMERGENCY),
        Some(drlc::PARTICIPATION_MANDATORY)
    );
    assert_eq!(
        drlc::criticality_participation(0x0c),
        Some(drlc::PARTICIPATION_UTILITY)
    );
    assert_eq!(drlc::criticality_participation(0x00), None);
}

// 07-5123-08-103-04: class/group overlap filters.
#[test]
fn vector_drlc_targeting_07_5123_08_103_04() {
    assert!(drlc::classes_overlap(0x0005, 0x0001));
    assert!(!drlc::classes_overlap(0x0004, 0x0001));
    assert!(drlc::groups_overlap(0x00, 0x07));
    assert!(drlc::groups_overlap(0x03, 0x00));
    assert!(drlc::groups_overlap(0x03, 0x03));
    assert!(!drlc::groups_overlap(0x03, 0x04));
}

// 07-5123-08-103-05: randomization application is pure caller math.
#[test]
fn vector_drlc_randomization_07_5123_08_103_05() {
    // No bits set: times pass through untouched.
    assert_eq!(drlc::apply_randomization(1000, 60, 0x00, 5, 7), (1000, 60));
    // Start bit delays the start; duration bit extends the duration.
    assert_eq!(
        drlc::apply_randomization(1000, 60, 0x03, 2, 3),
        (1000 + 120, 63)
    );
    // Start-only randomization keeps every event the same length.
    let (s1, d1) = drlc::apply_randomization(1000, 60, 0x01, 2, 0);
    let (s2, d2) = drlc::apply_randomization(1000, 60, 0x01, 4, 0);
    assert_eq!((d1, d2), (60, 60));
    assert_eq!((s2 - 1000) - (s1 - 1000), 120);
}

// 07-5123-08-103-07: cancel codec (zeroed effective-time tail).
#[test]
fn vector_drlc_cancel_codec_07_5123_08_103_07() {
    let cancel = drlc::CancelEvent {
        issuer_event_id: 0xaabb_ccdd,
        device_class: 0x0001,
        group: 0x02,
        cancel_control: 0x01,
    };
    let mut buf = [0u8; drlc::CANCEL_EVENT_LEN];
    let n = drlc::encode_cancel_event(&cancel, &mut buf).unwrap();
    assert_eq!(n, drlc::CANCEL_EVENT_LEN);
    assert_eq!(&buf[8..12], &[0x00, 0x00, 0x00, 0x00]);
    let back = drlc::decode_cancel_event(&buf).unwrap();
    assert_eq!(back, cancel);
    assert!(drlc::decode_cancel_event(&buf[..11]).is_err());
}

// 07-5123-08-103-08: report codec with bounded opaque signature.
#[test]
fn vector_drlc_report_codec_07_5123_08_103_08() {
    let event = ev(0x0102_0304, 0x0001, 0x00, 2000, 30);
    let rsp = drlc::unsigned_report(&event, drlc::STATUS_STARTED, 2001);
    assert_eq!(rsp.issuer_event_id, 0x0102_0304);
    assert_eq!(rsp.event_status, drlc::STATUS_STARTED);
    assert_eq!(rsp.signature_type, drlc::SIGNATURE_NONE);
    let mut buf = [0u8; drlc::REPORT_STATUS_PREFIX_LEN + drlc::MAX_SIGNATURE];
    let n = drlc::encode_report_event_status(&rsp, &mut buf).unwrap();
    assert_eq!(n, drlc::REPORT_STATUS_PREFIX_LEN + drlc::MAX_SIGNATURE);
    // The unused tail goes out as fill.
    assert!(buf[drlc::REPORT_STATUS_PREFIX_LEN..n]
        .iter()
        .all(|&b| b == 0xff));
    let back = drlc::decode_report_event_status(&buf[..n]).unwrap();
    assert_eq!(back, rsp);
    // Every defined outcome decodes; reserved values are refused.
    for s in [
        drlc::STATUS_RECEIVED,
        drlc::STATUS_OPT_OUT,
        drlc::STATUS_SUPERSEDED,
        drlc::STATUS_REJECTED_CANCEL,
        drlc::STATUS_REJECTED_UNDEFINED,
        drlc::STATUS_REJECTED,
    ] {
        assert!(drlc::report_status_known(s), "status {s:#04x}");
    }
    assert!(!drlc::report_status_known(0x00));
    assert!(!drlc::report_status_known(0x0b));
    // A zero status time is refused (never zero on the wire).
    let mut bad = rsp;
    bad.event_status_time = 0;
    assert!(drlc::encode_report_event_status(&bad, &mut buf).is_err());
}

// 07-5123-08-103-09: Get Scheduled Events codec (optional floor).
#[test]
fn vector_drlc_get_scheduled_codec_07_5123_08_103_09() {
    let bare = drlc::GetScheduledEvents {
        start_time: 5000,
        max_events: 2,
        min_issuer: None,
    };
    let mut buf = [0u8; 9];
    assert_eq!(drlc::encode_get_scheduled(&bare, &mut buf).unwrap(), 5);
    assert_eq!(drlc::decode_get_scheduled(&buf[..5]).unwrap(), bare);
    let paged = drlc::GetScheduledEvents {
        start_time: 5000,
        max_events: 1,
        min_issuer: Some(0x1234_5678),
    };
    assert_eq!(drlc::encode_get_scheduled(&paged, &mut buf).unwrap(), 9);
    assert_eq!(drlc::decode_get_scheduled(&buf[..9]).unwrap(), paged);
    // The all-ones floor means "no floor".
    let mut any = buf;
    any[5..9].copy_from_slice(&drlc::ISSUER_ANY.to_le_bytes());
    assert_eq!(drlc::decode_get_scheduled(&any).unwrap().min_issuer, None);
    assert!(drlc::decode_get_scheduled(&buf[..6]).is_err());
}

// ---- DRLC tables + behaviors (anchors p0685/p0693/p0699) -----------

// 07-5123-08-103-10: backlog with supersession, cancel, ordering.
#[test]
fn vector_drlc_table_07_5123_08_103_10() {
    let mut table = drlc::EventTable::new();
    assert!(table.is_empty());
    table.insert(ev(10, 0x0001, 0x00, 1000, 30));
    table.insert(ev(11, 0x0002, 0x00, 2000, 30));
    assert_eq!(table.len(), 2);
    // A newer overlapping event supersedes its older overlap only.
    table.insert(ev(12, 0x0001, 0x00, 1500, 30));
    assert_eq!(table.len(), 2);
    // An older-or-equal overlapping event loses.
    table.insert(ev(9, 0x0002, 0x00, 2500, 30));
    assert_eq!(table.len(), 2);
    // Non-overlapping classes coexist; a full table evicts the
    // oldest issuer id.
    table.insert(ev(13, 0x0004, 0x00, 1200, 30));
    table.insert(ev(14, 0x0008, 0x00, 1300, 30));
    assert_eq!(table.len(), 4);
    table.insert(ev(15, 0x0010, 0x00, 1400, 30));
    assert_eq!(table.len(), 4);
    assert!(!table.cancel(11));
    // Answers sort by (start, issuer id).
    let mut out = [ev(0, 0, 0, 0, 1); 4];
    let n = table.scheduled_since(0, 0, None, &mut out);
    assert_eq!(n, 4);
    let starts: Vec<u32> = out[..n].iter().map(|e| e.start_time).collect();
    let mut sorted = starts.clone();
    sorted.sort_unstable();
    assert_eq!(starts, sorted);
    // Cancel removes the named event only.
    assert!(table.cancel(12));
    assert!(!table.cancel(12));
    assert_eq!(table.len(), 3);
    table.cancel_all();
    assert!(table.is_empty());
}

// 07-5123-08-103-11: client filters + reports.
#[test]
fn vector_drlc_client_behavior_07_5123_08_103_11() {
    let mut store = drlc::client_store(0x0001).unwrap();
    let mut reporting = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut behavior = drlc::ClientBehavior::new();
    // A non-target event is ignored with SUCCESS, never stored.
    let foreign = ev(20, 0x0002, 0x00, 1000, 30);
    let outcome =
        behavior.handle_event(&mut ctx(&mut store, &mut reporting, &mut events), &foreign);
    assert!(outcome.is_ok());
    assert!(behavior.table().is_empty());
    // A targeted event stores and emits a received-status report.
    let targeted = ev(21, 0x0001, 0x00, 1000, 30);
    behavior
        .handle_event(&mut ctx(&mut store, &mut reporting, &mut events), &targeted)
        .unwrap();
    assert_eq!(behavior.table().len(), 1);
    // Cancel drops it; unknown cancels answer NOT_FOUND.
    let cancel = drlc::CancelEvent {
        issuer_event_id: 21,
        device_class: 0x0001,
        group: 0x00,
        cancel_control: 0x00,
    };
    behavior
        .handle_cancel(&mut ctx(&mut store, &mut reporting, &mut events), &cancel)
        .unwrap();
    assert!(behavior.table().is_empty());
    let missing = drlc::CancelEvent {
        issuer_event_id: 99,
        ..cancel
    };
    assert_eq!(
        behavior.handle_cancel(&mut ctx(&mut store, &mut reporting, &mut events), &missing),
        Err(ZclStatus::NotFound)
    );
    // Unknown commands are refused through the Behavior trait.
    assert_eq!(
        behavior.handle_cluster_command(
            &mut ctx(&mut store, &mut reporting, &mut events),
            &hdr(0xff),
            0xff,
            &[]
        ),
        Err(ZclStatus::UnsupCommand)
    );
    assert_eq!(
        behavior.handle_cluster_command(
            &mut ctx(&mut store, &mut reporting, &mut events),
            &hdr(drlc::CMD_LOAD_CONTROL_EVENT),
            drlc::CMD_LOAD_CONTROL_EVENT,
            &[0x00]
        ),
        Err(ZclStatus::MalformedCommand)
    );
}

// 07-5123-08-103-12: server answers scheduled queries in order.
#[test]
fn vector_drlc_server_behavior_07_5123_08_103_12() {
    let mut store = drlc::server_store().unwrap();
    let mut reporting = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut behavior = drlc::ServerBehavior::new();
    behavior.table_mut().insert(ev(30, 0x0001, 0x00, 3000, 30));
    behavior.table_mut().insert(ev(31, 0x0001, 0x00, 1000, 30));
    // Empty answer errors NOT_FOUND (the Get Scheduled Events rule).
    let empty = drlc::GetScheduledEvents {
        start_time: 9999,
        max_events: 0,
        min_issuer: None,
    };
    assert_eq!(
        behavior.answer_scheduled(&mut ctx(&mut store, &mut reporting, &mut events), &empty),
        Err(ZclStatus::NotFound)
    );
    let req = drlc::GetScheduledEvents {
        start_time: 0,
        max_events: 1,
        min_issuer: None,
    };
    assert_eq!(
        behavior.answer_scheduled(&mut ctx(&mut store, &mut reporting, &mut events), &req),
        Ok(1)
    );
    // Through the trait: malformed bodies refuse, unknown ids refuse.
    assert_eq!(
        behavior.handle_cluster_command(
            &mut ctx(&mut store, &mut reporting, &mut events),
            &hdr(drlc::CMD_GET_SCHEDULED_EVENTS),
            drlc::CMD_GET_SCHEDULED_EVENTS,
            &[0x01, 0x02]
        ),
        Err(ZclStatus::MalformedCommand)
    );
    assert_eq!(
        behavior.handle_cluster_command(
            &mut ctx(&mut store, &mut reporting, &mut events),
            &hdr(0xff),
            0xff,
            &[]
        ),
        Err(ZclStatus::UnsupCommand)
    );
}

// ---- Messaging identity + codecs (anchors p0821-p0826) --------------

// 07-5123-08-105-01: cluster identity and command sets.
#[test]
fn vector_messaging_identity_07_5123_08_105_01() {
    assert_eq!(messaging::CLUSTER_ID, 0x0703);
    assert!(messaging::ServerDef.attributes().is_empty());
    assert!(messaging::ClientDef.attributes().is_empty());
    let tx: Vec<u8> = messaging::ServerDef
        .generated_commands()
        .iter()
        .map(|c| c.id)
        .collect();
    let rx: Vec<u8> = messaging::ServerDef
        .received_commands()
        .iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(tx, vec![0x00, 0x01, 0x02, 0x03]);
    assert_eq!(rx, vec![0x00, 0x01, 0x02]);
}

// 07-5123-08-105-02/03: display codec + control rules.
#[test]
fn vector_messaging_display_codec_07_5123_08_105_03() {
    let text = b"hello";
    let mut bytes = [0u8; messaging::MAX_MESSAGE];
    bytes[..text.len()].copy_from_slice(text);
    let msg = messaging::DisplayMessage {
        message_id: 0x0102_0304,
        control: 0x80,
        start_time: messaging::START_NOW,
        duration_min: 30,
        len: text.len() as u8,
        text: bytes,
        ext_control: None,
    };
    assert!(messaging::control_valid(msg.control));
    assert!(messaging::confirmation_required(msg.control));
    assert_eq!(messaging::importance_of(0x08), messaging::IMPORTANCE_HIGH);
    let mut buf = [0u8; messaging::DISPLAY_PREFIX_LEN + messaging::MAX_MESSAGE + 1];
    let n = messaging::encode_display_message(&msg, &mut buf).unwrap();
    assert_eq!(n, messaging::DISPLAY_PREFIX_LEN + text.len());
    let back = messaging::decode_display_message(&buf[..n]).unwrap();
    assert_eq!(back, msg);
    // Deprecated Inter-PAN modes are refused, never carried ...
    assert!(!messaging::transmission_ok(0x01));
    assert!(!messaging::transmission_ok(0x02));
    assert!(messaging::transmission_ok(0x00));
    let mut interpan = msg;
    interpan.control = 0x02;
    assert!(!messaging::control_valid(interpan.control));
    assert!(messaging::encode_display_message(&interpan, &mut buf).is_err());
    // ... and enhanced confirmation never rides without plain confirmation.
    assert!(!messaging::control_valid(
        messaging::CONTROL_ENHANCED_CONFIRMATION
    ));
    assert!(messaging::control_valid(
        messaging::CONTROL_ENHANCED_CONFIRMATION | messaging::CONTROL_CONFIRMATION_REQUIRED
    ));
    // Truncation and over-long texts are refused.
    assert!(messaging::decode_display_message(&buf[..n - 1]).is_err());
    let mut long = msg;
    long.len = messaging::MAX_MESSAGE as u8 + 1;
    assert!(messaging::encode_display_message(&long, &mut buf).is_err());
}

// 07-5123-08-105-04: cancel codec (deprecated control ignored).
#[test]
fn vector_messaging_cancel_codec_07_5123_08_105_04() {
    let cancel = messaging::CancelMessage {
        message_id: 0xdead_beef,
    };
    let mut buf = [0u8; messaging::CANCEL_MESSAGE_LEN];
    let n = messaging::encode_cancel_message(&cancel, &mut buf).unwrap();
    assert_eq!(
        (n, &buf[4..5]),
        (messaging::CANCEL_MESSAGE_LEN, &[0x00][..])
    );
    assert_eq!(messaging::decode_cancel_message(&buf).unwrap(), cancel);
    assert!(messaging::decode_cancel_message(&buf[..4]).is_err());
}

// 07-5123-08-105-05: confirmation codec (basic + enhanced).
#[test]
fn vector_messaging_confirm_codec_07_5123_08_105_05() {
    let basic = messaging::MessageConfirmation {
        message_id: 0x1111_2222,
        confirmation_time: 0x3333_4444,
        control: None,
        response_len: 0,
        response: [0u8; messaging::MAX_CONFIRM_RESPONSE],
    };
    let mut buf = [0u8; 32];
    assert_eq!(
        messaging::encode_message_confirmation(&basic, &mut buf).unwrap(),
        8
    );
    assert_eq!(
        messaging::decode_message_confirmation(&buf[..8]).unwrap(),
        basic
    );
    let mut response = [0u8; messaging::MAX_CONFIRM_RESPONSE];
    response[..3].copy_from_slice(b"YES");
    let enhanced = messaging::MessageConfirmation {
        control: Some(messaging::CONFIRM_YES),
        response_len: 3,
        response,
        ..basic
    };
    let n = messaging::encode_message_confirmation(&enhanced, &mut buf).unwrap();
    assert_eq!(n, 13);
    assert_eq!(
        messaging::decode_message_confirmation(&buf[..n]).unwrap(),
        enhanced
    );
    assert!(messaging::decode_message_confirmation(&buf[..7]).is_err());
}

// 07-5123-08-105-06: box rules (latest wins, cancel, cancel-all).
#[test]
fn vector_messaging_box_07_5123_08_105_06() {
    let mut inbox = messaging::MessageBox::new();
    assert!(!inbox.has_message());
    assert_eq!(inbox.last(), None);
    let mk = |id: u32| messaging::DisplayMessage {
        message_id: id,
        control: 0x00,
        start_time: 100,
        duration_min: 10,
        len: 1,
        text: [0x41u8; messaging::MAX_MESSAGE],
        ext_control: None,
    };
    inbox.display(mk(1));
    inbox.display(mk(2));
    assert_eq!(inbox.last().unwrap().message_id, 2);
    assert!(messaging::message_active(&mk(2), 150));
    assert!(!messaging::message_active(&mk(2), 50));
    assert!(!messaging::message_active(&mk(2), 100 + 10 * 60 + 1));
    assert!(!inbox.cancel(1));
    assert!(inbox.cancel(2));
    assert!(!inbox.has_message());
    inbox.display(mk(3));
    inbox.cancel_all(9000);
    assert!(!inbox.has_message());
    assert_eq!(inbox.cancellation_since(8000), Some(9000));
    assert_eq!(inbox.cancellation_since(9001), None);
    // Confirmations mark the extended-control bit.
    inbox.display(mk(4));
    assert!(inbox.confirm(4));
    assert_eq!(
        inbox.last().unwrap().ext_control,
        Some(messaging::EXT_CONFIRMED)
    );
    assert!(!inbox.confirm(5));
}

// 07-5123-08-105-07: server behavior (get-last / confirm / cancel).
#[test]
fn vector_messaging_server_behavior_07_5123_08_105_07() {
    let mut store = AttrStore::new(None);
    store.add_globals(messaging::REVISION).unwrap();
    let mut reporting = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut behavior = messaging::ServerBehavior::new();
    // Empty box answers NOT_FOUND to GetLastMessage.
    assert_eq!(
        behavior.handle_cluster_command(
            &mut ctx(&mut store, &mut reporting, &mut events),
            &hdr(messaging::CMD_GET_LAST_MESSAGE),
            messaging::CMD_GET_LAST_MESSAGE,
            &[]
        ),
        Err(ZclStatus::NotFound)
    );
    // A held message is emitted; a confirmation flips the shared bit.
    let mk = messaging::DisplayMessage {
        message_id: 0x0a0b_0c0d,
        control: messaging::CONTROL_CONFIRMATION_REQUIRED,
        start_time: messaging::START_NOW,
        duration_min: messaging::DURATION_UNTIL_CHANGED,
        len: 2,
        text: {
            let mut t = [0u8; messaging::MAX_MESSAGE];
            t[..2].copy_from_slice(b"hi");
            t
        },
        ext_control: None,
    };
    behavior.inbox_mut().display(mk);
    behavior
        .handle_cluster_command(
            &mut ctx(&mut store, &mut reporting, &mut events),
            &hdr(messaging::CMD_GET_LAST_MESSAGE),
            messaging::CMD_GET_LAST_MESSAGE,
            &[],
        )
        .unwrap();
    let conf = messaging::MessageConfirmation {
        message_id: 0x0a0b_0c0d,
        confirmation_time: 777,
        control: None,
        response_len: 0,
        response: [0u8; messaging::MAX_CONFIRM_RESPONSE],
    };
    let mut cbuf = [0u8; 16];
    let cn = messaging::encode_message_confirmation(&conf, &mut cbuf).unwrap();
    behavior
        .handle_cluster_command(
            &mut ctx(&mut store, &mut reporting, &mut events),
            &hdr(messaging::CMD_MESSAGE_CONFIRMATION),
            messaging::CMD_MESSAGE_CONFIRMATION,
            &cbuf[..cn],
        )
        .unwrap();
    assert_eq!(
        behavior.inbox().last().unwrap().ext_control,
        Some(messaging::EXT_CONFIRMED)
    );
    // Confirming an unknown message answers NOT_FOUND.
    let mut unknown = conf;
    unknown.message_id = 0xffff_ffff;
    let un = messaging::encode_message_confirmation(&unknown, &mut cbuf).unwrap();
    assert_eq!(
        behavior.handle_cluster_command(
            &mut ctx(&mut store, &mut reporting, &mut events),
            &hdr(messaging::CMD_MESSAGE_CONFIRMATION),
            messaging::CMD_MESSAGE_CONFIRMATION,
            &cbuf[..un]
        ),
        Err(ZclStatus::NotFound)
    );
    // Cancellation queries answer the held record or NOT_FOUND.
    behavior.inbox_mut().cancel_all(5000);
    assert!(behavior
        .handle_cluster_command(
            &mut ctx(&mut store, &mut reporting, &mut events),
            &hdr(messaging::CMD_GET_MESSAGE_CANCELLATION),
            messaging::CMD_GET_MESSAGE_CANCELLATION,
            &5000u32.to_le_bytes(),
        )
        .is_ok());
    assert_eq!(
        behavior.handle_cluster_command(
            &mut ctx(&mut store, &mut reporting, &mut events),
            &hdr(messaging::CMD_GET_MESSAGE_CANCELLATION),
            messaging::CMD_GET_MESSAGE_CANCELLATION,
            &[0x01, 0x02]
        ),
        Err(ZclStatus::MalformedCommand)
    );
    assert_eq!(
        behavior.handle_cluster_command(
            &mut ctx(&mut store, &mut reporting, &mut events),
            &hdr(0xff),
            0xff,
            &[]
        ),
        Err(ZclStatus::UnsupCommand)
    );
}

// ---- opaque-with-cause pins (unmodeled bodies stay explicit) --------

// 07-5123-08-1046-02: non-carried snapshot shapes stay bounded opaque.
#[test]
fn vector_snapshot_opaque_shapes_07_5123_08_1046_02() {
    // Carried shapes decode typed ...
    assert!(snapshot::payload_type_known(
        snapshot::PAYLOAD_TOU_DELIVERED
    ));
    assert!(snapshot::payload_type_known(snapshot::PAYLOAD_UNAVAILABLE));
    // ... every other selector travels as bounded opaque bytes, never
    // silently and never interpreted here.
    assert!(!snapshot::payload_type_known(0x08));
    assert!(!snapshot::payload_type_known(0x81));
    let hdr = snapshot::PublishSnapshot {
        snapshot_id: 7,
        snapshot_time: 100,
        total_found: 1,
        command_index: 0,
        total_commands: 1,
        cause: snapshot::CAUSE_ALL,
        payload_type: 0x08,
    };
    let sub = [0xde, 0xad, 0xbe, 0xef];
    let mut buf = [0u8; snapshot::PUBLISH_HEADER_LEN + 4];
    let n = snapshot::encode_publish_snapshot(&hdr, &sub, &mut buf).unwrap();
    let back = snapshot::decode_publish_snapshot(&buf[..n]).unwrap();
    assert_eq!(back.header.payload_type, 0x08);
    assert_eq!(back.sub_payload(), &sub);
}

// 07-5123-08-2512-01: unmodeled clusters route to UnsupportedCluster.
#[test]
fn vector_unmodeled_clusters_deferred_07_5123_08_2512_01() {
    use rounddance_zcl::dispatch::Endpoint as Ep;
    let mut ep = Ep::new();
    ep.add(&messaging::ServerDef).unwrap();
    ep.add(&drlc::ServerDef).unwrap();
    // Modeled clusters resolve on the endpoint ...
    assert!(ep.find(messaging::CLUSTER_ID).is_some());
    assert!(ep.find(drlc::CLUSTER_ID).is_some());
    // ... while tunneling / prepayment / calendar / device-management
    // / events / energy-management / MDU / sub-GHz clusters have no
    // definition here (explicit follow-up, never silent scope).
    for id in [
        0x0704u16, 0x0705, 0x0706, 0x0707, 0x0708, 0x0709, 0x070a, 0x070b,
    ] {
        assert!(
            ep.find(id).is_none(),
            "cluster {id:#06x} unexpectedly modeled"
        );
    }
    assert_eq!(metering::CLUSTER_ID, 0x0702);
    assert_eq!(supply::CMD_CHANGE_SUPPLY, 0x0b);
}

// 07-5123-08-49-01: modeled measurement clusters keep their identity.
#[test]
fn vector_measurement_identity_07_5123_08_49_01() {
    assert_eq!(electrical::CLUSTER_ID, 0x0b04);
    assert_eq!(occupancy::CLUSTER_ID, 0x0406);
    let store = occupancy::server_store().unwrap();
    assert!(occupancy::is_occupied(
        occupancy::occupancy_of(&store) | 0x01
    ));
    // Unknown occupancy sensor types stay refused, never absorbed.
    assert!(!occupancy::sensor_type_known(0x04));
}
