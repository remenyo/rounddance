//! Wire vectors for the IAS ACE + IAS WD servers.
//!
//! Each test names the requirement ID it verifies. Byte strings are
//! hand-computed from the paraphrased layouts in doc `07-5123-08`
//! — never copied from spec text (D1, `SCOPE.md` §2).
//! Corpus-mined IDs are reused verbatim; repo-minted IDs are
//! MINTED-pending-confirm.

use rounddance_zcl::behavior::{AppEvent, Behavior, Ctx, EventQueue};
use rounddance_zcl::cluster::ClusterDef;
use rounddance_zcl::frame::{Direction, FrameControl, FrameType, Header};
use rounddance_zcl::*;

// ---- ace.rs -------------------------------------------------------

fn ace_harness() -> (
    ace::ServerBehavior,
    attrs::AttrStore,
    reporting::ReportingEngine,
    EventQueue,
) {
    (
        ace::ServerBehavior::new(),
        ace::server_store().unwrap(),
        reporting::ReportingEngine::new(),
        EventQueue::new(),
    )
}

fn ace_header(tsn: u8, cmd: u8) -> Header {
    Header {
        control: FrameControl {
            frame_type: FrameType::ClusterSpecific,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn,
        command_id: cmd,
    }
}

fn ace_drive(
    beh: &mut ace::ServerBehavior,
    store: &mut attrs::AttrStore,
    eng: &mut reporting::ReportingEngine,
    events: &mut EventQueue,
    tsn: u8,
    cmd: u8,
    payload: &[u8],
) -> Result<behavior::HandleOutcome, status::ZclStatus> {
    let mut ctx = Ctx {
        store,
        reporting: eng,
        events,
        now_s: 100,
        peer_onoff: None,
        sender_ieee: None,
    };
    <ace::ServerBehavior as Behavior>::handle_cluster_command(
        beh,
        &mut ctx,
        &ace_header(tsn, cmd),
        cmd,
        payload,
    )
}

fn outbound(events: &mut EventQueue) -> Vec<(u16, u8, u8, [u8; behavior::MAX_EVENT_PAYLOAD])> {
    let mut out = Vec::new();
    while let Some(ev) = events.pop() {
        if let AppEvent::OutboundCommand {
            cluster,
            cmd,
            tsn: _,
            len,
            payload,
        } = ev
        {
            out.push((cluster, cmd, len, payload));
        }
    }
    out
}

// 07-5123-08-831-01: ACE cluster shape.
#[test]
fn vector_ace_store_shape_07_5123_08_831_01() {
    assert_eq!(ace::CLUSTER_ID, 0x0501);
    assert_eq!(ace::REVISION, 2);
    let ids: Vec<u16> = ace::ServerDef.attributes().iter().map(|a| a.id).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
    for table in [ace::SERVER_RX, ace::SERVER_TX] {
        let cmds: Vec<u8> = table.iter().map(|c| c.id).collect();
        let mut s = cmds.clone();
        s.sort_unstable();
        assert_eq!(cmds, s);
    }
    assert_eq!(
        ace::SERVER_RX.iter().map(|c| c.id).collect::<Vec<u8>>(),
        vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]
    );
    assert_eq!(
        ace::SERVER_TX.iter().map(|c| c.id).collect::<Vec<u8>>(),
        vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    );
}

// 07-5123-08-833-01: Arm codec exact bytes.
#[test]
fn vector_arm_codec_07_5123_08_833_01() {
    let mut out = [0u8; 24];
    let n = ace::encode_arm(ace::ARM_ALL, b"1234", 0xff, &mut out).unwrap();
    assert_eq!(n, 7);
    assert_eq!(&out[..7], &[0x03, 0x04, b'1', b'2', b'3', b'4', 0xff]);
    let req = ace::decode_arm(&out[..7]).unwrap();
    assert_eq!(req.mode, ace::ARM_ALL);
    assert_eq!(req.code, b"1234");
    assert_eq!(req.zone_id, 0xff);
    // Empty code is the no-code form.
    let m = ace::encode_arm(ace::ARM_DISARM, b"", 0xff, &mut out).unwrap();
    assert_eq!(&out[..m], &[0x00, 0x00, 0xff]);
    // Malformed: short, trailing bytes, overlong count.
    assert!(ace::decode_arm(&out[..2]).is_err());
    assert!(ace::decode_arm(&out[..8]).is_err());
    assert!(ace::decode_arm(&[0x03, 0x11, 0x00]).is_err());
}

// 07-5123-08-832-01: every arm attempt closes with a verdict.
#[test]
fn vector_arm_all_closes_07_5123_08_832_01() {
    let (mut beh, mut store, mut eng, mut events) = ace_harness();
    let mut body = [0u8; 24];
    let n = ace::encode_arm(ace::ARM_ALL, b"", 0xff, &mut body).unwrap();
    ace_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        7,
        ace::CMD_ARM,
        &body[..n],
    )
    .unwrap();
    assert_eq!(beh.panel(), ace::PANEL_ARMED_AWAY);
    let out = outbound(&mut events);
    assert_eq!(out.len(), 2);
    assert_eq!(
        (out[0].0, out[0].1),
        (ace::CLUSTER_ID, ace::CMD_PANEL_STATUS_CHANGED)
    );
    assert_eq!(
        &out[0].3[..4],
        &[
            ace::PANEL_ARMED_AWAY,
            0x00,
            ace::AUDIBLE_DEFAULT,
            ace::ALARM_NONE
        ]
    );
    assert_eq!(
        (out[1].0, out[1].1),
        (ace::CLUSTER_ID, ace::CMD_ARM_RESPONSE)
    );
    assert_eq!(out[1].3[0], ace::ARM_NOTIFY_ALL);
}

// 07-5123-08-832-01: disarming an already-disarmed panel reports it.
#[test]
fn vector_disarm_already_07_5123_08_832_01() {
    let (mut beh, mut store, mut eng, mut events) = ace_harness();
    let mut body = [0u8; 24];
    let n = ace::encode_arm(ace::ARM_DISARM, b"", 0xff, &mut body).unwrap();
    ace_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        3,
        ace::CMD_ARM,
        &body[..n],
    )
    .unwrap();
    let out = outbound(&mut events);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].3[0], ace::ARM_NOTIFY_ALREADY_DISARMED);
    assert_eq!(beh.panel(), ace::PANEL_DISARMED);
}

// 07-5123-08-832-02: code handling (match, mismatch, non-UTF8).
#[test]
fn vector_arm_code_rules_07_5123_08_832_02() {
    assert!(ace::code_accepted(b"", b""));
    assert!(ace::code_accepted(b"1234", b""));
    assert!(!ace::code_accepted(b"", b"9999"));
    assert!(ace::code_accepted(b"9999", b"9999"));
    assert!(!ace::code_accepted(&[0xff, 0xfe], b""));
    assert!(!ace::code_accepted(&[0xff, 0xfe], &[0xff, 0xfe]));

    let (mut beh, mut store, mut eng, mut events) = ace_harness();
    beh.set_code(b"9999").unwrap();
    assert!(beh.set_code(&[0xff]).is_err());
    let mut body = [0u8; 24];
    let n = ace::encode_arm(ace::ARM_ALL, b"0000", 0xff, &mut body).unwrap();
    ace_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        9,
        ace::CMD_ARM,
        &body[..n],
    )
    .unwrap();
    assert_eq!(beh.panel(), ace::PANEL_DISARMED);
    let out = outbound(&mut events);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].3[0], ace::ARM_NOTIFY_BAD_CODE);
    // Non-UTF8 code is a malformed arm, not a verdict.
    let bad = [ace::ARM_ALL, 0x02, 0xff, 0xfe, 0xff];
    assert_eq!(
        ace_drive(
            &mut beh,
            &mut store,
            &mut eng,
            &mut events,
            10,
            ace::CMD_ARM,
            &bad
        ),
        Err(status::ZclStatus::InvalidField)
    );
    // Unknown mode is refused without a verdict.
    let odd = [0x07, 0x00, 0xff];
    assert_eq!(
        ace_drive(
            &mut beh,
            &mut store,
            &mut eng,
            &mut events,
            11,
            ace::CMD_ARM,
            &odd
        ),
        Err(status::ZclStatus::InvalidField)
    );
}

// 07-5123-08-832-01: not-ready panels refuse with 0x05.
#[test]
fn vector_arm_not_ready_07_5123_08_832_01() {
    let (mut beh, mut store, mut eng, mut events) = ace_harness();
    beh.set_not_ready(true);
    let mut body = [0u8; 24];
    let n = ace::encode_arm(ace::ARM_DAY_HOME, b"", 0xff, &mut body).unwrap();
    ace_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        5,
        ace::CMD_ARM,
        &body[..n],
    )
    .unwrap();
    assert_eq!(beh.panel(), ace::PANEL_DISARMED);
    let out = outbound(&mut events);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].3[0], ace::ARM_NOTIFY_NOT_READY);
}

// 07-5123-08-832-04: disarm clears non-permanent bypasses only.
#[test]
fn vector_disarm_clears_bypass_07_5123_08_832_04() {
    let (mut beh, mut store, mut eng, mut events) = ace_harness();
    beh.enroll_zone(3, 0x000d, [0x11; 8], b"Door", true)
        .unwrap();
    beh.enroll_zone(5, 0x000d, [0x22; 8], b"Window", false)
        .unwrap();
    assert!(beh.enroll_zone(16, 0x000d, [0x33; 8], b"X", false).is_err());
    // Bypass both.
    let bypass = [0x02, 0x03, 0x05, 0x00];
    ace_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        1,
        ace::CMD_BYPASS,
        &bypass,
    )
    .unwrap();
    assert_eq!(beh.bypassed_count(), 2);
    // Arm all, then disarm.
    let mut body = [0u8; 24];
    let n = ace::encode_arm(ace::ARM_ALL, b"", 0xff, &mut body).unwrap();
    ace_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        2,
        ace::CMD_ARM,
        &body[..n],
    )
    .unwrap();
    assert_eq!(beh.panel(), ace::PANEL_ARMED_AWAY);
    let m = ace::encode_arm(ace::ARM_DISARM, b"", 0xff, &mut body).unwrap();
    ace_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        3,
        ace::CMD_ARM,
        &body[..m],
    )
    .unwrap();
    assert_eq!(beh.panel(), ace::PANEL_DISARMED);
    assert!(!beh.zone(5).unwrap().bypassed);
    assert!(beh.zone(3).unwrap().bypassed);
    // Disarm fanned out panel-changed, bypassed-list, and the verdict.
    let out = outbound(&mut events);
    let kinds: Vec<u8> = out.iter().map(|o| o.1).collect();
    assert!(kinds.contains(&ace::CMD_PANEL_STATUS_CHANGED));
    assert!(kinds.contains(&ace::CMD_SET_BYPASSED_LIST));
    assert!(kinds.contains(&ace::CMD_ARM_RESPONSE));
    // The bypassed list now names only the permanent zone.
    let list = out
        .iter()
        .find(|o| o.1 == ace::CMD_SET_BYPASSED_LIST)
        .unwrap();
    assert_eq!(&list.3[..2], &[0x01, 0x03]);
}

// 07-5123-08-833-01: bypass results per zone.
#[test]
fn vector_bypass_results_07_5123_08_833_01() {
    let (mut beh, mut store, mut eng, mut events) = ace_harness();
    beh.enroll_zone(3, 0x000d, [0x11; 8], b"Door", false)
        .unwrap();
    // Known + unknown-range + out-of-range.
    let bypass = [0x03, 0x03, 0x09, 0x28, 0x00];
    ace_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        4,
        ace::CMD_BYPASS,
        &bypass,
    )
    .unwrap();
    let out = outbound(&mut events);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].1, ace::CMD_BYPASS_RESPONSE);
    assert_eq!(
        &out[0].3[..4],
        &[
            0x03,
            ace::BYPASS_OK,
            ace::BYPASS_UNKNOWN_ID,
            ace::BYPASS_INVALID_ID
        ]
    );
    assert!(beh.zone(3).unwrap().bypassed);
    // Wrong code fails every zone the same way.
    beh.set_code(b"9999").unwrap();
    let mut events2 = EventQueue::new();
    let bad = [0x01, 0x03, 0x04, b'0', b'0', b'0', b'0'];
    ace_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events2,
        5,
        ace::CMD_BYPASS,
        &bad,
    )
    .unwrap();
    let out2 = outbound(&mut events2);
    assert_eq!(&out2[0].3[..2], &[0x01, ace::BYPASS_BAD_CODE]);
    // Malformed bypass bodies are refused.
    assert_eq!(
        ace_drive(
            &mut beh,
            &mut store,
            &mut eng,
            &mut events2,
            6,
            ace::CMD_BYPASS,
            &[0x02, 0x03]
        ),
        Err(status::ZclStatus::MalformedCommand)
    );
}

// 07-5123-08-832-03: mask-flag filtering on zone-status queries.
#[test]
fn vector_zone_status_mask_07_5123_08_832_03() {
    let (mut beh, mut store, mut eng, mut events) = ace_harness();
    beh.enroll_zone(0, 0x000d, [0x11; 8], b"A", false).unwrap();
    beh.enroll_zone(1, 0x000d, [0x22; 8], b"B", false).unwrap();
    beh.enroll_zone(2, 0x000d, [0x33; 8], b"C", false).unwrap();
    beh.set_zone_status(0, 0x0001).unwrap();
    beh.set_zone_status(1, 0x0000).unwrap();
    beh.set_zone_status(2, 0x0003).unwrap();
    // Flag clear: every zone from 0.
    let q = ace::ZoneStatusQuery {
        start: 0,
        max: 8,
        mask_flag: false,
        mask: 0,
    };
    let mut body = [0u8; 5];
    ace::encode_zone_status_query(&q, &mut body).unwrap();
    assert_eq!(&body, &[0x00, 0x08, 0x00, 0x00, 0x00]);
    ace_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        8,
        ace::CMD_GET_ZONE_STATUS,
        &body,
    )
    .unwrap();
    let out = outbound(&mut events);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].1, ace::CMD_ZONE_STATUS_RESPONSE);
    assert_eq!(&out[0].3[..2], &[0x01, 0x03]);
    assert_eq!(&out[0].3[2..5], &[0x00, 0x01, 0x00]);
    assert_eq!(&out[0].3[5..8], &[0x01, 0x00, 0x00]);
    assert_eq!(&out[0].3[8..11], &[0x02, 0x03, 0x00]);
    // Flag set with mask 0x0002: only zone 2 (0x0003 & 0x0002).
    let mut events2 = EventQueue::new();
    let q2 = ace::ZoneStatusQuery {
        start: 0,
        max: 8,
        mask_flag: true,
        mask: 0x0002,
    };
    ace::encode_zone_status_query(&q2, &mut body).unwrap();
    ace_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events2,
        9,
        ace::CMD_GET_ZONE_STATUS,
        &body,
    )
    .unwrap();
    let out2 = outbound(&mut events2);
    assert_eq!(&out2[0].3[..2], &[0x01, 0x01]);
    assert_eq!(&out2[0].3[2..5], &[0x02, 0x03, 0x00]);
    // Max 1 with two matching zones: incomplete page.
    let mut events3 = EventQueue::new();
    let q3 = ace::ZoneStatusQuery {
        start: 0,
        max: 1,
        mask_flag: false,
        mask: 0,
    };
    ace::encode_zone_status_query(&q3, &mut body).unwrap();
    ace_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events3,
        10,
        ace::CMD_GET_ZONE_STATUS,
        &body,
    )
    .unwrap();
    let out3 = outbound(&mut events3);
    assert_eq!(&out3[0].3[..2], &[0x00, 0x01]);
    // Bad flag value is malformed.
    assert_eq!(
        ace_drive(
            &mut beh,
            &mut store,
            &mut eng,
            &mut events3,
            11,
            ace::CMD_GET_ZONE_STATUS,
            &[0x00, 0x08, 0x02, 0x00, 0x00]
        ),
        Err(status::ZclStatus::MalformedCommand)
    );
}

// 07-5123-08-833-02: zone-information answers (known + unallocated).
#[test]
fn vector_zone_info_answers_07_5123_08_833_02() {
    let (mut beh, mut store, mut eng, mut events) = ace_harness();
    beh.enroll_zone(
        2,
        0x0015,
        [0x78, 0x56, 0x34, 0x12, 0xaa, 0xbb, 0xcc, 0xdd],
        b"Hall",
        false,
    )
    .unwrap();
    ace_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        12,
        ace::CMD_GET_ZONE_INFO,
        &[0x02],
    )
    .unwrap();
    let out = outbound(&mut events);
    assert_eq!(out[0].1, ace::CMD_ZONE_INFO_RESPONSE);
    assert_eq!(out[0].3[0], 0x02);
    assert_eq!(&out[0].3[1..3], &[0x15, 0x00]);
    assert_eq!(
        &out[0].3[3..11],
        &[0x78, 0x56, 0x34, 0x12, 0xaa, 0xbb, 0xcc, 0xdd]
    );
    assert_eq!(out[0].3[11], 0x04);
    assert_eq!(&out[0].3[12..16], b"Hall");
    assert_eq!(out[0].2 as usize, 16);
    // Unallocated zone: type 0xffff, address all-1, empty label.
    let mut events2 = EventQueue::new();
    ace_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events2,
        13,
        ace::CMD_GET_ZONE_INFO,
        &[0x07],
    )
    .unwrap();
    let out2 = outbound(&mut events2);
    assert_eq!(out2[0].3[0], 0x07);
    assert_eq!(&out2[0].3[1..3], &[0xff, 0xff]);
    assert_eq!(&out2[0].3[3..11], &[0xff; 8]);
    assert_eq!(out2[0].3[11], 0x00);
}

// 07-5123-08-833-02: zone-ID-map bitmap sections.
#[test]
fn vector_zone_id_map_07_5123_08_833_02() {
    let (mut beh, mut store, mut eng, mut events) = ace_harness();
    beh.enroll_zone(0, 0x000d, [0x11; 8], b"A", false).unwrap();
    beh.enroll_zone(9, 0x000d, [0x22; 8], b"B", false).unwrap();
    ace_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        14,
        ace::CMD_GET_ZONE_ID_MAP,
        &[],
    )
    .unwrap();
    let out = outbound(&mut events);
    assert_eq!(out[0].1, ace::CMD_ZONE_ID_MAP_RESPONSE);
    assert_eq!(out[0].2, 32);
    assert_eq!(out[0].3[0], 0x01);
    assert_eq!(out[0].3[1], 0x02);
    assert!(out[0].3[2..32].iter().all(|b| *b == 0));
}

// 07-5123-08-834-01 (implementation inference): emergency/fire/panic raise panel alarm.
#[test]
fn vector_panic_raises_alarm_07_5123_08_834_01() {
    let (mut beh, mut store, mut eng, mut events) = ace_harness();
    for (cmd, alarm) in [
        (ace::CMD_EMERGENCY, ace::ALARM_EMERGENCY),
        (ace::CMD_FIRE, ace::ALARM_FIRE),
        (ace::CMD_PANIC, ace::ALARM_POLICE_PANIC),
    ] {
        ace_drive(&mut beh, &mut store, &mut eng, &mut events, 15, cmd, &[]).unwrap();
        assert_eq!(beh.panel(), ace::PANEL_IN_ALARM);
        assert_eq!(beh.alarm(), alarm);
    }
    let out = outbound(&mut events);
    assert_eq!(out.len(), 3);
    assert!(out.iter().all(|o| o.1 == ace::CMD_PANEL_STATUS_CHANGED));
    assert_eq!(
        &out[2].3[..4],
        &[
            ace::PANEL_IN_ALARM,
            0x00,
            ace::AUDIBLE_DEFAULT,
            ace::ALARM_POLICE_PANIC
        ]
    );
    // Payload-bearing panic is malformed.
    assert_eq!(
        ace_drive(
            &mut beh,
            &mut store,
            &mut eng,
            &mut events,
            16,
            ace::CMD_FIRE,
            &[0x00]
        ),
        Err(status::ZclStatus::MalformedCommand)
    );
}

// 07-5123-08-834-01 (implementation inference): panel-status query + delay countdown.
#[test]
fn vector_panel_delay_tick_07_5123_08_834_01() {
    let (mut beh, mut store, mut eng, mut events) = ace_harness();
    beh.start_delay(&mut events, 20, ace::PANEL_EXIT_DELAY, 3);
    assert_eq!(beh.panel(), ace::PANEL_EXIT_DELAY);
    ace::tick_1s(&mut beh, &mut events, 20, 1);
    assert_eq!(beh.panel(), ace::PANEL_EXIT_DELAY);
    let out = outbound(&mut events);
    assert_eq!(&out[1].3[..2], &[ace::PANEL_EXIT_DELAY, 0x02]);
    ace::tick_1s(&mut beh, &mut events, 20, 2);
    assert_eq!(beh.panel(), ace::PANEL_ARMED_AWAY);
    // Entry delay resolves into alarm.
    let mut events2 = EventQueue::new();
    beh.start_delay(&mut events2, 21, ace::PANEL_ENTRY_DELAY, 1);
    ace::tick_1s(&mut beh, &mut events2, 21, 1);
    assert_eq!(beh.panel(), ace::PANEL_IN_ALARM);
    assert_eq!(beh.alarm(), ace::ALARM_BURGLAR);
    // Panel-status query answers the live state.
    let mut events3 = EventQueue::new();
    ace_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events3,
        22,
        ace::CMD_GET_PANEL_STATUS,
        &[],
    )
    .unwrap();
    let out3 = outbound(&mut events3);
    assert_eq!(out3[0].1, ace::CMD_PANEL_STATUS_RESPONSE);
    assert_eq!(
        &out3[0].3[..4],
        &[
            ace::PANEL_IN_ALARM,
            0x00,
            ace::AUDIBLE_DEFAULT,
            ace::ALARM_BURGLAR
        ]
    );
}

// 07-5123-08-834-01 (implementation inference): zone-status fan-out carries id + status + label.
#[test]
fn vector_zone_status_fanout_07_5123_08_834_01() {
    let (mut beh, mut _store, mut _eng, mut events) = ace_harness();
    beh.enroll_zone(4, 0x000d, [0x44; 8], b"Porch", false)
        .unwrap();
    beh.report_zone_status(&mut events, 30, 4, 0x0001, ace::AUDIBLE_DEFAULT)
        .unwrap();
    assert_eq!(beh.zone(4).unwrap().status, 0x0001);
    let out = outbound(&mut events);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].1, ace::CMD_ZONE_STATUS_CHANGED);
    assert_eq!(&out[0].3[..4], &[0x04, 0x01, 0x00, ace::AUDIBLE_DEFAULT]);
    assert_eq!(out[0].3[4], 0x05);
    assert_eq!(&out[0].3[5..10], b"Porch");
    assert!(beh
        .report_zone_status(&mut events, 31, 9, 0x0001, 0)
        .is_err());
}

// 07-5123-08-833-02: client builders frame arm + zone-status.
#[test]
fn vector_ace_client_frames_07_5123_08_833_02() {
    let mut out = [0u8; 40];
    let n = ace::client::arm(0x41, ace::ARM_DISARM, b"", 0xff, &mut out).unwrap();
    let (h, p) = Header::decode(&out[..n]).unwrap();
    assert_eq!(h.command_id, ace::CMD_ARM);
    assert_eq!(h.tsn, 0x41);
    assert_eq!(p, &[0x00, 0x00, 0xff]);
    let q = ace::ZoneStatusQuery {
        start: 2,
        max: 4,
        mask_flag: true,
        mask: 0x00ff,
    };
    let m = ace::client::get_zone_status(0x42, &q, &mut out).unwrap();
    let (h2, p2) = Header::decode(&out[..m]).unwrap();
    assert_eq!(h2.command_id, ace::CMD_GET_ZONE_STATUS);
    assert_eq!(p2, &[0x02, 0x04, 0x01, 0xff, 0x00]);
}

// ---- wd.rs --------------------------------------------------------

// 07-5123-08-841-01: WD cluster shape.
#[test]
fn vector_wd_store_shape_07_5123_08_841_01() {
    assert_eq!(wd::CLUSTER_ID, 0x0502);
    assert_eq!(wd::REVISION, 2);
    let store = wd::server_store().unwrap();
    assert_eq!(wd::max_duration(&store), wd::DEFAULT_MAX_DURATION);
    assert_eq!(wd::DEFAULT_MAX_DURATION, 240);
    let cmds: Vec<u8> = wd::SERVER_RX.iter().map(|c| c.id).collect();
    assert_eq!(cmds, vec![0x00, 0x01]);
    assert!(wd::SERVER_TX.is_empty());
    assert!(!wd::SIREN_LEVELS.is_empty() && !wd::STROBE_LEVELS.is_empty());
}

// 07-5123-08-841-01: Start Warning codec exact bytes.
#[test]
fn vector_start_warning_codec_07_5123_08_841_01() {
    let w = wd::StartWarning {
        mode: wd::WARN_BURGLAR,
        strobe: wd::STROBE_PARALLEL,
        siren: 0x02,
        duration_s: 0x012c,
        duty: 40,
        level: 0x02,
    };
    let mut out = [0u8; 8];
    assert_eq!(wd::encode_start_warning(&w, &mut out), Ok(5));
    assert_eq!(&out[..5], &[0x91, 0x2c, 0x01, 40, 0x02]);
    assert_eq!(wd::decode_start_warning(&out[..5]).unwrap(), w);
    assert_eq!(wd::split_flags(0x91), (0x01, 0x01, 0x02));
    assert_eq!(wd::pack_flags(0x01, 0x01, 0x02), 0x91);
    assert!(wd::decode_start_warning(&out[..4]).is_err());
    assert!(wd::decode_start_warning(&out[..6]).is_err());
    // Mode out of range is refused.
    assert!(wd::decode_start_warning(&[0x07 | 0x80, 0x00, 0x00, 0x00, 0x00]).is_err());
    // Squawk round-trips (armed + strobe + high).
    let s = wd::Squawk {
        mode: wd::SQUAWK_ARMED,
        strobe: true,
        level: 0x02,
    };
    let mut sq = [0u8; 2];
    assert_eq!(wd::encode_squawk(&s, &mut sq), Ok(1));
    assert_eq!(sq[0], 0xa0);
    assert_eq!(wd::decode_squawk(&sq[..1]).unwrap(), s);
    // Reserved bit set is refused.
    assert!(wd::decode_squawk(&[0x10]).is_err());
}

fn wd_harness() -> (
    wd::ServerBehavior,
    attrs::AttrStore,
    reporting::ReportingEngine,
    EventQueue,
) {
    (
        wd::ServerBehavior::new(),
        wd::server_store().unwrap(),
        reporting::ReportingEngine::new(),
        EventQueue::new(),
    )
}

fn wd_drive(
    beh: &mut wd::ServerBehavior,
    store: &mut attrs::AttrStore,
    eng: &mut reporting::ReportingEngine,
    events: &mut EventQueue,
    cmd: u8,
    payload: &[u8],
) -> Result<behavior::HandleOutcome, status::ZclStatus> {
    let mut ctx = Ctx {
        store,
        reporting: eng,
        events,
        now_s: 50,
        peer_onoff: None,
        sender_ieee: None,
    };
    let header = Header {
        control: FrameControl {
            frame_type: FrameType::ClusterSpecific,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x55,
        command_id: cmd,
    };
    <wd::ServerBehavior as Behavior>::handle_cluster_command(beh, &mut ctx, &header, cmd, payload)
}

// 07-5123-08-842-01: new starts preempt; stop/stop silences.
#[test]
fn vector_warning_preemption_07_5123_08_842_01() {
    let (mut beh, mut store, mut eng, mut events) = wd_harness();
    assert!(beh.active().is_none());
    wd_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        wd::CMD_START_WARNING,
        &[0x91, 0x2c, 0x01, 40, 0x02],
    )
    .unwrap();
    assert_eq!(
        beh.active().unwrap(),
        wd::ActiveWarning {
            mode: wd::WARN_BURGLAR,
            strobe: wd::STROBE_PARALLEL,
            siren: 0x02,
            remaining_s: 300.min(wd::DEFAULT_MAX_DURATION),
            duty: 40,
            level: 0x02,
        }
    );
    // Fire preempts burglar outright.
    let fire = wd::StartWarning {
        mode: wd::WARN_FIRE,
        strobe: wd::STROBE_NONE,
        siren: 0x03,
        duration_s: 60,
        duty: 0,
        level: 0x01,
    };
    let mut body = [0u8; 5];
    wd::encode_start_warning(&fire, &mut body).unwrap();
    wd_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        wd::CMD_START_WARNING,
        &body,
    )
    .unwrap();
    assert_eq!(beh.active().unwrap().mode, wd::WARN_FIRE);
    // Stop/stop ignores duration and silences.
    wd_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        wd::CMD_START_WARNING,
        &[0x00, 0xff, 0xff, 0x00, 0x00],
    )
    .unwrap();
    assert!(beh.active().is_none());
}

// 07-5123-08-842-03: duty-cycle quantization.
#[test]
fn vector_duty_quantize_07_5123_08_842_03() {
    assert_eq!(wd::quantize_duty(0), 0);
    assert_eq!(wd::quantize_duty(4), 0);
    assert_eq!(wd::quantize_duty(5), 10);
    assert_eq!(wd::quantize_duty(44), 40);
    assert_eq!(wd::quantize_duty(45), 50);
    assert_eq!(wd::quantize_duty(95), 100);
    assert_eq!(wd::quantize_duty(100), 100);
    assert_eq!(wd::quantize_duty(200), 100);
    assert_eq!(wd::quantize_duty(255), 100);
}

// 07-5123-08-842-01: duration clamps to MaxDuration; expiry ticks out.
#[test]
fn vector_warning_duration_cap_07_5123_08_842_01() {
    let (mut beh, mut store, mut eng, mut events) = wd_harness();
    wd_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        wd::CMD_START_WARNING,
        &[0x91, 0xe8, 0x03, 0x00, 0x01],
    )
    .unwrap();
    assert_eq!(beh.active().unwrap().remaining_s, wd::DEFAULT_MAX_DURATION);
    wd::tick_1s(&mut beh, &mut events, 100);
    assert_eq!(
        beh.active().unwrap().remaining_s,
        wd::DEFAULT_MAX_DURATION - 100
    );
    wd::tick_1s(&mut beh, &mut events, 140);
    assert!(beh.active().is_none());
    // Zero tick on silence is a no-op.
    wd::tick_1s(&mut beh, &mut events, 10);
    assert!(beh.active().is_none());
}

// 07-5123-08-841-01: squawks never interrupt a live warning.
#[test]
fn vector_squawk_gated_07_5123_08_841_01() {
    let (mut beh, mut store, mut eng, mut events) = wd_harness();
    wd_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        wd::CMD_START_WARNING,
        &[0x91, 0x0a, 0x00, 0x00, 0x01],
    )
    .unwrap();
    wd_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        wd::CMD_SQUAWK,
        &[0xa0],
    )
    .unwrap();
    assert_eq!(beh.squawks(), 0);
    assert!(beh.active().is_some());
    wd::tick_1s(&mut beh, &mut events, 10);
    wd_drive(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        wd::CMD_SQUAWK,
        &[0x21],
    )
    .unwrap();
    assert_eq!(beh.squawks(), 1);
    // Unknown command is refused.
    assert_eq!(
        wd_drive(&mut beh, &mut store, &mut eng, &mut events, 0x02, &[]),
        Err(status::ZclStatus::UnsupCommand)
    );
}
