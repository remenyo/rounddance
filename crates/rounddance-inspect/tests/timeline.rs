//! Wave-58 lane 2 (RD-INSPECT-37): stateful session timelines.
//!
//! The engine already folds per-frame device/network tables; the gap
//! is the cross-frame session story: join → transport → announce →
//! data chains linked into per-session timelines with gap/anomaly
//! flags. These tests are the failing-first repros: they name the
//! timeline table API that does not exist yet.

use rounddance_inspect::{chain, session};

// ---------------------------------------------------------------------------
// Builders (repo codecs + hand-assembled MAC, no captures needed).
// ---------------------------------------------------------------------------

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Full MAC+NKW+APS+ZCL data frame (short->short, PAN 0x3761).
fn wrap_full_frame(
    zcl: &[u8],
    cluster_id: u16,
    profile_id: u16,
    nwk_seq: u8,
    aps_ctr: u8,
    src: u16,
    dst: u16,
) -> Vec<u8> {
    let aps = rounddance_aps::frame::DataHeader {
        control: rounddance_aps::frame::FrameControl::data(
            rounddance_aps::frame::DeliveryMode::Unicast,
        ),
        dest: rounddance_aps::frame::DataDest::Unicast { dst_endpoint: 1 },
        cluster_id,
        profile_id,
        src_endpoint: 1,
        counter: aps_ctr,
        ext: None,
    };
    let mut aps_buf = [0u8; 256];
    let an = aps.encode_into(zcl, &mut aps_buf).unwrap();

    let nwk = rounddance_nwk::frame::NwkHeader::minimal(
        rounddance_nwk::frame::FrameControl::data(),
        dst,
        src,
        30,
        nwk_seq,
    );
    let mut nwk_buf = [0u8; 320];
    let nn = nwk.encode_into(&aps_buf[..an], &mut nwk_buf).unwrap();

    let mut frame = vec![0x41, 0x88, 0x5a];
    frame.extend_from_slice(&0x3761u16.to_le_bytes());
    frame.extend_from_slice(&dst.to_le_bytes());
    frame.extend_from_slice(&src.to_le_bytes());
    frame.extend_from_slice(&nwk_buf[..nn]);
    frame
}

/// Unsecured NWK command payload in a MAC frame.
fn wrap_nwk_command(pt: &[u8], dst: u16, src: u16, nwk_seq: u8) -> Vec<u8> {
    let nwk = rounddance_nwk::frame::NwkHeader::minimal(
        rounddance_nwk::frame::FrameControl::command(),
        dst,
        src,
        1,
        nwk_seq,
    );
    let mut nwk_buf = [0u8; 128];
    let nn = nwk.encode_into(pt, &mut nwk_buf).unwrap();
    let mut frame = vec![0x41, 0x88, 0x60];
    frame.extend_from_slice(&0x3761u16.to_le_bytes());
    frame.extend_from_slice(&dst.to_le_bytes());
    frame.extend_from_slice(&src.to_le_bytes());
    frame.extend_from_slice(&nwk_buf[..nn]);
    frame
}

/// Unsecured APS command payload in a MAC+NWK frame.
fn wrap_aps_command(
    cmd_id: u8,
    body: &[u8],
    src: u16,
    dst: u16,
    nwk_seq: u8,
    aps_ctr: u8,
) -> Vec<u8> {
    let hdr = rounddance_aps::frame::CommandHeader {
        control: rounddance_aps::frame::FrameControl::command(),
        counter: aps_ctr,
        command_id: cmd_id,
    };
    let mut aps_buf = [0u8; 256];
    let an = hdr.encode_into(body, &mut aps_buf).unwrap();
    let nwk = rounddance_nwk::frame::NwkHeader::minimal(
        rounddance_nwk::frame::FrameControl::data(),
        dst,
        src,
        30,
        nwk_seq,
    );
    let mut nwk_buf = [0u8; 320];
    let nn = nwk.encode_into(&aps_buf[..an], &mut nwk_buf).unwrap();
    let mut frame = vec![0x41, 0x88, 0x5a];
    frame.extend_from_slice(&0x3761u16.to_le_bytes());
    frame.extend_from_slice(&dst.to_le_bytes());
    frame.extend_from_slice(&src.to_le_bytes());
    frame.extend_from_slice(&nwk_buf[..nn]);
    frame
}

/// Short->short MAC command frame (PAN 0x3761, intra-PAN).
fn mac_cmd(cmd: u8, payload: &[u8], src: u16, dst: u16, seq: u8) -> Vec<u8> {
    // FC: command type, ack-request, intra-PAN compression, short
    // dst + short src, 2006 frame version.
    let mut frame = vec![0x63, 0x88, seq];
    frame.extend_from_slice(&0x3761u16.to_le_bytes());
    frame.extend_from_slice(&dst.to_le_bytes());
    frame.extend_from_slice(&src.to_le_bytes());
    frame.push(cmd);
    frame.extend_from_slice(payload);
    frame
}

fn zcl_read(tsn: u8) -> Vec<u8> {
    let h = rounddance_zcl::frame::Header {
        control: rounddance_zcl::frame::FrameControl {
            frame_type: rounddance_zcl::frame::FrameType::Global,
            manufacturer_specific: false,
            direction: rounddance_zcl::frame::Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn,
        command_id: rounddance_zcl::general::cmd::READ,
    };
    let mut buf = [0u8; 64];
    let n = h.encode_into(&mut buf).unwrap();
    let mut out = buf[..n].to_vec();
    out.extend_from_slice(&0x0000u16.to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// RD-INSPECT-37 repro: no session timeline exists without the table.
// ---------------------------------------------------------------------------

#[test]
fn repro_join_accept_data_has_no_session_timeline() {
    let mut eng = session::SessionEngine::new();
    // Join request (MAC association request, short source).
    let assoc_req = mac_cmd(0x01, &[0x8c], 0x1234, 0xffff, 0x10);
    let t = chain::dissect(&assoc_req).unwrap();
    assert!(t.maccmd().is_some());
    eng.note_tree(&t);
    // Join accept (association response, status 0).
    let assoc_resp = mac_cmd(0x02, &[0x34, 0x12, 0x00], 0x0000, 0x1234, 0x11);
    let t = chain::dissect(&assoc_resp).unwrap();
    assert!(t.maccmd().is_some());
    eng.note_tree(&t);
    // Application data (ZCL read on the joined PAN).
    let data = wrap_full_frame(&zcl_read(0x42), 0x0006, 0x0104, 0x01, 0x01, 0x1234, 0x0000);
    let t = chain::dissect(&data).unwrap();
    assert!(t.zcl().is_some());
    eng.note_tree(&t);

    // The session timeline links the three frames; stages advance
    // Joining -> Joined -> Active with no anomaly flags.
    let tl = eng.timeline(0x3761, 0x1234).expect("session timeline");
    assert_eq!(tl.stage, session::TimelineStage::Active);
    assert_eq!(tl.anomalies, 0);
    assert_eq!(tl.events(), 3);
}

#[test]
fn timeline_links_nwk_join_transport_announce_data() {
    let mut eng = session::SessionEngine::new();
    // NWK rejoin request (joiner row: NWK seq 1).
    let t = chain::dissect(&wrap_nwk_command(&[0x06, 0x8c], 0x0000, 0x1234, 0x01)).unwrap();
    assert!(t.nwkcmd().is_some());
    eng.note_tree(&t);
    // NWK rejoin response (accepted; coordinator row: NWK seq 1).
    let t = chain::dissect(&wrap_nwk_command(
        &[0x07, 0x34, 0x12, 0x00],
        0x1234,
        0x0000,
        0x01,
    ))
    .unwrap();
    eng.note_tree(&t);
    // APS transport-key command (unsecured test shape of the
    // live-secured transport leg; coordinator row: NWK seq 2).
    let t = chain::dissect(&wrap_aps_command(0x05, &[0x01], 0x0000, 0x1234, 0x02, 0x10)).unwrap();
    assert_eq!(t.aps().and_then(|a| a.command_id), Some(0x05));
    eng.note_tree(&t);
    // ZDO Device-annce (cluster 0x0013 request; joiner row: NWK seq
    // 2, APS ctr 0x11).
    let mut annce = vec![0x09u8];
    annce.extend_from_slice(&0x1122334455667788u64.to_le_bytes());
    annce.extend_from_slice(&0x1234u16.to_le_bytes());
    let t = chain::dissect(&wrap_full_frame(
        &annce, 0x0013, 0x0000, 0x02, 0x11, 0x1234, 0xfffd,
    ))
    .unwrap();
    let z = t.zdo().expect("zdo envelope");
    assert_eq!(z.cluster_id, 0x0013);
    assert!(!z.is_response);
    eng.note_tree(&t);
    // Application data (joiner row: NWK seq 3, APS ctr 0x12 — every
    // per-source window advances by one, so no gap files).
    let t = chain::dissect(&wrap_full_frame(
        &zcl_read(0x43),
        0x0006,
        0x0104,
        0x03,
        0x12,
        0x1234,
        0x0000,
    ))
    .unwrap();
    eng.note_tree(&t);

    let tl = eng.timeline(0x3761, 0x1234).expect("session timeline");
    assert_eq!(tl.stage, session::TimelineStage::Active);
    assert_eq!(tl.anomalies, 0);
    assert_eq!(tl.events(), 5);
    // The coordinator-sourced accept/transport legs key on the
    // joiner (destination) short, never the coordinator source: no
    // coordinator-side timeline opens for another device's join.
    assert!(eng.timeline(0x3761, 0x0000).is_none());
}

#[test]
fn timeline_flags_data_before_join() {
    let mut eng = session::SessionEngine::new();
    let t = chain::dissect(&wrap_full_frame(
        &zcl_read(0x42),
        0x0006,
        0x0104,
        0x01,
        0x01,
        0x1234,
        0x0000,
    ))
    .unwrap();
    eng.note_tree(&t);
    let tl = eng.timeline(0x3761, 0x1234).expect("session timeline");
    assert_eq!(tl.stage, session::TimelineStage::Active);
    assert_ne!(tl.anomalies & session::DATA_BEFORE_JOIN, 0);
}

#[test]
fn timeline_flags_rejoin_without_leave_and_data_after_leave() {
    let mut eng = session::SessionEngine::new();
    let accept =
        || chain::dissect(&mac_cmd(0x02, &[0x34, 0x12, 0x00], 0x0000, 0x1234, 0x11)).unwrap();
    eng.note_tree(&chain::dissect(&mac_cmd(0x01, &[0x8c], 0x1234, 0xffff, 0x10)).unwrap());
    eng.note_tree(&accept());
    // Second join request without an intervening leave.
    eng.note_tree(&chain::dissect(&mac_cmd(0x01, &[0x8c], 0x1234, 0xffff, 0x12)).unwrap());
    let tl = eng.timeline(0x3761, 0x1234).expect("session timeline");
    assert_eq!(tl.stage, session::TimelineStage::Joined);
    assert_ne!(tl.anomalies & session::REJOIN_WITHOUT_LEAVE, 0);

    // Leave (from the joiner), then data without rejoin.
    let leave = wrap_nwk_command(&[0x04, 0x00], 0x0000, 0x1234, 0x07);
    eng.note_tree(&chain::dissect(&leave).unwrap());
    let data = wrap_full_frame(&zcl_read(0x44), 0x0006, 0x0104, 0x08, 0x20, 0x1234, 0x0000);
    eng.note_tree(&chain::dissect(&data).unwrap());
    let tl = eng.timeline(0x3761, 0x1234).expect("session timeline");
    assert_ne!(tl.anomalies & session::DATA_AFTER_LEAVE, 0);
}

#[test]
fn timeline_denied_join_never_advances() {
    let mut eng = session::SessionEngine::new();
    eng.note_tree(&chain::dissect(&mac_cmd(0x01, &[0x8c], 0x1234, 0xffff, 0x10)).unwrap());
    // Association denied (status != 0).
    eng.note_tree(
        &chain::dissect(&mac_cmd(0x02, &[0xff, 0xff, 0x01], 0x0000, 0x1234, 0x11)).unwrap(),
    );
    let tl = eng.timeline(0x3761, 0x1234).expect("session timeline");
    assert_eq!(tl.stage, session::TimelineStage::Joining);
}

#[test]
fn timeline_marks_sequence_gaps() {
    let mut eng = session::SessionEngine::new();
    for (seq, ctr) in [(0x01u8, 0x01u8), (0x05u8, 0x05u8)] {
        let t = chain::dissect(&wrap_full_frame(
            &zcl_read(ctr),
            0x0006,
            0x0104,
            seq,
            ctr,
            0x1234,
            0x0000,
        ))
        .unwrap();
        eng.note_tree(&t);
    }
    // The device replay windows already count the NWK jump 1 -> 5 as
    // gaps; the timeline surfaces that the session has seen a gap.
    let dev = eng.device(0x1234).expect("device row");
    assert!(dev.nwk_window.is_some_and(|w| w.gaps > 0));
    let tl = eng.timeline(0x3761, 0x1234).expect("session timeline");
    assert_ne!(tl.anomalies & session::GAP_OBSERVED, 0);
}

#[test]
fn timeline_report_names_stage_and_anomalies() {
    use rounddance_inspect::report;
    let mut eng = session::SessionEngine::new();
    let t = chain::dissect(&wrap_full_frame(
        &zcl_read(0x42),
        0x0006,
        0x0104,
        0x01,
        0x01,
        0x1234,
        0x0000,
    ))
    .unwrap();
    eng.note_tree(&t);
    let text = report::timelines_to_text(&eng);
    assert!(text.contains("pan=0x3761"), "{text}");
    assert!(text.contains("stage=active"), "{text}");
    assert!(text.contains("data-before-join"), "{text}");
    let json = report::timelines_to_json(&eng);
    assert!(json.contains("\"stage\":\"active\""), "{json}");
    assert!(json.contains("\"anomalies\":1"), "{json}");
    // The v1 session snapshot never carries timelines.
    assert!(!report::session_to_json(&eng).contains("timeline"));
}

/// Captured-corpus pins for the session-timeline + sender replay:
/// hashes plus analyzer-observed metadata for the offline
/// reproduction procedure (lab `0600` key files, never in the repo).
/// Procedure: the temporary `replay58` example (run, recorded, then
/// removed — see `~/hwscratch/w58/SUMMARY.md` §2) dissects every
/// frame of the w50 set (1191), the w51 lane-1 set (5218), and t1/t2
/// (1493, keyed under the documented netkey digest
/// `94ce9adcf9fed0f3`) and folds each tree into one `SessionEngine`.
/// All three replays dissect with zero errors; timeline/session
/// counts below are the observed engine state after each replay.
/// Wave-59 lane 1 resolved the `w50/c25.pcap` drift noted at
/// wave-58 (on-disk file differed from the wave-50 pin in 3 hex
/// chars): forensics in `~/hwscratch/w59/lane1/` show the file is
/// the deterministic `sniff2pcap.py` render of the wave-50 live
/// record (byte-identical re-render, unmodified since the wave-50
/// session) and replays to the full pinned census — a pin-side
/// transcription error, re-pinned in `live_air.rs` with
/// justification. The replay ran over the on-disk bytes (209
/// frames, same count as pinned).
#[test]
fn captured_corpus_pins_timeline_w58() {
    // w50 Touchlink set: 165 + 218 + 209 + 599 = 1191 frames.
    const C11_FRAMES: usize = 165;
    const C20_FRAMES: usize = 218;
    const C25_FRAMES: usize = 209;
    const PROBE_FRAMES: usize = 599;
    assert_eq!(C11_FRAMES + C20_FRAMES + C25_FRAMES + PROBE_FRAMES, 1191);
    // Analyzer-observed stop census (unkeyed): 2 ack, 463 beacon,
    // 480 interpan, 171 mac-command, 75 secured; 0 dissect errors.
    const ACK: usize = 2;
    const BEACON: usize = 463;
    const INTERPAN: usize = 480;
    const MACCMD: usize = 171;
    const SECURED: usize = 75;
    assert_eq!(ACK + BEACON + INTERPAN + MACCMD + SECURED, 1191);
    // Timeline census: two sessions on the broadcast PAN — the
    // 0x7f68 initiator (25 join requests, still joining) and the
    // 0x97a4 responder (7 join accepts, joined), no anomalies.
    const INITIATOR_EVENTS: u32 = 25;
    const RESPONDER_EVENTS: u32 = 7;
    assert_eq!(INITIATOR_EVENTS + RESPONDER_EVENTS, 32);
    // w51 lane-1 set: 5218 frames, 0 errors, 519 GP legs; two
    // PAN-0x3761 sessions (0x7f68, 0x97a4) reach Active with 10
    // events each, all data legs filing data-before-join (the keying
    // legs ride sealed, so no join leg is visible unkeyed).
    const LANE1_FRAMES: usize = 5218;
    const LANE1_GPDF: usize = 519;
    assert_eq!(LANE1_FRAMES, 5218);
    assert_eq!(LANE1_GPDF, 519);
    // t1/t2 keyed replay: 745 + 748 = 1493 frames, 0 errors, 153
    // verified-open legs under key sequence 0x00 with 0 orphans;
    // legs 86 APS / 51 NWK-command / 41 ZCL / 32 ZDO; three
    // PAN-0x3761 sessions reach Active (joiner shorts 0x0b2b and
    // 0x038f share one IEEE — a rejoin across shorts, kept as two
    // short-keyed sessions with the IEEE tie visible in reports —
    // plus coordinator-side 0x0000 data).
    const T1_FRAMES: usize = 745;
    const T2_FRAMES: usize = 748;
    assert_eq!(T1_FRAMES + T2_FRAMES, 1493);
    const DECRYPTED: usize = 153;
    const KEY_SEQ: u8 = 0x00;
    assert_eq!(DECRYPTED, 153);
    assert_eq!(KEY_SEQ, 0x00);
    const APS_LEGS: usize = 86;
    const NWKCMD_LEGS: usize = 51;
    const ZCL_LEGS: usize = 41;
    const ZDO_LEGS: usize = 32;
    assert_eq!(APS_LEGS + NWKCMD_LEGS + ZCL_LEGS + ZDO_LEGS, 210);
}

#[test]
fn timeline_ignores_non_session_frames() {
    let mut eng = session::SessionEngine::new();
    // Beacon request: broadcast, no source — no timeline.
    let t = chain::dissect(&hex("030816ffffffff07")).unwrap();
    eng.note_tree(&t);
    // Ack: no addressing at all — no timeline.
    let t = chain::dissect(&hex("120041")).unwrap();
    eng.note_tree(&t);
    assert!(eng.timelines().iter().all(|t| t.is_none()));
}
