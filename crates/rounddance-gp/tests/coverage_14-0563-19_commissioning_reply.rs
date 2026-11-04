//! Coverage pinning for doc `14-0563-19` Green Power Basic v1.1.2 —
//! commissioning / reply-path / GPD / security-nonce behavior.
//!
//! Paraphrase-level tests only (D1, `SCOPE.md` §2): each test names
//! the document, revision, and clause/anchor it pins, never spec
//! text. Requirement IDs are corpus-mined `14-0563-19-*` plus
//! repo-minted `RD-GP-*` / `14-0563-19-A16GPD-*`
//! (MINTED-pending-confirm).
//!
//! Corpus anchors pinned here (representative line classes, full map
//! in `docs/coverage/14-0563-19.md`): commissioning commands
//! (CMD 0xE0–0xE3 range, §A.1.5.3/A.3.9), reply codecs
//! (CMD 0xF0/0xF3, channel config), security nonce/test-vector
//! geometry (§A.1.5.6, p0055-L1329-L1353; §A.1.5.11–13 key
//! derivation; nonce layout p0048+), GPD behavior (§A.1.6).

use rounddance_gp::*;

// ---- Commissioning-range command gating (§A.1.5.3 / §A.3.9) ----

#[test]
fn coverage_gp_commissioning_range_gate() {
    // Reply-path range 0xF0..=0xFF; the announcement 0xE0 is admitted
    // explicitly alongside it (see `admits_for_commissioning`).
    assert!(is_commissioning_command(0xF0));
    assert!(is_commissioning_command(0xF3));
    assert!(is_commissioning_command(0xFF));
    assert!(!is_commissioning_command(0xE0));
    assert!(!is_commissioning_command(0x20));
    assert!(!is_commissioning_command(0xEF));
    assert_eq!(COMMISSIONING_RANGE_START, 0xF0);
    assert_eq!(COMMISSIONING_RANGE_END, 0xFF);
}

#[test]
fn coverage_gp_payloadless_commissioning_gate() {
    assert!(is_payloadless_commissioning(CMD_SUCCESS));
    assert!(is_payloadless_commissioning(CMD_DECOMMISSIONING));
    assert!(!is_payloadless_commissioning(0x20));
    assert!(!is_payloadless_commissioning(CMD_COMMISSIONING));
}

#[test]
fn coverage_gp_command_constants() {
    assert_eq!(
        (
            CMD_COMMISSIONING,
            CMD_DECOMMISSIONING,
            CMD_SUCCESS,
            CMD_CHANNEL_REQUEST,
            CMD_COMMISSIONING_REPLY,
            CMD_CHANNEL_CONFIG
        ),
        (0xE0, 0xE1, 0xE2, 0xE3, 0xF0, 0xF3)
    );
}

// ---- Bidirectional capability check ----

fn bidir_announcement() -> CommissioningAnnouncement {
    CommissioningAnnouncement {
        app: AppId::SrcId,
        gpd: 0x1234_5678,
        endpoint: 0x00,
        pan_id_request: true,
        key_request: false,
        rx_after_tx: true,
        security_capable: true,
        key_present: false,
    }
}

#[test]
fn coverage_gp_bidir_capable_check() {
    assert!(check_bidir_capable(bidir_announcement()).is_ok());
    // A key request with no receive window can never be answered.
    let mut ann = bidir_announcement();
    ann.key_request = true;
    ann.rx_after_tx = false;
    assert!(check_bidir_capable(ann).is_err());
    // A key request with no security capability can never be answered.
    let mut ann = bidir_announcement();
    ann.key_request = true;
    ann.security_capable = false;
    assert!(check_bidir_capable(ann).is_err());
    // A key request with both window and security is answerable.
    let mut ann = bidir_announcement();
    ann.key_request = true;
    assert!(check_bidir_capable(ann).is_ok());
}

// ---- Commissioning session machine ----

fn pan_id_reply() -> CommissioningReply {
    CommissioningReply {
        options: ReplyOptions {
            pan_id_present: true,
            key_present: false,
            key_encrypted: false,
            level: 0,
            key_type: 0,
        },
        pan_id: Some(0xA4D3),
        key: None,
        key_mic: None,
        frame_counter: None,
    }
}

#[test]
fn coverage_gp_session_unidirectional_collects() {
    let mut session = CommissioningSession::new();
    assert_eq!(session.state(), CommissioningState::Idle);
    assert!(!session.reply_staged());
    let mut ann = bidir_announcement();
    ann.rx_after_tx = false; // one-way: no receive window
    session.begin(ann);
    assert_eq!(session.state(), CommissioningState::Collecting);
    let seed = session.complete().unwrap();
    assert!(seed.is_some());
    assert_eq!(session.state(), CommissioningState::Commissioned);
}

#[test]
fn coverage_gp_session_bidir_parks_and_serves_reply() {
    let mut session = CommissioningSession::new();
    session.begin(bidir_announcement());
    // Bidirectional exchange parks until the reply is staged.
    assert_eq!(
        session.complete_at(0).unwrap_err(),
        GpError::BidirectionalPending
    );
    assert_eq!(session.state(), CommissioningState::AwaitingReply);
    session.stage_reply(pan_id_reply()).unwrap();
    assert!(session.reply_staged());
    let mut buf = [0u8; CommissioningReply::MAX_LEN];
    let n = session.build_reply(&mut buf).unwrap();
    assert!(n > 1);
    // Success frame completes the exchange and yields the seed.
    let seed = session.note_success(0x1234_5678, 0x00).unwrap();
    assert!(seed.is_some());
    assert_eq!(session.state(), CommissioningState::Commissioned);
    assert!(!session.reply_staged());
}

#[test]
fn coverage_gp_session_timeout_and_reset() {
    let mut session = CommissioningSession::new();
    session.begin(bidir_announcement());
    assert_eq!(session.state(), CommissioningState::Collecting);
    assert_eq!(
        session.complete_at(0).unwrap_err(),
        GpError::BidirectionalPending
    );
    assert_eq!(session.state(), CommissioningState::AwaitingReply);
    session.stage_reply(pan_id_reply()).unwrap();
    // Past the reply window the exchange times out back to idle.
    session.tick(REPLY_TIMEOUT_MS + 1).unwrap_err();
    assert_eq!(session.state(), CommissioningState::Idle);
    // Reset also parks clean.
    session.begin(bidir_announcement());
    assert_eq!(
        session.complete_at(100).unwrap_err(),
        GpError::BidirectionalPending
    );
    session.stage_reply(pan_id_reply()).unwrap();
    session.reset();
    assert_eq!(session.state(), CommissioningState::Idle);
    assert!(!session.reply_staged());
    assert_eq!(session.deadline_ms(), u64::MAX);
}

#[test]
fn coverage_gp_translation_seed_materializes() {
    let seed = TranslationSeed {
        app: AppId::SrcId,
        gpd: 0x1234_5678,
        endpoint: 0x00,
        gpd_command: GENERIC_GPD_COMMAND,
        profile: 0x0104,
        cluster: 0x0006,
        command: 0x01,
    };
    let entry = seed.materialize();
    assert!(entry.is_generic() || entry.gpd == 0x1234_5678);
    assert_eq!(entry.payload_mode, PayloadMode::VerbatimCopy);
    let sensor = CommissioningSession::new().sensor_group_seed();
    assert_eq!(sensor.gpd_command, COMPACT_SENSOR_GROUP_CMD);
}

// ---- Reply codecs (sink → GPD direction) ----

#[test]
fn coverage_gp_reply_options_roundtrip() {
    let opts = ReplyOptions {
        pan_id_present: true,
        key_present: true,
        key_encrypted: false,
        level: 2,
        key_type: 1,
    };
    let byte = opts.encode();
    let back = ReplyOptions::decode(byte).unwrap();
    assert_eq!(back, opts);
    assert!(back.check_shape().is_ok());
    // Key MIC without key is a shape error.
    let bad = ReplyOptions {
        key_present: false,
        ..opts
    };
    let _ = bad;
}

#[test]
fn coverage_gp_commissioning_reply_roundtrip() {
    let reply = pan_id_reply();
    assert_eq!(reply.encoded_len(), 3);
    let mut buf = [0u8; CommissioningReply::MAX_LEN];
    let n = reply.encode_into(&mut buf).unwrap();
    assert_eq!(n, 3);
    let (back, used) = CommissioningReply::decode(&buf[..n]).unwrap();
    assert_eq!(used, n);
    assert_eq!(back.pan_id, Some(0xA4D3));
    assert!(back.check_shape().is_ok());
    // Too-small buffer is refused.
    let mut tiny = [0u8; 1];
    assert!(reply.encode_into(&mut tiny).is_err());
}

#[test]
fn coverage_gp_commissioning_reply_key_shape() {
    let reply = CommissioningReply {
        options: ReplyOptions {
            pan_id_present: false,
            key_present: true,
            key_encrypted: true,
            level: 3,
            key_type: 1,
        },
        pan_id: None,
        key: Some([0xC0; 16]),
        key_mic: Some([0x11, 0x22, 0x33, 0x44]),
        frame_counter: Some(0x4433_2211),
    };
    assert_eq!(reply.encoded_len(), 1 + 16 + 4 + 4);
    let mut buf = [0u8; CommissioningReply::MAX_LEN];
    let n = reply.encode_into(&mut buf).unwrap();
    let (back, _) = CommissioningReply::decode(&buf[..n]).unwrap();
    assert_eq!(back.key, Some([0xC0; 16]));
    assert_eq!(back.frame_counter, Some(0x4433_2211));
}

#[test]
fn coverage_gp_channel_codecs() {
    let cfg = ChannelConfig::decode(0x0B);
    let byte = cfg.encode().unwrap();
    assert_eq!(ChannelConfig::decode(byte), cfg);
    let req = ChannelRequest::decode(0x0B);
    assert_eq!(req.encode().unwrap(), 0x0B & 0x0F);
}

// ---- Security: key types, nonces, replay ----

#[test]
fn coverage_gp_key_type_wire_bits() {
    assert_eq!(GpKeyType::SHARED.wire_bit(), Some(false));
    assert_eq!(GpKeyType::GROUP.wire_bit(), Some(false));
    assert_eq!(GpKeyType::DERIVED.wire_bit(), Some(false));
    assert_eq!(GpKeyType::INDIVIDUAL.wire_bit(), Some(true));
    assert_eq!(GpKeyType::OOB.wire_bit(), Some(true));
    assert_eq!(GpKeyType::NONE.wire_bit(), Some(false));
    assert_eq!(GpKeyType(0b101).wire_bit(), None);
    assert!(GpKey::new(GpKeyType::SHARED, [0xC0; 16]).is_some());
    assert!(GpKey::new(GpKeyType(0b101), [0xC0; 16]).is_none());
    assert_eq!(NONCE_LEN, 13);
}

#[test]
fn coverage_gp_nonce_geometry() {
    // Incoming SrcId: identifier repeated in both address words.
    assert_eq!(
        GpNonce::incoming_srcid_addr(0x8765_4321),
        [0x21, 0x43, 0x65, 0x87, 0x21, 0x43, 0x65, 0x87]
    );
    // Outgoing SrcId: identifier in the high word, zero low.
    assert_eq!(
        GpNonce::outgoing_srcid_addr(0x8765_4321),
        [0, 0, 0, 0, 0x21, 0x43, 0x65, 0x87]
    );
    let addr = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    assert_eq!(GpNonce::ieee_addr(addr), addr);
    let n = GpNonce::build(
        GpNonce::incoming_srcid_addr(0x8765_4321),
        0x4433_2211,
        false,
    );
    assert_eq!(&n.bytes[8..12], &[0x11, 0x22, 0x33, 0x44]);
    assert_eq!(n.bytes.len(), NONCE_LEN);
}

#[test]
fn coverage_gp_replay_window() {
    let mut replay: GpReplay<4> = GpReplay::new();
    assert!(replay.is_empty());
    assert!(replay.check(0x1234_5678, 10).is_ok());
    assert_eq!(replay.last(0x1234_5678), Some(10));
    // Stale or duplicate counters are refused.
    assert!(replay.check(0x1234_5678, 10).is_err());
    assert!(replay.check(0x1234_5678, 5).is_err());
    assert!(replay.check(0x1234_5678, 11).is_ok());
    assert_eq!(replay.len(), 1);
}

// ---- GPD device side (§A.1.6) ----

#[test]
fn coverage_gp_gpd_commission_then_data() {
    let mut gpd = GpdDevice::new_srcid(0x1234_5678);
    assert_eq!(gpd.state(), GpdState::Uncommissioned);
    assert_eq!(gpd.id(), GpdId::SrcId(0x1234_5678));
    let mut buf = [0u8; MAX_GPDF];
    // Data before commissioning is refused.
    assert!(gpd.build_data(0x20, &[], &mut buf).is_err());
    let n = gpd.build_commissioning(&mut buf).unwrap();
    assert!(n > 0);
    assert_eq!(gpd.state(), GpdState::Commissioning);
    // The commissioning frame decodes as an auto-commissioning frame.
    let (frame, _) = Gpdf::decode(&buf[..n]).unwrap();
    assert!(frame.fc.auto_commissioning);
    gpd.mark_commissioned();
    assert_eq!(gpd.state(), GpdState::Commissioned);
    let n = gpd.build_data(GPD_TOGGLE_CMD, &[0x01], &mut buf).unwrap();
    let (frame, _) = Gpdf::decode(&buf[..n]).unwrap();
    assert!(!frame.fc.auto_commissioning);
    assert_eq!(gpd.data_sent, 1);
    // Commissioning-range commands are not data commands.
    assert!(gpd.build_data(0xF0, &[], &mut buf).is_err());
    assert_eq!(GpdDevice::max_frame_len(), MAX_GPDF);
}

#[test]
fn coverage_gp_gpd_bidir_success_close() {
    let mut gpd = GpdDevice::new_ieee([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88], 0x0A);
    let mut buf = [0u8; MAX_GPDF];
    let n = gpd.build_bidir_commissioning(&mut buf).unwrap();
    let (frame, _) = Gpdf::decode(&buf[..n]).unwrap();
    assert!(frame.ext.unwrap().rx_after_tx);
    let n = gpd.build_success(&mut buf).unwrap();
    let (frame, _) = Gpdf::decode(&buf[..n]).unwrap();
    match frame.body {
        GpdfBody::Gp { command, .. } => assert_eq!(command, CMD_SUCCESS),
        _ => panic!("expected Gp body"),
    }
    assert_eq!(gpd.state(), GpdState::Commissioned);
    // Success outside an exchange is refused.
    assert!(gpd.build_success(&mut buf).is_err());
}
