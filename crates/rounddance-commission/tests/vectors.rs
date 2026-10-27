//! Join-flow transcripts, install-code vectors (provenance-marked derived
//! values), and finding/binding exchange vectors.
//!
//! Byte strings and transcripts below are hand-computed from the
//! paraphrased layouts — never spec text (D1, `SCOPE.md` §2).
//! Requirement IDs: corpus-mined `22-65816-030-*`; repo-minted
//! `05-3474-23-*` / `07-5123-08-*` (dots stripped),
//! MINTED-pending-confirm. Derived values carrying a `MOCK` comment
//! pin self-consistency of the [`rounddance_security::mock`] backend,
//! never interop.

use rounddance_commission::*;
use rounddance_security::mock::MockBackend;

fn coord_config() -> FormationConfig {
    FormationConfig {
        role: LogicalType::Coordinator,
        primary: ChannelMask::from_list(&[15, 20]).unwrap(),
        secondary: ChannelMask::from_list(&[26]).unwrap(),
        scan_duration: 3,
        pan: PanChoice::Auto,
        extended_pan: [0xAA; 8],
        router_short_addr: 0,
    }
}

// 22-65816-030-81-01: an end device must never form.
#[test]
fn vector_end_device_cannot_form_22_65816_030_81_01() {
    let mut cfg = coord_config();
    cfg.role = LogicalType::EndDevice;
    assert_eq!(
        FormationMachine::new(cfg).unwrap_err(),
        FormationError::BadRole
    );
}

// 22-65816-030-81-01: no channels anywhere fails validation.
#[test]
fn vector_no_channels_fails_22_65816_030_81_01() {
    let mut cfg = coord_config();
    cfg.primary = ChannelMask::empty();
    cfg.secondary = ChannelMask::empty();
    assert_eq!(
        FormationMachine::new(cfg).unwrap_err(),
        FormationError::NoChannels
    );
}

// 22-65816-030-81-01: already-on-network without a factory reset fails.
#[test]
fn vector_factory_reset_first_22_65816_030_81_01() {
    let mut m = FormationMachine::new(coord_config()).unwrap();
    m.begin(false, true);
    assert_eq!(m.state(), FormationState::Failed);
    assert_eq!(m.error(), Some(FormationError::AlreadyOnNetwork));
}

// 22-65816-030-81-01: primary scanned first, then secondary.
#[test]
fn vector_primary_then_secondary_22_65816_030_81_01() {
    let mut m = FormationMachine::new(coord_config()).unwrap();
    m.begin(true, false);
    assert_eq!(m.state(), FormationState::ScanningPrimary);
    assert_eq!(
        m.scan_phase_channels(),
        Some(ChannelMask::from_list(&[15, 20]).unwrap())
    );
    m.on_scan_complete(&FirstFreePan, false, &[]);
    assert_eq!(m.state(), FormationState::ScanningSecondary);
    assert_eq!(
        m.scan_phase_channels(),
        Some(ChannelMask::from_list(&[26]).unwrap())
    );
}

// 22-65816-030-81-02: fully-parameterized primitive invocation.
#[test]
fn vector_primitive_params_22_65816_030_81_02() {
    let mut m = FormationMachine::new(coord_config()).unwrap();
    m.begin(true, false);
    m.on_scan_complete(&FirstFreePan, true, &[0x1234]);
    assert_eq!(m.state(), FormationState::ResolvingPan);
    // PAN conflict: the only free pick avoids 0x1234.
    let pan = m.pan_id().unwrap();
    assert_ne!(pan, 0x1234);
    let req = m.primitive_params().unwrap();
    assert_eq!(req.beacon_order, FORMATION_BEACON_ORDER);
    assert_eq!(req.beacon_order, 0x0f);
    assert_eq!(req.superframe_order, FORMATION_SUPERFRAME_ORDER);
    assert_eq!(req.superframe_order, 0x00);
    assert!(!req.battery_life_extension);
    assert!(!req.distributed);
    assert_eq!(req.extended_pan, [0xAA; 8]);
    assert_eq!(req.scan_duration, 3);
}

// 22-65816-030-81-02: routers form distributed with their address attached.
#[test]
fn vector_router_distributed_params_22_65816_030_81_02() {
    let mut cfg = coord_config();
    cfg.role = LogicalType::Router;
    cfg.router_short_addr = 0x1111;
    let mut m = FormationMachine::new(cfg).unwrap();
    m.begin(true, false);
    m.on_scan_complete(&FirstFreePan, true, &[]);
    let req = m.primitive_params().unwrap();
    assert!(req.distributed);
    assert_eq!(req.short_addr, 0x1111);
}

// 22-65816-030-81-03: success raises on-network; coordinator owes TC startup.
#[test]
fn vector_success_raises_on_network_22_65816_030_81_03() {
    let mut m = FormationMachine::new(coord_config()).unwrap();
    m.begin(true, false);
    m.on_scan_complete(&FirstFreePan, true, &[]);
    m.on_invoked();
    m.on_confirm(true);
    assert_eq!(m.state(), FormationState::OnNetwork);
    assert!(m.trust_center_startup_due());
}

// 22-65816-030-81-03: a router finishes at join completion (no TC startup).
#[test]
fn vector_router_no_tc_startup_22_65816_030_81_03() {
    let mut cfg = coord_config();
    cfg.role = LogicalType::Router;
    let mut m = FormationMachine::new(cfg).unwrap();
    m.begin(true, false);
    m.on_scan_complete(&FirstFreePan, true, &[]);
    m.on_invoked();
    m.on_confirm(true);
    assert_eq!(m.state(), FormationState::OnNetwork);
    assert!(!m.trust_center_startup_due());
}

// 22-65816-030-81-03: exhausted channels fail the procedure.
#[test]
fn vector_exhausted_channels_fail_22_65816_030_81_03() {
    let mut cfg = coord_config();
    cfg.secondary = ChannelMask::empty();
    let mut m = FormationMachine::new(cfg).unwrap();
    m.begin(true, false);
    m.on_scan_complete(&FirstFreePan, false, &[]);
    assert_eq!(m.state(), FormationState::Failed);
    assert_eq!(m.error(), Some(FormationError::ScanExhausted));
}

// ChannelMask: bad channels rejected, listing is ascending.
#[test]
fn vector_channel_mask_rules() {
    assert_eq!(
        ChannelMask::from_list(&[11, 27]).unwrap_err(),
        FormationError::BadChannel
    );
    let mask = ChannelMask::from_list(&[20, 11, 26]).unwrap();
    assert!(mask.contains(11) && mask.contains(20) && mask.contains(26));
    assert!(!mask.contains(15));
    assert_eq!(mask.count(), 3);
    let mut out = [0u8; MAX_SCAN_CHANNELS];
    let n = mask.to_list(&mut out);
    assert_eq!(&out[..n], &[11, 20, 26]);
}

// 22-65816-030-91-01: the scan asks for join-permitted networks only.
#[test]
fn vector_discovery_scan_shape_22_65816_030_91_01() {
    let mask = ChannelMask::from_list(&[15]).unwrap();
    let scan = DiscoveryScan::new(mask, 3);
    assert!(scan.join_permitted_only);
    assert!(scan.require_end_device_capacity);
    assert_eq!(scan.channels, mask);
}

// 22-65816-030-91-01: a bad scan fails the procedure.
#[test]
fn vector_bad_scan_fails_22_65816_030_91_01() {
    let mut m = SteeringMachine::new();
    m.begin_scan(ChannelMask::from_list(&[15]).unwrap(), 3)
        .unwrap();
    m.on_scan_failed();
    assert_eq!(m.state(), SteeringState::Failed);
    assert!(m.scan_failed());
}

// 22-65816-030-91-01: highest acceptable link quality wins; ties break
// to the lower PAN; unacceptable rows never win.
#[test]
fn vector_candidate_ranking_22_65816_030_91_01() {
    let mut m = SteeringMachine::new();
    m.begin_scan(ChannelMask::all_24g(), 3).unwrap();
    let row = |pan, lqi, permit| BeaconSurveyEntry {
        pan_id: pan,
        channel: 15,
        lqi,
        permit_joining: permit,
        router_capacity: true,
        end_device_capacity: true,
        protocol_version: 2,
    };
    m.ingest(row(0x2222, 200, true)).unwrap();
    m.ingest(row(0x1111, 200, true)).unwrap();
    m.ingest(row(0x3333, 250, false)).unwrap();
    m.finish_scan(&BaselineSteeringPolicy {
        min_lqi: 100,
        min_version: 2,
    });
    assert_eq!(m.state(), SteeringState::CandidateSelected);
    assert_eq!(m.candidate().unwrap().pan_id, 0x1111);
}

// 22-65816-030-91-01: nothing acceptable parks in NoSuitableNetwork.
#[test]
fn vector_no_suitable_network_22_65816_030_91_01() {
    let mut m = SteeringMachine::new();
    m.begin_scan(ChannelMask::from_list(&[15]).unwrap(), 3)
        .unwrap();
    m.ingest(BeaconSurveyEntry {
        pan_id: 0x1234,
        channel: 15,
        lqi: 10,
        permit_joining: true,
        router_capacity: true,
        end_device_capacity: true,
        protocol_version: 2,
    })
    .unwrap();
    m.finish_scan(&BaselineSteeringPolicy {
        min_lqi: 100,
        min_version: 2,
    });
    assert_eq!(m.state(), SteeringState::NoSuitableNetwork);
    assert!(m.candidate().is_none());
}

// 22-65816-030-111-01: target must already be on-network.
#[test]
fn vector_target_needs_network_22_65816_030_111_01() {
    let mut t = FinderTarget::new();
    assert_eq!(
        t.start(false, 60).unwrap_err(),
        FindingError::TargetOffNetwork
    );
    t.start(true, 3).unwrap();
    assert!(t.answer_identify());
    assert!(t.serves_descriptors());
    assert!(!t.tick_1s());
    assert!(!t.tick_1s());
    assert!(t.tick_1s());
    assert_eq!(t.state(), TargetState::Done);
    assert!(!t.answer_identify());
    assert!(t.serves_descriptors());
}

// 22-65816-030-111-02: off-network initiator fails; silence fails; answers log.
#[test]
fn vector_initiator_query_flow_22_65816_030_111_02() {
    assert_eq!(IDENTIFY_QUERY_BROADCAST, 0xffff);
    let mut bad = FinderInitiator::new();
    bad.begin(false);
    assert_eq!(bad.state(), InitiatorState::Failed);
    assert_eq!(bad.error(), Some(FindingError::InitiatorOffNetwork));

    let mut empty = FinderInitiator::new();
    empty.begin(true);
    empty.finish_queries();
    assert_eq!(empty.state(), InitiatorState::Failed);
    assert_eq!(empty.error(), Some(FindingError::NoRespondents));

    let mut m = FinderInitiator::new();
    m.begin(true);
    m.note_answer(0x1234, 1);
    m.note_answer(0x5678, 2);
    m.finish_queries();
    assert_eq!(m.state(), InitiatorState::Matching);
    let logged: Vec<(u16, u8)> = m.respondents().map(|r| (r.nwk_addr, r.endpoint)).collect();
    assert_eq!(logged, vec![(0x1234, 1), (0x5678, 2)]);
    assert!(m.resolve_ieee(0x1234, 1, 0xAAAA_BBBB_CCCC_DDDD));
    assert!(!m.resolve_ieee(0x9999, 1, 1));
}

// 22-65816-030-111-03: supported clusters advance, others skip, empty moves on.
#[test]
fn vector_cluster_matching_22_65816_030_111_03() {
    let mut m = FinderInitiator::new();
    m.begin(true);
    m.note_answer(0x1234, 1);
    m.finish_queries();
    let respondent = m.respondents().next().unwrap();
    let req = FinderInitiator::match_request_for(0x2A, respondent, 0x0104);
    assert_eq!(req.nwk_of_interest, 0x1234);
    assert_eq!(req.profile_id, 0x0104);

    let mut matched = [0u16; MAX_MATCHED_CLUSTERS];
    let n = m
        .match_clusters(&[0x0006, 0x0008, 0x0300], &[0x0006, 0x0008], &mut matched)
        .unwrap();
    assert_eq!(&matched[..n], &[0x0006, 0x0008]);
    assert_eq!(
        m.match_clusters(&[0x0300], &[0x0006], &mut matched)
            .unwrap_err(),
        FindingError::NoMatch
    );
}

// 22-65816-030-111-04: group bind names mode + group id and pushes to target.
#[test]
fn vector_group_binding_22_65816_030_111_04() {
    let mut m = FinderInitiator::new();
    m.begin(true);
    m.note_answer(0x1234, 1);
    m.finish_queries();
    let r = *m.respondents().next().unwrap();
    let (entry, push) = m
        .bind_entry_for(0x01, 0x1111_2222_3333_4444, 1, &r, 0x0006, Some(0x4001))
        .unwrap();
    assert!(push);
    assert_eq!(entry.cluster_id, 0x0006);
    assert!(matches!(
        entry.dst,
        rounddance_zdo::BindDstMode::Group { group_addr: 0x4001 }
    ));
    m.finish_binding();
    assert_eq!(m.state(), InitiatorState::Done);
}

// 22-65816-030-111-04: unicast bind needs the resolved long address first.
#[test]
fn vector_unicast_binding_needs_ieee_22_65816_030_111_04() {
    let mut m = FinderInitiator::new();
    m.begin(true);
    m.note_answer(0x1234, 1);
    m.finish_queries();
    let r = *m.respondents().next().unwrap();
    assert_eq!(
        m.bind_entry_for(0x01, 0x1111_2222_3333_4444, 1, &r, 0x0006, None)
            .unwrap_err(),
        FindingError::UnknownIeee
    );
    m.resolve_ieee(0x1234, 1, 0xAAAA_BBBB_CCCC_DDDD);
    let r = *m.respondents().next().unwrap();
    let (entry, push) = m
        .bind_entry_for(0x01, 0x1111_2222_3333_4444, 1, &r, 0x0006, None)
        .unwrap();
    assert!(!push);
    assert!(matches!(
        entry.dst,
        rounddance_zdo::BindDstMode::Extended {
            dst_ieee: 0xAAAA_BBBB_CCCC_DDDD,
            dst_endpoint: 1
        }
    ));
}

// Touchlink command tables (07-5123-08-13322-01 / 13323-01, anchors
// p1132-L25931-L25932 + p1144-L26292-L26295).
#[test]
fn vector_touchlink_command_ids() {
    use rounddance_commission::touchlink::{rx, tx};
    assert_eq!(TOUCHLINK_CLUSTER, 0x1000);
    assert_eq!(TOUCHLINK_PROFILE, 0xc05e);
    assert_eq!(rx::SCAN_REQ, 0x00);
    assert_eq!(rx::DEVICE_INFO_REQ, 0x02);
    assert_eq!(rx::IDENTIFY_REQ, 0x06);
    assert_eq!(rx::RESET_FACTORY_REQ, 0x07);
    assert_eq!(rx::NWK_START_REQ, 0x10);
    assert_eq!(rx::NWK_JOIN_ROUTER_REQ, 0x12);
    assert_eq!(rx::NWK_JOIN_ED_REQ, 0x14);
    assert_eq!(rx::NWK_UPDATE_REQ, 0x16);
    assert_eq!(tx::SCAN_RSP, 0x01);
    assert_eq!(tx::DEVICE_INFO_RSP, 0x03);
    assert_eq!(tx::NWK_START_RSP, 0x11);
    assert_eq!(tx::NWK_JOIN_ROUTER_RSP, 0x13);
    assert_eq!(tx::NWK_JOIN_ED_RSP, 0x15);
}

// 22-65816-030-1211-01: transaction-bound frame codec round-trips.
#[test]
fn vector_touchlink_frame_codec() {
    let frame = TouchlinkFrame::new(0xDEAD_BEEF, 0x00, &[0x0B, 0x00]).unwrap();
    let mut buf = [0u8; MAX_TOUCHLINK_FRAME];
    let n = frame.encode_into(&mut buf).unwrap();
    assert_eq!(n, 7);
    let back = TouchlinkFrame::decode(&buf[..n]).unwrap();
    assert_eq!(back, frame);
    assert_eq!(back.transaction, 0xDEAD_BEEF);
    assert_eq!(back.payload_bytes(), &[0x0B, 0x00]);
    assert_eq!(
        TouchlinkFrame::decode(&buf[..4]).unwrap_err(),
        TouchlinkError::Truncated
    );
}

// 22-65816-030-121-02: scan-request payload codec.
#[test]
fn vector_scan_request_payload() {
    let p = ScanRequestPayload {
        touchlink_info: 0x0B,
        key_index: 0x00,
    };
    let mut buf = [0u8; 2];
    assert_eq!(p.encode_into(&mut buf).unwrap(), 2);
    assert_eq!(ScanRequestPayload::decode(&buf).unwrap(), p);
    assert_eq!(
        ScanRequestPayload::decode(&buf[..1]).unwrap_err(),
        TouchlinkError::Truncated
    );
}

// 22-65816-030-121-01 / 122-01: initiator/target skeleton handshake.
#[test]
fn vector_touchlink_skeleton_handshake() {
    let mut init = TouchlinkInitiator::new();
    init.begin_scan(0x1234_5678).unwrap();
    assert_eq!(init.state(), TouchlinkInitiatorState::Scanning);
    let scan = init.scan_request(0x0B, 0x00);
    assert_eq!(scan.transaction, 0x1234_5678);
    assert_eq!(scan.command, 0x00);
    init.note_response(false);
    assert_eq!(init.state(), TouchlinkInitiatorState::Scanning);
    init.note_response(true);
    assert_eq!(init.state(), TouchlinkInitiatorState::Selecting);
    init.proceed(false).unwrap();
    assert_eq!(init.state(), TouchlinkInitiatorState::JoiningNetwork);

    let mut target = TouchlinkTarget::new();
    target.on_scan_request(&scan);
    assert_eq!(target.state(), TouchlinkTargetState::ScanReceived);
    target.on_response_sent();
    assert_eq!(target.state(), TouchlinkTargetState::Responded);
    target.on_network_order(true);
    assert_eq!(target.state(), TouchlinkTargetState::Applying);
    // Stale transaction never advances the target.
    let mut stale = TouchlinkTarget::new();
    stale.on_scan_request(&scan);
    stale.on_response_sent();
    stale.on_network_order(false);
    assert_eq!(stale.state(), TouchlinkTargetState::Responded);
    init.finish(true);
    assert_eq!(init.state(), TouchlinkInitiatorState::Done);
    target.finish(true);
    assert_eq!(target.state(), TouchlinkTargetState::Done);
}

// Install codes: lengths fixed, check field enforced
// (22-65816-030-56-03).
#[test]
fn vector_install_code_validation() {
    for &len in &[6usize, 8, 12, 16] {
        let payload: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_add(1)).collect();
        let mut wire = [0u8; MAX_INSTALL_CODE_LEN];
        let n = InstallCode::with_crc(&payload, &mut wire).unwrap();
        assert_eq!(n, len + 2);
        let code = InstallCode::from_slice(&wire[..n]).unwrap();
        assert_eq!(code.payload(), payload.as_slice());
        // Any single-octet corruption fails.
        let mut bad = wire;
        bad[0] ^= 0x01;
        assert_eq!(
            InstallCode::from_slice(&bad[..n]).unwrap_err(),
            JoinError::BadInstallCode
        );
    }
    assert_eq!(
        InstallCode::from_slice(&[1, 2, 3]).unwrap_err(),
        JoinError::BadInstallCode
    );
    let mut out = [0u8; MAX_INSTALL_CODE_LEN];
    assert_eq!(
        InstallCode::with_crc(&[1, 2, 3, 4, 5], &mut out).unwrap_err(),
        JoinError::BadInstallCode
    );
}

// Install-code derivation through the injected backend: deterministic
// per (code, eui) and distinct across devices. MOCK provenance: values
// below pin the MockBackend stream, never interop.
#[test]
fn vector_install_code_derivation_mock() {
    let kdf = EccJoinKdf(MockBackend::new(0xC0));
    let payload = [0x11u8; 8];
    let mut wire = [0u8; MAX_INSTALL_CODE_LEN];
    let n = InstallCode::with_crc(&payload, &mut wire).unwrap();
    let code = InstallCode::from_slice(&wire[..n]).unwrap();
    let (mut k1, mut k1b, mut k2) = ([0u8; 16], [0u8; 16], [0u8; 16]);
    TrustCenter::install_code_key(&kdf, &code, &[0x01; 8], &mut k1).unwrap();
    TrustCenter::install_code_key(&kdf, &code, &[0x01; 8], &mut k1b).unwrap();
    TrustCenter::install_code_key(&kdf, &code, &[0x02; 8], &mut k2).unwrap();
    assert_eq!(k1, k1b);
    assert_ne!(k1, k2);
}

// 22-65816-030-91-03: symmetric joiner transcript
// beacon→assoc→key→verify→announce→close-out.
#[test]
fn vector_symmetric_join_transcript_22_65816_030_91_03() {
    let policy = JoinPolicy {
        cbke_supported: false,
        cbke_required: false,
        interview_tc: true,
        parent_is_r20_earlier: false,
    };
    let mut j = JoinerMachine::new(JoinMethod::InstallCode, policy);
    j.on_candidate();
    assert_eq!(j.state(), JoinerState::AwaitingCandidate);
    j.on_assoc_confirm(true);
    assert_eq!(j.state(), JoinerState::Authenticating);
    j.on_key_transport(true);
    assert_eq!(j.state(), JoinerState::KeyWait);
    // Wrong method marker never verifies.
    j.on_verify_confirm(true, KeyAttributes::NEGOTIATED);
    assert_eq!(j.state(), JoinerState::Failed);
    assert_eq!(j.error(), Some(JoinError::ConfirmMismatch));

    let mut j = JoinerMachine::new(JoinMethod::InstallCode, policy);
    j.on_candidate();
    j.on_assoc_confirm(true);
    j.on_key_transport(true);
    j.on_verify_confirm(true, KeyAttributes::SYMMETRIC);
    assert_eq!(j.state(), JoinerState::Announced);
    let annce = j.device_annce(0x0A, 0x1234, 0xAAAA_BBBB_CCCC_DDDD);
    assert_eq!(annce.nwk_addr, 0x1234);
    assert_eq!(annce.ieee, 0xAAAA_BBBB_CCCC_DDDD);
    j.close_out(false);
    assert_eq!(j.state(), JoinerState::Joined);
}

// 22-65816-030-91-06: a required handshake that cannot run fails the join.
#[test]
fn vector_cbke_required_gate_22_65816_030_91_06() {
    let policy = JoinPolicy {
        cbke_supported: false,
        cbke_required: true,
        interview_tc: false,
        parent_is_r20_earlier: false,
    };
    let mut j = JoinerMachine::new(JoinMethod::InstallCode, policy);
    j.on_candidate();
    j.on_assoc_confirm(true);
    j.on_key_transport(true);
    j.on_verify_confirm(true, KeyAttributes::SYMMETRIC);
    j.close_out(false);
    assert_eq!(j.state(), JoinerState::Failed);
}

// 22-65816-030-91-05: negotiation path (network key + token, then announce).
#[test]
fn vector_negotiation_join_transcript_22_65816_030_91_05() {
    let policy = JoinPolicy {
        cbke_supported: true,
        cbke_required: false,
        interview_tc: false,
        parent_is_r20_earlier: false,
    };
    let mut j = JoinerMachine::new(JoinMethod::Negotiation, policy);
    j.on_candidate();
    j.on_assoc_confirm(true);
    j.on_key_transport(true);
    j.on_negotiation_done(true, true);
    assert_eq!(j.state(), JoinerState::Announced);
    j.close_out(true);
    assert_eq!(j.state(), JoinerState::Joined);
    // A missing token is fatal once final.
    let mut j2 = JoinerMachine::new(JoinMethod::Negotiation, policy);
    j2.on_candidate();
    j2.on_assoc_confirm(true);
    j2.on_key_transport(true);
    j2.on_negotiation_done(true, false);
    assert_eq!(j2.state(), JoinerState::Failed);
}

// 22-65816-030-56-02 / 56-04: allow-list + timeout eviction.
#[test]
fn vector_allow_list_and_timeout_22_65816_030_56() {
    let mut tc = TrustCenter::new();
    assert_eq!(
        tc.admit(0x1111, 0x0001, JoinMethod::InstallCode, 5)
            .unwrap_err(),
        JoinError::NotAllowed
    );
    tc.set_allow_list(&[0x1111]);
    tc.admit(0x1111, 0x0001, JoinMethod::InstallCode, 2)
        .unwrap();
    assert!(tc.find(0x1111).is_some());
    assert!(tc.find(0x2222).is_none());
    // Two ticks pass the deadline; the device is reported for eviction.
    let mut timed_out = [0u64; 4];
    assert_eq!(tc.tick(&mut timed_out), 0);
    assert_eq!(tc.tick(&mut timed_out), 0);
    assert_eq!(tc.tick(&mut timed_out), 1);
    assert_eq!(timed_out[0], 0x1111);
    let dev = tc.evict(0x1111).unwrap();
    assert_eq!(dev.ieee, 0x1111);
    assert_eq!(tc.len(), 0);
    assert_eq!(tc.evict(0x1111).unwrap_err(), JoinError::NotFound);
}

// 22-65816-030-91-02: symmetric exchange key rules + verify promotion.
#[test]
fn vector_symmetric_exchange_rules_22_65816_030_91_02() {
    let mut tc = TrustCenter::new();
    tc.open();
    tc.admit(0x1111, 0x0001, JoinMethod::PreconfiguredKey, 10)
        .unwrap();
    let old = [0xAAu8; 16];
    // Same key back is no exchange.
    assert_eq!(
        tc.exchange_key(0x1111, &old, &old, 0x04).unwrap_err(),
        JoinError::BadTransportKey
    );
    // Wrong key type is no exchange.
    assert_eq!(
        tc.exchange_key(0x1111, &[0xBBu8; 16], &old, 0x00)
            .unwrap_err(),
        JoinError::BadTransportKey
    );
    let new = [0xBBu8; 16];
    let attrs = tc.exchange_key(0x1111, &new, &old, 0x04).unwrap();
    assert_eq!(attrs, KeyAttributes::SYMMETRIC);
    assert!(!tc.find(0x1111).unwrap().verified);
    assert_eq!(
        tc.on_verify_confirm(0x1111, false).unwrap_err(),
        JoinError::ConfirmMismatch
    );
    tc.on_verify_confirm(0x1111, true).unwrap();
    assert!(tc.find(0x1111).unwrap().verified);
}

// 05-3474-23-3615-01: rejoin checks gate the joined state.
#[test]
fn vector_rejoin_checks_05_3474_23_3615_01() {
    let mut r = RejoinMachine::new(true);
    assert!(r.secured());
    r.begin();
    assert_eq!(r.state(), RejoinState::OrphanScanning);
    r.on_orphan_scan(false);
    assert_eq!(r.state(), RejoinState::Failed);

    let mut r = RejoinMachine::new(false);
    r.begin();
    r.on_orphan_scan(true);
    assert_eq!(r.state(), RejoinState::Rejoining);
    r.on_confirm(false);
    assert_eq!(r.state(), RejoinState::Failed);

    let mut r = RejoinMachine::new(false);
    r.begin();
    r.on_orphan_scan(true);
    r.on_confirm(true);
    assert_eq!(r.state(), RejoinState::Joined);
}

// Leave forms name the device and the rejoin/children flags.
#[test]
fn vector_leave_forms() {
    let req = LeaveMachine::mgmt_leave_for(0x07, 0xDEAD_BEEF_CAFE_1234, true, false);
    assert_eq!(req.tsn, 0x07);
    assert_eq!(req.device_ieee, 0xDEAD_BEEF_CAFE_1234);
    assert!(req.rejoin);
    assert!(!req.remove_children);
}
