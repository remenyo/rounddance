//! Join-flow transcripts, install-code vectors (provenance-marked derived
//! values), and finding/binding exchange vectors.
//!
//! Byte strings and transcripts below are hand-computed from the
//! paraphrased layouts — never spec text (D1, `SCOPE.md` §2).
//! Requirement IDs: corpus-mined `22-65816-030-*`; repo-minted
//! `05-3474-23-*` / `07-5123-08-*` (dots stripped) / `RD-SIM-*`,
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
    let row = |pan, lqi, rssi, permit| BeaconSurveyEntry {
        pan_id: pan,
        channel: 15,
        lqi,
        rssi,
        permit_joining: permit,
        router_capacity: true,
        end_device_capacity: true,
        protocol_version: 2,
    };
    m.ingest(row(0x2222, 200, -40, true)).unwrap();
    m.ingest(row(0x1111, 200, -40, true)).unwrap();
    m.ingest(row(0x3333, 250, -40, false)).unwrap();
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
        // Strong frame (wave-27 bench tail-RSSI) that the absolute
        // gate still refuses: pins the old gate's documented behavior.
        rssi: -28,
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

// 07-5123-08-13322-01 / 13323-01: scan request/response wire shape.
// The transaction rides little-endian, then the frozen command octet
// (0x00 scan request, 0x01 scan response), then the info/key pair.
#[test]
fn vector_touchlink_scan_wire_ids() {
    let init = {
        let mut init = TouchlinkInitiator::new();
        init.begin_scan(0x1234_5678).unwrap();
        init
    };
    let req = init.scan_request(0x0B, 0x04);
    let mut buf = [0u8; MAX_TOUCHLINK_FRAME];
    let n = req.encode_into(&mut buf).unwrap();
    assert_eq!(&buf[..n], &[0x78, 0x56, 0x34, 0x12, 0x00, 0x0B, 0x04]);
    let back = TouchlinkFrame::decode(&buf[..n]).unwrap();
    assert_eq!(back.transaction, 0x1234_5678);
    assert_eq!(back.command, 0x00);

    let mut target = TouchlinkTarget::new();
    target.on_scan_request(&back);
    let rsp = target.scan_response(0x0C, 0x04);
    assert_eq!(rsp.transaction, 0x1234_5678);
    assert_eq!(rsp.command, 0x01);
    let m = rsp.encode_into(&mut buf).unwrap();
    assert_eq!(&buf[..m], &[0x78, 0x56, 0x34, 0x12, 0x01, 0x0C, 0x04]);
    let back_rsp = TouchlinkFrame::decode(&buf[..m]).unwrap();
    assert_eq!(back_rsp.command, 0x01);
    assert_eq!(back_rsp.transaction, 0x1234_5678);
}

// 22-65816-030-121-03 / 122-02: the SAP adapter puts one touchlink
// frame per inter-PAN payload on the requested channel; out-of-range
// channels surface as transport errors.
#[test]
fn vector_touchlink_sap_adapter_transfer() {
    use rounddance_mac_sap::{
        Channel, FramePayload, MacError, MacInterPanSap, TxConfirm, TxHandle,
    };

    struct Capture {
        channel: Option<Channel>,
        bytes: Vec<u8>,
        next: u32,
    }
    impl MacInterPanSap for Capture {
        fn interpan_request(
            &mut self,
            channel: Channel,
            msdu: &FramePayload,
        ) -> Result<TxHandle, MacError> {
            self.channel = Some(channel);
            self.bytes = msdu.as_slice().to_vec();
            self.next += 1;
            Ok(TxHandle(self.next))
        }
        fn poll_interpan_confirm(&mut self) -> Option<TxConfirm> {
            None
        }
        fn poll_interpan_indication(&mut self) -> Option<rounddance_mac_sap::InterPanIndication> {
            None
        }
    }

    let mut cap = Capture {
        channel: None,
        bytes: Vec::new(),
        next: 0,
    };
    let frame = TouchlinkFrame::new(0x1234_5678, 0x00, &[0x0B, 0x04]).unwrap();
    let err = {
        let mut sap = SapInterPan::new(&mut cap);
        sap.send(20, &frame).unwrap();
        // Channel 10 is outside the 2.4 GHz band: transport error.
        sap.send(10, &frame).unwrap_err()
    };
    assert_eq!(cap.channel, Some(Channel::new(20).unwrap()));
    assert_eq!(&cap.bytes, &[0x78, 0x56, 0x34, 0x12, 0x00, 0x0B, 0x04]);
    assert_eq!(err, MacError::InvalidChannel);
    assert_eq!(
        TouchlinkError::from(MacError::InvalidChannel),
        TouchlinkError::Transport
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

// 22-65816-030-56-07: BDB §6.11.1.1 worked example, frozen. Payload
// 83..05 takes check bytes C3 B5 on the wire (CRC 0xB5C3 stored
// little-endian, anchor p0041-L807-L815); big-endian storage of the
// same value is rejected.
#[test]
fn vector_install_code_crc_worked_22_65816_030_56_07() {
    let payload = [
        0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23, 0xA5, 0xC6, 0x39, 0xB2, 0x69, 0x16, 0xD5,
        0x05,
    ];
    let mut wire = [0u8; MAX_INSTALL_CODE_LEN];
    let n = InstallCode::with_crc(&payload, &mut wire).unwrap();
    assert_eq!(n, 18);
    assert_eq!(&wire[16..18], &[0xC3, 0xB5]);
    let code = InstallCode::from_slice(&wire[..n]).unwrap();
    assert_eq!(code.payload(), &payload);
    // The same check value in big-endian order is not the code.
    let mut swapped = wire;
    swapped[16] = 0xB5;
    swapped[17] = 0xC3;
    assert_eq!(
        InstallCode::from_slice(&swapped[..n]).unwrap_err(),
        JoinError::BadInstallCode
    );
    // A non-reflected-CRC code (old 0x9502 variant) is rejected.
    let mut stale = wire;
    stale[16] = 0x02;
    stale[17] = 0x95;
    assert_eq!(
        InstallCode::from_slice(&stale[..n]).unwrap_err(),
        JoinError::BadInstallCode
    );
}

// 22-65816-030-56-08: BDB §6.11.1.2 worked key, frozen. The MMO hash
// of the worked code (anchor p0041-L828-L834) must produce
// 66B6900981E1EE3CA4206B6B861C02BB — the same value the security
// crate pins at the hash layer, now reached through the Trust-Center
// derivation entry point. The joiner address is not an input.
#[test]
fn vector_install_code_mmo_worked_22_65816_030_56_08() {
    let wire = [
        0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23, 0xA5, 0xC6, 0x39, 0xB2, 0x69, 0x16, 0xD5,
        0x05, 0xC3, 0xB5,
    ];
    let code = InstallCode::from_slice(&wire).unwrap();
    let mut key = [0u8; 16];
    TrustCenter::install_code_key(&MmoJoinKdf, &code, &[0xAA; 8], &mut key).unwrap();
    assert_eq!(
        key,
        [
            0x66, 0xB6, 0x90, 0x09, 0x81, 0xE1, 0xEE, 0x3C, 0xA4, 0x20, 0x6B, 0x6B, 0x86, 0x1C,
            0x02, 0xBB
        ]
    );
    // Address-independence: a different EUI derives the same key.
    let mut key2 = [0u8; 16];
    TrustCenter::install_code_key(&MmoJoinKdf, &code, &[0x01; 8], &mut key2).unwrap();
    assert_eq!(key, key2);
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

// 05-3474-23-4433-01: TC-first transport classification. Only the
// (transport-key command, network key type) pair ends the
// post-association wait; every other first frame — vendor chatter,
// update-device-style commands, or a transport-key command naming a
// different key type — leaves the wait unchanged and latches
// nothing.
#[test]
fn vector_tc_first_transport_classification_05_3474_23_4433_01() {
    let policy = JoinPolicy {
        cbke_supported: false,
        cbke_required: false,
        interview_tc: false,
        parent_is_r20_earlier: false,
    };
    // Pre-association frames are ignored, never a promotion.
    let mut early = JoinerMachine::new(JoinMethod::InstallCode, policy);
    early.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_NETWORK);
    assert_eq!(early.state(), JoinerState::Unjoined);

    let mut j = JoinerMachine::new(JoinMethod::InstallCode, policy);
    j.on_candidate();
    j.on_assoc_confirm(true);
    // Vendor chatter and foreign commands do not promote.
    j.note_transport_frame(UNSECURED_VENDOR_CMD, 0x00);
    j.note_transport_frame(0x00, 0x00);
    j.note_transport_frame(TRANSPORT_KEY_CMD, 0x04);
    assert_eq!(j.state(), JoinerState::Authenticating);
    assert_eq!(j.unsecured_count(), 0);
    // The genuine TC-first transport promotes to the key wait.
    j.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_NETWORK);
    assert_eq!(j.state(), JoinerState::KeyWait);
    // A repeat while waiting is tolerated without effect.
    j.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_NETWORK);
    assert_eq!(j.state(), JoinerState::KeyWait);
    j.on_verify_confirm(true, KeyAttributes::SYMMETRIC);
    assert_eq!(j.state(), JoinerState::Announced);
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

// ---------------------------------------------------------------------------
// Touchlink commissioning completion (wave-20).
// ---------------------------------------------------------------------------

/// In-memory inter-PAN seam for the completion vectors.
struct VecTx {
    frames: Vec<(u8, Vec<u8>)>,
}

impl VecTx {
    fn new() -> Self {
        Self { frames: Vec::new() }
    }
}

impl InterPanTx for VecTx {
    type Error = TouchlinkError;

    fn send(&mut self, channel: u8, frame: &TouchlinkFrame) -> Result<(), TouchlinkError> {
        let mut buf = [0u8; MAX_TOUCHLINK_FRAME];
        let n = frame.encode_into(&mut buf)?;
        self.frames.push((channel, buf[..n].to_vec()));
        Ok(())
    }
}

/// Fixed completion fixtures: certification-key transport inputs and
/// the wrapped/unwrapped network key pair.
const CERT_TID: u32 = 0x3eaa_2009;
const CERT_RSID: u32 = 0x8876_2fb1;
const CERT_TRANSPORT: [u8; 16] = [
    0x66, 0x9e, 0x08, 0xe4, 0x02, 0x77, 0xed, 0x9a, 0xb3, 0x6b, 0x25, 0x80, 0x45, 0x6b, 0x41, 0x76,
];
const PLAIN_KEY: [u8; 16] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];
const WRAPPED_KEY: [u8; 16] = [
    0x83, 0x22, 0x63, 0x68, 0x73, 0xa7, 0xbb, 0x2a, 0x18, 0x9a, 0x53, 0x70, 0x8c, 0x60, 0x7b, 0xd0,
];

fn completion_ext_pan() -> [u8; 8] {
    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

fn completion_start_req() -> NetworkStartRequest {
    NetworkStartRequest {
        extended_pan: completion_ext_pan(),
        key_index: KEY_INDEX_CERTIFICATION,
        encrypted_key: WRAPPED_KEY,
        channel: 15,
        pan_id: 0x1a2b,
        network_address: 0x0001,
        group_begin: 0x0001,
        group_end: 0x0008,
        free_nwk_begin: 0x0002,
        free_nwk_end: 0x7fff,
        free_group_begin: 0x000b,
        free_group_end: 0x000c,
        initiator_ieee: [0xaa; 8],
        initiator_nwk: 0x0000,
    }
}

fn completion_join_req() -> NetworkJoinRequest {
    NetworkJoinRequest {
        extended_pan: completion_ext_pan(),
        key_index: KEY_INDEX_CERTIFICATION,
        encrypted_key: WRAPPED_KEY,
        network_update_id: 0x03,
        channel: 15,
        pan_id: 0x1a2b,
        network_address: 0x0002,
        group_begin: 0x0001,
        group_end: 0x0008,
        free_nwk_begin: 0x0002,
        free_nwk_end: 0x7fff,
        free_group_begin: 0x000b,
        free_group_end: 0x000c,
    }
}

/// Timer, status, and key-index constants.
#[test]
fn vector_touchlink_completion_constants() {
    assert_eq!(TRANSACTION_LIFETIME_MS, 8_000);
    assert_eq!(RX_WINDOW_MS, 5_000);
    assert_eq!(MIN_STARTUP_DELAY_MS, 2_000);
    assert_eq!(SCAN_BASE_MS, 250);
    assert_eq!(STATUS_SUCCESS, 0x00);
    assert_eq!(STATUS_FAILURE, 0x01);
    assert_eq!(KEY_INDEX_DEVELOPMENT, 0);
    assert_eq!(KEY_INDEX_MASTER, 4);
    assert_eq!(KEY_INDEX_CERTIFICATION, 15);
    assert_eq!(
        CERTIFICATION_KEY,
        [
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
            0xce, 0xcf
        ]
    );
}

// 07-5123-08-1333411-01: key-index negotiation picks the highest
// common bit; disjoint masks fail.
#[test]
fn vector_key_index_selection_07_5123_08_1333411_01() {
    assert_eq!(select_key_index(0x8010, 0x8010).unwrap(), 15);
    assert_eq!(select_key_index(0x0010, 0x8010).unwrap(), 4);
    assert_eq!(select_key_index(0x0001, 0x0001).unwrap(), 0);
    assert_eq!(
        select_key_index(0x0001, 0x8010 & !0x0001).unwrap_err(),
        TouchlinkError::BadKeyIndex
    );
    assert_eq!(
        transport_key_for(16, CERT_TID, CERT_RSID, &[0u8; 16]).unwrap_err(),
        TouchlinkError::BadKeyIndex
    );
}

// 07-5123-08-1333411-01: certification-key worked vector —
// derivation input, transport key, wrap, and unwrap.
#[test]
fn vector_transport_certification_worked_07_5123_08_1333411_01() {
    assert_eq!(
        transport_block(CERT_TID, CERT_RSID),
        [
            0x3e, 0xaa, 0x20, 0x09, 0x3e, 0xaa, 0x20, 0x09, 0x88, 0x76, 0x2f, 0xb1, 0x88, 0x76,
            0x2f, 0xb1
        ]
    );
    let transport =
        transport_key_for(KEY_INDEX_CERTIFICATION, CERT_TID, CERT_RSID, &[0u8; 16]).unwrap();
    assert_eq!(transport, CERT_TRANSPORT);
    assert_eq!(encrypt_network_key(&transport, &PLAIN_KEY), WRAPPED_KEY);
    assert_eq!(decrypt_network_key(&transport, &WRAPPED_KEY), PLAIN_KEY);
    // Development input wraps the two fixed markers around the ids.
    assert_eq!(
        development_block(CERT_TID, CERT_RSID),
        [
            b'P', b'h', b'L', b'i', 0x3e, 0xaa, 0x20, 0x09, b'C', b'L', b'S', b'N', 0x88, 0x76,
            0x2f, 0xb1
        ]
    );
    let dev = transport_key_for(KEY_INDEX_DEVELOPMENT, CERT_TID, CERT_RSID, &[0u8; 16]).unwrap();
    assert_eq!(dev, development_block(CERT_TID, CERT_RSID));
}

// Local ECB decryption agrees with the published cipher check:
// decrypting the reference ciphertext returns the reference
// plaintext.
#[test]
fn vector_decrypt_published_cipher_check() {
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let ciphertext: [u8; 16] = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];
    let plaintext: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    assert_eq!(decrypt_network_key(&key, &ciphertext), plaintext);
}

// 07-5123-08-13322-01: full scan-request body wire shape.
#[test]
fn vector_scan_request_body_wire() {
    let body = ScanRequestBody {
        zigbee_info: 0x05,
        touchlink_info: 0x83,
    };
    let mut buf = [0u8; 2];
    assert_eq!(body.encode_into(&mut buf).unwrap(), 2);
    assert_eq!(&buf, &[0x05, 0x83]);
    assert_eq!(ScanRequestBody::decode(&buf).unwrap(), body);
    assert_eq!(
        ScanRequestBody::decode(&buf[..1]).unwrap_err(),
        TouchlinkError::Truncated
    );
}

// 07-5123-08-133231-01: full scan-response body wire shape, with and
// without the single-sub-device tail.
#[test]
fn vector_scan_response_body_wire_07_5123_08_133231_01() {
    let rsp = ScanResponseBody {
        rssi_correction: 0x05,
        zigbee_info: 0x05,
        touchlink_info: 0x83,
        key_bitmask: 0x8010,
        response_id: CERT_RSID,
        extended_pan: completion_ext_pan(),
        network_update_id: 0x00,
        channel: 15,
        pan_id: 0x1a2b,
        network_address: 0xffff,
        sub_devices: 1,
        total_groups: 0x02,
        endpoint: 0x0a,
        profile_id: 0x0104,
        device_id: 0x0005,
        version: 0x01,
        group_count: 0x02,
    };
    let mut buf = [0u8; 64];
    let n = rsp.encode_into(&mut buf).unwrap();
    assert_eq!(n, 32);
    assert_eq!(
        &buf[..n],
        &[
            0x05, 0x05, 0x83, 0x10, 0x80, 0xb1, 0x2f, 0x76, 0x88, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, 0x08, 0x00, 0x0f, 0x2b, 0x1a, 0xff, 0xff, 0x01, 0x02, 0x0a, 0x04, 0x01,
            0x05, 0x00, 0x01, 0x02,
        ]
    );
    assert_eq!(ScanResponseBody::decode(&buf[..n]).unwrap(), rsp);
    // Bare form: no tail.
    let mut bare = rsp;
    bare.sub_devices = 0;
    bare.endpoint = 0;
    bare.profile_id = 0;
    bare.device_id = 0;
    bare.version = 0;
    bare.group_count = 0;
    let m = bare.encode_into(&mut buf).unwrap();
    assert_eq!(m, 25);
    assert_eq!(ScanResponseBody::decode(&buf[..m]).unwrap(), bare);
    // Two sub-devices are outside the bounded codec.
    let mut bad = rsp;
    bad.sub_devices = 2;
    assert_eq!(
        bad.encode_into(&mut buf).unwrap_err(),
        TouchlinkError::InvalidField
    );
    let mut over = [0u8; 25];
    over[23] = 2;
    assert_eq!(
        ScanResponseBody::decode(&over).unwrap_err(),
        TouchlinkError::InvalidField
    );
    assert_eq!(
        ScanResponseBody::decode(&buf[..10]).unwrap_err(),
        TouchlinkError::Truncated
    );
}

// 07-5123-08-133225-01: network start request wire shape.
#[test]
fn vector_network_start_wire_07_5123_08_133225_01() {
    let req = completion_start_req();
    let mut buf = [0u8; 64];
    assert_eq!(req.encode_into(&mut buf).unwrap(), 52);
    let mut want = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0f];
    want.extend_from_slice(&WRAPPED_KEY);
    want.extend_from_slice(&[
        0x0f, 0x2b, 0x1a, 0x01, 0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0xff, 0x7f, 0x0b, 0x00,
        0x0c, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00,
    ]);
    assert_eq!(&buf[..52], &want[..]);
    assert_eq!(NetworkStartRequest::decode(&buf[..52]).unwrap(), req);
    // Full frame wire: transaction + command + body.
    let frame = TouchlinkFrame::new(0x1234_5678, 0x10, &buf[..52]).unwrap();
    let mut wire = [0u8; MAX_TOUCHLINK_FRAME];
    let n = frame.encode_into(&mut wire).unwrap();
    assert_eq!(n, 57);
    assert_eq!(&wire[..5], &[0x78, 0x56, 0x34, 0x12, 0x10]);
    assert_eq!(&wire[5..n], &buf[..52]);
    assert_eq!(
        NetworkStartRequest::decode(&buf[..51]).unwrap_err(),
        TouchlinkError::Truncated
    );
}

// 07-5123-08-133226-01 / 133227-01: network join request wire shape
// (shared by router and end-device kinds).
#[test]
fn vector_network_join_wire_07_5123_08_133226_01() {
    let req = completion_join_req();
    let mut buf = [0u8; 64];
    assert_eq!(req.encode_into(&mut buf).unwrap(), 43);
    let mut want = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0f];
    want.extend_from_slice(&WRAPPED_KEY);
    want.extend_from_slice(&[
        0x03, 0x0f, 0x2b, 0x1a, 0x02, 0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0xff, 0x7f, 0x0b,
        0x00, 0x0c, 0x00,
    ]);
    assert_eq!(&buf[..43], &want[..]);
    assert_eq!(NetworkJoinRequest::decode(&buf[..43]).unwrap(), req);
    assert_eq!(JoinKind::Router.request_command(), 0x12);
    assert_eq!(JoinKind::Router.response_command(), 0x13);
    assert_eq!(JoinKind::EndDevice.request_command(), 0x14);
    assert_eq!(JoinKind::EndDevice.response_command(), 0x15);
}

// 07-5123-08-133233-01 / 133234-01 / 133235-01 + 133228-01:
// response and update wire shapes.
#[test]
fn vector_responses_and_update_wire() {
    let rsp = NetworkStartResponse::success(completion_ext_pan(), 0x00, 15, 0x1a2b);
    assert!(rsp.is_success());
    let mut buf = [0u8; 16];
    assert_eq!(rsp.encode_into(&mut buf).unwrap(), 13);
    assert_eq!(
        &buf[..13],
        &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x0f, 0x2b, 0x1a]
    );
    assert_eq!(NetworkStartResponse::decode(&buf[..13]).unwrap(), rsp);
    assert!(!NetworkStartResponse::failure().is_success());

    let join = NetworkJoinResponse::success();
    let mut one = [0u8; 1];
    assert_eq!(join.encode_into(&mut one).unwrap(), 1);
    assert_eq!(&one, &[0x00]);
    assert_eq!(NetworkJoinResponse::decode(&one).unwrap(), join);
    assert!(!NetworkJoinResponse::failure().is_success());

    let update = NetworkUpdateRequest {
        extended_pan: completion_ext_pan(),
        network_update_id: 0x04,
        channel: 20,
        pan_id: 0x1a2b,
        network_address: 0x0002,
    };
    let mut ubuf = [0u8; 16];
    assert_eq!(update.encode_into(&mut ubuf).unwrap(), 14);
    assert_eq!(
        &ubuf[..14],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x04, 0x14, 0x2b, 0x1a, 0x02, 0x00]
    );
    assert_eq!(NetworkUpdateRequest::decode(&ubuf[..14]).unwrap(), update);

    let ident = IdentifyRequest { duration_s: 10 };
    let mut ibuf = [0u8; 2];
    assert_eq!(ident.encode_into(&mut ibuf).unwrap(), 2);
    assert_eq!(&ibuf, &[0x0a, 0x00]);
    assert_eq!(IdentifyRequest::decode(&ibuf).unwrap(), ident);
    let dev = DeviceInfoRequest { start_index: 2 };
    let mut dbuf = [0u8; 1];
    assert_eq!(dev.encode_into(&mut dbuf).unwrap(), 1);
    assert_eq!(&dbuf, &[0x02]);
    assert_eq!(DeviceInfoRequest::decode(&dbuf).unwrap(), dev);
}

fn completion_scan_response() -> ScanResponseBody {
    ScanResponseBody {
        rssi_correction: 0x05,
        zigbee_info: 0x05,
        touchlink_info: 0x83,
        key_bitmask: 0x8010,
        response_id: CERT_RSID,
        extended_pan: [0; 8],
        network_update_id: 0x00,
        channel: 0,
        pan_id: 0x0000,
        network_address: 0xffff,
        sub_devices: 0,
        total_groups: 0x00,
        endpoint: 0,
        profile_id: 0,
        device_id: 0,
        version: 0,
        group_count: 0,
    }
}

fn completion_target_ctx() -> TargetOrderCtx {
    TargetOrderCtx {
        is_router: true,
        accept: true,
        key: TouchlinkKey::Certification,
        supported_keys: 0x8010,
    }
}

// 22-65816-030-121-04 / 122-03: full scan→start transcript —
// initiator forms a new network via touchlink, the target unwraps
// the transported key, both sides hand the same parameters to the
// classical layer.
#[test]
fn vector_full_start_transcript_22_65816_030_121_04() {
    let mut initiator = TouchlinkInitiator::new();
    let mut target = TouchlinkTarget::new();
    let mut air = VecTx::new();
    initiator.begin_scan(CERT_TID).unwrap();

    // Scan exchange on the heard channel.
    let scan = TouchlinkFrame::new(CERT_TID, 0x00, &[0x05, 0x83]).unwrap();
    target.on_scan_request(&scan);
    target
        .respond_full(&mut air, 15, &completion_scan_response())
        .unwrap();
    assert_eq!(target.state(), TouchlinkTargetState::Responded);
    let (_, rsp_wire) = air.frames.pop().unwrap();
    let rsp_frame = TouchlinkFrame::decode(&rsp_wire).unwrap();
    assert_eq!(rsp_frame.command, 0x01);
    let body = ScanResponseBody::decode(rsp_frame.payload_bytes()).unwrap();
    assert_eq!(body.response_id, CERT_RSID);

    // Initiator selects the highest common protection and wraps.
    initiator.note_response(rsp_frame.transaction == CERT_TID);
    let index = select_key_index(0x8010, body.key_bitmask).unwrap();
    assert_eq!(index, KEY_INDEX_CERTIFICATION);
    let transport = transport_key_for(index, CERT_TID, body.response_id, &[0u8; 16]).unwrap();
    assert_eq!(transport, CERT_TRANSPORT);
    let wrapped = encrypt_network_key(&transport, &PLAIN_KEY);
    assert_eq!(wrapped, WRAPPED_KEY);
    initiator.proceed(true).unwrap();

    // Start order over the air; the target unwraps and accepts.
    let mut req = completion_start_req();
    req.encrypted_key = wrapped;
    let mut order_air = VecTx::new();
    initiator
        .send_start(&mut order_air, 15, &req, &PLAIN_KEY)
        .unwrap();
    assert_eq!(
        initiator.state(),
        TouchlinkInitiatorState::AwaitingStartResponse
    );
    let (_, order_wire) = order_air.frames.pop().unwrap();
    let order_frame = TouchlinkFrame::decode(&order_wire).unwrap();
    assert_eq!(order_frame.command, 0x10);
    let order = NetworkStartRequest::decode(order_frame.payload_bytes()).unwrap();
    let reply = target
        .on_network_start(&order, order_frame.transaction, &completion_target_ctx())
        .unwrap();
    assert!(reply.is_success());
    assert_eq!(target.state(), TouchlinkTargetState::Applying);
    assert_eq!(reply.pan_id, 0x1a2b);

    // Success response closes the initiator leg after the delay.
    initiator.on_start_response(&reply, CERT_TID).unwrap();
    assert_eq!(initiator.state(), TouchlinkInitiatorState::StartupWait);
    assert!(!initiator.tick_ms(1_999));
    assert_eq!(initiator.state(), TouchlinkInitiatorState::StartupWait);
    assert!(initiator.tick_ms(1));
    assert_eq!(initiator.state(), TouchlinkInitiatorState::Done);

    // Both sides hand the same network to the classical layer (the
    // addresses differ by role: initiator keeps its own short).
    let init_handoff = initiator.take_handoff().unwrap();
    let target_handoff = target.take_pending().unwrap();
    assert_eq!(init_handoff.network_key, PLAIN_KEY);
    assert_eq!(target_handoff.network_key, PLAIN_KEY);
    assert_eq!(init_handoff.extended_pan, completion_ext_pan());
    assert_eq!(target_handoff.extended_pan, completion_ext_pan());
    assert_eq!(init_handoff.pan_id, target_handoff.pan_id);
    assert_eq!(init_handoff.channel, target_handoff.channel);
    assert_eq!(init_handoff.key_index, KEY_INDEX_CERTIFICATION);
    assert!(init_handoff.formed_new && target_handoff.formed_new);
    assert_eq!(target_handoff.network_address, 0x0001);
    target.finish(true);
    assert_eq!(target.state(), TouchlinkTargetState::Done);
}

// 22-65816-030-121-04 / 122-03: full scan→join transcript — an
// on-network initiator adds an end-device target to its network.
#[test]
fn vector_full_join_transcript_22_65816_030_121_04() {
    let mut initiator = TouchlinkInitiator::new();
    let mut target = TouchlinkTarget::new();
    let mut air = VecTx::new();
    initiator.begin_scan(CERT_TID).unwrap();
    let scan = TouchlinkFrame::new(CERT_TID, 0x00, &[0x05, 0x83]).unwrap();
    target.on_scan_request(&scan);
    target
        .respond_full(&mut air, 15, &completion_scan_response())
        .unwrap();
    let (_, rsp_wire) = air.frames.pop().unwrap();
    let rsp_frame = TouchlinkFrame::decode(&rsp_wire).unwrap();
    initiator.note_response(rsp_frame.transaction == CERT_TID);
    initiator.proceed(false).unwrap();

    let mut req = completion_join_req();
    req.encrypted_key = encrypt_network_key(&CERT_TRANSPORT, &PLAIN_KEY);
    let mut order_air = VecTx::new();
    initiator
        .send_join(&mut order_air, 15, JoinKind::EndDevice, &req, &PLAIN_KEY)
        .unwrap();
    assert_eq!(
        initiator.state(),
        TouchlinkInitiatorState::AwaitingJoinResponse
    );
    let (_, order_wire) = order_air.frames.pop().unwrap();
    let order_frame = TouchlinkFrame::decode(&order_wire).unwrap();
    assert_eq!(order_frame.command, JoinKind::EndDevice.request_command());
    let order = NetworkJoinRequest::decode(order_frame.payload_bytes()).unwrap();
    let ctx = TargetOrderCtx {
        is_router: false,
        ..completion_target_ctx()
    };
    let reply = target
        .on_network_join(
            &order,
            order_frame.transaction,
            JoinKind::EndDevice,
            true,
            &ctx,
        )
        .unwrap();
    assert!(reply.is_success());
    initiator.on_join_response(&reply, CERT_TID).unwrap();
    assert!(initiator.tick_ms(MIN_STARTUP_DELAY_MS));
    assert_eq!(initiator.state(), TouchlinkInitiatorState::Done);
    let handoff = target.take_pending().unwrap();
    assert_eq!(handoff.network_key, PLAIN_KEY);
    assert!(!handoff.formed_new);
    assert_eq!(handoff.network_update_id, 0x03);
}

// 22-65816-030-1211-02: stale transactions never advance either
// machine.
#[test]
fn vector_stale_transactions_rejected_22_65816_030_1211_02() {
    // Initiator leg.
    let mut initiator = TouchlinkInitiator::new();
    let mut air = VecTx::new();
    initiator.begin_scan(CERT_TID).unwrap();
    initiator.note_response(true);
    initiator.proceed(true).unwrap();
    initiator
        .send_start(&mut air, 15, &completion_start_req(), &PLAIN_KEY)
        .unwrap();
    let good = NetworkStartResponse::success(completion_ext_pan(), 0, 15, 0x1a2b);
    assert_eq!(
        initiator.on_start_response(&good, 0xDEAD_BEEF).unwrap_err(),
        TouchlinkError::StaleTransaction
    );
    assert_eq!(
        initiator.state(),
        TouchlinkInitiatorState::AwaitingStartResponse
    );
    let join_rsp = NetworkJoinResponse::success();
    assert_eq!(
        initiator
            .on_join_response(&join_rsp, 0xDEAD_BEEF)
            .unwrap_err(),
        TouchlinkError::BadState
    );

    // Target leg.
    let mut target = TouchlinkTarget::new();
    let scan = TouchlinkFrame::new(CERT_TID, 0x00, &[0x05, 0x83]).unwrap();
    target.on_scan_request(&scan);
    target
        .respond_full(&mut air, 15, &completion_scan_response())
        .unwrap();
    assert_eq!(
        target
            .on_network_start(
                &completion_start_req(),
                0xDEAD_BEEF,
                &completion_target_ctx()
            )
            .unwrap_err(),
        TouchlinkError::StaleTransaction
    );
    assert_eq!(target.state(), TouchlinkTargetState::Responded);
    assert!(!target.on_reset(0xDEAD_BEEF));
    assert_eq!(
        target
            .on_identify(0xDEAD_BEEF, &IdentifyRequest { duration_s: 5 })
            .unwrap_err(),
        TouchlinkError::StaleTransaction
    );
    assert_eq!(
        target
            .on_device_info(0xDEAD_BEEF, &DeviceInfoRequest { start_index: 0 })
            .unwrap_err(),
        TouchlinkError::StaleTransaction
    );
}

// 22-65816-030-122-03: unusable key index fails cleanly — the target
// answers failure and terminates, the initiator fails the leg.
#[test]
fn vector_bad_key_index_flow_22_65816_030_122_03() {
    let mut initiator = TouchlinkInitiator::new();
    let mut air = VecTx::new();
    initiator.begin_scan(CERT_TID).unwrap();
    initiator.note_response(true);
    initiator.proceed(true).unwrap();
    initiator
        .send_start(&mut air, 15, &completion_start_req(), &PLAIN_KEY)
        .unwrap();
    // Target holds development material but the order names the
    // certification index: failure, terminated.
    let mut target = TouchlinkTarget::new();
    let scan = TouchlinkFrame::new(CERT_TID, 0x00, &[0x05, 0x83]).unwrap();
    target.on_scan_request(&scan);
    target
        .respond_full(&mut air, 15, &completion_scan_response())
        .unwrap();
    let dev_ctx = TargetOrderCtx {
        is_router: true,
        accept: true,
        key: TouchlinkKey::Development,
        supported_keys: 0x0001,
    };
    let reply = target
        .on_network_start(&completion_start_req(), CERT_TID, &dev_ctx)
        .unwrap();
    assert!(!reply.is_success());
    assert_eq!(target.state(), TouchlinkTargetState::Restarted);
    assert!(target.take_pending().is_none());
    // Initiator fails the leg on the failure status.
    initiator.on_start_response(&reply, CERT_TID).unwrap();
    assert_eq!(initiator.state(), TouchlinkInitiatorState::Failed);
    assert!(initiator.take_handoff().is_none());
}

// 22-65816-030-121-04 / 122-03: receive-window, startup-delay, and
// transaction-lifetime rules on the injected clock.
#[test]
fn vector_timeout_and_abandon_rules() {
    // Silent target: the order leg fails when the receive window lapses.
    let mut initiator = TouchlinkInitiator::new();
    let mut air = VecTx::new();
    initiator.begin_scan(CERT_TID).unwrap();
    initiator.note_response(true);
    initiator.proceed(false).unwrap();
    initiator
        .send_join(
            &mut air,
            15,
            JoinKind::Router,
            &completion_join_req(),
            &PLAIN_KEY,
        )
        .unwrap();
    assert!(!initiator.tick_ms(RX_WINDOW_MS - 1));
    assert!(initiator.tick_ms(1));
    assert_eq!(initiator.state(), TouchlinkInitiatorState::Failed);

    // Silent exchange: the whole procedure abandons at the lifetime.
    let mut slow = TouchlinkInitiator::new();
    slow.begin_scan(CERT_TID).unwrap();
    assert!(!slow.tick_ms(TRANSACTION_LIFETIME_MS - 1));
    assert!(slow.tick_ms(1));
    assert_eq!(slow.state(), TouchlinkInitiatorState::Failed);

    // Target with no orders: abandoned at the lifetime.
    let mut target = TouchlinkTarget::new();
    let scan = TouchlinkFrame::new(CERT_TID, 0x00, &[0x05, 0x83]).unwrap();
    target.on_scan_request(&scan);
    target
        .respond_full(&mut air, 15, &completion_scan_response())
        .unwrap();
    assert!(!target.tick_ms(TRANSACTION_LIFETIME_MS - 1));
    assert_eq!(target.state(), TouchlinkTargetState::Responded);
    assert!(target.tick_ms(1));
    assert_eq!(target.state(), TouchlinkTargetState::Expired);
    // Expired exchanges take no orders.
    assert_eq!(
        target
            .on_network_start(&completion_start_req(), CERT_TID, &completion_target_ctx())
            .unwrap_err(),
        TouchlinkError::BadState
    );
}

// 22-65816-030-122-04: network update adoption and discard rules.
#[test]
fn vector_network_update_flow_22_65816_030_122_04() {
    let mut target = TouchlinkTarget::new();
    let mut air = VecTx::new();
    let scan = TouchlinkFrame::new(CERT_TID, 0x00, &[0x05, 0x83]).unwrap();
    target.on_scan_request(&scan);
    target
        .respond_full(&mut air, 15, &completion_scan_response())
        .unwrap();
    let stored = completion_ext_pan();
    let mk = |update, channel, pan| NetworkUpdateRequest {
        extended_pan: completion_ext_pan(),
        network_update_id: update,
        channel,
        pan_id: pan,
        network_address: 0x0002,
    };
    // Stale transaction, foreign network, and non-newer identifiers
    // are all ignored without state change.
    assert_eq!(
        target.on_network_update(&mk(0x04, 20, 0x1a2b), 0xDEAD_BEEF, &stored, 0x1a2b, 0x03),
        UpdateDisposition::Ignored
    );
    let mut foreign = mk(0x04, 20, 0x1a2b);
    foreign.extended_pan = [0x09; 8];
    assert_eq!(
        target.on_network_update(&foreign, CERT_TID, &stored, 0x1a2b, 0x03),
        UpdateDisposition::Ignored
    );
    assert_eq!(
        target.on_network_update(&mk(0x03, 20, 0x1a2b), CERT_TID, &stored, 0x1a2b, 0x03),
        UpdateDisposition::Ignored
    );
    assert_eq!(target.state(), TouchlinkTargetState::Responded);
    // A newer identifier on the same network adopts channel + id.
    assert_eq!(
        target.on_network_update(&mk(0x04, 20, 0x1a2b), CERT_TID, &stored, 0x1a2b, 0x03),
        UpdateDisposition::Applied(PendingUpdate {
            network_update_id: 0x04,
            channel: 20,
        })
    );
    assert_eq!(
        target.take_update(),
        Some(PendingUpdate {
            network_update_id: 0x04,
            channel: 20,
        })
    );
    // Initiator side sends the update while selecting.
    let mut initiator = TouchlinkInitiator::new();
    initiator.begin_scan(CERT_TID).unwrap();
    initiator.note_response(true);
    initiator
        .send_update(&mut air, 15, &mk(0x04, 20, 0x1a2b))
        .unwrap();
    let (_, wire) = air.frames.pop().unwrap();
    let frame = TouchlinkFrame::decode(&wire).unwrap();
    assert_eq!(frame.command, 0x16);
    assert_eq!(
        NetworkUpdateRequest::decode(frame.payload_bytes()).unwrap(),
        mk(0x04, 20, 0x1a2b)
    );
}

// 22-65816-030-122-03: refused steal fails the exchange; start needs
// a router and join kinds must match the logical type.
#[test]
fn vector_refuse_steal_and_role_gates_22_65816_030_122_03() {
    let mut air = VecTx::new();
    let mut latch = |target: &mut TouchlinkTarget| {
        let scan = TouchlinkFrame::new(CERT_TID, 0x00, &[0x05, 0x83]).unwrap();
        target.on_scan_request(&scan);
        target
            .respond_full(&mut air, 15, &completion_scan_response())
            .unwrap();
    };
    // Refused steal: failure answer, exchange terminated.
    let mut stolen = TouchlinkTarget::new();
    latch(&mut stolen);
    let mut refuse = completion_target_ctx();
    refuse.accept = false;
    let reply = stolen
        .on_network_join(
            &completion_join_req(),
            CERT_TID,
            JoinKind::Router,
            true,
            &refuse,
        )
        .unwrap();
    assert!(!reply.is_success());
    assert_eq!(stolen.state(), TouchlinkTargetState::Restarted);

    // Only routers start new networks.
    let mut end_device = TouchlinkTarget::new();
    latch(&mut end_device);
    let mut ed_ctx = completion_target_ctx();
    ed_ctx.is_router = false;
    assert_eq!(
        end_device
            .on_network_start(&completion_start_req(), CERT_TID, &ed_ctx)
            .unwrap_err(),
        TouchlinkError::WrongRole
    );
    assert_eq!(end_device.state(), TouchlinkTargetState::Responded);

    // Join kind must match the target logical type.
    let mut mismatch = TouchlinkTarget::new();
    latch(&mut mismatch);
    assert_eq!(
        mismatch
            .on_network_join(
                &completion_join_req(),
                CERT_TID,
                JoinKind::Router,
                false,
                &completion_target_ctx(),
            )
            .unwrap_err(),
        TouchlinkError::WrongRole
    );
    assert_eq!(mismatch.state(), TouchlinkTargetState::Responded);
}

// 22-65816-030-122-03: transaction discipline for the auxiliary
// orders — identify and device-info accept the latched transaction
// with no state change; reset terminates on a match.
#[test]
fn vector_auxiliary_order_discipline_22_65816_030_122_03() {
    let mut target = TouchlinkTarget::new();
    let mut air = VecTx::new();
    let scan = TouchlinkFrame::new(CERT_TID, 0x00, &[0x05, 0x83]).unwrap();
    target.on_scan_request(&scan);
    target
        .respond_full(&mut air, 15, &completion_scan_response())
        .unwrap();
    assert_eq!(
        target
            .on_identify(CERT_TID, &IdentifyRequest { duration_s: 30 })
            .unwrap(),
        30
    );
    assert_eq!(
        target
            .on_device_info(CERT_TID, &DeviceInfoRequest { start_index: 1 })
            .unwrap(),
        1
    );
    assert_eq!(target.state(), TouchlinkTargetState::Responded);
    assert!(target.on_reset(CERT_TID));
    assert_eq!(target.state(), TouchlinkTargetState::Restarted);
}

// 22-65816-030-91-02 + 22-65816-030-56-04: post-association wait with
// only unsecured vendor traffic. The joiner tolerates the observed
// vendor command id (counted and classified, no transition, no key
// latch) and the transport-missing timeout reports `NoTransport` —
// distinct from whole-window `JoinTimeout`.
#[test]
fn vector_join_tolerates_unsecured_then_no_transport() {
    let policy = JoinPolicy {
        cbke_supported: false,
        cbke_required: false,
        interview_tc: false,
        parent_is_r20_earlier: false,
    };
    let mut j = JoinerMachine::new(JoinMethod::PreconfiguredKey, policy);
    j.on_candidate();
    j.on_assoc_confirm(true);
    assert_eq!(j.state(), JoinerState::Authenticating);
    // Two post-association vendor frames, as captured on air: the
    // state never moves and nothing is latched.
    j.note_unsecured(UNSECURED_VENDOR_CMD);
    j.note_unsecured(UNSECURED_VENDOR_CMD);
    assert_eq!(j.state(), JoinerState::Authenticating);
    assert_eq!(j.error(), None);
    assert_eq!(j.unsecured_count(), 2);
    assert_eq!(j.last_unsecured_cmd(), Some(UNSECURED_VENDOR_CMD));
    // No transport-key frame ever arrives: the wait ends with
    // `NoTransport`, not a generic timeout.
    j.on_transport_timeout();
    assert_eq!(j.state(), JoinerState::Failed);
    assert_eq!(j.error(), Some(JoinError::NoTransport));
}

// 22-65816-030-91-02: same tolerance on the KeyWait leg, plus the
// edges — pre-association notes are ignored (no count, no fail) and
// a transport timeout outside the post-association states is
// `BadState`. Timeouts/retries elsewhere are unchanged.
#[test]
fn vector_join_unsecured_keywait_leg_and_edges() {
    let policy = JoinPolicy {
        cbke_supported: false,
        cbke_required: false,
        interview_tc: false,
        parent_is_r20_earlier: false,
    };
    // Pre-association chatter is ignored, never counted, never fatal.
    let mut early = JoinerMachine::new(JoinMethod::PreconfiguredKey, policy);
    early.note_unsecured(UNSECURED_VENDOR_CMD);
    assert_eq!(early.state(), JoinerState::Unjoined);
    assert_eq!(early.unsecured_count(), 0);
    assert_eq!(early.last_unsecured_cmd(), None);
    // A transport timeout with nothing pending is a caller bug.
    early.on_transport_timeout();
    assert_eq!(early.error(), Some(JoinError::BadState));

    // KeyWait leg: unsecured traffic is tolerated mid-wait, then the
    // missing transport is named.
    let mut j = JoinerMachine::new(JoinMethod::PreconfiguredKey, policy);
    j.on_candidate();
    j.on_assoc_confirm(true);
    j.on_key_transport(true);
    assert_eq!(j.state(), JoinerState::KeyWait);
    j.note_unsecured(UNSECURED_VENDOR_CMD);
    assert_eq!(j.state(), JoinerState::KeyWait);
    assert_eq!(j.unsecured_count(), 1);
    j.on_transport_timeout();
    assert_eq!(j.state(), JoinerState::Failed);
    assert_eq!(j.error(), Some(JoinError::NoTransport));
}

// 22-65816-030-56-04 (extended: joiner side of the time-box
// eviction): an incoming NWK leave mid-join ends the attempt with
// `JoinTimeout` — the "asked to leave" outcome — instead of polling
// until the transport timeout. Observed on air as the coordinator's
// per-poll eject unicast after the ~10 s grace
// (`~/hwscratch/w39/sniff_b1.txt`, decoded by
// `rounddance-nwk::decode_leave` as request-form).
#[test]
fn vector_join_leave_evicts_mid_join() {
    let policy = JoinPolicy {
        cbke_supported: false,
        cbke_required: false,
        interview_tc: false,
        parent_is_r20_earlier: false,
    };
    // Authenticating leg: the eject ends the attempt at once.
    let mut j = JoinerMachine::new(JoinMethod::PreconfiguredKey, policy);
    j.on_candidate();
    j.on_assoc_confirm(true);
    assert_eq!(j.state(), JoinerState::Authenticating);
    j.on_leave();
    assert_eq!(j.state(), JoinerState::Failed);
    assert_eq!(j.error(), Some(JoinError::JoinTimeout));
    // KeyWait leg: same outcome after the exchange started.
    let mut k = JoinerMachine::new(JoinMethod::PreconfiguredKey, policy);
    k.on_candidate();
    k.on_assoc_confirm(true);
    k.on_key_transport(true);
    assert_eq!(k.state(), JoinerState::KeyWait);
    k.on_leave();
    assert_eq!(k.state(), JoinerState::Failed);
    assert_eq!(k.error(), Some(JoinError::JoinTimeout));
    // A leave with nothing pending is a caller bug.
    let mut early = JoinerMachine::new(JoinMethod::PreconfiguredKey, policy);
    early.on_leave();
    assert_eq!(early.error(), Some(JoinError::BadState));
}

// 05-3474-23-4434-01: TC-first transport open. After the exact-pair
// classification promotes the joiner to the key wait, the auxiliary
// open outcome decides: a MIC-checked frame with a fresh counter
// latches the network-key adoption and the join rides to Joined; a
// MIC failure, a replayed or duplicate counter, or an open outside
// the key wait ends the attempt and never promotes.
#[test]
fn vector_tc_first_transport_open_05_3474_23_4434_01() {
    let policy = JoinPolicy {
        cbke_supported: false,
        cbke_required: false,
        interview_tc: false,
        parent_is_r20_earlier: false,
    };
    // Open outside the key wait is a caller bug.
    let mut early = JoinerMachine::new(JoinMethod::InstallCode, policy);
    early.on_candidate();
    early.on_assoc_confirm(true);
    early.on_transport_open(true, 0x0001_d000);
    assert_eq!(early.state(), JoinerState::Failed);
    assert_eq!(early.error(), Some(JoinError::BadState));
    assert!(!early.netkey_adopted());

    // MIC failure: tampered or forged transport never promotes and
    // never latches an adoption.
    let mut mic = JoinerMachine::new(JoinMethod::InstallCode, policy);
    mic.on_candidate();
    mic.on_assoc_confirm(true);
    mic.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_NETWORK);
    assert_eq!(mic.state(), JoinerState::KeyWait);
    mic.on_transport_open(false, 0x0001_d000);
    assert_eq!(mic.state(), JoinerState::Failed);
    assert_eq!(mic.error(), Some(JoinError::ConfirmMismatch));
    assert!(!mic.netkey_adopted());
    assert_eq!(mic.last_aux_counter(), None);

    // Counter replay: the same auxiliary counter opened twice, or a
    // lower one, is a replay — the attempt ends, nothing promotes.
    let mut replay = JoinerMachine::new(JoinMethod::InstallCode, policy);
    replay.on_candidate();
    replay.on_assoc_confirm(true);
    replay.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_NETWORK);
    replay.on_transport_open(true, 0x0001_d000);
    assert!(replay.netkey_adopted());
    assert_eq!(replay.last_aux_counter(), Some(0x0001_d000));
    replay.on_transport_open(true, 0x0001_d000);
    assert_eq!(replay.state(), JoinerState::Failed);
    assert_eq!(replay.error(), Some(JoinError::ConfirmMismatch));

    let mut lower = JoinerMachine::new(JoinMethod::InstallCode, policy);
    lower.on_candidate();
    lower.on_assoc_confirm(true);
    lower.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_NETWORK);
    lower.on_transport_open(true, 0x0001_d000);
    lower.on_transport_open(true, 0x0001_3000);
    assert_eq!(lower.state(), JoinerState::Failed);
    assert_eq!(lower.error(), Some(JoinError::ConfirmMismatch));

    // Fresh counters strictly advance; the full path rides the
    // adoption through verify, announce, and close-out to Joined.
    let mut j = JoinerMachine::new(JoinMethod::InstallCode, policy);
    assert!(!j.netkey_adopted());
    assert_eq!(j.last_aux_counter(), None);
    j.on_candidate();
    j.on_assoc_confirm(true);
    j.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_NETWORK);
    assert_eq!(j.state(), JoinerState::KeyWait);
    j.on_transport_open(true, 0x0001_d000);
    assert!(j.netkey_adopted());
    assert_eq!(j.last_aux_counter(), Some(0x0001_d000));
    assert_eq!(j.state(), JoinerState::KeyWait);
    j.on_verify_confirm(true, KeyAttributes::SYMMETRIC);
    assert_eq!(j.state(), JoinerState::Announced);
    let annce = j.device_annce(0x33, 0x5160, 0x6d49_11fe_ff13_8d34);
    assert_eq!(
        (annce.nwk_addr, annce.ieee),
        (0x5160, 0x6d49_11fe_ff13_8d34)
    );
    j.close_out(false);
    assert_eq!(j.state(), JoinerState::Joined);
}

// 22-65816-030-91-01: the field policy admits a strong link the old
// absolute gate refused. Transcript replayed from the wave-27 bench
// logs (`join_run5/6.log`): tail-LQI 10–11 with tail-RSSI −28 dBm on a
// permit-open beacon — one FCS-passing decode the C6 HAL attributed
// per-frame. `LinkEvidencePolicy::default()` selects it;
// `BaselineSteeringPolicy { min_lqi: 100, .. }` parks in
// `NoSuitableNetwork` on the identical row.
#[test]
fn vector_field_policy_admits_flat_lqi_strong_link() {
    let entry = BeaconSurveyEntry {
        pan_id: 0x1A2B,
        channel: 15,
        lqi: 10,
        rssi: -28,
        permit_joining: true,
        router_capacity: true,
        end_device_capacity: true,
        protocol_version: 2,
    };
    assert!(LinkEvidencePolicy::default().acceptable(&entry));
    let mut m = SteeringMachine::new();
    m.begin_scan(ChannelMask::from_list(&[15]).unwrap(), 3)
        .unwrap();
    m.ingest(entry).unwrap();
    m.finish_scan(&LinkEvidencePolicy::default());
    assert_eq!(m.state(), SteeringState::CandidateSelected);
    assert_eq!(m.candidate().unwrap().pan_id, 0x1A2B);

    // The old absolute gate on the same row: unpassable on this
    // hardware, by construction (pins the wave-26 survey outcome).
    let mut old = SteeringMachine::new();
    old.begin_scan(ChannelMask::from_list(&[15]).unwrap(), 3)
        .unwrap();
    old.ingest(entry).unwrap();
    old.finish_scan(&BaselineSteeringPolicy {
        min_lqi: 100,
        min_version: 2,
    });
    assert_eq!(old.state(), SteeringState::NoSuitableNetwork);
}

// 22-65816-030-91-01: the field policy still rejects every
// non-evidence leg — closed permit, no end-device room, old version,
// and pathologically weak RSSI each park the machine.
#[test]
fn vector_field_policy_reject_legs() {
    let good = BeaconSurveyEntry {
        pan_id: 0x1A2B,
        channel: 15,
        lqi: 11,
        rssi: -28,
        permit_joining: true,
        router_capacity: true,
        end_device_capacity: true,
        protocol_version: 2,
    };
    let legs = [
        (
            "closed permit",
            BeaconSurveyEntry {
                permit_joining: false,
                ..good
            },
        ),
        (
            "no room",
            BeaconSurveyEntry {
                end_device_capacity: false,
                ..good
            },
        ),
        (
            "old version",
            BeaconSurveyEntry {
                protocol_version: 1,
                ..good
            },
        ),
        ("weak rssi", BeaconSurveyEntry { rssi: -95, ..good }),
        ("floor rssi", BeaconSurveyEntry { rssi: -101, ..good }),
    ];
    for (name, entry) in legs {
        assert!(!LinkEvidencePolicy::default().acceptable(&entry), "{name}");
        let mut m = SteeringMachine::new();
        m.begin_scan(ChannelMask::from_list(&[15]).unwrap(), 3)
            .unwrap();
        m.ingest(entry).unwrap();
        m.finish_scan(&LinkEvidencePolicy::default());
        assert_eq!(m.state(), SteeringState::NoSuitableNetwork, "{name}");
    }
    // Sanity: the unmodified row still admits.
    assert!(LinkEvidencePolicy::default().acceptable(&good));
}

// 22-65816-030-91-01: ranking stays relative under the field policy —
// highest LQI wins, ties break to the lower PAN — and the opt-in LQI
// floor only bites when a calibrated radio asks for it.
#[test]
fn vector_field_policy_ranking_and_opt_in_floor() {
    let row = |pan, lqi| BeaconSurveyEntry {
        pan_id: pan,
        channel: 15,
        lqi,
        rssi: -28,
        permit_joining: true,
        router_capacity: true,
        end_device_capacity: true,
        protocol_version: 2,
    };
    let mut m = SteeringMachine::new();
    m.begin_scan(ChannelMask::all_24g(), 3).unwrap();
    m.ingest(row(0x2222, 11)).unwrap();
    m.ingest(row(0x1111, 11)).unwrap();
    m.ingest(row(0x3333, 10)).unwrap();
    m.finish_scan(&LinkEvidencePolicy::default());
    assert_eq!(m.state(), SteeringState::CandidateSelected);
    // Flat-meter tie (11 == 11) breaks to the lower PAN; the 10 loses
    // relatively without any absolute gate firing.
    assert_eq!(m.candidate().unwrap().pan_id, 0x1111);

    // Opt-in floor: a calibrated radio may demand LQI ≥ 200 — the flat
    // bench link then refuses (documented opt-in, never the default).
    let strict = LinkEvidencePolicy {
        lqi_floor: Some(200),
        ..LinkEvidencePolicy::default()
    };
    assert!(!strict.acceptable(&row(0x1A2B, 11)));
    assert!(strict.acceptable(&row(0x1A2B, 220)));
}

// RD-SIM-01: joiner-initiated TCLK update transcript — request,
// TCLK-typed transport classify, checked open latch, verify sent,
// success confirm authorizes; the device stays joined throughout.
#[test]
fn vector_tclk_update_transcript_rd_sim_01() {
    let mut u = TclkUpdate::new();
    assert_eq!(u.state(), TclkState::Idle);
    assert!(!u.tclk_latched());
    assert_eq!(u.error(), None);
    u.begin();
    assert_eq!(u.state(), TclkState::RequestSent);
    // Foreign first frames never promote: network-key-typed and
    // vendor-shaped commands leave the wait unchanged.
    u.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_NETWORK);
    u.note_transport_frame(UNSECURED_VENDOR_CMD, 0x00);
    assert_eq!(u.state(), TclkState::RequestSent);
    assert!(!u.tclk_latched());
    // The genuine TCLK transport classifies; the checked open latches.
    u.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_TCLK);
    assert_eq!(u.state(), TclkState::KeyWait);
    u.on_transport_open(true);
    assert!(u.tclk_latched());
    assert_eq!(u.state(), TclkState::KeyWait);
    u.note_verify_sent();
    assert_eq!(u.state(), TclkState::VerifySent);
    u.on_confirm(CONFIRM_KEY_STATUS_SUCCESS);
    assert_eq!(u.state(), TclkState::Authorized);
    assert_eq!(u.error(), None);
    assert!(u.tclk_latched());
}

// RD-SIM-01: the confirm status decides — anything but success fails
// the attempt with ConfirmMismatch and never authorizes.
#[test]
fn vector_tclk_bad_confirm_never_authorizes_rd_sim_01() {
    let mut u = TclkUpdate::new();
    u.begin();
    u.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_TCLK);
    u.on_transport_open(true);
    u.note_verify_sent();
    u.on_confirm(0x01);
    assert_eq!(u.state(), TclkState::Failed);
    assert_eq!(u.error(), Some(JoinError::ConfirmMismatch));
    // The latch stands (the key arrived intact) but the update is
    // dead: no authorize, no retry from Failed.
    assert!(u.tclk_latched());
}

// RD-SIM-01: a tampered transport open never latches and never
// promotes, even though the classification pair was genuine.
#[test]
fn vector_tclk_mic_fail_never_latches_rd_sim_01() {
    let mut u = TclkUpdate::new();
    u.begin();
    u.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_TCLK);
    assert_eq!(u.state(), TclkState::KeyWait);
    u.on_transport_open(false);
    assert_eq!(u.state(), TclkState::Failed);
    assert_eq!(u.error(), Some(JoinError::ConfirmMismatch));
    assert!(!u.tclk_latched());
}

// RD-SIM-01: sequencing order is load-bearing — verify before latch,
// confirm before verify, and double-begin are all caller bugs.
#[test]
fn vector_tclk_out_of_order_is_bad_state_rd_sim_01() {
    // Verify sent with nothing latched.
    let mut early = TclkUpdate::new();
    early.begin();
    early.note_verify_sent();
    assert_eq!(early.state(), TclkState::Failed);
    assert_eq!(early.error(), Some(JoinError::BadState));

    // Confirm heard with no verify outstanding.
    let mut unasked = TclkUpdate::new();
    unasked.begin();
    unasked.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_TCLK);
    unasked.on_transport_open(true);
    unasked.on_confirm(CONFIRM_KEY_STATUS_SUCCESS);
    assert_eq!(unasked.state(), TclkState::Failed);
    assert_eq!(unasked.error(), Some(JoinError::BadState));

    // The request goes out once.
    let mut twice = TclkUpdate::new();
    twice.begin();
    twice.begin();
    assert_eq!(twice.state(), TclkState::Failed);
    assert_eq!(twice.error(), Some(JoinError::BadState));
}

// RD-SIM-01: the wait still ends on time — silence names NoTransport
// from any waiting state, and a parent eject names JoinTimeout at
// once instead of polling to the bound.
#[test]
fn vector_tclk_wait_timeouts_and_eject_rd_sim_01() {
    // Silent peer at each waiting leg.
    for drive in [
        (|u: &mut TclkUpdate| u.begin()) as fn(&mut TclkUpdate),
        |u| {
            u.begin();
            u.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_TCLK);
        },
        |u| {
            u.begin();
            u.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_TCLK);
            u.on_transport_open(true);
            u.note_verify_sent();
        },
    ] {
        let mut u = TclkUpdate::new();
        drive(&mut u);
        u.on_transport_timeout();
        assert_eq!(u.state(), TclkState::Failed);
        assert_eq!(u.error(), Some(JoinError::NoTransport));
    }
    // Parent eject at each waiting leg.
    for drive in [
        (|u: &mut TclkUpdate| u.begin()) as fn(&mut TclkUpdate),
        |u| {
            u.begin();
            u.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_TCLK);
            u.on_transport_open(true);
        },
    ] {
        let mut u = TclkUpdate::new();
        drive(&mut u);
        u.on_leave();
        assert_eq!(u.state(), TclkState::Failed);
        assert_eq!(u.error(), Some(JoinError::JoinTimeout));
    }
    // After authorization there is nothing to time out or eject from.
    let mut done = TclkUpdate::new();
    done.begin();
    done.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_TCLK);
    done.on_transport_open(true);
    done.note_verify_sent();
    done.on_confirm(CONFIRM_KEY_STATUS_SUCCESS);
    done.on_transport_timeout();
    assert_eq!(done.state(), TclkState::Failed);
    assert_eq!(done.error(), Some(JoinError::BadState));
}
