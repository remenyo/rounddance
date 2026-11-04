//! Line-by-line coverage closure for BDB `22-65816-030` v3.1
//! (formation, steering, rejoin/leave, TCLK, touchlink completion,
//! secured/transport/keyprov helpers) plus commissioning-adjacent
//! core clauses.
//!
//! Paraphrase only (D1): every test cites document, revision, and
//! clause/line anchors. Complements (never duplicates)
//! `tests/vectors.rs` and `tests/via_builders.rs`.

use rounddance_commission::{
    BaselineSteeringPolicy, BeaconSurveyEntry, ChannelMask, DiscoveryScan, EndpointInformation,
    FirstFreePan, FormationConfig, FormationError, FormationMachine, FormationPolicy,
    FormationRequest, FormationState, GetEndpointListRequest, GetGroupIdentifiersRequest,
    IdentifyRequest, JoinError, JoinMethod, JoinPolicy, JoinedDevice, JoinerMachine, JoinerState,
    KeyAttributes, LeaveMachine, LogicalType, PanChoice, RejoinMachine, RejoinState,
    SteeringMachine, SteeringState, SurveyError, SurveyTable, TclkState, TclkUpdate,
    TouchlinkError, TrustCenter, CHANNEL_MAX, CHANNEL_MIN, MAX_SURVEY_ENTRIES,
    MIN_ELECTION_SIGHTINGS,
};

// ---------------------------------------------------------------------------
// §8 network formation (anchors p0055-L1204-L1212, p0057-L1217-L1256)
// ---------------------------------------------------------------------------

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

// 22-65816-030-81-01: only coordinator/router roles may form.
#[test]
fn bdb_formation_role_gate() {
    for role in [LogicalType::Coordinator, LogicalType::Router] {
        let mut cfg = coord_config();
        cfg.role = role;
        assert!(FormationMachine::new(cfg).is_ok());
    }
    let mut cfg = coord_config();
    cfg.role = LogicalType::EndDevice;
    assert_eq!(
        FormationMachine::new(cfg).unwrap_err(),
        FormationError::BadRole
    );
}

// 22-65816-030-81-01: already on a network without a factory reset fails.
#[test]
fn bdb_formation_factory_reset_first() {
    let mut m = FormationMachine::new(coord_config()).unwrap();
    m.begin(false, true);
    assert_eq!(m.state(), FormationState::Failed);
    assert_eq!(m.error(), Some(FormationError::AlreadyOnNetwork));
    // A factory reset lets the same node proceed to the primary scan.
    let mut m = FormationMachine::new(coord_config()).unwrap();
    m.begin(true, true);
    assert_eq!(m.state(), FormationState::ScanningPrimary);
}

// 22-65816-030-81-01: primary list first, then secondary, then exhausted.
#[test]
fn bdb_formation_scan_phase_order() {
    let mut m = FormationMachine::new(coord_config()).unwrap();
    m.begin(true, false);
    assert_eq!(
        m.scan_phase_channels(),
        Some(ChannelMask::from_list(&[15, 20]).unwrap())
    );
    struct NeverFree;
    impl FormationPolicy for NeverFree {
        fn pick_pan(&self, _in_use: &[u16]) -> Option<u16> {
            None
        }
        fn scan_usable(&self, _channels: ChannelMask) -> bool {
            true
        }
    }
    m.on_scan_complete(&NeverFree, false, &[]);
    assert_eq!(m.state(), FormationState::ScanningSecondary);
    assert_eq!(
        m.scan_phase_channels(),
        Some(ChannelMask::from_list(&[26]).unwrap())
    );
    m.on_scan_complete(&NeverFree, false, &[]);
    assert_eq!(m.state(), FormationState::Failed);
    assert_eq!(m.error(), Some(FormationError::ScanExhausted));
}

// 22-65816-030-81-02: the formation primitive carries beacon 0x0f,
// superframe 0x00, no battery-life extension; routers form distributed
// with their short address attached.
#[test]
fn bdb_formation_primitive_shape() {
    let mut m = FormationMachine::new(coord_config()).unwrap();
    m.begin(true, false);
    m.on_scan_complete(&FirstFreePan, true, &[]);
    let req: FormationRequest = m.primitive_params().unwrap();
    assert_eq!(req.beacon_order, 0x0f);
    assert_eq!(req.superframe_order, 0x00);
    assert!(!req.battery_life_extension);
    assert!(!req.distributed);

    let mut cfg = coord_config();
    cfg.role = LogicalType::Router;
    cfg.router_short_addr = 0x1111;
    let mut r = FormationMachine::new(cfg).unwrap();
    r.begin(true, false);
    r.on_scan_complete(&FirstFreePan, true, &[]);
    let rreq = r.primitive_params().unwrap();
    assert!(rreq.distributed);
    assert_eq!(rreq.short_addr, 0x1111);
}

// 22-65816-030-81-02/03: PAN conflict is avoided; success raises the
// on-network flag and the coordinator owes the Trust Center startup.
#[test]
fn bdb_formation_pan_conflict_and_confirm() {
    let mut m = FormationMachine::new(coord_config()).unwrap();
    m.begin(true, false);
    m.on_scan_complete(&FirstFreePan, true, &[0x1234]);
    assert_eq!(m.state(), FormationState::ResolvingPan);
    assert_ne!(m.pan_id().unwrap(), 0x1234);
    m.on_invoked();
    m.on_confirm(true);
    assert_eq!(m.state(), FormationState::OnNetwork);
    assert!(m.trust_center_startup_due());
}

// Channel admission only spans the 2.4 GHz band (11–26).
#[test]
fn bdb_channel_mask_band_edges() {
    assert_eq!(CHANNEL_MIN, 11);
    assert_eq!(CHANNEL_MAX, 26);
    assert!(ChannelMask::from_list(&[11, 26]).is_ok());
    assert_eq!(
        ChannelMask::from_list(&[10]).unwrap_err(),
        FormationError::BadChannel
    );
    assert_eq!(
        ChannelMask::from_list(&[27]).unwrap_err(),
        FormationError::BadChannel
    );
    assert!(ChannelMask::all_24g().count() == 16);
}

// ---------------------------------------------------------------------------
// §9.1 network discovery (anchors p0060-L1281-L1297)
// ---------------------------------------------------------------------------

// 22-65816-030-91-01: the discovery scan asks for join-permitted
// networks with end-device capacity only.
#[test]
fn bdb_discovery_scan_shape() {
    let scan = DiscoveryScan::new(ChannelMask::from_list(&[15]).unwrap(), 3);
    assert!(scan.join_permitted_only);
    assert!(scan.require_end_device_capacity);
}

// 22-65816-030-91-01: a failed scan ends the procedure; an empty
// survey ends it with no suitable network.
#[test]
fn bdb_discovery_scan_failure_ends() {
    let mut m = SteeringMachine::new();
    m.begin_scan(ChannelMask::from_list(&[15]).unwrap(), 3)
        .unwrap();
    m.on_scan_failed();
    assert_eq!(m.state(), SteeringState::Failed);
    assert!(m.scan_failed());
}

// 22-65816-030-91-01: ranking prefers the strongest acceptable row and
// breaks ties toward the lower PAN.
#[test]
fn bdb_discovery_ranking_prefers_strongest() {
    let mut m = SteeringMachine::new();
    m.begin_scan(ChannelMask::all_24g(), 3).unwrap();
    let row = |pan, lqi| BeaconSurveyEntry {
        pan_id: pan,
        channel: 15,
        lqi,
        rssi: -40,
        permit_joining: true,
        router_capacity: true,
        end_device_capacity: true,
        protocol_version: 2,
    };
    for pan in [0x2222u16, 0x1111] {
        m.ingest(row(pan, 200)).unwrap();
        m.ingest(row(pan, 200)).unwrap();
    }
    m.finish_scan(&BaselineSteeringPolicy {
        min_lqi: 100,
        min_version: 2,
    });
    assert_eq!(m.state(), SteeringState::CandidateSelected);
    assert_eq!(m.candidate().unwrap().pan_id, 0x1111);
}

// 22-65816-030-91-01: unacceptable rows never win.
#[test]
fn bdb_discovery_no_suitable_network() {
    let mut m = SteeringMachine::new();
    m.begin_scan(ChannelMask::from_list(&[15]).unwrap(), 3)
        .unwrap();
    m.ingest(BeaconSurveyEntry {
        pan_id: 0x1234,
        channel: 15,
        lqi: 10,
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

// Survey storage is bounded: the table refuses a 17th sighting.
#[test]
fn bdb_survey_table_bounded() {
    assert_eq!(MAX_SURVEY_ENTRIES, 16);
    assert_eq!(MIN_ELECTION_SIGHTINGS, 2);
    let mut t = SurveyTable::new();
    let row = BeaconSurveyEntry {
        pan_id: 0x0001,
        channel: 15,
        lqi: 200,
        rssi: -40,
        permit_joining: true,
        router_capacity: true,
        end_device_capacity: true,
        protocol_version: 2,
    };
    for _ in 0..MAX_SURVEY_ENTRIES {
        t.add(row).unwrap();
    }
    assert_eq!(t.len(), MAX_SURVEY_ENTRIES);
    assert_eq!(t.add(row).unwrap_err(), SurveyError::TableFull);
}

// ---------------------------------------------------------------------------
// §10 rejoin + leave forms (anchors p0075-L1614-L1649)
// ---------------------------------------------------------------------------

// 22-65816-030-10-01: secured vs TC rejoin selection is explicit; the
// orphan scan gates the request.
#[test]
fn bdb_rejoin_secured_flag_and_orphan_gate() {
    let mut secured = RejoinMachine::new(true);
    assert!(secured.secured());
    assert_eq!(secured.state(), RejoinState::Idle);
    secured.begin();
    assert_eq!(secured.state(), RejoinState::OrphanScanning);
    // A repeated begin never rewinds the machine.
    secured.begin();
    assert_eq!(secured.state(), RejoinState::OrphanScanning);
    secured.on_orphan_scan(true);
    assert_eq!(secured.state(), RejoinState::Rejoining);

    let plain = RejoinMachine::new(false);
    assert!(!plain.secured());
}

// 22-65816-030-10-01: orphan miss fails; confirm decides the outcome.
#[test]
fn bdb_rejoin_confirm_decides() {
    let mut m = RejoinMachine::new(false);
    m.begin();
    m.on_orphan_scan(false);
    assert_eq!(m.state(), RejoinState::Failed);

    let mut m = RejoinMachine::new(false);
    m.begin();
    m.on_orphan_scan(true);
    m.on_confirm(false);
    assert_eq!(m.state(), RejoinState::Failed);

    let mut m = RejoinMachine::new(false);
    m.begin();
    m.on_orphan_scan(true);
    m.on_confirm(true);
    assert_eq!(m.state(), RejoinState::Joined);
}

// Leave forms name the device and both flags (parent evict vs
// self-remove stay distinct at the type level).
#[test]
fn bdb_leave_forms_name_device_and_flags() {
    let evict = LeaveMachine::mgmt_leave_for(0x07, 0xDEAD_BEEF_CAFE_1234, false, true);
    assert_eq!(evict.tsn, 0x07);
    assert_eq!(evict.device_ieee, 0xDEAD_BEEF_CAFE_1234);
    assert!(!evict.rejoin);
    assert!(evict.remove_children);
    let self_leave = LeaveMachine::mgmt_leave_for(0x08, 0xDEAD_BEEF_CAFE_1234, true, false);
    assert!(self_leave.rejoin);
    assert!(!self_leave.remove_children);
}

// ---------------------------------------------------------------------------
// §7.2 on-network TCLK update (anchors p0011-L107-L108)
// ---------------------------------------------------------------------------

// Full TCLK transcript: request → TCLK-typed transport → verified
// open → verify sent → confirm success authorizes, still joined.
#[test]
fn bdb_tclk_full_transcript_authorizes() {
    use rounddance_commission::{
        CONFIRM_KEY_STATUS_SUCCESS, TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_TCLK,
    };
    let mut u = TclkUpdate::new();
    assert_eq!(u.state(), TclkState::Idle);
    u.begin();
    assert_eq!(u.state(), TclkState::RequestSent);
    // Foreign pairs (network key type, vendor chatter) never promote.
    u.note_transport_frame(TRANSPORT_KEY_CMD, 0x01);
    u.note_transport_frame(0x30, 0x00);
    assert_eq!(u.state(), TclkState::RequestSent);
    assert!(!u.tclk_latched());
    u.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_TCLK);
    assert_eq!(u.state(), TclkState::KeyWait);
    // A tampered transport never latches.
    u.on_transport_open(false);
    assert_eq!(u.state(), TclkState::Failed);
    assert_eq!(u.error(), Some(JoinError::ConfirmMismatch));

    let mut u = TclkUpdate::new();
    u.begin();
    u.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_TCLK);
    u.on_transport_open(true);
    assert!(u.tclk_latched());
    u.note_verify_sent();
    assert_eq!(u.state(), TclkState::VerifySent);
    u.on_confirm(CONFIRM_KEY_STATUS_SUCCESS);
    assert_eq!(u.state(), TclkState::Authorized);
    assert!(u.error().is_none());
}

// TCLK timeouts and mid-update leave fail with the documented causes.
#[test]
fn bdb_tclk_timeout_and_leave_causes() {
    let mut u = TclkUpdate::new();
    u.begin();
    u.on_transport_timeout();
    assert_eq!(u.state(), TclkState::Failed);
    assert_eq!(u.error(), Some(JoinError::NoTransport));

    let mut u = TclkUpdate::new();
    u.begin();
    u.on_leave();
    assert_eq!(u.error(), Some(JoinError::JoinTimeout));
}

// ---------------------------------------------------------------------------
// Trust-Center admission (anchors p0033-L530-L553, §5.6.3–§5.6.4)
// ---------------------------------------------------------------------------

// Join policy: closed by default, allow-list checked, negotiation
// method marks the negotiated attributes.
#[test]
fn bdb_trust_center_admission_marks_method() {
    let mut tc = TrustCenter::new();
    assert!(!tc.admitted(0x1111));
    assert_eq!(
        tc.admit(0x1111, 0x0001, JoinMethod::InstallCode, 5)
            .unwrap_err(),
        JoinError::NotAllowed
    );
    tc.set_allow_list(&[0x1111]);
    assert!(tc.admitted(0x1111));
    tc.admit(0x1111, 0x0001, JoinMethod::Negotiation, 5)
        .unwrap();
    let dev: JoinedDevice = tc.find(0x1111).unwrap();
    assert_eq!(dev.attrs, KeyAttributes::NEGOTIATED);
    assert!(!dev.verified);
    tc.on_verify_confirm(0x1111, true).unwrap();
    assert!(tc.find(0x1111).unwrap().verified);
}

// Joiner association gate: only a confirmed association starts the
// authentication wait.
#[test]
fn bdb_joiner_assoc_gate() {
    let policy = JoinPolicy {
        cbke_supported: false,
        cbke_required: false,
        interview_tc: false,
        parent_is_r20_earlier: false,
    };
    let mut j = JoinerMachine::new(JoinMethod::InstallCode, policy);
    assert_eq!(j.state(), JoinerState::Unjoined);
    j.on_candidate();
    j.on_assoc_confirm(false);
    assert_eq!(j.state(), JoinerState::Failed);
}

// ---------------------------------------------------------------------------
// §12 touchlink completion tables (anchors p0085-L1786+)
// ---------------------------------------------------------------------------

// Touchlink stays inside the 2.4 GHz band.
#[test]
fn bdb_touchlink_channel_band() {
    use rounddance_commission::{TOUCHLINK_CHANNEL_MAX, TOUCHLINK_CHANNEL_MIN};
    assert_eq!((TOUCHLINK_CHANNEL_MIN, TOUCHLINK_CHANNEL_MAX), (11, 26));
}

// Utility-table command ids (scan/device/identify/start/join/update
// are pinned in vectors.rs; these complete the table).
#[test]
fn bdb_touchlink_utility_command_ids() {
    use rounddance_commission::touchlink::rx;
    use rounddance_commission::touchlink::tx;
    assert_eq!(rx::UTIL_GET_GROUP_REQ, 0x41);
    assert_eq!(rx::UTIL_GET_ENDPOINT_REQ, 0x42);
    assert_eq!(tx::UTIL_ENDPOINT_INFO, 0x40);
    assert_eq!(tx::UTIL_GET_GROUP_RSP, 0x41);
    assert_eq!(tx::UTIL_GET_ENDPOINT_RSP, 0x42);
}

// Group-identifier paging request round-trips; empty input truncates.
#[test]
fn bdb_touchlink_group_identifiers_paging() {
    let req = GetGroupIdentifiersRequest { start_index: 2 };
    let mut buf = [0u8; 4];
    assert_eq!(req.encode_into(&mut buf).unwrap(), 1);
    assert_eq!(&buf[..1], &[0x02]);
    assert_eq!(GetGroupIdentifiersRequest::decode(&buf[..1]).unwrap(), req);
    assert_eq!(
        GetGroupIdentifiersRequest::decode(&[]).unwrap_err(),
        TouchlinkError::Truncated
    );
}

// Endpoint-list paging request round-trips; empty input truncates.
#[test]
fn bdb_touchlink_endpoint_list_paging() {
    let req = GetEndpointListRequest { start_index: 1 };
    let mut buf = [0u8; 4];
    assert_eq!(req.encode_into(&mut buf).unwrap(), 1);
    assert_eq!(GetEndpointListRequest::decode(&buf[..1]).unwrap(), req);
    assert_eq!(
        GetEndpointListRequest::decode(&[]).unwrap_err(),
        TouchlinkError::Truncated
    );
}

// Identify request carries the stay-awake duration in seconds.
#[test]
fn bdb_touchlink_identify_duration() {
    let req = IdentifyRequest { duration_s: 10 };
    assert_eq!(IdentifyRequest::LEN, 2);
    let mut buf = [0u8; 4];
    assert_eq!(req.encode_into(&mut buf).unwrap(), 2);
    assert_eq!(&buf[..2], &[0x0a, 0x00]);
    assert_eq!(IdentifyRequest::decode(&buf[..2]).unwrap(), req);
    assert_eq!(
        IdentifyRequest::decode(&buf[..1]).unwrap_err(),
        TouchlinkError::Truncated
    );
}

// Endpoint-information record round-trips through the bounded codec.
#[test]
fn bdb_touchlink_endpoint_information_codec() {
    let info = EndpointInformation {
        ieee: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        network_address: 0x1234,
        endpoint: 0x0a,
        profile_id: 0x0104,
        device_id: 0x0005,
        version: 0x01,
    };
    let mut buf = [0u8; 32];
    let n = info.encode_into(&mut buf).unwrap();
    assert_eq!(EndpointInformation::decode(&buf[..n]).unwrap(), info);
    assert_eq!(
        EndpointInformation::decode(&buf[..n - 1]).unwrap_err(),
        TouchlinkError::Truncated
    );
}

// ---------------------------------------------------------------------------
// Secured / transport / keyprov helpers (commissioning-adjacent core)
// ---------------------------------------------------------------------------

// Secured builder refuses oversize plaintext and short buffers.
#[test]
fn bdb_secured_builder_bounds() {
    use rounddance_commission::{
        build_secured_nwk_frame, SecuredError, SecuredNwkParams, SECURED_FRAME_MAX, SECURED_PT_MAX,
    };
    let params = SecuredNwkParams {
        dst_pan: 0xC601,
        dst_short: 0x0003,
        src_short: 0x0000,
        broadcast: false,
        src_eui: [0x68; 8],
        mac_seq: 0x5a,
        nwk_seq: 0x21,
        nwk_radius: 0x1e,
        auxctr: 0x0000_2000,
        netkey: [0x10; 16],
    };
    let big = [0u8; SECURED_PT_MAX + 1];
    let mut out = [0u8; SECURED_FRAME_MAX];
    assert_eq!(
        build_secured_nwk_frame(&big, &params, &mut out).unwrap_err(),
        SecuredError::TooSmall
    );
    let pt = [0u8; 8];
    let mut tiny = [0u8; 8];
    assert_eq!(
        build_secured_nwk_frame(&pt, &params, &mut tiny).unwrap_err(),
        SecuredError::TooSmall
    );
}

// Transport-key builder writes the full 71-octet frame; short
// buffers refuse.
#[test]
fn bdb_transport_builder_shape() {
    use rounddance_commission::{
        build_transport_key_frame, ha_transport_key, TransportError, TransportKeyParams,
        TRANSPORT_FRAME_LEN,
    };
    let p = TransportKeyParams {
        dst_pan: 0xC601,
        dst_short: 0x0003,
        dst_eui: [0x6d; 8],
        src_eui: [0x68; 8],
        mac_seq: 0x5a,
        nwk_seq: 0x21,
        nwk_radius: 0x1e,
        aps_ctr: 0x51,
        auxctr: 0x0000_1000,
        seq_no: 0x00,
        netkey: [0x10; 16],
        transport_key: ha_transport_key().unwrap(),
    };
    let mut frame = [0u8; TRANSPORT_FRAME_LEN];
    assert_eq!(
        build_transport_key_frame(&p, &mut frame).unwrap(),
        TRANSPORT_FRAME_LEN
    );
    let mut tiny = [0u8; 8];
    assert_eq!(
        build_transport_key_frame(&p, &mut tiny).unwrap_err(),
        TransportError::TooSmall
    );
}

// Hex key provisioning accepts exactly 32 hex digits, nothing else.
#[test]
fn bdb_keyprov_hex_rules() {
    use rounddance_commission::netkey_from_hex;
    let key = netkey_from_hex("00112233445566778899aabbccddeeff").unwrap();
    assert_eq!(key[0], 0x00);
    assert_eq!(key[15], 0xff);
    assert!(netkey_from_hex("00112233").is_err());
    assert!(netkey_from_hex("00112233445566778899aabbccddeefg").is_err());
    assert!(netkey_from_hex("00112233445566778899aabbccddeeff00").is_err());
}

// ---------------------------------------------------------------------------
// §12.2 target side: network-update adoption + reset-to-factory order
// ---------------------------------------------------------------------------

use rounddance_commission::{
    NetworkUpdateRequest, TouchlinkFrame, TouchlinkTarget, TouchlinkTargetState, UpdateDisposition,
};

fn responded_target(tid: u32) -> TouchlinkTarget {
    let mut t = TouchlinkTarget::new();
    t.on_scan_request(&TouchlinkFrame::new(tid, 0x00, &[0x05, 0x83]).unwrap());
    t.on_response_sent();
    assert_eq!(t.state(), TouchlinkTargetState::Responded);
    t
}

// 22-65816-030-122-04: a same-network update with a newer identifier
// is adopted; stale, foreign, or wrong-transaction orders are
// ignored and the exchange stays waiting.
#[test]
fn bdb_touchlink_target_update_disposition() {
    let ext = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut t = responded_target(0xA11CE);
    let newer = NetworkUpdateRequest {
        extended_pan: ext,
        network_update_id: 0x04,
        channel: 20,
        pan_id: 0x1a2b,
        network_address: 0x0002,
    };
    // Stale transaction never applies.
    assert_eq!(
        t.on_network_update(&newer, 0xDEAD, &ext, 0x1a2b, 0x02),
        UpdateDisposition::Ignored
    );
    // Older-or-equal identifiers never apply.
    assert_eq!(
        t.on_network_update(&newer, 0xA11CE, &ext, 0x1a2b, 0x04),
        UpdateDisposition::Ignored
    );
    // Foreign network identity never applies.
    assert_eq!(
        t.on_network_update(&newer, 0xA11CE, &[0xFF; 8], 0x1a2b, 0x02),
        UpdateDisposition::Ignored
    );
    assert_eq!(
        t.on_network_update(&newer, 0xA11CE, &ext, 0x1a2b, 0x02),
        UpdateDisposition::Applied(rounddance_commission::PendingUpdate {
            network_update_id: 0x04,
            channel: 20,
        })
    );
    let latched = t.take_update().unwrap();
    assert_eq!(latched.network_update_id, 0x04);
    assert_eq!(latched.channel, 20);
    assert!(t.take_update().is_none());
}

// 22-65816-030-122-03 + §13.2: a matching reset order restarts the
// target and clears pending state; anything else is ignored.
#[test]
fn bdb_touchlink_target_reset_order() {
    let mut t = responded_target(0xBEEF);
    assert!(!t.on_reset(0xDEAD));
    assert_eq!(t.state(), TouchlinkTargetState::Responded);
    assert!(t.on_reset(0xBEEF));
    assert_eq!(t.state(), TouchlinkTargetState::Restarted);
    assert!(t.take_pending().is_none());
    // Outside the waiting state the order cannot land.
    let mut fresh = TouchlinkTarget::new();
    assert!(!fresh.on_reset(0xBEEF));
}
