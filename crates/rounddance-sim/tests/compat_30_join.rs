//! 3.0-profile join + APS-secured ZCL transaction against the 4.0 stack.
//!
//! A 3.0-profile joiner (shared NWK version 2, install-code key path,
//! no negotiation support) completes join against our Trust Center and
//! then runs one secured On/Off Toggle as the APS payload; the 4.0
//! side admits every gate through `rounddance-compat`, applies the
//! toggle on a real server behavior, and rejects the replay.
//!
//! Corpus reuse (no new IDs for codec behavior): `22-65816-030-91-01`
//! (survey), `22-65816-030-56-03` (install-code key),
//! `22-65816-030-91-02/03` (exchange + announce), `05-3474-23-331-02`
//! (NWK version), `05-3474-23-451-01` (aux), `05-3474-23-4312-01`
//! (replay), `07-5123-08-241-01` (ZCL frame). Compat gates are
//! `RD-COMPAT-*` (repo-minted, MINTED-pending-confirm).

use rounddance_aps::{decode_data, DataDest, DataHeader, DeliveryMode, FrameControl as ApsFc};
use rounddance_commission::{
    BaselineSteeringPolicy, BeaconSurveyEntry, ChannelMask, InstallCode, JoinMethod, JoinPolicy,
    JoinerMachine, JoinerState, KeyAttributes, MmoJoinKdf, SteeringMachine, TrustCenter,
};
use rounddance_compat::negotiate::{
    admit_30_peer, admit_nwk_version, CompatError, KeyPolicy, SelectedMethod,
};
use rounddance_compat::profile::{CompatPeer, BASELINE_SEC_LEVEL};
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap, MacMgmtSap, TxOptions, TxRequest, TxStatus,
};
use rounddance_nwk::{decode as nwk_decode, FrameControl as NwkFc, NwkHeader};
use rounddance_security::{
    AuxHeader, FrameCounter, KeyIdMode, KeyIdentifier, ReplayTable, SecError, SecurityControl,
};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};
use rounddance_zcl::behavior::{Ctx, EventQueue};
use rounddance_zcl::frame::Header as ZclHeader;
use rounddance_zcl::{onoff, DispatchOutcome, Endpoint, ReportingEngine};

const PAN: u16 = 0x1a2b;
const TC_SHORT: u16 = 0x0000;
const JOINER_SHORT: u16 = 0x0001;
const JOINER_IEEE: u64 = 0x0200_0000_0000_0002;

/// Outcome of one 3.0-profile run: join state, toggle effect, bytes.
struct CompatOutcome {
    joined: bool,
    toggle_on: bool,
    wire: Vec<u8>,
    trace: Vec<String>,
}

/// One full 3.0-profile run: admit → steer → install-code join →
/// secured toggle → receive + apply.
fn run_30_transaction(seed: u64) -> CompatOutcome {
    // The peer is 3.0-profile: shared NWK version, symmetric methods
    // only. Admission selects install-code at baseline level 5.
    let peer = CompatPeer::profile_30();
    let (method, level) =
        admit_30_peer(&peer, true, &KeyPolicy::ALLOW_SYMMETRIC, BASELINE_SEC_LEVEL)
            .expect("3.0 peer is admissible");
    assert_eq!(method, SelectedMethod::InstallCode);
    assert_eq!(level, BASELINE_SEC_LEVEL);

    // Steering over a version-2 beacon, admitted by both the policy
    // floor and the compat version gate.
    let mut steering = SteeringMachine::new();
    steering
        .begin_scan(ChannelMask::from_list(&[15]).unwrap(), 3)
        .unwrap();
    steering
        .ingest(BeaconSurveyEntry {
            pan_id: PAN,
            channel: 15,
            lqi: 220,
            rssi: -40,
            permit_joining: true,
            router_capacity: true,
            end_device_capacity: true,
            protocol_version: 2,
        })
        .unwrap();
    steering.finish_scan(&BaselineSteeringPolicy {
        min_lqi: 100,
        min_version: 2,
    });
    assert_eq!(
        steering.state(),
        rounddance_commission::SteeringState::CandidateSelected
    );
    admit_nwk_version(2).expect("version 2 is the shared value");

    // Install-code join with the real MMO derivation (no mock KDF on
    // this path: the derivation is what a 3.0 device computes).
    let mut tc = TrustCenter::new();
    tc.open();
    tc.set_allow_list(&[JOINER_IEEE]);
    let mut wire = [0u8; 18];
    let n = InstallCode::with_crc(&[0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23], &mut wire)
        .unwrap();
    let code = InstallCode::from_slice(&wire[..n]).unwrap();
    let mut initial_key = [0u8; 16];
    TrustCenter::install_code_key(
        &MmoJoinKdf,
        &code,
        &JOINER_IEEE.to_be_bytes(),
        &mut initial_key,
    )
    .unwrap();

    let policy = JoinPolicy {
        cbke_supported: false,
        cbke_required: false,
        interview_tc: true,
        parent_is_r20_earlier: false,
    };
    let mut joiner = JoinerMachine::new(JoinMethod::InstallCode, policy);
    joiner.on_candidate();
    joiner.on_assoc_confirm(true);
    joiner.on_key_transport(true);
    tc.admit(JOINER_IEEE, JOINER_SHORT, JoinMethod::InstallCode, 100)
        .unwrap();
    let stored = [0x00u8; 16];
    let attrs = tc
        .exchange_key(JOINER_IEEE, &initial_key, &stored, 0x04)
        .unwrap();
    assert_eq!(attrs, KeyAttributes::SYMMETRIC);
    tc.on_verify_confirm(JOINER_IEEE, true).unwrap();
    joiner.on_verify_confirm(true, KeyAttributes::SYMMETRIC);
    assert_eq!(joiner.state(), JoinerState::Announced);
    joiner.close_out(false);
    assert_eq!(joiner.state(), JoinerState::Joined);

    // Secured ZCL Toggle: NWK (v2, security flag) | APS data |
    // aux level 5 | ZCL toggle frame.
    let mut tx_counter = FrameCounter::new(100, 4);
    let aux = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::Index, false).unwrap(),
        frame_counter: tx_counter.take().unwrap(),
        ext_source: None,
        key_id: KeyIdentifier::Index(0x01),
    };
    let mut zcl = [0u8; 8];
    let zlen = onoff::client::toggle(0x51, &mut zcl).unwrap();
    let aps = DataHeader {
        control: {
            let mut c = ApsFc::data(DeliveryMode::Unicast);
            c.security = true;
            c
        },
        dest: DataDest::Unicast { dst_endpoint: 0x01 },
        cluster_id: onoff::CLUSTER_ID,
        profile_id: 0x0104,
        src_endpoint: 0x01,
        counter: 0x3C,
        ext: None,
    };
    let mut nwk_ctl = NwkFc::data();
    nwk_ctl.security = true;
    let nwk = NwkHeader::minimal(nwk_ctl, TC_SHORT, JOINER_SHORT, 30, 0x7A);

    let alen = aux.header_len().unwrap();
    let mut payload = vec![0u8; aps.header_len() + alen + zlen];
    let an = aps.encode_into(&zcl[..zlen], &mut payload).unwrap();
    // Splice the aux header between APS and ZCL: shift the ZCL tail.
    let mut frame = vec![0u8; an + alen];
    frame[..aps.header_len()].copy_from_slice(&payload[..aps.header_len()]);
    let auxn = aux.encode_into(&mut frame[aps.header_len()..]).unwrap();
    assert_eq!(auxn, alen);
    frame[aps.header_len() + alen..].copy_from_slice(&zcl[..zlen]);
    let mut npdu = vec![0u8; 64];
    let nn = nwk.encode_into(&frame, &mut npdu).unwrap();

    // The toggle rides the scripted medium joiner → TC.
    let mut air = ScriptedRadio::new(Seed(seed), vec![ScriptAction::Deliver]);
    air.reset(true);
    air.set_channel(Channel::new(15).unwrap()).unwrap();
    air.set_pan_id(PAN);
    air.set_short_addr(JOINER_SHORT);
    air.data_request(TxRequest {
        dst: MacAddress::short(PAN, TC_SHORT),
        msdu: FramePayload::from_slice(&npdu[..nn]).expect("NPDU fits"),
        options: TxOptions::ACK,
    })
    .expect("queue has room");
    air.run_until_idle(16);
    assert_eq!(
        air.poll_confirm().expect("script confirms").status,
        TxStatus::Delivered
    );
    let on_air = air
        .poll_indication()
        .expect("delivery implies indication")
        .msdu
        .as_slice()
        .to_vec();

    // 4.0-side receive path: NWK version gate → APS → aux + replay →
    // ZCL decode → apply on a real server behavior.
    let npdu_rx = nwk_decode(&on_air).expect("NWK decodes");
    admit_nwk_version(npdu_rx.header.control.protocol_version).expect("shared version");
    assert!(npdu_rx.header.control.security);
    let aps_rx = decode_data(npdu_rx.payload).expect("APS data decodes");
    assert!(aps_rx.header.control.security);
    assert_eq!(aps_rx.header.cluster_id, onoff::CLUSTER_ID);
    let (aux_rx, aux_used) = AuxHeader::decode(aps_rx.payload).expect("aux decodes");
    assert_eq!(aux_rx.control.level, 5);
    let mut replay = ReplayTable::<8>::new();
    replay
        .check(JOINER_IEEE, aux_rx.frame_counter)
        .expect("first counter accepted");
    let zcl_wire = &aps_rx.payload[aux_used..];
    let (zcl_hdr, zcl_body) = ZclHeader::decode(zcl_wire).expect("ZCL decodes");
    assert_eq!(zcl_hdr.command_id, onoff::CMD_TOGGLE);
    assert_eq!(zcl_hdr.tsn, 0x51);
    assert!(zcl_body.is_empty());

    let def = onoff::ServerDef;
    let mut endpoint = Endpoint::new();
    endpoint.add(&def).unwrap();
    let mut store = onoff::server_store().expect("store builds");
    assert!(!onoff::onoff(&store), "server starts off");
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = onoff::ServerBehavior;
    let mut zcl_out = [0u8; 128];
    let mut ctx = Ctx {
        store: &mut store,
        reporting: &mut eng,
        events: &mut events,
        now_s: 0,
        peer_onoff: None,
        sender_ieee: Some(JOINER_IEEE),
    };
    match rounddance_zcl::dispatch(
        &endpoint,
        Some(&mut beh),
        &mut ctx,
        &zcl_hdr,
        zcl_body,
        onoff::CLUSTER_ID,
        None,
        &[],
        &mut zcl_out,
    )
    .expect("dispatch applies the toggle")
    {
        DispatchOutcome::Silent | DispatchOutcome::Respond(_) => {}
    }
    let toggle_on = onoff::onoff(&store);
    assert!(toggle_on, "toggle flips the server off→on");

    // Attacker replays the exact captured bytes: the counter no longer
    // advances, so the replay table refuses it.
    let replay_rx = nwk_decode(&on_air).expect("replay decodes");
    let replay_aps = decode_data(replay_rx.payload).expect("replay APS decodes");
    let (replay_aux, _) = AuxHeader::decode(replay_aps.payload).expect("replay aux decodes");
    assert_eq!(
        replay.check(JOINER_IEEE, replay_aux.frame_counter),
        Err(SecError::Replay)
    );

    CompatOutcome {
        joined: true,
        toggle_on,
        wire: on_air,
        trace: air.trace_lines().to_vec(),
    }
}

// The 3.0 profile completes join and the secured toggle flips the
// 4.0-side server attribute.
#[test]
fn compat_30_join_and_secured_toggle() {
    let out = run_30_transaction(0x30C4);
    assert!(out.joined);
    assert!(out.toggle_on);
    assert!(
        out.trace
            .iter()
            .any(|l| l.contains("confirm handle=0 status=Delivered")),
        "trace records delivery"
    );
}

// Decision determinism: same seed replays identical bytes + trace.
#[test]
fn compat_30_replays_deterministically() {
    let first = run_30_transaction(0xB3E);
    let second = run_30_transaction(0xB3E);
    assert_eq!(first.wire, second.wire);
    assert_eq!(first.trace, second.trace);
    assert_eq!(first.toggle_on, second.toggle_on);
}

// Unknown NWK versions never reach the join machine: steering may
// list the beacon, but the compat gate refuses it before any key
// material moves.
#[test]
fn compat_unknown_nwk_version_never_joins() {
    let mut steering = SteeringMachine::new();
    steering
        .begin_scan(ChannelMask::from_list(&[15]).unwrap(), 3)
        .unwrap();
    steering
        .ingest(BeaconSurveyEntry {
            pan_id: PAN,
            channel: 15,
            lqi: 220,
            rssi: -40,
            permit_joining: true,
            router_capacity: true,
            end_device_capacity: true,
            protocol_version: 9,
        })
        .unwrap();
    steering.finish_scan(&BaselineSteeringPolicy {
        min_lqi: 100,
        min_version: 2,
    });
    // The steering floor alone would admit 9; the compat gate refuses.
    assert_eq!(
        steering.state(),
        rounddance_commission::SteeringState::CandidateSelected
    );
    assert_eq!(
        admit_nwk_version(9),
        Err(CompatError::UnsupportedNwkVersion(9))
    );
}

// Mandatory-negotiation posture refuses a 3.0 peer instead of
// silently falling back to a symmetric key.
#[test]
fn compat_strict_posture_refuses_30_peer() {
    let peer = CompatPeer::profile_30();
    assert_eq!(
        admit_30_peer(
            &peer,
            true,
            &KeyPolicy::STRICT_NEGOTIATION,
            BASELINE_SEC_LEVEL
        ),
        Err(CompatError::NoCommonKeyMethod)
    );
}
