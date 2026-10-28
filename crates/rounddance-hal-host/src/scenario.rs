//! First complete host transaction: coordinator formation →
//! device join → secured ZCL On/Off command → attribute report,
//! over the [`crate::HostMedium`] loopback pair with APS security
//! on, driven entirely through host backends.
//!
//! Requirement traceability (all exercised end-to-end here; the
//! scenario asserts decisions, the checked-in `sample_trace.txt`
//! pins the trace):
//!
//! * Formation + permit: `05-3474-23-3611-01` (formation
//!   primitive shape), `22-65816-030-61-01` (coordinator role).
//! * Join: `22-65816-030-91-01/02/03` (survey + symmetric
//!   exchange + announce), `22-65816-030-56-03/07/08`
//!   (install-code key via AES-MMO-128), `05-3474-23-32214-01` +
//!   `05-3474-23-32215-01` (join indication/confirm shape).
//! * APS security on: `05-3474-23-22511-05` (security bit),
//!   `05-3474-23-451-01` (aux codec), `05-3474-23-4311-01`
//!   (outgoing counter), `05-3474-23-4312-01` (replay guard),
//!   `05-3474-23-446-01` (key selection), `05-3474-23-434-01`
//!   (counter checkpoint/resume across the simulated reboot).
//! * ZCL: `07-5123-08-383-01` (On effect), `07-5123-08-2511-01`
//!   (report generation).
//! * Harness: `SCOPE.md` §8 decision determinism — the outcome
//!   digest covers logical decisions only (states, values,
//!   counters, statuses), never bytes or time, so native and WASM
//!   runs must agree exactly.

use crate::{EventKind, HostEntropy, HostLog, HostMedium, HostStore, HostTimer};
use rounddance_aps::{DataDest, DataHeader, DeliveryMode, FrameControl as ApsControl};
use rounddance_commission::{
    BeaconSurveyEntry, ChannelMask, FormationConfig, InstallCode, JoinMethod, JoinPolicy,
    JoinerMachine, JoinerState, KeyAttributes, LinkEvidencePolicy, LogicalType, MmoJoinKdf,
    PanChoice, SteeringMachine, TrustCenter,
};
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap as _, MacMgmtSap as _, TxOptions, TxRequest,
    TxStatus,
};
use rounddance_nwk::{build_data_header, decode as nwk_decode, DiscoverRoute, NldeDataRequest};
use rounddance_roles::{AgingPolicy, CoordinatorMachine, CoordinatorState};
use rounddance_security::{
    AuxHeader, FrameCounter, KeyIdMode, KeyIdentifier, KeySet, NetworkKey, NvmStore as _,
    ReplayTable, SecError, SecurityControl, COUNTER_STRIDE, NETWORK_KEY_LEN,
};
use rounddance_zcl::behavior::{Ctx, EventQueue};
use rounddance_zcl::frame::Header as ZclHeader;
use rounddance_zcl::{dispatch, general, onoff, DispatchOutcome, Endpoint, ReportingEngine};

/// Fixed topology for the first transaction.
pub const HOST_PAN: u16 = 0x1a2b;
/// Coordinator short address.
pub const COORD_SHORT: u16 = 0x0000;
/// Joiner short address (assigned by the Trust Center).
pub const JOINER_SHORT: u16 = 0x0001;
/// Joiner long address.
pub const JOINER_IEEE: u64 = 0x0200_0000_0000_0002;
/// Coordinator long address.
pub const COORD_IEEE: u64 = 0x0200_0000_0000_0001;
/// HA profile + On/Off endpoint used on both ends.
pub const HA_PROFILE: u16 = 0x0104;
/// Application endpoint on both ends.
pub const APP_ENDPOINT: u8 = 0x01;
/// Network key both ends share after joining.
pub const NETWORK_KEY: [u8; NETWORK_KEY_LEN] = [0x77; NETWORK_KEY_LEN];
/// Key sequence both ends share after joining.
pub const KEY_SEQ: u8 = 1;
/// Report-timer id: the device reports only after this fires.
pub const REPORT_TIMER_ID: u64 = 7;
/// Report delay in medium microseconds (several idle pumps).
pub const REPORT_DELAY_US: u64 = 300;
/// Device for medium-level log lines (`0xFFFF` = the medium itself).
pub const DEV_MEDIUM: u16 = 0xFFFF;

// Requirement `22-65816-030-91-01` (survey + candidate).
fn survey_and_select(log: &mut HostLog, run_id: u64, now: u64) -> SteeringMachine {
    let mut steering = SteeringMachine::new();
    steering
        .begin_scan(ChannelMask::from_list(&[15]).expect("15 valid"), 3)
        .expect("scan starts");
    steering
        .ingest(BeaconSurveyEntry {
            pan_id: HOST_PAN,
            channel: 15,
            lqi: 220,
            rssi: -40,
            permit_joining: true,
            router_capacity: true,
            end_device_capacity: true,
            protocol_version: 2,
        })
        .expect("beacon ingested");
    log.transition(
        now,
        "commission",
        JOINER_SHORT,
        run_id,
        "scanning",
        "candidate-selected",
    );
    // Field admission (no absolute LQI gate — see
    // `LinkEvidencePolicy`); the scripted host beacon is strong.
    steering.finish_scan(&LinkEvidencePolicy::default());
    assert_eq!(
        steering.state(),
        rounddance_commission::SteeringState::CandidateSelected
    );
    steering
}

// Requirements `05-3474-23-3611-01` + `22-65816-030-61-01`:
// coordinator forms the network and opens the permit window.
fn form_network(log: &mut HostLog, run_id: u64, now: u64) -> CoordinatorMachine {
    let aging = AgingPolicy {
        age_out_ms: 300_000,
    };
    let mut coord = CoordinatorMachine::new(aging);
    let config = FormationConfig {
        role: LogicalType::Coordinator,
        primary: ChannelMask::from_list(&[15]).expect("15 valid"),
        secondary: ChannelMask::empty(),
        scan_duration: 3,
        pan: PanChoice::Auto,
        extended_pan: [0xAA; 8],
        router_short_addr: COORD_SHORT,
    };
    log.transition(now, "roles", COORD_SHORT, run_id, "forming", "formed");
    coord.begin_formation(config).expect("formation starts");
    assert_eq!(coord.formation_done(true), CoordinatorState::Formed);
    coord.open_permit(600_000).expect("permit opens");
    log.txn(now, "roles", COORD_SHORT, run_id, 0, "permit-open");
    coord
}

// Requirements `22-65816-030-56-03/07/08` + `22-65816-030-91-02`:
// install-code key, admission, symmetric exchange, verify.
fn join_device(
    log: &mut HostLog,
    run_id: u64,
    now: u64,
    coord: &mut CoordinatorMachine,
) -> (TrustCenter, JoinerMachine) {
    let mut tc = TrustCenter::new();
    tc.open();
    tc.set_allow_list(&[JOINER_IEEE]);

    let kdf = MmoJoinKdf;
    let mut wire = [0u8; 18];
    let n = InstallCode::with_crc(&[0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23], &mut wire)
        .expect("install code valid");
    let code = InstallCode::from_slice(&wire[..n]).expect("code parses");
    let mut initial_key = [0u8; NETWORK_KEY_LEN];
    TrustCenter::install_code_key(&kdf, &code, &JOINER_IEEE.to_be_bytes(), &mut initial_key)
        .expect("link key derives");

    let _steering = survey_and_select(log, run_id, now);

    let policy = JoinPolicy {
        cbke_supported: false,
        cbke_required: false,
        interview_tc: true,
        parent_is_r20_earlier: false,
    };
    let mut joiner = JoinerMachine::new(JoinMethod::InstallCode, policy);
    joiner.on_candidate();
    log.transition(
        now,
        "commission",
        JOINER_SHORT,
        run_id,
        "candidate",
        "associating",
    );
    joiner.on_assoc_confirm(true);
    joiner.on_key_transport(true);
    log.transition(
        now,
        "commission",
        JOINER_SHORT,
        run_id,
        "key-transport",
        "verifying",
    );

    tc.admit(JOINER_IEEE, JOINER_SHORT, JoinMethod::InstallCode, 100)
        .expect("TC admits");
    coord
        .admit_child(JOINER_SHORT, JOINER_IEEE, false, 1_000)
        .expect("coord admits child");
    let stored = [0x00u8; NETWORK_KEY_LEN];
    let attrs = tc
        .exchange_key(
            JOINER_IEEE,
            &initial_key,
            &stored,
            KeyAttributes::SYMMETRIC.key_type,
        )
        .expect("exchange accepts");
    assert_eq!(attrs, KeyAttributes::SYMMETRIC);
    tc.on_verify_confirm(JOINER_IEEE, true)
        .expect("TC verifies");
    joiner.on_verify_confirm(true, KeyAttributes::SYMMETRIC);
    assert_eq!(joiner.state(), JoinerState::Announced);
    log.transition(
        now,
        "commission",
        JOINER_SHORT,
        run_id,
        "verifying",
        "announced",
    );
    (tc, joiner)
}

/// Wrap ZCL octets in a secured APS data APDU (security bit set —
/// requirement `05-3474-23-22511-05`; aux codec `05-3474-23-451-01`).
fn secured_apdu(
    cluster: u16,
    aps_counter: u8,
    zcl: &[u8],
    keys: &KeySet,
    tx: &mut FrameCounter,
) -> Result<Vec<u8>, SecError> {
    let aux = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::DataKey, false).expect("level 5 valid"),
        frame_counter: tx.take()?,
        ext_source: None,
        key_id: KeyIdentifier::Seq(keys.active().seq),
    };
    let hlen = aux.header_len().ok_or(SecError::BadKeyIdMode)?;
    let mut inner = vec![0u8; hlen + zcl.len()];
    let n = aux.encode_into(&mut inner)?;
    inner[n..].copy_from_slice(zcl);
    let header = DataHeader {
        control: {
            let mut c = ApsControl::data(DeliveryMode::Unicast);
            c.ack_request = true;
            c.security = true;
            c
        },
        dest: DataDest::Unicast {
            dst_endpoint: APP_ENDPOINT,
        },
        cluster_id: cluster,
        profile_id: HA_PROFILE,
        src_endpoint: APP_ENDPOINT,
        counter: aps_counter,
        ext: None,
    };
    let mut out = vec![0u8; header.header_len() + inner.len()];
    let m = header
        .encode_into(&inner, &mut out)
        .map_err(|_| SecError::BadKeyIdMode)?;
    out.truncate(m);
    Ok(out)
}

/// Accept a secured APS APDU: security bit must be set, key must
/// resolve, counter must advance past the replay table
/// (`05-3474-23-4312-01`). Returns the inner ZCL frame.
fn accept_apdu<'a>(
    keys: &KeySet,
    rx: &mut ReplayTable<8>,
    src_ieee: u64,
    apdu: &'a [u8],
) -> Result<&'a [u8], SecError> {
    let decoded = rounddance_aps::decode_data(apdu).map_err(|_| SecError::BadKeyIdMode)?;
    if !decoded.header.control.security {
        return Err(SecError::BadKeyIdMode);
    }
    let (aux, used) = AuxHeader::decode(decoded.payload)?;
    let seq = match aux.key_id {
        KeyIdentifier::Seq(s) => s,
        _ => return Err(SecError::BadKeyIdMode),
    };
    let _key = keys.select(seq).ok_or(SecError::NotFound)?;
    rx.check(src_ieee, aux.frame_counter)?;
    Ok(&decoded.payload[used..])
}

/// Wrap bytes in an NWK data NPDU from `src` to `dst`.
fn encoded_npdu(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
    let req = NldeDataRequest {
        dst_addr: dst,
        use_alias: false,
        alias_src: 0,
        alias_seq: 0,
        radius_param: 3,
        discover_route: DiscoverRoute::Enable,
        generated_seq: 0x42,
        local_short_addr: src,
        max_depth: 5,
        associated: true,
    };
    let header = build_data_header(&req).expect("NPDU header builds");
    let mut out = vec![0u8; header.header_len() + payload.len()];
    let n = header.encode_into(payload, &mut out).expect("NPDU fits");
    out.truncate(n);
    out
}

/// Send `npdu` from `tx_radio` to the peer over the shared medium
/// and return the on-air copy.
/// Parameters for one [`medium_send`] trip bundled to keep the
/// harness call readable.
struct SendParams<'a> {
    rx_radio: &'a mut crate::radio::HostRadio,
    dst: u16,
    log: &'a mut HostLog,
    run_id: u64,
    txn: u64,
    phase: &'static str,
}

fn medium_send(tx_radio: &mut crate::radio::HostRadio, npdu: &[u8], p: SendParams<'_>) -> Vec<u8> {
    let medium = tx_radio.medium().clone();
    tx_radio
        .data_request(TxRequest {
            dst: MacAddress::short(HOST_PAN, p.dst),
            msdu: FramePayload::from_slice(npdu).expect("NPDU fits one MSDU"),
            options: TxOptions::ACK,
        })
        .expect("queue has room");
    medium.run_until_idle(16);
    let confirm = tx_radio.poll_confirm().expect("medium confirms");
    assert_eq!(confirm.status, TxStatus::Delivered);
    let now = medium.now_us();
    p.log
        .txn(now, "hal-host", DEV_MEDIUM, p.run_id, p.txn, p.phase);
    p.rx_radio
        .poll_indication()
        .expect("delivery implies indication")
        .msdu
        .as_slice()
        .to_vec()
}

/// 64-bit FNV-1a over logical decision values.
fn fnv1a(values: &[u64]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_4842_2225;
    for &v in values {
        for b in v.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_0000_01B3);
        }
    }
    h
}

/// Logical decisions asserted identical on native and WASM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionDecisions {
    /// Coordinator formed and opened the permit window.
    pub formed: bool,
    /// Trust-Center entry verified.
    pub tc_verified: bool,
    /// Joiner reached Joined after close-out.
    pub joiner_joined: bool,
    /// Device OnOff value after the command.
    pub server_onoff: bool,
    /// Reported OnOff value the coordinator decoded.
    pub reported_onoff: bool,
    /// APS security bit seen on both secured frames.
    pub aps_security_on: bool,
    /// Outgoing counters used for command and report.
    pub cmd_counter: u32,
    /// Outgoing counter used for the report.
    pub report_counter: u32,
    /// Resume mark after the simulated reboot (strictly above used).
    pub resume_next: u32,
    /// ZCL transaction number used end to end.
    pub tsn: u8,
    /// Digest over every field above (the cross-target assertion).
    pub digest: u64,
}

/// Full outcome: decisions plus the rendered trace.
#[derive(Clone, Debug)]
pub struct TransactionOutcome {
    /// Logical decisions (digest-pinned).
    pub decisions: TransactionDecisions,
    /// Combined structured-log + medium trace lines.
    pub trace: Vec<String>,
}

/// Scenario configuration.
#[derive(Clone, Copy, Debug)]
pub struct ScenarioConfig {
    /// Run id (doubles as the log run field and digest input).
    pub run_id: u64,
    /// Deterministic seed for entropy + medium jitter.
    pub seed: u64,
}

impl ScenarioConfig {
    /// Canonical first-transaction configuration.
    #[must_use]
    pub const fn first_transaction() -> Self {
        Self {
            run_id: 0xB057_7EA1,
            seed: 0xB057_7EA1,
        }
    }
}

/// Run the first complete host transaction.
///
/// 1. Coordinator forms the network (`roles` + `commission`
///    formation, permit opened).
/// 2. Device surveys, joins via the Trust Center (install-code
///    key, symmetric exchange, verify), and announces across the
///    loopback pair.
/// 3. The Trust Center checkpoints its frame counter through the
///    host store and resumes past it (simulated reboot —
///    `05-3474-23-434-01`).
/// 4. Coordinator sends ZCL On (APS security on) across the pair;
///    the device validates aux + replay, decodes NWK/APS/ZCL, and
///    flips its OnOff server off → on.
/// 5. The device reports the new OnOff value, but only after the
///    host timer fires; the coordinator validates and decodes the
///    report.
///
/// Returns the decisions plus the full trace. Panics on any
/// unexpected stack behavior (a failed assertion IS the test
/// signal).
#[must_use]
pub fn run_first_transaction(config: ScenarioConfig) -> TransactionOutcome {
    let run_id = config.run_id;
    let mut entropy = HostEntropy::seeded(config.seed);
    let (mut coord_radio, mut join_radio) = HostMedium::pair(config.seed);
    let medium = coord_radio.medium().clone();
    let mut log = HostLog::new();
    let mut timer = HostTimer::new();
    let mut store = HostStore::new();

    for radio in [&mut coord_radio, &mut join_radio] {
        radio.reset(true);
        radio
            .set_channel(Channel::new(15).expect("15 valid"))
            .expect("channel sets");
        radio.set_pan_id(HOST_PAN);
    }
    coord_radio.set_short_addr(COORD_SHORT);
    coord_radio.set_extended_addr(COORD_IEEE);
    join_radio.set_short_addr(JOINER_SHORT);
    join_radio.set_extended_addr(JOINER_IEEE);
    log.event(
        medium.now_us(),
        "hal-host",
        DEV_MEDIUM,
        run_id,
        EventKind::Note {
            msg: "medium pair up ch=15".to_string(),
        },
    );

    // 1. Formation + permit.
    let mut coord = form_network(&mut log, run_id, medium.now_us());

    // 2. Join: TC + joiner machines, announcement over the medium.
    let (tc, mut joiner) = join_device(&mut log, run_id, medium.now_us(), &mut coord);
    let annce = joiner.device_annce(0x0A, JOINER_SHORT, JOINER_IEEE);
    let mut annce_wire = [0u8; rounddance_zdo::DeviceAnnce::LEN];
    let alen = annce
        .encode_into(&mut annce_wire)
        .expect("announce encodes");
    let tsn: u8 = 0x60 | (entropy.below(16) as u8);
    log.txn(
        medium.now_us(),
        "commission",
        JOINER_SHORT,
        run_id,
        u64::from(tsn),
        "announce-tx",
    );
    let heard = medium_send(
        &mut join_radio,
        &annce_wire[..alen],
        SendParams {
            rx_radio: &mut coord_radio,
            dst: COORD_SHORT,
            log: &mut log,
            run_id,
            txn: u64::from(tsn),
            phase: "announce-rx",
        },
    );
    let decoded = rounddance_zdo::DeviceAnnce::decode(&heard).expect("announce decodes");
    assert_eq!(decoded.nwk_addr, JOINER_SHORT);
    assert_eq!(decoded.ieee, JOINER_IEEE);
    let entry = tc.find(JOINER_IEEE).expect("TC knows the device");
    assert_eq!(entry.nwk_addr, decoded.nwk_addr);
    assert!(entry.verified);
    joiner.close_out(false);
    assert_eq!(joiner.state(), JoinerState::Joined);
    log.transition(
        medium.now_us(),
        "commission",
        JOINER_SHORT,
        run_id,
        "announced",
        "joined",
    );

    // 3. Counter checkpoint + simulated reboot through the host store
    // (`05-3474-23-434-01`): the key/sequence both ends share from
    // here on is the joined network key.
    let keys = KeySet::new(NetworkKey::new(NETWORK_KEY, KEY_SEQ));
    let tc_counter = FrameCounter::new(0, COUNTER_STRIDE);
    store
        .save_outgoing(tc_counter.peek())
        .expect("checkpoint saves");
    let loaded = store.load().expect("checkpoint loads");
    let mut tx_counter = FrameCounter::new(0, COUNTER_STRIDE);
    tx_counter.resume(loaded.resume_next());
    let resume_next = tx_counter.peek();
    assert!(resume_next > tc_counter.peek());
    log.txn(
        medium.now_us(),
        "security",
        COORD_SHORT,
        run_id,
        u64::from(tsn),
        "counter-resume",
    );
    let mut rx_table = ReplayTable::<8>::new();

    // 4. Coordinator → device: secured ZCL On, applied to a live
    // OnOff server (`07-5123-08-383-01`).
    let mut on = [0u8; 16];
    let on_len = onoff::client::on(tsn, &mut on).expect("On encodes");
    let apdu = secured_apdu(
        onoff::CLUSTER_ID,
        0x09,
        &on[..on_len],
        &keys,
        &mut tx_counter,
    )
    .expect("command secures");
    let cmd_counter = tx_counter.peek() - 1;
    let sent = encoded_npdu(COORD_SHORT, JOINER_SHORT, &apdu);
    log.txn(
        medium.now_us(),
        "zcl",
        COORD_SHORT,
        run_id,
        u64::from(tsn),
        "on-tx",
    );
    let on_air = medium_send(
        &mut coord_radio,
        &sent,
        SendParams {
            rx_radio: &mut join_radio,
            dst: JOINER_SHORT,
            log: &mut log,
            run_id,
            txn: u64::from(tsn),
            phase: "on-rx",
        },
    );
    assert_eq!(on_air, sent);
    let npdu = nwk_decode(&on_air).expect("NPDU decodes");
    assert_eq!(npdu.header.dst_addr, JOINER_SHORT);
    let aps = rounddance_aps::decode_data(npdu.payload).expect("APDU decodes");
    assert!(aps.header.control.security, "APS security is on");
    assert_eq!(aps.header.cluster_id, onoff::CLUSTER_ID);
    let zcl_wire =
        accept_apdu(&keys, &mut rx_table, COORD_IEEE, npdu.payload).expect("aux + replay validate");
    let (header, payload) = ZclHeader::decode(zcl_wire).expect("ZCL decodes");
    assert_eq!(header.tsn, tsn);
    assert_eq!(header.command_id, onoff::CMD_ON);

    let def = onoff::ServerDef;
    let mut endpoint = Endpoint::new();
    endpoint.add(&def).expect("cluster attaches");
    let mut server_store = onoff::server_store().expect("server store builds");
    assert!(!onoff::onoff(&server_store), "starts off");
    let mut engine = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut behavior = onoff::ServerBehavior;
    let mut zcl_out = [0u8; 128];
    let mut ctx = Ctx {
        store: &mut server_store,
        reporting: &mut engine,
        events: &mut events,
        now_s: 0,
        peer_onoff: None,
        sender_ieee: None,
    };
    match dispatch(
        &endpoint,
        Some(&mut behavior),
        &mut ctx,
        &header,
        payload,
        onoff::CLUSTER_ID,
        Some(COORD_IEEE),
        &[],
        &mut zcl_out,
    )
    .expect("dispatch runs")
    {
        DispatchOutcome::Silent => {}
        DispatchOutcome::Respond(_) => panic!("On sends no reply"),
    }
    assert!(onoff::onoff(&server_store), "On flips the server");
    log.transition(medium.now_us(), "zcl", JOINER_SHORT, run_id, "off", "on");

    // 5. Device → coordinator: attribute report, gated on the host
    // timer (`07-5123-08-2511-01` + timer backend proof).
    timer
        .schedule_in(REPORT_TIMER_ID, medium.now_us(), REPORT_DELAY_US)
        .expect("report timer arms");
    log.txn(
        medium.now_us(),
        "hal-host",
        JOINER_SHORT,
        run_id,
        u64::from(tsn),
        "report-armed",
    );
    loop {
        let due = timer.poll_due(medium.now_us());
        if due.contains(&REPORT_TIMER_ID) {
            break;
        }
        medium.pump_idle();
    }
    log.txn(
        medium.now_us(),
        "hal-host",
        JOINER_SHORT,
        run_id,
        u64::from(tsn),
        "report-fired",
    );
    let rep_header = ZclHeader::reply_to(&header, general::cmd::REPORT);
    let mut zcl = [0u8; 32];
    let hn = rep_header
        .encode_into(&mut zcl)
        .expect("report header fits");
    let records = [general::ReportRecord {
        id: onoff::ATTR_ONOFF,
        dtype: rounddance_zcl::DataType::Bool.as_u8(),
        value: rounddance_zcl::Value::Bool(true),
    }];
    let bn = general::encode_report(&records, &mut zcl[hn..]).expect("report fits");
    let rsp_apdu = secured_apdu(
        onoff::CLUSTER_ID,
        0x0A,
        &zcl[..hn + bn],
        &keys,
        &mut tx_counter,
    )
    .expect("report secures");
    let report_counter = tx_counter.peek() - 1;
    let rsp_sent = encoded_npdu(JOINER_SHORT, COORD_SHORT, &rsp_apdu);
    log.txn(
        medium.now_us(),
        "zcl",
        JOINER_SHORT,
        run_id,
        u64::from(tsn),
        "report-tx",
    );
    let rsp_air = medium_send(
        &mut join_radio,
        &rsp_sent,
        SendParams {
            rx_radio: &mut coord_radio,
            dst: COORD_SHORT,
            log: &mut log,
            run_id,
            txn: u64::from(tsn),
            phase: "report-rx",
        },
    );
    let rsp_npdu = nwk_decode(&rsp_air).expect("report NPDU decodes");
    assert_eq!(rsp_npdu.header.dst_addr, COORD_SHORT);
    let rsp_aps = rounddance_aps::decode_data(rsp_npdu.payload).expect("report APDU decodes");
    assert!(rsp_aps.header.control.security, "APS security is on");
    let rsp_zcl = accept_apdu(&keys, &mut rx_table, JOINER_IEEE, rsp_npdu.payload)
        .expect("report aux + replay validate");
    let (rep_back, rep_payload) = ZclHeader::decode(rsp_zcl).expect("report ZCL decodes");
    assert_eq!(rep_back.tsn, tsn);
    assert_eq!(rep_back.command_id, general::cmd::REPORT);
    let mut recs = [general::ReportRecord {
        id: 0,
        dtype: 0,
        value: rounddance_zcl::Value::NoData,
    }; 4];
    assert_eq!(
        general::decode_report(rep_payload, &mut recs).expect("report decodes"),
        1
    );
    assert_eq!(recs[0].id, onoff::ATTR_ONOFF);
    assert_eq!(recs[0].value, rounddance_zcl::Value::Bool(true));

    // Replay attack on the captured command bytes must fail.
    let replay_npdu = nwk_decode(&on_air).expect("captured bytes re-parse");
    assert_eq!(
        accept_apdu(&keys, &mut rx_table, COORD_IEEE, replay_npdu.payload),
        Err(SecError::Replay)
    );
    log.txn(
        medium.now_us(),
        "security",
        COORD_SHORT,
        run_id,
        u64::from(tsn),
        "replay-rejected",
    );

    let decisions = TransactionDecisions {
        formed: true,
        tc_verified: entry.verified,
        joiner_joined: joiner.state() == JoinerState::Joined,
        server_onoff: onoff::onoff(&server_store),
        reported_onoff: recs[0].value == rounddance_zcl::Value::Bool(true),
        aps_security_on: aps.header.control.security && rsp_aps.header.control.security,
        cmd_counter,
        report_counter,
        resume_next,
        tsn,
        digest: 0,
    };
    let digest = fnv1a(&[
        run_id,
        u64::from(decisions.formed),
        u64::from(decisions.tc_verified),
        u64::from(decisions.joiner_joined),
        u64::from(decisions.server_onoff),
        u64::from(decisions.reported_onoff),
        u64::from(decisions.aps_security_on),
        u64::from(decisions.cmd_counter),
        u64::from(decisions.report_counter),
        u64::from(decisions.resume_next),
        u64::from(decisions.tsn),
    ]);
    let decisions = TransactionDecisions {
        digest,
        ..decisions
    };

    let mut trace = log.lines();
    trace.extend(medium.trace_lines());
    TransactionOutcome { decisions, trace }
}
