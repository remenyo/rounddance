//! Two-node secure join over scripted media: beacon survey on the joiner,
//! association, install-code key derivation, Trust-Center admission and
//! symmetric exchange, device announcement across the medium, and
//! deterministic replay of the whole run.
//!
//! Requirement traceability: `22-65816-030-91-01` (survey + candidate),
//! `22-65816-030-56-03` (install-code-derived key), `22-65816-030-91-02`
//! (symmetric exchange + verify), `22-65816-030-91-03` (announce +
//! close-out), `05-3474-23-32214-01` + `05-3474-23-32215-01` (join
//! indication/confirm shape).
//! Derived key bytes carry MOCK provenance (see commission vectors).

use rounddance_commission::{
    BeaconSurveyEntry, ChannelMask, EccJoinKdf, InstallCode, JoinMethod, JoinPolicy, JoinerMachine,
    KeyAttributes, LinkEvidencePolicy, SteeringMachine, TrustCenter,
};
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap, MacMgmtSap, TxOptions, TxRequest, TxStatus,
};
use rounddance_security::mock::MockBackend;
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};
use rounddance_zdo::DeviceAnnce;

const PAN: u16 = 0x1a2b;
const TC_SHORT: u16 = 0x0000;
const JOINER_SHORT: u16 = 0x0001;
const JOINER_IEEE: u64 = 0x0200_0000_0000_0002;

/// Join outcome: the TC's view of the device plus the joiner's final
/// state and the on-air announcement bytes.
struct JoinOutcome {
    tc_device: rounddance_commission::JoinedDevice,
    joiner_done: bool,
    announce_wire: Vec<u8>,
    trace: Vec<String>,
}

/// One scripted secure join: steering survey → association → key
/// exchange → announcement. `actions` programs the shared medium.
fn secure_join(seed: u64, actions: Vec<ScriptAction>) -> JoinOutcome {
    // Trust Center side: open joining, allow-list the joiner.
    let mut tc = TrustCenter::new();
    tc.open();
    tc.set_allow_list(&[JOINER_IEEE]);

    // Joiner side: survey the TC's beacon, pick the candidate.
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
    // Field admission (no absolute LQI gate — see
    // `LinkEvidencePolicy`); the scripted beacon is strong.
    steering.finish_scan(&LinkEvidencePolicy::default());
    assert_eq!(
        steering.state(),
        rounddance_commission::SteeringState::CandidateSelected
    );

    // Install-code-derived initial link key (MOCK backend: pins
    // determinism, never interop). 8-octet code + check field.
    let kdf = EccJoinKdf(MockBackend::new(0xC0));
    let mut wire = [0u8; 18];
    let n = InstallCode::with_crc(&[0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23], &mut wire)
        .unwrap();
    let code = InstallCode::from_slice(&wire[..n]).unwrap();
    let mut initial_key = [0u8; 16];
    TrustCenter::install_code_key(&kdf, &code, &JOINER_IEEE.to_be_bytes(), &mut initial_key)
        .unwrap();

    // Joiner transcript: candidate → assoc → key → verify → announced.
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

    // TC side: admit, then run the symmetric exchange on the transported
    // initial key (fresh unique key differs from the stored one).
    tc.admit(JOINER_IEEE, JOINER_SHORT, JoinMethod::InstallCode, 100)
        .unwrap();
    let stored = [0x00u8; 16];
    let attrs = tc
        .exchange_key(JOINER_IEEE, &initial_key, &stored, 0x04)
        .unwrap();
    assert_eq!(attrs, KeyAttributes::SYMMETRIC);
    tc.on_verify_confirm(JOINER_IEEE, true).unwrap();
    joiner.on_verify_confirm(true, KeyAttributes::SYMMETRIC);
    assert_eq!(
        joiner.state(),
        rounddance_commission::JoinerState::Announced
    );

    // The announcement rides the scripted medium as one MAC frame.
    let annce = joiner.device_annce(0x0A, JOINER_SHORT, JOINER_IEEE);
    let mut frame = [0u8; DeviceAnnce::LEN];
    let flen = annce.encode_into(&mut frame).unwrap();

    let mut air = ScriptedRadio::new(Seed(seed), actions);
    air.reset(true);
    air.set_channel(Channel::new(15).unwrap()).unwrap();
    air.set_pan_id(PAN);
    air.set_short_addr(JOINER_SHORT);
    air.data_request(TxRequest {
        dst: MacAddress::short(PAN, TC_SHORT),
        msdu: FramePayload::from_slice(&frame[..flen]).expect("announce fits"),
        options: TxOptions::ACK,
    })
    .expect("queue has room");
    air.run_until_idle(8);
    let confirm = air.poll_confirm().expect("script confirms");
    assert_eq!(confirm.status, TxStatus::Delivered);
    let on_air = air
        .poll_indication()
        .expect("delivery implies indication")
        .msdu
        .as_slice()
        .to_vec();

    // TC decodes the announcement: network + long address must match the
    // admitted device (join indication/confirm shape,
    // 05-3474-23-32214-01 + 05-3474-23-32215-01).
    let heard = DeviceAnnce::decode(&on_air).unwrap();
    assert_eq!(heard.nwk_addr, JOINER_SHORT);
    assert_eq!(heard.ieee, JOINER_IEEE);
    let tc_device = tc.find(JOINER_IEEE).unwrap();
    assert_eq!(tc_device.nwk_addr, heard.nwk_addr);
    assert!(tc_device.verified);

    joiner.close_out(false);
    let joiner_done = joiner.state() == rounddance_commission::JoinerState::Joined;
    assert!(joiner_done);

    JoinOutcome {
        tc_device,
        joiner_done,
        announce_wire: on_air,
        trace: air.trace_lines().to_vec(),
    }
}

// 22-65816-030-91-01 + 91-02 + 91-03: the full two-node secure join.
#[test]
fn two_node_secure_join_beacon_to_announce() {
    let out = secure_join(0x501E, vec![ScriptAction::Deliver]);
    assert!(out.joiner_done);
    assert!(out.tc_device.verified);
    assert_eq!(out.tc_device.attrs, KeyAttributes::SYMMETRIC);
    assert_eq!(out.announce_wire.len(), DeviceAnnce::LEN);
    assert!(
        out.trace
            .iter()
            .any(|l| l.contains("confirm handle=0 status=Delivered")),
        "trace records delivery"
    );
}

// Decision determinism: same seed + script replays the identical trace.
#[test]
fn secure_join_replays_deterministically() {
    let script = || {
        vec![
            ScriptAction::Delay {
                base_us: 320,
                jitter_us: 100,
            },
            ScriptAction::Deliver,
        ]
    };
    let first = secure_join(0xBEEF, script());
    let second = secure_join(0xBEEF, script());
    assert_eq!(first.trace, second.trace);
    assert_eq!(first.announce_wire, second.announce_wire);
    assert_eq!(first.tc_device, second.tc_device);
}

// Secure-join matrix: admission decisions are timing-independent.
// Four seeds incl. the 0/u64::MAX edges — per-seed double runs
// replay the identical trace + wire + device, and every seed admits
// the same device and announces the same bytes (same
// timing-vs-decision split as the GP matrices: Delay jitter moves
// `queued_us` timestamps, never the admission decision — the naive
// cross-seed trace pin fails on those timestamps only).
#[test]
fn secure_join_matrix_seeds_share_wire_and_device() {
    const SEEDS: [u64; 4] = [0x0000, 0x501E, 0xBEEF, u64::MAX];
    let script = || {
        vec![
            ScriptAction::Delay {
                base_us: 320,
                jitter_us: 100,
            },
            ScriptAction::Deliver,
        ]
    };
    let mut ref_wire: Option<Vec<u8>> = None;
    let mut ref_device = None;
    for &seed in &SEEDS {
        let first = secure_join(seed, script());
        let second = secure_join(seed, script());
        assert_eq!(
            first.trace, second.trace,
            "per-seed trace replay, seed {seed:#x}"
        );
        assert_eq!(
            first.announce_wire, second.announce_wire,
            "per-seed wire replay, seed {seed:#x}"
        );
        assert_eq!(
            first.tc_device, second.tc_device,
            "per-seed device replay, seed {seed:#x}"
        );
        assert!(first.joiner_done, "joiner joins, seed {seed:#x}");
        assert!(first.tc_device.verified, "device verified, seed {seed:#x}");
        assert_eq!(
            first.tc_device.attrs,
            KeyAttributes::SYMMETRIC,
            "symmetric attrs, seed {seed:#x}"
        );
        assert_eq!(
            first.announce_wire.len(),
            DeviceAnnce::LEN,
            "announce length pin, seed {seed:#x}"
        );
        assert!(
            first
                .trace
                .iter()
                .any(|l| l.contains("confirm handle=0 status=Delivered")),
            "trace records delivery, seed {seed:#x}"
        );
        match (&ref_wire, &ref_device) {
            (None, None) => {
                ref_wire = Some(first.announce_wire.clone());
                ref_device = Some(first.tc_device);
            }
            (Some(w), Some(d)) => {
                assert_eq!(
                    &first.announce_wire, w,
                    "cross-seed wire pin, seed {seed:#x}"
                );
                assert_eq!(&first.tc_device, d, "cross-seed device pin, seed {seed:#x}");
            }
            _ => unreachable!(),
        }
    }
}
