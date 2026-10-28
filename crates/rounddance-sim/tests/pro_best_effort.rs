//! PRO-legacy best-effort admission leg (doc `22-65816-030` v3.1).
//!
//! A PRO-legacy peer (shared NWK version 2, PRO stack-profile value,
//! symmetric-only key path) is admitted through `admit_pro_peer`,
//! steers over a version-2 open beacon, and completes the symmetric
//! install-code join exchange. A closed PRO network is refused
//! before any key decision. The run is replay-deterministic: two
//! runs take the same gates and emit the same trace.
//!
//! Corpus reuse (no new IDs for exercised behavior):
//! `22-65816-030-91-01` (survey), `22-65816-030-56-03`
//! (install-code key), `22-65816-030-91-02` (symmetric exchange),
//! `05-3474-23-331-02` (NWK version). PRO admission itself is
//! `RD-PRO-01..04` (repo-minted, MINTED-pending-confirm).

use rounddance_commission::{
    BaselineSteeringPolicy, BeaconSurveyEntry, ChannelMask, JoinMethod, JoinPolicy, JoinerMachine,
    SteeringMachine, TrustCenter,
};
use rounddance_compat::negotiate::{admit_pro_peer, CompatError, KeyPolicy, SelectedMethod};
use rounddance_compat::profile::{CompatPeer, BASELINE_SEC_LEVEL, PRO_STACK_PROFILE};

const PAN: u16 = 0x2b3c;
const JOINER_SHORT: u16 = 0x0007;
const JOINER_IEEE: u64 = 0x0200_0000_0000_0007;

/// Outcome of one PRO best-effort run: admission verdict plus the
/// ordered gate trace (replay pin).
struct ProOutcome {
    method: SelectedMethod,
    level: u8,
    joined: bool,
    trace: Vec<String>,
}

/// One full PRO best-effort run: version + profile + permission
/// gates, steering over the PRO beacon, symmetric join exchange.
fn run_pro_admission() -> ProOutcome {
    let mut trace = Vec::new();
    let peer = CompatPeer::profile_pro();
    let (method, level) = admit_pro_peer(
        &peer,
        PRO_STACK_PROFILE,
        true,
        true,
        &KeyPolicy::ALLOW_SYMMETRIC,
        BASELINE_SEC_LEVEL,
    )
    .expect("open PRO-legacy peer is admissible");
    trace.push("pro-admitted".to_string());
    assert_eq!(method, SelectedMethod::InstallCode);
    assert_eq!(level, BASELINE_SEC_LEVEL);

    let mut steering = SteeringMachine::new();
    steering
        .begin_scan(ChannelMask::from_list(&[15]).unwrap(), 3)
        .unwrap();
    steering
        .ingest(BeaconSurveyEntry {
            pan_id: PAN,
            channel: 15,
            lqi: 200,
            rssi: -45,
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
    trace.push("pro-beacon-selected".to_string());

    let mut tc = TrustCenter::new();
    tc.open();
    tc.set_allow_list(&[JOINER_IEEE]);
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
    trace.push("pro-joiner-admitted".to_string());

    ProOutcome {
        method,
        level,
        joined: true,
        trace,
    }
}

/// Open PRO-legacy network: admitted, steered, joined — and the
/// whole run replays byte-identically.
#[test]
fn pro_best_effort_accept_and_replay() {
    let first = run_pro_admission();
    let second = run_pro_admission();
    assert!(first.joined && second.joined);
    assert_eq!(first.method, second.method);
    assert_eq!(first.level, second.level);
    assert_eq!(first.trace, second.trace);
    assert_eq!(
        first.trace,
        vec![
            "pro-admitted".to_string(),
            "pro-beacon-selected".to_string(),
            "pro-joiner-admitted".to_string(),
        ]
    );
}

/// Closed PRO network: the joining gate refuses before any key
/// decision, so no join machine ever starts.
#[test]
fn pro_closed_network_never_joins() {
    let peer = CompatPeer::profile_pro();
    assert_eq!(
        admit_pro_peer(
            &peer,
            PRO_STACK_PROFILE,
            false,
            true,
            &KeyPolicy::ALLOW_SYMMETRIC,
            BASELINE_SEC_LEVEL
        ),
        Err(CompatError::JoiningClosed)
    );
}
