//! First complete host transaction: coordinator formation →
//! device join → secured ZCL On/Off command → attribute report,
//! over the hal-host loopback pair with APS security on.
//!
//! The pinned digest is the decision-determinism anchor: the same
//! seed + run-id must yield the identical digest on native and on
//! `wasm32` under wasmtime (logical decisions only, never bytes or
//! wall time). The checked-in `sample_trace.txt` pins the full
//! module/device/run-id/state-transition/transaction trace.

use rounddance_hal_host::scenario::{run_first_transaction, ScenarioConfig};

/// Pinned decision digest for [`ScenarioConfig::first_transaction`].
/// Recompute only by running the scenario and verifying every
/// decision line by hand — never to silence a drift.
const PINNED_DIGEST: u64 = 0x3ea3_1047_e193_3c90;

const SAMPLE_TRACE: &str = include_str!("../sample_trace.txt");

#[test]
fn host_first_transaction_end_to_end() {
    let outcome = run_first_transaction(ScenarioConfig::first_transaction());
    let d = &outcome.decisions;

    // Logical decisions: formation, join, secured command, report.
    assert!(d.formed);
    assert!(d.tc_verified, "Trust Center verified the joiner");
    assert!(d.joiner_joined, "joiner reached Joined");
    assert!(d.server_onoff, "On command flipped the server");
    assert!(d.reported_onoff, "coordinator decoded OnOff=true");
    assert!(d.aps_security_on, "APS security bit set both ways");
    assert_eq!(
        d.resume_next, d.cmd_counter,
        "resumed counter is the live counter (store roundtrip feeds security)"
    );
    assert!(
        d.report_counter > d.cmd_counter,
        "counters advance across the exchange"
    );

    // Decision-determinism anchor: identical on native and WASM.
    assert_eq!(d.digest, PINNED_DIGEST);

    // Trace proof: structured log + medium lines, pinned.
    let expected: Vec<&str> = SAMPLE_TRACE.lines().collect();
    assert_eq!(outcome.trace, expected);
    assert!(
        outcome
            .trace
            .iter()
            .any(|l| l.contains("mod=commission") && l.contains("transition")),
        "formation/join transitions are logged"
    );
    assert!(
        outcome
            .trace
            .iter()
            .any(|l| l.contains("txn=") && l.contains("phase=report-rx")),
        "report reception is logged"
    );
    assert!(
        outcome
            .trace
            .iter()
            .any(|l| l.contains("phase=replay-rejected")),
        "replay rejection is logged"
    );

    // Captured excerpt (visible with `-- --nocapture`).
    println!("DIGEST={:#018x}", d.digest);
    for line in outcome.trace.iter().take(8) {
        println!("{line}");
    }
    println!(
        "... ({} lines total, see sample_trace.txt)",
        outcome.trace.len()
    );
}

#[test]
fn host_first_transaction_replays_identically() {
    let first = run_first_transaction(ScenarioConfig::first_transaction());
    let second = run_first_transaction(ScenarioConfig::first_transaction());
    assert_eq!(first.decisions, second.decisions);
    assert_eq!(first.trace, second.trace);
}
