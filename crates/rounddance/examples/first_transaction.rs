//! First transaction through the facade: runs the host scenario
//! (form → join → toggle, all in software) and prints the decision
//! digest. Same coverage as
//! `rounddance-hal-host --example host_transaction`, proving the
//! single-dependency path works end to end.
//!
//! Run: `cargo run -p rounddance --example first_transaction`

use rounddance::host::scenario::{run_first_transaction, ScenarioConfig};

fn main() {
    let outcome = run_first_transaction(ScenarioConfig::first_transaction());
    let d = &outcome.decisions;
    println!("DIGEST={:#018x}", d.digest);
    println!(
        "DECISIONS formed={} tc_verified={} joiner_joined={} server_onoff={} reported_onoff={} aps_security_on={} tsn={:#04x}",
        d.formed,
        d.tc_verified,
        d.joiner_joined,
        d.server_onoff,
        d.reported_onoff,
        d.aps_security_on,
        d.tsn,
    );
    println!("TRACE_LINES={}", outcome.trace.len());
}
