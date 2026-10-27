//! First-transaction runner: executes the host scenario and prints
//! the decision digest plus the full trace.
//!
//! Native: `cargo run -p rounddance-hal-host --example host_transaction`
//! WASM: `cargo build -p rounddance-hal-host --example host_transaction
//! --target wasm32-wasip1 && wasmtime run <wasm>`

use rounddance_hal_host::scenario::{run_first_transaction, ScenarioConfig};

fn main() {
    let outcome = run_first_transaction(ScenarioConfig::first_transaction());
    let d = &outcome.decisions;
    println!("DIGEST={:#018x}", d.digest);
    println!(
        "DECISIONS formed={} tc_verified={} joiner_joined={} server_onoff={} reported_onoff={} aps_security_on={} cmd_counter={} report_counter={} resume_next={} tsn={:#04x}",
        d.formed,
        d.tc_verified,
        d.joiner_joined,
        d.server_onoff,
        d.reported_onoff,
        d.aps_security_on,
        d.cmd_counter,
        d.report_counter,
        d.resume_next,
        d.tsn,
    );
    println!("TRACE_LINES={}", outcome.trace.len());
    for line in &outcome.trace {
        println!("{line}");
    }
}
