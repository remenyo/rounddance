//! Browser-shape WASM bundle of the first complete transaction.
//!
//! Same scenario as the host leg
//! ([`rounddance_hal_host::scenario::run_first_transaction`]:
//! coordinator formation → install-code join → Trust-Center verify →
//! secured ZCL On → timer-gated attribute report), compiled to
//! `wasm32-unknown-unknown` with **zero imports**, so a browser can
//! instantiate it with `WebAssembly.instantiate(bytes, {})` and no
//! loader shims.
//!
//! ## Why manual exports, not wasm-bindgen
//!
//! The cross-target assertion is a fixed set of integers (the digest
//! fields). Each getter below re-runs the deterministic scenario and
//! returns one `u32` — no strings, no allocator handshake across the
//! boundary, no new dependencies. A JS harness reads the getters and
//! compares them against the native-pinned constants (see
//! `harness/browser/`).
//!
//! Every getter re-runs the whole scenario instead of caching it in
//! a `static`: shared mutable state would need `unsafe` blocks, and
//! this crate contains none. The run is milliseconds; re-running per
//! getter keeps each export pure.
//!
//! ## `unsafe` confinement
//!
//! Protocol crates carry `#![forbid(unsafe_code)]`. This bundle shim
//! is a boundary crate in the hal-esp sense: the crate root keeps
//! `#![deny(unsafe_code)]`, and the ONLY allowance is the
//! [`exports`] module, where each symbol carries
//! `#[unsafe(no_mangle)]` so the JS boundary sees stable names.
//! Those attributes name symbols; they introduce no `unsafe` blocks,
//! no derefs, no invariants — every export body is plain safe code
//! re-running the deterministic scenario.
//!
//! Requirement traceability: `REQUIREMENTS.md` wave-19 section
//! (`RD-BROWSER-*`, repo-minted, MINTED-pending-confirm).
#![deny(unsafe_code)]

use rounddance_hal_host::scenario::{run_first_transaction, ScenarioConfig, TransactionDecisions};

/// Re-run the canonical first transaction and return its decisions.
fn current() -> TransactionDecisions {
    run_first_transaction(ScenarioConfig::first_transaction()).decisions
}

/// Re-run and return the trace line count (deterministic, part of
/// the native `TRACE_LINES=` assertion).
fn trace_len() -> u32 {
    u32::try_from(
        run_first_transaction(ScenarioConfig::first_transaction())
            .trace
            .len(),
    )
    .expect("trace fits u32")
}

fn bit(b: bool) -> u32 {
    u32::from(b)
}

/// Stable-name WASM exports for the JS boundary (see the crate-level
/// `unsafe` confinement note: symbol naming only, bodies are safe).
pub mod exports {
    #![allow(unsafe_code)]
    use super::{bit, current, trace_len};

    /// High 32 bits of the decision digest (split so JS and CLI
    /// callers never face signed-i64 formatting differences).
    #[unsafe(no_mangle)]
    pub extern "C" fn rd_digest_hi() -> u32 {
        (current().digest >> 32) as u32
    }

    /// Low 32 bits of the decision digest.
    #[unsafe(no_mangle)]
    pub extern "C" fn rd_digest_lo() -> u32 {
        current().digest as u32
    }

    /// Coordinator formed the network (`formed`).
    #[unsafe(no_mangle)]
    pub extern "C" fn rd_formed() -> u32 {
        bit(current().formed)
    }

    /// Trust Center verified the joiner (`tc_verified`).
    #[unsafe(no_mangle)]
    pub extern "C" fn rd_tc_verified() -> u32 {
        bit(current().tc_verified)
    }

    /// Joiner completed admission (`joiner_joined`).
    #[unsafe(no_mangle)]
    pub extern "C" fn rd_joiner_joined() -> u32 {
        bit(current().joiner_joined)
    }

    /// Device OnOff server state after the secured On.
    #[unsafe(no_mangle)]
    pub extern "C" fn rd_server_onoff() -> u32 {
        bit(current().server_onoff)
    }

    /// Coordinator-decoded reported value (`reported_onoff`).
    #[unsafe(no_mangle)]
    pub extern "C" fn rd_reported_onoff() -> u32 {
        bit(current().reported_onoff)
    }

    /// APS security bit seen on both secured frames.
    #[unsafe(no_mangle)]
    pub extern "C" fn rd_aps_security_on() -> u32 {
        bit(current().aps_security_on)
    }

    /// Outgoing counter used for the ZCL On command.
    #[unsafe(no_mangle)]
    pub extern "C" fn rd_cmd_counter() -> u32 {
        current().cmd_counter
    }

    /// Outgoing counter used for the attribute report.
    #[unsafe(no_mangle)]
    pub extern "C" fn rd_report_counter() -> u32 {
        current().report_counter
    }

    /// Resume mark after the simulated reboot.
    #[unsafe(no_mangle)]
    pub extern "C" fn rd_resume_next() -> u32 {
        current().resume_next
    }

    /// ZCL transaction number used end to end.
    #[unsafe(no_mangle)]
    pub extern "C" fn rd_tsn() -> u32 {
        u32::from(current().tsn)
    }

    /// Number of trace lines the run emitted.
    #[unsafe(no_mangle)]
    pub extern "C" fn rd_trace_lines() -> u32 {
        trace_len()
    }
}

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-browser"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
    }
}
