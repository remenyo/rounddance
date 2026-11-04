//! Guest entry points: the native runner's call surface.
//!
//! The runner (see `host/rd_wasm_host.h`) drives the guest through
//! these exports; everything behind them runs over [`FfiHost`], never
//! over test doubles. On host, integration tests supply stub
//! definitions of the `rd_host_*` imports (same signatures, scripted
//! behavior), so the exact guest code paths below run verified
//! without a runner.
//!
//! `unsafe` confinement: this module carries the same allowance as
//! `rounddance-browser`'s exports module — `#[unsafe(no_mangle)]`
//! here is symbol naming only; the bodies are safe code, and every
//! `unsafe` call underneath lives confined in [`ffi`](crate::ffi).
//!
//! Requirement `RD-WASM-RT-05` (MINTED-pending-confirm).
#![allow(unsafe_code)]

use crate::ffi::FfiHost;
use crate::host::HostOps;
use rounddance_hal_esp::driver::MAX_AIR_FRAME;

/// Radio self-test through the real guest import path: init, tune,
/// power, addresses, receiver start, one transmit with confirm, one
/// energy scan. Returns `0` when every leg succeeds, otherwise the
/// negated 1-based step index of the first failure (deterministic
/// and log-free so the runner can report it over any channel).
#[unsafe(no_mangle)]
pub extern "C" fn rd_guest_radio_selftest() -> i32 {
    let mut host = FfiHost::new();
    if host.init().is_err() {
        return -1;
    }
    if host.set_channel(15).is_err() {
        return -2;
    }
    if host.set_tx_power(10).is_err() {
        return -3;
    }
    if host
        .set_addrs(
            0xC601,
            0x0000,
            &[0x68, 0x7F, 0x86, 0xFE, 0xFF, 0x62, 0xF2, 0xA0],
        )
        .is_err()
    {
        return -4;
    }
    if host.start_rx().is_err() {
        return -5;
    }
    // Minimal beacon-request PSDU; the host radiates it.
    let frame: [u8; 3] = [0x03, 0x08, 0xFF];
    let mut air = [0u8; MAX_AIR_FRAME];
    air[0] = (frame.len() + 2) as u8;
    air[1..1 + frame.len()].copy_from_slice(&frame);
    if host.transmit(&air[..1 + frame.len()]).is_err() {
        return -6;
    }
    match host.poll_tx() {
        Some(_) => {}
        None => return -7,
    }
    match host.energy_scan(15) {
        Ok(_) => 0,
        Err(_) => -8,
    }
}
