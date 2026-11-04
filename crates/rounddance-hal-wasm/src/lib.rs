//! WASM guest HAL: run the stack inside a WASM runner on ESP32.
//!
//! The Rust IDF shim (`esp-idf-sys`) only names the chips in its
//! allowlist, so targets outside it (e.g. the S31 preview target)
//! cannot build `rounddance-hal-esp` with the `esp` feature. This
//! crate is the portable way out, matching the frozen S31 row in
//! `SCOPE.md` §6 (WASM-isolation experiment): the protocol stack —
//! [`EspAdapter`](rounddance_hal_esp::EspAdapter) over
//! [`WasmDriver`] — compiles to `wasm32-unknown-unknown` as a guest,
//! and the *native* runner (a small C program built with the IDF C
//! toolchain, which does span the S31) owns the radio, NVS, and
//! timers, exposing them through the host-call ABI in
//! [`ffi`] (mirrored for C authors in `host/rd_wasm_host.h`).
//!
//! # Boundary shape (mirrors `rounddance-browser` discipline)
//!
//! * Guest imports are plain C functions taking only integers and
//!   byte buffers in guest linear memory — no strings, no allocator
//!   handshake, no WASI, no wasm-bindgen. The host reads/writes guest
//!   memory through its runtime's memory API (`wasm3`:
//!   `m3_GetMemory`; WAMR: `wasm_runtime_addr_app_to_native`).
//! * [`HostOps`] is the testable form of that contract:
//!   [`crate::ffi::FfiHost`] performs the real imports
//!   on-device; [`crate::mock::MockHost`] scripts it
//!   on host.
//! * [`crate::wasm::WasmDriver`] adapts any host to the
//!   [`Driver`](rounddance_hal_esp::Driver) seam, so `EspAdapter` and
//!   everything above it runs unmodified inside the guest.
//!
//! # Building the guest artifact
//!
//! Guest imports resolve at instantiation, not at link time, so the
//! link needs undefined symbols allowed:
//!
//! ```sh
//! RUSTFLAGS="-C link-args=--allow-undefined" cargo build -p rounddance-hal-wasm --target wasm32-unknown-unknown
//! ```
//!
//! The result imports exactly the `host.rd_host_*` functions its
//! exports reach (dead imports are GC'd) plus linear `memory`, and
//! exports `rd_guest_radio_selftest`. The native runner instantiates
//! it with those imports bound and calls the export.
//!
//! # Native runner duties (S31 mapping)
//!
//! The runner implements each `rd_host_*` import against the IDF C
//! 15.4 driver (which carries S31 support: `SOC_IEEE802154_SUPPORTED`
//! plus the `esp32s31` LL HAL in this IDF tree): init = NVS-first
//! `nvs_flash_init` then `esp_ieee802154_enable`; addresses/filtering
//! via `esp_ieee802154_set_{panid,short_address,extended_address,
//! promiscuous,rx_when_idle}`; TX through the single-flight submit
//! with TX-done events; RX pumped per frame with per-frame
//! channel/RSSI/LQI (never the most-recent getters); ED scan per
//! channel. ISR discipline from `rounddance-hal-esp` applies
//! unchanged: flag-only in ISR, pump in task context, release every
//! RX buffer (`receive_handle_done` analogue).
//!
//! # `unsafe` confinement
//!
//! Protocol crates carry `#![forbid(unsafe_code)]`. This crate is a
//! boundary shim in the `rounddance-browser` sense: the crate root
//! keeps `#![deny(unsafe_code)]`, and the ONLY allowance is the
//! [`ffi`] module, where each foreign call carries a `SAFETY`
//! comment. Everything else — including all tests — is safe code.
//!
//! Requirement IDs below are repo-minted (`RD-WASM-RT-*`),
//! MINTED-pending-confirm.
#![deny(unsafe_code)]

pub mod ffi;
pub mod guest;
pub mod host;
pub mod mock;
pub mod wasm;

pub use ffi::FfiHost;
pub use guest::rd_guest_radio_selftest;
pub use host::HostOps;
pub use mock::MockHost;
pub use wasm::WasmDriver;

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-hal-wasm"
}
