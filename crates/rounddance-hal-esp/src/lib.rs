//! ESP 802.15.4 HAL adapter: the MAC SAP over Espressif's 15.4 driver.
//!
//! Upper layers (NWK and above) talk only to
//! [`rounddance_mac_sap`] traits. This crate is the ESP-side adapter:
//! [`EspAdapter`] implements [`MacDataSap`], [`MacMgmtSap`], and
//! [`MacInterPanSap`] over the [`Driver`] seam, with the production
//! driver ([`EspIdfDriver`], `esp` feature) on one side and the
//! scriptable [`MockDriver`] (host tests, WASM) on the other.
//!
//! # Target scope
//!
//! C6, H2, C5, S31: the 15.4 driver application API is identical across
//! them (proven per-target in the bring-up waves — zero driver-code
//! deltas at this layer; only antenna-GPIO handling differs, and that
//! lives in board code, not here). The radio ceiling is the 15.4 DRIVER
//! (`esp_ieee802154` + `esp_hal_ieee802154`) and nothing above it: no
//! Zigbee/Thread upper-layer SDK is a dependency or a reference.
//!
//! # Documented invariants (enforced or asserted in code)
//!
//! * **TX-power standing cap**: [`MAX_TX_POWER_DBM`] (+10 dBm) is
//!   rejected in-code by [`EspAdapter::set_tx_power`]. Lab policy until
//!   human clears it; the driver never sees a hotter request.
//! * **NVS-init-first**: [`EspIdfDriver::init`] runs `nvs_flash_init`
//!   (with erase-on-version-mismatch, as the spike proved) before
//!   `esp_ieee802154_enable`. Calibration data lives in NVS.
//! * **Len+2**: every air frame's first octet is the on-air length
//!   INCLUDING the 2 trailing hardware-FCS octets. The builder
//!   ([`adapter::build_data_frame`], [`adapter::build_inter_pan_frame`])
//!   sets it; the RX parser checks it.
//! * **Antenna LOW/LOW**: Xiao C6 onboard-ceramic select is GPIO3 LOW +
//!   GPIO14 LOW. This is board code (see the `esp` example shape), never
//!   driven from this crate — and non-LOW/LOW combos are banned without
//!   human approval (suspected front-end damage vector on 3 units).
//! * **ISR discipline**: all 15.4 driver callbacks are ISR-context —
//!   flag-only, bounded copies, never log/lock. The `esp` driver pumps
//!   those flags in task context (`poll_tx` / `poll_rx`); the RX pump
//!   calls `receive_handle_done` for every frame or the driver's RX pool
//!   exhausts (~1 s stall under load, measured).
//! * **Filtering default**: init programs promiscuous mode OFF and
//!   `rx_when_idle` ON (the driver defaults promiscuous to TRUE —
//!   filtering must be explicitly enabled).
//! * **Retry policy**: the driver reports each transaction once
//!   (auto-ACK + CSMA in hardware, no HAL retry); this adapter maps the
//!   single report to the SAP confirm. Upper layers own retry.
//! * **Per-frame metering**: RX RSSI/LQI/channel come from the RX-done
//!   callback's `frame_info` (tail fallback if null) — never from the
//!   most-recent getters, which proved stale on air. C6 LQI reads flat
//!   9–11 on links that decode ~100%: a metering quirk, not a link
//!   verdict (see `esp` docs; admission policy lives in
//!   `rounddance-commission`).
//!
//! # `unsafe` confinement
//!
//! Protocol crates carry `#![forbid(unsafe_code)]`. This HAL shim is the
//! sanctioned exception: `unsafe` appears ONLY in `ffi` (extern
//! declarations for what `esp-idf-sys` 0.38 lacks, each with a header
//! cross-reference) and `esp` (the driver implementation, each block
//! with a `SAFETY` comment stating why it is sound). Both modules are
//! gated behind the `esp` cargo feature; the default build — the one
//! host CI, clippy, and WASM exercise — contains no `unsafe` at all.
//! Every public item in this crate is a safe API.
//!
//! [`MacDataSap`]: rounddance_mac_sap::MacDataSap
//! [`MacMgmtSap`]: rounddance_mac_sap::MacMgmtSap
//! [`MacInterPanSap`]: rounddance_mac_sap::MacInterPanSap
#![no_std]

#[cfg(test)]
extern crate std;

pub mod adapter;
pub mod app;
pub mod driver;
#[cfg(feature = "esp")]
pub mod esp;
#[cfg(feature = "esp")]
pub mod ffi;
pub mod mac_cmd;
pub mod mock;

pub use adapter::{EspAdapter, EspError, MAX_TX_POWER_DBM};
pub use app::{AppError, AppRole, CoordinatorApp, JoinerApp, SerialLog};
pub use driver::{Driver, DriverError, RxFrame, TxEvent, TxFail};
pub use mock::MockDriver;

#[cfg(feature = "esp")]
pub use esp::EspIdfDriver;

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-hal-esp"
}
