//! Rounddance: an open-source Zigbee-compatible stack as one library.
//!
//! The stack is split into focused crates (one protocol layer each, all
//! `no_std`-compatible at the core). This crate re-exports them under
//! short module names so downstream users depend on a single library:
//!
//! ```toml
//! rounddance = { path = "crates/rounddance" }
//! ```
//!
//! # Layer map
//!
//! | Module | Crate | Contents |
//! |--------|-------|----------|
//! | [`mac_sap`] | `rounddance-mac-sap` | MAC service access point (TX/RX types, capability discovery) |
//! | [`nwk`] | `rounddance-nwk` | NWK frame codec (§3 frame control, headers, NLDE guards) |
//! | [`aps`] | `rounddance-aps` | APS frame codec + fragmentation |
//! | [`zdo`] | `rounddance-zdo` | ZDO clusters, descriptors, ZDP, bind/mgmt |
//! | [`security`] | `rounddance-security` | Keys, CCM\*, aux headers, replay tables, CBKE/ECC backends |
//! | [`zcl`] | `rounddance-zcl` | ZCL engine: frames, attributes, dispatch, On/Off + Level + IAS Zone |
//! | [`gp`] | `rounddance-gp` | Green Power proxy/sink |
//! | [`commission`] | `rounddance-commission` | Classical / Touchlink / Direct commissioning, install-code KDF |
//! | [`compat`] | `rounddance-compat` | 3.0-profile vs 4.0 revision gates and negotiation |
//! | [`direct`] | `rounddance-direct` | Direct commissioning core/session/advert |
//! | [`roles`] | `rounddance-roles` | Device roles: child tables, keepalive aging, indirect queues |
//! | [`sim`] | `rounddance-sim` | Deterministic sim harness (seeded RNG, virtual clock/scripted medium) |
//! | [`host`] | `rounddance-hal-host` | Host HAL: clock, timer, entropy, store, loopback radio, scenarios |
//! | [`ifc`] | `rounddance-ifc` | Inter-module interface spec (CBOR envelope, HDLC-lite framing) |
//! | [`hal_esp`] | `rounddance-hal-esp` | ESP HAL: `EspAdapter` + apps over a `Driver` seam (`MockDriver` on host) |
//! | [`hal_wasm`] | `rounddance-hal-wasm` | WASM guest HAL: `EspAdapter` + apps over host-call imports (native runner owns the radio; S31 path) |
//! | [`browser`] | `rounddance-browser` | Browser/WASM bindings over the host HAL |
//! | [`rcp`] | `rounddance-rcp` | RCP frame codec (SYNC/LEN/KIND/SEQ/CRC16) for S3+H2 OTBR path |
//! | [`inspect`] | `rounddance-inspect` | Packet inspector over live or captured frames |
//! | [`sniffer`] | `rounddance-sniffer` | Sniffer front-end (generic over any `Read + Write` port) |
//!
//! Out of scope for this facade: `rounddance-ffi` (C ABI staticlib,
//! separate artifact) and the `fw/` firmware binaries (ESP-IDF images,
//! built with `cargo +esp`).
//!
//! # Quickstart
//!
//! Run the host first-transaction scenario (form → join → toggle, all
//! in software, decision digest pinned):
//!
//! ```sh
//! cargo run -p rounddance --example first_transaction
//! ```
//!
//! Seal and open a frame under a network key, then watch the integrity
//! check fail under the wrong key:
//!
//! ```sh
//! cargo run -p rounddance --example sealed_frame
//! ```
//!
//! Benchmark every layer with the host clock only (no engine):
//!
//! ```sh
//! cargo run --release -p rounddance --example bench_stack
//! ```
//!
//! Every stack domain has a runnable tour under
//! `crates/rounddance/examples/` (see `README.md` there): MAC, NWK,
//! APS, ZDO, security, ZCL, Green Power, commissioning, Touchlink,
//! 3.0-compat, routing, RCP, IFC, the inspector, plus the two
//! end-to-end scenarios above.
//!
//! # Status (honest)
//!
//! Air-proven on real C6 radios: coordinator↔joiner join handshake plus
//! a secured ZCL toggle with verified Default Response (see PROGRESS.md
//! and `~/hwscratch/w115/`). Retention, hardening, and three-pairing
//! interop breadth are proven; a joiner against a foreign trust center
//! and peer key-update remain parked with cause in BLOCKERS.md.

pub use rounddance_aps as aps;
pub use rounddance_browser as browser;
pub use rounddance_commission as commission;
pub use rounddance_compat as compat;
pub use rounddance_direct as direct;
pub use rounddance_gp as gp;
pub use rounddance_hal_esp as hal_esp;
pub use rounddance_hal_host as host;
pub use rounddance_hal_wasm as hal_wasm;
pub use rounddance_ifc as ifc;
pub use rounddance_inspect as inspect;
pub use rounddance_mac_sap as mac_sap;
pub use rounddance_nwk as nwk;
pub use rounddance_rcp as rcp;
pub use rounddance_roles as roles;
pub use rounddance_security as security;
pub use rounddance_sim as sim;
pub use rounddance_sniffer as sniffer;
pub use rounddance_zcl as zcl;
pub use rounddance_zdo as zdo;
