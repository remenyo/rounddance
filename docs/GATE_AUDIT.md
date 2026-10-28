# GATE_AUDIT.md — final gate-evidence audit (wave-32, HEAD 0af057e + sim `forbid`)

Verdict scale: GREEN = exit evidence in repo and verified this wave or by a
cited prior wave with no drift. RED = real work remains; each carries cause +
owner. `MINTED-pending-confirm` IDs are repo-minted per D1, wording in
code/tests is paraphrase only, never spec text.

Cheap-gate re-run at HEAD (+ wave-32 sim `forbid(unsafe_code)` fix):

- `cargo test --workspace`: 642 passed / 0 failed across 99 `test result: ok` suites, exit 0
- `cargo clippy --workspace --all-targets -- -D warnings`: 0 warnings, exit 0
- `cargo fmt --check`: clean, exit 0

Portability legs not re-run this wave; wave-30 matrix quoted (no drift:
zero behavior changes since — docs + one `forbid` attribute only):
7 crates `--no-default-features` green, `wasm32-unknown-unknown` workspace
check fails only on pre-existing arbitrator unix/pty host-tool errors,
`tools/host-wasm-check.sh` IDENTICAL native == wasm32-wasmtime,
`tools/browser-check.sh` DECISION-MATCH digest `0x3ea31047e1933c90`,
`tools/c-check.sh` DECISION-MATCH digest `0x3ea31047e1933c90` (gcc 14.2.0),
ESP `riscv32imac-esp-espidf +esp` check exit 0.

## Gate table

| Gate | Exit evidence (paths + symbols + tests) | Verdict + cause |
|------|------------------------------------------|-----------------|
| foundation | `SCOPE.md` (frozen D1–D5); `REQUIREMENTS.md` ID scheme + traceability rule; `Cargo.toml` 19 workspace members; `crates/rounddance-mac-sap` SAP traits + `SapInterPan` adapter; `crates/rounddance-sim` `Seed`/`VirtualClock`/`SeededRng`/`ScriptedRadio`; `LICENSE-MIT` + `LICENSE-APACHE`; wave-32: `rounddance-sim/src/lib.rs` `#![forbid(unsafe_code)]` (was the only protocol-side crate missing it; zero `unsafe` in crate, suite still green) | GREEN |
| standards readiness | NWK frame codec `rounddance-nwk/src/frame.rs` (`NwkHeader`, `FrameControl`, `SourceRoute`) — `tests/vectors.rs` 16 vectors + `tests/roundtrip.rs` 8k fuzz + `rounddance-sim/tests/nwk_transport.rs`; APS `rounddance-aps/src/{frame,frag,retry}.rs` (`plan_transmit`, `TxBlocks`, `Reassembler`) — 19 vectors + 8k fuzz + `aps_transport.rs`; ZDO `rounddance-zdo/src/{cluster,status,desc,zdp,endpoint,bind,mgmt}.rs` — 25 vectors + 8k fuzz + sim ZDP transaction; `REQUIREMENTS.md` wave-3/4/7 sections | GREEN (NWK routing/commands excluded — see R1) |
| lab readiness | `tools/arbitrator` (`leases.rs` exclusive leases + FIFO + crash-recovery + `EXPIRY_WARN_SECS`, per-chip flash profiles, `decode.py` + tcpdump hooks, reserve→…→release-or-quarantine); 23 unit + 2 pty loopback tests; `PROGRESS.md` wave-5 row | GREEN |
| radio boundary | MAC SAP + adapter split per `SCOPE.md` §4; `rounddance-hal-esp/src/adapter.rs` (`EspAdapter`, 4 TX slots, +10 dBm cap, Len+2, PAN/foreign-PAN routing) + `MockDriver` 26 tests + `examples/esp_adapter_shape.rs`; `RD-HAL-ESP-01..13` rows; wave-23 OTA field note + wave-25 `docs/otbr/{topology,protocol}.md` S3↔H2 UART @460800 | GREEN (full on-target validation parked — see R6) |
| first complete transaction | `rounddance-hal-host` `run_first_transaction(ScenarioConfig::first_transaction())`: form → install-code/MMO join → DeviceAnnce → counter checkpoint → secured ZCL On → timer-gated report → replay refused; digest `0x3ea31047e1933c90`, `sample_trace.txt` 35 lines; `tools/host-wasm-check.sh` IDENTICAL; `PROGRESS.md` row 28 | GREEN |
| core roles | `rounddance-roles/src/{children,indirect,coordinator,router,enddevice,sleepy,endpoint}.rs` (`ChildTable`, `IndirectQueue`, `RouterApp` route/app fairness `MAX_ROUTE_PER_TICK`/`MAX_APP_PER_TICK`); 8 role transcripts + 3 fairness proofs + 6k fuzz; `rounddance-sim/tests/roles_network.rs` 3-node coord+router-with-app-endpoint+sleepy join/route/indirect/rejoin + replay; `PROGRESS.md` row 18 | GREEN |
| app framework | C6-standalone `rounddance-hal-esp::app` (`CoordinatorApp`/`JoinerApp`, `role_from_mac`, `SerialLog`); `tests/c6_standalone.rs` 4 host proofs; S3+H2 `rounddance-rcp` (`frame/cmd/uart/driver/peer`) + 6-test `rcp_otbr_path.rs`; Direct `rounddance-direct` + `direct_commission.rs`; `rounddance-browser` 13 getters + `tools/browser-check.sh`; `rounddance-ffi` + `harness/c/{txn.c,txn.cpp}` + `tools/c-check.sh` | GREEN (real-browser run open — see R4) |
| coverage expansion | SE/metering `rounddance-zcl/{metering,electrical,price,keyest,mirror,snapshot,schedule,sampling,supply,notify}.rs` (waves 14/26/28/31) + sim `se_loop/se_mirror_loop/se_schedule_loop/se_notify_loop` + replays; IAS ACE/WD + price blocks (wave-22) + `ias_loop`/`se_block_loop`; Touchlink completion (wave-20) + `touchlink_commission.rs`; compressed-point P-256 (wave-29) + compressed sim leg; level-0 AUX hardening (wave-23) + `join_unsecured_tc.rs`; 3.0-compat (wave-24) + `compat_30_join.rs` | GREEN (deferrals closed or by-design; remainders — see R3, R5) |
| portability validation | Wave-30 matrix at HEAD: `cargo test --workspace` 97 suites green then (642 passed/0 failed re-verified this wave at 99 suites incl. sim-`forbid` change), clippy 0, fmt clean, no-default-features + wasm legs green, wasmtime/browser/C DECISION-MATCH pins, ESP-target check exit 0 | GREEN |

## Scope-element audit

| Element | Evidence | Verdict |
|---------|----------|---------|
| Zigbee 4.0-first + mandatory 3.0 compat | `SCOPE.md` §7; `rounddance-compat/src/negotiate.rs` (`admit_nwk_version`, `agree_security_level`, `select_key_method`, `highest_common_key_index`, `admit_gp_version`); 11 wire vectors + `compat_30_join.rs` (join + secured Toggle + replay + unknown-version/strict-posture negatives) | GREEN |
| NWK / APS / ZDO | Gate rows above; `REQUIREMENTS.md` waves 3/4/7 | GREEN (minus R1) |
| Security incl full SE + CBKE | `rounddance-security` (`classical.rs` aux/counter/store/keyupdate, `ecc.rs` + `p256field.rs`, `keyupdate.rs` MMO mask); `rounddance-zcl/{keyest,metering,electrical,price,mirror,snapshot,schedule,sampling,supply,notify}.rs`; `se_loop.rs` CBKE → key update → price/ack → meter/profile; tampered-MACV `BAD_KEY_CONFIRM` | GREEN |
| ZCL engine + clusters | `frame/type/attrs/store/dispatch/reporting/discovery` + On/Off 0x0006, Level 0x0008, IAS Zone 0x0500, ACE 0x0501, WD 0x0502, Metering 0x0702, Price 0x0700, KeyEst 0x0800, Electrical 0x0B04 | GREEN |
| Green Power | `rounddance-gp/{frame,security,proxy,sink,commissioning}.rs`; 32 vectors + 8k fuzz + `gp_forward.rs` proxy→sink + replay | GREEN (minus R3) |
| Commissioning classical / Touchlink / Direct | `rounddance-commission` (formation/steering/finding/classical/touchlink) + inter-PAN `MacInterPanSap` seam; `rounddance-direct` (gatt/attr/session/advert/commission); sims `commission_join`, `touchlink_commission`, `touchlink_interpan`, `direct_commission` | GREEN |
| All four roles + C6 router+app-endpoint simultaneity | `PROGRESS.md` row 18; `endpoint.rs::RouterApp` fairness budgets; `roles_network.rs` router-with-app-endpoint leg | GREEN |
| host/WASM + C6-standalone + native + browser + S3+H2 | host native + `wasm32-wasip1` wasmtime IDENTICAL; C6-standalone `app` + ESP-target check; browser wasm bundle 13 getters DECISION-MATCH; RCP S3↔H2 UART path sim | GREEN (minus R4) |
| Deterministic decision-level sim | `Seed` + `VirtualClock` (no wall clock) + `SeededRng` (SplitMix64, core-ops only) + `ScriptedRadio`; every sim test has a replay-twice-identical-trace leg | GREEN |
| Dual MIT/Apache-2.0 | `LICENSE-MIT`, `LICENSE-APACHE`, `Cargo.toml` `license = "MIT OR Apache-2.0"` | GREEN |
| `forbid(unsafe_code)` in protocol crates | All of mac-sap/nwk/aps/zdo/security/zcl/gp/commission/compat/direct/roles/rcp/ifc/sim carry `#![forbid(unsafe_code)]`; repo-wide `unsafe` grep hits only HAL shims (`hal-esp/esp.rs`, `ffi.rs` `unsafe extern "C"`) under SAFETY discipline, `ffi` `pub mod ffi` under crate `#![deny(unsafe_code)]` + per-block `#![allow]`, browser `#[unsafe(no_mangle)]` symbol-only | GREEN |
| Bounded/fallible/accountable alloc | Spot-checks: APS `frag.rs` (`MAX_RX_TRANSACTIONS=2`, `MAX_BLOCKS_PER_RX=32`, `MAX_ASDU_OCTETS=512`, `MAX_BLOCK_PAYLOAD=128`); security (`MAX_AUX_LEN=22`, `MAX_KDF_OUT=64`); roles (`MAX_CHILDREN=32`, `MAX_INDIRECT_QUEUE=16`, `MAX_INDIRECT_PAYLOAD=128`); ZCL `reporting.rs` (`MAX_REPORT_SLOTS=16`); mirror/notify/snapshot/schedule rings (4-entry/8-ring/4-file/2-session×16-sample) | GREEN |

## RED list

- R1 NWK routing/commands not started (`PROGRESS.md` row 9 note; confirmed: no `RouteRequest`/`RouteReply`/`LinkStatus` codecs in `rounddance-nwk`, only `discover_route` passthrough in `nlde.rs`). Cause: never scheduled. Owner: repo.
- R2 Standards corpus page/section coverage still "In progress (parallel stream)" (`PROGRESS.md` row 3). Cause: full-corpus sweep ongoing outside this repo. Owner: corpus.
- R3 GP bidirectional commissioning reply path: structures + explicit stubs only (wave-11 note). Cause: deferred follow-up. Owner: repo.
- R4 Real-browser run of `harness/browser/index.html` open (`RD-BROWSER-04`; wasmtime leg DECISION-MATCH only). Cause: no browser/JS engine on box. Owner: human-blocker (first box with a browser records the verdict).
- R5 PRO profile support: SCOPE §7 best-effort tracked fallback, zero PRO rows/evidence in repo. Cause: explicitly best-effort, never scheduled. Owner: repo.
- R6 Full on-target ESP validation beyond best-effort `cargo check`s parked on hardware/human (`BLOCKERS.md` B-001/B-002/B-003 wifi-deaf quarantines, 15.4-ONLY policy). Cause: needs hands + healthy units. Owner: HW/human-blocker.
- R7 802.15.4 MAC corpus requirements "coverage pending" (wave-16 note: no MAC corpus mined; `mac-sap` has no corpus req IDs). Cause: corpus gap. Owner: corpus.
