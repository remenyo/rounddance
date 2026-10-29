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

Wave-63 re-verification at HEAD 5ece806 (zero code changes since wave-62;
see "Wave-63 extension + re-confirmation" at the end of this file):

- `cargo test --workspace`: 120 `test result: ok` suites / 859 passed / 0 failed, exit 0
- `cargo clippy --workspace --all-targets -- -D warnings`: 0 warnings, exit 0
- `cargo fmt --check`: clean, exit 0
- `cargo check --workspace --exclude lab-arbitrator --target wasm32-unknown-unknown`: exit 0
- 15 crates `--no-default-features --target wasm32-unknown-unknown`: all green
  (mac-sap, nwk, aps, zdo, security, zcl, gp, commission, compat, direct,
  roles, rcp, ifc, sim, inspect)
- `tools/host-wasm-check.sh`: IDENTICAL native == wasm32-wasmtime, exit 0
- corpus `coverage_gate.py` read-only: PASS
  (docs=13 pages=3766/3766 unresolved=0 seed=519/519 pending=0), no corpus writes

## Gate table

| Gate | Exit evidence (paths + symbols + tests) | Verdict + cause |
|------|------------------------------------------|-----------------|
| foundation | `SCOPE.md` (frozen D1–D5); `REQUIREMENTS.md` ID scheme + traceability rule; `Cargo.toml` 19 workspace members; `crates/rounddance-mac-sap` SAP traits + `SapInterPan` adapter; `crates/rounddance-sim` `Seed`/`VirtualClock`/`SeededRng`/`ScriptedRadio`; `LICENSE-MIT` + `LICENSE-APACHE`; wave-32: `rounddance-sim/src/lib.rs` `#![forbid(unsafe_code)]` (was the only protocol-side crate missing it; zero `unsafe` in crate, suite still green) | GREEN |
| standards readiness | NWK frame codec `rounddance-nwk/src/frame.rs` (`NwkHeader`, `FrameControl`, `SourceRoute`) — `tests/vectors.rs` 16 vectors + `tests/roundtrip.rs` 8k fuzz + `rounddance-sim/tests/nwk_transport.rs`; APS `rounddance-aps/src/{frame,frag,retry}.rs` (`plan_transmit`, `TxBlocks`, `Reassembler`) — 19 vectors + 8k fuzz + `aps_transport.rs`; ZDO `rounddance-zdo/src/{cluster,status,desc,zdp,endpoint,bind,mgmt}.rs` — 25 vectors + 8k fuzz + sim ZDP transaction; `REQUIREMENTS.md` wave-3/4/7 sections | GREEN (NWK routing/commands excluded — see R1) |
| lab readiness | `tools/arbitrator` (`leases.rs` exclusive leases + FIFO + crash-recovery + `EXPIRY_WARN_SECS`, per-chip flash profiles, `decode.py` + tcpdump hooks, reserve→…→release-or-quarantine); 23 unit + 2 pty loopback tests; `PROGRESS.md` wave-5 row | GREEN |
| radio boundary | MAC SAP + adapter split per `SCOPE.md` §4; `rounddance-hal-esp/src/adapter.rs` (`EspAdapter`, 4 TX slots, +10 dBm cap, Len+2, PAN/foreign-PAN routing) + `MockDriver` 26 tests + `examples/esp_adapter_shape.rs`; `RD-HAL-ESP-01..13` rows; wave-23 OTA field note + wave-25 `docs/otbr/{topology,protocol}.md` S3↔H2 UART @460800 | GREEN (full on-target validation parked — see R6) |
| first complete transaction | `rounddance-hal-host` `run_first_transaction(ScenarioConfig::first_transaction())`: form → install-code/MMO join → DeviceAnnce → counter checkpoint → secured ZCL On → timer-gated report → replay refused; digest `0x3ea31047e1933c90`, `sample_trace.txt` 35 lines; `tools/host-wasm-check.sh` IDENTICAL; `PROGRESS.md` row 28 | GREEN |
| core roles | `rounddance-roles/src/{children,indirect,coordinator,router,enddevice,sleepy,endpoint}.rs` (`ChildTable`, `IndirectQueue`, `RouterApp` route/app fairness `MAX_ROUTE_PER_TICK`/`MAX_APP_PER_TICK`); 8 role transcripts + 3 fairness proofs + 6k fuzz; `rounddance-sim/tests/roles_network.rs` 3-node coord+router-with-app-endpoint+sleepy join/route/indirect/rejoin + replay; `PROGRESS.md` row 18 | GREEN |
| app framework | C6-standalone `rounddance-hal-esp::app` (`CoordinatorApp`/`JoinerApp`, `role_from_mac`, `SerialLog`); `tests/c6_standalone.rs` 4 host proofs; S3+H2 `rounddance-rcp` (`frame/cmd/uart/driver/peer`) + 6-test `rcp_otbr_path.rs`; Direct `rounddance-direct` + `direct_commission.rs`; `rounddance-browser` 13 getters + `tools/browser-check.sh`; `rounddance-ffi` + `harness/c/{txn.c,txn.cpp}` + `tools/c-check.sh`; real-browser run closed wave-34 (`tools/browser-real.sh`, headless Chromium DECISION-MATCH — see R4) | GREEN |
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
- R4 Real-browser run of `harness/browser/index.html` — CLOSED wave-34 (amended wave-63 with cited proof): `PROGRESS.md` wave-34 row records headless Chromium 156.0.8078.47 executing `harness/browser/index.html` → DECISION-MATCH digest `0x3ea31047e1933c90` trace_lines=35, all 13 getters == native (== pinned, == wasmtime); reproducer `tools/browser-real.sh` + install/run docs `harness/browser/README` both in repo at HEAD. (Pointer current: `REQUIREMENTS.md` row 582 now records the wave-34 closed verdict with the same cited proof — stale wording fixed wave-69 lane 2.)
- R5 PRO profile support: SCOPE §7 best-effort tracked fallback, zero PRO rows/evidence in repo. Cause: explicitly best-effort, never scheduled. Owner: repo.
- R6 Full on-target ESP validation beyond best-effort `cargo check`s parked on hardware/human (`BLOCKERS.md` B-001/B-002/B-003 wifi-deaf quarantines, 15.4-ONLY policy). Cause: needs hands + healthy units. Owner: HW/human-blocker.
- R7 802.15.4 MAC corpus requirements "coverage pending" (wave-16 note: no MAC corpus mined; `mac-sap` has no corpus req IDs). Cause: corpus gap. Owner: corpus.

## Waves 58–62 evidence-pointer addendum (no verdict changes)

Evidence pointers only — every gate verdict above stands unchanged
(each cited wave re-ran the full matrix green; RED list untouched).
Wave-62 lane 2 re-verified the matrix at HEAD: `cargo test
--workspace` 120 suites / 859 passed / 0 failed exit 0 (doctests
included), `cargo clippy --workspace --all-targets -- -D warnings` 0
warnings exit 0, `cargo fmt --check` clean exit 0, `cargo check
--workspace --exclude lab-arbitrator --target wasm32-unknown-unknown`
exit 0, 8 protocol crates `--no-default-features` wasm32 green,
`tools/host-wasm-check.sh` IDENTICAL, corpus `coverage_gate.py` PASS
(docs=13 pages=3766/3766 unresolved=0 seed=519/519 pending=0, no
corpus writes). Pedantic-leaning clippy reports only pre-existing
repo-wide style classes — zero code churn this wave.

- Wave-58 lane 2: `PROGRESS.md` wave-58 row; `REQUIREMENTS.md`
  wave-58 section (RD-INSPECT-37..38 CONFIRMED via sweep-39);
  evidence `~/hwscratch/w58/` (SUMMARY.md,
  sender_roundtrip.pcap).
- Wave-59 lane 1: `REQUIREMENTS.md` wave-58 section c25-drift
  resolution note; evidence `~/hwscratch/w59/lane1/`.
- Wave-60 lane 2: `PROGRESS.md` wave-60 row; `REQUIREMENTS.md`
  wave-60 section (RD-COMPAT-05..07 MINTED-pending-confirm at mint);
  evidence `~/hwscratch/w60/`.
- Wave-61 lane 2: `PROGRESS.md` wave-61 row; `REQUIREMENTS.md`
  wave-61 section (RD-COMPAT-05..07 flipped → CONFIRMED via
  sweep-41); evidence `~/hwscratch/w61/lane2/`.
- Wave-62 lane 2: `PROGRESS.md` wave-62 row; `REQUIREMENTS.md`
  wave-61 section (RD-COMPAT-08..10 flipped → CONFIRMED via
  sweep-42, 0 corrections / 0 REJECT); evidence `~/hwscratch/w62/`.

## Wave-63 extension + re-confirmation (HEAD 5ece806, 2026-10-29)

Repo-only, offline: no lab use, no corpus writes, zero new IDs.
Working tree clean at HEAD; zero code changes since wave-62 lane 2,
so the matrix below re-pins identical numbers (evidence
`~/hwscratch/w63/`: `test.log`, `clippy.log`, `fmt.log`, `wasm.log`,
`hostwasm.log`).

Full matrix (quoted, all exits 0):

- `cargo test --workspace`: 120 `test result: ok` suites / 859 passed / 0 failed, exit 0
- `cargo clippy --workspace --all-targets -- -D warnings`: 0 warnings, exit 0
- `cargo fmt --check`: clean, exit 0
- `cargo check --workspace --exclude lab-arbitrator --target wasm32-unknown-unknown`: exit 0
- 15 crates `--no-default-features --target wasm32-unknown-unknown`: all green
- `tools/host-wasm-check.sh`: IDENTICAL native == wasm32-wasmtime, exit 0
- corpus `coverage_gate.py` read-only: PASS
  (docs=13 pages=3766/3766 unresolved=0 seed=519/519 pending=0)

### 9-gate re-confirmation (every verdict stands, current evidence)

| Gate | Current evidence (waves 40–62) | Verdict |
|------|-------------------------------|---------|
| foundation | Unchanged since wave-32; `forbid(unsafe_code)` gap closed wave-32 and still holds — wave-63 grep: zero `unsafe` blocks/fns in all 14 protocol-crate `src` trees (only `inspect-live` bin + HAL/FFI shims, as documented) | GREEN |
| standards readiness | Unchanged; NWK/APS/ZDO codecs + vectors + fuzz + sim legs intact at 859-test HEAD; R1 closed wave-33 (`nwk::{commands,route}` + `RouterMachine` seam + `route_discovery.rs`) | GREEN |
| lab readiness | Unchanged repo-side; arbitrator + lease discipline exercised by every lab lane through wave-62 with zero quarantine (`~/hwscratch/w55`–`w62` lane SUMMARies all end leases-none/quarantine-none) | GREEN |
| radio boundary | Unchanged; `EspAdapter` + `MockDriver` + parity legs now also the reference for the Ember (wave-60) and TI (wave-61) adapter parity tests | GREEN |
| first complete transaction | Unchanged; host-wasm-check IDENTICAL re-pinned this wave | GREEN |
| core roles | Unchanged; `RouterMachine` routing seam (wave-33) rides the existing `forward` path, fairness budgets intact | GREEN |
| app framework | Real-browser leg now closed — see R4 amendment above; wasmtime/browser/C DECISION-MATCH pins unchanged | GREEN |
| coverage expansion | Unchanged; SE/keyest/Touchlink/3.0-compat/PRO-best-effort rows intact, all CONFIRMED or MINTED-pending-confirm as recorded | GREEN |
| portability validation | Re-pinned this wave: full matrix above, byte-identical to wave-62 (120/859/0) | GREEN |

### Extension exit-evidence rows (waves 40–62, proof pointers)

| Extension | Exit evidence (paths + results) |
|-----------|-------------------------------|
| Inspector engine + sender + air-loop | `crates/rounddance-inspect`: `session::SeqWindow` replay/gap/late accounting (wave-41, `tests/engine.rs` 13 tests) → `decrypt::open_nwk` + host `sniffer`/`inspect-live` + `live_air.rs` 11 tests with verbatim w48/w49 air goldens (wave-49) → sub-NWK dissectors + quirk split (wave-50, `decode_depth.rs`) → Touchlink (wave-51) + GPDF (wave-52) legs → `SessionTimeline` 16-row/8-event-ring tables + `LoopbackSender` 8×256B + `write_pcap` linktype-195 artifact `~/hwscratch/w58/sender_roundtrip.pcap` + 1191/1493/5218-frame zero-error replays (wave-58, `timeline.rs` 9 + `sender.rs` 4 tests); `REQUIREMENTS.md` RD-INSPECT-09..38 (09..36 CONFIRMED-or-pending as recorded, 37..38 CONFIRMED via sweep-39) |
| Ember + TI adapter skeletons | `rounddance-compat::{ember,ti}` + `tests/{ember,ti}_vectors.rs` 14+14 tests with byte-exact codec pins + decision-for-decision parity legs vs `EspAdapter`+`MockDriver` (waves 60–61); RD-COMPAT-05..10 all CONFIRMED (sweep-41/42, 0 corrections / 0 REJECT — `REQUIREMENTS.md` rows 721–723, 743–745); MG21/MG24/CC2652 untouched |
| ZBOSS MLME + NWK + stay-joined | Lab exit evidence (repo untouched): FULL MLME SUCCESS over the air — beacon-req→beacon, 3/3 assoc-req→MAC-ack, assoc-response short=0xB710 status=0 (w59 lane 2 `~/hwscratch/w59/lane2/SUMMARY.md`, NCS 2.x ZBOSS ported to nRF54L15 via 3-file patch, PAN 0x430D ch15); NWK join 4/4 SUCCESS with 115/115 secured opens under recovered netkey + host keyconfirm `0x5f5401af` all cycles (w60 lane 1 `~/hwscratch/w60/lane1/SUMMARY.md`, PAN 0xa6cc ch15, three-sided ESP+sniffer+ZBOSS logs); stay-joined MECHANISM NAILED: ZBOSS ejects ~13.6 s post-commission (`R21_TCLK` TIMEOUT → NWK Leave) because the joiner never initiates the TCLK exchange — TC authorization policy one layer up, follow-up scoped in §8 |
| fw-opt (E510-DEAF A/B) | Lab exit evidence (repo untouched): stock vs opt firmware behave IDENTICALLY on E510 (scan 0/0/0 both, join-fail both, full erase before every flash) while the same stock binary joins first-attempt on 7F68 — UNIT-FAULT (E510 WiFi RF path), suspect antenna call REFUTED (present+identical+executes); 5 opt deltas pinned (`~/hwscratch/w56/lane1/SUMMARY.md`, `scan-opt/` fair-A/B build); queued user-asked fw-optimization wave (partitions + sdkconfig) stays open by design |
| Fleet lessons | Standing lesson re-confirmed twice: full `erase-flash` CURED 7F68 wifi-deafness (w55 lane 1: first-attempt join, rssi −40…−43 dBm, NVS/PHY-cal corruption not RF damage — backup retained, restore deliberately skipped); E510 full-erase approved 2026-10-29, SDR fw need not be restored (memory `esp-fleet-lessons.md`); first remedy = full-erase, not quarantine (zero quarantine held all waves) |

Verdict changes this wave: exactly one — R4 open → CLOSED (cited proof
above). All 9 gate verdicts GREEN, no other amendments.
