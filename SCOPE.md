# SCOPE.md — rounddance frozen scope

Source of decisions: personal project memory `rounddance-decisions.md`
(D1–D5 resolved 2026-10-27, plus founding-note extraction). This file
paraphrases those decisions for repo use. It cites document numbers and
clause numbers only — never spec text (see D1).

## 1. Objective

An open-source Zigbee-compatible stack in Rust: a portable `no_std`
core with deterministic simulation, targeting Linux hosts, ESP32
radios, and browsers via WASM.

## 2. Constraints

- **D1 (spec hygiene):** CSA spec PDFs live in private on-Pi storage,
  never in the repo. Repo content cites document numbers, revisions,
  and clause numbers plus paraphrased requirements only. No verbatim
  extracts, no committed PDFs. Residual CSA "AS IS" IP risk is noted,
  not cleared.
- **Alloc (D5):** bounded + fallible + accountable. Core code may
  allocate only within declared per-subsystem budgets, all allocation
  is fallible (no abort-on-OOM paths), and no protocol decision may
  depend on allocator state. Radio parameters live in preallocated
  tunable tables, resized only at provisioning/reboot, never
  mid-transaction.
- **Unsafe bar (D5):** `#![forbid(unsafe_code)]` in every protocol
  crate. `unsafe` is permitted only in per-target HAL shims, each
  block carrying a SAFETY comment and checklist review.
- **Determinism:** decision determinism — same seed + event script
  yields the same emitted frames and state transitions across
  sim/host/WASM/ESP, verified by trace comparison. Not byte-identical
  memory.
- **License (D5):** dual MIT / Apache-2.0 (vendor-adoptable,
  IDF-compatible).
- **WASM posture:** WASM-is-just-Linux — browser and Pi share protocol
  artifacts; browser constraints are tested from day one. Core targets
  a runtime-agnostic WASM interface (WIT / component-model style),
  never a specific engine API. Native bare-metal `no_std` compile
  stays green alongside WASM.

## 3. Acceptance

- Every release interops with 3.0 networks/devices (**3.0-compat
  mandatory**); the revision matrix tests 4.0-native plus 3.0-compat,
  with PRO as best-effort tracked fallback (D2).
- MAC SAP + adapter split is designed up front so the host path and
  the C6-standalone path share the core from day one (D3).
- Smart Energy + CBKE (cert parsing, ECDSA, key agreement) is in MVP
  scope with its audit burden accepted (D4).
- Closed-source stacks and commercial devices are required test
  peers but never authorities; divergences are captured,
  clause-checked, and recorded; workarounds stay explicit and
  separate from normative behavior.

## 4. IN / OUT layer table

| Layer / area              | Status |
|---------------------------|--------|
| 802.15.4 MAC SAP boundary | IN — abstract trait boundary, shared core |
| NWK                       | IN |
| APS                       | IN |
| ZDO                       | IN |
| Security incl. SE + CBKE  | IN (MVP, D4) |
| ZCL engine + clusters     | IN |
| Green Power               | IN |
| Commissioning (classical, Touchlink, Direct) | IN |
| Deterministic sim harness | IN — first-class deliverable |
| Host HAL (Linux/Pi)       | IN |
| ESP HAL (C6/S3/H2, …)     | IN |
| Multi-network per radio   | OUT — research backlog only |
| Own Bluetooth stack       | OUT — Zigbee Direct uses a BLE capability interface, never our own BT stack |
| IP as prerequisite        | OUT — colocated functions are the baseline; each split declares colocation assumptions |

## 5. Roles

Coordinator, router, end device, and sleepy end device. C6 MUST route
while hosting full application endpoints (thermostat-that-routes, one
identity). Application modules run identically on router or
end device. Standalone ESP32 exposes state query/management over USB.

## 6. Deployment matrix

| Target | Path |
|--------|------|
| Linux host (Pi) | Native + WASM (Deno / Wasmtime preferred) |
| Browser | WASM, same protocol artifacts as host |
| ESP32-C6 standalone | Native `no_std`, full stack + app endpoints |
| ESP32-S3 + H2 | Multiprocessor board; Wi-Fi is the management transport |
| ESP32-H2 | Minimal-radio-only experiment |
| ESP32-S3 (S31) | WASM-isolation experiment |
| Constrained targets | Full sleepy end-device via native compile |

Host-first and C6-standalone are EQUAL priority parallel bring-up
paths (D3), not ordered.

## 7. Revision policy

Zigbee 4.0 first — not 3.0-then-deltas (D2). 3.0 compatibility is
mandatory per §3. PRO support is best-effort with tracked fallback.

## 8. Verification strategy

- Document-based hierarchical page/section coverage is mandatory
  planning input: every spec region gets a disposition
  (extracted / informative / superseded / N-A-with-cause /
  unresolved); uncovered regions auto-create triage tasks.
- "Accounted for" vs "implemented" vs "verified" are tracked
  separately; spec version changes reopen coverage.
- Sim harness: virtual time, seeded replay, scripted media/faults,
  mixed device types, parameter sweeps with delivery/latency/
  overhead/convergence/churn/memory/fairness/energy metrics across
  many topologies. Sim runs are arbitrated resources with CPU/RAM
  budgets like hardware.
- Hardware: serial access arbitrated (one owner per port), logs +
  PCAP captured per run, restore-or-quarantine after each run.
- Destructive scenarios run on a designated test network; foreign
  devices are assumed present in the test model.
