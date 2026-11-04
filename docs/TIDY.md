# Post-spike tidy checklist (run AFTER all background agents land)

Background work outstanding: zcl-all coverage only (drlc/messaging
hookup already merged by main agent — confirm its completion notice
before tidying zcl). LANDED: RCP/NCP roles (pchost + rcp mac/ncp +
fw/rd-rcp* + shared-file rows; air proof parked with procedure),
BDB commissioning, core-net, core-sec, GP/Direct/policy, checker
verification (one real bug found + fixed). Nothing below starts
until the last completion lands, or files will collide.

## 1. Merge hookups (main agent)
- [ ] `zcl`: `pub mod uncovered;` — DONE (applied 2026-11-04).
- [ ] New `src/<mod>.rs` from agents: add `pub mod` lines per their
      annex NOTEs, one crate at a time, `cargo test -p <crate>` after
      each. (Agents were additive-only; registrations are pending.)
- [ ] `commission`/`nwk` relay builders + `hal-esp` grandchild relay:
      already in tree and gated. Confirm still green after merges.

## 2. Bookkeeping (main agent, shared files — agents were forbidden)
- [ ] REQUIREMENTS.md: wave-grandchild-relay rows (in tree),
      uncovered drafts (ZCL agent NOTE), per-doc rows from annexes.
- [ ] PROGRESS.md: one row each for relay, uncovered, READMEs,
      annotation system, coverage waves. Zero new IDs except those.
- [x] `fw/rd-coord/src/main.rs:362` rustfmt reflow (applied 2026-11-04,
      single-spot; workspace `cargo fmt --all --check` clean).
- [x] `examples/bench_stack.rs` needless-borrow ×3 (applied 2026-11-04;
      clippy clean + example runs).
- [ ] Pre-existing clippy dead-code in `tests/compressed.rs` (`unhex`)
      under `-D warnings` (HEAD condition, fix at tidy time).

## 3. Docs leftovers
- [ ] READMEs for `rcp` + `pchost` (deferred to the RCP agent).
- [ ] Convert legacy free-form anchor cites to `@tags`
      opportunistically (checker counts both; no rush).

## 4. Hygiene then commit
- [ ] `cargo test --workspace` green (165 suites / 1246 passed baseline).
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] `cargo fmt --all -- --check` clean.
- [ ] `python3 tools/coverage/check.py --strict` clean.
- [ ] Commit with trailer, push via lab key. Do NOT publish crates
      (versions frozen per owner instruction).
