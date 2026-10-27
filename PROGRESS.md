# PROGRESS.md — milestone-1 status

| Item | Status |
|------|--------|
| Workspace scaffold (crates, CI, docs) | Done |
| Frozen scope (SCOPE.md from D1–D5) | Done |
| Standards corpus page/section coverage | In progress (parallel stream) |
| MAC SAP trait boundary | Done (wave-2: TX/RX types, capability discovery, error taxonomy, cancel/backpressure; spec-area docs, seed coverage pending) |
| NWK / APS / ZDO bring-up | In progress (wave-3: NWK frame codec done — header encode/decode, NLDE construction guards, spec vectors, sim transport, bounded fuzz; routing/commands/APS/ZDO not started) |
| NWK frame codec (wave-3) | Done (rounddance-nwk: Fig. 3-4/3-5 header codec + §3.2.1.1.3 NLDE guards; tests/vectors.rs 16 spec vectors, tests/roundtrip.rs 8k-case bounded fuzz, sim nwk_transport loopback + 2-node + replay) |
| Security incl. SE + CBKE | Not started |
| ZCL engine + clusters | Not started |
| Green Power | Not started |
| Commissioning (classical / Touchlink / Direct) | Not started |
| Sim harness | Skeleton done (wave-2: virtual clock, SplitMix64 seeded RNG, scripted-medium SAP stub, round-trip scenario + replay-twice-identical-trace test) |
| Host HAL | Not started (stub) |
| ESP HAL | Not started (stub) |
| 4.0-native + 3.0-compat revision matrix | Not started |
| Host-first / C6-standalone parallel bring-up | Not started |
