# PROGRESS.md — milestone-1 status

| Item | Status |
|------|--------|
| Workspace scaffold (crates, CI, docs) | Done |
| Frozen scope (SCOPE.md from D1–D5) | Done |
| Standards corpus page/section coverage | In progress (parallel stream) |
| MAC SAP trait boundary | Done (wave-2: TX/RX types, capability discovery, error taxonomy, cancel/backpressure; spec-area docs, seed coverage pending) |
| NWK / APS / ZDO bring-up | In progress (wave-3: NWK frame codec done; wave-4: APS frame codec + fragmentation done — APDU codec, retry/dup machines, binding/group table stubs, spec vectors, bounded fuzz, sim transport; NWK routing/commands/ZDO not started) |
| NWK frame codec (wave-3) | Done (rounddance-nwk: Fig. 3-4/3-5 header codec + §3.2.1.1.3 NLDE guards; tests/vectors.rs 16 spec vectors, tests/roundtrip.rs 8k-case bounded fuzz, sim nwk_transport loopback + 2-node + replay) |
| APS layer + fragmentation (wave-4) | Done (rounddance-aps: §2.2.5 data/command/ack codec + extended header, Fig 2-2 transmit planner with ASDU_TOO_LONG/PEER_CANNOT_FRAGMENT/UNKNOWN_FRAGMENT_SUPPORT mined from the PDF render, tick-clocked TxBlocks/Reassembler + RetrySession/DupRejector, binding/group table stubs with budgets; tests/vectors.rs 19 spec vectors, tests/roundtrip.rs 8k-case bounded fuzz, sim aps_transport loopback + fragmented-E2E + 2-node + replay) |
| Security incl. SE + CBKE | Not started |
| ZCL engine + clusters | Not started |
| Green Power | Not started |
| Commissioning (classical / Touchlink / Direct) | Not started |
| Sim harness | Skeleton done (wave-2: virtual clock, SplitMix64 seeded RNG, scripted-medium SAP stub, round-trip scenario + replay-twice-identical-trace test) |
| Host HAL | Not started (stub) |
| ESP HAL | Not started (stub) |
| 4.0-native + 3.0-compat revision matrix | Not started |
| Host-first / C6-standalone parallel bring-up | Not started |
| Lab arbitrator v0 (wave-5, Track H) | Done (lab-arbitrator: typed inventory from esp-inventory.md + live /dev discovery + /proc holder scan, exclusive leases with FIFO queues + JSON persist + crash-recovery + waiter TTL, per-chip flash profiles + timeout/kill run plans + bounded serial capture, decode.py + tcpdump capture hooks, reserve→…→release-or-quarantine runner with per-stage evidence; 23 unit + 2 pty-loopback integration tests, clippy 0 warnings, fmt clean; no real hardware touched by tests) |
