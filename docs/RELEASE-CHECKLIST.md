# Release checklist — bottom-up crates.io publication

Total order over ALL intra-workspace edges (normal + dev), computed from manifests and
verified acyclic 2026-11-04 (`cargo metadata` graph; dev-cycle elimination PROGRESS row).
Publish strictly in this order: when step N runs, every dependency it names (normal and dev)
is already live on the index, so `cargo publish` verification resolves fully offline-proof.
`cargo package --list --offline` is green for all 23 crates (file counts below; zero leaks:
no `*.log`/`*.pcap`/hwscratch/tmp/target entries); `cargo publish --dry-run` is green for the
5 zero-dependency leaves (`mac-sap`, `ifc`, `nwk`, `aps`, `lab-arbitrator`).

| Step | Crate | Normal deps | Dev-only deps | Files |
|------|-------|-------------|---------------|-------|
| 1 | `lab-arbitrator` | — | — | 14 |
| 2 | `rounddance-aps` | — | — | 14 |
| 3 | `rounddance-ifc` | — | — | 17 |
| 4 | `rounddance-mac-sap` | — | — | 5 |
| 5 | `rounddance-nwk` | — | — | 11 |
| 6 | `rounddance-rcp` | rounddance-mac-sap | — | 13 |
| 7 | `rounddance-security` | — | rounddance-aps, rounddance-mac-sap, rounddance-nwk | 21 |
| 8 | `rounddance-zdo` | rounddance-aps | rounddance-mac-sap, rounddance-nwk | 16 |
| 9 | `rounddance-commission` | rounddance-aps, rounddance-mac-sap, rounddance-nwk, rounddance-security, rounddance-zdo | — | 16 |
| 10 | `rounddance-gp` | rounddance-security | rounddance-mac-sap | 19 |
| 11 | `rounddance-zcl` | rounddance-security | rounddance-aps, rounddance-mac-sap, rounddance-nwk | 42 |
| 12 | `rounddance-direct` | rounddance-commission, rounddance-security | — | 13 |
| 13 | `rounddance-roles` | rounddance-commission, rounddance-nwk, rounddance-zdo | — | 16 |
| 14 | `rounddance-hal-esp` | rounddance-aps, rounddance-commission, rounddance-mac-sap, rounddance-nwk, rounddance-roles, rounddance-security, rounddance-zcl, rounddance-zdo | — | 25 |
| 15 | `rounddance-inspect` | rounddance-aps, rounddance-direct, rounddance-gp, rounddance-mac-sap, rounddance-nwk, rounddance-security, rounddance-zcl | — | 38 |
| 16 | `rounddance-compat` | rounddance-mac-sap | rounddance-aps, rounddance-commission, rounddance-gp, rounddance-hal-esp, rounddance-nwk, rounddance-security, rounddance-zcl | 14 |
| 17 | `rounddance-hal-wasm` | rounddance-hal-esp, rounddance-mac-sap | rounddance-commission, rounddance-security, rounddance-zcl, rounddance-zdo | 14 |
| 18 | `rounddance-sniffer` | rounddance-inspect | rounddance-aps, rounddance-nwk, rounddance-security, rounddance-zcl | 16 |
| 19 | `rounddance-sim` | rounddance-mac-sap | rounddance-aps, rounddance-commission, rounddance-compat, rounddance-direct, rounddance-gp, rounddance-nwk, rounddance-rcp, rounddance-roles, rounddance-security, rounddance-zcl, rounddance-zdo | 32 |
| 20 | `rounddance-hal-host` | rounddance-aps, rounddance-commission, rounddance-mac-sap, rounddance-nwk, rounddance-roles, rounddance-security, rounddance-sim, rounddance-zcl, rounddance-zdo | — | 15 |
| 21 | `rounddance-browser` | rounddance-hal-host | — | 6 |
| 22 | `rounddance-ffi` | rounddance-commission, rounddance-hal-esp, rounddance-hal-host, rounddance-security, rounddance-zcl | — | 7 |
| 23 | `rounddance` | rounddance-aps, rounddance-browser, rounddance-commission, rounddance-compat, rounddance-direct, rounddance-gp, rounddance-hal-esp, rounddance-hal-host, rounddance-hal-wasm, rounddance-ifc, rounddance-inspect, rounddance-mac-sap, rounddance-nwk, rounddance-rcp, rounddance-roles, rounddance-security, rounddance-sim, rounddance-sniffer, rounddance-zcl, rounddance-zdo | — | 8 |

Preconditions: crates.io token (`cargo login`), versions in lockstep
(`[workspace.package] version`; all `version = "0.1.0"` pins move together), clean tree
(`git status --porcelain` empty — no `--allow-dirty`), green matrix at HEAD.
Post-publish: index resolves downstream automatically; docs.rs builds each crate (rustdoc 0 warnings at HEAD).
Residue: the act itself is owner-gated (credentials + per-crate approval). Zero new requirement IDs.
