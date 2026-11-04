# rounddance

An open-source Zigbee-compatible stack in Rust, with a `no_std` core,
targeting Linux, ESP32 (C6, S31), WASM guests, and browsers.

## What it is

One library, layered crates: MAC SAP → NWK → APS → ZDO → security →
ZCL → commissioning → roles, plus a deterministic sim, host and ESP
HALs, Green Power, 3.0-compat gates, RCP codec, inspector, and sniffer.
Depend on it as a single library via `crates/rounddance`
(`rounddance::nwk`, `rounddance::zcl`, …).

## What is proven

Air-proven on real silicon: C6 coordinator↔joiner join handshake plus
a secured ZCL toggle with verified Default Response, NVM-backed frame
counters, confirm-driven retries, join-rate policy, three-pairing
interop breadth; S31 native coordinator (isolated air-proof: join →
Device_annce → NodeDesc → secured toggle → verified Default Response,
sniffer-corroborated) and C6 router uplink (`state Active`, endpoint
hosted, hold/poll-service live). Parked with cause: joiner vs foreign
trust center, forwarded-traffic + sleepy-child E2E (needs third node),
spare-radio legs, peer key-update. Details: PROGRESS.md, BLOCKERS.md.

## Quickstart

```sh
cargo test --workspace          # 151 suites / 1151 passed, 0 failed
cargo run -p rounddance --example first_transaction   # form→join→toggle sim
cargo run -p rounddance --example sealed_frame        # seal/open + wrong-key refusal
cargo doc -p rounddance --no-deps                    # API docs
```

Firmware images (`fw/rd-coord`, `fw/rd-joiner`, ESP-IDF C6) build with
`cargo +esp build --release` per image. Lab work goes through the
arbitrator (`cargo run -p lab-arbitrator -- status`) with by-id serial
paths only.

## Layout

- `crates/rounddance` — library facade (depend on this)
- `crates/rounddance-{nwk,aps,zdo,security,zcl,gp,commission,compat,direct,roles,mac-sap,ifc}` — protocol core
- `crates/rounddance-{sim,hal-host,hal-esp,hal-wasm,browser,rcp,inspect,sniffer}` — execution environments and tools
- `crates/rounddance-ffi` — C-ABI staticlib (separate artifact)
- `crates/rounddance/examples/` — 16 runnable domain tours (MAC → inspector + 2 end-to-end), indexed in its README
- `fw/` — ESP-IDF firmware binaries; `harness/` — sim harness; `tools/` — lab arbitrator
- `docs/` — gate audit, interface specs; `REQUIREMENTS.md` — corpus traceability

Zigbee is a registered trademark of the Connectivity Standards Alliance;
this is an independent project, not affiliated with or endorsed by CSA.
