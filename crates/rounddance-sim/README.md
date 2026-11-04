# rounddance-sim

Deterministic simulation harness: virtual clock, seeded RNG, scripted radio medium, and two/three-node scenario tests with replay-twice-identical traces.

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- sim (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Takes an event script + seed; emits frame traces and delivery outcomes. Time only advances when the test advances it; nothing here runs on a wall clock.

## API

Modules: virtual clock, `SeededRng`, scripted-medium MAC SAP stub, scenario helpers (`commission_join`, `nwk_transport`, `aps_transport`, `route_discovery`, `touchlink_*`, `join_tc_first`, ...). Faults (drop/corrupt/delay) are scripted, never random.

## Use

```toml
rounddance-sim = { path = "../rounddance-sim" }
```

```rust
use rounddance_sim::VirtualClock;
let mut c = VirtualClock::new();
```

Example: `crates/rounddance-sim/tests/route_discovery.rs` (`cargo run -p rounddance --example route_discovery`).

## Limits

Scenarios, not a live stack: time only advances when the test advances it, and traces not asserted byte-identical are not replay proofs.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
