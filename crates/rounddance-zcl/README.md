# rounddance-zcl

ZCL engine plus clusters: frame codec, data-type codec, attribute store, command dispatch, reporting, discovery, cluster definitions, behaviors, and the bundled clusters (On/Off, Level, IAS Zone/ACE/WD, metering/electrical/price/schedule/sampling/supply/snapshot/notify, key-establishment, plus the `uncovered` family: ERL Interface, Daily Schedule, Occupancy, Linky, device-type registry, Aliro bridge).

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- zcl (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Takes incoming ZCL frames + attribute writes; emits responses, reports, and behavior side-effects (e.g. lamp state). Application behavior beyond the bundled clusters is yours to add.

## API

Engine: `frame`, `types`, `attrs`, `general`, `reporting`, `dispatch`, `discovery`, `cluster`, `behavior`. Clusters: `onoff`, `level`, `ias_zone`, `ace`, `wd`, `metering`, `electrical`, `price`, `schedule`, `sampling`, `supply`, `snapshot`, `mirror`, `notify`, `keyest`, `uncovered` (`erl`, `dailysched`, `occupancy`, `linky`, `devtype`, `aliro`).

## Use

```toml
rounddance-zcl = { path = "../rounddance-zcl" }
```

```rust
use rounddance_zcl::onoff::{server_store, ServerBehavior};
let store = server_store().unwrap();
```

Example: `crates/rounddance/examples/zcl_frame.rs` (`cargo run -p rounddance --example zcl_frame`).

## Limits

Application behavior beyond the bundled clusters is yours to add via `ClusterDef`/`Behavior`. Poll cadence and persistence are app-owned; the engine exposes the hooks.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
