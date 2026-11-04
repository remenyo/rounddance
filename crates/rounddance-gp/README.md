# rounddance-gp

Green Power proxy/sink: GPDF frame codec, ingress filter, security (counter windows, key slots), proxy and sink tables, commissioning sessions with bidirectional reply path.

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- gp (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Takes raw Green Power frames + key slots; emits proxy/sink decisions and translation-table entries. Needs a 15.4 radio and a sink app around it.

## API

Modules: `frame` (data/maintenance/commissioning codecs), `security` (nonce/key-bit/counter open), `proxy` (table, queue, commissioning mode, role machine), `sink` (sink + translation tables), `commissioning` (uni completion + reply sessions), `reply` (commissioning-reply/channel codecs), `receive` (intake pipeline), `gpd` (device model).

## Use

```toml
rounddance-gp = { path = "../rounddance-gp" }
```

```rust
use rounddance_gp::proxy::ProxyTable;
let t = ProxyTable::new();
```

Example: `crates/rounddance/examples/gp_data_frame.rs` (`cargo run -p rounddance --example gp_data_frame`).

## Limits

Needs a 15.4 radio and a sink app around it. Bodies of tunneled commands stay opaque by design; bodies are named, not parsed.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
