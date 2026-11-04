# rounddance-direct

Zigbee Direct commissioning core over BLE: GATT service/characteristic descriptors, TLV attributes, provisioning/session/PSK state machines, advertisement records, and single-flight form/steer/join/key-update.

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- direct (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Takes GATT reads/writes from a BLE host; emits commissioning decisions (form/steer/join/key-update). Needs a BLE host around it; tested against scripted GATT peers.

## API

Modules: `gatt` (service/characteristic tables), `attr` (TLV codec), `session` (provisioning/basic/admin machines), `advert` (extension records), `commission` (single-flight machine reusing `commission` + `security`).

## Use

```toml
rounddance-direct = { path = "../rounddance-direct" }
```

```rust
use rounddance_direct::session::SessionMachine;
let s = SessionMachine::new();
```

Example: `crates/rounddance/examples/touchlink_scan.rs` (`cargo run -p rounddance --example touchlink_scan`).

## Limits

Needs a BLE host around it; tested against scripted GATT peers, not phones. Pair with `rounddance-commission` for the full join story.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
