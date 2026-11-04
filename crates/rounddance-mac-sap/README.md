# rounddance-mac-sap

MAC service-access traits: TX/RX types, capability discovery, error taxonomy, cancel/backpressure. The seam every radio driver implements and every upper layer programs against.

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- mac-sap (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Takes nothing but a radio driver; emits TX confirmations and RX indications. Every MAC driver (host loopback, ESP 15.4, UART radio, WASM guest) implements these traits; upper layers talk only to them.

## API

Modules: `data` (TX request/confirm, RX indication), `mgmt` (channel/power/PAN/addresses/energy scan), `interpan` (Touchlink path), `caps` (capability discovery). Key types: `TxRequest`, `TxConfirm`, `RxIndication`, `MacCapabilities`.

## Use

```toml
rounddance-mac-sap = { path = "../rounddance-mac-sap" }
```

```rust
use rounddance_mac_sap::{Channel, TxRequest};
let ch = Channel::new(15).unwrap();
```

Example: `crates/rounddance/examples/mac_beacon_req.rs` (`cargo run -p rounddance --example mac_beacon_req`).

## Limits

No radio attached: this crate only names the boundary. Timing, retries, and channel policy belong to the driver and the layers above.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
