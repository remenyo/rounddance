# rounddance-hal-host

Host HAL backends: clock, timer, seeded entropy, memory/file stores, structured log, loopback radio, and scripted scenarios including the first-transaction demo.

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- hal-host (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Implements the host backends (clock, timer, entropy, stores, log, loopback radio) behind the injected seams. Host-only; the ESP builds use `hal-esp` instead.

## API

Implements the injected seams (`NvmStore`, entropy, log, radio) for Linux/host targets plus `scenario::run_first_transaction` (form -> join -> DeviceAnnce -> secured ZCL).

## Use

```toml
rounddance-hal-host = { path = "../rounddance-hal-host" }
```

```rust
use rounddance_hal_host::scenario::{run_first_transaction, ScenarioConfig};
let o = run_first_transaction(ScenarioConfig::first_transaction());
```

Example: `crates/rounddance-hal-host/examples/host_transaction.rs` (`cargo run -p rounddance --example host_transaction`).

## Limits

Host-only backends; the ESP builds use `rounddance-hal-esp` instead. Run the example for the full form-to-report transcript.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
