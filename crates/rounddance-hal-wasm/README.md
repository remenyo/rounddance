# rounddance-hal-wasm

WASM guest HAL: the stack over eight host imports, for runners (e.g. an S31 native host) that own the radio. The guest implements formation/join/poll/report logic; the host implements the air.

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- hal-wasm (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Implements the stack over eight host imports for runners that own the radio (e.g. an S31 native host). Guest-only: it cannot touch hardware.

## API

Guest shims for clock/timer/entropy/store/log/radio behind the `host.rd_host_*` import surface; covers the same apps as `hal-esp` through the call boundary.

## Use

```toml
rounddance-hal-wasm = { path = "../rounddance-hal-wasm" }
```

```rust
let _ = rounddance_hal_wasm::name();
```

Example: `harness/browser/` (`cargo run -p rounddance --example `).

## Limits

Guest-only: it cannot touch hardware. Pair with a native host implementing the import surface.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
