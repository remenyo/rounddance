# rounddance-compat

Interop admission policy: profile/revision gates (shared NWK version, security floor, key-method selection), negotiation bundles, and an external co-processor adapter seam.

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- compat (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Takes a peer's profile/revision announcement; emits admit/refuse decisions and key-method selection. External co-processor adapters are a mock-backed seam; no radio hardware is touched by tests.

## API

Modules: `profile` (stack-profile admission), `negotiate` (admission bundles), adapter seam modules (command-octet namespace over mock transports in tests). Policy is pure logic: typed refusals, never silent downgrades.

## Use

```toml
rounddance-compat = { path = "../rounddance-compat" }
```

```rust
use rounddance_compat::profile::StackProfile;
```

Example: `crates/rounddance/examples/compat_profile.rs` (`cargo run -p rounddance --example compat_profile`).

## Limits

Best-effort interop surface: recognition/admission/version-gating are in scope, full foreign-stack commissioning is not. No radio hardware is touched by tests.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
