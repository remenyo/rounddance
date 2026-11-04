# rounddance-roles

Device roles over the protocol machines: child tables + keepalive aging, indirect queues for sleepy children, coordinator/router/end-device/sleepy machines, the router forwarding seam (next-hop, discovery origination, relay/hold, link estimators), and application-endpoint hosting.

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- roles (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Takes MAC/NWK indications + timers; emits child-table, indirect-queue, polling, and routing decisions for one device role at a time.

## API

Modules: `children` (child table + aging), `indirect` (hold-for-sleepy queue + expiry), `coordinator` (formation/permit/admit), `router` (join/forward/serve-poll/rejoin + routing seam), `enddevice` (poll/loss/rejoin/leave), `sleepy` (duty-cycled poll machine), `endpoint` (`AppEndpoint` hosting).

## Use

```toml
rounddance-roles = { path = "../rounddance-roles" }
```

```rust
use rounddance_roles::children::ChildTable;
let t = ChildTable::new();
```

Example: `crates/rounddance/examples/route_table.rs` (`cargo run -p rounddance --example route_table`).

## Limits

Single-role logic per machine; the coordinator app that drives them lives in `rounddance-hal-esp`. Grandchild learning and relay emission are the `hal-esp` app's job on top of these tables.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
