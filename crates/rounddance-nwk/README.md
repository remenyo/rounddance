# rounddance-nwk

NWK-layer frame codec plus bounded routing: NPDU header encode/decode (frame control, addresses, radius, sequence, extended addresses, source routes), NLDE-DATA construction guards, and the route-discovery machinery (route/link-status/leave codecs, route table, discovery sessions, loop suppression, neighbor costs).

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- nwk (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Takes APS payloads + neighbor/link inputs; emits addressed NPDUs and next-hop decisions. Mesh forwarding policy and retries live one layer up.

## API

Modules: `frame` (`NwkHeader`, `FrameControl`, `SourceRoute`), `nlde` (`TxPipeline`, `NldeDataRequest`), `commands` (route-request/reply, link-status, leave), `route` (`RouteTable`, `DiscoveryTable`, `SeenRequests`, `NeighborCosts`, `LinkEstimator`).

## Use

```toml
rounddance-nwk = { path = "../rounddance-nwk" }
```

```rust
use rounddance_nwk::route::{RouteTable, ROUTE_LIFETIME_MS};
let mut t = RouteTable::new();
t.install(0x0003, 0x0002, 1, 0, ROUTE_LIFETIME_MS).unwrap();
```

Example: `crates/rounddance/examples/nwk_frame.rs` (`cargo run -p rounddance --example nwk_frame`).

## Limits

Header framing plus routing tables only. Security transforms live in `rounddance-security`, forwarding/retry policy in `rounddance-roles`, relay framing in `rounddance-commission` (`*_via` builders).

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
