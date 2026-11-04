# rounddance-zdo

ZDO device/service discovery plus descriptors and management: cluster IDs, ZDP request/response codecs, node/power/simple descriptors, endpoint and binding tables, and the management primitives (leave, permit-joining, network-update).

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- zdo (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Takes local descriptors/tables + incoming ZDP requests; emits ZDP responses and management decisions. Join/leave choreography lives in `commission`.

## API

Modules: `cluster` (request/response IDs), `zdp` (NwkAddr/IeeeAddr/NodeDesc/PowerDesc/SimpleDesc/ActiveEp/MatchDesc/DeviceAnnce codecs), `desc` (descriptor codecs), `endpoint`/`bind` (`EndpointTable`, `BindManager` over the APS tables), `mgmt`, `transaction`, `status`.

## Use

```toml
rounddance-zdo = { path = "../rounddance-zdo" }
```

```rust
use rounddance_zdo::endpoint::EndpointTable;
let t = EndpointTable::new();
```

Example: `crates/rounddance/examples/zdo_descriptors.rs` (`cargo run -p rounddance --example zdo_descriptors`).

## Limits

Answers are built from the tables here; join/leave choreography lives in `rounddance-commission`, transport in NWK/APS.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
