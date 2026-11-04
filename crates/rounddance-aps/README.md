# rounddance-aps

APS-layer frame codecs, fragmentation plan/transmit/reassemble, retry sessions, duplicate rejection, and binding/group tables.

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- aps (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Takes application payloads + binding/group lookups; emits addressed APDUs, fragments, and delivery confirmations.

## API

Modules: `frame` (data/command/ack codecs, extended header), `frag` (plan, `TxBlocks`, `Reassembler`), `retry` (`RetrySession`), `tables` (binding, group, duplicate-rejection), `secure` (ack generation/parsing).

## Use

```toml
rounddance-aps = { path = "../rounddance-aps" }
```

```rust
use rounddance_aps::tables::BindingTable;
let t = BindingTable::new();
```

Example: `crates/rounddance/examples/aps_binding.rs` (`cargo run -p rounddance --example aps_binding`).

## Limits

Delivery across a real mesh needs the NWK + security + MAC layers around it; security-bit handling is verified through the secured-APS tests.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
