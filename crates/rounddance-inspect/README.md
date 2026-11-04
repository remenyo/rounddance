# rounddance-inspect

Offline packet inspector: MAC/NWK/APS/ZCL/GP dissectors reusing the protocol codecs, session engine with per-device/per-PAN tables and replay windows, key slots for decryptable-vs-orphan accounting, pcap in/out, text + JSON reports.

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- inspect (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Takes captured octets (offline pcap or live serial); emits decode trees, session tables, and text/JSON reports. Decode-only: never transmits, never decrypts without keys you supply.

## API

Modules: `mac`, `nwk`, `nwkcmd`, `aps`, `zdo`, `touchlink`, `gp`, `tree` (decode tree + radio/node details), `session` (devices, replay windows, key slots), `decrypt` (key-gated openers), `report` (text/JSON), `stream`/`sniffer` (ingest). `inspect-live` binary reads a serial probe.

## Use

```toml
rounddance-inspect = { path = "../rounddance-inspect" }
```

```rust
use rounddance_inspect::dissect;
```

Example: `crates/rounddance/examples/inspect_beacon.rs` (`cargo run -p rounddance --example inspect_beacon`).

## Limits

Decode-only: it never transmits and never decrypts without keys you supply. Live capture needs a probe; offline replay needs only a pcap or text feed.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
