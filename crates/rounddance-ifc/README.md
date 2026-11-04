# rounddance-ifc

Versioned inter-module interfaces: CBOR envelope + minimal codec, HDLC-lite framing, hello/accept/reject handshake, and credit windows for backpressure — one envelope shape across every local split.

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- ifc (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Takes versioned call envelopes; emits framed bytes (CBOR + HDLC-lite + hello/accept + credit windows). A local boundary shape, not a transport driver.

## API

Modules: `envelope` (CBOR Envelope), `frame` (HDLC-lite + CRC16), `handshake` (hello/accept/reject), `credit` (windows), `cbor` (minimal codec), `transport` (in-memory reference). Conformance suite under `docs/ifc/v0/`.

## Use

```toml
rounddance-ifc = { path = "../rounddance-ifc" }
```

```rust
use rounddance_ifc::envelope::Envelope;
```

Example: `crates/rounddance/examples/ifc_envelope.rs` (`cargo run -p rounddance --example ifc_envelope`).

## Limits

Covers the local boundary shapes; it is not a transport driver (no serial/USB/IP code lives here).

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
