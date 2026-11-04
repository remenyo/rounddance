# rounddance-security

Keys, CCM* seal/open, auxiliary headers, replay/counter tables, install-code KDF, key hierarchy (transport/load/data), and CBKE handshakes (mock + host backends).

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- security (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Takes keys + counters + peer credentials; emits sealed/open frames and handshake transcripts. No radio, no storage: counters persist through caller-provided stores, curve math through injected backends.

## API

Modules: `aux` (header codec), `ccm` (seal/open), `counter`/`replay` (monotonic handoff, dedup windows), `store` (`NvmStore`, `RamStore`), `keys` (network/link tables, rotation), `mmo` + `keyhierarchy` (install-code and transport derivation), `ecc`/`p256field` (curve seam), `cbke` (session machine), `keyupdate`.

## Use

```toml
rounddance-security = { path = "../rounddance-security" }
```

```rust
use rounddance_security::ReplayTable;
let mut t = ReplayTable::<8>::new();
```

Example: `crates/rounddance/examples/sealed_frame.rs` (`cargo run -p rounddance --example sealed_frame`).

## Limits

No radio or storage attached: frame counters persist through caller-provided stores, curve math through injected backends, payload encryption assist through the radio driver.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
