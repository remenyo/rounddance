# rounddance-browser

The stack as a headless-browser WASM bundle: the same first transaction as native, exposed through manual u32 exports (no binding generator, zero imports).

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- browser (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Bundles the stack as a headless-browser WASM module (manual u32 exports, zero imports). The same first transaction, verified digest-identical to native.

## API

`exports` module (13 getters + digest), harness under `harness/browser/` (empty-import instantiate + digest assert), `tools/browser-check.sh` (native == WASM proof).

## Use

```toml
rounddance-browser = { path = "../rounddance-browser" }
```

```rust
let d = rounddance_browser::exports::decision_digest();
```

Example: `tools/browser-check.sh` (`cargo run -p rounddance --example browser-check.sh`).

## Limits

Needs a JS/WASM engine to execute (wasmtime `--invoke` in CI); the real-browser driver is under `harness/browser/`.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
