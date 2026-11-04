# rounddance-ffi

C ABI over the first transaction: opaque context, decision getters, bounded trace lines, C/C++ harnesses. Ships as a staticlib consumed by the IDF component and the C sample.

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- ffi (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Exposes the first transaction over a C ABI (opaque context, decision getters, bounded trace lines) as a staticlib for C/C++ hosts. No new protocol; see `harness/c/`.

## API

`ffi` module (`rd_create`/`rd_destroy`, 12+ decision getters, `rd_trace_line`, `RD_OK`/`RD_ERR_*` with panic-to-status at every boundary) + `apps_ffi` (coordinator/joiner app surface: create, scan, ingest, feed, answer, toggle-verify). `unsafe` is confined to the FFI boundary modules.

## Use

```toml
rounddance-ffi = { path = "../rounddance-ffi" }
```

```rust
rd_context_t *c = rd_create(); /* ... */ rd_destroy(c);
```

Example: `harness/c/txn.c` (`cargo run -p rounddance --example txn.c`).

## Limits

Unsafe is confined to the C boundary by construction. See `tools/c-check.sh` for the native == C == C++ proof.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
