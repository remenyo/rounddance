# rounddance (library facade)

One dependency over the Rounddance Zigbee-compatible stack. Each
protocol layer lives in its own crate (`no_std`-compatible core);
this crate re-exports them as modules (`rounddance::nwk`,
`rounddance::zcl`, ...) so applications depend on a single library.

## Where it sits

```
your app (endpoints, behaviors, policy)
rounddance (this crate: one dependency, every layer)
+- commission (formation/steer/join)  direct (BLE)  compat (admission policy)
+- zdo (discovery/bind/mgmt)  zcl (clusters)  gp (proxy/sink)
+- aps (frames/frag/retry/tables)
+- security (keys/CCM*/counters/handshakes)
+- nwk (headers/routing)  ifc (envelopes/framing)
+- mac-sap (trait seam)
+- drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
+- harness: sim | observe: inspect/sniffer | embed: ffi/browser
firmware images: fw/ (ESP-IDF apps)   host runner: pchost (PC + radio chip)
```

Data flows down the left side (app -> APS -> security -> NWK -> MAC ->
driver) and back up as indications; `commission`/`roles`/`zdo`
orchestrate, `sim`/`inspect`/`sniffer` observe, `ffi`/`browser`
embed, `hal-*`/`rcp` radiate.

## API

One module per layer crate: `mac_sap`, `ifc`, `nwk`, `aps`,
`security`, `zdo`, `zcl`, `gp`, `commission`, `compat`, `direct`,
`roles`, `sim`, `host` (= hal-host), `hal_esp`, `hal_wasm`,
`browser`, `rcp`, `inspect`, `sniffer`. (`ffi` and `pchost` are
separate crates: C staticlib and host-runner binary respectively.)

## Use

```toml
rounddance = { path = "../rounddance" }
```

```rust
use rounddance::host::scenario::{run_first_transaction, ScenarioConfig};
let outcome = run_first_transaction(ScenarioConfig::first_transaction());
```

Examples (run from the workspace root):

- `first_transaction`: form -> join -> toggle in software, prints the
  pinned decision digest. `cargo run -p rounddance --example first_transaction`
- `sealed_frame` / `security_replay`: seal/open under a network key,
  then watch a wrong key fail the integrity check.
- `bench_stack`: portable host benchmark across the layers.
- Layer demos: `nwk_frame`, `zdo_descriptors`, `zcl_frame`,
  `aps_binding`, `steering_election`, `touchlink_scan`,
  `compat_profile`, `gp_data_frame`, `ifc_envelope`,
  `mac_beacon_req`, `rcp_frame`, `route_table`, `inspect_beacon`.

## Limits

Protocol layers, sim, host HAL, ESP HAL (host `MockDriver` path),
browser bindings, RCP codec, inspector, sniffer. Out of scope: the
`rounddance-ffi` C-ABI staticlib, the `rounddance-pchost` runner
binary, and the `fw/` ESP-IDF firmware images.

**Prerelease (`0.1.x`).** The API will change without deprecation
warnings until 1.0. Pin the exact version and expect breakage on
upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance);
report issues there, not here.
