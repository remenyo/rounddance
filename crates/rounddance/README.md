# rounddance (library facade)

One dependency over the Rounddance Zigbee-compatible stack. Each
protocol layer lives in its own crate (`no_std`-compatible core);
this crate re-exports them as modules (`rounddance::nwk`,
`rounddance::zcl`, …) so applications depend on a single library.

## Use

```toml
rounddance = { path = "../rounddance" }
```

```rust
use rounddance::host::scenario::{run_first_transaction, ScenarioConfig};
let outcome = run_first_transaction(ScenarioConfig::first_transaction());
```

## Examples

- `first_transaction`: form → join → toggle in software, prints the
  pinned decision digest. `cargo run -p rounddance --example first_transaction`
- `sealed_frame`: seal/open a frame under a network key, then watch a
  wrong key fail the integrity check. `cargo run -p rounddance --example sealed_frame`

Per-layer runnable demos also live in the layer crates
(`rounddance-hal-host --example host_transaction`,
`rounddance-hal-esp --example esp_adapter_shape`).

## Scope

Protocol layers, sim, host HAL, ESP HAL (host `MockDriver` path),
browser bindings, RCP codec, inspector, sniffer. Out of scope: the
`rounddance-ffi` C-ABI staticlib and the `fw/` ESP-IDF firmware images.
Status and air proofs: top-level PROGRESS.md / BLOCKERS.md.
