# rounddance-hal-esp

ESP 15.4 driver HAL plus coordinator/joiner/router apps over an injectable `Driver` seam (`MockDriver` on host): address/PAN/channel setup, TX power cap, TX confirm events, ISR-mailbox RX pump, energy scan, pending-data/indirect mode, plus the Trust-Center app (formation, permits, admits incl. grandchild-via-router learning, transport-key emission incl. relay leg, ZDO follow-through, toggle emission incl. routed leg) and the joiner/router apps.

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- hal-esp (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Implements the ESP 15.4 driver seam plus the coordinator/joiner/router apps over an injectable `Driver` (`MockDriver` on host). On-target paths need the `esp` feature + ESP-IDF toolchain.

## API

Modules: `driver` (`Driver` trait), `adapter` (`EspAdapter`, air-frame build/parse), `app` (`CoordinatorApp`, `JoinerApp`), `router_esp` (`RouterDevice` + `relay_for`/`nwk_dst_of`), `mock` (`MockDriver`), `mac_cmd`, `ffi` (raw 15.4 declarations), `esp` (target driver).

## Use

```toml
rounddance-hal-esp = { path = "../rounddance-hal-esp" }
```

```rust
use rounddance_hal_esp::mock::MockDriver;
let d = MockDriver::new();
```

Example: `crates/rounddance/examples/mac_beacon_req.rs` (`cargo run -p rounddance --example mac_beacon_req`).

## Limits

On-target code paths need the `esp` feature + ESP-IDF toolchain and real radio silicon; host tests cover the same logic over the mock driver.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
