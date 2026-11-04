# rounddance-commission

Commissioning: network formation, steering (discovery scan + survey ranking), finding/binding, Touchlink (scan/start/join/update + key-index negotiation), classical Trust-Center join (symmetric + install-code/MMO KDF + negotiation + rejoin/leave machines), and the relay-leg (`*_via`) builders plus secured-frame builder for Trust Center -> router -> grandchild delivery.

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- commission (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Takes scan results + Trust-Center policy + joiner credentials; emits formation/steering/join decisions and key-transport frames. Radio I/O and storage live outside.

## API

Modules: `formation` (formation machine), `steering` (discovery scan, survey ranking), `finding` (target/initiator), `touchlink` (initiator/target machines + codecs), `classical` (TrustCenter, Joiner/Rejoin/Leave machines, install-code validation), `transport` (key-transport frames + `*_via` relay form), `secured` (NWK-secured frames + `*_via` relay form), `keyprov`, `mmo`.

## Use

```toml
rounddance-commission = { path = "../rounddance-commission" }
```

```rust
use rounddance_commission::formation::{FormationMachine, FormationRequest};
```

Example: `crates/rounddance/examples/steering_election.rs` (`cargo run -p rounddance --example steering_election`).

## Limits

Radio I/O and nonvolatile storage live outside; SIM + host HAL show the wiring. Rekey and closed-network rate policy are application decisions built on these machines.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
