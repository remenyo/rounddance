# rounddance-sniffer

Live/offline capture front-end: probe driver, radio-header pcap ingest, dissect + report + pcap-out (`rd-sniff`), with an arbitrator lease guard so live runs never fight for ports.

## Where it sits

```
app endpoints (ZCL behaviors, IAS/price/metering)
commission (formation/steer/join)   direct (BLE)   compat (admission policy)
zdo (discovery/bind/mgmt)   zcl (clusters)   gp (proxy/sink)
aps (frames/frag/retry/tables)
security (keys/CCM*/counters/handshakes)
nwk (headers/routing)   ifc (envelopes/framing)
mac-sap (trait seam)               <-- sniffer (this crate)
drivers: hal-host (loopback) | hal-esp (ESP 15.4) | rcp (UART radio) | hal-wasm (guest)
harness: sim | observe: inspect/sniffer | embed: ffi/browser
```

Takes a serial probe or a pcap/text feed; emits dissected frames, reports, and pcap-out (`rd-sniff`). Live runs need a compatible sniffer probe; offline replay needs none.

## API

`live` (probe listener + framer + channel gate), `stream`/`run` (ingest + dissect + report + pcap-out), `bin/rd-sniff` (+ `lease_guard` for exclusive-port discipline).

## Use

```toml
rounddance-sniffer = { path = "../rounddance-sniffer" }
```

```rust
cargo run -p rounddance-sniffer --bin rd-sniff -- --help
```

Example: `crates/rounddance/examples/inspect_beacon.rs` (`cargo run -p rounddance --example inspect_beacon`).

## Limits

Live runs need a compatible sniffer probe and a free port; offline replays need only a pcap/text feed.

**Prerelease (`0.1.x`).** The API will change without deprecation warnings until 1.0. Pin the exact version and expect breakage on upgrade.

License: Apache-2.0 (see `LICENSE-APACHE`).
Part of [Rounddance](https://github.com/remenyo/rounddance); report issues there, not here.
