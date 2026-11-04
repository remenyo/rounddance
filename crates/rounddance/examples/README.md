# Examples

Small, runnable tours of every stack domain through the single-library
facade (`rounddance::…`). Each file is self-contained: build one frame
or run one decision, print the wire bytes, assert the round trip.

Run one: `cargo run -p rounddance --example <name>`
Run all: `for e in mac_beacon_req nwk_frame aps_binding zdo_descriptors security_replay zcl_frame gp_data_frame steering_election touchlink_scan compat_profile route_table rcp_frame ifc_envelope inspect_beacon bench_stack first_transaction sealed_frame; do cargo run -q -p rounddance --example $e || break; done`

| Example | Domain | What it shows |
|---------|--------|---------------|
| `mac_beacon_req` | MAC commands | Beacon-request build + parse + truncation refusal |
| `nwk_frame` | NWK codec | Minimal unicast header encode/decode round trip |
| `aps_binding` | APS tables | Bind, duplicate-collapse, destination lookup |
| `zdo_descriptors` | ZDO discovery | Node-descriptor build, logical type, 14-octet round trip |
| `security_replay` | Security | Replay-window accept/refuse/rewind/forget |
| `sealed_frame` | Security | CCM* seal/open + wrong-key refusal |
| `zcl_frame` | ZCL foundation | Global Read header encode/decode round trip |
| `gp_data_frame` | Green Power | Minimal SrcId GPDF encode/decode round trip |
| `steering_election` | Commissioning | Beacon survey → N-sighting election; phantom refusal |
| `touchlink_scan` | Touchlink | Transaction-bound scan frame codec round trip |
| `compat_profile` | 3.0-compat | 3.0 admission vs typed PRO refusal (no silent downgrade) |
| `route_table` | NWK routing | Install, next-hop forward, lifetime expiry |
| `rcp_frame` | RCP (S3+H2) | SYNC/LEN/KIND/SEQ/CRC16 encode + noise-hard streaming decode |
| `ifc_envelope` | Inter-module IFC | Versioned envelope wrap/unwrap |
| `inspect_beacon` | Inspector | Dissect a genuine on-air coordinator beacon |
| `bench_stack` | All layers | Portable per-op benchmark (host clock, no engine) |
| `first_transaction` | End-to-end | Host form → join → toggle, pinned decision digest |

Not covered here (target-bound, not runnable on host): `hal-esp`
on-device drivers, `hal-wasm` guest entry, `ffi` C ABI (see
`harness/c/`), `fw/` firmware images, `browser` bundle.
