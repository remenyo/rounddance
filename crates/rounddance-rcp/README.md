# rounddance-rcp — S3+H2 OTBR path (host side)

The Zigbee stack runs on the S3 host; the H2 is a bare 15.4 RCP
across a UART. This crate owns the host side of that split:

| Module | Owns |
|--------|------|
| `frame` | UART transport framing (`SYNC/LEN/KIND/SEQ/payload/CRC16`), streaming resync decoder |
| `cmd` | RCP command classes (reset/channel/power/PAN/addr/TX/scan/version/mode) + event classes (ready/confirm/RX/energy/error/version) |
| `uart` | `Uart` seam + scripted FIFOs (the only hardware boundary) |
| `driver` | `RcpDriver`: `MacDataSap` + `MacMgmtSap` + `MacInterPanSap` over any `Uart`, timeout/retry on an injected clock, desync→reset recovery, version latch, assoc-short confirm, recovery state machine |
| `peer` | `EmulatedRcp`: scripted H2-firmware model (faults included: drops, corruption, dead peer) with filtered/promiscuous modes + assoc-short snoop for host/sim tests |

Why a new crate instead of an `otbr` submodule: no OpenThread/OTBR
stack is ported — the S3 runs the rounddance stack and the H2
firmware is out of scope. This is a radio-transport adapter in the
same seam shape as `rounddance-hal-esp`, named for the seam.

Wiring (documented, see `docs/otbr/topology.md`): S3-GPIO18→H2-GPIO23,
S3-GPIO17←H2-GPIO24, S3-GPIO7→H2-EN, S3-GPIO8→H2-GPIO9, 460800 8N1.

Standing lab policy is enforced in code on both sides: TX power
above +10 dBm is refused by the driver *and* the emulated firmware.

## Use

```rust
let mut driver = RcpDriver::new(my_uart);
driver.reset(true); // opens the reset handshake
// ... pump UART bytes, then:
driver.poll();
assert!(driver.ready());
driver.set_channel(Channel::new(15).unwrap()).unwrap();
```

`no_std`, `#![forbid(unsafe_code)]`, bounded + fallible. Tests:
`cargo test -p rounddance-rcp`; WASM:
`cargo check -p rounddance-rcp --target wasm32-unknown-unknown`.
Full-stack proof: `rounddance-sim/tests/rcp_otbr_path.rs`.
