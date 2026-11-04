# rounddance-pchost

PC host runner: the radio (RCP) and half-host (NCP) roles the PC
plays against chip firmware over a serial UART. Host-only `std`
tool (like `lab-arbitrator`): it never builds for `no_std` or wasm
(the CI wasm job excludes it for exactly that reason).

- `rd-pchost --port /dev/ttyUSB1 --mode rcp --role coord [--target s31] [--capture run.bin]`
  owns the full stack on the PC (`CoordinatorApp` over
  `RcpDriver<SerialUart>`): probe → provision → form/permit/admit →
  MAC-command exchange → transport-key → announce → Node_desc →
  Toggle → Default Response. Exit 0 on the verified end state.
- `rd-pchost --port … --mode rcp --role joiner` runs the joiner
  side (scan → assoc → key → annce → lamp + toggle answer).
- `rd-pchost --port … --mode ncp …` commissions a half-host chip
  (form → permit → admit) and drives its lamp (toggle → Attr).

`SerialUart` is the production 460800 8N1 raw backend (`termios2`
+ `BOTHER`, DTR assert/pulse); the same `PcRunner`/`NcpRunner`
run over scripted FIFOs in `tests/` (see `pc_runner.rs`: two-node
form→join→toggle over RCP with real apps + NCP lamp drive +
target-probe matrix, and `serial_pty.rs`: the backend over a pty).

Serial access is arbitrated (one owner per port): reserve a lease
first (`arbitrator reserve --port …`), pass the by-id path,
release afterwards. Air runs log `RDHOST … <hex>` lines plus
`--capture` raw bytes for the sniffer + dual-serial leg.

License: Apache-2.0. Part of Rounddance.
