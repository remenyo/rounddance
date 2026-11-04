# Universal RCP radio firmware (`rd-rcp` engine + `rd-rcp-h2/c6/s31`)

The chip is a bare 15.4 radio speaking the RCP wire
(`docs/otbr/protocol.md`, crate `rounddance-rcp`): the PC
(`rd-pchost`) owns the full Zigbee stack. One engine, three thin
images:

| Image | Target | UART | Default pins | Caps bit |
|-------|--------|------|--------------|----------|
| `rd-rcp-h2` | `esp32h2` | UART1 | RX GPIO23 / TX GPIO24 (verified S3↔H2 pair) | `0x0100` |
| `rd-rcp-c6` | `esp32c6` | UART1 | RX GPIO16 / TX GPIO17 (unverified default) | `0x0200` |
| `rd-rcp-s31` | `esp32s31` | UART1 | RX GPIO15 / TX GPIO16 (unverified default) | `0x0400` |

Pin overrides without source edits (decimal, build-time):
`RD_RCP_RX_PIN` / `RD_RCP_TX_PIN`.

## Build

Each image is its own workspace (same shape as the standalone
images). From the image dir, with the IDF exported:

```text
source /home/dev/projects/esp-idf-v6/export.sh
cargo +esp check   # or: cargo +esp build
```

The S31 image vendors `esp-idf-sys`/`embuild` with the S31 chip
added (same shim as `rd-coord-s31`, see B-011); the H2/C6 images
use plain `esp-idf-sys 0.38`.

## Behavior

`run()` inits NVS + the 15.4 driver (receive running, promiscuous
until the host engages filtered + HW auto-ACK), installs UART1 at
460800 8N1, emits `Ready`, then serves the wire forever: per-class
apply (channel/power/PAN/addrs/promiscuous/TX/scan/version),
`TxConfirm` per TX (single-flight; host-contract breaks get an
`Error`, never a silent queue), `MacFrame` per RX with the real
arrival channel, SHORT-SNOOP latch programming the radio filter
immediately (same function the sim shares), energy results,
standing +10 dBm cap enforced. Console stays on USB-Serial-JTAG
(`RD-RCP-<TARGET>` lines); the RCP wire is UART1 only.

## Flash (Phase 2 owns execution)

Under an arbitrator lease, by-id path, backup-first +
readback-verify (standing approval):

```text
esptool.py --chip <esp32h2|esp32c6|esp32s31> read-flash 0x0 0x200000 backup.bin
esptool.py --chip … erase-flash
esptool.py --chip … write-flash 0x10000 rd-rcp-<target>.bin  # plus bootloader + partition-table per flasher_args.json
esptool.py --chip … verify-flash 0x10000 rd-rcp-<target>.bin
```

ELF → image: `esptool.py --chip <target> elf2image …` (the S31
path needs the IDF-native flow per B-011, not espflash).
