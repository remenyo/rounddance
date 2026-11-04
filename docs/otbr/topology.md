# PC↔radio topology (RCP) + half-host (NCP)

Multiprocessor Zigbee board (matrix row per `SCOPE.md` §3): the PC
(this dev machine, or any Linux host) runs the rounddance stack,
while 15.4 lives on the chip as radio firmware. This layout is
deliberately *not* the Thread layout — no Thread code, concepts, or
naming are inherited; only the host/RCP split shape is shared.

## Roles

- **PC host + RCP radio**: the PC owns PAN formation, addressing,
  retries, NWK/APS/ZDO/ security/ZCL, commissioning, talking to
  the chip exclusively through the RCP wire protocol
  (`docs/otbr/protocol.md`, crate `rounddance-rcp`, runner
  `rounddance-pchost`). The RCP firmware images (`fw/rd-rcp-h2`,
  `fw/rd-rcp-c6`, `fw/rd-rcp-s31`, shared engine `fw/rd-rcp`) are
  15.4 PHY only — CSMA, auto-ACK, energy detect, frame
  radiate/receive. Nothing above the MAC data plane, no
  Zigbee/Thread upper layers (radio SDK ceiling, `SCOPE.md` §2).
- **PC half-host + NCP chip** (new in v1): the chip runs the full
  stack plus the application endpoint; the PC commissions (form,
  permit, admit) and drives the lamp (toggle, attribute reports)
  over the same serial wire through the NCP frame family
  (`rounddance-rcp::ncp`, same runner binary with `--mode ncp`).
- **Standalone** (unchanged): `rd-coord`, `rd-coord-s31`,
  `rd-router`, `rd-joiner` boot the full stack on-chip and run
  with no PC attached. RCP/NCP flashing never disturbs them —
  switching roles is a reflash (backup-first, arbitrator lease),
  not a mode bit.

## Wiring (lab record, no hardware touched by the crates)

RCP wire is always 460800 baud 8N1 raw (`RCP_UART_BAUD`). The
firmware UART is UART1 by default; pins are build-time
overridable (`RD_RCP_RX_PIN` / `RD_RCP_TX_PIN`, decimal) so the
record below corrects without source edits.

| Chip | RCP RX (from host-TX) | RCP TX (to host-RX) | Reset | Console | Status |
|------|----------------------|---------------------|-------|---------|--------|
| H2 | GPIO23 | GPIO24 | DTR pulse / USB DTR+RTS via esptool / BOOT+EN strap | USB-Serial-JTAG | **Verified** — the S3↔H2 pair (S3-GPIO18→H2-GPIO23, S3-GPIO17←H2-GPIO24) carried the v0 link both directions with both-sides UART logs |
| C6 | GPIO16 (UART1) | GPIO17 (UART1) | DTR pulse / USB DTR+RTS via esptool (`esp32c6`) / BOOT+EN strap | USB-Serial-JTAG | **Unverified default** — pending the air proof; override via `RD_RCP_*_PIN` if the bench wiring differs |
| S31 | GPIO15 (UART1) | GPIO16 (UART1) | DTR pulse / USB DTR+RTS via esptool (`esp32s31`) / BOOT+EN strap | USB (CP2102N bridge on the lab unit) | **Unverified default** — pending the air proof; override via `RD_RCP_*_PIN` if the bench wiring differs |

S3-side record (the v0 origin pair, kept for the S3+H2 bench
shape): S3-GPIO18 (TX) → H2-GPIO23 (RX), S3-GPIO17 (RX) ←
H2-GPIO24 (TX); S3-GPIO7 → H2-EN is **unproven** (a 150 ms EN-low
pulse left H2 uptime continuous), S3-GPIO8 → H2-GPIO9 (BOOT)
unverified with the same caveat — hard resets go through USB DTR /
`esptool` instead. Constants `S3_UART_TX_GPIO` …
`RCP_UART_BAUD` in `rounddance-rcp` record the S3 side in code;
`Board::h2/c6/s31` in `fw/rd-rcp` record the firmware side.

Antenna note: Xiao-C6 onboard-ceramic select is GPIO3 LOW +
GPIO14 LOW (board code only; non-LOW/LOW banned without human
approval per the B-001 damage finding). S31/H2 boards must NOT
drive those pins (different front ends).

## Bring-up order

1. Chip strapped to RCP firmware (BOOT + EN sequence, or
   `esptool.py --chip <esp32h2|esp32c6|esp32s31> write-flash`
   under an arbitrator lease with backup-first + readback-verify).
2. PC opens the reset handshake (`RcpDriver::reset`, or
   `rd-pchost` which does it) and awaits `Ready` before any other
   command.
3. PC probes `query_version` → `Version` (fw/proto/caps/EUI +
   target name) and checks `--target` when given; PC provisions
   channel/PAN/addresses/power (idempotent sets, replayed from
   the driver cache after every handshake).
4. Normal operation: TX with confirm, async RX/energy events,
   timeout/retry and desync recovery per
   `docs/otbr/protocol.md`; MAC-command traffic (beacons,
   association) flows through the MAC queue.
5. NCP mode: `rd-pchost --mode ncp` resets, forms, permits,
   admits, and toggles through the NCP family instead.

## PC runner one-liners

```text
rd-pchost --port /dev/ttyUSB1 --mode rcp --role coord [--target s31] [--capture run.bin]
rd-pchost --port /dev/ttyUSB1 --mode rcp --role joiner
rd-pchost --port /dev/ttyUSB1 --mode ncp --role coord --admit a0f262fffe8597a4:0001
```

Serial access is arbitrated (one owner per port): reserve a lease
first (`arbitrator reserve --port …`), pass the by-id path, and
release afterwards. Air runs capture both sides: the runner's
`RDHOST … <hex>` stdout lines (air bytes) plus `--capture` raw
UART bytes, cross-checked against the nRF sniffer pcap.

## Standing constraints on this path

- TX power capped at +10 dBm everywhere until human clears it
  (enforced by driver *and* firmware; wave-11 lab policy).
- RCP/NCP builds share the 15.4-driver ceiling: nothing above
  `esp_ieee802154` on the firmware side.
