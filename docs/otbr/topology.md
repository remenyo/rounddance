# S3+H2 OTBR topology

Multiprocessor Zigbee board (matrix row per `SCOPE.md` §3): the S3
hosts Wi-Fi (management transport) plus the full rounddance stack,
while 15.4 lives on the H2 as radio firmware. This layout is
deliberately *not* the Thread layout — no Thread code, concepts, or
naming are inherited; only the host/RCP split shape is shared.

## Roles

- **S3 host**: PAN formation, addressing, retries, NWK/APS/ZDO/
  security/ZCL, commissioning. Talks to the H2 exclusively through
  the RCP wire protocol (`docs/otbr/protocol.md`, crate
  `rounddance-rcp`).
- **H2 RCP firmware** (out of repo scope; pinned by the
  `EmulatedRcp` contract model): 15.4 PHY only — CSMA, auto-ACK,
  energy detect, frame radiate/receive. Nothing above the MAC data
  plane, no Zigbee/Thread upper layers (radio SDK ceiling,
  `SCOPE.md` §2).

## Wiring (lab record, no hardware touched by this crate)

| S3 | H2 | Purpose | Verified |
|----|----|---------|----------|
| GPIO18 (TX) | GPIO23 (RX) | RCP commands S3→H2 | Lab-proven (both-sides UART logs) |
| GPIO17 (RX) | GPIO24 (TX) | RCP events H2→S3 | Lab-proven (both-sides UART logs) |
| GPIO7 | EN | Reset hold (host-driven) | **Unverified on this pair** — a 150 ms EN-low pulse left H2 uptime continuous, so the EN wire is unproven lab lore here; hard resets go through USB DTR / esptool instead |
| GPIO8 | GPIO9 (BOOT) | Boot select for RCP flashing | Unverified with EN (same caveat) |

UART 460800 baud 8N1, raw RCP frames. Constants
`S3_UART_TX_GPIO` … `RCP_UART_BAUD` in `rounddance-rcp` record this
table in code.

## Bring-up order

1. H2 strapped to RCP firmware (BOOT + EN sequence, out of scope).
2. S3 opens the reset handshake (`RcpDriver::reset`) and awaits
   `Ready` before any other command.
3. S3 provisions channel/PAN/addresses/power (idempotent sets,
   replayed from the driver cache after every handshake).
4. Normal operation: TX with confirm, async RX/energy events,
   timeout/retry and desync recovery per `docs/otbr/protocol.md`.

## Standing constraints on this path

- TX power capped at +10 dBm everywhere until human clears it
  (enforced by driver *and* firmware; wave-11 lab policy).
- H2 builds share the 15.4-driver ceiling: nothing above
  `esp_ieee802154` on the firmware side.
