# RCP wire protocol (v0)

Host↔RCP framing and command classes for the S3+H2 path. Wire IDs
are rounddance constructions — no spec corpus covers this UART —
so this document *is* the authority, pinned by `rounddance-rcp`
unit vectors, codec fuzz, and the `EmulatedRcp` contract model.

## Framing

```text
SYNC | LEN | KIND | SEQ | payload[0..=128] | CRC16-LE
0xA5   1     1      1                       2
```

`LEN` = `KIND + SEQ + payload + CRC` (4..=132). CRC-16/CCITT
(`poly 0x1021`, `init 0xFFFF`) over `KIND|SEQ|payload`; reference
`"123456789" → 0x29B1`. Decoders resync by scanning for `SYNC`;
short/long `LEN` and CRC mismatches drop exactly one run and
re-arm. Max payload 128 = one 15.4 PSDU (127) + the one flags octet
below.

## Classes

Host→RCP: `0x01` Reset `[mode]` (0 warm / 1 cold), `0x02`
SetChannel `[ch]`, `0x03` SetTxPower `[dbm]`, `0x04` SetPanId
`[u16LE]`, `0x05` SetShortAddr `[u16LE]`, `0x06` SetExtAddr
`[u64LE]`, `0x07` TxFrame `[flags, psdu…]` (bit 0 = inter-PAN),
`0x08` EnergyScan `[ch]`, `0x09` GetVersion `[]` (empty),
`0x0A` SetPromiscuous `[mode]` (0 = filtered + HW auto-ACK,
1 = promiscuous).

RCP→host: `0x80` Ready `[fw]`, `0x81` TxConfirm `[seq, status]`
(0 delivered / 1 channel-busy / 2 no-ack), `0x82` RxFrame
`[flags, rssi, lqi, psdu…]`, `0x83` EnergyResult `[ch, energy]`,
`0x84` Error `[code]` (1 bad-command / 2 bad-channel /
3 power-capped / 4 not-ready), `0x85` Version
`[fw, proto, caps-LE, eui64]`.

## Discipline

- Sets are ack-less and idempotent; the driver replays its
  provision cache (channel/power/PAN/addresses plus the
  promiscuous/filtered mode) after every reset handshake.
- TX is single-flight: 20 ms timeout on the host clock, resend with
  a fresh sequence, 3 retries, then `NoAck`. `Ready` is the only
  handshake; `Ready` after a reset re-arms provisioning.
- 4 consecutive dropped runs open a reset handshake (warm);
  cold resets also clear both sides' addressing.
- Energy scans are split-phase (arm → poll → read).
- Association runs filtered: the host engages filtered + HW
  auto-ACK before associating (the coordinator only transports
  after an ACKed association response). The RCP latches the
  assigned short from its own association response first
  (SHORT-SNOOP, microseconds, before any slow path); the host's
  `SetShortAddr` confirm is the idempotent second copy, sent
  before any slow work so the milliseconds-later transport still
  matches. While a join ladder runs, the ladder owns RX — the
  ambient idle drain stays parked.
- Host-side recovery: `start_recovery` opens a warm reset with
  the TX queue preserved; a rebooted peer lands `Recovered`
  (cache replayed, session resumes), a dead peer lands `Failed`
  after 3 unanswered reset writes — new frames refuse cleanly,
  nothing wedges.

## v0 non-goals (follow-ups)

MAC header build/parse (SAP MSDUs ride verbatim; RX sources are
`AddrMode::None`), confirm/RX timestamps, per-request inter-PAN
retune (inter-PAN rides the tuned channel), fragmented PSDUs.
