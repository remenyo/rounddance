# RCP wire protocol (v1)

Host↔RCP framing and command classes for the PC↔radio path (S3+H2
origin, now H2/C6/S31 universal). Wire IDs are rounddance
constructions — no spec corpus covers this UART — so this document
*is* the authority, pinned by `rounddance-rcp` unit vectors, codec
fuzz, and the `EmulatedRcp` contract model.

## Framing

```text
SYNC | LEN | KIND | SEQ | payload[0..=128] | CRC16-LE
0xA5   1     1      1                       2
```

`LEN` = `KIND + SEQ + payload + CRC` (4..=132). CRC-16/CCITT
(`poly 0x1021`, `init 0xFFFF`) over `KIND|SEQ|payload`; reference
`"123456789 → 0x29B1`. Decoders resync by scanning for `SYNC`;
short/long `LEN` and CRC mismatches drop exactly one run and
re-arm. Max payload 128 = one 15.4 PSDU (127) + the one flags octet
below. The NCP half-host family (below) reuses this envelope with a
disjoint KIND namespace, so one UART decoder serves both roles.

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
`[flags, rssi, lqi, psdu…]` (proto-1 legacy: no arrival channel —
the driver falls back to its provisioned channel), `0x83`
EnergyResult `[ch, energy]`, `0x84` Error `[code]` (1 bad-command /
2 bad-channel / 3 power-capped / 4 not-ready), `0x85` Version
`[fw, proto, caps-LE, eui64]`, `0x86` MacFrame `[flags, rssi, lqi,
channel, psdu…]` (proto-2: every frame carries its arrival
channel).

`proto` is `0x02` on v1 firmware (`0x01` = the frozen v0 shape:
verbatim MSDUs, no `0x86`). The driver speaks both: `0x82`
events still decode through the same MAC-header parse (below), so
old firmware and old captures keep working. `caps` bit `0x00FF`
is the v0 set (TX, promiscuous RX, energy scan, +10 dBm cap,
4-deep TX queue, extended addressing, version command, filtered
mode); v1 adds the radio-target bits `0x0100` H2 / `0x0200` C6 /
`0x0400` S31 (exactly one set by real firmware; the scripted peer
sets none). The universal PC runner (`rd-pchost`) probes
`query_version` first and names the radio from these bits — the
classes are identical on all three targets, so one runner works
everywhere.

## MAC header layer (v1, closes the v0 non-goals)

The host builds 802.15.4 headers; the firmware radiates and
forwards complete PSDUs verbatim and never classifies:

- `data_request` wraps the MSDU in a short-short intra-PAN header
  (`FC0 0x41` + AR bit when ACK is requested, `FC1 0x88`, MAC
  sequence, PAN-LE, dst-LE, src-LE — 9 octets) addressed from the
  provisioned PAN/short. Unprovisioned radios refuse `NotReady`
  (there is no source to put in the header); extended destinations
  refuse `Unsupported` (short-only path, mirroring `EspAdapter`).
- `interpan_request` builds the broadcast inter-PAN header (11
  octets, unacknowledged) and **retunes per request**: when the
  requested channel differs from the provisioned one the driver
  emits `SetChannel` first, so the peer is on the right channel
  before the frame.
- Accounting is enforced before air: MSDU ≤ 116 (the SAP bound)
  and header + MSDU + 2 FCS octets ≤ 127 (the PSDU ceiling), else
  `FrameTooLong` — never a truncation. An 11-octet inter-PAN
  header therefore caps its MSDU at 114 octets.
- Received PSDUs parse back into sources plus MSDUs. Data for our
  PAN lands on the PAN queue with the parsed short source; foreign
  PAN data rides the inter-PAN queue with its arrival channel;
  everything else (beacons, association traffic, polls) lands
  **verbatim on the MAC-command queue** with channel/RSSI/LQI for
  the upper layer to classify. Oversize-MSDU data frames (header
  parses, MSDU overflows the SAP bound) surface there too — visible,
  never silently dropped.
- Confirms and indications carry the injected-clock time
  (`timestamp_us = Some(now)`): host-arrival stamps, not SFD
  captures, and the capability flag says so.
- MAC commands travel as complete PSDUs through the `0x07` proxy:
  `transmit_mac` radiates them verbatim (single-flight shared with
  data, confirms on the normal confirm queue) and
  `poll_mac_indication` surfaces them. No new host→RCP class was
  needed; the only wire addition is the channel-tagged `0x86`.
- The association short is a two-copy latch: the firmware
  SHORT-SNOOPs its own association response at queue time
  (microseconds, programming the radio filter immediately so the
  milliseconds-later transport still matches) and the host's
  `SetShortAddr` confirm is the idempotent second copy. The snoop
  matches the current long-long `0x63cc` 25-octet shape naming the
  unit's PAN/EUI with a success status; wrong-PAN, foreign-EUI,
  denied, and `0xFFFF` responses never latch.

## NCP half-host family (v1)

Where RCP keeps every Zigbee layer on the PC, NCP inverts the
split: the chip runs the full stack plus the application endpoint,
and the PC commissions and drives it over the same serial wire
(same SYNC/LEN/KIND/SEQ/CRC16 envelope, disjoint KINDs, fixed
shapes instead of CBOR — the firmware stays as small as the RCP
one; the `ifc` envelope stays available if the surface outgrows
fixed shapes).

Host→NCP: `0x20` Reset `[mode]`, `0x21` Form
`[channel, pan-LE, power]`, `0x22` Permit `[window-secs-LE]`,
`0x23` Admit `[eui64, short-LE]`, `0x24` Toggle `[short-LE]`,
`0x25` GetState `[]`. NCP→host: `0xA0` Ready `[fw]`, `0xA1`
Status `[state, joined]` (0 idle / 1 formed / 2
permit-open), `0xA2` Joined `[short-LE, eui64]`, `0xA3` Attr
`[short-LE, cluster-LE, value]`, `0xA4` Error `[code]` (1
bad-command / 2 bad-channel / 3 not-ready / 4 no-such-device /
5 table-full). Sets are fire-and-forget and idempotent; the PC
runner applies its own wall-clock budget above and re-asks.

## Serial discipline

460800 baud, 8N1, raw, no flow control (`SerialUart` in
`rounddance-pchost`: `termios2` + `BOTHER` exact rate, no
nearest-baud fallback; non-blocking I/O, backpressure as
`UartFull`). Reset paths, in order: DTR pulse (150 ms, drops an
RCP unit in download-park back into its firmware — `pulse_dtr`),
then USB DTR/RTS via `esptool.py --chip …` / BOOT+EN strap (see
`docs/otbr/topology.md` per-chip wiring).

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
  after an ACKed association response). While a join ladder runs,
  the ladder owns RX — the ambient idle drain stays parked.
- Host-side recovery: `start_recovery` opens a warm reset with
  the TX queue preserved; a rebooted peer lands `Recovered`
  (cache replayed, session resumes), a dead peer lands `Failed`
  after 3 unanswered reset writes — new frames refuse cleanly,
  nothing wedges.
- `MacFrame` PSDU budgets: the 128-octet envelope holds
  `flags+rssi+lqi` + up to 125 PSDU octets (`RxFrame`) or
  `flags+rssi+lqi+channel` + up to 124 (`MacFrame`); larger
  PSDUs refuse `TooLong` at encode time (the fuzzer caught the
  127-octet `MacFrame` overflow pre-release).

## Closed v0 non-goals

MAC header build/parse, RX sources, confirm/RX timestamps,
per-request inter-PAN retune, and the MAC-command path all closed
in v1 above. Remaining: fragmented PSDUs (no 15.4 fragmentation
exists on this path — oversize refuses `FrameTooLong` by design).
