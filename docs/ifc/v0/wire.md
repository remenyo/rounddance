# IFC v0 — wire protocol

One envelope, three bindings. The CBOR [`Envelope`] (`local-abi.md`)
is the payload on every binding; only the transport framing differs.

## 1. Framing (USB/UART)

```text
frame  = FLAG stuffed(inner) FLAG
inner  = LEN:u16BE | body | CRC16-CCITT:u16BE
body   = CBOR envelope (<= 640 octets incl. CBOR overhead)
FLAG   = 0x7E, ESC = 0x7D, escape = ESC (b ^ 0x20)
```

- `LEN` counts `body` octets only. CRC covers `body` only; length is
  protected by the length-exactness check after a CRC pass.
- Byte-stuffing applies to `inner` only; flags are never stuffed.
- A lone `FLAG` mid-frame aborts the partial frame (resync). The
  sender re-drives completion via timeout (`semantics.md`); the link
  never deadlocks on noise.
- MTU: `body <= 640` octets. Rationale: one full 802.15.4 MSDU (116)
  plus envelope overhead plus margin, while staying small enough for
  ESP UART FIFOs and single-`read` pty scheduling. Larger APDUs are
  fragmented by the APS layer *above* IFC, never by IFC itself.
- Reference: `crates/rounddance-ifc/src/frame.rs` (`encode_frame`,
  `FrameDecoder`, CRC-16/CCITT-FALSE `poly 0x1021 init 0xFFFF` —
  test vector `crc16(b"123456789") == 0x29B1`).

## 2. Message envelope

```text
envelope = [ version:uint, if_id:uint, op:uint,
             seq:uint, flags:uint, payload:bytes ]
```

CBOR array of 6, shortest-form integers, one encoding per value
(canonical — trace comparison stays deterministic). `seq` is the
per-direction rolling counter (`semantics.md`). `flags` bit 0 =
wants-confirm; bits 1–7 reserved-zero on send, ignored on receive.
Unknown `if_id` → drop + `UnknownInterface` diagnostic; unknown `op`
→ drop + `UnknownOp`. Never guess, never trap.

## 3. Version negotiation handshake

Every link opens with (iface `0x00`):

```text
dialer   -> HELLO   { min_version, max_version }
listener -> ACCEPT  { chosen }        -- min <= chosen <= max on both sides
         -> REJECT  { max_supported }  -- ranges disjoint, link stays down
```

- `chosen` = highest version in the intersection. v0 endpoints offer
  `[0, 0]`; a v0 listener rejects any dialer with `min > 0`.
- Rejection is not sticky: fresh state machines may retry (e.g. after
  upgrade). A forged/out-of-range `ACCEPT` never brings the link up —
  the dialer checks `chosen` against its own range.
- Reference: `handshake.rs` (`Dialer` / `Listener` state machines —
  pure, no I/O, unit-tested both directions).

## 4. Keepalive

- `PING { nonce:u16 }` → `PONG { nonce }` echo, on iface `0x00`.
- Either side may ping when idle longer than its keepalive period
  (default 30 s host, 120 s constrained). Missing `PONG` within the
  binding timeout (`semantics.md`) marks the link suspect; two
  consecutive misses close it (`CLOSE { reason=timeout }` if writable).
- Keepalive frames carry no function state and never consume `seq`
  (they ride `seq = last_tx`, duplicated-safe).

## 5. IP/loopback binding

Same envelope, two transports:

- **TCP**: the exact §1 byte stream (flags, stuffing, CRC). Colocation
  assumption: loopback or link-local only in v0; no TLS (declared,
  not provided — management over IP inherits the host's boundary).
- **UDP**: one datagram = one unstuffed `inner`
  (`LEN | body | CRC`). No flags/escapes (datagram edges replace
  them). Oversize-for-MTU datagrams are never fragmented by IFC —
  the sender must fit `body <= 640`; receivers drop short/long
  datagrams without reply.
- **Colocation declarations** (required per SCOPE.md §4: every split
  declares them): USB/UART assumes a physically present peer;
  TCP assumes loopback-or-link-local; UDP assumes a lossy medium and
  requires the confirm/timeout machinery above IFC for any op that
  needs delivery. Colocated functions (single-process sim, C6
  standalone) may use the in-memory reference transport directly.

## 6. CBOR encoding rules (and why CBOR)

Chosen: CBOR (RFC 8949 subset — uint, bytes, array only in v0).

- **Why not JSON**: no float, no whitespace ambiguity, binary-safe
  payloads, ~40% smaller on our envelope shape, canonical encoding
  is definable (shortest-form ints).
- **Why not postcard/bespoke-varint**: CBOR decoders exist on every
  target language (Deno/browser, Python tooling, Rust), so captures
  and the management agent stay inspectable without our code. The v0
  subset is small enough to hand-roll (60-line decoder, no dependency
  — the `no_std` core gains no third-party codec attack surface).
- **Why a subset**: v0 needs three types. The decoder rejects
  everything else (`Truncated`), so a v1 peer's richer types fail
  closed instead of misparsing. Widening the subset is a versioned
  change (minor if old decoders still reject cleanly, major if old
  senders must emit new types).
- Rules: shortest-form integers mandatory on send; receivers SHOULD
  accept non-shortest form but MUST NOT emit it (leniency keeps old
  captures decoding); indefinite lengths rejected; max decode budget
  = 640 octets input, 512 payload output.
