# IFC v0 — conformance map

The required per-binding test skeletons live as Rust integration
tests in `crates/rounddance-ifc/tests/` (they compile and pass
against the reference transports — run `cargo test -p rounddance-ifc`).
This file maps each requirement to its test.

| Requirement | Test file | What it proves |
|---|---|---|
| Envelope round-trip (loopback) | `tests/loopback.rs` | encode → frame → decode is lossless for small, empty, and 512-octet-max payloads; every `if_id` (0x00–0x09) survives; `MemLink` delivers both directions in order |
| Version-mismatch rejection | `tests/version.rs` | disjoint ranges → `REJECT`, both ends terminal-down, no app ops exchanged; forged out-of-range `ACCEPT` never brings the link up; fresh machines converge after a reject |
| Credit exhaustion | `tests/credit.rs` | full queue → `QueueFull` (never block/grow); drain-one admits exactly one send; `Credits<N>` models the same contract; `close` rejects sends but still drains |
| Reconnect-resume | `tests/reconnect.rs` | resume-at/forward/wrap accepted; rollback rejected; migrated snapshot with older counters rejected; wrong snapshot format rejected before counter comparison |
| Serial-pair (pty) transport | `tests/serial_pair.rs` | framed bytes cross a real OS pty pair both directions (partial reads included); decoder resynchronizes after line noise and delivers the next good frame |

Reference transports:

- `src/transport.rs` (`MemLink`): in-memory bounded queues, `no_std`,
  deterministic interleaving by hand — the binding every other test
  uses.
- `src/frame.rs` (`encode_frame` / `FrameDecoder`): the byte-stream
  binding shared by USB/UART and TCP; exercised over a real pty in
  `serial_pair.rs` via `libc::openpty` (dev-dependency only, tests are
  host-`std`).
- `src/handshake.rs`, `src/credit.rs`: pure state machines both
  transports rely on.

To add a binding (e.g. real `/dev/ttyACM0`, TCP socket): drive the
same five test bodies against the new byte stream. The bodies assert
on `Envelope` equality and `IfcError` variants only — no transport
internals — so they port unchanged.
