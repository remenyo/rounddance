# IFC v0 — cross-cutting semantics

Normative verbs for backpressure, cancellation, timeouts, reset, state
transfer, and security handoff. Every binding and every function in
`functions.md` implements these; per-function deviations are listed in
that function's entry, never assumed.

## 1. Backpressure (credit / queue-free polling)

Model: the sender owns a fixed number of outstanding-transaction slots
per direction (like `MacDataSap.tx_queue_free` on the MAC SAP).

- `send` on a full queue fails with `QueueFull` — never blocks, never
  grows, never drops silently. The *caller* decides: retry later, shed
  load, or fail the upper operation. No protocol decision may depend on
  allocator state (D5).
- The peer returns one credit per completed transaction (confirm,
  cancel-ack, or explicit credit op on streaming interfaces).
- Readouts `*_free / *_capacity` are advisory (racy by nature); the
  `QueueFull` return is authoritative.
- Sim media and the MAC driver share the exact verbs so the same upper
  layer runs unmodified on hardware and in sim.
- Reference: `credit.rs` (`Credits<N>`) and the `credit` conformance
  test (fill → `QueueFull` → drain-one → exactly-one-fits).

## 2. Cancellation

- `data_cancel(handle)` revokes one outstanding transaction. A revoked
  transaction that has not completed reports `Cancelled`; an already
  finished or unknown handle reports `UnknownHandle` (never silent).
- Cancellation is advisory to the peer: a confirm already on the wire
  still arrives and the sender matches it by handle — duplicate
  completion after cancel is normal, not an error.
- Abort of multi-message sessions (`CBKE_ABORT`, commissioning `stop`)
  zeroizes ephemeral state first, then confirms the abort.

## 3. Timeouts

- Every `wants-confirm` op has a caller-side timeout (default 5 s host,
  30 s constrained; commissioning joins up to 180 s — declared per op).
  Timeout ≠ failure of the operation: the confirm may still arrive and
  MUST still be matched by `seq`/handle (late confirms are normal on
  lossy bindings).
- Binding timeouts (keepalive miss × 2, handshake no-answer 10 s) close
  the link; function transactions survive link closure and resume by
  `seq` on reconnect (below).
- Sim virtual time: timeouts tick in virtual ticks, so seeded replays
  reproduce timeout races exactly.

## 4. Reset / reconnect

- `reset(cold=false)` (warm): queues drained-or-cancelled, credits
  zeroed, addressing and keys retained, `seq` counters RETAINED.
- `reset(cold=true)`: as warm, plus addressing/tables cleared per
  function; frame counters and keys follow the handoff rule (§6).
- Reconnect: fresh handshake (`wire.md` §3), then `RESUME { next_seq }`
  both directions. The peer replays unconfirmed transactions from that
  `seq` onward; already-completed `seq`s are never replayed (dedup by
  `seq` + handle).
- `seq` wrap (`0xFFFF → 0x0000`) is legal and expected. Wrap-aware
  comparison (`wrapping_behind` in `credit.rs`): `a` is behind `b`
  iff `a != b && b - a < 0x8000` on the ring.

## 5. State transfer (future migration skeleton)

Placement is static-first; live migration is research. v0 ships only
the versioned export/import *format* so later work cannot silently
invent a second one:

```text
snapshot = { format:1, function:if_id, next_tx_seq, last_rx_seq,
             outstanding:u16, function_state:bytes(CBOR, function-defined) }
```

- `format:1` is checked before any counter comparison.
- Import rule: apply only if neither counter moves backwards
  (`LinkSnapshot::check_against`). Violation → reject the whole
  snapshot (`BadFrame`), keep serving from live state.
- `function_state` is opaque to IFC; each function versions its own
  blob inside (its own `format` field first).
- Migration without the security handoff (§6) is a protocol violation,
  not a degraded mode.

## 6. Security-handoff constraints (normative)

- Frame counters and key state NEVER move backwards across reset,
  reconnect, snapshot import, or function migration. A stale snapshot
  is rejected, never applied.
- Keys cross function boundaries only through the `security` function
  ops (`SET_KEY`/`GET_KEY` privileged); raw key bytes never appear in
  `mgmt-agent` logs, sim traces, or error details.
- Ephemeral session state (CBKE, commissioning) is zeroized on abort,
  completion, and reset — before any confirm is emitted.
- Counter-near-wrap emits `COUNTER_NEAR_WRAP_WARN` (event) while the
  link still works; rekey/rejoin is the operator's job, triggered by
  that event, never silently skipped.
- No spec text is reproduced here (D1): only our own rules above.
