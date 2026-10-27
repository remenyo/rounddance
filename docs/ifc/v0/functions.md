# IFC v0 — function inventory

Telco-style function interface: each deployable function below is a named
endpoint with owned state, a lifecycle, and versioned ops / events /
errors. Wire form for all of them: one CBOR [`Envelope`] per message
(`wire.md`); native-Rust and WASM-component projections in
`local-abi.md`. No ad-hoc cross-function channels are allowed once this
spec is adopted — if two functions exchange bytes, the exchange is an
op or event listed here (or in a later versioned amendment).

Interface ids live in `crates/rounddance-ifc/src/ids.rs`. Op ids
`0x00–0x0F` are reserved per interface (lifecycle/session); function
ops start at `0x10`. Every op names its confirm: either a dedicated
confirm op, or the `flags & WANTS_CONFIRM` reply convention from
`semantics.md`.

Conventions used in every entry:

- **Owned state**: what the function — and nobody else — stores.
- **Lifecycle**: `init` (cold, zeroed) → `start` (parameters bound) →
  `stop` (quiesce, complete or cancel outstanding) → `reset(cold?)`.
  After `stop`, no new ops are accepted (`NotReady`); confirms for
  already-accepted ops still drain.
- **Ordering**: per-sender FIFO per interface unless the op table says
  otherwise. Confirms may arrive out of order (matched by `seq`).

---

## 1. mac-driver (`IF_MAC_DRIVER = 0x01`)

The radio side: owns the 802.15.4 data/management service. Upper layers
see exactly the `rounddance-mac-sap` traits; this function is their
remote projection (`mac-sap-alignment.md`).

- Owned state: channel, PAN id, short/extended addresses, promiscuous
  flag, TX queue (depth = adapter provisioning, preallocated, never
  resized mid-transaction), pending-confirm table, energy-scan cache.
- Lifecycle: `init` (radio off) → `start(channel, pan, addrs)` →
  `stop` (TX queue drained-or-cancelled, radio parked) →
  `reset(cold)` (cold clears addressing, matching `MacMgmtSap::reset`).
- Ops: `DATA_REQ {dst, msdu, options, msdu_handle}` → confirm
  `DATA_CFM {msdu_handle, status, timestamp?}`; `DATA_CANCEL {handle}`;
  `SET_CHANNEL / SET_ADDRS / SET_PAN`; `ENERGY_SCAN {channel}` →
  confirm `ENERGY_CFM {max_energy}`; `RESET {cold}`.
- Events: `DATA_IND {src, lqi, timestamp?, msdu}` (unconfirmed stream).
- Errors: `QueueFull` (backpressure — upper layer retries or drops per
  its own policy), `FrameTooLong`, `InvalidChannel`, `NoAck`,
  `ChannelBusy`, `NotReady`, `UnknownHandle`, `Unsupported`, `RadioFault`.
- Ordering: requests FIFO; confirms by handle (any order); indications
  in reception order per sender.

## 2. nwk (`IF_NWK = 0x02`)

Network layer: addressing, routing, frame security processing hooks.

- Owned state: 16-bit short address, PAN id, neighbor table, routing
  table, route-discovery table, broadcast transaction table, frame
  counters (outgoing per key, incoming per neighbor — see
  security-handoff in `semantics.md`), radius default.
- Lifecycle: `init` → `start(as_coordinator | join:{pan, channel})` →
  `stop` (routing timers halted, tables retained) → `reset(cold)`
  (cold clears tables and counters).
- Ops: `NLDE_DATA_REQ {dst, nsdu, radius, options}` → `NLDE_DATA_CFM`;
  `NLME_JOIN / LEAVE / PERMIT_JOINING / RESET / SET_ATTR / GET_ATTR`.
- Events: `NLDE_DATA_IND`; `NLME_NETWORK_FORMATION_CFM`,
  `NLME_ROUTE_DISCOVERY_CFM`.
- Errors: `QueueFull`, `NoRoute`, `RouteDiscoveryFailed`, `FrameTooLong`,
  `NotReady`, `InvalidParameter`, `SecurityFail`.
- Ordering: per-destination FIFO for data; management confirms any order.

## 3. aps (`IF_APS = 0x03`)

Application support: endpoints, fragmentation, binding/group delivery,
acknowledgement and duplicate rejection.

- Owned state: endpoint table, binding table, group table, fragment
  transmit blocks + reassembly buffers (bounded, budgeted), retry
  sessions, duplicate-rejection cache.
- Lifecycle: `init` → `start(endpoints[])` → `stop` (reassembly
  buffers flushed, retry timers halted) → `reset(cold)`.
- Ops: `APSDE_DATA_REQ` → `APSDE_DATA_CFM`; `APSME_BIND / UNBIND /
  ADD_GROUP / REMOVE_GROUP / CLEAR_ALL`.
- Events: `APSDE_DATA_IND` (reassembled, deduped).
- Errors: `QueueFull`, `AsduTooLong`, `PeerCannotFragment`,
  `UnknownFragmentSupport` (the Fig 2-2 family — never guessed, always
  probed), `NoAck`, `SecurityFail`, `NotReady`.
- Ordering: per (dst endpoint, cluster) FIFO after reassembly; retries
  never reorder past a newer confirmed frame.

## 4. zdo (`IF_ZDO = 0x04`)

Device object: discovery, binding management, network management.

- Owned state: node descriptor, power descriptor, endpoint list,
  discovery cache, pending-request table.
- Lifecycle: `init` → `start` (after NWK up) → `stop` → `reset(cold)`.
- Ops: `NWK_ADDR_REQ / IEEE_ADDR_REQ / MATCH_DESC_REQ / BIND_REQ /
  UNBIND_REQ / MGMT_*` → matching `*_RSP` confirms.
- Events: `DEVICE_ANNCE_IND`, `LEAVE_IND`.
- Errors: `QueueFull`, `Timeout`, `NotFound`, `NotReady`,
  `InvalidParameter`.
- Ordering: request/response matched by transaction sequence; unsolicited
  indications any order.

## 5. security (`IF_SECURITY = 0x05`)

Keys, counters, challenge/response assists (incl. SE CBKE using the
ECQV construction — never X.509 for CBKE).

- Owned state: network key + key sequence number, link keys per partner,
  outgoing frame counters, incoming counter cache, CBKE ephemeral state
  (zeroized on completion/abort).
- Lifecycle: `init` (no keys) → `start(preconfigured | join-secure)` →
  `stop` (ephemerals zeroized, keys retained in NVM) →
  `reset(cold)` (cold destroys keys — explicit op only).
- Ops: `GET_KEY / SET_KEY` (privileged), `CHALLENGE_REQ`,
  `CBKE_START / CBKE_DATA / CBKE_ABORT`, `COUNTER_GET`.
- Events: `KEY_UPDATE_IND`, `COUNTER_NEAR_WRAP_WARN`.
- Errors: `QueueFull`, `SecurityFail`, `Unauthorized`, `NotReady`,
  `InvalidParameter`, `Aborted`.
- Ordering: counter-bearing ops strictly monotonic per key; CBKE
  messages lock-step per session.
- Handoff rule (normative for every binding): counters and keys never
  move backwards across reset, reconnect, or state migration. See
  `semantics.md`.

## 6. zcl-engine (`IF_ZCL_ENGINE = 0x06`)

Cluster library: frame encode/decode, attribute store, reporting.

- Owned state: attribute database, reporting configuration, scene/group
  membership views (owned by APS tables, cached here read-only),
  pending-report queue.
- Lifecycle: `init` → `start(clusters[])` → `stop` → `reset(cold)`.
- Ops: `COMMAND_REQ {cluster, cmd, payload}` → `COMMAND_CFM`;
  `READ_ATTR / WRITE_ATTR / CONFIGURE_REPORTING`.
- Events: `COMMAND_IND`, `ATTR_REPORT_IND`, `ATTR_CHANGED_IND`.
- Errors: `QueueFull`, `UnknownCluster`, `UnknownAttribute`,
  `UnsupportedCommand`, `InvalidType`, `NotReady`, `Timeout`.
- Ordering: per-cluster FIFO; reports coalesced but never reordered
  past a newer confirmed write.

## 7. commission (`IF_COMMISSION = 0x07`)

Classical, Touchlink, and Direct commissioning assists.

- Owned state: commissioning mode, open-network window timer,
  Touchlink transaction id, Direct bearer session (BLE capability
  handle — never our own BT stack).
- Lifecycle: `init` → `start(mode)` → `stop` (window closed, sessions
  aborted) → `reset(cold)`.
- Ops: `OPEN_NETWORK {timeout_s}` → `OPEN_CFM`; `TOUCHLINK_SCAN /
  TOUCHLINK_JOIN`; `DIRECT_ADVERTISE / DIRECT_JOIN`.
- Events: `DEVICE_JOINED_IND`, `JOIN_FAILED_IND`.
- Errors: `QueueFull`, `WindowExpired`, `NotReady`, `Aborted`,
  `Unsupported`.
- Ordering: one active session per bearer; join indications in join order.

## 8. sim-media (`IF_SIM_MEDIA = 0x08`)

Deterministic simulation medium: virtual time, seeded faults, scripted
topology. Same ops as `mac-driver` at the frame level, plus time/fault
control — sim and hardware stay behind one function shape.

- Owned state: virtual clock, RNG seed + stream position, link matrix
  (per-pair loss/delay/RSSI script), fault script cursor.
- Lifecycle: `init(seed)` → `start(script)` → `stop` (clock frozen,
  cursor retained for replay) → `reset(cold)` (cold clears to seed).
- Ops: `ADVANCE {ticks}` → `ADVANCE_CFM {delivered[]}`;
  `INJECT_FAULT / CLEAR_FAULTS`; same `DATA_REQ / DATA_IND` set as
  `mac-driver` (frames, not envelopes, cross here).
- Events: `DELIVERY_IND {frame, rssi, lqi, at_tick}`.
- Errors: `QueueFull`, `FrameTooLong`, `NotReady`, `InvalidScript`.
- Ordering: deliveries in virtual-tick order; same seed + script ⇒
  identical delivery sequence (decision determinism).

## 9. mgmt-agent (`IF_MGMT_AGENT = 0x09`)

State query, provisioning, diagnostics — the USB/operator face.

- Owned state: none protocol-critical; caches last-known snapshots of
  other functions (read-only, explicitly stale-able).
- Lifecycle: `init` → `start` (always available, even when the stack
  is down — diagnostics must work on a sick node) → `stop` →
  `reset(cold)`.
- Ops: `GET_STATE {function}` → `STATE_RSP`; `SET_PROVISIONING`;
  `GET_LOG {cursor}` → `LOG_RSP`; `DIAGNOSTIC {test_id}` → `DIAG_CFM`.
- Events: `ALARM_IND` (faults, counter-near-wrap, watchdog).
- Errors: `QueueFull`, `UnknownFunction`, `Unauthorized`, `NotReady`.
- Ordering: queries independent (any order); alarms in occurrence order.
