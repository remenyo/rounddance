# IFC v0 — MAC SAP alignment gap list

Analysis only: how the current `rounddance-mac-sap` trait boundary
(`crates/rounddance-mac-sap/src/lib.rs`) maps onto IFC v0. NO code
changes to mac-sap in this wave; each row is keep / change / deprecate
guidance for the wave that implements it.

| # | Current mac-sap item | v0 verdict | Rationale / work |
|---|---|---|---|
| 1 | `MacDataSap::data_request` → `Result<TxHandle, MacError>` | **keep** | Exact IFC data-op shape: fallible, handle-matched confirm. Becomes `DATA_REQ` op with `msdu_handle = TxHandle.0`. |
| 2 | `MacDataSap::data_cancel` → `Result<(), MacError>` | **keep** | Matches cancellation semantics (`semantics.md` §2) verbatim, incl. `UnknownHandle`. |
| 3 | `poll_confirm / poll_indication` | **keep** | The poll-not-callback rule (`local-abi.md` §1.4) is taken FROM this design; all new functions copy it. |
| 4 | `tx_queue_free / tx_queue_capacity / tx_queue_full` | **keep** | Becomes the cross-function credit readout (`semantics.md` §1). Provided method `tx_queue_full` stays. |
| 5 | `MacError` taxonomy (10 variants) | **keep, extend per function** | Core 10 variants become the shared prefix; each function appends its own (`NoRoute`, `AsduTooLong`, …). `Display` strings stay log-safe (no payload bytes). |
| 6 | `MacMgmtSap::reset(cold)` | **keep** | Matches warm/cold reset semantics (`semantics.md` §4). Cold-clears-addressing is the template for all functions. |
| 7 | `set_channel / set_short_addr / set_extended_addr / set_pan_id` | **change** | Fold into fewer ops on the wire: one `SET_ADDRS {pan, short?, ext?}` + `SET_CHANNEL` (§1 function entry). Native trait keeps fine-grained setters (source-compat); WIT exposes the folded pair only. |
| 8 | `energy_scan` → `Result<u8, MacError>` | **change** | Split into `ENERGY_SCAN_REQ` + async `ENERGY_CFM` on the wire (scans outlast a single poll on real radios); native trait keeps the sync form where the HAL can answer inline, documents blocking budget where not. |
| 9 | `HasCapabilities / MacCapabilities` (6 flags) | **keep, widen** | Every IFC function gets its own capability struct with the same honest-reporting rule. Add `max_payload` and `max_queue_depth` numeric fields — v0 discovery needs budgets, not just booleans. |
| 10 | `Channel::new` checked constructor | **keep** | The validated-newtype pattern (`InvalidChannel` at construction) applies to all IFC address/mode types. |
| 11 | `TxOptions` bitflags (`ACK` only) | **change** | Add `WANTS_CONFIRM` bit (maps to envelope `flags` bit 0) and a `PRIORITY` bit for sim-media scheduling. Keep `bits()` accessor shape. |
| 12 | `TxConfirm.timestamp_us: Option<u64>` | **keep** | `Option`-timestamp + `frame_timestamping` flag is the template for all optional-HW-feature data. |
| 13 | `BoundedOctets<N>` / `FramePayload` | **keep** | The bounded-buffer primitive every function's payload types copy. Consider promoting to a shared `rounddance-buf` crate when the second function needs it (not this wave). |
| 14 | `MacSap` blanket impl (`T: Data + Mgmt`) | **keep** | The auto-combined-trait pattern applies to every function with data + management halves. |
| 15 | Module-level doc citations ("coverage pending") | **deprecate** | Per-item requirement IDs move to the corpus coverage system; IFC docs cite document numbers/clauses only (D1). Remove the "coverage pending" markers once MAC extraction lands. |
| 16 | `TxStatus::Delivered / NoAck / ChannelBusy / Cancelled` | **keep** | Becomes the shared delivery-status enum prefix; functions add their own terminal states after it. |
| 17 | Missing: version constant on traits | **change (add)** | Every trait needs `const VERSION: u8` (`local-abi.md` §1.7). mac-sap gets `const VERSION: u8 = 0` in the implementing wave. |
| 18 | Missing: link management surface | **change (add)** | Handshake/keepalive/close live BELOW the SAP (binding driver), never in mac-sap itself — but the driver MUST surface link-state (`NotReady` on down, `Closed` on peer-close) through existing error variants, no new SAP methods. |

Net: the mac-sap design is confirmed as the v0 template — 10 keeps,
6 narrow changes, 1 doc-hygiene deprecation, 0 removals. The wire
projection of `DATA_REQ / DATA_IND / DATA_CFM` is byte-compatible
with the trait field order (dst, msdu, options) so the host and C6
adapters share one codec.
