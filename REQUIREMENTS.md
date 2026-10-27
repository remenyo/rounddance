# REQUIREMENTS.md — requirement ID scheme + traceability

## ID scheme

`<DOC>-<REV>-<CLAUSE>-<SEQ>`

- `DOC`: short document tag (e.g. `CORE`, `BDB`, `ZCL`, `GP`, `ZBD`,
  `SE`, `PRO`).
- `REV`: spec revision the requirement was extracted from (e.g.
  `R23`, `R40`, `V31`).
- `CLAUSE`: clause/section number within that revision (dots kept,
  e.g. `3.2.1`).
- `SEQ`: zero-padded sequence within the clause (e.g. `001`).

Example: `CORE-R40-3.2.1-001`.

## Traceability rule

Every requirement ID must trace both ways:

- **Up:** to its source document + revision + clause (document
  numbers and clause numbers only — never spec text, per D1).
- **Down:** to the covering page/section disposition, the
  implementing code or explicit N-A-with-cause, and the verifying
  test or sim run.

"Accounted for" vs "implemented" vs "verified" are tracked as
separate states per requirement. A spec version change reopens every
requirement sourced from the changed document.

## Wave-3 traceability — NWK frame codec (doc 05-3474-23 R23.2)

Seed IDs below are the paraphrased-requirement IDs from the private
corpus (`requirements-seed.md`); `§3.3/§3.4/§3.6.6` frame-layout IDs
are repo-minted (`05-3474-23-<clause>-<seq>`, dots stripped) pending
seed extraction of those clauses — wording in code/tests is paraphrase
only, never spec text (D1).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 05-3474-23-3211-01 | implemented + verified | `rounddance-nwk/src/nlde.rs`: `NldeDataRequest::associated` guard, `Error::NotAssociated` | `tests/vectors.rs::vector_unassociated_guard_05_3474_23_3211_01` |
| 05-3474-23-3211-02 | implemented + verified | `rounddance-nwk/src/nlde.rs`: `TxPipeline` early-confirm abort | `tests/vectors.rs::vector_early_confirm_aborts_05_3474_23_3211_02` |
| 05-3474-23-3211-03 | implemented + verified | `rounddance-nwk/src/nlde.rs`: `radius_for_request` | `tests/vectors.rs::vector_radius_mapping_05_3474_23_3211_03` |
| 05-3474-23-3211-04 | implemented + verified | `rounddance-nwk/src/nlde.rs`: `build_data_header` alias/normal source+seq | `tests/vectors.rs::vector_alias_vs_normal_source_05_3474_23_3211_04` |
| 05-3474-23-3211-05 | implemented + verified | `rounddance-nwk/src/nlde.rs`: `build_data_header` discover-route passthrough | `tests/vectors.rs::vector_discover_route_passthrough_05_3474_23_3211_05` |
| 05-3474-23-3213-01 | implemented + verified | `rounddance-nwk/src/nlde.rs`: `indication_for_local`; exercised via sim inbox path | `tests/vectors.rs::vector_inbound_delivery_guard_05_3474_23_3213_01`, `rounddance-sim/tests/nwk_transport.rs::nwk_loopback_decodes_identical_fields` |
| 05-3474-23-331-01 | implemented + verified | `rounddance-nwk/src/frame.rs`: `NwkHeader`, `encode_into`, `decode` (Fig. 3-4 order) | `tests/vectors.rs::vector_minimal_data_unicast_*`, `vector_full_command_header_*`, `vector_truncation_is_fallible_*`, `vector_presence_mismatch_*`; `tests/roundtrip.rs` fuzz round-trip |
| 05-3474-23-331-02 | implemented + verified | `rounddance-nwk/src/frame.rs`: `FrameControl`, `FrameType`, `DiscoverRoute` (Fig. 3-5) | `tests/vectors.rs::vector_frame_control_bits_*`, `vector_reserved_discriminants_rejected_*` |
| 05-3474-23-331-06 | implemented + verified | `rounddance-nwk/src/frame.rs`: broadcast + `dst_ieee` rejection (§3.3.1.6) | `tests/vectors.rs::vector_broadcast_never_carries_dst_ieee_*` |
| 05-3474-23-331-07 | implemented + verified | `rounddance-nwk/src/frame.rs`: `SourceRoute`, `MAX_SOURCE_ROUTE_RELAYS` (§3.3.1.8) | `tests/vectors.rs::vector_source_route_rules_*`, `tests/roundtrip.rs` |
| 05-3474-23-34-01 | implemented + verified | `rounddance-nwk/src/frame.rs`: `FrameControl::command` (§3.4 header rule) | `tests/vectors.rs::vector_command_headers_suppress_discovery_*` |
| 05-3474-23-366-01 | implemented + verified | `rounddance-nwk/src/frame.rs`: `BROADCAST_*` consts, `is_broadcast_addr`, `PAN_BROADCAST_LOOPBACK` (§3.6.6) | `tests/vectors.rs::vector_broadcast_addresses_*`, `rounddance-sim/tests/nwk_transport.rs::nwk_two_node_broadcast_handoff` |
