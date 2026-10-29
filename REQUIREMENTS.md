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

## Wave-4 traceability — APS frame codec + fragmentation (doc 05-3474-23 R23.2 ch2)

All IDs below are repo-minted (`05-3474-23-<clause>-<seq>`, dots
stripped) with line anchors from the private corpus
(`text/zigbee-spec-r23-05-3474-23/p*.txt`, trailing spec line numbers;
`Fig2-2(render)` = decision-tree body mined from the PDF page render
`corpus/qa-shots/r23-p0066.png`, lost in text extraction per
`corpus/qa.md`), MINTED-pending-confirm like the wave-3 §3.3/§3.4/§3.6.6
IDs. Wording in code/tests is paraphrase only, never spec text (D1).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 05-3474-23-22511-01 | implemented + verified | `rounddance-aps/src/frame.rs`: `FrameControl` bit layout Fig 2-4 (anchor p0086-L2166-L2168) | `tests/vectors.rs::vector_minimal_unicast_data_*` |
| 05-3474-23-22511-02 | implemented + verified | `FrameType` values Table 2-20 (anchor p0087-L2170-L2174) | `tests/vectors.rs::vector_reserved_discriminants_*`, `tests/roundtrip.rs` fuzz |
| 05-3474-23-22511-03 | implemented + verified | `DeliveryMode` values Table 2-21 + broadcast endpoint rule (anchor p0087-L2175-L2182) | `tests/vectors.rs::vector_broadcast_data_*` |
| 05-3474-23-22511-04 | implemented + verified | `FrameControl::ack_format` (§2.2.5.1.1.3, anchor p0087-L2188-L2190) | `tests/vectors.rs::vector_data_ack_*`, `vector_command_ack_*` |
| 05-3474-23-22511-05 | implemented + verified | `FrameControl::ack_request` + broadcast/ack rules (§2.2.5.1.1.5 + §2.2.8.4.3, anchors p0088-L2194-L2199, p0102-L2460-L2463) | `tests/vectors.rs::vector_command_ack_*` (AR rejected) |
| 05-3474-23-22511-06 | implemented + verified | `FrameControl::ext_header` (§2.2.5.1.1.6, anchor p0088-L2200-L2203) | `tests/vectors.rs::vector_first_fragment_ext_header_*` |
| 05-3474-23-22511-07 | implemented + verified | `DataDest::Unicast/Broadcast`, endpoint consts (§2.2.5.1.2, anchor p0088-L2204-L2211) | `tests/vectors.rs::vector_minimal_unicast_data_*`, `vector_broadcast_data_*` |
| 05-3474-23-22511-08 | implemented + verified | `DataDest::Group` (§2.2.5.1.3, anchor p0088-L2212-L2216) | `tests/vectors.rs::vector_group_data_*` |
| 05-3474-23-22511-09 | implemented + verified | `DataHeader::cluster_id` (§2.2.5.1.4, anchor p0088-L2217-L2220) | `tests/vectors.rs::vector_minimal_unicast_data_*` |
| 05-3474-23-22511-10 | implemented + verified | `DataHeader::profile_id` (§2.2.5.1.5, anchor p0088-L2221-L2224) | `tests/vectors.rs::vector_minimal_unicast_data_*` |
| 05-3474-23-22511-11 | implemented + verified | `DataHeader::src_endpoint` (§2.2.5.1.6, anchor p0088-L2225-L2228) | `tests/vectors.rs::vector_minimal_unicast_data_*` |
| 05-3474-23-22511-12 | implemented + verified | `DataHeader::counter` (§2.2.5.1.7, anchor p0088-L2229-L2230) | `tests/vectors.rs::vector_minimal_unicast_data_*` |
| 05-3474-23-22511-13 | implemented + verified | `ExtHeader`, `Fragmentation` values Table 2-22 (anchors p0089-L2232-L2242) | `tests/vectors.rs::vector_first_fragment_ext_header_*`, `vector_reserved_discriminants_*` |
| 05-3474-23-22511-14 | implemented + verified | `ExtHeader::block_number` rules (§2.2.5.1.8.2, anchor p0089-L2243-L2250) | `tests/vectors.rs::vector_block_split_markers_*` |
| 05-3474-23-22511-15 | implemented + verified | `ExtHeader::ack_bitfield` (§2.2.5.1.8.3, anchor p0089-L2251-L2255) | `tests/vectors.rs::vector_fragmented_ack_bitfield_*` |
| 05-3474-23-22511-16 | implemented + verified | `DataHeader` encode/decode Fig 2-7 (§2.2.5.2.1, anchor p0089-L2261-L2270) | `tests/vectors.rs::vector_*_data_*`, `tests/roundtrip.rs` fuzz, `rounddance-sim/tests/aps_transport.rs` |
| 05-3474-23-22511-17 | implemented + verified | `CommandHeader` Fig 2-8 (§2.2.5.2.2.1, anchor p0090-L2278-L2288) | `tests/vectors.rs::vector_command_frame_*`, `tests/roundtrip.rs` fuzz |
| 05-3474-23-22511-18 | implemented + verified | `AckHeader` Fig 2-9 (§2.2.5.2.3.1, anchor p0090-L2294-L2313 + p0092-L2307-L2313) | `tests/vectors.rs::vector_data_ack_*`, `vector_command_ack_*`, `vector_fragmented_ack_bitfield_*`, `tests/roundtrip.rs` fuzz |
| 05-3474-23-22411-01 | implemented + verified | `DataDest`/`TxOptions` mapping of DstAddrMode 0x00–0x03 (Table 2-2, anchor p0062-L1633-L1654) | `tests/vectors.rs::vector_*_data_*` (mode coverage), sim broadcast/unicast |
| 05-3474-23-22411-02 | implemented + verified | TxOptions bits 0x01/0x02/0x04/0x08/0x10 (Table 2-2, corpus p0063 Table 2-2 rows) | `rounddance-sim/tests/aps_transport.rs::aps_loopback_*` (ack-request path) |
| 05-3474-23-22411-03 | implemented + verified | `BindingTable::lookup` fan-out, indirect/group/NWK-addr mapping (§2.2.4.1.1.3, anchor p0064-L1658-L1690) | `tests/vectors.rs::vector_binding_table_*` |
| 05-3474-23-22411-04 | implemented + verified | `RetrySession` confirm mapping (SUCCESS/NO_ACK/NWK-fail), always-on route discovery (§2.2.4.1.1.3, anchors p0065-L1705-L1713) | `tests/vectors.rs::vector_retry_machine_*` |
| 05-3474-23-22411-05 | implemented + verified | `plan_transmit` oversize-broadcast → ASDU_TOO_LONG (§2.2.4.1.1.3, anchor p0065-L1713-L1715) | `tests/vectors.rs::vector_fragment_plan_gates_fig2_2` |
| 05-3474-23-22411-06 | implemented + verified | `plan_transmit` local-support gate → ASDU_TOO_LONG (Fig 2-2, anchor p0066-Fig2-2(render)) | `tests/vectors.rs::vector_fragment_plan_gates_fig2_2` |
| 05-3474-23-22411-07 | implemented + verified | `plan_transmit` discovery gates → UNKNOWN_FRAGMENT_SUPPORT / PEER_CANNOT_FRAGMENT (Fig 2-2, anchor p0066-Fig2-2(render)) | `tests/vectors.rs::vector_fragment_plan_gates_fig2_2` |
| 05-3474-23-22411-08 | implemented + verified | `plan_transmit` receiver-buffer gate → ASDU_TOO_LONG (Fig 2-2, anchor p0066-Fig2-2(render)) | `tests/vectors.rs::vector_fragment_plan_gates_fig2_2` |
| 05-3474-23-22841-01 | implemented + verified | transmit-side joined-only expectation documented in `frag::plan_transmit` (§2.2.8.4.1, anchor p0101-L2406-L2408) | `tests/vectors.rs::vector_fragment_plan_gates_fig2_2` (gate coverage) |
| 05-3474-23-22841-02 | implemented + verified | `BindingTable::lookup` + delivery-mode selection (§2.2.8.4.1, anchor p0101-L2417-L2427) | `tests/vectors.rs::vector_binding_table_*` |
| 05-3474-23-22841-03 | implemented + verified | route-discovery-always-on expectation documented in `retry.rs` (§2.2.8.4.1, anchor p0103-L2431-L2434) | `rounddance-sim/tests/aps_transport.rs::aps_loopback_*` (DiscoverRoute::Enable under test) |
| 05-3474-23-22842-01 | implemented + verified | `GroupTable::members` group delivery (§2.2.8.4.2, anchor p0102-L2436-L2455) | `tests/vectors.rs::vector_group_table_*` |
| 05-3474-23-22842-02 | implemented + verified | `DupRejectTable` (DUP_TABLE_SIZE ≥ apscMinDuplicateRejectionTableSize; §2.2.8.4.2, anchor p0102-L2455-L2458) | `tests/vectors.rs::vector_duplicate_rejection_*`, sim replay-duplicate |
| 05-3474-23-22843-01 | implemented + verified | `RetrySession` wait/timeout rules (§2.2.8.4.3, anchor p0102-L2460-L2463) | `tests/vectors.rs::vector_retry_machine_*` |
| 05-3474-23-22843-02 | implemented + verified | `RetrySession::on_ack` matching rule (§2.2.8.4.4, anchor p0102-L2472-L2476) | `tests/vectors.rs::vector_retry_machine_*` |
| 05-3474-23-22844-01 | implemented + verified | `RetrySession` retransmit cap + NO_ACK confirm (§2.2.8.4.4, anchor p0102-L2483-L2498) | `tests/vectors.rs::vector_retry_machine_*` |
| 05-3474-23-22845-01 | implemented + verified | `plan_transmit` preconditions: acked-unicast only, no broadcast/multicast (§2.2.8.4.5, anchor p0103-L2500-L2509) | `tests/vectors.rs::vector_fragment_plan_gates_fig2_2` |
| 05-3474-23-22845-02 | implemented + verified | window-size-1 interop baseline documented in `frag.rs` (§2.2.8.4.5, anchor p0104-L2511-L2512) | `tests/vectors.rs::vector_block_split_markers_*` (single-block-stride compatible) |
| 05-3474-23-22845-03 | implemented + verified | `PeerFragCaps` discovery + cache (§2.2.8.4.5.1, anchor p0104-L2514-L2527) | `tests/vectors.rs::vector_fragment_plan_gates_fig2_2` |
| 05-3474-23-22845-04 | implemented + verified | `MAX_ASDU_OCTETS` ≥ Table 2-28 128-octet minimum (§2.2.8.4.5.2, anchor p0104-L2528-L2532) | `tests/vectors.rs::vector_reassembly_*` (120-octet ASDU E2E) |
| 05-3474-23-22845-05 | implemented + verified | `TxBlocks` split rules (§2.2.8.4.5.3, anchor p0104-L2533-L2548) | `tests/vectors.rs::vector_block_split_markers_*`, sim `aps_fragmented_asdu_*` |
| 05-3474-23-22845-06 | implemented + verified | `Reassembler` window/timeout/duplicate rules (§2.2.8.4.5.4, anchor p0105-L2557-L2589) | `tests/vectors.rs::vector_reassembly_*`, `tests/roundtrip.rs` fuzz, sim `aps_fragmented_asdu_*` |
| 05-3474-23-2271-01 | implemented + verified | `MAX_FRAME_RETRIES` = 3, `MIN_DUP_TABLE_SIZE` = 1, tick-mapped ack-wait (Table 2-23 §2.2.7.1, anchor p0092-L2323-L2327) | `tests/vectors.rs::vector_retry_machine_*`, `vector_duplicate_rejection_*` |
| 05-3474-23-229-01 | implemented + verified | `ApsStatus` codes 0x00/0xa0–0xb2 (Table 2-29 §2.2.9, anchors p0109-L2604-L2608 + p0110 Table 2-29) | `tests/vectors.rs::vector_status_codes_*` |
| 05-3474-23-22431-01 | implemented + verified | `BindingTable::bind` (TableFull/IllegalRequest/SUCCESS, §2.2.4.3.1.3, anchor p0073-L1840-L1848) | `tests/vectors.rs::vector_binding_table_*` |
| 05-3474-23-22431-02 | implemented + verified | `BindingTable::unbind` (SUCCESS/INVALID_BINDING, §2.2.4.3.3.3, anchor p0076-L1890-L1898) | `tests/vectors.rs::vector_binding_table_*` |
| 05-3474-23-22451-01 | implemented + verified | `GroupTable::add` (idempotent SUCCESS/TABLE_FULL/INVALID_PARAMETER, §2.2.4.5.1.3, anchors p0081-L2024-L2032 + p0082-L2033-L2038) | `tests/vectors.rs::vector_group_table_*` |
| 05-3474-23-22451-02 | implemented + verified | `GroupTable::remove_exact` (SUCCESS/INVALID_GROUP, §2.2.4.5.3.3, anchor p0076-context Table 2-17 rows) | `tests/vectors.rs::vector_group_table_*` |
| 05-3474-23-22831-01 | implemented + verified | `GroupTable` association shape (§2.2.8.3.1, anchor p0100-L2393-L2402) | `tests/vectors.rs::vector_group_table_*` |

## Wave-7 traceability — ZDO device/service discovery + descriptors + bind/mgmt basics (doc 05-3474-23 R23.2 §§2.3.2/2.4.3/2.4.4)

All IDs below are repo-minted (`05-3474-23-<clause>-<seq>`, dots
stripped) with line anchors from the private corpus
(`text/zigbee-spec-r23-05-3474-23/p*.txt`, trailing spec line numbers),
MINTED-pending-confirm like the wave-3/4 NWK/APS IDs. Seed-confirmed
inputs consumed: `05-3474-23-22411-14` (Node_Desc_req as the
fragmentation-capability probe) and BDB `22-65816-030-111-03`
(initiators pull simple descriptors and match clusters) /
`22-65816-030-111-04` (initiators bind unicast or group with addressing
modes 0x03/0x01). Wording in code/tests is paraphrase only, never spec
text (D1).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 05-3474-23-24311-01 | implemented + verified | `rounddance-zdo/src/cluster.rs`: request cluster IDs 0x0000–0x0006 + 0x0013/0x0021/0x0022/0x0034/0x0036/0x0038 (Table 2-43 §2.4.3.1, anchor p0126-L3091-L3094) | `tests/vectors.rs::vector_cluster_ids_*`, `vector_ieee_addr_pair_*` |
| 05-3474-23-244-01 | implemented + verified | `rounddance-zdo/src/status.rs`: `ZdpStatus` codes 0x00/0x80–0x85/0x89–0x8B + `Unknown` preservation (spellings anchored p0174-L4273-L4277, p0178-L4305-L4307, p0126-L3083-L3088; values MINTED-pending-confirm) | `tests/vectors.rs::vector_status_codes_*` |
| 05-3474-23-244-02 | implemented + verified | `response_cluster` (response = request \| 0x8000; attested `NWK_addr_rsp` 0x8000, anchor p0174-L4273-L4274) | `tests/vectors.rs::vector_response_clusters_*` |
| 05-3474-23-24311-02 | implemented + verified | `NwkAddrReq` + `RequestType` single/extended (Table 2-44, anchor p0127-L3098-L3099) | `tests/vectors.rs::vector_nwk_addr_req_*`, `tests/roundtrip.rs` fuzz |
| 05-3474-23-24421-01 | implemented + verified | `NwkAddrRsp` single/extended + assoc bound (answer §2.4.4.2.1) | `tests/vectors.rs::vector_nwk_addr_rsp_*`, `tests/roundtrip.rs` fuzz |
| 05-3474-23-24422-01 | implemented + verified | `IeeeAddrReq`/`IeeeAddrRsp` mirror pair (answer §2.4.4.2.2, anchor p0177-L4288) | `tests/vectors.rs::vector_ieee_addr_pair_*`, `tests/roundtrip.rs` fuzz |
| 05-3474-23-2323-01 | implemented + verified | `NodeDescriptor` 14-octet codec (fields §§2.3.2.3.1–3.13, anchors p0114-L2733 through p0117-L2808) | `tests/vectors.rs::vector_node_desc_fields_*`, `tests/roundtrip.rs` fuzz |
| 05-3474-23-24311-03 | implemented + verified | `NodeDescReq` (Table 2-46, anchor p0130-L3170-L3171) | `tests/vectors.rs::vector_node_desc_pair_*`, sim `zdo_node_desc_transaction_two_node` |
| 05-3474-23-24423-01 | implemented + verified | `NodeDescRsp` success-only descriptor + borrowed trailing TLVs (answer §2.4.4.2.3, anchor p0178-L4303-L4331) | `tests/vectors.rs::vector_node_desc_pair_*`, `vector_node_desc_rsp_edge_*`, sim transaction |
| 05-3474-23-2324-01 | implemented + verified | `PowerDescriptor` 2-octet nibble codec (§§2.3.2.4.1–4.4, anchors p0117-L2809 through p0118-L2830) | `tests/vectors.rs::vector_power_desc_fields_*`, `tests/roundtrip.rs` fuzz |
| 05-3474-23-24311-04 | implemented + verified | `PowerDescReq` (Table 2-47, anchor p0131-L3190-L3191; unicast rule anchor p0131-L3192-L3198) | `tests/vectors.rs::vector_power_desc_pair_*` |
| 05-3474-23-24424-01 | implemented + verified | `PowerDescRsp` (answer §2.4.4.2.4, anchor p0131-L3199-L3201) | `tests/vectors.rs::vector_power_desc_pair_*` |
| 05-3474-23-2325-01 | implemented + verified | `SimpleDescriptor` bounded codec (Table 2-40, anchors p0119-L2835-L2842) | `tests/vectors.rs::vector_simple_desc_fields_*`, `tests/roundtrip.rs` fuzz |
| 05-3474-23-24311-05 | implemented + verified | `SimpleDescReq` (§2.4.3.1.5 Table 2-48, anchor p0131-L3202-L3206) | `tests/vectors.rs::vector_simple_desc_pair_*` |
| 05-3474-23-24425-01 | implemented + verified | `SimpleDescRsp` length-octet framing | `tests/vectors.rs::vector_simple_desc_pair_*` |
| 05-3474-23-24311-06 | implemented + verified | `ActiveEpReq` (§2.4.3.1.6 Table 2-49, anchor p0132-L3218-L3222) | `tests/vectors.rs::vector_active_ep_pair_*` |
| 05-3474-23-24426-01 | implemented + verified | `ActiveEpRsp` counted list | `tests/vectors.rs::vector_active_ep_pair_*`, `tests/roundtrip.rs` fuzz |
| 05-3474-23-24426-02 | implemented + verified | `EndpointTable::active_endpoints` local-only listing | `tests/vectors.rs::vector_endpoint_table_match_*` |
| 05-3474-23-24311-07 | implemented + verified | `MatchDescReq` (§2.4.3.1.7 Table 2-50, anchor p0132-L3233-L3238) | `tests/vectors.rs::vector_match_desc_pair_*`, `tests/roundtrip.rs` fuzz |
| 05-3474-23-24427-01 | implemented + verified | `MatchDescRsp` | `tests/vectors.rs::vector_match_desc_pair_*` |
| 05-3474-23-2325-02 | implemented + verified | `EndpointTable` bounded insert/get/remove + `match_desc` complementary-cluster logic | `tests/vectors.rs::vector_endpoint_table_match_*` |
| 05-3474-23-24425-02 | implemented + verified | `endpoint_answerable` guard (ZDO/broadcast endpoints not answerable) | `tests/vectors.rs` via table tests |
| 05-3474-23-24311-11 | implemented + verified | `DeviceAnnce` (§2.4.3.1.11 Table 2-51, anchor p0134-L3263-L3267) | `tests/vectors.rs::vector_device_annce_*`, `tests/roundtrip.rs` fuzz |
| 05-3474-23-24322-01 | implemented + verified | `BindEntry` + `BindDstMode` group/extended codecs (bind §2.4.3.2.2, anchor p0138-L3388) | `tests/vectors.rs::vector_bind_req_*`, `tests/roundtrip.rs` fuzz |
| 05-3474-23-24322-02 | implemented + verified | `BindManager::bind` over borrowed APS `BindingTable`/`GroupTable` (no duplication) | `tests/vectors.rs::vector_bind_manager_tables_*` |
| 05-3474-23-24323-01 | implemented + verified | `BindEntry` decode shared with unbind (unbind §2.4.3.2.3 Table 2-56, anchor p0140-L3408-L3409) | `tests/vectors.rs::vector_bind_req_extended_*` |
| 05-3474-23-24323-02 | implemented + verified | `BindManager::unbind` (absent entry → not-found) | `tests/vectors.rs::vector_bind_manager_tables_*` |
| 05-3474-23-24432-01 | implemented + verified | `BindRsp` status-only response | `tests/vectors.rs::vector_bind_req_extended_*` |
| 05-3474-23-24335-01 | implemented + verified | `MgmtLeaveReq` (§2.4.3.3.5, anchor p0145-L3530-L3531) | `tests/vectors.rs::vector_mgmt_leave_*`, `tests/roundtrip.rs` fuzz |
| 05-3474-23-24335-02 | implemented + verified | `MgmtLeaveRsp` | `tests/vectors.rs::vector_mgmt_leave_*` |
| 05-3474-23-24337-01 | implemented + verified | `MgmtPermitJoiningReq` (§2.4.3.3.7, anchor p0146-L3555-L3556) | `tests/vectors.rs::vector_mgmt_permit_joining_*`, `tests/roundtrip.rs` fuzz |
| 05-3474-23-24337-02 | implemented + verified | `MgmtPermitJoiningRsp` | `tests/vectors.rs::vector_mgmt_permit_joining_*` |
| 05-3474-23-24339-01 | implemented + verified | `MgmtNwkUpdateReq` (Table 2-64, anchor p0149-L3626) | `tests/vectors.rs::vector_mgmt_nwk_update_*`, `tests/roundtrip.rs` fuzz |
| 05-3474-23-24339-02 | implemented + verified | `MgmtNwkUpdateNotify` scan report, energy count = channel popcount (§2.4.3.3.9.3, anchors p0151-L3696-L3709) | `tests/vectors.rs::vector_mgmt_nwk_update_*` |
| 05-3474-23-232-01 | implemented + verified | `ZdoError`: every decoder fallible, oversize counts rejected, never truncating | `tests/roundtrip.rs::fuzz_malformed_never_panics` |

## Wave-8 traceability — classical security + ECQV/CBKE foundations (docs 05-3474-23 R23.2 ch4, 07-5356 SE 1.4a §§5/C.4.2)

Classical IDs are repo-minted (`05-3474-23-<clause>-<seq>`, dots
stripped) with line anchors from the private corpus
(`text/zigbee-spec-r23-05-3474-23/p*.txt`, trailing spec line numbers),
MINTED-pending-confirm. CBKE IDs are repo-minted (`07-5356-<clause>-<seq>`,
lettered appendix clauses kept, e.g. `C4224` = C.4.2.2.4) with anchors
from `text/smart-energy-07-5356-22/p*.txt`, MINTED-pending-confirm.
Wording in code/tests is paraphrase only, never spec text (D1).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 05-3474-23-4311-01 | implemented + verified | `FrameCounter::take` monotonic handoff, `CounterExhausted` forces rekey (§4.3.1.1, anchor p0421-L10119-L10123) | unit `outgoing_counter_monotonic_and_exhausts`, `tests/vectors.rs::vector_counter_replay_pair`, `tests/roundtrip.rs::fuzz_counter_monotonicity` |
| 05-3474-23-4312-01 | implemented + verified | `ReplayTable::check` strict-advance accept, evict-stalest bound (§4.3.1.2, anchor p0422-L10156-L10164) | `tests/vectors.rs::vector_counter_replay_pair`, `vector_replay_eviction`, `tests/roundtrip.rs::fuzz_counter_monotonicity`, sim replay-attack rejection |
| 05-3474-23-434-01 | implemented + verified | `NvmStore` + `RamStore`, `COUNTER_STRIDE` resume rule, watermark checkpoints (§4.3.4, anchor p0425-L10232-L10236: counters survive factory reset) | `tests/vectors.rs::vector_nvm_resume_stride`, sim `key_rotation_and_counter_persist_across_reboot` |
| 05-3474-23-446-01 | implemented + verified | `KeySet` two-phase rotation, `select` covers in-flight frames (§4.4.6, anchor p0446-L10756-L10759) | `tests/vectors.rs::vector_key_lifecycle`, sim rotation test |
| 05-3474-23-451-01 | implemented + verified | `AuxHeader` control/counter/ext-source/key-id codec (§4.5.1, anchors p0479-L11436-L11440 + p0480-L11461-L11462) | `tests/vectors.rs::vector_aux_*`, `vector_aux_truncation`, `tests/roundtrip.rs::fuzz_aux_header_roundtrip`, sim secured-frame E2E |
| 05-3474-23-B11-01 | implemented + verified | `aes.rs`: AES-128 block encryption feeding the B.4 hash (Annex B.1.1, anchors p0541-L13284-L13286 + p0541-L13296-L13300); repo-minted, MINTED-pending-confirm | `tests/vectors.rs::vector_aes128_published_cipher_check` (published cipher check) |
| 05-3474-23-451-02 | implemented + verified | `KeyIdMode` 2-bit selector, `KeyIdentifier` shapes (§4.5.1.1.2–1.1.3, anchors p0480-L11453-L11457) | `tests/vectors.rs::vector_aux_index`, `vector_aux_source4`, `vector_aux_source8_ext_nonce` |
| 05-3474-23-453-01 | implemented + verified | `NetworkKey` 16-octet descriptor + sequence (§4.5.3, anchor p0481-L11490) | `tests/vectors.rs::vector_key_lifecycle` |
| 05-3474-23-462-01 | implemented + verified | `LinkKeyEntry` + `LinkKeyTable` per-device keys with directional counters (§4.6.2, anchor p0482-L11530-L11534) | `tests/vectors.rs::vector_link_key_table_*` |
| 07-5356-C4224-01 | implemented + verified | `ImplicitCert` opaque 48-octet type (ICU layout anchor p0169-L4365-L4368; CBKE concept anchors p0149-L3853-L3857 + p0167-L4302-L4306) | `tests/vectors.rs::vector_host_handshake_known_answers` (cert bytes in transcript), unit `cert_is_opaque_48_octets` |
| 07-5356-C4224-02 | implemented + verified | `PeerIdentity` cert + 8-octet subject + reconstruction point (field anchors p0169-L4370-L4374) | `tests/vectors.rs::vector_host_handshake_known_answers`, `vector_mock_determinism` |
| 07-5356-C42-03 | implemented + verified | `reconstruct_static` SEC4-style pure logic over `EccBackend` (anchor p0169-L4370-L4372) | `tests/vectors.rs::vector_host_handshake_known_answers` (`REC_*` == `base_mul(W_*)`) |
| 07-5356-C42-04 | implemented + verified | `mqv_agree` two-pass combination, implicit-signature scalars (anchors p0168-L4321-L4322 shared key, L4325-L4326 no unilateral control) | `tests/vectors.rs::vector_host_handshake_known_answers` (`KEY_I` == `KEY_R`) |
| 07-5356-C42-05 | implemented + verified | `session_keys` domain separation + `confirm_tag` MACU/MACV (anchor p0168-L4323-L4325; failure anchor p0167-L4278) | `tests/vectors.rs::vector_host_handshake_known_answers` (`MACU`/`MACV` pins + tamper wipe), unit `session_keys_are_domain_separated` |
| 07-5356-C42-06 | implemented + verified | `CbkeSession` explicit state machine, canonical transcript, fallible errors (anchor p0167-L4302-L4306) | `tests/vectors.rs::vector_host_handshake_known_answers` (two-sided Done), unit `full_mock_handshake_single_side`, `responder_role_uses_mac_v_first`, sim secured-frame E2E (keys installed by this flow) |

## Wave-9 traceability — ZCL engine + first clusters (doc 07-5123-08)

Corpus-mined IDs below are reused verbatim from the full-corpus sweep
(`requirements-wave-full-corpus.md`); engine-gap and cluster IDs are
repo-minted (`07-5123-08-<clause>-<seq>`, dots stripped) with line
anchors from the private corpus (`text/zcl-07-5123-08/p*.txt`,
trailing spec line numbers), MINTED-pending-confirm. Wording in
code/tests is paraphrase only, never spec text (D1).

One disposition note: `07-5123-08-822-04` (sleepy poll until enrolled)
is accounted-for with N-A-with-cause at this layer — the poll cadence
is app/HAL-owned; the engine exposes `EnrollStage` for it. Everything
else below is implemented + verified.

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 07-5123-08-231-01 | implemented + verified | `cluster.rs`: `ClusterRole` server/client descriptor split | `tests/vectors.rs::vector_onoff_definition_*` (role asserts) |
| 07-5123-08-231-02 | implemented + verified | `frame.rs`: `FrameControl::encode` zeroes bits 5–7 | `tests/vectors.rs::vector_frame_control_bits_*` |
| 07-5123-08-232-01 | implemented + verified | `frame.rs`: `FrameControl::decode` ignores bits 5–7 | `tests/vectors.rs::vector_frame_control_bits_*` |
| 07-5123-08-232-02 | implemented + verified | `frame.rs`: `Header::decode` returns trailing octets as payload | `tests/roundtrip.rs::fuzz_header_roundtrip` |
| 07-5123-08-2321-01 | implemented + verified | `dispatch.rs`: per-side `dispatch` call documented for fan-out | `tests/vectors.rs::vector_dispatch_integration_onoff` |
| 07-5123-08-233-01 | implemented + verified | `dispatch.rs`: `check_manufacturer` gate | `tests/vectors.rs::vector_manufacturer_gate_*` |
| 07-5123-08-2343-01 | implemented + verified | `types.rs`: `Value::default_for` (Non-Value else zero) | `tests/vectors.rs::vector_type_defaults_*` |
| 07-5123-08-2344-01 | implemented + verified | `attrs.rs`: `access` R/W/cond-W/P/S classes (anchor p0058-L2309-L2313) | `tests/vectors.rs::vector_attr_store_guards_*` |
| 07-5123-08-2345-01 | implemented + verified | `attrs.rs`: `add_globals` ClusterRevision on every store | `tests/vectors.rs::vector_attr_store_guards_*` |
| 07-5123-08-2345-02 | implemented + verified | `cluster.rs`: `ClusterDef::revision` reported via global | `tests/vectors.rs::vector_*_definition_*` |
| 07-5123-08-2345-04 | implemented + verified | `attrs.rs`: `ATTR_CLUSTER_REVISION` 0xfffd uint16 R (anchor p0058-L2315-L2318) | discovery vectors carry 0xFFFD/0x21 |
| 07-5123-08-2346-01 | implemented + verified | `attrs.rs`: no NVM writes here; config-vs-computed split documented | code inspection (persistence is app-owned) |
| 07-5123-08-241-01 | implemented + verified | `frame.rs` + `types.rs`: LE octet order throughout | every vector byte string |
| 07-5123-08-2411-01 | implemented + verified | `frame.rs`: header/payload split, Fig 2-2/2-3 geometry | `tests/vectors.rs::vector_header_manuf_presence_*` |
| 07-5123-08-2411-02 | implemented + verified | `frame.rs`: `FrameControl` bit layout (anchor p0060-L2369-L2372) | `tests/vectors.rs::vector_frame_control_bits_*` |
| 07-5123-08-2411-03 | implemented + verified | `frame.rs`: `FrameType` global/cluster-specific, reserved rejected (anchor p0060-L2374-L2376) | `tests/vectors.rs::vector_frame_control_bits_*`, `tests/roundtrip.rs::fuzz_header_roundtrip` |
| 07-5123-08-24111-01 | implemented + verified | `frame.rs`: manufacturer-code presence rule + `PresenceMismatch` | `tests/vectors.rs::vector_header_manuf_presence_*` |
| 07-5123-08-2412-01 | implemented + verified | `frame.rs`: `Direction` client/server marking | `tests/vectors.rs::vector_reply_header_*` |
| 07-5123-08-2412-02 | implemented + verified | `frame.rs`: `reply_to` sets disable bit on responses (anchor p0061-L2386-L2391) | `tests/vectors.rs::vector_reply_header_*` |
| 07-5123-08-2413-01 | implemented + verified | `frame.rs`: `reply_to` copies the transaction sequence | `tests/vectors.rs::vector_reply_header_*` |
| 07-5123-08-25-01 | implemented + verified | `dispatch.rs`: server-side discover/read/write support baseline | `tests/vectors.rs::vector_dispatch_integration_onoff` |
| 07-5123-08-25-02 | implemented + verified | `general.rs`: `cmd` Table 2-3 identifiers (anchor p0062-L2431-L2432) | `tests/vectors.rs::vector_general_ids_and_read_*` |
| 07-5123-08-251-01 | implemented + verified | `general.rs`: `decode_id_list` + per-identifier records | `tests/vectors.rs::vector_general_ids_and_read_*`, dispatch read |
| 07-5123-08-251-02 | implemented + verified | `dispatch.rs`: overflowing records shrink to INSUFFICIENT_SPACE, frame goes out as assembled | `tests/vectors.rs::vector_dispatch_integration_onoff` (11-octet tiny-buffer vector) |
| 07-5123-08-252-01 | implemented + verified | `general.rs`: `ReadRecord` echo + type/value gating | `tests/vectors.rs::vector_read_rsp_records_*` |
| 07-5123-08-252-02 | implemented + verified | `dispatch.rs`: fit-truncation instead of fragmentation | tiny-buffer vector above |
| 07-5123-08-253-01 | implemented + verified | `attrs.rs`: `write` validation order | `tests/vectors.rs::vector_attr_store_guards_*` |
| 07-5123-08-253-02 | implemented + verified | `general.rs`: `encode_write_rsp` all-success compaction | `tests/vectors.rs::vector_write_rsp_compact_*` |
| 07-5123-08-256-01 | implemented + verified | `dispatch.rs`: WRITE_NO_RSP silent fire-and-forget | code path (no reply arm) + `tests/roundtrip.rs` behavior fuzz |
| 07-5123-08-257-01 | implemented + verified | `reporting.rs`: per-attribute slots; arrays/composites never reportable | `tests/vectors.rs::vector_reporting_lifecycle_*` |
| 07-5123-08-257-02 | implemented + verified | `reporting.rs`: disable/default-restore/interval encodings | `tests/vectors.rs::vector_reporting_lifecycle_*` |
| 07-5123-08-257-03 | implemented + verified | `reporting.rs`: `change_qualifies` analog magnitudes, sign ignored | `tests/vectors.rs::vector_analog_threshold_*` |
| 07-5123-08-257-04 | implemented + verified | `reporting.rs`: `configure` validation chain + per-record statuses | `tests/vectors.rs::vector_reporting_lifecycle_*` |
| 07-5123-08-257-05 | implemented + verified | `reporting.rs`: `configure_timeout` supervision slots | `QueryAnswer::Timeout` path + query vectors |
| 07-5123-08-25-10-01 | implemented + verified | `reporting.rs`: `query` four-case statuses | `tests/vectors.rs::vector_report_cfg_query_*` |
| 07-5123-08-2511-01 | implemented + verified | `general.rs`: `ReportRecord` codec (anchor p0078-L2903-L2920) | `tests/vectors.rs::vector_report_and_default_rsp_*`, sim report leg |
| 07-5123-08-2511-02 | implemented + verified | `reporting.rs`: tick-clocked `tick` engine (periodic/discrete/analog rules anchor p0079-L2931-L2947) | `tests/vectors.rs::vector_reporting_lifecycle_*`, `vector_analog_threshold_*` |
| 07-5123-08-2512-01 | implemented + verified | `dispatch.rs` + `status.rs`: `should_default_respond` triage (anchors p0080-L2980-L2994 + p0081-L3001-L3016); sweep-2 correction applied: unicast-to-missing-cluster emits `UnsupportedCluster` 0xC3 (anchor p0081-L3010-L3012), never FAILURE | `tests/vectors.rs::vector_default_response_triage_*`, dispatch unknown-cluster vector (expects 0xC3) |
| 07-5123-08-2512-02 | implemented + verified | `dispatch.rs`: broadcast/multicast errors stay silent (anchor p0081-L3005-L3006) | `tests/vectors.rs::vector_default_response_triage_*` (broadcast leg) |
| 07-5123-08-2512-03 | implemented + verified | `status.rs`: legacy error codes receivable — `from_u8` maps 0x01/0x90/0x91/0x93 to `Failure` (anchor p0081-L3012-L3013); `Failure` never emitted for peer-visible triage | `tests/vectors.rs::vector_legacy_failure_receipt_tolerance_07_5123_08_2512_03` |
| 07-5123-08-2513-01 | implemented + verified | `general.rs`: `DiscoverAttrs` codec (anchor p0081-L3020-L3033) | `tests/vectors.rs::vector_discover_attrs_*` |
| 07-5123-08-2514-01 | implemented + verified | `discovery.rs`: `handle_discover_attrs` ascending capped pages + completion (anchors p0082-L3040-L3071) | dispatch discovery vector (6-record On/Off page) |
| 07-5123-08-2518-01 | implemented + verified | `discovery.rs`: `handle_discover_cmds` received/generated sets (anchors p0089-L3277-L3300 + p0090-L3308-L3329) | `tests/vectors.rs::vector_discover_cmds_*` + dispatch vector |
| 07-5123-08-262-01 | implemented + verified | `types.rs`: `DataType` wire identifiers (anchors p0098-L3511 + p0099–p0100 bodies) | `tests/vectors.rs::vector_datatype_ids_*` |
| 07-5123-08-262-02 | implemented + verified | `types.rs`: scalar bodies LE, bool admits 0x00/0x01, int sign extension (anchor p0100-L3517-L3531) | `tests/vectors.rs::vector_scalar_bodies_*`, `tests/roundtrip.rs::fuzz_value_roundtrip` |
| 07-5123-08-262-03 | implemented + verified | `types.rs`: short/long strings + packed scalar arrays, bounded + fallible (anchors p0102-L3588-L3593 + p0103-L3595-L3601 + p0104-L3647-L3653) | `tests/vectors.rs::vector_strings_arrays_*`, fuzz |
| 07-5123-08-263-01 | implemented + verified | `status.rs`: `ZclStatus` set + deprecated remap, never emitted (anchors p0107-L3731-L3736 + p0108 body) | `tests/vectors.rs::vector_status_remap_*` |
| 07-5123-08-381-01 | implemented + verified | `onoff.rs`: `REVISION` 2 (anchor p0172-L5051-L5052) | `tests/vectors.rs::vector_onoff_definition_*` |
| 07-5123-08-382-01 | implemented + verified | `onoff.rs`: `SERVER_ATTRS` table (anchor p0172-L5064-L5066) | definition + store vectors |
| 07-5123-08-382-02 | implemented + verified | `onoff.rs`: GlobalSceneControl set/clear rules (anchor p0173-L5067-L5080) | `tests/vectors.rs::vector_onoff_scene_paths_*` |
| 07-5123-08-383-01 | implemented + verified | `onoff.rs`: Off/On/Toggle + timer coupling (anchor p0175-L5101-L5119) | `tests/vectors.rs::vector_onoff_basic_effects_*`, sim toggle leg |
| 07-5123-08-383-02 | implemented + verified | `onoff.rs`: Off With Effect payload + receipt (anchors p0175-L5120-L5129 + p0176-L5130-L5141) | scene-paths vector (incl. reserved-effect refusal) |
| 07-5123-08-383-03 | implemented + verified | `onoff.rs`: Recall Global Scene discard/recall (anchor p0176-L5142-L5152) | behavior fuzz exercises the arm |
| 07-5123-08-383-04 | implemented + verified | `onoff.rs`: Timed Off validation + guard window + `tick_100ms` (anchors p0176-L5154-L5178 + p0177-L5179-L5194) | `tests/vectors.rs::vector_onoff_timed_off_*` |
| 07-5123-08-3101-01 | implemented + verified | `level.rs`: `REVISION` 3 (anchor p0182-L5270-L5271) | `tests/vectors.rs::vector_level_definition_*` |
| 07-5123-08-3102-01 | implemented + verified | `level.rs`: `SERVER_ATTRS` table (anchor p0184-L5320-L5322) | definition + store vectors |
| 07-5123-08-3102-02 | implemented + verified | `level.rs`: ExecuteIfOff gate (anchor p0185-L5342-L5357) | `tests/vectors.rs::vector_level_basics_*` (gate case) |
| 07-5123-08-3102-03 | implemented + verified | `level.rs`: with/without-On/Off coupling via `take_onoff_request` (anchor p0183-L5296-L5312) | level-basics vector (Some(true)/Some(false)) |
| 07-5123-08-3102-04 | implemented + verified | `level.rs`: Move-to-Level/Move/Step/Stop payloads + effects (anchors p0187-L5388-L5412 + p0188-L5413-L5432 + p0189-L5434-L5448 + p0190-L5449-L5465) | level-basics vector + client-encoding vector |
| 07-5123-08-425-01 | implemented + verified | `level.rs`: `level_guard` envelope refusal | level-basics vector (below-min write refused) |
| 07-5123-08-821-01 | implemented + verified | `ias_zone.rs`: `REVISION` 2 (anchor p0524-L11910-L11911) | `tests/vectors.rs::vector_ias_definition_*` |
| 07-5123-08-822-01 | implemented + verified | `ias_zone.rs`: `sender_allowed` CIE gate | `tests/vectors.rs::vector_ias_enrollment_*` (foreign refusal) |
| 07-5123-08-822-02 | implemented + verified | `ias_zone.rs`: sensitivity stored verbatim (order preserved) | modes vector (level round-trips) |
| 07-5123-08-822-03 | implemented + verified | `behavior.rs`: extension contract + stub enrollment proof | unit `enrollment_stub_flow_is_expressible` |
| 07-5123-08-822-04 | accounted-for, N-A-with-cause at this layer | poll cadence is app/HAL-owned; `EnrollStage` exposed for it | — (policy test belongs to the HAL wave) |
| 07-5123-08-822-05 | implemented + verified | `ias_zone.rs`: `on_attribute_written` binds only on committed CIE writes; never self-assigns | enrollment vector (hook path) |
| 07-5123-08-822-06 | implemented + verified | `ias_zone.rs`: `trigger_enroll_request` + enroll-on-Success | enrollment vector (full handshake) |
| 07-5123-08-822-07 | implemented + verified | `ias_zone.rs`: `check_bind` NOT_AUTHORIZED lockdown | enrollment vector (stranger vs CIE) |
| 07-5123-08-822-08 | implemented + verified | `ias_zone.rs`: NormalOp retains config, clears test bit + notifies | `tests/vectors.rs::vector_ias_modes_notify_*` (dedicated NormalOp leg) |
| 07-5123-08-822-09 | implemented + verified | `ias_zone.rs`: TestMode entry/exit + `tick_1s` expiry | modes-notify vector |
| 07-5123-08-822-10 | implemented + verified | `ias_zone.rs`: `emit_notification` geometry (status + zero ext + zone id + delay) | modes-notify vector (byte-geometry asserts) |

## Wave-10 traceability — Commissioning core (docs 22-65816-030 BDB v3.1, 05-3474-23 R23.2, 07-5123-08 ZCL §13.3)

BDB `22-65816-030-*` IDs below are corpus-mined (anchors from the
private corpus `text/pro-bdb-22-65816-030/p*.txt`, trailing spec line
numbers). R23.2 / ZCL IDs are repo-minted (dots stripped) with line
anchors from the private corpus (`text/zigbee-spec-r23-05-3474-23/`
and `text/zcl-07-5123-08/`), MINTED-pending-confirm. Wording in
code/tests is paraphrase only, never spec text (D1).

Consumed inputs (implemented by earlier waves, not re-implemented):
`05-3474-23-24311-07` + `05-3474-23-24427-01` (Match_Desc),
`05-3474-23-24322-02` (`BindManager` over APS tables),
`05-3474-23-24335-01` (MgmtLeaveReq), `05-3474-23-24311-11`
(DeviceAnnce), `05-3474-23-453-01` + `05-3474-23-446-01`
(key storage/rotation), `05-3474-23-451-01` (aux codec),
`07-5356-C42-04`/`-05`/`-06` (CBKE handshake behind the policy gate).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 22-65816-030-81-01 | implemented + verified | `formation.rs`: `FormationMachine` role gating, factory-reset-first, primary-then-secondary scan (anchors p0055-L1204-L1212 + p0057-L1217-L1226) | `tests/vectors.rs::vector_*_22_65816_030_81_01` |
| 22-65816-030-81-02 | implemented + verified | `formation.rs`: `FormationRequest` fully-parameterized invocation (anchor p0057-L1228-L1241) | `tests/vectors.rs::vector_primitive_params_*`, `vector_router_distributed_params_*` |
| 22-65816-030-81-03 | implemented + verified | `formation.rs`: confirm raises on-network + coordinator TC startup (anchor p0057-L1242-L1256) | `tests/vectors.rs::vector_success_raises_on_network_*`, `vector_router_no_tc_startup_*`, `vector_exhausted_channels_fail_*` |
| 22-65816-030-91-01 | implemented + verified | `steering.rs`: `DiscoveryScan` join-permitted-only, `SurveyTable`, rank-by-LQI select (anchors p0059-L1261-L1268 + p0060-L1280-L1296) | `tests/vectors.rs::vector_discovery_scan_shape_*`, `vector_bad_scan_fails_*`, `vector_candidate_ranking_*`, `vector_no_suitable_network_*` |
| 22-65816-030-91-02 | implemented + verified | `classical.rs`: `TrustCenter::exchange_key` + `on_verify_confirm` (anchors p0061-L1307-L1334) | `tests/vectors.rs::vector_symmetric_exchange_rules_*`, sim `two_node_secure_join_*` |
| 22-65816-030-91-03 | implemented + verified | `classical.rs`: `JoinerMachine` symmetric transcript + `JoinPolicy` gates (anchors p0063-L1344-L1370) | `tests/vectors.rs::vector_symmetric_join_transcript_*`, sim join + replay |
| 22-65816-030-91-04 | implemented + verified | `classical.rs`: `KeyAttributes::NEGOTIATED` marker + `TrustCenter::admit` method mapping (anchors p0065-L1381-L1398) | `tests/vectors.rs::vector_negotiation_join_transcript_*` |
| 22-65816-030-91-05 | implemented + verified | `classical.rs`: `JoinerMachine::on_negotiation_done` (network key + token, fatal-if-missing) (anchors p0066-L1410-L1442) | `tests/vectors.rs::vector_negotiation_join_transcript_*` (token-missing leg) |
| 22-65816-030-91-06 | implemented + verified | `classical.rs`: `JoinerMachine::close_out` CBKE support/required gate (anchors p0067-L1443-L1449) | `tests/vectors.rs::vector_cbke_required_gate_*` |
| 22-65816-030-111-01 | implemented + verified | `finding.rs`: `FinderTarget` on-network gate + identify timer + always-serve descriptors (anchors p0079-L1699-L1712) | `tests/vectors.rs::vector_target_needs_network_*` |
| 22-65816-030-111-02 | implemented + verified | `finding.rs`: `FinderInitiator` off-network fail, broadcast `0xffff`, answer logging (anchors p0082-L1725-L1736) | `tests/vectors.rs::vector_initiator_query_flow_*` |
| 22-65816-030-111-03 | implemented + verified | `finding.rs`: `match_request_for` + `match_clusters` advance/skip (anchors p0082-L1737-L1750) | `tests/vectors.rs::vector_cluster_matching_*` |
| 22-65816-030-111-04 | implemented + verified | `finding.rs`: `bind_entry_for` group 0x01 + push flag / unicast 0x03 + resolve-first (anchors p0082-L1750-L1765) | `tests/vectors.rs::vector_group_binding_*`, `vector_unicast_binding_needs_ieee_*` |
| 22-65816-030-56-01 | accounted-for, N-A at this layer | Snap-back is TC policy config; no reduced-mode state lives here — `TrustCenter::close` restores the closed stance (anchor p0033-L525-L529; wave-27 bonus-2 span correction: page p0033, not p0032) | code inspection (no reduced-mode state in this crate) |
| 22-65816-030-56-02 | implemented + verified | `classical.rs`: `TrustCenter::set_allow_list` + `admitted` (anchor p0033-L534-L539) | `tests/vectors.rs::vector_allow_list_and_timeout_*` |
| 22-65816-030-56-03 | implemented + verified | `classical.rs`: install-code-gated dynamic keys (anchor p0033-L542-L547); sweep-2 corrections applied: reflected CRC + LE check field, MMO derivation via `MmoJoinKdf` (`EccJoinKdf` retained as injection seam only) | `tests/vectors.rs::vector_install_code_validation`, `vector_install_code_derivation_mock` (MOCK provenance), `vector_install_code_crc_worked_22_65816_030_56_07`, `vector_install_code_mmo_worked_22_65816_030_56_08` |
| 22-65816-030-56-07 | implemented + verified | `classical.rs`: install-code CRC parameter set — poly 0x1021, init 0xFFFF, XOR-out 0xFFFF, reflected in/out, LE check field (anchors p0041-L811-L827) | `tests/vectors.rs::vector_install_code_crc_worked_22_65816_030_56_07` (BDB worked example 0xB5C3 frozen; BE + non-reflected variants rejected) |
| 22-65816-030-56-08 | implemented + verified | `mmo.rs` + `classical.rs::MmoJoinKdf`: AES-128 key derived via AES-MMO-128 over the full code (anchors p0041-L828-L834); repo-minted, MINTED-pending-confirm | security `tests/vectors.rs::vector_install_code_mmo_worked_key_22_65816_030_56_08` + `vector_aes128_published_cipher_check`, commission `vector_install_code_mmo_worked_22_65816_030_56_08` |
| 22-65816-030-56-04 | implemented + verified | `classical.rs`: `TrustCenter::tick` deadline eviction report (anchor p0033-L554-L561) | `tests/vectors.rs::vector_allow_list_and_timeout_*` (timeout leg) |
| 22-65816-030-57-01 | implemented + verified | `classical.rs`: `JoinMethod::Negotiation` advertisement surface (anchor p0034-L574-L577) | `tests/vectors.rs::vector_negotiation_join_transcript_*` |
| 22-65816-030-61-01 | implemented + verified | `formation.rs`: `LogicalType` role split (anchor p0035-L598-L605) | `tests/vectors.rs::vector_end_device_cannot_form_*`, role-param vectors |
| 07-5123-08-133-01 | implemented + verified | `touchlink.rs`: `TOUCHLINK_CLUSTER` 0x1000 + profiles (anchor p1130-L25917-L25919) | `tests/vectors.rs::vector_touchlink_command_ids` |
| 07-5123-08-13322-01 | implemented + verified | `touchlink.rs`: `rx::` command IDs 0x00/02/06/07/10/12/14/16 + utility 0x41/42 (anchor p1132-L25931-L25932) | `tests/vectors.rs::vector_touchlink_command_ids` |
| 07-5123-08-13323-01 | implemented + verified | `touchlink.rs`: `tx::` command IDs 0x01/03/11/13/15 + utility 0x40/41/42 (anchor p1144-L26292-L26295) | `tests/vectors.rs::vector_touchlink_command_ids` |
| 22-65816-030-121-01 | implemented + verified | `touchlink.rs`: `TouchlinkInitiator` scan→select→start/join skeleton (anchor p0085-L1787+) | `tests/vectors.rs::vector_touchlink_skeleton_handshake` |
| 22-65816-030-1211-01 | implemented + verified | `touchlink.rs`: `TouchlinkFrame` transaction binding (anchor p0091-L2007-L2012) | `tests/vectors.rs::vector_touchlink_frame_codec` |
| 22-65816-030-121-02 | implemented + verified | `touchlink.rs`: `scan_request` per-channel broadcast frame (anchor p0087-L1821-L1835) | `tests/vectors.rs::vector_scan_request_payload`, `vector_touchlink_scan_wire_ids`, TX via `broadcast_scan` |
| 22-65816-030-121-03 | implemented + verified | `touchlink.rs` + `mac-sap`: initiator scan broadcast through `InterPanTx`/`SapInterPan` over `MacInterPanSap` (anchors p0087-L1821-L1835 + p0091-L2008-L2010); repo-minted, MINTED-pending-confirm | `tests/vectors.rs::vector_touchlink_sap_adapter_transfer`, `rounddance-sim/tests/touchlink_interpan.rs::touchlink_interpan_scan_round_trip` + replay |
| 22-65816-030-122-01 | implemented + verified | `touchlink.rs`: `TouchlinkTarget` respond/start-or-join skeleton (anchor p0092-L2054-L2064) | `tests/vectors.rs::vector_touchlink_skeleton_handshake` (stale-transaction leg) |
| 22-65816-030-122-02 | implemented + verified | `touchlink.rs`: `scan_response` + `respond` transmit the scan response on the heard channel (anchor p0092-L2054-L2064); repo-minted, MINTED-pending-confirm | `tests/vectors.rs::vector_touchlink_scan_wire_ids`, sim round-trip + replay |
| 05-3474-23-3611-01 | implemented + verified | `formation.rs`: formation primitive params shape (anchor p0221-L5224) | `tests/vectors.rs::vector_primitive_params_*` |
| 05-3474-23-3613-01 | implemented + verified | `steering.rs`: beacon survey rows feed discovery (anchor p0249-L5842) | `tests/vectors.rs::vector_candidate_ranking_*` |
| 05-3474-23-36161-01 | implemented + verified | `steering.rs`: application-configured discovery scan (anchor p0222-L5278) | `tests/vectors.rs::vector_discovery_scan_shape_*` |
| 05-3474-23-32214-01 | implemented + verified | `classical.rs`: `TrustCenter::admit` + announce decode as the indication side (anchor p0260-L6171) | sim `two_node_secure_join_*` (announce match leg) |
| 05-3474-23-32215-01 | implemented + verified | `classical.rs`: `JoinerMachine::close_out` + verified promotion as the confirm side (anchor p0261-L6194) | `tests/vectors.rs::vector_symmetric_join_transcript_*`, sim replay |
| 05-3474-23-3615-01 | implemented + verified | `classical.rs`: `RejoinMachine` orphan→rejoin with checks gate (anchors p0223-L5334-L5349 + p0225-L5380-L5382) | `tests/vectors.rs::vector_rejoin_checks_*` |
| 05-3474-23-36111-01 | implemented + verified | `classical.rs`: `LeaveMachine::mgmt_leave_for` self-remove form (anchor p0266-L6285) | `tests/vectors.rs::vector_leave_forms` |
| 05-3474-23-36113-01 | implemented + verified | `classical.rs`: `LeaveMachine::mgmt_leave_for` parent-evict form (anchor p0146-L3540) | `tests/vectors.rs::vector_leave_forms` |

## Wave-11 traceability — Green Power proxy + sink (doc 14-0563-19 Green Power Basic v1.1.2)

All IDs below are corpus-mined (`corpus/requirements-wave-full-corpus.md`,
§Green Power). Anchors name the private-corpus page + line. Wording in
code/tests is paraphrase only, never spec text (D1). No repo-minted IDs
this wave. Bidirectional commissioning completion (replies to the GPD)
is structures + explicit stubs — the reply path is a follow-up wave.

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 14-0563-19-A11-01 | implemented + verified | `frame.rs`: `GP_ENDPOINT` 0xF2 | vector sink/proxy flows address the GP endpoint |
| 14-0563-19-A11-02 | implemented + verified | `frame.rs`: LE encode/decode throughout | every vector byte string |
| 14-0563-19-A141-01 | implemented + verified | `frame.rs`: `FrameType`/`AppId` discriminants, reserved/foreign rejection (anchor p0041-L778-L779 + p0041-L803-L804 + p0044-L897-L900) | `vector_minimal_data_srcid_*`, `vector_reserved_frame_type_*`, `vector_foreign_app_id_*` |
| 14-0563-19-A141-02 | implemented + verified | `frame.rs`: `ingress_check` RxAfterTx+auto-commissioning conflict (anchor p0041-L786-L787) | `vector_rx_after_tx_auto_comm_conflict_*` |
| 14-0563-19-A141-03 | implemented + verified | `frame.rs`: direction coding, GPD-originated default (anchor p0043-L844-L846) | `vector_proxy_direction_dropped_*`, `vector_minimal_data_srcid_*` |
| 14-0563-19-A141-04 | implemented + verified | `frame.rs`: maintenance bare shape, no ext/identity/security (anchor p0044-L886-L889) | `vector_maintenance_travels_bare_*` |
| 14-0563-19-A152-01 | implemented + verified | `proxy.rs`: `GpTxQueue` one pending per GPD + bounded lifetime, `MIN_BASIC_TX_QUEUE`/`MIN_FULL_TX_QUEUE` (anchor p0046-L960-L972) | `vector_tx_queue_single_per_gpd_*` |
| 14-0563-19-A152-02 | implemented + verified | `proxy.rs`: `TX_OFFSET_MS` 20 / `TX_OFFSET_MAX_MS` 25 / `TX_DURATION_MS` 10 (anchor p0046-L974-L990) | code inspection (tick-clocked queue honors the window) |
| 14-0563-19-A152-03 | implemented + verified | `frame.rs`: `ingress_check` level gating + commissioning-range drops (anchor p0047-L1019-L1023 + p0160-L4322-L4323) | `vector_reserved_security_level_*`, `vector_unsecured_commissioning_*`, `vector_maintenance_commissioning_range_*` |
| 14-0563-19-A153-01 | implemented + verified | `security.rs`: `GpNonce` address/counter/control construction, `GpKeyType` wire mapping (anchor p0048-L1063-L1068 + p0049-L1081-L1109) | `vector_nonce_construction_*`, `vector_key_type_wire_bits_*` |
| 14-0563-19-A162-01 | implemented + verified | `frame.rs`: `GpdId::check` reserved-identity rejection (anchor p0065-L1772-L1780) | `vector_reserved_srcid_*` |
| 14-0563-19-A163-01 | accounted-for, N-A at this layer | GPD-side receive capability is GPD-firmware-owned; infra side records the triggering `rx_after_tx` in notifications | `vector_rx_after_tx_request_passes_*` (flag survives to the sink) |
| 14-0563-19-A34-01 | implemented + verified | `proxy.rs`: `Blocklist` (≥10), `BASIC_PROXY_FUNCTIONALITY` fixed subset (anchor p0150-L4020 + p0151-L4030-L4033) | `vector_blocklist_capacity_*` |
| 14-0563-19-A34-02 | implemented + verified | `proxy.rs`: `ProxyTable::read_page` complete-entries-only pagination (anchor p0155-L4147-L4168) | `vector_proxy_table_read_pages_*` |
| 14-0563-19-A36-01 | implemented + verified | `proxy.rs`: alias/sink mapping fields on `ProxyTableEntry` (anchor p0158-L4222-L4230) | `vector_proxy_passing_frame_notifies_*` (alias carried on the notification) |
| 14-0563-19-A36-02 | implemented + verified | `proxy.rs`: `upsert`/`pair_remove` endpoint-scoped lifecycle (anchor p0158-L4246-L4270 + p0159-L4268-L4270) | `vector_proxy_pairing_lifecycle_*` |
| 14-0563-19-A36-03 | implemented + verified | `proxy.rs`: `ProxyCommissioning` commanded/windowed/pairing-sensitive mode (anchor p0158-L4231-L4239 + p0168-L4613-L4622) | `vector_proxy_commissioning_mode_*` |
| 14-0563-19-A36-04 | implemented + verified | `proxy.rs`: `ProxyNotification` cleartext command, no MIC, options bits (anchor p0161-L4355-L4366) | `vector_proxy_passing_frame_notifies_*`, sim `gp_proxy_sink_forwarding_two_node` |
| 14-0563-19-A36-05 | implemented + verified | `security.rs`: `GpReplay` strict-advance counters over `ReplayTable` (anchor p0184-L5227-L5231) | `vector_counter_monotonic_no_rollover_*`, `vector_proxy_replay_drops_fresh_advances_*` |
| 14-0563-19-A36-06 | implemented + verified | `sink.rs`: `SinkMachine::accept` counter+level gate, group forward, translate (anchor p0181-L5121-L5143) | `vector_sink_generic_translation_*`, `vector_sink_group_forward_*`, sim forwarding leg |
| 14-0563-19-A36-07 | implemented + verified | `sink.rs`: `TranslationTable::lookup` specific-supersedes-generic; `commissioning.rs`: `TranslationSeed` population (anchor p0191-L5377-L5384) | `vector_sink_compact_and_specific_rules_*`, `vector_uni_commissioning_populates_table_*` |
| 14-0563-19-A36-08 | implemented + verified | `sink.rs`: compact-group/all-commands matching rules (anchor p0189-L5329-L5332) | `vector_sink_compact_and_specific_rules_*` |
| 14-0563-19-A36-09 | implemented + verified | `sink.rs`: `VectorOption::matches` masked contact check (anchor p0192-L5419-L5434) | `vector_sink_contact_mask_match_*` |
| 14-0563-19-A38-01 | implemented + verified | `proxy.rs`: `BasicProxy::process` table→security→notify flow (anchor p0213-Fig97) | `vector_proxy_passing_frame_notifies_*`, `vector_proxy_no_entry_drops_*`, sim `gp_proxy_sink_forwarding_two_node` + `gp_forwarding_replay_is_deterministic` |

## Wave-12 traceability — device roles + router/app simultaneity (doc 05-3474-23 R23.2 §3.6.1 family)

All IDs below are repo-minted (`05-3474-23-<clause>-<seq>` / `-ROLES-<seq>`,
dots stripped) with anchors to the private corpus
(`text/zigbee-spec-r23-05-3474-23/p*.txt`, trailing spec line numbers),
MINTED-pending-confirm like the wave-3/4/7/10 minted IDs. Wording in
code/tests is paraphrase only, never spec text (D1).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 05-3474-23-3612-01 | implemented + verified | `rounddance-roles/src/lib.rs`: `DeviceRole` four-variant enum | `tests/vectors.rs` (each role exercised), `rounddance-sim/tests/roles_network.rs` |
| 05-3474-23-3612-02 | implemented + verified | `children.rs`: `ChildTable` bounded admit (dup/full refusal) | `coordinator_table_full_refuses_*`, fuzz `fuzz_child_table_never_panics` |
| 05-3474-23-3612-03 | implemented + verified | `children.rs`: `heard` keepalive + `age` lapse drop | `coordinator_child_aging_*`, `tick` keepalive path |
| 05-3474-23-3612-04 | implemented + verified | `indirect.rs`: `IndirectQueue` bounded hold + `expire` | `router_indirect_hold_and_poll_*` (hold path), tick expiry leg |
| 05-3474-23-3612-05 | implemented + verified | `indirect.rs`: `poll_deliver` oldest-first; `router.rs::serve_poll` empty-ack path | `router_indirect_hold_and_poll_*`, sim `indirect-delivered` leg |
| 05-3474-23-3612-06 | implemented + verified | `coordinator.rs`: `CoordinatorMachine` form/permit/admit lifecycle | `coordinator_formation_permit_admit_*` |
| 05-3474-23-3612-07 | implemented + verified | `coordinator.rs`: `open_permit` window + `tick` close-out gating | `coordinator_formation_permit_admit_*` (permit-expiry leg) |
| 05-3474-23-3612-08 | implemented + verified | `router.rs`: `RouterMachine` join/forward/admit/serve lifecycle | `router_join_forward_children_*`, sim roles run |
| 05-3474-23-3612-09 | implemented + verified | `enddevice.rs`: `EndDeviceMachine` poll/acked/missed cycle | `enddevice_poll_loss_rejoin_leave_*` (poll legs) |
| 05-3474-23-3612-10 | implemented + verified | `sleepy.rs`: `SleepyEndDeviceMachine` duty-cycle + agreed interval + sleep/wake on injected clock | `sleepy_duty_cycle_rejoin_*`, sim sleepy legs |
| 05-3474-23-3613-01 | implemented + verified | `router.rs`: `parent_lost`/`rejoin_done` (child table survives) | `router_rejoin_and_leave_*` |
| 05-3474-23-3613-02 | implemented + verified | `enddevice.rs`/`sleepy.rs`: 3-miss loss → rejoin (secured + trust-center paths via commission `RejoinMachine`); 3 is the implementation default for the configurable parent-link retry threshold (spec leaves the loss-declaration scheme to the implementation) | `enddevice_poll_loss_rejoin_leave_*`, `sleepy_duty_cycle_rejoin_*`, sim `sleepy-rejoined` leg |
| 05-3474-23-3613-03 | implemented + verified | `enddevice.rs`/`sleepy.rs`: `rejoin_done` optional new-parent adoption | `enddevice_poll_loss_rejoin_leave_*` (0x0002 adoption), sim rejoin-through-router leg |
| 05-3474-23-3616-01 | implemented + verified | `children.rs::remove`, `coordinator.rs`/`router.rs::remove_child`, `enddevice.rs::leave`, `sleepy.rs::leave` | `router_rejoin_and_leave_*`, `enddevice_poll_loss_rejoin_leave_*`, `sleepy_duty_cycle_rejoin_*` (leave legs) |
| 05-3474-23-2325-ROLES-01 | implemented + verified | `endpoint.rs`: `AppEndpoint` host interface + role-agnostic `EndpointTable` | `endpoint_attach_rejects_bad_ids_*`, sim thermostat registration |
| 05-3474-23-2325-ROLES-02 | implemented + verified | `endpoint.rs`: `RouterApp` route/app fairness pair, per-tick budgets `MAX_ROUTE_PER_TICK`/`MAX_APP_PER_TICK` | `router_serves_own_endpoint_while_forwarding_*`, `fairness_budgets_hold_under_flood_*`, sim `tick1 fwd=1 app=1` leg |

## Wave-14 traceability — Smart Energy + metering clusters (docs 07-5123-08 ZCL §§4.9/10.2/10.4/10.7, 07-5356 SE 1.4a §C.3.1/C.4.1)

ZCL IDs below are repo-minted (`07-5123-08-<clause>-<seq>`, dots
stripped) with line anchors from the private corpus
(`text/zcl-07-5123-08/p*.txt`, trailing spec line numbers). SE IDs
are repo-minted (`07-5356-<clause>-<seq>`, dots stripped) with
anchors from `text/smart-energy-07-5356-22/p*.txt`.
MINTED-pending-confirm like earlier waves. Wording in code/tests is
paraphrase only, never spec text (D1).

Corpus-mined IDs reused here: `07-5123-08-102-03` (price backlog ≥5 +
`NOT_FOUND` when empty), `07-5123-08-107-01..04` (suite negotiation,
identity-as-certificate, initiation guards; suite-2 field validation
collapses to `UNSUPPORTED_SUITE` since this build holds no suite-2
credentials), `07-5356-22-C311-01/02` + `-C312-01..10` (cluster flows;
`C311-01` network-leave is app policy above the layer).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 07-5123-08-1041-01 | implemented + verified | `metering.rs`: `CLUSTER_ID` 0x0702 (§10.4.1.3, anchor p0714-L16287) | `se_vectors.rs::vector_metering_store_defaults_07_5123_08_1042_01` |
| 07-5123-08-1041-02 | implemented + verified | `metering.rs`: `REVISION` 2 (§10.4.1.1, anchor p0713-L16283-L16285) | `se_vectors.rs` store-defaults test (revision const) |
| 07-5123-08-1042-01 | implemented + verified | `metering.rs`: reading set, mandatory delivered summation, 48-bit saturating `add_consumption` (§10.4.2.2.1, anchors p0714-L16299-L16302 + p0715-L16303-L16308) | `se_vectors.rs::vector_metering_store_defaults_*`, `vector_metering_consumption_saturates_*` (fuzzer-hardened clamp, not mask) |
| 07-5123-08-1042-02 | implemented + verified | `metering.rs`: formatting set 0x0300–0x0308 subset (anchor p0732-L16686-L16687 + Table 10-71 reconcile) | `se_vectors.rs::vector_metering_store_defaults_*` (table shape + ordering) |
| 07-5123-08-1042-03 | implemented + verified | `metering.rs`: `scaled_value` multiplier/divisor pairing, zero-divisor unitary (§10.4.2.2.4.2–4.3, anchors p0735-L16701-L16710) | `se_vectors.rs::vector_metering_scaling_07_5123_08_1042_03` |
| 07-5123-08-1042-04 | implemented + verified | `metering.rs`: `split_formatting` digit layout (§10.4.2.2.4.4, anchors p0735-L16712-L16725) | `se_vectors.rs::vector_metering_formatting_07_5123_08_1042_04` |
| 07-5123-08-1043-01 | implemented + verified | `metering.rs`: `decode/encode_get_profile` 1+4+1 layout (§10.4.3.3.1.1, anchors p0800-L18072-L18083) | `se_vectors.rs::vector_get_profile_codec_07_5123_08_1043_01` (exact bytes) |
| 07-5123-08-1043-02 | implemented + verified | `metering.rs`: `ProfileBuffer` newest-first ring + status/cap rules (anchors p0773-L17387-L17397 + p0800-L18083-L18086) | `se_vectors.rs::vector_profile_answer_07_5123_08_1043_02`, `se_roundtrip.rs::fuzz_profile_answer_stays_bounded`, sim `se_loop.rs` profile leg |
| 07-5123-08-491-01 | implemented + verified | `electrical.rs`: `CLUSTER_ID` 0x0B04 (§4.9.1.3, anchor p0339-L8118) | `se_vectors.rs::vector_electrical_store_07_5123_08_492_01` |
| 07-5123-08-491-02 | implemented + verified | `electrical.rs`: `REVISION` 2 (§4.9.1.1, anchors p0338-L8115-L8116) | `se_vectors.rs` store test (revision const) |
| 07-5123-08-492-01 | implemented + verified | `electrical.rs`: server table, unknown sentinels (§4.9.2.2, anchors p0339-L8129-L8132 + p0346-L8262-L8263) | `se_vectors.rs::vector_electrical_store_07_5123_08_492_01` |
| 07-5123-08-492-02 | implemented + verified | `electrical.rs`: `scaled_u64`/`scaled_i64` paired scale, zero folded unitary (§4.9.1.4, anchors p0339-L8119-L8123 + p0343-L8172-L8179 + p0346-L8247-L8255) | `se_vectors.rs::vector_electrical_scaling_07_5123_08_492_02`, `se_roundtrip.rs` codec fuzz |
| 07-5123-08-492-03 | implemented + verified | `electrical.rs`: `scaled_active_power` delivered/received sign (§4.9.2.2.4.5, anchors p0344-L8211-L8214) | `se_vectors.rs::vector_electrical_scaling_07_5123_08_492_02` (signed leg) |
| 07-5123-08-1021-01 | implemented + verified | `price.rs`: `CLUSTER_ID` 0x0700 (§10.2.1.3, anchor p0618-L13901) | `se_vectors.rs::vector_price_store_07_5123_08_1021_03` |
| 07-5123-08-1021-02 | implemented + verified | `price.rs`: `REVISION` 2 (§10.2.1.1, anchors p0618-L13899-L13900) | `se_vectors.rs` store test (revision const) |
| 07-5123-08-1021-03 | implemented + verified | `price.rs`: Tier1..8 labels + read-only refusal (§10.2.2.2.1.1, anchors p0620-L13919-L13926) | `se_vectors.rs::vector_price_store_07_5123_08_1021_03` |
| 07-5123-08-1022-01 | implemented + verified | `price.rs`: server received table incl. mandatory GetCurrentPrice + SE1.1-mandatory PriceAck (§10.2.2.3, anchors p0640-L14267-L14269) | `se_vectors.rs` price-table tests (command coverage), sim `se_loop.rs` get/ack legs |
| 07-5123-08-1022-02 | implemented + verified | `price.rs`: `ServerBehavior` answers GetCurrentPrice with PublishPrice, `NOT_FOUND` when empty (§10.2.2.3.2, anchors p0640-L14272 + p0641-L14290-L14292) | `se_loop.rs::se_loop_meter_and_tc_agree` (over-air publish leg) |
| 07-5123-08-1022-03 | implemented + verified | `price.rs`: `decode/encode_price_ack` 4+4+4+1 layout (§10.2.2.3.4, anchors p0642-L14322-L14328) | `se_vectors.rs::vector_price_ack_tier_labels_07_5123_08_1022` (exact bytes), sim ack leg |
| 07-5123-08-1022-04 | implemented + verified | `price.rs`: `decode_get_scheduled` start + count; `first_ending_after` scheduled lookup (§10.2.2.3.3, anchors p0641-L14294-L14307) | `se_vectors.rs::vector_price_ack_tier_labels_07_5123_08_1022` |
| 07-5123-08-1022-05 | implemented + verified | `price.rs`: GetTierLabels request shape; tier-id + label serving (§10.2.2.3.12, anchors p0647-L14487-L14492) | `se_vectors.rs::vector_price_ack_tier_labels_07_5123_08_1022` (round-trip) |
| 07-5123-08-1024-01 | implemented + verified | `price.rs`: `decode/encode_publish_price` mandatory prefix + tolerated tail, `display_parts` decimal split (§10.2.2.4.1, anchors p0652-L14634-L14638) | `se_vectors.rs::vector_publish_price_codec_07_5123_08_1024_01` (exact bytes + tail), fuzzer-caught OOB fix |
| 07-5123-08-1024-02 | implemented + verified | `price.rs`: `PriceTable::insert` newer-issuer supersession + active-tail shorten (§10.2.2.4.1, anchors p0652-L14628-L14633) | `se_vectors.rs::vector_price_table_supersession_07_5123_08_1024_02`, `se_roundtrip.rs::fuzz_price_table_stays_bounded` |
| 07-5123-08-1024-03 | implemented + verified | `price.rs`: `decode/encode_publish_tier_labels` bounded list (§10.2.2.4.9, anchors p0671-L15137-L15140) | `se_vectors.rs::vector_price_ack_tier_labels_07_5123_08_1022` (round-trip) |
| 07-5123-08-1073-01 | implemented + verified | `keyest.rs`: `CLUSTER_ID` 0x0800 (§10.7.3.4, anchor p0849-L19341) | `se_vectors.rs::vector_keyest_initiate_codec_07_5123_08_1074_01` |
| 07-5123-08-1073-02 | implemented + verified | `keyest.rs`: suite attribute + bit meanings, server received table (§10.7.4.2.1, anchors p0850-L19350-L19365) | `se_vectors.rs` initiate + suite-guard tests |
| 07-5123-08-1073-03 | implemented + verified | `keyest.rs`: server/client received/generated tables (§10.7.4.2.1.1 + §10.7.5.3, anchors p0850-L19361-L19365 + p0855-L19498-L19501) | `se_vectors.rs` table-shape assertions via `ClusterDef` |
| 07-5123-08-1074-01 | implemented + verified | `keyest.rs`: `decode/encode_initiate` suite + times + 48-octet identity (§10.7.4.2.1.1.1, anchors p0851-L19369-L19381) | `se_vectors.rs::vector_keyest_initiate_codec_07_5123_08_1074_01` (exact bytes) |
| 07-5123-08-1074-02 | implemented + verified | `keyest.rs`: `on_ephemeral_request/response` sequence + exact-length rule (§10.7.4.2.1.1.2, anchors p0852-L19410-L19426) | `se_vectors.rs::vector_keyest_initiate_guards_*` (short-ephemeral leg), `vector_keyest_ephemeral_length_07_5123_08_1074_05` |
| 07-5123-08-1074-03 | implemented + verified | `keyest.rs`: `on_confirm_request/response` MACU/MACV compare, mismatch terminates (§10.7.4.2.1.1.3, anchors p0852-L19427-L19435 + p0853-L19436-L19447) | `se_vectors.rs::vector_keyest_handshake_transcript_*` + `vector_keyest_mac_fail_terminates_*` (cluster-level negative) |
| 07-5123-08-1074-04 | implemented + verified | `keyest.rs`: `TerminateMsg` codec + `retry_advice` wait/fallback/give-up mapping (§10.7.4.2.1.1.4, anchors p0853-L19448-L19458 + p0854-L19459-L19461 + p0854-L19462-L19472) | `se_vectors.rs::vector_keyest_retry_advice_07_5123_08_1074_04`, terminate-advice leg in guards test |
| 07-5123-08-1074-05 | implemented + verified | `keyest.rs`: `EPH_LEN` 64 expanded-point profile convention (suite-1 wire cert stays 48 octets per Table 10-143, anchor p0865-L19821; compressed-point codecs are follow-up) | `se_vectors.rs::vector_keyest_ephemeral_length_07_5123_08_1074_05` |
| 07-5356-C41-02 | implemented + verified | `keyupdate.rs`: `derive_update_mask`/`derive_update_key` MMO-masked rotation + `install_link_key` reset-counters install; `keyest.rs`: `install_negotiated_key`/`rotate_link_key` (§C.4.1 key-replacement idea, anchor p0167-L4287-L4297; formula is rounddance construction) | `rounddance-security/tests/vectors.rs::vector_link_key_update_07_5356_c41_02` (pinned mask), `se_vectors.rs` handshake install/rotate legs, sim `se_loop.rs` update leg |

## Wave-16 traceability — ESP HAL adapter (`rounddance-hal-esp`)

All IDs below are repo-minted (`RD-HAL-ESP-<seq>`), MINTED-pending-confirm:
no 802.15.4 MAC corpus requirement exists yet (mac-sap items are all
"coverage pending"), so there is no corpus req to fit. Inter-PAN legs
additionally exercise the wave-13 minted IDs `22-65816-030-121-03` +
`122-02` (anchors p0087-L1821-L1835, p0091-L2008-L2010, p0092-L2054-L2064).
Evidence for the driver contract is the wave-15 spike
(`rd-frame-tx/src/main.rs`: NVS-first L84-94, antenna L96-101,
enable sequence L120-129, Len+2 frame L143-154, ISR callbacks L50-78)
plus the wave-6 C leg (`hwleg1_main.c` RX copy + handle_done L60-80).
Wording in code/tests is paraphrase only, never spec text (D1).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| RD-HAL-ESP-01 | implemented + verified | `adapter.rs`: `MAX_TX_POWER_DBM`, `set_tx_power` rejects hotter requests before the driver | `adapter_mock.rs::power_cap_enforced_before_init` |
| RD-HAL-ESP-02 | implemented + verified | `esp.rs`: NVS-init-first + erase-on-version-mismatch, then driver enable; `adapter.rs::init` programs stored provisioning | `adapter_mock.rs::init_programs_filtering_defaults`, `init_applies_pre_provisioned_addrs`, `init_failure_surfaces_and_stays_down` |
| RD-HAL-ESP-03 | implemented + verified | `adapter.rs`: `build_data_frame`/`build_inter_pan_frame` Len+2 encode, `parse_data_frame`/`parse_inter_pan_frame` checked decode | `adapter_mock.rs::data_request_builds_len_plus_two_frame`, `frame_builders_reject_oversize`, RX parse legs |
| RD-HAL-ESP-04 | implemented + verified | `adapter.rs`: `map_tx_event` (Done→Delivered, CcaBusy→ChannelBusy, NoAck→NoAck, all other driver failures→NoAck, documented) | `adapter_mock.rs::tx_done_confirms_delivered`, `cca_fail_maps_channel_busy`, `noack_maps_noack`, `other_driver_failures_report_not_delivered` |
| RD-HAL-ESP-05 | implemented + verified | `esp.rs`: ISR flag-only + bounded mailbox copy + exactly-once `receive_handle_done` (overruns counted); `adapter.rs::pump` drains via `poll_rx` | `adapter_mock.rs::rx_pan_indication_parses_src_and_payload`, `foreign_pan_routes_to_interpan` |
| RD-HAL-ESP-06 | implemented + verified | `adapter.rs`: `energy_scan` delegates to the driver (sync seam over the async ED-done event on target) | `adapter_mock.rs::ed_scan_delegates_and_maps_sign` |
| RD-HAL-ESP-07 | implemented + verified | `adapter.rs`: 4 TX slots, `QueueFull` backpressure, `data_cancel` (queued→Cancelled, in-air→runs to completion, else `UnknownHandle`) | `adapter_mock.rs::queue_full_backpressure_then_ordered_confirms`, `cancel_revokes_queued_with_cancelled`, `cancel_air_submitted_runs_to_completion` |
| RD-HAL-ESP-08 | implemented + verified | `adapter.rs::init` programs promiscuous OFF + RX-when-idle ON (driver defaults promiscuous TRUE); antenna LOW/LOW is a board-code invariant (README + example) | `adapter_mock.rs::init_programs_filtering_defaults` |
| RD-HAL-ESP-09 | implemented + verified | `adapter.rs`: inter-PAN per-request channel retune, unacknowledged broadcast shape, confirm + channel-tagged indications; also serves `22-65816-030-121-03` + `122-02` | `adapter_mock.rs::interpan_path_tunes_channel_and_confirms`, `interpan_indication_carries_channel_and_bytes` |
| RD-HAL-ESP-10 | implemented + verified | `adapter.rs`: single-flight submit (in-air skipped by `oldest_queued`), submit faults stay queued + counted (`submit_faults`) | `adapter_mock.rs::submit_busy_stays_queued_then_flushes`, `submit_fault_stays_queued_and_counted` |
| RD-HAL-ESP-11 | implemented + verified | NWK-frame TX binary shape: repo codec output pinned to the frozen vector before framing (spike `main.rs` L104-118 pattern) | `examples/esp_adapter_shape.rs` output (`15 41 88 00 34 12 ff ff 01 00` + frozen NWK tail), `data_request_builds_len_plus_two_frame` |
| RD-HAL-ESP-12 | implemented + verified | `adapter.rs`: honest capabilities (HW auto-ACK + CSMA true, HAL retries false, ED true, timestamps false, promiscuous true) | `adapter_mock.rs::capabilities_report_hardware_truthfully` |

## Wave-17 traceability — Zigbee Direct core (`rounddance-direct`)

All `20-27688-041-*` IDs below are corpus-mined (page+clause
anchored, `reconcile` for exact wording — the extraction carries no
printed body line numbers). The admin-key default derivation
(`zb-direct` MMO construction) is repo-defined, MINTED-pending-confirm.
Wording in code/tests is paraphrase only, never spec text (D1).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 20-27688-041-53-01 | implemented + verified | role model: Direct runs over the BLE capability interface, no BT stack (`lib.rs` crate docs; ZDD/ZVD roles in `session.rs`/`advert.rs`) | `vectors.rs::vector_security_service_shape_20_27688_041_65_01` (service shape), sim `direct_commission.rs::direct_full_commissioning` |
| 20-27688-041-62-01 | implemented + verified | `advert.rs`: `AdvPolicy` (minimum 60 s timeout, quiet-until-resume) | `vectors.rs::vector_adv_provisioning_timeout_20_27688_041_62_01` |
| 20-27688-041-62-02 | implemented + verified | `advert.rs`: `mark_provisioned`/`mark_unprovisioned` (leave returns to open-to-provision) | sim `direct_commission.rs` form/leave legs via `AdvPolicy` transitions |
| 20-27688-041-63-01 | implemented + verified | `gatt.rs`: `authorize` (provisioning vs. provisioned gates, status reads excepted); `session.rs`: single-session no-second-provisioning rule | `vectors.rs::vector_access_control_20_27688_041_63_01`, `vector_anonymous_guard_and_admin_lifecycle` |
| 20-27688-041-63-02 | implemented + verified | `session.rs`: `PskKind` (default/install-code/anonymous/passcode), initiator-chosen key in `begin` | `vectors.rs::vector_establishment_timeout_20_27688_041_65_03` (PSK begin legs), sim `direct_commission.rs::direct_full_commissioning` |
| 20-27688-041-63-03 | implemented + verified | `session.rs`: anonymous begin needs positive countdown (`JoinWindowClosed`); `commission.rs`: `permit_remaining` countdown | `vectors.rs::vector_anonymous_guard_and_admin_lifecycle` |
| 20-27688-041-63-04 | implemented + verified | `session.rs`: `set_admin_key` once-only (`AdminKeyLocked`), `factory_reset` unlocks | `vectors.rs::vector_anonymous_guard_and_admin_lifecycle` |
| 20-27688-041-63-05 | implemented + verified | `session.rs`: `derive_admin_key` + `commission.rs::complete_join` TC-key default (`zb-direct` MMO construction, MINTED-pending-confirm) | sim `direct_commission.rs::direct_full_commissioning` (form-without-admin → join leg) |
| 20-27688-041-646-01 | implemented + verified | `session.rs`: `BleCounters` (increment-before-encrypt, stale-drop, retire-at-max) | `vectors.rs::vector_counters_20_27688_041_646_01`, `roundtrip.rs::fuzz_counters_reject_stale` |
| 20-27688-041-65-01 | implemented + verified | `gatt.rs`: `SECURITY_SERVICE_UUID` + 3 `SECURITY_CHARS` (§6.5, Table 5) | `vectors.rs::vector_security_service_shape_20_27688_041_65_01` |
| 20-27688-041-65-02 | implemented + verified | `gatt.rs`: per-method Authenticate characteristics (distinctive UUIDs, strict-sequence discipline in `session.rs`) | `vectors.rs::vector_security_service_shape_20_27688_041_65_01` |
| 20-27688-041-65-03 | implemented + verified | `session.rs`: 15 s establishment silence → drop; validation failure → immediate drop | `vectors.rs::vector_establishment_timeout_20_27688_041_65_03` |
| 20-27688-041-75-01 | implemented + verified | `advert.rs`: `suspend`/`resume_links` (extension dropped/freed with link capacity) | `vectors.rs::vector_adv_provisioning_timeout_20_27688_041_62_01` (policy legs) |
| 20-27688-041-76-01 | implemented + verified | `advert.rs`: `AdvExtension` 9-octet record (version nibble, flags, PAN/addr LE, all-ones sentinels), refresh-on-change | `vectors.rs::vector_adv_factory_new_record_20_27688_041_76_01` + `vector_adv_joined_record_20_27688_041_76_01`, `roundtrip.rs::fuzz_adv_record_round_trip` (fuzzer-caught flag-shift fix) |
| 20-27688-041-772-01 | implemented + verified | `gatt.rs`: commissioning service/characteristics (Table 26); `attr.rs`: TLV/status codec (Tables 27–33, LE); `commission.rs`: single-flight + busy rejection + 3 s timeout + failure-completes-with-notify | `vectors.rs` service-shape/access/TLV/timeout vectors, `roundtrip.rs` TLV/status fuzz + machine-rejection fuzz, sim `direct_commission.rs` full + timeout + replay tests |
| 20-27688-041-772-02 | implemented + verified | `commission.rs`: form-starts-closed + status notify, permit feeds window, leave erases params+keys, key rotation via `keyupdate`, link-key flag codec in `attr.rs` (Tables 34–35) | `vectors.rs::vector_form_starts_closed_20_27688_041_772_02` + `vector_join_bad_key_rejected` + `vector_leave_erases_everything_20_27688_041_772_02`, `vector_link_key_tlv_codec_20_27688_041_772_02`, sim `direct_commission.rs` full + bad-key tests |

## Wave-17 traceability — lab-arbitrator lease-expiry fix

Repo-minted IDs (`ARB-LEASE-<seq>`), MINTED-pending-confirm: no
corpus requirement covers host tooling.

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| ARB-LEASE-01 | implemented + verified | `leases.rs`: `EXPIRY_WARN_SECS` (300 s) + `expiring_soon` (swept, TTL-carrying, soonest-first); `main.rs::cmd_status` prints `WARNING … expires in Ns — renew with: arbitrator renew …` | `leases.rs::expiry_is_visible_and_renewable` (invisible fresh → visible with TTL → renewable → invisible) |
| ARB-LEASE-02 | implemented + verified | `main.rs::cmd_status` keeps per-lease `remaining=Ns` TTLs; explicit `renew` command (pre-existing) is the renewal path the warning points at | `leases.rs::expiry_is_visible_and_renewable` (renew leg), `renew_rejects_non_owner_and_extends` |

## Wave-18 traceability — S3+H2 OTBR path (`rounddance-rcp`)

All IDs below are repo-minted (`RD-RCP-<seq>`), MINTED-pending-confirm:
no corpus requirement covers the S3+H2 UART (no 802.15.4 MAC/RCP
clauses are mined yet). Wire classes are rounddance constructions
documented in `docs/otbr/protocol.md`; topology in
`docs/otbr/topology.md`. Wording in code/tests is paraphrase only,
never spec text (D1).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| RD-RCP-01 | implemented + verified | `frame.rs`: `SYNC/LEN/KIND/SEQ/payload/CRC16` framing, `encode` bounds | `frame.rs` layout + bounds tests, `vectors.rs::golden_set_channel_bytes` (independent-CRC golden) |
| RD-RCP-02 | implemented + verified | `frame.rs`: CRC-16/CCITT + `Decoder` streaming resync (noise skip, BadLen/BadCrc drops, worst-case re-arm) | `frame.rs::crc_reference_vector` (0x29B1), `decoder_round_trip_with_noise`, `decoder_drops_and_rearms`, `roundtrip.rs` 8k-case fuzz |
| RD-RCP-03 | implemented + verified | `cmd.rs`: `Command` classes reset/channel/power/PAN/addr/TX/scan with fixed shapes | `cmd.rs::command_vectors`, `malformed_command_rejected`, `roundtrip.rs::command_event_round_trip_all_classes` |
| RD-RCP-04 | implemented + verified | `cmd.rs`: `Event` classes ready/confirm/RX/energy/error + `TxOutcome` mapping | `cmd.rs::event_vectors`, `vectors.rs::golden_tx_confirm_and_max_psdu_reject` |
| RD-RCP-05 | implemented + verified | `driver.rs`: `RcpDriver` implements `MacDataSap`/`MacMgmtSap`/`MacInterPanSap` over `Uart` (4-slot single-flight pool, honest capabilities, split-phase scan) | `driver.rs::form_handshake_and_provisioning`, `tx_confirm_round_trip_and_cancel`, `interpan_path_confirms_separately`, `scan_split_phase_and_timeout` |
| RD-RCP-06 | implemented + verified | `driver.rs`: 20 ms timeout on the injected clock, fresh-sequence resend, 3 retries then `NoAck`; healing needs no reset | `driver.rs::timeout_retries_then_fails_noack`, sim `rcp_otbr_path.rs::rcp_uart_loss_costs_one_retry` + `rcp_timeout_fails_then_heals` |
| RD-RCP-07 | implemented + verified | `driver.rs`: 4-consecutive-drop meter opens a warm reset handshake; `Decoder` consecutive-bad clears on good frames | `driver.rs::desync_opens_reset_and_reprovisions`, sim `rcp_otbr_path.rs::rcp_desync_resync_and_replay` |
| RD-RCP-08 | implemented + verified | `driver.rs`: `Reset`/`Ready` handshake, provision-cache replay (`Reprovisioned`), storm-era slots drain post-heal | `driver.rs::form_handshake_and_provisioning`, `desync_opens_reset_and_reprovisions`, sim `rcp_otbr_path.rs` form + desync legs |
| RD-RCP-09 | implemented + verified | `lib.rs::MAX_TX_POWER_DBM` (+10 dBm standing cap) refused by driver *and* emulated firmware before anything applies | `driver.rs::form_handshake_and_provisioning` (cap leg), `peer.rs::guards_reject_out_of_policy`, `vectors.rs::scripted_exchange_transcript` (firmware mirror leg) |
| RD-RCP-10 | implemented + verified | Full OTBR stack over scripted RCP UART: form → install-code join + DeviceAnnce → APS-secured ZCL On applied to a live server + replay rejection; disturbed runs replay exactly | sim `rcp_otbr_path.rs` all 6 tests (form, join, secured On, loss, timeout, desync+replay) |
| RD-RCP-11 | implemented + verified | `docs/otbr/topology.md` (S3-GPIO18/17/7/8 ↔ H2-GPIO23/24/EN/GPIO9, 460800 8N1, roles, bring-up) + `docs/otbr/protocol.md` (framing/classes/discipline/v0 non-goals); pin constants in `lib.rs` | doc review (constants `S3_UART_TX_GPIO`…`RCP_UART_BAUD` compile-checked) |

## Wave-19 traceability — browser path (`rounddance-browser`)

All IDs below are repo-minted (`RD-BROWSER-<seq>`), MINTED-pending-confirm:
no corpus requirement covers the browser/WASM harness (tooling, same
standing as `ARB-LEASE-*`). Wording in code/tests is paraphrase only,
never spec text (D1).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| RD-BROWSER-01 | implemented + verified | `rounddance-browser`: same `run_first_transaction(ScenarioConfig::first_transaction())` scenario as the host leg, built for `wasm32-unknown-unknown` | `tools/browser-check.sh` builds the bundle; `browser_decisions.rs::browser_getters_match_native_pin` |
| RD-BROWSER-02 | implemented + verified | 13 `pub mod exports` getters (digest hi/lo + 6 bools + cmd/report/resume counters + tsn + trace_lines), zero-import shape (no bindgen, no new deps) | `harness/browser/check_imports.py` (zero imports gate in `browser-check.sh`); `index.html` reads all 13 via empty-import instantiate |
| RD-BROWSER-03 | implemented + verified (wasmtime leg) | `tools/browser-check.sh`: native `host_transaction` output vs `wasmtime --invoke` getter dump, digest + every field + trace_lines compared | `browser-check.sh` exit 0 with `DECISION-MATCH: digest 0x3ea31047e1933c90`; `harness/browser/expected.txt` pins the excerpt |
| RD-BROWSER-04 | implemented, browser execution open | `harness/browser/index.html`: real-browser driver (fetch + `instantiateStreaming` with `{}` imports, unsigned compare, PASS/MISMATCH verdict) | NOT run on-box — no browser engine (chromium/firefox/webkit) or JS engine (node/deno) installed; engine present = wasmtime 36.0.2 only. First box with a browser runs it and records the verdict here. |

## Wave-20 traceability — Touchlink commissioning completion (`rounddance-commission`)

All IDs below either reuse corpus requirements (touchlink command
tables + BDB procedures, anchors name the private-corpus page + line)
or are repo-minted (dots stripped), MINTED-pending-confirm. Wording in
code/tests is paraphrase only, never spec text (D1).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 07-5123-08-13322-01 | implemented + verified (extended) | `touchlink.rs`: `ScanRequestBody` field-correct form, `DeviceInfoRequest`, `IdentifyRequest` codecs; `info`/`zigbee` bit builders; wave-10 skeleton kept byte-compatible (anchors p1132-L25931-L25932, Table 13-13) | `tests/vectors.rs::vector_scan_request_body_wire`, `vector_responses_and_update_wire` (identify/device-info legs) |
| 07-5123-08-133225-01 | implemented + verified | `touchlink.rs::NetworkStartRequest` 52-octet codec (new-network params + wrapped key + initiator identity; anchors p1136-L26042-L26053 + p1137-L26061-L26078 + p1138-L26109-L26114, Figure 13-14 PDF-frozen) | `tests/vectors.rs::vector_network_start_wire_07_5123_08_133225_01` (frozen 52-byte wire + frame shape) |
| 07-5123-08-133226-01 | implemented + verified | `touchlink.rs::NetworkJoinRequest` 43-octet codec (router leg; anchors p1139-L26127-L26129, Figure 13-15 PDF-frozen) | `tests/vectors.rs::vector_network_join_wire_07_5123_08_133226_01` (frozen 43-byte wire + `JoinKind` command mapping) |
| 07-5123-08-133227-01 | implemented + verified | same codec via `JoinKind::EndDevice` (`0x14`/`0x15`; anchors p1141-L26194, Figure 13-16 PDF-frozen) | `vector_network_join_wire_*` (kind mapping leg) + sim `touchlink_join_existing_network` |
| 07-5123-08-133228-01 | implemented + verified | `touchlink.rs::NetworkUpdateRequest` 14-octet codec; initiator `send_update`, target `on_network_update` (anchors p1143-L26257-L26259, Figure 13-17 PDF-frozen) | `tests/vectors.rs::vector_responses_and_update_wire`, `vector_network_update_flow_22_65816_030_122_04`, sim negatives (pre-response ignore leg) |
| 07-5123-08-133231-01 | implemented + verified | `touchlink.rs::ScanResponseBody` 25-octet + 7-octet single-sub-device tail codec (anchors p1145-L26311-L26314 + p1146-L26319-L26320 + p1147-L26348-L26355 + p1148-L26393-L26396, Figure 13-20 PDF-frozen) | `tests/vectors.rs::vector_scan_response_body_wire_07_5123_08_133231_01` (frozen 32-byte + 25-byte wires, 2-sub-device reject) |
| 07-5123-08-133233-01 | implemented + verified | `touchlink.rs::NetworkStartResponse` 13-octet codec (status + verified params; anchors p1151-L26489-L26492 + p1151-L26497-L26500 + p1151-L26504-L26505, Figure 13-25 + Table 13-16 PDF-frozen) | `tests/vectors.rs::vector_responses_and_update_wire` (frozen 13-byte wire) |
| 07-5123-08-133234-01 | implemented + verified | `touchlink.rs::NetworkJoinResponse` 1-octet codec (router leg; anchors p1152-L26523-L26525 + p1152-L26530-L26533, Figure 13-26 + Table 13-17 PDF-frozen) | `tests/vectors.rs::vector_responses_and_update_wire` |
| 07-5123-08-133235-01 | implemented + verified | same codec via `JoinKind::EndDevice` (anchors p1153-L26546-L26548 + p1154-L26557, Figure 13-27 + Table 13-18 PDF-frozen) | sim `touchlink_join_existing_network` (end-device response leg) |
| 07-5123-08-1333411-01 | implemented + verified | `touchlink.rs`: `KEY_INDEX_*` consts, `CERTIFICATION_KEY`, `TouchlinkKey`, `transport_block`/`development_block`, `transport_key_for`, `encrypt/decrypt_network_key` (local ECB decrypt), `select_key_index` (anchors p1167-L26870-L26882 + p1168-L26898-L26906 + p1169-L26911-L26924 + p1171-L26959-L26961 + p1172-L26962-L26983 + p1173-L26984-L26990) | `tests/vectors.rs::vector_transport_certification_worked_07_5123_08_1333411_01` (worked derivation input + transport key + wrap/unwrap pin), `vector_decrypt_published_cipher_check` (cipher cross-check), `vector_key_index_selection_*`, roundtrip involution fuzz |
| 22-65816-030-121-04 | implemented + verified | `TouchlinkInitiator`: `send_start`/`send_join`/`send_update`, `on_start/join_response`, `tick_ms` (receive window + startup delay + lifetime), `take_handoff` (anchors p0085-L1787-L1804 + p0091-L2007-L2017 + ZCL Table 13-21 p1158-L26660-L26661) | `tests/vectors.rs::vector_full_start_transcript_*`, `vector_full_join_transcript_*`, `vector_timeout_and_abandon_rules`, sim `touchlink_complete_commissioning` + replay |
| 22-65816-030-1211-02 | implemented + verified | transaction binding on every order/response; stale frames refused with `StaleTransaction`, machines stay in state (anchors p0091-L2008-L2010 + 07-5123-08-p1163-L26726-L26733 + p0095-L2118-L2123) | `tests/vectors.rs::vector_stale_transactions_rejected_22_65816_030_1211_02`, sim negatives (stale join leg) |
| 22-65816-030-122-03 | implemented + verified | `TouchlinkTarget`: `respond_full` (latches response id), `on_network_start`/`on_network_join` (role + steal + key gates), `on_reset`/`on_identify`/`on_device_info` discipline, `tick_ms` lifetime → `Expired`, `take_pending` (anchors p0092-L2054-L2064 + p0093-L2066-L2080 + p0095-L2124-L2136 + p0096-L2148-L2158 + p0098-L2252-L2254) | `tests/vectors.rs::vector_bad_key_index_flow_*`, `vector_refuse_steal_and_role_gates_*`, `vector_auxiliary_order_discipline_*`, `vector_timeout_and_abandon_rules`, sim negatives |
| 22-65816-030-122-04 | implemented + verified | `TouchlinkTarget::on_network_update` + `PendingUpdate`/`UpdateDisposition` (anchors p0096-L2144-L2147) | `tests/vectors.rs::vector_network_update_flow_22_65816_030_122_04` |

## Wave-21 traceability — C ABI bindings + C/C++ harnesses (`rounddance-ffi`)

All IDs below are repo-minted (`RD-FFI-<seq>`), MINTED-pending-confirm:
no corpus requirement covers the C ABI harness (tooling, same standing
as `RD-BROWSER-*` / `ARB-LEASE-*`). Wording in code/tests is paraphrase
only, never spec text (D1).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| RD-FFI-01 | implemented + verified | `rounddance-ffi` (crate-type staticlib + rlib): same `run_first_transaction(ScenarioConfig::first_transaction())` scenario as the host leg, run to completion inside `rd_create` | `tools/c-check.sh` builds the staticlib; `tests/ffi_surface.rs::ffi_decisions_match_native` |
| RD-FFI-02 | implemented + verified | Opaque `RdContext` handle (`rd_create`/`rd_destroy`, null-tolerant destroy); 12 decision getters (digest hi/lo + 6 bools + cmd/report/resume counters + tsn + trace_lines) + nul-free bounded `rd_trace_line` (length out-param, `RD_ERR_SMALL` on truncation) | `tests/ffi_surface.rs` (byte-exact trace round-trip, null/range/small-buffer error statuses) |
| RD-FFI-03 | implemented + verified | `RD_OK`/`RD_ERR_*` status codes on every export; `catch_unwind` at each boundary mapping panics to `RD_ERR_PANIC` (panic=abort documented as FFI-safe termination); `unsafe` confined to `pub mod ffi` under crate `#![deny(unsafe_code)]`, each block with a SAFETY comment (hal-esp precedent); std-based like hal-host/browser, documented not-`no_std` | `tests/ffi_surface.rs::ffi_null_and_range_errors_are_statuses`; `cargo clippy --all-targets` 0 warnings (incl. `not_unsafe_ptr_arg_deref` + `missing_safety_doc`) |
| RD-FFI-04 | implemented + verified | `harness/c/txn.c` (gcc `-std=c11 -Wall -Wextra -Werror -O2`) asserting all 13 values + digest + trace_lines against the pinned native run | `tools/c-check.sh` exit 0 with `C-DECISION-MATCH: digest 0x3ea31047e1933c90, trace_lines=35`; `harness/c/expected.txt` pins the excerpt |
| RD-FFI-05 | implemented + verified | `harness/c/txn.cpp` (g++ `-std=c++17 -Wall -Wextra -Werror -O2`): same asserts as `txn.c` through the `extern "C"`-guarded `harness/c/rd_ffi.h`, proving C++ linkage compat | `tools/c-check.sh` exit 0 with `CPP-DECISION-MATCH: digest 0x3ea31047e1933c90, trace_lines=35` |
| RD-FFI-06 | implemented + verified (native leg) | `tools/c-check.sh`: fresh native `host_transaction` output vs both harness verdicts, digest + trace_lines compared, pin re-verified | `c-check.sh` exit 0 with `DECISION-MATCH: digest 0x3ea31047e1933c90, trace_lines=35, C + C++ == native` |

## Wave-22 traceability — coverage expansion: IAS ACE + IAS WD + price blocks (`rounddance-zcl`)

Corpus IDs (`07-5123-08-832-*`, `842-*`, `102-*`, `104-02`) reused
verbatim from the private corpus; the rest below are repo-minted
(dots stripped), MINTED-pending-confirm. Wording in code/tests is
paraphrase only, never spec text (D1). Deferred with cause:
metering mirrors/snapshots (mirror-table + CIE-substitution state
needs its own wave) and compressed-point ephemeral codecs (needs an
`EccBackend` decompression method plus a mock-provable sqrt — the
expanded-point profile stays the wire form).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 07-5123-08-832-01 | implemented + verified | `ace.rs`: every arm attempt closes with an arm-response verdict (not-ready → 0x05, bad code → 0x04, already-disarmed → 0x06; anchors p0538-L12243-L12245) | `tests/ias_vectors.rs::vector_arm_all_closes_*`, `vector_arm_not_ready_*`, `vector_disarm_already_*`, sim `ias_loop.rs` arm leg |
| 07-5123-08-832-02 | implemented + verified | `ace.rs::code_accepted`: codes are UTF-8, zero-length means none (anchors p0537-L12230-L12237) | `tests/ias_vectors.rs::vector_arm_code_rules_*` (match/mismatch/non-UTF8) |
| 07-5123-08-832-03 | implemented + verified | `ace.rs::answer_zone_status`: mask-flag clear returns every zone, set returns status-AND-mask-nonzero zones + complete flag (anchors p0540-L12313-L12333) | `tests/ias_vectors.rs::vector_zone_status_mask_*` (all/masked/paged legs), sim `ias_loop.rs` masked-query leg |
| 07-5123-08-832-04 | implemented + verified | `ace.rs::apply_disarm` (clears non-permanent bypasses, keeps permanent) + panel-status-changed on every transition (anchors p0544-L12407 + p0547-L12472-L12474) | `tests/ias_vectors.rs::vector_disarm_clears_bypass_*`, sim `ias_loop.rs` arm leg |
| 07-5123-08-831-01 | implemented + verified | `ace.rs`: cluster id 0x0501 + revision + received/generated tables + store (anchor p0536-L12218-L12221) | `tests/ias_vectors.rs::vector_ace_store_shape_*`, `roundtrip.rs` definition contract |
| 07-5123-08-833-01 | implemented + verified | `ace.rs`: Arm + Bypass received codecs (mode/code/zone-id + count/ids/code shapes; anchors p0537-L12224-L12225 + p0538-L12253-L12255) | `tests/ias_vectors.rs::vector_arm_codec_*`, `vector_bypass_results_*`, `roundtrip.rs::fuzz_ias_codec_roundtrip` |
| 07-5123-08-833-02 | implemented + verified | `ace.rs`: query codecs (zone-status/info/map/panel/bypassed-list) + response emitters (map/info/status/panel/bypass-list/bypass-response shapes; anchors p0539-L12273-L12282 + p0541-L12344-L12353 + p0542-L12359-L12365 + p0546-L12441-L12481 + p0548-L12489-L12496) | `tests/ias_vectors.rs::vector_zone_info_answers_*`, `vector_zone_id_map_*`, `vector_ace_client_frames_*` |
| 07-5123-08-834-01 | implemented + verified (implementation inference — see `ace.rs` module docs) | `ace.rs`: emergency/fire/panic → in-alarm panel, delay `start_delay` + `tick_1s` countdown with per-second fan-out, `report_zone_status` fan-out (anchors p0538-L12264-L12265 + p0543-L12378-L12393 + p0544-L12409-L12435). Inference: the corpus names these commands and lists the Alarm Status values but states no effect sentence linking receipt to a panel/alarm transition — Alarm Status corroborates only | `tests/ias_vectors.rs::vector_panic_raises_alarm_*`, `vector_panel_delay_tick_*`, `vector_zone_status_fanout_*`, sim `ias_loop.rs` trip leg |
| 07-5123-08-842-01 | implemented + verified | `wd.rs`: new starts preempt the live warning, stop/stop silences, durations tick out, MaxDuration clamp (anchors p0551-L12540-L12541 + p0550-L12531-L12532) | `tests/ias_vectors.rs::vector_warning_preemption_*`, `vector_warning_duration_cap_*`, sim `ias_loop.rs` warn/preempt/expiry legs |
| 07-5123-08-842-02 | implemented + verified | `wd.rs::SIREN_LEVELS`/`STROBE_LEVELS` non-empty supported sets (anchors p0552-L12558-L12559 + p0552-L12573-L12574) | `tests/ias_vectors.rs::vector_wd_store_shape_*` |
| 07-5123-08-842-03 | implemented + verified | `wd.rs::quantize_duty`: out-of-step values round to the nearest valid step over a one-second ON-first cycle (anchors p0552-L12564-L12570) | `tests/ias_vectors.rs::vector_duty_quantize_*` |
| 07-5123-08-841-01 | implemented + verified | `wd.rs`: cluster id 0x0502 + MaxDuration attr (default 240) + StartWarning/Squawk codecs + squawk-while-active gate (anchors p0550-L12525-L12536 + p0551-L12543-L12556 + p0553-L12580-L12595) | `tests/ias_vectors.rs::vector_start_warning_codec_*`, `vector_squawk_gated_*`, `roundtrip.rs::fuzz_ias_codec_roundtrip` |
| 07-5123-08-102-01 | implemented + verified | `price.rs::BlockTable::new` + `ThresholdStore::new` ready before any publication (anchors p0627-L14031-L14033) | `tests/se_vectors.rs::vector_block_table_supersede_cancel_*` (empty-then-loaded leg) |
| 07-5123-08-102-02 | implemented + verified | `price.rs::threshold_count_for_tariff`: TOU-only tariffs zero the count, single-set tariffs carry 1..15 (anchors p0629-L14065-L14067) | `tests/se_vectors.rs::vector_threshold_shape_and_scale_*` |
| 07-5123-08-102-03 | implemented + verified (extended) | `price.rs::BlockTable`: current-plus-upcoming retention answered from the backlog, NOT_FOUND when empty (anchors p0641-L14296-L14297 + p0642-L14337-L14338) | `tests/se_vectors.rs::vector_block_serve_and_not_found_*`, sim `se_block_loop.rs` recovery leg |
| 07-5123-08-104-02 | implemented + verified | `price.rs::scaled_threshold` reuses the metering multiplier/divisor pairing (zero in either is unitary; anchors p0624-L13976-L13983) | `tests/se_vectors.rs::vector_threshold_shape_and_scale_*`, sim `se_block_loop.rs` scaled leg |
| 07-5123-08-1023-01 | implemented + verified | `price.rs`: Get Block Period(s) codec (5/6-octet) + backlog serve with start-0-means-now, count-0-means-unlimited, tariff filter (anchors p0642-L14329 + p0643-L14342-L14353) | `tests/se_vectors.rs::vector_get_block_periods_codec_*`, `vector_block_serve_and_not_found_*` |
| 07-5123-08-1023-02 | implemented + verified | `price.rs::ThresholdStore`: newest thresholds per tariff slot + GetBlockThresholds serve + NOT_FOUND when empty (anchors p0646-L14447-L14459) | `tests/se_vectors.rs::vector_threshold_store_newest_wins_*`, `vector_block_serve_and_not_found_*` |
| 07-5123-08-1025-01 | implemented + verified | `price.rs`: PublishBlockPeriod 19-octet codec (anchors p0661-L14802-L14804) | `tests/se_vectors.rs::vector_block_period_codec_*`, `se_roundtrip.rs::fuzz_block_codecs_stay_bounded` |
| 07-5123-08-1025-02 | implemented + verified | `price.rs::BlockTable::insert`: newer issuer wins, cancel removes by provider + issuer, full table evicts oldest (anchors p0661-L14808-L14819) | `tests/se_vectors.rs::vector_block_table_supersede_cancel_*` |
| 07-5123-08-1026-01 | implemented + verified | `price.rs`: PublishBlockThresholds codec (19-octet header + tier/count-nibble sets + uint48 thresholds; anchors p0668-L15045-L15046 + p0669-L15075-L15080 + p0670-L15081-L15087) | `tests/se_vectors.rs::vector_block_thresholds_codec_*`, `se_roundtrip.rs::fuzz_block_codecs_stay_bounded`, sim `se_block_loop.rs` threshold leg |

## Wave-23 traceability — level-0 AUX RX + classical-join hardening

All IDs below are corpus-reused (no repo-minted IDs: the observed
vendor command id rides a named constant, not a requirement ID).
Wording in code/tests is paraphrase only, never spec text (D1). The
captured bytes in tests are field observations from a stock
coordinator's post-association traffic (level-0 plaintext vendor APS
command, never the standard transport-key command).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 05-3474-23-451-01 | implemented + verified (extended: level-0 RX) | `classical.rs::AuxReception::decode` routes level 0 to `Plaintext` (one control octet consumed, never decrypted; §4.5.1, anchors p0479-L11436-L11440) | security `tests/vectors.rs::vector_aux_level0_plaintext_reception` (captured 51-octet shape), `vector_aux_level0_all_control_shapes`, sim `join_unsecured_tc.rs` |
| 05-3474-23-4312-01 | implemented + verified (extended) | counter-less frames take no replay slot — enforced by the `Plaintext` shape (carries no counter to check; §4.3.1.2, anchor p0422-L10156-L10164) | type shape (nothing to feed `ReplayTable::check`); sim replay decodes the same capture twice with no replay state |
| 22-65816-030-91-02 | implemented + verified (extended) | `JoinerMachine::note_unsecured` counts/classifies vendor frames with no transition and no key latch (command-id-only signature); `UNSECURED_VENDOR_CMD` names the observed id (anchors p0061-L1307-L1334) | commission `tests/vectors.rs::vector_join_tolerates_unsecured_then_no_transport`, `vector_join_unsecured_keywait_leg_and_edges`, sim `join_unsecured_tc.rs` |
| 22-65816-030-56-04 | implemented + verified (extended) | `JoinError::NoTransport` names the transport-missing outcome (TC talked but never delivered keys vs never admitted); existing tick/window behavior unchanged (anchors p0032-L525-L561) | `vector_join_*_no_transport` legs, sim `unsecured_tc_challenge_then_no_transport` |

## Wave-24 traceability — 3.0-compat proof + inference labeling (`rounddance-compat`)

Corpus IDs below are reused verbatim (extended with 3.0-compat
coverage); `RD-COMPAT-*` rows are repo-minted, MINTED-pending-confirm.
Wording in code/tests is paraphrase only, never spec text (D1).

The audit result: the 3.0 profile and the R23.2 core share the NWK
protocol-version value (`2`), the GP version (`3`), the APS codec
(no version field), the security-level numbering with level 5 as the
transmitted baseline, the preconfigured/install-code key paths, and
the ZCL frame shape (reserved bits ignored on receipt). The compat
crate owns the admission/negotiation gates so no join path can skip
them; downgrade policy is never-silent (refusal is typed, see
`negotiate::CompatError`).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 05-3474-23-331-02 | implemented + verified (extended: 3.0 compat) | `compat::negotiate::admit_nwk_version` admits only the shared value 2; steering gate pairs `min_version: 2` with the compat refusal so unknown versions never reach the join machine (Fig. 3-5) | `compat/tests/vectors.rs::vector_nwk_30_data_header_wire`, `vector_nwk_unknown_version_refused`, sim `compat_30_join.rs::compat_unknown_nwk_version_never_joins` |
| 05-3474-23-22511-16 | implemented + verified (extended: 3.0 compat) | 3.0 APS unicast data shape decodes through the unchanged codec (Fig. 2-7) | `compat/tests/vectors.rs::vector_aps_30_data_shape_wire`, sim secured-toggle APS leg |
| 05-3474-23-451-01 | implemented + verified (extended: 3.0 compat) | baseline level-5 aux shape both profiles transmit; `agree_security_level` refuses anything under the floor instead of downgrading (§4.5.1) | `compat/tests/vectors.rs::vector_aux_30_baseline_level_wire`, `vector_aux_level_below_floor_refused`, sim replay-refusal leg |
| 05-3474-23-4312-01 | implemented + verified (extended: 3.0 compat) | captured 3.0-profile secured frame replayed by an attacker fails `ReplayTable::check` (§4.3.1.2) | sim `compat_30_join.rs::compat_30_join_and_secured_toggle` (replay leg) |
| 22-65816-030-91-02 | implemented + verified (extended: 3.0 compat) | 3.0-profile joiner completes the symmetric exchange over the MMO-derived install-code key (no mock KDF on this path) | sim `compat_30_join.rs::compat_30_join_and_secured_toggle` |
| 22-65816-030-56-03 | implemented + verified (extended: 3.0 compat) | install-code key via `MmoJoinKdf` (real derivation, what a 3.0 device computes) | sim join leg + `compat_30_replays_deterministically` |
| 07-5123-08-241-01 | implemented + verified (extended: 3.0 compat) | 3.0 Toggle shape decodes through the unchanged ZCL codec and applies on a live server via `dispatch` | `compat/tests/vectors.rs::vector_zcl_30_toggle_wire`, sim toggle-applies leg |
| 07-5123-08-231-02 | implemented + verified (extended: 3.0 compat) | ZCL reserved bits need no negotiation (zeroed on transmit, ignored on receipt, both sides) | `compat::negotiate::zcl_reserved_bits_need_no_negotiation`, vector `vector_zcl_30_toggle_wire` |
| 14-0563-19-A141-01 | implemented + verified (extended: 3.0 compat) | GP version gate mirrored in `admit_gp_version` (shared value 3) | `compat/tests/vectors.rs::vector_gp_version_gate` |
| RD-COMPAT-01 | implemented + verified | `negotiate::select_key_method`: negotiation preferred, install-code before preconfigured fallback, refusal under the strict posture | `compat/tests/vectors.rs::vector_key_method_selection`, sim `compat_strict_posture_refuses_30_peer` |
| RD-COMPAT-02 | implemented + verified | `negotiate::admit_30_peer`: full 3.0 admission (version + method + level) in one call | `compat/tests/vectors.rs::vector_admit_30_peer_bundle` |
| RD-COMPAT-03 | implemented + verified | `negotiate::highest_common_key_index`: bounded highest-common key-transport index | `compat/tests/vectors.rs::vector_highest_common_key_index` |
| RD-COMPAT-04 | implemented + verified | forward-compat corners: touchlink sub-device versions carried verbatim, higher ClusterRevisions tolerated | `compat/tests/vectors.rs::vector_forward_compat_corners` |

## Wave-25 traceability — C6-standalone full-stack app (`rounddance-hal-esp::app`)

The app layer composes repo crates only (roles, commission, NWK,
APS, security, ZDO, ZCL over `EspAdapter`); all behavior IDs below
are corpus IDs reused from their home waves — no new codec or
machine semantics, so no new corpus rows. The `RD-APP-C6-*` rows are
repo-minted (MINTED-pending-confirm) and cover only the app binding
itself: role selection, serial-log discipline, and the wired
composition the host proof exercises. Radio facts (channel 15, PAN
0xC601, +10 dBm cap, Len+2, short-short intra-PAN) are the wave-23
OTA run (`rd-c6join` in scratch `~/hwscratch/c6join`); no hardware
was touched by this wave — the proof runs the same app logic
against `MockDriver`.

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 22-65816-030-61-01 | implemented + verified (reused: app roles) | `app::AppRole::from` selection (`role_from_mac`: 0x86 coordinator / 0x85 joiner, refuse otherwise before touching the radio) | `c6_standalone.rs::c6_standalone_unknown_unit_refuses_role`, full-run role asserts |
| 05-3474-23-3611-01 | implemented + verified (reused: formation) | `CoordinatorApp::begin_formation` (centralized, fixed PAN) + `formation_done` | `c6_standalone.rs::c6_standalone_form_join_toggle` (C6APP FORMED leg) |
| 05-3474-23-3612-06 | implemented + verified (reused: coordinator lifecycle) | `CoordinatorApp` over `CoordinatorMachine` (form + permit + admit + child table) | full run (ADMIT leg + `joiner_heard` keepalive) |
| 05-3474-23-3612-07 | implemented + verified (reused: permit/admit) | `open_permit` + `admit_joiner` (formed + window required) | full run (C6APP PERMIT/ADMIT lines) |
| 22-65816-030-91-01 | implemented + verified (reused: survey) | `JoinerApp::begin_scan` + `survey` (channel-15 entry → candidate) | full run (C6APP SCAN/SURVEY legs) |
| 22-65816-030-91-03 | implemented + verified (reused: symmetric join) | `JoinerApp` over `JoinerMachine` (assoc → key → verify → announced → joined) + `UNSECURED_VENDOR_CMD` tolerance | full run incl. `tolerate_unsecured` count, `c6_standalone_unknown_unit_refuses_role` |
| 22-65816-030-56-03 | implemented + verified (reused: install-code KDF) | `CoordinatorApp::exchange_join_key` (real `MmoJoinKdf`, never a mock) | full run (SYMMETRIC attrs assert) |
| 05-3474-23-3615-01 | implemented + verified (reused: Trust-Center admission) | `admit_joiner` admits at both layers (child table + `TrustCenter`) | full run |
| 05-3474-23-24311-11 | implemented + verified (reused: DeviceAnnce) | `JoinerApp::build_annce` via `JoinerMachine::device_annce`, decoded by the coordinator side | full run (announce leg asserts) |
| 07-5123-08-241-01 | implemented + verified (reused: ZCL frame) | `build_toggle_request` (`onoff::client::toggle`) + `handle_toggle` decode | full run (lamp flips off→on) |
| 07-5123-08-383-01..04 | implemented + verified (reused: On/Off server) | live `ServerBehavior` over a real `AttrStore` via `dispatch` | full run (behavior applies the toggle) |
| 07-5123-08-2512-01 | implemented + verified (reused: Default Response triage) | `encode_default_rsp` + `should_default_respond` (success + error paths) | full run (`handle_defrsp` SUCCESS check) |
| 05-3474-23-4312-01 | implemented + verified (reused: replay) | per-direction `ReplayTable<8>` on both apps | `c6_standalone.rs::c6_standalone_replay_is_refused` |
| RD-APP-C6-01 | implemented + verified | `app::role_from_mac` + `eui_from_mac`: the OTA-proven pair selects, anything else refuses pre-radio | `c6_standalone_unknown_unit_refuses_role` |
| RD-APP-C6-02 | implemented + verified | `SerialLog` trait + `log_air` (bounded 512 B line, full air bytes, task-context only) | full run (8 discipline lines asserted) |
| RD-APP-C6-03 | implemented + verified | `CoordinatorApp` composition (machine + Trust Center + NWK/APS/aux/ZCL builders) | full run |
| RD-APP-C6-04 | implemented + verified | `JoinerApp` composition (steering + join machine + live ZCL endpoint + replay) | full run |
| RD-APP-C6-05 | implemented + verified | `build_secured_npdu` / `decode_secured_npdu` (NWK→APS→aux→ZCL, level-5 + address gates) | full run (byte-identical shuttled MSDUs) |
| RD-APP-C6-06 | implemented + verified | Error taxonomy `AppError` (BadRole/BadState/BadFrame/Replay/WrongCluster/BadStatus, no key material) | replay test (`AppError::Replay` on both legs) |
| RD-APP-C6-07 | implemented + verified | End-to-end proof shape: two `EspAdapter<MockDriver>` with mock-to-mock air shuttling + `Delivered` confirms | all 4 `c6_standalone.rs` tests, incl. determinism pin |
| RD-APP-C6-08 | implemented + verified | ESP-target build of the app (`no_std`, no `unsafe`, new deps all no_std) | `cargo check -p rounddance-hal-esp --features esp --target riscv32imac-esp-espidf -Z build-std=std,panic_abort` PASS (this wave) |

## Wave-26 traceability — metering mirrors + snapshots (`rounddance-zcl`)

Corpus IDs below are reused verbatim (`07-5123-08-104-01`,
`17-05019-012-422-02`, `17-05019-012-423-01/02`); the rest are
repo-minted (`07-5123-08-1044-*` mirror, `07-5123-08-1045-*`
snapshot, dots stripped), MINTED-pending-confirm. Wording in
code/tests is paraphrase only, never spec text (D1). Deferred with
cause: schedule/sampling/supply commands (ScheduleSnapshot,
StartSampling family, ChangeSupply family) — command shapes only,
no behavior; and the TOU/block sub-payload typed builders cover the
common delivered/received sets while rarer payload shapes travel as
bounded opaque bytes.

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 07-5123-08-104-01 | implemented + verified | `mirror.rs::MirrorClient` keeps the meter-side grant record distinct from the ESI-side `MirrorTable` (mirrored-metering vs metering device types live on different ends, never merged) | `tests/se_mirror_vectors.rs::vector_meter_grant_intake_*` + sim `se_mirror_loop.rs` end-to-end |
| 17-05019-012-422-02 | implemented + verified | `mirror.rs` direction model: physical meter hosts the server, ESI hosts client + one mirror server endpoint per granted meter | `tests/se_mirror_loop.rs::se_mirror_loop_end_to_end` (request → grant → push → release) |
| 17-05019-012-423-01 | implemented + verified | `mirror.rs::MirrorTable::may_push` (only the granted meter pushes; violations `NOT_AUTHORIZED`, unknown endpoints `NOT_FOUND`) + `has_capacity` (capacity advertisement) + `AttrReadiness::classify` (unsupported → `UNSUPPORTED_ATTRIBUTE`, supported-but-empty → `NOT_FOUND` mapping, corpus term `ATTRIBUTE_UNAVAILABLE` noted; anchors p0105-L2333-L2339 + p0105-L2344-L2348 — wave-27 bonus-2 span correction extends the tail) | `tests/se_mirror_vectors.rs::vector_mirror_push_gate_*`, `vector_mirror_readiness_*` |
| 17-05019-012-423-02 | implemented + verified | `snapshot.rs::SnapshotStore::query` (single matching snapshot by offset in take order, time window `[earliest, latest)`, cause-overlap filter, `CAUSE_ALL` wildcard; miss → `NOT_FOUND`) | `tests/se_mirror_vectors.rs::vector_meter_get_snapshot_*`, `vector_snapshot_store_take_query_*`, sim `se_mirror_loop.rs` retrieve leg |
| 07-5123-08-1044-01 | implemented + verified | `mirror.rs` empty `RequestMirror`/`RemoveMirror` codecs + `metering::ServerBehavior::request_mirror`/`remove_mirror` outbound emitters | `tests/se_mirror_vectors.rs::vector_empty_setup_codec_*`, `vector_meter_setup_outbound_*` |
| 07-5123-08-1044-02 | implemented + verified | `mirror.rs` 2-octet LE `RequestMirrorResponse`/`MirrorRemoved` codecs (incl. `0xFFFF` refusal + grantable-range gate) + `MirrorClient::on_response`/`on_removed` | `tests/se_mirror_vectors.rs::vector_mirror_endpoint_codec_*`, `vector_mirror_client_record_*`, `vector_meter_grant_intake_*` |
| 07-5123-08-1044-03 | implemented + verified | `mirror.rs::MirrorReport` (scheme + ≤8 flag words) codec + `MirrorClient::on_report` intake | `tests/se_mirror_vectors.rs::vector_mirror_report_codec_*`, `vector_mirror_client_report_*`, `vector_meter_report_intake_*` |
| 07-5123-08-1044-04 | implemented + verified | `mirror.rs::endpoint_is_grantable` (`0x0001..=0x00F0` grantable, `0xFFFF` refusal, rest reserved) | `tests/se_mirror_vectors.rs::vector_mirror_endpoint_codec_*` |
| 07-5123-08-1044-05 | implemented + verified | `mirror.rs::MirrorTable` (4-entry bounded ring, idempotent re-request, full → `0xFFFF` refusal, release only by granted meter or ESI) | `tests/se_mirror_vectors.rs::vector_mirror_table_grants_*`, `vector_mirror_table_remove_*`, `se_roundtrip.rs::fuzz_mirror_snapshot_stay_bounded` |
| 07-5123-08-1045-01 | implemented + verified | `snapshot.rs` TakeSnapshot/TakeSnapshotResponse codecs + `metering::ServerBehavior` take leg (manual bit folded in, live-summation sub-payload, tariff-change pair takes, unsupported-cause refusal without storing) | `tests/se_mirror_vectors.rs::vector_take_snapshot_codec_*`, `vector_meter_take_snapshot_*`, `vector_meter_take_unsupported_*` |
| 07-5123-08-1045-02 | implemented + verified | `snapshot.rs` GetSnapshot codec + PublishSnapshot header codec (16 octets) + bounded sub-payload carrier (≤48) + typed TOU builder (≤4 tiers) | `tests/se_mirror_vectors.rs::vector_get_snapshot_codec_*`, `vector_publish_snapshot_codec_*`, `vector_tou_sub_payload_*` |
| 07-5123-08-1045-03 | implemented + verified | `snapshot.rs` cause bits (tariff-change 3, manual 10, scheduled 16, `SUPPORTED_CAUSES` mask) + `SnapshotStore::take_pair` (before/after pair around tariff changes) | `tests/se_mirror_vectors.rs::vector_snapshot_take_pair_*` |
| 07-5123-08-1045-04 | implemented + verified | `snapshot.rs::SnapshotStore` (8-entry ring, consecutive ids, oldest evicted when full, `match_count` for `total_found`) | `tests/se_mirror_vectors.rs::vector_snapshot_store_take_query_*`, `se_roundtrip.rs::fuzz_mirror_snapshot_stay_bounded` |

## Wave-28 traceability — metering schedule/sampling/supply (`rounddance-zcl`)

Corpus ID `17-05019-012-423-03` is reused verbatim; the rest are
repo-minted (`07-5123-08-1046-*` schedule, `07-5123-08-1047-*`
sampling, `07-5123-08-1048-*` supply, dots stripped),
MINTED-pending-confirm. Wording in code/tests is paraphrase only,
never spec text (D1). This closes the wave-26 deferral: the common
schedule/sampling/supply sub-payload shapes are typed and wired into
the snapshot/metering server paths. Rarer shapes stay bounded-opaque
by design (documented, never silent): the notification-scheme
machinery (`ConfigureMirror`, `ConfigureNotificationScheme`,
`ConfigureNotificationFlag`, `GetNotifiedMessage` — server commands
`0x08..=0x0B`, answered `UnsupCommand`) and non-TOU publish
sub-payloads (carried as bounded bytes, never built here). Anchors
below are extraction page+line pins (zcl `07-5123-08` unless noted).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 17-05019-012-423-03 | implemented + verified (reused: supply-control ordering) | `supply.rs::SupplyMachine` (delayed commands serialize by issuer — newer overrides; immediate never auto-cancels; exact-match cancel resets the pending time without touching status; past-dated nonzero → `INVALID_VALUE`, unauthorized → `NOT_AUTHORIZED`, incapable → `UNSUP_COMMAND`; anchors p0101-L2192-L2202 + p0101-L2206-L2211) | `tests/se_schedule_vectors.rs::vector_supply_machine_ordering_17_05019_012_423_03`, `vector_meter_supply_orders_07_5123_08_1048_01` + sim `se_schedule_loop.rs` delayed leg |
| 07-5123-08-1046-01 | implemented + verified | `schedule.rs` ScheduleSnapshot codecs (client `0x04`: issuer + index/total + concatenated 13-octet entries; anchors p0799-L18066-L18069 + p0802-L18137-L18156) + fragment assembler (bounded 52 B / 4 fragments, in-order, retransmitted head restarts) + ScheduleSnapshotResponse codec (issuer + ≤4 confirmation pairs; anchor p0776-L17452-L17472) + `metering::ServerBehavior` schedule arm | `tests/se_schedule_vectors.rs::vector_schedule_entry_codec_*`, `vector_schedule_response_codec_*`, `vector_schedule_assembler_*`, `vector_meter_schedule_take_fire_*` + `se_roundtrip.rs::fuzz_schedule_sample_supply_stay_bounded` |
| 07-5123-08-1046-02 | implemented + verified | `schedule.rs::ScheduleTable` (4-entry bounded file: id range 1..=254, TOU-delivered-shape gate, cause-mask gate, newer-issuer replace / stale-ignore, full → insufficient-space, supports flag) + `collect_due` (per-grid-point firing with catch-up cursors) + `metering::tick_metering` schedule leg (fires into `SnapshotStore` with the scheduled bit folded in; entry layout anchor p0803-L18157-L18171) | `tests/se_schedule_vectors.rs::vector_schedule_table_intake_*`, `vector_schedule_table_due_*`, `vector_meter_schedule_take_fire_*` + sim `se_schedule_loop.rs` timetable leg |
| 07-5123-08-1046-03 | implemented + verified | `schedule.rs` bitmap split (low-20 count, bits 20-21 day/week/month unit, bits 22-23 phase hint) + `schedule_period_s` (day = 1 d, week = 7 d, month = 30 d; zero/reserved → 0, never fires; anchor p0803-L18162-L18165) | `tests/se_schedule_vectors.rs::vector_schedule_bitmap_07_5123_08_1046_03` |
| 07-5123-08-1047-01 | implemented + verified | `sampling.rs` StartSampling codec (13 octets: issuer/start/type/interval/max; anchors p0805-L18212-L18235) + StartSamplingResponse codec (session id or `0xFFFF` sentinel; anchor p0794-L17948-L17961) + `SampleEngine::open` (stale-issuer ignore, same-issuer cancel, capacity → sentinel, unknown-type/zero-interval/zero-count → `InvalidField`) + `metering::ServerBehavior` start arm | `tests/se_schedule_vectors.rs::vector_start_sampling_codec_*`, `vector_sample_engine_sessions_*`, `vector_meter_sampled_data_*` + sim `se_schedule_loop.rs` sampling leg |
| 07-5123-08-1047-02 | implemented + verified | `sampling.rs` GetSampledData codec (9 octets) + GetSampledDataResponse codec (11-octet header + 24-bit series, invalid sample `0xFFFFFF` preserved; anchors p0805-L18243-L18266 + p0786-L17736-L17765) + `SampleEngine::query` (id + type match, earliest filter, count cap, empty → `NOT_FOUND`) + `metering::ServerBehavior` retrieval arm | `tests/se_schedule_vectors.rs::vector_sampled_data_codec_*`, `vector_sample_engine_sessions_*`, `vector_meter_sampled_data_*` |
| 07-5123-08-1047-03 | implemented + verified | `sampling.rs` sample-type gate (`0..=4`: delivered/received/reactive pair + demand snapshots; anchor p0786-L17747-L17751 + alignment note p0800-L18073-L18077) + `SAMPLE_INVALID` marker passthrough + `MAX_SAMPLES_PER_SESSION` (16-sample log fits the 64-octet reply path) | `tests/se_schedule_vectors.rs::vector_start_sampling_codec_*`, `vector_sampled_data_codec_*` |
| 07-5123-08-1047-04 | implemented + verified | `sampling.rs::SampleEngine` (2-session bound, chronological capture log, future-dated opens on `tick`, session closes at capacity, push-refuses-quietly past the end) + `metering::tick_metering` sampling leg (activation state event) | `tests/se_schedule_vectors.rs::vector_sample_engine_sessions_*`, `vector_sample_engine_tick_*` + `se_roundtrip.rs::fuzz_schedule_sample_supply_stay_bounded` |
| 07-5123-08-1048-01 | implemented + verified | `supply.rs` ChangeSupply codec (18 octets) + SupplyStatusResponse codec (13 octets; anchors p0807-L18300-L18304 + p0793-L17925-L17947) + `SupplyMachine::apply_change`/`tick` (immediate/delayed/cancel paths, ack bit → response on execution) + `metering::ServerBehavior` change arm + `tick_metering` supply leg (delayed ack queued as outbound command) | `tests/se_schedule_vectors.rs::vector_change_supply_codec_*`, `vector_supply_machine_ordering_*`, `vector_meter_supply_orders_*` + sim `se_schedule_loop.rs` supply leg |
| 07-5123-08-1048-02 | implemented + verified | `supply.rs` LocalChangeSupply codec (remote states `ARMED`/`ON` only; anchor p0809-L18356-L18374) + `SupplyMachine::apply_local` (no response ever, incapable → `UNSUP_COMMAND`) + `metering::ServerBehavior` local arm (state event, no reply) | `tests/se_schedule_vectors.rs::vector_local_and_reset_codec_*`, `vector_supply_local_and_events_*`, `vector_meter_supply_orders_*` + sim `se_schedule_loop.rs` tamper leg |
| 07-5123-08-1048-03 | implemented + verified | `supply.rs` SetSupplyStatus codec (8 octets: issuer + 4 event states; anchor p0810-L18381-L18405) + `SupplyMachine::apply_set_status` (newer-issuer-wins, stale ignored) + `apply_event` (per-event directive, `UNCHANGED` → `None`) | `tests/se_schedule_vectors.rs::vector_set_supply_status_codec_*`, `vector_supply_local_and_events_*` + sim `se_schedule_loop.rs` tamper leg |
| 07-5123-08-1048-04 | implemented + verified | `supply.rs` SetUncontrolledFlowThreshold codec (18 octets, zero multiplier/divisor refused both directions; anchor p0811-L18406-L18435) + `SupplyMachine::apply_flow` (issuer-ordered) + `flow_trip_value` (threshold × multiplier ÷ divisor, zero threshold disables) | `tests/se_schedule_vectors.rs::vector_flow_threshold_codec_*`, `vector_supply_guard_and_reset_*`, `vector_meter_supply_orders_*` |
| 07-5123-08-1048-05 | implemented + verified | `supply.rs` ResetLoadLimitCounter codec (8 octets: provider + issuer; anchor p0807-L18285-L18298) + `SupplyMachine::reset_load_limit` (issuer-ordered counter zeroing) + `metering::ServerBehavior` reset arm (silent) | `tests/se_schedule_vectors.rs::vector_local_and_reset_codec_*`, `vector_supply_guard_and_reset_*` |

## Wave-27 traceability — LQI/RSSI metering fix + steering policy (`rounddance-hal-esp`, `rounddance-commission`)

Corpus ID reused verbatim: `22-65816-030-91-01` (suitability is read
from the discovery table by the application). One repo-minted ID
(`RD-HAL-ESP-13`), MINTED-pending-confirm. Wording in code/tests is
paraphrase only, never spec text (D1). No new corpus claims: the
metering contract comes from the IDF header
(`components/ieee802154/include/esp_ieee802154.h` §"reception" +
`esp_ieee802154_types.h` `frame_info_t`), and the flat-LQI phenomenon
is field evidence (bench logs `join_run5/6.log`: tail-LQI 10–11,
tail-RSSI −28 dBm, nRF grading the same air 252/255 at ~100% decode),
not a spec value.

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 22-65816-030-91-01 | implemented + verified (reused: application-side suitability) | `steering.rs::LinkEvidencePolicy` (decode-by-delivery + `min_rssi` sanity, default −90 dBm + `lqi_floor: None`; ranking stays relative, ties to lower PAN) + `JoinerApp::survey` + host `scenario.rs` switched from the absolute `min_lqi = 100` gate | `tests/vectors.rs::vector_field_policy_admits_flat_lqi_strong_link`, `vector_field_policy_reject_legs`, `vector_field_policy_ranking_and_opt_in_floor` + sim `commission_join.rs` end-to-end admit |
| RD-HAL-ESP-13 | implemented + verified | `esp.rs::esp_ieee802154_receive_done` reads per-frame channel/RSSI/LQI from the callback `frame_info` (primary) with the FCS-replaced frame-tail fallback + null-info counter; `ffi.rs::EspFrameInfo` repr(C) binding; most-recent getters deliberately unbound (stale on air) | `tests/adapter_mock.rs::rx_meters_are_per_frame_not_stale` (back-to-back + reversed pairs keep their own meters) + `c6_standalone.rs` full run under the field policy |

Bonus-2 span corrections applied (4, all mechanics, zero substance —
see corpus `mining-log.md`, bonus batch 2): `22-65816-030-56-01`
anchor is p0033-L525-L529 (embedded in its row above);
`17-05019-012-423-01` anchors are p0105-L2333-L2339 +
p0105-L2344-L2348 (embedded in its row above);
`17-05019-012-422-03` anchor extends to p0033-L670-L673 (no repo
implementing row — the alternative-unit claim lives in corpus only);
`07-5356-22-C26-02` anchor extends to p0149-L3856-L3860 (no repo
implementing row — method-selection claim lives in corpus only).

## Wave-29 traceability — compressed-point ephemeral (`rounddance-security`, `rounddance-zcl`)

Corpus IDs reused verbatim (`07-5123-08-1074-*` ephemeral exchange
rules, `07-5356-22-C312-06/07` sequence + length rules); zero new
repo-minted IDs. Wording in code/tests is paraphrase only, never spec
text (D1). This closes the wave-22 deferral ("compressed-point
codecs are follow-up work", previously recorded on `07-5123-08-1074-05):
ephemeral points are now accepted in both wire forms — the 33-octet
compressed encoding (parity tag + x, `y` recovered through the field
square root) and the 64-octet expanded convention — while transmit
uses the locally preferred form (`Exchange::set_tx_compressed`,
default expanded). The CBKE parameter table's ephemeral entries are
point-compressed values (anchor p0865-L19821); the 22-octet suite-1
sizes in that table belong to the older binary-curve suite and do not
govern this P-256 profile's 33-octet SEC1 form. The P-256 prime shape
(`p % 4 == 3`) is verified against the crypto stack's own field
source (`p256` 0.14 `arithmetic/field.rs` modulus
`ffffffff00000001…ffffffff`, trailing octet `0xFF`) and re-pinned by
`p256field::tests::prime_is_three_mod_four`, so the square root is a
single exponentiation to `(p + 1) / 4`, never an assumed shortcut.

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 07-5123-08-1074-02 | implemented + verified (extended: malformed compressed payloads terminate) | `keyest.rs::decode_peer` (wrong length, unknown tag, `x >= p`, non-residue `x` all map to `TERM_BAD_MESSAGE`; a malformed ephemeral field is never a certificate defect) + `on_ephemeral_request`/`on_ephemeral_response` accept 33 or 64 octets | `tests/se_vectors.rs::vector_keyest_compressed_rejection_07_5123_08_1074_02` (non-residue, bad tag, 32/34-octet legs on both paths, `TERM_BAD_MESSAGE` + `Failed` pinned) |
| 07-5123-08-1074-05 | implemented + verified (extended: both wire forms, was expanded-only) | `p256field.rs` (field add/sub/mul/pow, `sqrt_mod`, `y_from_x`) + `ecc.rs::compress_point`/`decompress_point` + `EccBackend::point_decompress` (default core body, so the mock backend proves the same bytes the host serves) + `keyest.rs::EphemeralPayload` (33/64-octet variants, `as_slice`/`len`/`is_compressed`) + `Exchange::set_tx_compressed`/`tx_compressed` preference (default expanded) | `tests/compressed.rs::vector_compressed_published_points_07_5123_08_1074_05` (G 0x03 + handshake pins rec_r 0x03 / rec_i 0x02, byte-pinned, stack-decoder agreement) + `vector_compressed_round_trip_host_07_5123_08_1074_05` (12 scalars both parities) + `vector_compressed_rejection_host_07_5123_08_1074_05` + `fuzz_compressed_never_panics_mock_matches` (8k, involution) + `tests/roundtrip.rs::fuzz_compressed_point_shape` (8k, backend-free) + `tests/se_vectors.rs::vector_keyest_compressed_forms_07_5123_08_1074_05` (default expanded, compressed expands to same point, responder answers in own form) + `se_roundtrip.rs::fuzz_compressed_ephemeral_shapes` (6k) |
| 07-5356-22-C312-06 | implemented + verified (reused: wire form never splits keys) | `keyest.rs` transcript absorbs expanded points in canonical role order regardless of wire form (`decode_peer` expands before `receive_peer`) | `tests/se_vectors.rs::vector_keyest_compressed_handshake_07_5356_22_c312` (compressed/compressed, mixed, and expanded-only runs release identical session keys) + sim `se_loop.rs::se_loop_compressed_ephemeral_agrees` (full CBKE → key → price → meter with compressed flights; exactly the 2 ephemeral frames differ on air) + `se_loop_compressed_replays_deterministically` (byte-identical replay) |
| 07-5356-22-C312-07 | implemented + verified (reused: exact form rule is now 33-or-64) | `keyest.rs::EPH_COMPRESSED_LEN` (33, compressed tag + x) beside `EPH_LEN` (64, expanded convention) | `tests/se_vectors.rs::vector_keyest_ephemeral_length_07_5123_08_1074_05` (64-octet rule preserved; 65-octet still refused) + the 1074-02 rejection legs above (32/34-octet refused) |

## Wave-31 traceability — metering notification-scheme machinery (`rounddance-zcl`)

No corpus IDs cover the deferred tail beyond the anchors below, so 6
repo-minted IDs (`07-5123-08-1049-*`, dots stripped),
MINTED-pending-confirm. Wording in code/tests is paraphrase only,
never spec text (D1). This closes the wave-28 deferral ("the
notification-scheme machinery ... stays bounded-opaque"): the four
server-generated commands (`0x08..=0x0B`) are now typed, the mirror
side stages configurations under issuer ordering, and the meter side
emits the commands and plans fetches from flag reports. Non-TOU
publish shapes (calendar / prepayment / device-management flag words
and their payloads) stay bounded-opaque by design — carried as raw
bits/bytes, never built here. The pending-message timeout is operator
policy (caller seconds), never prescribed; duplicate deliveries are
idempotent by (source, endpoint, TSN, cluster, command).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 07-5123-08-1049-01 | implemented + verified | `notify.rs` ConfigureMirror codec (9 octets: issuer + uint24 interval + reporting boolean + scheme; anchors p0787-L17773-L17774 + p0787-L17780-L17782 + p0788-L17783-L17786) + `MirrorNotify::apply_configure_mirror` (issuer-ordered, unsupported scheme → `INVALID_FIELD`, stale ignored, predefined enables at once; anchors p0790-L17811-L17816) + `metering::ServerBehavior::configure_mirror` emitter + SERVER_TX `0x08` | `tests/se_notify_vectors.rs::vector_configure_mirror_codec_07_5123_08_1049_01`, `vector_mirror_configure_07_5123_08_1049_01`, `vector_meter_configure_emits_07_5123_08_1049_01` + sim `se_notify_loop.rs` configure leg |
| 07-5123-08-1049-02 | implemented + verified | `notify.rs` scheme taxonomy (`NONE`/`A`/`B`/generic/MSP/reserved; order words `0x0FFFFFFF`/`0x01234FFF`; anchors p0789-L17802-L17807 + p0817-L18614-L18634) + ConfigureNotificationScheme codec (issuer + scheme + 8-nibble order; anchors p0790-L17828-L17842) + `MirrorNotify::apply_scheme` (predefined immutable, staged under issuer ordering, two-way gated until complete; anchors p0791-L17846-L17852) | `tests/se_notify_vectors.rs::vector_scheme_gates_07_5123_08_1049_02`, `vector_configure_scheme_codec_07_5123_08_1049_02`, `vector_generic_scheme_staging_07_5123_08_1049_02` + `se_roundtrip.rs::fuzz_notify_stay_bounded` |
| 07-5123-08-1049-03 | implemented + verified | `notify.rs` ConfigureNotificationFlag codec (7-octet header + ≤4 allocation records of cluster + mfr + count + ≤8 command ids; anchors p0791-L17862-L17870 + p0792-L17875-L17877) + `MirrorNotify::apply_flag` (predefined immutable, flag-attr ≤ 7, staged-scheme match; anchors p0792-L17888-L17894) + `metering::ServerBehavior::configure_flag`/`configure_scheme` emitters + SERVER_TX `0x09`/`0x0A` | `tests/se_notify_vectors.rs::vector_configure_flag_codec_07_5123_08_1049_03` + `se_roundtrip.rs::fuzz_notify_stay_bounded` |
| 07-5123-08-1049-04 | implemented + verified | `notify.rs` notification attribute set (functional `0x0000` + Flags2..8 `0x0001..=0x0007`, Read map32; anchors p0795-L17966-L17980) + implemented functional bits (stay-awake 4/5, supply 18/19/20, snapshot 22, sampled-data 23; anchors p0796-L17983-L17988) + price Flags2 bits (price 0, block period 1, block thresholds 9, tier labels 14, cancel tariff 15; anchor p0817-L18632-L18636) | `tests/se_notify_vectors.rs::vector_mirror_raise_lower_07_5123_08_1049_04` (raise/lower independence) + `vector_mirror_queue_*` (bit mapping) |
| 07-5123-08-1049-05 | implemented + verified | `notify.rs::MirrorNotify` pending queue (4-entry bounded cache, idempotent duplicates, oversize refused as full; anchors p0815-L18544-L18548) + `fetch` (scheme/flag/mask match, oldest-first, drained bits clear, empty → `NOT_FOUND`; bit-reset rule anchor p0795-L17975-L17979, fetch-effect anchors p0793-L17911-L17922) + `expire` (operator timeout → `TIMEOUT` originators; anchors p0816-L18556-L18562) + `status.rs::NotificationPending` (`0x9A`; anchor p0109 status table) + `metering::ServerBehavior::get_notified` emitter + SERVER_TX `0x0B` | `tests/se_notify_vectors.rs::vector_get_notified_codec_07_5123_08_1049_05`, `vector_notification_pending_status_07_5123_08_1049_05`, `vector_mirror_queue_07_5123_08_1049_05`, `vector_mirror_queue_edges_07_5123_08_1049_05` + sim `se_notify_loop.rs` fetch/timeout legs + `se_roundtrip.rs::fuzz_notify_stay_bounded` |
| 07-5123-08-1049-06 | implemented + verified | `notify.rs::BomdNotify` (configured-scheme record + latest flag report; the BOMD stays in control of when it fetches) + `plan_fetch` (functional fetchable bits only; publish-information bits stay on application Get commands) + report intake wired into `metering::ServerBehavior` (mirror-report arm notes into both `MirrorClient` and `BomdNotify`) | `tests/se_notify_vectors.rs::vector_meter_fetch_plan_07_5123_08_1049_05` + sim `se_notify_loop.rs` report → plan → fetch → execute → relay leg with deterministic replay |

## Wave-33 traceability — NWK routing commands + route discovery (doc 05-3474-23 R23.2 §3.4/§3.6.4)

No corpus IDs cover the routing commands or the discovery flow (the
seed corpus stops at header framing: `05-3474-23-331-*`,
`05-3474-23-34-01`, `05-3474-23-3211-*`), so 6 repo-minted IDs
(`05-3474-23-341-*`, `-342-*`, `-348-*`, `-3645-*`, dots stripped),
MINTED-pending-confirm. Wording in code/tests is paraphrase only,
never spec text (D1). Reused corpus IDs where they cover behavior:
header framing `05-3474-23-331-01/02` (command NPDUs ride the framed
header), command-header rule `05-3474-23-34-01`
(`FrameControl::command`), inbound guard `05-3474-23-3213-01`. Closes
audit R1 (wave-32): `RouteRequest`/`RouteReply`/`LinkStatus` codecs
now exist in `rounddance-nwk`, and route discovery runs over the
existing `RouterMachine::forward` / `RouterApp::tick` seam — no
second routing path.

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 05-3474-23-341-01 | implemented + verified | `commands.rs`: `RouteRequest` + `RouteRequestOptions` (`ManyToOne` 0..2, dst-ieee presence) + `decode_route_request` (TLV tail borrowed opaquely); `route.rs`: `add_path_cost` saturating sum | `tests/vectors.rs::vector_route_request_unicast_05_3474_23_341_01`, `vector_route_request_many_to_one_ieee_05_3474_23_341_01`, `vector_path_cost_saturates_05_3474_23_341_01` + `tests/roundtrip.rs::fuzz_command_round_trip_identity`, `fuzz_command_mutations_never_panic` |
| 05-3474-23-342-01 | implemented + verified | `commands.rs`: `RouteReply` + `RouteReplyOptions` (originator/responder IEEE presence) + `decode_route_reply` | `tests/vectors.rs::vector_route_reply_full_05_3474_23_342_01` + `tests/roundtrip.rs::fuzz_command_round_trip_identity`, `fuzz_command_mutations_never_panic` |
| 05-3474-23-348-01 | implemented + verified | `commands.rs`: `LinkStatus` + `LinkStatusEntry` (incoming 1..=7, outgoing 0..=7) + `LinkStatusOptions` (entry count + first/last) + `decode_link_status` (count-match enforced) + `MAX_LINK_STATUS_ENTRIES` (16), `LINK_COST_MAX_AGE_MS` | `tests/vectors.rs::vector_link_status_two_entries_05_3474_23_348_01` + `tests/roundtrip.rs::fuzz_command_round_trip_identity`, `fuzz_command_mutations_never_panic` |
| 05-3474-23-348-02 | implemented + verified | `route.rs`: `NeighborCosts` (outgoing = neighbor's advertised incoming for us; full-table refusal keeps live rows; `tick` aging at `LINK_COST_AGE_MS`) + `RouterMachine::{note_link_status, note_incoming_cost, outgoing_cost}` | `tests/vectors.rs::vector_link_cost_aging_05_3474_23_348_02` + `rounddance-roles/tests/vectors.rs::router_routing_seam_discovery_and_aging` |
| 05-3474-23-3645-01 | implemented + verified | `route.rs`: `RouteTable` (16-entry bounded; same-destination refresh cheaper-or-expired-wins; expired-slot reclaim; `TableFull` refusal) + `RouterMachine::{next_hop, install_route, tick_routing}` over the existing forward path | `tests/vectors.rs::vector_route_table_lifecycle_05_3474_23_3645_01` + `rounddance-roles/tests/vectors.rs::router_routing_seam_discovery_and_aging` + `rounddance-sim/tests/route_discovery.rs::route_discovery_then_routed_frame` |
| 05-3474-23-3645-02 | implemented + verified | `route.rs`: `DiscoveryTable` (4-session cap, per-destination single-flight, spaced retries ×3, 5 s deadline, stray replies refused) + `SeenRequests` (8-entry loop-suppression ring, 10 s lifetime) + `RouterMachine::{start_discovery, note_discovery_reply, should_suppress_request, authorize_discovery_retry}` | `tests/vectors.rs::vector_discovery_session_guards_05_3474_23_3645_02`, `vector_loop_suppression_05_3474_23_3645_02` + `rounddance-roles/tests/vectors.rs::router_routing_seam_discovery_and_aging` + `rounddance-sim/tests/route_discovery.rs::route_discovery_then_routed_frame`, `route_discovery_replays_identically` |

## Wave-34 traceability — GP bidirectional commissioning reply path (doc 14-0563-19 Green Power Basic v1.1.2 §A.1.7.3–A.1.7.5 / §A.4.2.1.2 / §A.4.2.1.4 / §A.4.2.1.5)

Closes audit R3 (wave-32): the bidirectional reply path is implemented
in `rounddance-gp` (`reply.rs` codecs + `commissioning.rs` session),
reusing the existing `GpTxQueue` one-per-GPD queue and the 20–25 ms
serve window (`TX_OFFSET_MS`/`TX_OFFSET_MAX_MS`). 7 repo-minted IDs
(`14-0563-19-A173-01/02`, `-A4211-01`, `-A4212-01/02`, `-A4214-01`,
`-A4215-01`, dots stripped), MINTED-pending-confirm. Wording in code/tests is
paraphrase only, never spec text (D1). Reused corpus IDs where they
cover behavior: `14-0563-19-A152-01` (queue), `14-0563-19-A152-02`
(window), `14-0563-19-A36-07` (table population on completion),
`14-0563-19-A163-01` (GPD receive capability behind the window).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 14-0563-19-A173-01 | implemented + verified | `commissioning.rs::check_bidir_capable` + `CommissioningSession::complete_at` peer gate (key request with no receive window, or with no security capability, refuses as `PeerIncapable`; anchors p0069-L1921-L1927 + p0242-L6842-L6844) | `tests/vectors.rs::vector_bidir_incapable_peer_14_0563_19_a173_01` |
| 14-0563-19-A173-02 | implemented + verified | `commissioning.rs::REPLY_TIMEOUT_MS` (5 s) + `CommissioningSession::{complete_at, tick}` (park with deadline, lapse returns to idle as `ReplyTimeout`; anchor p0071-L2007-L2009) | `tests/vectors.rs::vector_bidir_reply_timeout_14_0563_19_a173_02` + `rounddance-sim/tests/gp_bidir.rs::gp_bidir_mismatch_and_timeout_edges` |
| 14-0563-19-A4211-01 | implemented + verified | `reply.rs` command IDs (`CMD_COMMISSIONING` 0xE0, `CMD_DECOMMISSIONING` 0xE1, `CMD_SUCCESS` 0xE2, `CMD_CHANNEL_REQUEST` 0xE3, `CMD_COMMISSIONING_REPLY` 0xF0, `CMD_CHANNEL_CONFIG` 0xF3; anchors p0252-L6970-L6972 + p0258-L7210-L7212 + p0012 Table 55/56 rows) + `is_payloadless_commissioning` | `tests/vectors.rs::vector_bidir_command_ids_14_0563_19_a4211_01` |
| 14-0563-19-A4212-01 | implemented + verified | `reply.rs::CommissioningReply` + `ReplyOptions` (options/PANID/key/MIC/counter order; key material gated to nonzero levels; reserved level refused; anchors p0258-L7204-L7215 + p0259-L7217-L7237) + `MAX_LEN` 27 | `tests/vectors.rs::vector_reply_panid_only_14_0563_19_a4212_01`, `vector_reply_clear_key_14_0563_19_a4212_01`, `vector_reply_protected_key_14_0563_19_a4212_01`, `vector_reply_rejection_14_0563_19_a4212_01` + `tests/roundtrip.rs::fuzz_reply_round_trip`, `fuzz_reply_malformed_never_panics` |
| 14-0563-19-A4212-02 | implemented + verified | `commissioning.rs::CommissioningSession::{stage_reply, build_reply, note_success}` (shape-checked staging, in-window serve, identity-matched Success commissions with a translation seed else `TransactionMismatch`; anchors p0259-L7238-L7250) | `tests/vectors.rs::vector_bidir_full_exchange_14_0563_19_a4212_02`, `vector_bidir_state_gates_14_0563_19_a4212_02` + `rounddance-sim/tests/gp_bidir.rs::gp_bidir_commissioning_reply_two_node`, `gp_bidir_replay_is_deterministic` |
| 14-0563-19-A4214-01 | implemented + verified | `reply.rs::ChannelRequest` (1-octet toggling behavior, nibbles name channels 11..=26; anchors p0259-L7259-L7270) | `tests/vectors.rs::vector_channel_codecs_14_0563_19_a4214_01_a4215_01` + `tests/roundtrip.rs::fuzz_reply_round_trip` |
| 14-0563-19-A4215-01 | implemented + verified | `reply.rs::ChannelConfig` (1-octet channel: operational channel + basic-only flag; anchors p0260-L7275-L7292) | `tests/vectors.rs::vector_channel_codecs_14_0563_19_a4214_01_a4215_01` + `tests/roundtrip.rs::fuzz_reply_round_trip` |

## Wave-35 traceability — PRO best-effort evidence (`rounddance-compat`)

Closes audit R5 (wave-32): PRO (doc `22-65816-030` v3.1, 103 pp,
extracted per corpus `coverage.md` Doc 7) moves from ZERO repo
evidence to a tracked best-effort subset in the compat-crate seam.
4 repo-minted IDs (`RD-PRO-01..04`), MINTED-pending-confirm.
Wording in code/tests is paraphrase only, never spec text (D1).
Reused corpus IDs where they cover behavior: `05-3474-23-331-02`
(shared NWK version 2), `05-3474-23-3615-01` (discovery version /
profile filter), `22-65816-030-91-01/02` (survey + symmetric
exchange), `22-65816-030-56-03` (install-code key).

Best-effort boundary (also documented at `negotiate::admit_pro_peer`):
COVERS recognition of a PRO-legacy peer (shared NWK version 2 +
PRO stack-profile value + symmetric-only key capabilities), one
typed accept/refuse decision per candidate network, and the
version-gate extension keeping unknown versions out of the join
machine. Does NOT cover full PRO commissioning: no BDB
formation/steering procedures, no Trust-Center PRO policies, no
PRO install-code policy tables, no PRO commissioning-frame
translation. Admitted PRO peers join over the proven symmetric
exchange; anything PRO-specific beyond admission is a typed
refusal, never a silent downgrade.

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| RD-PRO-01 | implemented + verified | `negotiate::admit_pro_peer`: version → profile → permission → method → level bundle (doc `22-65816-030` v3.1 body, R23.2 §3.6.1.5 discovery anchors) | `compat/tests/vectors.rs::vector_pro_peer_accepted`, `rounddance-sim/tests/pro_best_effort.rs::pro_best_effort_accept_and_replay` |
| RD-PRO-02 | implemented + verified | `profile::PRO_STACK_PROFILE` 0x02 + `negotiate::admit_pro_stack_profile` (anchors: `05-3474-23-3615-01` discovery filter) | `compat/tests/vectors.rs::vector_pro_stack_profile_gate` |
| RD-PRO-03 | implemented + verified | refusal matrix in `admit_pro_peer` (`UnsupportedStackProfile`, `JoiningClosed`, plus reused `UnsupportedNwkVersion` / `NoCommonKeyMethod` / `SecurityDowngradeRefused`); closed networks refused before any key decision | `compat/tests/vectors.rs::vector_pro_peer_refusal_matrix`, `rounddance-sim/tests/pro_best_effort.rs::pro_closed_network_never_joins` |
| RD-PRO-04 | implemented + verified | version-gate extension: shared version-2 recognition (`admit_nwk_version`) explicitly covers PRO beacons via the `admit_pro_peer` bundle; `profile::StackProfile::Pro` + `CompatPeer::profile_pro` (symmetric-only, baseline level) | `compat/tests/vectors.rs::vector_pro_peer_accepted` (accept leg pins the shared version) |

## Wave-36 traceability — Ember NWK decrypt-gap closure (`rounddance-security`)

Root-causes the (b)-class interop blocker from wave-33 forensics
(`~/hwscratch/mg21form/nwk_decrypt.log`, `nwk_decrypt2.log`): offline
CCM\* opens of genuine Ember NWK frames failed because the scripts
fed the on-air auxiliary control octet (level bits zeroed by the
sender after protection) into the nonce and authenticated bytes.
The receiver must restore the network-base level into the control
octet first, then build the 13-octet nonce and authenticate
NwkHeader plus the restored auxiliary header. Proven by two
captured-air Ember frames (MG21, channel 25, PAN 0xB21D) opening
with the lab network key once restoration is applied.
2 repo-minted IDs (`05-3474-23-431-01`, `05-3474-23-4522-01`),
MINTED-pending-confirm. Wording in code/tests is paraphrase only,
never spec text (D1). Reused corpus IDs where they cover behavior:
`05-3474-23-4312-01` (replay guard still owns counter validation),
`05-3474-23-451-01` (aux codec shapes + the new `as_octet`
serializer), `05-3474-23-B11-01` (test-local opens ride the pinned
AES-128 block cipher; production payload crypto stays a radio/HAL
assist per the wave-2b contract).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 05-3474-23-431-01 | implemented + verified | `SecurityControl::with_level` (incoming level restore) + `AuxHeader::decode_with_level` (zeroed-level NWK decode; trailing octet under network-key bits is the key sequence number) + `AuxReception::decode` doc pointer (§4.3.1.1 outgoing step 8, anchor p0422-L10154; §4.3.1.2 incoming step 1, anchor p0422-L10159-L10160; sequence-number field §4.5.1.4, anchor p0481-L11467-L11469) | `security/tests/vectors.rs::vector_nwk_ember_zeroed_level_opens` (genuine Ember U1/B1 frames: raw decode sees level 0 = the wave-33 trap, restored decode opens both) + `fuzz_nwk_ember_open_rejects_mutations` (7 wrong levels refused) |
| 05-3474-23-4522-01 | implemented + verified | `NwkNonce::from_header` (13-octet source + counter + control order) + `NWK_NONCE_LEN` (§4.5.2.2, anchor p0481-L11480-L11488) | `security/tests/vectors.rs::vector_nwk_ember_zeroed_level_opens` (pinned nonce bytes per frame) + `vector_nwk_nonce_roundtrip_seal_open` (counter/sender sweep) + `fuzz_nwk_ember_open_rejects_mutations` (12495-case nonce/AAD/ciphertext mutation matrix all refused) |

## Wave-40 traceability — packet inspector scaffold (`rounddance-inspect`)

Inspector scaffold only: 802.15.4 MAC + NWK + APS + ZCL dissector chain
producing structured decode trees, offline pcap/pcapng ingest with text /
JSON reports, a stateful session-engine skeleton (per-device / network
tables), and listener / sender traits with NO live drivers. No spec text
mined (D1); wording in code/tests is paraphrase only. 8 repo-minted IDs
(`RD-INSPECT-01..08`), MINTED-pending-confirm. Live-driver binding,
keyed decryption of secured frames, and cluster-payload semantics are
explicit follow-ups, not this wave.

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| RD-INSPECT-01 | implemented + verified | `mac::decode`: bounded 802.15.4 header parse (frame-control LE, seq, PAN-ID compression, short/extended addressing; unsupported modes typed-refused) | `inspect/tests/goldens.rs::golden_full_chain_mac_nwk_aps_zcl` (MAC node fields) + `golden_empty_and_truncated_are_typed` |
| RD-INSPECT-02 | implemented + verified | `chain::dissect`: MAC → NWK → APS → ZCL chain reusing the `rounddance-nwk` / `rounddance-aps` / `rounddance-zcl` codecs; secured frames stop with a `secured` note, never decrypted | `golden_full_chain_mac_nwk_aps_zcl` (4-layer tree) + `golden_captured_air_secured_nwk_stops_chain` (genuine Ember U1/B1 stop at MAC + NWK + secured note; command id stays `None` while encrypted) |
| RD-INSPECT-03 | implemented + verified | `tree`: bounded `DecodeTree` (MAC + NWK + APS + ZCL + one stop note) of owned `Copy` scalars, no borrows, no allocator | `golden_full_chain_mac_nwk_aps_zcl` + `golden_captured_air_secured_nwk_stops_chain` (bare-NWK PDU dissects identically) |
| RD-INSPECT-04 | implemented + verified | `session::SessionEngine`: 32-entry device table + 4-entry network table folded from trees, stalest-row eviction, `device` / `network` lookup | `golden_sender_traits_and_session_engine` (counts, last-seq, PAN attribution, 40-device overfill stays capped) |
| RD-INSPECT-05 | implemented + verified | `capture::Listener` / `capture::Sender` traits (channel + rssi + lqi metadata; no live drivers) | `golden_sender_traits_and_session_engine` (in-memory `Sender` loopback) |
| RD-INSPECT-06 | implemented + verified | `pcap::read_all` (pcap + minimal pcapng: SHB/IDB/EPB, other blocks skipped by length) + `pcap::write_pcap` (pcap writer) | `golden_pcap_write_read_dissect` (round-trip + dissect) + `golden_pcapng_ingest_minimal` (hand-built SHB + IDB + EPB) |
| RD-INSPECT-07 | implemented + verified | `report::to_text` / `report::to_json` (owned-scalar rendering only; secured frames named, never decrypted) | `golden_sender_traits_and_session_engine` (text + JSON layer keys) + `golden_secured_report_names_stop` (`secured:true` in JSON) |
| RD-INSPECT-08 | implemented + verified | `no_std` core (`tree`, `mac`, `nwk`, `aps`, `zcl`, `chain`, `session`, `capture`) with `forbid(unsafe_code)`; `std` capture IO behind the `std` feature | `cargo build -p rounddance-inspect --no-default-features --target wasm32-unknown-unknown` green; default-feature build carries `pcap` + `report` |

## Wave-41 traceability — packet inspector stateful engine (`rounddance-inspect`)

Offline engine growth only: no live drivers, no corpus writes, no keyed
decryption (the reused NWK codec does not surface the security aux
header, so no inspect-layer decryptor can be built on it — key slots
report decryptability, they do not decrypt). 6 repo-minted IDs
(`RD-INSPECT-09..14`), MINTED-pending-confirm. Paraphrase only (D1).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| RD-INSPECT-09 | implemented + verified | `zcl::decode` payload summaries → `tree::ZclDetail`: foundation commands (Read/ReadRsp/Report/DefaultRsp with record count + first id + status) and cluster-specific families On/Off (0x0006), Level (0x0008, first args), IAS Zone (0x0500); unknown/short payloads degrade to `Unknown`/zeroed variants, never an error; `chain` feeds the APS cluster/profile into the node | `inspect/tests/engine.rs::detail_global_read_two_attrs` + `detail_onoff_toggle` + `detail_level_move_to_level` + `detail_global_report_and_default_rsp` + `detail_unknown_cluster_and_truncated_payload`; `golden_full_chain_mac_nwk_aps_zcl` extended with cluster/profile/detail asserts |
| RD-INSPECT-10 | implemented + verified | `session::SeqWindow`: 32-deep rolling window over wrapping 8-bit NWK seq / APS counter with replay/gap/late accounting, folded per attributed device row (APS counter attributed to the frame's source row) | `engine_windows_replay_gap_late` (seqs 10,11,12,11,14,2 → base 14, replays 1, gaps 1, late 1 on both windows) |
| RD-INSPECT-11 | implemented + verified | Short/long binding: IEEE-first row merge (rejoin keeps one row, newest short wins) + `device_by_ieee`; per-PAN distinct-device counting via an 8-short member cache (`EMPTY_MEMBER` sentinel) | `engine_rejoin_merges_by_ieee_and_counts_pan` (same IEEE under 0x1111 then 0x2222 merges; PAN 0 devices == 2) |
| RD-INSPECT-12 | implemented + verified | `keys::KeySlots` (2 NWK slots, replace-by-seq, saturating loads) + engine secured/orphan-vs-decryptable counters; secured frames with a loaded slot count decryptable-offline, never decrypted; keys never rendered | `engine_key_slots_gate_decryptability` (genuine Ember U1: orphan 1 without key, decryptable 1 with lab key; rotation caps at 2 slots) |
| RD-INSPECT-13 | implemented + verified | Stable session schema: `report::session_to_json` (schema `SESSION_SCHEMA = 1`, table-order arrays, null windows, key material never rendered) + `session_to_text`; tree JSON gains `cluster`/`profile`/`detail`, tree text gains cluster/profile/detail suffix | `session_schema_empty_engine_exact` (byte-exact empty snapshot) + `session_schema_one_tree_shape` (byte-exact one-tree snapshot) |
| RD-INSPECT-14 | implemented + verified | Parser robustness: every truncation prefix yields a sub-tree or a typed `TreeError`; 3000-case deterministic mutation sweep + exhaustive 1-/2-byte `zcl::decode` sweep + constant fills; bounded engine tables throughout; typed errors only, no panics | `robustness_truncations_are_typed` + `robustness_mutation_sweep_no_panics` + `robustness_zcl_byte_sweep_typed` |

## Wave-42 traceability — joiner backport (`rounddance-nwk`, `rounddance-commission`, `rounddance-security`)

Audit of the wave-39 lane findings against the repo crates: the
aux-level restore rule was already closed by wave-36, the
counter-zero and seal-shape handling by the existing aux codec —
those three get captured-air regression proofs under their existing
rows, no code changes. Two genuine gaps were backported: the NWK
leave command had no codec, and the join machine had no leave
input (an ejected joiner polled until the transport timeout). 1
repo-minted ID (`05-3474-23-344-01`), MINTED-pending-confirm.
Wording in code/tests is paraphrase only, never spec text (D1).
Reused corpus IDs where they cover behavior: `22-65816-030-56-04`
(time-boxed join, extended to the joiner side),
`05-3474-23-431-01` + `05-3474-23-4522-01` (level restore, proof
only), `05-3474-23-451-01` + `05-3474-23-451-02` (aux shapes and
key-identifier modes, proof only), `05-3474-23-4312-01` (replay
guard, proof only).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 05-3474-23-344-01 | implemented + verified | `commands.rs`: `Leave` + `LeaveOptions` (rejoin/request/remove-children bits 5/6/7, reserved bits zeroed on encode + ignored on decode) + `decode_leave` (TLV tail borrowed opaquely) + `CMD_LEAVE` 0x04 (§3.4.4 Figure 3-14, anchor p0304-L7185-L7189; options field Figure 3-15, anchor p0305-L7220-L7233) | `tests/vectors.rs::vector_leave_captured_eject_05_3474_23_344_01` (captured `04 60` eject plaintext), `vector_leave_options_and_edges_05_3474_23_344_01` + `tests/roundtrip.rs::fuzz_command_round_trip_identity`, `fuzz_command_mutations_never_panic` (leave legs) |
| 22-65816-030-56-04 | implemented + verified (extended: joiner side of the time-box eviction) | `classical.rs`: `JoinerMachine::on_leave` (mid-join eject ends the attempt with `JoinError::JoinTimeout`; `BadState` with nothing pending; rejoin routing stays with the caller) (anchor p0033-L554-L561) | `tests/vectors.rs::vector_join_leave_evicts_mid_join` (Authenticating + KeyWait + wrong-state legs) |

## Wave-43 traceability — mode-0 trailing-octet fix (`rounddance-security` + consumers)

Follow-up to the wave-42 audit §5 item 2. The auxiliary-header
codec carried a one-octet sequence number under the data-key bits
(mode 0); per §4.5.1 Figure 4-24 the key sequence number field is
present ONLY under the network-key bits (mode 1, anchor
p0481-L11467-L11469), and per §4.5.3 the data key equals the
link key (anchor p0481-L11490-L11497), so mode-0 headers end at
the frame counter (5 octets bare, 13 with the extended-nonce
source). `KeyIdentifier::Seq` is removed; `KeyIdentifier::DataKey`
(unit, zero-length) is the mode-0 shape and `KeyIdentifier::Index`
keeps carrying the NWK sequence octet under the mode-1 bits (the
`decode_with_level` contract — NWK names a network key — is
unchanged). Captured air agrees: the wave-39 F seal aux
(`06 00 00 00 00`) is 5 octets with `a5...` ciphertext after it,
and the Ember NWK frames name mode 1 with one trailing octet. All
network-key-secured producers (sim secured frames, hal-host
scenario APS envelope, hal-esp demo NPDU, compat baseline) move
to the mode-1 bits with the sequence octet; no join/leave decision
logic branches on the aux mode bits (the commission join machine
never reads the aux), so simulator join/leave outcomes are
unchanged. 1 repo-minted ID (`05-3474-23-4514-01`),
MINTED-pending-confirm. Wording in code/tests is paraphrase only,
never spec text (D1). Reused corpus IDs where they cover behavior:
`05-3474-23-451-01` (aux shapes) + `05-3474-23-451-02` (mode
selector) for the updated vectors.

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 05-3474-23-4514-01 | implemented + verified | `classical.rs`: `KeyIdentifier::DataKey` (zero-length mode-0 shape) + `encoded_len` 0 + encode/decode arms consuming no octet (§4.5.1.4, anchor p0481-L11467-L11469; data-key identity §4.5.3, anchor p0481-L11490-L11497); `AuxHeader` doc (presence conditioned on the mode bits) | `security/tests/vectors.rs::vector_aux_mode0_no_trailing_octet_05_3474_23_4514_01` (5/13-octet mode-0 layouts + roundtrip, 6-octet mode-1 contrast, truncation + flag/shape-mismatch legs), updated `vector_aux_data_key` (exact 5-octet layout), updated `vector_aps_seal_shape_keyid_modes_05_3474_23_451_02` F leg (captured `06 00*4` decodes 5 octets, `a5` is payload), updated `vector_aux_level0_all_control_shapes`, `tests/roundtrip.rs::fuzz_aux_header_roundtrip` (mode-0 fuzz legs over the unit shape) |

## Wave-44 traceability — Smart-Energy + key-establishment decode depth (`rounddance-inspect`)

Offline engine growth only: no live drivers, no corpus writes, no keyed
decryption and no CBKE crypto in the inspector — ephemeral points are
length-gated but never decompressed, confirm tags length-gated but never
verified, certificates never parsed, and no key material is retained or
rendered. 4 repo-minted IDs (`RD-INSPECT-15..18`), MINTED-pending-confirm.
Paraphrase only (D1).

Prepayment (`0x0705`) and tunneling (`0x0704`) are out of scope with cause:
`rounddance-zcl` carries no codecs for either cluster, so there is nothing
to reuse; their payloads stay `Unknown` under the existing RD-INSPECT-09
contract, no new ID minted. Lab captures exist only as a wave-41 beacon
baseline (`~/hwscratch/w41/sniff_ch26baseline.txt.pcap`, no SE traffic), so
goldens are repo-codec-built frames per the wave-40/41 precedent — no new
captures were taken.

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| RD-INSPECT-15 | implemented + verified | `zcl::summarize_metering` → `tree::ZclDetail::Metering`: GetProfile via `decode_get_profile` (channel/periods/end-time) + GetProfileResponse 7-octet prefix shape (status/count/newest end) + FastPollMode 2-octet / FastPoll response 5-octet shapes, direction-disambiguated; mirror/snapshot/sampling/supply/notification-scheme commands stay `Unknown` by design; `report` text/JSON gain the `metering` kind | `inspect/tests/se_decode.rs::se_metering_get_profile_req` (codec-built req, cluster/profile/direction asserts) + `se_metering_get_profile_rsp` (genuine `ProfileBuffer::answer` body) + `se_metering_fast_poll_shapes` + `se_metering_submodule_cmds_stay_unknown` (mirror/snapshot + truncated legs) |
| RD-INSPECT-16 | implemented + verified | `zcl::summarize_price` → `tree::ZclDetail::Price`: PublishPrice / PriceAck / GetScheduledPrices / GetBlockPeriods via cluster codecs + GetCurrentPrice 1-octet options + tariff-id 4-octet requests + PublishBlockPeriod / PublishBlockThresholds / PublishTierLabels (bounded 4-entry scratch) shapes, direction-disambiguated (0x00 GetCurrentPrice vs PublishPrice); `report` text/JSON gain the `price` kind | `se_price_publish_and_ack` (codec-built publish + ack, direction asserts) + `se_price_requests_and_direction_split` + `se_price_block_and_tier_publishes` (incl. zero-total thresholds and bad-count tier-label Unknown legs) |
| RD-INSPECT-17 | implemented + verified | `zcl::summarize_keyest` → `tree::ZclDetail::{KeyInit, KeyMsg, KeyTerminate}`: Initiate/Terminate via cluster codecs (either direction, identical shapes), ephemeral 33/64-octet length gate + confirm 16-octet length gate, decode-only; `report` text/JSON gain the `keyinit`/`keymsg`/`keyterm` kinds | `se_keyest_initiate_and_terminate` (codec-built bodies both directions + truncated legs) + `se_keyest_ephemeral_and_confirm_shapes` (both wire forms both directions, 14 wrong-length Unknown legs, unmodeled command) |
| RD-INSPECT-18 | implemented + verified | `report::session_from_json` (hand-rolled fixed-schema parser, schema-version gate → `SessionLoadError::BadSchema`, typed `Malformed` for truncation/mistype/range/over-capacity) + `SessionEngine::restore` + `KeySlots::restore` (zeroed placeholder slots, rotation counter restarts at slot count, member caches restart empty); schema stays v1, round trip re-renders byte-identically | `se_session_save_load_roundtrip` (windows + PAN rows + orphan/decryptable + 2 key slots + IEEE row, byte-identical re-render, whitespace leg, empty engine) + `se_session_load_rejects` (version/missing/type/range/slots/overflow/trailing legs + every-truncation-prefix sweep + 33-device over-capacity) |

## Wave-45 traceability — spec-exact key-transport derivation + TC-first join (lane 2)

Prior waves (w42/w44) burned 4.1M + 1.44M offline decrypts against the
captured proactive `0x30` A-frames with two guessed inputs: the
key-transport-key construction (`MMO(link || 0x00)`) and, in the crack
scripts, the wrong device's install code. The exact clauses say
otherwise: the install-code link key is the AES-MMO-128 hash of the
full code (payload + LE check field, CRC-verified), and the
key-transport / key-load keys are the B.1.4 keyed hash (HMAC over the
MMO hash, 16-octet block) under the link key with the one-octet domain
inputs `0x00` / `0x02`. The data key is the link key itself. This wave
implements that chain exactly and re-runs the offline battery: the
HMAC-derived transport key opens all five A-frames (w42 x2/x4/x5/x6 +
w44 k1) with MIC-valid opens whose plaintexts carry the lab network
key — SOLVED with zero residual gap (key ✓, nonce = source-EUI +
counter LE + control restored `0x30`→`0x35`, AAD = APS header +
restored aux, MIC-32; command `0x05` key-type `0x01` seq `0x00` +
joiner/src EUIs in every frame). Long-form MMO padding (2^16-bit
threshold) is not instantiated: every caller hashes at most 48 octets
and over-cap inputs are refused, never hashed with the wrong form.
On the join path, the solved TC-first flow is now classified in the
machine: only the (`0x05`, `0x01`) pair ends the post-association
wait — no update-device-first, no vendor-first. 3 repo-minted IDs
(`05-3474-23-B14-01`, `05-3474-23-453-01`, `05-3474-23-4433-01`),
MINTED-pending-confirm. Paraphrase only (D1).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 05-3474-23-B14-01 | implemented + verified | `security::mmo::hmac_mmo_128` (HMAC over AES-MMO-128, 16-octet block, inner pad `0x36` / outer pad `0x5C`; §B.1.4 shape, anchor p0541-L13301-L13312; 48-octet input cap keeps both legs under the hash cap) | `security/tests/vectors.rs::vector_hmac_mmo_worked_05_3474_23_b14_01` (128-bit keyed-hash worked example incl. outer leg) + `vector_hmac_mmo_kdf_shape_05_3474_23_b14_01` (one-octet KDF shape) + `keyhierarchy::tests::keyed_input_too_long_is_refused` (over-cap refusal) |
| 05-3474-23-453-01 | implemented + verified | `security::keyhierarchy::{derive_key_transport_key (0x00), derive_key_load_key (0x02), data_key_is_link_key}` (hierarchy clause, anchor p0481-L11489-L11497); `commission::MmoJoinKdf` + `TrustCenter::install_code_key` supply the link-key leg (full code incl. check field, BDB §6.11.1.2, pre-existing `22-65816-030-56-08` vector) | `security/tests/vectors.rs::vector_key_hierarchy_from_worked_link_05_3474_23_453_01` (transport/load pinned from the BDB worked link key, cross-checked against an independent Python model before freezing) + `keyhierarchy::tests::hierarchy_is_deterministic_and_domain_separated` + offline battery `~/hwscratch/w45/transport_open.py` (3 KATs + 5 A-frames × key battery; SOLVED report `~/hwscratch/w45/REPORT.md`) |
| 05-3474-23-4433-01 | implemented + verified | `commission::classical::{TRANSPORT_KEY_CMD (0x05), TRANSPORT_KEY_TYPE_NETWORK (0x01)}` + `JoinerMachine::note_transport_frame` (exact-pair classification: genuine pair moves `Authenticating`→`KeyWait`, repeat in `KeyWait` tolerated, all other pairs and all other states leave the wait unchanged; transport-key receipt clause, anchors p0438-L10533-L10550) | `commission/tests/vectors.rs::vector_tc_first_transport_classification_05_3474_23_4433_01` (pre-association ignore + foreign-pair tolerance + genuine promotion + repeat tolerance + full path to Joined) + `rounddance-sim/tests/join_tc_first.rs` (real k1 capture envelope through the NWK codec + aux-shape asserts with opaque 39-octet tail, foreign-first tolerance, transport→verify→announce→join, wrong-type-first→NoTransport, deterministic replay) |

## Wave-46 traceability — TC-first joiner path complete (lane 2)

Wave-45 classified the TC-first transport (exact `0x05`/`0x01` pair)
and proved the key chain (the HMAC-derived transport key opens all
five proactive `0x30` A-frames MIC-valid). This wave completes the
joiner path through the states the capture implies: the
post-association wait is now bounded by the named
`JOINER_TRANSPORT_GRACE_TICKS` grace (≈10 s parent eject, seen on air
in `~/hwscratch/w39/sniff_b1.txt`, surfaced via `on_leave` as
`JoinTimeout` instead of polling to `NoTransport`); the classified
frame is opened with the caller-computed integrity outcome plus its
auxiliary counter (`on_transport_open`: MIC failure and
non-advancing counters end the attempt with `ConfirmMismatch`, the
joiner-side application of the strictly-monotonic counter window);
success latches the network-key adoption and rides
verify→`DeviceAnnce`→close-out to `Joined`. The five battery
A-frames (w42 x2/x4/x5/x6 + w44 k1) ride in-repo as envelope
metadata + tail hashes only (procedure:
`python3 ~/hwscratch/w45/transport_open.py` with the lab `0600`
files; report `~/hwscratch/w45/REPORT_lane2_spec_derivation.md`);
key bytes stay local-only outside the repo. 1 repo-minted ID
(`05-3474-23-4434-01`), MINTED-pending-confirm. Paraphrase only (D1).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 05-3474-23-4434-01 | implemented + verified | `commission::classical::JoinerMachine::on_transport_open` (MIC-checked open in `KeyWait`: failure → `ConfirmMismatch`, never promotes, never latches; auxiliary counter must strictly advance the last adopted one — replay/duplicate → `ConfirmMismatch`; success latches `netkey_adopted` + `last_aux_counter`, stays in `KeyWait` for verify; outside `KeyWait` → `BadState`) + `JOINER_TRANSPORT_GRACE_TICKS` (10-tick ≈10 s bound for the post-association wait, `22-65816-030-56-04` time-box, no new ID) | `commission/tests/vectors.rs::vector_tc_first_transport_open_05_3474_23_4434_01` (wrong-state open, MIC-fail, same-counter replay, lower-counter replay, fresh-counter adopt + full path to Joined) + `rounddance-sim/tests/join_tc_first.rs` (complete flow through open→adopt→verify→announce→join, MIC-fail→`ConfirmMismatch`, leave-eject on both wait legs→`JoinTimeout`, counter-replay→`ConfirmMismatch`, 5-frame air panel + k1-row capture consistency, deterministic replay) |

## Wave-47 traceability — post-join application transaction path (lane 2)

Wave-46 closed the joiner path at `Joined`. This wave lands the
post-join application transaction path the joined device speaks next:
ZDO request/response correlation by transaction sequence plus cluster
(`zdo::transaction::PendingTable`, covering Match_Desc + Bind/Unbind +
Mgmt_Lqi and every other answered command — the response-less announce
never opens, strays never correlate); the previously missing
`Mgmt_Lqi_req` (0x0031) / `Mgmt_Lqi_rsp` neighbor-table codec; the ZCL
transaction layer (`zcl::transaction`: wrapping sequence allocator,
per-endpoint pending set keyed on sequence + cluster, Default
Response builder over the reused triage rule — errors answer even with
the disable bit set, successes stay silent when it is set, a Default
Response is never answered); and the secured APS data send/receive
path (`aps::SecureDataLink`: counter-managed secured headers, unicast
ack-expectation tracking, receive-side security-flag + duplicate
rejection). No w46/w47 captures carry post-join application traffic
(join runs only; `~/hwscratch/w47/` holds a backup log plus a state
dump, no HW-lane transaction set at commit time), so there are no
captured-air application vectors to hash in — the sim decision tests
pin the wire shapes instead (synthetic vectors, deterministic replay),
and the divergence note stands for wave-48: mirror the HW lane's
transaction set once it exists. Key bytes stay local-only outside the
repo. 7 repo-minted IDs, MINTED-pending-confirm (of which `22845-01/02`
sweep-28 REJECTed and wave-48 re-minted as `22843-03/04`, see wave-48
section). Paraphrase only (D1).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 05-3474-23-24332-01 | implemented + verified | `zdo::mgmt::MgmtLqiReq` (TSN + start index) + `CLUSTER_MGMT_LQI_REQ` (0x0031) wired into `response_cluster` | `zdo/tests/transaction.rs::mgmt_lqi_pair_round_trip` (round trip) + `rounddance-sim/tests/app_transaction.rs::zdo_match_bind_lqi_two_node` (request→page→correlate over the medium) |
| 05-3474-23-24332-02 | implemented + verified | `zdo::mgmt::MgmtLqiRsp` (total count + page start + `NeighborEntry` page, success-only entries, `MAX_NEIGHBORS` bound) + `NeighborEntry` (21-octet record, reserved-bit + range refusal) | `zdo/tests/transaction.rs::mgmt_lqi_pair_round_trip` (2-entry page round trip, reserved-bit refusal, over-long-page refusal, non-success carries no entries) + sim LQI leg (neighbor page names A with LQI 180) |
| 05-3474-23-24401-01 | implemented + verified | `zdo::transaction::{PendingTable, transaction_expected}` (open refuses response-less/duplicate/full; close correlates only on response-cluster + echoed TSN against an open entry, else `None`) | `zdo/tests/transaction.rs::match_desc_correlates_by_tsn_and_cluster` + `::bind_and_unbind_stay_distinct` + `::announce_never_opens_and_table_bounds_hold` + Match_Desc/Bind pair round trips + `rounddance-sim/tests/app_transaction.rs::zdo_match_bind_lqi_two_node` (three transactions over the medium, stray-duplicate uncorrelated) |
| 07-5123-08-2413-02 | implemented + verified | `zcl::transaction::{TsnAlloc, PendingTable, reply_direction_ok}` (wrapping allocator; pending keyed on sequence + cluster; reports carry no open entry so they stay uncorrelated) | `zcl/tests/transaction.rs::tsn_allocator_sequences_and_wraps` + `::pending_table_matches_tsn_and_cluster` + `::reply_direction_gate` + `rounddance-sim/tests/app_transaction.rs::zcl_read_toggle_defaultrsp_two_node` (Read TSN correlated, Toggle applied silent) |
| 07-5123-08-2512-03 | implemented + verified | `zcl::transaction::build_default_response` (reply header echoes TSN with flipped direction + disable bit set; body echoes command + status; triage `07-5123-08-2512-01/02` reused) | `zcl/tests/transaction.rs::default_response_builder_triage` (success answered/disabled-silent, error-always-answered, broadcast-silent, never-answers-DefaultRsp) + sim unknown-command leg (UNSUP_COMMAND round trip with TSN echo) |
| 05-3474-23-22845-01 | RE-MINTED as `05-3474-23-22843-03` (wave-48; sweep-28 REJECT: duplicates anchored batch-18 fragmentation entry) | `aps::SecureDataLink::send_header` + `note_ack` (wave-47 code, refs updated) | wave-47 tests, refs updated to `22843-03` |
| 05-3474-23-22845-02 | RE-MINTED as `05-3474-23-22843-04` (wave-48; sweep-28 REJECT: duplicates anchored batch-18 fragmentation entry) | `aps::SecureDataLink::accept` (wave-47 code, refs updated) | wave-47 tests, refs updated to `22843-04` |

## Wave-48 traceability — secured-APS re-mint + APS ack leg + captured-air vectors (lane 2)

Confirmation sweep 28 (wave-47) REJECTed the wave-47
`05-3474-23-22845-01/02` secured-APS-data rows: the numbers duplicate
the anchored batch-18 fragmentation entries
(`22845-01`/`-02` = §2.2.8.4.5 transmit preconditions / window-size-1
baseline, CONFIRM as cited). Content verified; numbers re-minted
under free numbers below. Freeness checked 2026-10-29 against this
file (no `22843-03/04`, no `22844-02`) and the private-corpus
full-corpus sweep file (`requirements-wave-full-corpus.md`: no
`22843-03/04`, no `22844-02`; `22843-01/02` + `22844-01` stay
untouched) plus `requirements-seed.md` and the repo tree — zero hits
outside wave-48. The secured-data rows keep their §2.2.8.4.3 (Use of
Acknowledgements) clause home: `-03` = send-side ack expectation,
`-04` = receive-side ack owed back (anchors p0102-L2460-L2463 /
p0102-L2472-L2476, the 22843-01/02 family spans). The new ack leg
(`ack_for` generation on the request bit, `parse_ack` parsing, retry
accounting, NO_ACK confirm) mints `05-3474-23-22844-02` under §2.2.8.4.4
Retransmissions (anchor p0102-L2483-L2498, the 22844-01 span). Old →
new mapping: `22845-01` → `22843-03`, `22845-02` → `22843-04`;
PROGRESS wave-48 row records the same mapping. 3 repo-minted IDs,
MINTED-pending-confirm. Paraphrase only (D1).

Captured-air vectors: wave-47 lane-1 ran post-join application
transactions on a live Ember TC (t1 no-ack → 3x retry →
DELIVERY_FAILED; t2 acked → SUCCESS) with sniffer pcaps
(`~/hwscratch/w47/t1.pcap` sha256
`c689d5675fc8356a633af5c2956b7c360d84a97b5fa61aa320d39b47d49a0e79`,
745 frames; `~/hwscratch/w47/t2.pcap` sha256
`aba1df7ae9ee70f72fa55cb83ee12571a97f36591b85343b1db172cadcbc8ce8`,
748 frames). Frames ride NWK-secured, so the repo pins hashes +
analyzer-observed decision metadata only (no key bytes, no
plaintext); offline reproduction procedure:
`python3 analyze47.py` in `~/hwscratch/w47` with the lab `0600` key
files (report `~/hwscratch/w47/SUMMARY.md` §1/§5).

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| 05-3474-23-22843-03 | implemented + verified | `aps::SecureDataLink::send_header` + `note_ack` (security flag set, counter taken + advanced, unicast-only ack expectation, off-unicast ack-request forced clear; §2.2.8.4.3, anchor p0102-L2460-L2463) | `aps/tests/secure.rs::secured_send_advances_counter_and_expects_ack` + `::secured_counter_wraps` + `rounddance-sim/tests/app_transaction.rs::secured_aps_data_two_node` (counter-managed secured send over the medium, ack clears) |
| 05-3474-23-22843-04 | implemented + verified | `aps::SecureDataLink::accept` (unsecured → `Unsecured`, non-data → `IllegalRequest`, replayed source + counter → `NoAck`, else ack expectation owed back; §2.2.8.4.3, anchor p0102-L2472-L2476) | `aps/tests/secure.rs::secured_receive_checks_flag_dup_and_ack` + sim secured leg (both-layer accept, captured replay refused at NWK guard then APS guard, next fresh frame advances) |
| 05-3474-23-22844-02 | implemented + verified | `aps::secure::{ack_for, parse_ack}` (ack generated only for ack-requested unicast — endpoints swapped, cluster/profile/counter copied, ack-request clear; parsing yields the correlation triple, command acks correlate to nothing; §2.2.8.4.4, anchor p0102-L2483-L2498) + `RetrySession` accounting (no-ack → retransmits to cap → `Failed(NoAck)` = DELIVERY_FAILED surfacing; ack → `Acked`) | `aps/tests/secure.rs::ack_generated_only_on_request_bit` + `::ack_roundtrip_parses_to_correlation_triple` + `::ack_parse_refuses_malformed` + `::retry_without_ack_fails_no_ack_after_cap` (t1 shape) + `::retry_with_ack_succeeds` (t2 shape) + `::captured_air_t1_t2_vector_shapes` (pcap hashes + copy-count metadata + T3 Read decision replay) + `rounddance-sim/tests/app_transaction.rs::aps_ack_leg_acked_vs_unacked_two_node` (acked → success then silent → `Failed(NoAck)` over the medium) |

## Wave-49 traceability — live-validation inspector gaps (lane 2)

Wave-48 lane 1 confirmed 4 inspector gaps on live air plus 2 seam
gaps (`~/hwscratch/w48/SUMMARY.md` §3): MAC acks surfacing as
`MacTruncated` (120/120 len-3), no NWK decrypt path (every secured
app frame stops), the transport-key APS outer misparsed (`0x30` aux
octet read as the command id), and MAC commands/beacons stopping at
`unknown`; plus INS-LIVE-01 (listener RSSI/LQI dropped downstream)
and INS-LIVE-02 (bogus positive sniffer power — documented, firmware
untouched). This wave closes G1+G3+G4+INS-LIVE-01 in
`rounddance-inspect`, adds the slotted-key-gated NWK decrypt path
(G2), and commits the cleaned host live-listener. No lab use, no
corpus writes; wording in code/tests is paraphrase only (D1). 5
repo-minted IDs (`RD-INSPECT-19..23`), MINTED-pending-confirm.

Captured-air vectors: the MAC ack / beacon / command octets and the
transport-key outer pinned in `inspect/tests/live_air.rs` are
verbatim wave-48 live frames (`~/hwscratch/w48/live1.frames.log`,
554 frames); the NWK
round trip seals with a synthetic test-only key so lab keys stay
local-only (never in the repo). Offline reproduction procedure:
`cargo run -p rounddance-inspect --features live --bin inspect-live --
--replay ~/hwscratch/w48/sniff_live1.txt --channel 25` (w47:
`sniff_t1.txt` / `sniff_t2.txt`) with the lab `0600` key files for
keyed opens; report `~/hwscratch/w49/SUMMARY.md` §1/§5.

| Requirement ID | State | Implementing code | Verifying test |
|----------------|-------|-------------------|----------------|
| RD-INSPECT-19 | implemented + verified | `mac::decode` ack path (type 2: frame control + sequence only, no addressing) + `MacNode::command_id` (first MSDU octet of unsecured command frames; never read on secured outers) + `chain` `ack` / `beacon` / `mac-command` stop notes + session source-PAN fallback attribution (beacons file under their source PAN, acks under PAN 0 with no device row) | `inspect/tests/live_air.rs::mac_ack_decodes_instead_of_truncated` (live f2/f4 + short-ack typed legs) + `::mac_beacon_and_commands_decode_with_named_stops` (live beacon f6, beacon-req, assoc-req/resp, data-req poll + report shapes) + `::acks_fold_without_device_attribution` + replays live1 (554 frames, 0 errors: 120 ack / 147 beacon / 242 mac-command), t1 (745: 133 ack), t2 (748: 126 ack), hex-parity vs the w48 glue log |
| RD-INSPECT-20 | implemented + verified | `aps::decode` refuses any APDU with the security bit set as `ApsError::Secured` before command-identifier / payload parsing + `chain` files it as a `secured` note (data, command, and ack shapes alike) | `inspect/tests/live_air.rs::transport_key_outer_stops_secured` (live f36: MAC + NWK + secured, no APS node, no `cmd=0x30`) + `::secured_aps_data_shape_refuses_before_payload` (codec-built secured/plain pair) + replays (t1/t2 trailing→secured +2 each) |
| RD-INSPECT-21 | implemented + verified | `decrypt::open_nwk` (network-base level-5 restore over the zeroed on-air octet, strict key-sequence slot match via `keys::key_by_seq`, extended-source nonce, 4-octet integrity verification, bounded allocation-free open; `None` on no slot, sequence miss, non-network-key shape, or any integrity failure) + `chain::dissect_with_keys` / `dissect_nwk_with_keys` (`decrypted` leg continues on the verified plaintext, all other secured frames keep the `secured` stop) | `inspect/tests/live_air.rs::nwk_decrypt_opens_with_slotted_key_and_stops_without` (synthetic seal→open round trip to APS+ZCL, no-key / wrong-sequence / wrong-key / mutated-octet / bare-NWK legs) + `::nwk_decrypt_gates_session_decryptability` (decryptable 1 vs orphan 1) + `::genuine_secured_air_never_opens_off_slot` (live f19) + `::captured_corpus_pins` (t1/t2 hashes + counts + procedure) |
| RD-INSPECT-22 | implemented + verified | `tree::Radio` + `DecodeTree::set_radio` (positive RSSI files as unknown) + session per-device `last_rssi` / `last_lqi` (quirk readings never overwrite) + `report` text/JSON radio legs + `capture::Captured::rssi` validity-range documentation (positive = unknown); session schema stays v1, signal is live state, never snapshot state | `inspect/tests/live_air.rs::radio_metadata_threads_tree_to_session` (tree attach, device fold, quirk non-overwrite, report shapes, schema has no radio keys) + replays (TC −104/255 vs joiner −117/228 per-device discrimination) |
| RD-INSPECT-23 | implemented + verified | `sniffer::parse_received` (shared `received:` line shape, FCS stripped) + `sniffer::ReplayListener` (`std`, saved-feed replay through the same parser) + `inspect-live` binary (`live` feature: termios serial driver with `unsafe` confined to the binary, live accounting with radio attach, `--replay` conformance mode) | `sniffer` unit tests (live shape, bogus-power passthrough, non-frame legs) + `inspect/tests/live_air.rs::replay_listener_feeds_chain_and_session` (saved feed → listener → chain → session) + replays (live1/t1/t2 byte-identical hex parity vs the w48 glue log; live == replay by shared parser) |
