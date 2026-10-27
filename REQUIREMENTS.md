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
| 07-5123-08-2512-01 | implemented + verified | `dispatch.rs`: `should_default_respond` triage (anchors p0080-L2980-L2994 + p0081-L3001-L3016); unknown-cluster mapping (FAILURE) is the documented MINTED uncertainty | `tests/vectors.rs::vector_default_response_triage_*` |
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
