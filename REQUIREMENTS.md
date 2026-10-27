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
| 05-3474-23-B11-01 | implemented + verified | `aes.rs`: AES-128 block encryption feeding the B.4 hash (Annex B.1.1, anchors p0541-L13284-L13286); repo-minted, MINTED-pending-confirm | `tests/vectors.rs::vector_aes128_published_cipher_check` (published cipher check) |
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
| 22-65816-030-56-01 | accounted-for, N-A at this layer | Snap-back is TC policy config; no reduced-mode state lives here — `TrustCenter::close` restores the closed stance | code inspection (no reduced-mode state in this crate) |
| 22-65816-030-56-02 | implemented + verified | `classical.rs`: `TrustCenter::set_allow_list` + `admitted` (anchor p0033-L534-L539) | `tests/vectors.rs::vector_allow_list_and_timeout_*` |
| 22-65816-030-56-03 | implemented + verified | `classical.rs`: install-code-gated dynamic keys (anchor p0033-L542-L547); sweep-2 corrections applied: reflected CRC + LE check field, MMO derivation via `MmoJoinKdf` (`EccJoinKdf` retained as injection seam only) | `tests/vectors.rs::vector_install_code_validation`, `vector_install_code_derivation_mock` (MOCK provenance), `vector_install_code_crc_worked_22_65816_030_56_07`, `vector_install_code_mmo_worked_22_65816_030_56_08` |
| 22-65816-030-56-07 | implemented + verified | `classical.rs`: install-code CRC parameter set — poly 0x1021, init 0xFFFF, XOR-out 0xFFFF, reflected in/out, LE check field (anchors p0041-L816-L827) | `tests/vectors.rs::vector_install_code_crc_worked_22_65816_030_56_07` (BDB worked example 0xB5C3 frozen; BE + non-reflected variants rejected) |
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
| 22-65816-030-121-03 | implemented + verified | `touchlink.rs` + `mac-sap`: initiator scan broadcast through `InterPanTx`/`SapInterPan` over `MacInterPanSap` (anchors p0087-L1821-L1835 + p0091-L1990-L1993); repo-minted, MINTED-pending-confirm | `tests/vectors.rs::vector_touchlink_sap_adapter_transfer`, `rounddance-sim/tests/touchlink_interpan.rs::touchlink_interpan_scan_round_trip` + replay |
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
| 05-3474-23-3613-02 | implemented + verified | `enddevice.rs`/`sleepy.rs`: 3-miss loss → rejoin (secured + trust-center paths via commission `RejoinMachine`) | `enddevice_poll_loss_rejoin_leave_*`, `sleepy_duty_cycle_rejoin_*`, sim `sleepy-rejoined` leg |
| 05-3474-23-3613-03 | implemented + verified | `enddevice.rs`/`sleepy.rs`: `rejoin_done` optional new-parent adoption | `enddevice_poll_loss_rejoin_leave_*` (0x0002 adoption), sim rejoin-through-router leg |
| 05-3474-23-3616-01 | implemented + verified | `children.rs::remove`, `coordinator.rs`/`router.rs::remove_child`, `enddevice.rs::leave`, `sleepy.rs::leave` | `router_rejoin_and_leave_*`, `enddevice_poll_loss_rejoin_leave_*`, `sleepy_duty_cycle_rejoin_*` (leave legs) |
| 05-3474-23-2325-ROLES-01 | implemented + verified | `endpoint.rs`: `AppEndpoint` host interface + role-agnostic `EndpointTable` | `endpoint_attach_rejects_bad_ids_*`, sim thermostat registration |
| 05-3474-23-2325-ROLES-02 | implemented + verified | `endpoint.rs`: `RouterApp` route/app fairness pair, per-tick budgets `MAX_ROUTE_PER_TICK`/`MAX_APP_PER_TICK` | `router_serves_own_endpoint_while_forwarding_*`, `fairness_budgets_hold_under_flood_*`, sim `tick1 fwd=1 app=1` leg |
