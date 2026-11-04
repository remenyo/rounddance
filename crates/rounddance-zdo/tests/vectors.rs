//! Wire-byte vectors for ZDP requests and responses.
//!
//! Each test names the requirement ID it verifies. Byte strings below
//! are hand-computed from the paraphrased layouts in doc `05-3474-23`
//! R23.2 §§2.4.3–2.4.4 — never copied from spec text (D1, `SCOPE.md`
//! §2). All IDs are repo-minted, MINTED-pending-confirm.

use rounddance_zdo::*;

// 05-3474-23-24311-01: request cluster IDs occupy the discovery range.
#[test]
fn vector_cluster_ids_05_3474_23_24311_01() {
    assert_eq!(CLUSTER_NWK_ADDR_REQ, 0x0000);
    assert_eq!(CLUSTER_IEEE_ADDR_REQ, 0x0001);
    assert_eq!(CLUSTER_NODE_DESC_REQ, 0x0002);
    assert_eq!(CLUSTER_POWER_DESC_REQ, 0x0003);
    assert_eq!(CLUSTER_SIMPLE_DESC_REQ, 0x0004);
    assert_eq!(CLUSTER_ACTIVE_EP_REQ, 0x0005);
    assert_eq!(CLUSTER_MATCH_DESC_REQ, 0x0006);
    assert_eq!(CLUSTER_DEVICE_ANNCE, 0x0013);
    assert_eq!(CLUSTER_BIND_REQ, 0x0021);
    assert_eq!(CLUSTER_UNBIND_REQ, 0x0022);
    assert_eq!(CLUSTER_MGMT_LEAVE_REQ, 0x0034);
    assert_eq!(CLUSTER_MGMT_PERMIT_JOINING_REQ, 0x0036);
    assert_eq!(CLUSTER_MGMT_NWK_UPDATE_REQ, 0x0038);
}

// 05-3474-23-244-02: responses set the high bit; announcements pair
// with nothing.
#[test]
fn vector_response_clusters_05_3474_23_244_02() {
    assert_eq!(response_cluster(CLUSTER_NWK_ADDR_REQ), Some(0x8000));
    assert_eq!(response_cluster(CLUSTER_NODE_DESC_REQ), Some(0x8002));
    assert_eq!(response_cluster(CLUSTER_MATCH_DESC_REQ), Some(0x8006));
    assert_eq!(response_cluster(CLUSTER_BIND_REQ), Some(0x8021));
    assert_eq!(response_cluster(CLUSTER_MGMT_NWK_UPDATE_REQ), Some(0x8038));
    assert_eq!(response_cluster(CLUSTER_DEVICE_ANNCE), None);
    assert_eq!(response_cluster(CLUSTER_COMPLEX_DESC_REQ), Some(0x8010));
    assert_eq!(response_cluster(0x0007), None);
}

// 05-3474-23-24311-02: single NWK_addr_req.
#[test]
fn vector_nwk_addr_req_single_05_3474_23_24311_02() {
    let wire: &[u8] = &[
        0x2A, // tsn
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // ieee LE
        0x00, // single
    ];
    let req = NwkAddrReq::decode(wire).unwrap();
    assert_eq!(req.tsn, 0x2A);
    assert_eq!(req.ieee_of_interest, 0x1122_3344_5566_7788);
    assert_eq!(req.req_type, RequestType::Single);
    let mut out = [0u8; 16];
    let n = req.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);
}

// 05-3474-23-24311-02: extended NWK_addr_req carries a start index;
// a bare 0x01 type octet without it is truncated.
#[test]
fn vector_nwk_addr_req_extended_05_3474_23_24311_02() {
    let wire: &[u8] = &[
        0x2B, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x05,
    ];
    let req = NwkAddrReq::decode(wire).unwrap();
    assert_eq!(req.req_type, RequestType::Extended { start_index: 0x05 });
    let mut out = [0u8; 16];
    let n = req.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);
    assert_eq!(NwkAddrReq::decode(&wire[..10]), Err(ZdoError::Truncated));
    assert_eq!(
        NwkAddrReq::decode(&[0x2B, 0, 0, 0, 0, 0, 0, 0, 0, 0x07]),
        Err(ZdoError::InvalidValue(0x07))
    );
}

// 05-3474-23-24421-01: NWK_addr_rsp success (single flavour).
#[test]
fn vector_nwk_addr_rsp_single_05_3474_23_24421_01() {
    let wire: &[u8] = &[
        0x2A, 0x00, // tsn, SUCCESS
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // ieee
        0x34, 0x12, // nwk 0x1234
    ];
    let rsp = NwkAddrRsp::decode(wire).unwrap();
    assert_eq!(rsp.tsn, 0x2A);
    assert_eq!(rsp.status, ZdpStatus::Success);
    assert_eq!(rsp.ieee, 0x1122_3344_5566_7788);
    assert_eq!(rsp.nwk_addr, 0x1234);
    assert!(!rsp.extended);
    let mut out = [0u8; 32];
    let n = rsp.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);
}

// 05-3474-23-24421-01: NWK_addr_rsp extended flavour with two
// associated devices; error responses carry no list.
#[test]
fn vector_nwk_addr_rsp_extended_05_3474_23_24421_01() {
    let wire: &[u8] = &[
        0x2B, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x78, 0x56, // nwk 0x5678
        0x02, // count
        0x05, // start index
        0x01, 0x00, 0x02, 0x00, // assoc list
    ];
    let rsp = NwkAddrRsp::decode(wire).unwrap();
    assert!(rsp.extended);
    assert_eq!(rsp.assoc_len, 2);
    assert_eq!(rsp.start_index, 0x05);
    assert_eq!(rsp.assoc[0], 0x0001);
    assert_eq!(rsp.assoc[1], 0x0002);
    let mut out = [0u8; 64];
    let n = rsp.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);

    // DEVICE_NOT_FOUND: fixed 12 octets, no list.
    let err_wire: &[u8] = &[
        0x2B, 0x81, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0xFF, 0xFF,
    ];
    let err = NwkAddrRsp::decode(err_wire).unwrap();
    assert_eq!(err.status, ZdpStatus::DeviceNotFound);
    assert!(!err.extended);
    let mut out2 = [0u8; 32];
    let n2 = err.encode_into(&mut out2).unwrap();
    assert_eq!(&out2[..n2], err_wire);
}

// 05-3474-23-24311-01 + 05-3474-23-24422-01: IEEE_addr mirror pair.
#[test]
fn vector_ieee_addr_pair_05_3474_23_24422_01() {
    let req_wire: &[u8] = &[0x07, 0x34, 0x12, 0x00];
    let req = IeeeAddrReq::decode(req_wire).unwrap();
    assert_eq!(req.nwk_of_interest, 0x1234);
    assert_eq!(req.req_type, RequestType::Single);
    let mut out = [0u8; 8];
    assert_eq!(req.encode_into(&mut out).unwrap(), 4);
    assert_eq!(&out[..4], req_wire);

    let rsp_wire: &[u8] = &[
        0x07, 0x00, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x34, 0x12,
    ];
    let rsp = IeeeAddrRsp::decode(rsp_wire).unwrap();
    assert_eq!(rsp.status, ZdpStatus::Success);
    assert_eq!(rsp.ieee, 0x1122_3344_5566_7788);
    assert_eq!(rsp.nwk_addr, 0x1234);
    let mut out2 = [0u8; 16];
    let n = rsp.encode_into(&mut out2).unwrap();
    assert_eq!(&out2[..n], rsp_wire);
}

// 05-3474-23-2323-01: node descriptor field order and values.
#[test]
fn vector_node_desc_fields_05_3474_23_2323_01() {
    // flags0: router(01) | complex avail(0) | user avail(0) = 0x01.
    let wire: &[u8] = &[
        0x01, // flags0: router
        0x00, // aps flags
        0x04, // freq band: 2.4 GHz bit
        0x8E, // mac cap
        0x34, 0x12, // mfr 0x1234
        0x52, // max buf 82
        0x52, 0x00, // max in 82
        0x00, 0x00, // server mask
        0x52, 0x00, // max out 82
        0x00, // desc cap (deprecated)
    ];
    let desc = NodeDescriptor::decode(wire).unwrap();
    assert_eq!(desc.logical_type().unwrap(), LogicalType::Router);
    assert_eq!(desc.mfr_code, 0x1234);
    assert_eq!(desc.max_buf, 82);
    assert_eq!(desc.max_in_transfer, 82);
    assert_eq!(desc.max_out_transfer, 82);
    let mut out = [0u8; 16];
    let n = desc.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);
    assert_eq!(n, NODE_DESCRIPTOR_LEN);
    // Reserved logical values are rejected, not misread.
    assert_eq!(
        NodeDescriptor::decode(&[0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .unwrap()
            .logical_type(),
        Err(ZdoError::InvalidValue(0x07))
    );
}

// 05-3474-23-24311-03 + 05-3474-23-24423-01: Node_Desc round trip,
// request then success response echoing tsn + interest address.
#[test]
fn vector_node_desc_pair_05_3474_23_24311_03() {
    let req_wire: &[u8] = &[0x51, 0x34, 0x12];
    let req = NodeDescReq::decode(req_wire).unwrap();
    assert_eq!(req.tsn, 0x51);
    assert_eq!(req.nwk_of_interest, 0x1234);

    let mut rsp_wire = vec![0x51, 0x00, 0x34, 0x12];
    rsp_wire.extend_from_slice(&[
        0x01, 0x00, 0x04, 0x8E, 0x34, 0x12, 0x52, 0x52, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00,
    ]);
    let rsp = NodeDescRsp::decode(&rsp_wire).unwrap();
    assert_eq!(rsp.tsn, 0x51);
    assert!(rsp.status.is_success());
    assert_eq!(rsp.nwk_of_interest, 0x1234);
    assert_eq!(rsp.descriptor.unwrap().mfr_code, 0x1234);
    assert_eq!(rsp.tlvs, &[]);
    let mut out = [0u8; 32];
    let n = rsp.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], rsp_wire);
}

// 05-3474-23-24423-01: error Node_Desc_rsp carries no descriptor;
// trailing TLV octets survive on success.
#[test]
fn vector_node_desc_rsp_edge_05_3474_23_24423_01() {
    let err = NodeDescRsp::decode(&[0x51, 0x81, 0x34, 0x12]).unwrap();
    assert_eq!(err.status, ZdpStatus::DeviceNotFound);
    assert_eq!(err.descriptor, None);

    let mut with_tlv = vec![0x51, 0x00, 0x34, 0x12];
    with_tlv.extend_from_slice(&[0u8; 14]);
    with_tlv.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
    let rsp = NodeDescRsp::decode(&with_tlv).unwrap();
    assert_eq!(rsp.tlvs, &[0xAA, 0xBB, 0xCC]);
    let mut out = [0u8; 32];
    let n = rsp.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], with_tlv);
}

// 05-3474-23-2324-01: power descriptor nibbles.
#[test]
fn vector_power_desc_fields_05_3474_23_2324_01() {
    // octet0: mode OnWhenIdle(0) | available mains bit (0x01 << 4).
    // octet1: source mains(1) | level full (0xC << 4).
    let wire: &[u8] = &[0x10, 0xC1];
    let desc = PowerDescriptor::decode(wire).unwrap();
    assert_eq!(desc.mode, PowerMode::OnWhenIdle);
    assert_eq!(desc.available, 0x01);
    assert_eq!(desc.source, 0x01);
    assert_eq!(desc.level, 0x0C);
    assert_eq!(desc.encode_into(&mut [0u8; 2]).unwrap(), 2);
    let mut out = [0u8; 2];
    let n = desc.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);
    assert_eq!(n, POWER_DESCRIPTOR_LEN);
    assert_eq!(
        PowerDescriptor::decode(&[0x0F, 0x00]),
        Err(ZdoError::InvalidValue(0x0F))
    );
}

// 05-3474-23-24311-04 + 05-3474-23-24424-01: Power_Desc pair.
#[test]
fn vector_power_desc_pair_05_3474_23_24311_04() {
    let req = PowerDescReq::decode(&[0x09, 0x78, 0x56]).unwrap();
    assert_eq!(req.nwk_of_interest, 0x5678);
    let rsp = PowerDescRsp::decode(&[0x09, 0x00, 0x78, 0x56, 0x10, 0xC1]).unwrap();
    assert!(rsp.status.is_success());
    assert_eq!(rsp.descriptor.unwrap().mode, PowerMode::OnWhenIdle);
    let mut out = [0u8; 8];
    let n = rsp.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], &[0x09, 0x00, 0x78, 0x56, 0x10, 0xC1]);
}

// 05-3474-23-2325-01: simple descriptor layout with in/out lists.
#[test]
fn vector_simple_desc_fields_05_3474_23_2325_01() {
    let wire: &[u8] = &[
        0x0A, // endpoint
        0x04, 0x01, // profile 0x0104
        0x00, 0x02, // device 0x0200
        0x01, // version
        0x02, // two in clusters
        0x00, 0x00, 0x06, 0x00, // 0x0000, 0x0006
        0x01, // one out cluster
        0x19, 0x00, // 0x0019
    ];
    let desc = SimpleDescriptor::decode(wire).unwrap();
    assert_eq!(desc.endpoint, 0x0A);
    assert_eq!(desc.profile_id, 0x0104);
    assert_eq!(desc.device_id, 0x0200);
    assert_eq!(desc.in_list(), &[0x0000, 0x0006]);
    assert_eq!(desc.out_list(), &[0x0019]);
    let mut out = [0u8; 32];
    let n = desc.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);
}

// 05-3474-23-24311-05 + 05-3474-23-24425-01: Simple_Desc pair with the
// length octet; error responses omit it.
#[test]
fn vector_simple_desc_pair_05_3474_23_24311_05() {
    let req = SimpleDescReq::decode(&[0x0D, 0x34, 0x12, 0x0A]).unwrap();
    assert_eq!(req.endpoint, 0x0A);
    let wire: &[u8] = &[
        0x0D, 0x00, 0x34, 0x12, 0x0A, // tsn, SUCCESS, nwk, length 10
        0x0A, 0x04, 0x01, 0x00, 0x02, 0x01, 0x01, 0x06, 0x00, 0x00,
    ];
    let rsp = SimpleDescRsp::decode(wire).unwrap();
    assert!(rsp.status.is_success());
    let desc = rsp.descriptor.unwrap();
    assert_eq!(desc.endpoint, 0x0A);
    assert_eq!(desc.in_list(), &[0x0006]);
    assert!(desc.out_list().is_empty());
    let mut out = [0u8; 32];
    let n = rsp.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);

    let err = SimpleDescRsp::decode(&[0x0D, 0x82, 0x34, 0x12]).unwrap();
    assert_eq!(err.status, ZdpStatus::InvalidEp);
    assert_eq!(err.descriptor, None);
}

// 05-3474-23-24311-06 + 05-3474-23-24426-01: Active_EP pair.
#[test]
fn vector_active_ep_pair_05_3474_23_24311_06() {
    let req = ActiveEpReq::decode(&[0x11, 0x34, 0x12]).unwrap();
    assert_eq!(req.nwk_of_interest, 0x1234);
    let wire: &[u8] = &[0x11, 0x00, 0x34, 0x12, 0x03, 0x01, 0x0A, 0xF2];
    let rsp = ActiveEpRsp::decode(wire).unwrap();
    assert_eq!(rsp.ep_list(), &[0x01, 0x0A, 0xF2]);
    let mut out = [0u8; 40];
    let n = rsp.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);
}

// 05-3474-23-24311-07 + 05-3474-23-24427-01: Match_Desc pair.
#[test]
fn vector_match_desc_pair_05_3474_23_24311_07() {
    let req_wire: &[u8] = &[
        0x21, 0xFF, 0xFD, // tsn, broadcast interest
        0x04, 0x01, // profile 0x0104
        0x01, 0x06, 0x00, // one in cluster 0x0006
        0x00, // no out clusters
    ];
    let req = MatchDescReq::decode(req_wire).unwrap();
    assert_eq!(req.profile_id, 0x0104);
    assert_eq!(req.in_clusters[0], 0x0006);
    assert_eq!(req.in_len, 1);
    assert_eq!(req.out_len, 0);
    let mut out = [0u8; 32];
    let n = req.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], req_wire);

    let rsp_wire: &[u8] = &[0x21, 0x00, 0x34, 0x12, 0x02, 0x0A, 0x0B];
    let rsp = MatchDescRsp::decode(rsp_wire).unwrap();
    assert_eq!(rsp.ep_list(), &[0x0A, 0x0B]);
    let mut out2 = [0u8; 40];
    let n2 = rsp.encode_into(&mut out2).unwrap();
    assert_eq!(&out2[..n2], rsp_wire);
}

// 05-3474-23-24311-11: Device_annce announces arrival, no response.
#[test]
fn vector_device_annce_05_3474_23_24311_11() {
    let wire: &[u8] = &[
        0x33, 0x34, 0x12, // tsn, nwk
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // ieee
        0x8E, // capability
    ];
    let ann = DeviceAnnce::decode(wire).unwrap();
    assert_eq!(ann.nwk_addr, 0x1234);
    assert_eq!(ann.ieee, 0x1122_3344_5566_7788);
    assert_eq!(ann.capability, 0x8E);
    assert_eq!(response_cluster(CLUSTER_DEVICE_ANNCE), None);
    let mut out = [0u8; 16];
    let n = ann.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);
}

// 05-3474-23-24322-01: Bind_req group flavour.
#[test]
fn vector_bind_req_group_05_3474_23_24322_01() {
    let wire: &[u8] = &[
        0x41, // tsn
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // src ieee
        0x0A, // src ep
        0x06, 0x00, // cluster 0x0006
        0x01, // group mode
        0x2A, 0x00, // group 0x002A
    ];
    let entry = BindEntry::decode(wire).unwrap();
    assert_eq!(entry.dst, BindDstMode::Group { group_addr: 0x002A });
    let mut out = [0u8; 24];
    let n = entry.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);
}

// 05-3474-23-24322-01: Bind_req extended flavour + Bind_rsp.
#[test]
fn vector_bind_req_extended_05_3474_23_24322_01() {
    let wire: &[u8] = &[
        0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x06, 0x00, 0x03, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x0B,
    ];
    let entry = BindEntry::decode(wire).unwrap();
    assert_eq!(
        entry.dst,
        BindDstMode::Extended {
            dst_ieee: 0x1817_1615_1413_1211,
            dst_endpoint: 0x0B,
        }
    );
    let mut out = [0u8; 32];
    let n = entry.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);

    let rsp = BindRsp::decode(&[0x42, 0x00]).unwrap();
    assert_eq!(rsp.status, ZdpStatus::Success);
    assert_eq!(response_cluster(CLUSTER_BIND_REQ), Some(0x8021));
    assert_eq!(response_cluster(CLUSTER_UNBIND_REQ), Some(0x8022));
    // Unknown destination modes are rejected, not misread.
    let mut bad = wire.to_vec();
    bad[12] = 0x02;
    assert_eq!(BindEntry::decode(&bad), Err(ZdoError::InvalidValue(0x02)));
}

// 05-3474-23-24335-01: Mgmt_Leave_req flags.
#[test]
fn vector_mgmt_leave_05_3474_23_24335_01() {
    let wire: &[u8] = &[
        0x61, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x03, // rejoin + remove children
    ];
    let req = MgmtLeaveReq::decode(wire).unwrap();
    assert!(req.rejoin);
    assert!(req.remove_children);
    let mut out = [0u8; 12];
    let n = req.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);
    let rsp = MgmtLeaveRsp::decode(&[0x61, 0x00]).unwrap();
    assert!(rsp.status.is_success());
}

// 05-3474-23-24337-01: Mgmt_Permit_Joining_req duration + significance.
#[test]
fn vector_mgmt_permit_joining_05_3474_23_24337_01() {
    let req = MgmtPermitJoiningReq::decode(&[0x62, 0xFF, 0x01]).unwrap();
    assert_eq!(req.duration, 0xFF);
    assert!(req.tc_significance);
    let mut out = [0u8; 4];
    let n = req.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], &[0x62, 0xFF, 0x01]);
    let rsp = MgmtPermitJoiningRsp::decode(&[0x62, 0x8B]).unwrap();
    assert_eq!(rsp.status, ZdpStatus::NotPermitted);
}

// 05-3474-23-24339-01 + 05-3474-23-24339-02: update request then a
// notify whose energy count matches the scanned-channel popcount.
#[test]
fn vector_mgmt_nwk_update_05_3474_23_24339_01() {
    let req = MgmtNwkUpdateReq::decode(&[0x70, 0x00, 0x08, 0x00, 0x00, 0x05, 0x02]).unwrap();
    assert_eq!(req.scan_channels, 0x0000_0800);
    assert_eq!(req.scan_duration, 0x05);
    assert_eq!(req.scan_count, 0x02);
    let mut out = [0u8; 8];
    let n = req.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], &[0x70, 0x00, 0x08, 0x00, 0x00, 0x05, 0x02]);

    // One scanned channel (bit 11 -> channel 11): one energy sample.
    let notify_wire: &[u8] = &[
        0x70, 0x00, 0x00, 0x08, 0x00, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x5A,
    ];
    let notify = MgmtNwkUpdateNotify::decode(notify_wire).unwrap();
    assert_eq!(notify.scanned_channels, 0x0000_0800);
    assert_eq!(notify.total_transmissions, 0x000A);
    assert_eq!(notify.failed_transmissions, 0x0001);
    assert_eq!(notify.energy_len, 1);
    assert_eq!(notify.energy[0], 0x5A);
    let mut out2 = [0u8; 40];
    let n2 = notify.encode_into(&mut out2).unwrap();
    assert_eq!(&out2[..n2], notify_wire);
    // Energy count disagreeing with the mask is refused.
    let mut bad = notify;
    bad.energy_len = 2;
    assert_eq!(bad.encode_into(&mut out2), Err(ZdoError::TooManyEntries));
}

// 05-3474-23-2325-02 + 05-3474-23-24311-07: endpoint table insert,
// active list, and complementary match logic.
#[test]
fn vector_endpoint_table_match_05_3474_23_2325_02() {
    let mut table = EndpointTable::new();
    let lamp = SimpleDescriptor {
        endpoint: 0x0A,
        profile_id: 0x0104,
        device_id: 0x0100,
        device_version: 0,
        in_clusters: {
            let mut list = [0u16; MAX_SIMPLE_CLUSTERS];
            list[0] = 0x0000;
            list[1] = 0x0006;
            list
        },
        in_len: 2,
        out_clusters: [0u16; MAX_SIMPLE_CLUSTERS],
        out_len: 0,
    };
    assert_eq!(table.insert(lamp), ZdpStatus::Success);
    assert_eq!(table.get(0x0A).unwrap().profile_id, 0x0104);
    // ZDO and broadcast endpoints never host descriptors.
    let mut bad = lamp;
    bad.endpoint = 0x00;
    assert_eq!(table.insert(bad), ZdpStatus::InvalidEp);

    let mut eps = [0u8; MAX_EP_LIST];
    let n = table.active_endpoints(&mut eps);
    assert_eq!(&eps[..n], &[0x0A]);

    // The lamp outputs nothing, so a requester *output* of 0x0006
    // matches; a requester *input* of 0x0008 does not.
    let mut hits = [0u8; MAX_EP_LIST];
    let m = table.match_desc(0x0104, &[], &[0x0006], &mut hits);
    assert_eq!(&hits[..m], &[0x0A]);
    let m2 = table.match_desc(0x0104, &[0x0008], &[], &mut hits);
    assert_eq!(m2, 0);
    // Profile mismatch never matches; empty lists match on profile.
    let m3 = table.match_desc(0x0105, &[], &[], &mut hits);
    assert_eq!(m3, 0);
    let m4 = table.match_desc(0x0104, &[], &[], &mut hits);
    assert_eq!(&hits[..m4], &[0x0A]);
}

// 05-3474-23-24322-02 + 05-3474-23-24323-02: bind manager executes
// group and unicast binds against the APS tables, then unbinds.
#[test]
fn vector_bind_manager_tables_05_3474_23_24322_02() {
    use rounddance_aps::{BindingTable, GroupTable};
    let mut bindings = BindingTable::new();
    let mut groups = GroupTable::new();
    let mut mgr = BindManager::new(&mut bindings, &mut groups);
    let local: u64 = 0xAAAA_BBBB_CCCC_DDDD;

    let group_entry = BindEntry {
        tsn: 0x41,
        src_ieee: local,
        src_endpoint: 0x0A,
        cluster_id: 0x0006,
        dst: BindDstMode::Group { group_addr: 0x002A },
    };
    assert_eq!(mgr.bind(&group_entry, local), ZdpStatus::Success);
    {
        let mut members = [0u8; 8];
        let n = mgr.group.members(0x002A, &mut members);
        assert_eq!(&members[..n], &[0x0A]);
    }
    assert_eq!(mgr.unbind(&group_entry), ZdpStatus::Success);
    // Second unbind: the entry is gone.
    assert_eq!(mgr.unbind(&group_entry), ZdpStatus::DeviceNotFound);

    let uni_entry = BindEntry {
        tsn: 0x42,
        src_ieee: local,
        src_endpoint: 0x0A,
        cluster_id: 0x0008,
        dst: BindDstMode::Extended {
            dst_ieee: 0x1111_2222_3333_4444,
            dst_endpoint: 0x0B,
        },
    };
    assert_eq!(mgr.bind(&uni_entry, local), ZdpStatus::Success);
    // Binding the ZDO endpoint is refused.
    let bad = BindEntry {
        src_endpoint: 0x00,
        ..uni_entry
    };
    assert_eq!(mgr.bind(&bad, local), ZdpStatus::InvalidEp);
}

// 05-3474-23-36110-01: local conflict detection — same network
// address claimed for a different long address conflicts; the local
// re-announce (same long address) and any other network address do
// not.
#[test]
fn vector_mgmt_conflict_detect_05_3474_23_36110_01() {
    const OWN_NWK: u16 = 0x1234;
    const OWN_IEEE: u64 = 0x1111_2222_3333_4444;
    const OTHER_IEEE: u64 = 0x5555_6666_7777_8888;
    // A stranger claiming our address: conflict.
    assert!(detect_local_conflict(
        OWN_NWK, OWN_IEEE, OWN_NWK, OTHER_IEEE
    ));
    // Our own re-announce echoing back: no conflict.
    assert!(!detect_local_conflict(OWN_NWK, OWN_IEEE, OWN_NWK, OWN_IEEE));
    // A stranger on any other address: no local conflict.
    assert!(!detect_local_conflict(
        OWN_NWK, OWN_IEEE, 0x5678, OTHER_IEEE
    ));
}

// 05-3474-23-36110-01: table-scope conflict scan — first neighbor row
// binding the watched network address to a different long address;
// no row, or an empty page, reports no conflict.
#[test]
fn vector_mgmt_conflict_table_05_3474_23_36110_01() {
    const WATCH_NWK: u16 = 0x1234;
    const WATCH_IEEE: u64 = 0x1111_2222_3333_4444;
    let blank = NeighborEntry {
        ext_pan: 0,
        ieee: 0,
        nwk: 0,
        device_type: 0,
        rx_on_idle: false,
        relationship: 0,
        depth: 0,
        lqi: 0,
    };
    let mut entries = [blank; MAX_NEIGHBORS];
    entries[0] = NeighborEntry {
        nwk: 0x5678,
        ieee: 0xAAAA_BBBB_CCCC_DDDD,
        ..blank
    };
    // Row 0 is a different address; row 1 re-binds the watched
    // address to a stranger: the scan names row 1.
    entries[1] = NeighborEntry {
        nwk: WATCH_NWK,
        ieee: 0x5555_6666_7777_8888,
        ..blank
    };
    assert_eq!(
        first_table_conflict(&entries[..2], WATCH_NWK, WATCH_IEEE),
        Some(1)
    );
    // The watched owner itself in the table: no conflict.
    entries[1].ieee = WATCH_IEEE;
    assert_eq!(
        first_table_conflict(&entries[..2], WATCH_NWK, WATCH_IEEE),
        None
    );
    // Empty page: no conflict.
    assert_eq!(first_table_conflict(&[], WATCH_NWK, WATCH_IEEE), None);
}

// 05-3474-23-36110-02: local-conflict decision — a router gives up
// the address (reporting the previous one unless the conflict arrived
// inside a status report), a coordinator keeps it (still reporting),
// an end device defers to its parent and stays silent.
#[test]
fn vector_mgmt_conflict_decide_05_3474_23_36110_02() {
    const OWN_NWK: u16 = 0x1234;
    // Router, fresh sighting: adopt a new address, report the old.
    let router = decide_local_conflict(ConflictRole::Router, OWN_NWK, false);
    assert_eq!(router.decision, ConflictDecision::AdoptNewAddress);
    assert_eq!(router.report_addr, Some(OWN_NWK));
    // Router, learned via a status report: same move, no new report.
    let router_via = decide_local_conflict(ConflictRole::Router, OWN_NWK, true);
    assert_eq!(router_via.decision, ConflictDecision::AdoptNewAddress);
    assert_eq!(router_via.report_addr, None);
    // Coordinator never changes its address, but still reports.
    let coord = decide_local_conflict(ConflictRole::Coordinator, OWN_NWK, false);
    assert_eq!(coord.decision, ConflictDecision::KeepAddress);
    assert_eq!(coord.report_addr, Some(OWN_NWK));
    // End device never self-resolves: parent owns the fix.
    let end = decide_local_conflict(ConflictRole::EndDevice, OWN_NWK, false);
    assert_eq!(end.decision, ConflictDecision::DeferToParent);
    assert_eq!(end.report_addr, None);
}

// 05-3474-23-36110-03: remote-conflict report — a router or the
// coordinator names the offending address for the status broadcast
// (suppressed when learned via a status report); an end device owes
// nothing.
#[test]
fn vector_mgmt_conflict_report_05_3474_23_36110_03() {
    const OFFENDER: u16 = 0x9ABC;
    assert_eq!(
        decide_remote_conflict(ConflictRole::Router, OFFENDER, false),
        Some(OFFENDER)
    );
    assert_eq!(
        decide_remote_conflict(ConflictRole::Coordinator, OFFENDER, false),
        Some(OFFENDER)
    );
    assert_eq!(
        decide_remote_conflict(ConflictRole::Router, OFFENDER, true),
        None
    );
    assert_eq!(
        decide_remote_conflict(ConflictRole::EndDevice, OFFENDER, false),
        None
    );
}

// 05-3474-23-36110-04: act edge — a device that adopts a new address
// re-announces itself under it; the announce round-trips the new
// address.
#[test]
fn vector_mgmt_conflict_reannounce_05_3474_23_36110_04() {
    const IEEE: u64 = 0x1111_2222_3333_4444;
    let ann = reannounce(0x33, 0x9ABC, IEEE, 0x8E);
    assert_eq!(ann.nwk_addr, 0x9ABC);
    assert_eq!(ann.ieee, IEEE);
    let mut out = [0u8; 16];
    let n = ann.encode_into(&mut out).unwrap();
    let seen = DeviceAnnce::decode(&out[..n]).unwrap();
    assert_eq!(seen, ann);
}

// 05-3474-23-244-01: status codes round-trip, unknowns preserved.
#[test]
fn vector_status_codes_05_3474_23_244_01() {
    for (code, status) in [
        (0x00, ZdpStatus::Success),
        (0x80, ZdpStatus::InvRequestType),
        (0x81, ZdpStatus::DeviceNotFound),
        (0x82, ZdpStatus::InvalidEp),
        (0x83, ZdpStatus::NotActive),
        (0x84, ZdpStatus::NotSupported),
        (0x85, ZdpStatus::Timeout),
        (0x89, ZdpStatus::NoMemory),
        (0x8A, ZdpStatus::NoTableSpace),
        (0x8B, ZdpStatus::NotPermitted),
    ] {
        assert_eq!(ZdpStatus::from_code(code), status);
        assert_eq!(status.code(), code);
    }
    // Unnamed values (e.g. NO_DESCRIPTOR until mined) survive.
    assert_eq!(ZdpStatus::from_code(0x8C), ZdpStatus::Unknown(0x8C));
    assert_eq!(ZdpStatus::Unknown(0x8C).code(), 0x8C);
}

// 05-3474-23-24330-01 + 05-3474-23-24330-02: discovery request then a
// two-entry response page over the air shape.
#[test]
fn vector_mgmt_nwk_disc_05_3474_23_24330_01() {
    let req = MgmtNwkDiscReq::decode(&[0x71, 0x00, 0x08, 0x00, 0x00, 0x05, 0x00]).unwrap();
    assert_eq!(req.scan_channels, 0x0000_0800);
    assert_eq!(req.scan_duration, 0x05);
    assert_eq!(req.start_index, 0x00);
    let mut out = [0u8; 8];
    let n = req.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], &[0x71, 0x00, 0x08, 0x00, 0x00, 0x05, 0x00]);
    assert_eq!(MgmtNwkDiscReq::decode(&[0x71]), Err(ZdoError::Truncated));

    let rsp = MgmtNwkDiscRsp {
        tsn: 0x71,
        status: ZdpStatus::Success,
        network_count: 2,
        start_index: 0,
        entries: [
            NetworkEntry {
                ext_pan: 0x0102_0304_0506_0708,
                pan: 0x1A62,
                channel: 15,
                stack_profile: 2,
                version: 1,
                permit_joining: true,
            },
            NetworkEntry {
                ext_pan: 0x1112_1314_1516_1718,
                pan: 0x3761,
                channel: 25,
                stack_profile: 2,
                version: 1,
                permit_joining: false,
            },
            NetworkEntry {
                ext_pan: 0,
                pan: 0,
                channel: 0,
                stack_profile: 0,
                version: 0,
                permit_joining: false,
            },
            NetworkEntry {
                ext_pan: 0,
                pan: 0,
                channel: 0,
                stack_profile: 0,
                version: 0,
                permit_joining: false,
            },
        ],
        entry_len: 2,
    };
    let mut rbuf = [0u8; 64];
    let rn = rsp.encode_into(&mut rbuf).unwrap();
    let back = MgmtNwkDiscRsp::decode(&rbuf[..rn]).unwrap();
    assert_eq!(back, rsp);
    assert_eq!(back.entry_list().len(), 2);
    assert!(back.entry_list()[0].permit_joining);
    // Over-budget page and truncation are refused, never truncated.
    let mut over = rsp;
    over.entry_len = 5;
    assert_eq!(over.encode_into(&mut rbuf), Err(ZdoError::TooManyEntries));
    assert_eq!(MgmtNwkDiscRsp::decode(&rbuf[..4]), Err(ZdoError::Truncated));
    // Error responses carry no list.
    let err = MgmtNwkDiscRsp::decode(&[0x71, 0x81, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(err.status, ZdpStatus::DeviceNotFound);
    assert_eq!(err.entry_len, 0);
}

// 05-3474-23-24332-03 + 05-3474-23-24332-04: routing-table page.
#[test]
fn vector_mgmt_rtg_05_3474_23_24332_03() {
    let req = MgmtRtgReq::decode(&[0x72, 0x00]).unwrap();
    assert_eq!(req.start_index, 0x00);
    let mut out = [0u8; 4];
    let n = req.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], &[0x72, 0x00]);
    assert_eq!(MgmtRtgReq::decode(&[0x72]), Err(ZdoError::Truncated));

    let rsp = MgmtRtgRsp {
        tsn: 0x72,
        status: ZdpStatus::Success,
        table_size: 3,
        start_index: 0,
        entries: [
            RtgEntry {
                dest: 0x0000,
                status: 0,
                next_hop: 0x0000,
            },
            RtgEntry {
                dest: 0x0001,
                status: 0,
                next_hop: 0x0004,
            },
            RtgEntry {
                dest: 0x0005,
                status: 1,
                next_hop: 0x0004,
            },
            RtgEntry {
                dest: 0,
                status: 0,
                next_hop: 0,
            },
            RtgEntry {
                dest: 0,
                status: 0,
                next_hop: 0,
            },
            RtgEntry {
                dest: 0,
                status: 0,
                next_hop: 0,
            },
            RtgEntry {
                dest: 0,
                status: 0,
                next_hop: 0,
            },
            RtgEntry {
                dest: 0,
                status: 0,
                next_hop: 0,
            },
        ],
        entry_len: 3,
    };
    let mut rbuf = [0u8; 64];
    let rn = rsp.encode_into(&mut rbuf).unwrap();
    let back = MgmtRtgRsp::decode(&rbuf[..rn]).unwrap();
    assert_eq!(back, rsp);
    assert_eq!(back.entry_list()[1].next_hop, 0x0004);
    // Reserved route states are refused on both paths.
    assert_eq!(
        RtgEntry::decode(&[0x00, 0x00, 0x03, 0x00, 0x00]),
        Err(ZdoError::InvalidValue(0x03))
    );
    assert_eq!(
        RtgEntry {
            dest: 0,
            status: 9,
            next_hop: 0
        }
        .encode_into(&mut out),
        Err(ZdoError::InvalidValue(9))
    );
    let mut over = rsp;
    over.entry_len = 9;
    assert_eq!(over.encode_into(&mut rbuf), Err(ZdoError::TooManyEntries));
    let err = MgmtRtgRsp::decode(&[0x72, 0x84, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(err.status, ZdpStatus::NotSupported);
}

// 05-3474-23-24333-01 + 05-3474-23-24333-02: binding-table page with
// group and extended entries.
#[test]
fn vector_mgmt_bind_05_3474_23_24333_01() {
    let req = MgmtBindReq::decode(&[0x73, 0x00]).unwrap();
    assert_eq!(req.start_index, 0x00);
    let mut out = [0u8; 4];
    let n = req.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], &[0x73, 0x00]);
    assert_eq!(MgmtBindReq::decode(&[0x73]), Err(ZdoError::Truncated));

    let group = MgmtBindEntry {
        src_ieee: 0x1122_3344_5566_7788,
        src_endpoint: 0x01,
        cluster_id: 0x0006,
        dst: crate::BindDstMode::Group { group_addr: 0x0001 },
    };
    let ext = MgmtBindEntry {
        src_ieee: 0x0102_0304_0506_0708,
        src_endpoint: 0x02,
        cluster_id: 0x0008,
        dst: crate::BindDstMode::Extended {
            dst_ieee: 0x1112_1314_1516_1718,
            dst_endpoint: 0x03,
        },
    };
    let rsp = MgmtBindRsp {
        tsn: 0x73,
        status: ZdpStatus::Success,
        table_size: 2,
        start_index: 0,
        entries: [
            group,
            ext,
            MgmtBindEntry {
                src_ieee: 0,
                src_endpoint: 0,
                cluster_id: 0,
                dst: crate::BindDstMode::Group { group_addr: 0 },
            },
            MgmtBindEntry {
                src_ieee: 0,
                src_endpoint: 0,
                cluster_id: 0,
                dst: crate::BindDstMode::Group { group_addr: 0 },
            },
        ],
        entry_len: 2,
    };
    let mut rbuf = [0u8; 96];
    let rn = rsp.encode_into(&mut rbuf).unwrap();
    let back = MgmtBindRsp::decode(&rbuf[..rn]).unwrap();
    assert_eq!(back, rsp);
    assert_eq!(back.entry_list().len(), 2);
    assert_eq!(back.entry_list()[0], group);
    // Bogus destination modes are refused, not misread.
    let mut bad = [0u8; 16];
    bad[..11].copy_from_slice(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x06, 0x00,
    ]);
    bad[11] = 0x02;
    assert_eq!(
        MgmtBindEntry::decode(&bad),
        Err(ZdoError::InvalidValue(0x02))
    );
    let mut over = rsp;
    over.entry_len = 5;
    assert_eq!(over.encode_into(&mut rbuf), Err(ZdoError::TooManyEntries));
    let err = MgmtBindRsp::decode(&[0x73, 0x8A, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(err.status, ZdpStatus::NoTableSpace);
}

// New management clusters pair with 0x8000 responses like the rest.
#[test]
fn vector_mgmt_new_clusters_05_3474_23_244_02() {
    assert_eq!(CLUSTER_MGMT_NWK_DISC_REQ, 0x0030);
    assert_eq!(CLUSTER_MGMT_RTG_REQ, 0x0032);
    assert_eq!(CLUSTER_MGMT_BIND_REQ, 0x0033);
    assert_eq!(response_cluster(CLUSTER_MGMT_NWK_DISC_REQ), Some(0x8030));
    assert_eq!(response_cluster(CLUSTER_MGMT_RTG_REQ), Some(0x8032));
    assert_eq!(response_cluster(CLUSTER_MGMT_BIND_REQ), Some(0x8033));
}

// 05-3474-23-24316-01..03: Parent_annce names joined children and
// the unicast Parent_annce_rsp echoes them back.
#[test]
fn vector_parent_annce_05_3474_23_24316_01() {
    assert_eq!(CLUSTER_PARENT_ANNCE, 0x001F);
    assert_eq!(response_cluster(CLUSTER_PARENT_ANNCE), Some(0x801F));
    assert!(transaction_expected(CLUSTER_PARENT_ANNCE));
    let wire: &[u8] = &[
        0x74, 0x02, // tsn, 2 children
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x05, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04,
        0x03, 0x02, 0x01, 0x06, 0x00,
    ];
    let ann = ParentAnnce::decode(wire).unwrap();
    assert_eq!(ann.tsn, 0x74);
    assert_eq!(ann.child_list().len(), 2);
    assert_eq!(ann.child_list()[0].child_ieee, 0x1122_3344_5566_7788);
    assert_eq!(ann.child_list()[0].child_nwk, 0x0005);
    assert_eq!(ann.child_list()[1].child_ieee, 0x0102_0304_0506_0708);
    let mut out = [0u8; 32];
    let n = ann.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);
    assert_eq!(ParentAnnce::decode(&wire[..11]), Err(ZdoError::Truncated));
    assert_eq!(
        ann.encode_into(&mut out[..11]),
        Err(ZdoError::BufferTooSmall)
    );
    let mut over = ann;
    over.child_len = 5;
    assert_eq!(over.encode_into(&mut out), Err(ZdoError::TooManyEntries));

    let rsp_wire: &[u8] = &[
        0x74, 0x00, 0x01, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x05, 0x00,
    ];
    let rsp = ParentAnnceRsp::decode(rsp_wire).unwrap();
    assert!(rsp.status.is_success());
    assert_eq!(rsp.child_list().len(), 1);
    assert_eq!(rsp.child_list()[0].child_nwk, 0x0005);
    let mut rout = [0u8; 32];
    let rn = rsp.encode_into(&mut rout).unwrap();
    assert_eq!(&rout[..rn], rsp_wire);
    let err = ParentAnnceRsp::decode(&[0x74, 0x81, 0x00]).unwrap();
    assert_eq!(err.status, ZdpStatus::DeviceNotFound);
    assert_eq!(err.child_len, 0);
}

// 05-3474-23-24320-01 + 05-3474-23-24320-02: end-device bind pairing
// with input and output cluster lists.
#[test]
fn vector_end_device_bind_05_3474_23_24320_01() {
    assert_eq!(CLUSTER_END_DEVICE_BIND_REQ, 0x0020);
    assert_eq!(response_cluster(CLUSTER_END_DEVICE_BIND_REQ), Some(0x8020));
    assert!(transaction_expected(CLUSTER_END_DEVICE_BIND_REQ));
    let wire: &[u8] = &[
        0x74, 0xFD, 0xFF, // tsn, binding target 0xFFFD
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // src ieee
        0x01, 0x04, 0x01, // src ep, profile 0x0104
        0x02, 0x00, 0x00, 0x06, 0x00, // 2 in-clusters: 0x0000, 0x0006
        0x01, 0x08, 0x00, // 1 out-cluster: 0x0008
    ];
    let req = EndDeviceBindReq::decode(wire).unwrap();
    assert_eq!(req.binding_target, 0xFFFD);
    assert_eq!(req.src_ieee, 0x0807_0605_0403_0201);
    assert_eq!(req.in_list(), &[0x0000, 0x0006]);
    assert_eq!(req.out_list(), &[0x0008]);
    let mut out = [0u8; 32];
    let n = req.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);
    // Over-budget lists and truncation are refused, never truncated.
    let mut over = req;
    over.in_len = 9;
    assert_eq!(over.encode_into(&mut out), Err(ZdoError::TooManyEntries));
    assert_eq!(
        EndDeviceBindReq::decode(&wire[..15]),
        Err(ZdoError::Truncated)
    );
    let mut bad_count = wire.to_vec();
    bad_count[14] = 9;
    assert_eq!(
        EndDeviceBindReq::decode(&bad_count),
        Err(ZdoError::TooManyEntries)
    );
    let rsp = EndDeviceBindRsp::decode(&[0x74, 0x00]).unwrap();
    assert!(rsp.status.is_success());
    let mut rout = [0u8; 4];
    assert_eq!(rsp.encode_into(&mut rout).unwrap(), 2);
    assert_eq!(&rout[..2], &[0x74, 0x00]);
}

// 05-3474-23-24317-01 + 05-3474-23-24317-02: complex-descriptor page
// with two tag-length-value fields.
#[test]
fn vector_complex_desc_05_3474_23_24317_01() {
    assert_eq!(CLUSTER_COMPLEX_DESC_REQ, 0x0010);
    assert_eq!(response_cluster(CLUSTER_COMPLEX_DESC_REQ), Some(0x8010));
    assert!(transaction_expected(CLUSTER_COMPLEX_DESC_REQ));
    let req = ComplexDescReq::decode(&[0x75, 0x34, 0x12]).unwrap();
    assert_eq!(req.nwk_of_interest, 0x1234);
    let mut out = [0u8; 4];
    assert_eq!(req.encode_into(&mut out).unwrap(), 3);
    assert_eq!(&out[..3], &[0x75, 0x34, 0x12]);
    assert_eq!(
        ComplexDescReq::decode(&[0x75, 0x34]),
        Err(ZdoError::Truncated)
    );

    let rsp = ComplexDescRsp {
        tsn: 0x75,
        status: ZdpStatus::Success,
        nwk_of_interest: 0x1234,
        fields: [
            ComplexField {
                tag: 0x01,
                body: {
                    let mut b = [0u8; MAX_COMPLEX_FIELD_LEN];
                    b[0] = 0xAA;
                    b[1] = 0xBB;
                    b
                },
                len: 2,
            },
            ComplexField {
                tag: 0x02,
                body: {
                    let mut b = [0u8; MAX_COMPLEX_FIELD_LEN];
                    b[0] = 0xCC;
                    b
                },
                len: 1,
            },
            ComplexField {
                tag: 0,
                body: [0; MAX_COMPLEX_FIELD_LEN],
                len: 0,
            },
            ComplexField {
                tag: 0,
                body: [0; MAX_COMPLEX_FIELD_LEN],
                len: 0,
            },
        ],
        field_len: 2,
    };
    let mut rbuf = [0u8; 64];
    let rn = rsp.encode_into(&mut rbuf).unwrap();
    let back = ComplexDescRsp::decode(&rbuf[..rn]).unwrap();
    assert_eq!(back, rsp);
    assert_eq!(back.field_list().len(), 2);
    assert_eq!(back.field_list()[0].tag, 0x01);
    // Over-budget pages and truncation are refused, never truncated.
    let mut over = rsp;
    over.field_len = 5;
    assert_eq!(over.encode_into(&mut rbuf), Err(ZdoError::TooManyEntries));
    assert_eq!(ComplexDescRsp::decode(&rbuf[..4]), Err(ZdoError::Truncated));
    let err = ComplexDescRsp::decode(&[0x75, 0x84, 0x34, 0x12, 0x00]).unwrap();
    assert_eq!(err.status, ZdpStatus::NotSupported);
    assert_eq!(err.field_len, 0);
}

// 05-3474-23-24318-01 + 05-3474-23-24318-02: user label roundtrip.
#[test]
fn vector_user_desc_05_3474_23_24318_01() {
    assert_eq!(CLUSTER_USER_DESC_REQ, 0x0011);
    assert_eq!(response_cluster(CLUSTER_USER_DESC_REQ), Some(0x8011));
    assert!(transaction_expected(CLUSTER_USER_DESC_REQ));
    let req = UserDescReq::decode(&[0x76, 0x78, 0x56]).unwrap();
    assert_eq!(req.nwk_of_interest, 0x5678);
    let mut out = [0u8; 4];
    assert_eq!(req.encode_into(&mut out).unwrap(), 3);
    assert_eq!(&out[..3], &[0x76, 0x78, 0x56]);

    let mut label = [0u8; MAX_USER_DESC_LEN];
    label[..5].copy_from_slice(b"lamp1");
    let rsp = UserDescRsp {
        tsn: 0x76,
        status: ZdpStatus::Success,
        nwk_of_interest: 0x5678,
        label,
        label_len: 5,
    };
    let mut rbuf = [0u8; 32];
    let rn = rsp.encode_into(&mut rbuf).unwrap();
    let back = UserDescRsp::decode(&rbuf[..rn]).unwrap();
    assert_eq!(back, rsp);
    assert_eq!(back.label_bytes(), b"lamp1");
    // Over-long labels are refused on encode; short reads on decode.
    let mut over = rsp;
    over.label_len = 17;
    assert_eq!(over.encode_into(&mut rbuf), Err(ZdoError::TooManyEntries));
    assert_eq!(UserDescRsp::decode(&rbuf[..7]), Err(ZdoError::Truncated));
    let err = UserDescRsp::decode(&[0x76, 0x81, 0x78, 0x56, 0x00]).unwrap();
    assert_eq!(err.status, ZdpStatus::DeviceNotFound);
}

// 05-3474-23-24336-01 + 05-3474-23-24336-02: direct-join admission of
// one designated device.
#[test]
fn vector_mgmt_direct_join_05_3474_23_24336_01() {
    assert_eq!(CLUSTER_MGMT_DIRECT_JOIN_REQ, 0x0035);
    assert_eq!(response_cluster(CLUSTER_MGMT_DIRECT_JOIN_REQ), Some(0x8035));
    assert!(transaction_expected(CLUSTER_MGMT_DIRECT_JOIN_REQ));
    let wire: &[u8] = &[0x77, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x8E];
    let req = MgmtDirectJoinReq::decode(wire).unwrap();
    assert_eq!(req.device_ieee, 0x0807_0605_0403_0201);
    assert_eq!(req.capability, 0x8E);
    let mut out = [0u8; 12];
    let n = req.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);
    assert_eq!(
        MgmtDirectJoinReq::decode(&wire[..9]),
        Err(ZdoError::Truncated)
    );
    let rsp = MgmtDirectJoinRsp::decode(&[0x77, 0x00]).unwrap();
    assert!(rsp.status.is_success());
    let mut rout = [0u8; 4];
    assert_eq!(rsp.encode_into(&mut rout).unwrap(), 2);
    assert_eq!(&rout[..2], &[0x77, 0x00]);
}

// Deprecated-but-recognized clusters: IDs + response pairing stay
// wired for 3.0-compat (R23.2 heading-only entries carry no wire
// codec in this layer).
#[test]
fn vector_deprecated_cluster_pairing_05_3474_23_244_02() {
    assert_eq!(CLUSTER_DISCOVERY_CACHE_REQ, 0x0012);
    assert_eq!(CLUSTER_USER_DESC_SET_REQ, 0x0014);
    assert_eq!(CLUSTER_DISCOVERY_STORE_REQ, 0x0016);
    assert_eq!(CLUSTER_NODE_DESC_STORE_REQ, 0x0017);
    assert_eq!(CLUSTER_BIND_REGISTER_REQ, 0x0023);
    assert_eq!(CLUSTER_REPLACE_DEVICE_REQ, 0x0024);
    assert_eq!(CLUSTER_STORE_BAK_BIND_ENTRY_REQ, 0x0025);
    assert_eq!(CLUSTER_REMOVE_BAK_BIND_ENTRY_REQ, 0x0026);
    assert_eq!(CLUSTER_BACKUP_BIND_TABLE_REQ, 0x0027);
    assert_eq!(CLUSTER_RECOVER_BIND_TABLE_REQ, 0x0028);
    assert_eq!(CLUSTER_MGMT_CACHE_REQ, 0x0037);
    for req in [
        CLUSTER_DISCOVERY_CACHE_REQ,
        CLUSTER_USER_DESC_SET_REQ,
        CLUSTER_BIND_REGISTER_REQ,
        CLUSTER_REPLACE_DEVICE_REQ,
        CLUSTER_STORE_BAK_BIND_ENTRY_REQ,
        CLUSTER_REMOVE_BAK_BIND_ENTRY_REQ,
        CLUSTER_BACKUP_BIND_TABLE_REQ,
        CLUSTER_RECOVER_BIND_TABLE_REQ,
        CLUSTER_DISCOVERY_STORE_REQ,
        CLUSTER_NODE_DESC_STORE_REQ,
        CLUSTER_MGMT_CACHE_REQ,
    ] {
        assert_eq!(response_cluster(req), Some(req | RESPONSE_BIT));
        assert!(transaction_expected(req));
    }
}

// 05-3474-23-24338-01 + 05-3474-23-24338-02: discovery-cache table
// page (DEPRECATED in R23.2 §2.4.3.3.8 heading-only; paged shape
// retained for 3.0-compat).
#[test]
fn vector_mgmt_cache_05_3474_23_24338_01() {
    assert_eq!(response_cluster(CLUSTER_MGMT_CACHE_REQ), Some(0x8037));
    let req = MgmtCacheReq::decode(&[0x77, 0x00]).unwrap();
    assert_eq!(req.start_index, 0x00);
    let mut out = [0u8; 4];
    assert_eq!(req.encode_into(&mut out).unwrap(), 2);
    assert_eq!(MgmtCacheReq::decode(&[0x77]), Err(ZdoError::Truncated));

    let rsp = MgmtCacheRsp {
        tsn: 0x77,
        status: ZdpStatus::Success,
        table_size: 2,
        start_index: 0,
        entries: [
            CacheEntry {
                ieee: 0x1122_3344_5566_7788,
                nwk: 0x0005,
            },
            CacheEntry {
                ieee: 0x0102_0304_0506_0708,
                nwk: 0x0006,
            },
            CacheEntry { ieee: 0, nwk: 0 },
            CacheEntry { ieee: 0, nwk: 0 },
        ],
        entry_len: 2,
    };
    let mut rbuf = [0u8; 64];
    let rn = rsp.encode_into(&mut rbuf).unwrap();
    let back = MgmtCacheRsp::decode(&rbuf[..rn]).unwrap();
    assert_eq!(back, rsp);
    assert_eq!(back.entry_list()[1].nwk, 0x0006);
    let mut over = rsp;
    over.entry_len = 5;
    assert_eq!(over.encode_into(&mut rbuf), Err(ZdoError::TooManyEntries));
    assert_eq!(MgmtCacheRsp::decode(&rbuf[..4]), Err(ZdoError::Truncated));
    let err = MgmtCacheRsp::decode(&[0x77, 0x89, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(err.status, ZdpStatus::NoMemory);
}

// 05-3474-23-24315-01 + 05-3474-23-24315-02: system-server discovery
// by 16-bit server mask, response echoes the responder's mask.
#[test]
fn vector_system_server_discovery_05_3474_23_24315_01() {
    assert_eq!(CLUSTER_SYSTEM_SERVER_DISCOVERY_REQ, 0x0015);
    assert_eq!(
        response_cluster(CLUSTER_SYSTEM_SERVER_DISCOVERY_REQ),
        Some(0x8015)
    );
    assert!(transaction_expected(CLUSTER_SYSTEM_SERVER_DISCOVERY_REQ));
    let req = SystemServerDiscoveryReq::decode(&[0x78, 0x01, 0x00]).unwrap();
    assert_eq!(req.server_mask, 0x0001);
    let mut out = [0u8; 4];
    assert_eq!(req.encode_into(&mut out).unwrap(), 3);
    assert_eq!(&out[..3], &[0x78, 0x01, 0x00]);
    assert_eq!(
        SystemServerDiscoveryReq::decode(&[0x78, 0x01]),
        Err(ZdoError::Truncated)
    );
    let rsp = SystemServerDiscoveryRsp::decode(&[0x78, 0x00, 0x01, 0x00]).unwrap();
    assert!(rsp.status.is_success());
    assert_eq!(rsp.server_mask, 0x0001);
    let mut rout = [0u8; 8];
    let rn = rsp.encode_into(&mut rout).unwrap();
    assert_eq!(rn, 4);
    assert_eq!(&rout[..rn], &[0x78, 0x00, 0x01, 0x00]);
    assert_eq!(
        SystemServerDiscoveryRsp::decode(&[0x78, 0x00, 0x01]),
        Err(ZdoError::Truncated)
    );
    let err = SystemServerDiscoveryRsp::decode(&[0x78, 0x85, 0x00, 0x00]).unwrap();
    assert_eq!(err.status, ZdpStatus::Timeout);
}

// 05-3474-23-2432C-01 + 05-3474-23-2432C-02: clear-bindings with a
// two-address EUI64 TLV, then the status-only response.
#[test]
fn vector_clear_all_bindings_05_3474_23_2432c_01() {
    assert_eq!(CLUSTER_CLEAR_ALL_BINDINGS_REQ, 0x002B);
    assert_eq!(
        response_cluster(CLUSTER_CLEAR_ALL_BINDINGS_REQ),
        Some(0x802B)
    );
    assert!(transaction_expected(CLUSTER_CLEAR_ALL_BINDINGS_REQ));
    let wire: &[u8] = &[
        0x78, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18,
    ];
    let req = ClearAllBindingsReq::decode(wire).unwrap();
    assert_eq!(
        req.ieee_list(),
        &[0x0807_0605_0403_0201, 0x1817_1615_1413_1211]
    );
    let mut out = [0u8; 32];
    let n = req.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);
    // Over-long lists and truncation are refused, never truncated.
    let mut over = req;
    over.ieee_len = 9;
    assert_eq!(over.encode_into(&mut out), Err(ZdoError::TooManyEntries));
    assert_eq!(
        ClearAllBindingsReq::decode(&wire[..10]),
        Err(ZdoError::Truncated)
    );
    assert_eq!(
        ClearAllBindingsReq::decode(&wire[..1]),
        Err(ZdoError::Truncated)
    );
    // Response carries the Table 2-99 outcome set.
    let rsp = ClearAllBindingsRsp::decode(&[0x78, 0x8B]).unwrap();
    assert_eq!(rsp.status, ZdpStatus::NotPermitted);
    let rsp2 = ClearAllBindingsRsp::decode(&[0x78, 0x00]).unwrap();
    assert!(rsp2.status.is_success());
    let mut rout = [0u8; 4];
    assert_eq!(rsp2.encode_into(&mut rout).unwrap(), 2);
    assert_eq!(&rout[..2], &[0x78, 0x00]);
}

// 05-3474-23-2433A-01 + 05-3474-23-2433A-02: joining allow-list page
// with two long addresses, plus the empty-list and error shapes.
#[test]
fn vector_mgmt_nwk_ieee_joining_list_05_3474_23_2433a_01() {
    assert_eq!(CLUSTER_MGMT_NWK_IEEE_JOINING_LIST_REQ, 0x003A);
    assert_eq!(
        response_cluster(CLUSTER_MGMT_NWK_IEEE_JOINING_LIST_REQ),
        Some(0x803A)
    );
    assert!(transaction_expected(CLUSTER_MGMT_NWK_IEEE_JOINING_LIST_REQ));
    assert_eq!(JoiningPolicy::decode(0x00), Ok(JoiningPolicy::AllJoin));
    assert_eq!(JoiningPolicy::decode(0x01), Ok(JoiningPolicy::IeelistJoin));
    assert_eq!(JoiningPolicy::decode(0x02), Ok(JoiningPolicy::NoJoin));
    assert_eq!(
        JoiningPolicy::decode(0x03),
        Err(ZdoError::InvalidValue(0x03))
    );
    let req = MgmtNwkIeeeJoiningListReq::decode(&[0x79, 0x00]).unwrap();
    assert_eq!(req.start_index, 0x00);
    let rsp = MgmtNwkIeeeJoiningListRsp {
        tsn: 0x79,
        status: ZdpStatus::Success,
        update_id: 0x04,
        policy: JoiningPolicy::IeelistJoin,
        total: 2,
        start_index: 0,
        entries: [
            0x1122_3344_5566_7788,
            0x0102_0304_0506_0708,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
        entry_len: 2,
    };
    let mut rbuf = [0u8; 64];
    let rn = rsp.encode_into(&mut rbuf).unwrap();
    let back = MgmtNwkIeeeJoiningListRsp::decode(&rbuf[..rn]).unwrap();
    assert_eq!(back, rsp);
    assert_eq!(back.entry_list().len(), 2);
    assert_eq!(back.policy.code(), 0x01);
    // Empty list omits the page; errors omit everything but status.
    let empty = MgmtNwkIeeeJoiningListRsp {
        tsn: 0x79,
        status: ZdpStatus::Success,
        update_id: 0x05,
        policy: JoiningPolicy::NoJoin,
        total: 0,
        start_index: 0,
        entries: [0; MAX_JOINING_IEEE],
        entry_len: 0,
    };
    let mut ebuf = [0u8; 16];
    let en = empty.encode_into(&mut ebuf).unwrap();
    assert_eq!(en, 5);
    assert_eq!(
        MgmtNwkIeeeJoiningListRsp::decode(&ebuf[..en]).unwrap(),
        empty
    );
    let err =
        MgmtNwkIeeeJoiningListRsp::decode(&[0x79, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(err.status, ZdpStatus::NotSupported);
    assert_eq!(err.entry_len, 0);
    // Over-budget pages and truncation are refused.
    let mut over = rsp;
    over.entry_len = 9;
    assert_eq!(over.encode_into(&mut rbuf), Err(ZdoError::TooManyEntries));
    assert_eq!(
        MgmtNwkIeeeJoiningListRsp::decode(&rbuf[..6]),
        Err(ZdoError::Truncated)
    );
}

// Deprecated source-bind family + newer mgmt clusters pair by the
// high bit; Enhanced_Update and Beacon_Survey have ID + pairing only
// (ChannelList/TLV codecs are follow-ups).
#[test]
fn vector_mgmt_newer_clusters_05_3474_23_244_02() {
    assert_eq!(CLUSTER_BACKUP_SOURCE_BIND_REQ, 0x0029);
    assert_eq!(CLUSTER_RECOVER_SOURCE_BIND_REQ, 0x002A);
    assert_eq!(CLUSTER_MGMT_NWK_ENHANCED_UPDATE_REQ, 0x0039);
    assert_eq!(CLUSTER_MGMT_NWK_BEACON_SURVEY_REQ, 0x003C);
    for req in [
        CLUSTER_BACKUP_SOURCE_BIND_REQ,
        CLUSTER_RECOVER_SOURCE_BIND_REQ,
        CLUSTER_CLEAR_ALL_BINDINGS_REQ,
        CLUSTER_MGMT_NWK_ENHANCED_UPDATE_REQ,
        CLUSTER_MGMT_NWK_IEEE_JOINING_LIST_REQ,
        CLUSTER_MGMT_NWK_BEACON_SURVEY_REQ,
    ] {
        assert_eq!(response_cluster(req), Some(req | RESPONSE_BIT));
        assert!(transaction_expected(req));
    }
}

// 05-3474-23-3210-01: channel list with two page masks, LE packing
// (top 5 bits page, low 27 bits channels).
#[test]
fn vector_channel_list_05_3474_23_3210_01() {
    let list = ChannelList {
        pages: [
            ChannelPageMask::make(0, 0x07FF_F800),
            ChannelPageMask::make(28, 0x0000_0001),
            ChannelPageMask(0),
            ChannelPageMask(0),
        ],
        page_len: 2,
    };
    assert_eq!(list.pages[0].split(), (0, 0x07FF_F800));
    assert_eq!(list.pages[1].split(), (28, 0x0000_0001));
    let mut buf = [0u8; 16];
    let n = list.encode_into(&mut buf).unwrap();
    assert_eq!(n, 9);
    assert_eq!(buf[0], 2);
    assert_eq!(
        u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
        0x07FF_F800
    );
    assert_eq!(
        u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]),
        (28 << 27) | 1
    );
    let (back, used) = ChannelList::decode(&buf[..n]).unwrap();
    assert_eq!(back, list);
    assert_eq!(used, n);
    assert_eq!(ChannelList::decode(&[]), Err(ZdoError::Truncated));
    let mut over = list;
    over.page_len = 5;
    assert_eq!(over.encode_into(&mut buf), Err(ZdoError::TooManyEntries));
}

// 05-3474-23-243310-01 + 05-3474-23-243310-02: enhanced update across
// all three duration classes, plus the scan-outcome notify.
#[test]
fn vector_mgmt_nwk_enhanced_update_05_3474_23_243310_01() {
    assert_eq!(CLUSTER_MGMT_NWK_ENHANCED_UPDATE_REQ, 0x0039);
    assert_eq!(
        response_cluster(CLUSTER_MGMT_NWK_ENHANCED_UPDATE_REQ),
        Some(0x8039)
    );
    assert!(transaction_expected(CLUSTER_MGMT_NWK_ENHANCED_UPDATE_REQ));
    // Energy-scan request: channel list + duration + scan count.
    let req = MgmtNwkEnhancedUpdateReq {
        tsn: 0x7A,
        channels: ChannelList {
            pages: [
                ChannelPageMask::make(0, 0x07FF_F800),
                ChannelPageMask(0),
                ChannelPageMask(0),
                ChannelPageMask(0),
            ],
            page_len: 1,
        },
        scan_duration: 0x03,
        scan_count: Some(2),
        nwk_update_id: None,
    };
    let mut buf = [0u8; 16];
    let n = req.encode_into(&mut buf).unwrap();
    let back = MgmtNwkEnhancedUpdateReq::decode(&buf[..n]).unwrap();
    assert_eq!(back, req);
    assert_eq!(back.scan_count, Some(2));
    assert_eq!(back.nwk_update_id, None);
    // Channel-change request: duration 0xfe carries the update ID.
    let chg = MgmtNwkEnhancedUpdateReq {
        tsn: 0x7B,
        channels: req.channels,
        scan_duration: 0xFE,
        scan_count: None,
        nwk_update_id: Some(0x42),
    };
    let mut cbuf = [0u8; 16];
    let cn = chg.encode_into(&mut cbuf).unwrap();
    let cback = MgmtNwkEnhancedUpdateReq::decode(&cbuf[..cn]).unwrap();
    assert_eq!(cback, chg);
    assert_eq!(cback.scan_count, None);
    assert_eq!(cback.nwk_update_id, Some(0x42));
    assert!(MgmtNwkEnhancedUpdateReq::decode(&buf[..2]).is_err());

    // Notify: status + single-page mask + counters + ED list.
    let mut energy = [0u8; MAX_ENHANCED_ENERGY];
    energy[0] = 0x5A;
    energy[1] = 0xFF;
    let notify = MgmtNwkEnhancedUpdateNotify {
        tsn: 0x7A,
        status: ZdpStatus::Success,
        scanned: ChannelPageMask::make(0, 0x0000_1800),
        total_transmissions: 0x000A,
        failed_transmissions: 0x0001,
        energy,
        energy_len: 2,
    };
    let mut nbuf = [0u8; 48];
    let nn = notify.encode_into(&mut nbuf).unwrap();
    assert_eq!(nn, 13);
    let nback = MgmtNwkEnhancedUpdateNotify::decode(&nbuf[..nn]).unwrap();
    assert_eq!(nback, notify);
    assert_eq!(nback.scanned.split(), (0, 0x0000_1800));
    assert_eq!(&nback.energy[..2], &[0x5A, 0xFF]);
    let mut over = notify;
    over.energy_len = 28;
    assert_eq!(over.encode_into(&mut nbuf), Err(ZdoError::TooManyEntries));
    assert_eq!(
        MgmtNwkEnhancedUpdateNotify::decode(&nbuf[..10]),
        Err(ZdoError::Truncated)
    );
}

// 05-3474-23-2433C-01 + 05-3474-23-2433C-02: beacon-survey request
// with the configuration TLV; the results/parents TLV response legs
// stay a follow-up.
#[test]
fn vector_mgmt_nwk_beacon_survey_05_3474_23_2433c_01() {
    assert_eq!(CLUSTER_MGMT_NWK_BEACON_SURVEY_REQ, 0x003C);
    assert_eq!(
        response_cluster(CLUSTER_MGMT_NWK_BEACON_SURVEY_REQ),
        Some(0x803C)
    );
    assert!(transaction_expected(CLUSTER_MGMT_NWK_BEACON_SURVEY_REQ));
    let req = MgmtNwkBeaconSurveyReq {
        tsn: 0x7C,
        channels: ChannelList {
            pages: [
                ChannelPageMask::make(0, 0x07FF_F800),
                ChannelPageMask(0),
                ChannelPageMask(0),
                ChannelPageMask(0),
            ],
            page_len: 1,
        },
        config: 0x01,
    };
    let mut buf = [0u8; 16];
    let n = req.encode_into(&mut buf).unwrap();
    assert_eq!(&buf[..2], &[0x7C, 0x01]);
    let back = MgmtNwkBeaconSurveyReq::decode(&buf[..n]).unwrap();
    assert_eq!(back, req);
    assert_eq!(back.channels.page_len, 1);
    assert_eq!(back.config, 0x01);
    // Trailing garbage is refused, never misread as another page.
    let mut long = buf.to_vec();
    long.extend_from_slice(&[0x99]);
    assert!(MgmtNwkBeaconSurveyReq::decode(&long).is_err());
    assert!(MgmtNwkBeaconSurveyReq::decode(&buf[..2]).is_err());
}

// 05-3474-23-2433C-02: beacon-survey response with two candidate
// parents, plus the empty and error shapes.
#[test]
fn vector_mgmt_nwk_beacon_survey_rsp_05_3474_23_2433c_01() {
    let rsp = MgmtNwkBeaconSurveyRsp {
        tsn: 0x7C,
        status: ZdpStatus::Success,
        results: BeaconSurveyResults {
            total: 10,
            on_network: 6,
            potential_parent: 2,
            other: 4,
        },
        current_parent: 0x0000,
        current_lqa: 200,
        parents: [
            PotentialParent {
                short: 0x0001,
                lqa: 210,
            },
            PotentialParent {
                short: 0x0002,
                lqa: 190,
            },
            PotentialParent { short: 0, lqa: 0 },
            PotentialParent { short: 0, lqa: 0 },
            PotentialParent { short: 0, lqa: 0 },
        ],
        parent_len: 2,
    };
    let mut rbuf = [0u8; 32];
    let rn = rsp.encode_into(&mut rbuf).unwrap();
    assert_eq!(rn, 16);
    let back = MgmtNwkBeaconSurveyRsp::decode(&rbuf[..rn]).unwrap();
    assert_eq!(back, rsp);
    assert_eq!(back.results.total, 10);
    assert_eq!(
        back.parent_list(),
        &[
            PotentialParent {
                short: 0x0001,
                lqa: 210
            },
            PotentialParent {
                short: 0x0002,
                lqa: 190
            }
        ][..]
    );
    // Empty parents and error shapes.
    let empty = MgmtNwkBeaconSurveyRsp {
        tsn: 0x7C,
        status: ZdpStatus::Success,
        results: BeaconSurveyResults {
            total: 0,
            on_network: 0,
            potential_parent: 0,
            other: 0,
        },
        current_parent: 0xFFFF,
        current_lqa: 0,
        parents: [PotentialParent { short: 0, lqa: 0 }; MAX_POTENTIAL_PARENTS],
        parent_len: 0,
    };
    let mut ebuf = [0u8; 16];
    assert_eq!(empty.encode_into(&mut ebuf).unwrap(), 10);
    assert_eq!(MgmtNwkBeaconSurveyRsp::decode(&ebuf[..10]).unwrap(), empty);
    let err = MgmtNwkBeaconSurveyRsp::decode(&[0x7C, 0x85]).unwrap();
    assert_eq!(err.status, ZdpStatus::Timeout);
    assert_eq!(err.parent_len, 0);
    // Over-budget pages and truncation are refused.
    let mut over = rsp;
    over.parent_len = 6;
    assert_eq!(over.encode_into(&mut rbuf), Err(ZdoError::TooManyEntries));
    assert_eq!(
        MgmtNwkBeaconSurveyRsp::decode(&rbuf[..9]),
        Err(ZdoError::Truncated)
    );
}
