//! Line-by-line coverage closure for commissioning-adjacent ZDO:
//! device-profile cluster table (§2.4.3–§2.4.4), descriptor codecs
//! (§2.3.2.3–§2.3.2.5), endpoint table, management commands
//! (permit-joining, leave, LQI, discovery), bind/unbind codecs, and
//! the transaction correlator.
//!
//! Paraphrase only (D1): every test cites document, revision, and
//! clause/line anchors. Complements (never duplicates) the existing
//! `tests/roundtrip.rs`, `tests/transaction.rs`, and
//! `tests/vectors.rs`.

use rounddance_zdo::{
    endpoint_bindable, response_cluster, ActiveEpReq, BindDstMode, BindEntry, DeviceAnnce,
    EndpointTable, MatchDescReq, MgmtLeaveReq, MgmtLqiReq, MgmtNwkDiscReq, MgmtPermitJoiningReq,
    NodeDescReq, NodeDescRsp, NodeDescriptor, PendingTable, SimpleDescReq, SimpleDescriptor,
    TxnError, ZdpStatus, CLUSTER_ACTIVE_EP_REQ, CLUSTER_BIND_REQ, CLUSTER_DEVICE_ANNCE,
    CLUSTER_IEEE_ADDR_REQ, CLUSTER_MATCH_DESC_REQ, CLUSTER_MGMT_BIND_REQ, CLUSTER_MGMT_LEAVE_REQ,
    CLUSTER_MGMT_LQI_REQ, CLUSTER_MGMT_NWK_DISC_REQ, CLUSTER_MGMT_PERMIT_JOINING_REQ,
    CLUSTER_MGMT_RTG_REQ, CLUSTER_NODE_DESC_REQ, CLUSTER_NWK_ADDR_REQ, CLUSTER_PARENT_ANNCE,
    CLUSTER_SIMPLE_DESC_REQ, CLUSTER_UNBIND_REQ, MAX_EP_LIST, MAX_SIMPLE_CLUSTERS, RESPONSE_BIT,
};

// ---------------------------------------------------------------------------
// §2.4.3–§2.4.4 cluster table (anchors p0139-L3393 → p0140-L3414)
// ---------------------------------------------------------------------------

// Core discovery/management cluster ids are frozen on the wire.
#[test]
fn bdb_zdo_cluster_ids_frozen() {
    assert_eq!(CLUSTER_NWK_ADDR_REQ, 0x0000);
    assert_eq!(CLUSTER_IEEE_ADDR_REQ, 0x0001);
    assert_eq!(CLUSTER_NODE_DESC_REQ, 0x0002);
    assert_eq!(CLUSTER_SIMPLE_DESC_REQ, 0x0004);
    assert_eq!(CLUSTER_ACTIVE_EP_REQ, 0x0005);
    assert_eq!(CLUSTER_MATCH_DESC_REQ, 0x0006);
    assert_eq!(CLUSTER_DEVICE_ANNCE, 0x0013);
    assert_eq!(CLUSTER_PARENT_ANNCE, 0x001F);
    assert_eq!(CLUSTER_BIND_REQ, 0x0021);
    assert_eq!(CLUSTER_UNBIND_REQ, 0x0022);
    assert_eq!(CLUSTER_MGMT_LQI_REQ, 0x0031);
    assert_eq!(CLUSTER_MGMT_RTG_REQ, 0x0032);
    assert_eq!(CLUSTER_MGMT_BIND_REQ, 0x0033);
    assert_eq!(CLUSTER_MGMT_LEAVE_REQ, 0x0034);
    assert_eq!(CLUSTER_MGMT_PERMIT_JOINING_REQ, 0x0036);
    assert_eq!(CLUSTER_MGMT_NWK_DISC_REQ, 0x0030);
}

// Responses ride the request cluster with the high bit set; the
// response-less announce never opens a transaction.
#[test]
fn bdb_zdo_response_bit_and_announce() {
    assert_eq!(RESPONSE_BIT, 0x8000);
    assert_eq!(
        response_cluster(CLUSTER_NODE_DESC_REQ),
        Some(CLUSTER_NODE_DESC_REQ | RESPONSE_BIT)
    );
    assert_eq!(response_cluster(CLUSTER_DEVICE_ANNCE), None);
    assert!(!rounddance_zdo::transaction_expected(CLUSTER_DEVICE_ANNCE));
    assert!(rounddance_zdo::transaction_expected(CLUSTER_MATCH_DESC_REQ));
}

// ---------------------------------------------------------------------------
// Device_annce + descriptor inquiry codecs
// ---------------------------------------------------------------------------

// The join-completion announce carries the new short + long address
// and the sender capability flags.
#[test]
fn bdb_zdo_device_annce_codec() {
    let a = DeviceAnnce {
        tsn: 0x0A,
        nwk_addr: 0x1234,
        ieee: 0xAAAA_BBBB_CCCC_DDDD,
        capability: 0x8E,
    };
    assert_eq!(DeviceAnnce::LEN, 12);
    let mut buf = [0u8; 12];
    assert_eq!(a.encode_into(&mut buf).unwrap(), 12);
    assert_eq!(DeviceAnnce::decode(&buf).unwrap(), a);
    assert_eq!(
        DeviceAnnce::decode(&buf[..11]).unwrap_err(),
        rounddance_zdo::ZdoError::Truncated
    );
}

// Node-descriptor inquiry names the address of interest.
#[test]
fn bdb_zdo_node_desc_req_codec() {
    let req = NodeDescReq {
        tsn: 0x07,
        nwk_of_interest: 0x1234,
    };
    assert_eq!(NodeDescReq::LEN, 3);
    let mut buf = [0u8; 4];
    assert_eq!(req.encode_into(&mut buf).unwrap(), 3);
    assert_eq!(&buf[..3], &[0x07, 0x34, 0x12]);
    assert_eq!(NodeDescReq::decode(&buf[..3]).unwrap(), req);
}

// A non-success node-descriptor response carries no descriptor.
#[test]
fn bdb_zdo_node_desc_rsp_status_path() {
    let rsp = NodeDescRsp::decode(&[0x07, 0x81, 0x34, 0x12]).unwrap();
    assert_eq!(rsp.tsn, 0x07);
    assert_eq!(rsp.status, ZdpStatus::DeviceNotFound);
    assert_eq!(rsp.nwk_of_interest, 0x1234);
    assert!(rsp.descriptor.is_none());
}

// Node descriptor flags preserve the logical-type low bits.
#[test]
fn bdb_zdo_node_descriptor_logical_type_bits() {
    let desc = NodeDescriptor {
        flags0: 0x01,
        aps_flags: 0,
        freq_band: 0x08,
        mac_cap: 0x8E,
        mfr_code: 0x1002,
        max_buf: 82,
        max_in_transfer: 82,
        server_mask: 0x0000,
        max_out_transfer: 82,
        desc_cap: 0x00,
    };
    assert_eq!(desc.flags0 & 0x07, 0x01);
}

// Simple-descriptor inquiry names address + endpoint.
#[test]
fn bdb_zdo_simple_desc_req_codec() {
    let req = SimpleDescReq {
        tsn: 0x09,
        nwk_of_interest: 0x1234,
        endpoint: 0x0A,
    };
    assert_eq!(SimpleDescReq::LEN, 4);
    let mut buf = [0u8; 4];
    assert_eq!(req.encode_into(&mut buf).unwrap(), 4);
    assert_eq!(&buf, &[0x09, 0x34, 0x12, 0x0A]);
    assert_eq!(SimpleDescReq::decode(&buf).unwrap(), req);
}

// Active-endpoint inquiry names the address of interest.
#[test]
fn bdb_zdo_active_ep_req_codec() {
    let req = ActiveEpReq {
        tsn: 0x0B,
        nwk_of_interest: 0x5678,
    };
    assert_eq!(ActiveEpReq::LEN, 3);
    let mut buf = [0u8; 3];
    assert_eq!(req.encode_into(&mut buf).unwrap(), 3);
    assert_eq!(ActiveEpReq::decode(&buf).unwrap(), req);
}

// Match-descriptor inquiry carries profile + cluster lists.
#[test]
fn bdb_zdo_match_desc_req_codec() {
    let mut in_clusters = [0u16; MAX_SIMPLE_CLUSTERS];
    in_clusters[0] = 0x0006;
    let mut out_clusters = [0u16; MAX_SIMPLE_CLUSTERS];
    out_clusters[0] = 0x0008;
    let req = MatchDescReq {
        tsn: 0x0C,
        nwk_of_interest: 0xFFFF,
        profile_id: 0x0104,
        in_clusters,
        in_len: 1,
        out_clusters,
        out_len: 1,
    };
    let mut buf = [0u8; 32];
    let n = req.encode_into(&mut buf).unwrap();
    assert_eq!(n, req.encoded_len());
    let back = MatchDescReq::decode(&buf[..n]).unwrap();
    assert_eq!(back.profile_id, 0x0104);
    assert_eq!(back.in_len, 1);
    assert_eq!(back.in_clusters[0], 0x0006);
    assert_eq!(back.out_len, 1);
    assert_eq!(back.out_clusters[0], 0x0008);
}

// ---------------------------------------------------------------------------
// Endpoint table: hosting + match (finding & binding reads these)
// ---------------------------------------------------------------------------

fn simple_ep(endpoint: u8, profile: u16, in_c: &[u16]) -> SimpleDescriptor {
    let mut in_clusters = [0u16; MAX_SIMPLE_CLUSTERS];
    in_clusters[..in_c.len()].copy_from_slice(in_c);
    SimpleDescriptor {
        endpoint,
        profile_id: profile,
        device_id: 0x0005,
        device_version: 1,
        in_clusters,
        in_len: in_c.len() as u8,
        out_clusters: [0u16; MAX_SIMPLE_CLUSTERS],
        out_len: 0,
    }
}

#[test]
fn bdb_zdo_endpoint_table_insert_get_remove() {
    let mut table = EndpointTable::new();
    assert_eq!(
        table.insert(simple_ep(0x0A, 0x0104, &[0x0006])),
        ZdpStatus::Success
    );
    assert_eq!(
        table.insert(simple_ep(0x00, 0x0104, &[])),
        ZdpStatus::InvalidEp
    );
    assert!(table.get(0x0A).is_some());
    assert!(table.get(0x0B).is_none());
    let mut eps = [0u8; MAX_EP_LIST];
    let n = table.active_endpoints(&mut eps);
    assert_eq!(&eps[..n], &[0x0A]);
    assert!(table.remove(0x0A));
    assert!(!table.remove(0x0A));
}

#[test]
fn bdb_zdo_endpoint_table_match_desc() {
    let mut table = EndpointTable::new();
    table.insert(simple_ep(0x0A, 0x0104, &[0x0006]));
    table.insert(simple_ep(0x0B, 0x0105, &[0x0006]));
    let mut hits = [0u8; MAX_EP_LIST];
    // Complementary pairing: the request's wanted output cluster is
    // one the endpoint takes as input.
    let n = table.match_desc(0x0104, &[], &[0x0006], &mut hits);
    assert_eq!(&hits[..n], &[0x0A]);
    assert_eq!(table.match_desc(0x0104, &[], &[0x0008], &mut hits), 0);
    // With both lists empty the profile alone decides: 0x0B answers.
    let m = table.match_desc(0x0105, &[], &[], &mut hits);
    assert_eq!(&hits[..m], &[0x0B]);
}

// Only application endpoints bind or answer inquiries.
#[test]
fn bdb_zdo_endpoint_bindable_rules() {
    assert!(endpoint_bindable(0x0A));
    assert!(!endpoint_bindable(0x00));
    assert!(!endpoint_bindable(0xFF));
}

// ---------------------------------------------------------------------------
// Bind/unbind codecs (§2.4.3.2.2–§2.4.3.2.3)
// ---------------------------------------------------------------------------

#[test]
fn bdb_zdo_bind_entry_group_codec() {
    let entry = BindEntry {
        tsn: 0x41,
        src_ieee: 0xAAAA_BBBB_CCCC_DDDD,
        src_endpoint: 0x0A,
        cluster_id: 0x0006,
        dst: BindDstMode::Group { group_addr: 0x002A },
    };
    let mut buf = [0u8; 32];
    let n = entry.encode_into(&mut buf).unwrap();
    let back = BindEntry::decode(&buf[..n]).unwrap();
    assert_eq!(back.cluster_id, 0x0006);
    assert_eq!(back.dst, BindDstMode::Group { group_addr: 0x002A });
}

#[test]
fn bdb_zdo_bind_entry_unicast_codec() {
    let entry = BindEntry {
        tsn: 0x42,
        src_ieee: 0xAAAA_BBBB_CCCC_DDDD,
        src_endpoint: 0x0A,
        cluster_id: 0x0008,
        dst: BindDstMode::Extended {
            dst_ieee: 0x1111_2222_3333_4444,
            dst_endpoint: 0x0B,
        },
    };
    let mut buf = [0u8; 32];
    let n = entry.encode_into(&mut buf).unwrap();
    let back = BindEntry::decode(&buf[..n]).unwrap();
    assert_eq!(
        back.dst,
        BindDstMode::Extended {
            dst_ieee: 0x1111_2222_3333_4444,
            dst_endpoint: 0x0B
        }
    );
}

// ---------------------------------------------------------------------------
// Management commands (permit-joining, leave, LQI, discovery)
// ---------------------------------------------------------------------------

#[test]
fn bdb_zdo_mgmt_permit_joining_codec() {
    let req = MgmtPermitJoiningReq {
        tsn: 0x05,
        duration: 0xFF,
        tc_significance: true,
    };
    assert_eq!(MgmtPermitJoiningReq::LEN, 3);
    let mut buf = [0u8; 4];
    assert_eq!(req.encode_into(&mut buf).unwrap(), 3);
    assert_eq!(MgmtPermitJoiningReq::decode(&buf[..3]).unwrap(), req);
    let closed = MgmtPermitJoiningReq {
        duration: 0x00,
        ..req
    };
    let mut cbuf = [0u8; 4];
    assert_eq!(closed.encode_into(&mut cbuf).unwrap(), 3);
    assert_eq!(cbuf[1], 0x00);
}

#[test]
fn bdb_zdo_mgmt_leave_codec() {
    let req = MgmtLeaveReq {
        tsn: 0x06,
        device_ieee: 0xDEAD_BEEF_CAFE_1234,
        rejoin: true,
        remove_children: false,
    };
    let mut buf = [0u8; 16];
    let n = req.encode_into(&mut buf).unwrap();
    assert_eq!(MgmtLeaveReq::decode(&buf[..n]).unwrap(), req);
}

#[test]
fn bdb_zdo_mgmt_lqi_and_disc_codecs() {
    let lqi = MgmtLqiReq {
        tsn: 0x07,
        start_index: 0,
    };
    assert_eq!(MgmtLqiReq::LEN, 2);
    let mut lbuf = [0u8; 4];
    assert_eq!(lqi.encode_into(&mut lbuf).unwrap(), 2);
    assert_eq!(MgmtLqiReq::decode(&lbuf[..2]).unwrap(), lqi);

    let disc = MgmtNwkDiscReq {
        tsn: 0x08,
        scan_channels: 0x07FF_F800,
        scan_duration: 3,
        start_index: 0,
    };
    assert_eq!(MgmtNwkDiscReq::LEN, 7);
    let mut dbuf = [0u8; 8];
    assert_eq!(disc.encode_into(&mut dbuf).unwrap(), 7);
    assert_eq!(MgmtNwkDiscReq::decode(&dbuf[..7]).unwrap(), disc);
}

// ---------------------------------------------------------------------------
// Transaction correlator (§2.4.4 response/TSN rule)
// ---------------------------------------------------------------------------

#[test]
fn bdb_zdo_pending_table_open_close() {
    let mut table = PendingTable::<4>::new();
    assert!(table.is_empty());
    table.open(CLUSTER_NODE_DESC_REQ, 0x07).unwrap();
    assert_eq!(table.len(), 1);
    assert_eq!(
        table.open(CLUSTER_NODE_DESC_REQ, 0x07).unwrap_err(),
        TxnError::Duplicate
    );
    // The announce carries no response: never opened.
    assert_eq!(
        table.open(CLUSTER_DEVICE_ANNCE, 0x08).unwrap_err(),
        TxnError::NoResponse
    );
    assert_eq!(
        table.close(CLUSTER_NODE_DESC_REQ | RESPONSE_BIT, 0x09),
        None
    );
    assert_eq!(
        table.close(CLUSTER_NODE_DESC_REQ | RESPONSE_BIT, 0x07),
        Some(CLUSTER_NODE_DESC_REQ)
    );
    assert!(table.is_empty());
}

#[test]
fn bdb_zdo_pending_table_full_refuses() {
    let mut table = PendingTable::<2>::new();
    table.open(CLUSTER_NODE_DESC_REQ, 0x01).unwrap();
    table.open(CLUSTER_SIMPLE_DESC_REQ, 0x01).unwrap();
    assert_eq!(
        table.open(CLUSTER_MATCH_DESC_REQ, 0x01).unwrap_err(),
        TxnError::TableFull
    );
}

// Status codes are frozen on the wire.
#[test]
fn bdb_zdo_status_codes_frozen() {
    assert_eq!(ZdpStatus::from_code(0x00), ZdpStatus::Success);
    assert_eq!(ZdpStatus::from_code(0x81), ZdpStatus::DeviceNotFound);
    assert_eq!(ZdpStatus::from_code(0x82), ZdpStatus::InvalidEp);
    assert_eq!(ZdpStatus::from_code(0x8A), ZdpStatus::NoTableSpace);
    assert!(ZdpStatus::Success.is_success());
    assert!(!ZdpStatus::DeviceNotFound.is_success());
}
