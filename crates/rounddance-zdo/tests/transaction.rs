//! ZDP transaction correlation: open/close by TSN + cluster for
//! Match_Desc, Bind, and Mgmt_Lqi, plus the Mgmt_Lqi wire round trip.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `05-3474-23-24401-01` (correlation), `05-3474-23-24332-01/02`
//! (Mgmt_Lqi pair), `05-3474-23-24311-07` + `05-3474-23-24427-01`
//! (Match_Desc), `05-3474-23-24322-01` + `05-3474-23-24432-01`
//! (Bind/Unbind).

use rounddance_zdo::{
    response_cluster, transaction_expected, BindDstMode, BindEntry, BindRsp, MatchDescReq,
    MatchDescRsp, MgmtLqiReq, MgmtLqiRsp, NeighborEntry, PendingTable, TxnError, ZdpStatus,
    CLUSTER_BIND_REQ, CLUSTER_DEVICE_ANNCE, CLUSTER_MATCH_DESC_REQ, CLUSTER_MGMT_LQI_REQ,
    CLUSTER_UNBIND_REQ, MAX_NEIGHBORS, RESPONSE_BIT,
};

// 05-3474-23-24401-01: Match_Desc opens on the request cluster + TSN
// and closes on the response cluster + echoed TSN.
#[test]
fn match_desc_correlates_by_tsn_and_cluster() {
    let mut table = PendingTable::<4>::new();
    assert!(table.is_empty());
    table.open(CLUSTER_MATCH_DESC_REQ, 0x33).unwrap();
    assert_eq!(table.len(), 1);
    // Wrong TSN never correlates.
    assert_eq!(
        table.close(CLUSTER_MATCH_DESC_REQ | RESPONSE_BIT, 0x34),
        None
    );
    // Bare request cluster (no response bit) never correlates.
    assert_eq!(table.close(CLUSTER_MATCH_DESC_REQ, 0x33), None);
    // Echoed response closes and names the request cluster.
    assert_eq!(
        table.close(CLUSTER_MATCH_DESC_REQ | RESPONSE_BIT, 0x33),
        Some(CLUSTER_MATCH_DESC_REQ)
    );
    assert!(table.is_empty());
    // Already closed: a replayed response stays uncorrelated.
    assert_eq!(
        table.close(CLUSTER_MATCH_DESC_REQ | RESPONSE_BIT, 0x33),
        None
    );
}

// 05-3474-23-24401-01: Bind and Unbind share one response shape, so
// the table tells the two transactions apart by cluster.
#[test]
fn bind_and_unbind_stay_distinct() {
    let mut table = PendingTable::<4>::new();
    table.open(CLUSTER_BIND_REQ, 0x41).unwrap();
    table.open(CLUSTER_UNBIND_REQ, 0x41).unwrap();
    assert_eq!(
        table.close(CLUSTER_UNBIND_REQ | RESPONSE_BIT, 0x41),
        Some(CLUSTER_UNBIND_REQ)
    );
    assert_eq!(
        table.close(CLUSTER_BIND_REQ | RESPONSE_BIT, 0x41),
        Some(CLUSTER_BIND_REQ)
    );
    assert!(table.is_empty());
}

// 05-3474-23-24401-01: the response-less announce never opens; a full
// table and a duplicate refuse instead of aliasing or growing.
#[test]
fn announce_never_opens_and_table_bounds_hold() {
    let mut table = PendingTable::<1>::new();
    assert_eq!(
        table.open(CLUSTER_DEVICE_ANNCE, 0x01),
        Err(TxnError::NoResponse)
    );
    assert!(!transaction_expected(CLUSTER_DEVICE_ANNCE));
    assert!(transaction_expected(CLUSTER_MGMT_LQI_REQ));
    table.open(CLUSTER_MGMT_LQI_REQ, 0x07).unwrap();
    assert_eq!(
        table.open(CLUSTER_MGMT_LQI_REQ, 0x07),
        Err(TxnError::Duplicate)
    );
    assert_eq!(
        table.open(CLUSTER_MGMT_LQI_REQ, 0x08),
        Err(TxnError::TableFull)
    );
    // Unknown response clusters never correlate either.
    assert_eq!(table.close(0x80ff, 0x07), None);
    assert_eq!(
        table.close(CLUSTER_MGMT_LQI_REQ | RESPONSE_BIT, 0x07),
        Some(CLUSTER_MGMT_LQI_REQ)
    );
}

// 05-3474-23-24311-07 + 05-3474-23-24427-01: Match_Desc pair round
// trip with a real endpoint list.
#[test]
fn match_desc_pair_round_trip() {
    let req = MatchDescReq {
        tsn: 0x55,
        nwk_of_interest: 0xfffd,
        profile_id: 0x0104,
        in_clusters: {
            let mut a = [0u16; 16];
            a[0] = 0x0006;
            a
        },
        in_len: 1,
        out_clusters: [0u16; 16],
        out_len: 0,
    };
    let mut buf = [0u8; 32];
    let n = req.encode_into(&mut buf).unwrap();
    let seen = MatchDescReq::decode(&buf[..n]).unwrap();
    assert_eq!(seen, req);

    let rsp = MatchDescRsp {
        tsn: seen.tsn,
        status: ZdpStatus::Success,
        nwk_of_interest: seen.nwk_of_interest,
        endpoints: {
            let mut a = [0u8; 32];
            a[0] = 0x01;
            a
        },
        ep_len: 1,
    };
    let mut rbuf = [0u8; 40];
    let rn = rsp.encode_into(&mut rbuf).unwrap();
    let seen_rsp = MatchDescRsp::decode(&rbuf[..rn]).unwrap();
    assert_eq!(seen_rsp, rsp);
    assert_eq!(seen_rsp.ep_list(), &[0x01]);
    assert_eq!(
        response_cluster(CLUSTER_MATCH_DESC_REQ),
        Some(CLUSTER_MATCH_DESC_REQ | RESPONSE_BIT)
    );
}

// 05-3474-23-24322-01 + 05-3474-23-24432-01: Bind pair round trip,
// group and extended flavours.
#[test]
fn bind_pair_round_trip() {
    for dst in [
        BindDstMode::Group { group_addr: 0x1234 },
        BindDstMode::Extended {
            dst_ieee: 0x1122_3344_5566_7788,
            dst_endpoint: 0x01,
        },
    ] {
        let entry = BindEntry {
            tsn: 0x61,
            src_ieee: 0xaabb_ccdd_eeff_0011,
            src_endpoint: 0x01,
            cluster_id: 0x0006,
            dst,
        };
        let mut buf = [0u8; 32];
        let n = entry.encode_into(&mut buf).unwrap();
        assert_eq!(BindEntry::decode(&buf[..n]).unwrap(), entry);
    }
    let rsp = BindRsp {
        tsn: 0x61,
        status: ZdpStatus::Success,
    };
    let mut rbuf = [0u8; 4];
    let rn = rsp.encode_into(&mut rbuf).unwrap();
    assert_eq!(BindRsp::decode(&rbuf[..rn]).unwrap(), rsp);
}

// 05-3474-23-24332-01/02: Mgmt_Lqi pair round trip with one neighbor
// entry; reserved flag bits and over-long pages are refused.
#[test]
fn mgmt_lqi_pair_round_trip() {
    let req = MgmtLqiReq {
        tsn: 0x71,
        start_index: 0,
    };
    let mut buf = [0u8; 4];
    let n = req.encode_into(&mut buf).unwrap();
    assert_eq!(MgmtLqiReq::decode(&buf[..n]).unwrap(), req);

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
        ext_pan: 0x0102_0304_0506_0708,
        ieee: 0x1111_2222_3333_4444,
        nwk: 0x0002,
        device_type: 1,
        rx_on_idle: true,
        relationship: 1,
        depth: 1,
        lqi: 200,
    };
    entries[1] = NeighborEntry {
        ext_pan: 0x0102_0304_0506_0708,
        ieee: 0x5555_6666_7777_8888,
        nwk: 0x0003,
        device_type: 2,
        rx_on_idle: false,
        relationship: 0,
        depth: 2,
        lqi: 150,
    };
    let rsp = MgmtLqiRsp {
        tsn: 0x71,
        status: ZdpStatus::Success,
        neighbor_count: 2,
        start_index: 0,
        entries,
        entry_len: 2,
    };
    let mut rbuf = [0u8; 64];
    let rn = rsp.encode_into(&mut rbuf).unwrap();
    assert_eq!(rn, MgmtLqiRsp::MIN_LEN + 2 * NeighborEntry::LEN);
    let seen = MgmtLqiRsp::decode(&rbuf[..rn]).unwrap();
    assert_eq!(seen, rsp);
    assert_eq!(seen.entry_list().len(), 2);
    assert_eq!(seen.entry_list()[0].lqi, 200);
    assert_eq!(
        response_cluster(CLUSTER_MGMT_LQI_REQ),
        Some(CLUSTER_MGMT_LQI_REQ | RESPONSE_BIT)
    );

    // Reserved flag bits set: refused.
    let mut bad = [0u8; NeighborEntry::LEN];
    NeighborEntry::decode(&bad).unwrap();
    bad[18] = 0xc0;
    assert!(NeighborEntry::decode(&bad).is_err());
    // Over-long page: refused.
    let mut over = [0u8; 8];
    over[0] = 0x71;
    over[1] = 0x00;
    over[2] = 0x09;
    over[3] = 0x00;
    over[4] = MAX_NEIGHBORS as u8 + 1;
    assert!(MgmtLqiRsp::decode(&over).is_err());
    // Non-success response carries no entries.
    let fail = MgmtLqiRsp {
        status: ZdpStatus::DeviceNotFound,
        entry_len: 0,
        ..rsp
    };
    let mut fbuf = [0u8; 8];
    let fn_ = fail.encode_into(&mut fbuf).unwrap();
    assert_eq!(fn_, MgmtLqiRsp::MIN_LEN);
    let seen_fail = MgmtLqiRsp::decode(&fbuf[..fn_]).unwrap();
    assert!(!seen_fail.status.is_success());
    assert!(seen_fail.entry_list().is_empty());
}
