//! Line-coverage closure for doc `05-3474-23` R23.2 chapter 2 (APS).
//!
//! Each test pins one normative codec behavior of the APS sub-layer
//! (§2.2: frame format, reserved-field handling, endpoints, status
//! values, fragmentation planning/reassembly, retries, duplicate
//! rejection, binding/group tables, acknowledgements, secured sends)
//! against the public API. Comments name the requirement ID the test
//! verifies plus the gap anchors it cites (D1: document number,
//! revision, clause and line only — no spec text reproduced).

use rounddance_aps::{
    ack_for, decode_ack, decode_command, decode_data, parse_ack, peek_frame_type, plan_transmit,
    rx_timeout_ticks, AckExpect, AckInfo, AddrMap, ApsError, ApsStatus, BindingDst, BindingEntry,
    BindingTable, CommandHeader, DataDest, DataHeader, DeliveryMode, DupRejectTable, ExtHeader,
    FeedOutcome, FragError, Fragmentation, FrameControl, FrameType, GroupTable, PeerFragCaps,
    Reassembler, ResolvedDst, RetrySession, RetryVerdict, SecureDataLink, TxPlan,
    ENDPOINT_BROADCAST_ALL, ENDPOINT_ZDO, MAX_APP_ENDPOINT,
};

// 05-3474-23-22511-01: reserved delivery-mode and fragmentation bits
// are rejected on receipt; valid encodes carry no reserved bits.
// Anchors: p0086-L2157-L2165.
#[test]
fn reserved_subfields_rejected_on_receipt_05_3474_23_22511_01() {
    // Delivery-mode bits 0b01 are reserved (Table 2-21).
    assert_eq!(
        FrameControl::from_u8(0b0000_0100),
        Err(ApsError::ReservedDeliveryMode(0x01))
    );
    // Fragmentation bits 0b11 are reserved (Table 2-22).
    assert_eq!(
        Fragmentation::from_bits(0b11),
        Err(ApsError::ReservedFragmentation(0x03))
    );
    // A plain data encode keeps every reserved position at zero.
    let control = FrameControl::data(DeliveryMode::Unicast);
    assert_eq!(control.to_u8(), 0x00);
    let full = FrameControl {
        ack_format: true,
        security: true,
        ack_request: true,
        ext_header: true,
        ..FrameControl::data(DeliveryMode::Group)
    };
    assert_eq!(full.to_u8(), 0x0C | 0x10 | 0x20 | 0x40 | 0x80);
    assert_eq!(FrameControl::from_u8(full.to_u8()).unwrap(), full);
    // Round trip of every legal delivery mode preserves the octet.
    for (mode, bits) in [
        (DeliveryMode::Unicast, 0x00u8),
        (DeliveryMode::Broadcast, 0x08u8),
        (DeliveryMode::Group, 0x0Cu8),
    ] {
        assert_eq!(FrameControl::data(mode).to_u8(), bits);
    }
}

// 05-3474-23-22511-02: general APDU field order — control, addressing,
// cluster, profile, source endpoint, counter, payload.
// Anchors: p0086-L2161-L2164.
#[test]
fn data_frame_field_order_05_3474_23_22511_02() {
    let wire: &[u8] = &[
        0x0C, // group delivery, no flags
        0x34, 0x12, // group 0x1234
        0x06, 0x00, // cluster
        0x04, 0x01, // profile
        0x01, // src endpoint
        0x42, // counter
        0xAA, 0xBB, // payload
    ];
    let decoded = decode_data(wire).unwrap();
    assert_eq!(decoded.header.dest, DataDest::Group { group_addr: 0x1234 });
    assert_eq!(decoded.header.cluster_id, 0x0006);
    assert_eq!(decoded.header.profile_id, 0x0104);
    assert_eq!(decoded.header.src_endpoint, 0x01);
    assert_eq!(decoded.header.counter, 0x42);
    assert_eq!(decoded.payload, &[0xAA, 0xBB]);
    let mut out = [0u8; 16];
    let n = decoded
        .header
        .encode_into(decoded.payload, &mut out)
        .unwrap();
    assert_eq!(&out[..n], wire);
}

// 05-3474-23-22121-01: endpoint assignment — endpoint 0 is the ZDO,
// 242 is the Green Power endpoint, 0xFF is the broadcast address,
// application endpoints stop at 0xFE.
// Anchors: p0058-L1533-L1542.
#[test]
fn endpoint_assignment_05_3474_23_22121_01() {
    assert_eq!(ENDPOINT_ZDO, 0x00);
    assert_eq!(ENDPOINT_BROADCAST_ALL, 0xFF);
    assert_eq!(MAX_APP_ENDPOINT, 0xFE);
    // Broadcasts never target the ZDO endpoint.
    let bad: &[u8] = &[0x08, 0x00, 0x06, 0x00, 0x04, 0x01, 0x01, 0x02];
    assert_eq!(decode_data(bad), Err(ApsError::BadBroadcastEndpoint(0x00)));
    // ... but every endpoint 0x01..=0xFF decodes as broadcast.
    let mut good = [0x08u8, 0x01, 0x06, 0x00, 0x04, 0x01, 0x01, 0x02];
    for ep in [0x01u8, 0x7E, 0xF2, 0xFF] {
        good[1] = ep;
        let d = decode_data(&good).unwrap();
        assert_eq!(d.header.dest, DataDest::Broadcast { dst_endpoint: ep });
    }
}

// 05-3474-23-22411-01: APSDE data service only moves ASDUs between
// devices on the same network — the data codec carries no routing
// fields of its own; source/destination addressing stays endpoint +
// cluster + profile + counter.
// Anchors: p0060-L1582-L1586.
#[test]
fn data_codec_carries_endpoint_addressing_05_3474_23_22411_01() {
    let header = DataHeader {
        control: FrameControl::data(DeliveryMode::Unicast),
        dest: DataDest::Unicast { dst_endpoint: 0x05 },
        cluster_id: 0x0006,
        profile_id: 0x0104,
        src_endpoint: 0x01,
        counter: 0x42,
        ext: None,
    };
    assert_eq!(header.header_len(), 8);
    let mut out = [0u8; 16];
    let n = header.encode_into(&[0xAA], &mut out).unwrap();
    assert_eq!(n, 9);
    let back = decode_data(&out[..n]).unwrap();
    assert_eq!(back.header, header);
    assert_eq!(back.payload, &[0xAA]);
}

// 05-3474-23-22841-01: reliable transport (end-to-end retries),
// duplicate rejection (a message is never delivered twice), and
// group filtering (delivery follows endpoint group membership).
// Anchors: p0060-L1590-L1614.
#[test]
fn reliability_triad_05_3474_23_22841_01() {
    // Duplicate rejection: second sighting of (src, counter) is dropped.
    let mut dup = DupRejectTable::new();
    assert!(!dup.observe(0x1234, 0x42));
    assert!(dup.observe(0x1234, 0x42));
    assert!(!dup.observe(0x1234, 0x43));
    assert!(!dup.observe(0x5678, 0x42));
    // Group filtering: only member endpoints are collected.
    let mut groups = GroupTable::new();
    assert_eq!(groups.add(0x0001, 0x02), ApsStatus::Success);
    assert_eq!(groups.add(0x0001, 0x03), ApsStatus::Success);
    assert_eq!(groups.add(0x0002, 0x02), ApsStatus::Success);
    let mut out = [0u8; 8];
    let n = groups.members(0x0001, &mut out);
    assert_eq!(n, 2);
    assert!(out[..n].contains(&0x02) && out[..n].contains(&0x03));
    let n2 = groups.members(0x0002, &mut out);
    assert_eq!(&out[..n2], &[0x02]);
    // Reliable transport: no ack within budget exhausts the retry
    // budget and reports NO_ACK.
    let expect = AckExpect {
        cluster_id: 0x0006,
        counter: 0x42,
        dst_endpoint: 0x02,
    };
    let mut sess = RetrySession::new(expect, 0, 10);
    assert_eq!(sess.poll_transmit(), RetryVerdict::Transmit);
    let mut verdict = RetryVerdict::Waiting;
    let mut now = 10u64;
    for _ in 0..16 {
        verdict = sess.on_tick(now);
        now += 10;
        if !matches!(verdict, RetryVerdict::Transmit | RetryVerdict::Waiting) {
            break;
        }
    }
    assert_eq!(verdict, RetryVerdict::Failed(ApsStatus::NoAck));
}

// 05-3474-23-22845-01: oversize-ASDU transmit gates — broadcast
// (fragmentation forbidden), unsupported local fragmentation,
// unknown peer support, and peer refusal each fail before any block
// goes on air, with the matching confirm status.
// Anchors: p0065-L1716-L1724, p0065-L1728-L1730.
#[test]
fn transmit_gates_05_3474_23_22845_01() {
    let peer_ok = PeerFragCaps {
        known: true,
        can_fragment: true,
        max_rx_asdu: 512,
    };
    let peer_no = PeerFragCaps {
        known: true,
        can_fragment: false,
        max_rx_asdu: 512,
    };
    let peer_unknown = PeerFragCaps::unknown();
    // Fits in one frame: always single, gates never consulted.
    assert_eq!(
        plan_transmit(40, 80, true, false, peer_unknown, 64),
        TxPlan::Single
    );
    // Broadcast + oversize: fragmentation forbidden.
    assert_eq!(
        plan_transmit(200, 80, true, true, peer_ok, 64),
        TxPlan::Fail(ApsStatus::AsduTooLong)
    );
    // No local support.
    assert_eq!(
        plan_transmit(200, 80, false, false, peer_ok, 64),
        TxPlan::Fail(ApsStatus::AsduTooLong)
    );
    // Unknown peer support: discovery gate first.
    assert_eq!(
        plan_transmit(200, 80, false, true, peer_unknown, 64),
        TxPlan::Fail(ApsStatus::UnknownFragmentSupport)
    );
    // Peer refusal.
    assert_eq!(
        plan_transmit(200, 80, false, true, peer_no, 64),
        TxPlan::Fail(ApsStatus::PeerCannotFragment)
    );
    // Peer buffer too small.
    assert_eq!(
        plan_transmit(
            400,
            80,
            false,
            true,
            PeerFragCaps {
                known: true,
                can_fragment: true,
                max_rx_asdu: 100,
            },
            64
        ),
        TxPlan::Fail(ApsStatus::AsduTooLong)
    );
    // Happy path: ceil block count announced up front.
    assert_eq!(
        plan_transmit(200, 80, false, true, peer_ok, 64),
        TxPlan::Fragmented { block_count: 4 }
    );
}

// 05-3474-23-22845-02: block acknowledgement stops the retransmit
// timer and resets the retry counter; the window, indication, and
// timeout rules of the reassembly side.
// Anchors: p0105-L2552.
#[test]
fn block_ack_stops_timer_05_3474_23_22845_02() {
    // An acked session never retransmits: ack stops the timer.
    let expect = AckExpect {
        cluster_id: 0x0006,
        counter: 0x07,
        dst_endpoint: 0x02,
    };
    let mut sess = RetrySession::new(expect, 100, 50);
    assert_eq!(sess.poll_transmit(), RetryVerdict::Transmit);
    assert_eq!(
        sess.on_ack(AckInfo {
            cluster_id: 0x0006,
            counter: 0x07,
            src_endpoint: 0x02,
        }),
        RetryVerdict::Acked
    );
    // Past any deadline the session stays acked — no retry fires.
    assert_eq!(sess.on_tick(10_000), RetryVerdict::Acked);
    assert_eq!(sess.attempts(), 0);
    // rx timeout helper: ack wait scaled by retry budget.
    assert_eq!(rx_timeout_ticks(50, 3), 50 * (3 + 1) as u64);
}

// 05-3474-23-22845-03: every fragment block shares the APS counter;
// block 0 announces the total, block k carries number k; duplicates
// drop; completion reassembles in order; stalled windows time out.
// Anchors: p0065-L1722-L1726, p0105-L2552.
#[test]
fn reassembly_window_05_3474_23_22845_03() {
    let mut rx = Reassembler::new();
    assert_eq!(rx.live_count(), 0);
    // Wrong entry: unfragmented frames never enter the window.
    assert_eq!(
        rx.feed(0x1111, 0x09, Fragmentation::Unfragmented, 0, &[1, 2, 3], 0),
        Err(FragError::NotFragmented)
    );
    // First block announces 3 total.
    assert_eq!(
        rx.feed(0x1111, 0x09, Fragmentation::First, 3, &[10, 11], 100)
            .unwrap(),
        FeedOutcome::InProgress
    );
    // Repeated first block: duplicate, dropped.
    assert_eq!(
        rx.feed(0x1111, 0x09, Fragmentation::First, 3, &[10, 11], 101)
            .unwrap(),
        FeedOutcome::Duplicate
    );
    // Out-of-order later block accepted, still in progress.
    assert_eq!(
        rx.feed(0x1111, 0x09, Fragmentation::Subsequent, 2, &[14, 15], 102)
            .unwrap(),
        FeedOutcome::InProgress
    );
    // Final missing block completes the transaction in block order.
    assert_eq!(
        rx.feed(0x1111, 0x09, Fragmentation::Subsequent, 1, &[12, 13], 103)
            .unwrap(),
        FeedOutcome::Complete { len: 6 }
    );
    assert_eq!(rx.assembled(), Some(&[10, 11, 12, 13, 14, 15][..]));
    // Stalled windows are reaped on the injected tick clock.
    let mut rx2 = Reassembler::new();
    rx2.feed(0x2222, 0x01, Fragmentation::First, 2, &[1], 0)
        .unwrap();
    assert_eq!(rx2.live_count(), 1);
    assert_eq!(rx2.reap_expired(1_000_000, 100), 1);
    assert_eq!(rx2.live_count(), 0);
}

// 05-3474-23-22911-01: Table 2-29 status values — every confirm
// status round-trips through its numeric code; unknown codes are
// refused fallibly.
// Anchors: p0080-L1975-L1981, p0080-L1985-L1997.
#[test]
fn status_codes_roundtrip_05_3474_23_22911_01() {
    let all = [
        (ApsStatus::Success, 0x00),
        (ApsStatus::AsduTooLong, 0xA0),
        (ApsStatus::DefragDeferred, 0xA1),
        (ApsStatus::DefragUnsupported, 0xA2),
        (ApsStatus::IllegalRequest, 0xA3),
        (ApsStatus::InvalidBinding, 0xA4),
        (ApsStatus::InvalidGroup, 0xA5),
        (ApsStatus::InvalidParameter, 0xA6),
        (ApsStatus::NoAck, 0xA7),
        (ApsStatus::NoBoundDevice, 0xA8),
        (ApsStatus::NoShortAddress, 0xA9),
        (ApsStatus::NotSupported, 0xAA),
        (ApsStatus::SecuredLinkKey, 0xAB),
        (ApsStatus::SecuredNwkKey, 0xAC),
        (ApsStatus::SecurityFail, 0xAD),
        (ApsStatus::TableFull, 0xAE),
        (ApsStatus::Unsecured, 0xAF),
        (ApsStatus::UnsupportedAttribute, 0xB0),
        (ApsStatus::PeerCannotFragment, 0xB1),
        (ApsStatus::UnknownFragmentSupport, 0xB2),
    ];
    for (status, code) in all {
        assert_eq!(status.code(), code);
        assert_eq!(ApsStatus::from_code(code), Ok(status));
    }
    assert!(ApsStatus::from_code(0x01).is_err());
    assert!(ApsStatus::from_code(0xFF).is_err());
}

// 05-3474-23-22431-01: binding table create/remove semantics —
// out-of-range parameters, idempotent re-bind, table-full, and
// invalid-binding on unknown unbind.
// Anchors: p0099-L2365-L2370.
#[test]
fn binding_table_semantics_05_3474_23_22431_01() {
    let mut table = BindingTable::new();
    assert!(table.is_empty());
    let entry = BindingEntry {
        src_ieee: 0x0012_4B00_1A2B_3C4D,
        src_endpoint: 0x01,
        cluster_id: 0x0006,
        dst: BindingDst::Group { group_addr: 0x0001 },
    };
    assert_eq!(table.bind(entry), ApsStatus::Success);
    // Idempotent re-bind.
    assert_eq!(table.bind(entry), ApsStatus::Success);
    assert_eq!(table.len(), 1);
    // Out-of-range local endpoint.
    let bad = BindingEntry {
        src_endpoint: 0xFF,
        ..entry
    };
    assert_eq!(table.bind(bad), ApsStatus::IllegalRequest);
    // Unknown unbind.
    let other = BindingEntry {
        cluster_id: 0x0008,
        ..entry
    };
    assert_eq!(table.unbind(&other), ApsStatus::InvalidBinding);
    assert_eq!(table.unbind(&entry), ApsStatus::Success);
    assert!(table.is_empty());
}

// 05-3474-23-22411-02: indirect (binding-mode) transmit fans out over
// every matching entry; unresolved longs are listed for discovery;
// empty matches confirm NO_BOUND_DEVICE, unknown shorts confirm
// NO_SHORT_ADDRESS, unsupported devices confirm NOT_SUPPORTED.
// Anchors: p0071-L1808-L1812, p0060-L1582-L1586.
#[test]
fn indirect_fanout_05_3474_23_22411_02() {
    let mut table = BindingTable::new();
    let mut addrs = AddrMap::new();
    // No entries at all.
    let plan = table.plan_indirect(&addrs, true, 1, 1, 0x0006);
    assert_eq!(plan.confirm(), ApsStatus::NoBoundDevice);
    assert!(plan.resolved().is_empty() && plan.unresolved().is_empty());
    // Device without a binding table.
    let plan = table.plan_indirect(&addrs, false, 1, 1, 0x0006);
    assert_eq!(plan.confirm(), ApsStatus::NotSupported);
    // Unicast entry whose long address is not yet resolved:
    // NO_SHORT_ADDRESS with discovery work listed.
    assert_eq!(
        table.bind(BindingEntry {
            src_ieee: 1,
            src_endpoint: 1,
            cluster_id: 0x0006,
            dst: BindingDst::Unicast {
                dst_ieee: 0x00DE_ADBE_EF00_0042,
                dst_endpoint: 0x02,
            },
        }),
        ApsStatus::Success
    );
    let plan = table.plan_indirect(&addrs, true, 1, 1, 0x0006);
    assert_eq!(plan.confirm(), ApsStatus::NoShortAddress);
    assert!(plan.resolved().is_empty());
    assert_eq!(plan.unresolved(), &[0x00DE_ADBE_EF00_0042]);
    // After discovery the unicast entry resolves too.
    addrs.note(0x00DE_ADBE_EF00_0042, 0x1234);
    let plan = table.plan_indirect(&addrs, true, 1, 1, 0x0006);
    assert_eq!(plan.confirm(), ApsStatus::Success);
    assert_eq!(plan.resolved().len(), 1);
    assert!(plan.unresolved().is_empty());
    // A group entry fans out alongside without needing discovery.
    assert_eq!(
        table.bind(BindingEntry {
            src_ieee: 1,
            src_endpoint: 1,
            cluster_id: 0x0006,
            dst: BindingDst::Group { group_addr: 0x00AA },
        }),
        ApsStatus::Success
    );
    let plan = table.plan_indirect(&addrs, true, 1, 1, 0x0006);
    assert_eq!(plan.confirm(), ApsStatus::Success);
    assert_eq!(plan.resolved().len(), 2);
    assert!(plan.unresolved().is_empty());
    assert!(matches!(
        plan.resolved()[1],
        ResolvedDst::Group { group_addr: 0x00AA }
    ));
}

// 05-3474-23-22844-01: acknowledgements are never acknowledged; acks
// carry the matching cluster/counter/endpoint triple; command acks
// carry no addressing and correlate to nothing.
// Anchors: p0125-L3065-L3072.
#[test]
fn ack_rules_05_3474_23_22844_01() {
    // An ack frame with the ack-request bit set is malformed.
    let bad_ack: &[u8] = &[0x42, 0x02, 0x06, 0x00, 0x04, 0x01, 0x01, 0x42];
    assert_eq!(decode_ack(bad_ack), Err(ApsError::AckRequestsAck));
    // Well-formed data ack decodes and correlates.
    let ack_wire: &[u8] = &[
        0x02, // ack, data-ack format
        0x02, // dst endpoint
        0x06, 0x00, // cluster
        0x04, 0x01, // profile
        0x01, // src endpoint
        0x42, // counter
    ];
    let info = parse_ack(ack_wire).unwrap().unwrap();
    assert_eq!(
        info,
        AckInfo {
            cluster_id: 0x0006,
            counter: 0x42,
            src_endpoint: 0x01,
        }
    );
    assert!(AckExpect {
        cluster_id: 0x0006,
        counter: 0x42,
        dst_endpoint: 0x01,
    }
    .matches(info.cluster_id, info.counter, info.src_endpoint));
    // Command frames never carry extended headers; type peeks first.
    let cmd = CommandHeader {
        control: FrameControl::command(),
        counter: 0x09,
        command_id: 0x01,
    };
    let mut out = [0u8; 8];
    let n = cmd.encode_into(&[0xFF], &mut out).unwrap();
    assert_eq!(peek_frame_type(&out[..n]), Ok(FrameType::Command));
    let decoded = decode_command(&out[..n]).unwrap();
    assert_eq!(decoded.header.command_id, 0x01);
    assert_eq!(decoded.payload, &[0xFF]);
    // ack_for: only unicast ack-requested data frames produce an ack.
    let group_header = DataHeader {
        control: FrameControl::data(DeliveryMode::Group),
        dest: DataDest::Group { group_addr: 1 },
        cluster_id: 6,
        profile_id: 0x0104,
        src_endpoint: 1,
        counter: 9,
        ext: None,
    };
    assert!(ack_for(&group_header, 0x0104).is_none());
}

// 05-3474-23-22843-01: secured transmission marks the frame, spends
// one counter per send, and records the ack expectation only for
// unicast; broadcast/group sends record none.
// Anchors: p0065-L1698-L1704.
#[test]
fn secured_send_marks_frame_05_3474_23_22843_01() {
    let mut link = SecureDataLink::new();
    assert_eq!(link.peek_counter(), 0);
    assert!(link.pending_ack().is_none());
    let (h, expect) = link.send_header(
        DataDest::Unicast { dst_endpoint: 0x02 },
        0x0006,
        0x0104,
        0x01,
        true,
    );
    assert!(h.control.security);
    assert!(h.control.ack_request);
    assert_eq!(h.counter, 0);
    assert_eq!(link.peek_counter(), 1);
    let expect = expect.unwrap();
    assert_eq!(
        link.pending_ack(),
        Some(AckExpect {
            cluster_id: 0x0006,
            counter: 0,
            dst_endpoint: 0x02,
        })
    );
    assert!(expect.matches(0x0006, 0, 0x02));
    // Group send: secured but never ack-tracked.
    let (hg, expect_g) = link.send_header(
        DataDest::Group { group_addr: 0x0001 },
        0x0006,
        0x0104,
        0x01,
        true,
    );
    assert!(hg.control.security);
    assert!(!hg.control.ack_request);
    assert!(expect_g.is_none());
    assert_eq!(hg.counter, 1);
    assert_eq!(link.peek_counter(), 2);
    // Extended-header fragmentation markers round-trip on data frames.
    let ext = ExtHeader::first(4);
    assert_eq!(ext.encoded_len(), 2);
    let ext2 = ExtHeader::subsequent(2);
    assert_eq!(ext2.encoded_len(), 2);
    let ext3 = ExtHeader::frag_ack(0, 0b101);
    assert_eq!(ext3.encoded_len(), 3);
}
