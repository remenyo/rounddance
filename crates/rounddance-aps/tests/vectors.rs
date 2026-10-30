//! Wire-byte spec vectors for the APS APDU frame.
//!
//! Each test names the requirement ID it verifies. Byte strings below
//! are hand-computed from the paraphrased layouts in doc `05-3474-23`
//! R23.2 §2.2.5 (Figs. 2-4–2-9, Tables 2-20–2-22) and the Table 2-29
//! status values — never copied from spec text (D1, `SCOPE.md` §2).

use rounddance_aps::{
    decode_ack, decode_command, decode_data, peek_frame_type, plan_transmit, rx_timeout_ticks,
    AckAddr, AckExpect, AckHeader, AckInfo, AddrMap, ApsError, ApsStatus, BindingDst, BindingEntry,
    BindingTable, CommandHeader, DataDest, DataHeader, DeliveryMode, DupRejectTable, ExtHeader,
    FeedOutcome, FragError, Fragmentation, Fragmentation as Frag, FrameControl, FrameType,
    GroupTable, PeerFragCaps, Reassembler, ResolvedDst, RetrySession, RetryVerdict, TxBlocks,
    TxPlan, MAX_ADDR_MAP, MAX_BINDINGS, MAX_FRAME_RETRIES, MAX_GROUPS,
};

// 05-3474-23-22511-01/07/09/10/11/12/16: minimal unicast data frame.
//
// control = Data(00) | Unicast(00) | no flags = 0x00.
#[test]
fn vector_minimal_unicast_data_05_3474_23_22511_01() {
    let wire: &[u8] = &[
        0x00, // frame control
        0x05, // dst endpoint
        0x06, 0x00, // cluster 0x0006
        0x04, 0x01, // profile 0x0104
        0x01, // src endpoint
        0x42, // counter
        0xAA, // payload
    ];
    let decoded = decode_data(wire).unwrap();
    let h = decoded.header;
    assert_eq!(h.control.frame_type, FrameType::Data);
    assert_eq!(h.control.delivery_mode, DeliveryMode::Unicast);
    assert_eq!(h.dest, DataDest::Unicast { dst_endpoint: 0x05 });
    assert_eq!(h.cluster_id, 0x0006);
    assert_eq!(h.profile_id, 0x0104);
    assert_eq!(h.src_endpoint, 0x01);
    assert_eq!(h.counter, 0x42);
    assert_eq!(h.ext, None);
    assert_eq!(decoded.payload, &[0xAA]);

    let mut out = [0u8; 32];
    let n = h.encode_into(decoded.payload, &mut out).unwrap();
    assert_eq!(&out[..n], wire);
    assert_eq!(n, h.header_len() + 1);
}

// 05-3474-23-22511-03: broadcast delivery mode.
//
// control = Data(00) | Broadcast(10 << 2) = 0x08.
#[test]
fn vector_broadcast_data_05_3474_23_22511_03() {
    let wire: &[u8] = &[
        0x08, 0xFF, // control, all-active-endpoints
        0x06, 0x00, 0x04, 0x01, // cluster, profile
        0x02, 0x07, // src endpoint, counter
        0x01, 0x02, // payload
    ];
    let decoded = decode_data(wire).unwrap();
    assert_eq!(
        decoded.header.dest,
        DataDest::Broadcast { dst_endpoint: 0xFF }
    );
    let mut out = [0u8; 32];
    let n = decoded
        .header
        .encode_into(decoded.payload, &mut out)
        .unwrap();
    assert_eq!(&out[..n], wire);

    // Endpoint-directed broadcast (0x01-0xFE) also decodes.
    let mut directed = wire.to_vec();
    directed[1] = 0x0A;
    assert_eq!(
        decode_data(&directed).unwrap().header.dest,
        DataDest::Broadcast { dst_endpoint: 0x0A }
    );
    // Endpoint 0x00 is not a valid broadcast target.
    let mut bad = wire.to_vec();
    bad[1] = 0x00;
    assert_eq!(decode_data(&bad), Err(ApsError::BadBroadcastEndpoint(0x00)));
    let bad_header = DataHeader {
        dest: DataDest::Broadcast { dst_endpoint: 0x00 },
        ..decoded.header
    };
    assert_eq!(
        bad_header.encode_into(decoded.payload, &mut out),
        Err(ApsError::BadBroadcastEndpoint(0x00))
    );
}

// 05-3474-23-22511-08: group delivery — group address present,
// destination endpoint omitted.
//
// control = Data(00) | Group(11 << 2) = 0x0C.
#[test]
fn vector_group_data_05_3474_23_22511_08() {
    let wire: &[u8] = &[
        0x0C, // control
        0x34, 0x12, // group 0x1234
        0x08, 0x00, // cluster
        0x04, 0x01, // profile
        0x03, // src endpoint
        0x09, // counter
        0xDE, 0xAD, // payload
    ];
    let decoded = decode_data(wire).unwrap();
    assert_eq!(decoded.header.dest, DataDest::Group { group_addr: 0x1234 });
    assert_eq!(decoded.payload, &[0xDE, 0xAD]);
    let mut out = [0u8; 32];
    let n = decoded
        .header
        .encode_into(decoded.payload, &mut out)
        .unwrap();
    assert_eq!(&out[..n], wire);

    // Delivery-mode / addressing disagreement is rejected on encode.
    let mut mismatch = decoded.header;
    mismatch.control.delivery_mode = DeliveryMode::Unicast;
    assert_eq!(
        mismatch.encode_into(decoded.payload, &mut out),
        Err(ApsError::PresenceMismatch("delivery_mode"))
    );
}

// 05-3474-23-22511-13/14: first fragment — extended header present,
// block number announces the total.
//
// control = Data | Unicast | ext(1 << 7) = 0x80;
// ext = frag 01 (First), total 4.
#[test]
fn vector_first_fragment_ext_header_05_3474_23_22511_13() {
    let mut wire = vec![
        0x80, 0x05, // control, dst endpoint
        0x06, 0x00, 0x04, 0x01, // cluster, profile
        0x01, 0x10, // src endpoint, counter
        0x01, 0x04, // ext: First, total 4
    ];
    wire.extend([0x55u8; 32]);
    let decoded = decode_data(&wire).unwrap();
    assert_eq!(decoded.header.ext, Some(ExtHeader::first(4)));
    assert_eq!(decoded.payload, &[0x55u8; 32]);
    let mut out = [0u8; 64];
    let n = decoded
        .header
        .encode_into(decoded.payload, &mut out)
        .unwrap();
    assert_eq!(&out[..n], wire.as_slice());

    // ACK bitfield on a data frame is rejected on encode.
    let mut bad = decoded.header;
    bad.ext = Some(ExtHeader {
        frag: Frag::First,
        block_number: Some(4),
        ack_bitfield: Some(0xFF),
    });
    assert_eq!(
        bad.encode_into(decoded.payload, &mut out),
        Err(ApsError::PresenceMismatch("ack_bitfield"))
    );
}

// 05-3474-23-22511-17: command frame — control + counter + command id.
//
// control = Command(01) = 0x01.
#[test]
fn vector_command_frame_05_3474_23_22511_17() {
    let wire: &[u8] = &[0x01, 0x20, 0x05, 0x00, 0x01];
    let decoded = decode_command(wire).unwrap();
    assert_eq!(decoded.header.counter, 0x20);
    assert_eq!(decoded.header.command_id, 0x05);
    assert_eq!(decoded.payload, &[0x00, 0x01]);
    let mut out = [0u8; 16];
    let n = decoded
        .header
        .encode_into(decoded.payload, &mut out)
        .unwrap();
    assert_eq!(&out[..n], wire);
    assert_eq!(decoded.header.header_len(), 3);

    // Command frames never carry the extended header.
    let mut bad_control = FrameControl::command();
    bad_control.ext_header = true;
    let bad = CommandHeader {
        control: bad_control,
        counter: 0,
        command_id: 0,
    };
    assert_eq!(
        bad.encode_into(&[], &mut out),
        Err(ApsError::PresenceMismatch("ext_header"))
    );
    // A data frame is not a command frame.
    assert_eq!(
        decode_command(&[0x00, 0x20, 0x05]),
        Err(ApsError::FrameTypeMismatch {
            expected: FrameType::Command,
            found: FrameType::Data,
        })
    );
}

// 05-3474-23-22511-18: data acknowledgement — ACK-format clear, so the
// addressing fields stay present (endpoints swapped relative to the
// frame being acknowledged).
//
// control = Ack(10) = 0x02.
#[test]
fn vector_data_ack_05_3474_23_22511_18() {
    let wire: &[u8] = &[
        0x02, // control: Ack, ack-format clear
        0x01, // dst endpoint (= original src)
        0x06, 0x00, // cluster (copied)
        0x04, 0x01, // profile (copied)
        0x05, // src endpoint (= original dst)
        0x42, // counter (copied)
    ];
    let decoded = decode_ack(wire).unwrap();
    assert_eq!(
        decoded.header.addr,
        Some(AckAddr {
            dst_endpoint: 0x01,
            cluster_id: 0x0006,
            profile_id: 0x0104,
            src_endpoint: 0x05,
        })
    );
    assert_eq!(decoded.header.counter, 0x42);
    assert!(decoded.payload.is_empty());
    let mut out = [0u8; 16];
    let n = decoded.header.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);
}

// 05-3474-23-22511-18: command acknowledgement — ACK-format set, so the
// addressing fields are omitted.
//
// control = Ack(10) | ack-format(1 << 4) = 0x12.
#[test]
fn vector_command_ack_05_3474_23_22511_18() {
    let wire: &[u8] = &[0x12, 0x20];
    let decoded = decode_ack(wire).unwrap();
    assert_eq!(decoded.header.addr, None);
    assert_eq!(decoded.header.counter, 0x20);
    let mut out = [0u8; 8];
    let n = decoded.header.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);

    // ACK-format/addressing disagreement is rejected on encode.
    let mut bad = decoded.header;
    bad.addr = Some(AckAddr {
        dst_endpoint: 1,
        cluster_id: 2,
        profile_id: 3,
        src_endpoint: 4,
    });
    assert_eq!(
        bad.encode_into(&mut out),
        Err(ApsError::PresenceMismatch("ack_format"))
    );
    // Acknowledgements never request acknowledgements.
    let mut ar = FrameControl::ack_for_data();
    ar.ack_request = true;
    let ack_ar = AckHeader {
        control: ar,
        addr: None,
        counter: 0,
        ext: None,
    };
    assert_eq!(
        decode_ack(&[0x02 | 0x40, 0x42]),
        Err(ApsError::AckRequestsAck)
    );
    // Encode with consistent addressing but the request bit set.
    let ack_ar_consistent = AckHeader {
        addr: Some(AckAddr {
            dst_endpoint: 1,
            cluster_id: 2,
            profile_id: 3,
            src_endpoint: 4,
        }),
        ..ack_ar
    };
    assert_eq!(
        ack_ar_consistent.encode_into(&mut out),
        Err(ApsError::AckRequestsAck)
    );
}

// Fragmented acknowledgement: same counter, extended header with
// window base + received-blocks mask.
//
// control = Ack | ext = 0x82; ext = frag 01, base 0, mask 0x07.
#[test]
fn vector_fragmented_ack_bitfield_05_3474_23_22511_15() {
    let wire: &[u8] = &[
        0x82, 0x01, 0x06, 0x00, 0x04, 0x01, 0x05, 0x10, 0x01, 0x00, 0x07,
    ];
    let decoded = decode_ack(wire).unwrap();
    assert_eq!(decoded.header.ext, Some(ExtHeader::frag_ack(0, 0x07)));
    assert_eq!(decoded.header.counter, 0x10);
    let mut out = [0u8; 16];
    let n = decoded.header.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], wire);
}

// 05-3474-23-22511-02/03: discriminants — reserved delivery mode and
// fragmentation values are rejected, never panic.
#[test]
fn vector_reserved_discriminants_rejected_05_3474_23_22511_02() {
    // Delivery mode 0b01, low byte 0x04.
    assert_eq!(
        decode_data(&[0x04, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02]),
        Err(ApsError::ReservedDeliveryMode(0x01))
    );
    // Fragmentation 0b11 in the extended header.
    assert_eq!(
        decode_data(&[0x80, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03]),
        Err(ApsError::ReservedFragmentation(0x03))
    );
    // Frame-type dispatch: peek then decode through the wrong entry.
    assert_eq!(peek_frame_type(&[0x01, 0x20, 0x05]), Ok(FrameType::Command));
    assert_eq!(
        decode_data(&[0x01, 0x20, 0x05]),
        Err(ApsError::FrameTypeMismatch {
            expected: FrameType::Data,
            found: FrameType::Command,
        })
    );
}

// 05-3474-23-22511-16: every strict prefix of a data frame is
// Truncated; full length and longer decode with the payload split.
#[test]
fn vector_truncation_is_fallible_05_3474_23_22511_16() {
    let wire: &[u8] = &[0x00, 0x05, 0x06, 0x00, 0x04, 0x01, 0x01, 0x42, 0xAA, 0xBB];
    for len in 0..8 {
        assert_eq!(
            decode_data(&wire[..len]),
            Err(ApsError::Truncated),
            "prefix len {len}"
        );
    }
    for len in 8..=wire.len() {
        let d = decode_data(&wire[..len]).unwrap();
        assert_eq!(d.payload, &wire[8..len]);
    }
    assert_eq!(decode_data(&[]), Err(ApsError::Truncated));
    // Encode into a short buffer fails instead of truncating.
    let header = decode_data(wire).unwrap().header;
    let mut short = [0u8; 4];
    assert_eq!(
        header.encode_into(&wire[8..], &mut short),
        Err(ApsError::BufferTooSmall)
    );
}

// 05-3474-23-229-01: every Table 2-29 status code round-trips; unknown
// codes are rejected.
#[test]
fn vector_status_codes_05_3474_23_229_01() {
    let cases: &[(ApsStatus, u8)] = &[
        (ApsStatus::Success, 0x00),
        (ApsStatus::AsduTooLong, 0xa0),
        (ApsStatus::DefragDeferred, 0xa1),
        (ApsStatus::DefragUnsupported, 0xa2),
        (ApsStatus::IllegalRequest, 0xa3),
        (ApsStatus::InvalidBinding, 0xa4),
        (ApsStatus::InvalidGroup, 0xa5),
        (ApsStatus::InvalidParameter, 0xa6),
        (ApsStatus::NoAck, 0xa7),
        (ApsStatus::NoBoundDevice, 0xa8),
        (ApsStatus::NoShortAddress, 0xa9),
        (ApsStatus::NotSupported, 0xaa),
        (ApsStatus::SecuredLinkKey, 0xab),
        (ApsStatus::SecuredNwkKey, 0xac),
        (ApsStatus::SecurityFail, 0xad),
        (ApsStatus::TableFull, 0xae),
        (ApsStatus::Unsecured, 0xaf),
        (ApsStatus::UnsupportedAttribute, 0xb0),
        (ApsStatus::PeerCannotFragment, 0xb1),
        (ApsStatus::UnknownFragmentSupport, 0xb2),
    ];
    for (status, code) in cases {
        assert_eq!(status.code(), *code);
        assert_eq!(ApsStatus::from_code(*code), Ok(*status));
    }
    assert!(ApsStatus::from_code(0x01).is_err());
    assert!(ApsStatus::from_code(0xC0).is_err());
}

// Fig 2-2 transmit gates (mined from the `r23-p0066.png` render):
// single, broadcast-too-long, local-support, discovery, peer-support,
// receiver-buffer gates.
#[test]
fn vector_fragment_plan_gates_fig2_2() {
    let peer = PeerFragCaps {
        known: true,
        can_fragment: true,
        max_rx_asdu: 200,
    };
    // Fits: single frame.
    assert_eq!(plan_transmit(40, 64, false, true, peer, 32), TxPlan::Single);
    // Oversize broadcast: ASDU_TOO_LONG (broadcasts never fragment).
    assert_eq!(
        plan_transmit(200, 64, true, true, peer, 32),
        TxPlan::Fail(ApsStatus::AsduTooLong)
    );
    // Local fragmentation unsupported: ASDU_TOO_LONG.
    assert_eq!(
        plan_transmit(200, 64, false, false, peer, 32),
        TxPlan::Fail(ApsStatus::AsduTooLong)
    );
    // No discovery result: UNKNOWN_FRAGMENT_SUPPORT.
    assert_eq!(
        plan_transmit(200, 64, false, true, PeerFragCaps::unknown(), 32),
        TxPlan::Fail(ApsStatus::UnknownFragmentSupport)
    );
    // Peer cannot fragment: PEER_CANNOT_FRAGMENT.
    assert_eq!(
        plan_transmit(
            200,
            64,
            false,
            true,
            PeerFragCaps {
                known: true,
                can_fragment: false,
                max_rx_asdu: 200,
            },
            32,
        ),
        TxPlan::Fail(ApsStatus::PeerCannotFragment)
    );
    // Peer's buffer too small: ASDU_TOO_LONG.
    assert_eq!(
        plan_transmit(
            200,
            64,
            false,
            true,
            PeerFragCaps {
                known: true,
                can_fragment: true,
                max_rx_asdu: 100,
            },
            32,
        ),
        TxPlan::Fail(ApsStatus::AsduTooLong)
    );
    // Fragmentable: block count is the ceiling.
    assert_eq!(
        plan_transmit(100, 64, false, true, peer, 32),
        TxPlan::Fragmented { block_count: 4 }
    );
}

// 05-3474-23-22845-05: block split markers — first announces the total,
// later blocks carry their 0x01-based index.
#[test]
fn vector_block_split_markers_05_3474_23_22845_05() {
    let asdu = [0xA5u8; 100];
    let tx = TxBlocks::new(&asdu, 32).unwrap();
    assert_eq!(tx.count(), 4);
    let (f0, n0, p0) = tx.block(0);
    assert_eq!((f0, n0), (Fragmentation::First, 4));
    assert_eq!(p0.len(), 32);
    let (f1, n1, _) = tx.block(1);
    assert_eq!((f1, n1), (Fragmentation::Subsequent, 1));
    let (f3, n3, p3) = tx.block(3);
    assert_eq!((f3, n3), (Fragmentation::Subsequent, 3));
    assert_eq!(p3.len(), 4);
    // Reassembled in order, the blocks reproduce the ASDU.
    let mut rx = Reassembler::new();
    let mut done = None;
    for i in 0..4 {
        let (f, n, p) = tx.block(i);
        match rx.feed(0x1234, 0x77, f, n, p, 100 + u64::from(i)).unwrap() {
            FeedOutcome::Complete { len } => done = Some(len),
            FeedOutcome::InProgress => {}
            FeedOutcome::Duplicate => panic!("no repeats fed"),
        }
    }
    assert_eq!(done, Some(100));
    assert_eq!(rx.assembled(), Some(asdu.as_slice()));
}

// 05-3474-23-22845-06: out-of-order arrival still reassembles exactly.
#[test]
fn vector_reassembly_out_of_order_05_3474_23_22845_06() {
    let asdu: Vec<u8> = (0..=99u8).collect();
    let tx = TxBlocks::new(&asdu, 32).unwrap();
    let mut rx = Reassembler::new();
    // Feed last-to-first: the short final block lands before the total
    // is known, and the transaction still completes exactly.
    for i in [3u8, 1, 2] {
        let (f, n, p) = tx.block(i);
        assert_eq!(
            rx.feed(0x0002, 0x01, f, n, p, 7),
            Ok(FeedOutcome::InProgress)
        );
    }
    // Block 0 announces the total and completes the transaction.
    let (f, n, p) = tx.block(0);
    assert_eq!(
        rx.feed(0x0002, 0x01, f, n, p, 8),
        Ok(FeedOutcome::Complete { len: 100 })
    );
    assert_eq!(rx.assembled(), Some(asdu.as_slice()));
    let (held, len) = rx.take_assembled().unwrap();
    assert_eq!(&held[..len], asdu.as_slice());
    assert!(rx.assembled().is_none());
}

// 05-3474-23-22845-06: protocol violations and budget exhaustion are
// fallible, never panics.
#[test]
fn vector_reassembly_rejects_05_3474_23_22845_06() {
    let mut rx = Reassembler::new();
    // Unfragmented frames do not belong on this path.
    assert_eq!(
        rx.feed(1, 1, Frag::Unfragmented, 0, &[0xAA], 0),
        Err(FragError::NotFragmented)
    );
    // Zero total announced.
    assert_eq!(
        rx.feed(1, 1, Frag::First, 0, &[0xAA], 0),
        Err(FragError::BadBlockCount)
    );
    // Over-budget total announced.
    assert_eq!(
        rx.feed(1, 1, Frag::First, 33, &[0xAA], 0),
        Err(FragError::BadBlockCount)
    );
    // Later-block index 0 is reserved for the first block.
    assert_eq!(
        rx.feed(2, 2, Frag::Subsequent, 0, &[0xAA], 0),
        Err(FragError::BlockOutOfRange)
    );
    // Oversize block payload.
    assert_eq!(
        rx.feed(2, 2, Frag::First, 2, &[0xAA; 129], 0),
        Err(FragError::PayloadTooLarge)
    );
    // Conflicting totals for one transaction.
    let mut rx2 = Reassembler::new();
    assert_eq!(
        rx2.feed(3, 3, Frag::First, 4, &[0x01; 8], 0),
        Ok(FeedOutcome::InProgress)
    );
    assert_eq!(
        rx2.feed(3, 3, Frag::Subsequent, 5, &[0x02; 8], 1),
        Err(FragError::BlockOutOfRange)
    );
    // Slot budget: two live transactions leave no room for a third.
    let mut rx3 = Reassembler::new();
    assert_eq!(
        rx3.feed(0x10, 0x01, Frag::Subsequent, 1, &[0x01], 0),
        Ok(FeedOutcome::InProgress)
    );
    assert_eq!(
        rx3.feed(0x11, 0x01, Frag::Subsequent, 1, &[0x01], 0),
        Ok(FeedOutcome::InProgress)
    );
    assert_eq!(rx3.live_count(), 2);
    assert_eq!(
        rx3.feed(0x12, 0x01, Frag::Subsequent, 1, &[0x01], 0),
        Err(FragError::NoSlot)
    );
    // Stalled transactions reap after the window timeout.
    let timeout = rx_timeout_ticks(100, u64::from(MAX_FRAME_RETRIES));
    assert_eq!(timeout, 400);
    assert_eq!(rx3.reap_expired(1000, timeout), 2);
    assert_eq!(rx3.live_count(), 0);
}

// 05-3474-23-22844-01: retry machine — transmit, wait, retransmit up
// to the cap, then confirm NO_ACK; matching acks end it early.
#[test]
fn vector_retry_machine_05_3474_23_22844_01() {
    let expect = AckExpect {
        cluster_id: 0x0006,
        counter: 0x42,
        dst_endpoint: 0x05,
    };
    let mut s = RetrySession::new(expect, 0, 100);
    assert_eq!(s.poll_transmit(), RetryVerdict::Transmit);
    assert_eq!(s.poll_transmit(), RetryVerdict::Waiting);
    // Wrong counter: attempt treated as failed, session keeps waiting.
    assert_eq!(
        s.on_ack(AckInfo {
            cluster_id: 0x0006,
            counter: 0x43,
            src_endpoint: 0x05,
        }),
        RetryVerdict::Waiting
    );
    assert_eq!(s.on_tick(50), RetryVerdict::Waiting);
    // Deadline passes: three retransmits, then NO_ACK.
    assert_eq!(s.on_tick(100), RetryVerdict::Transmit);
    assert_eq!(s.attempts(), 1);
    assert_eq!(s.on_tick(200), RetryVerdict::Transmit);
    assert_eq!(s.on_tick(300), RetryVerdict::Transmit);
    assert_eq!(s.attempts(), MAX_FRAME_RETRIES);
    assert_eq!(s.on_tick(400), RetryVerdict::Failed(ApsStatus::NoAck));
    // Terminal state sticks.
    assert_eq!(s.on_tick(9999), RetryVerdict::Failed(ApsStatus::NoAck));

    // Matching ack on the first wait: success, no retransmit.
    let mut ok = RetrySession::new(expect, 0, 100);
    assert_eq!(ok.poll_transmit(), RetryVerdict::Transmit);
    assert_eq!(
        ok.on_ack(AckInfo {
            cluster_id: 0x0006,
            counter: 0x42,
            src_endpoint: 0x05,
        }),
        RetryVerdict::Acked
    );
    assert_eq!(ok.on_tick(9999), RetryVerdict::Acked);
}

// 05-3474-23-22842-02: duplicate rejection — delivered once only.
#[test]
fn vector_duplicate_rejection_05_3474_23_22842_02() {
    let mut t = DupRejectTable::new();
    assert!(t.is_empty());
    assert!(!t.observe(0x1234, 0x01));
    assert!(t.observe(0x1234, 0x01));
    assert!(!t.observe(0x1234, 0x02));
    assert!(!t.observe(0x5678, 0x01));
    assert_eq!(t.len(), 3);
    // Ring eviction: after 4 distinct pairs the oldest drops out.
    assert!(!t.observe(0x9ABC, 0x01));
    assert_eq!(t.len(), 4);
    assert!(!t.observe(0xDEF0, 0x01));
    assert_eq!(t.len(), 4);
    assert!(!t.observe(0x1234, 0x01), "evicted pair is new again");
}

// 05-3474-23-22431-01/02: binding table — create, idempotent re-add,
// full-table and bad-parameter confirms, remove, fan-out lookup.
#[test]
fn vector_binding_table_05_3474_23_22431_01() {
    let mut table = BindingTable::new();
    let entry = BindingEntry {
        src_ieee: 0x0012_4B00_0000_0001,
        src_endpoint: 0x01,
        cluster_id: 0x0006,
        dst: BindingDst::Unicast {
            dst_ieee: 0x0012_4B00_0000_0002,
            dst_endpoint: 0x01,
        },
    };
    assert_eq!(table.bind(entry), ApsStatus::Success);
    assert_eq!(table.len(), 1);
    assert_eq!(table.bind(entry), ApsStatus::Success, "idempotent");
    assert_eq!(table.len(), 1);

    // Out-of-range endpoint: ILLEGAL_REQUEST.
    let bad = BindingEntry {
        src_endpoint: 0xFF,
        ..entry
    };
    assert_eq!(table.bind(bad), ApsStatus::IllegalRequest);

    // Fan-out lookup over matching entries.
    let group_entry = BindingEntry {
        dst: BindingDst::Group { group_addr: 0x1234 },
        ..entry
    };
    assert_eq!(table.bind(group_entry), ApsStatus::Success);
    let mut out = [BindingDst::Group { group_addr: 0 }; MAX_BINDINGS];
    let n = table.lookup(
        entry.src_ieee,
        entry.src_endpoint,
        entry.cluster_id,
        &mut out,
    );
    assert_eq!(n, 2);
    assert!(out[..n].contains(&entry.dst));
    assert!(out[..n].contains(&group_entry.dst));
    // Non-matching cluster finds nothing.
    assert_eq!(
        table.lookup(entry.src_ieee, entry.src_endpoint, 0x9999, &mut out),
        0
    );

    // Fill to capacity: the next create reports TABLE_FULL.
    for i in 0..(MAX_BINDINGS - 2) {
        let e = BindingEntry {
            src_ieee: 0x0012_4B00_0100_0000 + i as u64,
            ..entry
        };
        assert_eq!(table.bind(e), ApsStatus::Success);
    }
    assert_eq!(
        table.bind(BindingEntry {
            src_ieee: 0xFFFF,
            ..entry
        }),
        ApsStatus::TableFull
    );

    // Remove: present → SUCCESS, absent → INVALID_BINDING.
    assert_eq!(table.unbind(&group_entry), ApsStatus::Success);
    assert_eq!(table.unbind(&group_entry), ApsStatus::InvalidBinding);
}

// 05-3474-23-22451-01/02: group table — add, idempotent re-add,
// invalid endpoint, full table, remove, member fan-out.
#[test]
fn vector_group_table_05_3474_23_22451_01() {
    let mut table = GroupTable::new();
    assert_eq!(table.add(0x1234, 0x01), ApsStatus::Success);
    assert_eq!(table.add(0x1234, 0x01), ApsStatus::Success, "idempotent");
    assert_eq!(table.len(), 1);
    // Reserved endpoints are not group members.
    assert_eq!(table.add(0x1234, 0x00), ApsStatus::InvalidParameter);
    assert_eq!(table.add(0x1234, 0xFF), ApsStatus::InvalidParameter);
    // Second endpoint on the same group.
    assert_eq!(table.add(0x1234, 0x02), ApsStatus::Success);
    let mut members = [0u8; MAX_GROUPS];
    let n = table.members(0x1234, &mut members);
    assert_eq!(n, 2);
    assert!(members[..n].contains(&0x01));
    assert!(members[..n].contains(&0x02));
    // Fill to capacity.
    for i in 0..(MAX_GROUPS - 2) {
        assert_eq!(table.add(0x2000 + i as u16, 0x01), ApsStatus::Success);
    }
    assert_eq!(table.add(0x9999, 0x01), ApsStatus::TableFull);
    // Remove-group confirm mapping.
    assert_eq!(table.remove_exact(0x1234, 0x01), ApsStatus::Success);
    assert_eq!(table.remove_exact(0x1234, 0x01), ApsStatus::InvalidGroup);
    table.clear();
    assert!(table.is_empty());
}

// 05-3474-23-22411-09: discovery address map — note/lookup/refresh,
// forget, and bounded eviction under overflow.
#[test]
fn vector_addr_map_05_3474_23_22411_09() {
    let mut map = AddrMap::new();
    assert!(map.is_empty());
    assert_eq!(map.lookup(0x0012_4B00_0000_0002), None);

    // Discovery outcomes populate the cache.
    map.note(0x0012_4B00_0000_0002, 0x1234);
    map.note(0x0012_4B00_0000_0003, 0x5678);
    assert_eq!(map.len(), 2);
    assert_eq!(map.lookup(0x0012_4B00_0000_0002), Some(0x1234));

    // Re-announce with a new short refreshes in place (no growth).
    map.note(0x0012_4B00_0000_0002, 0x4321);
    assert_eq!(map.len(), 2);
    assert_eq!(map.lookup(0x0012_4B00_0000_0002), Some(0x4321));

    // Forget drops the pair; unknown pairs report false.
    assert!(map.forget(0x0012_4B00_0000_0003));
    assert!(!map.forget(0x0012_4B00_0000_0003));
    assert_eq!(map.lookup(0x0012_4B00_0000_0003), None);
    assert_eq!(map.len(), 1);

    // Overflow evicts the oldest pair; the cache never grows past
    // its declared budget and the newest pair is always present.
    for i in 0..(MAX_ADDR_MAP as u64 + 2) {
        map.note(0x0012_4B00_1000_0000 + i, 0x2000 + i as u16);
    }
    assert_eq!(map.len(), MAX_ADDR_MAP);
    assert_eq!(
        map.lookup(0x0012_4B00_1000_0000 + MAX_ADDR_MAP as u64 + 1),
        Some(0x2000 + MAX_ADDR_MAP as u16 + 1)
    );
    assert_eq!(map.lookup(0x0012_4B00_1000_0000), None);
}

// 05-3474-23-22411-10: indirect dispatch — mixed known/unknown/group
// entries resolve against the discovery cache; unknown shorts are
// reported for follow-on discovery, and the confirm pins pin down
// the indirect-transmit decision table.
#[test]
fn vector_indirect_dispatch_05_3474_23_22411_10() {
    const SRC: u64 = 0x0012_4B00_0000_0001;
    const KNOWN: u64 = 0x0012_4B00_0000_0002;
    const UNKNOWN: u64 = 0x0012_4B00_0000_0003;
    let mut binding = BindingTable::new();
    let mut addrs = AddrMap::new();
    addrs.note(KNOWN, 0x1234);

    // No matching entries at all: NO_BOUND_DEVICE.
    let empty = binding.plan_indirect(&addrs, true, SRC, 0x01, 0x0006);
    assert_eq!(empty.confirm(), ApsStatus::NoBoundDevice);
    assert!(empty.resolved().is_empty());
    assert!(empty.unresolved().is_empty());

    // Device without a binding table cannot do indirect: NOT_SUPPORTED.
    let unsupported = binding.plan_indirect(&addrs, false, SRC, 0x01, 0x0006);
    assert_eq!(unsupported.confirm(), ApsStatus::NotSupported);

    assert_eq!(
        binding.bind(BindingEntry {
            src_ieee: SRC,
            src_endpoint: 0x01,
            cluster_id: 0x0006,
            dst: BindingDst::Unicast {
                dst_ieee: KNOWN,
                dst_endpoint: 0x01,
            },
        }),
        ApsStatus::Success
    );
    assert_eq!(
        binding.bind(BindingEntry {
            src_ieee: SRC,
            src_endpoint: 0x01,
            cluster_id: 0x0006,
            dst: BindingDst::Unicast {
                dst_ieee: UNKNOWN,
                dst_endpoint: 0x02,
            },
        }),
        ApsStatus::Success
    );
    assert_eq!(
        binding.bind(BindingEntry {
            src_ieee: SRC,
            src_endpoint: 0x01,
            cluster_id: 0x0006,
            dst: BindingDst::Group { group_addr: 0xABCD },
        }),
        ApsStatus::Success
    );

    // Partial success: known unicast + group resolve; the unknown
    // short is listed for targeted discovery (IEEE_addr_req).
    let plan = binding.plan_indirect(&addrs, true, SRC, 0x01, 0x0006);
    assert_eq!(plan.confirm(), ApsStatus::Success);
    assert_eq!(plan.resolved().len(), 2);
    assert!(plan.resolved().contains(&ResolvedDst::Unicast {
        ieee: KNOWN,
        nwk: 0x1234,
        endpoint: 0x01,
    }));
    assert!(plan
        .resolved()
        .contains(&ResolvedDst::Group { group_addr: 0xABCD }));
    assert_eq!(plan.unresolved(), &[UNKNOWN]);

    // Once discovery resolves the missing short, the re-plan
    // succeeds fully with nothing left to discover.
    addrs.note(UNKNOWN, 0x5678);
    let full = binding.plan_indirect(&addrs, true, SRC, 0x01, 0x0006);
    assert_eq!(full.confirm(), ApsStatus::Success);
    assert_eq!(full.resolved().len(), 3);
    assert!(full.unresolved().is_empty());

    // Other clusters still have no entries: NO_BOUND_DEVICE.
    let other = binding.plan_indirect(&addrs, true, SRC, 0x01, 0x9999);
    assert_eq!(other.confirm(), ApsStatus::NoBoundDevice);
}

// 05-3474-23-22411-10 edge pins: entries with no resolvable short at
// all confirm NO_SHORT_ADDRESS (resolution is hop-agnostic: a cached
// short far beyond radio range still resolves — multi-hop path
// repair is the NWK layer's job); removing the entry flips the same
// key back to NO_BOUND_DEVICE (invalid-binding removal path).
#[test]
fn vector_indirect_dispatch_edges_05_3474_23_22411_10() {
    const SRC: u64 = 0x0012_4B00_0000_0001;
    const FAR: u64 = 0x0012_4B00_0000_0009;
    let mut binding = BindingTable::new();
    let mut addrs = AddrMap::new();
    let entry = BindingEntry {
        src_ieee: SRC,
        src_endpoint: 0x01,
        cluster_id: 0x0006,
        dst: BindingDst::Unicast {
            dst_ieee: FAR,
            dst_endpoint: 0x01,
        },
    };
    assert_eq!(binding.bind(entry), ApsStatus::Success);

    // Matched but unresolvable: NO_SHORT_ADDRESS, discovery pending.
    let stuck = binding.plan_indirect(&addrs, true, SRC, 0x01, 0x0006);
    assert_eq!(stuck.confirm(), ApsStatus::NoShortAddress);
    assert!(stuck.resolved().is_empty());
    assert_eq!(stuck.unresolved(), &[FAR]);

    // Hop-agnostic resolution: a cached short needs no neighbor
    // knowledge; the plan emits it and the NWK layer route-discovers.
    addrs.note(FAR, 0x9ABC);
    let via = binding.plan_indirect(&addrs, true, SRC, 0x01, 0x0006);
    assert_eq!(via.confirm(), ApsStatus::Success);
    assert_eq!(
        via.resolved(),
        &[ResolvedDst::Unicast {
            ieee: FAR,
            nwk: 0x9ABC,
            endpoint: 0x01,
        }]
    );

    // Unbind removes the entry; absent re-removal is INVALID_BINDING
    // and the key plans NO_BOUND_DEVICE again.
    assert_eq!(binding.unbind(&entry), ApsStatus::Success);
    assert_eq!(binding.unbind(&entry), ApsStatus::InvalidBinding);
    let gone = binding.plan_indirect(&addrs, true, SRC, 0x01, 0x0006);
    assert_eq!(gone.confirm(), ApsStatus::NoBoundDevice);
}
