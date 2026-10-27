//! Wire-byte spec vectors for the NWK general frame.
//!
//! Each test names the requirement ID it verifies. Byte strings below
//! are hand-computed from the paraphrased layouts in doc `05-3474-23`
//! R23.2 §3.3.1 (Figs. 3-4/3-5) and the NLDE construction rules of
//! §3.2.1.1.3 — never copied from spec text (D1, `SCOPE.md` §2).

use rounddance_nwk::{
    build_data_header, decode, indication_for_local, is_broadcast_addr, radius_for_request,
    Decoded, DiscoverRoute, FrameControl, FrameType, NldeDataRequest, NldeError, NwkError,
    NwkHeader, SourceRoute, TxPipeline, BROADCAST_ALL_DEVICES, BROADCAST_RESERVED_HIGH,
    BROADCAST_RESERVED_LOW, BROADCAST_ROUTERS,
};

// 05-3474-23-331-01: minimal data frame on the wire.
//
// control = Data | ver 2 | discover Enable =
//   0x00 | (2 << 2) | (1 << 6) = 0x48, high byte 0x00.
#[test]
fn vector_minimal_data_unicast_05_3474_23_331_01() {
    let wire: &[u8] = &[
        0x48, 0x00, // frame control
        0x34, 0x12, // dst 0x1234
        0x00, 0x00, // src 0x0000
        0x0A, // radius 10
        0x5C, // seq 0x5C
        0xDE, 0xAD, // payload
    ];
    let Decoded { header, payload } = decode(wire).unwrap();
    assert_eq!(header.control.frame_type, FrameType::Data);
    assert_eq!(header.control.protocol_version, 2);
    assert_eq!(header.control.discover_route, DiscoverRoute::Enable);
    assert_eq!(header.dst_addr, 0x1234);
    assert_eq!(header.src_addr, 0x0000);
    assert_eq!(header.radius, 10);
    assert_eq!(header.seq, 0x5C);
    assert_eq!(header.dst_ieee, None);
    assert_eq!(header.src_ieee, None);
    assert_eq!(header.source_route, None);
    assert_eq!(payload, &[0xDE, 0xAD]);

    // Re-encode is byte-identical.
    let mut out = [0u8; 32];
    let n = header.encode_into(payload, &mut out).unwrap();
    assert_eq!(&out[..n], wire);
}

// 05-3474-23-331-01/02/07: full header — command type, security, source
// route, both extended addresses, end-device initiator.
//
// fc = Command(01) | ver 2 (0010<<2) | discover 00 | sec | sr | dstI |
//   srcI | edi = 0x0001 | 0x0008 | 0x0200 | 0x0400 | 0x0800 | 0x1000 |
//   0x2000 = 0x3E09 -> LE [0x09, 0x3E].
#[test]
fn vector_full_command_header_05_3474_23_331_01() {
    let wire: &[u8] = &[
        0x09, 0x3E, // frame control
        0x44, 0x33, // dst 0x3344
        0x01, 0x00, // src 0x0001
        0x01, // radius
        0x07, // seq
        0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, // dst IEEE
        0xEF, 0xBE, 0x00, 0x00, 0x00, 0x4B, 0x12, 0x00, // src IEEE
        0x02, 0x01, // relay count 2, index 1
        0x11, 0x11, // relay[0]: closest to destination
        0x22, 0x22, // relay[1]: closest to originator
        0x01, 0x00, 0x5A, // command payload
    ];
    let Decoded { header, payload } = decode(wire).unwrap();
    assert_eq!(header.control.frame_type, FrameType::Command);
    assert!(header.control.security);
    assert!(header.control.source_route);
    assert!(header.control.dst_ieee);
    assert!(header.control.src_ieee);
    assert!(header.control.end_device_initiator);
    assert!(!header.control.multicast);
    assert_eq!(header.dst_addr, 0x3344);
    assert_eq!(header.dst_ieee, Some(0xAABBCCDDEEFF0011));
    assert_eq!(header.src_ieee, Some(0x00124B000000BEEF));
    let sr = header.source_route.unwrap();
    assert_eq!(sr.relay_count(), 2);
    assert_eq!(sr.relay_index, 1, "wire index preserved verbatim");
    assert_eq!(sr.relays(), &[0x1111, 0x2222]);
    assert_eq!(payload, &[0x01, 0x00, 0x5A]);

    let mut out = [0u8; 64];
    let n = header.encode_into(payload, &mut out).unwrap();
    assert_eq!(&out[..n], wire);
    assert_eq!(n, header.header_len() + payload.len());
}

// 05-3474-23-331-02: frame-control pack/unpack incl. Inter-PAN and the
// deprecated multicast bit carried verbatim.
#[test]
fn vector_frame_control_bits_05_3474_23_331_02() {
    let fc = FrameControl {
        frame_type: FrameType::InterPan,
        protocol_version: 3,
        discover_route: DiscoverRoute::Enable,
        multicast: true,
        security: false,
        source_route: false,
        dst_ieee: false,
        src_ieee: true,
        end_device_initiator: false,
    };
    // 0x03 | (3<<2)=0x0C | (1<<6)=0x40 -> low 0x4F;
    // high: (1<<8) | (1<<12) -> 0x11.
    assert_eq!(fc.to_u16(), 0x114F);
    let back = FrameControl::from_u16(0x114F).unwrap();
    assert_eq!(back, fc);

    // Reserved bits 14-15 are ignored on decode, zeroed on encode.
    let with_reserved = FrameControl::from_u16(0xC048).unwrap();
    assert_eq!(with_reserved.to_u16(), 0x0048);
}

// 05-3474-23-331-02: reserved discriminants are rejected, never panic.
#[test]
fn vector_reserved_discriminants_rejected_05_3474_23_331_02() {
    // Frame type 0b10, low byte 0xFA.
    let mut bad_type = [0xFA, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0xAA];
    assert_eq!(
        rounddance_nwk::decode(&bad_type),
        Err(NwkError::ReservedFrameType(0x02))
    );
    // Discover route 0b10, low byte 0x88 (type 00, ver 2).
    bad_type[0] = 0x88;
    assert_eq!(
        rounddance_nwk::decode(&bad_type),
        Err(NwkError::ReservedDiscoverRoute(0x02))
    );
}

// 05-3474-23-331-01: every strict prefix of a frame is Truncated; full
// length and longer decode with the exact payload split.
#[test]
fn vector_truncation_is_fallible_05_3474_23_331_01() {
    let wire: &[u8] = &[0x48, 0x00, 0x34, 0x12, 0x00, 0x00, 0x0A, 0x5C, 0xDE, 0xAD];
    for len in 0..8 {
        assert_eq!(
            rounddance_nwk::decode(&wire[..len]),
            Err(NwkError::Truncated),
            "prefix len {len}"
        );
    }
    for len in 8..=wire.len() {
        let d = rounddance_nwk::decode(&wire[..len]).unwrap();
        assert_eq!(d.payload, &wire[8..len]);
    }
    // Optional-field overruns are Truncated, not panics (dst_ieee flag
    // set, only 2 of the 8 address octets present).
    let short_ieee = [0x48, 0x08, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x11, 0x22];
    assert_eq!(
        rounddance_nwk::decode(&short_ieee),
        Err(NwkError::Truncated)
    );
}

// 05-3474-23-331-06: broadcast destinations never carry a destination
// IEEE address — rejected on decode and on encode.
#[test]
fn vector_broadcast_never_carries_dst_ieee_05_3474_23_331_06() {
    // dst 0xFFFF + dst_ieee flag.
    let wire: &[u8] = &[
        0x48, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08,
    ];
    assert_eq!(
        rounddance_nwk::decode(wire),
        Err(NwkError::BroadcastWithDstIeee)
    );
    let mut control = FrameControl::data();
    control.dst_ieee = true;
    let header = NwkHeader {
        control,
        dst_addr: BROADCAST_ROUTERS,
        src_addr: 0x0001,
        radius: 5,
        seq: 9,
        dst_ieee: Some(0xAABBCCDDEEFF0011),
        src_ieee: None,
        source_route: None,
    };
    let mut out = [0u8; 64];
    assert_eq!(
        header.encode_into(&[], &mut out),
        Err(NwkError::BroadcastWithDstIeee)
    );
}

// 05-3474-23-366-01: broadcast address set + range predicate.
#[test]
fn vector_broadcast_addresses_05_3474_23_366_01() {
    assert!(is_broadcast_addr(BROADCAST_ALL_DEVICES));
    assert!(is_broadcast_addr(BROADCAST_ROUTERS));
    assert!(is_broadcast_addr(BROADCAST_RESERVED_LOW));
    assert!(is_broadcast_addr(BROADCAST_RESERVED_HIGH));
    assert!(!is_broadcast_addr(0xFFF7));
    assert!(!is_broadcast_addr(0x1234));
    assert!(!is_broadcast_addr(0x0000));
}

// 05-3474-23-331-01: presence-flag/field consistency enforced on encode.
#[test]
fn vector_presence_mismatch_fails_encode_05_3474_23_331_01() {
    let mut control = FrameControl::data();
    control.src_ieee = true; // flag set, field absent
    let header = NwkHeader::minimal(control, 0x0002, 0x0001, 3, 4);
    let mut out = [0u8; 32];
    assert_eq!(
        header.encode_into(&[0xAA], &mut out),
        Err(NwkError::PresenceMismatch("src_ieee"))
    );
    // And the reverse: field present, flag clear.
    let mut control2 = FrameControl::data();
    control2.dst_ieee = false;
    let header2 = NwkHeader {
        control: control2,
        dst_addr: 0x0002,
        src_addr: 0x0001,
        radius: 3,
        seq: 4,
        dst_ieee: Some(0x1122334455667788),
        src_ieee: None,
        source_route: None,
    };
    assert_eq!(
        header2.encode_into(&[0xAA], &mut out),
        Err(NwkError::PresenceMismatch("dst_ieee"))
    );
    // Encode buffer too small is fallible.
    let header3 = NwkHeader::minimal(FrameControl::data(), 0x0002, 0x0001, 3, 4);
    let mut tiny = [0u8; 8];
    assert_eq!(
        header3.encode_into(&[0xAA], &mut tiny),
        Err(NwkError::BufferTooSmall)
    );
    let mut exact = [0u8; 9];
    assert_eq!(header3.encode_into(&[0xAA], &mut exact), Ok(9));
}

// 05-3474-23-331-07: source-route relay rules — originator index,
// verbatim wire index, empty/oversize rejection.
#[test]
fn vector_source_route_rules_05_3474_23_331_07() {
    let sr = SourceRoute::new(&[0x1111, 0x2222, 0x3333]).unwrap();
    assert_eq!(sr.relay_index, 2, "originator index = count - 1");
    assert_eq!(sr.relay_count(), 3);
    assert_eq!(SourceRoute::new(&[]), Err(NwkError::BadRelayCount(0)));
    let too_many = [0x0001u16; 17];
    assert_eq!(
        SourceRoute::new(&too_many),
        Err(NwkError::BadRelayCount(17))
    );
    // Wire count 0 with the flag set is rejected on decode.
    let zero_count: &[u8] = &[0x48, 0x04, 0x02, 0x00, 0x01, 0x00, 0x03, 0x04, 0x00, 0x00];
    assert_eq!(
        rounddance_nwk::decode(zero_count),
        Err(NwkError::BadRelayCount(0))
    );
}

// 05-3474-23-3211-03: radius mapping — nonzero passes through, zero
// selects twice nwkcMaxDepth.
#[test]
fn vector_radius_mapping_05_3474_23_3211_03() {
    assert_eq!(radius_for_request(7, 5), 7);
    assert_eq!(radius_for_request(1, 15), 1);
    assert_eq!(radius_for_request(0, 5), 10);
    assert_eq!(radius_for_request(0, 0), 0);
}

// 05-3474-23-3211-04: alias mode swaps source + sequence; normal mode
// uses the MAC short address and a generated sequence number.
#[test]
fn vector_alias_vs_normal_source_05_3474_23_3211_04() {
    let base = NldeDataRequest {
        dst_addr: 0x3344,
        use_alias: true,
        alias_src: 0xABCD,
        alias_seq: 0x99,
        radius_param: 3,
        discover_route: DiscoverRoute::Suppress,
        generated_seq: 0x42,
        local_short_addr: 0x0001,
        max_depth: 5,
        associated: true,
    };
    let aliased = build_data_header(&base).unwrap();
    assert_eq!(aliased.src_addr, 0xABCD);
    assert_eq!(aliased.seq, 0x99);
    let normal = build_data_header(&NldeDataRequest {
        use_alias: false,
        ..base
    })
    .unwrap();
    assert_eq!(normal.src_addr, 0x0001);
    assert_eq!(normal.seq, 0x42);
    assert_eq!(normal.dst_addr, 0x3344);
    assert_eq!(normal.radius, 3);
}

// 05-3474-23-3211-05: discover-route flag passes through to the header.
#[test]
fn vector_discover_route_passthrough_05_3474_23_3211_05() {
    let base = NldeDataRequest {
        dst_addr: 0x0002,
        use_alias: false,
        alias_src: 0,
        alias_seq: 0,
        radius_param: 0,
        discover_route: DiscoverRoute::Enable,
        generated_seq: 1,
        local_short_addr: 0x0001,
        max_depth: 5,
        associated: true,
    };
    let h = build_data_header(&base).unwrap();
    assert_eq!(h.control.discover_route, DiscoverRoute::Enable);
    assert_eq!(h.radius, 10, "zero radius param -> 2 x max_depth");
    let h2 = build_data_header(&NldeDataRequest {
        discover_route: DiscoverRoute::Suppress,
        ..base
    })
    .unwrap();
    assert_eq!(h2.control.discover_route, DiscoverRoute::Suppress);
}

// 05-3474-23-3211-01: unassociated devices build nothing.
#[test]
fn vector_unassociated_guard_05_3474_23_3211_01() {
    let req = NldeDataRequest {
        dst_addr: 0x0002,
        use_alias: false,
        alias_src: 0,
        alias_seq: 0,
        radius_param: 3,
        discover_route: DiscoverRoute::Suppress,
        generated_seq: 1,
        local_short_addr: 0x0001,
        max_depth: 5,
        associated: false,
    };
    assert_eq!(build_data_header(&req), Err(NldeError::NotAssociated));
}

// 05-3474-23-3211-02: confirm-before-transmit abandons the payload.
#[test]
fn vector_early_confirm_aborts_05_3474_23_3211_02() {
    let mut pipe = TxPipeline::new();
    assert_eq!(pipe.authorize_transmit(), Ok(()));
    pipe.mark_confirmed();
    assert_eq!(pipe.authorize_transmit(), Err(NldeError::TransmitAborted));
    // Transmitted-then-confirmed is the normal order: no abort.
    let mut pipe2 = TxPipeline::new();
    pipe2.mark_transmitted();
    pipe2.mark_confirmed();
    assert_eq!(pipe2.authorize_transmit(), Ok(()));
}

// 05-3474-23-3213-01: indications only for locally addressed frames.
#[test]
fn vector_inbound_delivery_guard_05_3474_23_3213_01() {
    assert!(indication_for_local(0x0001, 0x0001, false));
    assert!(!indication_for_local(0x0002, 0x0001, false));
    assert!(indication_for_local(BROADCAST_ALL_DEVICES, 0x0001, true));
    assert!(!indication_for_local(BROADCAST_ALL_DEVICES, 0x0001, false));
    assert!(!indication_for_local(0x0002, 0x0001, true));
}

// 05-3474-23-34-01: NWK command headers suppress route discovery.
#[test]
fn vector_command_headers_suppress_discovery_05_3474_23_34_01() {
    let fc = FrameControl::command();
    assert_eq!(fc.frame_type, FrameType::Command);
    assert_eq!(fc.discover_route, DiscoverRoute::Suppress);
    assert_eq!(fc.protocol_version, 2);
}
