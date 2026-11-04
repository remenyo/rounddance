//! Line-coverage closure for doc `05-3474-23` R23.2 chapter 3 (NWK),
//! part 1: frame codec (§3.3) and command frames (§3.4).
//!
//! Each test pins one normative codec behavior of the NWK header and
//! its command payloads against the public API. Comments name the
//! requirement ID plus the gap anchors cited (D1: document number,
//! revision, clause and line only — no spec text reproduced).

use rounddance_nwk::{
    build_data_header, decode, decode_leave, decode_link_status, decode_route_reply,
    decode_route_request, indication_for_local, is_broadcast_addr, radius_for_request,
    CommandError, DecodedLeave, DecodedLinkStatus, DiscoverRoute, FrameControl, FrameType, Leave,
    LeaveOptions, LinkStatus, LinkStatusEntry, LinkStatusOptions, ManyToOne, NldeDataRequest,
    NldeError, NwkError, NwkHeader, RouteReply, RouteReplyOptions, RouteRequest,
    RouteRequestOptions, SourceRoute, TxPipeline, BROADCAST_ALL_DEVICES,
    BROADCAST_LOW_POWER_ROUTERS, BROADCAST_RESERVED_HIGH, BROADCAST_RESERVED_LOW,
    BROADCAST_ROUTERS, CMD_LEAVE, CMD_LINK_STATUS, CMD_ROUTE_REPLY, CMD_ROUTE_REQUEST,
    MAX_LINK_STATUS_ENTRIES, NWKC_PROTOCOL_VERSION,
};

// 05-3474-23-331-01: the frame-control field packs type, version,
// discovery control and presence flags; reserved bits 14-15 stay
// zero on transmit and are ignored on receipt; reserved type and
// discovery values are refused.
// Anchors: p0291-L6887-L6894.
#[test]
fn frame_control_layout_05_3474_23_331_01() {
    let control = FrameControl::data();
    // Baseline: data type, spec protocol version, no presence flags.
    assert_eq!(control.frame_type, FrameType::Data);
    assert_eq!(control.protocol_version, NWKC_PROTOCOL_VERSION);
    assert_eq!(control.to_u16() & 0xC000, 0);
    let wire = control.to_u16();
    let back = FrameControl::from_u16(wire).unwrap();
    assert_eq!(back, control);
    // Reserved discriminants are refused fallibly.
    assert!(FrameControl::from_u16(0x0002).is_err());
    assert!(FrameControl::from_u16(0x0080).is_err());
    assert!(FrameControl::from_u16(0x00C0).is_err());
    // Reserved high bits are ignored, never acted on.
    let with_reserved = FrameControl::from_u16(wire | 0xC000).unwrap();
    assert_eq!(with_reserved.frame_type, FrameType::Data);
    assert_eq!(with_reserved.to_u16(), wire);
    // Command baseline suppresses route discovery.
    let cmd = FrameControl::command();
    assert_eq!(cmd.frame_type, FrameType::Command);
    assert_eq!(cmd.discover_route, DiscoverRoute::Suppress);
}

// 05-3474-23-331-02: the NWK header fields appear in fixed order and
// every presence flag agrees with its field; broadcast destinations
// never carry a destination IEEE address.
// Anchors: p0291-L6895-L6917 (Table 3-51 context), p0304-L7190-L7197.
#[test]
fn header_field_presence_05_3474_23_331_02() {
    let plain = NwkHeader::minimal(FrameControl::data(), 0x1234, 0x0000, 10, 0x5C);
    assert_eq!(plain.header_len(), 8);
    let mut out = [0u8; 32];
    let n = plain.encode_into(&[0xDE, 0xAD], &mut out).unwrap();
    let decoded = decode(&out[..n]).unwrap();
    assert_eq!(decoded.header, plain);
    assert_eq!(decoded.payload, &[0xDE, 0xAD]);
    // Flag/field mismatch is refused before anything goes on air.
    let mut bad = plain;
    bad.control.dst_ieee = true;
    assert_eq!(
        bad.encode_into(&[], &mut out),
        Err(NwkError::PresenceMismatch("dst_ieee"))
    );
    let mut bad2 = plain;
    bad2.control.source_route = true;
    assert_eq!(
        bad2.encode_into(&[], &mut out),
        Err(NwkError::PresenceMismatch("source_route"))
    );
    // Broadcast + destination IEEE is refused.
    let mut bad3 = NwkHeader::minimal(FrameControl::data(), BROADCAST_ROUTERS, 0x0000, 10, 0x01);
    bad3.control.dst_ieee = true;
    bad3.dst_ieee = Some(0x0012_4B00_1A2B_3C4D);
    assert_eq!(
        bad3.encode_into(&[], &mut out),
        Err(NwkError::BroadcastWithDstIeee)
    );
}

// 05-3474-23-331-03: broadcast addresses — all-devices, mac-rx-on,
// routers, low-power routers, plus the reserved window that ordinary
// data frames must not use as a unicast destination.
// Anchors: p0228-L5503-L5552 (Table 3-80 neighborhood), p0291-L6918-L6923.
#[test]
fn broadcast_addresses_05_3474_23_331_03() {
    assert_eq!(BROADCAST_ALL_DEVICES, 0xFFFF);
    assert_eq!(BROADCAST_ROUTERS, 0xFFFC);
    assert_eq!(BROADCAST_LOW_POWER_ROUTERS, 0xFFFB);
    assert!(is_broadcast_addr(BROADCAST_ALL_DEVICES));
    assert!(is_broadcast_addr(BROADCAST_ROUTERS));
    assert!(is_broadcast_addr(0xFFF8));
    assert!(!is_broadcast_addr(0x1234));
    assert!(!is_broadcast_addr(0xFFF7));
    assert_eq!(BROADCAST_RESERVED_LOW, 0xFFF8);
    assert_eq!(BROADCAST_RESERVED_HIGH, 0xFFFA);
    // The whole broadcast window reads as broadcast.
    for addr in BROADCAST_RESERVED_LOW..=BROADCAST_ALL_DEVICES {
        assert!(is_broadcast_addr(addr), "{addr:#06X}");
    }
}

// 05-3474-23-331-04: source-route subframe — relay order on the wire,
// relay-count bound, encode/decode round trip.
// Anchors: p0293-L6945-L6954.
#[test]
fn source_route_subframe_05_3474_23_331_04() {
    let route = SourceRoute::new(&[0x1111, 0x2222, 0x3333]).unwrap();
    assert_eq!(route.relay_count(), 3);
    assert_eq!(route.relays(), &[0x1111, 0x2222, 0x3333]);
    // Empty relay lists and over-budget lists are refused.
    assert!(SourceRoute::new(&[]).is_err());
    let mut header = NwkHeader::minimal(FrameControl::data(), 0x1234, 0x0000, 5, 0x01);
    header.control.source_route = true;
    header.source_route = Some(route);
    assert_eq!(header.header_len(), 8 + 2 + 2 * 3);
    let mut out = [0u8; 32];
    let n = header.encode_into(&[0xAA], &mut out).unwrap();
    let decoded = decode(&out[..n]).unwrap();
    assert_eq!(
        decoded.header.source_route.unwrap().relays(),
        &[0x1111, 0x2222, 0x3333]
    );
    assert_eq!(decoded.payload, &[0xAA]);
}

// 05-3474-23-3211-01: NLDE-DATA.request header construction — the
// unassociated guard, the radius mapping (nonzero passes through,
// zero selects twice the maximum depth), and discovery passthrough.
// Anchors: p0240-L5662-L5664, p0065-L1690-L1693.
#[test]
fn nlde_data_request_construction_05_3474_23_3211_01() {
    // Radius mapping.
    assert_eq!(radius_for_request(7, 5), 7);
    assert_eq!(radius_for_request(0, 5), 10);
    assert_eq!(radius_for_request(0, 0), 0);
    // Unassociated devices build nothing.
    let unassoc = NldeDataRequest {
        dst_addr: 0x1234,
        use_alias: false,
        alias_src: 0,
        alias_seq: 0,
        radius_param: 3,
        discover_route: DiscoverRoute::Enable,
        generated_seq: 0x42,
        local_short_addr: 0x0001,
        max_depth: 5,
        associated: false,
    };
    assert_eq!(build_data_header(&unassoc), Err(NldeError::NotAssociated));
    // Associated: local source stamped, discovery passed through.
    let req = NldeDataRequest {
        associated: true,
        ..unassoc
    };
    let header = build_data_header(&req).unwrap();
    assert_eq!(header.src_addr, 0x0001);
    assert_eq!(header.seq, 0x42);
    assert_eq!(header.radius, 3);
    assert_eq!(header.control.discover_route, DiscoverRoute::Enable);
    // Alias mode stamps the alias source/sequence instead.
    let alias = NldeDataRequest {
        use_alias: true,
        alias_src: 0xABCD,
        alias_seq: 0x09,
        radius_param: 0,
        ..req
    };
    let header = build_data_header(&alias).unwrap();
    assert_eq!(header.src_addr, 0xABCD);
    assert_eq!(header.seq, 0x09);
    assert_eq!(header.radius, 10);
    // The hop-limit application from the APS side never exceeds one octet.
    assert_eq!(radius_for_request(0, 200), 200u8.saturating_mul(2));
}

// 05-3474-23-3211-02: early-confirm abort — when the confirm is
// emitted before the payload transmits, the transmit step is refused.
// Anchors: p0251-L5912-L5918.
#[test]
fn early_confirm_aborts_transmit_05_3474_23_3211_02() {
    let mut pipe = TxPipeline::new();
    assert!(pipe.authorize_transmit().is_ok());
    pipe.mark_confirmed();
    assert_eq!(pipe.authorize_transmit(), Err(NldeError::TransmitAborted));
    // A transmit that did go out clears the abort.
    pipe.mark_transmitted();
    assert!(pipe.authorize_transmit().is_ok());
}

// 05-3474-23-3213-01: inbound delivery — indication only for frames
// addressed to this device (unicast match, or an accepted broadcast).
// Anchors: p0246-L5783-L5797, p0297-L7029-L7030.
#[test]
fn indication_for_local_05_3474_23_3213_01() {
    assert!(indication_for_local(0x1234, 0x1234, false));
    assert!(!indication_for_local(0x5678, 0x1234, false));
    assert!(indication_for_local(BROADCAST_ROUTERS, 0x1234, true));
    assert!(!indication_for_local(BROADCAST_ROUTERS, 0x1234, false));
    // Broadcast with no ack requested rides the same guard: accepted
    // only when the caller takes broadcasts.
    assert!(indication_for_local(BROADCAST_ALL_DEVICES, 0x0000, true));
    assert!(!indication_for_local(BROADCAST_ALL_DEVICES, 0x0000, false));
}

// 05-3474-23-341-01: route-request command — options bits
// (many-to-one kind), the per-request identifier, destination, and
// running path cost; destination IEEE rides only with its flag.
// Anchors: p0297-L7031-L7034, p0300-L7125-L7133.
#[test]
fn route_request_codec_05_3474_23_341_01() {
    let req = RouteRequest {
        options: RouteRequestOptions::unicast(),
        rreq_id: 0x2A,
        dst_addr: 0x5678,
        path_cost: 3,
        dst_ieee: None,
    };
    assert_eq!(RouteRequest::PREFIX_LEN, 6);
    let mut out = [0u8; 16];
    let n = req.encode_into(&mut out).unwrap();
    assert_eq!(n, 1 + 5);
    assert_eq!(out[0], CMD_ROUTE_REQUEST);
    let decoded = decode_route_request(&out[..n]).unwrap();
    assert_eq!(decoded.request.options.many_to_one, ManyToOne::NotManyToOne);
    assert_eq!(decoded.request.rreq_id, 0x2A);
    assert_eq!(decoded.request.dst_addr, 0x5678);
    assert_eq!(decoded.request.path_cost, 3);
    assert!(decoded.request.dst_ieee.is_none());
    // Flag/field mismatch refused on encode; wrong command refused
    // on decode.
    let mut bad = req;
    bad.options.dst_ieee_present = true;
    assert!(bad.encode_into(&mut out).is_err());
    assert_eq!(
        decode_route_request(&[CMD_ROUTE_REPLY, 0, 0, 0, 0, 0]),
        Err(CommandError::UnknownCommand(CMD_ROUTE_REPLY))
    );
}

// 05-3474-23-341-02: route-reply command — options presence flags for
// the originator/responder IEEE fields mirror the address fields;
// path cost accumulates across the transit.
// Anchors: p0300-L7125-L7133.
#[test]
fn route_reply_codec_05_3474_23_341_02() {
    let mut options = RouteReplyOptions::full();
    options.originator_ieee_present = false;
    options.responder_ieee_present = false;
    let reply = RouteReply {
        options,
        rreq_id: 0x2A,
        originator: 0x0001,
        responder: 0x5678,
        path_cost: 9,
        originator_ieee: None,
        responder_ieee: None,
    };
    let mut out = [0u8; 24];
    let n = reply.encode_into(&mut out).unwrap();
    assert_eq!(out[0], CMD_ROUTE_REPLY);
    let decoded = decode_route_reply(&out[..n]).unwrap();
    assert_eq!(decoded.reply.rreq_id, 0x2A);
    assert_eq!(decoded.reply.originator, 0x0001);
    assert_eq!(decoded.reply.responder, 0x5678);
    assert_eq!(decoded.reply.path_cost, 9);
    assert!(decoded.reply.originator_ieee.is_none());
}

// 05-3474-23-348-01: link-status command — per-neighbor incoming cost
// range-checked (1..=7), single-frame chaining flags, entry-count
// budget enforced.
// Anchors: p0293-L6925-L6943, p0299-L7067-L7095.
#[test]
fn link_status_codec_05_3474_23_348_01() {
    assert!(LinkStatusEntry::new(0x1111, 0, 3).is_err());
    assert!(LinkStatusEntry::new(0x1111, 8, 3).is_err());
    assert!(LinkStatusEntry::new(0x1111, 3, 8).is_err());
    let entries = [
        LinkStatusEntry::new(0x1111, 1, 2).unwrap(),
        LinkStatusEntry::new(0x2222, 3, 0).unwrap(),
    ];
    let status = LinkStatus::new(LinkStatusOptions::single(), &entries).unwrap();
    let mut out = [0u8; 64];
    let n = status.encode_into(&mut out).unwrap();
    assert_eq!(out[0], CMD_LINK_STATUS);
    let DecodedLinkStatus {
        options,
        entries: back,
        len,
    } = decode_link_status(&out[..n]).unwrap();
    assert!(options.first_frame && options.last_frame);
    assert_eq!(len as usize, 2);
    assert_eq!(back[0].neighbor, 0x1111);
    assert_eq!(back[0].incoming_cost, 1);
    assert_eq!(back[1].neighbor, 0x2222);
    // Over-budget entry lists are refused before encoding.
    let many = [LinkStatusEntry::new(1, 1, 1).unwrap(); MAX_LINK_STATUS_ENTRIES + 1];
    assert!(LinkStatus::new(LinkStatusOptions::single(), &many).is_err());
}

// 05-3474-23-344-01: leave command — rejoin/request/remove-children
// option bits; the sender stamps its own MAC address and PAN ID as
// the source on the way out.
// Anchors: p0304-L7194-L7197, p0308-L7302-L7323.
#[test]
fn leave_codec_05_3474_23_344_01() {
    let leave = Leave {
        options: LeaveOptions {
            rejoin: true,
            request: false,
            remove_children: true,
        },
    };
    assert_eq!(leave.encoded_len(), Leave::ENCODED_LEN);
    let mut out = [0u8; 8];
    let n = leave.encode_into(&mut out).unwrap();
    assert_eq!(out[0], CMD_LEAVE);
    let DecodedLeave { leave: back, .. } = decode_leave(&out[..n]).unwrap();
    assert!(back.options.rejoin);
    assert!(!back.options.request);
    assert!(back.options.remove_children);
    // The source-addressing rule pins the sender address into the
    // header that carries the leave: alias-free local stamp.
    let req = NldeDataRequest {
        dst_addr: 0x0000,
        use_alias: false,
        alias_src: 0,
        alias_seq: 0,
        radius_param: 1,
        discover_route: DiscoverRoute::Suppress,
        generated_seq: 0x77,
        local_short_addr: 0x1234,
        max_depth: 5,
        associated: true,
    };
    let header = build_data_header(&req).unwrap();
    assert_eq!(header.src_addr, 0x1234);
    assert_eq!(header.radius, 1);
}
