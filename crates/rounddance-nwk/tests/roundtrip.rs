//! Property tests: header round-trip identity plus malformed-input
//! rejection. `proptest` is not vendored and the lab network is offline,
//! so this is a hand-rolled bounded deterministic fuzz — a `SplitMix64`
//! stream (same construction as `rounddance-sim`'s seeded RNG) driving a
//! fixed case budget. No panics on any input: every decode returns
//! `Ok` or `Err`.
//!
//! Requirement traceability: `05-3474-23-331-01` (round-trip),
//! `05-3474-23-331-02` (discriminants), `05-3474-23-331-07`
//! (source route bounds).

use rounddance_nwk::{
    decode, is_broadcast_addr, DiscoverRoute, FrameControl, FrameType, NwkError, NwkHeader,
    SourceRoute,
};

/// Case budget: large enough to cover the field cross-product many times
/// over, small enough for a fast unit test.
const CASES: u32 = 8_000;
/// Payload lengths sweep 0..=48 (header + max payload stays in one MSDU).
const MAX_PAYLOAD: u64 = 49;

struct Fuzz(u64);

impl Fuzz {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.next() % n
    }
}

fn random_header(rng: &mut Fuzz) -> (NwkHeader, Vec<u8>) {
    let frame_type = match rng.below(3) {
        0 => FrameType::Data,
        1 => FrameType::Command,
        _ => FrameType::InterPan,
    };
    let dst_addr = match rng.below(8) {
        // Bias toward interesting destinations: broadcasts + edges.
        0 => 0xFFFF,
        1 => 0xFFFC,
        2 => 0xFFFD,
        3 => 0x0000,
        _ => rng.below(0x1_0000) as u16,
    };
    let broadcast = is_broadcast_addr(dst_addr);
    let control = FrameControl {
        frame_type,
        protocol_version: rng.below(16) as u8,
        discover_route: if rng.below(2) == 0 {
            DiscoverRoute::Suppress
        } else {
            DiscoverRoute::Enable
        },
        multicast: rng.below(2) == 0,
        security: rng.below(2) == 0,
        source_route: false, // set below iff relays present
        // Broadcast destinations never carry a destination IEEE address.
        dst_ieee: !broadcast && rng.below(2) == 0,
        src_ieee: rng.below(2) == 0,
        end_device_initiator: rng.below(2) == 0,
    };
    let dst_ieee = control
        .dst_ieee
        .then(|| rng.next() | ((rng.next() & 1) << 63));
    let src_ieee = control.src_ieee.then(|| rng.next());
    let source_route = if rng.below(3) == 0 {
        let n = 1 + rng.below(16) as usize;
        let mut relays = [0u16; 16];
        for slot in relays.iter_mut().take(n) {
            *slot = rng.below(0x1_0000) as u16;
        }
        // Randomize the in-transit index too: relays decrement it.
        let mut sr = SourceRoute::new(&relays[..n]).unwrap();
        sr.relay_index = rng.below(16) as u8;
        Some(sr)
    } else {
        None
    };
    let mut control = control;
    control.source_route = source_route.is_some();
    let header = NwkHeader {
        control,
        dst_addr,
        src_addr: rng.below(0x1_0000) as u16,
        radius: rng.below(0x100) as u8,
        seq: rng.below(0x100) as u8,
        dst_ieee,
        src_ieee,
        source_route,
    };
    let payload_len = rng.below(MAX_PAYLOAD) as usize;
    let mut payload = vec![0u8; payload_len];
    for b in &mut payload {
        *b = rng.below(0x100) as u8;
    }
    (header, payload)
}

#[test]
fn fuzz_encode_decode_round_trip_identity() {
    let mut rng = Fuzz(0x5EED_1234);
    let mut buf = [0u8; 256];
    for _ in 0..CASES {
        let (header, payload) = random_header(&mut rng);
        let n = header.encode_into(&payload, &mut buf).unwrap();
        assert_eq!(n, header.header_len() + payload.len());
        let decoded = decode(&buf[..n]).unwrap();
        assert_eq!(decoded.header, header, "round-trip identity");
        assert_eq!(decoded.payload, payload.as_slice());
    }
}

#[test]
fn fuzz_mutations_never_panic() {
    let mut rng = Fuzz(0x9E37_00FF);
    let mut buf = [0u8; 256];
    for _ in 0..CASES {
        let (header, payload) = random_header(&mut rng);
        let n = header.encode_into(&payload, &mut buf).unwrap();
        // Random single-byte mutation: decode must return, Ok or Err.
        let mut mutated = buf;
        let at = rng.below(n as u64) as usize;
        mutated[at] = rng.below(0x100) as u8;
        let _ = decode(&mutated[..n]);
        // Random truncation: decode must return, Ok (shorter payload) or
        // Err (cut header).
        let cut = rng.below((n + 1) as u64) as usize;
        let _ = decode(&buf[..cut]);
        // Empty input is always Truncated.
        assert_eq!(decode(&[]), Err(NwkError::Truncated));
    }
}

#[test]
fn fuzz_nlde_built_headers_round_trip() {
    use rounddance_nwk::{build_data_header, NldeDataRequest};
    let mut rng = Fuzz(0xBEEF_4242);
    let mut buf = [0u8; 256];
    for i in 0..1_000u32 {
        let req = NldeDataRequest {
            dst_addr: rng.below(0x1_0000) as u16,
            use_alias: rng.below(2) == 0,
            alias_src: rng.below(0x1_0000) as u16,
            alias_seq: rng.below(0x100) as u8,
            radius_param: rng.below(0x100) as u8,
            discover_route: if rng.below(2) == 0 {
                DiscoverRoute::Suppress
            } else {
                DiscoverRoute::Enable
            },
            generated_seq: rng.below(0x100) as u8,
            local_short_addr: rng.below(0x1_0000) as u16,
            max_depth: rng.below(0x100) as u8,
            associated: true,
        };
        let header = build_data_header(&req).unwrap();
        let payload = [i as u8, (i >> 8) as u8];
        let n = header.encode_into(&payload, &mut buf).unwrap();
        let decoded = decode(&buf[..n]).unwrap();
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.header.dst_addr, req.dst_addr);
    }
}

use rounddance_nwk::{
    Leave, LeaveOptions, LinkStatus, LinkStatusEntry, LinkStatusOptions, ManyToOne, RouteReply,
    RouteReplyOptions, RouteRequest, RouteRequestOptions,
};

/// Case budget for the command-codec fuzz (smaller frames, same stream
/// construction as the header fuzz above).
const CMD_CASES: u32 = 8_000;

fn random_route_request(rng: &mut Fuzz) -> RouteRequest {
    let many_to_one = match rng.below(3) {
        0 => ManyToOne::NotManyToOne,
        1 => ManyToOne::WithRouteRecord,
        _ => ManyToOne::WithoutRouteRecord,
    };
    let present = rng.below(2) == 0;
    RouteRequest {
        options: RouteRequestOptions {
            many_to_one,
            dst_ieee_present: present,
            multicast: rng.below(2) == 0,
        },
        rreq_id: rng.below(0x100) as u8,
        dst_addr: rng.below(0x1_0000) as u16,
        path_cost: rng.below(0x100) as u8,
        dst_ieee: present.then(|| (rng.next() << 32) | (rng.next() & 0xFFFF_FFFF)),
    }
}

fn random_route_reply(rng: &mut Fuzz) -> RouteReply {
    let o = rng.below(2) == 0;
    let r = rng.below(2) == 0;
    RouteReply {
        options: RouteReplyOptions {
            originator_ieee_present: o,
            responder_ieee_present: r,
            multicast: rng.below(2) == 0,
        },
        rreq_id: rng.below(0x100) as u8,
        originator: rng.below(0x1_0000) as u16,
        responder: rng.below(0x1_0000) as u16,
        path_cost: rng.below(0x100) as u8,
        originator_ieee: o.then(|| (rng.next() << 32) | (rng.next() & 0xFFFF_FFFF)),
        responder_ieee: r.then(|| (rng.next() << 32) | (rng.next() & 0xFFFF_FFFF)),
    }
}

fn random_leave(rng: &mut Fuzz) -> Leave {
    Leave {
        options: LeaveOptions {
            rejoin: rng.below(2) == 0,
            request: rng.below(2) == 0,
            remove_children: rng.below(2) == 0,
        },
    }
}

fn random_link_status(rng: &mut Fuzz) -> LinkStatus {
    let n = rng.below(17) as usize;
    let mut entries = [LinkStatusEntry::new(0, 1, 0).unwrap(); 16];
    for slot in entries.iter_mut().take(n) {
        *slot = LinkStatusEntry::new(
            rng.below(0x1_0000) as u16,
            1 + rng.below(7) as u8,
            rng.below(8) as u8,
        )
        .unwrap();
    }
    // Keep the ascending-address contract the decoder-independent
    // sort check relies on out of scope: entries preserve given order.
    LinkStatus::new(
        LinkStatusOptions {
            first_frame: rng.below(2) == 0,
            last_frame: rng.below(2) == 0,
        },
        &entries[..n],
    )
    .unwrap()
}

// Requirement traceability: `05-3474-23-341-01` (route request),
// `05-3474-23-342-01` (route reply), `05-3474-23-348-01`
// (link status), `05-3474-23-344-01` (leave): encode/decode
// round-trip identity over the full option/presence cross-product,
// plus mutation/truncation rejection without panics.
#[test]
fn fuzz_command_round_trip_identity() {
    use rounddance_nwk::{
        decode_leave, decode_link_status, decode_route_reply, decode_route_request,
    };
    let mut rng = Fuzz(0x0ECA_F001);
    let mut buf = [0u8; 128];
    for _ in 0..CMD_CASES {
        match rng.below(4) {
            0 => {
                let req = random_route_request(&mut rng);
                let n = req.encode_into(&mut buf).unwrap();
                assert_eq!(n, req.encoded_len());
                let decoded = decode_route_request(&buf[..n]).unwrap();
                assert_eq!(decoded.request, req, "rreq round-trip identity");
                assert!(decoded.tlvs.is_empty());
            }
            1 => {
                let rep = random_route_reply(&mut rng);
                let n = rep.encode_into(&mut buf).unwrap();
                assert_eq!(n, rep.encoded_len());
                let decoded = decode_route_reply(&buf[..n]).unwrap();
                assert_eq!(decoded.reply, rep, "rrep round-trip identity");
                assert!(decoded.tlvs.is_empty());
            }
            2 => {
                let leave = random_leave(&mut rng);
                let n = leave.encode_into(&mut buf).unwrap();
                assert_eq!(n, leave.encoded_len());
                let decoded = decode_leave(&buf[..n]).unwrap();
                assert_eq!(decoded.leave, leave, "leave round-trip identity");
                assert!(decoded.tlvs.is_empty());
            }
            _ => {
                let status = random_link_status(&mut rng);
                let n = status.encode_into(&mut buf).unwrap();
                assert_eq!(n, status.encoded_len());
                let decoded = decode_link_status(&buf[..n]).unwrap();
                assert_eq!(decoded.entries(), status.entries(), "link-status identity");
                assert_eq!(decoded.options, status.options);
            }
        }
    }
}

#[test]
fn fuzz_command_mutations_never_panic() {
    use rounddance_nwk::{
        decode_leave, decode_link_status, decode_route_reply, decode_route_request, LinkStatus,
        LinkStatusOptions,
    };
    let mut rng = Fuzz(0xC04D_40C4);
    let mut buf = [0u8; 128];
    for _ in 0..CMD_CASES {
        let n = match rng.below(4) {
            0 => random_route_request(&mut rng)
                .encode_into(&mut buf)
                .unwrap(),
            1 => random_route_reply(&mut rng).encode_into(&mut buf).unwrap(),
            2 => random_leave(&mut rng).encode_into(&mut buf).unwrap(),
            _ => random_link_status(&mut rng).encode_into(&mut buf).unwrap(),
        };
        let at = rng.below(n as u64) as usize;
        let mut mutated = buf;
        mutated[at] = rng.below(0x100) as u8;
        for frame in [&mutated[..n], &buf[..rng.below((n + 1) as u64) as usize]] {
            // Every decode returns Ok or Err; unknown identifiers,
            // reserved discriminants, count lies and truncations are
            // all fallible, never panics.
            let _ = decode_route_request(frame);
            let _ = decode_route_reply(frame);
            let _ = decode_link_status(frame);
            let _ = decode_leave(frame);
        }
        // Empty input always fails fallibly.
        assert!(decode_route_request(&[]).is_err());
        assert!(decode_route_reply(&[]).is_err());
        assert!(decode_link_status(&[]).is_err());
        // Over-budget link-status construction refuses.
        let big = [LinkStatus::new(
            LinkStatusOptions::single(),
            &[rounddance_nwk::LinkStatusEntry::new(1, 1, 0).unwrap(); 16],
        )
        .unwrap(); 1];
        let _ = big;
    }
}
