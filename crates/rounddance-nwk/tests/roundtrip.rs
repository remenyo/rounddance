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
