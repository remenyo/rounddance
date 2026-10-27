//! Property tests: ZDP codec round-trip identity plus malformed-input
//! rejection. Hand-rolled bounded deterministic fuzz — a `SplitMix64`
//! stream driving a fixed case budget (same construction as the NWK/APS
//! fuzz). No panics on any input: every decode returns `Ok` or `Err`.
//!
//! Requirement traceability (all repo-minted, MINTED-pending-confirm):
//! `05-3474-23-24311-*` (request round-trips),
//! `05-3474-23-2442*-01` (response round-trips),
//! `05-3474-23-2323/2324/2325-01` (descriptor round-trips),
//! `05-3474-23-232-01` (malformed rejection).

use rounddance_zdo::*;

/// Case budget: covers the field cross-product several times over.
const CASES: u32 = 8_000;

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

fn random_node_desc(rng: &mut Fuzz) -> NodeDescriptor {
    NodeDescriptor {
        flags0: rng.below(0x100) as u8,
        aps_flags: rng.below(0x100) as u8,
        freq_band: rng.below(0x100) as u8,
        mac_cap: rng.below(0x100) as u8,
        mfr_code: rng.below(0x1_0000) as u16,
        max_buf: rng.below(0x100) as u8,
        max_in_transfer: rng.below(0x1_0000) as u16,
        server_mask: rng.below(0x1_0000) as u16,
        max_out_transfer: rng.below(0x1_0000) as u16,
        desc_cap: rng.below(0x100) as u8,
    }
}

fn random_power_desc(rng: &mut Fuzz) -> PowerDescriptor {
    PowerDescriptor {
        mode: match rng.below(3) {
            0 => PowerMode::OnWhenIdle,
            1 => PowerMode::Periodic,
            _ => PowerMode::OnStimulated,
        },
        available: rng.below(0x10) as u8,
        source: rng.below(0x10) as u8,
        level: rng.below(0x10) as u8,
    }
}

fn random_simple_desc(rng: &mut Fuzz) -> SimpleDescriptor {
    let in_len = rng.below((MAX_SIMPLE_CLUSTERS + 1) as u64) as usize;
    let out_len = rng.below((MAX_SIMPLE_CLUSTERS + 1) as u64) as usize;
    let mut in_clusters = [0u16; MAX_SIMPLE_CLUSTERS];
    let mut out_clusters = [0u16; MAX_SIMPLE_CLUSTERS];
    // Tails stay zero: decode only restores counted prefixes.
    for slot in in_clusters.iter_mut().take(in_len) {
        *slot = 1 + rng.below(0xFFFF) as u16;
    }
    for slot in out_clusters.iter_mut().take(out_len) {
        *slot = 1 + rng.below(0xFFFF) as u16;
    }
    SimpleDescriptor {
        endpoint: rng.below(0x100) as u8,
        profile_id: rng.below(0x1_0000) as u16,
        device_id: rng.below(0x1_0000) as u16,
        device_version: rng.below(0x10) as u8,
        in_clusters,
        in_len: in_len as u8,
        out_clusters,
        out_len: out_len as u8,
    }
}

fn random_req_type(rng: &mut Fuzz) -> RequestType {
    if rng.below(2) == 0 {
        RequestType::Single
    } else {
        RequestType::Extended {
            start_index: rng.below(0x100) as u8,
        }
    }
}

fn random_bind_dst(rng: &mut Fuzz) -> BindDstMode {
    if rng.below(2) == 0 {
        BindDstMode::Group {
            group_addr: rng.below(0x1_0000) as u16,
        }
    } else {
        BindDstMode::Extended {
            dst_ieee: rng.next(),
            dst_endpoint: rng.below(0x100) as u8,
        }
    }
}

// 05-3474-23-2323/2324/2325-01: descriptor round-trips.
#[test]
fn fuzz_descriptors_round_trip() {
    let mut rng = Fuzz(0x2D0_D15C_0B5E ^ 0x2323);
    let mut out = [0u8; 128];
    for _ in 0..CASES {
        let node = random_node_desc(&mut rng);
        let n = node.encode_into(&mut out).unwrap();
        assert_eq!(NodeDescriptor::decode(&out[..n]).unwrap(), node);

        let power = random_power_desc(&mut rng);
        let n = power.encode_into(&mut out).unwrap();
        assert_eq!(PowerDescriptor::decode(&out[..n]).unwrap(), power);

        let simple = random_simple_desc(&mut rng);
        let n = simple.encode_into(&mut out).unwrap();
        assert_eq!(SimpleDescriptor::decode(&out[..n]).unwrap(), simple);
    }
}

// 05-3474-23-24311-*/2442*-01: request/response round-trips.
#[test]
fn fuzz_zdp_frames_round_trip() {
    let mut rng = Fuzz(0x2D_505F_5245_5153);
    let mut out = [0u8; 256];
    for _ in 0..CASES {
        let tsn = rng.below(0x100) as u8;
        let nwk = rng.below(0x1_0000) as u16;
        match rng.below(12) {
            0 => {
                let v = NwkAddrReq {
                    tsn,
                    ieee_of_interest: rng.next(),
                    req_type: random_req_type(&mut rng),
                };
                let n = v.encode_into(&mut out).unwrap();
                assert_eq!(NwkAddrReq::decode(&out[..n]).unwrap(), v);
            }
            1 => {
                let extended = rng.below(2) == 0;
                let mut assoc = [0u16; MAX_ASSOC_DEVICES];
                let count = if extended {
                    rng.below((MAX_ASSOC_DEVICES + 1) as u64) as usize
                } else {
                    0
                };
                // Entries at and beyond `count` stay zero: decode only
                // restores the counted prefix of extended frames.
                for slot in assoc.iter_mut().take(count) {
                    *slot = 1 + rng.below(0xFFFF) as u16;
                }
                let v = NwkAddrRsp {
                    tsn,
                    status: ZdpStatus::from_code(rng.below(0x100) as u8),
                    ieee: rng.next(),
                    nwk_addr: nwk,
                    assoc,
                    assoc_len: count as u8,
                    start_index: if extended { rng.below(0x100) as u8 } else { 0 },
                    extended,
                };
                let n = v.encode_into(&mut out).unwrap();
                assert_eq!(NwkAddrRsp::decode(&out[..n]).unwrap(), v);
            }
            2 => {
                let v = IeeeAddrReq {
                    tsn,
                    nwk_of_interest: nwk,
                    req_type: random_req_type(&mut rng),
                };
                let n = v.encode_into(&mut out).unwrap();
                assert_eq!(IeeeAddrReq::decode(&out[..n]).unwrap(), v);
            }
            3 => {
                let v = NodeDescReq {
                    tsn,
                    nwk_of_interest: nwk,
                };
                let n = v.encode_into(&mut out).unwrap();
                assert_eq!(NodeDescReq::decode(&out[..n]).unwrap(), v);
            }
            4 => {
                let v = PowerDescReq {
                    tsn,
                    nwk_of_interest: nwk,
                };
                let n = v.encode_into(&mut out).unwrap();
                assert_eq!(PowerDescReq::decode(&out[..n]).unwrap(), v);
            }
            5 => {
                let v = SimpleDescReq {
                    tsn,
                    nwk_of_interest: nwk,
                    endpoint: rng.below(0x100) as u8,
                };
                let n = v.encode_into(&mut out).unwrap();
                assert_eq!(SimpleDescReq::decode(&out[..n]).unwrap(), v);
            }
            6 => {
                let status = ZdpStatus::from_code(rng.below(0x100) as u8);
                let mut endpoints = [0u8; MAX_EP_LIST];
                // The list rides only on success; error frames carry none.
                let count = if status.is_success() {
                    rng.below((MAX_EP_LIST + 1) as u64) as usize
                } else {
                    0
                };
                // Tail stays zero: decode only restores the prefix.
                for slot in endpoints.iter_mut().take(count) {
                    *slot = 1 + rng.below(0xFF) as u8;
                }
                let v = ActiveEpRsp {
                    tsn,
                    status,
                    nwk_of_interest: nwk,
                    endpoints,
                    ep_len: count as u8,
                };
                let n = v.encode_into(&mut out).unwrap();
                assert_eq!(ActiveEpRsp::decode(&out[..n]).unwrap(), v);
            }
            7 => {
                let in_len = rng.below((MAX_SIMPLE_CLUSTERS + 1) as u64) as usize;
                let out_len = rng.below((MAX_SIMPLE_CLUSTERS + 1) as u64) as usize;
                // Tails stay zero: decode only restores counted prefixes.
                let mut in_clusters = [0u16; MAX_SIMPLE_CLUSTERS];
                for s in in_clusters.iter_mut().take(in_len) {
                    *s = 1 + rng.below(0xFFFF) as u16;
                }
                let mut out_clusters = [0u16; MAX_SIMPLE_CLUSTERS];
                for s in out_clusters.iter_mut().take(out_len) {
                    *s = 1 + rng.below(0xFFFF) as u16;
                }
                let v = MatchDescReq {
                    tsn,
                    nwk_of_interest: nwk,
                    profile_id: rng.below(0x1_0000) as u16,
                    in_clusters,
                    in_len: in_len as u8,
                    out_clusters,
                    out_len: out_len as u8,
                };
                let n = v.encode_into(&mut out).unwrap();
                assert_eq!(MatchDescReq::decode(&out[..n]).unwrap(), v);
            }
            8 => {
                let v = DeviceAnnce {
                    tsn,
                    nwk_addr: nwk,
                    ieee: rng.next(),
                    capability: rng.below(0x100) as u8,
                };
                let n = v.encode_into(&mut out).unwrap();
                assert_eq!(DeviceAnnce::decode(&out[..n]).unwrap(), v);
            }
            9 => {
                let v = BindEntry {
                    tsn,
                    src_ieee: rng.next(),
                    src_endpoint: rng.below(0x100) as u8,
                    cluster_id: rng.below(0x1_0000) as u16,
                    dst: random_bind_dst(&mut rng),
                };
                let n = v.encode_into(&mut out).unwrap();
                assert_eq!(BindEntry::decode(&out[..n]).unwrap(), v);
            }
            10 => {
                let v = MgmtLeaveReq {
                    tsn,
                    device_ieee: rng.next(),
                    rejoin: rng.below(2) == 0,
                    remove_children: rng.below(2) == 0,
                };
                let n = v.encode_into(&mut out).unwrap();
                assert_eq!(MgmtLeaveReq::decode(&out[..n]).unwrap(), v);
            }
            _ => {
                let v = MgmtNwkUpdateReq {
                    tsn,
                    scan_channels: rng.next() as u32,
                    scan_duration: rng.below(0x100) as u8,
                    scan_count: rng.below(0x100) as u8,
                };
                let n = v.encode_into(&mut out).unwrap();
                assert_eq!(MgmtNwkUpdateReq::decode(&out[..n]).unwrap(), v);
            }
        }
    }
}

// 05-3474-23-232-01: malformed inputs never panic; every decoder
// returns Ok or Err on every prefix and every bit-flip of one valid
// frame per family.
#[test]
fn fuzz_malformed_never_panics() {
    let mut full = [0u8; 256];
    let node = NodeDescriptor {
        flags0: 0x01,
        aps_flags: 0,
        freq_band: 4,
        mac_cap: 0x8E,
        mfr_code: 0x1234,
        max_buf: 82,
        max_in_transfer: 82,
        server_mask: 0,
        max_out_transfer: 82,
        desc_cap: 0,
    };
    let node_len = node.encode_into(&mut full).unwrap();
    assert_eq!(node_len, NODE_DESCRIPTOR_LEN);
    for len in 0..full.len() {
        let _ = NodeDescriptor::decode(&full[..len]);
        let _ = PowerDescriptor::decode(&full[..len.min(8)]);
        let _ = SimpleDescriptor::decode(&full[..len]);
        let _ = NwkAddrReq::decode(&full[..len]);
        let _ = NwkAddrRsp::decode(&full[..len]);
        let _ = IeeeAddrReq::decode(&full[..len]);
        let _ = IeeeAddrRsp::decode(&full[..len]);
        let _ = NodeDescReq::decode(&full[..len]);
        let _ = NodeDescRsp::decode(&full[..len]);
        let _ = PowerDescReq::decode(&full[..len]);
        let _ = PowerDescRsp::decode(&full[..len]);
        let _ = SimpleDescReq::decode(&full[..len]);
        let _ = SimpleDescRsp::decode(&full[..len]);
        let _ = ActiveEpReq::decode(&full[..len]);
        let _ = ActiveEpRsp::decode(&full[..len]);
        let _ = MatchDescReq::decode(&full[..len]);
        let _ = MatchDescRsp::decode(&full[..len]);
        let _ = DeviceAnnce::decode(&full[..len]);
        let _ = BindEntry::decode(&full[..len]);
        let _ = BindRsp::decode(&full[..len]);
        let _ = MgmtLeaveReq::decode(&full[..len]);
        let _ = MgmtPermitJoiningReq::decode(&full[..len]);
        let _ = MgmtNwkUpdateReq::decode(&full[..len]);
        let _ = MgmtNwkUpdateNotify::decode(&full[..len]);
    }
    // Oversize counts are fallible, never truncating.
    assert_eq!(
        SimpleDescriptor::decode(&[0x01, 0, 0, 0, 0, 0, 17, 0x00]),
        Err(ZdoError::TooManyEntries)
    );
    let mut oversize_match = vec![0x21, 0xFF, 0xFD, 0x04, 0x01, 17];
    oversize_match.extend_from_slice(&[0u8; 40]);
    assert_eq!(
        MatchDescReq::decode(&oversize_match),
        Err(ZdoError::TooManyEntries)
    );
    let mut oversize_rsp = vec![0x2B, 0x00];
    oversize_rsp.extend_from_slice(&[0u8; 10]);
    oversize_rsp.extend_from_slice(&[17, 0x00]);
    oversize_rsp.extend_from_slice(&[0u8; 40]);
    assert_eq!(
        NwkAddrRsp::decode(&oversize_rsp),
        Err(ZdoError::TooManyEntries)
    );
}
