//! Property tests: codec round-trips plus state-machine input rejection.
//! Hand-rolled bounded deterministic fuzz — a `SplitMix64` stream driving
//! a fixed case budget (same construction as the NWK/APS/ZDO fuzz). No
//! panics on any input: every decode returns `Ok` or `Err`, and every
//! machine event is accepted or rejected without panicking.
//!
//! Requirement traceability: `22-65816-030-*` (frame codec + machine
//! rejection), `05-3474-23-32214-01`/`32215-01` +
//! `05-3474-23-36111-01`/`36113-01`/`3615-01` (join/leave rejection).

use rounddance_commission::*;

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

#[test]
fn fuzz_touchlink_frame_round_trip() {
    let mut rng = Fuzz(0x70C4);
    let mut buf = [0u8; MAX_TOUCHLINK_FRAME + 8];
    for _ in 0..CASES {
        let payload_len = rng.below((MAX_TOUCHLINK_PAYLOAD + 1) as u64) as usize;
        let mut payload = [0u8; MAX_TOUCHLINK_PAYLOAD];
        for slot in payload[..payload_len].iter_mut() {
            *slot = rng.below(0x100) as u8;
        }
        let frame = TouchlinkFrame::new(
            rng.next() as u32,
            rng.below(0x100) as u8,
            &payload[..payload_len],
        )
        .unwrap();
        let n = frame.encode_into(&mut buf).unwrap();
        let back = TouchlinkFrame::decode(&buf[..n]).unwrap();
        assert_eq!(back, frame);
    }
}

#[test]
fn fuzz_malformed_frames_never_panic() {
    let mut rng = Fuzz(0x7A6C);
    let mut buf = [0u8; 128];
    for _ in 0..CASES {
        let len = rng.below(129) as usize;
        for slot in buf[..len].iter_mut() {
            *slot = rng.below(0x100) as u8;
        }
        let _ = TouchlinkFrame::decode(&buf[..len]);
        let _ = ScanRequestPayload::decode(&buf[..len]);
        let _ = ChannelMask::from_list(&buf[..len.min(8)]);
        let _ = InstallCode::from_slice(&buf[..len.min(MAX_INSTALL_CODE_LEN)]);
    }
}

#[test]
fn fuzz_machines_reject_arbitrary_events() {
    let mut rng = Fuzz(0xBDB);
    for _ in 0..CASES {
        let pick = rng.below(6);
        match pick {
            0 => {
                let role = match rng.below(3) {
                    0 => LogicalType::Coordinator,
                    1 => LogicalType::Router,
                    _ => LogicalType::EndDevice,
                };
                let ch = rng.below(0x100) as u8;
                let cfg = FormationConfig {
                    role,
                    primary: ChannelMask::from_list(&[ch]).unwrap_or(ChannelMask::empty()),
                    secondary: ChannelMask::empty(),
                    scan_duration: rng.below(0x100) as u8,
                    pan: if rng.below(2) == 0 {
                        PanChoice::Auto
                    } else {
                        PanChoice::Fixed(rng.below(0x1_0000) as u16)
                    },
                    extended_pan: [0xCC; 8],
                    router_short_addr: rng.below(0x1_0000) as u16,
                };
                if let Ok(mut m) = FormationMachine::new(cfg) {
                    m.begin(rng.below(2) == 0, rng.below(2) == 0);
                    let pans = [rng.below(0x1_0000) as u16];
                    m.on_scan_complete(&FirstFreePan, rng.below(2) == 0, &pans);
                    let _ = m.primitive_params();
                    m.on_invoked();
                    m.on_confirm(rng.below(2) == 0);
                }
            }
            1 => {
                let mut m = SteeringMachine::new();
                let ch = rng.below(0x100) as u8;
                let mask = ChannelMask::from_list(&[ch]).unwrap_or(ChannelMask::empty());
                if m.begin_scan(mask, rng.below(0x100) as u8).is_ok() {
                    m.ingest(BeaconSurveyEntry {
                        pan_id: rng.below(0x1_0000) as u16,
                        channel: 11 + rng.below(16) as u8,
                        lqi: rng.below(0x100) as u8,
                        permit_joining: rng.below(2) == 0,
                        router_capacity: rng.below(2) == 0,
                        end_device_capacity: rng.below(2) == 0,
                        protocol_version: rng.below(4) as u8,
                    })
                    .ok();
                    if rng.below(2) == 0 {
                        m.on_scan_failed();
                    } else {
                        m.finish_scan(&BaselineSteeringPolicy {
                            min_lqi: rng.below(0x100) as u8,
                            min_version: rng.below(4) as u8,
                        });
                    }
                }
            }
            2 => {
                let mut t = FinderTarget::new();
                t.start(rng.below(2) == 0, rng.below(300) as u32).ok();
                let _ = t.answer_identify();
                for _ in 0..rng.below(5) {
                    t.tick_1s();
                }
                let mut init = FinderInitiator::new();
                init.begin(rng.below(2) == 0);
                init.note_answer(rng.below(0x1_0000) as u16, rng.below(0x100) as u8);
                init.finish_queries();
                init.resolve_ieee(
                    rng.below(0x1_0000) as u16,
                    rng.below(0x100) as u8,
                    rng.next(),
                );
                let r = Respondent {
                    nwk_addr: rng.below(0x1_0000) as u16,
                    endpoint: rng.below(0x100) as u8,
                    ieee: if rng.below(2) == 0 {
                        Some(rng.next())
                    } else {
                        None
                    },
                };
                let group = if rng.below(2) == 0 {
                    Some(rng.below(0x1_0000) as u16)
                } else {
                    None
                };
                let mut matched = [0u16; 4];
                let clusters = [0x0006u16, 0x0008];
                let supported = [0x0006u16, 0x0008, 0x0300];
                let _ = init.match_clusters(&clusters, &supported, &mut matched);
                let _ = init.bind_entry_for(
                    rng.below(0x100) as u8,
                    rng.next(),
                    rng.below(0x100) as u8,
                    &r,
                    0x0006,
                    group,
                );
                init.finish_binding();
            }
            3 => {
                let mut init = TouchlinkInitiator::new();
                init.begin_scan(rng.next() as u32).ok();
                let frame = init.scan_request(rng.below(0x100) as u8, rng.below(0x100) as u8);
                init.note_response(rng.below(2) == 0);
                init.proceed(rng.below(2) == 0).ok();
                init.finish(rng.below(2) == 0);
                let mut target = TouchlinkTarget::new();
                target.on_scan_request(&frame);
                target.on_response_sent();
                target.on_network_order(rng.below(2) == 0);
                target.finish(rng.below(2) == 0);
            }
            4 => {
                let method = match rng.below(5) {
                    0 => JoinMethod::PreconfiguredKey,
                    1 => JoinMethod::InstallCode,
                    2 => JoinMethod::Negotiation,
                    3 => JoinMethod::RejoinSecure,
                    _ => JoinMethod::RejoinUnsecured,
                };
                let policy = JoinPolicy {
                    cbke_supported: rng.below(2) == 0,
                    cbke_required: rng.below(2) == 0,
                    interview_tc: rng.below(2) == 0,
                    parent_is_r20_earlier: rng.below(2) == 0,
                };
                let mut j = JoinerMachine::new(method, policy);
                j.on_candidate();
                j.on_assoc_confirm(rng.below(2) == 0);
                j.on_key_transport(rng.below(2) == 0);
                j.on_verify_confirm(
                    rng.below(2) == 0,
                    if rng.below(2) == 0 {
                        KeyAttributes::SYMMETRIC
                    } else {
                        KeyAttributes::NEGOTIATED
                    },
                );
                j.on_negotiation_done(rng.below(2) == 0, rng.below(2) == 0);
                let _ = j.device_annce(
                    rng.below(0x100) as u8,
                    rng.below(0x1_0000) as u16,
                    rng.next(),
                );
                j.close_out(rng.below(2) == 0);
                let mut r = RejoinMachine::new(rng.below(2) == 0);
                r.begin();
                r.on_orphan_scan(rng.below(2) == 0);
                r.on_confirm(rng.below(2) == 0);
                let _ = LeaveMachine::mgmt_leave_for(
                    rng.below(0x100) as u8,
                    rng.next(),
                    rng.below(2) == 0,
                    rng.below(2) == 0,
                );
            }
            _ => {
                let mut tc = TrustCenter::new();
                if rng.below(2) == 0 {
                    tc.open();
                }
                let ieee = rng.next();
                let _ = tc.admit(
                    ieee,
                    rng.below(0x1_0000) as u16,
                    JoinMethod::PreconfiguredKey,
                    rng.below(10) as u32,
                );
                let _ = tc.exchange_key(ieee, &[0x11; 16], &[0x22; 16], 0x04);
                let _ = tc.on_verify_confirm(ieee, rng.below(2) == 0);
                let mut timed_out = [0u64; 2];
                let _ = tc.tick(&mut timed_out);
                let _ = tc.evict(ieee);
            }
        }
    }
}
