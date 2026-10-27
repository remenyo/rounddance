//! Property tests: attribute-codec round-trips plus machine input
//! rejection. Hand-rolled bounded deterministic fuzz — a
//! `SplitMix64` stream driving a fixed case budget (same
//! construction as the commission fuzz). No panics on any input:
//! every decode returns `Ok` or `Err`, and every machine event is
//! accepted or rejected without panicking.
//!
//! Requirement traceability: `20-27688-041-772-01` (TLV codec +
//! machine rejection), `20-27688-041-772-02` (key TLV codec),
//! `20-27688-041-76-01` (advertisement codec),
//! `20-27688-041-646-01` (counter discipline).

use rounddance_direct::attr::{decode_tlv, encode_tlv};
use rounddance_direct::*;

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
fn fuzz_tlv_round_trip() {
    let mut rng = Fuzz(0xD1EC7);
    let mut buf = [0u8; TLV_MAX_BODY + 8];
    for _ in 0..CASES {
        let tag = rng.below(256) as u8;
        let len = rng.below((TLV_MAX_BODY + 1) as u64) as usize;
        let mut body = [0u8; TLV_MAX_BODY];
        for b in body.iter_mut().take(len) {
            *b = rng.below(256) as u8;
        }
        let n = encode_tlv(tag, &body[..len], &mut buf).unwrap();
        let (tlv, used) = decode_tlv(&buf[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(tlv.tag, tag);
        assert_eq!(tlv.body, &body[..len]);
    }
}

#[test]
fn fuzz_tlv_decode_never_panics() {
    let mut rng = Fuzz(0x57A1);
    let mut buf = [0u8; 40];
    for _ in 0..CASES {
        let len = rng.below(41) as usize;
        for b in buf.iter_mut().take(len) {
            *b = rng.below(256) as u8;
        }
        let _ = decode_tlv(&buf[..len]);
        let _ = StatusReport::decode_body(&buf[..len]);
        let _ = LinkKeyTlv::decode_body(&buf[..len]);
        let _ = AdvExtension::decode(&buf[..len]);
        let _ = NetStatusMap(buf[0]).valid();
        let _ = JoinMethod::decode(buf[0]);
        let _ = DeviceType::decode(buf[0]);
    }
}

#[test]
fn fuzz_status_report_round_trip() {
    let mut rng = Fuzz(0x5747);
    let mut buf = [0u8; 8];
    for _ in 0..CASES {
        let domain = rng.below(8) as u8;
        let code = rng.below(256) as u8;
        let r = StatusReport { domain, code };
        let n = r.encode_into(&mut buf).unwrap();
        let (tlv, _) = decode_tlv(&buf[..n]).unwrap();
        let back = StatusReport::decode_body(tlv.body).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.is_success(), code == 0);
    }
}

#[test]
fn fuzz_adv_record_round_trip() {
    let mut rng = Fuzz(0xAD0);
    let mut buf = [0u8; ADV_RECORD_LEN];
    for _ in 0..CASES {
        let adv = AdvExtension {
            tunnel_supported: rng.below(2) == 1,
            permit_join: rng.below(2) == 1,
            pan_id: rng.below(0x1_0000) as u16,
            nwk_addr: rng.below(0x1_0000) as u16,
        };
        adv.encode_into(&mut buf).unwrap();
        let back = AdvExtension::decode(&buf).unwrap();
        assert_eq!(back.tunnel_supported, adv.tunnel_supported);
        assert_eq!(back.pan_id, adv.pan_id);
        assert_eq!(back.nwk_addr, adv.nwk_addr);
        // Permit-join survives only while joined.
        assert_eq!(back.permit_join, adv.permit_join && adv.joined());
    }
}

#[test]
fn fuzz_counters_reject_stale() {
    let mut rng = Fuzz(0xC047);
    let mut c = BleCounters::new();
    let mut accepted: u32 = 0;
    for _ in 0..CASES {
        let v = rng.below(0x1_0000_0000) as u32;
        if c.accept_rx(v).is_ok() {
            assert!(v >= accepted || accepted == 0);
            accepted = v.saturating_add(1);
        }
    }
    // Monotonic acceptance: replaying any earlier value is stale.
    if accepted > 1 {
        assert!(c.accept_rx(accepted - 2).is_err());
    }
}

#[test]
fn fuzz_machine_rejection() {
    let mut rng = Fuzz(0x9E97);
    let ops = [
        DirectOp::Form,
        DirectOp::PermitJoining,
        DirectOp::Join,
        DirectOp::Leave,
        DirectOp::UpdateKey,
        DirectOp::FindingBinding,
    ];
    let mut d = DirectCommission::new();
    for _ in 0..CASES {
        let op = ops[rng.below(6) as usize];
        // submit/complete/tick in arbitrary order: never panics,
        // every call returns a verdict.
        let _ = d.submit(op);
        d.tick_1s();
        if rng.below(2) == 0 {
            d.recover();
        }
        let mut notes = [StatusReport::success(StatusDomain::GENERAL); 4];
        let _ = d.take_notifications(&mut notes);
    }
}
