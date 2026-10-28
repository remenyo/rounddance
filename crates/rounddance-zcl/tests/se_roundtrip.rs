//! Bounded deterministic fuzz for the SE + metering codecs: every
//! decode entry point must return `Ok` or `Err` on any input, never
//! panic.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `07-5123-08-1043-*` (metering profile codec),
//! `07-5123-08-1024-*` (price codecs), `07-5123-08-1074-*`
//! (key-establishment codecs), `07-5356-C41-02` (update-key path).

use rounddance_security::{derive_update_mask, install_link_key, LinkKeyTable, MmoError};
use rounddance_zcl::*;

/// Case budget: covers the field cross-product several times over.
const CASES: u32 = 6_000;

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

    fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let v = self.next();
            let mut k = 0;
            while k < 8 && i + k < buf.len() {
                buf[i + k] = (v >> (8 * k)) as u8;
                k += 1;
            }
            i += 8;
        }
    }
}

// Metering + price + keyest decoders never panic on any input.
#[test]
fn fuzz_se_codecs_reject_without_panic() {
    let mut fz = Fuzz(0x5EED_0702);
    let mut buf = [0u8; 80];
    let mut i = 0;
    while i < CASES {
        fz.fill(&mut buf);
        let len = fz.below(81) as usize;
        let slice = &buf[..len];
        let _ = metering::decode_get_profile(slice);
        let mut pp = [0u8; 8];
        let _ = metering::encode_get_profile(
            &metering::GetProfileRequest {
                channel: fz.next() as u8,
                end_time: fz.next() as u32,
                periods: fz.next() as u8,
            },
            &mut pp,
        );
        let _ = price::decode_publish_price(slice);
        let _ = price::decode_get_scheduled(slice);
        let _ = price::decode_price_ack(slice);
        let mut slots = [price::TierLabelEntry {
            tier_id: 0,
            len: 0,
            label: [0; price::MAX_LABEL],
        }; 4];
        let _ = price::decode_publish_tier_labels(slice, &mut slots);
        let _ = keyest::decode_initiate(slice);
        let _ = keyest::decode_terminate(slice);
        // Mirror + snapshot decoders never panic on any input.
        let _ = mirror::decode_mirror_endpoint(slice);
        let _ = mirror::decode_empty_setup(slice);
        let mut rep = mirror::MirrorReport::new(0);
        let _ = mirror::decode_mirror_report(slice, &mut rep);
        let _ = snapshot::decode_take_snapshot(slice);
        let _ = snapshot::decode_take_snapshot_response(slice);
        let _ = snapshot::decode_get_snapshot(slice);
        let _ = snapshot::decode_publish_snapshot(slice);
        let _ = price::display_parts(fz.next() as u32, fz.next() as u8);
        i += 1;
    }
}

// Profile answers over random backlogs never panic; counts stay in
// bound and bodies stay well-formed.
#[test]
fn fuzz_profile_answer_stays_bounded() {
    let mut fz = Fuzz(0x5EED_1043);
    let mut i = 0;
    while i < CASES {
        let mut profile = metering::ProfileBuffer::new();
        let fills = fz.below(30) as usize;
        let mut k = 0;
        while k < fills {
            profile.record(fz.next() as u32, fz.next() as u32);
            k += 1;
        }
        let req = metering::GetProfileRequest {
            channel: fz.next() as u8,
            end_time: fz.next() as u32,
            periods: fz.next() as u8,
        };
        let mut out = [0u8; 64];
        if let Ok(n) = profile.answer(&req, &mut out) {
            assert!(n <= 7 + 3 * metering::MAX_RESPONSE_INTERVALS);
            assert!(n >= 7);
            assert_eq!(out[4], metering::PROFILE_STATUS_SUCCESS);
            assert!((out[6] as usize) <= metering::MAX_RESPONSE_INTERVALS);
        }
        i += 1;
    }
}

// Price table inserts over random events never panic; length stays
// within the backlog bound.
#[test]
fn fuzz_price_table_stays_bounded() {
    let mut fz = Fuzz(0x5EED_1024);
    let mut table = price::PriceTable::new();
    let mut i = 0;
    while i < CASES {
        let mut label = [0u8; price::MAX_LABEL];
        let llen = fz.below(13) as usize;
        let mut b = 0;
        while b < llen {
            label[b] = fz.next() as u8;
            b += 1;
        }
        table.insert(price::PublishPrice {
            provider_id: fz.next() as u32,
            rate_len: llen as u8,
            rate_label: label,
            issuer_event_id: fz.next() as u32,
            current_time: fz.next() as u32,
            unit_of_measure: fz.next() as u8,
            currency: fz.next() as u16,
            trailing_tier: fz.next() as u8,
            tiers_register: fz.next() as u8,
            start_time: fz.next() as u32,
            duration_min: fz.next() as u16,
            price: fz.next() as u32,
        });
        assert!(table.len() <= price::MAX_PRICE_EVENTS);
        let _ = table.current(fz.next() as u32);
        let _ = table.first_ending_after(fz.next() as u32);
        i += 1;
    }
}

// Block-period + threshold codecs never panic; round-trips are
// exact and tables stay bounded.
#[test]
fn fuzz_block_codecs_stay_bounded() {
    let mut fz = Fuzz(0x5EED_1025);
    let mut buf = [0u8; 400];
    let mut table = price::BlockTable::new();
    let mut thresholds = price::ThresholdStore::new();
    let mut i = 0;
    while i < CASES {
        fz.fill(&mut buf);
        let len = fz.below(401) as usize;
        let slice = &buf[..len];
        let _ = price::decode_publish_block_period(slice);
        let _ = price::decode_get_block_periods(slice);
        let _ = price::decode_publish_block_thresholds(slice);
        let ev = price::BlockPeriod {
            provider_id: fz.next() as u32,
            issuer_event_id: fz.next() as u32,
            start_time: fz.next() as u32,
            duration: (fz.next() & 0x00ff_ffff) as u32,
            control: fz.next() as u8,
            duration_type: (fz.next() & 0x23) as u8,
            tariff_type: fz.next() as u8,
            tariff_resolution: fz.next() as u8,
        };
        let mut wire = [0u8; 19];
        assert_eq!(price::encode_publish_block_period(&ev, &mut wire), Ok(19));
        assert_eq!(price::decode_publish_block_period(&wire), Ok(ev));
        table.insert(ev);
        assert!(table.len() <= price::MAX_BLOCK_PERIODS);
        let mut hits = [ev; price::MAX_BLOCK_PERIODS];
        let n = table.scheduled_since(
            fz.next() as u32,
            fz.next() as u8,
            if fz.next() & 1 == 0 {
                None
            } else {
                Some(fz.next() as u8)
            },
            &mut hits,
        );
        assert!(n <= price::MAX_BLOCK_PERIODS);
        let _ = table.mirror_for(fz.next() as u32);
        if let Ok(msg) = price::decode_publish_block_thresholds(slice) {
            // Decoded-then-encoded-then-decoded is a fixed point.
            let mut wire2 = [0u8; 400];
            if let Ok(n2) = price::encode_publish_block_thresholds(&msg, &mut wire2) {
                let rt = price::decode_publish_block_thresholds(&wire2[..n2]).unwrap();
                assert_eq!(rt.set_count, msg.set_count);
                assert_eq!(
                    rt.sets[..rt.set_count as usize],
                    msg.sets[..msg.set_count as usize]
                );
            }
            thresholds.insert(&msg);
            let _ = thresholds.for_tariff(msg.issuer_tariff_id);
        }
        let _ = price::threshold_count_for_tariff(fz.next() & 1 == 0, fz.next() as u8);
        let _ = price::scaled_threshold(fz.next(), fz.next(), fz.next());
        i += 1;
    }
}

// Mirror table + snapshot store never panic; tables stay bounded,
// grants stay idempotent, encodes round-trip.
#[test]
fn fuzz_mirror_snapshot_stay_bounded() {
    let mut fz = Fuzz(0x5EED_1044);
    let mut table = mirror::MirrorTable::new();
    let mut store = snapshot::SnapshotStore::new();
    let mut sub = [0u8; snapshot::MAX_SNAPSHOT_SUB];
    let mut i = 0;
    while i < CASES {
        let meter = fz.next();
        let ep = table.request(meter);
        assert!(table.len() <= mirror::MAX_MIRRORS);
        if ep != mirror::ENDPOINT_REFUSED {
            assert!(mirror::endpoint_is_grantable(ep));
            assert_eq!(table.endpoint_for(meter), Some(ep));
            assert!(table.may_push(ep, meter).is_ok());
            assert_eq!(
                table.may_push(ep, meter.wrapping_add(1)),
                Err(ZclStatus::NotAuthorized)
            );
            // Idempotent re-request keeps the same endpoint.
            assert_eq!(table.request(meter), ep);
            // Release by owner or ESI; strangers are refused.
            if fz.next() & 1 == 0 {
                if fz.next() & 1 == 0 {
                    assert_eq!(
                        table.remove(ep, mirror::ReleaseRequester::Meter(meter)),
                        Ok(ep)
                    );
                    assert_eq!(table.endpoint_for(meter), None);
                } else {
                    assert_eq!(table.remove(ep, mirror::ReleaseRequester::Esi), Ok(ep));
                }
            } else {
                assert_eq!(
                    table.remove(ep, mirror::ReleaseRequester::Meter(meter.wrapping_add(1))),
                    Err(ZclStatus::NotAuthorized)
                );
            }
        } else {
            assert!(!table.has_capacity());
        }
        // Snapshot takes over random causes/subs; queries stay sound.
        fz.fill(&mut sub);
        let sub_len = fz.below((snapshot::MAX_SNAPSHOT_SUB + 1) as u64) as usize;
        let cause = fz.next() as u32;
        let (id, conf) = store.take(fz.next() as u32, cause, fz.next() as u8, &sub[..sub_len]);
        assert!(store.len() <= snapshot::MAX_SNAPSHOTS);
        if conf == snapshot::CONFIRM_ACCEPTED {
            if let Ok(got) = store.query(0, 0xFFFF_FFFF, 0, snapshot::CAUSE_ALL) {
                assert!(got.id <= id);
                // Encode-then-decode of a publish round-trips.
                let hdr = snapshot::PublishSnapshot {
                    snapshot_id: got.id,
                    snapshot_time: got.time,
                    total_found: 1,
                    command_index: 0,
                    total_commands: 1,
                    cause: got.cause,
                    payload_type: got.payload_type,
                };
                let mut wire = [0u8; 64];
                let n =
                    snapshot::encode_publish_snapshot(&hdr, got.sub_payload(), &mut wire).unwrap();
                let back = snapshot::decode_publish_snapshot(&wire[..n]).unwrap();
                assert_eq!(back.header, hdr);
                assert_eq!(back.sub_payload(), got.sub_payload());
            }
        } else {
            assert_eq!(conf, snapshot::CONFIRM_CAUSE_NOT_SUPPORTED);
        }
        // Meter-side record absorbs any response shape.
        let mut client = mirror::MirrorClient::new();
        let _ = client.on_response(fz.next() as u16);
        client.on_removed(fz.next() as u16);
        i += 1;
    }
}

// Update-mask derivation and table install never panic; masks stay
// deterministic per (ieee, nonce).
#[test]
fn fuzz_update_key_path_never_panics() {
    let mut fz = Fuzz(0x5EED_C420);
    let mut table = LinkKeyTable::<4>::new();
    let mut i = 0;
    while i < CASES {
        let mut ieee = [0u8; 8];
        ieee.copy_from_slice(&fz.next().to_le_bytes());
        let nonce = fz.next() as u32;
        let m1 = derive_update_mask(&ieee, nonce);
        let m2 = derive_update_mask(&ieee, nonce);
        assert_eq!(m1, m2);
        assert!(m1.is_ok() || m1 == Err(MmoError::TooLong));
        let mut key = [0u8; 16];
        fz.fill(&mut key);
        let _ = install_link_key(&mut table, ieee, key);
        let _ = table.find(&ieee).map(|e| e.key);
        i += 1;
    }
}
