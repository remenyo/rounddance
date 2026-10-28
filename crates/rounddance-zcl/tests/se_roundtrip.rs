//! Bounded deterministic fuzz for the SE + metering codecs: every
//! decode entry point must return `Ok` or `Err` on any input, never
//! panic.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `07-5123-08-1043-*` (metering profile codec),
//! `07-5123-08-1024-*` (price codecs), `07-5123-08-1074-*`
//! (key-establishment codecs), `07-5356-C41-02` (update-key path),
//! `07-5123-08-1046-*` (schedule codecs/table),
//! `07-5123-08-1047-*` (sampling codecs/engine),
//! `07-5123-08-1048-*` (supply codecs/machine),
//! `07-5123-08-1049-*` (notification-scheme codecs/engines).

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
        // Schedule/sampling/supply decoders never panic on any input.
        let _ = schedule::decode_schedule_entry(slice);
        let _ = schedule::decode_schedule_response(slice);
        let _ = sampling::decode_start_sampling(slice);
        let _ = sampling::decode_start_response(slice);
        let _ = sampling::decode_get_sampled_data(slice);
        let _ = sampling::decode_sampled_data_response(slice);
        let _ = supply::decode_change_supply(slice);
        let _ = supply::decode_supply_status_response(slice);
        let _ = supply::decode_local_change_supply(slice);
        let _ = supply::decode_set_supply_status(slice);
        let _ = supply::decode_flow_threshold(slice);
        let _ = supply::decode_reset_load_limit(slice);
        i += 1;
    }
}

// Ephemeral wire forms never panic: arbitrary 33-octet inputs are
// rejected or expand with the involution property; payload shapes
// report their own lengths (07-5123-08-1074-05).
#[test]
fn fuzz_compressed_ephemeral_shapes() {
    let mut fz = Fuzz(0x5EED_0800);
    let mut buf = [0u8; 64];
    let mut i = 0;
    while i < CASES {
        fz.fill(&mut buf);
        let mut c = [0u8; 33];
        c.copy_from_slice(&buf[..33]);
        if let Ok(p) = rounddance_security::decompress_point(&c) {
            assert_eq!(rounddance_security::compress_point(&p), c);
        }
        let e = keyest::EphemeralPayload::Expanded(buf);
        assert_eq!(e.len(), keyest::EPH_LEN);
        assert!(!e.is_compressed());
        assert_eq!(e.as_slice(), &buf[..]);
        let k = keyest::EphemeralPayload::Compressed(c);
        assert_eq!(k.len(), keyest::EPH_COMPRESSED_LEN);
        assert!(k.is_compressed());
        assert_eq!(k.as_slice(), &c[..]);
        i += 1;
    }
}

// Schedule tables + sampling engines + supply machines never panic
// on adversarial streams; tables stay bounded, confirms are exact,
// and encode/decode round-trips are fixed points.
#[test]
fn fuzz_schedule_sample_supply_stay_bounded() {
    let mut fz = Fuzz(0x5EED_1046);
    let mut buf = [0u8; 64];
    let mut i = 0;
    while i < CASES {
        fz.fill(&mut buf);
        let len = fz.below(65) as usize;
        let slice = &buf[..len];
        // Codecs round-trip when they accept.
        if let Ok(entry) = schedule::decode_schedule_entry(slice) {
            let mut wire = [0u8; schedule::SCHEDULE_ENTRY_LEN];
            assert_eq!(
                schedule::encode_schedule_entry(&entry, &mut wire),
                Ok(schedule::SCHEDULE_ENTRY_LEN)
            );
            assert_eq!(schedule::decode_schedule_entry(&wire), Ok(entry));
        }
        if let Ok(back) = schedule::decode_schedule_response(slice) {
            let mut wire = [0u8; 16];
            let pairs: [(u8, u8); schedule::MAX_SCHEDULE_CONFIRM] = back.confirmations;
            let n = schedule::encode_schedule_response(
                back.issuer,
                &pairs[..back.count as usize],
                &mut wire,
            )
            .unwrap();
            assert_eq!(
                schedule::decode_schedule_response(&wire[..n]).unwrap(),
                back
            );
        }
        if let Ok(req) = sampling::decode_start_sampling(slice) {
            let mut wire = [0u8; 13];
            assert_eq!(sampling::encode_start_sampling(&req, &mut wire), Ok(13));
            assert_eq!(sampling::decode_start_sampling(&wire), Ok(req));
        }
        if let Ok(req) = sampling::decode_get_sampled_data(slice) {
            let mut wire = [0u8; 9];
            assert_eq!(sampling::encode_get_sampled_data(&req, &mut wire), Ok(9));
            assert_eq!(sampling::decode_get_sampled_data(&wire), Ok(req));
        }
        if let Ok(req) = supply::decode_change_supply(slice) {
            let mut wire = [0u8; 18];
            assert_eq!(supply::encode_change_supply(&req, &mut wire), Ok(18));
            assert_eq!(supply::decode_change_supply(&wire), Ok(req));
        }
        // Table intake stays bounded and idempotent per issuer.
        let mut table = schedule::ScheduleTable::new();
        let mut k = 0;
        while k < 6 {
            let entry = schedule::ScheduleEntry {
                id: fz.next() as u8,
                start: fz.next() as u32,
                bitmap: fz.next() as u32,
                payload_type: fz.next() as u8,
                cause: fz.next() as u32,
            };
            let conf = table.intake(fz.next() as u32, &entry);
            assert!(conf <= schedule::SCHEDULE_CONF_INSUFFICIENT_SPACE);
            assert!(table.len() <= schedule::MAX_SCHEDULES);
            k += 1;
        }
        let mut due = [(0u32, 0u8); schedule::MAX_SCHEDULES];
        let n = table.collect_due(fz.next() as u32, &mut due);
        assert!(n <= schedule::MAX_SCHEDULES);
        // Engine open/push/query/tick never panic; sessions and
        // captures stay within their bounds.
        let mut eng = sampling::SampleEngine::new();
        let mut j = 0;
        while j < 4 {
            let req = sampling::StartSampling {
                issuer: fz.next() as u32,
                start: fz.next() as u32,
                sample_type: fz.next() as u8,
                interval_s: fz.next() as u16,
                max_samples: fz.next() as u16,
            };
            let _ = eng.open(&req, fz.next() as u32);
            assert!(eng.len() <= sampling::MAX_SESSIONS);
            let id = (fz.next() & 3) as u16;
            let _ = eng.push(id, fz.next() as u32, fz.next() as u32);
            let _ = eng.tick(fz.next() as u32);
            let q = sampling::GetSampledData {
                sample_id: id,
                earliest: fz.next() as u32,
                sample_type: fz.next() as u8,
                count: fz.next() as u16,
            };
            let mut values = [0u32; sampling::MAX_SAMPLES_PER_RESPONSE];
            if let Ok((_, _, _, count)) = eng.query(&q, &mut values) {
                assert!((count as usize) <= sampling::MAX_SAMPLES_PER_RESPONSE);
                let mut wire = [0u8; 64];
                let n = sampling::encode_sampled_data_response(
                    id,
                    0,
                    q.sample_type,
                    0,
                    &values[..count as usize],
                    &mut wire,
                )
                .unwrap();
                let back = sampling::decode_sampled_data_response(&wire[..n]).unwrap();
                assert_eq!(back.sample_values(), &values[..count as usize]);
            }
            j += 1;
        }
        // Supply machines serialize delayed commands and stay in
        // their typed states under any stream.
        let mut m = supply::SupplyMachine::new();
        let req = supply::ChangeSupply {
            provider: fz.next() as u32,
            issuer: fz.next() as u32,
            request_time: fz.next() as u32,
            impl_time: fz.next() as u32,
            proposed: fz.next() as u8,
            control: fz.next() as u8,
        };
        let now = fz.next() as u32;
        match m.apply_change(&req, now) {
            Ok(supply::SupplyOutcome::Applied { .. }) => {
                assert!(supply::supply_status_known(m.status()))
            }
            Ok(_) => {}
            Err(_) => {}
        }
        let _ = m.tick(now);
        let _ = m.apply_local(fz.next() as u8);
        let _ = m.apply_set_status(&supply::SetSupplyStatus {
            issuer: fz.next() as u32,
            tamper: fz.next() as u8,
            depletion: fz.next() as u8,
            uncontrolled: fz.next() as u8,
            load_limit: fz.next() as u8,
        });
        let _ = m.apply_event(match fz.next() & 3 {
            0 => supply::SupplyEvent::Tamper,
            1 => supply::SupplyEvent::Depletion,
            2 => supply::SupplyEvent::UncontrolledFlow,
            _ => supply::SupplyEvent::LoadLimit,
        });
        assert!(supply::supply_status_known(m.status()) || m.status() == supply::SUPPLY_UNCHANGED);
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

// Notification-scheme codecs and engines never panic on any input;
// the mirror engine stays bounded (queue, flags, configuration)
// and the meter-side record never plans a fetch it did not
// configure.
#[test]
fn fuzz_notify_stay_bounded() {
    let mut fz = Fuzz(0x5EED_1049);
    let mut eng = notify::MirrorNotify::new();
    let mut bomd = notify::BomdNotify::new();
    let mut i = 0;
    while i < CASES {
        // Random codec inputs: decoders return Ok or Err, never panic.
        let mut wire = [0u8; 64];
        fz.fill(&mut wire);
        let len = fz.below(65) as usize;
        let slice = &wire[..len];
        let _ = notify::decode_configure_mirror(slice);
        let _ = notify::decode_configure_scheme(slice);
        let mut flag_cfg = notify::ConfigureFlag::new(0, 0, 0);
        let _ = notify::decode_configure_flag(slice, &mut flag_cfg);
        let _ = notify::decode_get_notified(slice);
        // Random encodes of structured values: Ok or bounded Err.
        let mirror_cfg = notify::ConfigureMirror {
            issuer: fz.next() as u32,
            interval_s: fz.next() as u32,
            reporting: fz.next() & 1 == 0,
            scheme: fz.next() as u8,
        };
        let mut enc = [0u8; 9];
        let _ = notify::encode_configure_mirror(&mirror_cfg, &mut enc);
        let scheme_cfg = notify::ConfigureScheme {
            issuer: fz.next() as u32,
            scheme: fz.next() as u8,
            order: fz.next() as u32,
        };
        let _ = notify::encode_configure_scheme(&scheme_cfg, &mut enc);
        // Engine absorbs any configuration sequence; stays bounded.
        let _ = eng.apply_configure_mirror(&mirror_cfg);
        let _ = eng.apply_scheme(&scheme_cfg);
        if let Ok(flag) = flag_from_fuzz(&mut fz) {
            let _ = eng.apply_flag(&flag);
        }
        assert!(eng.pending_len() <= notify::MAX_PENDING);
        // Queue absorbs any originator/payload; fetch/expire are total.
        let origin = notify::Originator {
            src: fz.next(),
            endpoint: fz.next() as u8,
            tsn: fz.next() as u8,
            cluster: fz.next() as u16,
            cmd: fz.next() as u8,
        };
        let mut payload = [0u8; 32];
        fz.fill(&mut payload);
        let plen = fz.below(33) as usize;
        let _ = eng.cache(origin, &payload[..plen], fz.next());
        assert!(eng.pending_len() <= notify::MAX_PENDING);
        let msg = notify::GetNotifiedMessage {
            scheme: fz.next() as u8,
            flag_attr: (fz.next() & 0x0F) as u16,
            flags: fz.next() as u32,
        };
        let _ = eng.fetch(&msg);
        let _ = eng.raise((fz.next() & 0x0F) as u16, fz.next() as u32);
        let _ = eng.lower((fz.next() & 0x0F) as u16, fz.next() as u32);
        let mut expired = [origin; 4];
        let _ = eng.expire(fz.next(), fz.below(10_000), &mut expired);
        let words = eng.flag_words();
        let _ = words;
        // Meter side absorbs any report; planned fetches name the
        // configured scheme only.
        bomd.note_configured(&mirror_cfg);
        let mut rep = mirror::MirrorReport::new(fz.next() as u8);
        let _ = mirror::decode_mirror_report(slice, &mut rep);
        bomd.note_report(&rep);
        let mut plan = [notify::GetNotifiedMessage {
            scheme: 0,
            flag_attr: 0,
            flags: 0,
        }; 2];
        let n = bomd.plan_fetch(&mut plan);
        assert!(n <= 1);
        if n == 1 {
            assert_eq!(plan[0].scheme, bomd.scheme());
            let mut gw = [0u8; 7];
            assert_eq!(notify::encode_get_notified(&plan[0], &mut gw), Ok(7));
            assert_eq!(notify::decode_get_notified(&gw), Ok(plan[0]));
        }
        i += 1;
    }
}

fn flag_from_fuzz(fz: &mut Fuzz) -> Result<notify::ConfigureFlag, ()> {
    let mut cfg =
        notify::ConfigureFlag::new(fz.next() as u32, fz.next() as u8, (fz.next() & 0x0F) as u16);
    let recs = 1 + fz.below(notify::MAX_ALLOC_RECORDS as u64) as usize;
    let mut r = 0;
    while r < recs {
        let ncmds = 1 + fz.below(notify::MAX_ALLOC_CMDS as u64) as usize;
        let mut cmds = [0u8; notify::MAX_ALLOC_CMDS];
        let mut k = 0;
        while k < ncmds {
            cmds[k] = fz.next() as u8;
            k += 1;
        }
        cfg.allocs[r] = notify::FlagAlloc {
            cluster: fz.next() as u16,
            mfr: fz.next() as u16,
            cmds,
            cmd_count: ncmds as u8,
        };
        r += 1;
    }
    cfg.alloc_count = recs as u8;
    Ok(cfg)
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
