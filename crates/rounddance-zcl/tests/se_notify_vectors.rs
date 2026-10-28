//! Wire vectors for the metering notification-scheme machinery
//! (cluster 0x0702, server commands `0x08..=0x0B`).
//!
//! Each test names the requirement ID it verifies. Byte strings are
//! hand-computed from the paraphrased layouts in `notify.rs` (docs
//! `07-5123-08` §10.4) — never copied from spec text (D1,
//! `SCOPE.md` §2). Repo-minted IDs are MINTED-pending-confirm.

use rounddance_zcl::behavior::{AppEvent, Ctx, EventQueue};
use rounddance_zcl::{metering, mirror, notify, supply, ReportingEngine, ZclStatus};

// ---- ConfigureMirror codec --------------------------------------

// 07-5123-08-1049-01: 9-octet body (issuer + uint24 interval +
// reporting flag + scheme).
#[test]
fn vector_configure_mirror_codec_07_5123_08_1049_01() {
    let cfg = notify::ConfigureMirror {
        issuer: 0x0102_0304,
        interval_s: 0x0005_0607,
        reporting: true,
        scheme: notify::SCHEME_B,
    };
    let mut out = [0u8; 9];
    assert_eq!(notify::encode_configure_mirror(&cfg, &mut out), Ok(9));
    assert_eq!(out, [0x04, 0x03, 0x02, 0x01, 0x07, 0x06, 0x05, 0x01, 0x02]);
    assert_eq!(notify::decode_configure_mirror(&out), Ok(cfg));
    // Reporting flag is a Boolean: only 0/1 accepted.
    let mut bad = out;
    bad[7] = 0x02;
    assert!(notify::decode_configure_mirror(&bad).is_err());
    // Interval wider than uint24 is refused, never truncated.
    let wide = notify::ConfigureMirror {
        interval_s: 0x0100_0000,
        ..cfg
    };
    assert!(notify::encode_configure_mirror(&wide, &mut out).is_err());
    // Length must be exact; short buffers fail.
    assert!(notify::decode_configure_mirror(&out[..8]).is_err());
    assert!(notify::encode_configure_mirror(&cfg, &mut out[..8]).is_err());
}

// ---- scheme + order validation -----------------------------------

// 07-5123-08-1049-02: usable vs reserved schemes; predefined schemes
// are immutable; order nibbles gate.
#[test]
fn vector_scheme_gates_07_5123_08_1049_02() {
    assert!(notify::scheme_usable(notify::SCHEME_A));
    assert!(notify::scheme_usable(notify::SCHEME_B));
    assert!(notify::scheme_usable(notify::SCHEME_GENERIC_MIN));
    assert!(notify::scheme_usable(notify::SCHEME_GENERIC_MAX));
    assert!(notify::scheme_usable(notify::SCHEME_MSP_MIN));
    assert!(notify::scheme_usable(notify::SCHEME_MSP_MAX));
    assert!(!notify::scheme_usable(notify::SCHEME_NONE));
    assert!(!notify::scheme_usable(notify::SCHEME_RESERVED));
    assert!(notify::scheme_predefined(notify::SCHEME_A));
    assert!(notify::scheme_predefined(notify::SCHEME_B));
    assert!(!notify::scheme_predefined(notify::SCHEME_GENERIC_MIN));
    // Predefined order words: A names only the functional flags,
    // B names functional + Flags2..5.
    assert_eq!(notify::SCHEME_A_ORDER, 0x0FFF_FFFF);
    assert_eq!(notify::SCHEME_B_ORDER, 0x0123_4FFF);
    assert!(notify::order_valid(notify::SCHEME_A_ORDER));
    assert!(notify::order_valid(notify::SCHEME_B_ORDER));
    assert!(!notify::order_valid(0x0123_48FF));
    assert_eq!(notify::order_flag(0x00), Some(Some(0)));
    assert_eq!(notify::order_flag(0x07), Some(Some(7)));
    assert_eq!(notify::order_flag(notify::ORDER_BLANK), Some(None));
    assert_eq!(notify::order_flag(0x08), None);
    assert_eq!(notify::order_flag(0x0E), None);
}

// 07-5123-08-1049-02: ConfigureNotificationScheme is 9 octets
// (issuer + scheme + flag-order map).
#[test]
fn vector_configure_scheme_codec_07_5123_08_1049_02() {
    let cfg = notify::ConfigureScheme {
        issuer: 0x1122_3344,
        scheme: 0x05,
        order: notify::SCHEME_B_ORDER,
    };
    let mut out = [0u8; 9];
    assert_eq!(notify::encode_configure_scheme(&cfg, &mut out), Ok(9));
    assert_eq!(out, [0x44, 0x33, 0x22, 0x11, 0x05, 0xFF, 0x4F, 0x23, 0x01]);
    assert_eq!(notify::decode_configure_scheme(&out), Ok(cfg));
    // Reserved nibbles are a field error on both paths.
    let mut bad = out;
    bad[6] = 0x4F | 0x80;
    assert!(notify::decode_configure_scheme(&bad).is_err());
    let bad_cfg = notify::ConfigureScheme {
        order: 0x0000_0080,
        ..cfg
    };
    assert!(notify::encode_configure_scheme(&bad_cfg, &mut out).is_err());
    assert!(notify::decode_configure_scheme(&out[..8]).is_err());
}

// ---- ConfigureNotificationFlag codec -----------------------------

// 07-5123-08-1049-03: 7-octet header plus allocation records
// (cluster + mfr + count + command ids).
#[test]
fn vector_configure_flag_codec_07_5123_08_1049_03() {
    let mut cfg = notify::ConfigureFlag::new(0xAABB_CCDD, 0x05, 0x0000);
    cfg.allocs[0] = notify::FlagAlloc {
        cluster: metering::CLUSTER_ID,
        mfr: 0x1234,
        cmds: {
            let mut c = [0u8; notify::MAX_ALLOC_CMDS];
            c[0] = supply::CMD_CHANGE_SUPPLY;
            c[1] = supply::CMD_LOCAL_CHANGE_SUPPLY;
            c
        },
        cmd_count: 2,
    };
    cfg.alloc_count = 1;
    let mut out = [0u8; 64];
    assert_eq!(notify::encode_configure_flag(&cfg, &mut out), Ok(7 + 5 + 2));
    assert_eq!(
        &out[..14],
        &[0xDD, 0xCC, 0xBB, 0xAA, 0x05, 0x00, 0x00, 0x02, 0x07, 0x34, 0x12, 0x02, 0x0B, 0x0C]
    );
    let mut back = notify::ConfigureFlag::new(0, 0, 0);
    notify::decode_configure_flag(&out[..14], &mut back).unwrap();
    assert_eq!(back, cfg);
    // Empty record list and zero-count records are refused.
    let empty = notify::ConfigureFlag::new(1, 0x05, 0);
    assert!(notify::encode_configure_flag(&empty, &mut out).is_err());
    // Flag attributes stop at Flags8 (0x0007).
    let mut bad_attr = cfg;
    bad_attr.flag_attr = 0x0008;
    assert!(notify::encode_configure_flag(&bad_attr, &mut out).is_err());
    let mut bad_wire = out;
    bad_wire[5] = 0x08;
    assert!(notify::decode_configure_flag(&bad_wire[..14], &mut back).is_err());
    // Ragged tails are field errors, never partial intake.
    assert!(notify::decode_configure_flag(&out[..13], &mut back).is_err());
}

// ---- GetNotifiedMessage codec ------------------------------------

// 07-5123-08-1049-05: 7-octet body (scheme + flag attr + flags).
#[test]
fn vector_get_notified_codec_07_5123_08_1049_05() {
    let msg = notify::GetNotifiedMessage {
        scheme: notify::SCHEME_B,
        flag_attr: notify::ATTR_FUNCTIONAL,
        flags: 1u32 << notify::FUNC_CHANGE_SUPPLY,
    };
    let mut out = [0u8; 7];
    assert_eq!(notify::encode_get_notified(&msg, &mut out), Ok(7));
    assert_eq!(out, [0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00]);
    assert_eq!(notify::decode_get_notified(&out), Ok(msg));
    assert!(notify::decode_get_notified(&out[..6]).is_err());
    let mut bad = out;
    bad[1] = 0x08;
    assert!(notify::decode_get_notified(&bad).is_err());
}

// ---- status -------------------------------------------------------

// 07-5123-08-1049-05: 0x9A is NOTIFICATION_PENDING (queue receipt),
// distinct from INSUFFICIENT_SPACE (queue full).
#[test]
fn vector_notification_pending_status_07_5123_08_1049_05() {
    assert_eq!(ZclStatus::from_u8(0x9a), ZclStatus::NotificationPending);
    assert_eq!(ZclStatus::NotificationPending.as_u8(), 0x9a);
    assert_eq!(
        notify::CacheVerdict::Pending.status(),
        ZclStatus::NotificationPending
    );
    assert_eq!(
        notify::CacheVerdict::Full.status(),
        ZclStatus::InsufficientSpace
    );
}

// ---- mirror engine: configuration --------------------------------

// 07-5123-08-1049-01/02/03: issuer-ordered configuration with
// predefined-scheme immutability and staged generic completion.
#[test]
fn vector_mirror_configure_07_5123_08_1049_01() {
    let mut eng = notify::MirrorNotify::new();
    assert!(!eng.enabled());
    // Unsupported schemes are a field error, never staged.
    let bad = notify::ConfigureMirror {
        issuer: 1,
        interval_s: 60,
        reporting: true,
        scheme: notify::SCHEME_RESERVED,
    };
    assert_eq!(
        eng.apply_configure_mirror(&bad),
        Err(ZclStatus::InvalidField)
    );
    let none = notify::ConfigureMirror {
        scheme: notify::SCHEME_NONE,
        ..bad
    };
    assert_eq!(
        eng.apply_configure_mirror(&none),
        Err(ZclStatus::InvalidField)
    );
    // Predefined scheme B enables two-way retrieval at once.
    let cfg_b = notify::ConfigureMirror {
        issuer: 10,
        interval_s: 60,
        reporting: true,
        scheme: notify::SCHEME_B,
    };
    eng.apply_configure_mirror(&cfg_b).unwrap();
    assert!(eng.enabled());
    assert_eq!(eng.scheme(), notify::SCHEME_B);
    assert_eq!(eng.interval_s(), 60);
    assert!(eng.reporting());
    // Stale issuers are ignored, never applied.
    let stale = notify::ConfigureMirror { issuer: 9, ..cfg_b };
    eng.apply_configure_mirror(&stale).unwrap();
    assert_eq!(eng.interval_s(), 60);
    // Predefined schemes cannot be overwritten by scheme/flag
    // commands.
    let overwrite = notify::ConfigureScheme {
        issuer: 11,
        scheme: notify::SCHEME_B,
        order: notify::SCHEME_B_ORDER,
    };
    assert_eq!(eng.apply_scheme(&overwrite), Err(ZclStatus::InvalidField));
    let mut flag = notify::ConfigureFlag::new(11, notify::SCHEME_B, 0);
    flag.alloc_count = 1;
    assert_eq!(eng.apply_flag(&flag), Err(ZclStatus::InvalidField));
}

// 07-5123-08-1049-02/03: a generic scheme enables only once every
// non-blank ordered flag has an allocation.
#[test]
fn vector_generic_scheme_staging_07_5123_08_1049_02() {
    let mut eng = notify::MirrorNotify::new();
    let cfg = notify::ConfigureMirror {
        issuer: 5,
        interval_s: 30,
        reporting: false,
        scheme: 0x05,
    };
    eng.apply_configure_mirror(&cfg).unwrap();
    assert!(!eng.enabled());
    // Order naming only the functional flag + blanks.
    let scheme = notify::ConfigureScheme {
        issuer: 6,
        scheme: 0x05,
        order: 0xFFFF_FFF0,
    };
    eng.apply_scheme(&scheme).unwrap();
    assert!(!eng.enabled());
    // Mismatched-scheme flags are refused.
    let mut wrong = notify::ConfigureFlag::new(7, 0x06, 0);
    wrong.alloc_count = 1;
    assert_eq!(eng.apply_flag(&wrong), Err(ZclStatus::InvalidField));
    let mut flag = notify::ConfigureFlag::new(7, 0x05, 0);
    flag.allocs[0] = notify::FlagAlloc {
        cluster: metering::CLUSTER_ID,
        mfr: 0,
        cmds: {
            let mut c = [0u8; notify::MAX_ALLOC_CMDS];
            c[0] = supply::CMD_CHANGE_SUPPLY;
            c
        },
        cmd_count: 1,
    };
    flag.alloc_count = 1;
    eng.apply_flag(&flag).unwrap();
    assert!(eng.enabled());
    // Polling mode survives: no report solicitation.
    assert!(!eng.reporting());
}

// ---- mirror engine: queue -----------------------------------------

fn change_origin(tsn: u8) -> notify::Originator {
    notify::Originator {
        src: 0x1111_2222_3333_4444,
        endpoint: 1,
        tsn,
        cluster: metering::CLUSTER_ID,
        cmd: supply::CMD_CHANGE_SUPPLY,
    }
}

fn enabled_b() -> notify::MirrorNotify {
    let mut eng = notify::MirrorNotify::new();
    eng.apply_configure_mirror(&notify::ConfigureMirror {
        issuer: 10,
        interval_s: 60,
        reporting: true,
        scheme: notify::SCHEME_B,
    })
    .unwrap();
    eng
}

// 07-5123-08-1049-05: caching sets the mapped functional bit;
// fetch hands the entry back and the bit drains; duplicates are
// idempotent; a full queue refuses.
#[test]
fn vector_mirror_queue_07_5123_08_1049_05() {
    let mut eng = enabled_b();
    let mut body = [0u8; 18];
    supply::encode_change_supply(
        &supply::ChangeSupply {
            provider: 1,
            issuer: 2,
            request_time: 100,
            impl_time: 0,
            proposed: supply::SUPPLY_ON,
            control: supply::CONTROL_ACK_REQUIRED,
        },
        &mut body,
    )
    .unwrap();
    assert_eq!(
        eng.cache(change_origin(7), &body, 1_000),
        notify::CacheVerdict::Pending
    );
    assert_eq!(eng.pending_len(), 1);
    // Duplicate delivery of the same originator is idempotent.
    assert_eq!(
        eng.cache(change_origin(7), &body, 1_001),
        notify::CacheVerdict::Pending
    );
    assert_eq!(eng.pending_len(), 1);
    // ChangeSupply maps to functional bit 18.
    assert_eq!(
        eng.flag_words()[0] & (1u32 << notify::FUNC_CHANGE_SUPPLY),
        1u32 << notify::FUNC_CHANGE_SUPPLY
    );
    // Fetch with a matching mask returns the oldest entry.
    let entry = eng
        .fetch(&notify::GetNotifiedMessage {
            scheme: notify::SCHEME_B,
            flag_attr: notify::ATTR_FUNCTIONAL,
            flags: 1u32 << notify::FUNC_CHANGE_SUPPLY,
        })
        .unwrap();
    assert_eq!(entry.origin, change_origin(7));
    assert_eq!(&entry.payload[..18], &body);
    assert_eq!(eng.pending_len(), 0);
    // Drained bits clear on their own.
    assert_eq!(eng.flag_words()[0], 0);
    // Fetching drained bits answers NOT_FOUND.
    assert_eq!(
        eng.fetch(&notify::GetNotifiedMessage {
            scheme: notify::SCHEME_B,
            flag_attr: notify::ATTR_FUNCTIONAL,
            flags: 1u32 << notify::FUNC_CHANGE_SUPPLY,
        }),
        Err(ZclStatus::NotFound)
    );
    // Wrong scheme or empty mask is a field error.
    assert_eq!(
        eng.fetch(&notify::GetNotifiedMessage {
            scheme: notify::SCHEME_A,
            flag_attr: notify::ATTR_FUNCTIONAL,
            flags: 1u32 << notify::FUNC_CHANGE_SUPPLY,
        }),
        Err(ZclStatus::InvalidField)
    );
    assert_eq!(
        eng.fetch(&notify::GetNotifiedMessage {
            scheme: notify::SCHEME_B,
            flag_attr: notify::ATTR_FUNCTIONAL,
            flags: 0,
        }),
        Err(ZclStatus::InvalidField)
    );
}

// 07-5123-08-1049-05: full queue refuses; non-specified commands
// park behind stay-awake; timeouts name their originators.
#[test]
fn vector_mirror_queue_edges_07_5123_08_1049_05() {
    let mut eng = enabled_b();
    let body = [0xAAu8; 4];
    let mut i = 0u8;
    while i < notify::MAX_PENDING as u8 {
        let mut o = change_origin(i);
        o.tsn = i;
        // Distinct TSNs are distinct deliveries.
        o.cmd = supply::CMD_LOCAL_CHANGE_SUPPLY;
        assert_eq!(eng.cache(o, &body, 2_000), notify::CacheVerdict::Pending);
        i += 1;
    }
    assert_eq!(eng.pending_len(), notify::MAX_PENDING);
    assert_eq!(
        eng.cache(change_origin(9), &body, 2_000),
        notify::CacheVerdict::Full
    );
    // LocalChangeSupply maps to functional bit 19.
    assert_eq!(
        eng.flag_words()[0] & (1u32 << notify::FUNC_LOCAL_CHANGE_SUPPLY),
        1u32 << notify::FUNC_LOCAL_CHANGE_SUPPLY
    );
    // Oversize payloads never grow the queue: refused as full.
    let big = [0u8; notify::MAX_PENDING_PAYLOAD + 1];
    assert_eq!(
        eng.cache(change_origin(10), &big, 2_000),
        notify::CacheVerdict::Full
    );
    // A non-specified cluster parks behind stay-awake (HAN).
    let mut eng2 = enabled_b();
    let foreign = notify::Originator {
        cluster: 0x0006,
        cmd: 0x01,
        ..change_origin(20)
    };
    eng2.cache(foreign, &body, 3_000);
    assert_eq!(
        eng2.flag_words()[0] & (1u32 << notify::FUNC_STAY_AWAKE_HAN),
        1u32 << notify::FUNC_STAY_AWAKE_HAN
    );
    // Expiry names originators oldest-first for TIMEOUT answers.
    let mut out = [change_origin(0); 4];
    assert_eq!(eng.expire(2_000 + 40, 3_600, &mut out), 0);
    assert_eq!(
        eng.expire(2_000 + 3_601, 3_600, &mut out),
        notify::MAX_PENDING
    );
    assert_eq!(out[0].cmd, supply::CMD_LOCAL_CHANGE_SUPPLY);
    assert_eq!(eng.pending_len(), 0);
    assert_eq!(eng.flag_words()[0], 0);
}

// 07-5123-08-1049-04/05: application event bits (publish information)
// raise and lower independently of queue-derived bits.
#[test]
fn vector_mirror_raise_lower_07_5123_08_1049_04() {
    let mut eng = enabled_b();
    eng.raise(1, 1u32 << notify::PRICE2_PUBLISH_PRICE).unwrap();
    eng.raise(1, 1u32 << notify::PRICE2_BLOCK_PERIOD).unwrap();
    assert_eq!(eng.flag_words()[1], 0x0000_0003);
    eng.lower(1, 1u32 << notify::PRICE2_PUBLISH_PRICE).unwrap();
    assert_eq!(eng.flag_words()[1], 0x0000_0002);
    assert!(eng.raise(8, 1).is_err());
}

// ---- meter side: emitters + fetch planning ------------------------

// 07-5123-08-1049-01/06: the meter emits ConfigureMirror toward the
// mirror and records the scheme it configured.
#[test]
fn vector_meter_configure_emits_07_5123_08_1049_01() {
    let mut store = metering::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = metering::ServerBehavior::new();
    let cfg = notify::ConfigureMirror {
        issuer: 0x0102_0304,
        interval_s: 0x0005_0607,
        reporting: true,
        scheme: notify::SCHEME_B,
    };
    let mut ctx = Ctx {
        store: &mut store,
        reporting: &mut eng,
        events: &mut events,
        now_s: 100,
        peer_onoff: None,
        sender_ieee: None,
    };
    beh.configure_mirror(&mut ctx, &cfg).unwrap();
    assert_eq!(beh.notify().scheme(), notify::SCHEME_B);
    let mut saw = false;
    while let Some(ev) = events.pop() {
        if let AppEvent::OutboundCommand {
            cluster,
            cmd,
            len,
            payload,
            ..
        } = ev
        {
            assert_eq!(cluster, metering::CLUSTER_ID);
            assert_eq!(cmd, notify::CMD_CONFIGURE_MIRROR);
            assert_eq!(len, 9);
            assert_eq!(
                &payload[..9],
                &[0x04, 0x03, 0x02, 0x01, 0x07, 0x06, 0x05, 0x01, 0x02]
            );
            saw = true;
        }
    }
    assert!(saw);
    // The notify commands are server-generated: the meter's
    // definition carries them on the TX side (the RX side keeps the
    // client-driven commands sharing the numeric space, e.g.
    // GetSampledData on 0x08 — direction distinguishes them).
    let def = metering::ServerDef;
    assert!(rounddance_zcl::cluster::find_generated(&def, notify::CMD_CONFIGURE_MIRROR).is_some());
    assert!(
        rounddance_zcl::cluster::find_generated(&def, notify::CMD_GET_NOTIFIED_MESSAGE).is_some()
    );
}

// 07-5123-08-1049-05/06: the meter plans a GetNotifiedMessage from a
// report naming buffered supply commands, and emits it.
#[test]
fn vector_meter_fetch_plan_07_5123_08_1049_05() {
    let mut beh = metering::ServerBehavior::new();
    // No report yet: nothing planned.
    let mut plan = [notify::GetNotifiedMessage {
        scheme: 0,
        flag_attr: 0,
        flags: 0,
    }; 2];
    assert_eq!(beh.notify_mut().plan_fetch(&mut plan), 0);
    beh.notify_mut().note_configured(&notify::ConfigureMirror {
        issuer: 10,
        interval_s: 60,
        reporting: true,
        scheme: notify::SCHEME_B,
    });
    // A report under a foreign scheme never plans a fetch.
    beh.notify_mut().note_report(&mirror::MirrorReport {
        scheme: notify::SCHEME_A,
        flags: {
            let mut f = [0u32; mirror::MAX_NOTIFICATION_FLAGS];
            f[0] = 1u32 << notify::FUNC_CHANGE_SUPPLY;
            f
        },
        count: 1,
    });
    assert_eq!(beh.notify_mut().plan_fetch(&mut plan), 0);
    // A matching report plans exactly one fetch with the set bits.
    beh.notify_mut().note_report(&mirror::MirrorReport {
        scheme: notify::SCHEME_B,
        flags: {
            let mut f = [0u32; mirror::MAX_NOTIFICATION_FLAGS];
            f[0] = (1u32 << notify::FUNC_CHANGE_SUPPLY) | (1u32 << notify::FUNC_FLOW_THRESHOLD);
            f[1] = 1u32 << notify::PRICE2_PUBLISH_PRICE;
            f
        },
        count: 2,
    });
    assert_eq!(beh.notify_mut().plan_fetch(&mut plan), 1);
    assert_eq!(
        plan[0],
        notify::GetNotifiedMessage {
            scheme: notify::SCHEME_B,
            flag_attr: notify::ATTR_FUNCTIONAL,
            flags: (1u32 << notify::FUNC_CHANGE_SUPPLY) | (1u32 << notify::FUNC_FLOW_THRESHOLD),
        }
    );
    // The planned fetch encodes to the 7-octet wire shape.
    let mut store = metering::server_store().unwrap();
    let mut reng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut ctx = Ctx {
        store: &mut store,
        reporting: &mut reng,
        events: &mut events,
        now_s: 200,
        peer_onoff: None,
        sender_ieee: None,
    };
    beh.get_notified(&mut ctx, &plan[0]).unwrap();
    let mut saw = false;
    while let Some(ev) = events.pop() {
        if let AppEvent::OutboundCommand { cmd, len, .. } = ev {
            assert_eq!(cmd, notify::CMD_GET_NOTIFIED_MESSAGE);
            assert_eq!(len, 7);
            saw = true;
        }
    }
    assert!(saw);
}
