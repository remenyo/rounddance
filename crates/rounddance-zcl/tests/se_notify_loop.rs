//! Notification-scheme loop: the meter configures a two-way mirror,
//! the ESI caches a supply command behind a flag, the meter fetches it
//! with GetNotifiedMessage, the buffered command executes with its
//! acknowledgement relayed — twice, with byte-identical traces.
//!
//! Requirement traceability (repo-minted `07-5123-08-1049-*`,
//! MINTED-pending-confirm) and `SCOPE.md` §8 (decision
//! determinism).

use rounddance_zcl::behavior::{AppEvent, Behavior, Ctx, EventQueue};
use rounddance_zcl::frame::{Direction, FrameControl, FrameType, Header};
use rounddance_zcl::{metering, mirror, notify, supply, ReportingEngine, ZclStatus};

fn ctx_for<'a>(
    store: &'a mut rounddance_zcl::AttrStore,
    eng: &'a mut ReportingEngine,
    events: &'a mut EventQueue,
    now_s: u64,
) -> Ctx<'a> {
    Ctx {
        store,
        reporting: eng,
        events,
        now_s,
        peer_onoff: None,
        sender_ieee: None,
    }
}

fn hdr(cmd: u8) -> Header {
    Header {
        control: FrameControl {
            frame_type: FrameType::ClusterSpecific,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x31,
        command_id: cmd,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Drain emitted outbound commands into the trace as `cmd:hex(body)`.
fn drain(trace: &mut Vec<String>, events: &mut EventQueue) {
    while let Some(ev) = events.pop() {
        if let AppEvent::OutboundCommand {
            cmd, len, payload, ..
        } = ev
        {
            trace.push(format!("ev{cmd:02x}:{}", hex(&payload[..len as usize])));
        }
    }
}

/// Drive one received command; record `cmd:hex(reply)` (or the status
/// name on refusal) in the trace.
#[allow(clippy::too_many_arguments)]
fn drive(
    trace: &mut Vec<String>,
    beh: &mut metering::ServerBehavior,
    store: &mut rounddance_zcl::AttrStore,
    eng: &mut ReportingEngine,
    events: &mut EventQueue,
    now_s: u64,
    cmd: u8,
    payload: &[u8],
) {
    let outcome = <metering::ServerBehavior as Behavior>::handle_cluster_command(
        beh,
        &mut ctx_for(store, eng, events, now_s),
        &hdr(cmd),
        cmd,
        payload,
    );
    match &outcome {
        Ok(o) => match o.reply_cmd {
            Some(rc) => trace.push(format!(
                "{cmd:02x}>{rc:02x}:{esc}",
                esc = hex(&o.reply_body[..o.reply_len as usize])
            )),
            None => trace.push(format!("{cmd:02x}>--")),
        },
        Err(e) => trace.push(format!("{cmd:02x}>!!{e:?}")),
    }
    drain(trace, events);
}

/// Run the whole notification loop; returns the trace plus the final
/// supply status and the meter's configured scheme.
fn run_loop() -> (Vec<String>, u8, u8) {
    let mut trace = Vec::new();
    let mut store = metering::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = metering::ServerBehavior::new();
    // ESI-side mirror engine (the other end of the conversation).
    let mut esi = notify::MirrorNotify::new();

    // 1. The meter configures a predefined scheme-B two-way mirror.
    beh.configure_mirror(
        &mut ctx_for(&mut store, &mut eng, &mut events, 100),
        &notify::ConfigureMirror {
            issuer: 10,
            interval_s: 60,
            reporting: true,
            scheme: notify::SCHEME_B,
        },
    )
    .unwrap();
    assert!(beh.notify().scheme() == notify::SCHEME_B);
    drain(&mut trace, &mut events);
    // The ESI applies the same configuration and enables retrieval.
    esi.apply_configure_mirror(&notify::ConfigureMirror {
        issuer: 10,
        interval_s: 60,
        reporting: true,
        scheme: notify::SCHEME_B,
    })
    .unwrap();
    assert!(esi.enabled());

    // 2. The head-end caches a ChangeSupply for the sleeping meter.
    let mut change = [0u8; 18];
    supply::encode_change_supply(
        &supply::ChangeSupply {
            provider: 0x0A0B_0C0D,
            issuer: 0x0000_0011,
            request_time: 900,
            impl_time: supply::IMPL_IMMEDIATE,
            proposed: supply::SUPPLY_OFF,
            control: supply::CONTROL_ACK_REQUIRED,
        },
        &mut change,
    )
    .unwrap();
    let origin = notify::Originator {
        src: 0xAAAA_BBBB_CCCC_DDDD,
        endpoint: 9,
        tsn: 0x42,
        cluster: metering::CLUSTER_ID,
        cmd: supply::CMD_CHANGE_SUPPLY,
    };
    assert_eq!(
        esi.cache(origin, &change, 1_000),
        notify::CacheVerdict::Pending
    );
    trace.push(format!("cache:{:?}", esi.cache(origin, &change, 1_000)));
    // Duplicate delivery is idempotent, never double-queued.
    assert_eq!(esi.pending_len(), 1);
    // New publish information raises the price Flags2 bit.
    esi.raise(1, 1u32 << notify::PRICE2_PUBLISH_PRICE).unwrap();

    // 3. The meter wakes, takes the flag report, and plans a fetch.
    let words = esi.flag_words();
    assert_eq!(
        words[0] & (1u32 << notify::FUNC_CHANGE_SUPPLY),
        1u32 << notify::FUNC_CHANGE_SUPPLY
    );
    assert_eq!(words[1], 1u32 << notify::PRICE2_PUBLISH_PRICE);
    let report = mirror::MirrorReport {
        scheme: esi.scheme(),
        flags: {
            let mut f = [0u32; mirror::MAX_NOTIFICATION_FLAGS];
            f[0] = words[0];
            f[1] = words[1];
            f
        },
        count: 2,
    };
    let mut rep_wire = [0u8; 16];
    let n = mirror::encode_mirror_report(&report, &mut rep_wire).unwrap();
    drive(
        &mut trace,
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        2_000,
        mirror::CMD_MIRROR_REPORT_ATTR_RESPONSE,
        &rep_wire[..n],
    );
    let mut plan = [notify::GetNotifiedMessage {
        scheme: 0,
        flag_attr: 0,
        flags: 0,
    }; 2];
    assert_eq!(beh.notify_mut().plan_fetch(&mut plan), 1);
    beh.get_notified(
        &mut ctx_for(&mut store, &mut eng, &mut events, 2_000),
        &plan[0],
    )
    .unwrap();
    drain(&mut trace, &mut events);

    // 4. The mirror hands down the buffered command; the meter
    // executes it and the ack relays to the recorded originator.
    let fetched = esi
        .fetch(
            &notify::decode_get_notified(&{
                let mut w = [0u8; 7];
                notify::encode_get_notified(&plan[0], &mut w).unwrap();
                w
            })
            .unwrap(),
        )
        .unwrap();
    assert_eq!(fetched.origin, origin);
    trace.push(format!(
        "fetch:{:04x}:{:02x}:{}",
        fetched.origin.cluster,
        fetched.origin.cmd,
        hex(&fetched.payload[..fetched.len as usize])
    ));
    drive(
        &mut trace,
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        2_001,
        supply::CMD_CHANGE_SUPPLY,
        &fetched.payload[..fetched.len as usize],
    );
    trace.push(format!(
        "relay:{:016x}:{:02x}:{:02x}",
        fetched.origin.src, fetched.origin.endpoint, fetched.origin.tsn
    ));
    // The drained flag clears on the mirror once retrieved.
    assert_eq!(esi.flag_words()[0], 0);
    // The price bit stays until the meter's own Get commands clear it.
    assert_eq!(esi.flag_words()[1], 1u32 << notify::PRICE2_PUBLISH_PRICE);
    esi.lower(1, 1u32 << notify::PRICE2_PUBLISH_PRICE).unwrap();

    // 5. A second cached command outlives its operator timeout.
    let mut origin2 = origin;
    origin2.tsn = 0x43;
    assert_eq!(
        esi.cache(origin2, &change, 3_000),
        notify::CacheVerdict::Pending
    );
    let mut expired = [origin; 4];
    assert_eq!(esi.expire(3_000 + 100, 3_600, &mut expired), 0);
    let n_exp = esi.expire(3_000 + 3_601, 3_600, &mut expired);
    assert_eq!(n_exp, 1);
    trace.push(format!(
        "timeout:{:?}:{}",
        ZclStatus::Timeout,
        hex(&[expired[0].tsn])
    ));

    (trace, beh.supply().status(), beh.notify().scheme())
}

// 07-5123-08-1049-01..06: the full configure → cache → report →
// fetch → execute → timeout loop replays byte-identically.
#[test]
fn se_notify_loop_replays_07_5123_08_1049() {
    let (first, status_a, scheme_a) = run_loop();
    let (second, status_b, scheme_b) = run_loop();
    assert_eq!(first, second);
    assert_eq!(status_a, supply::SUPPLY_OFF);
    assert_eq!(status_b, supply::SUPPLY_OFF);
    assert_eq!(scheme_a, notify::SCHEME_B);
    assert_eq!(scheme_b, notify::SCHEME_B);
    // The loop actually exercised the machinery: configure, flag
    // report, fetch, acknowledged execution, relay, timeout.
    assert!(first.iter().any(|t| t.starts_with("ev08:")));
    assert!(first.iter().any(|t| t.starts_with("0b>0c:")));
    assert!(first.iter().any(|t| t.starts_with("timeout:Timeout:")));
    assert!(first
        .iter()
        .any(|t| t.starts_with("relay:aaaabbbbccccdddd:09:42")));
}
