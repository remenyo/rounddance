//! Scheduled metering loop: a timetable fires a snapshot, a
//! sampling session captures and answers, and supply orders execute
//! with acknowledgement — twice, with byte-identical traces.
//!
//! Requirement traceability (repo-minted `07-5123-08-1046-*` /
//! `1047-*` / `1048-*`, MINTED-pending-confirm, plus corpus-reused
//! `17-05019-012-423-03` for delayed execution) and `SCOPE.md` §8
//! (decision determinism).

use rounddance_zcl::behavior::{AppEvent, Behavior, Ctx, EventQueue, HandleOutcome};
use rounddance_zcl::frame::{Direction, FrameControl, FrameType, Header};
use rounddance_zcl::{metering, sampling, schedule, snapshot, supply, ReportingEngine, ZclStatus};

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

/// Drive one command; record `cmd:hex(reply)` (or the status name on
/// refusal) in the trace.
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
) -> Result<HandleOutcome, ZclStatus> {
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
                "{cmd:02x}>{rc:02x}:{}",
                hex(&o.reply_body[..o.reply_len as usize])
            )),
            None => trace.push(format!("{cmd:02x}>--")),
        },
        Err(e) => trace.push(format!("{cmd:02x}>!!{e:?}")),
    }
    outcome
}

/// Run the whole scheduled loop; returns the trace plus the fired
/// snapshot id, the sampled series, and the final supply status.
fn run_loop() -> (Vec<String>, u32, Vec<u32>, u8) {
    let mut trace = Vec::new();
    let mut store = metering::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = metering::ServerBehavior::new();
    beh.add_consumption(&mut store, 2_000_000);

    // 1. File a daily timetable starting at t=5000.
    let entry = schedule::ScheduleEntry {
        id: 1,
        start: 5_000,
        bitmap: 1,
        payload_type: snapshot::PAYLOAD_TOU_DELIVERED,
        cause: 0x00,
    };
    let mut entry_wire = [0u8; schedule::SCHEDULE_ENTRY_LEN];
    schedule::encode_schedule_entry(&entry, &mut entry_wire).unwrap();
    let mut cmd = [0u8; 6 + schedule::SCHEDULE_ENTRY_LEN];
    cmd[..4].copy_from_slice(&7u32.to_le_bytes());
    cmd[4] = 0;
    cmd[5] = 1;
    cmd[6..].copy_from_slice(&entry_wire);
    drive(
        &mut trace,
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        100,
        schedule::CMD_SCHEDULE_SNAPSHOT,
        &cmd,
    )
    .unwrap();

    // 2. The due tick files the scheduled snapshot; retrieval finds it.
    beh.tick_metering(&store, &mut events, 4_999);
    assert!(beh.snapshots().is_empty());
    beh.tick_metering(&store, &mut events, 5_000);
    assert_eq!(beh.snapshots().len(), 1);
    let mut get = [0u8; 13];
    snapshot::encode_get_snapshot(
        &snapshot::GetSnapshot {
            earliest: 0,
            latest: 0xFFFF_FFFF,
            offset: 0,
            cause: 1 << snapshot::CAUSE_SCHEDULED_BIT,
        },
        &mut get,
    )
    .unwrap();
    drive(
        &mut trace,
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        5_001,
        snapshot::CMD_GET_SNAPSHOT,
        &get,
    )
    .unwrap();
    let snap = beh
        .snapshots()
        .query(0, 0xFFFF_FFFF, 0, snapshot::CAUSE_ALL)
        .unwrap();

    // 3. Sampling session: open, capture three interval values, read.
    let mut start = [0u8; 13];
    sampling::encode_start_sampling(
        &sampling::StartSampling {
            issuer: 1,
            start: 0,
            sample_type: sampling::SAMPLE_DELIVERED,
            interval_s: 10,
            max_samples: 3,
        },
        &mut start,
    )
    .unwrap();
    drive(
        &mut trace,
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        5_002,
        sampling::CMD_START_SAMPLING,
        &start,
    )
    .unwrap();
    assert!(beh.samples_mut().push(1, 1_000, 5_000));
    assert!(beh.samples_mut().push(1, 1_100, 5_010));
    assert!(beh.samples_mut().push(1, 1_200, 5_020));
    let mut getd = [0u8; 9];
    sampling::encode_get_sampled_data(
        &sampling::GetSampledData {
            sample_id: 1,
            earliest: 0,
            sample_type: sampling::SAMPLE_DELIVERED,
            count: 3,
        },
        &mut getd,
    )
    .unwrap();
    drive(
        &mut trace,
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        5_030,
        sampling::CMD_GET_SAMPLED_DATA,
        &getd,
    )
    .unwrap();
    let mut values = [0u32; sampling::MAX_SAMPLES_PER_RESPONSE];
    let (_, _, _, count) = beh
        .samples()
        .query(
            &sampling::GetSampledData {
                sample_id: 1,
                earliest: 0,
                sample_type: sampling::SAMPLE_DELIVERED,
                count: 3,
            },
            &mut values,
        )
        .unwrap();

    // 4. Delayed supply change with ack: filed now, executed on tick.
    let mut change = [0u8; 18];
    supply::encode_change_supply(
        &supply::ChangeSupply {
            provider: 9,
            issuer: 2,
            request_time: 5_030,
            impl_time: 8_000,
            proposed: supply::SUPPLY_OFF,
            control: supply::CONTROL_ACK_REQUIRED,
        },
        &mut change,
    )
    .unwrap();
    drive(
        &mut trace,
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        5_031,
        supply::CMD_CHANGE_SUPPLY,
        &change,
    )
    .unwrap();
    beh.tick_metering(&store, &mut events, 7_999);
    assert_eq!(beh.supply().status(), supply::SUPPLY_ON);
    beh.tick_metering(&store, &mut events, 8_000);
    assert_eq!(beh.supply().status(), supply::SUPPLY_OFF);
    // Drain events into the trace: the ack plus state transitions.
    while let Some(ev) = events.pop() {
        match ev {
            AppEvent::OutboundCommand {
                cmd, len, payload, ..
            } => {
                trace.push(format!("ev>{cmd:02x}:{}", hex(&payload[..len as usize])));
            }
            AppEvent::StateChanged { from, to, .. } => {
                trace.push(format!("ev#{from:02x}>{to:02x}"));
            }
            _ => {}
        }
    }

    // 5. Local change plus a tamper event selects the filed OFF state.
    let mut local = [0u8; 1];
    supply::encode_local_change_supply(supply::SUPPLY_ARMED, &mut local).unwrap();
    drive(
        &mut trace,
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        8_001,
        supply::CMD_LOCAL_CHANGE_SUPPLY,
        &local,
    )
    .unwrap();
    let mut set = [0u8; 8];
    supply::encode_set_supply_status(
        &supply::SetSupplyStatus {
            issuer: 3,
            tamper: supply::SUPPLY_OFF,
            depletion: supply::SUPPLY_UNCHANGED,
            uncontrolled: supply::SUPPLY_UNCHANGED,
            load_limit: supply::SUPPLY_UNCHANGED,
        },
        &mut set,
    )
    .unwrap();
    drive(
        &mut trace,
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        8_002,
        supply::CMD_SET_SUPPLY_STATUS,
        &set,
    )
    .unwrap();
    let tampered = beh.supply_mut().apply_event(supply::SupplyEvent::Tamper);
    trace.push(format!("tamper>{tampered:02x?}"));

    (
        trace,
        snap.id,
        values[..count as usize].to_vec(),
        beh.supply().status(),
    )
}

// Timetable fires, sampling answers, delayed supply executes + acks,
// local/event states apply.
#[test]
fn se_schedule_loop_end_to_end() {
    let (trace, snap_id, series, status) = run_loop();
    assert!(!trace.is_empty());
    assert_eq!(snap_id, 0);
    assert_eq!(series, vec![1_000, 1_100, 1_200]);
    assert_eq!(status, supply::SUPPLY_OFF);
    assert!(trace.iter().any(|t| t.starts_with("04>04:")));
    assert!(trace.iter().any(|t| t.starts_with("08>07:")));
    assert!(trace.iter().any(|t| t.starts_with("ev>0c:")));
}

// Decision determinism: the same script replays byte-identically.
#[test]
fn se_schedule_loop_replays_deterministically() {
    let (t1, s1, v1, st1) = run_loop();
    let (t2, s2, v2, st2) = run_loop();
    assert_eq!(t1, t2);
    assert_eq!((s1, v1, st1), (s2, v2, st2));
}
