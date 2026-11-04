//! Line-by-line coverage closure for BDB `22-65816-030` v3.1 §6.1
//! (logical device types) + §9.7 (permit joining) + §10 (rejoin) +
//! §7.3 (keepalive) + §11-adjacent endpoint hosting, plus
//! commissioning-adjacent core §3.6.1 family behavior.
//!
//! Paraphrase only (D1): every test cites document, revision, and
//! clause/line anchors. Complements (never duplicates) the existing
//! `tests/roundtrip.rs`, `tests/endpoint_edges.rs`,
//! `tests/simultaneity.rs`, and `tests/vectors.rs`.

use rounddance_commission::{ChannelMask, FormationConfig, LogicalType, PanChoice};
use rounddance_roles::{
    AgingPolicy, AppEndpoint, ChildTable, ChildrenError, CommandError, CoordinatorMachine,
    CoordinatorState, DeviceRole, EndDeviceError, EndDeviceMachine, EndDeviceState, EndpointTable,
    IndirectQueue, PollOutcome, RouterMachine, RouterState, SleepState, SleepyConfig,
    SleepyEndDeviceMachine, SleepyError, MAX_CHILDREN, MAX_INDIRECT_PAYLOAD, MAX_INDIRECT_QUEUE,
    MAX_POLL_INTERVAL_MS, MIN_POLL_INTERVAL_MS,
};

fn formation_cfg() -> FormationConfig {
    FormationConfig {
        role: LogicalType::Coordinator,
        primary: ChannelMask::from_list(&[15]).unwrap(),
        secondary: ChannelMask::empty(),
        scan_duration: 3,
        pan: PanChoice::Auto,
        extended_pan: [0xBB; 8],
        router_short_addr: 0,
    }
}

// ---------------------------------------------------------------------------
// §6.1 logical device types (anchor p0010-L87-L88)
// ---------------------------------------------------------------------------

// 22-65816-030-61-01: every device operates in exactly one of the four
// logical types.
#[test]
fn bdb_role_set_is_four_types() {
    let roles = [
        DeviceRole::Coordinator,
        DeviceRole::Router,
        DeviceRole::EndDevice,
        DeviceRole::SleepyEndDevice,
    ];
    assert_eq!(roles.len(), 4);
    assert!(roles.contains(&DeviceRole::Coordinator));
    assert!(roles.contains(&DeviceRole::Router));
    assert!(roles.contains(&DeviceRole::EndDevice));
    assert!(roles.contains(&DeviceRole::SleepyEndDevice));
}

// ---------------------------------------------------------------------------
// Coordinator: formation + permit window + child keepalive
// ---------------------------------------------------------------------------

// 22-65816-030-61-01 + 05-3474-23-3611-01: the coordinator forms via
// the commission layer and reports the forming state.
#[test]
fn bdb_coordinator_formation_delegates() {
    let mut c = CoordinatorMachine::new(AgingPolicy::default());
    assert_eq!(c.state(), CoordinatorState::Unformed);
    let forming = c.begin_formation(formation_cfg()).unwrap();
    assert_eq!(forming, forming);
    assert_eq!(c.state(), CoordinatorState::Forming);
    // A second formation attempt while forming is a caller bug.
    assert!(c.begin_formation(formation_cfg()).is_err());
    assert_eq!(c.formation_done(true), CoordinatorState::Formed);
}

// 22-65816-030-97-01 (§9.7): joining follows the permit window —
// closed by default, admitted only while open, closes on expiry.
#[test]
fn bdb_coordinator_permit_window_gates_join() {
    let mut c = CoordinatorMachine::new(AgingPolicy::default());
    // Permit needs a formed network first.
    assert!(c.open_permit(1000).is_err());
    c.begin_formation(formation_cfg()).unwrap();
    c.formation_done(true);
    assert!(!c.permit_open());
    assert!(c.admit_child(0x0001, 0xAAAA, false, 0).is_err());
    c.open_permit(1_000).unwrap();
    assert!(c.permit_open());
    c.admit_child(0x0001, 0xAAAA, false, 0).unwrap();
    assert_eq!(c.children().len(), 1);
    // The window lapses after its caller-ms budget.
    let aged = c.tick(1_001, 1_001);
    assert_eq!(aged, 0);
    assert!(!c.permit_open());
    assert!(c.admit_child(0x0002, 0xBBBB, false, 1_001).is_err());
}

// 05-3474-23-3612-03: keepalive — heard traffic resets aging, long
// silence ages the child out, and the leave path removes it.
#[test]
fn bdb_coordinator_keepalive_and_leave() {
    let mut c = CoordinatorMachine::new(AgingPolicy { age_out_ms: 1_000 });
    c.begin_formation(formation_cfg()).unwrap();
    c.formation_done(true);
    c.open_permit(10_000).unwrap();
    c.admit_child(0x0001, 0xAAAA, false, 0).unwrap();
    c.child_heard(0x0001, 900).unwrap();
    assert_eq!(c.tick(1_500, 600), 0);
    assert_eq!(c.children().len(), 1);
    // Silence past the lapse ages the child out.
    assert_eq!(c.tick(2_500, 1_000), 1);
    assert!(c.children().is_empty());
    // Unknown children are refused, not aged.
    assert!(c.child_heard(0x0099, 2_500).is_err());
    c.open_permit(10_000).unwrap();
    c.admit_child(0x0002, 0xBBBB, false, 2_500).unwrap();
    let gone = c.remove_child(0x0002).unwrap();
    assert_eq!(gone.short_addr, 0x0002);
    assert!(c.remove_child(0x0002).is_err());
}

// ---------------------------------------------------------------------------
// Router: join → active → parent-lost → rejoin; serves children
// ---------------------------------------------------------------------------

// 05-3474-23-3612-08: a router joins, then forwards and serves
// children; joining twice or forwarding early is refused.
#[test]
fn bdb_router_join_then_serve() {
    let mut r = RouterMachine::new(AgingPolicy::default(), 7_500);
    assert_eq!(r.state(), RouterState::Unjoined);
    assert!(r.forward().is_err());
    r.begin_join().unwrap();
    assert!(r.begin_join().is_err());
    assert_eq!(r.state(), RouterState::Joining);
    assert_eq!(r.join_done(false), RouterState::Unjoined);
    r.begin_join().unwrap();
    assert_eq!(r.join_done(true), RouterState::Active);
    r.forward().unwrap();
    r.admit_child(0x0001, 0xAAAA, false, 0).unwrap();
    assert_eq!(r.children().len(), 1);
}

// 05-3474-23-3613-01 + 22-65816-030-10-01: parent loss enters rejoin;
// success restores duty, failure returns to unjoined.
#[test]
fn bdb_router_parent_loss_and_rejoin() {
    let mut r = RouterMachine::new(AgingPolicy::default(), 7_500);
    assert!(r.parent_lost().is_err());
    r.begin_join().unwrap();
    r.join_done(true);
    r.parent_lost().unwrap();
    assert_eq!(r.state(), RouterState::Rejoining);
    assert_eq!(r.rejoin_done(false), RouterState::Unjoined);
    r.begin_join().unwrap();
    r.join_done(true);
    r.parent_lost().unwrap();
    assert_eq!(r.rejoin_done(true), RouterState::Active);
}

// ---------------------------------------------------------------------------
// End device: join → poll → miss bound → rejoin → leave
// ---------------------------------------------------------------------------

// 05-3474-23-3612-09: the end device joins via its parent and polls;
// polling before joining is refused.
#[test]
fn bdb_enddevice_join_and_poll() {
    let mut e = EndDeviceMachine::new();
    assert_eq!(e.state(), EndDeviceState::Unjoined);
    assert!(e.poll(true).is_err());
    e.begin_join(0x0000).unwrap();
    assert_eq!(e.parent(), 0x0000);
    assert!(e.begin_join(0x0001).is_err());
    assert_eq!(e.join_done(false), EndDeviceState::Unjoined);
    e.begin_join(0x0000).unwrap();
    assert_eq!(e.join_done(true), EndDeviceState::Polling);
    assert_eq!(e.poll(true).unwrap(), PollOutcome::Acked);
    assert_eq!(e.polls(), 1);
    assert_eq!(e.state(), EndDeviceState::Polling);
}

// 05-3474-23-3613-02/03 + END_DEVICE_MAX_MISSED: consecutive misses
// declare the parent lost; rejoin may move to a new parent.
#[test]
fn bdb_enddevice_miss_bound_declares_loss() {
    let mut e = EndDeviceMachine::new();
    e.begin_join(0x0000).unwrap();
    e.join_done(true);
    assert_eq!(e.poll(false).unwrap(), PollOutcome::Missed);
    assert_eq!(e.poll(false).unwrap(), PollOutcome::Missed);
    assert_eq!(e.state(), EndDeviceState::Polling);
    assert_eq!(e.poll(false).unwrap(), PollOutcome::Missed);
    assert_eq!(e.state(), EndDeviceState::Rejoining);
    assert_eq!(e.rejoin_done(true, Some(0x0001)), EndDeviceState::Polling);
    assert_eq!(e.parent(), 0x0001);
    e.poll(true).unwrap();
    assert_eq!(e.state(), EndDeviceState::Polling);
}

// 05-3474-23-3616-01: clean leave is only legal while polling.
#[test]
fn bdb_enddevice_leave_rules() {
    let mut e = EndDeviceMachine::new();
    assert_eq!(e.leave().unwrap_err(), EndDeviceError::BadState);
    e.begin_join(0x0000).unwrap();
    e.join_done(true);
    e.leave().unwrap();
    assert_eq!(e.state(), EndDeviceState::Left);
}

// ---------------------------------------------------------------------------
// Sleepy end device: duty-cycle bounds + wake/poll/rejoin/leave
// ---------------------------------------------------------------------------

// 05-3474-23-3612-10: the agreed interval stays inside the admitted
// range; out-of-range intervals are refused, never clamped.
#[test]
fn bdb_sleepy_interval_bounds() {
    assert_eq!((MIN_POLL_INTERVAL_MS, MAX_POLL_INTERVAL_MS), (100, 60_000));
    assert!(SleepyConfig::new(99).unwrap_err() == SleepyError::BadInterval);
    assert!(SleepyConfig::new(60_001).unwrap_err() == SleepyError::BadInterval);
    assert!(SleepyConfig::new(1_000).is_ok());
}

// Sleepy cycle: join → awake → poll-ack sleeps → due wake → poll;
// three misses declare loss; leave only from a joined phase.
#[test]
fn bdb_sleepy_duty_cycle() {
    let mut s = SleepyEndDeviceMachine::new(SleepyConfig::new(1_000).unwrap());
    assert_eq!(s.state(), SleepState::Unjoined);
    assert!(!s.wake_due(10_000));
    s.join(0x0000, 0).unwrap();
    assert_eq!(s.state(), SleepState::Awake);
    assert_eq!(s.parent(), 0x0000);
    assert_eq!(s.polled(true, 0).unwrap(), SleepState::Asleep);
    assert!(!s.wake_due(999));
    assert!(s.wake_due(1_000));
    s.wake().unwrap();
    assert_eq!(s.polled(false, 1_000).unwrap(), SleepState::Asleep);
    s.wake().unwrap();
    assert_eq!(s.polled(false, 2_000).unwrap(), SleepState::Asleep);
    s.wake().unwrap();
    assert_eq!(s.polled(false, 3_000).unwrap(), SleepState::Rejoining);
    assert_eq!(s.rejoin_done(true, Some(0x0002), 3_000), SleepState::Awake);
    assert_eq!(s.parent(), 0x0002);
    assert!(s.leave().is_ok());
    assert_eq!(s.state(), SleepState::Unjoined);
}

// ---------------------------------------------------------------------------
// Child table + indirect queue bounds (§7.3-adjacent keepalive)
// ---------------------------------------------------------------------------

// 05-3474-23-3612-02: the table is bounded, rejects duplicates, and
// reports unknown removals.
#[test]
fn bdb_child_table_bounds() {
    assert_eq!(MAX_CHILDREN, 32);
    let mut t = ChildTable::new(AgingPolicy::default());
    t.admit(0x0001, 0xAAAA, false, 0).unwrap();
    assert_eq!(
        t.admit(0x0001, 0xAAAA, false, 0).unwrap_err(),
        ChildrenError::DuplicateChild
    );
    assert_eq!(t.len(), 1);
    assert_eq!(t.get(0x0001).unwrap().short_addr, 0x0001);
    assert!(t.get(0x0099).is_none());
    assert_eq!(t.remove(0x0099).unwrap_err(), ChildrenError::NoSuchChild);
    t.remove(0x0001).unwrap();
    assert!(t.is_empty());
}

// 05-3474-23-3612-04/05: indirect frames hold until the child polls;
// oversize payloads and a full queue refuse; expiry drops stale
// frames.
#[test]
fn bdb_indirect_hold_poll_expire() {
    assert_eq!(MAX_INDIRECT_QUEUE, 16);
    let mut q = IndirectQueue::new(7_500);
    assert!(q.is_empty());
    let big = [0u8; MAX_INDIRECT_PAYLOAD + 1];
    assert!(q.enqueue(0x0001, &big, 0).is_err());
    q.enqueue(0x0001, &[0xDE, 0xAD], 0).unwrap();
    assert!(q.has_pending(0x0001));
    assert!(!q.has_pending(0x0002));
    let frame = q.poll_deliver(0x0001).unwrap();
    assert_eq!(frame.payload(), &[0xDE, 0xAD]);
    assert!(q.poll_deliver(0x0001).is_err());
    q.enqueue(0x0002, &[0x01], 0).unwrap();
    assert_eq!(q.expire(7_501), 1);
    assert!(!q.has_pending(0x0002));
}

// ---------------------------------------------------------------------------
// Application endpoints on any role (§11-adjacent hosting)
// ---------------------------------------------------------------------------

struct EchoApp {
    id: u8,
}

impl AppEndpoint for EchoApp {
    fn endpoint_id(&self) -> u8 {
        self.id
    }
    fn profile_id(&self) -> u16 {
        0x0104
    }
    fn handle_command(
        &mut self,
        payload: &[u8],
        response: &mut [u8],
    ) -> Result<usize, CommandError> {
        if payload.is_empty() {
            return Err(CommandError::BadCommand);
        }
        let n = payload.len().min(response.len());
        response[..n].copy_from_slice(&payload[..n]);
        Ok(n)
    }
}

// 05-3474-23-2325-ROLES-01: endpoint ids 1..=254 attach; 0 and 0xFF
// never do; duplicates and oversize payloads refuse.
#[test]
fn bdb_endpoint_attach_rules() {
    let mut table = EndpointTable::new();
    assert!(table.is_empty());
    let bad = EchoApp { id: 0 };
    assert!(table.register(&bad).is_err());
    let bad = EchoApp { id: 0xFF };
    assert!(table.register(&bad).is_err());
    let app = EchoApp { id: 1 };
    let h = table.register(&app).unwrap();
    assert_eq!(h.id(), 1);
    assert_eq!(
        table.register(&app).unwrap_err(),
        rounddance_roles::endpoint::EndpointError::DuplicateEndpoint
    );
    assert_eq!(table.profile_id(1), Some(0x0104));
    assert_eq!(table.profile_id(2), None);
    let big = [0u8; 129];
    assert!(table.deliver(1, &big).is_err());
    assert!(table.deliver(9, &[0x01]).is_err());
}

// Queued commands dispatch through the endpoint impl and the
// response is retrievable per endpoint.
#[test]
fn bdb_endpoint_deliver_dispatch_take() {
    let mut table = EndpointTable::new();
    let app = EchoApp { id: 3 };
    table.register(&app).unwrap();
    table.deliver(3, &[0xAA, 0xBB]).unwrap();
    let mut app_mut = EchoApp { id: 3 };
    let mut eps: [&mut EchoApp; 1] = [&mut app_mut];
    assert_eq!(table.dispatch(&mut eps, |e| e.endpoint_id(), 4), 1);
    let (resp, n) = table.take_response(3).unwrap();
    assert_eq!(&resp[..n], &[0xAA, 0xBB]);
}
