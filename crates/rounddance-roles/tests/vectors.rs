//! Role transcripts: join → poll → rejoin → leave across all roles.
//!
//! Paraphrase-level vectors; each test cites the requirement ID it
//! verifies. Provenance: synthetic (constructed here, no spec bytes).

use rounddance_commission::{ChannelMask, FormationConfig, LogicalType, PanChoice};
use rounddance_roles::{
    AgingPolicy, CoordinatorMachine, CoordinatorState, EndDeviceMachine, EndDeviceState,
    PollOutcome, RouterMachine, RouterState, SleepState, SleepyConfig, SleepyEndDeviceMachine,
    MAX_CHILDREN,
};

fn formation_config() -> FormationConfig {
    FormationConfig {
        role: LogicalType::Coordinator,
        primary: ChannelMask::from_list(&[15]).unwrap(),
        secondary: ChannelMask::empty(),
        scan_duration: 3,
        pan: PanChoice::Auto,
        extended_pan: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        router_short_addr: 0x0000,
    }
}

#[test]
fn coordinator_formation_permit_admit_05_3474_23_3612_06_07() {
    let mut coord = CoordinatorMachine::new(AgingPolicy::default());
    assert_eq!(coord.state(), CoordinatorState::Unformed);
    // Admit before formation is refused.
    assert!(coord
        .admit_child(0x0001, 0x0200_0000_0000_0001, false, 0)
        .is_err());
    coord.begin_formation(formation_config()).unwrap();
    assert_eq!(coord.state(), CoordinatorState::Forming);
    assert_eq!(coord.formation_done(true), CoordinatorState::Formed);
    // Permit closed: admit refused.
    assert!(coord
        .admit_child(0x0001, 0x0200_0000_0000_0001, false, 0)
        .is_err());
    coord.open_permit(60_000).unwrap();
    assert!(coord.permit_open());
    coord
        .admit_child(0x0001, 0x0200_0000_0000_0001, false, 1_000)
        .unwrap();
    assert_eq!(coord.children().len(), 1);
    // Permit expiry closes the window.
    coord.tick(61_001, 61_001);
    assert!(!coord.permit_open());
    assert!(coord
        .admit_child(0x0002, 0x0200_0000_0000_0002, false, 61_001)
        .is_err());
}

#[test]
fn coordinator_child_aging_05_3474_23_3612_03() {
    let mut coord = CoordinatorMachine::new(AgingPolicy { age_out_ms: 1_000 });
    coord.begin_formation(formation_config()).unwrap();
    coord.formation_done(true);
    coord.open_permit(10_000).unwrap();
    coord
        .admit_child(0x0001, 0x0200_0000_0000_0001, false, 0)
        .unwrap();
    // Keepalive resets the clock.
    coord.child_heard(0x0001, 900).unwrap();
    assert_eq!(coord.tick(1_500, 100), 0);
    // Silence past the policy ages the child out.
    assert_eq!(coord.tick(2_000, 600), 1);
    assert!(coord.children().is_empty());
}

#[test]
fn coordinator_table_full_refuses_05_3474_23_3612_02() {
    let mut coord = CoordinatorMachine::new(AgingPolicy::default());
    coord.begin_formation(formation_config()).unwrap();
    coord.formation_done(true);
    coord.open_permit(u64::MAX / 2).unwrap();
    for i in 0..MAX_CHILDREN {
        coord
            .admit_child(
                0x0001 + i as u16,
                0x0200_0000_0000_0000 + i as u64,
                false,
                0,
            )
            .unwrap();
    }
    assert!(coord
        .admit_child(0xFFFF, 0xDEAD_BEEF_CAFE_0000, false, 0)
        .is_err());
}

#[test]
fn router_join_forward_children_05_3474_23_3612_08() {
    let mut router = RouterMachine::new(AgingPolicy::default(), 7_500);
    assert_eq!(router.state(), RouterState::Unjoined);
    assert!(router.forward().is_err());
    router.begin_join().unwrap();
    assert_eq!(router.join_done(true), RouterState::Active);
    router.forward().unwrap();
    router.forward().unwrap();
    assert_eq!(router.forwarded, 2);
    router
        .admit_child(0x0003, 0x0200_0000_0000_0003, false, 100)
        .unwrap();
    assert_eq!(router.children().len(), 1);
}

#[test]
fn router_indirect_hold_and_poll_05_3474_23_3612_04_05() {
    let mut router = RouterMachine::new(AgingPolicy::default(), 7_500);
    router.begin_join().unwrap();
    router.join_done(true);
    router
        .admit_child(0x0004, 0x0200_0000_0000_0004, true, 0)
        .unwrap();
    router.hold_for_child(0x0004, &[0xAA, 0xBB], 1_000).unwrap();
    assert!(router.indirect().has_pending(0x0004));
    let frame = router.serve_poll(0x0004, 2_000).unwrap().unwrap();
    assert_eq!(frame.payload(), &[0xAA, 0xBB]);
    // Second poll with nothing held: empty ack path.
    assert!(router.serve_poll(0x0004, 3_000).unwrap().is_none());
    // Hold expires without a poll.
    router.hold_for_child(0x0004, &[0xCC], 4_000).unwrap();
    let (aged, expired) = router.tick(4_000 + 7_500);
    assert_eq!((aged, expired), (0, 1));
    assert!(!router.indirect().has_pending(0x0004));
}

#[test]
fn router_rejoin_and_leave_05_3474_23_3613_01_3616_01() {
    let mut router = RouterMachine::new(AgingPolicy::default(), 7_500);
    router.begin_join().unwrap();
    router.join_done(true);
    router
        .admit_child(0x0005, 0x0200_0000_0000_0005, false, 0)
        .unwrap();
    router.parent_lost().unwrap();
    assert_eq!(router.state(), RouterState::Rejoining);
    assert_eq!(router.rejoin_done(true), RouterState::Active);
    // Child table survives the parent's rejoin: children stay.
    assert_eq!(router.children().len(), 1);
    let removed = router.remove_child(0x0005).unwrap();
    assert_eq!(removed.short_addr, 0x0005);
    assert!(router.children().is_empty());
}

#[test]
fn enddevice_poll_loss_rejoin_leave_05_3474_23_3612_09_3613() {
    let mut dev = EndDeviceMachine::new();
    dev.begin_join(0x0001).unwrap();
    assert_eq!(dev.join_done(true), EndDeviceState::Polling);
    assert_eq!(dev.parent(), 0x0001);
    assert_eq!(dev.poll(true).unwrap(), PollOutcome::Acked);
    assert_eq!(dev.poll(false).unwrap(), PollOutcome::Missed);
    assert_eq!(dev.poll(false).unwrap(), PollOutcome::Missed);
    // Third consecutive miss declares the parent lost.
    assert_eq!(dev.poll(false).unwrap(), PollOutcome::Missed);
    assert_eq!(dev.state(), EndDeviceState::Rejoining);
    assert_eq!(dev.rejoin_done(true, Some(0x0002)), EndDeviceState::Polling);
    assert_eq!(dev.parent(), 0x0002);
    assert_eq!(dev.polls(), 4);
    dev.leave().unwrap();
    assert_eq!(dev.state(), EndDeviceState::Left);
}

#[test]
fn sleepy_duty_cycle_rejoin_05_3474_23_3612_10() {
    let config = SleepyConfig::new(1_000).unwrap();
    assert!(SleepyConfig::new(50).is_err());
    assert!(SleepyConfig::new(61_000).is_err());
    let mut dev = SleepyEndDeviceMachine::new(config);
    assert_eq!(dev.poll_interval_ms(), 1_000);
    dev.join(0x0001, 0).unwrap();
    assert_eq!(dev.state(), SleepState::Awake);
    // Awake poll re-arms sleep for one interval.
    assert_eq!(dev.polled(true, 0).unwrap(), SleepState::Asleep);
    assert!(!dev.wake_due(999));
    assert!(dev.wake_due(1_000));
    dev.wake().unwrap();
    assert_eq!(dev.polled(true, 1_000).unwrap(), SleepState::Asleep);
    assert_eq!(dev.polls(), 2);
    // Three consecutive missed polls declare loss.
    for t in [2_000, 3_000, 4_000] {
        dev.wake().unwrap();
        dev.polled(false, t).unwrap();
    }
    assert_eq!(dev.state(), SleepState::Rejoining);
    assert_eq!(dev.rejoin_done(true, None, 5_000), SleepState::Awake);
    assert_eq!(dev.parent(), 0x0001);
    dev.polled(true, 5_000).unwrap();
    dev.leave().unwrap();
    assert_eq!(dev.state(), SleepState::Unjoined);
}
