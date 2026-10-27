//! Fuzz: machine input rejection — adversarial inputs never panic.
//!
//! Bounded 8k-case deterministic sweep (seeded LCG, std harness only;
//! the crate under test stays `no_std`). Covers child-table,
//! indirect-queue, endpoint-table, and machine edge inputs.

use rounddance_roles::{
    AgingPolicy, ChildTable, CoordinatorMachine, EndDeviceMachine, EndpointTable, IndirectQueue,
    RouterMachine, SleepyConfig, SleepyEndDeviceMachine, MAX_INDIRECT_PAYLOAD,
};

fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state >> 33
}

#[test]
fn fuzz_child_table_never_panics() {
    let mut rng = 0x1234_5678_9ABC_DEF0u64;
    let mut table = ChildTable::new(AgingPolicy::default());
    for _ in 0..2000 {
        let short = lcg(&mut rng) as u16;
        let ieee = lcg(&mut rng);
        let now = lcg(&mut rng) % 10_000_000;
        match lcg(&mut rng) % 4 {
            0 => {
                let _ = table.admit(short, ieee, lcg(&mut rng).is_multiple_of(2), now);
            }
            1 => {
                let _ = table.heard(short, now);
            }
            2 => {
                let _ = table.remove(short);
            }
            _ => {
                let _ = table.age(now);
            }
        }
        assert!(table.len() <= rounddance_roles::MAX_CHILDREN);
        assert_eq!(table.len(), table.iter().count());
    }
}

#[test]
fn fuzz_indirect_queue_never_panics() {
    let mut rng = 0x0FED_CBA9_8765_4321u64;
    let mut queue = IndirectQueue::default();
    let mut payload = [0u8; MAX_INDIRECT_PAYLOAD + 16];
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    for _ in 0..2000 {
        let child = lcg(&mut rng) as u16;
        let len = (lcg(&mut rng) % (MAX_INDIRECT_PAYLOAD as u64 + 16)) as usize;
        let now = lcg(&mut rng) % 100_000;
        match lcg(&mut rng) % 3 {
            0 => {
                let _ = queue.enqueue(child, &payload[..len], now);
            }
            1 => {
                let _ = queue.poll_deliver(child);
            }
            _ => {
                let _ = queue.expire(now);
            }
        }
        assert!(queue.len() <= rounddance_roles::MAX_INDIRECT_QUEUE);
    }
}

#[test]
fn fuzz_machines_reject_bad_transitions() {
    let mut rng = 0x5555_AAAA_5555_AAAAu64;
    for _ in 0..2000 {
        let op = lcg(&mut rng) % 12;
        match op {
            0 => {
                let mut m = CoordinatorMachine::new(AgingPolicy::default());
                let _ = m.open_permit(lcg(&mut rng));
                let _ = m.admit_child(lcg(&mut rng) as u16, lcg(&mut rng), false, 0);
                let _ = m.child_heard(lcg(&mut rng) as u16, 0);
                let _ = m.remove_child(lcg(&mut rng) as u16);
                let _ = m.tick(lcg(&mut rng), lcg(&mut rng));
            }
            1 => {
                let mut m = RouterMachine::new(AgingPolicy::default(), lcg(&mut rng));
                let _ = m.begin_join();
                let _ = m.join_done(lcg(&mut rng).is_multiple_of(2));
                let _ = m.parent_lost();
                let _ = m.rejoin_done(lcg(&mut rng).is_multiple_of(2));
                let _ = m.forward();
                let payload = [0xAAu8; 8];
                let _ = m.hold_for_child(lcg(&mut rng) as u16, &payload, 0);
                let _ = m.serve_poll(lcg(&mut rng) as u16, 0);
            }
            2 => {
                let mut m = EndDeviceMachine::new();
                let _ = m.begin_join(lcg(&mut rng) as u16);
                let _ = m.join_done(lcg(&mut rng).is_multiple_of(2));
                let _ = m.poll(lcg(&mut rng).is_multiple_of(2));
                let _ = m.rejoin_done(lcg(&mut rng).is_multiple_of(2), None);
                let _ = m.leave();
            }
            3 => {
                let interval = lcg(&mut rng);
                if let Ok(config) = SleepyConfig::new(interval) {
                    let mut m = SleepyEndDeviceMachine::new(config);
                    let _ = m.join(lcg(&mut rng) as u16, 0);
                    let _ = m.wake();
                    let _ = m.polled(lcg(&mut rng).is_multiple_of(2), lcg(&mut rng));
                    let _ = m.rejoin_done(lcg(&mut rng).is_multiple_of(2), None, 0);
                    let _ = m.leave();
                } else {
                    assert!(!(rounddance_roles::MIN_POLL_INTERVAL_MS
                        ..=rounddance_roles::MAX_POLL_INTERVAL_MS)
                        .contains(&interval));
                }
            }
            _ => {
                let mut table = EndpointTable::new();
                let _ = table.deliver((lcg(&mut rng) % 256) as u8, &[0xAA]);
                let _ = table.take_response((lcg(&mut rng) % 256) as u8);
            }
        }
    }
}
