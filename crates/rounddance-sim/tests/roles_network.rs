//! Three-node network: coordinator + router-with-app-endpoint + sleepy.
//!
//! Scenario (deterministic, virtual time only):
//! 1. Coordinator forms, opens permit; router + sleepy join.
//! 2. App traffic routes THROUGH the router while the router serves
//!    its own endpoint in the same tick (simultaneity).
//! 3. Sleepy child polls; the router-held indirect frame is
//!    delivered.
//! 4. Router reboots (state reset); sleepy child declares loss and
//!    rejoins through the recovered router.
//! 5. The whole run replays byte-identically (trace comparison).
//!
//! Requirement traceability: `05-3474-23-3612-06` …
//! `05-3474-23-3612-10`, `05-3474-23-3613-01` …
//! `05-3474-23-3613-03`, `05-3474-23-3616-01`,
//! `05-3474-23-2325-ROLES-01/02` (all MINTED-pending-confirm).

use rounddance_commission::{ChannelMask, FormationConfig, LogicalType, PanChoice};
use rounddance_roles::{
    AgingPolicy, AppEndpoint, CommandError, CoordinatorMachine, EndpointTable, RouterApp,
    RouterMachine, SleepState, SleepyConfig, SleepyEndDeviceMachine, MAX_APP_PAYLOAD,
};
use rounddance_sim::{Seed, VirtualClock};

const COORD: u16 = 0x0000;
const ROUTER: u16 = 0x0001;
const SLEEPY_IEEE: u64 = 0x0200_0000_0000_0003;
const SLEEPY_SHORT: u16 = 0x0003;

struct Thermostat {
    setpoint: u8,
}

impl AppEndpoint for Thermostat {
    fn endpoint_id(&self) -> u8 {
        1
    }
    fn profile_id(&self) -> u16 {
        0x0104
    }
    fn handle_command(
        &mut self,
        payload: &[u8],
        response: &mut [u8],
    ) -> Result<usize, CommandError> {
        // Command 0x00 + 1 data byte sets the setpoint; respond with
        // the stored setpoint.
        if payload.len() == 2 && payload[0] == 0x00 {
            self.setpoint = payload[1];
        }
        if response.is_empty() {
            return Err(CommandError::ResponseTooSmall);
        }
        response[0] = self.setpoint;
        Ok(1)
    }
}

fn lookup(ep: &Thermostat) -> u8 {
    ep.endpoint_id()
}

struct NetworkRun {
    trace: Vec<String>,
    forwarded: u32,
    app_served: u32,
    polls: u32,
    setpoint: u8,
    router_rejoined: bool,
}

/// One deterministic run of the 3-node scenario at `seed`.
fn run(seed: u64) -> NetworkRun {
    let _clock = VirtualClock::new(seed);
    let mut trace = Vec::new();
    let aging = AgingPolicy {
        age_out_ms: 300_000,
    };

    // 1. Coordinator forms + opens permit.
    let mut coord = CoordinatorMachine::new(aging);
    coord
        .begin_formation(FormationConfig {
            role: LogicalType::Coordinator,
            primary: ChannelMask::from_list(&[15]).unwrap(),
            secondary: ChannelMask::empty(),
            scan_duration: 3,
            pan: PanChoice::Auto,
            extended_pan: [0xAA; 8],
            router_short_addr: COORD,
        })
        .unwrap();
    assert_eq!(
        coord.formation_done(true),
        rounddance_roles::CoordinatorState::Formed
    );
    coord.open_permit(600_000).unwrap();
    trace.push("coord-formed".to_string());

    // 2. Router joins (via coordinator) with a hosted thermostat.
    let mut router = RouterMachine::new(aging, 7_500);
    router.begin_join().unwrap();
    router.join_done(true);
    coord
        .admit_child(ROUTER, 0x0200_0000_0000_0001, false, 1_000)
        .unwrap();
    let mut pair = RouterApp::new();
    let mut app_table = EndpointTable::new();
    let mut thermostat = Thermostat { setpoint: 20 };
    app_table.register(&thermostat).unwrap();
    trace.push("router-joined".to_string());

    // Sleepy child joins through the router.
    let mut sleepy = SleepyEndDeviceMachine::new(SleepyConfig::new(5_000).unwrap());
    sleepy.join(ROUTER, 2_000).unwrap();
    router
        .admit_child(SLEEPY_SHORT, SLEEPY_IEEE, true, 2_000)
        .unwrap();
    trace.push("sleepy-joined".to_string());

    // 3. Route app traffic THROUGH the router while it serves its
    // own endpoint in the same tick.
    pair.queue_route(SLEEPY_SHORT, &[0x01, 0x02]).unwrap();
    app_table.deliver(1, &[0x00, 21]).unwrap();
    let mut out = [(0u16, [0u8; MAX_APP_PAYLOAD], 0usize); 8];
    let mut eps: [&mut Thermostat; 1] = [&mut thermostat];
    let (forwarded, served) = pair.tick(&mut app_table, &mut eps, lookup, &mut out);
    assert_eq!((forwarded, served), (1, 1));
    router.forward().unwrap();
    let (resp, n) = app_table.take_response(1).unwrap();
    assert_eq!(&resp[..n], &[21]);
    trace.push(format!("tick1 fwd={forwarded} app={served}"));

    // Sleepy polls; router-held indirect frame is delivered.
    router.hold_for_child(SLEEPY_SHORT, &[0x99], 3_000).unwrap();
    // Sleepy is awake right after join; this poll re-arms sleep.
    sleepy.polled(true, 3_000).unwrap();
    let delivered = router.serve_poll(SLEEPY_SHORT, 3_000).unwrap().unwrap();
    assert_eq!(delivered.payload(), &[0x99]);
    trace.push("indirect-delivered".to_string());

    // 4. Router reboots: fresh machine, rejoins; sleepy misses polls
    // and rejoins through it.
    let mut router2 = RouterMachine::new(aging, 7_500);
    router2.begin_join().unwrap();
    router2.join_done(true);
    router2
        .admit_child(SLEEPY_SHORT, SLEEPY_IEEE, true, 60_000)
        .unwrap();
    // Sleepy misses three polls against the dead parent.
    sleepy.wake().unwrap();
    sleepy.polled(true, 8_000).unwrap(); // last good poll, sleep
    sleepy.wake().unwrap();
    sleepy.polled(false, 13_000).unwrap();
    sleepy.wake().unwrap();
    sleepy.polled(false, 18_000).unwrap();
    sleepy.wake().unwrap();
    assert_eq!(sleepy.polled(false, 23_000).unwrap(), SleepState::Rejoining);
    assert_eq!(
        sleepy.rejoin_done(true, Some(ROUTER), 24_000),
        SleepState::Awake
    );
    let held = router2.serve_poll(SLEEPY_SHORT, 24_000).unwrap();
    assert!(held.is_none()); // reboot cleared the hold: empty ack
    trace.push("sleepy-rejoined".to_string());

    let _ = Seed(seed);
    NetworkRun {
        trace,
        forwarded: pair.forwarded,
        app_served: pair.app_served,
        polls: sleepy.polls(),
        setpoint: thermostat.setpoint,
        router_rejoined: router2.state() == rounddance_roles::RouterState::Active,
    }
}

#[test]
fn three_node_roles_network() {
    let run = run(0xC0FFEE);
    assert_eq!(
        run.trace,
        vec![
            "coord-formed",
            "router-joined",
            "sleepy-joined",
            "tick1 fwd=1 app=1",
            "indirect-delivered",
            "sleepy-rejoined",
        ]
    );
    assert_eq!(run.forwarded, 1);
    assert_eq!(run.app_served, 1);
    assert_eq!(run.polls, 5);
    assert_eq!(run.setpoint, 21);
    assert!(run.router_rejoined);
}

#[test]
fn three_node_roles_replay_is_deterministic() {
    let first = run(1234);
    let second = run(1234);
    assert_eq!(first.trace, second.trace);
    assert_eq!(first.forwarded, second.forwarded);
    assert_eq!(first.app_served, second.app_served);
    assert_eq!(first.polls, second.polls);
    assert_eq!(first.setpoint, second.setpoint);
}
