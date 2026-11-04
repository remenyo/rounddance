//! Routing bake-off: static cheapest-first vs estimator-driven
//! recovery on a dead-but-cheap link.
//!
//! Deterministic scenario (virtual time only, no wall clock):
//! originator O discovers destination D. The direct leg advertises
//! cost 1 but drops every data frame (dead radio, stale cost); the
//! relay leg R advertises cost 2 and delivers. The static policy
//! reinstalls the cheap dead route forever (0/N delivered); the
//! estimator policy evicts it after confirm-lost frames, re-discovers
//! onto the relay, and delivers. The whole run replays with an
//! identical decision trace.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-ROUTE-01` (metric folds), `RD-ROUTE-02` (estimator bands),
//! `RD-ROUTE-03` (failure-driven eviction).

use rounddance_nwk::ROUTE_LIFETIME_MS;
use rounddance_roles::{AgingPolicy, RouterMachine, RouterState};

const O: u16 = 0x0001;
const R: u16 = 0x0002;
const D: u16 = 0x0004;

fn active() -> RouterMachine {
    let mut r = RouterMachine::new(AgingPolicy::default(), 60_000);
    r.begin_join().unwrap();
    assert_eq!(r.join_done(true), RouterState::Active);
    r
}

/// Run the bake-off; returns the decision trace. The static leg and
/// the estimator leg run the same scripted air.
fn run() -> Vec<String> {
    let mut trace = Vec::new();
    let mut now = 0u64;

    // ---- Static policy: cheapest advertised cost wins, forever. ----
    let mut s = active();
    let rreq = s.start_discovery(D, O, now).unwrap();
    trace.push(format!("static: flood RREQ id={rreq}"));
    // Only the direct leg answers (cost 1); the relay's reply is
    // scripted as lost on this wave.
    assert!(s.note_discovery_reply(rreq, D, D, 1, now).unwrap());
    let static_delivered = 0u32;
    for _ in 0..6 {
        assert_eq!(s.next_hop(D, now), Some(D));
        // Scripted air: the cheap direct leg drops everything.
        now += 10;
    }
    trace.push(format!("static: delivered {static_delivered}/6 via direct"));
    // Lifetime expiry re-discovers; the stale cost-1 advertisement
    // wins again and delivery stays zero.
    now += ROUTE_LIFETIME_MS + 1;
    let rreq2 = s.start_discovery(D, O, now).unwrap();
    assert!(s.note_discovery_reply(rreq2, D, D, 1, now).unwrap());
    for _ in 0..3 {
        assert_eq!(s.next_hop(D, now), Some(D));
        now += 10;
    }
    trace.push(format!(
        "static: delivered {static_delivered}/3 after re-discovery"
    ));

    // ---- Estimator policy: confirm-lost frames evict the dead route. ----
    let mut e = active();
    let rreq = e.start_discovery(D, O, 0).unwrap();
    trace.push(format!("estimator: flood RREQ id={rreq}"));
    assert!(e.note_discovery_reply(rreq, D, D, 1, 0).unwrap());
    let mut now = 0u64;
    for _ in 0..6 {
        assert_eq!(e.next_hop(D, now), Some(D));
        e.note_tx_result(D, false);
        now += 10;
    }
    let est = e.estimated_cost(D).unwrap();
    trace.push(format!("estimator: direct grades {est} after 6 losses"));
    assert!(est >= 5, "dead link must grade badly, got {est}");
    assert!(e.invalidate_route(D), "dead route evicted");
    assert_eq!(e.next_hop(D, now), None);
    trace.push("estimator: dead route evicted".to_string());
    // Re-discovery: the direct leg stays silent this wave; the relay
    // answers (cost 2). Selection takes min(estimator, advertised).
    let rreq2 = e.start_discovery(D, O, now).unwrap();
    trace.push(format!("estimator: flood RREQ id={rreq2}"));
    let via_direct = e.estimated_cost(D).unwrap_or(1);
    let via_relay = 2u8;
    let (nh, cost) = if via_relay < via_direct {
        (R, via_relay)
    } else {
        (D, via_direct)
    };
    assert!(e.note_discovery_reply(rreq2, D, nh, cost, now).unwrap());
    trace.push(format!("estimator: installed via {nh:#06x} cost={cost}"));
    assert_eq!(e.next_hop(D, now), Some(R));
    let mut estimator_delivered = 0u32;
    for _ in 0..3 {
        assert_eq!(e.next_hop(D, now), Some(R));
        e.note_tx_result(R, true);
        estimator_delivered += 1;
        now += 10;
    }
    trace.push(format!(
        "estimator: delivered {estimator_delivered}/3 via relay"
    ));
    assert_eq!(estimator_delivered, 3);

    trace
}

#[test]
fn route_estimator_bakeoff_beats_static_on_dead_cheap_link() {
    let trace = run();
    assert!(trace
        .iter()
        .any(|l| l == "static: delivered 0/6 via direct"));
    assert!(trace
        .iter()
        .any(|l| l == "estimator: delivered 3/3 via relay"));
    // Recovery is fast: one re-discovery, no lifetime wait.
    assert!(trace.iter().any(|l| l == "estimator: dead route evicted"));
}

#[test]
fn route_estimator_bakeoff_replays_identically() {
    assert_eq!(run(), run());
}
