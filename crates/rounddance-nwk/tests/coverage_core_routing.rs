//! Line-coverage closure for doc `05-3474-23` R23.2 chapter 3 (NWK),
//! part 2: routing (§3.6) — path cost, route table, discovery,
//! broadcast-flood suppression, neighbor costs, link estimation.
//!
//! Each test pins one normative routing behavior against the public
//! API. Comments name the requirement ID plus the gap anchors cited
//! (D1: document number, revision, clause and line only — no spec
//! text reproduced).

use rounddance_nwk::{
    accumulate_path_cost, add_path_cost, DiscoveryTable, LinkEstimator, LinkStatusEntry,
    NeighborCosts, NeighborLink, PathCostMetric, RouteEntry, RouteTable, RoutingError,
    SeenRequests, DISCOVERY_RETRY_INTERVAL_MS, DISCOVERY_TIMEOUT_MS, LINK_COST_AGE_MS,
    MAX_DISCOVERY_ATTEMPTS, ROUTE_LIFETIME_MS,
};

// 05-3474-23-3641-01: path cost folds one hop at a time — saturating
// addition, hop counting, and bottleneck tracking; out-of-scale
// meter readings are clamped into the 1..=7 link scale.
// Anchors: p0300-L7125-L7127, p0297-L7031-L7034.
#[test]
fn path_cost_folds_05_3474_23_3641_01() {
    assert_eq!(add_path_cost(3, 2), 5);
    assert_eq!(add_path_cost(250, 7), 255);
    assert_eq!(accumulate_path_cost(PathCostMetric::SaturatingSum, 3, 2), 5);
    assert_eq!(accumulate_path_cost(PathCostMetric::HopCount, 3, 7), 4);
    assert_eq!(accumulate_path_cost(PathCostMetric::Bottleneck, 3, 7), 7);
    assert_eq!(accumulate_path_cost(PathCostMetric::Bottleneck, 7, 2), 7);
    // A misbehaving meter (0, or above 7) can never poison a route.
    assert_eq!(accumulate_path_cost(PathCostMetric::SaturatingSum, 3, 0), 4);
    assert_eq!(
        accumulate_path_cost(PathCostMetric::SaturatingSum, 3, 200),
        10
    );
    assert_eq!(accumulate_path_cost(PathCostMetric::HopCount, 3, 0), 4);
}

// 05-3474-23-3645-01: the routing table serves the cheapest known
// next hop per destination, expired entries stop matching, cheaper
// refreshes win, and failure-driven eviction drops dead routes early.
// Anchors: p0304-L7190-L7194, p0308-L7302-L7323.
#[test]
fn route_table_lifecycle_05_3474_23_3645_01() {
    let mut table = RouteTable::new();
    assert_eq!(table.len(0), 0);
    assert_eq!(table.next_hop(0x5678, 0), None);
    table
        .install(0x5678, 0x1111, 5, 0, ROUTE_LIFETIME_MS)
        .unwrap();
    assert_eq!(table.next_hop(0x5678, 1_000), Some(0x1111));
    assert_eq!(table.len(1_000), 1);
    // A worse-cost refresh does not displace the live entry.
    table
        .install(0x5678, 0x2222, 9, 2_000, ROUTE_LIFETIME_MS)
        .unwrap();
    assert_eq!(table.next_hop(0x5678, 3_000), Some(0x1111));
    // A cheaper refresh does.
    table
        .install(0x5678, 0x2222, 2, 4_000, ROUTE_LIFETIME_MS)
        .unwrap();
    assert_eq!(table.next_hop(0x5678, 5_000), Some(0x2222));
    // Expiry stops the match; the sweeper reclaims the slot.
    assert_eq!(table.next_hop(0x5678, ROUTE_LIFETIME_MS + 5_000), None);
    assert_eq!(table.expire(ROUTE_LIFETIME_MS + 5_000), 1);
    assert_eq!(table.len(ROUTE_LIFETIME_MS + 5_000), 0);
    // Failure-driven eviction drops the dead route immediately.
    table
        .install(0x9999, 0x1111, 4, 0, ROUTE_LIFETIME_MS)
        .unwrap();
    assert!(table.remove(0x9999));
    assert!(!table.remove(0x9999));
    assert_eq!(table.next_hop(0x9999, 1), None);
    // Entry liveness is wrapping-safe at the boundary.
    let entry = RouteEntry {
        dst: 1,
        next_hop: 2,
        cost: 1,
        expires_ms: 100,
    };
    assert!(entry.live(99));
    assert!(!entry.live(100));
}

// 05-3474-23-3645-02: route discovery — one session per destination,
// spaced retries up to the attempt budget, resolution by the reply,
// deadline retirement.
// Anchors: p0297-L7031-L7034, p0300-L7125-L7133.
#[test]
fn discovery_session_lifecycle_05_3474_23_3645_02() {
    let mut table = DiscoveryTable::new();
    assert_eq!(table.pending_count(0), 0);
    let session = table.start(0x5678, 0x2A, 0).unwrap();
    assert_eq!(session.dst, 0x5678);
    assert_eq!(session.attempts, 1);
    assert_eq!(table.pending_count(0), 1);
    // A second flood for the same destination is refused.
    assert_eq!(
        table.start(0x5678, 0x2B, 1),
        Err(RoutingError::DiscoveryPending)
    );
    // Before the retry clock: hold; after it: retransmit authorized.
    assert_eq!(table.authorize_retry(0x5678, 1), Ok(false));
    assert_eq!(
        table.authorize_retry(0x5678, DISCOVERY_RETRY_INTERVAL_MS),
        Ok(true)
    );
    // The reply resolves the session by its request identifier.
    let resolved = table.resolve(0x2A, DISCOVERY_RETRY_INTERVAL_MS).unwrap();
    assert_eq!(resolved.dst, 0x5678);
    assert_eq!(table.pending_count(DISCOVERY_RETRY_INTERVAL_MS), 0);
    // Past the deadline an unresolved session retires instead.
    table.start(0x1111, 0x01, 0).unwrap();
    let mut now = 0u64;
    let mut retired = false;
    for _ in 0..(MAX_DISCOVERY_ATTEMPTS as usize + 2) {
        now += DISCOVERY_RETRY_INTERVAL_MS;
        match table.authorize_retry(0x1111, now) {
            Ok(_) => {}
            Err(_) => {
                retired = true;
                break;
            }
        }
        if now > DISCOVERY_TIMEOUT_MS {
            break;
        }
    }
    assert!(retired || table.sweep(DISCOVERY_TIMEOUT_MS + 1) >= 1);
}

// 05-3474-23-3645-03: broadcast-flood suppression — a relay that has
// already seen (originator, request-id) suppresses the repeat;
// memories age out on the seen lifetime.
// Anchors: p0297-L7029-L7034, p0308-L7302-L7323.
#[test]
fn seen_requests_suppress_reflood_05_3474_23_3645_03() {
    let mut seen = SeenRequests::new();
    assert!(!seen.observe(0x0001, 0x2A, 0));
    // Repeat within lifetime: suppress.
    assert!(seen.observe(0x0001, 0x2A, 100));
    // Different id or originator: new flood.
    assert!(!seen.observe(0x0001, 0x2B, 100));
    assert!(!seen.observe(0x0002, 0x2A, 100));
    // Aged memories are forgotten.
    assert_eq!(seen.expire(1_000_000), 3);
    assert!(!seen.observe(0x0001, 0x2A, 1_000_000));
}

// 05-3474-23-348-02: neighbor link costs — own incoming measurement,
// outgoing cost learned from the neighbor's link-status frame, and
// freshness aging that drops stale estimates.
// Anchors: p0293-L6925-L6943, p0299-L7067-L7095.
#[test]
fn neighbor_costs_age_05_3474_23_348_02() {
    let mut costs = NeighborCosts::new();
    assert_eq!(costs.outgoing_to(0x1111, 0), None);
    // Out-of-scale measurements are ignored, never stored.
    costs.note_incoming(0x1111, 0, 0);
    costs.note_incoming(0x1111, 9, 0);
    assert_eq!(costs.outgoing_to(0x1111, 1), None);
    // A valid measurement lands; the outgoing side is still unknown.
    costs.note_incoming(0x1111, 2, 10);
    assert_eq!(costs.outgoing_to(0x1111, 11), None);
    // The neighbor's link-status frame teaches us our outgoing cost
    // (its incoming measurement of us).
    let frame = [
        LinkStatusEntry::new(0x1234, 3, 0).unwrap(),
        LinkStatusEntry::new(0x9999, 5, 0).unwrap(),
    ];
    costs.note_link_status(0x1111, 0x1234, &frame, 20);
    assert_eq!(costs.outgoing_to(0x1111, 21), Some(3));
    // Entries for other devices do not leak across neighbors.
    assert_eq!(costs.outgoing_to(0x9999, 21), None);
    // Stale estimates age out on the link-cost lifetime.
    assert_eq!(costs.tick(LINK_COST_AGE_MS + 100), 1);
    assert_eq!(costs.outgoing_to(0x1111, LINK_COST_AGE_MS + 101), None);
    // Freshness is wrapping-safe at the boundary.
    let link = NeighborLink {
        neighbor: 1,
        incoming_cost: 2,
        outgoing_cost: 2,
        last_update_ms: 50,
    };
    assert!(link.fresh(51));
    assert!(!link.fresh(50 + LINK_COST_AGE_MS + 1));
}

// 05-3474-23-3641-02: the delivery-driven estimator — confirmed
// frames improve the cost toward 1, lost frames degrade it; unknown
// neighbors report nothing so the caller falls back.
// Anchors: p0300-L7125-L7127, p0299-L7067-L7095.
#[test]
fn link_estimator_tracks_delivery_05_3474_23_3641_02() {
    let mut est = LinkEstimator::new();
    assert_eq!(est.cost(0x1111), None);
    est.note_result(0x1111, true);
    let first = est.cost(0x1111).unwrap();
    assert!((1..=7).contains(&first));
    // Sustained delivery drives the cost to the floor.
    for _ in 0..64 {
        est.note_result(0x1111, true);
    }
    assert_eq!(est.cost(0x1111), Some(1));
    // Sustained loss degrades it again.
    for _ in 0..64 {
        est.note_result(0x1111, false);
    }
    assert!(est.cost(0x1111).unwrap() > 1);
    // A neighbor never measured stays unknown.
    assert_eq!(est.cost(0x2222), None);
}
