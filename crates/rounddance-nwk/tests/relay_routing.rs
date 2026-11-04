//! Route-table checks for the relay leg: install, next-hop lookup,
//! expiry, cost-gated refresh, failure-driven removal, and
//! table-full refusal.
//!
//! @covers doc=05-3474-23 rev=R23.2 clause=3.6 lines=p0249-L5842 req=05-3474-23-3645-01
//! @covers doc=05-3474-23 rev=R23.2 clause=3.6 lines=p0249-L5842 req=05-3474-23-3645-02

use rounddance_nwk::route::{RouteError, RouteTable, MAX_ROUTES, ROUTE_LIFETIME_MS};

const NOW: u64 = 1_000_000;

#[test]
fn install_then_next_hop_via_router() {
    // TC -> 0x0003 via 0x0002: the relay leg the grandchild relay
    // installs on first learning the grandchild.
    let mut t = RouteTable::new();
    assert_eq!(t.len(NOW), 0);
    t.install(0x0003, 0x0002, 1, NOW, ROUTE_LIFETIME_MS)
        .unwrap();
    assert_eq!(t.next_hop(0x0003, NOW), Some(0x0002));
    assert_eq!(t.next_hop(0x0004, NOW), None);
    assert_eq!(t.len(NOW), 1);
}

#[test]
fn expired_route_is_uncovered_until_refreshed() {
    let mut t = RouteTable::new();
    t.install(0x0003, 0x0002, 1, NOW, 1_000).unwrap();
    assert_eq!(t.next_hop(0x0003, NOW + 999), Some(0x0002));
    assert_eq!(t.next_hop(0x0003, NOW + 1_000), None);
    assert_eq!(t.len(NOW + 1_000), 0);
    assert_eq!(t.expire(NOW + 1_000), 1);
    // Re-install after expiry recovers the leg.
    t.install(0x0003, 0x0002, 1, NOW + 1_000, ROUTE_LIFETIME_MS)
        .unwrap();
    assert_eq!(t.next_hop(0x0003, NOW + 1_000), Some(0x0002));
}

#[test]
fn worse_cost_refresh_keeps_cheaper_next_hop() {
    let mut t = RouteTable::new();
    t.install(0x0003, 0x0002, 1, NOW, ROUTE_LIFETIME_MS)
        .unwrap();
    // A worse-cost report for the same destination is acknowledged
    // but does not displace the cheaper installed leg.
    t.install(0x0003, 0x0004, 5, NOW + 10, ROUTE_LIFETIME_MS)
        .unwrap();
    assert_eq!(t.next_hop(0x0003, NOW + 10), Some(0x0002));
    // A cheaper report does displace it.
    t.install(0x0003, 0x0004, 0, NOW + 20, ROUTE_LIFETIME_MS)
        .unwrap();
    assert_eq!(t.next_hop(0x0003, NOW + 20), Some(0x0004));
}

#[test]
fn remove_evicts_dead_route_for_rediscovery() {
    let mut t = RouteTable::new();
    t.install(0x0003, 0x0002, 1, NOW, ROUTE_LIFETIME_MS)
        .unwrap();
    assert!(t.remove(0x0003));
    assert_eq!(t.next_hop(0x0003, NOW), None);
    assert!(!t.remove(0x0003));
}

#[test]
fn full_table_refuses_then_reclaims_expired_slot() {
    let mut t = RouteTable::new();
    for i in 0..MAX_ROUTES {
        t.install(0x0010 + i as u16, 0x0002, 1, NOW, ROUTE_LIFETIME_MS)
            .unwrap();
    }
    assert_eq!(
        t.install(0x00FF, 0x0002, 1, NOW, ROUTE_LIFETIME_MS),
        Err(RouteError::TableFull)
    );
    // An expired slot is reclaimed before refusing.
    assert_eq!(t.expire(NOW + ROUTE_LIFETIME_MS), MAX_ROUTES);
    t.install(
        0x00FF,
        0x0002,
        1,
        NOW + ROUTE_LIFETIME_MS,
        ROUTE_LIFETIME_MS,
    )
    .unwrap();
    assert_eq!(t.next_hop(0x00FF, NOW + ROUTE_LIFETIME_MS), Some(0x0002));
}
