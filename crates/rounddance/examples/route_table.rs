//! Route table: install a route, forward by next hop, and watch it
//! expire off the clock. Covers the discovery-independent half of
//! NWK routing.
//!
//! Run: `cargo run -p rounddance --example route_table`

use rounddance::nwk::RouteTable;

fn main() {
    let mut table = RouteTable::new();
    table
        .install(0x0002, 0x0001, 3, 0, 60_000)
        .expect("slot free");
    assert_eq!(table.next_hop(0x0002, 1_000), Some(0x0001));
    println!("INSTALLED dst=0x0002 via=0x0001 (60 s lifetime)");

    assert_eq!(table.next_hop(0x0003, 1_000), None);
    println!("UNKNOWN dst uncovered, as it should be");

    assert_eq!(table.next_hop(0x0002, 61_000), None);
    println!("EXPIRED route stops forwarding after its lifetime");
}
