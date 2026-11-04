//! APS binding table: bind a local cluster to a group, look the
//! binding back up, and watch duplicates collapse instead of
//! doubling. Covers the addressing input the finding/binding flow
//! feeds on.
//!
//! Run: `cargo run -p rounddance --example aps_binding`

use rounddance::aps::{ApsStatus, BindingDst, BindingEntry, BindingTable, MAX_BINDINGS};

fn main() {
    let mut table = BindingTable::new();
    let entry = BindingEntry {
        src_ieee: 0xa0f262fffe8597a4,
        src_endpoint: 0x01,
        cluster_id: 0x0006,
        dst: BindingDst::Group { group_addr: 0x0001 },
    };
    assert_eq!(table.bind(entry), ApsStatus::Success);
    assert_eq!(table.bind(entry), ApsStatus::Success);
    assert_eq!(table.len(), 1);
    println!("BIND ok, duplicate collapses (len={})", table.len());

    let mut out = [BindingDst::Group { group_addr: 0x0000 }; MAX_BINDINGS];
    let n = table.lookup(0xa0f262fffe8597a4, 0x01, 0x0006, &mut out);
    println!("LOOKUP hits={n} (expected 1)");
    assert_eq!(n, 1);
}
