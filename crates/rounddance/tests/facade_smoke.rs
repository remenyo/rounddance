//! Facade smoke tests: the `rounddance` library re-export surface plus
//! the pinned first-transaction digest through the facade path.
//!
//! @covers doc=05-3474-23 rev=R23.2 clause=3.6 lines=p0221-L5224 req=05-3474-23-3611-01

use rounddance::host::scenario::{run_first_transaction, ScenarioConfig};
use rounddance::{aps, commission, nwk, roles, security, zcl, zdo};

#[test]
fn facade_first_transaction_matches_pinned_digest() {
    let outcome = run_first_transaction(ScenarioConfig::first_transaction());
    assert_eq!(outcome.decisions.digest, 0x3ea31047e1933c90);
    assert_eq!(outcome.trace.len(), 35);
    assert!(outcome.decisions.server_onoff);
    assert!(outcome.decisions.reported_onoff);
}

#[test]
fn facade_reexports_resolve_per_layer() {
    // One concrete type per layer through the facade modules.
    let _ = nwk::route::RouteTable::new();
    let _ = aps::tables::BindingTable::new();
    let _ = zdo::endpoint::EndpointTable::new();
    let _ = zcl::onoff::server_store().unwrap();
    let _ = security::ReplayTable::<8>::new();
    // Type-level resolution (no construction needed).
    let _ = core::mem::size_of::<commission::formation::FormationMachine>();
    let _ = core::mem::size_of::<roles::children::ChildTable>();
}
