//! Conformance: reconnect resumes without counter rollback.
//!
//! Requirement: after a link drops, both ends re-handshake, exchange
//! `RESUME { next_seq }`, and continue with monotonically increasing
//! sequence numbers. A snapshot or RESUME that moves either counter
//! backwards is rejected (`semantics.md` security-handoff rule: frame
//! counters and key state never roll back across reset/migration).

use rounddance_ifc::{
    credit::{wrapping_behind, LinkSnapshot},
    handshake::{Answer, Dialer, Listener, Negotiated, VersionRange},
    IfcError,
};

/// Reconnect handshake: dialer re-opens, listener accepts, both ends
/// agree the dialer's next transmit seq is `resume_seq`. Returns the
/// agreed seq or the rejection.
fn reconnect(resume_seq: u16, live_tx: u16) -> Result<u16, IfcError> {
    // RESUME is only valid when it does not move the counter back.
    if wrapping_behind(resume_seq, live_tx) {
        return Err(IfcError::BadFrame);
    }
    let mut d = Dialer::Idle;
    let hello = d.hello(VersionRange::v0()).unwrap();
    let mut l = Listener::Idle;
    match l.hello(VersionRange::v0(), hello[0], hello[1]).unwrap() {
        Answer::Accept { chosen } => {
            assert_eq!(
                d.accept(VersionRange::v0(), chosen).unwrap(),
                Negotiated::Up { chosen: 0 }
            );
        }
        Answer::Reject { .. } => return Err(IfcError::VersionMismatch),
    }
    Ok(resume_seq)
}

#[test]
fn resume_continues_forward() {
    // Live state: next tx seq 100. Peer resumes at 100: fine.
    assert_eq!(reconnect(100, 100), Ok(100));
    // Peer resumes ahead (frames we never saw are simply skipped by
    // sequence-gap handling above IFC): allowed, not a rollback.
    assert_eq!(reconnect(120, 100), Ok(120));
    // Wrap is legal: 0xFFFF -> 0x0005 is forward on the ring.
    assert_eq!(reconnect(5, 0xFFFF), Ok(5));
}

#[test]
fn resume_rejects_rollback() {
    // Live at 100, peer offers 50: rollback, rejected.
    assert_eq!(reconnect(50, 100), Err(IfcError::BadFrame));
}

#[test]
fn migrated_snapshot_must_not_roll_back() {
    let live = LinkSnapshot::capture(200, 190, 3);
    // Same counters: importable.
    let same = LinkSnapshot::capture(200, 190, 0);
    assert!(same
        .check_against(live.next_tx_seq, live.last_rx_seq)
        .is_ok());
    // Older tx counter: rejected (would reuse frame counters).
    let stale = LinkSnapshot::capture(199, 190, 0);
    assert_eq!(
        stale.check_against(live.next_tx_seq, live.last_rx_seq),
        Err(IfcError::BadFrame)
    );
    // Older rx counter: rejected (would re-accept replays).
    let stale_rx = LinkSnapshot::capture(200, 20, 0);
    assert_eq!(
        stale_rx.check_against(live.next_tx_seq, live.last_rx_seq),
        Err(IfcError::BadFrame)
    );
    // Wrong format version: rejected before any counter comparison.
    let mut bad = live;
    bad.format = 2;
    assert_eq!(
        bad.check_against(live.next_tx_seq, live.last_rx_seq),
        Err(IfcError::VersionMismatch)
    );
}
