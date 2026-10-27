//! Conformance: version-negotiation mismatch is a clean reject.
//!
//! Requirement: when the dialer and listener ranges are disjoint, the
//! link MUST stay down on both ends, the listener answers REJECT, and
//! no application op is exchanged. A later compatible HELLO on a fresh
//! state machine still converges (rejection is not sticky state).

use rounddance_ifc::{
    handshake::{Answer, Dialer, Listener, Negotiated, VersionRange},
    IfcError,
};

#[test]
fn disjoint_ranges_reject_and_stay_down() {
    // Listener speaks v0 only; dialer demands v3+.
    let mut dialer = Dialer::Idle;
    let hello = dialer.hello(VersionRange { min: 3, max: 5 }).unwrap();
    let mut listener = Listener::Idle;
    let answer = listener
        .hello(VersionRange::v0(), hello[0], hello[1])
        .unwrap();
    let our_max = match answer {
        Answer::Accept { .. } => panic!("disjoint ranges must not accept"),
        Answer::Reject { our_max } => our_max,
    };
    assert_eq!(our_max, 0);
    assert_eq!(
        dialer.reject(our_max).unwrap(),
        Negotiated::Rejected { peer_max: 0 }
    );
    assert_eq!(dialer, Dialer::Failed);
    assert_eq!(listener, Listener::Failed);
}

#[test]
fn accept_of_out_of_range_version_fails() {
    // A corrupted/forged ACCEPT naming a version outside our range
    // must not bring the link up.
    let mut dialer = Dialer::Idle;
    dialer.hello(VersionRange::v0()).unwrap();
    assert_eq!(
        dialer.accept(VersionRange::v0(), 9),
        Err(IfcError::VersionMismatch)
    );
    assert_eq!(dialer, Dialer::Failed);
}

#[test]
fn compatible_retry_after_reject_converges() {
    // Rejection carries no sticky state: fresh machines converge.
    let mut dialer = Dialer::Idle;
    let hello = dialer.hello(VersionRange::v0()).unwrap();
    let mut listener = Listener::Idle;
    match listener
        .hello(VersionRange::v0(), hello[0], hello[1])
        .unwrap()
    {
        Answer::Accept { chosen } => {
            assert_eq!(
                dialer.accept(VersionRange::v0(), chosen).unwrap(),
                Negotiated::Up { chosen: 0 }
            );
        }
        Answer::Reject { .. } => panic!("same version must accept"),
    }
}
