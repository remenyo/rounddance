//! Version negotiation: pure state machines, no I/O.
//!
//! The dialer offers `[min, max]`; the listener picks the highest
//! version it also supports, or rejects with its own maximum so the
//! dialer can log something actionable. Both sides converge on
//! [`Negotiated::Up`] with the same `chosen` version, or both land on
//! a terminal reject/closed state. Timeouts and retries belong to the
//! binding driver (see `semantics.md`), not here.

use crate::IfcError;

/// Our supported range on this endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionRange {
    /// Lowest version we speak.
    pub min: u8,
    /// Highest version we speak (`>= min`).
    pub max: u8,
}

impl VersionRange {
    /// This revision: v0 only.
    #[must_use]
    pub const fn v0() -> Self {
        Self { min: 0, max: 0 }
    }
}

/// Terminal outcome of a negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Negotiated {
    /// Link is up on `chosen`.
    Up {
        /// Agreed version.
        chosen: u8,
    },
    /// Peer range missed ours; `peer_max` is what they offered.
    Rejected {
        /// Highest version the peer supports.
        peer_max: u8,
    },
}

/// Dialer side (the end that sends `HELLO` first).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialer {
    /// Nothing sent yet.
    Idle,
    /// `HELLO` sent, awaiting `ACCEPT`/`REJECT`.
    HelloSent,
    /// Terminal: link up.
    Up {
        /// Agreed version.
        chosen: u8,
    },
    /// Terminal: rejected.
    Failed,
}

impl Dialer {
    /// Start from idle; returns the `HELLO` payload `[min, max]`.
    pub fn hello(&mut self, ours: VersionRange) -> Result<[u8; 2], IfcError> {
        if *self != Self::Idle {
            return Err(IfcError::NotReady);
        }
        *self = Self::HelloSent;
        Ok([ours.min, ours.max])
    }

    /// Consume an `ACCEPT { chosen }` payload.
    pub fn accept(&mut self, ours: VersionRange, chosen: u8) -> Result<Negotiated, IfcError> {
        if *self != Self::HelloSent {
            return Err(IfcError::NotReady);
        }
        if chosen < ours.min || chosen > ours.max {
            *self = Self::Failed;
            return Err(IfcError::VersionMismatch);
        }
        *self = Self::Up { chosen };
        Ok(Negotiated::Up { chosen })
    }

    /// Consume a `REJECT { peer_max }` payload.
    pub fn reject(&mut self, peer_max: u8) -> Result<Negotiated, IfcError> {
        if *self != Self::HelloSent {
            return Err(IfcError::NotReady);
        }
        *self = Self::Failed;
        Ok(Negotiated::Rejected { peer_max })
    }
}

/// Listener side (the end that answers `HELLO`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Listener {
    /// Awaiting `HELLO`.
    Idle,
    /// Terminal: link up.
    Up {
        /// Agreed version.
        chosen: u8,
    },
    /// Terminal: rejected the dialer.
    Failed,
}

/// Listener answer to a `HELLO`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Send `ACCEPT` with this version.
    Accept {
        /// Agreed version.
        chosen: u8,
    },
    /// Send `REJECT` with our maximum.
    Reject {
        /// Highest version we support.
        our_max: u8,
    },
}

impl Listener {
    /// Answer a `HELLO { dial_min, dial_max }` payload.
    pub fn hello(
        &mut self,
        ours: VersionRange,
        dial_min: u8,
        dial_max: u8,
    ) -> Result<Answer, IfcError> {
        if *self != Self::Idle {
            return Err(IfcError::NotReady);
        }
        let top = ours.max.min(dial_max);
        let bottom = ours.min.max(dial_min);
        if bottom <= top {
            *self = Self::Up { chosen: top };
            Ok(Answer::Accept { chosen: top })
        } else {
            *self = Self::Failed;
            Ok(Answer::Reject { our_max: ours.max })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_version_converges() {
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
            Answer::Reject { .. } => panic!("same version must accept"),
        }
        assert_eq!(l, Listener::Up { chosen: 0 });
    }

    #[test]
    fn disjoint_ranges_reject() {
        let mut d = Dialer::Idle;
        let hello = d.hello(VersionRange { min: 3, max: 5 }).unwrap();
        let mut l = Listener::Idle;
        match l.hello(VersionRange::v0(), hello[0], hello[1]).unwrap() {
            Answer::Accept { .. } => panic!("disjoint ranges must reject"),
            Answer::Reject { our_max } => {
                assert_eq!(
                    d.reject(our_max).unwrap(),
                    Negotiated::Rejected { peer_max: 0 }
                );
            }
        }
    }
}
