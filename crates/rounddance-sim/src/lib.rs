//! Deterministic simulation harness stub.
//!
//! Same core + virtualized effects: virtual time, seeded replay, scripted
//! media/faults. `std` is allowed here (harness, not protocol core).
//! Decision determinism: same seed + event script yields the same emitted
//! frames and state transitions, verified by trace comparison.

/// Simulation seed; placeholder type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seed(pub u64);

/// Crate identifier placeholder until implementation lands.
pub fn name() -> &'static str {
    "rounddance-sim"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
        assert_eq!(Seed(42), Seed(42));
    }
}
