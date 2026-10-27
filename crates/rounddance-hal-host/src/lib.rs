//! Host HAL backends (Linux/Pi + WASM): capability implementations
//! that let the full protocol stack run on the host with no radio
//! hardware.
//!
//! The protocol crates (`mac-sap` through `roles`) are `no_std` and
//! never read time, randomness, or storage directly: every effect
//! arrives through an injected seam. This crate provides the host
//! side of each seam, in two flavors:
//!
//! * **Deterministic** (tests, WASM replay): [`HostClock`] (explicit
//!   ticks), [`HostTimer`], [`HostEntropy::seeded`], [`HostStore`]
//!   (memory), [`HostLog`], and the [`HostMedium`] loopback radio
//!   pair. Same seed + run-id yields identical decisions on native
//!   and `wasm32` (`SCOPE.md` §2 decision determinism).
//! * **Live** (Pi tooling): [`wall_now_us`], [`HostEntropy::from_os`],
//!   and [`FileStore`] (native-only file persistence).
//!
//! [`scenario`] wires every backend into the first complete host
//! transaction: coordinator formation → device join → secured ZCL
//! On command → attribute report, over the loopback pair with APS
//! security on.
//!
//! # Spec-area citations
//!
//! Harness detail per `SCOPE.md` §8 (same core + virtualized
//! effects); requirements-seed: N-A (the harness verifies
//! requirements, it is not one). Scenario steps cite the
//! requirement IDs they exercise (see [`scenario`]).
#![deny(unsafe_code)]

pub mod clock;
pub mod entropy;
pub mod log;
pub mod radio;
pub mod scenario;
pub mod store;
pub mod timer;

pub use clock::{wall_now_us, HostClock};
pub use entropy::HostEntropy;
pub use log::{EventKind, HostLog, LogEvent};
pub use radio::{HostMedium, HostRadio, NodeId};
#[cfg(not(target_arch = "wasm32"))]
pub use store::FileStore;
pub use store::{HostStore, KvError};
pub use timer::{HostTimer, TimerError};

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-hal-host"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
    }
}
