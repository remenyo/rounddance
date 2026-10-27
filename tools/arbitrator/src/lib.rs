//! Lab hardware arbitrator (Track H, v0).
//!
//! Exclusive serial-port leases, flash/reset/run helpers, capture hooks,
//! and a clean-lifecycle runner with restore-or-quarantine.
//!
//! Host tooling: `std` is allowed here (this crate never ships on ESP).

pub mod capture;
pub mod flash;
pub mod inventory;
pub mod leases;
pub mod pty;
pub mod runner;
