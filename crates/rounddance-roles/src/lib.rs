//! Device roles: coordinator, router, end device, sleepy end device.
//!
//! Paraphrase-level orchestration over `rounddance-commission`
//! (formation, steering, classical join/rejoin/leave), `rounddance-zdo`
//! (endpoint table, management primitives), and the NWK/APS/security
//! layers those crates already sequence. Nothing here duplicates those
//! machines; this crate only binds them to per-role state machines,
//! parent/child bookkeeping, and application-endpoint hosting.
//!
//! Requirement model (paraphrase only, D1, `SCOPE.md` §2):
//! * Role set + coordinator formation/permit-joining: BDB roles
//!   (`22-65816-030-61-01`, corpus-mined, wave-10) and R23.2 §3.6.1
//!   formation family (repo-minted `05-3474-23-3611-*`, wave-10).
//! * Parent/child table, keepalive/aging, poll handling, indirect
//!   queue: R23.2 §3.6.1.2 family (repo-minted `05-3474-23-3612-*`,
//!   MINTED-pending-confirm).
//! * Rejoin (secured + trust-center paths) and leave: R23.2 §3.6.1.3
//!   family + commission `RejoinMachine`/`LeaveMachine` (repo-minted
//!   `05-3474-23-3613-*`, `05-3474-23-3616-*`, MINTED-pending-confirm).
//! * Application endpoints on any role + router/app simultaneity:
//!   repo-minted `05-3474-23-2325-ROLES-*` (endpoint attach on any
//!   role; MINTED-pending-confirm). Core scope requirement: the C6
//!   MUST route while hosting full app endpoints under one network
//!   identity (founding note; `SCOPE.md`).
//!
//! # Design notes (mirror sibling crates)
//!
//! * `no_std` + `#![forbid(unsafe_code)]`, bounded + fallible +
//!   accountable: child tables, indirect queues, and endpoint slots
//!   are fixed-size arrays; every fallible path returns a typed error.
//! * Time is never read: ticks take caller microseconds (sim virtual
//!   time drives everything deterministically).
//! * Every public item cites the requirement ID it implements.
#![no_std]
#![forbid(unsafe_code)]

pub mod children;
pub mod coordinator;
pub mod enddevice;
pub mod endpoint;
pub mod indirect;
pub mod router;
pub mod sleepy;

pub use children::{AgingPolicy, ChildEntry, ChildTable, ChildrenError, MAX_CHILDREN};
pub use coordinator::{CoordinatorError, CoordinatorMachine, CoordinatorState};
pub use enddevice::{EndDeviceError, EndDeviceMachine, EndDeviceState, PollOutcome};
pub use endpoint::{
    AppEndpoint, CommandError, EndpointHandle, EndpointTable, EndpointTable as AppEndpointTable,
    RouterApp, MAX_APP_ENDPOINTS, MAX_APP_PAYLOAD, MAX_APP_PER_TICK, MAX_ROUTE_PER_TICK,
};
pub use indirect::{
    IndirectError, IndirectQueue, PendingFrame, MAX_INDIRECT_PAYLOAD, MAX_INDIRECT_QUEUE,
};
pub use router::{RouterError, RouterMachine, RouterState};
pub use sleepy::{
    SleepState, SleepyConfig, SleepyEndDeviceMachine, SleepyError, MAX_POLL_INTERVAL_MS,
    MIN_POLL_INTERVAL_MS,
};

/// Device role: the four supported logical types.
///
/// Requirement `05-3474-23-3612-01` (MINTED-pending-confirm): every
/// device operates in exactly one of coordinator / router / end
/// device / sleepy end device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRole {
    /// Network founder; forms and admits joiners.
    Coordinator,
    /// Forwards traffic and serves children + own app endpoints.
    Router,
    /// Non-routing child; polls its parent.
    EndDevice,
    /// Duty-cycled child; polls on a parent-agreed schedule.
    SleepyEndDevice,
}

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-roles"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
    }
}
