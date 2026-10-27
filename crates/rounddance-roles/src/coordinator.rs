//! Coordinator role: formation + permit-joining + child table + aging.
//!
//! Thin orchestration: formation sequencing stays in
//! `rounddance-commission` (`FormationMachine`), admission policy in
//! its `JoinPolicy`/`TrustCenter`; this machine binds them to the
//! coordinator lifecycle and owns the child table.
//!
//! Paraphrase-level model of BDB formation roles (§6.1,
//! `22-65816-030-61-01`, corpus-mined) and the R23.2 §3.6.1.1
//! formation + permit-joining family (repo-minted
//! `05-3474-23-3611-*`, wave-10; new IDs here
//! `05-3474-23-3612-*`, MINTED-pending-confirm). All wording here is
//! paraphrase (D1, `SCOPE.md` §2).

use crate::children::{AgingPolicy, ChildEntry, ChildTable, ChildrenError};
use rounddance_commission::{FormationConfig, FormationMachine, FormationState};

/// Failures from the coordinator machine.
///
/// Requirement `05-3474-23-3612-06` (MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinatorError {
    /// Operation not allowed in the current state.
    BadState,
    /// Child-table failure (full / duplicate / unknown).
    Children(ChildrenError),
    /// Formation layer rejected the request.
    Formation,
}

/// Coordinator lifecycle.
///
/// Requirement `05-3474-23-3612-06` (MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinatorState {
    /// Not formed yet.
    Unformed,
    /// Formation in progress (delegated to commission).
    Forming,
    /// On-network; joining follows the permit window.
    Formed,
}

/// Coordinator: forms the network, gates joining on a permit window,
/// tracks children, and ages silent ones out.
///
/// Requirement `05-3474-23-3612-06` (MINTED-pending-confirm).
pub struct CoordinatorMachine {
    state: CoordinatorState,
    formation: Option<FormationMachine>,
    children: ChildTable,
    /// Permit-joining window: remaining caller ms (0 = closed).
    permit_ms: u64,
}

impl CoordinatorMachine {
    /// New unformed coordinator under `policy`.
    #[must_use]
    pub const fn new(policy: AgingPolicy) -> Self {
        Self {
            state: CoordinatorState::Unformed,
            formation: None,
            children: ChildTable::new(policy),
            permit_ms: 0,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> CoordinatorState {
        self.state
    }

    /// Begin formation with `config`.
    ///
    /// Requirement `05-3474-23-3611-01` (wave-10, reused).
    pub fn begin_formation(
        &mut self,
        config: FormationConfig,
    ) -> Result<FormationState, CoordinatorError> {
        if self.state != CoordinatorState::Unformed {
            return Err(CoordinatorError::BadState);
        }
        let mut machine = FormationMachine::new(config).map_err(|_| CoordinatorError::Formation)?;
        machine.begin(true, false);
        let state = machine.state();
        self.formation = Some(machine);
        self.state = CoordinatorState::Forming;
        Ok(state)
    }

    /// Formation primitive outcome: success marks the network formed.
    ///
    /// Requirement `05-3474-23-3611-01` (wave-10, reused).
    pub fn formation_done(&mut self, success: bool) -> CoordinatorState {
        if self.state == CoordinatorState::Forming {
            if let Some(machine) = self.formation.as_mut() {
                machine.on_confirm(success);
            }
            self.state = if success {
                CoordinatorState::Formed
            } else {
                CoordinatorState::Unformed
            };
        }
        self.state
    }

    /// Open the permit-joining window for `window_ms` caller ms.
    ///
    /// Requirement `05-3474-23-3612-07` (MINTED-pending-confirm).
    pub fn open_permit(&mut self, window_ms: u64) -> Result<(), CoordinatorError> {
        if self.state != CoordinatorState::Formed {
            return Err(CoordinatorError::BadState);
        }
        self.permit_ms = window_ms;
        Ok(())
    }

    /// True while joining is currently permitted.
    #[must_use]
    pub const fn permit_open(&self) -> bool {
        self.permit_ms > 0
    }

    /// Advance the permit window and child aging by `elapsed_ms`.
    ///
    /// Requirement `05-3474-23-3612-07` + `05-3474-23-3612-03`
    /// (MINTED-pending-confirm). Returns children aged out.
    pub fn tick(&mut self, now_ms: u64, elapsed_ms: u64) -> usize {
        self.permit_ms = self.permit_ms.saturating_sub(elapsed_ms);
        self.children.age(now_ms)
    }

    /// Admit a joiner: requires formed state + open permit window.
    ///
    /// Requirement `05-3474-23-3612-07` (MINTED-pending-confirm).
    pub fn admit_child(
        &mut self,
        short_addr: u16,
        ieee_addr: u64,
        sleepy: bool,
        now_ms: u64,
    ) -> Result<(), CoordinatorError> {
        if self.state != CoordinatorState::Formed || !self.permit_open() {
            return Err(CoordinatorError::BadState);
        }
        self.children
            .admit(short_addr, ieee_addr, sleepy, now_ms)
            .map_err(CoordinatorError::Children)
    }

    /// Record traffic from a child (keepalive).
    ///
    /// Requirement `05-3474-23-3612-03` (MINTED-pending-confirm).
    pub fn child_heard(&mut self, short_addr: u16, now_ms: u64) -> Result<(), CoordinatorError> {
        self.children
            .heard(short_addr, now_ms)
            .map_err(CoordinatorError::Children)
    }

    /// Remove a child (leave path).
    ///
    /// Requirement `05-3474-23-3616-01` (MINTED-pending-confirm).
    pub fn remove_child(&mut self, short_addr: u16) -> Result<ChildEntry, CoordinatorError> {
        self.children
            .remove(short_addr)
            .map_err(CoordinatorError::Children)
    }

    /// Borrow the child table.
    #[must_use]
    pub const fn children(&self) -> &ChildTable {
        &self.children
    }
}
