//! Router role: join + forward + serve children + indirect hold.
//!
//! Thin orchestration: joining/rejoin sequencing stays in
//! `rounddance-commission` (`JoinerMachine`/`RejoinMachine`); this
//! machine binds those outcomes to router duties — a child table,
//! an indirect queue for sleepy children, and a bounded forward
//! counter for the simultaneity tick.
//!
//! Paraphrase-level model of the R23.2 router family (§3.6.1.2 router
//! duties; repo-minted `05-3474-23-3612-*`, MINTED-pending-confirm).
//! All wording here is paraphrase (D1, `SCOPE.md` §2).

use crate::children::{AgingPolicy, ChildEntry, ChildTable, ChildrenError};
use crate::indirect::{IndirectError, IndirectQueue, PendingFrame};

/// Failures from the router machine.
///
/// Requirement `05-3474-23-3612-08` (MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterError {
    /// Operation not allowed in the current state.
    BadState,
    /// Child-table failure.
    Children(ChildrenError),
    /// Indirect-queue failure.
    Indirect(IndirectError),
}

/// Router lifecycle.
///
/// Requirement `05-3474-23-3612-08` (MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterState {
    /// Not on any network.
    Unjoined,
    /// Join in progress (delegated to commission).
    Joining,
    /// On-network: forwarding + serving children.
    Active,
    /// Parent lost; rejoin in progress.
    Rejoining,
}

/// Router: joins, forwards, serves children, and holds indirect
/// data for sleepy children until they poll.
///
/// Requirement `05-3474-23-3612-08` (MINTED-pending-confirm).
pub struct RouterMachine {
    state: RouterState,
    children: ChildTable,
    indirect: IndirectQueue,
    /// Lifetime count of frames forwarded.
    pub forwarded: u32,
}

impl RouterMachine {
    /// New unjoined router.
    #[must_use]
    pub const fn new(policy: AgingPolicy, hold_ms: u64) -> Self {
        Self {
            state: RouterState::Unjoined,
            children: ChildTable::new(policy),
            indirect: IndirectQueue::new(hold_ms),
            forwarded: 0,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> RouterState {
        self.state
    }

    /// Begin joining (caller runs the commission join exchange).
    pub fn begin_join(&mut self) -> Result<(), RouterError> {
        if self.state != RouterState::Unjoined {
            return Err(RouterError::BadState);
        }
        self.state = RouterState::Joining;
        Ok(())
    }

    /// Join outcome: success activates routing duties.
    pub fn join_done(&mut self, success: bool) -> RouterState {
        if self.state == RouterState::Joining {
            self.state = if success {
                RouterState::Active
            } else {
                RouterState::Unjoined
            };
        }
        self.state
    }

    /// Parent lost: enter rejoin.
    ///
    /// Requirement `05-3474-23-3613-01` (MINTED-pending-confirm).
    pub fn parent_lost(&mut self) -> Result<(), RouterError> {
        if self.state != RouterState::Active {
            return Err(RouterError::BadState);
        }
        self.state = RouterState::Rejoining;
        Ok(())
    }

    /// Rejoin outcome: success restores active duty.
    ///
    /// Requirement `05-3474-23-3613-01` (MINTED-pending-confirm).
    pub fn rejoin_done(&mut self, success: bool) -> RouterState {
        if self.state == RouterState::Rejoining {
            self.state = if success {
                RouterState::Active
            } else {
                RouterState::Unjoined
            };
        }
        self.state
    }

    /// Admit a child (router serves children like a coordinator).
    ///
    /// Requirement `05-3474-23-3612-08` (MINTED-pending-confirm).
    pub fn admit_child(
        &mut self,
        short_addr: u16,
        ieee_addr: u64,
        sleepy: bool,
        now_ms: u64,
    ) -> Result<(), RouterError> {
        if self.state != RouterState::Active {
            return Err(RouterError::BadState);
        }
        self.children
            .admit(short_addr, ieee_addr, sleepy, now_ms)
            .map_err(RouterError::Children)
    }

    /// Forward one frame (caller moves the bytes); counts it.
    ///
    /// Requirement `05-3474-23-3612-08` (MINTED-pending-confirm).
    pub fn forward(&mut self) -> Result<(), RouterError> {
        if self.state != RouterState::Active {
            return Err(RouterError::BadState);
        }
        self.forwarded += 1;
        Ok(())
    }

    /// Hold a frame for a sleepy child.
    ///
    /// Requirement `05-3474-23-3612-04` (MINTED-pending-confirm).
    pub fn hold_for_child(
        &mut self,
        child_short: u16,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<(), RouterError> {
        if self.state != RouterState::Active {
            return Err(RouterError::BadState);
        }
        self.children
            .heard(child_short, now_ms)
            .map_err(RouterError::Children)?;
        self.indirect
            .enqueue(child_short, payload, now_ms)
            .map_err(RouterError::Indirect)
    }

    /// Serve a child poll: deliver the oldest held frame, if any.
    /// Returns `None` when nothing is pending (empty ack path).
    ///
    /// Requirement `05-3474-23-3612-05` (MINTED-pending-confirm).
    pub fn serve_poll(
        &mut self,
        child_short: u16,
        now_ms: u64,
    ) -> Result<Option<PendingFrame>, RouterError> {
        if self.state != RouterState::Active {
            return Err(RouterError::BadState);
        }
        self.children
            .heard(child_short, now_ms)
            .map_err(RouterError::Children)?;
        match self.indirect.poll_deliver(child_short) {
            Ok(frame) => Ok(Some(frame)),
            Err(IndirectError::NothingPending) => Ok(None),
            Err(e) => Err(RouterError::Indirect(e)),
        }
    }

    /// Advance aging + indirect expiry; returns `(aged, expired)`.
    ///
    /// Requirement `05-3474-23-3612-03` + `05-3474-23-3612-04`
    /// (MINTED-pending-confirm).
    pub fn tick(&mut self, now_ms: u64) -> (usize, usize) {
        (self.children.age(now_ms), self.indirect.expire(now_ms))
    }

    /// Remove a child (leave path).
    ///
    /// Requirement `05-3474-23-3616-01` (MINTED-pending-confirm).
    pub fn remove_child(&mut self, short_addr: u16) -> Result<ChildEntry, RouterError> {
        self.children
            .remove(short_addr)
            .map_err(RouterError::Children)
    }

    /// Borrow the child table.
    #[must_use]
    pub const fn children(&self) -> &ChildTable {
        &self.children
    }

    /// Borrow the indirect queue.
    #[must_use]
    pub const fn indirect(&self) -> &IndirectQueue {
        &self.indirect
    }
}
