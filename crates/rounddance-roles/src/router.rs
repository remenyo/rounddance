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
use rounddance_nwk::{
    DiscoveryTable, LinkStatusEntry, NeighborCosts, RouteTable, RoutingError, SeenRequests,
    ROUTE_LIFETIME_MS,
};

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
    /// Routing-table / discovery failure.
    Routing(RoutingError),
}

impl From<RoutingError> for RouterError {
    fn from(e: RoutingError) -> Self {
        Self::Routing(e)
    }
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
    routes: RouteTable,
    discovery: DiscoveryTable,
    seen: SeenRequests,
    links: NeighborCosts,
    /// Last request identifier issued by our own discoveries.
    rreq_seq: u8,
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
            routes: RouteTable::new(),
            discovery: DiscoveryTable::new(),
            seen: SeenRequests::new(),
            links: NeighborCosts::new(),
            rreq_seq: 0,
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

    /// Next hop toward `dst` from the installed route table, if live.
    /// `forward` still moves the bytes; this answers where they go —
    /// one routing path, not a second one.
    ///
    /// Requirement `05-3474-23-3645-01` (MINTED-pending-confirm).
    #[must_use]
    pub fn next_hop(&self, dst: u16, now_ms: u64) -> Option<u16> {
        self.routes.next_hop(dst, now_ms)
    }

    /// Open route discovery for `dst`: stamps the next request
    /// identifier and returns it so the caller can build the flooded
    /// request. Refuses when not active, when a session for `dst` is
    /// already pending, or under a discovery storm.
    ///
    /// Requirement `05-3474-23-3645-02` (MINTED-pending-confirm).
    pub fn start_discovery(
        &mut self,
        dst: u16,
        local: u16,
        now_ms: u64,
    ) -> Result<u8, RouterError> {
        if self.state != RouterState::Active {
            return Err(RouterError::BadState);
        }
        if dst == local {
            return Err(RouterError::Routing(RoutingError::BadState));
        }
        self.rreq_seq = self.rreq_seq.wrapping_add(1);
        self.discovery
            .start(dst, self.rreq_seq, now_ms)
            .map(|s| s.rreq_id)
            .map_err(RouterError::Routing)
    }

    /// Fold an inbound route reply: resolves the matching pending
    /// session and installs the route via `next_hop` at `cost`.
    /// Returns `true` when a session resolved; stray replies return
    /// `false` and install nothing.
    ///
    /// Requirement `05-3474-23-3645-02` (MINTED-pending-confirm).
    pub fn note_discovery_reply(
        &mut self,
        rreq_id: u8,
        dst: u16,
        next_hop: u16,
        cost: u8,
        now_ms: u64,
    ) -> Result<bool, RouterError> {
        if self.state != RouterState::Active {
            return Err(RouterError::BadState);
        }
        match self.discovery.resolve(rreq_id, now_ms) {
            Ok(session) => {
                self.routes
                    .install(dst, next_hop, cost, now_ms, ROUTE_LIFETIME_MS)
                    .map_err(RouterError::Routing)?;
                let _ = session;
                Ok(true)
            }
            Err(RoutingError::UnknownReply) => Ok(false),
            Err(e) => Err(RouterError::Routing(e)),
        }
    }

    /// Loop suppression for flooded requests: returns `true` when
    /// this (originator, id) was seen within its lifetime and the
    /// caller must drop the repeat instead of re-flooding.
    ///
    /// Requirement `05-3474-23-3645-02` (MINTED-pending-confirm).
    pub fn should_suppress_request(&mut self, originator: u16, rreq_id: u8, now_ms: u64) -> bool {
        self.seen.observe(originator, rreq_id, now_ms)
    }

    /// Fold an inbound link-status frame from `src`: entries naming
    /// `local` refresh our outgoing cost to `src`. Unknown senders
    /// take a free row; a full table keeps live rows and ignores the
    /// rest.
    ///
    /// Requirement `05-3474-23-348-02` (MINTED-pending-confirm).
    pub fn note_link_status(
        &mut self,
        src: u16,
        local: u16,
        entries: &[LinkStatusEntry],
        now_ms: u64,
    ) -> Result<(), RouterError> {
        if self.state != RouterState::Active {
            return Err(RouterError::BadState);
        }
        self.links.note_link_status(src, local, entries, now_ms);
        Ok(())
    }

    /// Record our own incoming-cost measurement for a neighbor.
    ///
    /// Requirement `05-3474-23-348-02` (MINTED-pending-confirm).
    pub fn note_incoming_cost(&mut self, neighbor: u16, cost: u8, now_ms: u64) {
        self.links.note_incoming(neighbor, cost, now_ms);
    }

    /// Our outgoing cost toward `neighbor`, if freshly known.
    ///
    /// Requirement `05-3474-23-348-02` (MINTED-pending-confirm).
    #[must_use]
    pub fn outgoing_cost(&self, neighbor: u16, now_ms: u64) -> Option<u8> {
        self.links.outgoing_to(neighbor, now_ms)
    }

    /// Install a relay-learned route leg (reverse leg from a flooded
    /// request, forward leg from a transiting reply). Same table and
    /// lifetime as discovered routes — one routing path.
    ///
    /// Requirement `05-3474-23-3645-01` (MINTED-pending-confirm).
    pub fn install_route(
        &mut self,
        dst: u16,
        next_hop: u16,
        cost: u8,
        now_ms: u64,
    ) -> Result<(), RouterError> {
        if self.state != RouterState::Active {
            return Err(RouterError::BadState);
        }
        self.routes
            .install(dst, next_hop, cost, now_ms, ROUTE_LIFETIME_MS)
            .map_err(RouterError::Routing)
    }

    /// Authorize a discovery retransmit for `dst`: `Ok(true)` means
    /// flood again now, `Ok(false)` means hold for the retry clock,
    /// `Err` retires the session (caller backs off).
    ///
    /// Requirement `05-3474-23-3645-02` (MINTED-pending-confirm).
    pub fn authorize_discovery_retry(
        &mut self,
        dst: u16,
        now_ms: u64,
    ) -> Result<bool, RouterError> {
        if self.state != RouterState::Active {
            return Err(RouterError::BadState);
        }
        self.discovery
            .authorize_retry(dst, now_ms)
            .map_err(RouterError::Routing)
    }

    /// Age routing state: expires installed routes, retires dead
    /// discovery sessions, ages neighbor costs. Returns
    /// `(routes_expired, sessions_retired, links_aged)`.
    ///
    /// Requirements `05-3474-23-3645-01`, `05-3474-23-348-02`
    /// (MINTED-pending-confirm).
    pub fn tick_routing(&mut self, now_ms: u64) -> (usize, usize, usize) {
        let r = self.routes.expire(now_ms);
        let d = self.discovery.sweep(now_ms);
        let l = self.links.tick(now_ms);
        self.seen.expire(now_ms);
        (r, d, l)
    }

    /// Borrow the route table (test seam).
    #[must_use]
    pub const fn routes(&self) -> &RouteTable {
        &self.routes
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
