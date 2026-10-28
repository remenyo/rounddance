//! Route discovery and route/link-cost tables over the NWK command
//! codecs (`commands.rs`).
//!
//! Paraphrase-level model of the discovery flow (doc `05-3474-23`
//! R23.2 §§3.6.4.4–3.6.4.5): a source floods a route request, relays
//! suppress repeats they have already seen, the destination answers
//! with a route reply, and every hop installs the cheaper direction.
//! Link costs age out between reports (§3.4.8 one-hop broadcasts).
//! All wording here is paraphrase; citations name document, revision,
//! and clause only (D1, `SCOPE.md` §2).
//!
//! # Design notes
//!
//! * `no_std` + `#![forbid(unsafe_code)]`, bounded + fallible +
//!   accountable (D5, `SCOPE.md` §2): fixed-size arrays, no allocator,
//!   every exhaustion path returns [`RouteError`] instead of dropping
//!   silently.
//! * One routing path only: these tables back the existing
//!   `RouterMachine::forward` / `RouterApp::tick` seam in
//!   `rounddance-roles` — `next_hop` answers where `forward` sends.
//!   Nothing here moves bytes; the owner moves them.
//! * Time is caller milliseconds (`u64`, wrapping-safe via
//!   `wrapping_sub`): the tables never read a clock, so sim virtual
//!   time and target ticks behave identically.

use crate::commands::{LinkStatusEntry, LINK_COST_MAX_AGE_MS};

/// Declared per-subsystem budget for installed routes (D5).
///
/// Requirement `05-3474-23-3645-01`.
pub const MAX_ROUTES: usize = 16;

/// Declared per-subsystem budget for concurrently pending outgoing
/// discoveries (D5): request storms are refused, never queued
/// unboundedly.
///
/// Requirement `05-3474-23-3645-02`.
pub const MAX_PENDING_DISCOVERIES: usize = 4;

/// Declared per-subsystem budget for remembered
/// (originator, request-id) pairs used for loop suppression (D5).
///
/// Requirement `05-3474-23-3645-02`.
pub const MAX_SEEN_REQUESTS: usize = 8;

/// Declared per-subsystem budget for tracked neighbor link costs (D5).
///
/// Requirement `05-3474-23-348-02`.
pub const MAX_NEIGHBOR_LINKS: usize = 16;

/// How long one installed route lives without refresh.
///
/// Requirement `05-3474-23-3645-01`.
pub const ROUTE_LIFETIME_MS: u64 = 60_000;

/// How long a seen request suppresses repeats (covers the flood
/// window of one discovery wave).
///
/// Requirement `05-3474-23-3645-02`.
pub const SEEN_LIFETIME_MS: u64 = 10_000;

/// Retransmit budget for one outgoing discovery before it fails and
/// the caller backs off.
///
/// Requirement `05-3474-23-3645-02`.
pub const MAX_DISCOVERY_ATTEMPTS: u8 = 3;

/// Minimum spacing between retransmits of the same discovery.
///
/// Requirement `05-3474-23-3645-02`.
pub const DISCOVERY_RETRY_INTERVAL_MS: u64 = 500;

/// Whole-discovery deadline: no session outlives this window.
///
/// Requirement `05-3474-23-3645-02`.
pub const DISCOVERY_TIMEOUT_MS: u64 = 5_000;

/// Saturating path-cost addition: link costs sum along the path and
/// pin at the `u8` ceiling instead of wrapping.
///
/// Requirement `05-3474-23-341-01`.
#[must_use]
pub const fn add_path_cost(base: u8, link: u8) -> u8 {
    base.saturating_add(link)
}

/// Failures from the routing tables. Every variant is a caller-visible
/// refusal, never a silent drop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteError {
    /// Route table holds [`MAX_ROUTES`] entries and none covers `dst`.
    TableFull,
    /// Discovery table holds [`MAX_PENDING_DISCOVERIES`] sessions.
    DiscoveryFull,
    /// A discovery for `dst` is already pending.
    DiscoveryPending,
    /// No discovery session matches this reply.
    UnknownReply,
    /// No route covers `dst` (or every candidate expired).
    NoRoute,
    /// Operation not allowed now (e.g. discovery for our own address).
    BadState,
}

impl core::fmt::Display for RouteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TableFull => write!(f, "route table full"),
            Self::DiscoveryFull => write!(f, "too many pending discoveries"),
            Self::DiscoveryPending => write!(f, "discovery already pending"),
            Self::UnknownReply => write!(f, "reply matches no pending discovery"),
            Self::NoRoute => write!(f, "no route to destination"),
            Self::BadState => write!(f, "routing operation not allowed now"),
        }
    }
}

impl core::error::Error for RouteError {}

/// One installed route: destination via next hop at a known cost.
///
/// Requirement `05-3474-23-3645-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    /// Destination short address this entry covers.
    pub dst: u16,
    /// Next-hop short address toward `dst`.
    pub next_hop: u16,
    /// Accumulated path cost at install time.
    pub cost: u8,
    /// Caller milliseconds after which the entry stops matching.
    pub expires_ms: u64,
}

impl RouteEntry {
    /// True while `now_ms` precedes expiry (wrapping-safe).
    #[must_use]
    pub const fn live(self, now_ms: u64) -> bool {
        now_ms.wrapping_sub(self.expires_ms) >> 63 != 0 && now_ms != self.expires_ms
    }
}

/// Bounded routing table: longest-useful-wins per destination, oldest
/// expiry reclaimed under pressure, never silent growth.
///
/// Requirement `05-3474-23-3645-01`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteTable {
    slots: [Option<RouteEntry>; MAX_ROUTES],
}

impl Default for RouteTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteTable {
    /// Empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_ROUTES],
        }
    }

    /// Live entries (unexpired at `now_ms`).
    #[must_use]
    pub fn len(&self, now_ms: u64) -> usize {
        self.slots
            .iter()
            .filter(|s| s.is_some_and(|e| e.live(now_ms)))
            .count()
    }

    /// Next hop toward `dst`, or `None` when uncovered or expired.
    #[must_use]
    pub fn next_hop(&self, dst: u16, now_ms: u64) -> Option<u16> {
        self.slots.iter().filter_map(|s| *s).find_map(|e| {
            if e.dst == dst && e.live(now_ms) {
                Some(e.next_hop)
            } else {
                None
            }
        })
    }

    /// Install (or refresh) a route. A same-destination entry is
    /// replaced only when the new cost is not worse or the old entry
    /// expired; a genuinely new destination takes a free slot, else
    /// the table refuses with [`RouteError::TableFull`].
    pub fn install(
        &mut self,
        dst: u16,
        next_hop: u16,
        cost: u8,
        now_ms: u64,
        lifetime_ms: u64,
    ) -> Result<(), RouteError> {
        let entry = RouteEntry {
            dst,
            next_hop,
            cost,
            expires_ms: now_ms.wrapping_add(lifetime_ms),
        };
        // Same-destination refresh first: cheaper (or expired) wins.
        for slot in self.slots.iter_mut() {
            if let Some(e) = slot {
                if e.dst == dst && (!e.live(now_ms) || cost <= e.cost) {
                    *slot = Some(entry);
                    return Ok(());
                } else if e.dst == dst {
                    return Ok(());
                }
            }
        }
        // Reclaim an expired slot before refusing.
        for slot in self.slots.iter_mut() {
            if slot.is_none_or(|e| !e.live(now_ms)) {
                *slot = Some(entry);
                return Ok(());
            }
        }
        Err(RouteError::TableFull)
    }

    /// Drop entries at or past expiry; returns the reclaimed count.
    pub fn expire(&mut self, now_ms: u64) -> usize {
        let mut n = 0;
        for slot in self.slots.iter_mut() {
            if let Some(e) = *slot {
                if !e.live(now_ms) {
                    *slot = None;
                    n += 1;
                }
            }
        }
        n
    }
}

/// One outgoing discovery session: the request identifier flood plus
/// the retry clock. Replies resolve it; timeout retires it.
///
/// Requirement `05-3474-23-3645-02`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoverySession {
    /// Destination under discovery.
    pub dst: u16,
    /// Flood identifier stamped on our requests.
    pub rreq_id: u8,
    /// Retransmits sent so far (initial flood counts as one).
    pub attempts: u8,
    /// Earliest caller milliseconds for the next retransmit.
    pub next_retry_ms: u64,
    /// Caller milliseconds after which the session fails.
    pub deadline_ms: u64,
}

impl DiscoverySession {
    /// True while the session may still resolve (attempts remain and
    /// the deadline has not passed).
    #[must_use]
    pub const fn pending(self, now_ms: u64) -> bool {
        self.attempts < MAX_DISCOVERY_ATTEMPTS && self.deadline_ok(now_ms)
    }

    /// True while the deadline has not passed (wrapping-safe).
    #[must_use]
    pub const fn deadline_ok(self, now_ms: u64) -> bool {
        now_ms.wrapping_sub(self.deadline_ms) >> 63 != 0 && now_ms != self.deadline_ms
    }
}

/// Bounded set of outgoing discovery sessions with storm guards:
/// one session per destination, a global cap, spaced retries, and a
/// hard deadline after which the destination fails and the caller
/// backs off before restarting.
///
/// Requirement `05-3474-23-3645-02`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryTable {
    slots: [Option<DiscoverySession>; MAX_PENDING_DISCOVERIES],
}

impl Default for DiscoveryTable {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryTable {
    /// No pending sessions.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_PENDING_DISCOVERIES],
        }
    }

    /// Pending sessions (attempts remain and deadline unpassed).
    #[must_use]
    pub fn pending_count(&self, now_ms: u64) -> usize {
        self.slots
            .iter()
            .filter(|s| s.is_some_and(|e| e.pending(now_ms)))
            .count()
    }

    /// Open a session for `dst`. Refuses duplicates
    /// ([`RouteError::DiscoveryPending`]) and storms
    /// ([`RouteError::DiscoveryFull`]); expired slots are reclaimed
    /// before refusing.
    pub fn start(
        &mut self,
        dst: u16,
        rreq_id: u8,
        now_ms: u64,
    ) -> Result<DiscoverySession, RouteError> {
        for e in self.slots.iter().flatten() {
            if e.dst == dst && e.pending(now_ms) {
                return Err(RouteError::DiscoveryPending);
            }
        }
        self.sweep(now_ms);
        let session = DiscoverySession {
            dst,
            rreq_id,
            attempts: 1,
            next_retry_ms: now_ms.wrapping_add(DISCOVERY_RETRY_INTERVAL_MS),
            deadline_ms: now_ms.wrapping_add(DISCOVERY_TIMEOUT_MS),
        };
        for slot in self.slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(session);
                return Ok(session);
            }
        }
        Err(RouteError::DiscoveryFull)
    }

    /// Authorize a retransmit: `Ok(true)` means send again now (and the
    /// attempt is counted); `Ok(false)` means hold until the retry
    /// clock; `Err` retires the session (deadline passed or attempts
    /// spent — the caller backs off before restarting).
    pub fn authorize_retry(&mut self, dst: u16, now_ms: u64) -> Result<bool, RouteError> {
        for slot in self.slots.iter_mut() {
            if let Some(e) = slot {
                if e.dst == dst {
                    if !e.deadline_ok(now_ms) || e.attempts >= MAX_DISCOVERY_ATTEMPTS {
                        *slot = None;
                        return Err(RouteError::NoRoute);
                    }
                    if now_ms.wrapping_sub(e.next_retry_ms) >> 63 == 0 || now_ms == e.next_retry_ms
                    {
                        e.attempts += 1;
                        e.next_retry_ms = now_ms.wrapping_add(DISCOVERY_RETRY_INTERVAL_MS);
                        return Ok(true);
                    }
                    return Ok(false);
                }
            }
        }
        Err(RouteError::UnknownReply)
    }

    /// Resolve the session whose request identifier matches an
    /// inbound reply; returns the session (caller installs the route
    /// via `RouteTable::install`). Unknown identifiers are refused so
    /// stray replies never install state.
    pub fn resolve(&mut self, rreq_id: u8, now_ms: u64) -> Result<DiscoverySession, RouteError> {
        for slot in self.slots.iter_mut() {
            if let Some(e) = *slot {
                if e.rreq_id == rreq_id && e.pending(now_ms) {
                    *slot = None;
                    return Ok(e);
                }
            }
        }
        Err(RouteError::UnknownReply)
    }

    /// Retire dead sessions (deadline passed or attempts spent);
    /// returns the retired count.
    pub fn sweep(&mut self, now_ms: u64) -> usize {
        let mut n = 0;
        for slot in self.slots.iter_mut() {
            if let Some(e) = *slot {
                if !e.pending(now_ms) {
                    *slot = None;
                    n += 1;
                }
            }
        }
        n
    }
}

/// Remembered (originator, request-id) floods for loop suppression:
/// a relay that has already seen a request must not re-flood it.
///
/// Requirement `05-3474-23-3645-02`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeenRequests {
    slots: [(u16, u8, u64); MAX_SEEN_REQUESTS],
    len: usize,
    cursor: usize,
}

impl Default for SeenRequests {
    fn default() -> Self {
        Self::new()
    }
}

impl SeenRequests {
    /// Empty memory.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [(0, 0, 0); MAX_SEEN_REQUESTS],
            len: 0,
            cursor: 0,
        }
    }

    /// Observe a request flood: returns `true` when this exact
    /// (originator, id) was seen within its lifetime — the caller
    /// suppresses the repeat. Otherwise records it and returns
    /// `false`. The oldest slot is recycled under pressure, so a
    /// storm of distinct floods degrades to re-flooding, never to
    /// unbounded memory.
    pub fn observe(&mut self, originator: u16, rreq_id: u8, now_ms: u64) -> bool {
        self.expire(now_ms);
        for i in 0..self.len {
            let (o, id, _) = self.slots[i];
            if o == originator && id == rreq_id {
                return true;
            }
        }
        let at = if self.len < MAX_SEEN_REQUESTS {
            let at = self.len;
            self.len += 1;
            at
        } else {
            let at = self.cursor;
            self.cursor = (self.cursor + 1) % MAX_SEEN_REQUESTS;
            at
        };
        self.slots[at] = (originator, rreq_id, now_ms);
        false
    }

    /// Drop entries past their lifetime; returns the dropped count.
    pub fn expire(&mut self, now_ms: u64) -> usize {
        let before = self.len;
        let mut kept = 0;
        for i in 0..self.len {
            let (_, _, seen) = self.slots[i];
            if now_ms.wrapping_sub(seen) < SEEN_LIFETIME_MS {
                self.slots[kept] = self.slots[i];
                kept += 1;
            }
        }
        self.len = kept;
        if kept == 0 {
            self.cursor = 0;
        }
        before - kept
    }
}

/// One tracked neighbor: our measured incoming cost plus the
/// outgoing cost the neighbor last advertised for us.
///
/// Requirement `05-3474-23-348-02`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighborLink {
    /// Neighbor short address.
    pub neighbor: u16,
    /// Our own incoming-cost estimate, 1..=7 (0 = no estimate yet).
    pub incoming_cost: u8,
    /// Neighbor's advertised incoming cost for us, 0..=7.
    pub outgoing_cost: u8,
    /// Caller milliseconds of the last update from either side.
    pub last_update_ms: u64,
}

impl NeighborLink {
    /// True while the estimate is fresh (wrapping-safe).
    #[must_use]
    pub const fn fresh(self, now_ms: u64) -> bool {
        now_ms.wrapping_sub(self.last_update_ms) < LINK_COST_AGE_MS
    }
}

/// How long a neighbor estimate survives without refresh; older
/// entries age out on `tick`.
///
/// Requirement `05-3474-23-348-02`.
pub const LINK_COST_AGE_MS: u64 = LINK_COST_MAX_AGE_MS;

/// Neighbor link-cost table fed by inbound link-status frames: our
/// outgoing cost to a neighbor is whatever incoming cost that
/// neighbor last advertised for us (§3.6.4.4), and entries age out
/// between reports.
///
/// Requirement `05-3474-23-348-02`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeighborCosts {
    slots: [Option<NeighborLink>; MAX_NEIGHBOR_LINKS],
}

impl Default for NeighborCosts {
    fn default() -> Self {
        Self::new()
    }
}

impl NeighborCosts {
    /// Empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_NEIGHBOR_LINKS],
        }
    }

    /// Fresh estimates (within [`LINK_COST_AGE_MS`] of `now_ms`).
    #[must_use]
    pub fn len(&self, now_ms: u64) -> usize {
        self.slots
            .iter()
            .filter(|s| s.is_some_and(|e| e.fresh(now_ms)))
            .count()
    }

    /// Our outgoing cost toward `neighbor`, if freshly known.
    #[must_use]
    pub fn outgoing_to(&self, neighbor: u16, now_ms: u64) -> Option<u8> {
        self.slots.iter().filter_map(|s| *s).find_map(|e| {
            if e.neighbor == neighbor && e.fresh(now_ms) && e.outgoing_cost > 0 {
                Some(e.outgoing_cost)
            } else {
                None
            }
        })
    }

    /// Record our own incoming-cost measurement for a neighbor
    /// (caller measures it from received frames).
    pub fn note_incoming(&mut self, neighbor: u16, cost: u8, now_ms: u64) {
        if cost == 0 || cost > 7 {
            return;
        }
        self.upsert(neighbor, Some(cost), None, now_ms);
    }

    /// Fold one inbound link-status frame from `src`: every entry
    /// naming `local` refreshes our outgoing cost to `src` with the
    /// advertised incoming cost. Unknown senders take a free slot;
    /// a full table keeps the freshest entries and ignores the rest
    /// (refusal, never silent eviction of live state).
    pub fn note_link_status(
        &mut self,
        src: u16,
        local: u16,
        entries: &[LinkStatusEntry],
        now_ms: u64,
    ) {
        for e in entries {
            if e.neighbor == local && e.incoming_cost >= 1 && e.incoming_cost <= 7 {
                self.upsert(src, None, Some(e.incoming_cost), now_ms);
            }
        }
    }

    /// Drop stale estimates; returns the dropped count.
    pub fn tick(&mut self, now_ms: u64) -> usize {
        let mut n = 0;
        for slot in self.slots.iter_mut() {
            if let Some(e) = *slot {
                if !e.fresh(now_ms) {
                    *slot = None;
                    n += 1;
                }
            }
        }
        n
    }

    /// Insert or refresh one neighbor row.
    fn upsert(&mut self, neighbor: u16, incoming: Option<u8>, outgoing: Option<u8>, now_ms: u64) {
        for e in self.slots.iter_mut().flatten() {
            if e.neighbor == neighbor {
                if let Some(c) = incoming {
                    e.incoming_cost = c;
                }
                if let Some(c) = outgoing {
                    e.outgoing_cost = c;
                }
                e.last_update_ms = now_ms;
                return;
            }
        }
        for slot in self.slots.iter_mut() {
            if slot.is_none_or(|e| !e.fresh(now_ms)) {
                *slot = Some(NeighborLink {
                    neighbor,
                    incoming_cost: incoming.unwrap_or(0),
                    outgoing_cost: outgoing.unwrap_or(0),
                    last_update_ms: now_ms,
                });
                return;
            }
        }
        // Full of fresh rows: refuse, keep live state.
    }
}
