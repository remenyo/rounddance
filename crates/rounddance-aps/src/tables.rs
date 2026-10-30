//! Binding and group table stubs: typed structures with declared
//! capacity budgets, insert/remove/lookup, and the confirm statuses the
//! primitives produce. The indirect-transmit bind-manager decision
//! (discovery-fed address resolution plus per-destination fan-out
//! planning) lives here too; on-air discovery exchanges and route
//! repair stay with the ZDO/NWK layers (see residue note on
//! [`AddrMap`]).
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2 §§2.2.4.3
//! (binding), 2.2.4.5 (group management), and 2.2.8.3 (group table).
//! All wording here is paraphrase.
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped) pending seed
//! extraction of chapter 2.

use crate::status::ApsStatus;

/// Binding table capacity (declared budget; the spec fixes no size —
/// a full table confirms `TABLE_FULL`, §2.2.4.3.1.3).
///
/// Requirement `05-3474-23-22431-01`.
pub const MAX_BINDINGS: usize = 16;

/// Group table capacity in (group, endpoint) associations (declared
/// budget; a full table confirms `TABLE_FULL`, §2.2.4.5.1.3).
///
/// Requirement `05-3474-23-22451-01`.
pub const MAX_GROUPS: usize = 8;

/// Discovery address-map capacity in long-to-short pairs (declared
/// budget; resolution state only — the spec fixes no size).
///
/// Requirement `05-3474-23-22411-09`.
pub const MAX_ADDR_MAP: usize = 16;

/// Binding destination: unicast device address or group address, from
/// the bind-request destination parameters (§2.2.4.3.1.1).
///
/// Requirement `05-3474-23-22431-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingDst {
    /// Unicast binding target.
    Unicast {
        /// 64-bit extended address of the destination device.
        dst_ieee: u64,
        /// Destination endpoint on that device.
        dst_endpoint: u8,
    },
    /// Group binding target.
    Group {
        /// 16-bit group identifier.
        group_addr: u16,
    },
}

/// One binding table entry: local source (endpoint + cluster) mapped
/// to a destination (§2.2.4.3.1.1).
///
/// Requirement `05-3474-23-22431-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingEntry {
    /// 64-bit address of the local bound device.
    pub src_ieee: u64,
    /// Local endpoint (`0x00`–`0xFE`).
    pub src_endpoint: u8,
    /// Cluster the binding covers.
    pub cluster_id: u16,
    /// Where matching frames go.
    pub dst: BindingDst,
}

impl BindingEntry {
    /// Parameter sanity: local endpoint in range (§2.2.4.3.1.3 reports
    /// `ILLEGAL_REQUEST` for out-of-range parameters).
    #[must_use]
    pub const fn params_valid(&self) -> bool {
        self.src_endpoint <= crate::frame::MAX_APP_ENDPOINT
            && match self.dst {
                BindingDst::Unicast { dst_endpoint, .. } => {
                    dst_endpoint <= crate::frame::MAX_APP_ENDPOINT
                }
                BindingDst::Group { .. } => true,
            }
    }
}

/// Binding table with a declared capacity budget.
///
/// Requirement `05-3474-23-22431-01`.
#[derive(Clone, Copy, Debug)]
pub struct BindingTable {
    entries: [Option<BindingEntry>; MAX_BINDINGS],
    len: usize,
}

impl Default for BindingTable {
    fn default() -> Self {
        Self::new()
    }
}

impl BindingTable {
    /// Empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_BINDINGS],
            len: 0,
        }
    }

    /// Entries currently held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the table holds nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Create the entry (§2.2.4.3.1.3): out-of-range parameters →
    /// `ILLEGAL_REQUEST`; already present → idempotent `SUCCESS`;
    /// no room → `TABLE_FULL`; otherwise stored → `SUCCESS`.
    pub fn bind(&mut self, entry: BindingEntry) -> ApsStatus {
        if !entry.params_valid() {
            return ApsStatus::IllegalRequest;
        }
        if self.entries.contains(&Some(entry)) {
            return ApsStatus::Success;
        }
        if self.len >= MAX_BINDINGS {
            return ApsStatus::TableFull;
        }
        if let Some(slot) = self.entries.iter_mut().find(|e| e.is_none()) {
            *slot = Some(entry);
            self.len += 1;
            ApsStatus::Success
        } else {
            ApsStatus::TableFull
        }
    }

    /// Remove the entry (§2.2.4.3.3.3): present → removed with
    /// `SUCCESS`; absent → `INVALID_BINDING`.
    pub fn unbind(&mut self, entry: &BindingEntry) -> ApsStatus {
        match self.entries.iter_mut().find(|e| **e == Some(*entry)) {
            Some(slot) => {
                *slot = None;
                self.len -= 1;
                ApsStatus::Success
            }
            None => ApsStatus::InvalidBinding,
        }
    }

    /// Collect destinations bound to one local source endpoint and
    /// cluster into `out`; returns the number written. Used on the
    /// indirect-transmit path (§2.2.4.1.1.3: one request fans out over
    /// every matching entry).
    ///
    /// Requirement `05-3474-23-22411-03`.
    pub fn lookup(
        &self,
        src_ieee: u64,
        src_endpoint: u8,
        cluster_id: u16,
        out: &mut [BindingDst; MAX_BINDINGS],
    ) -> usize {
        let mut n = 0;
        for e in self.entries.iter().flatten() {
            if e.src_ieee == src_ieee
                && e.src_endpoint == src_endpoint
                && e.cluster_id == cluster_id
            {
                out[n] = e.dst;
                n += 1;
            }
        }
        n
    }
}

/// Group table with a declared capacity budget: the set of
/// (group, endpoint) associations (§2.2.8.3.1).
///
/// Requirement `05-3474-23-22831-01`.
#[derive(Clone, Copy, Debug)]
pub struct GroupTable {
    entries: [Option<(u16, u8)>; MAX_GROUPS],
    len: usize,
}

impl Default for GroupTable {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupTable {
    /// Empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_GROUPS],
            len: 0,
        }
    }

    /// Associations currently held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the table holds nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Add the (group, endpoint) association (§2.2.4.5.1.3):
    /// endpoint outside `0x01`–`0xFE` → `INVALID_PARAMETER`; already
    /// present → idempotent `SUCCESS`; no room → `TABLE_FULL`;
    /// otherwise stored → `SUCCESS`.
    ///
    /// Requirement `05-3474-23-22451-01`.
    pub fn add(&mut self, group_addr: u16, endpoint: u8) -> ApsStatus {
        if endpoint == crate::frame::ENDPOINT_ZDO
            || endpoint == crate::frame::ENDPOINT_BROADCAST_ALL
        {
            return ApsStatus::InvalidParameter;
        }
        if self.entries.contains(&Some((group_addr, endpoint))) {
            return ApsStatus::Success;
        }
        if self.len >= MAX_GROUPS {
            return ApsStatus::TableFull;
        }
        match self.entries.iter_mut().find(|e| e.is_none()) {
            Some(slot) => {
                *slot = Some((group_addr, endpoint));
                self.len += 1;
                ApsStatus::Success
            }
            None => ApsStatus::TableFull,
        }
    }

    /// Remove one association. `true` when something was removed
    /// (§2.2.4.5.3.3 confirms `SUCCESS` then; unknown groups confirm
    /// `INVALID_GROUP` — see [`GroupTable::remove_exact`]).
    pub fn remove(&mut self, group_addr: u16, endpoint: u8) -> bool {
        match self
            .entries
            .iter_mut()
            .find(|e| **e == Some((group_addr, endpoint)))
        {
            Some(slot) => {
                *slot = None;
                self.len -= 1;
                true
            }
            None => false,
        }
    }

    /// Remove-group confirm mapping (§2.2.4.5.3.3): removed →
    /// `SUCCESS`, absent → `INVALID_GROUP`.
    ///
    /// Requirement `05-3474-23-22451-02`.
    pub fn remove_exact(&mut self, group_addr: u16, endpoint: u8) -> ApsStatus {
        if self.remove(group_addr, endpoint) {
            ApsStatus::Success
        } else {
            ApsStatus::InvalidGroup
        }
    }

    /// Collect endpoints associated with `group_addr` into `out`
    /// (§2.2.8.4.2 group delivery); returns the number written.
    ///
    /// Requirement `05-3474-23-22842-01`.
    pub fn members(&self, group_addr: u16, out: &mut [u8; MAX_GROUPS]) -> usize {
        let mut n = 0;
        for (g, ep) in self.entries.iter().flatten() {
            if *g == group_addr {
                out[n] = *ep;
                n += 1;
            }
        }
        n
    }

    /// Drop every association (remove-all-groups, §2.2.4.5.5).
    pub fn clear(&mut self) {
        self.entries = [None; MAX_GROUPS];
        self.len = 0;
    }
}

/// One discovery-learned long-to-short pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AddrPair {
    /// 64-bit extended address the pair was learned for.
    ieee: u64,
    /// Last reported 16-bit network address for that device.
    nwk: u16,
}

/// Bounded long-to-short address cache fed by discovery outcomes.
///
/// Paraphrase-level model of the §2.2.4.1.1.3 network-address mapping
/// (anchor p0064-L1658-L1690): binding entries name unicast targets
/// by long address, but frames go out by short address, so the
/// indirect-transmit decision consults this cache. The caller records
/// discovery outcomes here (`Device_annce`, `IEEE_addr_rsp` /
/// `NWK_addr_rsp` successes surface through the ZDO layer); this
/// table only stores them.
///
/// Residue (deliberately out of scope, cause noted): the on-air
/// discovery exchanges themselves, their timeouts/retries, and
/// multi-hop path repair all live one layer down (ZDO discovery, NWK
/// route discovery, which the APS always leaves enabled — see the SAP
/// note in [`crate::retry`]). A cached short is hop-agnostic: nearby
/// and multi-hop targets resolve identically.
///
/// Eviction is a declared-budget policy, not spec text: a repeated
/// report refreshes the pair in place; a new long address takes an
/// empty slot; a full map overwrites the oldest slot (ring).
///
/// Requirement `05-3474-23-22411-09`.
#[derive(Clone, Copy, Debug)]
pub struct AddrMap {
    entries: [Option<AddrPair>; MAX_ADDR_MAP],
    len: usize,
    next: usize,
}

impl Default for AddrMap {
    fn default() -> Self {
        Self::new()
    }
}

impl AddrMap {
    /// Empty map.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_ADDR_MAP],
            len: 0,
            next: 0,
        }
    }

    /// Pairs currently held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the map holds nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Short address last reported for `ieee`, if any.
    #[must_use]
    pub const fn lookup(&self, ieee: u64) -> Option<u16> {
        let mut i = 0;
        while i < MAX_ADDR_MAP {
            if let Some(pair) = self.entries[i] {
                if pair.ieee == ieee {
                    return Some(pair.nwk);
                }
            }
            i += 1;
        }
        None
    }

    /// Record a discovery outcome: refresh in place when the long
    /// address is already cached, fill an empty slot, or overwrite
    /// the oldest slot when full (never grows past [`MAX_ADDR_MAP`]).
    pub fn note(&mut self, ieee: u64, nwk: u16) {
        let mut i = 0;
        while i < MAX_ADDR_MAP {
            if let Some(pair) = self.entries[i] {
                if pair.ieee == ieee {
                    self.entries[i] = Some(AddrPair { ieee, nwk });
                    return;
                }
            }
            i += 1;
        }
        if self.len < MAX_ADDR_MAP {
            let mut j = 0;
            while j < MAX_ADDR_MAP {
                if self.entries[j].is_none() {
                    self.entries[j] = Some(AddrPair { ieee, nwk });
                    self.len += 1;
                    return;
                }
                j += 1;
            }
        } else {
            self.entries[self.next % MAX_ADDR_MAP] = Some(AddrPair { ieee, nwk });
            self.next = (self.next + 1) % MAX_ADDR_MAP;
        }
    }

    /// Drop the pair for `ieee`. Returns `true` when something was
    /// removed.
    pub fn forget(&mut self, ieee: u64) -> bool {
        let mut i = 0;
        while i < MAX_ADDR_MAP {
            if let Some(pair) = self.entries[i] {
                if pair.ieee == ieee {
                    self.entries[i] = None;
                    self.len -= 1;
                    return true;
                }
            }
            i += 1;
        }
        false
    }
}

/// One resolved indirect destination: a binding entry whose network
/// address is known, ready to hand down with route discovery enabled.
///
/// Requirement `05-3474-23-22411-10`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedDst {
    /// Unicast target: long address plus its resolved short and the
    /// destination endpoint from the binding entry.
    Unicast {
        /// 64-bit extended address from the binding entry.
        ieee: u64,
        /// Resolved 16-bit network address.
        nwk: u16,
        /// Destination endpoint from the binding entry.
        endpoint: u8,
    },
    /// Group target: no short address is needed.
    Group {
        /// 16-bit group identifier from the binding entry.
        group_addr: u16,
    },
}

/// Indirect-transmit dispatch plan: the resolved fan-out plus the
/// long addresses still needing discovery and the confirm the
/// indirect request reports.
///
/// Built by [`BindingTable::plan_indirect`]; arrays are dense in
/// `[0, len)` and bounded by [`MAX_BINDINGS`].
///
/// Requirement `05-3474-23-22411-10`.
#[derive(Clone, Copy, Debug)]
pub struct IndirectPlan {
    dests: [ResolvedDst; MAX_BINDINGS],
    dest_len: usize,
    needs: [u64; MAX_BINDINGS],
    need_len: usize,
    confirm: ApsStatus,
}

impl Default for IndirectPlan {
    fn default() -> Self {
        Self::new()
    }
}

impl IndirectPlan {
    /// Empty plan: nothing resolved, nothing pending, confirm carries
    /// `NO_BOUND_DEVICE` until [`BindingTable::plan_indirect`] fills
    /// it in.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            dests: [ResolvedDst::Group { group_addr: 0 }; MAX_BINDINGS],
            dest_len: 0,
            needs: [0; MAX_BINDINGS],
            need_len: 0,
            confirm: ApsStatus::NoBoundDevice,
        }
    }

    /// Confirm the indirect request reports (`SUCCESS`,
    /// `NO_BOUND_DEVICE`, `NO_SHORT_ADDRESS`, or `NOT_SUPPORTED`).
    #[must_use]
    pub const fn confirm(&self) -> ApsStatus {
        self.confirm
    }

    /// Resolved destinations, in binding-table order.
    #[must_use]
    pub fn resolved(&self) -> &[ResolvedDst] {
        let n = if self.dest_len < MAX_BINDINGS {
            self.dest_len
        } else {
            MAX_BINDINGS
        };
        self.dests.split_at(n).0
    }

    /// Long addresses with a matching entry but no cached short:
    /// the caller should run targeted discovery (`IEEE_addr_req`)
    /// for these, record the outcome via [`AddrMap::note`], and
    /// re-plan.
    #[must_use]
    pub fn unresolved(&self) -> &[u64] {
        let n = if self.need_len < MAX_BINDINGS {
            self.need_len
        } else {
            MAX_BINDINGS
        };
        self.needs.split_at(n).0
    }
}

impl BindingTable {
    /// Plan one indirect (binding-mode) transmit (§2.2.4.1.1.3, anchor
    /// p0064-L1658-L1690): fan out over every entry matching
    /// (`src_ieee`, `src_endpoint`, `cluster_id`), resolve each
    /// unicast entry through the discovery-fed [`AddrMap`], and pass
    /// group entries through unresolved (they need no short).
    ///
    /// Decision table (confirms are the Table 2-29 values from
    /// [`ApsStatus`]):
    /// * device holds no binding table (`binding_supported == false`)
    ///   → `NOT_SUPPORTED`, empty plan;
    /// * no entry matches → `NO_BOUND_DEVICE`, empty plan;
    /// * entries match and at least one resolves → `SUCCESS` with the
    ///   resolved fan-out; unresolvable longs are additionally listed
    ///   by [`IndirectPlan::unresolved`] for follow-on discovery;
    /// * entries match but none resolves → `NO_SHORT_ADDRESS` with
    ///   every long listed for discovery.
    ///
    /// Resolution is hop-agnostic on purpose: a cached short may name
    /// a neighbor or a multi-hop target — the NWK layer (which the
    /// APS always asks to route-discover) owns the path. Nothing
    /// here touches the radio; the caller transmits the resolved
    /// destinations and runs discovery for the rest.
    ///
    /// Requirement `05-3474-23-22411-10`.
    #[must_use]
    pub fn plan_indirect(
        &self,
        addrs: &AddrMap,
        binding_supported: bool,
        src_ieee: u64,
        src_endpoint: u8,
        cluster_id: u16,
    ) -> IndirectPlan {
        let mut plan = IndirectPlan::new();
        if !binding_supported {
            plan.confirm = ApsStatus::NotSupported;
            return plan;
        }
        let mut matched = false;
        for entry in self.entries.iter().flatten() {
            if entry.src_ieee != src_ieee
                || entry.src_endpoint != src_endpoint
                || entry.cluster_id != cluster_id
            {
                continue;
            }
            matched = true;
            match entry.dst {
                BindingDst::Group { group_addr } => {
                    if plan.dest_len < MAX_BINDINGS {
                        plan.dests[plan.dest_len] = ResolvedDst::Group { group_addr };
                        plan.dest_len += 1;
                    }
                }
                BindingDst::Unicast {
                    dst_ieee,
                    dst_endpoint,
                } => match addrs.lookup(dst_ieee) {
                    Some(nwk) => {
                        if plan.dest_len < MAX_BINDINGS {
                            plan.dests[plan.dest_len] = ResolvedDst::Unicast {
                                ieee: dst_ieee,
                                nwk,
                                endpoint: dst_endpoint,
                            };
                            plan.dest_len += 1;
                        }
                    }
                    None => {
                        if plan.need_len < MAX_BINDINGS
                            && !plan.needs[..plan.need_len].contains(&dst_ieee)
                        {
                            plan.needs[plan.need_len] = dst_ieee;
                            plan.need_len += 1;
                        }
                    }
                },
            }
        }
        plan.confirm = if !matched {
            ApsStatus::NoBoundDevice
        } else if plan.dest_len == 0 {
            ApsStatus::NoShortAddress
        } else {
            ApsStatus::Success
        };
        plan
    }
}
