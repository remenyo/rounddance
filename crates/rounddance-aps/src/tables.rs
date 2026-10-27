//! Binding and group table stubs: typed structures with declared
//! capacity budgets, insert/remove/lookup, and the confirm statuses the
//! primitives produce. Full bind-manager behavior (discovery-driven
//! binding, multi-hop resolution) is a later wave; structures now.
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
