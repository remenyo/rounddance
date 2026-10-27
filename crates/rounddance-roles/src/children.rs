//! Parent/child table with keepalive aging.
//!
//! Paraphrase-level model of the R23.2 parent/child bookkeeping
//! family (§3.6.1.2: a parent tracks joined children, drops entries
//! whose keepalive lapses, and refuses new children at capacity). All
//! wording here is paraphrase (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped), MINTED-pending-confirm.

/// Bound on child entries per parent (declared budget).
///
/// Requirement `05-3474-23-3612-02` (MINTED-pending-confirm).
pub const MAX_CHILDREN: usize = 32;

/// Keepalive lapse after which a silent child ages out, in
/// milliseconds of caller time.
///
/// Requirement `05-3474-23-3612-03` (MINTED-pending-confirm).
pub const CHILD_AGE_OUT_MS: u64 = 3 * 3_600_000;

/// Failures from child-table management.
///
/// Requirement `05-3474-23-3612-02` (MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildrenError {
    /// Table is full; the joiner must be refused.
    TableFull,
    /// No entry for this child address.
    NoSuchChild,
    /// Entry already present for this child address.
    DuplicateChild,
}

/// Aging policy: how long a silent child is kept.
///
/// Requirement `05-3474-23-3612-03` (MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgingPolicy {
    /// Silence lapse that ages a child out (caller ms).
    pub age_out_ms: u64,
}

impl Default for AgingPolicy {
    fn default() -> Self {
        Self {
            age_out_ms: CHILD_AGE_OUT_MS,
        }
    }
}

/// One joined child: network + link identity and last-heard time.
///
/// Requirement `05-3474-23-3612-02` (MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildEntry {
    /// Child short address.
    pub short_addr: u16,
    /// Child extended (IEEE) address.
    pub ieee_addr: u64,
    /// Last-heard caller time in ms (`u64::MAX` = never heard).
    pub last_heard_ms: u64,
    /// True while the child polls on a duty-cycled (sleepy) schedule.
    pub sleepy: bool,
}

/// Bounded table of joined children with keepalive aging.
///
/// Requirement `05-3474-23-3612-02` (MINTED-pending-confirm).
#[derive(Debug, Clone)]
pub struct ChildTable {
    entries: [Option<ChildEntry>; MAX_CHILDREN],
    len: usize,
    policy: AgingPolicy,
}

impl Default for ChildTable {
    fn default() -> Self {
        Self::new(AgingPolicy::default())
    }
}

impl ChildTable {
    /// Empty table under `policy`.
    #[must_use]
    pub const fn new(policy: AgingPolicy) -> Self {
        Self {
            entries: [None; MAX_CHILDREN],
            len: 0,
            policy,
        }
    }

    /// Number of live entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True when no child is tracked.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Admit a child; refuses duplicates and a full table.
    ///
    /// Requirement `05-3474-23-3612-02` (MINTED-pending-confirm).
    pub fn admit(
        &mut self,
        short_addr: u16,
        ieee_addr: u64,
        sleepy: bool,
        now_ms: u64,
    ) -> Result<(), ChildrenError> {
        if self.find_slot(short_addr).is_some() {
            return Err(ChildrenError::DuplicateChild);
        }
        if self.len >= MAX_CHILDREN {
            return Err(ChildrenError::TableFull);
        }
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(ChildEntry {
                    short_addr,
                    ieee_addr,
                    last_heard_ms: now_ms,
                    sleepy,
                });
                self.len += 1;
                return Ok(());
            }
        }
        Err(ChildrenError::TableFull)
    }

    /// Record traffic from a child (resets its keepalive).
    ///
    /// Requirement `05-3474-23-3612-03` (MINTED-pending-confirm).
    pub fn heard(&mut self, short_addr: u16, now_ms: u64) -> Result<(), ChildrenError> {
        match self.find_slot_mut(short_addr) {
            Some(entry) => {
                entry.last_heard_ms = now_ms;
                Ok(())
            }
            None => Err(ChildrenError::NoSuchChild),
        }
    }

    /// Remove a child (leave / rejoin-cleanup path).
    ///
    /// Requirement `05-3474-23-3616-01` (MINTED-pending-confirm).
    pub fn remove(&mut self, short_addr: u16) -> Result<ChildEntry, ChildrenError> {
        for slot in self.entries.iter_mut() {
            if let Some(entry) = slot {
                if entry.short_addr == short_addr {
                    let removed = *entry;
                    *slot = None;
                    self.len -= 1;
                    return Ok(removed);
                }
            }
        }
        Err(ChildrenError::NoSuchChild)
    }

    /// Drop every child silent longer than the aging policy; returns
    /// the number aged out.
    ///
    /// Requirement `05-3474-23-3612-03` (MINTED-pending-confirm).
    pub fn age(&mut self, now_ms: u64) -> usize {
        let mut dropped = 0;
        for slot in self.entries.iter_mut() {
            if let Some(entry) = slot {
                let silent = now_ms.saturating_sub(entry.last_heard_ms);
                if silent >= self.policy.age_out_ms {
                    *slot = None;
                    dropped += 1;
                }
            }
        }
        self.len -= dropped;
        dropped
    }

    /// Look up a child by short address.
    #[must_use]
    pub fn get(&self, short_addr: u16) -> Option<ChildEntry> {
        self.find_slot(short_addr).map(|i| self.entries[i].unwrap())
    }

    /// Iterate live entries.
    pub fn iter(&self) -> impl Iterator<Item = ChildEntry> + '_ {
        self.entries.iter().filter_map(|slot| *slot)
    }

    fn find_slot(&self, short_addr: u16) -> Option<usize> {
        self.entries
            .iter()
            .position(|slot| matches!(slot, Some(entry) if entry.short_addr == short_addr))
    }

    fn find_slot_mut(&mut self, short_addr: u16) -> Option<&mut ChildEntry> {
        self.entries
            .iter_mut()
            .filter_map(|slot| slot.as_mut())
            .find(|entry| entry.short_addr == short_addr)
    }
}
