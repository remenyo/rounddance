//! Bounded typed attribute store with access rules.
//!
//! Paraphrase-level model of doc `07-5123-08` §2.3.4.4 (attribute
//! access classes, anchor p0058-L2309-L2313), §2.3.4.5 (mandatory
//! globals, anchor p0058-L2316), Table 2-1 (global attributes,
//! anchor p0058-L2317-L2318), §2.3.4.6 (configuration persistence,
//! anchor p0059-L2346), and the write-validation order of §2.5.3.3
//! (anchor p0067-L2561-L2581). All wording here is paraphrase (D1).
//!
//! Requirement IDs: `07-5123-08-2344-01` + `07-5123-08-2345-04`
//! (repo-minted, MINTED-pending-confirm); `07-5123-08-2345-01`,
//! `07-5123-08-2346-01`, `07-5123-08-253-01` corpus-mined and reused.

use crate::types::{DataType, Value};
use crate::{Error, ZclStatus};

/// Largest attribute population one store holds. Cluster definitions
/// here stay far below it; oversize definitions are rejected at init.
pub const MAX_ATTRS: usize = 32;

/// Access classes granted to global read/write/report commands.
///
/// Requirement `07-5123-08-2344-01` (MINTED-pending-confirm).
pub mod access {
    /// Readable via global read commands.
    pub const READ: u8 = 0x01;
    /// Writable via global write commands.
    pub const WRITE: u8 = 0x02;
    /// Conditionally writable (implementation decides; refusals report
    /// `ReadOnly` unless the cluster says otherwise).
    pub const WRITE_COND: u8 = 0x04;
    /// Reportable via the reporting mechanism.
    pub const REPORT: u8 = 0x08;
    /// Scene member (accessed via scene extension fields).
    pub const SCENE: u8 = 0x10;
}

/// Static description of one attribute: identifier, wire type, access,
/// and whether the cluster lists it as reportable.
///
/// Requirements `07-5123-08-2344-01` + `07-5123-08-257-01`
/// (corpus-mined, reportable set declared per cluster).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttrDef {
    /// Attribute identifier.
    pub id: u16,
    /// Wire data type.
    pub datatype: u8,
    /// [`access`] bitmask.
    pub access: u8,
    /// In the cluster's reportable set (extra attributes may still be
    /// enabled per implementation).
    pub reportable: bool,
}

impl AttrDef {
    /// Readable through global read commands.
    #[must_use]
    pub const fn readable(self) -> bool {
        self.access & access::READ != 0
    }

    /// Writable through global write commands (plain or conditional;
    /// conditional refusals surface per-attribute).
    #[must_use]
    pub const fn writable(self) -> bool {
        self.access & (access::WRITE | access::WRITE_COND) != 0
    }
}

/// Global ClusterRevision attribute (mandatory on every instance).
///
/// Requirement `07-5123-08-2345-04` (MINTED-pending-confirm).
pub const ATTR_CLUSTER_REVISION: u16 = 0xfffd;
/// Global AttributeReportingStatus attribute (optional).
///
/// Requirement `07-5123-08-2345-04` (MINTED-pending-confirm).
pub const ATTR_REPORTING_STATUS: u16 = 0xfffe;

/// Range/acceptability hook for cluster-specific write guards
/// (e.g. level envelope, sensitivity bounds). Returns the status to
/// report on rejection, or `None` to accept.
pub type WriteGuard = fn(attr: u16, value: &Value) -> Option<ZclStatus>;

/// One live attribute: static definition plus current value.
#[derive(Clone, Copy, Debug)]
struct Entry {
    def: AttrDef,
    value: Value,
}

/// Bounded store of typed attribute values.
///
/// Requirement `07-5123-08-2345-01` (corpus-mined): the store always
/// carries the mandatory globals. Requirement `07-5123-08-2346-01`
/// (corpus-mined): persistence of configuration attributes is the
/// app's job (NVM writes on [`AttrStore::write`] success); sensor or
/// computed values are never treated as configuration here.
#[derive(Clone, Debug)]
pub struct AttrStore {
    entries: [Option<Entry>; MAX_ATTRS],
    len: u8,
    guard: Option<WriteGuard>,
}

impl AttrStore {
    /// Empty store with an optional cluster write guard.
    #[must_use]
    pub const fn new(guard: Option<WriteGuard>) -> Self {
        Self {
            entries: [None; MAX_ATTRS],
            len: 0,
            guard,
        }
    }

    /// Number of live attributes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// No attributes registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Register one attribute with its initial value. The value's
    /// wire type must match the definition; globals may be added by
    /// the caller or via [`AttrStore::add_globals`].
    pub fn add(&mut self, def: AttrDef, value: Value) -> Result<(), Error> {
        if value.datatype().as_u8() != def.datatype {
            return Err(Error::TypeMismatch);
        }
        if self.len as usize >= MAX_ATTRS {
            return Err(Error::TooManyAttributes);
        }
        if self.find_index(def.id).is_some() {
            return Err(Error::DuplicateAttribute);
        }
        self.entries[self.len as usize] = Some(Entry { def, value });
        self.len += 1;
        Ok(())
    }

    /// Register the mandatory ClusterRevision global with `revision`.
    ///
    /// Requirement `07-5123-08-2345-01` (corpus-mined).
    pub fn add_globals(&mut self, revision: u16) -> Result<(), Error> {
        self.add(
            AttrDef {
                id: ATTR_CLUSTER_REVISION,
                datatype: DataType::UInt(2).as_u8(),
                access: access::READ,
                reportable: false,
            },
            Value::UInt {
                width: 2,
                v: revision as u64,
            },
        )
    }

    const fn find_index(&self, id: u16) -> Option<usize> {
        let mut i = 0;
        while i < self.len as usize {
            if let Some(e) = self.entries[i] {
                if e.def.id == id {
                    return Some(i);
                }
            }
            i += 1;
        }
        None
    }

    /// Static definition for `id`, if implemented.
    #[must_use]
    pub fn definition(&self, id: u16) -> Option<AttrDef> {
        self.find_index(id).map(|i| self.entries[i].unwrap().def)
    }

    /// Current value for `id`, if implemented.
    #[must_use]
    pub fn get(&self, id: u16) -> Option<Value> {
        self.find_index(id).map(|i| self.entries[i].unwrap().value)
    }

    /// Local (non-protocol) update: bypasses access checks, keeps the
    /// type check. Used by cluster behaviors applying command effects.
    pub fn set_local(&mut self, id: u16, value: Value) -> Result<(), Error> {
        let i = self.find_index(id).ok_or(Error::UnknownAttribute(id))?;
        let def = self.entries[i].unwrap().def;
        if value.datatype().as_u8() != def.datatype {
            return Err(Error::TypeMismatch);
        }
        // NOTE: entries are `Copy`; mutate in place, never via `unwrap()`.
        self.entries[i].as_mut().unwrap().value = value;
        Ok(())
    }

    /// Protocol write path with the fixed validation order:
    /// implemented → type correct → writable → acceptable/in range.
    ///
    /// Requirement `07-5123-08-253-01` (corpus-mined).
    pub fn write(&mut self, id: u16, value: Value) -> Result<(), ZclStatus> {
        let i = self.find_index(id).ok_or(ZclStatus::UnsupportedAttribute)?;
        let def = self.entries[i].unwrap().def;
        if value.datatype().as_u8() != def.datatype {
            return Err(ZclStatus::InvalidDataType);
        }
        if !def.writable() {
            return Err(ZclStatus::ReadOnly);
        }
        if let Some(guard) = self.guard {
            if let Some(status) = guard(id, &value) {
                return Err(status);
            }
        }
        // NOTE: entries are `Copy`; mutate in place, never via `unwrap()`.
        self.entries[i].as_mut().unwrap().value = value;
        Ok(())
    }

    /// Identifier of the `n`-th attribute (ascending registration
    /// order is the caller's responsibility: cluster definitions list
    /// attributes ascending, so discovery walks in order).
    #[must_use]
    pub fn nth(&self, n: usize) -> Option<(u16, u8)> {
        if n < self.len as usize {
            self.entries[n].map(|e| (e.def.id, e.def.datatype))
        } else {
            None
        }
    }

    /// First index with identifier at or above `start` (definitions
    /// are registered ascending, so this is a linear lower bound).
    #[must_use]
    pub fn lower_bound(&self, start: u16) -> usize {
        let mut i = 0;
        while i < self.len as usize {
            if let Some(e) = self.entries[i] {
                if e.def.id >= start {
                    return i;
                }
            }
            i += 1;
        }
        i
    }
}
