//! Configurable attribute reporting with tick-clocked delivery.
//!
//! Paraphrase-level model of doc `07-5123-08` §2.5.7.1.5–1.7
//! (interval + change semantics, anchors p0071-L2696-L2714),
//! §2.5.7.3 (validation chain, anchors p0072-L2732-L2755 +
//! p0073-L2761-L2768), §2.5.10.1.2 (query statuses, anchor
//! p0076-L2852-L2858), and §2.5.11.2.1–2.5.11.2.3 (periodic,
//! discrete-change, analog-change generation rules, anchors
//! p0079-L2931-L2947). All wording here is paraphrase (D1).
//!
//! Requirement IDs: `07-5123-08-257-01..05` + `07-5123-08-25-10-01`
//! corpus-mined and reused; `07-5123-08-2511-02` (tick engine)
//! repo-minted, MINTED-pending-confirm.
//!
//! Time is caller-supplied seconds (`now_s`); this engine never reads
//! a clock, mirroring the APS/NWK tick-clocked blocks.

use crate::attrs::AttrStore;
use crate::general::ReportCfgRecord;
use crate::types::{DataType, Value};
use crate::ZclStatus;

/// Largest live report configuration population.
pub const MAX_REPORT_SLOTS: usize = 16;

/// Minimum reporting interval that restores the default configuration
/// when paired with a zero maximum.
pub const DEFAULT_RESTORE_MIN: u16 = 0xffff;
/// Maximum reporting interval that disables reporting for the entry.
pub const REPORTING_DISABLED_MAX: u16 = 0xffff;

/// One live report configuration: intervals, change threshold, and
/// the last reported value/time for change detection.
///
/// Requirements `07-5123-08-257-02` (corpus-mined, interval encoding)
/// plus `07-5123-08-257-03` (corpus-mined, analog-only threshold).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportSlot {
    /// Configured attribute.
    pub attr: u16,
    /// Floor between change reports (0 = no floor).
    pub min_s: u16,
    /// Periodic ceiling (`0xffff` = reporting disabled).
    pub max_s: u16,
    /// Analog change threshold (meaningful for analog types only).
    pub change: Value,
    /// Value at the last emitted report (change baseline).
    pub last_value: Value,
    /// Caller seconds at the last emitted report.
    pub last_at_s: u64,
}

/// Tick-clocked reporting engine: bounded slots, fallible setup,
/// deterministic due computation.
///
/// Requirement `07-5123-08-2511-02` (MINTED-pending-confirm).
#[derive(Clone, Debug)]
pub struct ReportingEngine {
    slots: [Option<ReportSlot>; MAX_REPORT_SLOTS],
    len: u8,
    timeouts: [Option<TimeoutSlot>; MAX_REPORT_SLOTS],
    timeout_len: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TimeoutSlot {
    attr: u16,
    timeout_s: u16,
}

impl Default for ReportingEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportingEngine {
    /// Empty engine.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_REPORT_SLOTS],
            len: 0,
            timeouts: [None; MAX_REPORT_SLOTS],
            timeout_len: 0,
        }
    }

    /// Live send-configuration count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// No live configurations.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    const fn find(&self, attr: u16) -> Option<usize> {
        let mut i = 0;
        while i < self.len as usize {
            if let Some(s) = self.slots[i] {
                if s.attr == attr {
                    return Some(i);
                }
            }
            i += 1;
        }
        None
    }

    /// Apply one validated send-direction record against `store`.
    /// Returns the per-record status for the response frame.
    ///
    /// Requirements `07-5123-08-257-04` (corpus-mined, validation
    /// chain) + `07-5123-08-257-02` (corpus-mined, disable/default
    /// encodings).
    pub fn configure(&mut self, store: &AttrStore, rec: &ReportCfgRecord, now_s: u64) -> ZclStatus {
        let def = match store.definition(rec.id) {
            Some(d) => d,
            None => return ZclStatus::UnsupportedAttribute,
        };
        let dtype = match DataType::from_u8(def.datatype) {
            Ok(t) => t,
            Err(_) => return ZclStatus::InvalidDataType,
        };
        // Collection types are never reportable (257-01).
        if matches!(
            dtype,
            DataType::Array | DataType::Composite(_) | DataType::Unknown
        ) {
            return ZclStatus::UnreportableAttribute;
        }
        if !def.reportable {
            return ZclStatus::UnreportableAttribute;
        }
        if rec.dtype != def.datatype {
            return ZclStatus::InvalidDataType;
        }
        // Restore-default encoding: drop any live slot.
        if rec.max == 0x0000 && rec.min == DEFAULT_RESTORE_MIN {
            if let Some(i) = self.find(rec.id) {
                self.remove_at(i);
            }
            return ZclStatus::Success;
        }
        // Interval sanity: non-zero maximum below the minimum, or an
        // unsupported pairing, is rejected.
        if rec.max != 0x0000 && rec.max < rec.min {
            return ZclStatus::InvalidValue;
        }
        // Disable encoding: configuration need not be kept.
        if rec.max == REPORTING_DISABLED_MAX {
            if let Some(i) = self.find(rec.id) {
                self.remove_at(i);
            }
            return ZclStatus::Success;
        }
        let current = match store.get(rec.id) {
            Some(v) => v,
            None => return ZclStatus::UnsupportedAttribute,
        };
        let change = if dtype.is_analog() {
            match rec.change {
                Some(c)
                    if c.datatype() == dtype
                        || (matches!(c.datatype(), DataType::UInt(_) | DataType::Int(_))
                            && matches!(dtype, DataType::UInt(_) | DataType::Int(_))) =>
                {
                    c
                }
                // Zero-valued threshold for the disable/default
                // encodings above already returned; a missing analog
                // threshold here means the record is malformed.
                _ => return ZclStatus::InvalidField,
            }
        } else {
            current
        };
        let slot = ReportSlot {
            attr: rec.id,
            min_s: rec.min,
            max_s: rec.max,
            change,
            last_value: current,
            last_at_s: now_s,
        };
        if let Some(i) = self.find(rec.id) {
            self.slots[i] = Some(slot);
        } else {
            if self.len as usize >= MAX_REPORT_SLOTS {
                return ZclStatus::InsufficientSpace;
            }
            self.slots[self.len as usize] = Some(slot);
            self.len += 1;
        }
        ZclStatus::Success
    }

    /// Apply one receive-direction record (timeout supervision).
    ///
    /// Requirement `07-5123-08-257-05` (corpus-mined).
    pub fn configure_timeout(&mut self, store: &AttrStore, rec: &ReportCfgRecord) -> ZclStatus {
        let def = match store.definition(rec.id) {
            Some(d) => d,
            None => return ZclStatus::UnsupportedAttribute,
        };
        if !def.reportable {
            return ZclStatus::UnreportableAttribute;
        }
        let mut i = 0;
        while i < self.timeout_len as usize {
            if self.timeouts[i].map(|t| t.attr) == Some(rec.id) {
                self.timeouts[i] = Some(TimeoutSlot {
                    attr: rec.id,
                    timeout_s: rec.timeout,
                });
                return ZclStatus::Success;
            }
            i += 1;
        }
        if self.timeout_len as usize >= MAX_REPORT_SLOTS {
            return ZclStatus::InsufficientSpace;
        }
        self.timeouts[self.timeout_len as usize] = Some(TimeoutSlot {
            attr: rec.id,
            timeout_s: rec.timeout,
        });
        self.timeout_len += 1;
        ZclStatus::Success
    }

    fn remove_at(&mut self, i: usize) {
        let mut j = i;
        while j + 1 < self.len as usize {
            self.slots[j] = self.slots[j + 1];
            j += 1;
        }
        self.slots[self.len as usize - 1] = None;
        self.len -= 1;
    }

    /// Configured send slot for `attr`, if any.
    #[must_use]
    pub fn slot(&self, attr: u16) -> Option<ReportSlot> {
        self.find(attr).map(|i| self.slots[i].unwrap())
    }

    /// Compute due reports at `now_s`: periodic ceiling reached, or a
    /// qualifying value change past the minimum floor. Due slots have
    /// their baseline advanced so the next tick re-arms. Returns the
    /// count written into `due_out`.
    ///
    /// Requirements `07-5123-08-2511-02` (MINTED-pending-confirm) +
    /// §2.5.11.2.1–2.5.11.2.3 generation rules (corpus-mined).
    pub fn tick(&mut self, store: &AttrStore, now_s: u64, due_out: &mut [u16]) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < self.len as usize {
            if let Some(mut slot) = self.slots[i] {
                let current = store.get(slot.attr);
                let mut due = false;
                if let Some(v) = current {
                    let elapsed = now_s.saturating_sub(slot.last_at_s);
                    if slot.max_s != 0 && elapsed >= slot.max_s as u64 {
                        // Periodic ceiling reached.
                        due = true;
                    } else if change_qualifies(slot, slot.last_value, v)
                        && (slot.min_s == 0 || elapsed >= slot.min_s as u64)
                    {
                        due = true;
                    }
                    if due {
                        slot.last_value = v;
                        slot.last_at_s = now_s;
                        self.slots[i] = Some(slot);
                        if n < due_out.len() {
                            due_out[n] = slot.attr;
                            n += 1;
                        }
                    }
                }
            }
            i += 1;
        }
        n
    }

    /// Answer one reporting-configuration query record.
    ///
    /// Requirement `07-5123-08-25-10-01` (corpus-mined): absent →
    /// UNSUPPORTED_ATTRIBUTE, non-reportable → UNREPORTABLE_ATTRIBUTE,
    /// unconfigured → NOT_FOUND, else SUCCESS with the live values.
    #[must_use]
    pub fn query(&self, store: &AttrStore, direction: u8, id: u16) -> QueryAnswer {
        let def = match store.definition(id) {
            Some(d) => d,
            None => {
                return QueryAnswer::Bare {
                    status: ZclStatus::UnsupportedAttribute,
                }
            }
        };
        if !def.reportable && direction == 0x00 {
            return QueryAnswer::Bare {
                status: ZclStatus::UnreportableAttribute,
            };
        }
        if direction == 0x01 {
            let mut i = 0;
            while i < self.timeout_len as usize {
                if let Some(t) = self.timeouts[i] {
                    if t.attr == id {
                        return QueryAnswer::Timeout {
                            timeout_s: t.timeout_s,
                        };
                    }
                }
                i += 1;
            }
            return QueryAnswer::Bare {
                status: ZclStatus::NotFound,
            };
        }
        match self.find(id) {
            Some(i) => {
                let s = self.slots[i].unwrap();
                QueryAnswer::Send {
                    dtype: def.datatype,
                    min_s: s.min_s,
                    max_s: s.max_s,
                    change: s.change,
                }
            }
            None => QueryAnswer::Bare {
                status: ZclStatus::NotFound,
            },
        }
    }
}

/// Reporting-configuration query outcome for one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryAnswer {
    /// Non-success record: only direction + identifier travel.
    Bare {
        /// Status to report.
        status: ZclStatus,
    },
    /// Live send configuration.
    Send {
        /// Attribute wire type.
        dtype: u8,
        /// Minimum interval seconds.
        min_s: u16,
        /// Maximum interval seconds.
        max_s: u16,
        /// Change threshold (analog) or current value (discrete).
        change: Value,
    },
    /// Live receive timeout.
    Timeout {
        /// Timeout seconds.
        timeout_s: u16,
    },
}

/// Whether the move from `old` to `new` qualifies as a reportable
/// change: any move for discrete types; at-or-past threshold for
/// analog types (sign of the threshold ignored).
///
/// Requirements `07-5123-08-257-03` (corpus-mined) +
/// §2.5.11.2.2/2.5.11.2.3 (corpus-mined).
#[must_use]
pub fn change_qualifies(slot: ReportSlot, old: Value, new: Value) -> bool {
    if old == new {
        return false;
    }
    let dtype = match DataType::from_u8(old.datatype().as_u8()) {
        Ok(t) => t,
        Err(_) => return true,
    };
    if !dtype.is_analog() {
        return true;
    }
    // Integer thresholds compare as magnitudes (threshold sign
    // ignored); mixed int/uint pairings compare over i128.
    fn int_threshold(t: Value) -> i128 {
        match t {
            Value::Int { v, .. } => v as i128,
            Value::UInt { v, .. } => v as i128,
            _ => 0,
        }
    }
    match (old, new) {
        (Value::UInt { v: a, .. }, Value::UInt { v: b, .. }) => {
            a.abs_diff(b) as i128 >= int_threshold(slot.change).unsigned_abs() as i128
        }
        (Value::Int { v: a, .. }, Value::Int { v: b, .. }) => {
            (a as i128 - b as i128).unsigned_abs() >= int_threshold(slot.change).unsigned_abs()
        }
        (Value::Single(a), Value::Single(b)) => match slot.change {
            Value::Single(t) => {
                (f32::from_bits(b) - f32::from_bits(a)).abs() >= f32::from_bits(t).abs()
            }
            _ => true,
        },
        (Value::Double(a), Value::Double(b)) => match slot.change {
            Value::Double(t) => {
                (f64::from_bits(b) - f64::from_bits(a)).abs() >= f64::from_bits(t).abs()
            }
            _ => true,
        },
        (Value::Time { v: a, .. }, Value::Time { v: b, .. }) => match slot.change {
            Value::Time { v: t, .. } => a.abs_diff(b) >= t,
            _ => true,
        },
        _ => true,
    }
}
