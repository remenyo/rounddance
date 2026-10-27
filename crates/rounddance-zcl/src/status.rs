//! Command-status enumerations carried in ZCL status fields.
//!
//! Paraphrase-level model of doc `07-5123-08` §2.6.3 Table 2-12
//! (anchor p0107-L3731-L3736 + p0108 table body). All wording here is
//! paraphrase; numeric values are cited, not quoted (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are corpus-mined (`07-5123-08-263-01` family,
//! MINTED-pending-confirm) except where the full-corpus sweep already
//! assigned one (reused verbatim).

/// Status value carried in Default Response, read/write/reporting
/// records, and cluster-specific confirmations.
///
/// Requirement `07-5123-08-263-01` (MINTED-pending-confirm): the
/// enumerated set below; deprecated senders map to their replacements
/// on receipt and are never emitted. `Failure` is receipt-only: it is
/// accepted from pre-revision-6 senders (`07-5123-08-2512-03`) but
/// never emitted for peer-visible triage conditions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZclStatus {
    /// Operation was successful.
    Success,
    /// Legacy / local failure marker. Accepted on receipt (deprecated
    /// senders, local faults); never emitted for peer-visible
    /// protocol triage — each condition has its own code below
    /// (`07-5123-08-2512-01` correction: unknown cluster emits
    /// [`ZclStatus::UnsupportedCluster`], not this).
    Failure,
    /// Sender lacks authorization for the command.
    NotAuthorized,
    /// Command fields are missing or carry invalid entries.
    MalformedCommand,
    /// Command is not supported on the device (covers the 0x82/0x83/0x84
    /// deprecated manufacturer/general variants, mapped on receipt).
    UnsupCommand,
    /// A command field holds a value outside its specified set.
    InvalidField,
    /// Named attribute is not implemented here.
    UnsupportedAttribute,
    /// Value is out of range or reserved; attribute keeps its old value.
    InvalidValue,
    /// Write targets a read-only attribute.
    ReadOnly,
    /// Operation failed for lack of free space.
    InsufficientSpace,
    /// Requested information (e.g. report configuration) not found.
    NotFound,
    /// Periodic reports cannot be issued for this attribute.
    UnreportableAttribute,
    /// Supplied data type does not match the attribute.
    InvalidDataType,
    /// Structured selector is incorrect (no structured support here).
    InvalidSelector,
    /// Exchange aborted on excessive response time.
    Timeout,
    /// Named cluster is not implemented on this endpoint
    /// (`07-5123-08-2512-01` correction, anchor p0081-L3010-L3012:
    /// unicast to a missing cluster answers with this, never
    /// [`ZclStatus::Failure`]).
    UnsupportedCluster,
    /// Unknown/reserved value preserved verbatim (forward compat;
    /// never generated locally, only echoed from the wire).
    Other(u8),
}

impl ZclStatus {
    /// Decode a wire octet, mapping deprecated values to their
    /// replacements (never surfaced as distinct variants).
    ///
    /// Requirement `07-5123-08-263-01` (MINTED-pending-confirm).
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            // 0x8a duplicate-entry maps to SUCCESS on receipt.
            0x00 | 0x8a => Self::Success,
            0x01 | 0x90 | 0x91 | 0x93 => Self::Failure,
            // 0x8f write-only maps to NOT_AUTHORIZED on receipt.
            0x7e | 0x8f => Self::NotAuthorized,
            0x80 => Self::MalformedCommand,
            // 0x81 plus deprecated 0x82-0x84 manufacturer/general variants.
            0x81..=0x84 => Self::UnsupCommand,
            0x85 => Self::InvalidField,
            0x86 => Self::UnsupportedAttribute,
            0x87 => Self::InvalidValue,
            0x88 => Self::ReadOnly,
            0x89 => Self::InsufficientSpace,
            0x8b => Self::NotFound,
            0x8c => Self::UnreportableAttribute,
            0x8d => Self::InvalidDataType,
            0x8e => Self::InvalidSelector,
            0x94 => Self::Timeout,
            0xc3 => Self::UnsupportedCluster,
            other => Self::Other(other),
        }
    }

    /// Wire octet. Deprecated values are never emitted.
    ///
    /// Requirement `07-5123-08-263-01` (MINTED-pending-confirm).
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Success => 0x00,
            Self::Failure => 0x01,
            Self::NotAuthorized => 0x7e,
            Self::MalformedCommand => 0x80,
            Self::UnsupCommand => 0x81,
            Self::InvalidField => 0x85,
            Self::UnsupportedAttribute => 0x86,
            Self::InvalidValue => 0x87,
            Self::ReadOnly => 0x88,
            Self::InsufficientSpace => 0x89,
            Self::NotFound => 0x8b,
            Self::UnreportableAttribute => 0x8c,
            Self::InvalidDataType => 0x8d,
            Self::InvalidSelector => 0x8e,
            Self::Timeout => 0x94,
            Self::UnsupportedCluster => 0xc3,
            Self::Other(v) => v,
        }
    }

    /// Convenience predicate.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}
