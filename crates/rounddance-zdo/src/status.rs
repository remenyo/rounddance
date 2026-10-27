//! ZDO response status values.
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2 §2.4.4 (ZDP server
//! services). All wording here is paraphrase; citations name document,
//! revision, and clause/line only (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped) with line anchors from
//! the private corpus
//! (`text/zigbee-spec-r23-05-3474-23/p*.txt`, trailing spec line
//! numbers), MINTED-pending-confirm like the wave-3/4 NWK/APS IDs.
//! Status *spellings* are anchored in response-field tables
//! (`NWK_addr_rsp`: `SUCCESS`/`INV_REQUESTTYPE`/`DEVICE_NOT_FOUND`,
//! anchor p0174-L4273-L4277; `Node_Desc_rsp` adds `NO_DESCRIPTOR`,
//! anchor p0178-L4305-L4307; restricted-mode procedure names
//! `NOT_AUTHORIZED`, anchor p0126-L3083-L3088). Numeric values follow
//! the long-established cross-stack assignment; value mapping stays
//! MINTED-pending-confirm until the status-enumeration clause is
//! seed-mined. Unknown codes decode losslessly as [`ZdpStatus::Unknown`]
//! so a future status never breaks parsing.

/// ZDP response status (response-frame status octet, §2.4.4).
///
/// Requirement `05-3474-23-244-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZdpStatus {
    /// `0x00`: the request executed successfully.
    Success,
    /// `0x80`: the request type is invalid for the addressed device
    /// (e.g. descriptor interest addressed to a non-caching end
    /// device, §2.4.4.2.3 anchor p0178-L4323-L4325).
    InvRequestType,
    /// `0x81`: no device with the requested address is known
    /// (coordinator/router answer for unknown interest,
    /// anchor p0178-L4326-L4327).
    DeviceNotFound,
    /// `0x82`: the named endpoint is not valid here.
    InvalidEp,
    /// `0x83`: the addressed endpoint is not active.
    NotActive,
    /// `0x84`: the command is not supported here.
    NotSupported,
    /// `0x85`: the request timed out.
    Timeout,
    /// `0x89`: no memory for the request.
    NoMemory,
    /// `0x8A`: no table space for the request.
    NoTableSpace,
    /// `0x8B`: the request is not permitted here.
    NotPermitted,
    /// Any other code: preserved verbatim so parsing never fails on
    /// a status this layer does not name yet (covers `NO_DESCRIPTOR`,
    /// `NOT_AUTHORIZED`, and later additions until mined).
    Unknown(u8),
}

impl ZdpStatus {
    /// Decode the status octet; total — every value maps somewhere.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            0x00 => Self::Success,
            0x80 => Self::InvRequestType,
            0x81 => Self::DeviceNotFound,
            0x82 => Self::InvalidEp,
            0x83 => Self::NotActive,
            0x84 => Self::NotSupported,
            0x85 => Self::Timeout,
            0x89 => Self::NoMemory,
            0x8A => Self::NoTableSpace,
            0x8B => Self::NotPermitted,
            other => Self::Unknown(other),
        }
    }

    /// Numeric wire value.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0x00,
            Self::InvRequestType => 0x80,
            Self::DeviceNotFound => 0x81,
            Self::InvalidEp => 0x82,
            Self::NotActive => 0x83,
            Self::NotSupported => 0x84,
            Self::Timeout => 0x85,
            Self::NoMemory => 0x89,
            Self::NoTableSpace => 0x8A,
            Self::NotPermitted => 0x8B,
            Self::Unknown(code) => code,
        }
    }

    /// Whether this status reports success.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}
