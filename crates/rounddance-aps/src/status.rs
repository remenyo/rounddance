//! APS sub-layer status values (Table 2-29, §2.2.9).
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2. Values are numeric
//! wire/primitive codes mined from the Table 2-29 text plus the Fig 2-2
//! decision tree render (private corpus, `qa-shots/r23-p0066.png`); all
//! wording here is paraphrase.
//!
//! Requirement `05-3474-23-229-01` (repo-minted, pending seed confirm).

/// APS confirm/indication status (Table 2-29, §2.2.9).
///
/// Requirement `05-3474-23-229-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApsStatus {
    /// `0x00`: the request executed successfully.
    Success,
    /// `0xa0`: transmit failed — ASDU too large and fragmentation not
    /// supported here (also the Fig 2-2 local-support and
    /// receiver-buffer gates).
    AsduTooLong,
    /// `0xa1`: a received fragmented frame could not be defragmented
    /// at the current time.
    DefragDeferred,
    /// `0xa2`: a received fragmented frame could not be defragmented
    /// since the device does not support fragmentation.
    DefragUnsupported,
    /// `0xa3`: a parameter value was out of range.
    IllegalRequest,
    /// `0xa4`: an unbind failed — the requested entry was not found.
    InvalidBinding,
    /// `0xa5`: a remove-group named an unknown group.
    InvalidGroup,
    /// `0xa6`: a parameter value was invalid or out of range.
    InvalidParameter,
    /// `0xa7`: acknowledged transmission got no acknowledgement.
    NoAck,
    /// `0xa8`: indirect (binding-mode) request with no binding entries.
    NoBoundDevice,
    /// `0xa9`: 64-bit destination had no mapped 16-bit NWK address.
    NoShortAddress,
    /// `0xaa`: indirect request on a device with no binding table.
    NotSupported,
    /// `0xab`: a received ASDU was secured with a link key.
    SecuredLinkKey,
    /// `0xac`: a received ASDU was secured with the network key.
    SecuredNwkKey,
    /// `0xad`: requested security processing failed.
    SecurityFail,
    /// `0xae`: a bind or add-group found no room in its table.
    TableFull,
    /// `0xaf`: an ASDU arrived without any security.
    Unsecured,
    /// `0xb0`: get/set named an unknown attribute identifier.
    UnsupportedAttribute,
    /// `0xb1`: the target cannot receive fragmented transmissions and
    /// the ASDU requires fragmentation (Fig 2-2 discovery gate).
    PeerCannotFragment,
    /// `0xb2`: the target did not answer the fragmentation-parameter
    /// discovery (Fig 2-2 discovery gate).
    UnknownFragmentSupport,
}

impl ApsStatus {
    /// Numeric code from Table 2-29.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0x00,
            Self::AsduTooLong => 0xa0,
            Self::DefragDeferred => 0xa1,
            Self::DefragUnsupported => 0xa2,
            Self::IllegalRequest => 0xa3,
            Self::InvalidBinding => 0xa4,
            Self::InvalidGroup => 0xa5,
            Self::InvalidParameter => 0xa6,
            Self::NoAck => 0xa7,
            Self::NoBoundDevice => 0xa8,
            Self::NoShortAddress => 0xa9,
            Self::NotSupported => 0xaa,
            Self::SecuredLinkKey => 0xab,
            Self::SecuredNwkKey => 0xac,
            Self::SecurityFail => 0xad,
            Self::TableFull => 0xae,
            Self::Unsecured => 0xaf,
            Self::UnsupportedAttribute => 0xb0,
            Self::PeerCannotFragment => 0xb1,
            Self::UnknownFragmentSupport => 0xb2,
        }
    }

    /// Decode a numeric code; unknown values are rejected fallibly.
    pub const fn from_code(code: u8) -> Result<Self, StatusError> {
        match code {
            0x00 => Ok(Self::Success),
            0xa0 => Ok(Self::AsduTooLong),
            0xa1 => Ok(Self::DefragDeferred),
            0xa2 => Ok(Self::DefragUnsupported),
            0xa3 => Ok(Self::IllegalRequest),
            0xa4 => Ok(Self::InvalidBinding),
            0xa5 => Ok(Self::InvalidGroup),
            0xa6 => Ok(Self::InvalidParameter),
            0xa7 => Ok(Self::NoAck),
            0xa8 => Ok(Self::NoBoundDevice),
            0xa9 => Ok(Self::NoShortAddress),
            0xaa => Ok(Self::NotSupported),
            0xab => Ok(Self::SecuredLinkKey),
            0xac => Ok(Self::SecuredNwkKey),
            0xad => Ok(Self::SecurityFail),
            0xae => Ok(Self::TableFull),
            0xaf => Ok(Self::Unsecured),
            0xb0 => Ok(Self::UnsupportedAttribute),
            0xb1 => Ok(Self::PeerCannotFragment),
            0xb2 => Ok(Self::UnknownFragmentSupport),
            other => Err(StatusError::UnknownCode(other)),
        }
    }
}

/// Fallible status-code error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusError {
    /// Code outside the Table 2-29 assignment.
    UnknownCode(u8),
}

impl core::fmt::Display for StatusError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownCode(v) => write!(f, "unknown APS status {v:#04x}"),
        }
    }
}

impl core::error::Error for StatusError {}
