//! NLDE-DATA.request header-construction rules (§3.2.1.1.3).
//!
//! Paraphrase-level helpers: given the data-request parameters, produce
//! the header fields the NWK layer stamps on the outgoing NPDU. Routing,
//! MAC interfacing, and confirm generation live above this module; only
//! the field-mapping rules from §3.2.1.1.3 are modeled here.

use crate::frame::{DiscoverRoute, Error as FrameError, FrameControl, NwkHeader};

/// NLDE data-path errors: frame-codec errors plus request guards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Underlying header/frame error.
    Frame(FrameError),
    /// Request arrived on an unassociated device: no frame is built;
    /// the NLDE answers with an illegal-request-type confirm
    /// (§3.2.1.1.3).
    ///
    /// Requirement `05-3474-23-3211-01`.
    NotAssociated,
    /// The confirm primitive was emitted before transmission, so every
    /// further step for the payload is abandoned (§3.2.1.1.3).
    ///
    /// Requirement `05-3474-23-3211-02`.
    TransmitAborted,
}

impl From<FrameError> for Error {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Frame(e) => write!(f, "{e}"),
            Self::NotAssociated => write!(f, "device not associated"),
            Self::TransmitAborted => write!(f, "transmit aborted by early confirm"),
        }
    }
}

impl core::error::Error for Error {}

/// Parameters for one NLDE-DATA.request header build (Table 3-2, §3.2.1.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NldeDataRequest {
    /// Caller destination (stamped verbatim into the header).
    pub dst_addr: u16,
    /// Alias mode: stamp `alias_src`/`alias_seq` instead of the local
    /// address and a generated sequence number.
    pub use_alias: bool,
    /// Alias source address (used iff `use_alias`).
    pub alias_src: u16,
    /// Alias sequence number (used iff `use_alias`).
    pub alias_seq: u8,
    /// Caller hop budget; zero selects the `2 × max_depth` default.
    pub radius_param: u8,
    /// Route-discovery control, passed through to the header.
    pub discover_route: DiscoverRoute,
    /// Freshly generated sequence number for non-alias frames
    /// (generated per §3.6.2.1 by the caller).
    pub generated_seq: u8,
    /// This device's MAC short address (non-alias source).
    pub local_short_addr: u16,
    /// NIB `nwkcMaxDepth`, doubled when `radius_param` is zero.
    pub max_depth: u8,
    /// Association state; false rejects the request before any frame
    /// is built.
    pub associated: bool,
}

/// Map the Radius parameter to the header radius octet (§3.2.1.1.3):
/// nonzero passes through, zero selects twice `max_depth`.
///
/// Requirement `05-3474-23-3211-03`.
#[must_use]
pub const fn radius_for_request(radius_param: u8, max_depth: u8) -> u8 {
    if radius_param != 0 {
        radius_param
    } else {
        max_depth.saturating_mul(2)
    }
}

/// Build the outgoing NPDU header for an NLDE-DATA.request.
///
/// Applies, in order: the unassociated-device guard (no frame built),
/// the source/sequence selection (alias vs. local + generated), the
/// radius mapping, and the discover-route passthrough.
///
/// Requirements `05-3474-23-3211-01`, `05-3474-23-3211-03`,
/// `05-3474-23-3211-04`, `05-3474-23-3211-05`.
pub fn build_data_header(req: &NldeDataRequest) -> Result<NwkHeader, Error> {
    if !req.associated {
        return Err(Error::NotAssociated);
    }
    let (src_addr, seq) = if req.use_alias {
        (req.alias_src, req.alias_seq)
    } else {
        (req.local_short_addr, req.generated_seq)
    };
    let mut control = FrameControl::data();
    control.discover_route = req.discover_route;
    Ok(NwkHeader::minimal(
        control,
        req.dst_addr,
        src_addr,
        radius_for_request(req.radius_param, req.max_depth),
        seq,
    ))
}

/// Transmit gate modeling the early-confirm abort (§3.2.1.1.3): if the
/// data entity emits its confirm before the payload transmits, every
/// further step is abandoned and nothing goes on air.
///
/// Requirement `05-3474-23-3211-02`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxPipeline {
    confirm_emitted: bool,
    transmitted: bool,
}

impl TxPipeline {
    /// New pipeline: neither confirmed nor transmitted.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            confirm_emitted: false,
            transmitted: false,
        }
    }

    /// Record that the NLDE-DATA.confirm primitive was emitted.
    pub const fn mark_confirmed(&mut self) {
        self.confirm_emitted = true;
    }

    /// Record that the payload reached the medium.
    pub const fn mark_transmitted(&mut self) {
        self.transmitted = true;
    }

    /// Authorize the transmit step: fails when the confirm already went
    /// out first and nothing has been transmitted yet.
    pub const fn authorize_transmit(&self) -> Result<(), Error> {
        if self.confirm_emitted && !self.transmitted {
            return Err(Error::TransmitAborted);
        }
        Ok(())
    }
}

/// Inbound delivery guard (§§3.2.1.3.2–3.2.1.3.3): the data entity raises
/// an indication only for frames the local MAC handed up that are
/// addressed to this device — a unicast match, or a broadcast the
/// caller accepts (device-type filtering per Table 3-80 stays with the
/// caller).
///
/// Requirement `05-3474-23-3213-01`.
#[must_use]
pub const fn indication_for_local(dst_addr: u16, local_addr: u16, accept_broadcast: bool) -> bool {
    if dst_addr == local_addr {
        return true;
    }
    accept_broadcast && crate::frame::is_broadcast_addr(dst_addr)
}
