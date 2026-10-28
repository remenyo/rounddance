//! Metering mirror support (cluster 0x0702): mirror-setup command
//! codecs, the ESI-side mirror table, the meter-side grant record,
//! and the mirror-report notification-flag carrier.
//!
//! Paraphrase-level model of doc `07-5123-08` §10.4.2.3.1.2/3
//! (server-generated setup commands), §10.4.3.3.1.2/3/10
//! (client-generated response commands), and §10.4.4.4 (mirroring
//! guidelines: endpoint validity, grant-gated pushes, capacity
//! advertisement, attribute-availability answers), plus doc
//! `17-05019-012` §10.4.4.4.2 (mirror access control). All wording
//! here is paraphrase (D1).
//!
//! Requirement IDs below are corpus-reused (`07-5123-08-104-01`,
//! `17-05019-012-422-02`, `17-05019-012-423-01`) or repo-minted
//! (`07-5123-08-1044-*`, dots stripped), MINTED-pending-confirm.
//! Schedule/sampling/supply commands stay explicitly follow-up, not
//! silent scope.
//!
//! Direction reminder (matches the tables above): the physical meter
//! hosts the metering server; the ESI hosts a metering client plus
//! one mirror server endpoint per granted meter. `RequestMirror` and
//! `RemoveMirror` are therefore server-generated (meter asks the ESI
//! to mirror / release); `RequestMirrorResponse`, `MirrorRemoved`,
//! and `MirrorReportAttributeResponse` are client-generated (ESI
//! answers toward the meter).

use crate::{Error, ZclStatus};

/// Server generated: RequestMirror (empty body: ask the ESI to
/// mirror this meter's data).
///
/// Requirement `07-5123-08-1044-01` (MINTED-pending-confirm).
pub const CMD_REQUEST_MIRROR: u8 = 0x01;
/// Server generated: RemoveMirror (empty body: ask the ESI to
/// release the mirror endpoint).
///
/// Requirement `07-5123-08-1044-01` (MINTED-pending-confirm).
pub const CMD_REMOVE_MIRROR: u8 = 0x02;
/// Client generated: RequestMirrorResponse (granted endpoint, or
/// refusal).
///
/// Requirement `07-5123-08-1044-02` (MINTED-pending-confirm).
pub const CMD_REQUEST_MIRROR_RESPONSE: u8 = 0x01;
/// Client generated: MirrorRemoved (released endpoint).
///
/// Requirement `07-5123-08-1044-02` (MINTED-pending-confirm).
pub const CMD_MIRROR_REMOVED: u8 = 0x02;
/// Client generated: MirrorReportAttributeResponse (notification
/// scheme plus waiting-command flags, mirror to meter).
///
/// Requirement `07-5123-08-1044-03` (MINTED-pending-confirm).
pub const CMD_MIRROR_REPORT_ATTR_RESPONSE: u8 = 0x09;

/// Smallest grantable mirror endpoint id.
///
/// Requirement `07-5123-08-1044-04` (MINTED-pending-confirm).
pub const ENDPOINT_MIN: u16 = 0x0001;
/// Largest grantable mirror endpoint id.
///
/// Requirement `07-5123-08-1044-04` (MINTED-pending-confirm).
pub const ENDPOINT_MAX: u16 = 0x00F0;
/// Endpoint value meaning the ESI refused to mirror.
///
/// Requirement `07-5123-08-1044-04` (MINTED-pending-confirm).
pub const ENDPOINT_REFUSED: u16 = 0xFFFF;

/// Largest mirror table held here (bounded; a full table refuses
/// with [`ENDPOINT_REFUSED`]).
///
/// Requirement `07-5123-08-1044-05` (MINTED-pending-confirm).
pub const MAX_MIRRORS: usize = 4;
/// Largest notification-flag backlog carried in one
/// MirrorReportAttributeResponse here.
///
/// Requirement `07-5123-08-1044-03` (MINTED-pending-confirm).
pub const MAX_NOTIFICATION_FLAGS: usize = 8;

/// A grantable endpoint id is inside the grantable range; the
/// refusal value and every reserved value are rejected.
///
/// Requirement `07-5123-08-1044-04` (MINTED-pending-confirm).
#[must_use]
pub const fn endpoint_is_grantable(endpoint: u16) -> bool {
    endpoint >= ENDPOINT_MIN && endpoint <= ENDPOINT_MAX
}

/// Encode an empty-bodied setup command (`RequestMirror`,
/// `RemoveMirror`): always zero octets.
pub fn encode_empty_setup(out: &mut [u8]) -> Result<usize, Error> {
    let _ = out;
    Ok(0)
}

/// Decode an empty-bodied setup command: only a zero-length body
/// is accepted.
pub fn decode_empty_setup(buf: &[u8]) -> Result<(), Error> {
    if buf.is_empty() {
        Ok(())
    } else {
        Err(Error::InvalidValue(0))
    }
}

/// Encode a mirror endpoint carrier (`RequestMirrorResponse`,
/// `MirrorRemoved`): 2 octets, little-endian.
pub fn encode_mirror_endpoint(endpoint: u16, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 2 {
        return Err(Error::BufferTooSmall);
    }
    out[..2].copy_from_slice(&endpoint.to_le_bytes());
    Ok(2)
}

/// Decode a mirror endpoint carrier: exactly 2 octets.
pub fn decode_mirror_endpoint(buf: &[u8]) -> Result<u16, Error> {
    if buf.len() != 2 {
        return Err(Error::Truncated);
    }
    Ok(u16::from_le_bytes([buf[0], buf[1]]))
}

/// Mirror-report notification flags carried mirror to meter.
///
/// Requirement `07-5123-08-1044-03` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MirrorReport {
    /// Notification scheme selecting the flag-to-command mapping.
    pub scheme: u8,
    /// Waiting-command flag words (map32 each).
    pub flags: [u32; MAX_NOTIFICATION_FLAGS],
    /// Significant flag words in `flags`.
    pub count: u8,
}

impl MirrorReport {
    /// Empty report under `scheme`.
    #[must_use]
    pub const fn new(scheme: u8) -> Self {
        Self {
            scheme,
            flags: [0; MAX_NOTIFICATION_FLAGS],
            count: 0,
        }
    }

    /// Flag word count carried.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count as usize
    }

    /// No flag words carried.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Encode a MirrorReportAttributeResponse body: 1 scheme octet plus
/// 4 octets per flag word (little-endian).
pub fn encode_mirror_report(report: &MirrorReport, out: &mut [u8]) -> Result<usize, Error> {
    let need = 1 + 4 * report.len();
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    if report.len() > MAX_NOTIFICATION_FLAGS {
        return Err(Error::InvalidValue(report.count));
    }
    out[0] = report.scheme;
    let mut i = 0;
    while i < report.len() {
        out[1 + 4 * i..5 + 4 * i].copy_from_slice(&report.flags[i].to_le_bytes());
        i += 1;
    }
    Ok(need)
}

/// Decode a MirrorReportAttributeResponse body into `report`; at
/// most [`MAX_NOTIFICATION_FLAGS`] words are kept, further words
/// are a field error (bounded, never grown).
pub fn decode_mirror_report(buf: &[u8], report: &mut MirrorReport) -> Result<(), Error> {
    // A scheme octet plus whole flag words: (len - 1) is a multiple
    // of 4 exactly when len % 4 == 1.
    if buf.is_empty() || buf.len() % 4 != 1 {
        return Err(Error::Truncated);
    }
    let n = (buf.len() - 1) / 4;
    if n > MAX_NOTIFICATION_FLAGS {
        return Err(Error::InvalidValue(n as u8));
    }
    report.scheme = buf[0];
    report.flags = [0; MAX_NOTIFICATION_FLAGS];
    let mut i = 0;
    while i < n {
        report.flags[i] = u32::from_le_bytes([
            buf[1 + 4 * i],
            buf[2 + 4 * i],
            buf[3 + 4 * i],
            buf[4 + 4 * i],
        ]);
        i += 1;
    }
    report.count = n as u8;
    Ok(())
}

/// One granted mirror endpoint: the endpoint id plus the meter it
/// was granted to.
///
/// Requirement `07-5123-08-1044-05` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MirrorEntry {
    /// Granted mirror endpoint id.
    pub endpoint: u16,
    /// Meter the endpoint was granted to (IEEE address).
    pub meter: u64,
}

/// Who asks to release a mirror: the granted meter, or the ESI
/// itself (`None`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseRequester {
    /// The ESI releases its own mirror.
    Esi,
    /// A meter asks for release; only the granted meter may.
    Meter(u64),
}

/// ESI-side mirror table: bounded endpoint grants with
/// supersession and removal rules.
///
/// Requirement `07-5123-08-1044-05` (MINTED-pending-confirm): a
/// meter that already holds an endpoint gets the same endpoint
/// back (no duplicates); a full table refuses with
/// [`ENDPOINT_REFUSED`]; only the granted meter or the ESI itself
/// may release an endpoint.
///
/// Requirement `17-05019-012-423-01` (corpus-mined): only the
/// granted meter may push to its endpoint (violations answer
/// `NOT_AUTHORIZED`); capacity is advertised through
/// [`MirrorTable::has_capacity`].
#[derive(Clone, Copy, Debug)]
pub struct MirrorTable {
    entries: [Option<MirrorEntry>; MAX_MIRRORS],
    len: u8,
    next_endpoint: u16,
}

impl Default for MirrorTable {
    fn default() -> Self {
        Self::new()
    }
}

impl MirrorTable {
    /// Empty table; first grant starts at [`ENDPOINT_MIN`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_MIRRORS],
            len: 0,
            next_endpoint: ENDPOINT_MIN,
        }
    }

    /// Granted endpoint count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// No endpoints granted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether another mirror can currently be granted (the
    /// capacity advertisement behind the environment attribute).
    ///
    /// Requirement `17-05019-012-423-01` (corpus-mined).
    #[must_use]
    pub const fn has_capacity(&self) -> bool {
        (self.len as usize) < MAX_MIRRORS
    }

    /// Endpoint currently granted to `meter`, if any.
    #[must_use]
    pub const fn endpoint_for(&self, meter: u64) -> Option<u16> {
        let mut i = 0;
        while i < MAX_MIRRORS {
            if let Some(entry) = self.entries[i] {
                if entry.meter == meter {
                    return Some(entry.endpoint);
                }
            }
            i += 1;
        }
        None
    }

    /// Grant (or re-confirm) a mirror endpoint for `meter`:
    /// idempotent for a meter that already holds one, refusal
    /// ([`ENDPOINT_REFUSED`]) when full.
    pub fn request(&mut self, meter: u64) -> u16 {
        if let Some(endpoint) = self.endpoint_for(meter) {
            return endpoint;
        }
        if !self.has_capacity() {
            return ENDPOINT_REFUSED;
        }
        // Walk the grantable range from the cursor; the capacity
        // check above guarantees a free id exists.
        let mut tries = 0;
        while tries <= (ENDPOINT_MAX - ENDPOINT_MIN) {
            let candidate = self.next_endpoint;
            self.next_endpoint += 1;
            if self.next_endpoint > ENDPOINT_MAX {
                self.next_endpoint = ENDPOINT_MIN;
            }
            if !self.endpoint_taken(candidate) {
                let mut i = 0;
                while i < MAX_MIRRORS {
                    if self.entries[i].is_none() {
                        self.entries[i] = Some(MirrorEntry {
                            endpoint: candidate,
                            meter,
                        });
                        self.len += 1;
                        return candidate;
                    }
                    i += 1;
                }
            }
            tries += 1;
        }
        ENDPOINT_REFUSED
    }

    /// Release `endpoint`: unknown endpoints answer `NotFound`,
    /// other meters' endpoints answer `NotAuthorized`, and a
    /// granted release frees the slot and returns the endpoint id
    /// for the `MirrorRemoved` payload.
    pub fn remove(&mut self, endpoint: u16, requester: ReleaseRequester) -> Result<u16, ZclStatus> {
        let mut i = 0;
        while i < MAX_MIRRORS {
            if let Some(entry) = self.entries[i] {
                if entry.endpoint == endpoint {
                    let allowed = match requester {
                        ReleaseRequester::Esi => true,
                        ReleaseRequester::Meter(meter) => meter == entry.meter,
                    };
                    if !allowed {
                        return Err(ZclStatus::NotAuthorized);
                    }
                    self.entries[i] = None;
                    self.len -= 1;
                    return Ok(endpoint);
                }
            }
            i += 1;
        }
        Err(ZclStatus::NotFound)
    }

    /// Push gate: only the granted meter may push readings to its
    /// endpoint; anything else answers `NotAuthorized`.
    ///
    /// Requirement `17-05019-012-423-01` (corpus-mined).
    pub fn may_push(&self, endpoint: u16, meter: u64) -> Result<(), ZclStatus> {
        let mut i = 0;
        while i < MAX_MIRRORS {
            if let Some(entry) = self.entries[i] {
                if entry.endpoint == endpoint {
                    if entry.meter == meter {
                        return Ok(());
                    }
                    return Err(ZclStatus::NotAuthorized);
                }
            }
            i += 1;
        }
        Err(ZclStatus::NotFound)
    }

    fn endpoint_taken(&self, endpoint: u16) -> bool {
        let mut i = 0;
        while i < MAX_MIRRORS {
            if let Some(entry) = self.entries[i] {
                if entry.endpoint == endpoint {
                    return true;
                }
            }
            i += 1;
        }
        false
    }
}

/// Readiness of a mirrored attribute behind a read query.
///
/// Requirement `17-05019-012-423-01` (corpus-mined): attributes the
/// mirror does not support answer `UNSUPPORTED_ATTRIBUTE`;
/// supported attributes with no pushed value yet are *empty*
/// (mapped here to `NOT_FOUND`, the closest receipt-side status in
/// this crate's set — the corpus term for it is
/// `ATTRIBUTE_UNAVAILABLE`). Caller-visible so tests can pin the
/// three-way split.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttrReadiness {
    /// A pushed value is available.
    Ready,
    /// Supported but no value pushed yet.
    Empty,
    /// Not supported by this mirror.
    Unsupported,
}

impl AttrReadiness {
    /// Receipt-side status for this readiness.
    #[must_use]
    pub const fn status(self) -> ZclStatus {
        match self {
            Self::Ready => ZclStatus::Success,
            Self::Empty => ZclStatus::NotFound,
            Self::Unsupported => ZclStatus::UnsupportedAttribute,
        }
    }

    /// Classify readiness from support + availability flags.
    #[must_use]
    pub const fn classify(supported: bool, available: bool) -> Self {
        if !supported {
            Self::Unsupported
        } else if !available {
            Self::Empty
        } else {
            Self::Ready
        }
    }
}

/// Meter-side mirror record: the granted endpoint (if any) plus
/// the latest waiting-command flags from the mirror.
///
/// Requirement `07-5123-08-104-01` (corpus-mined): the mirror
/// carries the mirrored-metering device type while the physical
/// meter keeps its metering type — the two ends stay distinct
/// records, never merged.
#[derive(Clone, Copy, Debug)]
pub struct MirrorClient {
    granted: Option<u16>,
    report: MirrorReport,
}

impl Default for MirrorClient {
    fn default() -> Self {
        Self::new()
    }
}

impl MirrorClient {
    /// No grant, no waiting flags.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            granted: None,
            report: MirrorReport::new(0),
        }
    }

    /// Granted mirror endpoint, if the ESI granted one.
    #[must_use]
    pub const fn granted(&self) -> Option<u16> {
        self.granted
    }

    /// Latest waiting-command flags from the mirror.
    #[must_use]
    pub const fn report(&self) -> &MirrorReport {
        &self.report
    }

    /// Apply a `RequestMirrorResponse` endpoint: refusal clears the
    /// grant; a grantable id records it; reserved values are a
    /// field error.
    pub fn on_response(&mut self, endpoint: u16) -> Result<(), ZclStatus> {
        if endpoint == ENDPOINT_REFUSED {
            self.granted = None;
            return Ok(());
        }
        if !endpoint_is_grantable(endpoint) {
            return Err(ZclStatus::InvalidField);
        }
        self.granted = Some(endpoint);
        Ok(())
    }

    /// Apply a `MirrorRemoved` endpoint: clears a matching grant;
    /// other endpoints are not ours and are ignored.
    pub fn on_removed(&mut self, endpoint: u16) {
        if self.granted == Some(endpoint) {
            self.granted = None;
        }
    }

    /// Apply a `MirrorReportAttributeResponse`: stash the scheme and
    /// flags; the meter (application) then requests whatever
    /// information is waiting. Returns the flag-word count.
    pub fn on_report(&mut self, report: &MirrorReport) -> usize {
        self.report = *report;
        report.len()
    }
}
