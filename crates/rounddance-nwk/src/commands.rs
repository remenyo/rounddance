//! NWK command frames: route request, route reply, link status.
//!
//! Bounded, fallible codecs for the three routing commands named by the
//! R1 gap (doc `05-3474-23` R23.2 §3.4, command identifiers Table 3-54).
//! All wording here is paraphrase; citations name document, revision,
//! and clause only (D1, `SCOPE.md` §2).
//!
//! # Design notes
//!
//! * `no_std` + `#![forbid(unsafe_code)]`: decode of the fixed prefix is
//!   into owned values; variable tails (optional IEEE addresses, TLV
//!   area, link-status entries) are bounded — IEEE tails borrow the
//!   input, entries decode into a fixed-size array.
//! * Every fallible path returns [`Error`]; nothing panics, including
//!   on adversarial input (short buffers, reserved discriminants,
//!   count-field lies).
//! * Reserved option bits are zeroed on encode and ignored on decode
//!   (reserved-field handling per §1.4.2), matching `frame.rs`.
//! * Trailing TLV bytes (R23 extension area) are neither parsed nor
//!   rejected: `decode` exposes them as a borrowed `tlvs` slice so a
//!   forwarder preserves them opaquely.

/// Route-request command identifier (Table 3-54).
pub const CMD_ROUTE_REQUEST: u8 = 0x01;

/// Route-reply command identifier (Table 3-54).
pub const CMD_ROUTE_REPLY: u8 = 0x02;

/// Link-status command identifier (Table 3-54).
pub const CMD_LINK_STATUS: u8 = 0x08;

/// Declared per-subsystem budget for link-status entries (D5: bounded +
/// fallible + accountable, `SCOPE.md` §2).
///
/// Worst-case payload is 2 + 3 × entries = 50 octets, leaving room for
/// the NWK header plus the security auxiliary header and MIC inside one
/// MAC MSDU. Longer on-wire lists are rejected fallibly on decode
/// instead of truncating. Senders with more router neighbors chain
/// frames via the first/last flags (§3.4.8).
///
/// Requirement `05-3474-23-348-01`.
pub const MAX_LINK_STATUS_ENTRIES: usize = 16;

/// A link is usable only while its cost estimate stays this fresh;
/// older entries are aged out by [`crate::route::NeighborCosts::tick`].
///
/// Requirement `05-3474-23-348-02`.
pub const LINK_COST_MAX_AGE_MS: u64 = 60_000;

/// Fallible codec errors. No panics on any input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Fewer octets than the fixed prefix or a declared optional field
    /// or entry list overruns the buffer.
    Truncated,
    /// Caller encode buffer too small for the frame.
    BufferTooSmall,
    /// First payload octet is not one of the three routing commands
    /// implemented here.
    UnknownCommand(u8),
    /// Many-to-one value `3` (reserved, Table 3-55).
    ReservedManyToOne(u8),
    /// Presence flag disagrees with the matching `Option` field; the
    /// payload names the field (`"dst_ieee"`, `"originator_ieee"`,
    /// `"responder_ieee"`).
    PresenceMismatch(&'static str),
    /// Link-status entry count above [`MAX_LINK_STATUS_ENTRIES`].
    BadEntryCount(usize),
    /// Link-status option count disagrees with the entries actually
    /// present; carries `(declared, actual)`.
    EntryCountMismatch {
        /// Count stated in the options octet.
        declared: usize,
        /// Entries that fit in the remaining buffer.
        actual: usize,
    },
    /// Incoming link cost outside 1..=7 (0 = no usable estimate).
    BadIncomingCost(u8),
    /// Outgoing link cost above 7 (0 = not yet known, allowed).
    BadOutgoingCost(u8),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => write!(f, "command frame truncated"),
            Self::BufferTooSmall => write!(f, "encode buffer too small"),
            Self::UnknownCommand(v) => write!(f, "unknown NWK command {v:#04x}"),
            Self::ReservedManyToOne(v) => write!(f, "reserved many-to-one {v:#04x}"),
            Self::PresenceMismatch(field) => {
                write!(f, "presence flag mismatch for {field}")
            }
            Self::BadEntryCount(n) => write!(f, "bad link-status entry count {n}"),
            Self::EntryCountMismatch { declared, actual } => write!(
                f,
                "link-status count {declared} disagrees with {actual} entries present"
            ),
            Self::BadIncomingCost(v) => write!(f, "bad incoming link cost {v}"),
            Self::BadOutgoingCost(v) => write!(f, "bad outgoing link cost {v}"),
        }
    }
}

impl core::error::Error for Error {}

/// Many-to-one sub-field values, RREQ options bits 3–4 (Table 3-55).
///
/// Requirement `05-3474-23-341-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManyToOne {
    /// `0`: ordinary one-to-one discovery.
    NotManyToOne,
    /// `1`: concentrator keeps a route-record table.
    WithRouteRecord,
    /// `2`: concentrator keeps no route-record table.
    WithoutRouteRecord,
}

impl ManyToOne {
    /// Decode the 2-bit value; `3` is reserved and rejected.
    pub fn from_bits(bits: u8) -> Result<Self, Error> {
        match bits & 0x03 {
            0x00 => Ok(Self::NotManyToOne),
            0x01 => Ok(Self::WithRouteRecord),
            0x02 => Ok(Self::WithoutRouteRecord),
            v => Err(Error::ReservedManyToOne(v)),
        }
    }

    /// 2-bit wire value.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::NotManyToOne => 0x00,
            Self::WithRouteRecord => 0x01,
            Self::WithoutRouteRecord => 0x02,
        }
    }
}

/// Route-request options octet (§3.4.1.3.1): many-to-one kind in bits
/// 3–4, destination-IEEE presence in bit 5. Reserved bits are zero on
/// encode, ignored on decode; the deprecated bit 6 is carried verbatim
/// (never set by this stack), mirroring `FrameControl::multicast`.
///
/// Requirement `05-3474-23-341-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteRequestOptions {
    /// Many-to-one discovery kind (bits 3–4).
    pub many_to_one: ManyToOne,
    /// Bit 5: destination IEEE address follows the path cost.
    pub dst_ieee_present: bool,
    /// Bit 6: deprecated flag, carried verbatim.
    pub multicast: bool,
}

impl RouteRequestOptions {
    /// Ordinary one-to-one request, presence flag clear.
    #[must_use]
    pub const fn unicast() -> Self {
        Self {
            many_to_one: ManyToOne::NotManyToOne,
            dst_ieee_present: false,
            multicast: false,
        }
    }

    /// Pack to the wire octet (reserved bits zero).
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        (self.many_to_one.bits() << 3)
            | ((self.dst_ieee_present as u8) << 5)
            | ((self.multicast as u8) << 6)
    }

    /// Unpack a wire octet; reserved many-to-one `3` is rejected.
    pub fn from_u8(raw: u8) -> Result<Self, Error> {
        Ok(Self {
            many_to_one: ManyToOne::from_bits(raw >> 3)?,
            dst_ieee_present: raw & (1 << 5) != 0,
            multicast: raw & (1 << 6) != 0,
        })
    }
}

/// Route-request command body (§3.4.1.3): per-originator sequence
/// number, intended destination, accumulated path cost, and the
/// optional destination IEEE address; R23 TLV tails ride opaquely.
///
/// Requirement `05-3474-23-341-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteRequest {
    /// Command options (many-to-one kind + presence flag).
    pub options: RouteRequestOptions,
    /// Originator sequence number, bumped per request (§3.4.1.3.2).
    pub rreq_id: u8,
    /// Intended destination short address (§3.4.1.3.3).
    pub dst_addr: u16,
    /// Running cost summation (§3.4.1.3.4).
    pub path_cost: u8,
    /// Destination IEEE address, iff `options.dst_ieee_present`.
    pub dst_ieee: Option<u64>,
}

impl RouteRequest {
    /// Fixed prefix length without the optional IEEE address.
    pub const PREFIX_LEN: usize = 6;

    /// Consistency between the presence flag and the field.
    fn check_consistency(&self) -> Result<(), Error> {
        if self.options.dst_ieee_present != self.dst_ieee.is_some() {
            return Err(Error::PresenceMismatch("dst_ieee"));
        }
        Ok(())
    }

    /// Encoded length including the command identifier octet.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        Self::PREFIX_LEN + if self.dst_ieee.is_some() { 8 } else { 0 }
    }

    /// Encode into `out`; returns bytes written. TLV tails are never
    /// emitted by this stack (forwarders preserve received ones).
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check_consistency()?;
        let total = self.encoded_len();
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }
        out[0] = CMD_ROUTE_REQUEST;
        out[1] = self.options.to_u8();
        out[2] = self.rreq_id;
        out[3..5].copy_from_slice(&self.dst_addr.to_le_bytes());
        out[5] = self.path_cost;
        if let Some(ieee) = self.dst_ieee {
            out[6..14].copy_from_slice(&ieee.to_le_bytes());
        }
        Ok(total)
    }
}

/// Zero-copy decode view: owned prefix plus borrowed TLV tail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedRouteRequest<'a> {
    /// Parsed command body.
    pub request: RouteRequest,
    /// Trailing TLV area, preserved opaquely by forwarders.
    pub tlvs: &'a [u8],
}

/// Decode one route-request body from the front of `buf` (which must
/// start at the command identifier octet).
///
/// Requirement `05-3474-23-341-01`.
pub fn decode_route_request(buf: &[u8]) -> Result<DecodedRouteRequest<'_>, Error> {
    if buf.is_empty() || buf[0] != CMD_ROUTE_REQUEST {
        return Err(Error::UnknownCommand(buf.first().copied().unwrap_or(0)));
    }
    if buf.len() < RouteRequest::PREFIX_LEN {
        return Err(Error::Truncated);
    }
    let options = RouteRequestOptions::from_u8(buf[1])?;
    let mut pos = RouteRequest::PREFIX_LEN;
    let dst_ieee = if options.dst_ieee_present {
        if buf.len() < pos + 8 {
            return Err(Error::Truncated);
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&buf[pos..pos + 8]);
        pos += 8;
        Some(u64::from_le_bytes(b))
    } else {
        None
    };
    Ok(DecodedRouteRequest {
        request: RouteRequest {
            options,
            rreq_id: buf[2],
            dst_addr: u16::from_le_bytes([buf[3], buf[4]]),
            path_cost: buf[5],
            dst_ieee,
        },
        tlvs: &buf[pos..],
    })
}

/// Route-reply options octet (§3.4.2.3.1): originator-IEEE presence in
/// bit 4, responder-IEEE presence in bit 5. Both bits are always set on
/// transmit (§3.4.2.3.1.1/2); decode accepts either combination so a
/// forwarder never drops a legal frame.
///
/// Requirement `05-3474-23-342-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteReplyOptions {
    /// Bit 4: originator IEEE address follows the path cost.
    pub originator_ieee_present: bool,
    /// Bit 5: responder IEEE address follows the originator address.
    pub responder_ieee_present: bool,
    /// Bit 6: deprecated flag, carried verbatim.
    pub multicast: bool,
}

impl RouteReplyOptions {
    /// Both IEEE addresses present (the transmit shape).
    #[must_use]
    pub const fn full() -> Self {
        Self {
            originator_ieee_present: true,
            responder_ieee_present: true,
            multicast: false,
        }
    }

    /// Pack to the wire octet (reserved bits zero).
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        ((self.originator_ieee_present as u8) << 4)
            | ((self.responder_ieee_present as u8) << 5)
            | ((self.multicast as u8) << 6)
    }

    /// Unpack a wire octet.
    #[must_use]
    pub const fn from_u8(raw: u8) -> Self {
        Self {
            originator_ieee_present: raw & (1 << 4) != 0,
            responder_ieee_present: raw & (1 << 5) != 0,
            multicast: raw & (1 << 6) != 0,
        }
    }
}

/// Route-reply command body (§3.4.2.3): echoed request identifier,
/// originator and responder short addresses, accumulated path cost,
/// and the optional IEEE addresses; R23 TLV tails ride opaquely.
///
/// Requirement `05-3474-23-342-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteReply {
    /// Command options (IEEE presence flags).
    pub options: RouteReplyOptions,
    /// Echo of the request identifier being answered (§3.4.2.3.2).
    pub rreq_id: u8,
    /// Originator of the answered request (§3.4.2.3.3).
    pub originator: u16,
    /// Responder: the requested destination (§3.4.2.3.4).
    pub responder: u16,
    /// Running cost summation (§3.4.2.3.5).
    pub path_cost: u8,
    /// Originator IEEE address, iff `options.originator_ieee_present`.
    pub originator_ieee: Option<u64>,
    /// Responder IEEE address, iff `options.responder_ieee_present`.
    pub responder_ieee: Option<u64>,
}

impl RouteReply {
    /// Fixed prefix length without optional IEEE addresses.
    pub const PREFIX_LEN: usize = 8;

    /// Consistency between presence flags and fields.
    fn check_consistency(&self) -> Result<(), Error> {
        if self.options.originator_ieee_present != self.originator_ieee.is_some() {
            return Err(Error::PresenceMismatch("originator_ieee"));
        }
        if self.options.responder_ieee_present != self.responder_ieee.is_some() {
            return Err(Error::PresenceMismatch("responder_ieee"));
        }
        Ok(())
    }

    /// Encoded length including the command identifier octet.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        Self::PREFIX_LEN
            + if self.originator_ieee.is_some() { 8 } else { 0 }
            + if self.responder_ieee.is_some() { 8 } else { 0 }
    }

    /// Encode into `out`; returns bytes written.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check_consistency()?;
        let total = self.encoded_len();
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }
        out[0] = CMD_ROUTE_REPLY;
        out[1] = self.options.to_u8();
        out[2] = self.rreq_id;
        out[3..5].copy_from_slice(&self.originator.to_le_bytes());
        out[5..7].copy_from_slice(&self.responder.to_le_bytes());
        out[7] = self.path_cost;
        let mut pos = Self::PREFIX_LEN;
        if let Some(ieee) = self.originator_ieee {
            out[pos..pos + 8].copy_from_slice(&ieee.to_le_bytes());
            pos += 8;
        }
        if let Some(ieee) = self.responder_ieee {
            out[pos..pos + 8].copy_from_slice(&ieee.to_le_bytes());
        }
        Ok(total)
    }
}

/// Zero-copy decode view: owned prefix plus borrowed TLV tail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedRouteReply<'a> {
    /// Parsed command body.
    pub reply: RouteReply,
    /// Trailing TLV area, preserved opaquely by forwarders.
    pub tlvs: &'a [u8],
}

/// Decode one route-reply body from the front of `buf`.
///
/// Requirement `05-3474-23-342-01`.
pub fn decode_route_reply(buf: &[u8]) -> Result<DecodedRouteReply<'_>, Error> {
    if buf.is_empty() || buf[0] != CMD_ROUTE_REPLY {
        return Err(Error::UnknownCommand(buf.first().copied().unwrap_or(0)));
    }
    if buf.len() < RouteReply::PREFIX_LEN {
        return Err(Error::Truncated);
    }
    let options = RouteReplyOptions::from_u8(buf[1]);
    let mut pos = RouteReply::PREFIX_LEN;
    let originator_ieee = if options.originator_ieee_present {
        if buf.len() < pos + 8 {
            return Err(Error::Truncated);
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&buf[pos..pos + 8]);
        pos += 8;
        Some(u64::from_le_bytes(b))
    } else {
        None
    };
    let responder_ieee = if options.responder_ieee_present {
        if buf.len() < pos + 8 {
            return Err(Error::Truncated);
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&buf[pos..pos + 8]);
        pos += 8;
        Some(u64::from_le_bytes(b))
    } else {
        None
    };
    Ok(DecodedRouteReply {
        reply: RouteReply {
            options,
            rreq_id: buf[2],
            originator: u16::from_le_bytes([buf[3], buf[4]]),
            responder: u16::from_le_bytes([buf[5], buf[6]]),
            path_cost: buf[7],
            originator_ieee,
            responder_ieee,
        },
        tlvs: &buf[pos..],
    })
}

/// One link-status entry (§3.4.8.3.2): the router neighbor plus this
/// device's cost estimates for the link. Incoming cost is 1..=7 on the
/// wire (0 carries no usable estimate and is rejected); outgoing cost
/// is 0..=7 with 0 meaning not yet known.
///
/// Requirement `05-3474-23-348-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkStatusEntry {
    /// Router neighbor short address (least-significant octet first).
    pub neighbor: u16,
    /// This device's incoming-cost estimate, 1..=7.
    pub incoming_cost: u8,
    /// Last advertised outgoing cost toward the neighbor, 0..=7.
    pub outgoing_cost: u8,
}

impl LinkStatusEntry {
    /// Build with range checks; rejects unusable costs fallibly.
    pub fn new(neighbor: u16, incoming_cost: u8, outgoing_cost: u8) -> Result<Self, Error> {
        if incoming_cost == 0 || incoming_cost > 7 {
            return Err(Error::BadIncomingCost(incoming_cost));
        }
        if outgoing_cost > 7 {
            return Err(Error::BadOutgoingCost(outgoing_cost));
        }
        Ok(Self {
            neighbor,
            incoming_cost,
            outgoing_cost,
        })
    }

    /// Pack the status octet (reserved bits zero).
    #[must_use]
    pub const fn status_byte(self) -> u8 {
        (self.incoming_cost & 0x07) | ((self.outgoing_cost & 0x07) << 4)
    }

    /// Unpack one entry body (status octet already split out).
    pub fn from_parts(neighbor: u16, status: u8) -> Result<Self, Error> {
        Self::new(neighbor, status & 0x07, (status >> 4) & 0x07)
    }
}

/// Link-status options octet (§3.4.8.3.1): the entry count in bits
/// 0–4 with first/last frame flags chaining multi-frame reports.
///
/// Requirement `05-3474-23-348-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkStatusOptions {
    /// Bit 5: first frame of this sender's report.
    pub first_frame: bool,
    /// Bit 6: last frame of this sender's report.
    pub last_frame: bool,
}

impl LinkStatusOptions {
    /// Single-frame report: both flags set (§3.4.8.3.1).
    #[must_use]
    pub const fn single() -> Self {
        Self {
            first_frame: true,
            last_frame: true,
        }
    }

    /// Pack the count + flags octet.
    pub const fn to_u8(self, count: usize) -> Result<u8, Error> {
        if count > MAX_LINK_STATUS_ENTRIES {
            return Err(Error::BadEntryCount(count));
        }
        Ok((count as u8) | ((self.first_frame as u8) << 5) | ((self.last_frame as u8) << 6))
    }
}

/// Link-status command body (§3.4.8.3): neighbor entries sorted
/// ascending by network address (§3.4.8.3.2); the entry count rides in
/// the options octet so it is derived, never stored.
///
/// Requirement `05-3474-23-348-01`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkStatus {
    /// Chaining flags for this frame.
    pub options: LinkStatusOptions,
    /// Neighbor entries, ascending by address, at most
    /// [`MAX_LINK_STATUS_ENTRIES`].
    pub entries: [LinkStatusEntry; MAX_LINK_STATUS_ENTRIES],
    /// Live prefix length of `entries`.
    pub len: u8,
}

impl LinkStatus {
    /// Build from an entry slice; rejects over-budget lists and exige
    /// ascending order is the caller's contract (encode preserves the
    /// given order verbatim).
    pub fn new(options: LinkStatusOptions, entries: &[LinkStatusEntry]) -> Result<Self, Error> {
        if entries.len() > MAX_LINK_STATUS_ENTRIES {
            return Err(Error::BadEntryCount(entries.len()));
        }
        let mut arr = [LinkStatusEntry {
            neighbor: 0,
            incoming_cost: 1,
            outgoing_cost: 0,
        }; MAX_LINK_STATUS_ENTRIES];
        arr[..entries.len()].copy_from_slice(entries);
        Ok(Self {
            options,
            entries: arr,
            len: entries.len() as u8,
        })
    }

    /// Live entries.
    #[must_use]
    pub fn entries(&self) -> &[LinkStatusEntry] {
        &self.entries[..self.len as usize]
    }

    /// Encoded length including command identifier + options octets.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        2 + 3 * self.len as usize
    }

    /// Encode into `out`; returns bytes written.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let total = self.encoded_len();
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }
        out[0] = CMD_LINK_STATUS;
        out[1] = self.options.to_u8(self.len as usize)?;
        for (i, e) in self.entries().iter().enumerate() {
            out[2 + 3 * i..4 + 3 * i].copy_from_slice(&e.neighbor.to_le_bytes());
            out[4 + 3 * i] = e.status_byte();
        }
        Ok(total)
    }
}

/// Zero-copy decode view: owned entries plus chaining flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedLinkStatus {
    /// Chaining flags for this frame.
    pub options: LinkStatusOptions,
    /// Entries carried by this frame (at most
    /// [`MAX_LINK_STATUS_ENTRIES`]).
    pub entries: [LinkStatusEntry; MAX_LINK_STATUS_ENTRIES],
    /// Live prefix length of `entries`.
    pub len: u8,
}

impl DecodedLinkStatus {
    /// Live entries.
    #[must_use]
    pub fn entries(&self) -> &[LinkStatusEntry] {
        &self.entries[..self.len as usize]
    }
}

/// Decode one link-status body from the front of `buf`. The declared
/// count must match the entries actually present; anything else is a
/// corrupt or truncated frame, never a partial list.
///
/// Requirement `05-3474-23-348-01`.
pub fn decode_link_status(buf: &[u8]) -> Result<DecodedLinkStatus, Error> {
    if buf.is_empty() || buf[0] != CMD_LINK_STATUS {
        return Err(Error::UnknownCommand(buf.first().copied().unwrap_or(0)));
    }
    if buf.len() < 2 {
        return Err(Error::Truncated);
    }
    let declared = (buf[1] & 0x1F) as usize;
    if declared > MAX_LINK_STATUS_ENTRIES {
        return Err(Error::BadEntryCount(declared));
    }
    let available = buf.len().saturating_sub(2) / 3;
    let trailing = buf.len().saturating_sub(2) % 3;
    if declared != available || trailing != 0 {
        // A short final entry is truncation; a count lie is a mismatch.
        // Both are rejected; distinguish only for diagnostics.
        if buf.len() < 2 + 3 * declared {
            return Err(Error::Truncated);
        }
        return Err(Error::EntryCountMismatch {
            declared,
            actual: available,
        });
    }
    let mut entries = [LinkStatusEntry {
        neighbor: 0,
        incoming_cost: 1,
        outgoing_cost: 0,
    }; MAX_LINK_STATUS_ENTRIES];
    for (i, slot) in entries.iter_mut().enumerate().take(declared) {
        let neighbor = u16::from_le_bytes([buf[2 + 3 * i], buf[3 + 3 * i]]);
        *slot = LinkStatusEntry::from_parts(neighbor, buf[4 + 3 * i])?;
    }
    Ok(DecodedLinkStatus {
        options: LinkStatusOptions {
            first_frame: buf[1] & (1 << 5) != 0,
            last_frame: buf[1] & (1 << 6) != 0,
        },
        entries,
        len: declared as u8,
    })
}
