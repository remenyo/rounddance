//! NWK general frame (NPDU) header: control field, addresses, radius,
//! sequence number, optional extended addresses, optional source route.
//!
//! Layout paraphrased from doc `05-3474-23` R23.2 §3.3.1 (Fig. 3-4) with
//! sub-field semantics from §§3.3.1.1–3.3.1.8. Wire order is header
//! first: frame control (2 octets, little-endian), destination short (2),
//! source short (2), radius (1), sequence number (1), destination IEEE
//! (0/8), source IEEE (0/8), source-route subframe, then payload.

/// R23.2 Zigbee NWK protocol version (`nwkcProtocolVersion`, §1.4.2).
///
/// Requirement `05-3474-23-331-02`: the protocol-version sub-field of
/// every Zigbee-stack frame carries this value.
pub const NWKC_PROTOCOL_VERSION: u8 = 0x02;

/// Green-Power protocol-version value (§1.4.2). Recognized on decode so
/// Inter-PAN/GP-adjacent frames are describable; this codec never emits it.
pub const NWKC_PROTOCOL_VERSION_GP: u8 = 0x03;

/// Broadcast: all devices in PAN (§3.6.6, Table 3-80).
///
/// Requirement `05-3474-23-366-01`.
pub const BROADCAST_ALL_DEVICES: u16 = 0xFFFF;
/// Broadcast: receivers with `macRxOnWhenIdle = TRUE` (Table 3-80).
///
/// Requirement `05-3474-23-366-01`.
pub const BROADCAST_RX_ON_WHEN_IDLE: u16 = 0xFFFD;
/// Broadcast: all routers and coordinator (Table 3-80).
///
/// Requirement `05-3474-23-366-01`.
pub const BROADCAST_ROUTERS: u16 = 0xFFFC;
/// Broadcast: low-power routers only (Table 3-80).
///
/// Requirement `05-3474-23-366-01`.
pub const BROADCAST_LOW_POWER_ROUTERS: u16 = 0xFFFB;
/// Reserved broadcast range bottom (Table 3-80).
///
/// Requirement `05-3474-23-366-01`.
pub const BROADCAST_RESERVED_LOW: u16 = 0xFFF8;
/// Reserved broadcast range top (Table 3-80).
///
/// Requirement `05-3474-23-366-01`.
pub const BROADCAST_RESERVED_HIGH: u16 = 0xFFFA;

/// Destination used when a broadcast frame is looped back over the local
/// MAC (`DstAddr 0xFFFF` on MCPS-DATA.request, §3.6.6).
///
/// Requirement `05-3474-23-366-01`.
pub const PAN_BROADCAST_LOOPBACK: u16 = 0xFFFF;

/// Declared per-subsystem budget for source-route relays (D5: bounded +
/// fallible + accountable, `SCOPE.md` §2).
///
/// Worst-case header with this budget is 8 (fixed) + 16 (IEEE pair) + 2
/// (subframe head) + 2 × relays = 58 octets, leaving room for payload
/// inside one MAC MSDU. Longer on-wire relay lists are rejected
/// fallibly on decode instead of truncating.
///
/// Requirement `05-3474-23-331-07`.
pub const MAX_SOURCE_ROUTE_RELAYS: usize = 16;

/// Fixed header length before optional fields (Fig. 3-4, §3.3.1).
pub const FIXED_HEADER_LEN: usize = 8;

/// True when `addr` is any NWK broadcast destination (Table 3-80 range
/// `0xFFF8`–`0xFFFF`).
///
/// Requirement `05-3474-23-366-01`.
#[must_use]
pub const fn is_broadcast_addr(addr: u16) -> bool {
    addr >= BROADCAST_RESERVED_LOW
}

/// Frame-type sub-field values, Fig. 3-5 bits 0–1 (Table 3-52, §3.3.1.1.1).
///
/// Requirement `05-3474-23-331-02`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameType {
    /// `00`: NWK data frame.
    Data,
    /// `01`: NWK command frame.
    Command,
    /// `11`: Inter-PAN frame.
    InterPan,
}

impl FrameType {
    /// Decode the 2-bit value; `0b10` is reserved and rejected (the stack
    /// never generates it, §1.4.2).
    pub fn from_bits(bits: u8) -> Result<Self, Error> {
        match bits & 0x03 {
            0x00 => Ok(Self::Data),
            0x01 => Ok(Self::Command),
            0x03 => Ok(Self::InterPan),
            v => Err(Error::ReservedFrameType(v)),
        }
    }

    /// 2-bit wire value.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::Data => 0x00,
            Self::Command => 0x01,
            Self::InterPan => 0x03,
        }
    }
}

/// Discover-route sub-field values, Fig. 3-5 bits 6–7 (Table 3-53,
/// §3.3.1.1.3).
///
/// Requirement `05-3474-23-331-02`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoverRoute {
    /// `0x00`: suppress route discovery.
    Suppress,
    /// `0x01`: enable route discovery.
    Enable,
}

impl DiscoverRoute {
    /// Decode the 2-bit value; `0x02`/`0x03` are reserved and rejected.
    pub fn from_bits(bits: u8) -> Result<Self, Error> {
        match bits & 0x03 {
            0x00 => Ok(Self::Suppress),
            0x01 => Ok(Self::Enable),
            v => Err(Error::ReservedDiscoverRoute(v)),
        }
    }

    /// 2-bit wire value.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::Suppress => 0x00,
            Self::Enable => 0x01,
        }
    }
}

/// NWK frame-control field, Fig. 3-5 (§3.3.1.1).
///
/// Requirement `05-3474-23-331-02`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameControl {
    /// Bits 0–1: data / command / Inter-PAN.
    pub frame_type: FrameType,
    /// Bits 2–5: protocol version (`NWKC_PROTOCOL_VERSION` on transmit).
    pub protocol_version: u8,
    /// Bits 6–7: route-discovery control.
    pub discover_route: DiscoverRoute,
    /// Bit 8: deprecated multicast flag; carried verbatim, never set by
    /// this stack on transmit.
    pub multicast: bool,
    /// Bit 9: NWK security enabled (§3.3.1.1.4).
    pub security: bool,
    /// Bit 10: source-route subframe present (§3.3.1.1.5).
    pub source_route: bool,
    /// Bit 11: destination IEEE address present (§3.3.1.1.6).
    pub dst_ieee: bool,
    /// Bit 12: source IEEE address present (§3.3.1.1.7).
    pub src_ieee: bool,
    /// Bit 13: end-device initiator (§3.3.1.1.8).
    pub end_device_initiator: bool,
}

impl FrameControl {
    /// Data frame with protocol version set, all presence flags clear,
    /// route discovery suppressed.
    #[must_use]
    pub const fn data() -> Self {
        Self {
            frame_type: FrameType::Data,
            protocol_version: NWKC_PROTOCOL_VERSION,
            discover_route: DiscoverRoute::Suppress,
            multicast: false,
            security: false,
            source_route: false,
            dst_ieee: false,
            src_ieee: false,
            end_device_initiator: false,
        }
    }

    /// Command frame baseline: type set, discovery suppressed per §3.4
    /// (every command header suppresses route discovery).
    ///
    /// Requirement `05-3474-23-34-01`.
    #[must_use]
    pub const fn command() -> Self {
        Self {
            frame_type: FrameType::Command,
            protocol_version: NWKC_PROTOCOL_VERSION,
            discover_route: DiscoverRoute::Suppress,
            multicast: false,
            security: false,
            source_route: false,
            dst_ieee: false,
            src_ieee: false,
            end_device_initiator: false,
        }
    }

    /// Pack to the 16-bit wire value (reserved bits 14–15 always zero).
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        (self.frame_type.bits() as u16)
            | ((self.protocol_version as u16 & 0x0F) << 2)
            | ((self.discover_route.bits() as u16) << 6)
            | ((self.multicast as u16) << 8)
            | ((self.security as u16) << 9)
            | ((self.source_route as u16) << 10)
            | ((self.dst_ieee as u16) << 11)
            | ((self.src_ieee as u16) << 12)
            | ((self.end_device_initiator as u16) << 13)
    }

    /// Unpack a 16-bit wire value; reserved frame-type / discover-route
    /// values are rejected, reserved bits 14–15 are ignored (§1.4.2).
    pub fn from_u16(raw: u16) -> Result<Self, Error> {
        Ok(Self {
            frame_type: FrameType::from_bits(raw as u8)?,
            protocol_version: ((raw >> 2) & 0x0F) as u8,
            discover_route: DiscoverRoute::from_bits((raw >> 6) as u8)?,
            multicast: raw & (1 << 8) != 0,
            security: raw & (1 << 9) != 0,
            source_route: raw & (1 << 10) != 0,
            dst_ieee: raw & (1 << 11) != 0,
            src_ieee: raw & (1 << 12) != 0,
            end_device_initiator: raw & (1 << 13) != 0,
        })
    }
}

/// Source-route subframe, Fig. 3-6 (§3.3.1.8).
///
/// The relay closest to the destination is listed first; the relay
/// closest to the originator last (§3.3.1.8.3). The originator
/// initializes `relay_index` to one less than the relay count
/// (§3.3.1.8.2); relays decrement it in transit, so decode preserves
/// the wire value verbatim.
///
/// Requirement `05-3474-23-331-07`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceRoute {
    relays: [u16; MAX_SOURCE_ROUTE_RELAYS],
    len: u8,
    /// Index of the next relay (§3.3.1.8.2).
    pub relay_index: u8,
}

impl SourceRoute {
    /// Build from a relay list (destination-closest first); index is
    /// initialized to `len - 1` per §3.3.1.8.2. Empty lists are rejected:
    /// use `None` in the header instead of an empty subframe.
    pub fn new(relays: &[u16]) -> Result<Self, Error> {
        if relays.is_empty() || relays.len() > MAX_SOURCE_ROUTE_RELAYS {
            return Err(Error::BadRelayCount(relays.len()));
        }
        let mut arr = [0u16; MAX_SOURCE_ROUTE_RELAYS];
        arr[..relays.len()].copy_from_slice(relays);
        let len = relays.len() as u8;
        Ok(Self {
            relays: arr,
            len,
            relay_index: len - 1,
        })
    }

    /// Relay list, destination-closest first.
    #[must_use]
    pub fn relays(&self) -> &[u16] {
        &self.relays[..self.len as usize]
    }

    /// Relay count sub-field value (§3.3.1.8.1).
    #[must_use]
    pub const fn relay_count(&self) -> u8 {
        self.len
    }
}

/// Owned NWK header (Fig. 3-4 routing fields, §§3.3.1.2–3.3.1.8).
///
/// Requirement `05-3474-23-331-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NwkHeader {
    /// Frame control (Fig. 3-5).
    pub control: FrameControl,
    /// Destination 16-bit network address, always present (§3.3.1.2).
    /// Holds a broadcast address for broadcast frames (Table 3-80).
    pub dst_addr: u16,
    /// Source 16-bit network address, always present (§3.3.1.3).
    pub src_addr: u16,
    /// Hop budget, decremented by each receiver (§3.3.1.4).
    pub radius: u8,
    /// Per-source sequence number (§3.3.1.5).
    pub seq: u8,
    /// Destination extended address, iff `control.dst_ieee` (§3.3.1.6).
    /// Must be absent for broadcast/multicast destinations.
    pub dst_ieee: Option<u64>,
    /// Source extended address, iff `control.src_ieee` (§3.3.1.7).
    pub src_ieee: Option<u64>,
    /// Source-route subframe, iff `control.source_route` (§3.3.1.8).
    pub source_route: Option<SourceRoute>,
}

impl NwkHeader {
    /// Minimal data header: no extended addresses, no source route.
    #[must_use]
    pub const fn minimal(
        control: FrameControl,
        dst_addr: u16,
        src_addr: u16,
        radius: u8,
        seq: u8,
    ) -> Self {
        Self {
            control,
            dst_addr,
            src_addr,
            radius,
            seq,
            dst_ieee: None,
            src_ieee: None,
            source_route: None,
        }
    }

    /// Encoded header length in octets (payload excluded).
    #[must_use]
    pub const fn header_len(&self) -> usize {
        FIXED_HEADER_LEN
            + if self.dst_ieee.is_some() { 8 } else { 0 }
            + if self.src_ieee.is_some() { 8 } else { 0 }
            + match self.source_route {
                Some(r) => 2 + 2 * r.relay_count() as usize,
                None => 0,
            }
    }

    /// Consistency between presence flags and optional fields, checked
    /// before every encode so a half-built header can never go on air.
    fn check_consistency(&self) -> Result<(), Error> {
        if self.control.dst_ieee != self.dst_ieee.is_some() {
            return Err(Error::PresenceMismatch("dst_ieee"));
        }
        if self.control.src_ieee != self.src_ieee.is_some() {
            return Err(Error::PresenceMismatch("src_ieee"));
        }
        if self.control.source_route != self.source_route.is_some() {
            return Err(Error::PresenceMismatch("source_route"));
        }
        if self.dst_ieee.is_some() && is_broadcast_addr(self.dst_addr) {
            return Err(Error::BroadcastWithDstIeee);
        }
        Ok(())
    }

    /// Encode header + `payload` into `out`; returns bytes written.
    /// Fails with [`Error::BufferTooSmall`] instead of truncating.
    pub fn encode_into(&self, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        self.check_consistency()?;
        let total = self
            .header_len()
            .checked_add(payload.len())
            .ok_or(Error::BufferTooSmall)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }
        let fc = self.control.to_u16().to_le_bytes();
        out[0] = fc[0];
        out[1] = fc[1];
        out[2..4].copy_from_slice(&self.dst_addr.to_le_bytes());
        out[4..6].copy_from_slice(&self.src_addr.to_le_bytes());
        out[6] = self.radius;
        out[7] = self.seq;
        let mut pos = FIXED_HEADER_LEN;
        if let Some(ieee) = self.dst_ieee {
            out[pos..pos + 8].copy_from_slice(&ieee.to_le_bytes());
            pos += 8;
        }
        if let Some(ieee) = self.src_ieee {
            out[pos..pos + 8].copy_from_slice(&ieee.to_le_bytes());
            pos += 8;
        }
        if let Some(sr) = &self.source_route {
            out[pos] = sr.relay_count();
            out[pos + 1] = sr.relay_index;
            pos += 2;
            for (i, relay) in sr.relays().iter().enumerate() {
                out[pos + 2 * i..pos + 2 * i + 2].copy_from_slice(&relay.to_le_bytes());
            }
            pos += 2 * sr.relays().len();
        }
        out[pos..pos + payload.len()].copy_from_slice(payload);
        Ok(total)
    }
}

/// Zero-copy decode result: owned header plus payload borrowed from the
/// input frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoded<'a> {
    /// Parsed header fields.
    pub header: NwkHeader,
    /// Frame payload (data octets or command id + payload).
    pub payload: &'a [u8],
}

/// Decode one NPDU from the front of `buf`.
///
/// Requirement `05-3474-23-331-01`.
pub fn decode(buf: &[u8]) -> Result<Decoded<'_>, Error> {
    fn take_u16(buf: &[u8], pos: usize) -> Result<u16, Error> {
        let b: [u8; 2] = buf
            .get(pos..pos + 2)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?;
        Ok(u16::from_le_bytes(b))
    }
    if buf.len() < FIXED_HEADER_LEN {
        return Err(Error::Truncated);
    }
    let control = FrameControl::from_u16(take_u16(buf, 0)?)?;
    let dst_addr = take_u16(buf, 2)?;
    let src_addr = take_u16(buf, 4)?;
    let radius = buf[6];
    let seq = buf[7];
    let mut pos = FIXED_HEADER_LEN;
    let dst_ieee = if control.dst_ieee {
        if is_broadcast_addr(dst_addr) {
            return Err(Error::BroadcastWithDstIeee);
        }
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
    let src_ieee = if control.src_ieee {
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
    let source_route = if control.source_route {
        if buf.len() < pos + 2 {
            return Err(Error::Truncated);
        }
        let count = buf[pos] as usize;
        let index = buf[pos + 1];
        if count == 0 || count > MAX_SOURCE_ROUTE_RELAYS {
            return Err(Error::BadRelayCount(count));
        }
        if buf.len() < pos + 2 + 2 * count {
            return Err(Error::Truncated);
        }
        let mut relays = [0u16; MAX_SOURCE_ROUTE_RELAYS];
        for (i, slot) in relays.iter_mut().enumerate().take(count) {
            *slot = u16::from_le_bytes([buf[pos + 2 + 2 * i], buf[pos + 2 + 2 * i + 1]]);
        }
        pos += 2 + 2 * count;
        Some(SourceRoute {
            relays,
            len: count as u8,
            relay_index: index,
        })
    } else {
        None
    };
    Ok(Decoded {
        header: NwkHeader {
            control,
            dst_addr,
            src_addr,
            radius,
            seq,
            dst_ieee,
            src_ieee,
            source_route,
        },
        payload: &buf[pos..],
    })
}

/// Fallible codec errors. No panics on any input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Fewer than [`FIXED_HEADER_LEN`] octets, or an optional field or
    /// relay list overruns the buffer.
    Truncated,
    /// Caller encode buffer too small for header + payload.
    BufferTooSmall,
    /// Frame-type bits `0b10` (reserved, Table 3-52).
    ReservedFrameType(u8),
    /// Discover-route bits `0x02`/`0x03` (reserved, Table 3-53).
    ReservedDiscoverRoute(u8),
    /// Presence flag disagrees with the matching `Option` field; the
    /// payload names the field (`"dst_ieee"`, `"src_ieee"`,
    /// `"source_route"`).
    PresenceMismatch(&'static str),
    /// Destination IEEE address present on a broadcast destination
    /// (§3.3.1.6: the field SHALL NOT be present then).
    BroadcastWithDstIeee,
    /// Source-route relay count of 0, or above
    /// [`MAX_SOURCE_ROUTE_RELAYS`].
    BadRelayCount(usize),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => write!(f, "frame truncated"),
            Self::BufferTooSmall => write!(f, "encode buffer too small"),
            Self::ReservedFrameType(v) => write!(f, "reserved frame type {v:#04x}"),
            Self::ReservedDiscoverRoute(v) => write!(f, "reserved discover-route {v:#04x}"),
            Self::PresenceMismatch(field) => {
                write!(f, "presence flag mismatch for {field}")
            }
            Self::BroadcastWithDstIeee => {
                write!(f, "destination IEEE on broadcast destination")
            }
            Self::BadRelayCount(n) => write!(f, "bad source-route relay count {n}"),
        }
    }
}

impl core::error::Error for Error {}
