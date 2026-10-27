//! APS APDU frame codec: general frame header, data / command /
//! acknowledgement layouts, and the fragmentation extended header.
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2 §2.2.5 (frame
//! formats). All wording here is paraphrase; citations name document,
//! revision, and clause/line only (D1, `SCOPE.md` §2).
//!
//! # Design notes (mirror `rounddance-nwk`)
//!
//! * `no_std` + `#![forbid(unsafe_code)]`, no allocator: decode is
//!   zero-copy (`payload` borrows the input), encode writes into a
//!   caller buffer.
//! * Every fallible path returns [`Error`]; nothing panics, including
//!   on adversarial input (short buffers, reserved discriminants).
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped) pending seed
//! extraction of chapter 2 — wording in code/tests is paraphrase only.

/// Endpoint addressing the local Zigbee device object (§2.2.5.1.2).
///
/// Requirement `05-3474-23-22511-07`.
pub const ENDPOINT_ZDO: u8 = 0x00;

/// Endpoint addressing every active endpoint except the ZDO
/// (§2.2.5.1.2).
///
/// Requirement `05-3474-23-22511-07`.
pub const ENDPOINT_BROADCAST_ALL: u8 = 0xFF;

/// Highest endpoint value available to applications (§2.2.5.1.2).
///
/// Requirement `05-3474-23-22511-07`.
pub const MAX_APP_ENDPOINT: u8 = 0xFE;

/// Frame-type sub-field values, bits 0–1 (Table 2-20, §2.2.5.1.1.1).
///
/// Requirement `05-3474-23-22511-02`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameType {
    /// `0b00`: data frame.
    Data,
    /// `0b01`: command frame.
    Command,
    /// `0b10`: acknowledgement frame.
    Ack,
    /// `0b11`: Inter-PAN APS frame (recognized, never emitted here).
    InterPan,
}

impl FrameType {
    /// Decode the 2-bit value; all four patterns are assigned.
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0x00 => Self::Data,
            0x01 => Self::Command,
            0x02 => Self::Ack,
            _ => Self::InterPan,
        }
    }

    /// 2-bit wire value.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::Data => 0x00,
            Self::Command => 0x01,
            Self::Ack => 0x02,
            Self::InterPan => 0x03,
        }
    }
}

/// Delivery-mode sub-field values, bits 2–3 (Table 2-21, §2.2.5.1.1.2).
///
/// Requirement `05-3474-23-22511-03`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryMode {
    /// `0b00`: normal unicast to one endpoint.
    Unicast,
    /// `0b10`: broadcast; the destination endpoint selects specific
    /// (`0x01`–`0xFE`) or all active (`0xFF`) endpoints.
    Broadcast,
    /// `0b11`: group addressing via the group address field.
    Group,
}

impl DeliveryMode {
    /// Decode the 2-bit value; `0b01` is reserved and rejected.
    pub fn from_bits(bits: u8) -> Result<Self, Error> {
        match bits & 0x03 {
            0x00 => Ok(Self::Unicast),
            0x02 => Ok(Self::Broadcast),
            0x03 => Ok(Self::Group),
            v => Err(Error::ReservedDeliveryMode(v)),
        }
    }

    /// 2-bit wire value.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::Unicast => 0x00,
            Self::Broadcast => 0x02,
            Self::Group => 0x03,
        }
    }
}

/// APS frame-control field, one octet (Fig. 2-4, §2.2.5.1.1).
///
/// Bit layout: 0–1 frame type, 2–3 delivery mode, 4 ACK format, 5
/// security, 6 acknowledgement request, 7 extended header present.
///
/// Requirement `05-3474-23-22511-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameControl {
    /// Bits 0–1: data / command / acknowledgement / Inter-PAN.
    pub frame_type: FrameType,
    /// Bits 2–3: unicast / broadcast / group.
    pub delivery_mode: DeliveryMode,
    /// Bit 4: ACK format — clear carries addressing fields (data
    /// acknowledgement), set omits them (command acknowledgement)
    /// (§§2.2.5.1.1.3, 2.2.5.2.3.1).
    ///
    /// Requirement `05-3474-23-22511-04`.
    pub ack_format: bool,
    /// Bit 5: security enabled (managed by the security provider).
    pub security: bool,
    /// Bit 6: acknowledgement requested; always clear on broadcast /
    /// multicast and on acknowledgement frames themselves
    /// (§§2.2.5.1.1.5, 2.2.8.4.3).
    ///
    /// Requirement `05-3474-23-22511-05`.
    pub ack_request: bool,
    /// Bit 7: extended header sub-frame present.
    ///
    /// Requirement `05-3474-23-22511-06`.
    pub ext_header: bool,
}

impl FrameControl {
    /// Data-frame baseline with the given delivery mode.
    #[must_use]
    pub const fn data(delivery_mode: DeliveryMode) -> Self {
        Self {
            frame_type: FrameType::Data,
            delivery_mode,
            ack_format: false,
            security: false,
            ack_request: false,
            ext_header: false,
        }
    }

    /// Command-frame baseline: never fragmented, never extended
    /// (§2.2.5.2.2.1).
    ///
    /// Requirement `05-3474-23-22511-17`.
    #[must_use]
    pub const fn command() -> Self {
        Self {
            frame_type: FrameType::Command,
            delivery_mode: DeliveryMode::Unicast,
            ack_format: false,
            security: false,
            ack_request: false,
            ext_header: false,
        }
    }

    /// Acknowledgement for a data frame: ACK-format bit clear, so the
    /// addressing fields stay present (§2.2.5.2.3.1).
    ///
    /// Requirement `05-3474-23-22511-18`.
    #[must_use]
    pub const fn ack_for_data() -> Self {
        Self {
            frame_type: FrameType::Ack,
            delivery_mode: DeliveryMode::Unicast,
            ack_format: false,
            security: false,
            ack_request: false,
            ext_header: false,
        }
    }

    /// Acknowledgement for a command frame: ACK-format bit set, so the
    /// addressing fields are omitted (§2.2.5.2.3.1).
    ///
    /// Requirement `05-3474-23-22511-18`.
    #[must_use]
    pub const fn ack_for_command() -> Self {
        Self {
            frame_type: FrameType::Ack,
            delivery_mode: DeliveryMode::Unicast,
            ack_format: true,
            security: false,
            ack_request: false,
            ext_header: false,
        }
    }

    /// Pack to the wire octet.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self.frame_type.bits()
            | (self.delivery_mode.bits() << 2)
            | ((self.ack_format as u8) << 4)
            | ((self.security as u8) << 5)
            | ((self.ack_request as u8) << 6)
            | ((self.ext_header as u8) << 7)
    }

    /// Unpack a wire octet; reserved delivery modes are rejected.
    pub fn from_u8(raw: u8) -> Result<Self, Error> {
        Ok(Self {
            frame_type: FrameType::from_bits(raw),
            delivery_mode: DeliveryMode::from_bits(raw >> 2)?,
            ack_format: raw & (1 << 4) != 0,
            security: raw & (1 << 5) != 0,
            ack_request: raw & (1 << 6) != 0,
            ext_header: raw & (1 << 7) != 0,
        })
    }
}

/// Fragmentation sub-field values, extended-frame-control bits 0–1
/// (Table 2-22, §2.2.5.1.8.1).
///
/// Requirement `05-3474-23-22511-13`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fragmentation {
    /// `0b00`: transmission is not fragmented.
    Unfragmented,
    /// `0b01`: first fragment; the block number carries the total
    /// block count.
    First,
    /// `0b10`: later fragment; the block number carries this block's
    /// index (`0x01` = second fragment, and so on).
    Subsequent,
}

impl Fragmentation {
    /// Decode the 2-bit value; `0b11` is reserved and rejected.
    pub fn from_bits(bits: u8) -> Result<Self, Error> {
        match bits & 0x03 {
            0x00 => Ok(Self::Unfragmented),
            0x01 => Ok(Self::First),
            0x02 => Ok(Self::Subsequent),
            v => Err(Error::ReservedFragmentation(v)),
        }
    }

    /// 2-bit wire value.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::Unfragmented => 0x00,
            Self::First => 0x01,
            Self::Subsequent => 0x02,
        }
    }
}

/// Extended header sub-frame (Fig. 2-5, §2.2.5.1.8).
///
/// The block number is present exactly when the transmission is
/// fragmented (§2.2.5.1.8.2); the ACK bitfield is additionally present
/// only on fragmented acknowledgements (§2.2.5.1.8.3).
///
/// Requirements `05-3474-23-22511-13`, `05-3474-23-22511-14`,
/// `05-3474-23-22511-15`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtHeader {
    /// Fragmentation sub-field of the extended frame control.
    pub frag: Fragmentation,
    /// Block number: total count on the first fragment, this block's
    /// index on later ones; absent when unfragmented.
    pub block_number: Option<u8>,
    /// ACK bitfield: received-blocks mask on fragmented
    /// acknowledgements only.
    pub ack_bitfield: Option<u8>,
}

impl ExtHeader {
    /// Unfragmented extended header (no block fields).
    #[must_use]
    pub const fn unfragmented() -> Self {
        Self {
            frag: Fragmentation::Unfragmented,
            block_number: None,
            ack_bitfield: None,
        }
    }

    /// First-fragment header carrying the total block count.
    #[must_use]
    pub const fn first(total_blocks: u8) -> Self {
        Self {
            frag: Fragmentation::First,
            block_number: Some(total_blocks),
            ack_bitfield: None,
        }
    }

    /// Later-fragment header carrying this block's index.
    #[must_use]
    pub const fn subsequent(block_index: u8) -> Self {
        Self {
            frag: Fragmentation::Subsequent,
            block_number: Some(block_index),
            ack_bitfield: None,
        }
    }

    /// Fragmented-acknowledgement header: block number of the window
    /// base plus the received-blocks mask.
    #[must_use]
    pub const fn frag_ack(window_base: u8, bitfield: u8) -> Self {
        Self {
            frag: Fragmentation::First,
            block_number: Some(window_base),
            ack_bitfield: Some(bitfield),
        }
    }

    /// Consistency between sub-field and optional fields, checked on
    /// every encode for the frame type being built.
    fn check(&self, frame_type: FrameType) -> Result<(), Error> {
        if self.frag == Fragmentation::Unfragmented {
            if self.block_number.is_some() || self.ack_bitfield.is_some() {
                return Err(Error::PresenceMismatch("ext_header"));
            }
            return Ok(());
        }
        if self.block_number.is_none() {
            return Err(Error::PresenceMismatch("block_number"));
        }
        let want_bitfield = frame_type == FrameType::Ack;
        if self.ack_bitfield.is_some() != want_bitfield {
            return Err(Error::PresenceMismatch("ack_bitfield"));
        }
        Ok(())
    }

    /// Encoded length in octets.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        1 + if self.block_number.is_some() { 1 } else { 0 }
            + if self.ack_bitfield.is_some() { 1 } else { 0 }
    }
}

/// Destination addressing of a data frame (§§2.2.5.1.2–2.2.5.1.3).
///
/// Requirement `05-3474-23-22511-07`, `05-3474-23-22511-08`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataDest {
    /// Normal unicast: destination endpoint present.
    Unicast {
        /// `0x00` = ZDO, `0x01`–`0xFE` = application, `0xFF` is not
        /// valid here.
        dst_endpoint: u8,
    },
    /// Broadcast: endpoint `0x01`–`0xFE` for endpoint-directed
    /// broadcast, `0xFF` for all active endpoints.
    Broadcast {
        /// Must not be `0x00`.
        dst_endpoint: u8,
    },
    /// Group addressing: group address present, destination endpoint
    /// omitted.
    Group {
        /// 16-bit group identifier.
        group_addr: u16,
    },
}

impl DataDest {
    /// Delivery mode implied by the variant.
    #[must_use]
    pub const fn delivery_mode(&self) -> DeliveryMode {
        match self {
            Self::Unicast { .. } => DeliveryMode::Unicast,
            Self::Broadcast { .. } => DeliveryMode::Broadcast,
            Self::Group { .. } => DeliveryMode::Group,
        }
    }
}

/// Data-frame header (Fig. 2-7, §2.2.5.2.1).
///
/// Carries frame control, destination addressing, cluster and profile
/// identifiers, source endpoint, APS counter, and the optional
/// extended header; the frame payload follows.
///
/// Requirement `05-3474-23-22511-16`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataHeader {
    /// Frame control; `frame_type` must be data.
    pub control: FrameControl,
    /// Destination addressing; must agree with `control.delivery_mode`.
    pub dest: DataDest,
    /// Cluster identifier, always present on data frames.
    pub cluster_id: u16,
    /// Profile identifier, always present on data frames.
    pub profile_id: u16,
    /// Originating endpoint, always present on data frames.
    pub src_endpoint: u8,
    /// Per-originator sequence counter (§2.2.5.1.7).
    pub counter: u8,
    /// Extended header; present iff `control.ext_header` is set.
    pub ext: Option<ExtHeader>,
}

impl DataHeader {
    /// Consistency between flags and fields, checked before every
    /// encode so a half-built header can never go on air.
    fn check(&self) -> Result<(), Error> {
        if self.control.frame_type != FrameType::Data {
            return Err(Error::FrameTypeMismatch {
                expected: FrameType::Data,
                found: self.control.frame_type,
            });
        }
        if self.control.delivery_mode != self.dest.delivery_mode() {
            return Err(Error::PresenceMismatch("delivery_mode"));
        }
        if self.control.ext_header != self.ext.is_some() {
            return Err(Error::PresenceMismatch("ext_header"));
        }
        if let DataDest::Broadcast { dst_endpoint } = self.dest {
            if dst_endpoint == ENDPOINT_ZDO {
                return Err(Error::BadBroadcastEndpoint(dst_endpoint));
            }
        }
        if let Some(ext) = &self.ext {
            ext.check(FrameType::Data)?;
        }
        Ok(())
    }

    /// Encoded header length in octets (payload excluded).
    #[must_use]
    pub fn header_len(&self) -> usize {
        1 + match self.dest {
            DataDest::Unicast { .. } | DataDest::Broadcast { .. } => 1,
            DataDest::Group { .. } => 2,
        } + 2
            + 2
            + 1
            + 1
            + self.ext.map_or(0, |e| e.encoded_len())
    }

    /// Encode header + `payload` into `out`; returns bytes written.
    /// Fails with [`Error::BufferTooSmall`] instead of truncating.
    pub fn encode_into(&self, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        self.check()?;
        let total = self
            .header_len()
            .checked_add(payload.len())
            .ok_or(Error::BufferTooSmall)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }
        let mut pos = 0;
        out[pos] = self.control.to_u8();
        pos += 1;
        match self.dest {
            DataDest::Unicast { dst_endpoint } | DataDest::Broadcast { dst_endpoint } => {
                out[pos] = dst_endpoint;
                pos += 1;
            }
            DataDest::Group { group_addr } => {
                out[pos..pos + 2].copy_from_slice(&group_addr.to_le_bytes());
                pos += 2;
            }
        }
        out[pos..pos + 2].copy_from_slice(&self.cluster_id.to_le_bytes());
        pos += 2;
        out[pos..pos + 2].copy_from_slice(&self.profile_id.to_le_bytes());
        pos += 2;
        out[pos] = self.src_endpoint;
        pos += 1;
        out[pos] = self.counter;
        pos += 1;
        if let Some(ext) = &self.ext {
            out[pos] = ext.frag.bits();
            pos += 1;
            if let Some(n) = ext.block_number {
                out[pos] = n;
                pos += 1;
            }
            if let Some(b) = ext.ack_bitfield {
                out[pos] = b;
                pos += 1;
            }
        }
        out[pos..pos + payload.len()].copy_from_slice(payload);
        Ok(total)
    }
}

/// Addressing fields echoed in a data-frame acknowledgement
/// (§2.2.5.2.3.1): endpoints are swapped relative to the frame being
/// acknowledged, cluster/profile/counter are copied.
///
/// Requirement `05-3474-23-22511-18`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckAddr {
    /// Original source endpoint.
    pub dst_endpoint: u8,
    /// Copied cluster identifier.
    pub cluster_id: u16,
    /// Copied profile identifier.
    pub profile_id: u16,
    /// Original destination endpoint.
    pub src_endpoint: u8,
}

/// Acknowledgement-frame header (Fig. 2-9, §2.2.5.2.3).
///
/// Requirement `05-3474-23-22511-18`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckHeader {
    /// Frame control; `frame_type` must be acknowledgement and the
    /// ACK-request bit must be clear (§2.2.8.4.3).
    pub control: FrameControl,
    /// Addressing fields: present exactly when `ack_format` is clear
    /// (data acknowledgement), omitted for command acknowledgements.
    pub addr: Option<AckAddr>,
    /// Copied APS counter of the frame being acknowledged.
    pub counter: u8,
    /// Extended header; present iff `control.ext_header` is set.
    pub ext: Option<ExtHeader>,
}

impl AckHeader {
    /// Consistency between flags and fields, checked before every encode.
    fn check(&self) -> Result<(), Error> {
        if self.control.frame_type != FrameType::Ack {
            return Err(Error::FrameTypeMismatch {
                expected: FrameType::Ack,
                found: self.control.frame_type,
            });
        }
        if self.control.ack_request {
            return Err(Error::AckRequestsAck);
        }
        // ACK-format set = command acknowledgement: no addressing
        // fields. Clear = data acknowledgement: fields present.
        if self.control.ack_format == self.addr.is_some() {
            return Err(Error::PresenceMismatch("ack_format"));
        }
        if self.control.ext_header != self.ext.is_some() {
            return Err(Error::PresenceMismatch("ext_header"));
        }
        if let Some(ext) = &self.ext {
            ext.check(FrameType::Ack)?;
        }
        Ok(())
    }

    /// Encoded header length in octets.
    #[must_use]
    pub fn header_len(&self) -> usize {
        1 + self.addr.map_or(0, |_| 1 + 2 + 2 + 1) + 1 + self.ext.map_or(0, |e| e.encoded_len())
    }

    /// Encode header (acknowledgements carry no separate payload —
    /// the bitfield form lives in the extended header) into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check()?;
        let total = self.header_len();
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }
        let mut pos = 0;
        out[pos] = self.control.to_u8();
        pos += 1;
        if let Some(addr) = &self.addr {
            out[pos] = addr.dst_endpoint;
            pos += 1;
            out[pos..pos + 2].copy_from_slice(&addr.cluster_id.to_le_bytes());
            pos += 2;
            out[pos..pos + 2].copy_from_slice(&addr.profile_id.to_le_bytes());
            pos += 2;
            out[pos] = addr.src_endpoint;
            pos += 1;
        }
        out[pos] = self.counter;
        pos += 1;
        if let Some(ext) = &self.ext {
            out[pos] = ext.frag.bits();
            pos += 1;
            if let Some(n) = ext.block_number {
                out[pos] = n;
                pos += 1;
            }
            if let Some(b) = ext.ack_bitfield {
                out[pos] = b;
            }
        }
        Ok(total)
    }
}

/// Command-frame header (Fig. 2-8, §2.2.5.2.2): frame control plus APS
/// counter only — never fragmented, never extended.
///
/// Requirement `05-3474-23-22511-17`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandHeader {
    /// Frame control; `frame_type` must be command and `ext_header`
    /// must be clear.
    pub control: FrameControl,
    /// APS counter.
    pub counter: u8,
    /// Command identifier (§2.2.5.2.2.2).
    pub command_id: u8,
}

impl CommandHeader {
    /// Consistency between flags and fields, checked before every encode.
    fn check(&self) -> Result<(), Error> {
        if self.control.frame_type != FrameType::Command {
            return Err(Error::FrameTypeMismatch {
                expected: FrameType::Command,
                found: self.control.frame_type,
            });
        }
        if self.control.ext_header {
            return Err(Error::PresenceMismatch("ext_header"));
        }
        Ok(())
    }

    /// Encoded header length in octets: control + counter + command id.
    #[must_use]
    pub const fn header_len(&self) -> usize {
        3
    }

    /// Encode header + command payload into `out`.
    pub fn encode_into(&self, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        self.check()?;
        let total = self
            .header_len()
            .checked_add(payload.len())
            .ok_or(Error::BufferTooSmall)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.control.to_u8();
        out[1] = self.counter;
        out[2] = self.command_id;
        out[3..3 + payload.len()].copy_from_slice(payload);
        Ok(total)
    }
}

/// Zero-copy decode result: owned header plus payload borrowed from the
/// input frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedData<'a> {
    /// Parsed data header.
    pub header: DataHeader,
    /// Frame payload (part or all of the ASDU, §2.2.5.2.1.1).
    pub payload: &'a [u8],
}

/// Zero-copy decode result for acknowledgement frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedAck<'a> {
    /// Parsed acknowledgement header.
    pub header: AckHeader,
    /// Trailing octets, if any (normally empty).
    pub payload: &'a [u8],
}

/// Zero-copy decode result for command frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedCommand<'a> {
    /// Parsed command header.
    pub header: CommandHeader,
    /// Command payload (§2.2.5.2.2.3).
    pub payload: &'a [u8],
}

fn take_byte(buf: &[u8], pos: usize) -> Result<u8, Error> {
    buf.get(pos).copied().ok_or(Error::Truncated)
}

fn take_u16_le(buf: &[u8], pos: usize) -> Result<u16, Error> {
    let lo = take_byte(buf, pos)?;
    let hi = take_byte(buf, pos + 1)?;
    Ok(u16::from_le_bytes([lo, hi]))
}

fn decode_ext(buf: &[u8], pos: usize, frame_type: FrameType) -> Result<(ExtHeader, usize), Error> {
    let raw = take_byte(buf, pos)?;
    let frag = Fragmentation::from_bits(raw)?;
    // Upper bits of the extended frame control are reserved.
    let mut at = pos + 1;
    let block_number = if frag != Fragmentation::Unfragmented {
        let n = take_byte(buf, at)?;
        at += 1;
        Some(n)
    } else {
        None
    };
    let ack_bitfield = if frame_type == FrameType::Ack && frag != Fragmentation::Unfragmented {
        let b = take_byte(buf, at)?;
        at += 1;
        Some(b)
    } else {
        None
    };
    let ext = ExtHeader {
        frag,
        block_number,
        ack_bitfield,
    };
    ext.check(frame_type)?;
    Ok((ext, at))
}

/// Peek the frame type of the frame at the front of `buf`.
pub fn peek_frame_type(buf: &[u8]) -> Result<FrameType, Error> {
    Ok(FrameType::from_bits(take_byte(buf, 0)?))
}

/// Decode one data APDU from the front of `buf`.
///
/// Requirement `05-3474-23-22511-16`.
pub fn decode_data(buf: &[u8]) -> Result<DecodedData<'_>, Error> {
    let control = FrameControl::from_u8(take_byte(buf, 0)?)?;
    if control.frame_type != FrameType::Data {
        return Err(Error::FrameTypeMismatch {
            expected: FrameType::Data,
            found: control.frame_type,
        });
    }
    let mut pos = 1;
    let dest = match control.delivery_mode {
        DeliveryMode::Unicast => {
            let ep = take_byte(buf, pos)?;
            pos += 1;
            DataDest::Unicast { dst_endpoint: ep }
        }
        DeliveryMode::Broadcast => {
            let ep = take_byte(buf, pos)?;
            pos += 1;
            if ep == ENDPOINT_ZDO {
                return Err(Error::BadBroadcastEndpoint(ep));
            }
            DataDest::Broadcast { dst_endpoint: ep }
        }
        DeliveryMode::Group => {
            let g = take_u16_le(buf, pos)?;
            pos += 2;
            DataDest::Group { group_addr: g }
        }
    };
    let cluster_id = take_u16_le(buf, pos)?;
    pos += 2;
    let profile_id = take_u16_le(buf, pos)?;
    pos += 2;
    let src_endpoint = take_byte(buf, pos)?;
    pos += 1;
    let counter = take_byte(buf, pos)?;
    pos += 1;
    let ext = if control.ext_header {
        let (ext, next) = decode_ext(buf, pos, FrameType::Data)?;
        pos = next;
        Some(ext)
    } else {
        None
    };
    let header = DataHeader {
        control,
        dest,
        cluster_id,
        profile_id,
        src_endpoint,
        counter,
        ext,
    };
    Ok(DecodedData {
        header,
        payload: buf.get(pos..).ok_or(Error::Truncated)?,
    })
}

/// Decode one acknowledgement APDU from the front of `buf`.
///
/// Requirement `05-3474-23-22511-18`.
pub fn decode_ack(buf: &[u8]) -> Result<DecodedAck<'_>, Error> {
    let control = FrameControl::from_u8(take_byte(buf, 0)?)?;
    if control.frame_type != FrameType::Ack {
        return Err(Error::FrameTypeMismatch {
            expected: FrameType::Ack,
            found: control.frame_type,
        });
    }
    if control.ack_request {
        return Err(Error::AckRequestsAck);
    }
    let mut pos = 1;
    // ACK-format clear = data acknowledgement: addressing fields present.
    let addr = if control.ack_format {
        None
    } else {
        let dst_endpoint = take_byte(buf, pos)?;
        pos += 1;
        let cluster_id = take_u16_le(buf, pos)?;
        pos += 2;
        let profile_id = take_u16_le(buf, pos)?;
        pos += 2;
        let src_endpoint = take_byte(buf, pos)?;
        pos += 1;
        Some(AckAddr {
            dst_endpoint,
            cluster_id,
            profile_id,
            src_endpoint,
        })
    };
    let counter = take_byte(buf, pos)?;
    pos += 1;
    let ext = if control.ext_header {
        let (ext, next) = decode_ext(buf, pos, FrameType::Ack)?;
        pos = next;
        Some(ext)
    } else {
        None
    };
    let header = AckHeader {
        control,
        addr,
        counter,
        ext,
    };
    Ok(DecodedAck {
        header,
        payload: buf.get(pos..).ok_or(Error::Truncated)?,
    })
}

/// Decode one command APDU from the front of `buf`.
///
/// Requirement `05-3474-23-22511-17`.
pub fn decode_command(buf: &[u8]) -> Result<DecodedCommand<'_>, Error> {
    let control = FrameControl::from_u8(take_byte(buf, 0)?)?;
    if control.frame_type != FrameType::Command {
        return Err(Error::FrameTypeMismatch {
            expected: FrameType::Command,
            found: control.frame_type,
        });
    }
    if control.ext_header {
        return Err(Error::PresenceMismatch("ext_header"));
    }
    let counter = take_byte(buf, 1)?;
    let command_id = take_byte(buf, 2)?;
    let header = CommandHeader {
        control,
        counter,
        command_id,
    };
    Ok(DecodedCommand {
        header,
        payload: buf.get(3..).ok_or(Error::Truncated)?,
    })
}

/// Fallible codec errors. No panics on any input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Fewer octets than the fixed prefix, or an optional field
    /// overruns the buffer.
    Truncated,
    /// Caller encode buffer too small for header + payload.
    BufferTooSmall,
    /// Delivery-mode bits `0b01` (reserved, Table 2-21).
    ReservedDeliveryMode(u8),
    /// Fragmentation bits `0b11` (reserved, Table 2-22).
    ReservedFragmentation(u8),
    /// A typed decode/encode entry point met another frame type.
    FrameTypeMismatch {
        /// The frame type the entry point handles.
        expected: FrameType,
        /// The frame type on the wire / in the header.
        found: FrameType,
    },
    /// Presence flag disagrees with the matching field; the payload
    /// names the field (`"delivery_mode"`, `"ext_header"`,
    /// `"block_number"`, `"ack_bitfield"`, `"ack_format"`).
    PresenceMismatch(&'static str),
    /// Broadcast destination endpoint `0x00` (§2.2.5.1.2: broadcasts
    /// use `0x01`–`0xFE` or `0xFF`).
    BadBroadcastEndpoint(u8),
    /// An acknowledgement frame with the acknowledgement-request bit
    /// set (§2.2.8.4.3: acknowledgements are never acknowledged).
    AckRequestsAck,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => write!(f, "frame truncated"),
            Self::BufferTooSmall => write!(f, "encode buffer too small"),
            Self::ReservedDeliveryMode(v) => write!(f, "reserved delivery mode {v:#04x}"),
            Self::ReservedFragmentation(v) => write!(f, "reserved fragmentation {v:#04x}"),
            Self::FrameTypeMismatch { expected, found } => {
                write!(f, "expected {expected:?}, found {found:?}")
            }
            Self::PresenceMismatch(field) => write!(f, "presence flag mismatch for {field}"),
            Self::BadBroadcastEndpoint(v) => write!(f, "broadcast endpoint {v:#04x}"),
            Self::AckRequestsAck => write!(f, "acknowledgement requests acknowledgement"),
        }
    }
}

impl core::error::Error for Error {}
