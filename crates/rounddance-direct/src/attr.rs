//! Direct TLV attribute codec.
//!
//! Paraphrase-level model of doc `20-27688-041` §7.7.2.4 (TLV
//! items per the referenced Zigbee TLV format: one-octet tag,
//! one-octet length, value octets; Table 27 TLV IDs; Table 28
//! device types; Table 29 joining methods; Table 30 network-status
//! map; Tables 31–33 status-code TLV; Tables 34–35 link-key TLV).
//! All values little-endian (§7.7.2.1, `20-27688-041-772-01`).
//!
//! Requirement IDs: `20-27688-041-772-01` (service discipline),
//! `20-27688-041-772-02` (network-operation closure: key TLV
//! global/unique + provisional/permanent attributes).

/// Codec failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrError {
    /// Input ends mid-TLV.
    Truncated,
    /// A fixed-shape TLV carries an impossible length.
    LengthMismatch,
    /// Caller buffer too small.
    BufferTooSmall,
    /// Reserved/unknown domain or structurally invalid value.
    BadValue,
}

/// Longest TLV body this codec accepts (a 16-octet key plus tag
/// flags; anything longer cannot be a defined commissioning TLV).
pub const TLV_MAX_BODY: usize = 24;

/// Local TLV IDs for commissioning, Table 27
/// (`20-27688-041-772-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlvId(pub u8);

impl TlvId {
    pub const EXT_PAN_ID: Self = Self(0x00);
    pub const SHORT_PAN_ID: Self = Self(0x01);
    pub const NETWORK_CHANNEL: Self = Self(0x02);
    pub const NETWORK_KEY: Self = Self(0x03);
    pub const LINK_KEY: Self = Self(0x04);
    pub const DEVICE_TYPE: Self = Self(0x05);
    pub const NWK_ADDRESS: Self = Self(0x06);
    pub const JOINING_METHOD: Self = Self(0x07);
    pub const IEEE_ADDRESS: Self = Self(0x08);
    pub const TC_ADDRESS: Self = Self(0x09);
    pub const NET_STATUS_MAP: Self = Self(0x0A);
    pub const NWK_UPDATE_ID: Self = Self(0x0B);
    pub const NWK_KEY_SEQ: Self = Self(0x0C);
    pub const ADMIN_KEY: Self = Self(0x0D);
    pub const STATUS_CODE: Self = Self(0x0E);
    pub const EXT_STATUS_CODE: Self = Self(0x0F);

    /// Reserved range (`0x10`–`0xFF`).
    #[must_use]
    pub fn is_reserved(self) -> bool {
        self.0 >= 0x10
    }
}

/// One decoded TLV item: tag plus borrowed body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// Tag octet.
    pub tag: u8,
    /// Body octets (exactly `length`).
    pub body: &'a [u8],
}

/// Encode one TLV (`tag`, `body`) into `out`.
/// Returns the written length.
pub fn encode_tlv(tag: u8, body: &[u8], out: &mut [u8]) -> Result<usize, AttrError> {
    if body.len() > TLV_MAX_BODY || out.len() < 2 + body.len() {
        return Err(AttrError::BufferTooSmall);
    }
    out[0] = tag;
    out[1] = body.len() as u8;
    out[2..2 + body.len()].copy_from_slice(body);
    Ok(2 + body.len())
}

/// Decode the first TLV in `input`.
/// Returns the item plus consumed length. Unknown and reserved
/// tags decode like any other — general TLV processing skips
/// what it does not understand; callers filter by tag.
pub fn decode_tlv(input: &[u8]) -> Result<(Tlv<'_>, usize), AttrError> {
    if input.len() < 2 {
        return Err(AttrError::Truncated);
    }
    let len = input[1] as usize;
    if input.len() < 2 + len {
        return Err(AttrError::Truncated);
    }
    Ok((
        Tlv {
            tag: input[0],
            body: &input[2..2 + len],
        },
        2 + len,
    ))
}

/// Status domains/operations, Table 33 (`20-27688-041-772-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusDomain(pub u8);

impl StatusDomain {
    pub const GENERAL: Self = Self(0x00);
    pub const FORM_NETWORK: Self = Self(0x01);
    pub const JOIN_NETWORK: Self = Self(0x02);
    pub const PERMIT_JOINING: Self = Self(0x03);
    pub const LEAVE_NETWORK: Self = Self(0x04);
    pub const MANAGE_JOINERS: Self = Self(0x05);
    pub const IDENTIFY: Self = Self(0x06);
    pub const FINDING_BINDING: Self = Self(0x07);

    /// Defined domains are `0x00`–`0x07`.
    #[must_use]
    pub fn is_defined(self) -> bool {
        self.0 <= 0x07
    }
}

/// Status Code TLV body (Tables 31–32): domain/operation octet
/// plus status octet; success is zero, every non-zero value is a
/// failure — there is no partial success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusReport {
    /// Domain/operation scope.
    pub domain: u8,
    /// Status within that scope (`0` = success).
    pub code: u8,
}

impl StatusReport {
    /// Success report for one operation scope.
    #[must_use]
    pub fn success(domain: StatusDomain) -> Self {
        Self {
            domain: domain.0,
            code: 0,
        }
    }

    /// Whether this report signals success.
    #[must_use]
    pub fn is_success(self) -> bool {
        self.code == 0
    }

    /// Encode as a full TLV into `out`; returns written length.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, AttrError> {
        encode_tlv(TlvId::STATUS_CODE.0, &[self.domain, self.code], out)
    }

    /// Decode a Status Code TLV body.
    pub fn decode_body(body: &[u8]) -> Result<Self, AttrError> {
        if body.len() != 2 {
            return Err(AttrError::LengthMismatch);
        }
        if !StatusDomain(body[0]).is_defined() {
            return Err(AttrError::BadValue);
        }
        Ok(Self {
            domain: body[0],
            code: body[1],
        })
    }
}

/// Link-Key TLV flags, Table 35 (`20-27688-041-772-02`): bit 0
/// selects unique vs. global, bit 1 provisional vs. permanent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkKeyFlags(pub u8);

impl LinkKeyFlags {
    /// Global permanent key (both bits clear).
    pub const GLOBAL_PERMANENT: Self = Self(0x00);

    /// Bit 0: unique (vs. global) key.
    #[must_use]
    pub fn unique(self) -> bool {
        self.0 & 0x01 != 0
    }

    /// Bit 1: provisional (vs. permanent) key.
    #[must_use]
    pub fn provisional(self) -> bool {
        self.0 & 0x02 != 0
    }

    /// Only bits 0–1 are defined; higher bits must be clear.
    #[must_use]
    pub fn valid(self) -> bool {
        self.0 & 0xFC == 0
    }
}

/// Link-Key TLV body (Table 34): flags octet plus 16-octet key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkKeyTlv {
    /// Key flags.
    pub flags: LinkKeyFlags,
    /// 16-octet link key.
    pub key: [u8; 16],
}

impl LinkKeyTlv {
    /// Encode as a full TLV into `out`; returns written length.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, AttrError> {
        if !self.flags.valid() {
            return Err(AttrError::BadValue);
        }
        let mut body = [0u8; 17];
        body[0] = self.flags.0;
        body[1..].copy_from_slice(&self.key);
        encode_tlv(TlvId::LINK_KEY.0, &body, out)
    }

    /// Decode a Link-Key TLV body.
    pub fn decode_body(body: &[u8]) -> Result<Self, AttrError> {
        if body.len() != 17 {
            return Err(AttrError::LengthMismatch);
        }
        let flags = LinkKeyFlags(body[0]);
        if !flags.valid() {
            return Err(AttrError::BadValue);
        }
        let mut key = [0u8; 16];
        key.copy_from_slice(&body[1..]);
        Ok(Self { flags, key })
    }
}

/// Joining-method values, Table 29 (`20-27688-041-772-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinMethod {
    /// Join through the MAC association procedure.
    MacAssociation = 0x00,
    /// Secure network rejoin (with key).
    SecureRejoin = 0x01,
    /// Out-of-band commissioning: parameters apply as-is
    /// (plausibility and range checks still apply).
    OutOfBand = 0x02,
}

impl JoinMethod {
    /// Decode the single-octet value; unknown values fail.
    pub fn decode(v: u8) -> Result<Self, AttrError> {
        match v {
            0x00 => Ok(Self::MacAssociation),
            0x01 => Ok(Self::SecureRejoin),
            0x02 => Ok(Self::OutOfBand),
            _ => Err(AttrError::BadValue),
        }
    }
}

/// Device-type values, Table 28.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// Zigbee coordinator.
    Coordinator = 0x00,
    /// Zigbee router.
    Router = 0x01,
    /// Zigbee end device.
    EndDevice = 0x02,
}

impl DeviceType {
    /// Decode the single-octet value; unknown values fail.
    pub fn decode(v: u8) -> Result<Self, AttrError> {
        match v {
            0x00 => Ok(Self::Coordinator),
            0x01 => Ok(Self::Router),
            0x02 => Ok(Self::EndDevice),
            _ => Err(AttrError::BadValue),
        }
    }
}

/// Network-status map bits, Table 30.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetStatusMap(pub u8);

impl NetStatusMap {
    /// Bits 0–2: joined status (0 = not commissioned,
    /// 1 = commissioning in progress, 2 = commissioned).
    #[must_use]
    pub fn joined_status(self) -> u8 {
        self.0 & 0x07
    }

    /// Bit 3: open (`true`) vs. closed network.
    #[must_use]
    pub fn open(self) -> bool {
        self.0 & 0x08 != 0
    }

    /// Bit 4: centralized (`true`) vs. distributed network.
    #[must_use]
    pub fn centralized(self) -> bool {
        self.0 & 0x10 != 0
    }

    /// Reserved bits 5–7 must be clear.
    #[must_use]
    pub fn valid(self) -> bool {
        self.0 & 0xE0 == 0 && self.joined_status() <= 2
    }
}

/// Little-endian `u16` helpers (all multi-octet values ride
/// little-endian, §7.7.2.1).
#[must_use]
pub fn u16_le(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}

/// Decode a little-endian `u16` body.
pub fn decode_u16_le(body: &[u8]) -> Result<u16, AttrError> {
    if body.len() != 2 {
        return Err(AttrError::LengthMismatch);
    }
    Ok(u16::from_le_bytes([body[0], body[1]]))
}
