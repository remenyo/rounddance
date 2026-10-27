//! ZCL data-type codec: scalar types, strings, bounded arrays.
//!
//! Paraphrase-level model of doc `07-5123-08` §2.6.2 (data types,
//! anchor p0096-L3486-L3489), Table 2-11 (type identifiers, anchor
//! p0098-L3511 + p0099–p0100 bodies), §2.6.2.5–2.6.2.8 (boolean,
//! bitmap, integer ranges, anchors p0100-L3517-L3531), and the
//! string/array layouts (§2.6.2.13/2.6.2.14/2.6.2.18, anchors
//! p0102-L3588-L3593, p0103-L3595-L3601, p0104-L3647-L3653). All
//! wording here is paraphrase (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are repo-minted
//! (`07-5123-08-<clause>-<seq>`, dots stripped), MINTED-pending-confirm.

use crate::Error;

/// Longest short/long string this codec accepts inline (octets).
/// Longer wire values are rejected fallibly, never truncated.
pub const MAX_STR_LEN: usize = 32;
/// Largest packed array body this codec accepts inline (octets).
pub const MAX_ARRAY_BYTES: usize = 32;
/// Largest element count a decoded array may carry.
pub const MAX_ARRAY_ELEMS: usize = 16;

/// Data-type identifiers carried on the wire (Table 2-11 values).
///
/// Requirement `07-5123-08-262-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataType {
    /// 0x00: attribute with no associated data.
    NoData,
    /// 0x08–0x0f: opaque data, 1–8 octets.
    Data(u8),
    /// 0x10: logical value.
    Bool,
    /// 0x18–0x1f: bit maps, 1–8 octets.
    Map(u8),
    /// 0x20–0x27: unsigned integers, 1–8 octets.
    UInt(u8),
    /// 0x28–0x2f: signed integers, 1–8 octets.
    Int(u8),
    /// 0x30: 8-bit enumeration.
    Enum8,
    /// 0x31: 16-bit enumeration.
    Enum16,
    /// 0x38: 16-bit IEEE-754 half (carried raw; discrete).
    Semi,
    /// 0x39: 32-bit float (carried as bits).
    Single,
    /// 0x3a: 64-bit float (carried as bits).
    Double,
    /// 0x41: length-prefixed octet string.
    OctetStr,
    /// 0x42: length-prefixed character string.
    CharStr,
    /// 0x43: 16-bit-length octet string.
    LongOctetStr,
    /// 0x44: 16-bit-length character string.
    LongCharStr,
    /// 0x48: packed array (scalar elements only here).
    Array,
    /// 0x4c/0x50/0x51: composite types (recognized, not coded).
    Composite(u8),
    /// 0xe0/0xe1/0xe2: time-of-day, date, UTC (32-bit, analog).
    Time(u8),
    /// 0xe8/0xe9/0xea: cluster/attribute id, BACnet OID.
    Id16or32(u8),
    /// 0xf0: 64-bit IEEE address.
    Eui64,
    /// 0xf1: 128-bit key.
    Key128,
    /// 0xff: unknown placeholder (never identifies real data).
    Unknown,
}

impl DataType {
    /// Decode a wire type octet. Unlisted values are rejected.
    ///
    /// Requirement `07-5123-08-262-01` (MINTED-pending-confirm).
    pub const fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            0x00 => Ok(Self::NoData),
            0x08..=0x0f => Ok(Self::Data(v - 0x08 + 1)),
            0x10 => Ok(Self::Bool),
            0x18..=0x1f => Ok(Self::Map(v - 0x18 + 1)),
            0x20..=0x27 => Ok(Self::UInt(v - 0x20 + 1)),
            0x28..=0x2f => Ok(Self::Int(v - 0x28 + 1)),
            0x30 => Ok(Self::Enum8),
            0x31 => Ok(Self::Enum16),
            0x38 => Ok(Self::Semi),
            0x39 => Ok(Self::Single),
            0x3a => Ok(Self::Double),
            0x41 => Ok(Self::OctetStr),
            0x42 => Ok(Self::CharStr),
            0x43 => Ok(Self::LongOctetStr),
            0x44 => Ok(Self::LongCharStr),
            0x48 => Ok(Self::Array),
            0x4c | 0x50 | 0x51 => Ok(Self::Composite(v)),
            0xe0..=0xe2 => Ok(Self::Time(v)),
            0xe8..=0xea => Ok(Self::Id16or32(v)),
            0xf0 => Ok(Self::Eui64),
            0xf1 => Ok(Self::Key128),
            0xff => Ok(Self::Unknown),
            _ => Err(Error::UnknownDatatype(v)),
        }
    }

    /// Wire octet for this type.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::NoData => 0x00,
            Self::Data(w) => 0x08 + w - 1,
            Self::Bool => 0x10,
            Self::Map(w) => 0x18 + w - 1,
            Self::UInt(w) => 0x20 + w - 1,
            Self::Int(w) => 0x28 + w - 1,
            Self::Enum8 => 0x30,
            Self::Enum16 => 0x31,
            Self::Semi => 0x38,
            Self::Single => 0x39,
            Self::Double => 0x3a,
            Self::OctetStr => 0x41,
            Self::CharStr => 0x42,
            Self::LongOctetStr => 0x43,
            Self::LongCharStr => 0x44,
            Self::Array => 0x48,
            Self::Composite(v) | Self::Time(v) | Self::Id16or32(v) => v,
            Self::Eui64 => 0xf0,
            Self::Key128 => 0xf1,
            Self::Unknown => 0xff,
        }
    }

    /// Analog types support arithmetic/change thresholds; discrete
    /// types report on any change (Table 2-11 class column).
    ///
    /// Requirement `07-5123-08-262-02` (MINTED-pending-confirm).
    #[must_use]
    pub const fn is_analog(self) -> bool {
        matches!(
            self,
            Self::UInt(_) | Self::Int(_) | Self::Single | Self::Double | Self::Time(_)
        )
    }

    /// Fixed body length in octets, if the type has one.
    #[must_use]
    pub const fn fixed_len(self) -> Option<usize> {
        match self {
            Self::NoData | Self::Unknown => Some(0),
            Self::Data(w) | Self::Map(w) | Self::UInt(w) | Self::Int(w) => Some(w as usize),
            Self::Bool | Self::Enum8 => Some(1),
            Self::Enum16 | Self::Semi | Self::Id16or32(0xe8) | Self::Id16or32(0xe9) => Some(2),
            Self::Single | Self::Time(_) | Self::Id16or32(_) => Some(4),
            Self::Double | Self::Eui64 => Some(8),
            Self::Key128 => Some(16),
            _ => None,
        }
    }

    /// Whether this codec can carry a value of the type (composite
    /// struct/set/bag and the unknown placeholder are recognized but
    /// never coded as attribute data here).
    #[must_use]
    pub const fn is_codable(self) -> bool {
        !matches!(self, Self::Composite(_) | Self::Unknown)
    }
}

/// Owned attribute/command-field value with bounded inline storage.
///
/// Widths (`w`) count octets: 1, 2, 3, 4, 5, 6, 7, or 8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    /// No associated data.
    NoData,
    /// Opaque bytes, `w` octets significant.
    Data { width: u8, bytes: [u8; 8] },
    /// Logical value.
    Bool(bool),
    /// Bit map, `w` octets significant (little-endian).
    Map { width: u8, bytes: [u8; 8] },
    /// Unsigned integer, `w` octets significant (little-endian).
    UInt { width: u8, v: u64 },
    /// Signed integer, `w` octets significant (little-endian two's
    /// complement over the low `w` octets).
    Int { width: u8, v: i64 },
    /// 8-bit enumeration.
    Enum8(u8),
    /// 16-bit enumeration.
    Enum16(u16),
    /// Half-precision float, raw bits (discrete handling).
    Semi(u16),
    /// Single-precision float, raw bits.
    Single(u32),
    /// Double-precision float, raw bits.
    Double(u64),
    /// Octet string (`len` significant bytes).
    OctetStr { len: u8, bytes: [u8; MAX_STR_LEN] },
    /// Character string (`len` significant bytes).
    CharStr { len: u8, bytes: [u8; MAX_STR_LEN] },
    /// Long octet string (`len` significant bytes).
    LongOctetStr { len: u16, bytes: [u8; MAX_STR_LEN] },
    /// Long character string (`len` significant bytes).
    LongCharStr { len: u16, bytes: [u8; MAX_STR_LEN] },
    /// Packed array of scalar elements: element type octet, packed
    /// little-endian bodies, `count` elements.
    Array {
        elem: u8,
        count: u8,
        bytes: [u8; MAX_ARRAY_BYTES],
    },
    /// Time-of-day / date / UTC value (raw 32-bit).
    Time {
        /// Type octet (0xe0/0xe1/0xe2).
        tag: u8,
        v: u32,
    },
    /// Cluster id / attribute id (16-bit raw).
    Id16 {
        /// Type octet (0xe8/0xe9).
        tag: u8,
        v: u16,
    },
    /// BACnet object identifier (raw 32-bit).
    BacOid(u32),
    /// 64-bit IEEE address.
    Eui64([u8; 8]),
    /// 128-bit key material.
    Key128([u8; 16]),
}

impl Value {
    /// Data type this value encodes as.
    #[must_use]
    pub const fn datatype(self) -> DataType {
        match self {
            Self::NoData => DataType::NoData,
            Self::Data { width, .. } => DataType::Data(width),
            Self::Bool(_) => DataType::Bool,
            Self::Map { width, .. } => DataType::Map(width),
            Self::UInt { width, .. } => DataType::UInt(width),
            Self::Int { width, .. } => DataType::Int(width),
            Self::Enum8(_) => DataType::Enum8,
            Self::Enum16(_) => DataType::Enum16,
            Self::Semi(_) => DataType::Semi,
            Self::Single(_) => DataType::Single,
            Self::Double(_) => DataType::Double,
            Self::OctetStr { .. } => DataType::OctetStr,
            Self::CharStr { .. } => DataType::CharStr,
            Self::LongOctetStr { .. } => DataType::LongOctetStr,
            Self::LongCharStr { .. } => DataType::LongCharStr,
            Self::Array { .. } => DataType::Array,
            Self::Time { tag, .. } => DataType::Time(tag),
            Self::Id16 { tag, .. } => DataType::Id16or32(tag),
            Self::BacOid(_) => DataType::Id16or32(0xea),
            Self::Eui64(_) => DataType::Eui64,
            Self::Key128(_) => DataType::Key128,
        }
    }

    /// Default for a type with no explicit default: the type's
    /// Non-Value where one is defined, else zero.
    ///
    /// Requirement `07-5123-08-2343-01` (corpus-mined).
    #[must_use]
    pub const fn default_for(dtype: DataType) -> Option<Self> {
        match dtype {
            DataType::NoData => Some(Self::NoData),
            DataType::Data(w) => Some(Self::Data {
                width: w,
                bytes: [0; 8],
            }),
            DataType::Bool => Some(Self::Bool(false)),
            DataType::Map(w) => Some(Self::Map {
                width: w,
                bytes: [0; 8],
            }),
            DataType::UInt(w) => Some(Self::UInt {
                width: w,
                v: uint_non_value(w),
            }),
            DataType::Int(w) => Some(Self::Int {
                width: w,
                v: int_non_value(w),
            }),
            DataType::Enum8 => Some(Self::Enum8(0xff)),
            DataType::Enum16 => Some(Self::Enum16(0xffff)),
            DataType::Semi => Some(Self::Semi(0xffff)),
            DataType::Single => Some(Self::Single(0x7fc0_0000)),
            DataType::Double => Some(Self::Double(0x7ff8_0000_0000_0000)),
            DataType::OctetStr => Some(Self::OctetStr {
                len: 0,
                bytes: [0; MAX_STR_LEN],
            }),
            DataType::CharStr => Some(Self::CharStr {
                len: 0,
                bytes: [0; MAX_STR_LEN],
            }),
            DataType::LongOctetStr => Some(Self::LongOctetStr {
                len: 0,
                bytes: [0; MAX_STR_LEN],
            }),
            DataType::LongCharStr => Some(Self::LongCharStr {
                len: 0,
                bytes: [0; MAX_STR_LEN],
            }),
            DataType::Array => Some(Self::Array {
                elem: 0x00,
                count: 0,
                bytes: [0; MAX_ARRAY_BYTES],
            }),
            DataType::Time(tag) => Some(Self::Time {
                tag,
                v: 0xffff_ffff,
            }),
            DataType::Id16or32(0xea) => Some(Self::BacOid(0xffff_ffff)),
            DataType::Id16or32(tag) => Some(Self::Id16 { tag, v: 0xffff }),
            DataType::Eui64 => Some(Self::Eui64([0xff; 8])),
            DataType::Key128 => Some(Self::Key128([0; 16])),
            DataType::Composite(_) | DataType::Unknown => None,
        }
    }

    /// Encoded body length (without any type octet).
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        match self {
            Self::NoData => 0,
            Self::Data { width, .. } | Self::Map { width, .. } => width as usize,
            Self::UInt { width, .. } | Self::Int { width, .. } => width as usize,
            Self::Bool(_) | Self::Enum8(_) => 1,
            Self::Enum16(_) | Self::Semi(_) => 2,
            Self::Single(_) => 4,
            Self::Double(_) | Self::Eui64(_) => 8,
            Self::Key128(_) => 16,
            Self::OctetStr { len, .. } | Self::CharStr { len, .. } => 1 + len as usize,
            Self::LongOctetStr { len, .. } | Self::LongCharStr { len, .. } => 2 + len as usize,
            Self::Array { .. } => array_body_len(self),
            Self::Time { .. } | Self::BacOid(_) => 4,
            Self::Id16 { .. } => 2,
        }
    }

    /// Encode the body (least-significant octet first) into `out`.
    ///
    /// Requirement `07-5123-08-241-01` (corpus-mined, octet order).
    pub fn encode_into(self, out: &mut [u8]) -> Result<usize, Error> {
        // Arrays carry their own length validation (unsupported element
        // tags must report `UnsupportedType`, not `BufferTooSmall`).
        if matches!(self, Self::Array { .. }) {
            return encode_array(self, out);
        }
        let n = self.encoded_len();
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        match self {
            Self::NoData => Ok(0),
            Self::Data { width, bytes } | Self::Map { width, bytes } => {
                out[..width as usize].copy_from_slice(&bytes[..width as usize]);
                Ok(width as usize)
            }
            Self::UInt { width, v } => {
                encode_uint(v, width, out);
                Ok(width as usize)
            }
            Self::Int { width, v } => {
                encode_uint(v as u64, width, out);
                Ok(width as usize)
            }
            Self::Bool(b) => {
                out[0] = u8::from(b);
                Ok(1)
            }
            Self::Enum8(v) => {
                out[0] = v;
                Ok(1)
            }
            Self::Enum16(v) => {
                out[..2].copy_from_slice(&v.to_le_bytes());
                Ok(2)
            }
            Self::Semi(v) => {
                out[..2].copy_from_slice(&v.to_le_bytes());
                Ok(2)
            }
            Self::Single(bits) => {
                out[..4].copy_from_slice(&bits.to_le_bytes());
                Ok(4)
            }
            Self::Double(bits) => {
                out[..8].copy_from_slice(&bits.to_le_bytes());
                Ok(8)
            }
            Self::OctetStr { len, bytes } | Self::CharStr { len, bytes } => {
                out[0] = len;
                out[1..1 + len as usize].copy_from_slice(&bytes[..len as usize]);
                Ok(1 + len as usize)
            }
            Self::LongOctetStr { len, bytes } | Self::LongCharStr { len, bytes } => {
                out[..2].copy_from_slice(&len.to_le_bytes());
                out[2..2 + len as usize].copy_from_slice(&bytes[..len as usize]);
                Ok(2 + len as usize)
            }
            Self::Array { .. } => encode_array(self, out),
            Self::Time { v, .. } | Self::BacOid(v) => {
                out[..4].copy_from_slice(&v.to_le_bytes());
                Ok(4)
            }
            Self::Id16 { v, .. } => {
                out[..2].copy_from_slice(&v.to_le_bytes());
                Ok(2)
            }
            Self::Eui64(b) => {
                out[..8].copy_from_slice(&b);
                Ok(8)
            }
            Self::Key128(b) => {
                out[..16].copy_from_slice(&b);
                Ok(16)
            }
        }
    }

    /// Decode a body of wire type `dtype` from the front of `buf`,
    /// returning the value and consumed length.
    pub fn decode(dtype: DataType, buf: &[u8]) -> Result<(Self, usize), Error> {
        if !dtype.is_codable() {
            return Err(Error::UnsupportedType(dtype.as_u8()));
        }
        if let Some(fixed) = dtype.fixed_len() {
            if buf.len() < fixed {
                return Err(Error::Truncated);
            }
        }
        match dtype {
            DataType::NoData | DataType::Unknown | DataType::Composite(_) => {
                Err(Error::UnsupportedType(dtype.as_u8()))
            }
            DataType::Data(w) => {
                let mut bytes = [0u8; 8];
                bytes[..w as usize].copy_from_slice(&buf[..w as usize]);
                Ok((Self::Data { width: w, bytes }, w as usize))
            }
            DataType::Bool => match buf[0] {
                // Only FALSE/TRUE plus the Non-Value travel; anything
                // else is a malformed field.
                0x00 => Ok((Self::Bool(false), 1)),
                0x01 => Ok((Self::Bool(true), 1)),
                v => Err(Error::InvalidValue(v)),
            },
            DataType::Map(w) => {
                let mut bytes = [0u8; 8];
                bytes[..w as usize].copy_from_slice(&buf[..w as usize]);
                Ok((Self::Map { width: w, bytes }, w as usize))
            }
            DataType::UInt(w) => Ok((
                Self::UInt {
                    width: w,
                    v: decode_uint(&buf[..w as usize]),
                },
                w as usize,
            )),
            DataType::Int(w) => Ok((
                Self::Int {
                    width: w,
                    v: decode_int(&buf[..w as usize]),
                },
                w as usize,
            )),
            DataType::Enum8 => Ok((Self::Enum8(buf[0]), 1)),
            DataType::Enum16 => Ok((Self::Enum16(u16::from_le_bytes([buf[0], buf[1]])), 2)),
            DataType::Semi => Ok((Self::Semi(u16::from_le_bytes([buf[0], buf[1]])), 2)),
            DataType::Single => Ok((
                Self::Single(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])),
                4,
            )),
            DataType::Double => Ok((
                Self::Double(u64::from_le_bytes([
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                ])),
                8,
            )),
            DataType::OctetStr | DataType::CharStr => {
                if buf.is_empty() {
                    return Err(Error::Truncated);
                }
                let len = buf[0];
                if len == 0xff {
                    return Err(Error::InvalidValue(len));
                }
                if len as usize > MAX_STR_LEN || buf.len() < 1 + len as usize {
                    return Err(if (len as usize) > MAX_STR_LEN {
                        Error::StringTooLong
                    } else {
                        Error::Truncated
                    });
                }
                let mut bytes = [0u8; MAX_STR_LEN];
                bytes[..len as usize].copy_from_slice(&buf[1..1 + len as usize]);
                let v = if dtype == DataType::OctetStr {
                    Self::OctetStr { len, bytes }
                } else {
                    Self::CharStr { len, bytes }
                };
                Ok((v, 1 + len as usize))
            }
            DataType::LongOctetStr | DataType::LongCharStr => {
                if buf.len() < 2 {
                    return Err(Error::Truncated);
                }
                let len = u16::from_le_bytes([buf[0], buf[1]]);
                if len == 0xffff {
                    return Err(Error::InvalidValue(0xff));
                }
                if len as usize > MAX_STR_LEN || buf.len() < 2 + len as usize {
                    return Err(if (len as usize) > MAX_STR_LEN {
                        Error::StringTooLong
                    } else {
                        Error::Truncated
                    });
                }
                let mut bytes = [0u8; MAX_STR_LEN];
                bytes[..len as usize].copy_from_slice(&buf[2..2 + len as usize]);
                let v = if dtype == DataType::LongOctetStr {
                    Self::LongOctetStr { len, bytes }
                } else {
                    Self::LongCharStr { len, bytes }
                };
                Ok((v, 2 + len as usize))
            }
            DataType::Array => decode_array(buf),
            DataType::Time(tag) => Ok((
                Self::Time {
                    tag,
                    v: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
                },
                4,
            )),
            DataType::Id16or32(0xea) => Ok((
                Self::BacOid(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])),
                4,
            )),
            DataType::Id16or32(tag) => Ok((
                Self::Id16 {
                    tag,
                    v: u16::from_le_bytes([buf[0], buf[1]]),
                },
                2,
            )),
            DataType::Eui64 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&buf[..8]);
                Ok((Self::Eui64(b), 8))
            }
            DataType::Key128 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&buf[..16]);
                Ok((Self::Key128(b), 16))
            }
        }
    }
}

/// All-ones Non-Value masked to `width` octets (unsigned classes).
const fn uint_non_value(width: u8) -> u64 {
    match width {
        1 => 0xff,
        2 => 0xffff,
        3 => 0xff_ffff,
        4 => 0xffff_ffff,
        5 => 0xff_ffff_ffff,
        6 => 0xffff_ffff_ffff,
        7 => 0xff_ffff_ffff_ffff,
        _ => 0xffff_ffff_ffff_ffff,
    }
}

/// High-bit-only Non-Value sign-extended over `width` octets.
const fn int_non_value(width: u8) -> i64 {
    let raw = 1u64 << (width as u32 * 8 - 1);
    let shift = 64 - width as u32 * 8;
    (raw << shift) as i64 >> shift
}

const fn encode_uint(mut v: u64, width: u8, out: &mut [u8]) {
    let mut i = 0;
    while i < width {
        out[i as usize] = (v & 0xff) as u8;
        v >>= 8;
        i += 1;
    }
}

const fn decode_uint(buf: &[u8]) -> u64 {
    let mut v = 0u64;
    let mut i = buf.len();
    while i > 0 {
        i -= 1;
        v = (v << 8) | buf[i] as u64;
    }
    v
}

/// Sign-extend the low `buf.len()` octets to a full `i64`.
const fn decode_int(buf: &[u8]) -> i64 {
    let raw = decode_uint(buf);
    let shift = 64 - buf.len() as u32 * 8;
    (raw << shift) as i64 >> shift
}

/// Wire body length of a scalar element tag (`usize::MAX` when the
/// tag is variable-length or unsupported here).
const fn scalar_len_of_tag(tag: u8) -> usize {
    match tag {
        0x08..=0x0f => (tag - 0x08 + 1) as usize,
        0x10 | 0x30 => 1,
        0x18..=0x1f => (tag - 0x18 + 1) as usize,
        0x20..=0x27 => (tag - 0x20 + 1) as usize,
        0x28..=0x2f => (tag - 0x28 + 1) as usize,
        0x31 | 0x38 | 0xe8 | 0xe9 => 2,
        0x39 | 0xe0 | 0xe1 | 0xe2 | 0xea => 4,
        0x3a | 0xf0 => 8,
        0xf1 => 16,
        _ => usize::MAX,
    }
}

const fn array_body_len(v: Value) -> usize {
    match v {
        Value::Array { elem, count, .. } => {
            let each = scalar_len_of_tag(elem);
            if each == usize::MAX {
                usize::MAX
            } else {
                3 + count as usize * each
            }
        }
        _ => 0,
    }
}

/// Element body length for scalar array element types.
fn scalar_elem_len(elem: DataType) -> Option<usize> {
    match elem {
        DataType::NoData | DataType::Unknown | DataType::Composite(_) => None,
        DataType::Array => None,
        DataType::OctetStr | DataType::CharStr | DataType::LongOctetStr | DataType::LongCharStr => {
            None
        }
        t => t.fixed_len(),
    }
}

fn encode_array(v: Value, out: &mut [u8]) -> Result<usize, Error> {
    let (elem_tag, count, bytes) = match v {
        Value::Array { elem, count, bytes } => (elem, count, bytes),
        _ => return Err(Error::TypeMismatch),
    };
    let elem = DataType::from_u8(elem_tag)?;
    let each = scalar_elem_len(elem).ok_or(Error::UnsupportedType(elem_tag))?;
    let body = count as usize * each;
    if body > MAX_ARRAY_BYTES {
        return Err(Error::ArrayTooLong);
    }
    let total = 3 + body;
    if out.len() < total {
        return Err(Error::BufferTooSmall);
    }
    out[0] = elem_tag;
    out[1..3].copy_from_slice(&(count as u16).to_le_bytes());
    out[3..total].copy_from_slice(&bytes[..count as usize * each]);
    Ok(total)
}

fn decode_array(buf: &[u8]) -> Result<(Value, usize), Error> {
    if buf.len() < 3 {
        return Err(Error::Truncated);
    }
    let elem = DataType::from_u8(buf[0])?;
    let count = u16::from_le_bytes([buf[1], buf[2]]);
    if count == 0xffff {
        // Array Non-Value: undefined array, carried as empty + marker.
        // This codec has no undefined marker, so reject explicitly.
        return Err(Error::InvalidValue(0xff));
    }
    let each = scalar_elem_len(elem).ok_or(Error::UnsupportedType(buf[0]))?;
    if count as usize > MAX_ARRAY_ELEMS {
        return Err(Error::ArrayTooLong);
    }
    let total = 3 + count as usize * each;
    if total - 3 > MAX_ARRAY_BYTES || buf.len() < total {
        return Err(if total - 3 > MAX_ARRAY_BYTES {
            Error::ArrayTooLong
        } else {
            Error::Truncated
        });
    }
    let mut bytes = [0u8; MAX_ARRAY_BYTES];
    bytes[..count as usize * each].copy_from_slice(&buf[3..total]);
    // Validate each packed scalar body parses (bool fields, …).
    let mut off = 0;
    let mut i = 0;
    while i < count as usize {
        let (elem_v, used) = Value::decode(elem, &bytes[off..off + each])?;
        let _ = elem_v;
        debug_assert_eq!(used, each);
        off += each;
        i += 1;
    }
    #[allow(clippy::cast_possible_truncation)]
    let count_u8 = count as u8;
    Ok((
        Value::Array {
            elem: buf[0],
            count: count_u8,
            bytes,
        },
        total,
    ))
}
