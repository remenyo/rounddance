//! ZDP request/response frame codecs: discovery, descriptors, bind.
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2 §2.4.3.1 (discovery
//! client services; `NWK_addr_req` Table 2-44 anchor p0127-L3098-L3099,
//! `Node_Desc_req` Table 2-46 anchor p0130-L3170-L3171, `Power_Desc_req`
//! Table 2-47 anchor p0131-L3190-L3191 plus When Generated unicast rule
//! anchor p0131-L3192-L3198, `Simple_Desc_req` §2.4.3.1.5 Table 2-48
//! anchor p0131-L3202-L3206, `Active_EP_req` §2.4.3.1.6 Table 2-49
//! anchor p0132-L3218-L3222, `Match_Desc_req` §2.4.3.1.7 Table 2-50
//! anchor p0132-L3233-L3238, `Device_annce` §2.4.3.1.11 Table 2-51
//! anchor p0134-L3263-L3267), §2.4.3.2 (binding: `Bind_req` §2.4.3.2.2
//! anchor p0138-L3388, `Unbind_req` Table 2-56 anchor p0140-L3408-L3409)
//! and §2.4.4.2 (server responses: `NWK_addr_rsp` §2.4.4.2.1 anchor
//! p0174-L4273-L4274, `IEEE_addr_rsp` §2.4.4.2.2 anchor p0177-L4288,
//! `Node_Desc_rsp` §2.4.4.2.3 anchor p0178-L4303-L4331). All wording
//! here is paraphrase (D1, `SCOPE.md` §2).
//!
//! Frame shape shared by every command here: the first octet is the
//! transaction sequence number; responses add a status octet next and
//! echo the request sequence. Response clusters are the request
//! cluster with [`crate::cluster::RESPONSE_BIT`] set.
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped), MINTED-pending-confirm.

use crate::desc::{Error, NodeDescriptor, PowerDescriptor, SimpleDescriptor, MAX_SIMPLE_CLUSTERS};
use crate::status::ZdpStatus;

/// Address-discovery request flavour: one answer or the extended
/// paged list (Tables 2-44/2-45 pattern).
///
/// Requirement `05-3474-23-24311-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestType {
    /// Single response for the interest address.
    Single,
    /// Extended response starting at `start_index`.
    Extended {
        /// First list entry to report.
        start_index: u8,
    },
}

impl RequestType {
    /// Decode the type octet plus optional start index.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.is_empty() {
            return Err(Error::Truncated);
        }
        match buf[0] {
            0x00 => Ok(Self::Single),
            0x01 => {
                if buf.len() < 2 {
                    return Err(Error::Truncated);
                }
                Ok(Self::Extended {
                    start_index: buf[1],
                })
            }
            v => Err(Error::InvalidValue(v)),
        }
    }

    /// Encoded length: 1 for single, 2 for extended.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        match self {
            Self::Single => 1,
            Self::Extended { .. } => 2,
        }
    }

    /// Encode into `out`.
    pub fn encode_into(self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < self.encoded_len() {
            return Err(Error::BufferTooSmall);
        }
        match self {
            Self::Single => {
                out[0] = 0x00;
                Ok(1)
            }
            Self::Extended { start_index } => {
                out[0] = 0x01;
                out[1] = start_index;
                Ok(2)
            }
        }
    }
}

/// Bound on associated-device entries carried in one extended address
/// response (declared budget; longer over-air lists are rejected with
/// [`Error::TooManyEntries`]).
///
/// Requirement `05-3474-23-24421-01` (MINTED-pending-confirm).
pub const MAX_ASSOC_DEVICES: usize = 16;

/// `NWK_addr_req`: resolve a long address to its network address
/// (Table 2-44, anchor p0127-L3098-L3099).
///
/// Requirement `05-3474-23-24311-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NwkAddrReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// Long address whose network address is wanted.
    pub ieee_of_interest: u64,
    /// Single or extended (paged) answer.
    pub req_type: RequestType,
}

impl NwkAddrReq {
    /// Shortest wire length (single flavour).
    pub const MIN_LEN: usize = 10;

    /// Decode a request frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        match RequestType::decode(&buf[9..]) {
            Ok(req_type) => Ok(Self {
                tsn: buf[0],
                ieee_of_interest: u64::from_le_bytes([
                    buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
                ]),
                req_type,
            }),
            Err(e) => Err(e),
        }
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = 9 + self.req_type.encoded_len();
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        let ieee = self.ieee_of_interest.to_le_bytes();
        out[1] = ieee[0];
        out[2] = ieee[1];
        out[3] = ieee[2];
        out[4] = ieee[3];
        out[5] = ieee[4];
        out[6] = ieee[5];
        out[7] = ieee[6];
        out[8] = ieee[7];
        // `split_mut` is not const; write through an offset instead.
        match self.req_type {
            RequestType::Single => {
                out[9] = 0x00;
                Ok(10)
            }
            RequestType::Extended { start_index } => {
                out[9] = 0x01;
                out[10] = start_index;
                Ok(11)
            }
        }
    }
}

/// `NWK_addr_rsp`: answer to [`NwkAddrReq`] (§2.4.4.2.1, anchor
/// p0174-L4273-L4274).
///
/// Requirement `05-3474-23-24421-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NwkAddrRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the lookup.
    pub status: ZdpStatus,
    /// Long address from the request.
    pub ieee: u64,
    /// Network address found.
    pub nwk_addr: u16,
    /// Associated devices, valid when `extended` is set (first
    /// `assoc_len` entries).
    pub assoc: [u16; MAX_ASSOC_DEVICES],
    /// How many associated entries are present.
    pub assoc_len: u8,
    /// Start index echoed for the extended flavour.
    pub start_index: u8,
    /// Whether the extended trailing list is present.
    pub extended: bool,
}

impl NwkAddrRsp {
    /// Shortest wire length (single flavour, success or not).
    pub const MIN_LEN: usize = 12;

    /// Decode a response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let mut rsp = Self {
            tsn: buf[0],
            status: ZdpStatus::from_code(buf[1]),
            ieee: u64::from_le_bytes([
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            ]),
            nwk_addr: u16::from_le_bytes([buf[10], buf[11]]),
            assoc: [0; MAX_ASSOC_DEVICES],
            assoc_len: 0,
            start_index: 0,
            extended: false,
        };
        if buf.len() == Self::MIN_LEN {
            return Ok(rsp);
        }
        // Extended flavour: count + start index + list.
        if buf.len() < Self::MIN_LEN + 2 {
            return Err(Error::Truncated);
        }
        let count = buf[12] as usize;
        if count > MAX_ASSOC_DEVICES {
            return Err(Error::TooManyEntries);
        }
        if buf.len() < Self::MIN_LEN + 2 + 2 * count {
            return Err(Error::Truncated);
        }
        rsp.start_index = buf[13];
        rsp.extended = true;
        rsp.assoc_len = count as u8;
        let mut i = 0;
        while i < count {
            rsp.assoc[i] = u16::from_le_bytes([buf[14 + 2 * i], buf[14 + 2 * i + 1]]);
            i += 1;
        }
        Ok(rsp)
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let count = self.assoc_len as usize;
        if count > MAX_ASSOC_DEVICES {
            return Err(Error::TooManyEntries);
        }
        let n = if self.extended {
            Self::MIN_LEN + 2 + 2 * count
        } else {
            Self::MIN_LEN
        };
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        let ieee = self.ieee.to_le_bytes();
        out[2] = ieee[0];
        out[3] = ieee[1];
        out[4] = ieee[2];
        out[5] = ieee[3];
        out[6] = ieee[4];
        out[7] = ieee[5];
        out[8] = ieee[6];
        out[9] = ieee[7];
        let nwk = self.nwk_addr.to_le_bytes();
        out[10] = nwk[0];
        out[11] = nwk[1];
        if self.extended {
            out[12] = self.assoc_len;
            out[13] = self.start_index;
            let mut i = 0;
            while i < count {
                let addr = self.assoc[i].to_le_bytes();
                out[14 + 2 * i] = addr[0];
                out[14 + 2 * i + 1] = addr[1];
                i += 1;
            }
        }
        Ok(n)
    }
}

/// `IEEE_addr_req`: resolve a network address to its long address
/// (Table 2-43; mirrored layout to [`NwkAddrReq`]).
///
/// Requirement `05-3474-23-24311-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IeeeAddrReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// Network address whose long address is wanted.
    pub nwk_of_interest: u16,
    /// Single or extended (paged) answer.
    pub req_type: RequestType,
}

impl IeeeAddrReq {
    /// Shortest wire length (single flavour).
    pub const MIN_LEN: usize = 4;

    /// Decode a request frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        match RequestType::decode(&buf[3..]) {
            Ok(req_type) => Ok(Self {
                tsn: buf[0],
                nwk_of_interest: u16::from_le_bytes([buf[1], buf[2]]),
                req_type,
            }),
            Err(e) => Err(e),
        }
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = 3 + self.req_type.encoded_len();
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        let nwk = self.nwk_of_interest.to_le_bytes();
        out[1] = nwk[0];
        out[2] = nwk[1];
        match self.req_type {
            RequestType::Single => {
                out[3] = 0x00;
                Ok(4)
            }
            RequestType::Extended { start_index } => {
                out[3] = 0x01;
                out[4] = start_index;
                Ok(5)
            }
        }
    }
}

/// `IEEE_addr_rsp`: answer to [`IeeeAddrReq`] (§2.4.4.2.2, anchor
/// p0177-L4288).
///
/// Requirement `05-3474-23-24422-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IeeeAddrRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the lookup.
    pub status: ZdpStatus,
    /// Long address found.
    pub ieee: u64,
    /// Network address from the request.
    pub nwk_addr: u16,
    /// Associated long addresses, first `assoc_len` entries valid.
    pub assoc: [u64; MAX_ASSOC_DEVICES],
    /// How many associated entries are present.
    pub assoc_len: u8,
    /// Start index echoed for the extended flavour.
    pub start_index: u8,
    /// Whether the extended trailing list is present.
    pub extended: bool,
}

impl IeeeAddrRsp {
    /// Shortest wire length (single flavour).
    pub const MIN_LEN: usize = 12;

    /// Decode a response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let mut rsp = Self {
            tsn: buf[0],
            status: ZdpStatus::from_code(buf[1]),
            ieee: u64::from_le_bytes([
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            ]),
            nwk_addr: u16::from_le_bytes([buf[10], buf[11]]),
            assoc: [0; MAX_ASSOC_DEVICES],
            assoc_len: 0,
            start_index: 0,
            extended: false,
        };
        if buf.len() == Self::MIN_LEN {
            return Ok(rsp);
        }
        if buf.len() < Self::MIN_LEN + 2 {
            return Err(Error::Truncated);
        }
        let count = buf[12] as usize;
        if count > MAX_ASSOC_DEVICES {
            return Err(Error::TooManyEntries);
        }
        if buf.len() < Self::MIN_LEN + 2 + 8 * count {
            return Err(Error::Truncated);
        }
        rsp.start_index = buf[13];
        rsp.extended = true;
        rsp.assoc_len = count as u8;
        for (i, slot) in rsp.assoc.iter_mut().take(count).enumerate() {
            let base = 14 + 8 * i;
            *slot = u64::from_le_bytes([
                buf[base],
                buf[base + 1],
                buf[base + 2],
                buf[base + 3],
                buf[base + 4],
                buf[base + 5],
                buf[base + 6],
                buf[base + 7],
            ]);
        }
        Ok(rsp)
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let count = self.assoc_len as usize;
        if count > MAX_ASSOC_DEVICES {
            return Err(Error::TooManyEntries);
        }
        let n = if self.extended {
            Self::MIN_LEN + 2 + 8 * count
        } else {
            Self::MIN_LEN
        };
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        let ieee = self.ieee.to_le_bytes();
        out[2..10].copy_from_slice(&ieee);
        let nwk = self.nwk_addr.to_le_bytes();
        out[10] = nwk[0];
        out[11] = nwk[1];
        if self.extended {
            out[12] = self.assoc_len;
            out[13] = self.start_index;
            for (i, addr) in self.assoc.iter().take(count).enumerate() {
                let bytes = addr.to_le_bytes();
                out[14 + 8 * i..14 + 8 * i + 8].copy_from_slice(&bytes);
            }
        }
        Ok(n)
    }
}

/// `Node_Desc_req`: ask for the node descriptor of one network address
/// (Table 2-46, anchor p0130-L3170-L3171).
///
/// Requirement `05-3474-23-24311-03` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeDescReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// Network address whose descriptor is wanted.
    pub nwk_of_interest: u16,
}

impl NodeDescReq {
    /// Wire length.
    pub const LEN: usize = 3;

    /// Decode a request frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            nwk_of_interest: u16::from_le_bytes([buf[1], buf[2]]),
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        let nwk = self.nwk_of_interest.to_le_bytes();
        out[1] = nwk[0];
        out[2] = nwk[1];
        Ok(Self::LEN)
    }
}

/// `Node_Desc_rsp`: answer to [`NodeDescReq`] (§2.4.4.2.3, anchor
/// p0178-L4303-L4331). The node descriptor is present only on success;
/// trailing R23 TLV octets (e.g. the fragmentation-parameters TLV of
/// `05-3474-23-22411-14`) are carried as borrowed `tlvs`, never
/// rejected.
///
/// Requirement `05-3474-23-24423-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeDescRsp<'a> {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the inquiry.
    pub status: ZdpStatus,
    /// Network address from the request.
    pub nwk_of_interest: u16,
    /// Descriptor, present exactly when `status` is success.
    pub descriptor: Option<NodeDescriptor>,
    /// Trailing TLV octets after the descriptor.
    pub tlvs: &'a [u8],
}

impl<'a> NodeDescRsp<'a> {
    /// Shortest wire length (non-success: no descriptor).
    pub const MIN_LEN: usize = 4;

    /// Decode a response frame.
    pub fn decode(buf: &'a [u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let status = ZdpStatus::from_code(buf[1]);
        let rsp = Self {
            tsn: buf[0],
            status,
            nwk_of_interest: u16::from_le_bytes([buf[2], buf[3]]),
            descriptor: None,
            tlvs: &[],
        };
        if !status.is_success() {
            return Ok(rsp);
        }
        let descriptor = NodeDescriptor::decode(&buf[4..])?;
        let rest = &buf[4 + crate::desc::NODE_DESCRIPTOR_LEN..];
        Ok(Self {
            descriptor: Some(descriptor),
            tlvs: rest,
            ..rsp
        })
    }

    /// Encoded length of this value.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        Self::MIN_LEN
            + self
                .descriptor
                .map_or(0, |_| crate::desc::NODE_DESCRIPTOR_LEN)
            + self.tlvs.len()
    }

    /// Encode into `out` (descriptor first, then the TLV octets).
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len();
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        let nwk = self.nwk_of_interest.to_le_bytes();
        out[2] = nwk[0];
        out[3] = nwk[1];
        if let Some(descriptor) = self.descriptor {
            descriptor.encode_into(&mut out[4..])?;
            out[4 + crate::desc::NODE_DESCRIPTOR_LEN..n].copy_from_slice(self.tlvs);
        }
        Ok(n)
    }
}

/// `Power_Desc_req`: ask for the power descriptor of one network
/// address (Table 2-47, anchor p0131-L3190-L3191; unicast to the device
/// itself or its discovery cache, §2.4.3.1.4.1 anchor p0131-L3192-L3198).
///
/// Requirement `05-3474-23-24311-04` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerDescReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// Network address whose descriptor is wanted.
    pub nwk_of_interest: u16,
}

impl PowerDescReq {
    /// Wire length.
    pub const LEN: usize = 3;

    /// Decode a request frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            nwk_of_interest: u16::from_le_bytes([buf[1], buf[2]]),
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        let nwk = self.nwk_of_interest.to_le_bytes();
        out[1] = nwk[0];
        out[2] = nwk[1];
        Ok(Self::LEN)
    }
}

/// `Power_Desc_rsp`: answer to [`PowerDescReq`] (§2.4.4.2.4, cited by
/// the When Generated rule, anchor p0131-L3199-L3201). The power
/// descriptor is present only on success.
///
/// Requirement `05-3474-23-24424-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerDescRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the inquiry.
    pub status: ZdpStatus,
    /// Network address from the request.
    pub nwk_of_interest: u16,
    /// Descriptor, present exactly when `status` is success.
    pub descriptor: Option<PowerDescriptor>,
}

impl PowerDescRsp {
    /// Shortest wire length (non-success: no descriptor).
    pub const MIN_LEN: usize = 4;

    /// Decode a response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let status = ZdpStatus::from_code(buf[1]);
        if !status.is_success() {
            return Ok(Self {
                tsn: buf[0],
                status,
                nwk_of_interest: u16::from_le_bytes([buf[2], buf[3]]),
                descriptor: None,
            });
        }
        Ok(Self {
            tsn: buf[0],
            status,
            nwk_of_interest: u16::from_le_bytes([buf[2], buf[3]]),
            descriptor: Some(PowerDescriptor::decode(&buf[4..])?),
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = Self::MIN_LEN
            + self
                .descriptor
                .map_or(0, |_| crate::desc::POWER_DESCRIPTOR_LEN);
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        let nwk = self.nwk_of_interest.to_le_bytes();
        out[2] = nwk[0];
        out[3] = nwk[1];
        if let Some(descriptor) = self.descriptor {
            descriptor.encode_into(&mut out[4..])?;
        }
        Ok(n)
    }
}

/// `Simple_Desc_req`: ask for one endpoint's simple descriptor
/// (§2.4.3.1.5, Table 2-48, anchor p0131-L3202-L3206).
///
/// Requirement `05-3474-23-24311-05` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimpleDescReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// Network address holding the endpoint.
    pub nwk_of_interest: u16,
    /// Endpoint of interest (1–254).
    pub endpoint: u8,
}

impl SimpleDescReq {
    /// Wire length.
    pub const LEN: usize = 4;

    /// Decode a request frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            nwk_of_interest: u16::from_le_bytes([buf[1], buf[2]]),
            endpoint: buf[3],
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        let nwk = self.nwk_of_interest.to_le_bytes();
        out[1] = nwk[0];
        out[2] = nwk[1];
        out[3] = self.endpoint;
        Ok(Self::LEN)
    }
}

/// `Simple_Desc_rsp`: answer to [`SimpleDescReq`]. Carries a length
/// octet before the descriptor; the descriptor is present only on
/// success.
///
/// Requirement `05-3474-23-24425-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimpleDescRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the inquiry.
    pub status: ZdpStatus,
    /// Network address from the request.
    pub nwk_of_interest: u16,
    /// Descriptor, present exactly when `status` is success.
    pub descriptor: Option<SimpleDescriptor>,
}

impl SimpleDescRsp {
    /// Shortest wire length (non-success: no length octet).
    pub const MIN_LEN: usize = 4;

    /// Decode a response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let status = ZdpStatus::from_code(buf[1]);
        let head = Self {
            tsn: buf[0],
            status,
            nwk_of_interest: u16::from_le_bytes([buf[2], buf[3]]),
            descriptor: None,
        };
        if !status.is_success() {
            return Ok(head);
        }
        if buf.len() < Self::MIN_LEN + 1 {
            return Err(Error::Truncated);
        }
        let len = buf[4] as usize;
        if buf.len() < Self::MIN_LEN + 1 + len {
            return Err(Error::Truncated);
        }
        let descriptor = SimpleDescriptor::decode(&buf[5..5 + len])?;
        Ok(Self {
            descriptor: Some(descriptor),
            ..head
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let body = self.descriptor.map_or(0, |d| d.encoded_len());
        let n = Self::MIN_LEN
            + if self.descriptor.is_some() {
                1 + body
            } else {
                0
            };
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        let nwk = self.nwk_of_interest.to_le_bytes();
        out[2] = nwk[0];
        out[3] = nwk[1];
        if let Some(descriptor) = self.descriptor {
            out[4] = body as u8;
            descriptor.encode_into(&mut out[5..])?;
        }
        Ok(n)
    }
}

/// `Active_EP_req`: ask for the endpoint list of one network address
/// (§2.4.3.1.6, Table 2-49, anchor p0132-L3218-L3222).
///
/// Requirement `05-3474-23-24311-06` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActiveEpReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// Network address whose endpoints are wanted.
    pub nwk_of_interest: u16,
}

impl ActiveEpReq {
    /// Wire length.
    pub const LEN: usize = 3;

    /// Decode a request frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            nwk_of_interest: u16::from_le_bytes([buf[1], buf[2]]),
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        let nwk = self.nwk_of_interest.to_le_bytes();
        out[1] = nwk[0];
        out[2] = nwk[1];
        Ok(Self::LEN)
    }
}

/// Bound on endpoints carried in one active-endpoint or match response
/// (declared budget).
///
/// Requirement `05-3474-23-24426-01` (MINTED-pending-confirm).
pub const MAX_EP_LIST: usize = 32;

/// `Active_EP_rsp`: answer to [`ActiveEpReq`]. The endpoint list is
/// present only on success.
///
/// Requirement `05-3474-23-24426-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActiveEpRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the inquiry.
    pub status: ZdpStatus,
    /// Network address from the request.
    pub nwk_of_interest: u16,
    /// Endpoints, first `ep_len` entries valid (present on success).
    pub endpoints: [u8; MAX_EP_LIST],
    /// How many endpoints are present.
    pub ep_len: u8,
}

impl ActiveEpRsp {
    /// Shortest wire length (non-success: no count octet).
    pub const MIN_LEN: usize = 4;

    /// Decode a response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let mut rsp = Self {
            tsn: buf[0],
            status: ZdpStatus::from_code(buf[1]),
            nwk_of_interest: u16::from_le_bytes([buf[2], buf[3]]),
            endpoints: [0; MAX_EP_LIST],
            ep_len: 0,
        };
        if !rsp.status.is_success() {
            return Ok(rsp);
        }
        if buf.len() < Self::MIN_LEN + 1 {
            return Err(Error::Truncated);
        }
        let count = buf[4] as usize;
        if count > MAX_EP_LIST {
            return Err(Error::TooManyEntries);
        }
        if buf.len() < Self::MIN_LEN + 1 + count {
            return Err(Error::Truncated);
        }
        rsp.ep_len = count as u8;
        rsp.endpoints[..count].copy_from_slice(&buf[5..5 + count]);
        Ok(rsp)
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let count = self.ep_len as usize;
        if count > MAX_EP_LIST {
            return Err(Error::TooManyEntries);
        }
        let success = self.status.is_success();
        let n = Self::MIN_LEN + if success { 1 + count } else { 0 };
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        let nwk = self.nwk_of_interest.to_le_bytes();
        out[2] = nwk[0];
        out[3] = nwk[1];
        if success {
            out[4] = self.ep_len;
            out[5..5 + count].copy_from_slice(&self.endpoints[..count]);
        }
        Ok(n)
    }

    /// Endpoint list as a slice.
    #[must_use]
    pub fn ep_list(&self) -> &[u8] {
        &self.endpoints[..self.ep_len as usize]
    }
}

/// `Match_Desc_req`: find endpoints speaking a profile plus cluster
/// lists (§2.4.3.1.7, Table 2-50, anchor p0132-L3233-L3238).
///
/// Requirement `05-3474-23-24311-07` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchDescReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// Network address to search (broadcast reaches many devices).
    pub nwk_of_interest: u16,
    /// Application profile to match.
    pub profile_id: u16,
    /// Wanted input clusters, first `in_len` entries valid.
    pub in_clusters: [u16; MAX_SIMPLE_CLUSTERS],
    /// How many input clusters are named.
    pub in_len: u8,
    /// Wanted output clusters, first `out_len` entries valid.
    pub out_clusters: [u16; MAX_SIMPLE_CLUSTERS],
    /// How many output clusters are named.
    pub out_len: u8,
}

impl MatchDescReq {
    /// Shortest wire length (both lists empty).
    pub const MIN_LEN: usize = 7;

    /// Decode a request frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let in_len = buf[5] as usize;
        if in_len > MAX_SIMPLE_CLUSTERS {
            return Err(Error::TooManyEntries);
        }
        let mut pos = 6 + 2 * in_len;
        if buf.len() < pos + 1 {
            return Err(Error::Truncated);
        }
        let out_len = buf[pos] as usize;
        if out_len > MAX_SIMPLE_CLUSTERS {
            return Err(Error::TooManyEntries);
        }
        pos += 1;
        if buf.len() < pos + 2 * out_len {
            return Err(Error::Truncated);
        }
        let mut req = Self {
            tsn: buf[0],
            nwk_of_interest: u16::from_le_bytes([buf[1], buf[2]]),
            profile_id: u16::from_le_bytes([buf[3], buf[4]]),
            in_clusters: [0; MAX_SIMPLE_CLUSTERS],
            in_len: in_len as u8,
            out_clusters: [0; MAX_SIMPLE_CLUSTERS],
            out_len: out_len as u8,
        };
        for (i, slot) in req.in_clusters.iter_mut().take(in_len).enumerate() {
            *slot = u16::from_le_bytes([buf[6 + 2 * i], buf[6 + 2 * i + 1]]);
        }
        let base = 6 + 2 * in_len + 1;
        for (i, slot) in req.out_clusters.iter_mut().take(out_len).enumerate() {
            *slot = u16::from_le_bytes([buf[base + 2 * i], buf[base + 2 * i + 1]]);
        }
        Ok(req)
    }

    /// Encoded length of this value.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        Self::MIN_LEN + 2 * self.in_len as usize + 2 * self.out_len as usize
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let in_len = self.in_len as usize;
        let out_len = self.out_len as usize;
        if in_len > MAX_SIMPLE_CLUSTERS || out_len > MAX_SIMPLE_CLUSTERS {
            return Err(Error::TooManyEntries);
        }
        let n = self.encoded_len();
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        let nwk = self.nwk_of_interest.to_le_bytes();
        out[1] = nwk[0];
        out[2] = nwk[1];
        let profile = self.profile_id.to_le_bytes();
        out[3] = profile[0];
        out[4] = profile[1];
        out[5] = self.in_len;
        for (i, cluster) in self.in_clusters.iter().take(in_len).enumerate() {
            let bytes = cluster.to_le_bytes();
            out[6 + 2 * i] = bytes[0];
            out[6 + 2 * i + 1] = bytes[1];
        }
        let base = 6 + 2 * in_len;
        out[base] = self.out_len;
        for (i, cluster) in self.out_clusters.iter().take(out_len).enumerate() {
            let bytes = cluster.to_le_bytes();
            out[base + 1 + 2 * i] = bytes[0];
            out[base + 1 + 2 * i + 1] = bytes[1];
        }
        Ok(n)
    }
}

/// `Match_Desc_rsp`: endpoints that matched [`MatchDescReq`]. The
/// endpoint list is present only on success.
///
/// Requirement `05-3474-23-24427-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchDescRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the search.
    pub status: ZdpStatus,
    /// Network address from the request.
    pub nwk_of_interest: u16,
    /// Matching endpoints, first `ep_len` entries valid.
    pub endpoints: [u8; MAX_EP_LIST],
    /// How many endpoints matched.
    pub ep_len: u8,
}

impl MatchDescRsp {
    /// Shortest wire length (non-success: no count octet).
    pub const MIN_LEN: usize = 4;

    /// Decode a response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let inner = ActiveEpRsp::decode(buf)?;
        Ok(Self {
            tsn: inner.tsn,
            status: inner.status,
            nwk_of_interest: inner.nwk_of_interest,
            endpoints: inner.endpoints,
            ep_len: inner.ep_len,
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        ActiveEpRsp {
            tsn: self.tsn,
            status: self.status,
            nwk_of_interest: self.nwk_of_interest,
            endpoints: self.endpoints,
            ep_len: self.ep_len,
        }
        .encode_into(out)
    }

    /// Matching endpoints as a slice.
    #[must_use]
    pub fn ep_list(&self) -> &[u8] {
        &self.endpoints[..self.ep_len as usize]
    }
}

/// `Device_annce`: a device announces its arrival (network address,
/// long address, capability) with no response expected
/// (§2.4.3.1.11, Table 2-51, anchor p0134-L3263-L3267).
///
/// Requirement `05-3474-23-24311-11` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceAnnce {
    /// Transaction sequence.
    pub tsn: u8,
    /// Announcing device's network address.
    pub nwk_addr: u16,
    /// Announcing device's long address.
    pub ieee: u64,
    /// MAC capability flags of the announcer.
    pub capability: u8,
}

impl DeviceAnnce {
    /// Wire length.
    pub const LEN: usize = 12;

    /// Decode an announcement frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            nwk_addr: u16::from_le_bytes([buf[1], buf[2]]),
            ieee: u64::from_le_bytes([
                buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10],
            ]),
            capability: buf[11],
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        let nwk = self.nwk_addr.to_le_bytes();
        out[1] = nwk[0];
        out[2] = nwk[1];
        let ieee = self.ieee.to_le_bytes();
        out[3..11].copy_from_slice(&ieee);
        out[11] = self.capability;
        Ok(Self::LEN)
    }
}

/// Bind destination addressing mode (Tables 2-53/2-56 pattern:
/// group mode 0x01, extended mode 0x03).
///
/// Requirement `05-3474-23-24322-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindDstMode {
    /// Group binding: frames fan out to `group_addr`.
    Group {
        /// 16-bit group identifier.
        group_addr: u16,
    },
    /// Unicast binding: frames go to one endpoint.
    Extended {
        /// Destination long address.
        dst_ieee: u64,
        /// Destination endpoint.
        dst_endpoint: u8,
    },
}

impl BindDstMode {
    /// Decode the mode octet plus address tail.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.is_empty() {
            return Err(Error::Truncated);
        }
        match buf[0] {
            0x01 => {
                if buf.len() < 3 {
                    return Err(Error::Truncated);
                }
                Ok(Self::Group {
                    group_addr: u16::from_le_bytes([buf[1], buf[2]]),
                })
            }
            0x03 => {
                if buf.len() < 10 {
                    return Err(Error::Truncated);
                }
                Ok(Self::Extended {
                    dst_ieee: u64::from_le_bytes([
                        buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
                    ]),
                    dst_endpoint: buf[9],
                })
            }
            v => Err(Error::InvalidValue(v)),
        }
    }

    /// Encoded length of this value.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        match self {
            Self::Group { .. } => 3,
            Self::Extended { .. } => 10,
        }
    }

    /// Encode into `out`.
    pub fn encode_into(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len();
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        match self {
            Self::Group { group_addr } => {
                out[0] = 0x01;
                let bytes = group_addr.to_le_bytes();
                out[1] = bytes[0];
                out[2] = bytes[1];
                Ok(3)
            }
            Self::Extended {
                dst_ieee,
                dst_endpoint,
            } => {
                out[0] = 0x03;
                let bytes = dst_ieee.to_le_bytes();
                out[1..9].copy_from_slice(&bytes);
                out[9] = dst_endpoint;
                Ok(10)
            }
        }
    }
}

/// `Bind_req` / `Unbind_req` body: one binding entry named by source
/// plus destination (§2.4.3.2.2/§2.4.3.2.3, anchors p0138-L3388 and
/// p0140-L3408-L3409).
///
/// Requirement `05-3474-23-24322-01` / `05-3474-23-24323-01`
/// (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindEntry {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// Bound device's long address.
    pub src_ieee: u64,
    /// Bound local endpoint.
    pub src_endpoint: u8,
    /// Bound cluster.
    pub cluster_id: u16,
    /// Where matching frames go.
    pub dst: BindDstMode,
}

impl BindEntry {
    /// Shortest wire length (group flavour).
    pub const MIN_LEN: usize = 15;

    /// Decode a bind/unbind frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            src_ieee: u64::from_le_bytes([
                buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
            ]),
            src_endpoint: buf[9],
            cluster_id: u16::from_le_bytes([buf[10], buf[11]]),
            dst: BindDstMode::decode(&buf[12..])?,
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = 12 + self.dst.encoded_len();
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        let src = self.src_ieee.to_le_bytes();
        out[1..9].copy_from_slice(&src);
        out[9] = self.src_endpoint;
        let cluster = self.cluster_id.to_le_bytes();
        out[10] = cluster[0];
        out[11] = cluster[1];
        self.dst.encode_into(&mut out[12..])?;
        Ok(n)
    }
}

/// `Bind_rsp` / `Unbind_rsp`: sequence echo plus outcome only.
///
/// Requirement `05-3474-23-24432-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the bind/unbind.
    pub status: ZdpStatus,
}

impl BindRsp {
    /// Wire length.
    pub const LEN: usize = 2;

    /// Decode a bind/unbind response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            status: ZdpStatus::from_code(buf[1]),
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        Ok(Self::LEN)
    }
}
