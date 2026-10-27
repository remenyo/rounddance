//! Node, power, and simple descriptors: bounded codecs.
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2 §2.3.2.3 (node
//! descriptor fields §§2.3.2.3.1–3.13, anchors p0114-L2733 through
//! p0117-L2808), §2.3.2.4 (power descriptor §§2.3.2.4.1–4.4, anchors
//! p0117-L2809 through p0118-L2830), and §2.3.2.5 (simple descriptor,
//! Table 2-40, anchors p0119-L2835-L2842). All wording here is
//! paraphrase (D1, `SCOPE.md` §2).
//!
//! * `no_std` + `#![forbid(unsafe_code)]`, no allocator: decode
//!   validates into fixed-size arrays, encode writes into caller
//!   buffers.
//! * Every fallible path returns [`Error`]; nothing panics on
//!   adversarial input.
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped), MINTED-pending-confirm.

/// Codec failure: truncated input, oversized lists, out-of-range
/// values, or an encode buffer with no room.
///
/// Requirement `05-3474-23-232-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Input ends before the fixed part of the structure.
    Truncated,
    /// A count field names more entries than fit the bounded array.
    TooManyEntries,
    /// A fixed value (logical type, power mode, …) is out of range.
    InvalidValue(u8),
    /// The encode buffer has no room for the structure.
    BufferTooSmall,
}

/// Device role announced in the node descriptor (§2.3.2.3.1, anchor
/// p0114-L2733).
///
/// Requirement `05-3474-23-23231-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicalType {
    /// Full-function end device.
    EndDevice,
    /// Forwards traffic for others.
    Router,
    /// Network coordinator.
    Coordinator,
}

impl LogicalType {
    /// Decode the 3-bit field; values above 2 are reserved.
    pub const fn from_bits(bits: u8) -> Result<Self, Error> {
        match bits & 0x07 {
            0x00 => Ok(Self::EndDevice),
            0x01 => Ok(Self::Router),
            0x02 => Ok(Self::Coordinator),
            v => Err(Error::InvalidValue(v)),
        }
    }

    /// 3-bit wire value.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::EndDevice => 0x00,
            Self::Router => 0x01,
            Self::Coordinator => 0x02,
        }
    }
}

/// Node descriptor: capability summary of one device (§2.3.2.3).
/// Exactly 14 octets on the wire.
///
/// Requirement `05-3474-23-2323-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeDescriptor {
    /// First octet: logical type in bits 0–2; upper bits preserved
    /// verbatim (deprecated availability flags read as zero).
    pub flags0: u8,
    /// APS flags octet (§2.3.2.3.5, anchor p0114-L2749).
    pub aps_flags: u8,
    /// Frequency-band bitmask octet (§2.3.2.3.6, anchor p0114-L2753).
    pub freq_band: u8,
    /// MAC capability flags octet (§2.3.2.3.7, anchor p0115-L2759).
    pub mac_cap: u8,
    /// Manufacturer code, little-endian (§2.3.2.3.8, anchor
    /// p0115-L2778).
    pub mfr_code: u16,
    /// Largest ASDU the application supports here (§2.3.2.3.9, anchor
    /// p0116-L2781).
    pub max_buf: u8,
    /// Largest incoming transfer, little-endian (§2.3.2.3.10, anchor
    /// p0116-L2787).
    pub max_in_transfer: u16,
    /// Server mask, little-endian (§2.3.2.3.11, anchor p0116-L2793).
    pub server_mask: u16,
    /// Largest outgoing transfer, little-endian (§2.3.2.3.12, anchor
    /// p0116-L2803).
    pub max_out_transfer: u16,
    /// Descriptor-capability octet, deprecated, preserved verbatim
    /// (§2.3.2.3.13, anchor p0117-L2808).
    pub desc_cap: u8,
}

/// Wire length of an encoded node descriptor.
///
/// Requirement `05-3474-23-2323-01`.
pub const NODE_DESCRIPTOR_LEN: usize = 14;

impl NodeDescriptor {
    /// Device role from the first octet.
    pub const fn logical_type(&self) -> Result<LogicalType, Error> {
        LogicalType::from_bits(self.flags0)
    }

    /// Set the device role, preserving the upper bits of octet zero.
    pub const fn set_logical_type(&mut self, logical: LogicalType) {
        self.flags0 = (self.flags0 & 0xF8) | logical.bits();
    }

    /// Decode exactly [`NODE_DESCRIPTOR_LEN`] octets.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < NODE_DESCRIPTOR_LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            flags0: buf[0],
            aps_flags: buf[1],
            freq_band: buf[2],
            mac_cap: buf[3],
            mfr_code: u16::from_le_bytes([buf[4], buf[5]]),
            max_buf: buf[6],
            max_in_transfer: u16::from_le_bytes([buf[7], buf[8]]),
            server_mask: u16::from_le_bytes([buf[9], buf[10]]),
            max_out_transfer: u16::from_le_bytes([buf[11], buf[12]]),
            desc_cap: buf[13],
        })
    }

    /// Encode into `out`; needs [`NODE_DESCRIPTOR_LEN`] octets.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < NODE_DESCRIPTOR_LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.flags0;
        out[1] = self.aps_flags;
        out[2] = self.freq_band;
        out[3] = self.mac_cap;
        let mfr = self.mfr_code.to_le_bytes();
        out[4] = mfr[0];
        out[5] = mfr[1];
        out[6] = self.max_buf;
        let max_in = self.max_in_transfer.to_le_bytes();
        out[7] = max_in[0];
        out[8] = max_in[1];
        let mask = self.server_mask.to_le_bytes();
        out[9] = mask[0];
        out[10] = mask[1];
        let max_out = self.max_out_transfer.to_le_bytes();
        out[11] = max_out[0];
        out[12] = max_out[1];
        out[13] = self.desc_cap;
        Ok(NODE_DESCRIPTOR_LEN)
    }
}

/// Receiver-on-when-idle reporting in the power descriptor
/// (§2.3.2.4.1, anchor p0117-L2815).
///
/// Requirement `05-3474-23-23241-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerMode {
    /// Receiver on when the device is idle.
    OnWhenIdle,
    /// Receiver cycles on periodically.
    Periodic,
    /// Receiver on only when stimulated.
    OnStimulated,
}

impl PowerMode {
    /// Decode the low nibble; values above 2 are reserved.
    pub const fn from_bits(bits: u8) -> Result<Self, Error> {
        match bits & 0x0F {
            0x00 => Ok(Self::OnWhenIdle),
            0x01 => Ok(Self::Periodic),
            0x02 => Ok(Self::OnStimulated),
            v => Err(Error::InvalidValue(v)),
        }
    }

    /// Nibble wire value.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::OnWhenIdle => 0x00,
            Self::Periodic => 0x01,
            Self::OnStimulated => 0x02,
        }
    }
}

/// Power descriptor: power story of one device in two octets
/// (§2.3.2.4): octet zero carries the current mode (low nibble) and
/// the available-sources bitmask (high nibble, §2.3.2.4.2, anchor
/// p0117-L2820); octet one carries the current source (low nibble,
/// §2.3.2.4.3, anchor p0118-L2825) and its level (high nibble,
/// §2.3.2.4.4, anchor p0118-L2830).
///
/// Requirement `05-3474-23-2324-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerDescriptor {
    /// Current power mode (low nibble of octet zero).
    pub mode: PowerMode,
    /// Available-sources bitmask (high nibble of octet zero).
    pub available: u8,
    /// Current source nibble (low nibble of octet one).
    pub source: u8,
    /// Current source level nibble (high nibble of octet one).
    pub level: u8,
}

/// Wire length of an encoded power descriptor.
///
/// Requirement `05-3474-23-2324-01`.
pub const POWER_DESCRIPTOR_LEN: usize = 2;

impl PowerDescriptor {
    /// Decode exactly [`POWER_DESCRIPTOR_LEN`] octets.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < POWER_DESCRIPTOR_LEN {
            return Err(Error::Truncated);
        }
        match PowerMode::from_bits(buf[0] & 0x0F) {
            Ok(mode) => Ok(Self {
                mode,
                available: buf[0] >> 4,
                source: buf[1] & 0x0F,
                level: buf[1] >> 4,
            }),
            Err(e) => Err(e),
        }
    }

    /// Encode into `out`; needs [`POWER_DESCRIPTOR_LEN`] octets.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < POWER_DESCRIPTOR_LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.mode.bits() | (self.available << 4);
        out[1] = (self.source & 0x0F) | (self.level << 4);
        Ok(POWER_DESCRIPTOR_LEN)
    }
}

/// Bound on cluster lists in one simple descriptor (declared budget;
/// the over-air count octet allows more, which decode rejects with
/// [`Error::TooManyEntries`] instead of truncating).
///
/// Requirement `05-3474-23-2325-01` (MINTED-pending-confirm).
pub const MAX_SIMPLE_CLUSTERS: usize = 16;

/// Simple descriptor: what one endpoint speaks (§2.3.2.5, Table 2-40,
/// anchors p0119-L2835-L2842): endpoint (§2.3.2.5.1), application
/// profile (§2.3.2.5.2), device identifier (§2.3.2.5.3), device version
/// low nibble (§2.3.2.5.4), then counted input and output cluster
/// lists.
///
/// Requirement `05-3474-23-2325-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimpleDescriptor {
    /// Endpoint this descriptor belongs to (1–254, §2.3.2.5.1, anchor
    /// p0119-L2843).
    pub endpoint: u8,
    /// Application profile, little-endian (§2.3.2.5.2, anchor
    /// p0119-L2848).
    pub profile_id: u16,
    /// Application device identifier, little-endian (§2.3.2.5.3,
    /// anchor p0119-L2851).
    pub device_id: u16,
    /// Device version, low nibble (§2.3.2.5.4, anchor p0119-L2855).
    pub device_version: u8,
    /// Input (server) clusters, first `in_len` entries valid.
    pub in_clusters: [u16; MAX_SIMPLE_CLUSTERS],
    /// How many input clusters are present.
    pub in_len: u8,
    /// Output (client) clusters, first `out_len` entries valid.
    pub out_clusters: [u16; MAX_SIMPLE_CLUSTERS],
    /// How many output clusters are present.
    pub out_len: u8,
}

impl SimpleDescriptor {
    /// Smallest wire footprint: endpoint + profile + device + version
    /// + two empty counts.
    pub const MIN_LEN: usize = 8;

    /// Largest wire footprint under the declared budgets.
    pub const MAX_LEN: usize = 8 + 2 * MAX_SIMPLE_CLUSTERS * 2;

    /// Decode one descriptor; the caller positions `buf` at the
    /// descriptor start (after any response length octet).
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let in_len = buf[6] as usize;
        if in_len > MAX_SIMPLE_CLUSTERS {
            return Err(Error::TooManyEntries);
        }
        let mut pos = 7 + 2 * in_len;
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
        let mut desc = Self {
            endpoint: buf[0],
            profile_id: u16::from_le_bytes([buf[1], buf[2]]),
            device_id: u16::from_le_bytes([buf[3], buf[4]]),
            device_version: buf[5] & 0x0F,
            in_clusters: [0; MAX_SIMPLE_CLUSTERS],
            in_len: in_len as u8,
            out_clusters: [0; MAX_SIMPLE_CLUSTERS],
            out_len: out_len as u8,
        };
        for (i, slot) in desc.in_clusters.iter_mut().take(in_len).enumerate() {
            *slot = u16::from_le_bytes([buf[7 + 2 * i], buf[7 + 2 * i + 1]]);
        }
        let base = 7 + 2 * in_len + 1;
        for (i, slot) in desc.out_clusters.iter_mut().take(out_len).enumerate() {
            *slot = u16::from_le_bytes([buf[base + 2 * i], buf[base + 2 * i + 1]]);
        }
        Ok(desc)
    }

    /// Encoded length of this value.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        8 + 2 * self.in_len as usize + 2 * self.out_len as usize
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len();
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        if self.in_len as usize > MAX_SIMPLE_CLUSTERS || self.out_len as usize > MAX_SIMPLE_CLUSTERS
        {
            return Err(Error::TooManyEntries);
        }
        out[0] = self.endpoint;
        let profile = self.profile_id.to_le_bytes();
        out[1] = profile[0];
        out[2] = profile[1];
        let device = self.device_id.to_le_bytes();
        out[3] = device[0];
        out[4] = device[1];
        out[5] = self.device_version & 0x0F;
        out[6] = self.in_len;
        for (i, cluster) in self
            .in_clusters
            .iter()
            .take(self.in_len as usize)
            .enumerate()
        {
            let bytes = cluster.to_le_bytes();
            out[7 + 2 * i] = bytes[0];
            out[7 + 2 * i + 1] = bytes[1];
        }
        let base = 7 + 2 * self.in_len as usize;
        out[base] = self.out_len;
        for (i, cluster) in self
            .out_clusters
            .iter()
            .take(self.out_len as usize)
            .enumerate()
        {
            let bytes = cluster.to_le_bytes();
            out[base + 1 + 2 * i] = bytes[0];
            out[base + 1 + 2 * i + 1] = bytes[1];
        }
        Ok(n)
    }

    /// Input cluster list as a slice.
    #[must_use]
    pub fn in_list(&self) -> &[u16] {
        &self.in_clusters[..self.in_len as usize]
    }

    /// Output cluster list as a slice.
    #[must_use]
    pub fn out_list(&self) -> &[u16] {
        &self.out_clusters[..self.out_len as usize]
    }
}
