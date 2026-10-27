//! ZCL frame header codec: frame control, manufacturer code,
//! transaction sequence, command identifier.
//!
//! Paraphrase-level model of doc `07-5123-08` §2.4.1 (general frame,
//! anchor p0060-L2365-L2367), §2.4.1.1 (frame control, anchor
//! p0060-L2369-L2372), §2.4.1.1.1–1.2 (frame type + manufacturer
//! presence, anchor p0060-L2374-L2382), §2.4.1.1.3 (direction, anchor
//! p0061-L2383-L2385), §2.4.1.1.4 (disable-default-response, anchor
//! p0061-L2386-L2391), §2.4.1.2 (manufacturer code, anchor
//! p0061-L2392-L2396), §2.4.1.3 (transaction sequence, anchor
//! p0061-L2398-L2404), §2.4.1.4 (command identifier, anchor
//! p0061-L2407-L2412). All wording here is paraphrase (D1).
//!
//! Requirement IDs below are repo-minted
//! (`07-5123-08-<clause>-<seq>`, dots stripped), MINTED-pending-confirm,
//! except `07-5123-08-241-01/02/2411-01/24111-01/2412-01/2413-01` which
//! are corpus-mined and reused.

use crate::Error;

/// Frame-type sub-field values (bits 0–1 of frame control).
///
/// Requirement `07-5123-08-2411-03` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameType {
    /// Command applies to every cluster.
    Global,
    /// Command is defined by one cluster.
    ClusterSpecific,
}

impl FrameType {
    /// Decode the 2-bit sub-field; reserved values rejected.
    ///
    /// Requirement `07-5123-08-2411-03` (MINTED-pending-confirm).
    pub const fn from_bits(bits: u8) -> Result<Self, Error> {
        match bits & 0x03 {
            0x00 => Ok(Self::Global),
            0x01 => Ok(Self::ClusterSpecific),
            v => Err(Error::InvalidValue(v)),
        }
    }

    /// Encode to the 2-bit sub-field.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::Global => 0x00,
            Self::ClusterSpecific => 0x01,
        }
    }
}

/// Transfer direction (bit 3 of frame control).
///
/// Requirement `07-5123-08-2412-01` (corpus-mined): set on frames that
/// are the immediate effect of a received frame, i.e. server-to-client
/// for responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Client side sends toward the server side.
    ToServer,
    /// Server side sends toward the client side.
    ToClient,
}

impl Direction {
    #[must_use]
    pub const fn bit(self) -> u8 {
        match self {
            Self::ToServer => 0,
            Self::ToClient => 1,
        }
    }

    #[must_use]
    pub const fn from_bit(bit: bool) -> Self {
        if bit {
            Self::ToClient
        } else {
            Self::ToServer
        }
    }

    /// Flip direction for a reply frame.
    #[must_use]
    pub const fn flip(self) -> Self {
        match self {
            Self::ToServer => Self::ToClient,
            Self::ToClient => Self::ToServer,
        }
    }
}

/// Decoded frame-control octet.
///
/// Requirements `07-5123-08-2411-01` (corpus-mined, Fig 2-2/2-3
/// geometry) + `07-5123-08-2411-02` (MINTED-pending-confirm, bit
/// layout with bits 5–7 reserved-zeroed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameControl {
    /// Global vs cluster-specific command set.
    pub frame_type: FrameType,
    /// Manufacturer extension flag (gates the manufacturer-code field).
    pub manufacturer_specific: bool,
    /// Client/server direction of this frame.
    pub direction: Direction,
    /// Default-Response suppression flag.
    pub disable_default_response: bool,
}

impl FrameControl {
    /// Encode one octet; reserved bits 5–7 are zeroed on transmit.
    ///
    /// Requirements `07-5123-08-2411-02` + `07-5123-08-231-02`
    /// (corpus-mined: reserved sub-fields zeroed on transmit).
    #[must_use]
    pub const fn encode(self) -> u8 {
        self.frame_type.bits()
            | ((self.manufacturer_specific as u8) << 2)
            | (self.direction.bit() << 3)
            | ((self.disable_default_response as u8) << 4)
    }

    /// Decode one octet; reserved bits 5–7 are parsed then ignored.
    ///
    /// Requirements `07-5123-08-2411-02` + `07-5123-08-232-01`
    /// (corpus-mined: reserved sub-fields ignored on receipt).
    pub const fn decode(byte: u8) -> Result<Self, Error> {
        match FrameType::from_bits(byte) {
            Ok(frame_type) => Ok(Self {
                frame_type,
                manufacturer_specific: byte & 0x04 != 0,
                direction: Direction::from_bit(byte & 0x08 != 0),
                disable_default_response: byte & 0x10 != 0,
            }),
            Err(e) => Err(e),
        }
    }
}

/// Decoded ZCL header: control + optional manufacturer code +
/// transaction sequence + command identifier.
///
/// Requirements `07-5123-08-241-01` (corpus-mined, message service +
/// LE octet order) and `07-5123-08-24111-01` (corpus-mined,
/// manufacturer-code presence rule).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Frame-control flags.
    pub control: FrameControl,
    /// Manufacturer code, present exactly when the flag is set.
    pub manufacturer_code: Option<u16>,
    /// Transaction identifier chaining requests to replies.
    pub tsn: u8,
    /// Global command id (frame type 0b00) or cluster command id.
    pub command_id: u8,
}

impl Header {
    /// Minimum encoded length without the manufacturer code.
    pub const MIN_LEN: usize = 3;
    /// Maximum encoded length with the manufacturer code.
    pub const MAX_LEN: usize = 5;

    /// Encoded header length for this control value.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        if self.manufacturer_code.is_some() {
            5
        } else {
            3
        }
    }

    /// Encode into `out`; manufacturer code is little-endian.
    ///
    /// Requirement `07-5123-08-241-01` (corpus-mined).
    pub fn encode_into(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len();
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        // Presence must match the flag (24111-01).
        let flag = self.control.manufacturer_specific;
        if flag != self.manufacturer_code.is_some() {
            return Err(Error::PresenceMismatch);
        }
        out[0] = self.control.encode();
        let mut i = 1;
        if let Some(code) = self.manufacturer_code {
            out[1..3].copy_from_slice(&code.to_le_bytes());
            i = 3;
        }
        out[i] = self.tsn;
        out[i + 1] = self.command_id;
        Ok(n)
    }

    /// Decode from the front of `buf`, returning header + payload.
    /// Trailing octets past the defined frame end stay in the payload
    /// slice for the caller (forward-compat: ignored per
    /// `07-5123-08-232-02`, corpus-mined).
    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8]), Error> {
        if buf.is_empty() {
            return Err(Error::Truncated);
        }
        let control = FrameControl::decode(buf[0])?;
        let mut i = 1;
        let mut manufacturer_code = None;
        if control.manufacturer_specific {
            if buf.len() < 3 {
                return Err(Error::Truncated);
            }
            manufacturer_code = Some(u16::from_le_bytes([buf[1], buf[2]]));
            i = 3;
        }
        if buf.len() < i + 2 {
            return Err(Error::Truncated);
        }
        Ok((
            Self {
                control,
                manufacturer_code,
                tsn: buf[i],
                command_id: buf[i + 1],
            },
            &buf[i + 2..],
        ))
    }

    /// Build the reply header for `request`: same transaction number,
    /// flipped direction, response frames always disable Default
    /// Response, manufacturer echo preserved.
    ///
    /// Requirements `07-5123-08-2413-01` (corpus-mined, sequence copy)
    /// plus `07-5123-08-2412-02` (MINTED-pending-confirm: responses set
    /// the disable bit).
    #[must_use]
    pub const fn reply_to(request: &Self, command_id: u8) -> Self {
        Self {
            control: FrameControl {
                frame_type: request.control.frame_type,
                manufacturer_specific: request.control.manufacturer_specific,
                direction: request.control.direction.flip(),
                disable_default_response: true,
            },
            manufacturer_code: request.manufacturer_code,
            tsn: request.tsn,
            command_id,
        }
    }
}
