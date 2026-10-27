//! The v0 message envelope: one CBOR array over every binding.
//!
//! ```text
//! envelope = [ version:uint, if_id:uint, op:uint,
//!              seq:uint, flags:uint, payload:bytes ]
//! ```
//!
//! `seq` is the per-direction rolling counter (see `semantics.md`:
//! wrap is legal, rollback is not). `flags` bit 0 = `wants-confirm`
//! (the sender expects a confirm op in reply); bits 1–7 are reserved
//! and MUST be zero on send, ignored on receive.

use crate::{
    cbor::{encode_array, encode_bytes, encode_uint, Decoder},
    IfcError, IFC_MAX_PAYLOAD,
};

/// `flags` bit: sender expects a confirm op for this `seq`.
pub const FLAG_WANTS_CONFIRM: u8 = 0x01;

/// One message between two functions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Interface protocol version (always [`crate::IFC_VERSION`] on send).
    pub version: u8,
    /// Target function (see [`crate::ids`]).
    pub if_id: u8,
    /// Operation within the interface.
    pub op: u8,
    /// Per-direction rolling sequence number.
    pub seq: u16,
    /// Bit 0 = wants-confirm; rest reserved-zero.
    pub flags: u8,
    /// Op payload (interface-defined CBOR, opaque here).
    pub payload: Payload,
}

/// Bounded payload bytes (stack-allocated, no heap).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payload {
    buf: [u8; IFC_MAX_PAYLOAD],
    len: usize,
}

impl Payload {
    /// Empty payload.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0; IFC_MAX_PAYLOAD],
            len: 0,
        }
    }

    /// Copy `bytes` in, or [`IfcError::FrameTooLong`].
    pub fn from_slice(bytes: &[u8]) -> Result<Self, IfcError> {
        if bytes.len() > IFC_MAX_PAYLOAD {
            return Err(IfcError::FrameTooLong);
        }
        let mut p = Self::new();
        p.buf[..bytes.len()].copy_from_slice(bytes);
        p.len = bytes.len();
        Ok(p)
    }

    /// Live payload bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Payload length in octets.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for Payload {
    fn default() -> Self {
        Self::new()
    }
}

impl Envelope {
    /// CBOR-encoded length of `self`.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        encoded_len_of(self)
    }

    /// Encode into `out`. [`IfcError::FrameTooLong`] when it does not fit.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, IfcError> {
        let mut pos = 0;
        pos += encode_array(&mut out[pos..], 6).map_err(|_| IfcError::FrameTooLong)?;
        pos += encode_uint(&mut out[pos..], u64::from(self.version))
            .map_err(|_| IfcError::FrameTooLong)?;
        pos += encode_uint(&mut out[pos..], u64::from(self.if_id))
            .map_err(|_| IfcError::FrameTooLong)?;
        pos +=
            encode_uint(&mut out[pos..], u64::from(self.op)).map_err(|_| IfcError::FrameTooLong)?;
        pos += encode_uint(&mut out[pos..], u64::from(self.seq))
            .map_err(|_| IfcError::FrameTooLong)?;
        pos += encode_uint(&mut out[pos..], u64::from(self.flags))
            .map_err(|_| IfcError::FrameTooLong)?;
        pos += encode_bytes(&mut out[pos..], self.payload.as_slice())
            .map_err(|_| IfcError::FrameTooLong)?;
        Ok(pos)
    }

    /// Decode one envelope; trailing bytes are an error.
    pub fn decode(inp: &[u8]) -> Result<Self, IfcError> {
        let mut d = Decoder::new(inp)?;
        if d.array()? != 6 {
            return Err(IfcError::Truncated);
        }
        let version = u8::try_from(d.uint()?).map_err(|_| IfcError::Truncated)?;
        let if_id = u8::try_from(d.uint()?).map_err(|_| IfcError::Truncated)?;
        let op = u8::try_from(d.uint()?).map_err(|_| IfcError::Truncated)?;
        let seq = u16::try_from(d.uint()?).map_err(|_| IfcError::Truncated)?;
        let flags = u8::try_from(d.uint()?).map_err(|_| IfcError::Truncated)?;
        let mut pbuf = [0u8; IFC_MAX_PAYLOAD];
        let n = d.bytes_into(&mut pbuf)?;
        if !d.done() {
            return Err(IfcError::Truncated);
        }
        let mut payload = Payload::new();
        payload.buf[..n].copy_from_slice(&pbuf[..n]);
        payload.len = n;
        Ok(Self {
            version,
            if_id,
            op,
            seq,
            flags,
            payload,
        })
    }
}

fn encoded_len_of(e: &Envelope) -> usize {
    uint_len(u64::from(e.version))
        + uint_len(u64::from(e.if_id))
        + uint_len(u64::from(e.op))
        + uint_len(u64::from(e.seq))
        + uint_len(u64::from(e.flags))
        + bytes_len(e.payload.len())
        + array_len(6)
}

fn uint_len(v: u64) -> usize {
    if v <= 23 {
        1
    } else if v <= 0xff {
        2
    } else if v <= 0xffff {
        3
    } else if v <= 0xffff_ffff {
        5
    } else {
        9
    }
}

fn bytes_len(n: usize) -> usize {
    uint_len(n as u64) + n
}

fn array_len(n: usize) -> usize {
    uint_len(n as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_bounded() {
        let big = [0xAA; IFC_MAX_PAYLOAD + 1];
        assert_eq!(Payload::from_slice(&big), Err(IfcError::FrameTooLong));
        assert!(Payload::from_slice(&[]).unwrap().is_empty());
    }

    #[test]
    fn envelope_round_trip() {
        let e = Envelope {
            version: 0,
            if_id: 1,
            op: 2,
            seq: 0x1234,
            flags: FLAG_WANTS_CONFIRM,
            payload: Payload::from_slice(&[9, 8, 7]).unwrap(),
        };
        let mut buf = [0u8; 600];
        let n = e.encode(&mut buf).unwrap();
        assert_eq!(n, e.encoded_len());
        assert_eq!(Envelope::decode(&buf[..n]).unwrap(), e);
    }
}
