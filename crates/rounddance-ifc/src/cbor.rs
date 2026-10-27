//! Minimal deterministic CBOR codec (subset of RFC 8949).
//!
//! Only what the v0 envelope needs: unsigned integers (major 0),
//! byte strings (major 2), and array headers (major 4), plus the
//! matching decoder with a strict input budget. Hand-rolled so the
//! `no_std` core carries no third-party codec dependency: the encoder
//! output is canonical by construction (shortest-form integers, one
//! encoding per value), which keeps trace comparison deterministic.
//!
//! Anything outside the subset (negative ints, text, maps, tags,
//! floats, indefinite lengths) is rejected by the decoder with
//! [`IfcError::Truncated`]. v1 may widen the subset; v0 endpoints must
//! reject, never guess.

use crate::{IfcError, IFC_MAX_FRAME_BODY};

/// Encode an unsigned integer, shortest form. Returns bytes written.
pub fn encode_uint(out: &mut [u8], v: u64) -> Result<usize, IfcError> {
    let (major, n) = head_len(0, v);
    if out.len() < n {
        return Err(IfcError::FrameTooLong);
    }
    write_head(out, major, v);
    Ok(n)
}

/// Encode a byte string header + bytes. Returns bytes written.
pub fn encode_bytes(out: &mut [u8], b: &[u8]) -> Result<usize, IfcError> {
    let (_, n) = head_len(2, b.len() as u64);
    if out.len() < n + b.len() {
        return Err(IfcError::FrameTooLong);
    }
    write_head(out, 2, b.len() as u64);
    out[n..n + b.len()].copy_from_slice(b);
    Ok(n + b.len())
}

/// Encode an array header of `len` items. Returns bytes written.
pub fn encode_array(out: &mut [u8], len: usize) -> Result<usize, IfcError> {
    let (major, n) = head_len(4, len as u64);
    if out.len() < n {
        return Err(IfcError::FrameTooLong);
    }
    write_head(out, major, len as u64);
    Ok(n)
}

/// Decoded CBOR head: major type, argument, head length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Head {
    major: u8,
    arg: u64,
    len: usize,
}

fn read_head(inp: &[u8]) -> Result<Head, IfcError> {
    let b0 = *inp.first().ok_or(IfcError::Truncated)?;
    let major = b0 >> 5;
    let info = b0 & 0x1f;
    let (arg, len) = match info {
        0..=23 => (u64::from(info), 1),
        24 => (u64::from(*inp.get(1).ok_or(IfcError::Truncated)?), 2),
        25 => {
            let a = inp.get(1..3).ok_or(IfcError::Truncated)?;
            (u64::from(u16::from_be_bytes([a[0], a[1]])), 3)
        }
        26 => {
            let a = inp.get(1..5).ok_or(IfcError::Truncated)?;
            (u64::from(u32::from_be_bytes([a[0], a[1], a[2], a[3]])), 5)
        }
        27 => {
            let a = inp.get(1..9).ok_or(IfcError::Truncated)?;
            (
                u64::from_be_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]),
                9,
            )
        }
        _ => return Err(IfcError::Truncated),
    };
    if inp.len() > IFC_MAX_FRAME_BODY {
        return Err(IfcError::FrameTooLong);
    }
    Ok(Head { major, arg, len })
}

/// Minimal pull decoder over a bounded slice.
pub struct Decoder<'a> {
    inp: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Borrow `inp`; anything past [`IFC_MAX_FRAME_BODY`] is rejected.
    pub fn new(inp: &'a [u8]) -> Result<Self, IfcError> {
        if inp.len() > IFC_MAX_FRAME_BODY {
            return Err(IfcError::FrameTooLong);
        }
        Ok(Self { inp, pos: 0 })
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], IfcError> {
        let end = self.pos.checked_add(n).ok_or(IfcError::Truncated)?;
        if end > self.inp.len() {
            return Err(IfcError::Truncated);
        }
        let s = &self.inp[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Decode one unsigned integer (major 0 only).
    pub fn uint(&mut self) -> Result<u64, IfcError> {
        let rest = self.inp.get(self.pos..).ok_or(IfcError::Truncated)?;
        let h = read_head(rest)?;
        if h.major != 0 {
            return Err(IfcError::Truncated);
        }
        self.pos += h.len;
        Ok(h.arg)
    }

    /// Decode one array header, returning the item count.
    pub fn array(&mut self) -> Result<usize, IfcError> {
        let rest = self.inp.get(self.pos..).ok_or(IfcError::Truncated)?;
        let h = read_head(rest)?;
        if h.major != 4 {
            return Err(IfcError::Truncated);
        }
        self.pos += h.len;
        usize::try_from(h.arg).map_err(|_| IfcError::Truncated)
    }

    /// Decode one byte string into `out`. Returns the byte count.
    pub fn bytes_into(&mut self, out: &mut [u8]) -> Result<usize, IfcError> {
        let rest = self.inp.get(self.pos..).ok_or(IfcError::Truncated)?;
        let h = read_head(rest)?;
        if h.major != 2 {
            return Err(IfcError::Truncated);
        }
        let n = usize::try_from(h.arg).map_err(|_| IfcError::Truncated)?;
        if n > out.len() {
            return Err(IfcError::FrameTooLong);
        }
        self.pos += h.len;
        let s = self.take(n)?;
        out[..n].copy_from_slice(s);
        Ok(n)
    }

    /// True when every input byte has been consumed.
    #[must_use]
    pub fn done(&self) -> bool {
        self.pos == self.inp.len()
    }
}

fn head_len(major: u8, v: u64) -> (u8, usize) {
    if v <= 23 {
        (major, 1)
    } else if v <= 0xff {
        (major, 2)
    } else if v <= 0xffff {
        (major, 3)
    } else if v <= 0xffff_ffff {
        (major, 5)
    } else {
        (major, 9)
    }
}

fn write_head(out: &mut [u8], major: u8, v: u64) {
    let prefix = major << 5;
    if v <= 23 {
        out[0] = prefix | v as u8;
    } else if v <= 0xff {
        out[0] = prefix | 24;
        out[1] = v as u8;
    } else if v <= 0xffff {
        out[0] = prefix | 25;
        let b = (v as u16).to_be_bytes();
        out[1..3].copy_from_slice(&b);
    } else if v <= 0xffff_ffff {
        out[0] = prefix | 26;
        let b = (v as u32).to_be_bytes();
        out[1..5].copy_from_slice(&b);
    } else {
        out[0] = prefix | 27;
        out[1..9].copy_from_slice(&v.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint_round_trips_at_size_edges() {
        for v in [
            0,
            1,
            23,
            24,
            255,
            256,
            65535,
            65536,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut buf = [0u8; 9];
            let n = encode_uint(&mut buf, v).unwrap();
            let mut d = Decoder::new(&buf[..n]).unwrap();
            assert_eq!(d.uint().unwrap(), v);
            assert!(d.done());
        }
    }

    #[test]
    fn bytes_round_trip() {
        let mut buf = [0u8; 64];
        let n = encode_bytes(&mut buf, b"hello").unwrap();
        let mut d = Decoder::new(&buf[..n]).unwrap();
        let mut out = [0u8; 64];
        assert_eq!(d.bytes_into(&mut out).unwrap(), 5);
        assert_eq!(&out[..5], b"hello");
    }

    #[test]
    fn wrong_major_rejected() {
        let mut buf = [0u8; 8];
        let n = encode_array(&mut buf, 3).unwrap();
        let mut d = Decoder::new(&buf[..n]).unwrap();
        assert_eq!(d.uint(), Err(IfcError::Truncated));
    }

    #[test]
    fn truncated_input_rejected() {
        let mut d = Decoder::new(&[0x19]).unwrap();
        assert_eq!(d.uint(), Err(IfcError::Truncated));
    }
}
