//! Byte-stream framing for USB/UART (and the TCP binding).
//!
//! ```text
//! frame  = FLAG stuffed(inner) FLAG
//! inner  = LEN:u16BE | body | CRC16-CCITT:u16BE
//! body   = CBOR envelope (<= IFC_MAX_PAYLOAD + overhead)
//! ```
//!
//! `LEN` counts `body` octets only. The CRC covers `body` only
//! (length is protected by the CRC passing + exact-length check).
//! Byte-stuffing: `0x7D` escapes `FLAG`/`ESC` with `b ^ 0x20`.
//! A lone `FLAG` resynchronizes the decoder (aborts a partial frame).
//!
//! The same framing wraps the byte stream on the TCP binding
//! (`wire.md`); UDP datagrams carry exactly one unstuffed `inner`
//! each (datagram boundaries replace flags).

use crate::{IfcError, IFC_MAX_FRAME_BODY};

/// Frame boundary flag.
pub const FLAG: u8 = 0x7E;
/// Escape byte.
pub const ESC: u8 = 0x7D;
/// Escape xor mask.
pub const ESC_XOR: u8 = 0x20;

/// Largest stuffed frame on the wire (worst case: every byte escaped).
pub const MAX_STUFFED: usize = 2 + 2 * (2 + IFC_MAX_FRAME_BODY + 2);

/// CRC-16/CCITT-FALSE (`poly 0x1021`, `init 0xFFFF`).
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Encode `body` as one complete frame into `out`. Returns bytes written.
pub fn encode_frame(body: &[u8], out: &mut [u8]) -> Result<usize, IfcError> {
    if body.len() > IFC_MAX_FRAME_BODY {
        return Err(IfcError::FrameTooLong);
    }
    let mut inner = [0u8; 2 + IFC_MAX_FRAME_BODY + 2];
    let blen = u16::try_from(body.len()).map_err(|_| IfcError::FrameTooLong)?;
    inner[0..2].copy_from_slice(&blen.to_be_bytes());
    inner[2..2 + body.len()].copy_from_slice(body);
    inner[2 + body.len()..4 + body.len()].copy_from_slice(&crc16(body).to_be_bytes());
    let inner = &inner[..4 + body.len()];

    let mut pos = 0;
    let put = |b: u8, out: &mut [u8], pos: &mut usize| -> Result<(), IfcError> {
        if *pos >= out.len() {
            return Err(IfcError::FrameTooLong);
        }
        out[*pos] = b;
        *pos += 1;
        Ok(())
    };
    put(FLAG, out, &mut pos)?;
    for &b in inner {
        if b == FLAG || b == ESC {
            put(ESC, out, &mut pos)?;
            put(b ^ ESC_XOR, out, &mut pos)?;
        } else {
            put(b, out, &mut pos)?;
        }
    }
    put(FLAG, out, &mut pos)?;
    Ok(pos)
}

/// Streaming frame decoder. Feed bytes with [`FrameDecoder::push`];
/// a complete, CRC-valid body is returned as soon as its closing
/// `FLAG` arrives. A lone `FLAG` mid-frame discards the partial frame
/// (resynchronization — the sender re-drives completion via timeout).
#[derive(Debug)]
pub struct FrameDecoder {
    in_frame: bool,
    escaped: bool,
    buf: [u8; 2 + IFC_MAX_FRAME_BODY + 2],
    len: usize,
    overflow: bool,
}

impl FrameDecoder {
    /// New idle decoder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            in_frame: false,
            escaped: false,
            buf: [0; 2 + IFC_MAX_FRAME_BODY + 2],
            len: 0,
            overflow: false,
        }
    }

    /// Push one byte. `Ok(Some(n))` means `self.body()[..n]` is a fresh
    /// CRC-valid body (valid until the next `push`). `Ok(None)` means
    /// "need more bytes". `Err` reports a corrupt frame and resets to
    /// idle (the caller keeps feeding — sync resumes at the next FLAG).
    pub fn push(&mut self, b: u8) -> Result<Option<usize>, IfcError> {
        if b == FLAG {
            if !self.in_frame {
                self.reset();
                self.in_frame = true;
                return Ok(None);
            }
            // Closing flag: validate what we have.
            self.in_frame = false;
            if self.escaped || self.overflow || self.len < 4 {
                self.reset();
                return Err(IfcError::BadFrame);
            }
            let body_len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if body_len + 4 != self.len || body_len > IFC_MAX_FRAME_BODY {
                self.reset();
                return Err(IfcError::BadFrame);
            }
            let body = &self.buf[2..2 + body_len];
            let want = u16::from_be_bytes([self.buf[2 + body_len], self.buf[3 + body_len]]);
            if crc16(body) != want {
                self.reset();
                return Err(IfcError::BadCrc);
            }
            return Ok(Some(body_len));
        }
        if !self.in_frame {
            return Ok(None);
        }
        let byte = if self.escaped {
            self.escaped = false;
            b ^ ESC_XOR
        } else if b == ESC {
            self.escaped = true;
            return Ok(None);
        } else {
            b
        };
        if self.len >= self.buf.len() {
            self.overflow = true;
        } else {
            self.buf[self.len] = byte;
            self.len += 1;
        }
        Ok(None)
    }

    /// Body bytes of the last completed frame.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        let body_len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
        &self.buf[2..2 + body_len]
    }

    fn reset(&mut self) {
        self.escaped = false;
        self.len = 0;
        self.overflow = false;
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_known_vector() {
        assert_eq!(crc16(b"123456789"), 0x29B1);
    }

    #[test]
    fn frame_round_trip_with_flags_inside() {
        let body = [FLAG, ESC, 0x00, 0x7E, 0x7D, 0x41];
        let mut wire = [0u8; MAX_STUFFED];
        let n = encode_frame(&body, &mut wire).unwrap();
        let mut d = FrameDecoder::new();
        let mut got = None;
        for &b in &wire[..n] {
            if let Some(m) = d.push(b).unwrap() {
                got = Some(m);
            }
        }
        assert_eq!(got, Some(body.len()));
        assert_eq!(d.body(), body);
    }

    #[test]
    fn resync_after_garbage() {
        let mut d = FrameDecoder::new();
        for b in [0x00, 0x01, FLAG, 0x99] {
            let _ = d.push(b);
        }
        // Partial frame aborted by a fresh FLAG pair around junk:
        // lone FLAG restarts, then garbage then closing FLAG -> BadFrame.
        assert_eq!(d.push(FLAG), Err(IfcError::BadFrame));
    }

    #[test]
    fn bad_crc_reported() {
        let body = [1, 2, 3, 4];
        let mut wire = [0u8; MAX_STUFFED];
        let n = encode_frame(&body, &mut wire).unwrap();
        wire[n - 3] ^= 0xFF; // corrupt body byte (unstuffed region here)
        let mut d = FrameDecoder::new();
        let mut err = None;
        for &b in &wire[..n] {
            if let Err(e) = d.push(b) {
                err = Some(e);
            }
        }
        assert_eq!(err, Some(IfcError::BadCrc));
    }

    #[test]
    fn oversize_rejected() {
        let big = [0u8; IFC_MAX_FRAME_BODY + 1];
        let mut wire = [0u8; MAX_STUFFED + 16];
        assert_eq!(encode_frame(&big, &mut wire), Err(IfcError::FrameTooLong));
    }
}
