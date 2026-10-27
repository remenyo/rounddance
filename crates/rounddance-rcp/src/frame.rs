//! UART transport framing for the S3+H2 OTBR path.
//!
//! The H2 runs 15.4 radio firmware speaking a small command/response
//! protocol over UART; the S3 host runs the rounddance stack and drives
//! it through [`crate::driver::RcpDriver`]. This module is the byte
//! layer both sides share: every transfer is one frame
//!
//! ```text
//! SYNC | LEN | KIND | SEQ | payload[..] | CRC16-LE
//! 0xA5   1     1      1     0..=128        2
//! ```
//!
//! * `LEN` counts every octet after itself up to and including the CRC
//!   (`KIND + SEQ + payload + 2`), so 4..=132.
//! * `CRC16` is CRC-16/CCITT (`poly 0x1021`, `init 0xFFFF`) over
//!   `KIND | SEQ | payload`.
//! * The maximum payload (128) fits one 15.4 PSDU (127) plus the one
//!   command-flags octet the [`crate::cmd`] layer prepends.
//!
//! [`Decoder`] is a streaming byte pump: unknown bytes ahead of `SYNC`
//! are skipped (resync by scan), short/long `LEN` and CRC mismatches
//! surface as [`Outcome::Dropped`] and the parser re-arms at the next
//! `SYNC`. It never panics and holds no allocator state.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-RCP-01` (framing), `RD-RCP-02` (CRC + resync).

use core::fmt;

/// Frame synchronisation octet.
pub const SYNC: u8 = 0xA5;

/// Largest command/event payload in octets.
pub const MAX_RCP_PAYLOAD: usize = 128;

/// Smallest legal `LEN` (`KIND + SEQ + CRC16`, empty payload).
pub const MIN_LEN: u8 = 4;

/// Largest legal `LEN` (`KIND + SEQ + full payload + CRC16`).
pub const MAX_LEN: u8 = (2 + MAX_RCP_PAYLOAD + 2) as u8;

/// Largest encoded frame: `SYNC + LEN + LEN-bytes`.
pub const MAX_FRAME_BYTES: usize = 2 + MAX_LEN as usize;

/// Framing errors: encode-side only (decode never fails — it drops).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Payload exceeds [`MAX_RCP_PAYLOAD`].
    TooLong,
    /// Output slice fits fewer than the encoded bytes.
    BufferTooSmall,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => f.write_str("RCP payload exceeds 128 octets"),
            Self::BufferTooSmall => f.write_str("RCP output buffer too small"),
        }
    }
}

impl core::error::Error for FrameError {}

/// CRC-16/CCITT over `data` (`poly 0x1021`, `init 0xFFFF`).
///
/// Reference check: `crc16(b"123456789") == 0x29B1`.
#[must_use]
pub const fn crc16(mut data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    while let [b, rest @ ..] = data {
        data = rest;
        crc ^= (*b as u16) << 8;
        let mut i = 0;
        while i < 8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
            i += 1;
        }
    }
    crc
}

/// One decoded frame: kind + sequence + bounded payload copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Command/event class (see [`crate::cmd`]).
    pub kind: u8,
    /// Sequence number (command echo / event counter).
    pub seq: u8,
    /// Live payload length.
    pub payload_len: u8,
    /// Payload bytes (first `payload_len` live).
    pub payload: [u8; MAX_RCP_PAYLOAD],
}

impl Frame {
    /// Live payload bytes.
    #[must_use]
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }
}

/// Encode one frame into `out`; returns bytes written.
///
/// # Errors
///
/// [`FrameError::TooLong`] when the payload exceeds
/// [`MAX_RCP_PAYLOAD`], [`FrameError::BufferTooSmall`] when `out` is
/// short (prefix unwritten — encoding is all-or-nothing).
pub fn encode(kind: u8, seq: u8, payload: &[u8], out: &mut [u8]) -> Result<usize, FrameError> {
    if payload.len() > MAX_RCP_PAYLOAD {
        return Err(FrameError::TooLong);
    }
    let total = 2 + 2 + payload.len() + 2;
    if out.len() < total {
        return Err(FrameError::BufferTooSmall);
    }
    out[0] = SYNC;
    out[1] = (2 + payload.len() + 2) as u8;
    out[2] = kind;
    out[3] = seq;
    out[4..4 + payload.len()].copy_from_slice(payload);
    let crc = crc16(&out[2..4 + payload.len()]);
    out[4 + payload.len()] = (crc & 0xFF) as u8;
    out[5 + payload.len()] = (crc >> 8) as u8;
    Ok(total)
}

/// Why a byte run was dropped instead of decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// `LEN` outside `4..=132`.
    BadLen(u8),
    /// Trailing CRC mismatch.
    BadCrc,
}

/// One decoder step result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A complete, CRC-clean frame.
    Frame(Frame),
    /// A malformed run was skipped; the parser re-armed at `SYNC`.
    Dropped(DropReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Sync,
    Len,
    Kind,
    Seq,
    Payload,
    CrcLo,
    CrcHi,
}

/// Streaming frame parser: feed UART bytes, collect outcomes.
///
/// Bytes before the first `SYNC` are skipped silently (line noise, a
/// peer mid-frame on attach). A bad `LEN` or CRC surfaces as
/// [`Outcome::Dropped`] and re-arms the parser, so one corrupt run
/// can never wedge the stream — the property the driver's desync
/// recovery counts on.
#[derive(Clone, Debug)]
pub struct Decoder {
    state: State,
    want: u8,
    kind: u8,
    seq: u8,
    payload: [u8; MAX_RCP_PAYLOAD],
    pos: usize,
    crc_lo: u8,
    dropped: u32,
    consecutive_bad: u32,
}

impl Decoder {
    /// Parser waiting at `SYNC`, counters zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: State::Sync,
            want: 0,
            kind: 0,
            seq: 0,
            payload: [0; MAX_RCP_PAYLOAD],
            pos: 0,
            crc_lo: 0,
            dropped: 0,
            consecutive_bad: 0,
        }
    }

    /// Total dropped runs so far (diagnostic).
    #[must_use]
    pub fn dropped(&self) -> u32 {
        self.dropped
    }

    /// Dropped runs since the last good frame (desync meter).
    #[must_use]
    pub fn consecutive_bad(&self) -> u32 {
        self.consecutive_bad
    }

    fn drop(&mut self, reason: DropReason) -> Outcome {
        self.state = State::Sync;
        self.pos = 0;
        self.dropped = self.dropped.saturating_add(1);
        self.consecutive_bad = self.consecutive_bad.saturating_add(1);
        Outcome::Dropped(reason)
    }

    /// Feed one byte; at most one outcome per call.
    pub fn push_byte(&mut self, byte: u8) -> Option<Outcome> {
        match self.state {
            State::Sync => {
                if byte == SYNC {
                    self.state = State::Len;
                }
                None
            }
            State::Len => {
                if !(MIN_LEN..=MAX_LEN).contains(&byte) {
                    Some(self.drop(DropReason::BadLen(byte)))
                } else {
                    // Payload length = LEN - KIND - SEQ - CRC16.
                    self.want = byte - MIN_LEN;
                    self.state = State::Kind;
                    None
                }
            }
            State::Kind => {
                self.kind = byte;
                self.state = State::Seq;
                None
            }
            State::Seq => {
                self.seq = byte;
                self.pos = 0;
                self.state = if self.want == 0 {
                    State::CrcLo
                } else {
                    State::Payload
                };
                None
            }
            State::Payload => {
                // `pos < want <= 128` by construction; the index is safe.
                self.payload[self.pos] = byte;
                self.pos += 1;
                if self.pos >= self.want as usize {
                    self.state = State::CrcLo;
                }
                None
            }
            State::CrcLo => {
                self.crc_lo = byte;
                self.state = State::CrcHi;
                None
            }
            State::CrcHi => {
                let mut body = [0u8; 2 + MAX_RCP_PAYLOAD];
                body[0] = self.kind;
                body[1] = self.seq;
                body[2..2 + self.want as usize]
                    .copy_from_slice(&self.payload[..self.want as usize]);
                let got = (byte as u16) << 8 | self.crc_lo as u16;
                if crc16(&body[..2 + self.want as usize]) != got {
                    return Some(self.drop(DropReason::BadCrc));
                }
                let frame = Frame {
                    kind: self.kind,
                    seq: self.seq,
                    payload_len: self.want,
                    payload: self.payload,
                };
                self.state = State::Sync;
                self.pos = 0;
                self.consecutive_bad = 0;
                Some(Outcome::Frame(frame))
            }
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn crc_reference_vector() {
        assert_eq!(crc16(b"123456789"), 0x29B1);
        assert_eq!(crc16(&[]), 0xFFFF);
    }

    #[test]
    fn encode_layout_positions() {
        let mut out = [0u8; MAX_FRAME_BYTES];
        let n = encode(0x02, 0x09, &[15], &mut out).unwrap();
        assert_eq!(n, 2 + 2 + 1 + 2);
        assert_eq!(out[0], SYNC);
        assert_eq!(out[1], 5, "LEN = KIND + SEQ + 1 payload + CRC16");
        assert_eq!(out[2], 0x02);
        assert_eq!(out[3], 0x09);
        assert_eq!(out[4], 15);
        let crc = crc16(&[0x02, 0x09, 15]);
        assert_eq!(out[5], (crc & 0xFF) as u8);
        assert_eq!(out[6], (crc >> 8) as u8);
    }

    #[test]
    fn encode_rejects_bounds() {
        let mut out = [0u8; MAX_FRAME_BYTES];
        let big = [0xAA; MAX_RCP_PAYLOAD + 1];
        assert_eq!(encode(1, 0, &big, &mut out), Err(FrameError::TooLong));
        assert_eq!(
            encode(1, 0, &[1, 2, 3], &mut out[..4]),
            Err(FrameError::BufferTooSmall)
        );
    }

    #[test]
    fn decoder_round_trip_with_noise() {
        let mut wire = [0u8; MAX_FRAME_BYTES];
        let n = encode(0x07, 0x41, &[0xDE, 0xAD], &mut wire).unwrap();
        let mut dec = Decoder::new();
        // Line noise ahead of SYNC is skipped, never counted.
        for b in [0x00u8, 0xFF, 0x13] {
            assert_eq!(dec.push_byte(b), None);
        }
        assert_eq!(dec.dropped(), 0);
        let mut got = None;
        for b in &wire[..n] {
            if let Some(o) = dec.push_byte(*b) {
                got = Some(o);
            }
        }
        let collected: Vec<u8> = match got {
            Some(Outcome::Frame(f)) => {
                assert_eq!((f.kind, f.seq), (0x07, 0x41));
                f.payload_bytes().to_vec()
            }
            other => panic!("expected one frame, got {other:?}"),
        };
        assert_eq!(collected, [0xDE, 0xAD]);
    }

    #[test]
    fn decoder_drops_and_rearms() {
        let mut dec = Decoder::new();
        // Bad LEN: SYNC then 0x01.
        assert_eq!(dec.push_byte(SYNC), None);
        assert_eq!(
            dec.push_byte(0x01),
            Some(Outcome::Dropped(DropReason::BadLen(1)))
        );
        assert_eq!(dec.consecutive_bad(), 1);
        // Corrupt CRC: good header, flipped CRC high byte.
        let mut wire = [0u8; MAX_FRAME_BYTES];
        let n = encode(0x01, 0x02, &[0x07], &mut wire).unwrap();
        wire[n - 1] ^= 0xFF;
        let mut last = None;
        for b in &wire[..n] {
            if let Some(o) = dec.push_byte(*b) {
                last = Some(o);
            }
        }
        assert_eq!(last, Some(Outcome::Dropped(DropReason::BadCrc)));
        assert_eq!(dec.consecutive_bad(), 2);
        // A clean frame still decodes and clears the meter.
        let m = encode(0x01, 0x03, &[0x07], &mut wire).unwrap();
        let mut last = None;
        for b in &wire[..m] {
            if let Some(o) = dec.push_byte(*b) {
                last = Some(o);
            }
        }
        assert!(matches!(last, Some(Outcome::Frame(_))));
        assert_eq!(dec.consecutive_bad(), 0);
        assert_eq!(dec.dropped(), 2);
    }
}
