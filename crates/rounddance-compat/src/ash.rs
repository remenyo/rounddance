//! ASH link-control codec for the Ember/EZSP radio-backend path.
//!
//! Paraphrase-level model only (D1, `SCOPE.md` §2): this module names
//! document numbers and clause anchors, never spec text. It pins the
//! link-layer header that wraps EZSP frames on the EmberZNet wire:
//! DATA frames carry a control octet with 3-bit frame/acknowledge
//! numbers plus a retransmit flag, and the link also exchanges
//! ACK-only / NAK / RST / RSTACK / ERROR control frames. All control
//! values below are an adapter-local skeleton namespace — the same
//! precedent the wave-60 EZSP framing (`ember`) and the wave-61 MT
//! framing (`ti`) set — not the NCP command set: pinning real NCP
//! values waits for the transport decision the consolidated goal
//! leaves to the user choice. The codec mechanics (delimiting,
//! length discipline, stuffing, numbering, CRC) are what the vectors
//! pin. Offline only: no serial, no lab hardware.
//!
//! # Framing (adapter-local skeleton shape)
//!
//! ```text
//! FLAG | LEN | ASH_CTRL | payload[..] | CRC16-LE | FLAG
//! 0x7E   1       1         0..=134          2         0x7E
//! ```
//!
//! * `LEN` counts every octet after itself up to and including the
//!   CRC (`ASH_CTRL + payload + 2`), so `3..=137`.
//! * `CRC16` is CRC-16/CCITT (`poly 0x1021`, `init 0xFFFF`) over
//!   `ASH_CTRL | payload` — the shared check `crc16(b"123456789")
//!   == 0x29B1`, reused from [`crate::ember::crc16`].
//! * `FLAG`/`ESC` body octets are stuffed (`ESC` + octet `^`
//!   `ESC_XOR`); the two delimiting `FLAG` octets never are. The
//!   `FLAG`, `ESC`, `ESC_XOR` values are reused from
//!   [`crate::ember`].
//! * DATA frames carry an opaque payload (on the full stack: one
//!   unstuffed EZSP frame body); control frames carry either no body
//!   (ACK-only, NAK, RST) or exactly two version/status octets
//!   (RSTACK, ERROR).
//!
//! # Control octet (adapter-local skeleton shape)
//!
//! ```text
//! DATA: 0 | reTx | ackNum[2:0] | frmNum[2:0]
//! ACK:  1 | 0 | ackNum[2:0] | 0 0 0        (0x80 | ackNum << 3)
//! NAK:  1 | 0 | ackNum[2:0] | 0 0 1        (0x81 | ackNum << 3)
//! RST:  1 | 1 | 0 0 0 0 0 0                (0xC0)
//! RSTACK:                              0xC1 + [version, status]
//! ERROR:                               0xC2 + [version, code]
//! ```
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-COMPAT-11` (ASH link-control codec + ack-window state machine).
//!
//! # Ack-window state machine ([`AshTxWindow`], [`AshRxState`])
//!
//! Codec-only framing above is not enough to move DATA: the sender
//! tracks which 3-bit frame numbers are still unacknowledged
//! ([`AshTxWindow`]: cumulative ACK/NAK intake, `reTx` retransmit
//! cursor, window-full backpressure) and the receiver tracks the
//! next expected frame number ([`AshRxState`]: in-order accept,
//! duplicate re-acknowledge, gap → NAK). Both sides are plain
//! bounded counters — no heap, no panics — and every frame they
//! name still goes through the [`encode_data`]/[`decode`] path
//! above (all-or-nothing), so the vectors pin the wire, not the
//! counters.

use crate::ember::{crc16, ESC, ESC_XOR, FLAG};

/// Largest DATA payload in octets: one maximum unstuffed EZSP frame
/// body (`CTRL + ID + 128 + CRC`) plus one spare octet.
pub const MAX_ASH_DATA: usize = 134;

/// Largest encoded frame: two flags plus a fully-stuffed body.
pub const MAX_ENCODED_ASH: usize = 2 + 2 * (1 + 1 + MAX_ASH_DATA + 2);

/// DATA-frame control bit: this frame is a retransmission.
pub const RETX_BIT: u8 = 0x40;
/// ACK-only control base (`ackNum` shifted into bits 5..3).
pub const ACK_BASE: u8 = 0x80;
/// NAK control base (`ackNum` shifted into bits 5..3).
pub const NAK_BASE: u8 = 0x81;
/// RST control octet (reset the link, no body).
pub const RST_CTRL: u8 = 0xC0;
/// RSTACK control octet (link reset complete, 2-octet body).
pub const RSTACK_CTRL: u8 = 0xC1;
/// ERROR control octet (link error, 2-octet body).
pub const ERROR_CTRL: u8 = 0xC2;

/// 3-bit number mask (frame and acknowledge numbers are `0..=7`).
pub const NUM_MASK: u8 = 0x07;

/// Smallest legal `LEN` (`ASH_CTRL + CRC`, empty payload).
pub const MIN_ASH_LEN: u8 = 3;

/// Link-control errors: encode-side and decode-side alike (decode
/// never panics and holds no allocator state).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AshError {
    /// Payload exceeds [`MAX_ASH_DATA`].
    TooLong,
    /// Output slice fits fewer than the encoded bytes.
    BufferTooSmall,
    /// First octet is not [`FLAG`] (resync by scan, same discipline
    /// as the RCP UART decoder).
    BadFlag,
    /// Closing [`FLAG`] never arrives.
    Truncated,
    /// `ESC` with no following octet.
    BadEscape,
    /// `LEN` disagrees with the delimited body length, names a body
    /// shorter than `ASH_CTRL + CRC`, or disagrees with the control
    /// kind's body contract (ACK/NAK/RST must be empty, RSTACK/ERROR
    /// exactly two octets).
    BadLength,
    /// CRC-16/CCITT mismatch (frame dropped, never decoded).
    BadCrc,
    /// Control octet matches no known link-control shape.
    BadControl,
    /// Frame or acknowledge number exceeds 3 bits on encode.
    BadNumber,
}

impl core::fmt::Display for AshError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::TooLong => "ASH payload exceeds 134 octets",
            Self::BufferTooSmall => "ASH output buffer too small",
            Self::BadFlag => "ASH frame does not start with FLAG",
            Self::Truncated => "ASH frame truncated before closing FLAG",
            Self::BadEscape => "ASH dangling escape octet",
            Self::BadLength => "ASH LEN disagrees with body or control kind",
            Self::BadCrc => "ASH CRC mismatch",
            Self::BadControl => "ASH control octet matches no known shape",
            Self::BadNumber => "ASH frame/acknowledge number exceeds 3 bits",
        };
        f.write_str(s)
    }
}

impl core::error::Error for AshError {}

/// One decoded link-control shape: the DATA numbers when present,
/// the version/status pair for RSTACK/ERROR, nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AshKind {
    /// DATA header: 3-bit frame number, 3-bit acknowledge number,
    /// retransmit flag.
    Data {
        /// This frame's sequence number (`0..=7`).
        frm_num: u8,
        /// Newest in-order frame number received by the sender
        /// (`0..=7`, piggybacked on every DATA frame).
        ack_num: u8,
        /// True when this frame repeats an earlier transmission.
        re_tx: bool,
    },
    /// ACK-only: cumulative acknowledgement of `ack_num`.
    Ack {
        /// Newest in-order frame number received (`0..=7`).
        ack_num: u8,
    },
    /// NAK: `ack_num` is still the newest in-order frame received;
    /// the sender retransmits from `ack_num + 1`.
    Nak {
        /// Newest in-order frame number received (`0..=7`).
        ack_num: u8,
    },
    /// Reset the link (no body).
    Rst,
    /// Reset complete: protocol version plus reset status code.
    Rstack {
        /// Link protocol version.
        version: u8,
        /// Reset status code.
        status: u8,
    },
    /// Link error: protocol version plus error code.
    Error {
        /// Link protocol version.
        version: u8,
        /// Error code.
        code: u8,
    },
}

impl AshKind {
    /// Control octet for this kind (DATA numbers included).
    #[must_use]
    pub const fn control_octet(self) -> u8 {
        match self {
            Self::Data {
                frm_num,
                ack_num,
                re_tx,
            } => {
                (if re_tx { RETX_BIT } else { 0 })
                    | ((ack_num & NUM_MASK) << 3)
                    | (frm_num & NUM_MASK)
            }
            Self::Ack { ack_num } => ACK_BASE | ((ack_num & NUM_MASK) << 3),
            Self::Nak { ack_num } => NAK_BASE | ((ack_num & NUM_MASK) << 3),
            Self::Rst => RST_CTRL,
            Self::Rstack { .. } => RSTACK_CTRL,
            Self::Error { .. } => ERROR_CTRL,
        }
    }

    /// True for the DATA kind (the only kind carrying a payload).
    #[must_use]
    pub const fn is_data(self) -> bool {
        matches!(self, Self::Data { .. })
    }
}

/// Decode one control octet into its link-control shape.
///
/// # Errors
///
/// [`AshError::BadControl`] when the octet matches no known shape.
pub const fn decode_control(octet: u8) -> Result<AshKind, AshError> {
    if octet & 0x80 == 0 {
        return Ok(AshKind::Data {
            frm_num: octet & NUM_MASK,
            ack_num: (octet >> 3) & NUM_MASK,
            re_tx: octet & RETX_BIT != 0,
        });
    }
    if octet == RST_CTRL {
        return Ok(AshKind::Rst);
    }
    if octet == RSTACK_CTRL {
        // RSTACK carries its version/status in the two body octets;
        // the shape alone decodes with placeholder zeros and the
        // full-frame decoder fills them in.
        return Ok(AshKind::Rstack {
            version: 0,
            status: 0,
        });
    }
    if octet == ERROR_CTRL {
        return Ok(AshKind::Error {
            version: 0,
            code: 0,
        });
    }
    if octet & 0xC0 == 0x80 {
        let ack_num = (octet >> 3) & NUM_MASK;
        match octet & NUM_MASK {
            0 => {
                return Ok(AshKind::Ack { ack_num });
            }
            1 => {
                return Ok(AshKind::Nak { ack_num });
            }
            _ => {}
        }
    }
    Err(AshError::BadControl)
}

/// One decoded ASH frame: control shape plus the DATA payload (other
/// kinds carry no payload; RSTACK/ERROR version and status live in
/// the returned [`AshKind`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AshFrame {
    /// Link-control shape of this frame.
    pub kind: AshKind,
    /// Live payload length (nonzero only for DATA).
    pub payload_len: u8,
    /// Payload bytes (first `payload_len` live).
    pub payload: [u8; MAX_ASH_DATA],
}

impl AshFrame {
    /// Live payload bytes (empty for every non-DATA kind).
    #[must_use]
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }
}

/// Advance a 3-bit link number, wrapping `7 -> 0`.
#[must_use]
pub const fn next_num(n: u8) -> u8 {
    (n + 1) & NUM_MASK
}

/// Pack a DATA control octet, checking the 3-bit numbers.
///
/// # Errors
///
/// [`AshError::BadNumber`] when `frm_num` or `ack_num` exceeds 7.
pub const fn pack_data_header(frm_num: u8, ack_num: u8, re_tx: bool) -> Result<u8, AshError> {
    if frm_num > NUM_MASK || ack_num > NUM_MASK {
        return Err(AshError::BadNumber);
    }
    Ok(AshKind::Data {
        frm_num,
        ack_num,
        re_tx,
    }
    .control_octet())
}

/// Encode one frame with `control` and `body` (`ASH_CTRL | payload`)
/// into `out`; returns bytes written.
///
/// # Errors
///
/// [`AshError::TooLong`] when the payload exceeds
/// [`MAX_ASH_DATA`], [`AshError::BufferTooSmall`] when `out` is
/// short (prefix unwritten — encoding is all-or-nothing).
fn encode_raw(control: u8, body: &[u8], out: &mut [u8]) -> Result<usize, AshError> {
    if body.len() > MAX_ASH_DATA {
        return Err(AshError::TooLong);
    }
    let body_len = 1 + body.len() + 2;
    let crc = crc16_raw(control, body).to_le_bytes();
    // Stage the unescaped body after the flags, then stuff in place.
    // `staged` holds `LEN | ASH_CTRL | payload | CRC`.
    let mut staged = [0u8; 1 + 1 + MAX_ASH_DATA + 2];
    staged[0] = body_len as u8;
    staged[1] = control;
    staged[2..2 + body.len()].copy_from_slice(body);
    staged[2 + body.len()] = crc[0];
    staged[2 + body.len() + 1] = crc[1];
    let staged_len = 1 + body_len;

    // Stuff into a bounded temp first: unlike the EZSP-frame layer
    // (whose control octet can never need stuffing), an ASH control
    // octet or LEN byte may itself be FLAG/ESC, so the check below —
    // not an upfront estimate — is what keeps indexing panic-free.
    // `out` stays untouched when it cannot hold the frame
    // (all-or-nothing, same contract as the EZSP-frame encoder).
    let mut tmp = [0u8; MAX_ENCODED_ASH];
    tmp[0] = FLAG;
    let mut w = 1;
    let mut i = 0;
    while i < staged_len {
        let b = staged[i];
        if b == FLAG || b == ESC {
            if w + 2 > tmp.len() {
                return Err(AshError::BufferTooSmall);
            }
            tmp[w] = ESC;
            tmp[w + 1] = b ^ ESC_XOR;
            w += 2;
        } else {
            if w + 1 > tmp.len() {
                return Err(AshError::BufferTooSmall);
            }
            tmp[w] = b;
            w += 1;
        }
        i += 1;
    }
    if w + 1 > tmp.len() {
        return Err(AshError::BufferTooSmall);
    }
    tmp[w] = FLAG;
    let total = w + 1;
    if out.len() < total {
        return Err(AshError::BufferTooSmall);
    }
    out[..total].copy_from_slice(&tmp[..total]);
    Ok(total)
}

/// CRC over the unescaped `ASH_CTRL | payload` body.
fn crc16_raw(control: u8, body: &[u8]) -> u16 {
    let mut chained = [0u8; 1 + MAX_ASH_DATA];
    chained[0] = control;
    chained[1..1 + body.len()].copy_from_slice(body);
    crc16(&chained[..1 + body.len()])
}

/// Encode one DATA frame; returns bytes written.
///
/// # Errors
///
/// [`AshError::BadNumber`] on out-of-range numbers,
/// [`AshError::TooLong`] on oversize payloads,
/// [`AshError::BufferTooSmall`] when `out` is short.
pub fn encode_data(
    frm_num: u8,
    ack_num: u8,
    re_tx: bool,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, AshError> {
    let control = pack_data_header(frm_num, ack_num, re_tx)?;
    encode_raw(control, payload, out)
}

/// Encode one ACK-only frame; returns bytes written.
///
/// # Errors
///
/// [`AshError::BadNumber`] on out-of-range `ack_num`,
/// [`AshError::BufferTooSmall`] when `out` is short.
pub fn encode_ack(ack_num: u8, out: &mut [u8]) -> Result<usize, AshError> {
    if ack_num > NUM_MASK {
        return Err(AshError::BadNumber);
    }
    encode_raw(AshKind::Ack { ack_num }.control_octet(), &[], out)
}

/// Encode one NAK frame; returns bytes written.
///
/// # Errors
///
/// [`AshError::BadNumber`] on out-of-range `ack_num`,
/// [`AshError::BufferTooSmall`] when `out` is short.
pub fn encode_nak(ack_num: u8, out: &mut [u8]) -> Result<usize, AshError> {
    if ack_num > NUM_MASK {
        return Err(AshError::BadNumber);
    }
    encode_raw(AshKind::Nak { ack_num }.control_octet(), &[], out)
}

/// Encode one RST frame; returns bytes written.
///
/// # Errors
///
/// [`AshError::BufferTooSmall`] when `out` is short.
pub fn encode_rst(out: &mut [u8]) -> Result<usize, AshError> {
    encode_raw(RST_CTRL, &[], out)
}

/// Encode one RSTACK frame; returns bytes written.
///
/// # Errors
///
/// [`AshError::BufferTooSmall`] when `out` is short.
pub fn encode_rstack(version: u8, status: u8, out: &mut [u8]) -> Result<usize, AshError> {
    encode_raw(RSTACK_CTRL, &[version, status], out)
}

/// Encode one ERROR frame; returns bytes written.
///
/// # Errors
///
/// [`AshError::BufferTooSmall`] when `out` is short.
pub fn encode_error(version: u8, code: u8, out: &mut [u8]) -> Result<usize, AshError> {
    encode_raw(ERROR_CTRL, &[version, code], out)
}

/// Decode the first FLAG-delimited frame in `buf`; returns the frame
/// plus consumed bytes (through the closing `FLAG`).
///
/// # Errors
///
/// [`AshError::BadFlag`] when `buf` does not start with [`FLAG`],
/// [`AshError::Truncated`] when the closing flag never arrives,
/// [`AshError::BadEscape`] on a dangling [`ESC`],
/// [`AshError::BadLength`] on a `LEN`/body mismatch or a control
/// kind with an illegal body length, [`AshError::BadCrc`] on a
/// checksum mismatch, [`AshError::BadControl`] on an unknown
/// control octet.
pub fn decode(buf: &[u8]) -> Result<(AshFrame, usize), AshError> {
    if buf.is_empty() || buf[0] != FLAG {
        return Err(if buf.is_empty() {
            AshError::Truncated
        } else {
            AshError::BadFlag
        });
    }
    let mut end = None;
    let mut i = 1;
    while i < buf.len() {
        if buf[i] == FLAG {
            end = Some(i);
            break;
        }
        i += 1;
    }
    let Some(end) = end else {
        return Err(AshError::Truncated);
    };
    // Unstuff the body between the flags.
    let mut body = [0u8; 1 + 1 + MAX_ASH_DATA + 2];
    let mut w = 0usize;
    let mut j = 1;
    while j < end {
        let b = buf[j];
        if b == ESC {
            j += 1;
            if j >= end {
                return Err(AshError::BadEscape);
            }
            if w >= body.len() {
                return Err(AshError::BadLength);
            }
            body[w] = buf[j] ^ ESC_XOR;
            w += 1;
        } else {
            if w >= body.len() {
                return Err(AshError::BadLength);
            }
            body[w] = b;
            w += 1;
        }
        j += 1;
    }
    if w < 1 || body[0] as usize != w - 1 {
        return Err(AshError::BadLength);
    }
    if w < 1 + 1 + 2 {
        return Err(AshError::BadLength);
    }
    let control = body[1];
    let kind = decode_control(control)?;
    let payload_len = w - (1 + 1 + 2);
    // Control-kind body contract: only DATA carries a free-length
    // payload; RSTACK/ERROR carry exactly two version/status octets.
    match kind {
        AshKind::Data { .. } => {}
        AshKind::Rstack { .. } | AshKind::Error { .. } => {
            if payload_len != 2 {
                return Err(AshError::BadLength);
            }
        }
        AshKind::Ack { .. } | AshKind::Nak { .. } | AshKind::Rst => {
            if payload_len != 0 {
                return Err(AshError::BadLength);
            }
        }
    }
    let crc_wire = u16::from_le_bytes([body[w - 2], body[w - 1]]);
    let crc_calc = {
        let mut c: u16 = 0xFFFF;
        let mut k = 1;
        while k < w - 2 {
            c ^= (body[k] as u16) << 8;
            let mut b = 0;
            while b < 8 {
                if c & 0x8000 != 0 {
                    c = (c << 1) ^ 0x1021;
                } else {
                    c <<= 1;
                }
                b += 1;
            }
            k += 1;
        }
        c
    };
    if crc_calc != crc_wire {
        return Err(AshError::BadCrc);
    }
    let kind = match kind {
        AshKind::Rstack { .. } => AshKind::Rstack {
            version: body[2],
            status: body[3],
        },
        AshKind::Error { .. } => AshKind::Error {
            version: body[2],
            code: body[3],
        },
        other => other,
    };
    let mut frame = AshFrame {
        kind,
        payload_len: payload_len as u8,
        payload: [0u8; MAX_ASH_DATA],
    };
    if matches!(kind, AshKind::Data { .. }) {
        frame.payload[..payload_len].copy_from_slice(&body[2..2 + payload_len]);
    }
    Ok((frame, end + 1))
}

/// Largest count of DATA frames the sender may leave unacknowledged
/// at once: with 3-bit sequence numbers one number must stay free so
/// a fresh frame number never aliases an outstanding one.
pub const ASH_TX_WINDOW: u8 = 7;

/// Where a retransmission run starts and how many frames it covers.
/// Frame numbers run `start, start+1, ...` modulo 8; every frame in
/// the run re-encodes with the retransmit flag set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetxDecision {
    /// First frame number to retransmit (`0..=7`).
    pub start_frm: u8,
    /// Count of frames to retransmit (`0` when nothing is owed).
    pub count: u8,
}

impl RetxDecision {
    /// True when at least one frame is owed a retransmission.
    #[must_use]
    pub const fn needed(self) -> bool {
        self.count > 0
    }
}

/// Sender-side ack-window bookkeeping: which frame numbers are still
/// owed an acknowledgement. Numbers only — payload storage stays
/// with the caller; every (re)transmission still goes through
/// [`encode_data`], with `re_tx = false` for fresh frames and
/// `re_tx = true` for frames inside a [`RetxDecision`] run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AshTxWindow {
    /// Oldest unacknowledged frame number (valid only while
    /// `outstanding > 0`).
    base: u8,
    /// Next fresh frame number to hand out.
    next_frm: u8,
    /// Count of unacknowledged frames (`0..=ASH_TX_WINDOW`).
    outstanding: u8,
}

impl AshTxWindow {
    /// Reset link: no frame owed, both cursors at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            base: 0,
            next_frm: 0,
            outstanding: 0,
        }
    }

    /// Oldest unacknowledged frame number (`base`; meaningful only
    /// while [`Self::outstanding`] is nonzero).
    #[must_use]
    pub const fn base(self) -> u8 {
        self.base
    }

    /// Next fresh frame number [`Self::try_allocate`] will hand out.
    #[must_use]
    pub const fn next_frm(self) -> u8 {
        self.next_frm
    }

    /// Count of frames still owed an acknowledgement.
    #[must_use]
    pub const fn outstanding(self) -> u8 {
        self.outstanding
    }

    /// True while another fresh frame may be allocated.
    #[must_use]
    pub const fn can_send(self) -> bool {
        self.outstanding < ASH_TX_WINDOW
    }

    /// True when the window is exhausted: the sender must stop
    /// allocating fresh frames until an ACK/NAK frees a slot
    /// (backpressure signal).
    #[must_use]
    pub const fn window_full(self) -> bool {
        self.outstanding >= ASH_TX_WINDOW
    }

    /// Allocate a fresh frame number (`re_tx = false` on the wire),
    /// or `None` when the window is full (backpressure — send
    /// nothing, wait for an ACK/NAK).
    pub fn try_allocate(&mut self) -> Option<u8> {
        if self.window_full() {
            return None;
        }
        let frm = self.next_frm;
        self.next_frm = next_num(self.next_frm);
        self.outstanding += 1;
        Some(frm)
    }

    /// Cumulative ACK intake: every outstanding frame numbered
    /// `base..=ack_num` (mod 8) is retired. Returns how many frames
    /// were newly acknowledged (`0` for a duplicate or stale ACK
    /// that retires nothing — never an error).
    ///
    /// # Errors
    ///
    /// [`AshError::BadNumber`] when `ack_num` exceeds 3 bits.
    pub fn on_ack(&mut self, ack_num: u8) -> Result<u8, AshError> {
        if ack_num > NUM_MASK {
            return Err(AshError::BadNumber);
        }
        // Distance from `base` through `ack_num` inclusive, mod 8
        // (`1..=8`): the frames this ACK would retire.
        let span = (ack_num.wrapping_add(8).wrapping_sub(self.base) & NUM_MASK) + 1;
        if span > self.outstanding {
            // Names frames already retired or never sent: stale or
            // duplicate ACK, retires nothing.
            return Ok(0);
        }
        self.base = next_num(ack_num);
        self.outstanding -= span;
        Ok(span)
    }

    /// Current retransmit run: from `base` over every outstanding
    /// frame (`count == 0` when nothing is owed).
    #[must_use]
    pub const fn retransmit_pending(self) -> RetxDecision {
        RetxDecision {
            start_frm: self.base,
            count: self.outstanding,
        }
    }

    /// NAK intake: first retires whatever the piggybacked `ack_num`
    /// cumulatively acknowledges (same rule as [`Self::on_ack`]),
    /// then reports the retransmit run starting at
    /// `ack_num + 1` over the frames still outstanding. Every frame
    /// in the run re-encodes with the retransmit flag set.
    ///
    /// # Errors
    ///
    /// [`AshError::BadNumber`] when `ack_num` exceeds 3 bits.
    pub fn on_nak(&mut self, ack_num: u8) -> Result<RetxDecision, AshError> {
        self.on_ack(ack_num)?;
        Ok(self.retransmit_pending())
    }
}

impl Default for AshTxWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// What the receiver owes the sender after one DATA frame number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxOutcome {
    /// In-order frame: advance and (piggyback or standalone) ACK it.
    Accept,
    /// Repeat of the newest accepted frame: re-ACK, deliver nothing.
    Duplicate,
    /// Anything else: a gap — NAK with [`AshRxState::ack_num`].
    Gap,
}

/// Receiver-side frame-number bookkeeping: the next expected DATA
/// frame number plus the newest in-order number received (the value
/// every piggybacked/standalone ACK or NAK carries).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AshRxState {
    /// Next in-order DATA frame number.
    expected: u8,
    /// Newest in-order DATA frame number received (the ACK number).
    ack: u8,
}

impl AshRxState {
    /// Reset link: expect frame 0, acknowledge number 0.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            expected: 0,
            ack: 0,
        }
    }

    /// Next in-order DATA frame number.
    #[must_use]
    pub const fn expected(self) -> u8 {
        self.expected
    }

    /// Newest in-order DATA frame number received: the `ack_num` for
    /// the next piggybacked DATA header, ACK-only, or NAK frame.
    #[must_use]
    pub const fn ack_num(self) -> u8 {
        self.ack
    }

    /// Reset both cursors (link reset).
    pub fn reset(&mut self) {
        self.expected = 0;
        self.ack = 0;
    }

    /// File one received DATA frame number.
    ///
    /// # Errors
    ///
    /// [`AshError::BadNumber`] when `frm_num` exceeds 3 bits.
    pub fn on_data(&mut self, frm_num: u8) -> Result<RxOutcome, AshError> {
        if frm_num > NUM_MASK {
            return Err(AshError::BadNumber);
        }
        if frm_num == self.expected {
            self.ack = frm_num;
            self.expected = next_num(self.expected);
            Ok(RxOutcome::Accept)
        } else if frm_num == self.ack && self.expected != self.ack {
            // Repeat of the newest accepted frame (the `expected !=
            // ack` guard keeps the very first frame 0 from reading
            // as its own duplicate before anything arrived).
            Ok(RxOutcome::Duplicate)
        } else {
            Ok(RxOutcome::Gap)
        }
    }
}

impl Default for AshRxState {
    fn default() -> Self {
        Self::new()
    }
}
