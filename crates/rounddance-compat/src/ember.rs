//! Ember/EZSP radio-backend skeleton: framing codec plus the
//! [`EmberAdapter`] [`MacDataSap`] mapping over a mock transport.
//!
//! Paraphrase-level model only (D1, `SCOPE.md` §2): this module names
//! document numbers and clause anchors, never spec text. The Ember
//! side of the consolidated-goal extension ("EmberZNet/TI sticks as
//! radio backends") starts here: the MG21/MG24 lab units run
//! EmberZNet as lab test counterparts and are never touched — all
//! proof below is offline over [`MockEzspTransport`], no serial, no
//! hardware.
//!
//! # Framing (adapter-local skeleton shape)
//!
//! Each transfer is one FLAG-delimited frame:
//!
//! ```text
//! FLAG | LEN | CTRL | ID LO | ID HI | payload[..] | CRC16-LE | FLAG
//! 0x7E   1      1      1         1      0..=128        2          0x7E
//! ```
//!
//! * `LEN` counts every octet after itself up to and including the
//!   CRC (`CTRL + ID + payload + 2`), so `5..=133`.
//! * `CTRL` carries the 3-bit sequence number (`CTRL_SEQ_MASK`); the
//!   NCP sets [`CTRL_CALLBACK`] on stack callbacks so responses and
//!   callbacks never alias.
//! * `CRC16` is CRC-16/CCITT (`poly 0x1021`, `init 0xFFFF`) over
//!   `CTRL | ID | payload` — the same check the RCP UART frame
//!   (`rounddance-rcp::frame`) pins (`crc16(b"123456789") == 0x29B1`).
//! * `FLAG`/`ESC` body octets are stuffed (`ESC` + octet `^`
//!   [`ESC_XOR`]); the two delimiting `FLAG` octets never are.
//!
//! Command identifiers below are an adapter-local skeleton namespace
//! (`CMD_*` host-to-NCP, `EVT_*` NCP-to-host with the callback bit),
//! not the NCP command set: pinning real NCP command values waits for
//! the transport decision the consolidated goal leaves to the user
//! choice. The codec mechanics (delimiting, escaping, sequencing,
//! CRC) are what the vectors pin.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-COMPAT-05` (codec), `RD-COMPAT-06` (SAP mapping),
//! `RD-COMPAT-07` (join-flow parity with the existing MAC codec).

use rounddance_mac_sap::{
    AddrMode, Channel, ExtAddr, FramePayload, HasCapabilities, MacAddress, MacCapabilities,
    MacDataSap, MacError, MacMgmtSap, PanId, RxIndication, ShortAddr, TxConfirm, TxHandle,
    TxRequest, TxStatus, MAX_MSDU_LEN,
};

/// Frame delimiter (also the closing octet).
pub const FLAG: u8 = 0x7E;
/// Escape octet for stuffed body bytes.
pub const ESC: u8 = 0x7D;
/// XOR mask applied to a stuffed octet.
pub const ESC_XOR: u8 = 0x20;

/// Sequence-number bits in the control octet (3-bit, `0..=7`).
pub const CTRL_SEQ_MASK: u8 = 0x07;
/// Control bit marking an NCP stack callback (vs a command echo).
pub const CTRL_CALLBACK: u8 = 0x80;

/// Largest command/callback payload in octets: one 15.4 PSDU plus
/// the one options octet the send command prepends.
pub const MAX_EZSP_PAYLOAD: usize = 128;

/// Largest encoded frame: two flags plus a fully-stuffed body.
pub const MAX_ENCODED_FRAME: usize = 2 + 2 * (1 + 2 + MAX_EZSP_PAYLOAD + 2);

/// Skeleton command: host asks the NCP to transmit. Payload is
/// `dst LE | options | MSDU`, options bit 0 = ACK requested.
pub const CMD_DATA_SEND: u16 = 0x0001;
/// Skeleton callback: the NCP reports a transmit outcome. Payload
/// is `seq | status` ([`STATUS_DELIVERED`] / [`STATUS_NO_ACK`]).
pub const EVT_TX_CONFIRM: u16 = 0x0081;
/// Skeleton callback: the NCP delivers a received frame. Payload is
/// `src LE | lqi | MSDU`.
pub const EVT_DATA_RECEIVE: u16 = 0x0082;

/// Confirm status: the frame was delivered (ACK received when asked).
pub const STATUS_DELIVERED: u8 = 0x00;
/// Confirm status: no acknowledgement within the NCP retry budget.
pub const STATUS_NO_ACK: u8 = 0x01;

/// Smallest legal `LEN` (`CTRL + ID + CRC`, empty payload).
pub const MIN_LEN: u8 = 5;

/// Framing errors: encode-side and decode-side alike (decode never
/// panics and holds no allocator state).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EzspError {
    /// Payload exceeds [`MAX_EZSP_PAYLOAD`].
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
    /// `LEN` disagrees with the delimited body length, or names a
    /// body shorter than `CTRL + ID + CRC`.
    BadLength,
    /// CRC-16/CCITT mismatch (frame dropped, never decoded).
    BadCrc,
}

impl core::fmt::Display for EzspError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::TooLong => "EZSP payload exceeds 128 octets",
            Self::BufferTooSmall => "EZSP output buffer too small",
            Self::BadFlag => "EZSP frame does not start with FLAG",
            Self::Truncated => "EZSP frame truncated before closing FLAG",
            Self::BadEscape => "EZSP dangling escape octet",
            Self::BadLength => "EZSP LEN disagrees with body length",
            Self::BadCrc => "EZSP CRC mismatch",
        };
        f.write_str(s)
    }
}

impl core::error::Error for EzspError {}

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

/// One decoded EZSP frame: control + command id + bounded payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EzspFrame {
    /// Control octet (sequence in [`CTRL_SEQ_MASK`], callback bit in
    /// [`CTRL_CALLBACK`]).
    pub control: u8,
    /// Command/callback identifier.
    pub frame_id: u16,
    /// Live payload length.
    pub payload_len: u8,
    /// Payload bytes (first `payload_len` live).
    pub payload: [u8; MAX_EZSP_PAYLOAD],
}

impl EzspFrame {
    /// 3-bit sequence number of this frame.
    #[must_use]
    pub const fn seq(self) -> u8 {
        self.control & CTRL_SEQ_MASK
    }

    /// True when the NCP marked this frame a stack callback.
    #[must_use]
    pub const fn is_callback(self) -> bool {
        self.control & CTRL_CALLBACK != 0
    }

    /// Live payload bytes.
    #[must_use]
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }
}

/// Advance a 3-bit sequence number, wrapping `7 -> 0`.
#[must_use]
pub const fn next_seq(seq: u8) -> u8 {
    (seq + 1) & CTRL_SEQ_MASK
}

/// Encode one frame with `control` into `out`; returns bytes
/// written.
///
/// # Errors
///
/// [`EzspError::TooLong`] when the payload exceeds
/// [`MAX_EZSP_PAYLOAD`], [`EzspError::BufferTooSmall`] when `out` is
/// short (prefix unwritten — encoding is all-or-nothing).
pub fn encode_with_control(
    control: u8,
    frame_id: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, EzspError> {
    if payload.len() > MAX_EZSP_PAYLOAD {
        return Err(EzspError::TooLong);
    }
    let body_len = 1 + 2 + payload.len() + 2;
    let stuffed_worst = 2 * body_len;
    if out.len() < 2 + stuffed_worst {
        return Err(EzspError::BufferTooSmall);
    }
    let id = frame_id.to_le_bytes();
    let crc = crc16_body(control, id, payload).to_le_bytes();
    // Stage the unescaped body after the flags, then stuff in place.
    // `staged` holds `LEN | CTRL | ID | payload | CRC`.
    let mut staged = [0u8; 1 + 1 + 2 + MAX_EZSP_PAYLOAD + 2];
    staged[0] = body_len as u8;
    staged[1] = control;
    staged[2] = id[0];
    staged[3] = id[1];
    staged[4..4 + payload.len()].copy_from_slice(payload);
    staged[4 + payload.len()] = crc[0];
    staged[4 + payload.len() + 1] = crc[1];
    let staged_len = 1 + body_len;

    out[0] = FLAG;
    let mut w = 1;
    let mut i = 0;
    while i < staged_len {
        let b = staged[i];
        if b == FLAG || b == ESC {
            out[w] = ESC;
            out[w + 1] = b ^ ESC_XOR;
            w += 2;
        } else {
            out[w] = b;
            w += 1;
        }
        i += 1;
    }
    out[w] = FLAG;
    Ok(w + 1)
}

/// CRC over the unescaped `CTRL | ID | payload` body.
fn crc16_body(control: u8, id: [u8; 2], payload: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    let mut feed = |b: u8| {
        crc ^= (b as u16) << 8;
        let mut i = 0;
        while i < 8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
            i += 1;
        }
    };
    feed(control);
    feed(id[0]);
    feed(id[1]);
    let mut i = 0;
    while i < payload.len() {
        feed(payload[i]);
        i += 1;
    }
    crc
}

/// Encode one host-to-NCP command frame (sequence in `CTRL`, no
/// callback bit); returns bytes written.
///
/// # Errors
///
/// See [`encode_with_control`].
pub fn encode(seq: u8, frame_id: u16, payload: &[u8], out: &mut [u8]) -> Result<usize, EzspError> {
    encode_with_control(seq & CTRL_SEQ_MASK, frame_id, payload, out)
}

/// Decode the first FLAG-delimited frame in `buf`; returns the frame
/// plus consumed bytes (through the closing `FLAG`).
///
/// # Errors
///
/// [`EzspError::BadFlag`] when `buf` does not start with [`FLAG`],
/// [`EzspError::Truncated`] when the closing flag never arrives,
/// [`EzspError::BadEscape`] on a dangling [`ESC`],
/// [`EzspError::BadLength`] on a `LEN`/body mismatch, and
/// [`EzspError::BadCrc`] on a checksum mismatch.
pub fn decode(buf: &[u8]) -> Result<(EzspFrame, usize), EzspError> {
    if buf.is_empty() || buf[0] != FLAG {
        return Err(if buf.is_empty() {
            EzspError::Truncated
        } else {
            EzspError::BadFlag
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
        return Err(EzspError::Truncated);
    };
    // Unstuff the body between the flags.
    let mut body = [0u8; 1 + 1 + 2 + MAX_EZSP_PAYLOAD + 2];
    let mut w = 0usize;
    let mut j = 1;
    while j < end {
        let b = buf[j];
        if b == ESC {
            j += 1;
            if j >= end {
                return Err(EzspError::BadEscape);
            }
            if w >= body.len() {
                return Err(EzspError::BadLength);
            }
            body[w] = buf[j] ^ ESC_XOR;
            w += 1;
        } else {
            if w >= body.len() {
                return Err(EzspError::BadLength);
            }
            body[w] = b;
            w += 1;
        }
        j += 1;
    }
    if w < 1 || body[0] as usize != w - 1 {
        return Err(EzspError::BadLength);
    }
    if w < 1 + 1 + 2 + 2 {
        return Err(EzspError::BadLength);
    }
    let control = body[1];
    let frame_id = u16::from_le_bytes([body[2], body[3]]);
    let payload_len = w - (1 + 1 + 2 + 2);
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
        return Err(EzspError::BadCrc);
    }
    let mut frame = EzspFrame {
        control,
        frame_id,
        payload_len: payload_len as u8,
        payload: [0u8; MAX_EZSP_PAYLOAD],
    };
    frame.payload[..payload_len].copy_from_slice(&body[4..4 + payload_len]);
    Ok((frame, end + 1))
}

/// Mock NCP transport: records every encoded host-to-NCP frame and
/// replays scripted NCP-to-host bytes. No serial, no hardware — the
/// offline double for the EZSP framing and the SAP mapping alike.
#[derive(Clone, Copy, Debug)]
pub struct MockEzspTransport {
    tx_log: [[u8; MAX_ENCODED_FRAME]; 8],
    tx_lens: [usize; 8],
    tx_count: usize,
    rx_queue: [[u8; MAX_ENCODED_FRAME]; 8],
    rx_lens: [usize; 8],
    rx_len: usize,
    rx_pos: usize,
}

/// Recorded-transport depth (matches the adapter slot fan-out).
pub const TRANSPORT_DEPTH: usize = 8;

impl Default for MockEzspTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockEzspTransport {
    /// Empty transport: nothing recorded, nothing scripted.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tx_log: [[0u8; MAX_ENCODED_FRAME]; 8],
            tx_lens: [0; 8],
            tx_count: 0,
            rx_queue: [[0u8; MAX_ENCODED_FRAME]; 8],
            rx_lens: [0; 8],
            rx_len: 0,
            rx_pos: 0,
        }
    }

    /// Record one transmitted frame; false (dropped) when the log is
    /// full — the adapter treats that as backpressure, never loss.
    pub fn push_tx(&mut self, bytes: &[u8]) -> bool {
        if self.tx_count >= TRANSPORT_DEPTH || bytes.len() > MAX_ENCODED_FRAME {
            return false;
        }
        self.tx_log[self.tx_count][..bytes.len()].copy_from_slice(bytes);
        self.tx_lens[self.tx_count] = bytes.len();
        self.tx_count += 1;
        true
    }

    /// Number of recorded transmitted frames.
    #[must_use]
    pub const fn tx_count(self) -> usize {
        self.tx_count
    }

    /// Recorded transmitted frame `i`, when present.
    #[must_use]
    pub fn tx_frame(&self, i: usize) -> Option<&[u8]> {
        if i < self.tx_count {
            Some(&self.tx_log[i][..self.tx_lens[i]])
        } else {
            None
        }
    }

    /// Script one inbound NCP frame; false (dropped) when the queue
    /// is full.
    pub fn inject_rx(&mut self, bytes: &[u8]) -> bool {
        if self.rx_len >= TRANSPORT_DEPTH || bytes.len() > MAX_ENCODED_FRAME {
            return false;
        }
        let at = (self.rx_pos + self.rx_len) % TRANSPORT_DEPTH;
        self.rx_queue[at][..bytes.len()].copy_from_slice(bytes);
        self.rx_lens[at] = bytes.len();
        self.rx_len += 1;
        true
    }

    /// Take the oldest scripted inbound frame, if any.
    pub fn pop_rx(&mut self) -> Option<([u8; MAX_ENCODED_FRAME], usize)> {
        if self.rx_len == 0 {
            return None;
        }
        let at = self.rx_pos;
        self.rx_pos = (self.rx_pos + 1) % TRANSPORT_DEPTH;
        self.rx_len -= 1;
        Some((self.rx_queue[at], self.rx_lens[at]))
    }

    /// Build one NCP callback frame (callback bit set) for tests and
    /// harnesses scripting the NCP side.
    #[must_use]
    pub fn callback_frame(
        &self,
        frame_id: u16,
        payload: &[u8],
    ) -> ([u8; MAX_ENCODED_FRAME], usize) {
        let mut out = [0u8; MAX_ENCODED_FRAME];
        let n = encode_with_control(CTRL_CALLBACK, frame_id, payload, &mut out).unwrap_or(0);
        (out, n)
    }
}

/// Outstanding Ember transaction (preallocated, never resized — D5).
#[derive(Clone, Copy, Debug)]
struct EmberSlot {
    handle: TxHandle,
    seq: u8,
}

/// Outstanding PAN transactions (same depth as the existing MAC
/// codec so backpressure decisions coincide).
pub const EMBER_TX_SLOTS: usize = 4;
/// Pending-confirm queue depth.
const EMBER_CONFIRM_DEPTH: usize = 8;
/// Pending-indication queue depth.
const EMBER_INDICATION_DEPTH: usize = 8;

/// [`MacDataSap`] over an Ember/EZSP NCP, offline-skeleton form: the
/// wire below is the [`MockEzspTransport`], so every SAP decision is
/// provable on-host. The mapping mirrors the existing short-short
/// MAC codec decision for decision: short addresses only, explicit
/// backpressure, cancel revokes queued transactions as
/// [`TxStatus::Cancelled`], confirms and indications arrive through
/// the same poll contract.
#[derive(Clone, Debug)]
pub struct EmberAdapter {
    transport: MockEzspTransport,
    pan: PanId,
    short: ShortAddr,
    ext: [u8; 8],
    channel: u8,
    seq: u8,
    next_handle: u32,
    slots: [Option<EmberSlot>; EMBER_TX_SLOTS],
    confirms: [Option<TxConfirm>; EMBER_CONFIRM_DEPTH],
    confirms_len: usize,
    indications: [Option<EmberIndication>; EMBER_INDICATION_DEPTH],
    indications_len: usize,
    rx_dropped: u32,
}

/// Owned indication slot (the SAP hands out owned values, so the
/// queue stores them directly).
type EmberIndication = RxIndication;

impl EmberAdapter {
    /// Unprovisioned adapter on the default channel.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            transport: MockEzspTransport::new(),
            pan: 0xC601,
            short: 0x0002,
            ext: [0; 8],
            channel: 15,
            seq: 0,
            next_handle: 0,
            slots: [None; EMBER_TX_SLOTS],
            confirms: [None; EMBER_CONFIRM_DEPTH],
            confirms_len: 0,
            indications: [None, None, None, None, None, None, None, None],
            indications_len: 0,
            rx_dropped: 0,
        }
    }

    /// Borrow the mock transport (frame inspection escape for
    /// tests and harnesses).
    #[must_use]
    pub const fn transport(&self) -> &MockEzspTransport {
        &self.transport
    }

    /// Count of inbound NCP frames dropped (unparseable, unknown id,
    /// or full queue) — visible, never silent.
    #[must_use]
    pub const fn rx_dropped(self) -> u32 {
        self.rx_dropped
    }

    /// Script one NCP transmit-confirm for the `n`th recorded send
    /// (`seq` taken from that send): the offline stand-in for the
    /// NCP answering `CMD_DATA_SEND`.
    pub fn inject_ncp_confirm(&mut self, tx_index: usize, status: u8) {
        let Some(raw) = self.transport.tx_frame(tx_index) else {
            return;
        };
        let Ok((sent, _)) = decode(raw) else {
            return;
        };
        let (cb, n) = self
            .transport
            .callback_frame(EVT_TX_CONFIRM, &[sent.seq(), status]);
        let _ = self.transport.inject_rx(&cb[..n]);
    }

    /// Script one NCP receive callback: the offline stand-in for the
    /// NCP delivering an air frame.
    pub fn inject_ncp_receive(&mut self, src: ShortAddr, lqi: u8, msdu: &[u8]) {
        let mut payload = [0u8; 2 + 1 + MAX_MSDU_LEN];
        payload[..2].copy_from_slice(&src.to_le_bytes());
        payload[2] = lqi;
        let n = msdu.len().min(MAX_MSDU_LEN);
        payload[3..3 + n].copy_from_slice(&msdu[..n]);
        let (cb, m) = self
            .transport
            .callback_frame(EVT_DATA_RECEIVE, &payload[..3 + n]);
        let _ = self.transport.inject_rx(&cb[..m]);
    }

    fn take_handle(&mut self) -> TxHandle {
        let h = TxHandle(self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1);
        h
    }

    fn take_seq(&mut self) -> u8 {
        let s = self.seq;
        self.seq = next_seq(self.seq);
        s
    }

    fn push_confirm(&mut self, c: TxConfirm) {
        if self.confirms_len < EMBER_CONFIRM_DEPTH {
            self.confirms[self.confirms_len] = Some(c);
            self.confirms_len += 1;
        }
    }

    fn push_indication(&mut self, ind: RxIndication) {
        if self.indications_len < EMBER_INDICATION_DEPTH {
            self.indications[self.indications_len] = Some(ind);
            self.indications_len += 1;
        } else {
            self.rx_dropped = self.rx_dropped.saturating_add(1);
        }
    }

    fn drain_all(&mut self) {
        self.slots = [None; EMBER_TX_SLOTS];
        self.confirms = [None; EMBER_CONFIRM_DEPTH];
        self.confirms_len = 0;
        self.indications = [None, None, None, None, None, None, None, None];
        self.indications_len = 0;
    }

    /// Pump scripted NCP callbacks into SAP queues.
    pub fn pump(&mut self) {
        while let Some((raw, len)) = self.transport.pop_rx() {
            let Ok((frame, _)) = decode(&raw[..len]) else {
                self.rx_dropped = self.rx_dropped.saturating_add(1);
                continue;
            };
            match frame.frame_id {
                EVT_TX_CONFIRM => self.note_confirm(&frame),
                EVT_DATA_RECEIVE => self.note_receive(&frame),
                _ => {
                    self.rx_dropped = self.rx_dropped.saturating_add(1);
                }
            }
        }
    }

    fn note_confirm(&mut self, frame: &EzspFrame) {
        let body = frame.payload_bytes();
        if body.len() != 2 {
            self.rx_dropped = self.rx_dropped.saturating_add(1);
            return;
        }
        let (seq, status) = (body[0] & CTRL_SEQ_MASK, body[1]);
        let mut at = None;
        let mut i = 0;
        while i < self.slots.len() {
            if self.slots[i].is_some_and(|s| s.seq == seq) {
                at = Some(i);
                break;
            }
            i += 1;
        }
        let Some(at) = at else {
            self.rx_dropped = self.rx_dropped.saturating_add(1);
            return;
        };
        let slot = self.slots[at].take().expect("slot present");
        self.push_confirm(TxConfirm {
            handle: slot.handle,
            status: if status == STATUS_DELIVERED {
                TxStatus::Delivered
            } else {
                // Every non-delivery NCP outcome shares one SAP
                // truth: the frame was not delivered. Same collapse
                // the existing MAC codec applies to driver failures.
                TxStatus::NoAck
            },
            timestamp_us: None,
        });
    }

    fn note_receive(&mut self, frame: &EzspFrame) {
        let body = frame.payload_bytes();
        if body.len() < 3 || body.len() - 3 > MAX_MSDU_LEN {
            self.rx_dropped = self.rx_dropped.saturating_add(1);
            return;
        }
        let src = u16::from_le_bytes([body[0], body[1]]);
        let lqi = body[2];
        let Ok(msdu) = FramePayload::from_slice(&body[3..]) else {
            self.rx_dropped = self.rx_dropped.saturating_add(1);
            return;
        };
        self.push_indication(RxIndication {
            src: MacAddress::short(self.pan, src),
            lqi,
            timestamp_us: None,
            msdu,
        });
    }
}

impl Default for EmberAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl HasCapabilities for EmberAdapter {
    fn capabilities(&self) -> MacCapabilities {
        MacCapabilities {
            // The NCP owns ACK + CSMA; it reports each transaction
            // once — no adapter retry (upper layers own retry).
            hw_auto_ack: true,
            hw_csma_ca: true,
            hw_retries: false,
            // Skeleton transports no energy scan yet.
            energy_scan: false,
            // No SFD timestamps wired through; confirms carry None.
            frame_timestamping: false,
            // Filtering is fixed-function on this path.
            promiscuous_mode: false,
        }
    }
}

impl MacDataSap for EmberAdapter {
    fn data_request(&mut self, req: TxRequest) -> Result<TxHandle, MacError> {
        if req.msdu.len() > MAX_MSDU_LEN {
            return Err(MacError::FrameTooLong);
        }
        let dst = match req.dst.addr {
            AddrMode::Short(a) => a,
            // Well-formed but beyond the short-only skeleton.
            AddrMode::Extended(_) => return Err(MacError::Unsupported),
            AddrMode::None => return Err(MacError::InvalidAddress),
        };
        let free = self.slots.iter().position(|s| s.is_none());
        let Some(idx) = free else {
            return Err(MacError::QueueFull);
        };
        let handle = self.take_handle();
        let seq = self.take_seq();
        let mut payload = [0u8; 2 + 1 + MAX_MSDU_LEN];
        payload[..2].copy_from_slice(&dst.to_le_bytes());
        payload[2] = u8::from(req.options.wants_ack());
        payload[3..3 + req.msdu.len()].copy_from_slice(req.msdu.as_slice());
        let mut encoded = [0u8; MAX_ENCODED_FRAME];
        let n = encode(
            seq,
            CMD_DATA_SEND,
            &payload[..3 + req.msdu.len()],
            &mut encoded,
        )
        .map_err(|_| MacError::FrameTooLong)?;
        if !self.transport.push_tx(&encoded[..n]) {
            return Err(MacError::QueueFull);
        }
        self.slots[idx] = Some(EmberSlot { handle, seq });
        self.pump();
        Ok(handle)
    }

    fn data_cancel(&mut self, handle: TxHandle) -> Result<(), MacError> {
        let mut i = 0;
        while i < self.slots.len() {
            if self.slots[i].is_some_and(|s| s.handle == handle) {
                self.slots[i] = None;
                self.push_confirm(TxConfirm {
                    handle,
                    status: TxStatus::Cancelled,
                    timestamp_us: None,
                });
                return Ok(());
            }
            i += 1;
        }
        Err(MacError::UnknownHandle)
    }

    fn poll_confirm(&mut self) -> Option<TxConfirm> {
        self.pump();
        if self.confirms_len == 0 {
            return None;
        }
        let c = self.confirms[0].take();
        self.confirms.rotate_left(1);
        self.confirms_len -= 1;
        c
    }

    fn poll_indication(&mut self) -> Option<RxIndication> {
        self.pump();
        if self.indications_len == 0 {
            return None;
        }
        let ind = self.indications[0].take();
        self.indications.rotate_left(1);
        self.indications_len -= 1;
        ind
    }

    fn tx_queue_free(&self) -> usize {
        self.slots.iter().filter(|s| s.is_none()).count()
    }

    fn tx_queue_capacity(&self) -> usize {
        EMBER_TX_SLOTS
    }
}

impl MacMgmtSap for EmberAdapter {
    fn reset(&mut self, cold: bool) {
        self.drain_all();
        if cold {
            self.channel = 15;
            self.pan = 0xFFFF;
            self.short = 0xFFFF;
            self.ext = [0; 8];
            self.seq = 0;
        }
    }

    fn set_channel(&mut self, channel: Channel) -> Result<(), MacError> {
        self.channel = channel.number();
        Ok(())
    }

    fn set_short_addr(&mut self, addr: ShortAddr) {
        self.short = addr;
    }

    fn set_extended_addr(&mut self, addr: ExtAddr) {
        self.ext = addr.to_le_bytes();
    }

    fn set_pan_id(&mut self, pan: PanId) {
        self.pan = pan;
    }

    fn energy_scan(&mut self, _channel: Channel) -> Result<u8, MacError> {
        Err(MacError::Unsupported)
    }
}
