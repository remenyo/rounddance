//! TI/Z-Stack-MT radio-backend skeleton: framing codec plus the
//! [`TiAdapter`] [`MacDataSap`] mapping over a mock transport.
//!
//! Paraphrase-level model only (D1, `SCOPE.md` §2): this module names
//! document numbers and clause anchors, never spec text. The TI side
//! of the consolidated-goal extension ("EmberZNet/TI sticks as radio
//! backends") starts here: the CC2652 lab unit is parked for tomorrow
//! and is never touched — all proof below is offline over
//! [`MockMtTransport`], no serial, no hardware.
//!
//! # Framing (adapter-local skeleton shape)
//!
//! Each transfer is one SOF-led, length-delimited frame:
//!
//! ```text
//! SOF  | LEN | CMD0 | CMD1 | DATA[..] | FCS
//! 0xFE   1     1      1      0..=128    1 (XOR over LEN|CMD0|CMD1|DATA)
//! ```
//!
//! * `LEN` counts `DATA` octets only, so `0..=128`.
//! * `CMD0` carries the command type in [`MT_TYPE_MASK`] (host SREQ
//!   vs NCP AREQ) so responses and callbacks never alias.
//! * `FCS` is the XOR fold over `LEN | CMD0 | CMD1 | DATA`.
//!
//! Command identifiers below are an adapter-local skeleton namespace
//! (`CMD_*` host-to-NCP, `EVT_*` NCP-to-host with the AREQ type), not
//! the NCP command set: pinning real NCP values waits for the
//! transport decision the consolidated goal leaves to the user
//! choice. The codec mechanics (delimiting, length discipline, FCS)
//! are what the vectors pin.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-COMPAT-08` (codec), `RD-COMPAT-09` (SAP mapping),
//! `RD-COMPAT-10` (join-flow parity with the existing MAC codec),
//! `RD-COMPAT-12` (streaming [`MtDecoder`]).

use rounddance_mac_sap::{
    AddrMode, Channel, ExtAddr, FramePayload, MacAddress, MacCapabilities, MacDataSap, MacError,
    MacMgmtSap, PanId, RxIndication, ShortAddr, TxConfirm, TxHandle, TxRequest, TxStatus,
    MAX_MSDU_LEN,
};

/// Start-of-frame octet (also the only framing marker; length, not
/// flags, delimits).
pub const SOF: u8 = 0xFE;

/// Type bits of the first command octet.
pub const MT_TYPE_MASK: u8 = 0xE0;
/// Host-to-NCP request type.
pub const MT_TYPE_SREQ: u8 = 0x20;
/// NCP-to-host asynchronous type (callbacks).
pub const MT_TYPE_AREQ: u8 = 0x40;

/// Skeleton command, first octet: host asks the NCP to transmit.
pub const CMD_DATA_SEND_C0: u8 = 0x24;
/// Skeleton command, second octet: host asks the NCP to transmit.
pub const CMD_DATA_SEND_C1: u8 = 0x01;
/// Skeleton callback, first octet: the NCP reports a transmit outcome.
pub const EVT_TX_CONFIRM_C0: u8 = 0x44;
/// Skeleton callback, second octet: the NCP reports a transmit outcome.
pub const EVT_TX_CONFIRM_C1: u8 = 0x81;
/// Skeleton callback, first octet: the NCP delivers a received frame.
pub const EVT_DATA_RECEIVE_C0: u8 = 0x44;
/// Skeleton callback, second octet: the NCP delivers a received frame.
pub const EVT_DATA_RECEIVE_C1: u8 = 0x82;

/// Send-data layout: `token | dst LE | options | MSDU`. The token is
/// an adapter-local transaction tag (one octet, wrapping) the NCP
/// echoes in the confirm so confirms match slots even after cancels;
/// options bit 0 = ACK requested.
pub const SEND_TOKEN_LEN: usize = 1;
/// Send-data overhead before the MSDU (`token | dst | options`).
pub const SEND_OVERHEAD: usize = 1 + 2 + 1;

/// Largest command/callback data payload in octets: the send
/// overhead plus one 15.4 PSDU.
pub const MAX_MT_PAYLOAD: usize = 128;

/// Largest encoded frame: SOF + LEN + CMD0 + CMD1 + data + FCS.
pub const MAX_ENCODED_MT: usize = 1 + 1 + 2 + MAX_MT_PAYLOAD + 1;

/// Confirm status: the frame was delivered (ACK received when asked).
pub const STATUS_DELIVERED: u8 = 0x00;
/// Confirm status: no acknowledgement within the NCP retry budget.
pub const STATUS_NO_ACK: u8 = 0x01;

/// Framing errors: encode-side and decode-side alike (decode never
/// panics and holds no allocator state).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtError {
    /// Data payload exceeds [`MAX_MT_PAYLOAD`].
    TooLong,
    /// Output slice fits fewer than the encoded bytes.
    BufferTooSmall,
    /// First octet is not [`SOF`] (resync by scan, same discipline
    /// as the RCP UART decoder).
    BadSof,
    /// `LEN` names more bytes than are present, or the FCS octet is
    /// missing.
    Truncated,
    /// `LEN` names more than [`MAX_MT_PAYLOAD`] data octets.
    BadLength,
    /// FCS (XOR-fold) mismatch (frame dropped, never decoded).
    BadFcs,
}

impl core::fmt::Display for MtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::TooLong => "MT data payload exceeds 128 octets",
            Self::BufferTooSmall => "MT output buffer too small",
            Self::BadSof => "MT frame does not start with SOF",
            Self::Truncated => "MT frame truncated before FCS",
            Self::BadLength => "MT LEN exceeds bounded data capacity",
            Self::BadFcs => "MT FCS mismatch",
        };
        f.write_str(s)
    }
}

impl core::error::Error for MtError {}

/// XOR-fold checksum over `LEN | CMD0 | CMD1 | data`.
///
/// Reference check: `fcs(0x00, 0x24, 0x01, &[]) == 0x25`.
#[must_use]
pub const fn fcs(len: u8, cmd0: u8, cmd1: u8, data: &[u8]) -> u8 {
    let mut acc = len ^ cmd0 ^ cmd1;
    let mut rest = data;
    while let [b, tail @ ..] = rest {
        rest = tail;
        acc ^= *b;
    }
    acc
}

/// One decoded MT frame: command octets plus bounded data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MtFrame {
    /// First command octet (type in [`MT_TYPE_MASK`]).
    pub cmd0: u8,
    /// Second command octet (command identifier).
    pub cmd1: u8,
    /// Live data length.
    pub data_len: u8,
    /// Data bytes (first `data_len` live).
    pub data: [u8; MAX_MT_PAYLOAD],
}

impl MtFrame {
    /// Command type bits of this frame ([`MT_TYPE_SREQ`] /
    /// [`MT_TYPE_AREQ`).
    #[must_use]
    pub const fn cmd_type(self) -> u8 {
        self.cmd0 & MT_TYPE_MASK
    }

    /// Live data bytes.
    #[must_use]
    pub fn payload_bytes(&self) -> &[u8] {
        &self.data[..self.data_len as usize]
    }
}

/// Encode one frame with command octets into `out`; returns bytes
/// written (`5 + data.len()`).
///
/// # Errors
///
/// [`MtError::TooLong`] when the data exceeds [`MAX_MT_PAYLOAD`],
/// [`MtError::BufferTooSmall`] when `out` is short (prefix
/// unwritten — encoding is all-or-nothing).
pub fn encode(cmd0: u8, cmd1: u8, data: &[u8], out: &mut [u8]) -> Result<usize, MtError> {
    if data.len() > MAX_MT_PAYLOAD {
        return Err(MtError::TooLong);
    }
    let total = 1 + 1 + 2 + data.len() + 1;
    if out.len() < total {
        return Err(MtError::BufferTooSmall);
    }
    out[0] = SOF;
    out[1] = data.len() as u8;
    out[2] = cmd0;
    out[3] = cmd1;
    out[4..4 + data.len()].copy_from_slice(data);
    out[4 + data.len()] = fcs(data.len() as u8, cmd0, cmd1, data);
    Ok(total)
}

/// Decode the first SOF-led frame in `buf`; returns the frame plus
/// consumed bytes (`5 + LEN`, trailing bytes untouched).
///
/// # Errors
///
/// [`MtError::BadSof`] when `buf` does not start with [`SOF`],
/// [`MtError::Truncated`] when the named bytes never arrive,
/// [`MtError::BadLength`] when `LEN` exceeds [`MAX_MT_PAYLOAD`],
/// and [`MtError::BadFcs`] on a checksum mismatch.
pub fn decode(buf: &[u8]) -> Result<(MtFrame, usize), MtError> {
    let Some(&sof) = buf.first() else {
        return Err(MtError::Truncated);
    };
    if sof != SOF {
        return Err(MtError::BadSof);
    }
    if buf.len() < 5 {
        return Err(MtError::Truncated);
    }
    let len = buf[1] as usize;
    if len > MAX_MT_PAYLOAD {
        return Err(MtError::BadLength);
    }
    let total = 1 + 1 + 2 + len + 1;
    if buf.len() < total {
        return Err(MtError::Truncated);
    }
    let (cmd0, cmd1) = (buf[2], buf[3]);
    let data = &buf[4..4 + len];
    if fcs(buf[1], cmd0, cmd1, data) != buf[4 + len] {
        return Err(MtError::BadFcs);
    }
    let mut frame = MtFrame {
        cmd0,
        cmd1,
        data_len: len as u8,
        data: [0u8; MAX_MT_PAYLOAD],
    };
    frame.data[..len].copy_from_slice(data);
    Ok((frame, total))
}

/// Why a byte run was dropped instead of decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtDropReason {
    /// `LEN` names more than [`MAX_MT_PAYLOAD`] data octets.
    BadLen(u8),
    /// Trailing FCS mismatch.
    BadFcs,
}

/// One decoder step result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtOutcome {
    /// A complete, FCS-clean frame.
    Frame(MtFrame),
    /// A malformed run was skipped; the parser re-armed at [`SOF`].
    Dropped(MtDropReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MtState {
    Sync,
    Len,
    Cmd0,
    Cmd1,
    Data,
    Fcs,
}

/// Streaming MT frame parser: feed wire bytes, collect outcomes.
///
/// Bytes before the first [`SOF`] are skipped silently (line noise,
/// a peer mid-frame on attach). A bad `LEN` or FCS surfaces as
/// [`MtOutcome::Dropped`] and re-arms the parser, so one corrupt run
/// can never wedge the stream. A [`SOF`] octet inside a frame body
/// is data, not a delimiter — only length delimits, same contract as
/// [`decode`]. It never panics and holds no allocator state.
#[derive(Clone, Debug)]
pub struct MtDecoder {
    state: MtState,
    len: u8,
    cmd0: u8,
    cmd1: u8,
    data: [u8; MAX_MT_PAYLOAD],
    pos: usize,
    dropped: u32,
    consecutive_bad: u32,
}

impl MtDecoder {
    /// Parser waiting at [`SOF`], counters zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: MtState::Sync,
            len: 0,
            cmd0: 0,
            cmd1: 0,
            data: [0; MAX_MT_PAYLOAD],
            pos: 0,
            dropped: 0,
            consecutive_bad: 0,
        }
    }

    /// Total dropped runs so far (diagnostic).
    #[must_use]
    pub const fn dropped(&self) -> u32 {
        self.dropped
    }

    /// Dropped runs since the last good frame (desync meter).
    #[must_use]
    pub const fn consecutive_bad(&self) -> u32 {
        self.consecutive_bad
    }

    fn drop(&mut self, reason: MtDropReason) -> MtOutcome {
        self.state = MtState::Sync;
        self.pos = 0;
        self.dropped = self.dropped.saturating_add(1);
        self.consecutive_bad = self.consecutive_bad.saturating_add(1);
        MtOutcome::Dropped(reason)
    }

    /// Feed one byte; at most one outcome per call (`None` while the
    /// frame is still arriving or noise is being skipped).
    pub fn push_byte(&mut self, byte: u8) -> Option<MtOutcome> {
        match self.state {
            MtState::Sync => {
                if byte == SOF {
                    self.state = MtState::Len;
                }
                None
            }
            MtState::Len => {
                if byte as usize > MAX_MT_PAYLOAD {
                    Some(self.drop(MtDropReason::BadLen(byte)))
                } else {
                    self.len = byte;
                    self.state = MtState::Cmd0;
                    None
                }
            }
            MtState::Cmd0 => {
                self.cmd0 = byte;
                self.state = MtState::Cmd1;
                None
            }
            MtState::Cmd1 => {
                self.cmd1 = byte;
                self.pos = 0;
                self.state = if self.len == 0 {
                    MtState::Fcs
                } else {
                    MtState::Data
                };
                None
            }
            MtState::Data => {
                // `pos < len <= MAX_MT_PAYLOAD` by construction.
                self.data[self.pos] = byte;
                self.pos += 1;
                if self.pos >= self.len as usize {
                    self.state = MtState::Fcs;
                }
                None
            }
            MtState::Fcs => {
                let body = &self.data[..self.len as usize];
                if fcs(self.len, self.cmd0, self.cmd1, body) != byte {
                    return Some(self.drop(MtDropReason::BadFcs));
                }
                let mut frame = MtFrame {
                    cmd0: self.cmd0,
                    cmd1: self.cmd1,
                    data_len: self.len,
                    data: [0u8; MAX_MT_PAYLOAD],
                };
                frame.data[..self.len as usize].copy_from_slice(body);
                self.state = MtState::Sync;
                self.pos = 0;
                self.consecutive_bad = 0;
                Some(MtOutcome::Frame(frame))
            }
        }
    }
}

impl Default for MtDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock NCP transport: records every encoded host-to-NCP frame and
/// replays scripted NCP-to-host bytes. No serial, no hardware — the
/// offline double for the MT framing and the SAP mapping alike.
#[derive(Clone, Copy, Debug)]
pub struct MockMtTransport {
    tx_log: [[u8; MAX_ENCODED_MT]; 8],
    tx_lens: [usize; 8],
    tx_count: usize,
    rx_queue: [[u8; MAX_ENCODED_MT]; 8],
    rx_lens: [usize; 8],
    rx_len: usize,
    rx_pos: usize,
}

/// Recorded-transport depth (matches the adapter slot fan-out).
pub const TRANSPORT_DEPTH: usize = 8;

impl Default for MockMtTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockMtTransport {
    /// Empty transport: nothing recorded, nothing scripted.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tx_log: [[0u8; MAX_ENCODED_MT]; 8],
            tx_lens: [0; 8],
            tx_count: 0,
            rx_queue: [[0u8; MAX_ENCODED_MT]; 8],
            rx_lens: [0; 8],
            rx_len: 0,
            rx_pos: 0,
        }
    }

    /// Record one transmitted frame; false (dropped) when the log is
    /// full — the adapter treats that as backpressure, never loss.
    pub fn push_tx(&mut self, bytes: &[u8]) -> bool {
        if self.tx_count >= TRANSPORT_DEPTH || bytes.len() > MAX_ENCODED_MT {
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
        if self.rx_len >= TRANSPORT_DEPTH || bytes.len() > MAX_ENCODED_MT {
            return false;
        }
        let at = (self.rx_pos + self.rx_len) % TRANSPORT_DEPTH;
        self.rx_queue[at][..bytes.len()].copy_from_slice(bytes);
        self.rx_lens[at] = bytes.len();
        self.rx_len += 1;
        true
    }

    /// Take the oldest scripted inbound frame, if any.
    pub fn pop_rx(&mut self) -> Option<([u8; MAX_ENCODED_MT], usize)> {
        if self.rx_len == 0 {
            return None;
        }
        let at = self.rx_pos;
        self.rx_pos = (self.rx_pos + 1) % TRANSPORT_DEPTH;
        self.rx_len -= 1;
        Some((self.rx_queue[at], self.rx_lens[at]))
    }

    /// Build one NCP callback frame (AREQ type) for tests and
    /// harnesses scripting the NCP side.
    #[must_use]
    pub fn callback_frame(&self, cmd0: u8, cmd1: u8, data: &[u8]) -> ([u8; MAX_ENCODED_MT], usize) {
        let mut out = [0u8; MAX_ENCODED_MT];
        let n = encode(cmd0, cmd1, data, &mut out).unwrap_or(0);
        (out, n)
    }
}

/// Outstanding TI transaction (preallocated, never resized — D5).
#[derive(Clone, Copy, Debug)]
struct TiSlot {
    handle: TxHandle,
    token: u8,
}

/// Outstanding PAN transactions (same depth as the existing MAC
/// codec so backpressure decisions coincide).
pub const TI_TX_SLOTS: usize = 4;
/// Pending-confirm queue depth.
const TI_CONFIRM_DEPTH: usize = 8;
/// Pending-indication queue depth.
const TI_INDICATION_DEPTH: usize = 8;

/// [`MacDataSap`] over a TI/Z-Stack-MT NCP, offline-skeleton form:
/// the wire below is the [`MockMtTransport`], so every SAP decision
/// is provable on-host. The mapping mirrors the existing short-short
/// MAC codec decision for decision: short addresses only, explicit
/// backpressure, cancel revokes queued transactions as
/// [`TxStatus::Cancelled`], confirms and indications arrive through
/// the same poll contract.
#[derive(Clone, Debug)]
pub struct TiAdapter {
    transport: MockMtTransport,
    pan: PanId,
    short: ShortAddr,
    ext: [u8; 8],
    channel: u8,
    token: u8,
    next_handle: u32,
    slots: [Option<TiSlot>; TI_TX_SLOTS],
    confirms: [Option<TxConfirm>; TI_CONFIRM_DEPTH],
    confirms_len: usize,
    indications: [Option<TiIndication>; TI_INDICATION_DEPTH],
    indications_len: usize,
    rx_dropped: u32,
}

/// Owned indication slot (the SAP hands out owned values, so the
/// queue stores them directly).
type TiIndication = RxIndication;

impl TiAdapter {
    /// Unprovisioned adapter on the default channel.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            transport: MockMtTransport::new(),
            pan: 0xC601,
            short: 0x0002,
            ext: [0; 8],
            channel: 15,
            token: 0,
            next_handle: 0,
            slots: [None; TI_TX_SLOTS],
            confirms: [None; TI_CONFIRM_DEPTH],
            confirms_len: 0,
            indications: [None, None, None, None, None, None, None, None],
            indications_len: 0,
            rx_dropped: 0,
        }
    }

    /// Borrow the mock transport (frame inspection escape for
    /// tests and harnesses).
    #[must_use]
    pub const fn transport(&self) -> &MockMtTransport {
        &self.transport
    }

    /// Count of inbound NCP frames dropped (unparseable, unknown
    /// command, or full queue) — visible, never silent.
    #[must_use]
    pub const fn rx_dropped(self) -> u32 {
        self.rx_dropped
    }

    /// Script one NCP transmit-confirm for the `n`th recorded send
    /// (token taken from that send): the offline stand-in for the
    /// NCP answering `CMD_DATA_SEND`.
    pub fn inject_ncp_confirm(&mut self, tx_index: usize, status: u8) {
        let Some(raw) = self.transport.tx_frame(tx_index) else {
            return;
        };
        let Ok((sent, _)) = decode(raw) else {
            return;
        };
        let token = sent.payload_bytes().first().copied().unwrap_or(0);
        let (cb, n) =
            self.transport
                .callback_frame(EVT_TX_CONFIRM_C0, EVT_TX_CONFIRM_C1, &[token, status]);
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
        let (cb, m) = self.transport.callback_frame(
            EVT_DATA_RECEIVE_C0,
            EVT_DATA_RECEIVE_C1,
            &payload[..3 + n],
        );
        let _ = self.transport.inject_rx(&cb[..m]);
    }

    fn take_handle(&mut self) -> TxHandle {
        let h = TxHandle(self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1);
        h
    }

    fn take_token(&mut self) -> u8 {
        let t = self.token;
        self.token = self.token.wrapping_add(1);
        t
    }

    fn push_confirm(&mut self, c: TxConfirm) {
        if self.confirms_len < TI_CONFIRM_DEPTH {
            self.confirms[self.confirms_len] = Some(c);
            self.confirms_len += 1;
        }
    }

    fn push_indication(&mut self, ind: RxIndication) {
        if self.indications_len < TI_INDICATION_DEPTH {
            self.indications[self.indications_len] = Some(ind);
            self.indications_len += 1;
        } else {
            self.rx_dropped = self.rx_dropped.saturating_add(1);
        }
    }

    fn drain_all(&mut self) {
        self.slots = [None; TI_TX_SLOTS];
        self.confirms = [None; TI_CONFIRM_DEPTH];
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
            match (frame.cmd0, frame.cmd1) {
                (EVT_TX_CONFIRM_C0, EVT_TX_CONFIRM_C1) => self.note_confirm(&frame),
                (EVT_DATA_RECEIVE_C0, EVT_DATA_RECEIVE_C1) => self.note_receive(&frame),
                _ => {
                    self.rx_dropped = self.rx_dropped.saturating_add(1);
                }
            }
        }
    }

    fn note_confirm(&mut self, frame: &MtFrame) {
        let body = frame.payload_bytes();
        if body.len() != 2 {
            self.rx_dropped = self.rx_dropped.saturating_add(1);
            return;
        }
        let (token, status) = (body[0], body[1]);
        let mut at = None;
        let mut i = 0;
        while i < self.slots.len() {
            if self.slots[i].is_some_and(|s| s.token == token) {
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

    fn note_receive(&mut self, frame: &MtFrame) {
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

impl Default for TiAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl rounddance_mac_sap::HasCapabilities for TiAdapter {
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

impl MacDataSap for TiAdapter {
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
        if SEND_OVERHEAD + req.msdu.len() > MAX_MT_PAYLOAD {
            return Err(MacError::FrameTooLong);
        }
        let free = self.slots.iter().position(|s| s.is_none());
        let Some(idx) = free else {
            return Err(MacError::QueueFull);
        };
        let handle = self.take_handle();
        let token = self.take_token();
        let mut payload = [0u8; SEND_OVERHEAD + MAX_MSDU_LEN];
        payload[0] = token;
        payload[1..3].copy_from_slice(&dst.to_le_bytes());
        payload[3] = u8::from(req.options.wants_ack());
        payload[SEND_OVERHEAD..SEND_OVERHEAD + req.msdu.len()].copy_from_slice(req.msdu.as_slice());
        let mut encoded = [0u8; MAX_ENCODED_MT];
        let n = encode(
            CMD_DATA_SEND_C0,
            CMD_DATA_SEND_C1,
            &payload[..SEND_OVERHEAD + req.msdu.len()],
            &mut encoded,
        )
        .map_err(|_| MacError::FrameTooLong)?;
        if !self.transport.push_tx(&encoded[..n]) {
            return Err(MacError::QueueFull);
        }
        self.slots[idx] = Some(TiSlot { handle, token });
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
        TI_TX_SLOTS
    }
}

impl MacMgmtSap for TiAdapter {
    fn reset(&mut self, cold: bool) {
        self.drain_all();
        if cold {
            self.channel = 15;
            self.pan = 0xFFFF;
            self.short = 0xFFFF;
            self.ext = [0; 8];
            self.token = 0;
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
