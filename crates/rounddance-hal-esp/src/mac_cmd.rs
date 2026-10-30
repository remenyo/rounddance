//! MAC beacon / association command frames + coordinator responder.
//!
//! Productizes the wave-23 OTA leg (`rd-c6join` in scratch
//! `~/hwscratch/c6join`): the joiner's beacon-request → coordinator
//! beacon answer, association-request → association-response, and the
//! long-form data-request poll that re-fetches a pending association
//! answer. All wire bytes below are the OTA-proven scratch shapes
//! (`pure.rs` builders, pinned by the `main.rs` self-test); no spec
//! text is reproduced here (D1, `SCOPE.md` §2).
//!
//! # What this covers (LADDER gap G-01)
//!
//! * Frames in (coordinator RX): beacon-request (MAC command `0x07`,
//!   broadcast, 8 B), association-request (`0x01`, long source, 19 B),
//!   long data-request poll (`0x04`, long source, 18 B — the fetch
//!   edge `main.rs` uses to re-arm a pending association answer).
//! * Frames out (coordinator TX): beacon (MAC beacon, 26 B:
//!   superframe `0xCFFF` + empty GTS/pending + 15 B network payload),
//!   association-response (`0x02`, 19 B: assigned short + status).
//! * Pacing: solicited answers via the pending flags plus gratuitous
//!   beacons every [`GRATUITOUS_BEACON_INTERVAL_MS`] ms while serving
//!   unassociated ([`gratuitous_due`]); the superframe permit bit stays
//!   set while serving (OTA pin `0xCFFF`) — the window gates assoc
//!   answers, not beacons.
//! * State ([`CoordAssoc`]): pending-beacon counter + pending-assoc
//!   flag + latched device EUI, gated only by an explicit permit bit
//!   and a bounded allow-list the application maintains next to its
//!   child-table / Trust-Center admission. No timeouts, no retries,
//!   no suitability ranking here: those live in `rounddance-roles`
//!   (permit window), `rounddance-commission` (survey, join machine),
//!   and the firmware TX pacing (gratuitous beacons, re-sends).
//!
//! # How the radio paths carry these
//!
//! * ESP: board code enables promiscuous on the coordinator
//!   (broadcast beacon-requests never pass the hardware filter —
//!   scratch `main.rs` stays promiscuous on the coordinator for
//!   exactly this reason), feeds received PSDUs from
//!   [`EspAdapter`](crate::adapter::EspAdapter) `poll_mac_indication`
//!   to [`classify`]/[`CoordAssoc`], and radiates answers plus
//!   gratuitous beacons via `transmit_mac` (single-flight through the
//!   same adapter queues as data, so no direct-`Driver` race).
//!   Driving the [`Driver`](crate::driver::Driver) seam directly
//!   remains possible on bare hardware, but firmware uses the adapter
//!   queues so command and data TX share backpressure.
//!   [`EspAdapter`](crate::adapter::EspAdapter)
//!   routes command PSDUs to the MAC queue and counts only
//!   non-command / full-queue frames in `rx_dropped`.
//! * RCP: the scripted peer already carries arbitrary PSDUs
//!   (`EmulatedRcp::queue_rx`, `peer.rs`) and latches association
//!   shorts from the response shape (SHORT-SNOOP, `peer.rs`), with
//!   the host-side confirm in `RcpDriver::note_assoc_response`
//!   (`driver.rs`); no RCP wire change was needed for this leg.
//!
//! # Bounds (D5)
//!
//! Fixed PSDU sizes only (8/18/19/26 B); the allow-list holds at most
//! [`MAX_ALLOW`] EUIs; every fallible copy reports
//! [`MacCmdError`] instead of panicking or truncating.

use core::fmt;

/// MAC command id: association request.
pub const MAC_ASSOC_REQ: u8 = 0x01;
/// MAC command id: association response.
pub const MAC_ASSOC_RSP: u8 = 0x02;
/// MAC command id: data request (poll).
pub const MAC_DATA_REQ: u8 = 0x04;
/// MAC command id: beacon request.
pub const MAC_BEACON_REQ: u8 = 0x07;

/// Joiner capability octet on the OTA leg: end device, mains powered,
/// receiver stays on while idle, short address requested (matches
/// `app::MAC_CAPS`).
pub const MAC_CAPS: u8 = 0x8c;

/// Beacon superframe on the OTA leg: beacon order 15, superframe order
/// 15, final slot `0xf`, PAN-coordinator set, association permitted.
/// The permit bit (bit 15) is part of the value the application passes
/// to [`build_beacon`]; this constant is the open-window OTA pin.
/// BO=15/SO=15 is the standard nonbeacon-network shape the Ember scan
/// parser requires: the pre-fix `0xCF0F` (SO=0) mixed nonbeacon markers
/// (BO=15) with beaconed-network fields and was dropped (rung-3 §2).
pub const SUPERFRAME_ASSOC_PERMIT: u16 = 0xCFFF;

/// Beacon-request PSDU length (broadcast short pair, no source).
pub const BEACON_REQ_LEN: usize = 8;
/// Association-request PSDU length (long source + caps).
pub const ASSOC_REQ_LEN: usize = 19;
/// Long-form data-request poll PSDU length (long source, no caps).
pub const DATA_POLL_LONG_LEN: usize = 18;
/// Beacon PSDU length (superframe + GTS + pending + 15 B payload).
pub const BEACON_LEN: usize = 26;
/// Association-response PSDU length (assigned short + status).
pub const ASSOC_RSP_LEN: usize = 19;
/// Beacon network-payload length (marker + stack + caps + ext PAN +
/// offsets + update id).
pub const BEACON_PAYLOAD_LEN: usize = 15;
/// Largest coordinator allow-list (distinct EUIs, application-held).
pub const MAX_ALLOW: usize = 8;

/// Gratuitous-beacon interval in caller ms while serving unassociated:
/// the OTA leg re-beacons every 2000 ms when no answer is owed and no
/// joiner has latched yet (`rd-c6join` Serve `beacon-grat`, TX gap
/// 2000 ms), so a passive sniffer sees unsolicited beacons.
pub const GRATUITOUS_BEACON_INTERVAL_MS: u64 = 2000;

/// True when a gratuitous beacon is due: at least `interval_ms` caller
/// ms since `last_ms` (wrapping-subtract, so a wrapping clock stays
/// safe). The caller also gates on unassociated (`dev_eui.is_none()`
/// in the OTA Serve leg) — this helper is pure timing.
#[must_use]
pub const fn gratuitous_due(last_ms: u64, now_ms: u64, interval_ms: u64) -> bool {
    now_ms.wrapping_sub(last_ms) >= interval_ms
}

/// Orientation-insensitive EUI equality for allow-list / short-table
/// lookups: matches when `b` equals `a` byte-for-byte, or the byte
/// reverse of `a`. 802.15.4 radiates long addresses LSB-first, so the
/// same EUI appears display-order in NCP tooling and reversed on air;
/// both spellings must key to the same admitted entry. A reversed
/// collision between two distinct admitted EUIs would need crafted
/// addresses and is not a concern for an explicit allow-list.
#[must_use]
pub fn eui_matches(a: &[u8; 8], b: &[u8; 8]) -> bool {
    if a == b {
        return true;
    }
    let mut rev = *a;
    rev.reverse();
    &rev == b
}

/// Codec / responder failures (bounded + fallible throughout, D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacCmdError {
    /// Caller buffer too small for the frame under construction.
    BufferTooSmall,
    /// Frame failed to decode (bad shape, id, or length).
    BadFrame,
    /// Allow-list is full.
    TableFull,
}

impl fmt::Display for MacCmdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::BufferTooSmall => "buffer too small for MAC command frame",
            Self::BadFrame => "malformed MAC command frame",
            Self::TableFull => "association allow-list full",
        };
        f.write_str(s)
    }
}

impl core::error::Error for MacCmdError {}

/// One decoded beacon-request: broadcast scan, no source address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconReq {
    /// MAC sequence number (echoed in no reply; logged only).
    pub seq: u8,
}

/// One decoded association-request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssocReq {
    /// MAC sequence number.
    pub seq: u8,
    /// Destination PAN (must be ours to answer).
    pub dst_pan: u16,
    /// Destination short (the coordinator short).
    pub dst_short: u16,
    /// Joiner long address (allow-list key).
    pub src_eui: [u8; 8],
    /// Joiner capability octet (observed, never gated here).
    pub caps: u8,
}

/// One decoded long-form data-request poll (association-answer fetch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataPoll {
    /// MAC sequence number.
    pub seq: u8,
    /// Polling joiner long address.
    pub src_eui: [u8; 8],
}

/// One decoded beacon (joiner-side survey input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconInfo {
    /// MAC sequence number.
    pub seq: u8,
    /// Advertising PAN.
    pub src_pan: u16,
    /// Advertising coordinator short.
    pub src_short: u16,
    /// Raw superframe (permit flag = bit 15).
    pub superframe: u16,
    /// True when the superframe advertises joining permitted.
    pub assoc_permit: bool,
    /// Offset of the 15 B network payload inside the parsed PSDU.
    pub payload_off: usize,
}

/// One decoded association-response (joiner-side confirm input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssocRsp {
    /// MAC sequence number.
    pub seq: u8,
    /// Destination joiner long address.
    pub dst_eui: [u8; 8],
    /// Responding coordinator short.
    pub src_short: u16,
    /// Assigned short (`0xFFFF` = denied at this layer by status).
    pub short: u16,
    /// Association status (`0x00` = success).
    pub status: u8,
}

/// Classified inbound PSDU (coordinator RX).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Incoming {
    /// Beacon request: answer with a beacon while serving.
    BeaconReq {
        /// MAC sequence number.
        seq: u8,
    },
    /// Association request: admit-check, then answer.
    AssocReq(AssocReq),
    /// Long-form data poll: re-arm for the latched EUI only.
    DataPoll(DataPoll),
    /// Anything else (data, foreign commands, beacons): not ours.
    Other,
}

/// Build a beacon-request PSDU into `out` (8 B).
///
/// Layout: `FC 03 08 | seq | dst pan ffff | dst ffff | cmd 0x07`.
///
/// # Errors
///
/// [`MacCmdError::BufferTooSmall`] when `out` holds fewer than
/// [`BEACON_REQ_LEN`] octets.
pub fn build_beacon_req(seq: u8, out: &mut [u8]) -> Result<usize, MacCmdError> {
    if out.len() < BEACON_REQ_LEN {
        return Err(MacCmdError::BufferTooSmall);
    }
    out[0] = 0x03;
    out[1] = 0x08;
    out[2] = seq;
    out[3..5].copy_from_slice(&0xffffu16.to_le_bytes());
    out[5..7].copy_from_slice(&0xffffu16.to_le_bytes());
    out[7] = MAC_BEACON_REQ;
    Ok(BEACON_REQ_LEN)
}

/// Parse a beacon-request PSDU.
#[must_use]
pub fn parse_beacon_req(psdu: &[u8]) -> Option<BeaconReq> {
    if psdu.len() != BEACON_REQ_LEN {
        return None;
    }
    if psdu[0] != 0x03 || psdu[1] != 0x08 {
        return None;
    }
    if psdu[3..5] != [0xff, 0xff] || psdu[5..7] != [0xff, 0xff] {
        return None;
    }
    if psdu[7] != MAC_BEACON_REQ {
        return None;
    }
    Some(BeaconReq { seq: psdu[2] })
}

/// Build an association-request PSDU into `out` (19 B).
///
/// Layout: `FC 23 c8 | seq | dst pan | dst short | src pan ffff |
/// src eui | cmd 0x01 | caps`.
///
/// # Errors
///
/// [`MacCmdError::BufferTooSmall`] when `out` holds fewer than
/// [`ASSOC_REQ_LEN`] octets.
pub fn build_assoc_req(
    seq: u8,
    dst_pan: u16,
    dst_short: u16,
    src_eui: &[u8; 8],
    caps: u8,
    out: &mut [u8],
) -> Result<usize, MacCmdError> {
    if out.len() < ASSOC_REQ_LEN {
        return Err(MacCmdError::BufferTooSmall);
    }
    out[0] = 0x23;
    out[1] = 0xc8;
    out[2] = seq;
    out[3..5].copy_from_slice(&dst_pan.to_le_bytes());
    out[5..7].copy_from_slice(&dst_short.to_le_bytes());
    out[7..9].copy_from_slice(&0xffffu16.to_le_bytes());
    out[9..17].copy_from_slice(src_eui);
    out[17] = MAC_ASSOC_REQ;
    out[18] = caps;
    Ok(ASSOC_REQ_LEN)
}

/// Parse an association-request PSDU.
#[must_use]
pub fn parse_assoc_req(psdu: &[u8]) -> Option<AssocReq> {
    if psdu.len() != ASSOC_REQ_LEN {
        return None;
    }
    if psdu[0] != 0x23 || psdu[1] != 0xc8 {
        return None;
    }
    if psdu[7..9] != [0xff, 0xff] {
        return None;
    }
    if psdu[17] != MAC_ASSOC_REQ {
        return None;
    }
    let mut src_eui = [0u8; 8];
    src_eui.copy_from_slice(&psdu[9..17]);
    Some(AssocReq {
        seq: psdu[2],
        dst_pan: u16::from_le_bytes([psdu[3], psdu[4]]),
        dst_short: u16::from_le_bytes([psdu[5], psdu[6]]),
        src_eui,
        caps: psdu[18],
    })
}

/// Build a long-form data-request poll PSDU into `out` (18 B).
///
/// Same header as the association request with command `0x04` and no
/// caps octet: the pre-association fetch of a pending answer.
///
/// # Errors
///
/// [`MacCmdError::BufferTooSmall`] when `out` holds fewer than
/// [`DATA_POLL_LONG_LEN`] octets.
pub fn build_data_poll_long(
    seq: u8,
    dst_pan: u16,
    dst_short: u16,
    src_eui: &[u8; 8],
    out: &mut [u8],
) -> Result<usize, MacCmdError> {
    if out.len() < DATA_POLL_LONG_LEN {
        return Err(MacCmdError::BufferTooSmall);
    }
    out[0] = 0x23;
    out[1] = 0xc8;
    out[2] = seq;
    out[3..5].copy_from_slice(&dst_pan.to_le_bytes());
    out[5..7].copy_from_slice(&dst_short.to_le_bytes());
    out[7..9].copy_from_slice(&0xffffu16.to_le_bytes());
    out[9..17].copy_from_slice(src_eui);
    out[17] = MAC_DATA_REQ;
    Ok(DATA_POLL_LONG_LEN)
}

/// Parse a long-form data-request poll PSDU.
#[must_use]
pub fn parse_data_poll_long(psdu: &[u8]) -> Option<DataPoll> {
    if psdu.len() != DATA_POLL_LONG_LEN {
        return None;
    }
    if psdu[0] != 0x23 || psdu[1] != 0xc8 {
        return None;
    }
    if psdu[7..9] != [0xff, 0xff] {
        return None;
    }
    if psdu[17] != MAC_DATA_REQ {
        return None;
    }
    let mut src_eui = [0u8; 8];
    src_eui.copy_from_slice(&psdu[9..17]);
    Some(DataPoll {
        seq: psdu[2],
        src_eui,
    })
}

/// Build a beacon PSDU into `out` (26 B).
///
/// Layout: `FC 00 80 | seq | src pan | src short | superframe |
/// GTS 00 | pending 00 | payload[15]`. The payload is the OTA shape
/// (marker `0x00`, stack `0x22` (Zigbee PRO profile 2 / revision 2 —
/// every live network surveyed emits `0x22`; `0x02` made Ember scan
/// parsers drop the beacon, rung-3 diag), caps [`MAC_CAPS`], `ext_pan`,
/// 3-octet offset `0xFF`, update id `0x00`). The `0xFF` offset is the
/// standard nonbeacon-network marker the Ember scan parser requires:
/// the pre-fix `0x00` offset was dropped alongside SO=0 (rung-3 §2).
///
/// # Errors
///
/// [`MacCmdError::BufferTooSmall`] when `out` holds fewer than
/// [`BEACON_LEN`] octets.
pub fn build_beacon(
    seq: u8,
    src_pan: u16,
    src_short: u16,
    superframe: u16,
    ext_pan: &[u8; 8],
    out: &mut [u8],
) -> Result<usize, MacCmdError> {
    if out.len() < BEACON_LEN {
        return Err(MacCmdError::BufferTooSmall);
    }
    out[0] = 0x00;
    out[1] = 0x80;
    out[2] = seq;
    out[3..5].copy_from_slice(&src_pan.to_le_bytes());
    out[5..7].copy_from_slice(&src_short.to_le_bytes());
    out[7..9].copy_from_slice(&superframe.to_le_bytes());
    out[9] = 0x00;
    out[10] = 0x00;
    out[11] = 0x00;
    out[12] = 0x22; // Stack profile 2 / revision 2 (see doc above).
    out[13] = MAC_CAPS;
    out[14..22].copy_from_slice(ext_pan);
    out[22] = 0xff;
    out[23] = 0xff;
    out[24] = 0xff;
    out[25] = 0x00;
    Ok(BEACON_LEN)
}

/// Parse a beacon PSDU (GTS/pending counts honored, bounds-checked).
#[must_use]
pub fn parse_beacon(psdu: &[u8]) -> Option<BeaconInfo> {
    if psdu.len() < 11 {
        return None;
    }
    if psdu[0] != 0x00 || psdu[1] != 0x80 {
        return None;
    }
    let superframe = u16::from_le_bytes([psdu[7], psdu[8]]);
    let gts_count = (psdu[9] & 0x07) as usize;
    let mut pos = 10usize;
    if gts_count > 0 {
        pos = pos.checked_add(1 + gts_count * 3)?;
    }
    let pend = *psdu.get(pos)?;
    pos = pos.checked_add(1)?;
    let n_short = (pend & 0x07) as usize;
    let n_ext = ((pend >> 4) & 0x07) as usize;
    pos = pos.checked_add(2 * n_short + 8 * n_ext)?;
    if pos > psdu.len() || psdu.len() - pos < BEACON_PAYLOAD_LEN {
        return None;
    }
    Some(BeaconInfo {
        seq: psdu[2],
        src_pan: u16::from_le_bytes([psdu[3], psdu[4]]),
        src_short: u16::from_le_bytes([psdu[5], psdu[6]]),
        superframe,
        assoc_permit: superframe & 0x8000 != 0,
        payload_off: pos,
    })
}

/// Whether a beacon network payload advertises our network (marker +
/// our extended PAN at the documented offset).
#[must_use]
pub fn beacon_payload_is_ours(payload: &[u8], ext_pan: &[u8; 8]) -> bool {
    payload.len() >= 11 && payload[0] == 0x00 && payload[3..11] == ext_pan[..]
}

/// Build an association-response PSDU into `out` (19 B).
///
/// Layout: `FC 63 8c | seq | dst pan | dst eui | src short |
/// cmd 0x02 | short LE | status`. Denied requests get no response at
/// all (scratch `ASSOC-DENY` leg); `status` is the success value the
/// application authorized.
///
/// # Errors
///
/// [`MacCmdError::BufferTooSmall`] when `out` holds fewer than
/// [`ASSOC_RSP_LEN`] octets.
#[allow(clippy::too_many_arguments)]
pub fn build_assoc_rsp(
    seq: u8,
    dst_pan: u16,
    dst_eui: &[u8; 8],
    src_short: u16,
    short: u16,
    status: u8,
    out: &mut [u8],
) -> Result<usize, MacCmdError> {
    if out.len() < ASSOC_RSP_LEN {
        return Err(MacCmdError::BufferTooSmall);
    }
    out[0] = 0x63;
    out[1] = 0x8c;
    out[2] = seq;
    out[3..5].copy_from_slice(&dst_pan.to_le_bytes());
    out[5..13].copy_from_slice(dst_eui);
    out[13..15].copy_from_slice(&src_short.to_le_bytes());
    out[15] = MAC_ASSOC_RSP;
    out[16..18].copy_from_slice(&short.to_le_bytes());
    out[18] = status;
    Ok(ASSOC_RSP_LEN)
}

/// Parse an association-response PSDU.
#[must_use]
pub fn parse_assoc_rsp(psdu: &[u8]) -> Option<AssocRsp> {
    if psdu.len() != ASSOC_RSP_LEN {
        return None;
    }
    if psdu[0] != 0x63 || psdu[1] != 0x8c {
        return None;
    }
    if psdu[15] != MAC_ASSOC_RSP {
        return None;
    }
    let mut dst_eui = [0u8; 8];
    dst_eui.copy_from_slice(&psdu[5..13]);
    Some(AssocRsp {
        seq: psdu[2],
        dst_eui,
        src_short: u16::from_le_bytes([psdu[13], psdu[14]]),
        short: u16::from_le_bytes([psdu[16], psdu[17]]),
        status: psdu[18],
    })
}

/// Classify one inbound PSDU for the coordinator responder.
#[must_use]
pub fn classify(psdu: &[u8]) -> Incoming {
    if let Some(req) = parse_beacon_req(psdu) {
        return Incoming::BeaconReq { seq: req.seq };
    }
    if let Some(req) = parse_assoc_req(psdu) {
        return Incoming::AssocReq(req);
    }
    if let Some(poll) = parse_data_poll_long(psdu) {
        return Incoming::DataPoll(poll);
    }
    Incoming::Other
}

/// Coordinator association responder: pending answers + admission gate.
///
/// Mirrors the scratch serve pacing: every beacon-request pends one
/// beacon answer; an association-request pends one response only when
/// the permit window is open AND the source EUI is allow-listed (else
/// it is denied with no response, the scratch `ASSOC-DENY` leg); a
/// long poll re-arms the response for the already-latched EUI.
/// Request addressing must match the provisioned PAN/short or the
/// frame is ignored (staggered-reboot neighbors reuse our PAN by
/// design, so the check is on destination, never on source PAN).
///
/// The application owns the policy inputs: [`CoordAssoc::set_permit`]
/// follows the roles permit window, [`CoordAssoc::allow`] follows the
/// Trust-Center/child-table admission, and the `take_*` sequence
/// numbers come from the firmware MAC sequence.
#[derive(Debug, Clone, Copy)]
pub struct CoordAssoc {
    pan: u16,
    short: u16,
    permit: bool,
    allowed: [Option<[u8; 8]>; MAX_ALLOW],
    pending_beacon: u32,
    pending_assoc: bool,
    dev_eui: Option<[u8; 8]>,
}

impl CoordAssoc {
    /// New responder: unprovisioned, window closed, nothing pending.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pan: 0xFFFF,
            short: 0xFFFF,
            permit: false,
            allowed: [None; MAX_ALLOW],
            pending_beacon: 0,
            pending_assoc: false,
            dev_eui: None,
        }
    }

    /// Provision our PAN + short (destination match for requests).
    pub fn provision(&mut self, pan: u16, short: u16) {
        self.pan = pan;
        self.short = short;
    }

    /// Open (`true`) or close the permit window.
    pub fn set_permit(&mut self, permit: bool) {
        self.permit = permit;
    }

    /// Whether the permit window is open.
    #[must_use]
    pub const fn permit(&self) -> bool {
        self.permit
    }

    /// Allow-list one joiner EUI (idempotent; full table errors).
    ///
    /// # Errors
    ///
    /// [`MacCmdError::TableFull`] when [`MAX_ALLOW`] distinct EUIs are
    /// already held.
    pub fn allow(&mut self, eui: [u8; 8]) -> Result<(), MacCmdError> {
        if self.allowed.contains(&Some(eui)) {
            return Ok(());
        }
        match self.allowed.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(eui);
                Ok(())
            }
            None => Err(MacCmdError::TableFull),
        }
    }

    /// Drop the whole allow-list (formation reset helper).
    pub fn clear_allow(&mut self) {
        self.allowed = [None; MAX_ALLOW];
    }

    /// Whether `eui` is allow-listed. Comparison is orientation-insensitive
    /// (see [`eui_matches`]): 802.15.4 radiates long addresses LSB-first,
    /// so the NCP-reported display order (`34:8d:13:ff:fe:11:49:6d`)
    /// arrives on air reversed (`6d:49:11:fe:ff:13:8d:34`) — rung-3
    /// proved a byte-exact check deafens the coordinator to real joiners.
    #[must_use]
    pub fn is_allowed(&self, eui: &[u8; 8]) -> bool {
        self.allowed.iter().any(|slot| match slot {
            Some(a) => eui_matches(a, eui),
            None => false,
        })
    }

    /// Pending beacon answers (saturating counter).
    #[must_use]
    pub const fn pending_beacon(&self) -> u32 {
        self.pending_beacon
    }

    /// Whether an association response is owed.
    #[must_use]
    pub const fn assoc_pending(&self) -> bool {
        self.pending_assoc
    }

    /// Latched device EUI (the admitted joiner), if any.
    #[must_use]
    pub const fn device_eui(&self) -> Option<[u8; 8]> {
        self.dev_eui
    }

    /// Note one beacon-request: pends one beacon answer.
    pub fn on_beacon_req(&mut self) {
        self.pending_beacon = self.pending_beacon.saturating_add(1);
    }

    /// Note one association-request: latch + pend only when the
    /// window is open, the EUI is allow-listed, and the request is
    /// addressed to our PAN/short. Returns true when accepted.
    #[must_use]
    pub fn on_assoc_req(&mut self, req: &AssocReq) -> bool {
        if !self.permit {
            return false;
        }
        if req.dst_pan != self.pan || req.dst_short != self.short {
            return false;
        }
        if !self.is_allowed(&req.src_eui) {
            return false;
        }
        self.dev_eui = Some(req.src_eui);
        self.pending_assoc = true;
        true
    }

    /// Note one long poll: re-arm the response only for the latched
    /// EUI (the association-answer fetch edge). Returns true when the
    /// poll re-armed a pending response.
    #[must_use]
    pub fn on_data_poll(&mut self, poll: &DataPoll) -> bool {
        if self.dev_eui == Some(poll.src_eui) {
            self.pending_assoc = true;
            true
        } else {
            false
        }
    }

    /// Build one pending beacon into `out`, consuming one pending
    /// answer. Returns `Ok(0)` (nothing radiated) when idle.
    ///
    /// # Errors
    ///
    /// [`MacCmdError::BufferTooSmall`] when an answer is owed but
    /// `out` holds fewer than [`BEACON_LEN`] octets.
    pub fn take_beacon(
        &mut self,
        seq: u8,
        ext_pan: &[u8; 8],
        out: &mut [u8],
    ) -> Result<usize, MacCmdError> {
        if self.pending_beacon == 0 {
            return Ok(0);
        }
        build_beacon(
            seq,
            self.pan,
            self.short,
            SUPERFRAME_ASSOC_PERMIT,
            ext_pan,
            out,
        )?;
        self.pending_beacon -= 1;
        Ok(BEACON_LEN)
    }

    /// Build the pending association-response into `out`, consuming
    /// the pending answer. Returns `Ok(0)` (nothing radiated) when
    /// idle.
    ///
    /// # Errors
    ///
    /// [`MacCmdError::BufferTooSmall`] when an answer is owed but
    /// `out` holds fewer than [`ASSOC_RSP_LEN`] octets.
    pub fn take_assoc_rsp(
        &mut self,
        seq: u8,
        short: u16,
        status: u8,
        out: &mut [u8],
    ) -> Result<usize, MacCmdError> {
        if !self.pending_assoc {
            return Ok(0);
        }
        let Some(eui) = self.dev_eui else {
            self.pending_assoc = false;
            return Ok(0);
        };
        build_assoc_rsp(seq, self.pan, &eui, self.short, short, status, out)?;
        self.pending_assoc = false;
        Ok(ASSOC_RSP_LEN)
    }
}

impl Default for CoordAssoc {
    fn default() -> Self {
        Self::new()
    }
}
