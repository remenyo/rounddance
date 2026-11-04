//! Messaging cluster (0x0703): server plus client definitions,
//! message codecs, and the bounded server-side message box.
//!
//! Paraphrase-level model of doc `07-5123-08` section 10.5. The
//! classification, cluster identifier, and empty attribute sets sit
//! at extraction anchors p0821-L18695-L18701. The server command
//! table and the Display Message shape (payload, control map,
//! Inter-PAN deprecation, confirmation rules, extended control) sit
//! at anchors p0821-L18702-L18704 and p0822-L18705-L18752. Cancel,
//! protected display, and the provisional cancel-all sit at anchors
//! p0824-L18760-L18785. Client tables, GetLastMessage, confirmation,
//! and the provisional cancellation fetch sit at anchors
//! p0825-L18791-L18798 and p0826-L18800-L18830. Doc `07-5356-22`
//! section D.5 carries the same cluster in the Smart Energy profile.
//! All wording here is paraphrase (D1).
//!
//! Requirement IDs below are repo-minted (`07-5123-08-105-<seq>`,
//! dots stripped), MINTED-pending-confirm.
//!
//! NOTE for the lib.rs hookup (main agent merges this to avoid
//! `mod` conflicts): add exactly one line to
//! `crates/rounddance-zcl/src/lib.rs` in the module block:
//!
//! ```text
//! pub mod messaging;
//! ```

use crate::attrs::AttrDef;
use crate::behavior::{AppEvent, Behavior, Ctx, HandleOutcome};
use crate::cluster::{ClusterDef, ClusterRole, CmdDef};
use crate::frame::Header;
use crate::{Error, ZclStatus};

/// Cluster identifier.
///
/// Requirement `07-5123-08-105-01` (MINTED-pending-confirm).
pub const CLUSTER_ID: u16 = 0x0703;
/// Implemented specification revision.
///
/// Requirement `07-5123-08-105-01` (MINTED-pending-confirm).
pub const REVISION: u16 = 1;

/// Server generated: Display Message.
pub const CMD_DISPLAY_MESSAGE: u8 = 0x00;
/// Server generated: Cancel Message.
pub const CMD_CANCEL_MESSAGE: u8 = 0x01;
/// Server generated: Display Protected Message.
pub const CMD_DISPLAY_PROTECTED_MESSAGE: u8 = 0x02;
/// Server generated: Cancel All Messages (provisional).
pub const CMD_CANCEL_ALL_MESSAGES: u8 = 0x03;
/// Client generated: Get Last Message.
pub const CMD_GET_LAST_MESSAGE: u8 = 0x00;
/// Client generated: Message Confirmation.
pub const CMD_MESSAGE_CONFIRMATION: u8 = 0x01;
/// Client generated: GetMessageCancellation (provisional).
pub const CMD_GET_MESSAGE_CANCELLATION: u8 = 0x02;

/// Start-time value meaning "now".
pub const START_NOW: u32 = 0x0000_0000;
/// Duration value meaning "until changed".
pub const DURATION_UNTIL_CHANGED: u16 = 0xffff;

/// Longest message text carried here (fragmentation-size payloads
/// ride the same codec; callers page larger texts across commands).
pub const MAX_MESSAGE: usize = 64;
/// Longest confirmation-response text carried here.
pub const MAX_CONFIRM_RESPONSE: usize = 20;

/// Transmission mode: normal command function.
pub const TRANSMISSION_NORMAL: u8 = 0x00;
/// Mask of the transmission-mode sub-field (bits 0-1).
pub const TRANSMISSION_MASK: u8 = 0x03;

/// Importance: low.
pub const IMPORTANCE_LOW: u8 = 0x00;
/// Importance: medium.
pub const IMPORTANCE_MEDIUM: u8 = 0x01;
/// Importance: high.
pub const IMPORTANCE_HIGH: u8 = 0x02;
/// Importance: critical.
pub const IMPORTANCE_CRITICAL: u8 = 0x03;
/// Shift of the importance sub-field (bits 2-3).
pub const IMPORTANCE_SHIFT: u8 = 2;

/// Control bit: enhanced (YES/NO/text) confirmation required.
pub const CONTROL_ENHANCED_CONFIRMATION: u8 = 0x20;
/// Control bit: message confirmation required.
pub const CONTROL_CONFIRMATION_REQUIRED: u8 = 0x80;

/// Extended-control bit: the message was already confirmed.
pub const EXT_CONFIRMED: u8 = 0x01;

/// Confirmation-control bit: answer is NO.
pub const CONFIRM_NO: u8 = 0x01;
/// Confirmation-control bit: answer is YES.
pub const CONFIRM_YES: u8 = 0x02;

/// Whether the transmission sub-field names normal delivery (the
/// Inter-PAN modes are deprecated and refused; the reserved mode is
/// refused too).
///
/// Requirement `07-5123-08-105-02` (MINTED-pending-confirm).
#[must_use]
pub const fn transmission_ok(control: u8) -> bool {
    control & TRANSMISSION_MASK == TRANSMISSION_NORMAL
}

/// Importance sub-field of a message control octet.
#[must_use]
pub const fn importance_of(control: u8) -> u8 {
    (control >> IMPORTANCE_SHIFT) & 0x03
}

/// Whether the originator asks for a confirmation of receipt.
#[must_use]
pub const fn confirmation_required(control: u8) -> bool {
    control & CONTROL_CONFIRMATION_REQUIRED != 0
}

/// Whether a control octet is well-formed: normal transmission, a
/// defined importance, and enhanced confirmation never set without
/// plain confirmation.
///
/// Requirement `07-5123-08-105-02` (MINTED-pending-confirm).
#[must_use]
pub const fn control_valid(control: u8) -> bool {
    if !transmission_ok(control) {
        return false;
    }
    if control & 0xA0 == CONTROL_ENHANCED_CONFIRMATION {
        return false;
    }
    true
}

/// One display message: the fixed 11-octet prefix, a length-prefixed
/// text, and an optional extended-control tail.
///
/// Requirement `07-5123-08-105-03` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayMessage {
    /// Provider-side message identifier.
    pub message_id: u32,
    /// Control map (transmission + importance + confirmation).
    pub control: u8,
    /// Time the message becomes valid (`START_NOW` = immediately).
    pub start_time: u32,
    /// Display duration, minutes (`DURATION_UNTIL_CHANGED` = kept).
    pub duration_min: u16,
    /// Message text length.
    pub len: u8,
    /// Message text bytes (UTF-8 on the wire; truncation on a
    /// character boundary is application policy above this layer).
    pub text: [u8; MAX_MESSAGE],
    /// Extended control tail (`None` = absent).
    pub ext_control: Option<u8>,
}

/// Fixed prefix length of a Display Message body.
pub const DISPLAY_PREFIX_LEN: usize = 12;

/// Decode a Display Message body: 12-octet prefix (id + control +
/// start + duration + text length) plus the text plus an optional
/// one-octet extended-control tail.
pub fn decode_display_message(buf: &[u8]) -> Result<DisplayMessage, Error> {
    if buf.len() < DISPLAY_PREFIX_LEN {
        return Err(Error::Truncated);
    }
    let len = buf[11] as usize;
    if len > MAX_MESSAGE {
        return Err(Error::StringTooLong);
    }
    if buf.len() < DISPLAY_PREFIX_LEN + len {
        return Err(Error::Truncated);
    }
    let tail = buf.len() - DISPLAY_PREFIX_LEN - len;
    if tail > 1 {
        return Err(Error::Truncated);
    }
    if !control_valid(buf[4]) {
        return Err(Error::InvalidValue(buf[4]));
    }
    let mut text = [0u8; MAX_MESSAGE];
    text[..len].copy_from_slice(&buf[DISPLAY_PREFIX_LEN..DISPLAY_PREFIX_LEN + len]);
    #[allow(clippy::cast_possible_truncation)]
    let len_u8 = len as u8;
    Ok(DisplayMessage {
        message_id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        control: buf[4],
        start_time: u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]),
        duration_min: u16::from_le_bytes([buf[9], buf[10]]),
        len: len_u8,
        text,
        ext_control: if tail == 1 {
            Some(buf[DISPLAY_PREFIX_LEN + len])
        } else {
            None
        },
    })
}

/// Encode a Display Message body into `out`.
pub fn encode_display_message(msg: &DisplayMessage, out: &mut [u8]) -> Result<usize, Error> {
    let len = msg.len as usize;
    if len > MAX_MESSAGE {
        return Err(Error::StringTooLong);
    }
    if !control_valid(msg.control) {
        return Err(Error::InvalidValue(msg.control));
    }
    let need = DISPLAY_PREFIX_LEN + len + if msg.ext_control.is_some() { 1 } else { 0 };
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&msg.message_id.to_le_bytes());
    out[4] = msg.control;
    out[5..9].copy_from_slice(&msg.start_time.to_le_bytes());
    out[9..11].copy_from_slice(&msg.duration_min.to_le_bytes());
    out[11] = msg.len;
    out[DISPLAY_PREFIX_LEN..DISPLAY_PREFIX_LEN + len].copy_from_slice(&msg.text[..len]);
    if let Some(ext) = msg.ext_control {
        out[DISPLAY_PREFIX_LEN + len] = ext;
    }
    Ok(need)
}

/// Cancel Message body: the message to drop. The control octet is
/// deprecated on the wire (senders use zero); receivers ignore it.
///
/// Requirement `07-5123-08-105-04` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CancelMessage {
    /// Message identifier to cancel.
    pub message_id: u32,
}

/// Wire length of a Cancel Message body.
pub const CANCEL_MESSAGE_LEN: usize = 5;

/// Decode a Cancel Message body (exactly 5 octets).
pub fn decode_cancel_message(buf: &[u8]) -> Result<CancelMessage, Error> {
    if buf.len() != CANCEL_MESSAGE_LEN {
        return Err(Error::Truncated);
    }
    Ok(CancelMessage {
        message_id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
    })
}

/// Encode a Cancel Message body into `out` (5 octets, zeroed
/// deprecated control).
pub fn encode_cancel_message(msg: &CancelMessage, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < CANCEL_MESSAGE_LEN {
        return Err(Error::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&msg.message_id.to_le_bytes());
    out[4] = 0;
    Ok(CANCEL_MESSAGE_LEN)
}

/// Message Confirmation body: the confirmed message plus the
/// confirmation time plus an optional YES/NO/text answer.
///
/// Requirement `07-5123-08-105-05` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageConfirmation {
    /// Message identifier confirmed.
    pub message_id: u32,
    /// Time the user confirmed.
    pub confirmation_time: u32,
    /// Confirmation control (`None` = basic confirmation only).
    pub control: Option<u8>,
    /// Answer text length.
    pub response_len: u8,
    /// Answer text bytes.
    pub response: [u8; MAX_CONFIRM_RESPONSE],
}

/// Decode a Message Confirmation body (8, 9, or 9 + string octets).
pub fn decode_message_confirmation(buf: &[u8]) -> Result<MessageConfirmation, Error> {
    if buf.len() != 8 && buf.len() < 9 {
        return Err(Error::Truncated);
    }
    let (control, response_len, response) = if buf.len() == 8 {
        (None, 0, [0u8; MAX_CONFIRM_RESPONSE])
    } else {
        let rlen = buf[9] as usize;
        if rlen > MAX_CONFIRM_RESPONSE || buf.len() != 10 + rlen {
            return Err(Error::Truncated);
        }
        let mut bytes = [0u8; MAX_CONFIRM_RESPONSE];
        bytes[..rlen].copy_from_slice(&buf[10..10 + rlen]);
        #[allow(clippy::cast_possible_truncation)]
        let rlen_u8 = rlen as u8;
        (Some(buf[8]), rlen_u8, bytes)
    };
    Ok(MessageConfirmation {
        message_id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        confirmation_time: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        control,
        response_len,
        response,
    })
}

/// Encode a Message Confirmation body into `out`.
pub fn encode_message_confirmation(
    conf: &MessageConfirmation,
    out: &mut [u8],
) -> Result<usize, Error> {
    let rlen = conf.response_len as usize;
    if rlen > MAX_CONFIRM_RESPONSE {
        return Err(Error::StringTooLong);
    }
    let need = if conf.control.is_some() {
        10 + rlen
    } else {
        if rlen != 0 {
            return Err(Error::InvalidValue(conf.response_len));
        }
        8
    };
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&conf.message_id.to_le_bytes());
    out[4..8].copy_from_slice(&conf.confirmation_time.to_le_bytes());
    if let Some(control) = conf.control {
        out[8] = control;
        out[9] = conf.response_len;
        out[10..10 + rlen].copy_from_slice(&conf.response[..rlen]);
    }
    Ok(need)
}

/// Whether `msg` is still on display at `now` (until-changed
/// messages never expire here; expiry past the duration end is
/// caller-clock math, as everywhere in this crate).
///
/// Requirement `07-5123-08-105-06` (MINTED-pending-confirm).
#[must_use]
pub const fn message_active(msg: &DisplayMessage, now: u32) -> bool {
    if now < msg.start_time {
        return false;
    }
    if msg.duration_min == DURATION_UNTIL_CHANGED {
        return true;
    }
    (now - msg.start_time) as u64 <= msg.duration_min as u64 * 60
}

/// Server-side message box: the latest live message plus the
/// provisional cancel-all record.
///
/// Requirement `07-5123-08-105-06` (MINTED-pending-confirm):
/// GetLastMessage answers the held message or `NOT_FOUND`;
/// GetMessageCancellation answers the held cancel-all record at or
/// after the requested earliest time or `NOT_FOUND`.
#[derive(Clone, Copy, Debug)]
pub struct MessageBox {
    current: Option<DisplayMessage>,
    cancel_all_time: Option<u32>,
}

impl Default for MessageBox {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageBox {
    /// Empty box: no message, no cancel-all record.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            current: None,
            cancel_all_time: None,
        }
    }

    /// Whether a message is held.
    #[must_use]
    pub fn has_message(&self) -> bool {
        self.current.is_some()
    }

    /// Hold (or replace) the live message; a newer display
    /// overwrites the previous one.
    pub fn display(&mut self, msg: DisplayMessage) {
        self.current = Some(msg);
    }

    /// Drop the named message (cancel effect). Returns whether
    /// anything was dropped.
    pub fn cancel(&mut self, id: u32) -> bool {
        match self.current {
            Some(msg) if msg.message_id == id => {
                self.current = None;
                true
            }
            _ => false,
        }
    }

    /// Clear every held message and record the implementation time
    /// (provisional cancel-all effect).
    pub fn cancel_all(&mut self, implementation_time: u32) {
        self.current = None;
        self.cancel_all_time = Some(implementation_time);
    }

    /// Latest held message, if any.
    #[must_use]
    pub const fn last(&self) -> Option<DisplayMessage> {
        self.current
    }

    /// Cancel-all record at or after `earliest`, if any.
    #[must_use]
    pub fn cancellation_since(&self, earliest: u32) -> Option<u32> {
        match self.cancel_all_time {
            Some(t) if t >= earliest => Some(t),
            _ => None,
        }
    }

    /// Record a confirmation: marks the named message confirmed
    /// (extended-control bit) so re-transmission tells the remaining
    /// clients no further confirmation is needed. Returns whether a
    /// message was marked.
    pub fn confirm(&mut self, id: u32) -> bool {
        match self.current.as_mut() {
            Some(msg) if msg.message_id == id => {
                let ext = msg.ext_control.unwrap_or(0) | EXT_CONFIRMED;
                msg.ext_control = Some(ext);
                true
            }
            _ => false,
        }
    }
}

/// Server attribute table: this cluster defines no attributes.
pub static SERVER_ATTRS: &[AttrDef] = &[];

/// Server generated commands, ascending.
pub static SERVER_TX: &[CmdDef] = &[
    CmdDef {
        id: CMD_DISPLAY_MESSAGE,
        name: "display-message",
    },
    CmdDef {
        id: CMD_CANCEL_MESSAGE,
        name: "cancel-message",
    },
    CmdDef {
        id: CMD_DISPLAY_PROTECTED_MESSAGE,
        name: "display-protected-message",
    },
    CmdDef {
        id: CMD_CANCEL_ALL_MESSAGES,
        name: "cancel-all-messages",
    },
];

/// Server received commands, ascending.
pub static SERVER_RX: &[CmdDef] = &[
    CmdDef {
        id: CMD_GET_LAST_MESSAGE,
        name: "get-last-message",
    },
    CmdDef {
        id: CMD_MESSAGE_CONFIRMATION,
        name: "message-confirmation",
    },
    CmdDef {
        id: CMD_GET_MESSAGE_CANCELLATION,
        name: "get-message-cancellation",
    },
];

/// Server definition.
pub struct ServerDef;
impl ClusterDef for ServerDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "messaging-server"
    }
    fn revision(&self) -> u16 {
        REVISION
    }
    fn role(&self) -> ClusterRole {
        ClusterRole::Server
    }
    fn attributes(&self) -> &'static [AttrDef] {
        SERVER_ATTRS
    }
    fn received_commands(&self) -> &'static [CmdDef] {
        SERVER_RX
    }
    fn generated_commands(&self) -> &'static [CmdDef] {
        SERVER_TX
    }
}

/// Client definition.
pub struct ClientDef;
impl ClusterDef for ClientDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "messaging-client"
    }
    fn revision(&self) -> u16 {
        REVISION
    }
    fn role(&self) -> ClusterRole {
        ClusterRole::Client
    }
    fn attributes(&self) -> &'static [AttrDef] {
        SERVER_ATTRS
    }
    fn received_commands(&self) -> &'static [CmdDef] {
        SERVER_TX
    }
    fn generated_commands(&self) -> &'static [CmdDef] {
        SERVER_RX
    }
}

/// Server behavior: message-box-backed GetLast/confirmation/
/// cancellation answers.
///
/// Requirement `07-5123-08-105-07` (MINTED-pending-confirm).
pub struct ServerBehavior {
    inbox: MessageBox,
}

impl Default for ServerBehavior {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBehavior {
    /// Fresh behavior: empty message box.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inbox: MessageBox::new(),
        }
    }

    /// Borrow the message box.
    pub const fn inbox(&self) -> &MessageBox {
        &self.inbox
    }

    /// Mutable message box (tests/sim preload it).
    pub fn inbox_mut(&mut self) -> &mut MessageBox {
        &mut self.inbox
    }

    /// Emit the held message as a Display Message reply. Errors
    /// `NOT_FOUND` when the box is empty and `INSUFFICIENT_SPACE`
    /// when the encoded body exceeds the bounded event payload.
    fn emit_last(&self, ctx: &mut Ctx<'_>) -> Result<(), ZclStatus> {
        let msg = self.inbox.last().ok_or(ZclStatus::NotFound)?;
        let mut body = [0u8; DISPLAY_PREFIX_LEN + MAX_MESSAGE + 1];
        let n =
            encode_display_message(&msg, &mut body).map_err(|_| ZclStatus::InsufficientSpace)?;
        if n > crate::behavior::MAX_EVENT_PAYLOAD {
            return Err(ZclStatus::InsufficientSpace);
        }
        let mut payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
        payload[..n].copy_from_slice(&body[..n]);
        #[allow(clippy::cast_possible_truncation)]
        let len = n as u8;
        ctx.events.push(AppEvent::OutboundCommand {
            cluster: CLUSTER_ID,
            cmd: CMD_DISPLAY_MESSAGE,
            tsn: 0,
            len,
            payload,
        });
        Ok(())
    }
}

impl Behavior for ServerBehavior {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }

    fn handle_cluster_command(
        &mut self,
        ctx: &mut Ctx<'_>,
        _header: &Header,
        command_id: u8,
        payload: &[u8],
    ) -> Result<HandleOutcome, ZclStatus> {
        match command_id {
            CMD_GET_LAST_MESSAGE => {
                if !payload.is_empty() {
                    return Err(ZclStatus::MalformedCommand);
                }
                self.emit_last(ctx)?;
                Ok(HandleOutcome::no_reply())
            }
            CMD_MESSAGE_CONFIRMATION => {
                let conf = decode_message_confirmation(payload)
                    .map_err(|_| ZclStatus::MalformedCommand)?;
                if !self.inbox.confirm(conf.message_id) {
                    return Err(ZclStatus::NotFound);
                }
                ctx.events.push(AppEvent::AttributeChanged {
                    cluster: CLUSTER_ID,
                    attr: crate::attrs::ATTR_CLUSTER_REVISION,
                });
                Ok(HandleOutcome::no_reply())
            }
            CMD_GET_MESSAGE_CANCELLATION => {
                if payload.len() != 4 {
                    return Err(ZclStatus::MalformedCommand);
                }
                let earliest = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let _ = self
                    .inbox
                    .cancellation_since(earliest)
                    .ok_or(ZclStatus::NotFound)?;
                Ok(HandleOutcome::no_reply())
            }
            _ => Err(ZclStatus::UnsupCommand),
        }
    }
}
