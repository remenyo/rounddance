//! Green-Power device-frame dissector: reused `rounddance-gp` codec
//! → [`GpNode`](crate::tree::GpNode).
//!
//! GPDFs ride straight in the 802.15.4 MAC payload (stub NWK,
//! protocol version 3), so the chain only reaches here after the
//! stack NWK codec refuses the bytes. Every decodable frame names a
//! leg: frame control (data vs maintenance, auto-commissioning),
//! addressing (source identifier or IEEE address plus endpoint), the
//! protection level with key bit, the receive-after-transmit request
//! (bidirectional-reply window), the security frame counter, and the
//! command section — commissioning, data, and reply-window shapes
//! alike. Counter-protected and encrypted shapes name exactly what
//! travels in the clear: a sealed command section stays
//! [`GpKind::EncryptedSealed`] with no command identifier until a
//! verified [`crate::decrypt`] open reveals it. Bodies stay
//! unmodeled by design (as with ZDO envelopes): the command
//! identifier plus payload length are always filed, never a guess.

use crate::tree::{GpKind, GpNode};
use rounddance_gp::frame::{AppId, FrameType, Gpdf, GpdfBody, WireSecurityLevel};

/// Green-Power dissector failure (codec refusal, passed through).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpError {
    /// Codec refusal; discriminant preserved for the report.
    Codec(u8),
}

/// Map the codec error to a stable small discriminant for reports.
fn discriminant(e: rounddance_gp::frame::GpError) -> u8 {
    use rounddance_gp::frame::GpError as E;
    match e {
        E::TooSmall | E::PayloadTooLarge => 1,
        E::Truncated | E::MissingExtControl | E::ForbiddenExtControl | E::BadIdentifier => 2,
        E::ReservedFrameType(_)
        | E::BadVersion(_)
        | E::ForeignAppId(_)
        | E::ReservedSecurityLevel(_) => 3,
        E::ProxyOriginated
        | E::ConflictingFlags
        | E::UnsecuredCommissioning
        | E::BadMaintenanceCommand => 4,
        _ => 5,
    }
}

/// Application-identifier value carried in the node.
fn app_id_bits(app: AppId) -> u8 {
    match app {
        AppId::SrcId => 0,
        AppId::Lped => 1,
        AppId::Ieee => 2,
    }
}

/// Protection-level value carried in the node (0 none, 2 MIC, 3 enc).
fn level_bits(level: WireSecurityLevel) -> u8 {
    match level {
        WireSecurityLevel::None => 0,
        WireSecurityLevel::MicOnly => 2,
        WireSecurityLevel::Encrypted => 3,
    }
}

/// Name one data-frame command identifier. The six reply-path
/// identifiers reuse the `rounddance-gp` reply codec's command
/// values; every other data command is the open data-command class.
/// Sealed (encrypted, unverified) sections never reach here.
fn data_kind(command: u8) -> GpKind {
    use rounddance_gp::reply as R;
    match command {
        c if c == R::CMD_COMMISSIONING => GpKind::Commissioning,
        c if c == R::CMD_DECOMMISSIONING => GpKind::Decommissioning,
        c if c == R::CMD_SUCCESS => GpKind::Success,
        c if c == R::CMD_CHANNEL_REQUEST => GpKind::ChannelRequest,
        c if c == R::CMD_COMMISSIONING_REPLY => GpKind::CommissioningReply,
        c if c == R::CMD_CHANNEL_CONFIG => GpKind::ChannelConfig,
        _ => GpKind::Data,
    }
}

/// Build the node from a decoded GPDF plus an optional verified
/// command section. `plain` carries the integrity-checked command
/// section (command identifier first) after a
/// [`crate::decrypt`] open; `None` names only what travels in the
/// clear — an encrypted, unverified section seals the command.
fn node_from(gpdf: &Gpdf<'_>, plain: Option<&[u8]>) -> GpNode {
    let frame_type = match gpdf.fc.frame_type {
        FrameType::Data => 0,
        FrameType::Maintenance => 1,
    };
    let (app_id, level_bits_v, key_bit, rx_after_tx, direction_proxy) = match gpdf.ext {
        Some(ext) => (
            app_id_bits(ext.app_id),
            level_bits(ext.level),
            ext.key_bit,
            ext.rx_after_tx,
            ext.direction_proxy,
        ),
        None => (0, 0, false, false, false),
    };
    let (src_id, ieee, endpoint) = match gpdf.id {
        Some(rounddance_gp::frame::GpdId::SrcId(id)) => (id, None, None),
        Some(rounddance_gp::frame::GpdId::Ieee { addr, endpoint }) => {
            (0, Some(u64::from_le_bytes(addr)), Some(endpoint))
        }
        None => (0, None, None),
    };
    let secured = level_bits_v == 2 || level_bits_v == 3;
    // Maintenance frames and LPED bodies carry no GPD command
    // envelope; an encrypted, unverified section is opaque; anything
    // else names the (verified or cleartext) command section.
    if matches!(gpdf.fc.frame_type, FrameType::Maintenance) {
        let (command_id, payload_len) = match gpdf.body {
            GpdfBody::Gp { command, payload } => (Some(command), payload.len()),
            GpdfBody::LpedOpaque(raw) => (None, raw.len()),
        };
        return GpNode {
            frame_type,
            auto_commissioning: gpdf.fc.auto_commissioning,
            app_id: app_id_bits(AppId::SrcId),
            level: 0,
            key_bit: false,
            rx_after_tx: false,
            direction_proxy: false,
            src_id: 0,
            ieee: None,
            endpoint: None,
            frame_counter: None,
            command_id,
            kind: GpKind::Maintenance,
            payload_len: payload_len.min(u16::MAX as usize) as u16,
            secured: false,
        };
    }
    if matches!(gpdf.ext.map(|e| e.app_id), Some(AppId::Lped)) {
        let len = match gpdf.body {
            GpdfBody::LpedOpaque(raw) => raw.len(),
            GpdfBody::Gp { payload, .. } => payload.len() + 1,
        };
        return GpNode {
            frame_type,
            auto_commissioning: gpdf.fc.auto_commissioning,
            app_id,
            level: level_bits_v,
            key_bit,
            rx_after_tx,
            direction_proxy,
            src_id: 0,
            ieee: None,
            endpoint: None,
            frame_counter: gpdf.frame_counter,
            command_id: None,
            kind: GpKind::LpedOpaque,
            payload_len: len.min(u16::MAX as usize) as u16,
            secured,
        };
    }
    if secured && level_bits_v == 3 && plain.is_none() {
        return GpNode {
            frame_type,
            auto_commissioning: gpdf.fc.auto_commissioning,
            app_id,
            level: level_bits_v,
            key_bit,
            rx_after_tx,
            direction_proxy,
            src_id,
            ieee,
            endpoint,
            frame_counter: gpdf.frame_counter,
            command_id: None,
            kind: GpKind::EncryptedSealed,
            payload_len: 0,
            secured,
        };
    }
    let (command_id, payload_len) = match plain {
        Some(cmd) if !cmd.is_empty() => (Some(cmd[0]), cmd.len() - 1),
        _ => match gpdf.body {
            GpdfBody::Gp { command, payload } => (Some(command), payload.len()),
            GpdfBody::LpedOpaque(raw) => (None, raw.len()),
        },
    };
    let kind = match command_id {
        Some(c) => data_kind(c),
        None => GpKind::LpedOpaque,
    };
    GpNode {
        frame_type,
        auto_commissioning: gpdf.fc.auto_commissioning,
        app_id,
        level: level_bits_v,
        key_bit,
        rx_after_tx,
        direction_proxy,
        src_id,
        ieee,
        endpoint,
        frame_counter: gpdf.frame_counter,
        command_id,
        kind,
        payload_len: payload_len.min(u16::MAX as usize) as u16,
        secured,
    }
}

/// Dissect one MAC-payload GPDF; names every visible field. An
/// encrypted, unverified command section seals the command
/// identifier ([`GpKind::EncryptedSealed`]).
pub fn decode(msdu: &[u8]) -> Result<GpNode, GpError> {
    match Gpdf::decode(msdu) {
        Ok((gpdf, _)) => Ok(node_from(&gpdf, None)),
        Err(e) => Err(GpError::Codec(discriminant(e))),
    }
}

/// Dissect one MAC-payload GPDF with a verified command section
/// from a [`crate::decrypt`] open: the header still comes from the
/// air bytes, the command envelope from the checked plaintext.
pub fn decode_opened(msdu: &[u8], plain: &[u8]) -> Result<GpNode, GpError> {
    match Gpdf::decode(msdu) {
        Ok((gpdf, _)) => Ok(node_from(&gpdf, Some(plain))),
        Err(e) => Err(GpError::Codec(discriminant(e))),
    }
}
