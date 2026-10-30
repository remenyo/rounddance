//! APS transport-key command dissector: names the join leg the chain
//! used to abandon at `trailing`.
//!
//! Every other stack layer already earns a named sub-leg (MAC command,
//! NWK command, ZDO, ZCL, Green Power, Touchlink); APS command frames
//! (`frame_type == 1`) stopped at an anonymous `trailing` note with
//! only the header command identifier filed. This module names the
//! transport-key command (`0x05`, the frame the Trust-Center-first
//! join turns on) by its key type over the live and spec-agreed
//! shapes: the network-key descriptor is an exact 33 octets (key +
//! sequence + destination + source), the Trust-Center-link and
//! application-link descriptors carry optional trailing TLVs so only
//! their fixed prefixes gate the name. Key bytes are never rendered —
//! the node carries the key type alone, exactly as Touchlink order
//! bodies keep wrapped keys sealed. Reserved key types and every other
//! command identifier file as [`ApsCmdKind::Unknown`] with the
//! identifier, never a guess. Only an empty payload refuses outright.

use crate::tree::{ApsCmdKind, ApsCmdNode};

/// APS transport-key command identifier (Table 4-31).
pub const CMD_TRANSPORT_KEY: u8 = 0x05;

/// Standard key type: network key (Table 4-9; 33-octet descriptor).
pub const KEY_TYPE_NETWORK: u8 = 0x01;
/// Standard key type: application link key (Table 4-9; 25-octet fixed
/// prefix plus optional TLVs).
pub const KEY_TYPE_APP_LINK: u8 = 0x03;
/// Standard key type: Trust-Center link key (Table 4-9; 32-octet fixed
/// prefix plus optional TLVs).
pub const KEY_TYPE_TC_LINK: u8 = 0x04;

/// APS command dissector failure (empty payload only: there is no
/// key type to name).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApsCmdError {
    /// No payload octets at all.
    Empty,
}

/// Dissect one APS command body (the octets past the header command
/// identifier, which the chain files on the APS envelope), on
/// unsecured as well as verified-open legs. Returns the tree node
/// plus the octets consumed, so the chain can file the remainder under
/// the terminal stop.
pub fn decode(cmd_id: u8, buf: &[u8]) -> Result<(ApsCmdNode, usize), ApsCmdError> {
    if buf.is_empty() {
        return Err(ApsCmdError::Empty);
    }
    let len = buf.len();
    let kind = match cmd_id {
        // Transport-key: the key type octet gates the fixed shape.
        // Lengths count the header command octet: the network-key
        // body is an exact 34 octets (type + 33-octet descriptor);
        // the link bodies admit trailing TLVs, so their fixed
        // prefixes are minimum gates. Reserved key types are never
        // guessed.
        CMD_TRANSPORT_KEY => {
            let key_type = buf[0];
            let fixed = match key_type {
                KEY_TYPE_NETWORK => len == 34,
                KEY_TYPE_TC_LINK => len >= 33,
                KEY_TYPE_APP_LINK => len >= 26,
                _ => false,
            };
            if fixed {
                ApsCmdKind::TransportKey { key_type }
            } else {
                ApsCmdKind::Unknown
            }
        }
        _ => ApsCmdKind::Unknown,
    };
    Ok((
        ApsCmdNode {
            command_id: cmd_id,
            kind,
            payload_len: (len + 1).min(u16::MAX as usize) as u16,
        },
        len,
    ))
}
