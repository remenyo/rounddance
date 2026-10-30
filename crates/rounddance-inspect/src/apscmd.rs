//! APS transport-key, update-device, remove-device, request-key, and
//! switch-key command dissector: names the join legs the chain used to
//! abandon at `trailing`.
//!
//! Every other stack layer already earns a named sub-leg (MAC command,
//! NWK command, ZDO, ZCL, Green Power, Touchlink); APS command frames
//! (`frame_type == 1`) stopped at an anonymous `trailing` note with
//! only the header command identifier filed. This module names the
//! transport-key command (`0x05`, the frame the Trust-Center-first
//! join turns on) by its key type over the live and spec-agreed
//! shapes, the update-device command (`0x06`, the router-to-Trust
//! Center status report) by its status + short over the spec Fig 4-13
//! fixed prefix: the 8-octet device address, the 2-octet device short
//! address, and the 1-octet status, with optional R23 JoinerTLVs after
//! them, so only the 11-octet fixed prefix gates the name, the
//! remove-device command (`0x07`, the Trust-Center-to-router removal
//! order) by its 8-octet device address alone: an exact 8-octet body
//! gate with no TLV tail, the request-key command (`0x08`, the
//! device-to-Trust-Center key request) by its 1-octet key type plus
//! the 8-octet partner address alone: an exact 9-octet body gate with
//! no TLV tail, and the switch-key command (`0x09`, the
//! Trust-Center-to-device key-switch order) by its 1-octet sequence
//! number alone: an exact 1-octet body gate with no TLV tail. Key bytes are never rendered — the transport-key
//! node carries the key type alone, exactly as Touchlink order bodies
//! keep wrapped keys sealed; the update-device, remove-device, and
//! request-key EUIs stay in the capture (the network-report EPID
//! precedent). Status and key-type values are never validated (the
//! network-status precedent). Reserved key types on the variable-shape
//! transport-key command and every other command identifier file as
//! [`ApsCmdKind::Unknown`] with the identifier, never a guess. Only an
//! empty payload refuses outright.

use crate::tree::{ApsCmdKind, ApsCmdNode};

/// APS transport-key command identifier (Table 4-31).
pub const CMD_TRANSPORT_KEY: u8 = 0x05;

/// APS update-device command identifier (Table 4-31).
pub const CMD_UPDATE_DEVICE: u8 = 0x06;

/// APS remove-device command identifier (Table 4-31).
pub const CMD_REMOVE_DEVICE: u8 = 0x07;

/// APS request-key command identifier (Table 4-31).
pub const CMD_REQUEST_KEY: u8 = 0x08;

/// APS switch-key command identifier (Table 4-31).
pub const CMD_SWITCH_KEY: u8 = 0x09;

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
        // Update-device: the Fig 4-13 fixed prefix (8-octet device
        // address + 2-octet short + 1-octet status) gates the name;
        // optional R23 JoinerTLVs after it are admitted unparsed, so
        // the gate is a minimum length. Status semantics are never
        // validated here.
        CMD_UPDATE_DEVICE => {
            if len >= 11 {
                ApsCmdKind::UpdateDevice {
                    status: buf[10],
                    short_addr: u16::from_le_bytes([buf[8], buf[9]]),
                }
            } else {
                ApsCmdKind::Unknown
            }
        }
        // Remove-device: the device address alone (8 octets, no
        // short, no status, no TLV tail), so the gate is exact. The
        // EUI stays in the capture, never in the node.
        CMD_REMOVE_DEVICE => {
            if len == 8 {
                ApsCmdKind::RemoveDevice
            } else {
                ApsCmdKind::Unknown
            }
        }
        // Request-key: the key type plus the partner address alone
        // (1 + 8 octets, no TLV tail), so the gate is exact. The
        // partner EUI stays in the capture, never in the node; the
        // key type rides the node unvalidated (the update-device
        // status precedent — the fixed length needs no type gate,
        // and no key material rides this command).
        CMD_REQUEST_KEY => {
            if len == 9 {
                ApsCmdKind::RequestKey { key_type: buf[0] }
            } else {
                ApsCmdKind::Unknown
            }
        }
        // Switch-key: the key sequence number alone (1 octet, no
        // addresses, no key material, no TLV tail), so the gate is
        // exact. The node carries the sequence alone — the
        // request-key key-type precedent; values are the stack's,
        // never validated here.
        CMD_SWITCH_KEY => {
            if len == 1 {
                ApsCmdKind::SwitchKey { key_seq: buf[0] }
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
