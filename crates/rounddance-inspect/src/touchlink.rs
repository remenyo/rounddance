//! Touchlink (inter-PAN) payload dissector: the envelope the chain
//! routes broadcast-PAN MAC outers to instead of NWK.
//!
//! An inter-PAN MAC outer (data frame, unsecured, destination PAN
//! and destination both broadcast, broadcast source PAN) carries no
//! NWK header: the MSDU opens with a little-endian transaction
//! identifier (4 octets) plus a command octet, then a fixed-shape
//! body. The live wave-50 census names six commands — scan request
//! / response, network-start request / response, network-join
//! (router-join) request / response — each at one exact MSDU
//! length; anything else files as [`TouchlinkKind::Unknown`] with
//! its identifier, never a guess. Only a payload too short to hold
//! the transaction plus the command refuses outright. Bodies are
//! length-validated and named-field only (decode, never unwrap:
//! the wrapped key inside start/join orders stays sealed bytes).

use crate::tree::{TouchlinkKind, TouchlinkNode};

/// Scan request: factory-new probe leg.
pub const CMD_SCAN_REQ: u8 = 0x00;
/// Scan response: router information leg.
pub const CMD_SCAN_RSP: u8 = 0x01;
/// Network-start (commissioning) request: wrapped-key order leg.
pub const CMD_START_REQ: u8 = 0x10;
/// Network-start response: status leg.
pub const CMD_START_RSP: u8 = 0x11;
/// Network-join (router-join) request: wrapped-key order leg.
pub const CMD_JOIN_REQ: u8 = 0x12;
/// Network-join response: status leg.
pub const CMD_JOIN_RSP: u8 = 0x13;

/// MSDU length of a scan request (transaction + command + 2 body).
pub const SCAN_REQ_LEN: usize = 7;
/// MSDU length of a scan response (transaction + command + 25 body).
pub const SCAN_RSP_LEN: usize = 30;
/// MSDU length of a start request (transaction + command + 52 body).
pub const START_REQ_LEN: usize = 57;
/// MSDU length of a start response (transaction + command + 13 body).
pub const START_RSP_LEN: usize = 18;
/// MSDU length of a join request (transaction + command + 43 body).
pub const JOIN_REQ_LEN: usize = 48;
/// MSDU length of a join response (transaction + command + 1 body).
pub const JOIN_RSP_LEN: usize = 6;

/// Touchlink dissector failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchlinkError {
    /// Fewer than the 4 transaction octets plus the command octet.
    Empty,
    /// Named command at an unexpected MSDU length (fixed shapes
    /// only — a truncated order is a refusal, never a partial leg).
    Length {
        /// Command identifier.
        command_id: u8,
        /// MSDU length seen (transaction + command + body).
        len: usize,
    },
}

/// Dissect one inter-PAN MSDU (transaction LE + command + body).
/// Returns the tree node plus the octets consumed (always the full
/// MSDU: named shapes are exact, unknown commands file whole).
pub fn decode(buf: &[u8]) -> Result<(TouchlinkNode, usize), TouchlinkError> {
    if buf.len() < 5 {
        return Err(TouchlinkError::Empty);
    }
    let tid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let cmd = buf[4];
    let body = &buf[5..];
    let len = buf.len();
    let kind = match cmd {
        CMD_SCAN_REQ if len == SCAN_REQ_LEN => TouchlinkKind::ScanReq {
            zigbee_info: body[0],
            touchlink_info: body[1],
        },
        CMD_SCAN_RSP if len == SCAN_RSP_LEN => TouchlinkKind::ScanRsp {
            key_mask: u16::from_le_bytes([body[3], body[4]]),
        },
        CMD_START_REQ if len == START_REQ_LEN => TouchlinkKind::StartReq { key_index: body[8] },
        CMD_START_RSP if len == START_RSP_LEN => TouchlinkKind::StartRsp { status: body[0] },
        CMD_JOIN_REQ if len == JOIN_REQ_LEN => TouchlinkKind::JoinReq { key_index: body[8] },
        CMD_JOIN_RSP if len == JOIN_RSP_LEN => TouchlinkKind::JoinRsp { status: body[0] },
        CMD_SCAN_REQ | CMD_SCAN_RSP | CMD_START_REQ | CMD_START_RSP | CMD_JOIN_REQ
        | CMD_JOIN_RSP => {
            return Err(TouchlinkError::Length {
                command_id: cmd,
                len,
            });
        }
        _ => TouchlinkKind::Unknown,
    };
    Ok((
        TouchlinkNode {
            tid,
            command_id: cmd,
            kind,
            payload_len: len.min(u16::MAX as usize) as u16,
        },
        len,
    ))
}
