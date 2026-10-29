//! NWK command payload dissector: names the command leg the chain
//! used to abandon at `trailing`.
//!
//! Routing and leave shapes reuse the `rounddance-nwk` codecs (the
//! same parsers the stack decodes with). Rejoin-request /
//! rejoin-response and timeout-request / timeout-response have no
//! repo codec, so they are length-gated names over the live shapes
//! (capability octet; short + status; two preserved octets). Any
//! other identifier — or a named shape at an unexpected length —
//! files as [`NwkCmdKind::Unknown`] with its identifier, never a
//! guess. Only an empty payload refuses outright.

use crate::tree::{NwkCmdKind, NwkCmdNode};
use rounddance_nwk::commands as C;

/// NWK command dissector failure (empty payload only: there is no
/// command identifier to name).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NwkCmdError {
    /// No payload octets at all.
    Empty,
}

/// Dissect one NWK command payload (command identifier octet first),
/// on unsecured as well as verified-open legs. Returns the tree node
/// plus the octets consumed, so the chain can file the remainder
/// (codec TLV tails) under the terminal stop.
pub fn decode(buf: &[u8]) -> Result<(NwkCmdNode, usize), NwkCmdError> {
    if buf.is_empty() {
        return Err(NwkCmdError::Empty);
    }
    let id = buf[0];
    let len = buf.len();
    let (kind, consumed) = match id {
        C::CMD_ROUTE_REQUEST => match C::decode_route_request(buf) {
            Ok(d) => (
                NwkCmdKind::RouteRequest {
                    rreq_id: d.request.rreq_id,
                    dst_addr: d.request.dst_addr,
                },
                len - d.tlvs.len(),
            ),
            Err(_) => (NwkCmdKind::Unknown, 0),
        },
        C::CMD_ROUTE_REPLY => match C::decode_route_reply(buf) {
            Ok(d) => (
                NwkCmdKind::RouteReply {
                    rreq_id: d.reply.rreq_id,
                    originator: d.reply.originator,
                },
                len - d.tlvs.len(),
            ),
            Err(_) => (NwkCmdKind::Unknown, 0),
        },
        C::CMD_LINK_STATUS => match C::decode_link_status(buf) {
            Ok(d) => (
                NwkCmdKind::LinkStatus {
                    entries: d.len,
                    first_neighbor: d.entries().first().map(|e| e.neighbor).unwrap_or(0xffff),
                },
                len,
            ),
            Err(_) => (NwkCmdKind::Unknown, 0),
        },
        C::CMD_LEAVE => match C::decode_leave(buf) {
            Ok(d) => (
                NwkCmdKind::Leave {
                    options: d.leave.options.to_u8(),
                },
                len - d.tlvs.len(),
            ),
            Err(_) => (NwkCmdKind::Unknown, 0),
        },
        // Secured rejoin request: identifier + capability octet (the
        // live shape on every keys-kept rejoin; unsecured probes
        // share it).
        0x06 if len == 2 => (
            NwkCmdKind::RejoinRequest {
                capabilities: buf[1],
            },
            len,
        ),
        // Secured rejoin response: identifier + re-admitted short +
        // status (repeated per MAC retry on air).
        0x07 if len == 4 => (
            NwkCmdKind::RejoinResponse {
                short_addr: u16::from_le_bytes([buf[1], buf[2]]),
                status: buf[3],
            },
            len,
        ),
        // End-device timeout pair: 3-octet shape, layout unmodeled —
        // the two trailing octets are preserved, never parsed.
        0x0b if len >= 3 => (
            NwkCmdKind::TimeoutRequest {
                arg0: buf[1],
                arg1: buf[2],
            },
            3,
        ),
        0x0c if len >= 3 => (
            NwkCmdKind::TimeoutResponse {
                arg0: buf[1],
                arg1: buf[2],
            },
            3,
        ),
        _ => (NwkCmdKind::Unknown, 0),
    };
    Ok((
        NwkCmdNode {
            command_id: id,
            kind,
            payload_len: len.min(u16::MAX as usize) as u16,
        },
        consumed,
    ))
}
