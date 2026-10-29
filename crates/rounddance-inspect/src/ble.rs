//! BLE/ATT decode leg: HCI framing → ATT opcodes → Direct envelopes.
//!
//! Decode-only, no crypto. HCI records arrive as one btsnoop record
//! each (see [`crate::btsnoop`]): the flags discriminate commands,
//! events, and ACL directions; the payload is the raw HCI packet
//! without the H4 type octet. ATT PDUs ride L2CAP CID `0x0004`.
//! Handles are always decoded; values stay length-named — the only
//! value legs are the Direct discovery bitmap (UUIDs attributed
//! against the reused `rounddance-direct` GATT tables, never a
//! parallel table here) and the Direct TLV envelope (tags, counts,
//! and the Status domain/code — bodies are never carried, since
//! commissioning values may seal key material).

use crate::tree::{AttKind, AttNode, DirectKind, DirectNode, HciKind, HciNode};
use rounddance_direct::{attr, gatt};

/// btsnoop record flags: host-to-controller HCI command.
pub const FLAGS_HCI_CMD: u32 = 2;
/// btsnoop record flags: controller-to-host HCI event.
pub const FLAGS_HCI_EVT: u32 = 3;
/// btsnoop record flags: host-to-controller ACL data.
pub const FLAGS_ACL_TX: u32 = 4;
/// btsnoop record flags: controller-to-host ACL data.
pub const FLAGS_ACL_RX: u32 = 5;

/// ATT L2CAP channel identifier: every ATT PDU rides CID `0x0004`.
pub const ATT_CID: u16 = 0x0004;
/// HCI event code for LE Meta (carries the subevent octet).
pub const EVT_LE_META: u8 = 0x3e;
/// Direct Status-Code TLV tag (see `rounddance-direct` attributes).
pub const STATUS_TAG: u8 = 0x0e;
/// Direct UUIDs attributed: 2 services + 3 security + 8
/// commissioning characteristics.
pub const DIRECT_UUID_COUNT: usize =
    gatt::DIRECT_SERVICES.len() + gatt::SECURITY_CHARS.len() + gatt::COMMISSIONING_CHARS.len();

/// BLE dissector failure (bounded, typed — never a panic).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BleError {
    /// No record octets at all.
    Empty,
    /// Record ends mid-header (HCI header, L2CAP header, or ATT
    /// fixed shape).
    Truncated,
    /// Unknown btsnoop flags, L2CAP length mismatch, or wrong fixed
    /// parameter length.
    Malformed,
}

/// Decode one btsnoop HCI record payload under `flags` (2 = command,
/// 3 = event, 4 = ACL TX, 5 = ACL RX). Returns the HCI node plus the
/// ATT PDU slice for ACL records carrying CID `0x0004` (`None` for
/// commands/events and for ACL records on other CIDs — the chain
/// files those with a `ble-unknown` stop beside the HCI leg).
pub fn decode_hci(flags: u32, buf: &[u8]) -> Result<(HciNode, Option<&[u8]>), BleError> {
    if buf.is_empty() {
        return Err(BleError::Empty);
    }
    match flags {
        FLAGS_HCI_CMD => {
            if buf.len() < 3 {
                return Err(BleError::Truncated);
            }
            let plen = buf[2] as usize;
            if buf.len() < 3 + plen {
                return Err(BleError::Truncated);
            }
            if buf.len() > 3 + plen {
                return Err(BleError::Malformed);
            }
            Ok((
                HciNode {
                    kind: HciKind::Command,
                    conn_handle: None,
                    opcode: Some(u16::from_le_bytes([buf[0], buf[1]])),
                    event: None,
                    subevent: None,
                    payload_len: plen.min(u16::MAX as usize) as u16,
                },
                None,
            ))
        }
        FLAGS_HCI_EVT => {
            if buf.len() < 2 {
                return Err(BleError::Truncated);
            }
            let plen = buf[1] as usize;
            if buf.len() < 2 + plen {
                return Err(BleError::Truncated);
            }
            if buf.len() > 2 + plen {
                return Err(BleError::Malformed);
            }
            let subevent = if buf[0] == EVT_LE_META && plen >= 1 {
                Some(buf[2])
            } else {
                None
            };
            Ok((
                HciNode {
                    kind: HciKind::Event,
                    conn_handle: None,
                    opcode: None,
                    event: Some(buf[0]),
                    subevent,
                    payload_len: plen.min(u16::MAX as usize) as u16,
                },
                None,
            ))
        }
        FLAGS_ACL_TX | FLAGS_ACL_RX => {
            if buf.len() < 4 {
                return Err(BleError::Truncated);
            }
            let dlen = u16::from_le_bytes([buf[2], buf[3]]) as usize;
            if buf.len() < 4 + dlen {
                return Err(BleError::Truncated);
            }
            if buf.len() > 4 + dlen {
                return Err(BleError::Malformed);
            }
            let acl = &buf[4..4 + dlen];
            if acl.len() < 4 {
                return Err(BleError::Truncated);
            }
            let l2_len = u16::from_le_bytes([acl[0], acl[1]]) as usize;
            let cid = u16::from_le_bytes([acl[2], acl[3]]);
            if acl.len() < 4 + l2_len {
                return Err(BleError::Truncated);
            }
            if acl.len() > 4 + l2_len {
                return Err(BleError::Malformed);
            }
            let node = HciNode {
                kind: if flags == FLAGS_ACL_TX {
                    HciKind::AclTx
                } else {
                    HciKind::AclRx
                },
                conn_handle: Some(u16::from_le_bytes([buf[0], buf[1]]) & 0x0fff),
                opcode: None,
                event: None,
                subevent: None,
                payload_len: l2_len.min(u16::MAX as usize) as u16,
            };
            if cid != ATT_CID {
                return Ok((node, None));
            }
            let att = &acl[4..4 + l2_len];
            if att.is_empty() {
                return Err(BleError::Truncated);
            }
            Ok((node, Some(att)))
        }
        _ => Err(BleError::Malformed),
    }
}

fn u16le_at(buf: &[u8], i: usize) -> Option<u16> {
    buf.get(i..i + 2).map(|w| u16::from_le_bytes([w[0], w[1]]))
}

fn base(opcode: u8, kind: AttKind) -> AttNode {
    AttNode {
        opcode,
        kind,
        handle: None,
        handle_end: None,
        mtu: None,
        uuid16: None,
        uuid128: false,
        req_opcode: None,
        error: None,
        payload_len: 0,
    }
}

/// Decode one ATT PDU (L2CAP CID-`0x0004` payload). Unknown opcodes
/// file [`AttKind::Unknown`] with the octet; only truncation and
/// fixed-shape length mismatches fail.
pub fn decode_att(pdu: &[u8]) -> Result<AttNode, BleError> {
    let opcode = *pdu.first().ok_or(BleError::Empty)?;
    let rest = &pdu[1..];
    let plen = |n: usize| rest.len().saturating_sub(n).min(u16::MAX as usize) as u16;
    match opcode {
        0x01 => {
            // Error Response: request opcode + handle + code.
            if rest.len() < 4 {
                return Err(BleError::Truncated);
            }
            if rest.len() > 4 {
                return Err(BleError::Malformed);
            }
            let mut n = base(opcode, AttKind::Error);
            n.req_opcode = Some(rest[0]);
            n.handle = u16le_at(rest, 1);
            n.error = Some(rest[3]);
            Ok(n)
        }
        0x02 | 0x03 => {
            // MTU exchange: one LE u16, exact length.
            if rest.len() < 2 {
                return Err(BleError::Truncated);
            }
            if rest.len() > 2 {
                return Err(BleError::Malformed);
            }
            let mut n = base(opcode, AttKind::Mtu);
            n.mtu = u16le_at(rest, 0);
            Ok(n)
        }
        0x04 => {
            // Find Information Request: handle range, exact length.
            if rest.len() < 4 {
                return Err(BleError::Truncated);
            }
            if rest.len() > 4 {
                return Err(BleError::Malformed);
            }
            let mut n = base(opcode, AttKind::FindInfo);
            n.handle = u16le_at(rest, 0);
            n.handle_end = u16le_at(rest, 2);
            Ok(n)
        }
        0x05 => {
            // Find Information Response: format + list.
            if rest.is_empty() {
                return Err(BleError::Truncated);
            }
            let mut n = base(opcode, AttKind::FindInfo);
            n.payload_len = plen(1);
            Ok(n)
        }
        0x08 | 0x10 => {
            // Discovery requests: range + 2- or 16-octet UUID.
            if rest.len() < 6 {
                return Err(BleError::Truncated);
            }
            if rest.len() != 6 && rest.len() != 20 {
                return Err(BleError::Malformed);
            }
            let mut n = base(
                opcode,
                if opcode == 0x08 {
                    AttKind::ReadByType
                } else {
                    AttKind::ReadByGroup
                },
            );
            n.handle = u16le_at(rest, 0);
            n.handle_end = u16le_at(rest, 2);
            if rest.len() == 6 {
                n.uuid16 = u16le_at(rest, 4);
            } else {
                n.uuid128 = true;
            }
            Ok(n)
        }
        0x09 | 0x11 => {
            // Discovery responses: entry length + list. Entries are
            // attributed by the Direct leg; the node files the list
            // length only.
            if rest.is_empty() {
                return Err(BleError::Truncated);
            }
            let mut n = base(
                opcode,
                if opcode == 0x09 {
                    AttKind::ReadByType
                } else {
                    AttKind::ReadByGroup
                },
            );
            n.payload_len = plen(1);
            Ok(n)
        }
        0x0a => {
            // Read Request: handle, exact length.
            if rest.len() < 2 {
                return Err(BleError::Truncated);
            }
            if rest.len() > 2 {
                return Err(BleError::Malformed);
            }
            let mut n = base(opcode, AttKind::Read);
            n.handle = u16le_at(rest, 0);
            Ok(n)
        }
        0x0b => {
            // Read Response: value bytes stay length-named.
            let mut n = base(opcode, AttKind::Read);
            n.payload_len = rest.len().min(u16::MAX as usize) as u16;
            Ok(n)
        }
        0x12 => {
            // Write Request: handle + value (possibly empty).
            if rest.len() < 2 {
                return Err(BleError::Truncated);
            }
            let mut n = base(opcode, AttKind::Write);
            n.handle = u16le_at(rest, 0);
            n.payload_len = plen(2);
            Ok(n)
        }
        0x13 => {
            // Write Response: empty.
            if !rest.is_empty() {
                return Err(BleError::Malformed);
            }
            Ok(base(opcode, AttKind::WriteResult))
        }
        0x1b => {
            // Notification: handle + value (possibly empty).
            if rest.len() < 2 {
                return Err(BleError::Truncated);
            }
            let mut n = base(opcode, AttKind::Notify);
            n.handle = u16le_at(rest, 0);
            n.payload_len = plen(2);
            Ok(n)
        }
        0x1d | 0x1e => {
            // Indication / confirmation: handle + value.
            if opcode == 0x1d && rest.len() < 2 {
                return Err(BleError::Truncated);
            }
            if opcode == 0x1e && !rest.is_empty() {
                return Err(BleError::Malformed);
            }
            let mut n = base(opcode, AttKind::Indicate);
            n.handle = u16le_at(rest, 0);
            n.payload_len = plen(2);
            Ok(n)
        }
        _ => {
            let mut n = base(opcode, AttKind::Unknown);
            n.payload_len = rest.len().min(u16::MAX as usize) as u16;
            Ok(n)
        }
    }
}

/// Attribute one little-endian wire UUID (16 octets, LSB first as
/// ATT carries 128-bit UUIDs) against the Direct GATT tables.
/// Returns `(service_bit, sec_index, comm_index)` — at most one is
/// `Some` per UUID.
fn attribute(uuid_le: &[u8]) -> (Option<u8>, Option<u8>, Option<u8>) {
    if uuid_le.len() != 16 {
        return (None, None, None);
    }
    let mut be = [0u8; 16];
    for (i, b) in uuid_le.iter().enumerate() {
        be[15 - i] = *b;
    }
    for (i, s) in gatt::DIRECT_SERVICES.iter().enumerate() {
        if s.uuid.0 == be {
            return (Some(i as u8), None, None);
        }
    }
    for (i, c) in gatt::SECURITY_CHARS.iter().enumerate() {
        if c.uuid.0 == be {
            return (None, Some(i as u8), None);
        }
    }
    for (i, c) in gatt::COMMISSIONING_CHARS.iter().enumerate() {
        if c.uuid.0 == be {
            return (None, None, Some(i as u8));
        }
    }
    (None, None, None)
}

/// Maximum discovery entries scanned per response (bounded loop).
const MAX_DISC_ENTRIES: usize = 32;
/// Maximum TLVs walked per write envelope (bounded loop).
const MAX_ENV_TLVS: usize = 8;

/// Attempt the Direct leg for one decoded ATT PDU (full PDU including
/// the opcode octet; fixed headers are stripped here per opcode):
/// discovery responses carrying ≥1 Direct UUID → [`DirectKind::Discovery`]
/// with the attribution bitmap; Status-Code TLV notifications →
/// [`DirectKind::Status`]; write values shaped as ≥2 complete
/// defined-tag TLVs → [`DirectKind::Envelope`]. Anything else —
/// including single-TLV values like bare CCC writes, which are not
/// Direct envelopes — returns `Err` and the chain keeps the ATT leg
/// with no Direct layer.
pub fn decode_direct(att: &AttNode, pdu: &[u8]) -> Result<DirectNode, BleError> {
    match att.opcode {
        0x09 | 0x11 => decode_discovery(pdu.get(1..).ok_or(BleError::Truncated)?),
        0x1b => {
            let value = pdu.get(3..).ok_or(BleError::Truncated)?;
            if value.len() == 4 {
                decode_status(value)
            } else {
                Err(BleError::Malformed)
            }
        }
        0x12 => decode_envelope(pdu.get(3..).ok_or(BleError::Truncated)?),
        _ => Err(BleError::Malformed),
    }
}

/// Attribute every entry of a discovery response list. Entry shape
/// is `handle(2) [+ range-end(2)] + uuid(2 | 16)`; the entry length
/// comes from the ATT node only implicitly, so entries are walked
/// by trying the three live shapes (7, 21 for declarations; 6, 20
/// for group pairs) from the remaining length.
fn decode_discovery(value: &[u8]) -> Result<DirectNode, BleError> {
    if value.len() < 2 {
        return Err(BleError::Truncated);
    }
    let elen = value[0] as usize;
    // Live shapes: declaration entries (7 = 16-bit UUID, 21 =
    // 128-bit UUID) and group entries (6 / 20). Anything else is
    // not attributable here.
    if elen != 7 && elen != 21 && elen != 6 && elen != 20 {
        return Err(BleError::Malformed);
    }
    let mut rest = &value[1..];
    let mut node = DirectNode {
        kind: DirectKind::Discovery,
        services: 0,
        sec_chars: 0,
        comm_chars: 0,
        entries: 0,
        first_tag: 0xff,
        domain: 0xff,
        code: 0xff,
        payload_len: value.len().min(u16::MAX as usize) as u16,
    };
    let mut seen_direct = false;
    for _ in 0..MAX_DISC_ENTRIES {
        if rest.is_empty() {
            break;
        }
        if rest.len() < elen {
            return Err(BleError::Truncated);
        }
        let (entry, tail) = rest.split_at(elen);
        rest = tail;
        node.entries = node.entries.saturating_add(1);
        // The UUID is the last 16 octets of a long entry, or the
        // last 2 octets of a short one (short UUIDs never name a
        // Direct service here).
        if elen >= 20 {
            let (svc, sec, comm) = attribute(&entry[elen - 16..]);
            if let Some(i) = svc {
                node.services |= 1 << i;
                seen_direct = true;
            }
            if let Some(i) = sec {
                node.sec_chars |= 1 << i;
                seen_direct = true;
            }
            if let Some(i) = comm {
                node.comm_chars |= 1 << i;
                seen_direct = true;
            }
        }
    }
    if !rest.is_empty() {
        return Err(BleError::Malformed);
    }
    if seen_direct {
        Ok(node)
    } else {
        Err(BleError::Malformed)
    }
}

/// Name a Status-Code TLV notification: exactly `[0x0e, 0x02,
/// domain, code]` with a defined domain (`0x00`–`0x07`).
fn decode_status(value: &[u8]) -> Result<DirectNode, BleError> {
    let (tlv, used) = attr::decode_tlv(value).map_err(|_| BleError::Truncated)?;
    if used != value.len() || tlv.tag != STATUS_TAG || tlv.body.len() != 2 {
        return Err(BleError::Malformed);
    }
    if !attr::StatusDomain(tlv.body[0]).is_defined() {
        return Err(BleError::Malformed);
    }
    Ok(DirectNode {
        kind: DirectKind::Status,
        services: 0,
        sec_chars: 0,
        comm_chars: 0,
        entries: 1,
        first_tag: 0xff,
        domain: tlv.body[0],
        code: tlv.body[1],
        payload_len: value.len().min(u16::MAX as usize) as u16,
    })
}

/// Name a Direct write envelope: ≥2 complete TLVs, every tag a
/// defined commissioning tag (`0x00`–`0x0f`), exact consumption.
/// Bodies are counted, never carried or rendered.
fn decode_envelope(value: &[u8]) -> Result<DirectNode, BleError> {
    let mut rest = value;
    let mut count = 0u8;
    let mut first_tag = 0xffu8;
    for _ in 0..MAX_ENV_TLVS {
        if rest.is_empty() {
            break;
        }
        let (tlv, used) = attr::decode_tlv(rest).map_err(|_| BleError::Truncated)?;
        if attr::TlvId(tlv.tag).is_reserved() {
            return Err(BleError::Malformed);
        }
        if count == 0 {
            first_tag = tlv.tag;
        }
        count = count.saturating_add(1);
        rest = &rest[used..];
    }
    if !rest.is_empty() || count < 2 {
        return Err(BleError::Malformed);
    }
    Ok(DirectNode {
        kind: DirectKind::Envelope,
        services: 0,
        sec_chars: 0,
        comm_chars: 0,
        entries: count,
        first_tag,
        domain: 0xff,
        code: 0xff,
        payload_len: value.len().min(u16::MAX as usize) as u16,
    })
}
