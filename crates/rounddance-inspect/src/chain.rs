//! Dissector chain: MAC → NWK → APS → ZCL/ZDO over one captured frame.
//!
//! Each layer is attempted in order while bytes remain. The chain stops
//! with a [`Note`](crate::tree::NoteNode) node — never an `Err` — when
//! a secured frame, an Inter-PAN shape, a MAC acknowledgement /
//! beacon / command frame, or trailing bytes need a live key or a
//! further dissector. Only a MAC-level refusal fails the whole frame,
//! since without the MAC header nothing is addressable.
//!
//! Named sub-dissector legs ride alongside the stop notes: fixed-shape
//! MAC command payloads ([`mac`](crate::mac)), NWK command payloads
//! on unsecured as well as verified-open legs ([`nwkcmd`](crate::nwkcmd)),
//! the transport-key, update-device, remove-device, request-key,
//! switch-key, tunnel, verify-key, and confirm-key APS command payloads on unsecured as well as verified-open legs
//! ([`apscmd`](crate::apscmd)),
//! the Touchlink envelope on broadcast-PAN outers
//! ([`touchlink`](crate::touchlink)), the ZDO envelope on profile
//! `0x0000` ([`zdo`](crate::zdo)) instead of a ZCL misparse, and the
//! Green-Power device frame on payloads the stack NWK codec refuses
//! ([`gp`](crate::gp)). The terminal stop taxonomy never moves for
//! a named leg: the note
//! still files the remainder (zero when the leg consumes the
//! payload).
//!
//! Secured NWK frames open through
//! [`decrypt`](crate::decrypt) when the caller supplies loaded lab
//! keys ([`dissect_with_keys`]); without a matching slotted key the
//! chain stops with the historical `secured` note and the bytes stay
//! sealed. A MAC sealed outer stops `mac-secured` instead: no link
//! key exists offline, and the name keeps it distinct from the
//! NWK/APS key-domain misses counted under `secured`.

use crate::decrypt::{self, MAX_SECURED_PAYLOAD};
use crate::keys::KeySlots;
use crate::tree::{Addr, DecodeTree, Layer, NoteNode, TreeError};

fn stop(tree: &mut DecodeTree, reason: &'static str, remaining: usize) {
    tree.push(Layer::Note(NoteNode {
        reason,
        remaining: remaining.min(u16::MAX as usize) as u16,
    }));
}

/// Dissect a full 802.15.4-captured frame (MAC header onward) with no
/// lab keys: secured NWK frames stop with a `secured` note.
pub fn dissect(frame: &[u8]) -> Result<DecodeTree, TreeError> {
    dissect_with_keys(frame, &KeySlots::new())
}

/// Dissect a full 802.15.4-captured frame (MAC header onward),
/// opening secured NWK payloads against `keys`.
///
/// A secured NWK frame whose auxiliary header names a loaded key
/// sequence continues the chain on the verified plaintext (with a
/// `decrypted` stop note marking the leg); any other secured frame
/// — no slot, unslotted sequence, non-network-key shape, or failed
/// integrity check — stops with a `secured` note, exactly as
/// [`dissect`] files it.
pub fn dissect_with_keys(frame: &[u8], keys: &KeySlots) -> Result<DecodeTree, TreeError> {
    let mut tree = DecodeTree::new();
    let (mac, mut rest) = crate::mac::decode(frame).map_err(TreeError::from)?;
    tree.push(Layer::Mac(mac.node));

    // Secured MAC payload: no further dissection without the link
    // key. The stop names the MAC layer (`mac-secured`), never the
    // NWK/APS key domain (`secured`): garbage that parses as a sealed
    // outer must not mix with netkey misses in keyed-run accounting.
    if mac.node.security_enabled {
        stop(&mut tree, "mac-secured", rest.len());
        return Ok(tree);
    }

    // Non-data MAC frames carry no NWK payload: name the stop.
    match mac.node.frame_type {
        1 => {}
        2 => {
            stop(&mut tree, "ack", rest.len());
            return Ok(tree);
        }
        0 => {
            stop(&mut tree, "beacon", rest.len());
            return Ok(tree);
        }
        3 => {
            // Fixed-shape command payloads earn a named layer; the
            // `mac-command` stop still files the MSDU either way, so
            // the stop taxonomy (and every replay histogram over it)
            // never moves for a named leg.
            if let Some(cmd) = mac.node.command_id {
                if let Ok(node) = crate::mac::decode_command(cmd, rest) {
                    tree.push(Layer::MacCmd(node));
                }
            }
            stop(&mut tree, "mac-command", rest.len());
            return Ok(tree);
        }
        _ => {
            stop(&mut tree, "unknown", rest.len());
            return Ok(tree);
        }
    }

    // Inter-PAN (Touchlink) data frames never enter the NWK
    // dissector: a broadcast-PAN / broadcast-destination outer with
    // a broadcast source PAN carries a Touchlink envelope
    // (little-endian transaction + command + fixed body), never an
    // NWK header. Routing one to NWK hallucinates headers out of
    // transaction-ID bytes — a version-5 "NWK" header with APS/ZCL
    // legs on the wave-50 captures. The Touchlink leg rides beside
    // the `interpan` stop; a payload too short to name (or a named
    // command at a wrong length) keeps the stop with no leg.
    if !mac.node.security_enabled
        && mac.node.dst_pan == Some(0xffff)
        && mac.node.dst == Addr::Short(0xffff)
        && mac.node.src_pan == Some(0xffff)
    {
        match crate::touchlink::decode(rest) {
            Ok((node, consumed)) => {
                tree.push(Layer::Touchlink(node));
                stop(&mut tree, "interpan", rest.len().saturating_sub(consumed));
            }
            Err(_) => {
                stop(&mut tree, "interpan", rest.len());
            }
        }
        return Ok(tree);
    }

    match crate::nwk::decode(rest) {
        Ok((nwk, header_len, payload)) => {
            let header = rest.get(..header_len).unwrap_or(&[]);
            tree.push(Layer::Nwk(nwk));
            if nwk.security {
                let mut scratch = [0u8; MAX_SECURED_PAYLOAD];
                let opened = decrypt::open_nwk(keys, header, payload, &mut scratch);
                match opened.and_then(|n| scratch.get(..n)) {
                    Some(plain) => {
                        stop(&mut tree, "decrypted", plain.len());
                        // The plaintext borrows the local scratch; the
                        // tail consumes it synchronously (owned nodes
                        // only) before the buffer drops.
                        return finish_after_nwk(tree, plain);
                    }
                    None => {
                        stop(&mut tree, "secured", payload.len());
                        return Ok(tree);
                    }
                }
            }
            rest = payload;
        }
        Err(_) => {
            // Not a stack NWK payload: Green-Power device frames
            // ride straight in the MAC payload (stub NWK, version
            // 3), so a refused NWK header earns a GP leg attempt
            // before the historical `unknown` stop. Anything the GP
            // codec also refuses keeps the stop with the MAC node.
            return finish_gp_or_unknown(tree, rest, keys);
        }
    }

    finish_after_nwk(tree, rest)
}

/// Attempt the Green-Power leg on bytes the stack NWK codec
/// refused: a decoded GPDF names its leg beside a terminal stop, an
/// undecodable payload keeps the historical `unknown` stop. The
/// command envelope of a counter-protected GPDF is named from the
/// cleartext travel (counter-plus-MIC level) or sealed (encrypted
/// level) until a slotted GP key verifies it open — exactly the
/// slotted-key gate of the NWK decrypt leg, so no protected GPDF
/// ever decrypts without a slotted key.
fn finish_gp_or_unknown(
    mut tree: DecodeTree,
    rest: &[u8],
    keys: &KeySlots,
) -> Result<DecodeTree, TreeError> {
    let node = match crate::gp::decode(rest) {
        Ok(node) => node,
        Err(_) => {
            stop(&mut tree, "unknown", rest.len());
            return Ok(tree);
        }
    };
    if !node.secured {
        tree.push(Layer::Gp(node));
        stop(&mut tree, "trailing", 0);
        return Ok(tree);
    }
    // Counter-protected GPDF: the stop stays `secured` unless a
    // slotted GP key verifies the section open.
    let mut scratch = [0u8; decrypt::MAX_GP_OPEN];
    match decrypt::open_gp(keys, rest, &mut scratch) {
        Some(n) => match scratch.get(..n) {
            Some(plain) => match crate::gp::decode_opened(rest, plain) {
                Ok(opened) => {
                    tree.push(Layer::Gp(opened));
                    stop(&mut tree, "decrypted", 0);
                }
                Err(_) => {
                    tree.push(Layer::Gp(node));
                    stop(&mut tree, "secured", rest.len());
                }
            },
            None => {
                tree.push(Layer::Gp(node));
                stop(&mut tree, "secured", rest.len());
            }
        },
        None => {
            tree.push(Layer::Gp(node));
            stop(&mut tree, "secured", rest.len());
        }
    }
    Ok(tree)
}

/// Continue the chain on a plaintext / plain NWK payload: NWK
/// command frames name their command leg (no APS header rides one),
/// otherwise APS then ZCL (or ZDO on profile `0x0000`).
fn finish_after_nwk(mut tree: DecodeTree, rest: &[u8]) -> Result<DecodeTree, TreeError> {
    // NWK command frames carry no APS header: name the command leg,
    // then file the remainder (codec TLV tails, if any) as trailing.
    if tree.nwk().map(|n| n.frame_type).unwrap_or(0) != 0 {
        let mut remaining = rest.len();
        if let Ok((node, consumed)) = crate::nwkcmd::decode(rest) {
            tree.push(Layer::NwkCmd(node));
            remaining = rest.len().saturating_sub(consumed);
        }
        stop(&mut tree, "trailing", remaining);
        return Ok(tree);
    }
    finish_aps_zcl(tree, rest)
}

fn finish_aps_zcl(mut tree: DecodeTree, rest: &[u8]) -> Result<DecodeTree, TreeError> {
    let mut rest = rest;
    match crate::aps::decode(rest) {
        Ok((aps, payload)) => {
            tree.push(Layer::Aps(aps));
            rest = payload;
        }
        Err(crate::aps::ApsError::Secured) => {
            // APS security bit set (e.g. a transport-key outer): the
            // command identifier rides sealed, never parse the aux.
            stop(&mut tree, "secured", rest.len());
            return Ok(tree);
        }
        Err(_) => {
            stop(&mut tree, "unknown", rest.len());
            return Ok(tree);
        }
    }

    // APS command frames name their command leg (no ZCL payload rides
    // one); acks stop here.
    if tree.aps().map(|a| a.frame_type).unwrap_or(9) == 1 {
        let mut remaining = rest.len();
        if let Some(cmd) = tree.aps().and_then(|a| a.command_id) {
            if let Ok((node, consumed)) = crate::apscmd::decode(cmd, rest) {
                tree.push(Layer::ApsCmd(node));
                remaining = rest.len().saturating_sub(consumed);
            }
        }
        stop(&mut tree, "trailing", remaining);
        return Ok(tree);
    }
    // Only APS data frames carry a ZCL payload; acks stop here.
    if tree.aps().map(|a| a.frame_type).unwrap_or(9) != 0 {
        stop(&mut tree, "trailing", rest.len());
        return Ok(tree);
    }

    let (cluster_id, profile_id) = tree
        .aps()
        .map(|a| (a.cluster_id, a.profile_id))
        .unwrap_or((0xffff, 0xffff));
    // Device-profile payloads are ZDO, never ZCL: routing them to the
    // ZCL dissector misattributes the layer (a tsn that parses as a
    // frame-control octet decodes as a bogus cluster-specific
    // command).
    if profile_id == 0x0000 {
        match crate::zdo::decode(cluster_id, rest) {
            Ok(zdo) => {
                tree.push(Layer::Zdo(zdo));
            }
            Err(_) => {
                stop(&mut tree, "unknown", rest.len());
            }
        }
        return Ok(tree);
    }
    match crate::zcl::decode(rest, cluster_id, profile_id) {
        Ok(zcl) => {
            tree.push(Layer::Zcl(zcl));
        }
        Err(_) => {
            stop(&mut tree, "unknown", rest.len());
        }
    }
    Ok(tree)
}

/// Dissect one BLE HCI record (one btsnoop record: flags plus the raw
/// HCI packet without the H4 type octet).
///
/// Commands and events file an HCI layer only. ACL packets carrying
/// L2CAP CID `0x0004` continue to the ATT leg (MTU exchange, handle
/// decode on reads/writes/notifies); discovery responses carrying
/// Direct UUIDs and Direct TLV write/notify values earn a Direct
/// leg beside it. An ACL packet the ATT codec refuses (non-ATT CID,
/// truncation, fixed-shape mismatch) keeps the HCI leg with a
/// `ble-unknown` stop — the bytes are still shown, never silently
/// dropped. Only an HCI-level refusal fails the whole record, since
/// without the HCI header nothing is addressable. BLE trees carry
/// no 15.4 layers, so the session engine counts them under PAN 0
/// with no device row and zero secured accounting.
pub fn dissect_ble(flags: u32, record: &[u8]) -> Result<DecodeTree, TreeError> {
    if record.is_empty() {
        return Err(TreeError::Empty);
    }
    let mut tree = DecodeTree::new();
    let (hci, att) = crate::ble::decode_hci(flags, record).map_err(|e| match e {
        crate::ble::BleError::Empty => TreeError::Empty,
        crate::ble::BleError::Truncated => TreeError::BleTruncated,
        crate::ble::BleError::Malformed => TreeError::BleMalformed,
    })?;
    tree.push(Layer::Hci(hci));
    let pdu = match att {
        Some(p) => p,
        // Commands/events file the HCI leg only; an ACL packet on
        // a non-ATT channel keeps the HCI leg with a stop.
        None => {
            if matches!(
                hci.kind,
                crate::tree::HciKind::AclTx | crate::tree::HciKind::AclRx
            ) {
                stop(&mut tree, "ble-unknown", record.len());
            }
            return Ok(tree);
        }
    };
    match crate::ble::decode_att(pdu) {
        Ok(node) => {
            tree.push(Layer::Att(node));
            // Direct legs ride beside the ATT layer: discovery
            // bitmaps, status notifications, and TLV envelopes.
            // Anything the Direct codec refuses keeps the ATT leg
            // with no Direct layer.
            if let Ok(direct) = crate::ble::decode_direct(&node, pdu) {
                tree.push(Layer::Direct(direct));
            }
            Ok(tree)
        }
        Err(_) => {
            stop(&mut tree, "ble-unknown", pdu.len());
            Ok(tree)
        }
    }
}

/// Dissect a bare NWK payload (no 802.15.4 MAC header, e.g. a captured
/// NWK PDU from an existing lab log) with no lab keys: secured
/// frames stop after NWK.
pub fn dissect_nwk(nwk_pdu: &[u8]) -> Result<DecodeTree, TreeError> {
    dissect_nwk_with_keys(nwk_pdu, &KeySlots::new())
}

/// Dissect a bare NWK payload with lab keys: a secured frame naming
/// a loaded sequence continues on the verified plaintext, any other
/// secured frame stops after NWK with a `secured` note.
pub fn dissect_nwk_with_keys(nwk_pdu: &[u8], keys: &KeySlots) -> Result<DecodeTree, TreeError> {
    if nwk_pdu.is_empty() {
        return Err(TreeError::Empty);
    }
    let mut tree = DecodeTree::new();
    match crate::nwk::decode(nwk_pdu) {
        Ok((nwk, header_len, payload)) => {
            let header = nwk_pdu.get(..header_len).unwrap_or(&[]);
            tree.push(Layer::Nwk(nwk));
            if nwk.security {
                let mut scratch = [0u8; MAX_SECURED_PAYLOAD];
                let opened = decrypt::open_nwk(keys, header, payload, &mut scratch);
                match opened.and_then(|n| scratch.get(..n)) {
                    Some(plain) => {
                        stop(&mut tree, "decrypted", plain.len());
                        return finish_after_nwk(tree, plain);
                    }
                    None => {
                        stop(&mut tree, "secured", payload.len());
                        return Ok(tree);
                    }
                }
            }
            stop(
                &mut tree,
                if nwk.security { "secured" } else { "trailing" },
                payload.len(),
            );
            Ok(tree)
        }
        Err(_) => Err(TreeError::MacMalformed),
    }
}
