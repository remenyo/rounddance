//! Dissector chain: MAC → NWK → APS → ZCL over one captured frame.
//!
//! Each layer is attempted in order while bytes remain. The chain stops
//! with a [`Note`](crate::tree::NoteNode) node — never an `Err` — when
//! a secured frame, an Inter-PAN shape, a MAC acknowledgement /
//! beacon / command frame, or trailing bytes need a live key or a
//! future dissector. Only a MAC-level refusal fails the whole frame,
//! since without the MAC header nothing is addressable.
//!
//! Secured NWK frames open through
//! [`decrypt`](crate::decrypt) when the caller supplies loaded lab
//! keys ([`dissect_with_keys`]); without a matching slotted key the
//! chain stops with the historical `secured` note and the bytes stay
//! sealed.

use crate::decrypt::{self, MAX_SECURED_PAYLOAD};
use crate::keys::KeySlots;
use crate::tree::{DecodeTree, Layer, NoteNode, TreeError};

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

    // Secured MAC payload: no further dissection without the link key.
    if mac.node.security_enabled {
        stop(&mut tree, "secured", rest.len());
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
            stop(&mut tree, "mac-command", rest.len());
            return Ok(tree);
        }
        _ => {
            stop(&mut tree, "unknown", rest.len());
            return Ok(tree);
        }
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
            // Not a Zigbee NWK payload (e.g. an Inter-PAN shape):
            // record the stop and keep the MAC node.
            stop(&mut tree, "unknown", rest.len());
            return Ok(tree);
        }
    }

    finish_after_nwk(tree, rest)
}

/// Continue the chain on a plaintext / plain NWK payload: NWK
/// command frames carry no APS header, otherwise APS then ZCL.
fn finish_after_nwk(mut tree: DecodeTree, rest: &[u8]) -> Result<DecodeTree, TreeError> {
    // NWK command frames carry no APS header.
    if tree.nwk().map(|n| n.frame_type).unwrap_or(0) != 0 {
        stop(&mut tree, "trailing", rest.len());
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

    // Only APS data frames carry a ZCL payload; acks/commands stop here.
    if tree.aps().map(|a| a.frame_type).unwrap_or(9) != 0 {
        stop(&mut tree, "trailing", rest.len());
        return Ok(tree);
    }

    let (cluster_id, profile_id) = tree
        .aps()
        .map(|a| (a.cluster_id, a.profile_id))
        .unwrap_or((0xffff, 0xffff));
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
