//! Dissector chain: MAC → NWK → APS → ZCL over one captured frame.
//!
//! Each layer is attempted in order while bytes remain. The chain stops
//! with a [`Note`](crate::tree::NoteNode) node — never an `Err` — when
//! a secured frame, an Inter-PAN shape, or trailing bytes need a live
//! key or a future dissector. Only a MAC-level refusal fails the whole
//! frame, since without the MAC header nothing is addressable.

use crate::tree::{DecodeTree, Layer, NoteNode, TreeError};

/// Dissect a full 802.15.4-captured frame (MAC header onward).
pub fn dissect(frame: &[u8]) -> Result<DecodeTree, TreeError> {
    let mut tree = DecodeTree::new();
    let (mac, mut rest) = crate::mac::decode(frame).map_err(TreeError::from)?;
    tree.push(Layer::Mac(mac.node));

    // Secured MAC payload: no further dissection without the link key.
    if mac.node.security_enabled {
        tree.push(Layer::Note(NoteNode {
            reason: "secured",
            remaining: rest.len().min(u16::MAX as usize) as u16,
        }));
        return Ok(tree);
    }

    match crate::nwk::decode(rest) {
        Ok((nwk, payload)) => {
            tree.push(Layer::Nwk(nwk));
            rest = payload;
        }
        Err(_) => {
            // Not a Zigbee NWK payload (e.g. MAC command or Inter-PAN):
            // record the stop and keep the MAC node.
            tree.push(Layer::Note(NoteNode {
                reason: "unknown",
                remaining: rest.len().min(u16::MAX as usize) as u16,
            }));
            return Ok(tree);
        }
    }

    // Secured NWK: APS/ZCL need the network key (cf. wave-36).
    if tree.nwk().map(|n| n.security).unwrap_or(false) {
        tree.push(Layer::Note(NoteNode {
            reason: "secured",
            remaining: rest.len().min(u16::MAX as usize) as u16,
        }));
        return Ok(tree);
    }

    // NWK command frames carry no APS header.
    if tree.nwk().map(|n| n.frame_type).unwrap_or(0) != 0 {
        tree.push(Layer::Note(NoteNode {
            reason: "trailing",
            remaining: rest.len().min(u16::MAX as usize) as u16,
        }));
        return Ok(tree);
    }

    match crate::aps::decode(rest) {
        Ok((aps, payload)) => {
            tree.push(Layer::Aps(aps));
            rest = payload;
        }
        Err(_) => {
            tree.push(Layer::Note(NoteNode {
                reason: "unknown",
                remaining: rest.len().min(u16::MAX as usize) as u16,
            }));
            return Ok(tree);
        }
    }

    // Only APS data frames carry a ZCL payload; acks/commands stop here.
    if tree.aps().map(|a| a.frame_type).unwrap_or(9) != 0 {
        tree.push(Layer::Note(NoteNode {
            reason: "trailing",
            remaining: rest.len().min(u16::MAX as usize) as u16,
        }));
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
            tree.push(Layer::Note(NoteNode {
                reason: "unknown",
                remaining: rest.len().min(u16::MAX as usize) as u16,
            }));
        }
    }
    Ok(tree)
}

/// Dissect a bare NWK payload (no 802.15.4 MAC header, e.g. a captured
/// NWK PDU from an existing lab log). Stops after NWK when secured.
pub fn dissect_nwk(nwk_pdu: &[u8]) -> Result<DecodeTree, TreeError> {
    if nwk_pdu.is_empty() {
        return Err(TreeError::Empty);
    }
    let mut tree = DecodeTree::new();
    match crate::nwk::decode(nwk_pdu) {
        Ok((nwk, rest)) => {
            tree.push(Layer::Nwk(nwk));
            tree.push(Layer::Note(NoteNode {
                reason: if nwk.security { "secured" } else { "trailing" },
                remaining: rest.len().min(u16::MAX as usize) as u16,
            }));
            Ok(tree)
        }
        Err(_) => Err(TreeError::MacMalformed),
    }
}
