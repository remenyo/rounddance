//! Minimal 802.15.4 MAC header dissector (2006/2015-compatible subset).
//!
//! The repo has no 802.15.4 air codec (`rounddance-mac-sap` defines the
//! SAP seam, not the on-air frame), so the inspector carries its own
//! bounded header parser: 2-octet frame control (LE) plus sequence number
//! plus addressing fields per the addressing-mode bits. Only the modes
//! the Zigbee stack emits are accepted. Anything else is a typed
//! refusal, never a guess.

use crate::tree::{Addr, MacNode, TreeError};

/// Frame-control bits we interpret.
const FC_TYPE_MASK: u16 = 0x0007;
const FC_SECURITY: u16 = 0x0008;
const FC_SEQ_SUPPRESS: u16 = 0x0100;
const FC_DST_MODE_MASK: u16 = 0x0c00;
const FC_VERSION_MASK: u16 = 0x3000;
const FC_SRC_MODE_MASK: u16 = 0xc000;

/// Decoded MAC header plus payload offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedMac {
    /// Header summary for the tree.
    pub node: MacNode,
    /// Payload after the MAC header.
    pub header_len: usize,
}

/// MAC dissector failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacError {
    /// Fewer than the 2 frame-control octets.
    Empty,
    /// Header runs past the end of the frame.
    Truncated,
    /// Addressing mode combination the inspector does not emit/accept.
    UnsupportedAddressing { dst_mode: u8, src_mode: u8 },
}

fn mode_addr(buf: &[u8], pos: usize, mode: u8) -> Result<(Addr, usize), MacError> {
    match mode {
        0 => Ok((Addr::None, pos)),
        2 => {
            if buf.len() < pos + 2 {
                return Err(MacError::Truncated);
            }
            Ok((
                Addr::Short(u16::from_le_bytes([buf[pos], buf[pos + 1]])),
                pos + 2,
            ))
        }
        3 => {
            if buf.len() < pos + 8 {
                return Err(MacError::Truncated);
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&buf[pos..pos + 8]);
            Ok((Addr::Extended(u64::from_le_bytes(b)), pos + 8))
        }
        _ => Err(MacError::Truncated),
    }
}

/// Dissect one 802.15.4 MAC header from the front of `buf`.
pub fn decode(buf: &[u8]) -> Result<(DecodedMac, &[u8]), MacError> {
    if buf.len() < 2 {
        return Err(MacError::Empty);
    }
    let fc = u16::from_le_bytes([buf[0], buf[1]]);
    let frame_type = (fc & FC_TYPE_MASK) as u8;
    let security_enabled = fc & FC_SECURITY != 0;
    let seq_present = fc & FC_SEQ_SUPPRESS == 0;
    let dst_mode = ((fc & FC_DST_MODE_MASK) >> 10) as u8;
    let src_mode = ((fc & FC_SRC_MODE_MASK) >> 14) as u8;
    if dst_mode == 1 || src_mode == 1 {
        return Err(MacError::UnsupportedAddressing { dst_mode, src_mode });
    }
    let mut pos = 2;
    let mut seq = 0u8;
    if seq_present {
        if buf.len() < pos + 1 {
            return Err(MacError::Truncated);
        }
        seq = buf[pos];
        pos += 1;
    }
    let version = ((fc & FC_VERSION_MASK) >> 12) as u8;
    let pan_compress = fc & 0x0040 != 0;
    // Destination PAN: present unless addressing is `None/None`.
    let mut dst_pan = None;
    if dst_mode != 0 || (src_mode == 0 && version != 2) {
        if buf.len() < pos + 2 {
            return Err(MacError::Truncated);
        }
        dst_pan = Some(u16::from_le_bytes([buf[pos], buf[pos + 1]]));
        pos += 2;
    }
    let (dst, at) = mode_addr(buf, pos, dst_mode)?;
    pos = at;
    // Source PAN: present when both addresses are present without
    // compression, or with compression only when modes differ in kind.
    let mut src_pan = None;
    if src_mode != 0 {
        let need_src_pan = !pan_compress || dst_mode == 0;
        if need_src_pan {
            if buf.len() < pos + 2 {
                return Err(MacError::Truncated);
            }
            src_pan = Some(u16::from_le_bytes([buf[pos], buf[pos + 1]]));
            pos += 2;
        } else {
            src_pan = dst_pan;
        }
    }
    let (src, at) = mode_addr(buf, pos, src_mode)?;
    pos = at;
    if pos > u8::MAX as usize {
        return Err(MacError::Truncated);
    }
    let node = MacNode {
        frame_type,
        security_enabled,
        seq,
        seq_present,
        dst_pan,
        dst,
        src_pan,
        src,
        header_len: pos as u8,
    };
    Ok((
        DecodedMac {
            node,
            header_len: pos,
        },
        &buf[pos..],
    ))
}

impl From<MacError> for TreeError {
    fn from(e: MacError) -> Self {
        match e {
            MacError::Empty => TreeError::Empty,
            MacError::Truncated => TreeError::MacTruncated,
            MacError::UnsupportedAddressing { .. } => TreeError::MacMalformed,
        }
    }
}
