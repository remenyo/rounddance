//! ZCL dissector: reused `rounddance-zcl` codec → [`ZclNode`](crate::tree::ZclNode).

use crate::tree::ZclNode;

/// ZCL dissector failure (codec refusal, passed through).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZclError {
    /// Codec refusal; discriminant preserved for the report.
    Codec(u8),
}

/// Dissect one ZCL frame; returns the tree node (payload length kept,
/// cluster payload stays opaque at scaffold scope).
pub fn decode(buf: &[u8]) -> Result<ZclNode, ZclError> {
    match rounddance_zcl::frame::Header::decode(buf) {
        Ok((h, payload)) => {
            if payload.len() > u16::MAX as usize {
                return Err(ZclError::Codec(1));
            }
            Ok(ZclNode {
                frame_type: h.control.frame_type.bits(),
                manufacturer_specific: h.control.manufacturer_specific,
                direction: h.control.direction.bit(),
                manufacturer_code: h.manufacturer_code,
                tsn: h.tsn,
                command_id: h.command_id,
                payload_len: payload.len() as u16,
            })
        }
        Err(_) => Err(ZclError::Codec(2)),
    }
}
