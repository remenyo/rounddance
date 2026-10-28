//! NWK dissector: reused `rounddance-nwk` codec → [`NwkNode`](crate::tree::NwkNode).

use crate::tree::NwkNode;

/// NWK dissector failure (codec refusal, passed through).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NwkError {
    /// Codec refusal; discriminant preserved for the report.
    Codec(u8),
}

/// Map the codec error to a stable small discriminant for reports.
fn discriminant(e: &rounddance_nwk::frame::Error) -> u8 {
    use rounddance_nwk::frame::Error as E;
    match e {
        E::Truncated | E::BufferTooSmall => 1,
        E::ReservedFrameType(_) | E::ReservedDiscoverRoute(_) => 2,
        E::PresenceMismatch(_) | E::BroadcastWithDstIeee => 3,
        E::BadRelayCount(_) => 4,
    }
}

/// On-air 2-bit NWK frame-type value.
fn frame_type_bits(t: rounddance_nwk::frame::FrameType) -> u8 {
    use rounddance_nwk::frame::FrameType as T;
    match t {
        T::Data => 0,
        T::Command => 1,
        T::InterPan => 3,
    }
}

/// Dissect one NWK header; returns the tree node plus the NWK payload.
pub fn decode(buf: &[u8]) -> Result<(NwkNode, &[u8]), NwkError> {
    match rounddance_nwk::frame::decode(buf) {
        Ok(d) => {
            // The command id is the first payload octet only on
            // unsecured command frames; on secured frames the payload
            // starts with the aux header and the id is encrypted.
            let command_id = if d.header.control.frame_type
                == rounddance_nwk::frame::FrameType::Command
                && !d.header.control.security
            {
                d.payload.first().copied()
            } else {
                None
            };
            Ok((
                NwkNode {
                    frame_type: frame_type_bits(d.header.control.frame_type),
                    protocol_version: d.header.control.protocol_version,
                    security: d.header.control.security,
                    dst_addr: d.header.dst_addr,
                    src_addr: d.header.src_addr,
                    radius: d.header.radius,
                    seq: d.header.seq,
                    command_id,
                    dst_ieee: d.header.dst_ieee,
                    src_ieee: d.header.src_ieee,
                },
                d.payload,
            ))
        }
        Err(e) => Err(NwkError::Codec(discriminant(&e))),
    }
}
