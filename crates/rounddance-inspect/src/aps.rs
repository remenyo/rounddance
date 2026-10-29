//! APS dissector: reused `rounddance-aps` codec → [`ApsNode`](crate::tree::ApsNode).

use crate::tree::ApsNode;

/// APS dissector failure (codec refusal, passed through).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApsError {
    /// Codec refusal; discriminant preserved for the report.
    Codec(u8),
    /// The APS security bit is set: the header is followed by the
    /// auxiliary header and ciphertext, so the command identifier
    /// (or ZCL payload) is sealed inside and must never be parsed
    /// from the aux octets. The chain files these as `secured`.
    Secured,
}

fn discriminant(e: &rounddance_aps::frame::Error) -> u8 {
    use rounddance_aps::frame::Error as E;
    match e {
        E::Truncated | E::BufferTooSmall => 1,
        E::ReservedDeliveryMode(_) | E::ReservedFragmentation(_) => 2,
        E::FrameTypeMismatch { .. } | E::PresenceMismatch(_) => 3,
        E::BadBroadcastEndpoint(_) | E::AckRequestsAck => 4,
    }
}

fn frame_type_bits(t: rounddance_aps::frame::FrameType) -> u8 {
    use rounddance_aps::frame::FrameType as T;
    match t {
        T::Data => 0,
        T::Command => 1,
        T::Ack => 2,
        T::InterPan => 3,
    }
}

fn delivery_bits(d: rounddance_aps::frame::DeliveryMode) -> u8 {
    use rounddance_aps::frame::DeliveryMode as D;
    match d {
        D::Unicast => 0,
        D::Broadcast => 2,
        D::Group => 3,
    }
}

/// Dissect one APDU; returns the tree node plus the APS payload.
pub fn decode(buf: &[u8]) -> Result<(ApsNode, &[u8]), ApsError> {
    let ty = rounddance_aps::frame::peek_frame_type(buf)
        .map_err(|e| ApsError::Codec(discriminant(&e)))?;
    // A set security bit means an auxiliary header plus ciphertext
    // follows the APS header: refuse before any command-identifier
    // or payload parse can misread the aux control octet (seen live
    // on a transport-key outer whose `0x30` aux octet parsed as a
    // bogus command).
    if buf.first().is_some_and(|b| b & 0x20 != 0) {
        return Err(ApsError::Secured);
    }
    match ty {
        rounddance_aps::frame::FrameType::Data => {
            let d = rounddance_aps::frame::decode_data(buf)
                .map_err(|e| ApsError::Codec(discriminant(&e)))?;
            Ok((
                ApsNode {
                    frame_type: frame_type_bits(d.header.control.frame_type),
                    delivery_mode: delivery_bits(d.header.control.delivery_mode),
                    dst_endpoint: match d.header.dest {
                        rounddance_aps::frame::DataDest::Unicast { dst_endpoint }
                        | rounddance_aps::frame::DataDest::Broadcast { dst_endpoint } => {
                            dst_endpoint
                        }
                        rounddance_aps::frame::DataDest::Group { .. } => 0xff,
                    },
                    cluster_id: d.header.cluster_id,
                    profile_id: d.header.profile_id,
                    src_endpoint: d.header.src_endpoint,
                    counter: d.header.counter,
                    command_id: None,
                },
                d.payload,
            ))
        }
        rounddance_aps::frame::FrameType::Command => {
            let d = rounddance_aps::frame::decode_command(buf)
                .map_err(|e| ApsError::Codec(discriminant(&e)))?;
            Ok((
                ApsNode {
                    frame_type: frame_type_bits(d.header.control.frame_type),
                    delivery_mode: delivery_bits(d.header.control.delivery_mode),
                    dst_endpoint: 0,
                    cluster_id: 0,
                    profile_id: 0,
                    src_endpoint: 0,
                    counter: d.header.counter,
                    command_id: Some(d.header.command_id),
                },
                d.payload,
            ))
        }
        rounddance_aps::frame::FrameType::Ack => {
            let d = rounddance_aps::frame::decode_ack(buf)
                .map_err(|e| ApsError::Codec(discriminant(&e)))?;
            Ok((
                ApsNode {
                    frame_type: frame_type_bits(d.header.control.frame_type),
                    delivery_mode: delivery_bits(d.header.control.delivery_mode),
                    dst_endpoint: 0,
                    cluster_id: 0,
                    profile_id: 0,
                    src_endpoint: 0,
                    counter: d.header.counter,
                    command_id: None,
                },
                d.payload,
            ))
        }
        rounddance_aps::frame::FrameType::InterPan => Err(ApsError::Codec(8)),
    }
}
