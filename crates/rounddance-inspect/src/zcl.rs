//! ZCL dissector: reused `rounddance-zcl` codec → [`ZclNode`](crate::tree::ZclNode).
//!
//! The header always decodes via the codec; the payload additionally
//! gets a bounded [`ZclDetail`](crate::tree::ZclDetail) summary for the
//! foundation commands and the top clusters observed in lab captures
//! (On/Off `0x0006`, Level Control `0x0008`, IAS Zone `0x0500`).
//! Anything else — or any short payload — degrades to a named
//! variant, never an error: a truncated cluster payload is still a
//! successfully dissected frame.

use crate::tree::{ZclDetail, ZclNode};

/// ZCL dissector failure (codec refusal, passed through).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZclError {
    /// Codec refusal; discriminant preserved for the report.
    Codec(u8),
}

/// Scratch caps: at most this many foundation records are decoded;
/// the summary keeps only the count and the first record's key.
const SCRATCH_RECORDS: usize = 8;

/// Dissect one ZCL frame; returns the tree node (payload length kept,
/// plus a bounded payload summary). `cluster_id` / `profile_id` are
/// the APS envelope the payload rode in (`0xffff` when unknown).
pub fn decode(buf: &[u8], cluster_id: u16, profile_id: u16) -> Result<ZclNode, ZclError> {
    match rounddance_zcl::frame::Header::decode(buf) {
        Ok((h, payload)) => {
            if payload.len() > u16::MAX as usize {
                return Err(ZclError::Codec(1));
            }
            let frame_type = h.control.frame_type.bits();
            let detail = summarize(frame_type, h.command_id, cluster_id, payload);
            Ok(ZclNode {
                frame_type,
                manufacturer_specific: h.control.manufacturer_specific,
                direction: h.control.direction.bit(),
                manufacturer_code: h.manufacturer_code,
                tsn: h.tsn,
                command_id: h.command_id,
                payload_len: payload.len() as u16,
                cluster_id,
                profile_id,
                detail,
            })
        }
        Err(_) => Err(ZclError::Codec(2)),
    }
}

fn summarize(frame_type: u8, cmd: u8, cluster_id: u16, payload: &[u8]) -> ZclDetail {
    // Empty payloads still name the family for cluster-specific
    // commands (Off/On/Toggle carry no payload); only the global
    // summary needs record bytes.
    if frame_type == 0 {
        return summarize_global(cmd, payload);
    }
    if frame_type == 1 {
        match cluster_id {
            rounddance_zcl::onoff::CLUSTER_ID => {
                return match cmd {
                    rounddance_zcl::onoff::CMD_OFF
                    | rounddance_zcl::onoff::CMD_ON
                    | rounddance_zcl::onoff::CMD_TOGGLE
                    | rounddance_zcl::onoff::CMD_OFF_EFFECT
                    | rounddance_zcl::onoff::CMD_ON_RECALL_SCENE
                    | rounddance_zcl::onoff::CMD_ON_TIMED_OFF => ZclDetail::OnOff { cmd },
                    _ => ZclDetail::Unknown { cmd },
                };
            }
            rounddance_zcl::level::CLUSTER_ID => return summarize_level(cmd, payload),
            rounddance_zcl::ias_zone::CLUSTER_ID => {
                // Command ids overlap across directions (0x00/0x01 in
                // both); the summary is direction-agnostic on purpose.
                return match cmd {
                    0x00..=0x02 => ZclDetail::IasZone { cmd },
                    _ => ZclDetail::Unknown { cmd },
                };
            }
            _ => return ZclDetail::Unknown { cmd },
        }
    }
    ZclDetail::Unknown { cmd }
}

fn summarize_global(cmd: u8, payload: &[u8]) -> ZclDetail {
    use rounddance_zcl::general::cmd as G;
    match cmd {
        G::READ => {
            let mut ids = [0u16; SCRATCH_RECORDS];
            match rounddance_zcl::general::decode_id_list(payload, &mut ids) {
                Ok(n) => ZclDetail::Global {
                    cmd,
                    records: n.min(u8::MAX as usize) as u8,
                    first_id: if n > 0 { ids[0] } else { 0xffff },
                    status: 0xff,
                },
                Err(_) => ZclDetail::Global {
                    cmd,
                    records: 0,
                    first_id: 0xffff,
                    status: 0xff,
                },
            }
        }
        G::READ_RSP => {
            let mut recs = [rounddance_zcl::general::ReadRecord {
                id: 0,
                status: rounddance_zcl::status::ZclStatus::Failure,
                dtype: 0,
                value: rounddance_zcl::types::Value::NoData,
            }; SCRATCH_RECORDS];
            match rounddance_zcl::general::decode_read_rsp(payload, &mut recs) {
                Ok(n) => {
                    let first = if n > 0 { Some(recs[0]) } else { None };
                    ZclDetail::Global {
                        cmd,
                        records: n.min(u8::MAX as usize) as u8,
                        first_id: first.map(|r| r.id).unwrap_or(0xffff),
                        status: first.map(|r| r.status.as_u8()).unwrap_or(0xff),
                    }
                }
                Err(_) => ZclDetail::Global {
                    cmd,
                    records: 0,
                    first_id: 0xffff,
                    status: 0xff,
                },
            }
        }
        G::REPORT => {
            let mut recs = [rounddance_zcl::general::ReportRecord {
                id: 0,
                dtype: 0,
                value: rounddance_zcl::types::Value::NoData,
            }; SCRATCH_RECORDS];
            match rounddance_zcl::general::decode_report(payload, &mut recs) {
                Ok(n) => ZclDetail::Global {
                    cmd,
                    records: n.min(u8::MAX as usize) as u8,
                    first_id: if n > 0 { recs[0].id } else { 0xffff },
                    status: 0xff,
                },
                Err(_) => ZclDetail::Global {
                    cmd,
                    records: 0,
                    first_id: 0xffff,
                    status: 0xff,
                },
            }
        }
        G::DEFAULT_RSP => match rounddance_zcl::general::DefaultRsp::decode(payload) {
            Ok(d) => ZclDetail::Global {
                cmd,
                records: 1,
                first_id: u16::from(d.cmd),
                status: d.status.as_u8(),
            },
            Err(_) => ZclDetail::Global {
                cmd,
                records: 0,
                first_id: 0xffff,
                status: 0xff,
            },
        },
        _ => ZclDetail::Global {
            cmd,
            records: 0,
            first_id: 0xffff,
            status: 0xff,
        },
    }
}

fn summarize_level(cmd: u8, payload: &[u8]) -> ZclDetail {
    use rounddance_zcl::level as L;
    let at = |i: usize| payload.get(i).copied().unwrap_or(0);
    let le16 = |i: usize| u16::from_le_bytes([at(i), at(i + 1)]);
    match cmd {
        L::CMD_MOVE_TO_LEVEL | L::CMD_MOVE_TO_LEVEL_ONOFF => ZclDetail::Level {
            cmd,
            arg0: at(0),
            arg1: le16(1),
        },
        L::CMD_MOVE | L::CMD_MOVE_ONOFF => ZclDetail::Level {
            cmd,
            arg0: at(0),
            arg1: u16::from(at(1)),
        },
        L::CMD_STEP | L::CMD_STEP_ONOFF => ZclDetail::Level {
            cmd,
            arg0: at(1),
            arg1: le16(2),
        },
        L::CMD_STOP | L::CMD_STOP_ONOFF => ZclDetail::Level {
            cmd,
            arg0: 0,
            arg1: 0,
        },
        _ => ZclDetail::Unknown { cmd },
    }
}
