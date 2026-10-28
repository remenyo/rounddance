//! ZCL dissector: reused `rounddance-zcl` codec → [`ZclNode`](crate::tree::ZclNode).
//!
//! The header always decodes via the codec; the payload additionally
//! gets a bounded [`ZclDetail`](crate::tree::ZclDetail) summary for the
//! foundation commands, the top clusters observed in lab captures
//! (On/Off `0x0006`, Level Control `0x0008`, IAS Zone `0x0500`), the
//! Smart-Energy Metering (`0x0702`) and Price (`0x0700`) headline
//! commands, and the Key Establishment (`0x0800`) frame shapes.
//! Anything else — or any short payload — degrades to a named
//! variant, never an error: a truncated cluster payload is still a
//! successfully dissected frame.
//!
//! The Smart-Energy and Key Establishment summaries are decode-only:
//! ephemeral points are length-checked but never decompressed,
//! confirm tags are length-checked but never verified, and no key
//! material is retained.

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
            let direction = h.control.direction.bit();
            let detail = summarize(frame_type, direction, h.command_id, cluster_id, payload);
            Ok(ZclNode {
                frame_type,
                manufacturer_specific: h.control.manufacturer_specific,
                direction,
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

fn summarize(frame_type: u8, direction: u8, cmd: u8, cluster_id: u16, payload: &[u8]) -> ZclDetail {
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
            // Same ids name requests one way and responses the other
            // (0x00 GetProfile vs GetProfileResponse), so the
            // direction bit picks the shape here — unlike the
            // direction-agnostic families above.
            rounddance_zcl::metering::CLUSTER_ID => {
                return summarize_metering(direction, cmd, payload)
            }
            rounddance_zcl::price::CLUSTER_ID => return summarize_price(direction, cmd, payload),
            // Initiate / ephemeral / confirm / terminate share ids
            // across directions with identical shapes, so the keyest
            // summary ignores the direction bit.
            rounddance_zcl::keyest::CLUSTER_ID => return summarize_keyest(cmd, payload),
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

/// Smart-Energy Metering headline shapes: GetProfile (+ response)
/// and FastPollMode (+ response). Mirror / snapshot / sampling /
/// supply / notification-scheme commands have no summary here and
/// stay `Unknown` by design.
fn summarize_metering(direction: u8, cmd: u8, payload: &[u8]) -> ZclDetail {
    use rounddance_zcl::metering as M;
    let le32 = |i: usize| {
        u32::from_le_bytes([
            payload.get(i).copied().unwrap_or(0),
            payload.get(i + 1).copied().unwrap_or(0),
            payload.get(i + 2).copied().unwrap_or(0),
            payload.get(i + 3).copied().unwrap_or(0),
        ])
    };
    if direction == 0 {
        match cmd {
            M::CMD_GET_PROFILE => match M::decode_get_profile(payload) {
                Ok(req) => ZclDetail::Metering {
                    cmd,
                    arg0: req.channel,
                    arg1: req.periods,
                    arg2: req.end_time,
                },
                Err(_) => ZclDetail::Unknown { cmd },
            },
            // RequestFastPollMode is a fixed 2-octet body (period
            // seconds + duration minutes); no codec exists, so the
            // length gate is the shape check.
            M::CMD_REQUEST_FAST_POLL if payload.len() == 2 => ZclDetail::Metering {
                cmd,
                arg0: payload[0],
                arg1: payload[1],
                arg2: 0,
            },
            _ => ZclDetail::Unknown { cmd },
        }
    } else {
        match cmd {
            // GetProfileResponse has no decoder in the cluster crate;
            // the fixed 7-octet prefix (end time + status + period
            // enum + count) is the shape check, intervals trail it.
            M::CMD_GET_PROFILE_RESPONSE if payload.len() >= 7 => ZclDetail::Metering {
                cmd,
                arg0: payload[4],
                arg1: payload[6],
                arg2: le32(0),
            },
            // FastPoll response is a fixed 5-octet body (period +
            // end time); no codec exists, so the length gate is the
            // shape check.
            M::CMD_FAST_POLL_RESPONSE if payload.len() == 5 => ZclDetail::Metering {
                cmd,
                arg0: payload[0],
                arg1: 0,
                arg2: le32(1),
            },
            _ => ZclDetail::Unknown { cmd },
        }
    }
}

/// Smart-Energy Price headline shapes, reusing the cluster codecs
/// where they exist. The two 4-octet tariff-id requests
/// (GetBlockThresholds / GetTierLabels) have no decoder, so an
/// exact-4-octet body is their shape check.
fn summarize_price(direction: u8, cmd: u8, payload: &[u8]) -> ZclDetail {
    use rounddance_zcl::price as P;
    let tariff_id = || {
        if payload.len() == 4 {
            Some(u32::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]))
        } else {
            None
        }
    };
    if direction == 0 {
        match cmd {
            // GetCurrentPrice is a 1-octet options body; no codec
            // exists, so the length gate is the shape check.
            P::CMD_GET_CURRENT_PRICE if payload.len() == 1 => ZclDetail::Price {
                cmd,
                arg0: u32::from(payload[0]),
                arg1: 0,
            },
            P::CMD_GET_SCHEDULED_PRICES => match P::decode_get_scheduled(payload) {
                Ok((start, count)) => ZclDetail::Price {
                    cmd,
                    arg0: start,
                    arg1: u32::from(count),
                },
                Err(_) => ZclDetail::Unknown { cmd },
            },
            P::CMD_PRICE_ACK => match P::decode_price_ack(payload) {
                Ok((_provider, issuer, ack_time, _control)) => ZclDetail::Price {
                    cmd,
                    arg0: issuer,
                    arg1: ack_time,
                },
                Err(_) => ZclDetail::Unknown { cmd },
            },
            P::CMD_GET_BLOCK_PERIODS => match P::decode_get_block_periods(payload) {
                Ok(req) => ZclDetail::Price {
                    cmd,
                    arg0: req.start_time,
                    arg1: u32::from(req.max_events),
                },
                Err(_) => ZclDetail::Unknown { cmd },
            },
            P::CMD_GET_BLOCK_THRESHOLDS | P::CMD_GET_TIER_LABELS => match tariff_id() {
                Some(tariff) => ZclDetail::Price {
                    cmd,
                    arg0: tariff,
                    arg1: 0,
                },
                None => ZclDetail::Unknown { cmd },
            },
            _ => ZclDetail::Unknown { cmd },
        }
    } else {
        match cmd {
            P::CMD_PUBLISH_PRICE => match P::decode_publish_price(payload) {
                Ok((ev, _tail)) => ZclDetail::Price {
                    cmd,
                    arg0: ev.issuer_event_id,
                    arg1: ev.price,
                },
                Err(_) => ZclDetail::Unknown { cmd },
            },
            P::CMD_PUBLISH_BLOCK_PERIOD => match P::decode_publish_block_period(payload) {
                Ok(ev) => ZclDetail::Price {
                    cmd,
                    arg0: ev.issuer_event_id,
                    arg1: ev.start_time,
                },
                Err(_) => ZclDetail::Unknown { cmd },
            },
            P::CMD_PUBLISH_BLOCK_THRESHOLDS => match P::decode_publish_block_thresholds(payload) {
                Ok(ev) => ZclDetail::Price {
                    cmd,
                    arg0: ev.issuer_event_id,
                    arg1: ev.start_time,
                },
                Err(_) => ZclDetail::Unknown { cmd },
            },
            P::CMD_PUBLISH_TIER_LABELS => {
                let mut scratch = [P::TierLabelEntry {
                    tier_id: 0,
                    len: 0,
                    label: [0u8; P::MAX_LABEL],
                }; P::MAX_TIER_LABELS];
                match P::decode_publish_tier_labels(payload, &mut scratch) {
                    Ok((_provider, issuer, _tariff, _index, count)) => ZclDetail::Price {
                        cmd,
                        arg0: issuer,
                        arg1: count as u32,
                    },
                    Err(_) => ZclDetail::Unknown { cmd },
                }
            }
            _ => ZclDetail::Unknown { cmd },
        }
    }
}

/// Confirm-tag length the Key Establishment exchange checks (the
/// 16-octet CBKE confirmation tag). Decode-only shape gate here.
const KEYEST_CONFIRM_LEN: usize = 16;

/// Key Establishment frame shapes, decode-only: Initiate bodies go
/// through the codec, ephemeral / confirm flights are
/// length-gated (the point is never decompressed, the tag never
/// verified), Terminate bodies go through the codec.
fn summarize_keyest(cmd: u8, payload: &[u8]) -> ZclDetail {
    use rounddance_zcl::keyest as K;
    match cmd {
        K::CMD_INITIATE_REQ => match K::decode_initiate(payload) {
            Ok(m) => ZclDetail::KeyInit {
                suite: m.suite,
                eph_time: m.eph_time,
                confirm_time: m.confirm_time,
            },
            Err(_) => ZclDetail::Unknown { cmd },
        },
        K::CMD_EPHEMERAL_REQ => match payload.len() {
            K::EPH_LEN | K::EPH_COMPRESSED_LEN => ZclDetail::KeyMsg {
                cmd,
                len: payload.len() as u8,
            },
            _ => ZclDetail::Unknown { cmd },
        },
        K::CMD_CONFIRM_REQ if payload.len() == KEYEST_CONFIRM_LEN => ZclDetail::KeyMsg {
            cmd,
            len: KEYEST_CONFIRM_LEN as u8,
        },
        K::CMD_TERMINATE => match K::decode_terminate(payload) {
            Ok(m) => ZclDetail::KeyTerminate {
                status: m.status,
                wait_s: m.wait_s,
                suite: m.suite,
            },
            Err(_) => ZclDetail::Unknown { cmd },
        },
        _ => ZclDetail::Unknown { cmd },
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
