//! General (foundation) command payload codecs: attribute
//! read/write, reporting configuration, reports, discovery, and the
//! Default Response.
//!
//! Paraphrase-level model of doc `07-5123-08` Table 2-3 (command
//! identifiers, anchor p0062-L2431-L2432), §2.5.1–2.5.2 (read,
//! anchors p0063-L2452-L2455 + p0064-L2475-L2501), §2.5.3/2.5.5
//! (write + write response, anchors p0067-L2561-L2587 +
//! p0068-L2596-L2615), §2.5.6 (no-response write, anchor
//! p0070-L2645-L2657), §2.5.7–2.5.10 (reporting setup + query,
//! anchors p0070-L2659-L2669 + p0072-L2711-L2741 + p0073-L2764-L2768
//! plus p0076-L2852-L2866), §2.5.11 (report frame, anchor
//! p0078-L2903-L2920), §2.5.12 (Default Response, anchors
//! p0080-L2980-L2994 + p0081-L3001-L3016), §2.5.13–2.5.14
//! (attribute discovery, anchors p0081-L3020-L3033 +
//! p0082-L3040-L3071), §2.5.18–2.5.19 (command discovery, anchors
//! p0089-L3277-L3300 + p0090-L3308-L3329). All wording is paraphrase.
//!
//! Requirement IDs: `07-5123-08-25-02` (command table),
//! `07-5123-08-2512-01`/`2513-01`/`2514-01`/`2518-01`/`2511-01`
//! (repo-minted, MINTED-pending-confirm); `07-5123-08-251-01/02`,
//! `252-01/02`, `253-01/02`, `256-01`, `257-01..05`, `25-10-01`
//! corpus-mined and reused.

use crate::types::{DataType, Value};
use crate::{Error, ZclStatus};

/// Largest record list one payload carries here. Longer wire lists
/// are rejected fallibly (the peer must page via discovery or split
/// the request).
pub const MAX_RECORDS: usize = 16;

/// General command identifiers (Table 2-3 values).
///
/// Requirement `07-5123-08-25-02` (MINTED-pending-confirm).
pub mod cmd {
    /// Read Attributes.
    pub const READ: u8 = 0x00;
    /// Read Attributes Response.
    pub const READ_RSP: u8 = 0x01;
    /// Write Attributes.
    pub const WRITE: u8 = 0x02;
    /// Write Attributes Undivided.
    pub const WRITE_UNDIVIDED: u8 = 0x03;
    /// Write Attributes Response.
    pub const WRITE_RSP: u8 = 0x04;
    /// Write Attributes No Response.
    pub const WRITE_NO_RSP: u8 = 0x05;
    /// Configure Reporting.
    pub const CONFIG_REPORT: u8 = 0x06;
    /// Configure Reporting Response.
    pub const CONFIG_REPORT_RSP: u8 = 0x07;
    /// Read Reporting Configuration.
    pub const READ_REPORT_CFG: u8 = 0x08;
    /// Read Reporting Configuration Response.
    pub const READ_REPORT_CFG_RSP: u8 = 0x09;
    /// Report Attributes.
    pub const REPORT: u8 = 0x0a;
    /// Default Response.
    pub const DEFAULT_RSP: u8 = 0x0b;
    /// Discover Attributes.
    pub const DISCOVER_ATTRS: u8 = 0x0c;
    /// Discover Attributes Response.
    pub const DISCOVER_ATTRS_RSP: u8 = 0x0d;
    /// Discover Commands Received.
    pub const DISCOVER_CMDS_RX: u8 = 0x11;
    /// Discover Commands Received Response.
    pub const DISCOVER_CMDS_RX_RSP: u8 = 0x12;
    /// Discover Commands Generated.
    pub const DISCOVER_CMDS_TX: u8 = 0x13;
    /// Discover Commands Generated Response.
    pub const DISCOVER_CMDS_TX_RSP: u8 = 0x14;
}

/// Decode a packed `u16` list (Read Attributes request body).
pub fn decode_id_list(buf: &[u8], out: &mut [u16]) -> Result<usize, Error> {
    if !buf.len().is_multiple_of(2) {
        return Err(Error::MalformedList);
    }
    let n = buf.len() / 2;
    if n == 0 {
        return Err(Error::Truncated);
    }
    if n > out.len() {
        return Err(Error::TooManyRecords);
    }
    let mut i = 0;
    while i < n {
        out[i] = u16::from_le_bytes([buf[2 * i], buf[2 * i + 1]]);
        i += 1;
    }
    Ok(n)
}

/// Encode a packed `u16` list.
pub fn encode_id_list(ids: &[u16], out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < ids.len() * 2 {
        return Err(Error::BufferTooSmall);
    }
    let mut i = 0;
    while i < ids.len() {
        out[2 * i..2 * i + 2].copy_from_slice(&ids[i].to_le_bytes());
        i += 1;
    }
    Ok(ids.len() * 2)
}

/// One Read Attributes Response status record: identifier echoed,
/// type + value present only on success.
///
/// Requirement `07-5123-08-252-01` (corpus-mined).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadRecord {
    /// Requested identifier echoed back.
    pub id: u16,
    /// Evaluated status.
    pub status: ZclStatus,
    /// Wire type (meaningful only on success).
    pub dtype: u8,
    /// Current value (meaningful only on success).
    pub value: Value,
}

/// Decode read-response records; over-long lists are rejected, short
/// reads stop at the first truncation error.
pub fn decode_read_rsp(buf: &[u8], out: &mut [ReadRecord]) -> Result<usize, Error> {
    let mut off = 0;
    let mut n = 0;
    while off < buf.len() {
        if n >= out.len() {
            return Err(Error::TooManyRecords);
        }
        if buf.len() - off < 3 {
            return Err(Error::Truncated);
        }
        let id = u16::from_le_bytes([buf[off], buf[off + 1]]);
        let status = ZclStatus::from_u8(buf[off + 2]);
        off += 3;
        let (dtype, value) = if status.is_success() {
            if buf.len() - off < 1 {
                return Err(Error::Truncated);
            }
            let dtype = DataType::from_u8(buf[off])?;
            let (v, used) = Value::decode(dtype, &buf[off + 1..])?;
            off += 1 + used;
            (buf[off - used - 1], v)
        } else {
            (0x00, Value::NoData)
        };
        out[n] = ReadRecord {
            id,
            status,
            dtype,
            value,
        };
        n += 1;
    }
    if n == 0 {
        return Err(Error::Truncated);
    }
    Ok(n)
}

/// Encode read-response records.
pub fn encode_read_rsp(records: &[ReadRecord], out: &mut [u8]) -> Result<usize, Error> {
    let mut off = 0;
    let mut i = 0;
    while i < records.len() {
        let r = &records[i];
        let need = 3 + if r.status.is_success() {
            1 + r.value.encoded_len()
        } else {
            0
        };
        if out.len() - off < need {
            return Err(Error::BufferTooSmall);
        }
        out[off..off + 2].copy_from_slice(&r.id.to_le_bytes());
        out[off + 2] = r.status.as_u8();
        off += 3;
        if r.status.is_success() {
            // The type octet precedes the body; encode past it so the
            // body never clobbers the type.
            out[off] = r.dtype;
            let wn = r.value.encode_into(&mut out[off + 1..])?;
            off += 1 + wn;
        }
        i += 1;
    }
    if records.is_empty() {
        return Err(Error::Truncated);
    }
    Ok(off)
}

/// One Write Attributes record: identifier, wire type, new value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteRecord {
    /// Target attribute.
    pub id: u16,
    /// Claimed wire type (checked against the definition).
    pub dtype: u8,
    /// Proposed value.
    pub value: Value,
}

/// Decode write records.
pub fn decode_write(buf: &[u8], out: &mut [WriteRecord]) -> Result<usize, Error> {
    let mut off = 0;
    let mut n = 0;
    while off < buf.len() {
        if n >= out.len() {
            return Err(Error::TooManyRecords);
        }
        if buf.len() - off < 3 {
            return Err(Error::Truncated);
        }
        let id = u16::from_le_bytes([buf[off], buf[off + 1]]);
        let dtype = DataType::from_u8(buf[off + 2])?;
        let (value, used) = Value::decode(dtype, &buf[off + 3..])?;
        off += 3 + used;
        out[n] = WriteRecord {
            id,
            dtype: buf[off - used - 1],
            value,
        };
        n += 1;
    }
    if n == 0 {
        return Err(Error::Truncated);
    }
    Ok(n)
}

/// One Write Attributes Response record: status first, identifier
/// present only on failure; total success compacts to a single bare
/// SUCCESS record.
///
/// Requirement `07-5123-08-253-02` (corpus-mined).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteStatus {
    /// Outcome for the record.
    pub status: ZclStatus,
    /// Failed identifier (`None` in the all-success compact form).
    pub id: Option<u16>,
}

/// Encode a write response, applying the all-success compaction.
pub fn encode_write_rsp(statuses: &[WriteStatus], out: &mut [u8]) -> Result<usize, Error> {
    if statuses.is_empty() {
        return Err(Error::Truncated);
    }
    if statuses.len() == 1 && statuses[0].status.is_success() {
        if out.is_empty() {
            return Err(Error::BufferTooSmall);
        }
        out[0] = ZclStatus::Success.as_u8();
        return Ok(1);
    }
    let mut off = 0;
    let mut i = 0;
    while i < statuses.len() {
        let s = &statuses[i];
        // Successful per-attribute records are omitted to save
        // bandwidth; only failures travel with identifiers.
        if s.status.is_success() {
            i += 1;
            continue;
        }
        if out.len() - off < 3 {
            return Err(Error::BufferTooSmall);
        }
        out[off] = s.status.as_u8();
        let id = s.id.ok_or(Error::MalformedList)?;
        out[off + 1..off + 3].copy_from_slice(&id.to_le_bytes());
        off += 3;
        i += 1;
    }
    if off == 0 {
        // Every record succeeded but the caller passed them
        // uncompacted: emit the compact form.
        if out.is_empty() {
            return Err(Error::BufferTooSmall);
        }
        out[0] = ZclStatus::Success.as_u8();
        return Ok(1);
    }
    Ok(off)
}

/// Decode a write response (compact or per-record form).
pub fn decode_write_rsp(buf: &[u8], out: &mut [WriteStatus]) -> Result<usize, Error> {
    if buf.is_empty() {
        return Err(Error::Truncated);
    }
    if buf.len() == 1 {
        if out.is_empty() {
            return Err(Error::TooManyRecords);
        }
        out[0] = WriteStatus {
            status: ZclStatus::from_u8(buf[0]),
            id: None,
        };
        return Ok(1);
    }
    if !buf.len().is_multiple_of(3) {
        return Err(Error::MalformedList);
    }
    let n = buf.len() / 3;
    if n > out.len() {
        return Err(Error::TooManyRecords);
    }
    let mut i = 0;
    while i < n {
        out[i] = WriteStatus {
            status: ZclStatus::from_u8(buf[3 * i]),
            id: Some(u16::from_le_bytes([buf[3 * i + 1], buf[3 * i + 2]])),
        };
        i += 1;
    }
    Ok(n)
}

/// One Configure Reporting record. For send direction (`0x00`) the
/// type + intervals travel, with the change threshold present exactly
/// for analog types; for receive direction (`0x01`) only the timeout
/// travels.
///
/// Requirements `07-5123-08-257-01` (corpus-mined, one record per
/// attribute) + `07-5123-08-257-03` (corpus-mined, analog-only
/// change field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportCfgRecord {
    /// `0x00` = configure sent reports, `0x01` = configure reception.
    pub direction: u8,
    /// Target attribute.
    pub id: u16,
    /// Claimed wire type (send direction only).
    pub dtype: u8,
    /// Minimum interval seconds (send direction only).
    pub min: u16,
    /// Maximum interval seconds (send direction only).
    pub max: u16,
    /// Change threshold, analog types only (send direction only).
    pub change: Option<Value>,
    /// Reception timeout seconds (receive direction only).
    pub timeout: u16,
}

/// Decode configure-reporting records.
pub fn decode_config_report(buf: &[u8], out: &mut [ReportCfgRecord]) -> Result<usize, Error> {
    let mut off = 0;
    let mut n = 0;
    while off < buf.len() {
        if n >= out.len() {
            return Err(Error::TooManyRecords);
        }
        if buf.len() - off < 3 {
            return Err(Error::Truncated);
        }
        let direction = buf[off];
        let id = u16::from_le_bytes([buf[off + 1], buf[off + 2]]);
        off += 3;
        let rec = match direction {
            0x00 => {
                if buf.len() - off < 5 {
                    return Err(Error::Truncated);
                }
                let dtype = DataType::from_u8(buf[off])?;
                let min = u16::from_le_bytes([buf[off + 1], buf[off + 2]]);
                let max = u16::from_le_bytes([buf[off + 3], buf[off + 4]]);
                off += 5;
                let change = if dtype.is_analog() {
                    let (v, used) = Value::decode(dtype, &buf[off..])?;
                    off += used;
                    Some(v)
                } else {
                    None
                };
                ReportCfgRecord {
                    direction,
                    id,
                    dtype: dtype.as_u8(),
                    min,
                    max,
                    change,
                    timeout: 0,
                }
            }
            0x01 => {
                if buf.len() - off < 2 {
                    return Err(Error::Truncated);
                }
                let timeout = u16::from_le_bytes([buf[off], buf[off + 1]]);
                off += 2;
                ReportCfgRecord {
                    direction,
                    id,
                    dtype: 0x00,
                    min: 0,
                    max: 0,
                    change: None,
                    timeout,
                }
            }
            v => return Err(Error::InvalidValue(v)),
        };
        out[n] = rec;
        n += 1;
    }
    if n == 0 {
        return Err(Error::Truncated);
    }
    Ok(n)
}

/// Encode configure-reporting records.
pub fn encode_config_report(records: &[ReportCfgRecord], out: &mut [u8]) -> Result<usize, Error> {
    if records.is_empty() {
        return Err(Error::Truncated);
    }
    let mut off = 0;
    let mut i = 0;
    while i < records.len() {
        let r = &records[i];
        match r.direction {
            0x00 => {
                let dtype = DataType::from_u8(r.dtype)?;
                let need = 3
                    + 5
                    + if dtype.is_analog() {
                        r.change.map(|c| c.encoded_len()).unwrap_or(0)
                    } else {
                        0
                    };
                if out.len() - off < need {
                    return Err(Error::BufferTooSmall);
                }
                out[off] = 0x00;
                out[off + 1..off + 3].copy_from_slice(&r.id.to_le_bytes());
                out[off + 3] = r.dtype;
                out[off + 4..off + 6].copy_from_slice(&r.min.to_le_bytes());
                out[off + 6..off + 8].copy_from_slice(&r.max.to_le_bytes());
                off += 8;
                if dtype.is_analog() {
                    let c = r.change.ok_or(Error::MalformedList)?;
                    off += c.encode_into(&mut out[off..])?;
                }
            }
            0x01 => {
                if out.len() - off < 5 {
                    return Err(Error::BufferTooSmall);
                }
                out[off] = 0x01;
                out[off + 1..off + 3].copy_from_slice(&r.id.to_le_bytes());
                out[off + 3..off + 5].copy_from_slice(&r.timeout.to_le_bytes());
                off += 5;
            }
            v => return Err(Error::InvalidValue(v)),
        }
        i += 1;
    }
    Ok(off)
}

/// One Configure Reporting Response record: status, with direction +
/// identifier present on failure; total success compacts to bare
/// SUCCESS.
///
/// Requirement `07-5123-08-257-04` (corpus-mined, per-record status).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CfgStatus {
    /// Outcome for the record.
    pub status: ZclStatus,
    /// Failed direction (`None` in the all-success compact form).
    pub direction: Option<u8>,
    /// Failed identifier (`None` in the all-success compact form).
    pub id: Option<u16>,
}

/// Encode a configure-reporting response with success compaction.
pub fn encode_config_report_rsp(statuses: &[CfgStatus], out: &mut [u8]) -> Result<usize, Error> {
    if statuses.is_empty() {
        return Err(Error::Truncated);
    }
    if statuses.len() == 1 && statuses[0].status.is_success() {
        if out.is_empty() {
            return Err(Error::BufferTooSmall);
        }
        out[0] = ZclStatus::Success.as_u8();
        return Ok(1);
    }
    let mut off = 0;
    let mut i = 0;
    while i < statuses.len() {
        let s = &statuses[i];
        if s.status.is_success() {
            i += 1;
            continue;
        }
        if out.len() - off < 4 {
            return Err(Error::BufferTooSmall);
        }
        out[off] = s.status.as_u8();
        out[off + 1] = s.direction.ok_or(Error::MalformedList)?;
        let id = s.id.ok_or(Error::MalformedList)?;
        out[off + 2..off + 4].copy_from_slice(&id.to_le_bytes());
        off += 4;
        i += 1;
    }
    if off == 0 {
        if out.is_empty() {
            return Err(Error::BufferTooSmall);
        }
        out[0] = ZclStatus::Success.as_u8();
        return Ok(1);
    }
    Ok(off)
}

/// Decode a configure-reporting response.
pub fn decode_config_report_rsp(buf: &[u8], out: &mut [CfgStatus]) -> Result<usize, Error> {
    if buf.is_empty() {
        return Err(Error::Truncated);
    }
    if buf.len() == 1 {
        if out.is_empty() {
            return Err(Error::TooManyRecords);
        }
        out[0] = CfgStatus {
            status: ZclStatus::from_u8(buf[0]),
            direction: None,
            id: None,
        };
        return Ok(1);
    }
    if !buf.len().is_multiple_of(4) {
        return Err(Error::MalformedList);
    }
    let n = buf.len() / 4;
    if n > out.len() {
        return Err(Error::TooManyRecords);
    }
    let mut i = 0;
    while i < n {
        out[i] = CfgStatus {
            status: ZclStatus::from_u8(buf[4 * i]),
            direction: Some(buf[4 * i + 1]),
            id: Some(u16::from_le_bytes([buf[4 * i + 2], buf[4 * i + 3]])),
        };
        i += 1;
    }
    Ok(n)
}

/// One Read Reporting Configuration query: direction + identifier.
///
/// Requirement `07-5123-08-25-10-01` (corpus-mined).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadCfgQuery {
    /// `0x00` = sent reports, `0x01` = received reports.
    pub direction: u8,
    /// Queried attribute.
    pub id: u16,
}

/// Decode read-reporting-configuration queries.
pub fn decode_read_report_cfg(buf: &[u8], out: &mut [ReadCfgQuery]) -> Result<usize, Error> {
    if buf.is_empty() || !buf.len().is_multiple_of(3) {
        return Err(if buf.is_empty() {
            Error::Truncated
        } else {
            Error::MalformedList
        });
    }
    let n = buf.len() / 3;
    if n > out.len() {
        return Err(Error::TooManyRecords);
    }
    let mut i = 0;
    while i < n {
        let direction = buf[3 * i];
        if direction != 0x00 && direction != 0x01 {
            return Err(Error::InvalidValue(direction));
        }
        out[i] = ReadCfgQuery {
            direction,
            id: u16::from_le_bytes([buf[3 * i + 1], buf[3 * i + 2]]),
        };
        i += 1;
    }
    Ok(n)
}

/// One attribute report: identifier, type, current value.
///
/// Requirement `07-5123-08-2511-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportRecord {
    /// Reported attribute.
    pub id: u16,
    /// Wire type.
    pub dtype: u8,
    /// Reported value.
    pub value: Value,
}

/// Decode report records.
pub fn decode_report(buf: &[u8], out: &mut [ReportRecord]) -> Result<usize, Error> {
    let mut off = 0;
    let mut n = 0;
    while off < buf.len() {
        if n >= out.len() {
            return Err(Error::TooManyRecords);
        }
        if buf.len() - off < 3 {
            return Err(Error::Truncated);
        }
        let id = u16::from_le_bytes([buf[off], buf[off + 1]]);
        let dtype = DataType::from_u8(buf[off + 2])?;
        let (value, used) = Value::decode(dtype, &buf[off + 3..])?;
        off += 3 + used;
        out[n] = ReportRecord {
            id,
            dtype: buf[off - used - 1],
            value,
        };
        n += 1;
    }
    if n == 0 {
        return Err(Error::Truncated);
    }
    Ok(n)
}

/// Encode report records.
pub fn encode_report(records: &[ReportRecord], out: &mut [u8]) -> Result<usize, Error> {
    if records.is_empty() {
        return Err(Error::Truncated);
    }
    let mut off = 0;
    let mut i = 0;
    while i < records.len() {
        let r = &records[i];
        let need = 3 + r.value.encoded_len();
        if out.len() - off < need {
            return Err(Error::BufferTooSmall);
        }
        out[off..off + 2].copy_from_slice(&r.id.to_le_bytes());
        out[off + 2] = r.dtype;
        off += 3 + r.value.encode_into(&mut out[off + 3..])?;
        i += 1;
    }
    Ok(off)
}

/// Discover Attributes request: start identifier + result cap.
///
/// Requirement `07-5123-08-2513-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoverAttrs {
    /// First identifier to consider.
    pub start: u16,
    /// Maximum records to return.
    pub max: u8,
}

impl DiscoverAttrs {
    /// Decode the 3-octet request.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 3 {
            return Err(Error::Truncated);
        }
        Ok(Self {
            start: u16::from_le_bytes([buf[0], buf[1]]),
            max: buf[2],
        })
    }

    /// Encode the 3-octet request.
    pub fn encode_into(self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < 3 {
            return Err(Error::BufferTooSmall);
        }
        out[..2].copy_from_slice(&self.start.to_le_bytes());
        out[2] = self.max;
        Ok(3)
    }
}

/// Encode a Discover Attributes Response: completion flag plus
/// ascending identifier/type pairs.
///
/// Requirement `07-5123-08-2514-01` (MINTED-pending-confirm).
pub fn encode_discover_attrs_rsp(
    records: &[(u16, u8)],
    complete: bool,
    out: &mut [u8],
) -> Result<usize, Error> {
    let need = 1 + records.len() * 3;
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    out[0] = u8::from(complete);
    let mut i = 0;
    while i < records.len() {
        out[1 + 3 * i..1 + 3 * i + 2].copy_from_slice(&records[i].0.to_le_bytes());
        out[1 + 3 * i + 2] = records[i].1;
        i += 1;
    }
    Ok(need)
}

/// Decode a Discover Attributes Response into `out`.
pub fn decode_discover_attrs_rsp(
    buf: &[u8],
    out: &mut [(u16, u8)],
) -> Result<(bool, usize), Error> {
    if buf.is_empty() || !buf.len().saturating_sub(1).is_multiple_of(3) {
        return Err(if buf.is_empty() {
            Error::Truncated
        } else {
            Error::MalformedList
        });
    }
    let complete = match buf[0] {
        0x00 => false,
        0x01 => true,
        v => return Err(Error::InvalidValue(v)),
    };
    let n = (buf.len() - 1) / 3;
    if n > out.len() {
        return Err(Error::TooManyRecords);
    }
    let mut i = 0;
    while i < n {
        out[i] = (
            u16::from_le_bytes([buf[1 + 3 * i], buf[1 + 3 * i + 1]]),
            buf[1 + 3 * i + 2],
        );
        i += 1;
    }
    Ok((complete, n))
}

/// Discover Commands request: start identifier + result cap.
///
/// Requirement `07-5123-08-2518-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoverCmds {
    /// First command identifier to consider.
    pub start: u8,
    /// Maximum records to return.
    pub max: u8,
}

impl DiscoverCmds {
    /// Decode the 2-octet request.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 2 {
            return Err(Error::Truncated);
        }
        Ok(Self {
            start: buf[0],
            max: buf[1],
        })
    }

    /// Encode the 2-octet request.
    pub fn encode_into(self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < 2 {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.start;
        out[1] = self.max;
        Ok(2)
    }
}

/// Encode a Discover Commands Response: completion flag plus
/// ascending command identifiers.
pub fn encode_discover_cmds_rsp(
    ids: &[u8],
    complete: bool,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < 1 + ids.len() {
        return Err(Error::BufferTooSmall);
    }
    out[0] = u8::from(complete);
    out[1..1 + ids.len()].copy_from_slice(ids);
    Ok(1 + ids.len())
}

/// Decode a Discover Commands Response into `out`.
pub fn decode_discover_cmds_rsp(buf: &[u8], out: &mut [u8]) -> Result<(bool, usize), Error> {
    if buf.is_empty() {
        return Err(Error::Truncated);
    }
    let complete = match buf[0] {
        0x00 => false,
        0x01 => true,
        v => return Err(Error::InvalidValue(v)),
    };
    if buf.len() - 1 > out.len() {
        return Err(Error::TooManyRecords);
    }
    out[..buf.len() - 1].copy_from_slice(&buf[1..]);
    Ok((complete, buf.len() - 1))
}

/// Default Response body: echoed command identifier + status.
///
/// Requirement `07-5123-08-2512-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DefaultRsp {
    /// Identifier of the command this answers.
    pub cmd: u8,
    /// Outcome status.
    pub status: ZclStatus,
}

impl DefaultRsp {
    /// Decode the 2-octet body.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 2 {
            return Err(Error::Truncated);
        }
        Ok(Self {
            cmd: buf[0],
            status: ZclStatus::from_u8(buf[1]),
        })
    }

    /// Encode the 2-octet body.
    pub fn encode_into(self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < 2 {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.cmd;
        out[1] = self.status.as_u8();
        Ok(2)
    }
}
