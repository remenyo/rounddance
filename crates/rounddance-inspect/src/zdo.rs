//! ZDO envelope dissector: the device-profile leg for APS payloads
//! on profile `0x0000`.
//!
//! ZDO frames are never ZCL. Before this leg, a response whose
//! transaction sequence happened to look like a ZCL frame-control
//! octet misparsed as a ZCL command (`zcl: ... profile=0x0000
//! unknown cmd`), and every other ZDO body stopped `unknown`. The
//! envelope — request/response direction from the cluster's
//! `0x8000` bit, transaction sequence, response status — is always
//! named; per-cluster bodies stay unmodeled by design (as with
//! unmodeled ZCL clusters).

use crate::tree::ZdoNode;

/// Response-bit position in a ZDO cluster identifier.
const RESPONSE_BIT: u16 = 0x8000;

/// ZDO dissector failure (empty payload only: there is no
/// transaction sequence to file).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZdoError {
    /// No payload octets at all.
    Empty,
}

/// Dissect one ZDO payload on `cluster_id` (the APS envelope the
/// payload rode in). A lone transaction-sequence octet still names
/// the frame; a one-octet response leaves its status unknown rather
/// than guessing.
pub fn decode(cluster_id: u16, buf: &[u8]) -> Result<ZdoNode, ZdoError> {
    let tsn = buf.first().copied().ok_or(ZdoError::Empty)?;
    let is_response = cluster_id & RESPONSE_BIT != 0;
    let status = if is_response && buf.len() >= 2 {
        Some(buf[1])
    } else {
        None
    };
    Ok(ZdoNode {
        cluster_id,
        is_response,
        tsn,
        status,
        payload_len: buf.len().min(u16::MAX as usize) as u16,
    })
}
