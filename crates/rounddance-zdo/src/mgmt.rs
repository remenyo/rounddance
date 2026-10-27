//! Network-manager basics: leave / permit-joining / channel-update
//! structures plus codecs. Full management logic (scan scheduling,
//! conflict resolution) is a later wave; structures now.
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2 §2.4.3.3.5
//! (`Mgmt_Leave_req` 0x0034, anchor p0145-L3530-L3531), §2.4.3.3.7
//! (`Mgmt_Permit_Joining_req` 0x0036, anchor p0146-L3555-L3556),
//! §2.4.3.3.9 (`Mgmt_NWK_Update_req` 0x0038, anchor
//! p0148-L3620-L3625) and the update-notify procedure (§2.4.3.3.9.3,
//! anchors p0151-L3696-L3709: the local device reports the scan
//! outcome in a notify naming scanned channels, transmission counts,
//! and per-channel energy). All wording here is paraphrase (D1,
//! `SCOPE.md` §2).
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped), MINTED-pending-confirm.

use crate::desc::Error;
use crate::status::ZdpStatus;

/// `Mgmt_Leave_req`: ask a remote device to leave the network
/// (§2.4.3.3.5, anchor p0145-L3530-L3531).
///
/// Requirement `05-3474-23-24335-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtLeaveReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// Long address of the device that must leave.
    pub device_ieee: u64,
    /// Rejoin flag: ask the device to rejoin afterwards.
    pub rejoin: bool,
    /// Remove-children flag: its children leave too.
    pub remove_children: bool,
}

impl MgmtLeaveReq {
    /// Wire length.
    pub const LEN: usize = 10;

    /// Decode a leave request frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            device_ieee: u64::from_le_bytes([
                buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
            ]),
            rejoin: buf[9] & 0x01 != 0,
            remove_children: buf[9] & 0x02 != 0,
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        let ieee = self.device_ieee.to_le_bytes();
        out[1..9].copy_from_slice(&ieee);
        out[9] = (u8::from(self.rejoin)) | (u8::from(self.remove_children) << 1);
        Ok(Self::LEN)
    }
}

/// `Mgmt_Leave_rsp`: sequence echo plus outcome only.
///
/// Requirement `05-3474-23-24335-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtLeaveRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the leave.
    pub status: ZdpStatus,
}

impl MgmtLeaveRsp {
    /// Wire length.
    pub const LEN: usize = 2;

    /// Decode a leave response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            status: ZdpStatus::from_code(buf[1]),
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        Ok(Self::LEN)
    }
}

/// `Mgmt_Permit_Joining_req`: open or close joining on a remote device
/// (§2.4.3.3.7, anchor p0146-L3555-L3556).
///
/// Requirement `05-3474-23-24337-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtPermitJoiningReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// Seconds joining stays open (`0x00` closes, `0xFF` opens
    /// indefinitely).
    pub duration: u8,
    /// Whether the change applies network-wide.
    pub tc_significance: bool,
}

impl MgmtPermitJoiningReq {
    /// Wire length.
    pub const LEN: usize = 3;

    /// Decode a permit-joining request frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            duration: buf[1],
            tc_significance: buf[2] != 0,
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.duration;
        out[2] = u8::from(self.tc_significance);
        Ok(Self::LEN)
    }
}

/// `Mgmt_Permit_Joining_rsp`: sequence echo plus outcome only.
///
/// Requirement `05-3474-23-24337-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtPermitJoiningRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the request.
    pub status: ZdpStatus,
}

impl MgmtPermitJoiningRsp {
    /// Wire length.
    pub const LEN: usize = 2;

    /// Decode a permit-joining response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            status: ZdpStatus::from_code(buf[1]),
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        Ok(Self::LEN)
    }
}

/// `Mgmt_NWK_Update_req`: ask a device to scan channels or change
/// network-update parameters (§2.4.3.3.9, Table 2-64, anchor
/// p0149-L3626).
///
/// Requirement `05-3474-23-24339-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtNwkUpdateReq {
    /// Transaction sequence, echoed in the notify.
    pub tsn: u8,
    /// Channel bitmask to scan.
    pub scan_channels: u32,
    /// Scan duration exponent per channel.
    pub scan_duration: u8,
    /// How many scans to run.
    pub scan_count: u8,
}

impl MgmtNwkUpdateReq {
    /// Wire length.
    pub const LEN: usize = 7;

    /// Decode an update request frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            scan_channels: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
            scan_duration: buf[5],
            scan_count: buf[6],
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        let mask = self.scan_channels.to_le_bytes();
        out[1..5].copy_from_slice(&mask);
        out[5] = self.scan_duration;
        out[6] = self.scan_count;
        Ok(Self::LEN)
    }
}

/// Bound on energy samples in one update report: one per 2.4 GHz
/// channel (11–26).
///
/// Requirement `05-3474-23-24339-02` (MINTED-pending-confirm).
pub const MAX_ENERGY_VALUES: usize = 27;

/// `Mgmt_NWK_Update_notify` (and the update response, same shape):
/// scan outcome naming scanned channels, transmission counts, and one
/// energy sample per scanned channel (§2.4.3.3.9.3, anchors
/// p0151-L3696-L3709).
///
/// Requirement `05-3474-23-24339-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtNwkUpdateNotify {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the scan.
    pub status: ZdpStatus,
    /// Channels that were scanned.
    pub scanned_channels: u32,
    /// Transmissions attempted during the scan.
    pub total_transmissions: u16,
    /// Transmissions that failed during the scan.
    pub failed_transmissions: u16,
    /// Energy per scanned channel, first `energy_len` entries valid.
    /// `energy_len` must equal the popcount of `scanned_channels`.
    pub energy: [u8; MAX_ENERGY_VALUES],
    /// How many energy samples are present.
    pub energy_len: u8,
}

impl MgmtNwkUpdateNotify {
    /// Shortest wire length (no scanned channels).
    pub const MIN_LEN: usize = 10;

    /// Decode a notify/response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let scanned = u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]);
        let expect = scanned.count_ones() as usize;
        if expect > MAX_ENERGY_VALUES {
            return Err(Error::TooManyEntries);
        }
        if buf.len() < Self::MIN_LEN + expect {
            return Err(Error::Truncated);
        }
        let mut notify = Self {
            tsn: buf[0],
            status: ZdpStatus::from_code(buf[1]),
            scanned_channels: scanned,
            total_transmissions: u16::from_le_bytes([buf[6], buf[7]]),
            failed_transmissions: u16::from_le_bytes([buf[8], buf[9]]),
            energy: [0; MAX_ENERGY_VALUES],
            energy_len: expect as u8,
        };
        notify.energy[..expect].copy_from_slice(&buf[10..10 + expect]);
        Ok(notify)
    }

    /// Encoded length of this value.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        Self::MIN_LEN + self.energy_len as usize
    }

    /// Encode into `out`; the energy count must match the scanned
    /// channel popcount.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let expect = self.scanned_channels.count_ones() as usize;
        if self.energy_len as usize != expect || expect > MAX_ENERGY_VALUES {
            return Err(Error::TooManyEntries);
        }
        let n = self.encoded_len();
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        let mask = self.scanned_channels.to_le_bytes();
        out[2..6].copy_from_slice(&mask);
        let total = self.total_transmissions.to_le_bytes();
        out[6] = total[0];
        out[7] = total[1];
        let failed = self.failed_transmissions.to_le_bytes();
        out[8] = failed[0];
        out[9] = failed[1];
        out[10..10 + expect].copy_from_slice(&self.energy[..expect]);
        Ok(n)
    }
}
