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

/// Bound on neighbor entries carried in one `Mgmt_Lqi_rsp` (declared
/// budget; longer over-air lists are rejected with
/// [`Error::TooManyEntries`]).
///
/// Requirement `05-3474-23-24332-02` (MINTED-pending-confirm).
pub const MAX_NEIGHBORS: usize = 8;

/// `Mgmt_Lqi_req`: ask for a page of the remote neighbor table
/// (§2.4.3.3.2, by the cluster-numbering pattern of the sibling
/// management commands; no line anchor claimed).
///
/// Requirement `05-3474-23-24332-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtLqiReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// First neighbor-table entry to report.
    pub start_index: u8,
}

impl MgmtLqiReq {
    /// Wire length.
    pub const LEN: usize = 2;

    /// Decode a neighbor-table request frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            start_index: buf[1],
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.start_index;
        Ok(Self::LEN)
    }
}

/// One neighbor-table entry in a `Mgmt_Lqi_rsp`: who the neighbor is
/// and how well it hears (paraphrase of the neighbor-table record
/// shape; no line anchor claimed).
///
/// Requirement `05-3474-23-24332-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighborEntry {
    /// Extended PAN the neighbor belongs to.
    pub ext_pan: u64,
    /// Neighbor's long address.
    pub ieee: u64,
    /// Neighbor's network address.
    pub nwk: u16,
    /// Device kind: `0` coordinator, `1` router, `2` end device.
    pub device_type: u8,
    /// Whether the neighbor's receiver stays on when idle.
    pub rx_on_idle: bool,
    /// Relationship: `0` parent, `1` child, `2` sibling, `3` none,
    /// `4` previous child.
    pub relationship: u8,
    /// Neighbor's tree depth.
    pub depth: u8,
    /// Last measured link quality (0–255).
    pub lqi: u8,
}

impl NeighborEntry {
    /// Wire length of one entry.
    pub const LEN: usize = 21;

    /// Decode one entry.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        let device_type = buf[18] & 0x03;
        if buf[18] & 0xc0 != 0 {
            return Err(Error::InvalidValue(buf[18]));
        }
        let relationship = (buf[18] >> 3) & 0x07;
        if device_type > 2 || relationship > 4 {
            return Err(Error::InvalidValue(buf[18]));
        }
        Ok(Self {
            ext_pan: u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            ieee: u64::from_le_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]),
            nwk: u16::from_le_bytes([buf[16], buf[17]]),
            device_type,
            rx_on_idle: buf[18] & 0x04 != 0,
            relationship,
            depth: buf[19],
            lqi: buf[20],
        })
    }

    /// Encode one entry into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.device_type > 2 || self.relationship > 4 {
            return Err(Error::InvalidValue(0xff));
        }
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0..8].copy_from_slice(&self.ext_pan.to_le_bytes());
        out[8..16].copy_from_slice(&self.ieee.to_le_bytes());
        out[16..18].copy_from_slice(&self.nwk.to_le_bytes());
        out[18] = self.device_type | (u8::from(self.rx_on_idle) << 2) | (self.relationship << 3);
        out[19] = self.depth;
        out[20] = self.lqi;
        Ok(Self::LEN)
    }
}

/// `Mgmt_Lqi_rsp`: answer to [`MgmtLqiReq`]: total entry count, page
/// start, and the entry page itself (empty unless the outcome is
/// success).
///
/// Requirement `05-3474-23-24332-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtLqiRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the inquiry.
    pub status: ZdpStatus,
    /// Total neighbor-table entries on the responder.
    pub neighbor_count: u8,
    /// Page start echoed from the request.
    pub start_index: u8,
    /// Page entries, first `entry_len` entries valid (present only on
    /// success).
    pub entries: [NeighborEntry; MAX_NEIGHBORS],
    /// How many page entries are present.
    pub entry_len: u8,
}

impl MgmtLqiRsp {
    /// Wire length without entries.
    pub const MIN_LEN: usize = 5;

    /// Decode a neighbor-table response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let status = ZdpStatus::from_code(buf[1]);
        let mut rsp = Self {
            tsn: buf[0],
            status,
            neighbor_count: buf[2],
            start_index: buf[3],
            entries: [NeighborEntry {
                ext_pan: 0,
                ieee: 0,
                nwk: 0,
                device_type: 0,
                rx_on_idle: false,
                relationship: 0,
                depth: 0,
                lqi: 0,
            }; MAX_NEIGHBORS],
            entry_len: 0,
        };
        if !status.is_success() {
            return Ok(rsp);
        }
        let count = buf[4] as usize;
        if count > MAX_NEIGHBORS {
            return Err(Error::TooManyEntries);
        }
        if buf.len() < Self::MIN_LEN + NeighborEntry::LEN * count {
            return Err(Error::Truncated);
        }
        rsp.entry_len = count as u8;
        let mut i = 0;
        while i < count {
            let base = Self::MIN_LEN + NeighborEntry::LEN * i;
            rsp.entries[i] = NeighborEntry::decode(&buf[base..base + NeighborEntry::LEN])?;
            i += 1;
        }
        Ok(rsp)
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let count = self.entry_len as usize;
        if count > MAX_NEIGHBORS {
            return Err(Error::TooManyEntries);
        }
        let success = self.status.is_success();
        let n = Self::MIN_LEN
            + if success {
                NeighborEntry::LEN * count
            } else {
                0
            };
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        out[2] = self.neighbor_count;
        out[3] = self.start_index;
        out[4] = self.entry_len;
        if success {
            let mut i = 0;
            while i < count {
                let base = Self::MIN_LEN + NeighborEntry::LEN * i;
                self.entries[i].encode_into(&mut out[base..base + NeighborEntry::LEN])?;
                i += 1;
            }
        }
        Ok(n)
    }

    /// Page entries as a slice.
    #[must_use]
    pub fn entry_list(&self) -> &[NeighborEntry] {
        &self.entries[..self.entry_len as usize]
    }
}

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
