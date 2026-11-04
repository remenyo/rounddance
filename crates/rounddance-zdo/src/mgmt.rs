//! Network-manager basics: leave / permit-joining / channel-update
//! structures plus codecs, and the network-address conflict-resolution
//! core (detect → decide → report/act). Emitting the report broadcast
//! and owning address tables stay with later waves (see residue note
//! on [`decide_remote_conflict`]); the decision itself lives here.
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
use crate::zdp::{BindDstMode, DeviceAnnce};

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

/// `Mgmt_Direct_Join_req`: ask a router to admit one designated
/// device directly (§2.4.3.3.6, same leave-shape family as
/// [`MgmtLeaveReq`]; no line anchor claimed).
///
/// Requirement `05-3474-23-24336-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtDirectJoinReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// Long address of the device to admit.
    pub device_ieee: u64,
    /// MAC capability flags the device will join with.
    pub capability: u8,
}

impl MgmtDirectJoinReq {
    /// Wire length.
    pub const LEN: usize = 10;

    /// Decode a direct-join request frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            device_ieee: u64::from_le_bytes([
                buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
            ]),
            capability: buf[9],
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1..9].copy_from_slice(&self.device_ieee.to_le_bytes());
        out[9] = self.capability;
        Ok(Self::LEN)
    }
}

/// `Mgmt_Direct_Join_rsp`: sequence echo plus outcome only.
///
/// Requirement `05-3474-23-24336-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtDirectJoinRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the admission.
    pub status: ZdpStatus,
}

impl MgmtDirectJoinRsp {
    /// Wire length.
    pub const LEN: usize = 2;

    /// Decode a direct-join response frame.
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

/// Bound on cache entries carried in one `Mgmt_Cache_rsp`
/// (declared budget; longer over-air lists are rejected with
/// [`Error::TooManyEntries`]).
///
/// Requirement `05-3474-23-24338-02` (MINTED-pending-confirm).
pub const MAX_CACHE_ENTRIES: usize = 4;

/// `Mgmt_Cache_req`: ask for a page of the remote discovery-cache
/// table (§2.4.3.3.8, same paged shape as [`MgmtRtgReq`]; no line
/// anchor claimed).
///
/// Requirement `05-3474-23-24338-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtCacheReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// First cache-table entry to report.
    pub start_index: u8,
}

impl MgmtCacheReq {
    /// Wire length.
    pub const LEN: usize = 2;

    /// Decode a cache-table request frame.
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

/// One discovery-cache entry in a `Mgmt_Cache_rsp`: the cached
/// device's addresses (paraphrase of the cache-table record shape).
///
/// Requirement `05-3474-23-24338-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheEntry {
    /// Cached device's long address.
    pub ieee: u64,
    /// Cached device's network address.
    pub nwk: u16,
}

impl CacheEntry {
    /// Wire length of one entry.
    pub const LEN: usize = 10;

    /// Decode one entry.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            ieee: u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            nwk: u16::from_le_bytes([buf[8], buf[9]]),
        })
    }

    /// Encode one entry into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0..8].copy_from_slice(&self.ieee.to_le_bytes());
        out[8..10].copy_from_slice(&self.nwk.to_le_bytes());
        Ok(Self::LEN)
    }
}

/// `Mgmt_Cache_rsp`: answer to [`MgmtCacheReq`]: total table size,
/// page start, and the entry page itself (empty unless the outcome
/// is success).
///
/// Requirement `05-3474-23-24338-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtCacheRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the inquiry.
    pub status: ZdpStatus,
    /// Total cache-table entries on the responder.
    pub table_size: u8,
    /// Page start echoed from the request.
    pub start_index: u8,
    /// Page entries, first `entry_len` entries valid (present only on
    /// success).
    pub entries: [CacheEntry; MAX_CACHE_ENTRIES],
    /// How many page entries are present.
    pub entry_len: u8,
}

impl MgmtCacheRsp {
    /// Wire length without entries.
    pub const MIN_LEN: usize = 5;

    /// Decode a cache-table response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let status = ZdpStatus::from_code(buf[1]);
        let mut rsp = Self {
            tsn: buf[0],
            status,
            table_size: buf[2],
            start_index: buf[3],
            entries: [CacheEntry { ieee: 0, nwk: 0 }; MAX_CACHE_ENTRIES],
            entry_len: 0,
        };
        if !status.is_success() {
            return Ok(rsp);
        }
        let count = buf[4] as usize;
        if count > MAX_CACHE_ENTRIES {
            return Err(Error::TooManyEntries);
        }
        if buf.len() < Self::MIN_LEN + CacheEntry::LEN * count {
            return Err(Error::Truncated);
        }
        rsp.entry_len = count as u8;
        let mut i = 0;
        while i < count {
            let base = Self::MIN_LEN + CacheEntry::LEN * i;
            rsp.entries[i] = CacheEntry::decode(&buf[base..base + CacheEntry::LEN])?;
            i += 1;
        }
        Ok(rsp)
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let count = self.entry_len as usize;
        if count > MAX_CACHE_ENTRIES {
            return Err(Error::TooManyEntries);
        }
        let success = self.status.is_success();
        let n = Self::MIN_LEN + if success { CacheEntry::LEN * count } else { 0 };
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        out[2] = self.table_size;
        out[3] = self.start_index;
        out[4] = self.entry_len;
        if success {
            let mut i = 0;
            while i < count {
                let base = Self::MIN_LEN + CacheEntry::LEN * i;
                self.entries[i].encode_into(&mut out[base..base + CacheEntry::LEN])?;
                i += 1;
            }
        }
        Ok(n)
    }

    /// Page entries as a slice.
    #[must_use]
    pub fn entry_list(&self) -> &[CacheEntry] {
        &self.entries[..self.entry_len as usize]
    }
}

/// Bound on IEEE addresses in one `MgmtNwkIeeeJoiningListRsp`
/// (declared budget; longer over-air lists are rejected with
/// [`Error::TooManyEntries`]).
///
/// Requirement `05-3474-23-2433A-02` (MINTED-pending-confirm).
pub const MAX_JOINING_IEEE: usize = 8;

/// Joining policy for the allow-list (§2.4.4.3.11, Table 2-112).
///
/// Requirement `05-3474-23-2433A-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoiningPolicy {
    /// Any device may join.
    AllJoin,
    /// Only devices on the allow-list may join.
    IeelistJoin,
    /// No device may join.
    NoJoin,
}

impl JoiningPolicy {
    /// Decode one policy octet; anything else is rejected.
    pub fn decode(byte: u8) -> Result<Self, Error> {
        match byte {
            0x00 => Ok(Self::AllJoin),
            0x01 => Ok(Self::IeelistJoin),
            0x02 => Ok(Self::NoJoin),
            v => Err(Error::InvalidValue(v)),
        }
    }

    /// Encode one policy octet.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::AllJoin => 0x00,
            Self::IeelistJoin => 0x01,
            Self::NoJoin => 0x02,
        }
    }
}

/// `Mgmt_NWK_IEEE_Joining_List_req`: ask for the allow-list page at
/// `start_index` (§2.4.3.3.11, Figure 2-39 + Table 2-66: StartIndex
/// only; no line anchor claimed).
///
/// Requirement `05-3474-23-2433A-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtNwkIeeeJoiningListReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// First allow-list entry to report.
    pub start_index: u8,
}

impl MgmtNwkIeeeJoiningListReq {
    /// Wire length.
    pub const LEN: usize = 2;

    /// Decode a joining-list request frame.
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

/// `Mgmt_NWK_IEEE_Joining_List_rsp`: answer to
/// [`MgmtNwkIeeeJoiningListReq`] (§2.4.4.3.11, Table 2-111: Status,
/// list-update ID, policy, totals, and — unless the total is zero —
/// the page start, entry count, and long addresses; no line anchor
/// claimed).
///
/// Requirement `05-3474-23-2433A-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtNwkIeeeJoiningListRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the inquiry.
    pub status: ZdpStatus,
    /// Allow-list issue ID (wraps at 0xFF).
    pub update_id: u8,
    /// Current joining policy.
    pub policy: JoiningPolicy,
    /// Total allow-list entries on the responder.
    pub total: u8,
    /// Page start echoed from the request (present only when the
    /// total is nonzero).
    pub start_index: u8,
    /// Page entries, first `entry_len` entries valid (present only on
    /// success with a nonzero total).
    pub entries: [u64; MAX_JOINING_IEEE],
    /// How many page entries are present.
    pub entry_len: u8,
}

impl MgmtNwkIeeeJoiningListRsp {
    /// Wire length without the page (non-success, or empty list).
    pub const MIN_LEN: usize = 5;

    /// Decode a joining-list response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let status = ZdpStatus::from_code(buf[1]);
        let mut rsp = Self {
            tsn: buf[0],
            status,
            update_id: 0,
            policy: JoiningPolicy::AllJoin,
            total: 0,
            start_index: 0,
            entries: [0; MAX_JOINING_IEEE],
            entry_len: 0,
        };
        if !status.is_success() {
            return Ok(rsp);
        }
        if buf.len() < 5 {
            return Err(Error::Truncated);
        }
        rsp.update_id = buf[2];
        rsp.policy = JoiningPolicy::decode(buf[3])?;
        rsp.total = buf[4];
        if rsp.total == 0 {
            return Ok(rsp);
        }
        if buf.len() < 7 {
            return Err(Error::Truncated);
        }
        let start = buf[5] as usize;
        let count = buf[6] as usize;
        if count > MAX_JOINING_IEEE {
            return Err(Error::TooManyEntries);
        }
        if buf.len() < 7 + 8 * count {
            return Err(Error::Truncated);
        }
        rsp.start_index = start as u8;
        rsp.entry_len = count as u8;
        let mut i = 0;
        while i < count {
            let base = 7 + 8 * i;
            rsp.entries[i] = u64::from_le_bytes([
                buf[base],
                buf[base + 1],
                buf[base + 2],
                buf[base + 3],
                buf[base + 4],
                buf[base + 5],
                buf[base + 6],
                buf[base + 7],
            ]);
            i += 1;
        }
        Ok(rsp)
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let count = self.entry_len as usize;
        if count > MAX_JOINING_IEEE {
            return Err(Error::TooManyEntries);
        }
        if !self.status.is_success() {
            if out.len() < 2 {
                return Err(Error::BufferTooSmall);
            }
            out[0] = self.tsn;
            out[1] = self.status.code();
            return Ok(2);
        }
        if self.total == 0 {
            if out.len() < Self::MIN_LEN {
                return Err(Error::BufferTooSmall);
            }
            out[0] = self.tsn;
            out[1] = self.status.code();
            out[2] = self.update_id;
            out[3] = self.policy.code();
            out[4] = 0;
            return Ok(Self::MIN_LEN);
        }
        let n = 7 + 8 * count;
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        out[2] = self.update_id;
        out[3] = self.policy.code();
        out[4] = self.total;
        out[5] = self.start_index;
        out[6] = self.entry_len;
        let mut i = 0;
        while i < count {
            let base = 7 + 8 * i;
            out[base..base + 8].copy_from_slice(&self.entries[i].to_le_bytes());
            i += 1;
        }
        Ok(n)
    }

    /// Page entries as a slice.
    #[must_use]
    pub fn entry_list(&self) -> &[u64] {
        &self.entries[..self.entry_len as usize]
    }
}

/// Bound on channel pages in one [`ChannelList`] (declared
/// budget; scan requests with more pages are refused with
/// [`Error::TooManyEntries`]).
///
/// Requirement `05-3474-23-3210-01` (MINTED-pending-confirm).
pub const MAX_CHANNEL_PAGES: usize = 4;

/// One 2.4 GHz page mask as carried on air: the top 5 bits name the
/// page, the low 27 bits name the channels (Table 3-8 little-endian
/// packing; single-radio devices use page 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelPageMask(pub u32);

impl ChannelPageMask {
    /// Split into (page, 27-bit channel mask).
    #[must_use]
    pub const fn split(self) -> (u8, u32) {
        ((self.0 >> 27) as u8, self.0 & 0x07FF_FFFF)
    }

    /// Build from a page number and a 27-bit channel mask.
    #[must_use]
    pub const fn make(page: u8, mask: u32) -> Self {
        Self((((page & 0x1F) as u32) << 27) | (mask & 0x07FF_FFFF))
    }
}

/// Channel list: a counted set of page masks (§3.2.2.2.1, Tables 3-6
/// through 3-8: one count octet naming up to one instance per page,
/// then one little-endian 32-bit page mask each; no line anchor
/// claimed).
///
/// Requirement `05-3474-23-3210-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelList {
    /// Page masks, first `page_len` entries valid.
    pub pages: [ChannelPageMask; MAX_CHANNEL_PAGES],
    /// How many page masks are present.
    pub page_len: u8,
}

impl ChannelList {
    /// Wire length.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        1 + 4 * self.page_len as usize
    }

    /// Decode one channel list from the head of `buf`.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), Error> {
        if buf.is_empty() {
            return Err(Error::Truncated);
        }
        let count = buf[0] as usize;
        if count > MAX_CHANNEL_PAGES || buf.len() < 1 + 4 * count {
            return Err(if count > MAX_CHANNEL_PAGES {
                Error::TooManyEntries
            } else {
                Error::Truncated
            });
        }
        let mut list = Self {
            pages: [ChannelPageMask(0); MAX_CHANNEL_PAGES],
            page_len: count as u8,
        };
        let mut i = 0;
        while i < count {
            let base = 1 + 4 * i;
            list.pages[i] = ChannelPageMask(u32::from_le_bytes([
                buf[base],
                buf[base + 1],
                buf[base + 2],
                buf[base + 3],
            ]));
            i += 1;
        }
        Ok((list, 1 + 4 * count))
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let count = self.page_len as usize;
        if count > MAX_CHANNEL_PAGES {
            return Err(Error::TooManyEntries);
        }
        let n = 1 + 4 * count;
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.page_len;
        let mut i = 0;
        while i < count {
            let base = 1 + 4 * i;
            out[base..base + 4].copy_from_slice(&self.pages[i].0.to_le_bytes());
            i += 1;
        }
        Ok(n)
    }
}

/// Largest energy-sample list in one enhanced-update notify
/// (one sample per 2.4 GHz channel, as in [`MAX_ENERGY_VALUES`]).
///
/// Requirement `05-3474-23-24339-03` (MINTED-pending-confirm).
pub const MAX_ENHANCED_ENERGY: usize = 27;

/// `Mgmt_NWK_Enhanced_Update_req`: scan or retune across channel
/// pages (§2.4.3.3.10, Table 2-65: TSN + channel list + duration +
/// conditional scan-count / update-ID; no line anchor claimed).
///
/// Requirement `05-3474-23-243310-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtNwkEnhancedUpdateReq {
    /// Transaction sequence, echoed in the notify.
    pub tsn: u8,
    /// Pages + channels to act on.
    pub channels: ChannelList,
    /// Scan duration exponent (0x00–0x05), channel-change (0xfe),
    /// or attribute-change (0xff) request.
    pub scan_duration: u8,
    /// Energy scans to run and report (present only when the
    /// duration names a scan, 0x00–0x05).
    pub scan_count: Option<u8>,
    /// Manager-supplied update ID (present only for 0xfe/0xff).
    pub nwk_update_id: Option<u8>,
}

impl MgmtNwkEnhancedUpdateReq {
    /// Decode an enhanced-update request frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.is_empty() {
            return Err(Error::Truncated);
        }
        let (channels, used) = ChannelList::decode(&buf[1..]).map_err(|_| Error::Truncated)?;
        let mut at = 1 + used;
        if buf.len() < at + 1 {
            return Err(Error::Truncated);
        }
        let scan_duration = buf[at];
        at += 1;
        let (scan_count, nwk_update_id) = match scan_duration {
            0x00..=0x05 => {
                if buf.len() < at + 1 {
                    return Err(Error::Truncated);
                }
                (Some(buf[at]), None)
            }
            0xFE | 0xFF => {
                if buf.len() < at + 1 {
                    return Err(Error::Truncated);
                }
                (None, Some(buf[at]))
            }
            _ => (None, None),
        };
        Ok(Self {
            tsn: buf[0],
            channels,
            scan_duration,
            scan_count,
            nwk_update_id,
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut n = 1 + self.channels.encoded_len() + 1;
        n += match self.scan_duration {
            0x00..=0x05 | 0xFE | 0xFF => 1,
            _ => 0,
        };
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        let used = self.channels.encode_into(&mut out[1..])?;
        let mut at = 1 + used;
        out[at] = self.scan_duration;
        at += 1;
        match self.scan_duration {
            0x00..=0x05 => {
                out[at] = self.scan_count.unwrap_or(0);
                at += 1;
            }
            0xFE | 0xFF => {
                out[at] = self.nwk_update_id.unwrap_or(0);
                at += 1;
            }
            _ => {}
        }
        Ok(at)
    }
}

/// `Mgmt_NWK_Enhanced_Update_notify`: scan outcome naming scanned
/// channels, transmission counts, and per-channel energy (§2.4.4.3.10,
/// Table 2-110: Status, single-page ScannedChannels mask,
/// transmission counters, counted ED list; no line anchor claimed).
///
/// Requirement `05-3474-23-243310-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtNwkEnhancedUpdateNotify {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the scan.
    pub status: ZdpStatus,
    /// Scanned page + channel mask (single 32-bit page mask: top 5
    /// bits page, low 27 bits channels).
    pub scanned: ChannelPageMask,
    /// Transmissions attempted during the scan.
    pub total_transmissions: u16,
    /// Transmissions that failed during the scan.
    pub failed_transmissions: u16,
    /// Energy per scanned channel, first `energy_len` entries valid.
    pub energy: [u8; MAX_ENHANCED_ENERGY],
    /// How many energy samples are present.
    pub energy_len: u8,
}

impl MgmtNwkEnhancedUpdateNotify {
    /// Shortest wire length (no scanned channels).
    pub const MIN_LEN: usize = 11;

    /// Decode a notify frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let status = ZdpStatus::from_code(buf[1]);
        let energy_len = buf[10] as usize;
        if energy_len > MAX_ENHANCED_ENERGY || buf.len() < Self::MIN_LEN + energy_len {
            return Err(if energy_len > MAX_ENHANCED_ENERGY {
                Error::TooManyEntries
            } else {
                Error::Truncated
            });
        }
        let mut notify = Self {
            tsn: buf[0],
            status,
            scanned: ChannelPageMask(u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]])),
            total_transmissions: u16::from_le_bytes([buf[6], buf[7]]),
            failed_transmissions: u16::from_le_bytes([buf[8], buf[9]]),
            energy: [0; MAX_ENHANCED_ENERGY],
            energy_len: energy_len as u8,
        };
        notify.energy[..energy_len].copy_from_slice(&buf[11..11 + energy_len]);
        Ok(notify)
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let len = self.energy_len as usize;
        if len > MAX_ENHANCED_ENERGY {
            return Err(Error::TooManyEntries);
        }
        let n = Self::MIN_LEN + len;
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        out[2..6].copy_from_slice(&self.scanned.0.to_le_bytes());
        out[6..8].copy_from_slice(&self.total_transmissions.to_le_bytes());
        out[8..10].copy_from_slice(&self.failed_transmissions.to_le_bytes());
        out[10] = self.energy_len;
        out[11..11 + len].copy_from_slice(&self.energy[..len]);
        Ok(n)
    }
}

/// Tag of the single TLV a beacon-survey request carries: the
/// survey configuration (§2.4.3.3.12.1, TLV ID 0).
///
/// Requirement `05-3474-23-2433C-02` (MINTED-pending-confirm).
pub const BEACON_SURVEY_CONFIG_TAG: u8 = 0;

/// `Mgmt_NWK_Beacon_Survey_req`: ask for a beacon survey over the
/// listed pages (§2.4.3.3.12, Figures 2-40/2-41: TSN plus one
/// configuration TLV holding the channel list and a configuration
/// bitmask octet; the tag + length octets are the generic TLV
/// envelope as read from the figures; result/parents TLV legs of the
/// response stay a follow-up — ID and pairing cover them; no line
/// anchor claimed).
///
/// Requirement `05-3474-23-2433C-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtNwkBeaconSurveyReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// Pages + channels to survey.
    pub channels: ChannelList,
    /// Survey configuration bitmask (Table 2-68).
    pub config: u8,
}

impl MgmtNwkBeaconSurveyReq {
    /// Decode a beacon-survey request frame: TSN plus the bare
    /// configuration-TLV value (channel list, then the configuration
    /// octet). Later TLV kinds are a follow-up and refuse here rather
    /// than misparse.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 3 {
            return Err(Error::Truncated);
        }
        let (channels, used) = ChannelList::decode(&buf[1..]).map_err(|_| Error::Truncated)?;
        if buf.len() != 1 + used + 1 {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            channels,
            config: buf[1 + used],
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = 1 + self.channels.encoded_len() + 1;
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        let used = self.channels.encode_into(&mut out[1..])?;
        out[1 + used] = self.config;
        Ok(n)
    }
}

/// Bound on potential parents in one beacon-survey response
/// (at most 5 per §2.4.4.3.13.1.2; longer over-air lists are rejected
/// with [`Error::TooManyEntries`]).
///
/// Requirement `05-3474-23-2433C-02` (MINTED-pending-confirm).
pub const MAX_POTENTIAL_PARENTS: usize = 5;

/// Beacon-survey beacon counts (§2.4.4.3.13.1.1, Table 2-115: four
/// one-octet counters; no line anchor claimed).
///
/// Requirement `05-3474-23-2433C-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeaconSurveyResults {
    /// Total 802.15.4 beacons heard during the scan.
    pub total: u8,
    /// Beacons whose extended PAN matches the local network.
    pub on_network: u8,
    /// Matching beacons advertising end-device capacity.
    pub potential_parent: u8,
    /// Beacons from other networks.
    pub other: u8,
}

/// One potential parent: short address plus link quality.
///
/// Requirement `05-3474-23-2433C-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PotentialParent {
    /// Candidate parent short address (`0xFFFF` names the current
    /// parent slot of a router/coordinator with nothing better).
    pub short: u16,
    /// Link quality to that candidate.
    pub lqa: u8,
}

/// `Mgmt_NWK_Beacon_Survey_rsp`: answer to
/// [`MgmtNwkBeaconSurveyReq`] carrying the survey outcome (§2.4.4.3.13,
/// Table 2-114: Status plus — on success — the 4-octet results TLV
/// and the variable parents TLV (current parent + LQA + count +
/// short/LQA legs, Table 2-116); the TLVs ride bare in fixed order:
/// the "4 bytes" and "4 to 19 bytes" lengths given leave no room for
/// extra tag/length octets; no line anchor claimed).
///
/// Requirement `05-3474-23-2433C-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtNwkBeaconSurveyRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the survey.
    pub status: ZdpStatus,
    /// Beacon counters (present only on success).
    pub results: BeaconSurveyResults,
    /// Current parent short address (present only on success;
    /// `0xFFFF` when the responder has no parent).
    pub current_parent: u16,
    /// Link quality to the current parent (present only on success).
    pub current_lqa: u8,
    /// Candidate parents, first `parent_len` entries valid (present
    /// only on success).
    pub parents: [PotentialParent; MAX_POTENTIAL_PARENTS],
    /// How many candidate parents are present.
    pub parent_len: u8,
}

/// Empty potential parent for array initialization.
const EMPTY_PARENT: PotentialParent = PotentialParent { short: 0, lqa: 0 };

impl MgmtNwkBeaconSurveyRsp {
    /// Wire length without parent entries (TSN + status + 4-octet
    /// results + current parent + LQA + count).
    pub const MIN_LEN: usize = 10;

    /// Decode a beacon-survey response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 2 {
            return Err(Error::Truncated);
        }
        let status = ZdpStatus::from_code(buf[1]);
        let mut rsp = Self {
            tsn: buf[0],
            status,
            results: BeaconSurveyResults {
                total: 0,
                on_network: 0,
                potential_parent: 0,
                other: 0,
            },
            current_parent: 0xFFFF,
            current_lqa: 0,
            parents: [EMPTY_PARENT; MAX_POTENTIAL_PARENTS],
            parent_len: 0,
        };
        if !status.is_success() {
            return Ok(rsp);
        }
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        rsp.results = BeaconSurveyResults {
            total: buf[2],
            on_network: buf[3],
            potential_parent: buf[4],
            other: buf[5],
        };
        rsp.current_parent = u16::from_le_bytes([buf[6], buf[7]]);
        rsp.current_lqa = buf[8];
        let count = buf[9] as usize;
        if count > MAX_POTENTIAL_PARENTS {
            return Err(Error::TooManyEntries);
        }
        if buf.len() < Self::MIN_LEN + 3 * count {
            return Err(Error::Truncated);
        }
        rsp.parent_len = count as u8;
        let mut i = 0;
        while i < count {
            let base = Self::MIN_LEN + 3 * i;
            rsp.parents[i] = PotentialParent {
                short: u16::from_le_bytes([buf[base], buf[base + 1]]),
                lqa: buf[base + 2],
            };
            i += 1;
        }
        Ok(rsp)
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if !self.status.is_success() {
            if out.len() < 2 {
                return Err(Error::BufferTooSmall);
            }
            out[0] = self.tsn;
            out[1] = self.status.code();
            return Ok(2);
        }
        let count = self.parent_len as usize;
        if count > MAX_POTENTIAL_PARENTS {
            return Err(Error::TooManyEntries);
        }
        let n = Self::MIN_LEN + 3 * count;
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        out[2] = self.results.total;
        out[3] = self.results.on_network;
        out[4] = self.results.potential_parent;
        out[5] = self.results.other;
        out[6..8].copy_from_slice(&self.current_parent.to_le_bytes());
        out[8] = self.current_lqa;
        out[9] = self.parent_len;
        let mut i = 0;
        while i < count {
            let base = Self::MIN_LEN + 3 * i;
            out[base..base + 2].copy_from_slice(&self.parents[i].short.to_le_bytes());
            out[base + 2] = self.parents[i].lqa;
            i += 1;
        }
        Ok(n)
    }

    /// Candidate parents as a slice.
    #[must_use]
    pub fn parent_list(&self) -> &[PotentialParent] {
        &self.parents[..self.parent_len as usize]
    }
}

/// `Mgmt_NWK_Unsolicited_Enhanced_Update_notify`: a device
/// volunteers its local channel conditions (Table 2-113: in-use
/// channel mask plus MAC TX counters over a minute-window; no line
/// anchor claimed).
///
/// Requirement `05-3474-23-243311-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtNwkUnsolicitedEnhancedUpdateNotify {
    /// Transaction sequence (unsolicited: locally allocated).
    pub tsn: u8,
    /// Channel page + mask currently in use (top 5 bits page, low 27
    /// bits channels, as in [`ChannelPageMask`]).
    pub channel_in_use: ChannelPageMask,
    /// MAC unicast transactions attempted (retries not counted).
    pub tx_total: u16,
    /// Failed MAC unicast transactions.
    pub tx_failures: u16,
    /// MAC retries regardless of outcome.
    pub tx_retries: u16,
    /// Minutes the counters were measured over.
    pub period_minutes: u8,
}

impl MgmtNwkUnsolicitedEnhancedUpdateNotify {
    /// Wire length.
    pub const LEN: usize = 12;

    /// Decode an unsolicited enhanced-update notify frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            channel_in_use: ChannelPageMask(u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]])),
            tx_total: u16::from_le_bytes([buf[5], buf[6]]),
            tx_failures: u16::from_le_bytes([buf[7], buf[8]]),
            tx_retries: u16::from_le_bytes([buf[9], buf[10]]),
            period_minutes: buf[11],
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1..5].copy_from_slice(&self.channel_in_use.0.to_le_bytes());
        out[5..7].copy_from_slice(&self.tx_total.to_le_bytes());
        out[7..9].copy_from_slice(&self.tx_failures.to_le_bytes());
        out[9..11].copy_from_slice(&self.tx_retries.to_le_bytes());
        out[11] = self.period_minutes;
        Ok(Self::LEN)
    }
}

/// Local device role for conflict handling: only routers and the
/// coordinator decide, and only the coordinator keeps a disputed
/// address.
///
/// Requirement `05-3474-23-36110-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictRole {
    /// Never changes its address, still files the report.
    Coordinator,
    /// Gives up a disputed address for a fresh one.
    Router,
    /// Never self-resolves; the parent owns the fix.
    EndDevice,
}

/// What happens to the local address after a confirmed local
/// conflict.
///
/// Requirement `05-3474-23-36110-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictDecision {
    /// Keep using the address (coordinator).
    KeepAddress,
    /// Stop using the address; the caller acquires a fresh one via
    /// rejoin or a parent-assigned pick, then re-announces.
    AdoptNewAddress,
    /// Take no local action; the parent resolves it (end device).
    DeferToParent,
}

/// Decided fate plus the report duty: `report_addr` names the
/// offending address the caller owes a status broadcast for, or
/// `None` when no broadcast is owed.
///
/// Requirement `05-3474-23-36110-03` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConflictOutcome {
    /// Fate of the local address.
    pub decision: ConflictDecision,
    /// Address to name in the report broadcast, if any.
    pub report_addr: Option<u16>,
}

/// Whether one sighting claims the local network address for a
/// different long address: same network address plus a mismatched
/// long address is a local conflict; the local re-announce (same
/// long address) and any other network address are not.
///
/// Paraphrase of the receipt rule (§3.6.1.10.2, anchor
/// p0363-L8275-L8278).
///
/// Requirement `05-3474-23-36110-01` (MINTED-pending-confirm).
#[must_use]
pub const fn detect_local_conflict(
    own_nwk: u16,
    own_ieee: u64,
    seen_nwk: u16,
    seen_ieee: u64,
) -> bool {
    own_nwk == seen_nwk && own_ieee != seen_ieee
}

/// Table-scope scan: index of the first neighbor-table row binding
/// `addr_nwk` to a long address other than `addr_ieee` — a second
/// claimant of the watched address — or `None` when every row
/// agrees. Lets callers check the local address and any announced
/// address against one neighbor page with the same pass.
///
/// Paraphrase of the table-consistency check (§2.4.3.1.11.2, anchor
/// p0135-L3279-L3281: match on long address plus a different node
/// identifier names the conflict).
///
/// Requirement `05-3474-23-36110-01` (MINTED-pending-confirm).
#[must_use]
pub fn first_table_conflict(
    entries: &[NeighborEntry],
    addr_nwk: u16,
    addr_ieee: u64,
) -> Option<usize> {
    entries
        .iter()
        .position(|e| e.nwk == addr_nwk && e.ieee != addr_ieee)
}

/// Decide a confirmed local conflict: the coordinator keeps its
/// address, a router adopts a new one, an end device defers to its
/// parent (paraphrase of §3.6.1.10.5: coordinator never changes,
/// end devices never resolve, changer re-announces; anchors
/// p0365-L8356-L8358). A conflict learned inside a status report
/// owes no fresh report broadcast; any other sighting reports the
/// previous address (anchors p0364-L8349-L8352).
///
/// Requirement `05-3474-23-36110-02` (MINTED-pending-confirm).
#[must_use]
pub const fn decide_local_conflict(
    role: ConflictRole,
    own_nwk: u16,
    via_status_report: bool,
) -> ConflictOutcome {
    let report_addr = if via_status_report {
        None
    } else {
        Some(own_nwk)
    };
    match role {
        ConflictRole::Coordinator => ConflictOutcome {
            decision: ConflictDecision::KeepAddress,
            report_addr,
        },
        ConflictRole::Router => ConflictOutcome {
            decision: ConflictDecision::AdoptNewAddress,
            report_addr,
        },
        ConflictRole::EndDevice => ConflictOutcome {
            decision: ConflictDecision::DeferToParent,
            report_addr: None,
        },
    }
}

/// Report duty for a conflict on somebody else's address (e.g. a
/// table row disagreeing with an announcement about an address the
/// local device does not hold): routers and the coordinator name
/// the offending address for the status broadcast, unless the
/// conflict itself arrived inside a status report; end devices owe
/// nothing. Emitting that broadcast stays with the NWK/roles owner
/// (timed, jittered send); this names the payload address.
///
/// Paraphrase of §3.6.1.10.5 (anchors p0364-L8343-L8348).
///
/// Requirement `05-3474-23-36110-03` (MINTED-pending-confirm).
#[must_use]
pub const fn decide_remote_conflict(
    role: ConflictRole,
    offender: u16,
    via_status_report: bool,
) -> Option<u16> {
    match role {
        ConflictRole::Router | ConflictRole::Coordinator => {
            if via_status_report {
                None
            } else {
                Some(offender)
            }
        }
        ConflictRole::EndDevice => None,
    }
}

/// Act edge for [`ConflictDecision::AdoptNewAddress`]: the
/// re-announce a device broadcasts under its replacement address
/// (paraphrase of §3.6.1.10.5, anchor p0365-L8367-L8369). Consumes
/// [`DeviceAnnce`] (`05-3474-23-24311-11`).
///
/// Requirement `05-3474-23-36110-04` (MINTED-pending-confirm).
#[must_use]
pub const fn reannounce(tsn: u8, new_nwk: u16, ieee: u64, capability: u8) -> DeviceAnnce {
    DeviceAnnce {
        tsn,
        nwk_addr: new_nwk,
        ieee,
        capability,
    }
}

/// Bound on network descriptors carried in one `Mgmt_NWK_Disc_rsp`
/// (declared budget; longer over-air lists are rejected with
/// [`Error::TooManyEntries`]).
///
/// Requirement `05-3474-23-24330-02` (MINTED-pending-confirm).
pub const MAX_NETWORKS: usize = 4;

/// Bound on routing-table entries carried in one `Mgmt_Rtg_rsp`
/// (declared budget).
///
/// Requirement `05-3474-23-24332-04` (MINTED-pending-confirm).
pub const MAX_RTG_ENTRIES: usize = 8;

/// Bound on binding-table entries carried in one `Mgmt_Bind_rsp`
/// (declared budget).
///
/// Requirement `05-3474-23-24333-02` (MINTED-pending-confirm).
pub const MAX_MGMT_BIND_ENTRIES: usize = 4;

/// `Mgmt_NWK_Disc_req`: ask a device to report the networks it hears
/// (§2.4.3.3.1, same scan-parameter shape as [`MgmtNwkUpdateReq`]
/// plus the paged-table start index).
///
/// Requirement `05-3474-23-24330-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtNwkDiscReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// Channel bitmask to scan.
    pub scan_channels: u32,
    /// Scan duration exponent per channel.
    pub scan_duration: u8,
    /// First network-list entry to report.
    pub start_index: u8,
}

impl MgmtNwkDiscReq {
    /// Wire length.
    pub const LEN: usize = 7;

    /// Decode a discovery request frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Self {
            tsn: buf[0],
            scan_channels: u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
            scan_duration: buf[5],
            start_index: buf[6],
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
        out[6] = self.start_index;
        Ok(Self::LEN)
    }
}

/// One heard network in a `Mgmt_NWK_Disc_rsp`: addressing plus the
/// capability subset the join decision needs (paraphrase of the
/// network-descriptor record shape).
///
/// Requirement `05-3474-23-24330-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkEntry {
    /// Extended PAN identifier of the heard network.
    pub ext_pan: u64,
    /// 16-bit PAN identifier.
    pub pan: u16,
    /// Logical channel the network operates on.
    pub channel: u8,
    /// Stack profile the network runs.
    pub stack_profile: u8,
    /// Protocol version the network runs.
    pub version: u8,
    /// Whether the network currently permits joining.
    pub permit_joining: bool,
}

impl NetworkEntry {
    /// Wire length of one entry.
    pub const LEN: usize = 14;

    /// Decode one entry.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        if buf[12] > 1 {
            return Err(Error::InvalidValue(buf[12]));
        }
        Ok(Self {
            ext_pan: u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            pan: u16::from_le_bytes([buf[8], buf[9]]),
            channel: buf[10],
            stack_profile: buf[11],
            version: buf[12],
            permit_joining: buf[13] != 0,
        })
    }

    /// Encode one entry into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.version > 1 {
            return Err(Error::InvalidValue(self.version));
        }
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0..8].copy_from_slice(&self.ext_pan.to_le_bytes());
        out[8..10].copy_from_slice(&self.pan.to_le_bytes());
        out[10] = self.channel;
        out[11] = self.stack_profile;
        out[12] = self.version;
        out[13] = u8::from(self.permit_joining);
        Ok(Self::LEN)
    }
}

/// `Mgmt_NWK_Disc_rsp`: answer to [`MgmtNwkDiscReq`]: total network
/// count, page start, and the entry page itself (empty unless the
/// outcome is success).
///
/// Requirement `05-3474-23-24330-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtNwkDiscRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the inquiry.
    pub status: ZdpStatus,
    /// Total networks heard by the responder.
    pub network_count: u8,
    /// Page start echoed from the request.
    pub start_index: u8,
    /// Page entries, first `entry_len` entries valid (present only on
    /// success).
    pub entries: [NetworkEntry; MAX_NETWORKS],
    /// How many page entries are present.
    pub entry_len: u8,
}

impl MgmtNwkDiscRsp {
    /// Wire length without entries.
    pub const MIN_LEN: usize = 5;

    /// Decode a discovery response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let status = ZdpStatus::from_code(buf[1]);
        let mut rsp = Self {
            tsn: buf[0],
            status,
            network_count: buf[2],
            start_index: buf[3],
            entries: [NetworkEntry {
                ext_pan: 0,
                pan: 0,
                channel: 0,
                stack_profile: 0,
                version: 0,
                permit_joining: false,
            }; MAX_NETWORKS],
            entry_len: 0,
        };
        if !status.is_success() {
            return Ok(rsp);
        }
        let count = buf[4] as usize;
        if count > MAX_NETWORKS {
            return Err(Error::TooManyEntries);
        }
        if buf.len() < Self::MIN_LEN + NetworkEntry::LEN * count {
            return Err(Error::Truncated);
        }
        rsp.entry_len = count as u8;
        let mut i = 0;
        while i < count {
            let base = Self::MIN_LEN + NetworkEntry::LEN * i;
            rsp.entries[i] = NetworkEntry::decode(&buf[base..base + NetworkEntry::LEN])?;
            i += 1;
        }
        Ok(rsp)
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let count = self.entry_len as usize;
        if count > MAX_NETWORKS {
            return Err(Error::TooManyEntries);
        }
        let success = self.status.is_success();
        let n = Self::MIN_LEN
            + if success {
                NetworkEntry::LEN * count
            } else {
                0
            };
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        out[2] = self.network_count;
        out[3] = self.start_index;
        out[4] = self.entry_len;
        if success {
            let mut i = 0;
            while i < count {
                let base = Self::MIN_LEN + NetworkEntry::LEN * i;
                self.entries[i].encode_into(&mut out[base..base + NetworkEntry::LEN])?;
                i += 1;
            }
        }
        Ok(n)
    }

    /// Page entries as a slice.
    #[must_use]
    pub fn entry_list(&self) -> &[NetworkEntry] {
        &self.entries[..self.entry_len as usize]
    }
}

/// `Mgmt_Rtg_req`: ask for a page of the remote routing table
/// (§2.4.3.3.3, same paged shape as [`MgmtLqiReq`]).
///
/// Requirement `05-3474-23-24332-03` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtRtgReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// First routing-table entry to report.
    pub start_index: u8,
}

impl MgmtRtgReq {
    /// Wire length.
    pub const LEN: usize = 2;

    /// Decode a routing-table request frame.
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

/// One routing-table entry in a `Mgmt_Rtg_rsp`: where the route leads
/// and whether it is usable (paraphrase of the routing-table record
/// shape).
///
/// Requirement `05-3474-23-24332-04` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtgEntry {
    /// Destination network address.
    pub dest: u16,
    /// Route state: `0` active, `1` discovery in progress,
    /// `2` inactive.
    pub status: u8,
    /// Next hop toward the destination.
    pub next_hop: u16,
}

impl RtgEntry {
    /// Wire length of one entry.
    pub const LEN: usize = 5;

    /// Decode one entry.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        if buf[2] > 2 {
            return Err(Error::InvalidValue(buf[2]));
        }
        Ok(Self {
            dest: u16::from_le_bytes([buf[0], buf[1]]),
            status: buf[2],
            next_hop: u16::from_le_bytes([buf[3], buf[4]]),
        })
    }

    /// Encode one entry into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.status > 2 {
            return Err(Error::InvalidValue(self.status));
        }
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0..2].copy_from_slice(&self.dest.to_le_bytes());
        out[2] = self.status;
        out[3..5].copy_from_slice(&self.next_hop.to_le_bytes());
        Ok(Self::LEN)
    }
}

/// `Mgmt_Rtg_rsp`: answer to [`MgmtRtgReq`]: total table size, page
/// start, and the entry page itself (empty unless the outcome is
/// success).
///
/// Requirement `05-3474-23-24332-04` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtRtgRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the inquiry.
    pub status: ZdpStatus,
    /// Total routing-table entries on the responder.
    pub table_size: u8,
    /// Page start echoed from the request.
    pub start_index: u8,
    /// Page entries, first `entry_len` entries valid (present only on
    /// success).
    pub entries: [RtgEntry; MAX_RTG_ENTRIES],
    /// How many page entries are present.
    pub entry_len: u8,
}

impl MgmtRtgRsp {
    /// Wire length without entries.
    pub const MIN_LEN: usize = 5;

    /// Decode a routing-table response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let status = ZdpStatus::from_code(buf[1]);
        let mut rsp = Self {
            tsn: buf[0],
            status,
            table_size: buf[2],
            start_index: buf[3],
            entries: [RtgEntry {
                dest: 0,
                status: 0,
                next_hop: 0,
            }; MAX_RTG_ENTRIES],
            entry_len: 0,
        };
        if !status.is_success() {
            return Ok(rsp);
        }
        let count = buf[4] as usize;
        if count > MAX_RTG_ENTRIES {
            return Err(Error::TooManyEntries);
        }
        if buf.len() < Self::MIN_LEN + RtgEntry::LEN * count {
            return Err(Error::Truncated);
        }
        rsp.entry_len = count as u8;
        let mut i = 0;
        while i < count {
            let base = Self::MIN_LEN + RtgEntry::LEN * i;
            rsp.entries[i] = RtgEntry::decode(&buf[base..base + RtgEntry::LEN])?;
            i += 1;
        }
        Ok(rsp)
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let count = self.entry_len as usize;
        if count > MAX_RTG_ENTRIES {
            return Err(Error::TooManyEntries);
        }
        let success = self.status.is_success();
        let n = Self::MIN_LEN + if success { RtgEntry::LEN * count } else { 0 };
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        out[2] = self.table_size;
        out[3] = self.start_index;
        out[4] = self.entry_len;
        if success {
            let mut i = 0;
            while i < count {
                let base = Self::MIN_LEN + RtgEntry::LEN * i;
                self.entries[i].encode_into(&mut out[base..base + RtgEntry::LEN])?;
                i += 1;
            }
        }
        Ok(n)
    }

    /// Page entries as a slice.
    #[must_use]
    pub fn entry_list(&self) -> &[RtgEntry] {
        &self.entries[..self.entry_len as usize]
    }
}

/// `Mgmt_Bind_req`: ask for a page of the remote binding table
/// (§2.4.3.3.4, same paged shape as [`MgmtRtgReq`]).
///
/// Requirement `05-3474-23-24333-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtBindReq {
    /// Transaction sequence, echoed in the response.
    pub tsn: u8,
    /// First binding-table entry to report.
    pub start_index: u8,
}

impl MgmtBindReq {
    /// Wire length.
    pub const LEN: usize = 2;

    /// Decode a binding-table request frame.
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

/// One binding-table entry in a `Mgmt_Bind_rsp`: the bound source
/// plus [`BindDstMode`], without the `Bind_req` transaction octet
/// (the response carries one TSN for the whole page).
///
/// Requirement `05-3474-23-24333-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtBindEntry {
    /// Bound device's long address.
    pub src_ieee: u64,
    /// Bound local endpoint.
    pub src_endpoint: u8,
    /// Bound cluster.
    pub cluster_id: u16,
    /// Where matching frames go.
    pub dst: BindDstMode,
}

impl MgmtBindEntry {
    /// Shortest wire length (group flavour).
    pub const MIN_LEN: usize = 14;

    /// Decode one entry from the head of `buf`, returning the entry
    /// plus the octets consumed.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let dst = BindDstMode::decode(&buf[11..])?;
        let n = 11 + dst.encoded_len();
        if buf.len() < n {
            return Err(Error::Truncated);
        }
        Ok((
            Self {
                src_ieee: u64::from_le_bytes([
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                ]),
                src_endpoint: buf[8],
                cluster_id: u16::from_le_bytes([buf[9], buf[10]]),
                dst,
            },
            n,
        ))
    }

    /// Encode one entry into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = 11 + self.dst.encoded_len();
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        out[0..8].copy_from_slice(&self.src_ieee.to_le_bytes());
        out[8] = self.src_endpoint;
        out[9..11].copy_from_slice(&self.cluster_id.to_le_bytes());
        self.dst.encode_into(&mut out[11..])?;
        Ok(n)
    }
}

/// `Mgmt_Bind_rsp`: answer to [`MgmtBindReq`]: total table size, page
/// start, and the entry page itself (empty unless the outcome is
/// success). Entries are variable-length on the wire, so decode walks
/// a cursor and encode packs sequentially.
///
/// Requirement `05-3474-23-24333-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtBindRsp {
    /// Echoed transaction sequence.
    pub tsn: u8,
    /// Outcome of the inquiry.
    pub status: ZdpStatus,
    /// Total binding-table entries on the responder.
    pub table_size: u8,
    /// Page start echoed from the request.
    pub start_index: u8,
    /// Page entries, first `entry_len` entries valid (present only on
    /// success).
    pub entries: [MgmtBindEntry; MAX_MGMT_BIND_ENTRIES],
    /// How many page entries are present.
    pub entry_len: u8,
}

/// Default table entry (group flavour, zero addresses) for array
/// initialization.
const EMPTY_BIND_ENTRY: MgmtBindEntry = MgmtBindEntry {
    src_ieee: 0,
    src_endpoint: 0,
    cluster_id: 0,
    dst: BindDstMode::Group { group_addr: 0 },
};

impl MgmtBindRsp {
    /// Wire length without entries.
    pub const MIN_LEN: usize = 5;

    /// Decode a binding-table response frame.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let status = ZdpStatus::from_code(buf[1]);
        let mut rsp = Self {
            tsn: buf[0],
            status,
            table_size: buf[2],
            start_index: buf[3],
            entries: [EMPTY_BIND_ENTRY; MAX_MGMT_BIND_ENTRIES],
            entry_len: 0,
        };
        if !status.is_success() {
            return Ok(rsp);
        }
        let count = buf[4] as usize;
        if count > MAX_MGMT_BIND_ENTRIES {
            return Err(Error::TooManyEntries);
        }
        let mut at = Self::MIN_LEN;
        let mut i = 0;
        while i < count {
            let (entry, n) = MgmtBindEntry::decode(&buf[at..])?;
            rsp.entries[i] = entry;
            at += n;
            i += 1;
        }
        rsp.entry_len = count as u8;
        Ok(rsp)
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Error> {
        let count = self.entry_len as usize;
        if count > MAX_MGMT_BIND_ENTRIES {
            return Err(Error::TooManyEntries);
        }
        if out.len() < Self::MIN_LEN {
            return Err(Error::BufferTooSmall);
        }
        out[0] = self.tsn;
        out[1] = self.status.code();
        out[2] = self.table_size;
        out[3] = self.start_index;
        out[4] = self.entry_len;
        if !self.status.is_success() {
            return Ok(Self::MIN_LEN);
        }
        let mut at = Self::MIN_LEN;
        let mut i = 0;
        while i < count {
            at += self.entries[i].encode_into(&mut out[at..])?;
            i += 1;
        }
        Ok(at)
    }

    /// Page entries as a slice.
    #[must_use]
    pub fn entry_list(&self) -> &[MgmtBindEntry] {
        &self.entries[..self.entry_len as usize]
    }
}
