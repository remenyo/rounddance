//! Local endpoint table and match-descriptor evaluation.
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2 §2.3.2.5 (endpoint
//! descriptions live in simple descriptors, Table 2-40, anchor
//! p0119-L2842) and §2.4.3.1.7 (match inquiry, Table 2-50, anchor
//! p0132-L3233-L3238). All wording here is paraphrase (D1, `SCOPE.md`
//! §2).
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped), MINTED-pending-confirm.

use crate::desc::{Error, SimpleDescriptor};
use crate::status::ZdpStatus;

/// Bound on locally hosted endpoints (declared budget).
///
/// Requirement `05-3474-23-2325-02` (MINTED-pending-confirm).
pub const MAX_LOCAL_ENDPOINTS: usize = 16;

/// Local endpoint table: the simple descriptors this device answers
/// inquiry commands from. Insertions validate the endpoint range and
/// refuse duplicates; a full table reports no room.
///
/// Requirement `05-3474-23-2325-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug)]
pub struct EndpointTable {
    entries: [Option<SimpleDescriptor>; MAX_LOCAL_ENDPOINTS],
    len: usize,
}

impl Default for EndpointTable {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointTable {
    /// Empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_LOCAL_ENDPOINTS],
            len: 0,
        }
    }

    /// Entries currently held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the table holds nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Look up one endpoint's descriptor.
    #[must_use]
    pub fn get(&self, endpoint: u8) -> Option<&SimpleDescriptor> {
        self.entries
            .iter()
            .flatten()
            .find(|desc| desc.endpoint == endpoint)
    }

    /// Register a descriptor: endpoint 0 and 0xFF are not application
    /// endpoints (`rounddance-aps` `ENDPOINT_ZDO` /
    /// `ENDPOINT_BROADCAST_ALL`); a duplicate endpoint replaces the
    /// stored descriptor; a full table reports `NoTableSpace`.
    pub fn insert(&mut self, desc: SimpleDescriptor) -> ZdpStatus {
        if desc.endpoint == 0x00 || desc.endpoint == 0xFF {
            return ZdpStatus::InvalidEp;
        }
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|e| matches!(e, Some(d) if d.endpoint == desc.endpoint))
        {
            *slot = Some(desc);
            return ZdpStatus::Success;
        }
        if self.len >= MAX_LOCAL_ENDPOINTS {
            return ZdpStatus::NoTableSpace;
        }
        match self.entries.iter_mut().find(|e| e.is_none()) {
            Some(slot) => {
                *slot = Some(desc);
                self.len += 1;
                ZdpStatus::Success
            }
            None => ZdpStatus::NoTableSpace,
        }
    }

    /// Remove one endpoint's descriptor; `true` when something was
    /// removed.
    pub fn remove(&mut self, endpoint: u8) -> bool {
        match self
            .entries
            .iter_mut()
            .find(|e| matches!(e, Some(d) if d.endpoint == endpoint))
        {
            Some(slot) => {
                *slot = None;
                self.len -= 1;
                true
            }
            None => false,
        }
    }

    /// Collect hosted endpoints into `out`; returns the number written
    /// (answers `Active_EP_req` with locally owned values only).
    ///
    /// Requirement `05-3474-23-24426-02` (MINTED-pending-confirm).
    pub fn active_endpoints(&self, out: &mut [u8; crate::zdp::MAX_EP_LIST]) -> usize {
        let mut n = 0;
        for desc in self.entries.iter().flatten() {
            if n >= out.len() {
                break;
            }
            out[n] = desc.endpoint;
            n += 1;
        }
        n
    }

    /// Evaluate a match inquiry against every hosted endpoint: an
    /// endpoint matches when the profile agrees and at least one
    /// complementary cluster pair lines up (a requested input cluster
    /// the endpoint outputs, or a requested output cluster the endpoint
    /// inputs); with both request lists empty the profile alone
    /// decides. Matching endpoints are collected into `out`, up to its
    /// length; returns the number written.
    ///
    /// Requirement `05-3474-23-24311-07` (MINTED-pending-confirm).
    pub fn match_desc(
        &self,
        profile_id: u16,
        in_clusters: &[u16],
        out_clusters: &[u16],
        out: &mut [u8; crate::zdp::MAX_EP_LIST],
    ) -> usize {
        let mut n = 0;
        for desc in self.entries.iter().flatten() {
            if desc.profile_id != profile_id {
                continue;
            }
            if !Self::clusters_match(desc, in_clusters, out_clusters) {
                continue;
            }
            if n >= out.len() {
                break;
            }
            out[n] = desc.endpoint;
            n += 1;
        }
        n
    }

    /// Complementary-cluster check for one hosted descriptor.
    fn clusters_match(desc: &SimpleDescriptor, in_clusters: &[u16], out_clusters: &[u16]) -> bool {
        if in_clusters.is_empty() && out_clusters.is_empty() {
            return true;
        }
        let local_in = desc.in_list();
        let local_out = desc.out_list();
        in_clusters.iter().any(|c| local_out.contains(c))
            || out_clusters.iter().any(|c| local_in.contains(c))
    }
}

/// Malformed-request guard for [`EndpointTable::insert`]: descriptors
/// naming more clusters than the declared budget are rejected instead
/// of truncated.
///
/// Requirement `05-3474-23-2325-01` (MINTED-pending-confirm).
#[must_use]
pub const fn simple_desc_fits(desc: &SimpleDescriptor) -> bool {
    desc.in_len as usize <= crate::desc::MAX_SIMPLE_CLUSTERS
        && desc.out_len as usize <= crate::desc::MAX_SIMPLE_CLUSTERS
}

/// Validate a `Simple_Desc_req` endpoint before answering: the ZDO
/// endpoint answers nothing and the broadcast endpoint is not a real
/// local endpoint.
///
/// Requirement `05-3474-23-24425-02` (MINTED-pending-confirm).
pub const fn endpoint_answerable(endpoint: u8) -> Result<(), Error> {
    if endpoint == 0x00 || endpoint == 0xFF {
        return Err(Error::InvalidValue(endpoint));
    }
    Ok(())
}
