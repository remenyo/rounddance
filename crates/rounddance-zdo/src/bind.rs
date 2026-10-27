//! Bind/unbind manager wired to the APS tables (no duplication).
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2 §2.4.3.2.2
//! (`Bind_req` When Generated / Effect on Receipt, anchors
//! p0139-L3393 and p0139-L3399) and §2.4.3.2.3 (`Unbind_req`, anchors
//! p0140-L3405 and p0140-L3410-L3414), executed against the
//! `rounddance-aps` [`BindingTable`](rounddance_aps::BindingTable) and
//! [`GroupTable`](rounddance_aps::GroupTable): group mode (0x01) maps to
//! a group binding, extended mode (0x03) to a unicast binding. This
//! crate owns the ZDP validation and status mapping; storage stays in
//! the APS layer. All wording here is paraphrase (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped), MINTED-pending-confirm.

use crate::status::ZdpStatus;
use crate::zdp::{BindDstMode, BindEntry};
use rounddance_aps::{ApsStatus, BindingDst, GroupTable};
use rounddance_aps::{BindingEntry as ApsBindingEntry, BindingTable};

/// Bind/unbind front end over borrowed APS tables.
///
/// Requirement `05-3474-23-24322-02` (MINTED-pending-confirm).
pub struct BindManager<'a> {
    /// Binding table owned by the APS layer.
    pub binding: &'a mut BindingTable,
    /// Group table owned by the APS layer.
    pub group: &'a mut GroupTable,
}

impl<'a> BindManager<'a> {
    /// Wrap borrowed APS tables.
    #[must_use]
    pub const fn new(binding: &'a mut BindingTable, group: &'a mut GroupTable) -> Self {
        Self { binding, group }
    }

    /// Execute a `Bind_req`: validate the source endpoint and the
    /// destination mode, then store the entry. Destination endpoints
    /// follow the same 0x00/0xFF exclusion as the endpoint table; a
    /// full binding table reports no room; group bindings additionally
    /// join the destination endpoint to the group table.
    ///
    /// Requirement `05-3474-23-24322-02` (MINTED-pending-confirm).
    pub fn bind(&mut self, entry: &BindEntry, local_ieee: u64) -> ZdpStatus {
        if !endpoint_bindable(entry.src_endpoint) {
            return ZdpStatus::InvalidEp;
        }
        let dst = match entry.dst {
            BindDstMode::Group { group_addr } => BindingDst::Group { group_addr },
            BindDstMode::Extended {
                dst_ieee,
                dst_endpoint,
            } => {
                if !endpoint_bindable(dst_endpoint) {
                    return ZdpStatus::InvalidEp;
                }
                BindingDst::Unicast {
                    dst_ieee,
                    dst_endpoint,
                }
            }
        };
        let aps_entry = ApsBindingEntry {
            src_ieee: entry.src_ieee,
            src_endpoint: entry.src_endpoint,
            cluster_id: entry.cluster_id,
            dst,
        };
        match self.binding.bind(aps_entry) {
            ApsStatus::Success => {}
            ApsStatus::IllegalRequest => return ZdpStatus::InvRequestType,
            ApsStatus::TableFull => return ZdpStatus::NoTableSpace,
            _ => return ZdpStatus::NotSupported,
        }
        // Group bindings also associate the group with this device's
        // membership view so group delivery reaches the bound cluster.
        if let BindingDst::Group { group_addr } = dst {
            let member_ep = group_member_endpoint(entry.src_endpoint, local_ieee, entry.src_ieee);
            match self.group.add(group_addr, member_ep) {
                ApsStatus::Success | ApsStatus::InvalidParameter => {}
                ApsStatus::TableFull => return ZdpStatus::NoTableSpace,
                _ => return ZdpStatus::NotSupported,
            }
        }
        ZdpStatus::Success
    }

    /// Execute an `Unbind_req`: remove the entry; an absent entry
    /// reports not-found.
    ///
    /// Requirement `05-3474-23-24323-02` (MINTED-pending-confirm).
    pub fn unbind(&mut self, entry: &BindEntry) -> ZdpStatus {
        let dst = match entry.dst {
            BindDstMode::Group { group_addr } => BindingDst::Group { group_addr },
            BindDstMode::Extended {
                dst_ieee,
                dst_endpoint,
            } => BindingDst::Unicast {
                dst_ieee,
                dst_endpoint,
            },
        };
        let aps_entry = ApsBindingEntry {
            src_ieee: entry.src_ieee,
            src_endpoint: entry.src_endpoint,
            cluster_id: entry.cluster_id,
            dst,
        };
        match self.binding.unbind(&aps_entry) {
            ApsStatus::Success => ZdpStatus::Success,
            ApsStatus::InvalidBinding => ZdpStatus::DeviceNotFound,
            _ => ZdpStatus::NotSupported,
        }
    }
}

/// Endpoints usable in a binding: application endpoints only (the ZDO
/// endpoint and the broadcast endpoint never bind).
///
/// Requirement `05-3474-23-24322-02` (MINTED-pending-confirm).
#[must_use]
pub const fn endpoint_bindable(endpoint: u8) -> bool {
    endpoint != 0x00 && endpoint != 0xFF
}

/// Group-membership endpoint recorded for a group bind: the request's
/// source endpoint when the binding names this device, otherwise the
/// first application endpoint as the local membership anchor.
///
/// Requirement `05-3474-23-24322-02` (MINTED-pending-confirm).
#[must_use]
pub const fn group_member_endpoint(src_endpoint: u8, local_ieee: u64, src_ieee: u64) -> u8 {
    if src_ieee == local_ieee && endpoint_bindable(src_endpoint) {
        src_endpoint
    } else {
        0x01
    }
}
