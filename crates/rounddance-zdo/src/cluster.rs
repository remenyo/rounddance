//! ZDP cluster identifiers and request/response pairing.
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2 §2.4.3.1 Table 2-43
//! (discovery client commands, anchor p0126-L3091-L3094), §2.4.3.2
//! (binding commands: `Bind_req` §2.4.3.2.2 anchor p0138-L3388,
//! `Unbind_req` §2.4.3.2.3 Table 2-56 anchor p0140-L3408-L3409),
//! §2.4.3.3 (management commands: `Mgmt_Leave_req` 0x0034
//! §2.4.3.3.5 anchor p0145-L3530-L3531, `Mgmt_Permit_Joining_req` 0x0036
//! §2.4.3.3.7 anchor p0146-L3555-L3556, `Mgmt_NWK_Update_req` 0x0038
//! §2.4.3.3.9 anchor p0148-L3620-L3625), and §2.4.4.2 (server responses,
//! e.g. `NWK_addr_rsp` 0x8000 anchor p0174-L4273-L4274).
//! All wording here is paraphrase (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped), MINTED-pending-confirm.

/// ZDP request cluster: network address lookup by long address
/// (Table 2-43).
///
/// Requirement `05-3474-23-24311-01`.
pub const CLUSTER_NWK_ADDR_REQ: u16 = 0x0000;
/// ZDP request cluster: long address lookup by network address
/// (Table 2-43).
///
/// Requirement `05-3474-23-24311-01`.
pub const CLUSTER_IEEE_ADDR_REQ: u16 = 0x0001;
/// ZDP request cluster: node descriptor inquiry (Table 2-43; the
/// mandatory discovery command, also the fragmentation-capability probe
/// of `05-3474-23-22411-14`).
///
/// Requirement `05-3474-23-24311-01`.
pub const CLUSTER_NODE_DESC_REQ: u16 = 0x0002;
/// ZDP request cluster: power descriptor inquiry (Table 2-43).
///
/// Requirement `05-3474-23-24311-01`.
pub const CLUSTER_POWER_DESC_REQ: u16 = 0x0003;
/// ZDP request cluster: simple descriptor inquiry (Table 2-43).
///
/// Requirement `05-3474-23-24311-01`.
pub const CLUSTER_SIMPLE_DESC_REQ: u16 = 0x0004;
/// ZDP request cluster: active endpoint list inquiry (Table 2-43).
///
/// Requirement `05-3474-23-24311-01`.
pub const CLUSTER_ACTIVE_EP_REQ: u16 = 0x0005;
/// ZDP request cluster: profile/cluster match inquiry (Table 2-43).
///
/// Requirement `05-3474-23-24311-01`.
pub const CLUSTER_MATCH_DESC_REQ: u16 = 0x0006;
/// ZDP announce cluster: device announcement, no response
/// (§2.4.3.1.11, anchor p0134-L3263-L3267).
///
/// Requirement `05-3474-23-24311-11` (MINTED-pending-confirm).
pub const CLUSTER_DEVICE_ANNCE: u16 = 0x0013;
/// ZDP request cluster: create a binding table entry
/// (§2.4.3.2.2, anchor p0138-L3388).
///
/// Requirement `05-3474-23-24322-01` (MINTED-pending-confirm).
pub const CLUSTER_BIND_REQ: u16 = 0x0021;
/// ZDP request cluster: remove a binding table entry
/// (§2.4.3.2.3, anchor p0140-L3408-L3409).
///
/// Requirement `05-3474-23-24323-01` (MINTED-pending-confirm).
pub const CLUSTER_UNBIND_REQ: u16 = 0x0022;
/// ZDP request cluster: neighbor-table (LQI) inquiry (§2.4.3.3.2,
/// by the cluster-numbering pattern of the sibling management
/// commands; no line anchor claimed).
///
/// Requirement `05-3474-23-24332-01` (MINTED-pending-confirm).
pub const CLUSTER_MGMT_LQI_REQ: u16 = 0x0031;
/// ZDP request cluster: ask a remote device to leave the network
/// (§2.4.3.3.5, anchor p0145-L3530-L3531).
///
/// Requirement `05-3474-23-24335-01` (MINTED-pending-confirm).
pub const CLUSTER_MGMT_LEAVE_REQ: u16 = 0x0034;
/// ZDP request cluster: control permit-joining on a remote device
/// (§2.4.3.3.7, anchor p0146-L3555-L3556).
///
/// Requirement `05-3474-23-24337-01` (MINTED-pending-confirm).
pub const CLUSTER_MGMT_PERMIT_JOINING_REQ: u16 = 0x0036;
/// ZDP request cluster: channel scan / network update management
/// (§2.4.3.3.9, anchor p0148-L3620-L3625).
///
/// Requirement `05-3474-23-24339-01` (MINTED-pending-confirm).
pub const CLUSTER_MGMT_NWK_UPDATE_REQ: u16 = 0x0038;

/// Response-cluster bit: server responses set the high bit of the
/// request cluster (attested `NWK_addr_rsp` 0x8000, anchor
/// p0174-L4273-L4274; `Node_Desc_rsp` §2.4.4.2.3, anchor p0178-L4303).
///
/// Requirement `05-3474-23-244-02` (MINTED-pending-confirm).
pub const RESPONSE_BIT: u16 = 0x8000;

/// Map a request cluster to its response cluster, or `None` for
/// commands that carry no response (`Device_annce`).
///
/// Requirement `05-3474-23-244-02` (MINTED-pending-confirm).
#[must_use]
pub const fn response_cluster(request: u16) -> Option<u16> {
    match request {
        CLUSTER_NWK_ADDR_REQ
        | CLUSTER_IEEE_ADDR_REQ
        | CLUSTER_NODE_DESC_REQ
        | CLUSTER_POWER_DESC_REQ
        | CLUSTER_SIMPLE_DESC_REQ
        | CLUSTER_ACTIVE_EP_REQ
        | CLUSTER_MATCH_DESC_REQ
        | CLUSTER_BIND_REQ
        | CLUSTER_UNBIND_REQ
        | CLUSTER_MGMT_LQI_REQ
        | CLUSTER_MGMT_LEAVE_REQ
        | CLUSTER_MGMT_PERMIT_JOINING_REQ
        | CLUSTER_MGMT_NWK_UPDATE_REQ => Some(request | RESPONSE_BIT),
        _ => None,
    }
}
