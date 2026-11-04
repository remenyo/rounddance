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
/// ZDP request cluster: complex descriptor inquiry (§2.4.3.1.8;
/// DEPRECATED in R23.2 — heading-only entry at the R23.2 cluster
/// number, codec retained for 3.0-compat decode; no line anchor
/// claimed).
///
/// Requirement `05-3474-23-24317-01` (MINTED-pending-confirm).
pub const CLUSTER_COMPLEX_DESC_REQ: u16 = 0x0010;
/// ZDP request cluster: user descriptor inquiry (§2.4.3.1.9;
/// DEPRECATED in R23.2 — heading-only entry at the R23.2 cluster
/// number, codec retained for 3.0-compat decode; no line anchor
/// claimed).
///
/// Requirement `05-3474-23-24318-01` (MINTED-pending-confirm).
pub const CLUSTER_USER_DESC_REQ: u16 = 0x0011;
/// ZDP request cluster: discovery-cache inquiry (§2.4.3.1.10,
/// Table 2-43; DEPRECATED in R23.2 — heading-only entry, retained
/// here for 3.0-compat recognition; no line anchor claimed).
///
/// Requirement `05-3474-23-24319-01` (MINTED-pending-confirm).
pub const CLUSTER_DISCOVERY_CACHE_REQ: u16 = 0x0012;
/// ZDP request cluster: user-descriptor set (§2.4.3.1.13, Table 2-43;
/// DEPRECATED in R23.2 — heading-only entry, retained here for
/// 3.0-compat recognition; no line anchor claimed).
///
/// Requirement `05-3474-23-2431B-01` (MINTED-pending-confirm).
pub const CLUSTER_USER_DESC_SET_REQ: u16 = 0x0014;
/// ZDP request cluster: system-server discovery (§2.4.3.1.14,
/// Table 2-43; answered by `System_Server_Discovery_rsp` 0x8015,
/// §2.4.4.2.10; no line anchor claimed).
///
/// Requirement `05-3474-23-24315-01` (MINTED-pending-confirm).
pub const CLUSTER_SYSTEM_SERVER_DISCOVERY_REQ: u16 = 0x0015;
/// ZDP request cluster: discovery-store inquiry (Table 2-43;
/// DEPRECATED in R23.2 — heading-only entry, ID and response pairing
/// retained for 3.0-compat recognition; no line anchor claimed).
///
/// Requirement `05-3474-23-2431C-01` (MINTED-pending-confirm).
pub const CLUSTER_DISCOVERY_STORE_REQ: u16 = 0x0016;
/// ZDP request cluster: node-descriptor-store inquiry (Table 2-43;
/// DEPRECATED in R23.2 — heading-only entry, ID and response pairing
/// retained for 3.0-compat recognition; no line anchor claimed).
///
/// Requirement `05-3474-23-2431D-01` (MINTED-pending-confirm).
pub const CLUSTER_NODE_DESC_STORE_REQ: u16 = 0x0017;
/// ZDP announce cluster: parent names the children that joined under
/// it (§2.4.3.1.12; answered by `Parent_annce_rsp` on cluster
/// `0x801F`, §2.4.4.2.22; no line anchor claimed).
///
/// Requirement `05-3474-23-24316-01` (MINTED-pending-confirm).
pub const CLUSTER_PARENT_ANNCE: u16 = 0x001F;
/// ZDP request cluster: stash one source binding in the backup
/// store (§2.4.3.2.10, Table 2-54; DEPRECATED in R23.2 — heading-only
/// entry, ID and response pairing retained for 3.0-compat
/// recognition; no line anchor claimed).
///
/// Requirement `05-3474-23-2432A-01` (MINTED-pending-confirm).
pub const CLUSTER_BACKUP_SOURCE_BIND_REQ: u16 = 0x0029;
/// ZDP request cluster: restore one source binding from the backup
/// store (§2.4.3.2.11, Table 2-54; DEPRECATED in R23.2 — heading-only
/// entry, ID and response pairing retained for 3.0-compat
/// recognition; no line anchor claimed).
///
/// Requirement `05-3474-23-2432B-01` (MINTED-pending-confirm).
pub const CLUSTER_RECOVER_SOURCE_BIND_REQ: u16 = 0x002A;
/// ZDP request cluster: clear the remote binding table, optionally
/// scoped to listed devices (§2.4.3.2.12, Figures 2-30/2-31 +
/// Table 2-57/2-99; the request carries exactly one EUI64-list TLV).
///
/// Requirement `05-3474-23-2432C-01` (MINTED-pending-confirm).
pub const CLUSTER_CLEAR_ALL_BINDINGS_REQ: u16 = 0x002B;
/// ZDP request cluster: end-device bind pairing inquiry (§2.4.3.2.1;
/// DEPRECATED in R23.2 — heading-only entry, codec retained for
/// 3.0-compat decode; no line anchor claimed).
///
/// Requirement `05-3474-23-24320-01` (MINTED-pending-confirm).
pub const CLUSTER_END_DEVICE_BIND_REQ: u16 = 0x0020;
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
/// ZDP request cluster: register one device's binding table with the
/// trust center (§2.4.3.2.4, by the cluster-numbering pattern of the
/// sibling binding commands; no line anchor claimed).
///
/// Requirement `05-3474-23-24324-01` (MINTED-pending-confirm).
/// DEPRECATED in R23.2 (§2.4.3.2.4 heading-only); the ID and the
/// response pairing are retained for 3.0-compat recognition.
pub const CLUSTER_BIND_REGISTER_REQ: u16 = 0x0023;
/// ZDP request cluster: swap one bound device for another
/// (§2.4.3.2.5, by the cluster-numbering pattern of the sibling
/// binding commands; no line anchor claimed).
///
/// Requirement `05-3474-23-24325-01` (MINTED-pending-confirm).
/// DEPRECATED in R23.2 (§2.4.3.2.5 heading-only); the ID and the
/// response pairing are retained for 3.0-compat recognition.
pub const CLUSTER_REPLACE_DEVICE_REQ: u16 = 0x0024;
/// ZDP request cluster: stash one binding entry in the backup store
/// (§2.4.3.2.6, by the cluster-numbering pattern of the sibling
/// binding commands; no line anchor claimed).
///
/// Requirement `05-3474-23-24326-01` (MINTED-pending-confirm).
/// DEPRECATED in R23.2 (§2.4.3.2.6 heading-only); the ID and the
/// response pairing are retained for 3.0-compat recognition.
pub const CLUSTER_STORE_BAK_BIND_ENTRY_REQ: u16 = 0x0025;
/// ZDP request cluster: drop one binding entry from the backup store
/// (§2.4.3.2.7, by the cluster-numbering pattern of the sibling
/// binding commands; no line anchor claimed).
///
/// Requirement `05-3474-23-24327-01` (MINTED-pending-confirm).
/// DEPRECATED in R23.2 (§2.4.3.2.7 heading-only); the ID and the
/// response pairing are retained for 3.0-compat recognition.
pub const CLUSTER_REMOVE_BAK_BIND_ENTRY_REQ: u16 = 0x0026;
/// ZDP request cluster: read back pages of the backup binding table
/// (§2.4.3.2.8, by the cluster-numbering pattern of the sibling
/// binding commands; no line anchor claimed).
///
/// Requirement `05-3474-23-24328-01` (MINTED-pending-confirm).
/// DEPRECATED in R23.2 (§2.4.3.2.8 heading-only); the ID and the
/// response pairing are retained for 3.0-compat recognition.
pub const CLUSTER_BACKUP_BIND_TABLE_REQ: u16 = 0x0027;
/// ZDP request cluster: restore backup binding-table pages onto a
/// device (§2.4.3.2.9, by the cluster-numbering pattern of the
/// sibling binding commands; no line anchor claimed).
///
/// Requirement `05-3474-23-24329-01` (MINTED-pending-confirm).
/// DEPRECATED in R23.2 (§2.4.3.2.9 heading-only); the ID and the
/// response pairing are retained for 3.0-compat recognition.
pub const CLUSTER_RECOVER_BIND_TABLE_REQ: u16 = 0x0028;
/// ZDP request cluster: discovery-cache inquiry (§2.4.3.3.8,
/// by the cluster-numbering pattern of the sibling management
/// commands; no line anchor claimed).
///
/// Requirement `05-3474-23-24338-01` (MINTED-pending-confirm).
pub const CLUSTER_MGMT_CACHE_REQ: u16 = 0x0037;
/// ZDP request cluster: direct-join a designated device
/// (§2.4.3.3.6; DEPRECATED in R23.2 — heading-only entry, codec
/// retained for 3.0-compat decode; no line anchor claimed).
///
/// Requirement `05-3474-23-24336-01` (MINTED-pending-confirm).
pub const CLUSTER_MGMT_DIRECT_JOIN_REQ: u16 = 0x0035;
/// ZDP request cluster: neighbor-table (LQI) inquiry (§2.4.3.3.2,
/// by the cluster-numbering pattern of the sibling management
/// commands; no line anchor claimed).
///
/// Requirement `05-3474-23-24332-01` (MINTED-pending-confirm).
pub const CLUSTER_MGMT_LQI_REQ: u16 = 0x0031;
/// ZDP request cluster: network discovery inquiry (§2.4.3.3.1;
/// DEPRECATED in R23.2 — heading-only entry, codec retained for
/// 3.0-compat decode).
///
/// Requirement `05-3474-23-24330-01` (MINTED-pending-confirm).
pub const CLUSTER_MGMT_NWK_DISC_REQ: u16 = 0x0030;
/// ZDP request cluster: routing-table inquiry (§2.4.3.3.3,
/// by the cluster-numbering pattern of the sibling management
/// commands; no line anchor claimed).
///
/// Requirement `05-3474-23-24332-03` (MINTED-pending-confirm).
pub const CLUSTER_MGMT_RTG_REQ: u16 = 0x0032;
/// ZDP request cluster: binding-table inquiry (§2.4.3.3.4,
/// by the cluster-numbering pattern of the sibling management
/// commands; no line anchor claimed).
///
/// Requirement `05-3474-23-24333-01` (MINTED-pending-confirm).
pub const CLUSTER_MGMT_BIND_REQ: u16 = 0x0033;
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
/// ZDP request cluster: multi-page channel scan / update management
/// (§2.4.3.3.10, Figure 2-38 + Table 2-65; the scan list uses the
/// §3.2.2.2.1 ChannelList structure — codec deferred as follow-up,
/// ID and response pairing retained here; no line anchor claimed).
///
/// Requirement `05-3474-23-243310-01` (MINTED-pending-confirm).
pub const CLUSTER_MGMT_NWK_ENHANCED_UPDATE_REQ: u16 = 0x0039;
/// ZDP request cluster: read the Citadel joining allow-list page
/// (§2.4.3.3.11, Figure 2-39 + Tables 2-66/2-111/2-112; no line anchor
/// claimed).
///
/// Requirement `05-3474-23-2433A-01` (MINTED-pending-confirm).
pub const CLUSTER_MGMT_NWK_IEEE_JOINING_LIST_REQ: u16 = 0x003A;
/// ZDP request cluster: beacon-survey inquiry (§2.4.3.3.13, Figures
/// 2-40/2-41 + Tables 2-67/2-114/2-115/2-116; the results ride TLVs —
/// codec deferred as follow-up, ID and response pairing retained
/// here; no line anchor claimed).
///
/// Requirement `05-3474-23-2433C-01` (MINTED-pending-confirm).
pub const CLUSTER_MGMT_NWK_BEACON_SURVEY_REQ: u16 = 0x003C;

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
        | CLUSTER_COMPLEX_DESC_REQ
        | CLUSTER_USER_DESC_REQ
        | CLUSTER_DISCOVERY_CACHE_REQ
        | CLUSTER_DISCOVERY_STORE_REQ
        | CLUSTER_NODE_DESC_STORE_REQ
        | CLUSTER_PARENT_ANNCE
        | CLUSTER_USER_DESC_SET_REQ
        | CLUSTER_SYSTEM_SERVER_DISCOVERY_REQ
        | CLUSTER_BIND_REQ
        | CLUSTER_UNBIND_REQ
        | CLUSTER_END_DEVICE_BIND_REQ
        | CLUSTER_BIND_REGISTER_REQ
        | CLUSTER_REPLACE_DEVICE_REQ
        | CLUSTER_STORE_BAK_BIND_ENTRY_REQ
        | CLUSTER_REMOVE_BAK_BIND_ENTRY_REQ
        | CLUSTER_BACKUP_BIND_TABLE_REQ
        | CLUSTER_RECOVER_BIND_TABLE_REQ
        | CLUSTER_BACKUP_SOURCE_BIND_REQ
        | CLUSTER_RECOVER_SOURCE_BIND_REQ
        | CLUSTER_CLEAR_ALL_BINDINGS_REQ
        | CLUSTER_MGMT_NWK_DISC_REQ
        | CLUSTER_MGMT_LQI_REQ
        | CLUSTER_MGMT_DIRECT_JOIN_REQ
        | CLUSTER_MGMT_CACHE_REQ
        | CLUSTER_MGMT_RTG_REQ
        | CLUSTER_MGMT_BIND_REQ
        | CLUSTER_MGMT_LEAVE_REQ
        | CLUSTER_MGMT_PERMIT_JOINING_REQ
        | CLUSTER_MGMT_NWK_UPDATE_REQ
        | CLUSTER_MGMT_NWK_ENHANCED_UPDATE_REQ
        | CLUSTER_MGMT_NWK_IEEE_JOINING_LIST_REQ
        | CLUSTER_MGMT_NWK_BEACON_SURVEY_REQ => Some(request | RESPONSE_BIT),
        _ => None,
    }
}
