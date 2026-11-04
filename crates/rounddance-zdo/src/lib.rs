//! Zigbee Device Objects (ZDO): discovery, descriptors, binding, and
//! network-manager structures.
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2 §2.3.2.3–§2.3.2.5
//! (descriptors) and §§2.4.3–2.4.4 (device profile client/server
//! services). All wording here is paraphrase; citations name document,
//! revision, and clause/line only (D1, `SCOPE.md` §2).
//!
//! # Design notes (mirror `rounddance-nwk` / `rounddance-aps`)
//!
//! * `no_std` + `#![forbid(unsafe_code)]`, no allocator: decode
//!   validates into fixed-size arrays (variable lists reject oversize
//!   counts instead of growing), encode writes into caller buffers.
//! * Every fallible path returns a typed error; nothing panics on
//!   adversarial input.
//! * Time is never read here; response timeouts belong to the caller
//!   (e.g. the apsZdoResponseTimeout wait of `05-3474-23-22411-14`).
//! * Every public item cites the requirement ID it implements
//!   (`05-3474-23-<clause>-<seq>`, dots stripped — repo-minted pending
//!   seed extraction of the ZDO clauses).
#![no_std]
#![forbid(unsafe_code)]

pub mod bind;
pub mod cluster;
pub mod desc;
pub mod endpoint;
pub mod mgmt;
pub mod status;
pub mod transaction;
pub mod zdp;

pub use bind::{endpoint_bindable, group_member_endpoint, BindManager};
pub use cluster::{
    response_cluster, CLUSTER_ACTIVE_EP_REQ, CLUSTER_BACKUP_BIND_TABLE_REQ,
    CLUSTER_BACKUP_SOURCE_BIND_REQ, CLUSTER_BIND_REGISTER_REQ, CLUSTER_BIND_REQ,
    CLUSTER_CLEAR_ALL_BINDINGS_REQ, CLUSTER_COMPLEX_DESC_REQ, CLUSTER_DEVICE_ANNCE,
    CLUSTER_DISCOVERY_CACHE_REQ, CLUSTER_DISCOVERY_STORE_REQ, CLUSTER_END_DEVICE_BIND_REQ,
    CLUSTER_IEEE_ADDR_REQ, CLUSTER_MATCH_DESC_REQ, CLUSTER_MGMT_BIND_REQ, CLUSTER_MGMT_CACHE_REQ,
    CLUSTER_MGMT_DIRECT_JOIN_REQ, CLUSTER_MGMT_LEAVE_REQ, CLUSTER_MGMT_LQI_REQ,
    CLUSTER_MGMT_NWK_BEACON_SURVEY_REQ, CLUSTER_MGMT_NWK_DISC_REQ,
    CLUSTER_MGMT_NWK_ENHANCED_UPDATE_REQ, CLUSTER_MGMT_NWK_IEEE_JOINING_LIST_REQ,
    CLUSTER_MGMT_NWK_UPDATE_REQ, CLUSTER_MGMT_PERMIT_JOINING_REQ, CLUSTER_MGMT_RTG_REQ,
    CLUSTER_NODE_DESC_REQ, CLUSTER_NODE_DESC_STORE_REQ, CLUSTER_NWK_ADDR_REQ, CLUSTER_PARENT_ANNCE,
    CLUSTER_POWER_DESC_REQ, CLUSTER_RECOVER_BIND_TABLE_REQ, CLUSTER_RECOVER_SOURCE_BIND_REQ,
    CLUSTER_REMOVE_BAK_BIND_ENTRY_REQ, CLUSTER_REPLACE_DEVICE_REQ, CLUSTER_SIMPLE_DESC_REQ,
    CLUSTER_STORE_BAK_BIND_ENTRY_REQ, CLUSTER_SYSTEM_SERVER_DISCOVERY_REQ, CLUSTER_UNBIND_REQ,
    CLUSTER_USER_DESC_REQ, CLUSTER_USER_DESC_SET_REQ, RESPONSE_BIT,
};
pub use desc::{
    Error as ZdoError, LogicalType, NodeDescriptor, PowerDescriptor, PowerMode, SimpleDescriptor,
    MAX_SIMPLE_CLUSTERS, NODE_DESCRIPTOR_LEN, POWER_DESCRIPTOR_LEN,
};
pub use endpoint::{endpoint_answerable, simple_desc_fits, EndpointTable, MAX_LOCAL_ENDPOINTS};
pub use mgmt::{
    decide_local_conflict, decide_remote_conflict, detect_local_conflict, first_table_conflict,
    reannounce, BeaconSurveyResults, CacheEntry, ChannelList, ChannelPageMask, ConflictDecision,
    ConflictOutcome, ConflictRole, JoiningPolicy, MgmtBindEntry, MgmtBindReq, MgmtBindRsp,
    MgmtCacheReq, MgmtCacheRsp, MgmtDirectJoinReq, MgmtDirectJoinRsp, MgmtLeaveReq, MgmtLeaveRsp,
    MgmtLqiReq, MgmtLqiRsp, MgmtNwkBeaconSurveyReq, MgmtNwkBeaconSurveyRsp, MgmtNwkDiscReq,
    MgmtNwkDiscRsp, MgmtNwkEnhancedUpdateNotify, MgmtNwkEnhancedUpdateReq,
    MgmtNwkIeeeJoiningListReq, MgmtNwkIeeeJoiningListRsp, MgmtNwkUpdateNotify, MgmtNwkUpdateReq,
    MgmtPermitJoiningReq, MgmtPermitJoiningRsp, MgmtRtgReq, MgmtRtgRsp, NeighborEntry,
    NetworkEntry, PotentialParent, RtgEntry, BEACON_SURVEY_CONFIG_TAG, MAX_CACHE_ENTRIES,
    MAX_CHANNEL_PAGES, MAX_ENERGY_VALUES, MAX_ENHANCED_ENERGY, MAX_JOINING_IEEE,
    MAX_MGMT_BIND_ENTRIES, MAX_NEIGHBORS, MAX_NETWORKS, MAX_POTENTIAL_PARENTS, MAX_RTG_ENTRIES,
};
pub use status::ZdpStatus;
pub use transaction::{transaction_expected, Pending, PendingTable, TxnError};
pub use zdp::{
    ActiveEpReq, ActiveEpRsp, BindDstMode, BindEntry, BindRsp, ChildInfo, ClearAllBindingsReq,
    ClearAllBindingsRsp, ComplexDescReq, ComplexDescRsp, ComplexField, DeviceAnnce,
    EndDeviceBindReq, EndDeviceBindRsp, IeeeAddrReq, IeeeAddrRsp, MatchDescReq, MatchDescRsp,
    NodeDescReq, NodeDescRsp, NwkAddrReq, NwkAddrRsp, ParentAnnce, ParentAnnceRsp, PowerDescReq,
    PowerDescRsp, RequestType, SimpleDescReq, SimpleDescRsp, SystemServerDiscoveryReq,
    SystemServerDiscoveryRsp, UserDescReq, UserDescRsp, CLEAR_BINDINGS_EUI64_TAG,
    MAX_ASSOC_DEVICES, MAX_CHILD_INFO, MAX_CLEAR_EUI64S, MAX_COMPLEX_FIELDS, MAX_COMPLEX_FIELD_LEN,
    MAX_EP_LIST, MAX_EZB_CLUSTERS, MAX_USER_DESC_LEN,
};

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-zdo"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
    }
}
