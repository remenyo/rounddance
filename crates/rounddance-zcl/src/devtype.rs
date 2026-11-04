//! Device Type Library: generic device descriptors plus the
//! Door Lock device (0x000A) and conformance helpers.
//!
//! Paraphrase-level model of doc `23-02016-002` (Door Lock device
//! anchors p0055-L927-L939, required-attribute table anchor
//! p0056-L941-L944, received-command table anchor
//! p0056-L945-L947, generated-command table anchor
//! p0056-L948-L950, PICS anchor p0057-L951-L954; the
//! classification/revision-headers pattern also appears in doc
//! `17-05031-011` §2.1–2.2 anchors p0009-L59-L76 and doc
//! `15-0014-05` §13.1 anchors p0053-L738-L743). Descriptors carry
//! no runtime behavior by design: state machines live in the
//! per-cluster behavior modules; this registry answers "which
//! clusters must an endpoint field". All wording here is
//! paraphrase (D1).
//!
//! Requirement IDs below are repo-minted
//! (`23-02016-002-<clause>-<seq>`, dots stripped),
//! MINTED-pending-confirm.

/// Device classes carried by the descriptors here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceClass {
    /// Always-addressable endpoint device.
    Simple,
    /// Sleeping endpoint device.
    Sleepy,
}

/// Static description of one device type: identity, revision, and
/// the cluster lists an endpoint must field.
#[derive(Clone, Copy, Debug)]
pub struct DeviceDef {
    /// Device identifier.
    pub id: u16,
    /// Short stable name (diagnostics only).
    pub name: &'static str,
    /// Device class.
    pub class: DeviceClass,
    /// Implemented device revision (rev table tip).
    pub revision: u8,
    /// Server clusters the device must field, ascending.
    pub server_mandatory: &'static [u16],
    /// Client clusters the device must field, ascending.
    pub client_mandatory: &'static [u16],
    /// Recommended server clusters (optional), ascending.
    pub server_optional: &'static [u16],
    /// Recommended client clusters (optional), ascending.
    pub client_optional: &'static [u16],
}

impl DeviceDef {
    /// Whether the endpoint's server list covers the mandatory
    /// server set.
    #[must_use]
    pub const fn servers_covered(&self, server_clusters: &[u16]) -> bool {
        covers(server_clusters, self.server_mandatory)
    }

    /// Whether the endpoint's client list covers the mandatory
    /// client set.
    #[must_use]
    pub const fn clients_covered(&self, client_clusters: &[u16]) -> bool {
        covers(client_clusters, self.client_mandatory)
    }

    /// Whether both endpoint sides satisfy the mandatory tables.
    #[must_use]
    pub const fn conforms(&self, server_clusters: &[u16], client_clusters: &[u16]) -> bool {
        self.servers_covered(server_clusters) && self.clients_covered(client_clusters)
    }
}

/// Whether `clusters` covers every entry of `mandatory`.
#[must_use]
pub const fn covers(clusters: &[u16], mandatory: &[u16]) -> bool {
    let mut i = 0;
    while i < mandatory.len() {
        let mut found = false;
        let mut j = 0;
        while j < clusters.len() {
            if clusters[j] == mandatory[i] {
                found = true;
            }
            j += 1;
        }
        if !found {
            return false;
        }
        i += 1;
    }
    true
}

/// Door Lock device identifier.
///
/// Requirement `23-02016-002-14-01` (MINTED-pending-confirm).
pub const DOOR_LOCK_ID: u16 = 0x000a;
/// Implemented Door Lock device revision (rev table tip).
pub const DOOR_LOCK_REVISION: u8 = 1;

/// Door Lock cluster.
pub const CLUSTER_DOOR_LOCK: u16 = 0x0101;
/// Basic cluster.
pub const CLUSTER_BASIC: u16 = 0x0000;
/// Identify cluster.
pub const CLUSTER_IDENTIFY: u16 = 0x0003;
/// Power Configuration cluster (recommended).
pub const CLUSTER_POWER_CONFIG: u16 = 0x0001;
/// Alarms cluster (recommended).
pub const CLUSTER_ALARMS: u16 = 0x0009;
/// Poll Control cluster (recommended).
pub const CLUSTER_POLL_CONTROL: u16 = 0x0020;
/// Time cluster (recommended).
pub const CLUSTER_TIME: u16 = 0x000a;
/// OTA Upgrade cluster (recommended).
pub const CLUSTER_OTA: u16 = 0x0019;
/// Groups cluster (restricted on the server side).
pub const CLUSTER_GROUPS: u16 = 0x0004;
/// Scenes cluster (restricted on the server side).
pub const CLUSTER_SCENES: u16 = 0x0005;

/// Door Lock mandatory server clusters, ascending.
///
/// Requirement `23-02016-002-14-02` (MINTED-pending-confirm).
pub const DOOR_LOCK_SERVER_MANDATORY: &[u16] =
    &[CLUSTER_BASIC, CLUSTER_IDENTIFY, CLUSTER_DOOR_LOCK];

/// Door Lock recommended optional server clusters, ascending.
pub const DOOR_LOCK_SERVER_OPTIONAL: &[u16] = &[
    CLUSTER_POWER_CONFIG,
    CLUSTER_ALARMS,
    CLUSTER_POLL_CONTROL,
    CLUSTER_TIME,
    CLUSTER_OTA,
];

/// Door Lock descriptor.
///
/// Requirement `23-02016-002-14-01` (MINTED-pending-confirm).
pub const DOOR_LOCK: DeviceDef = DeviceDef {
    id: DOOR_LOCK_ID,
    name: "door-lock",
    class: DeviceClass::Simple,
    revision: DOOR_LOCK_REVISION,
    server_mandatory: DOOR_LOCK_SERVER_MANDATORY,
    client_mandatory: &[],
    server_optional: DOOR_LOCK_SERVER_OPTIONAL,
    client_optional: &[],
};

/// Whether a server cluster list trips the Door Lock restriction
/// (Groups/Scenes servers would bypass the lock's authorization
/// path, so a conforming lock omits them).
///
/// Requirement `23-02016-002-14-03` (MINTED-pending-confirm).
#[must_use]
pub const fn door_lock_restricted(server_clusters: &[u16]) -> bool {
    let mut i = 0;
    while i < server_clusters.len() {
        if server_clusters[i] == CLUSTER_GROUPS || server_clusters[i] == CLUSTER_SCENES {
            return true;
        }
        i += 1;
    }
    false
}

/// Door Lock required attributes (cluster, identifier) in device
/// table order.
///
/// Requirement `23-02016-002-14-04` (MINTED-pending-confirm).
pub const DOOR_LOCK_ATTRS: &[(u16, u16)] = &[
    (CLUSTER_BASIC, 0x0000),
    (CLUSTER_BASIC, 0x0007),
    (CLUSTER_IDENTIFY, 0x0000),
    (CLUSTER_GROUPS, 0x0000),
    (CLUSTER_SCENES, 0x0000),
    (CLUSTER_SCENES, 0x0001),
    (CLUSTER_SCENES, 0x0002),
    (CLUSTER_SCENES, 0x0003),
    (CLUSTER_SCENES, 0x0004),
    (CLUSTER_DOOR_LOCK, 0x0000),
    (CLUSTER_DOOR_LOCK, 0x0001),
    (CLUSTER_DOOR_LOCK, 0x0002),
];

/// Door Lock required received commands (cluster, identifier).
///
/// Requirement `23-02016-002-14-05` (MINTED-pending-confirm).
pub const DOOR_LOCK_COMMANDS_RX: &[(u16, u8)] = &[
    (CLUSTER_IDENTIFY, 0x00),
    (CLUSTER_IDENTIFY, 0x01),
    (CLUSTER_DOOR_LOCK, 0x00),
    (CLUSTER_DOOR_LOCK, 0x01),
];

/// Door Lock generated commands (cluster, identifier, trigger).
///
/// Requirement `23-02016-002-14-05` (MINTED-pending-confirm).
pub const DOOR_LOCK_COMMANDS_TX: &[(u16, u8, u8)] = &[
    (CLUSTER_IDENTIFY, 0x00, 0x01),
    (CLUSTER_DOOR_LOCK, 0x00, 0x00),
    (CLUSTER_DOOR_LOCK, 0x01, 0x01),
];

/// Registry of the device descriptors carried in this module.
pub const DEVICES: &[DeviceDef] = &[DOOR_LOCK];

/// Look up a device descriptor by identifier.
#[must_use]
pub const fn find_device(id: u16) -> Option<DeviceDef> {
    let mut i = 0;
    while i < DEVICES.len() {
        if DEVICES[i].id == id {
            return Some(DEVICES[i]);
        }
        i += 1;
    }
    None
}
