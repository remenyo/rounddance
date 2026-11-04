//! ERL Interface device (0x0509): device descriptor, required
//! cluster/attribute/command tables, and conformance helpers.
//!
//! Paraphrase-level model of doc `17-05031-011` (device list
//! anchors p0007-L56-L58 + p0008-L58, format anchors
//! p0009-L59-L88, base-device anchors p0010-L91-L106, ERL
//! classification anchors p0011-L107-L117, cluster table anchor
//! p0011-L118-L123, attribute table anchors p0012-L124-L129 +
//! p0013-L129 + p0014-L129 + p0015-L129 + p0016-L129, reporting
//! table anchors p0017-L130-L133 + p0018-L133, received-command
//! table anchor p0018-L134-L136, generated-command table anchors
//! p0018-L137-L140 + p0019-L140). Numeric cluster identifiers for
//! the named clusters reuse this crate's cluster constants where
//! they exist (`metering`, `electrical`, `dailysched`); the
//! remaining assignments are the standard identifiers for the named
//! clusters. All wording here is paraphrase (D1).
//!
//! Requirement IDs below are repo-minted
//! (`17-05031-011-4-<seq>`, dots stripped),
//! MINTED-pending-confirm.

use super::dailysched;
use crate::electrical;
use crate::metering;

/// Device identifier.
///
/// Requirement `17-05031-011-4-01` (MINTED-pending-confirm).
pub const DEVICE_ID: u16 = 0x0509;
/// Implemented device revision (rev table tip).
///
/// Requirement `17-05031-011-4-02` (MINTED-pending-confirm).
pub const REVISION: u8 = 1;

/// Basic cluster (server + client base requirements).
pub const CLUSTER_BASIC: u16 = 0x0000;
/// Identify cluster.
pub const CLUSTER_IDENTIFY: u16 = 0x0003;
/// Time cluster.
pub const CLUSTER_TIME: u16 = 0x000a;
/// Messaging cluster.
pub const CLUSTER_MESSAGING: u16 = 0x0703;
/// Meter Identification cluster.
pub const CLUSTER_METER_ID: u16 = 0x0b01;
/// Diagnostics cluster.
pub const CLUSTER_DIAGNOSTICS: u16 = 0x0b05;
/// OTA Upgrade cluster (recommended optional).
pub const CLUSTER_OTA: u16 = 0x0019;

/// Mandatory server clusters, ascending.
///
/// Requirement `17-05031-011-4-03` (MINTED-pending-confirm).
pub const SERVER_MANDATORY: &[u16] = &[
    CLUSTER_BASIC,
    CLUSTER_IDENTIFY,
    CLUSTER_TIME,
    metering::CLUSTER_ID,
    CLUSTER_MESSAGING,
    dailysched::CLUSTER_ID,
    CLUSTER_METER_ID,
    electrical::CLUSTER_ID,
    CLUSTER_DIAGNOSTICS,
];

/// Mandatory client clusters, ascending.
///
/// Requirement `17-05031-011-4-03` (MINTED-pending-confirm).
pub const CLIENT_MANDATORY: &[u16] = &[CLUSTER_IDENTIFY, CLUSTER_TIME];

/// Recommended optional clusters (OTA Upgrade, either side).
pub const OPTIONAL: &[u16] = &[CLUSTER_OTA];

/// One required attribute row: owning cluster, identifier, and
/// whether the row is marked reportable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttrReq {
    /// Owning cluster identifier.
    pub cluster: u16,
    /// Attribute identifier.
    pub attr: u16,
    /// Row marked reportable in the device table.
    pub reportable: bool,
}

/// Required attributes, grouped by cluster (Basic, Identify, Time,
/// Meter Identification, Electrical Measurement, Diagnostics,
/// Metering, Daily Schedule), in device-table order.
///
/// Requirement `17-05031-011-4-04` (MINTED-pending-confirm).
pub const REQUIRED_ATTRS: &[AttrReq] = &[
    // Basic (server).
    AttrReq {
        cluster: CLUSTER_BASIC,
        attr: 0x0000,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_BASIC,
        attr: 0x0001,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_BASIC,
        attr: 0x0002,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_BASIC,
        attr: 0x0003,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_BASIC,
        attr: 0x0004,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_BASIC,
        attr: 0x0005,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_BASIC,
        attr: 0x0006,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_BASIC,
        attr: 0x0007,
        reportable: false,
    },
    // Identify (server).
    AttrReq {
        cluster: CLUSTER_IDENTIFY,
        attr: 0x0000,
        reportable: false,
    },
    // Time (server).
    AttrReq {
        cluster: CLUSTER_TIME,
        attr: 0x0000,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_TIME,
        attr: 0x0001,
        reportable: true,
    },
    AttrReq {
        cluster: CLUSTER_TIME,
        attr: 0x0002,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_TIME,
        attr: 0x0003,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_TIME,
        attr: 0x0004,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_TIME,
        attr: 0x0005,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_TIME,
        attr: 0x0006,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_TIME,
        attr: 0x0007,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_TIME,
        attr: 0x0008,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_TIME,
        attr: 0x0009,
        reportable: false,
    },
    // Meter Identification (server).
    AttrReq {
        cluster: CLUSTER_METER_ID,
        attr: 0x0000,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_METER_ID,
        attr: 0x0001,
        reportable: true,
    },
    AttrReq {
        cluster: CLUSTER_METER_ID,
        attr: 0x0004,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_METER_ID,
        attr: 0x0006,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_METER_ID,
        attr: 0x000c,
        reportable: true,
    },
    AttrReq {
        cluster: CLUSTER_METER_ID,
        attr: 0x000d,
        reportable: true,
    },
    AttrReq {
        cluster: CLUSTER_METER_ID,
        attr: 0x000e,
        reportable: true,
    },
    // Electrical Measurement (server).
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0000,
        reportable: false,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0304,
        reportable: true,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0306,
        reportable: true,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0402,
        reportable: false,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0403,
        reportable: false,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0505,
        reportable: true,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0508,
        reportable: true,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x050b,
        reportable: true,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x050f,
        reportable: true,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0511,
        reportable: false,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0600,
        reportable: false,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0601,
        reportable: false,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0602,
        reportable: false,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0603,
        reportable: false,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0604,
        reportable: false,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0605,
        reportable: false,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0905,
        reportable: true,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0908,
        reportable: true,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x090b,
        reportable: true,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x090f,
        reportable: true,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0911,
        reportable: false,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0a05,
        reportable: true,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0a08,
        reportable: true,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0a0b,
        reportable: true,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0a0f,
        reportable: true,
    },
    AttrReq {
        cluster: electrical::CLUSTER_ID,
        attr: 0x0a11,
        reportable: false,
    },
    // Diagnostics (server).
    AttrReq {
        cluster: CLUSTER_DIAGNOSTICS,
        attr: 0x0000,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_DIAGNOSTICS,
        attr: 0x011c,
        reportable: false,
    },
    AttrReq {
        cluster: CLUSTER_DIAGNOSTICS,
        attr: 0x011d,
        reportable: false,
    },
    // Metering (server).
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0000,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0001,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0020,
        reportable: true,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0023,
        reportable: true,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0100,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0101,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0102,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0104,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0106,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0108,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x010a,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x010c,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x010e,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0110,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0112,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0200,
        reportable: true,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0204,
        reportable: true,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0206,
        reportable: true,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0208,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0209,
        reportable: true,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0300,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0301,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0302,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0303,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0304,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0305,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0306,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0307,
        reportable: true,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0308,
        reportable: true,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x030e,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0400,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x045d,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x045e,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x045f,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0460,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0461,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0462,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0463,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0464,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0500,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0d05,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0d06,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0d07,
        reportable: false,
    },
    AttrReq {
        cluster: metering::CLUSTER_ID,
        attr: 0x0d08,
        reportable: false,
    },
    // Daily Schedule (server).
    AttrReq {
        cluster: dailysched::CLUSTER_ID,
        attr: 0x0000,
        reportable: false,
    },
    AttrReq {
        cluster: dailysched::CLUSTER_ID,
        attr: 0x0001,
        reportable: false,
    },
    AttrReq {
        cluster: dailysched::CLUSTER_ID,
        attr: 0x0002,
        reportable: false,
    },
    AttrReq {
        cluster: dailysched::CLUSTER_ID,
        attr: 0x0003,
        reportable: false,
    },
    AttrReq {
        cluster: dailysched::CLUSTER_ID,
        attr: 0x0004,
        reportable: false,
    },
    AttrReq {
        cluster: dailysched::CLUSTER_ID,
        attr: 0x0005,
        reportable: false,
    },
    AttrReq {
        cluster: dailysched::CLUSTER_ID,
        attr: 0x0006,
        reportable: false,
    },
    AttrReq {
        cluster: dailysched::CLUSTER_ID,
        attr: 0x0007,
        reportable: false,
    },
    AttrReq {
        cluster: dailysched::CLUSTER_ID,
        attr: 0x0100,
        reportable: true,
    },
    AttrReq {
        cluster: dailysched::CLUSTER_ID,
        attr: 0x0101,
        reportable: true,
    },
    AttrReq {
        cluster: dailysched::CLUSTER_ID,
        attr: 0x0102,
        reportable: false,
    },
    AttrReq {
        cluster: dailysched::CLUSTER_ID,
        attr: 0x0103,
        reportable: true,
    },
    AttrReq {
        cluster: dailysched::CLUSTER_ID,
        attr: 0x0104,
        reportable: false,
    },
    AttrReq {
        cluster: dailysched::CLUSTER_ID,
        attr: 0x0105,
        reportable: false,
    },
    AttrReq {
        cluster: dailysched::CLUSTER_ID,
        attr: 0x0106,
        reportable: false,
    },
];

/// One required command row: owning cluster plus command id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CmdReq {
    /// Owning cluster identifier.
    pub cluster: u16,
    /// Command identifier.
    pub cmd: u8,
}

/// Commands the device receives and processes, in device-table
/// order.
///
/// Requirement `17-05031-011-4-05` (MINTED-pending-confirm).
pub const COMMANDS_RX: &[CmdReq] = &[
    CmdReq {
        cluster: CLUSTER_IDENTIFY,
        cmd: 0x00,
    },
    CmdReq {
        cluster: CLUSTER_IDENTIFY,
        cmd: 0x01,
    },
    CmdReq {
        cluster: CLUSTER_IDENTIFY,
        cmd: 0x40,
    },
    CmdReq {
        cluster: metering::CLUSTER_ID,
        cmd: 0x00,
    },
    CmdReq {
        cluster: metering::CLUSTER_ID,
        cmd: 0x06,
    },
    CmdReq {
        cluster: metering::CLUSTER_ID,
        cmd: 0x08,
    },
    CmdReq {
        cluster: CLUSTER_MESSAGING,
        cmd: 0x00,
    },
    CmdReq {
        cluster: CLUSTER_MESSAGING,
        cmd: 0x01,
    },
    CmdReq {
        cluster: dailysched::CLUSTER_ID,
        cmd: 0x00,
    },
    CmdReq {
        cluster: dailysched::CLUSTER_ID,
        cmd: 0x01,
    },
    CmdReq {
        cluster: dailysched::CLUSTER_ID,
        cmd: 0x05,
    },
];

/// Commands the device generates with the triggering receipt.
///
/// Requirement `17-05031-011-4-05` (MINTED-pending-confirm).
pub const COMMANDS_TX: &[CmdGen] = &[
    CmdGen {
        cluster: CLUSTER_IDENTIFY,
        cmd: 0x00,
        on_receipt_of: 0x01,
    },
    CmdGen {
        cluster: metering::CLUSTER_ID,
        cmd: 0x00,
        on_receipt_of: 0x00,
    },
    CmdGen {
        cluster: metering::CLUSTER_ID,
        cmd: 0x06,
        on_receipt_of: 0x06,
    },
    CmdGen {
        cluster: metering::CLUSTER_ID,
        cmd: 0x07,
        on_receipt_of: 0x08,
    },
    CmdGen {
        cluster: CLUSTER_MESSAGING,
        cmd: 0x00,
        on_receipt_of: 0x00,
    },
    CmdGen {
        cluster: CLUSTER_MESSAGING,
        cmd: 0x01,
        on_receipt_of: 0xff,
    },
    CmdGen {
        cluster: dailysched::CLUSTER_ID,
        cmd: 0x00,
        on_receipt_of: 0x00,
    },
    CmdGen {
        cluster: dailysched::CLUSTER_ID,
        cmd: 0x01,
        on_receipt_of: 0x01,
    },
    CmdGen {
        cluster: dailysched::CLUSTER_ID,
        cmd: 0x06,
        on_receipt_of: 0xff,
    },
];

/// One generated-command row with its triggering received command
/// (`0xff` marks unsolicited transmission).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CmdGen {
    /// Owning cluster identifier.
    pub cluster: u16,
    /// Generated command identifier.
    pub cmd: u8,
    /// Received command triggering it (`0xff` = unsolicited).
    pub on_receipt_of: u8,
}

/// Look up a required attribute row.
#[must_use]
pub const fn find_attr(cluster: u16, attr: u16) -> Option<AttrReq> {
    let mut i = 0;
    while i < REQUIRED_ATTRS.len() {
        let row = REQUIRED_ATTRS[i];
        if row.cluster == cluster && row.attr == attr {
            return Some(row);
        }
        i += 1;
    }
    None
}

/// Whether `clusters` (one endpoint side) covers every mandatory
/// entry of `mandatory`.
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

/// Whether an endpoint's server/client cluster lists satisfy the
/// ERL mandatory tables.
///
/// Requirement `17-05031-011-4-06` (MINTED-pending-confirm).
#[must_use]
pub const fn conforms(server_clusters: &[u16], client_clusters: &[u16]) -> bool {
    covers(server_clusters, SERVER_MANDATORY) && covers(client_clusters, CLIENT_MANDATORY)
}
