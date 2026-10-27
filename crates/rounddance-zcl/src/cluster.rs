//! DEFINITIONS layer: machine-usable cluster tables.
//!
//! The middle of the 3-level ZCL architecture (engine / definitions /
//! behavior): every cluster ships a static [`ClusterDef`] describing
//! its identity, revision, attribute set, and both command sets. The
//! engine's discovery handlers and the dispatcher read these tables
//! directly, so definition mistakes surface as vector failures, not
//! as behavior mysteries.
//!
//! Requirement `07-5123-08-231-01` (corpus-mined): server clusters
//! live in the input (server) list of the endpoint descriptor, client
//! clusters in the output (client) list — [`ClusterDef::role`] tells
//! the descriptor builder which list takes this cluster.

use crate::attrs::AttrDef;

/// Endpoint role this definition implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterRole {
    /// Server side: hosts attributes, receives commands.
    Server,
    /// Client side: sends commands, receives reports.
    Client,
}

/// One cluster-specific command entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CmdDef {
    /// Command identifier.
    pub id: u8,
    /// Short stable name (diagnostics only, never on the wire).
    pub name: &'static str,
}

/// Static description of one cluster side: identity, revision,
/// attributes, and both command directions.
///
/// Attribute slices MUST be sorted ascending by identifier (the
/// discovery handler relies on it); command slices MUST be sorted
/// ascending by command identifier.
pub trait ClusterDef {
    /// Cluster identifier (e.g. On/Off = `0x0006`).
    fn cluster_id(&self) -> u16;
    /// Short stable name (diagnostics only).
    fn name(&self) -> &'static str;
    /// Implemented specification revision, reported via the
    /// ClusterRevision global.
    ///
    /// Requirement `07-5123-08-2345-02` (corpus-mined).
    fn revision(&self) -> u16;
    /// Which endpoint list hosts this side.
    ///
    /// Requirement `07-5123-08-231-01` (corpus-mined).
    fn role(&self) -> ClusterRole;
    /// Attribute table, ascending by identifier.
    fn attributes(&self) -> &'static [AttrDef];
    /// Commands this side receives, ascending by identifier.
    fn received_commands(&self) -> &'static [CmdDef];
    /// Commands this side generates, ascending by identifier.
    fn generated_commands(&self) -> &'static [CmdDef];
    /// Whether `attr` belongs to the reportable set (implementations
    /// may additionally enable others; collection types stay out).
    ///
    /// Requirement `07-5123-08-257-01` (corpus-mined).
    fn is_reportable(&self, attr: u16) -> bool {
        self.attributes()
            .iter()
            .any(|a| a.id == attr && a.reportable)
    }
}

/// Look up a received-command entry by identifier.
#[must_use]
pub fn find_received(def: &dyn ClusterDef, cmd: u8) -> Option<CmdDef> {
    def.received_commands()
        .iter()
        .find(|c| c.id == cmd)
        .copied()
}

/// Look up a generated-command entry by identifier.
#[must_use]
pub fn find_generated(def: &dyn ClusterDef, cmd: u8) -> Option<CmdDef> {
    def.generated_commands()
        .iter()
        .find(|c| c.id == cmd)
        .copied()
}
