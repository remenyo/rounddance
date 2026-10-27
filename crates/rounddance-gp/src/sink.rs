//! Sink role: sink table, translation table, and the command-accept
//! path (group forwarding plus translation into local commands).
//!
//! Paraphrase-level model of doc `14-0563-19` §A.3.6.2 (sink
//! operation; anchors p0181-L5115-L5156), §A.3.6.2.2 (translation
//! table; anchors p0191-L5376-L5394, p0189-L5314-L5343,
//! p0192-L5414-L5445). All wording here is paraphrase (D1,
//! `SCOPE.md` §2).
//!
//! Requirement IDs below are corpus-mined `14-0563-19-*`.

use crate::frame::{AppId, GpError, GpdId, WireSecurityLevel};

/// Wildcard source identifier marking generic translations: applies
/// to every GPD.
///
/// Requirement `14-0563-19-A36-07`.
pub const GENERIC_SRC_ID: u32 = 0xFFFF_FFFF;

/// GPD command value matching every GPD command.
///
/// Requirement `14-0563-19-A36-08`.
pub const GENERIC_GPD_COMMAND: u8 = 0xFF;

/// GPD command value grouping the sensor-report commands (never used
/// for compact attribute reporting).
///
/// Requirement `14-0563-19-A36-08`.
pub const COMPACT_SENSOR_GROUP_CMD: u8 = 0xAF;

/// GPD compact attribute reporting command identifier.
///
/// Requirement `14-0563-19-A36-08`.
pub const COMPACT_ATTR_REPORT_CMD: u8 = 0xA8;

/// Largest translation payload template carried per entry.
pub const MAX_TRANSLATION_PAYLOAD: usize = 24;

/// Largest group list held per sink-table entry (bounded budget).
pub const MAX_SINK_GROUPS: usize = 4;

/// Typed failure for sink-table and translation operations.
pub use crate::frame::GpError as SinkError;

/// How the translated command payload is formed.
///
/// Requirement `14-0563-19-A36-07` (template rules).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadMode {
    /// No payload travels with the translated command.
    None,
    /// Fixed template bytes travel verbatim.
    Fixed,
    /// Triggering command payload copied verbatim.
    VerbatimCopy,
    /// Payload needs manufacturer parsing (handled by the app layer).
    Parsed,
}

impl PayloadMode {
    /// Decode the length-sub-field convention into a mode.
    ///
    /// Requirement `14-0563-19-A36-07`.
    #[must_use]
    pub const fn from_length_byte(len: u8) -> Self {
        match len {
            0x00 => Self::None,
            0xFF => Self::VerbatimCopy,
            0xFE => Self::Parsed,
            _ => Self::Fixed,
        }
    }
}

/// Contact match option for 8-bit vector press/release translations.
///
/// Requirement `14-0563-19-A36-09`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorOption {
    /// Contact state to match.
    pub contact_status: u8,
    /// Bitmask applied to the received contact state first.
    pub contact_mask: u8,
}

impl VectorOption {
    /// True when the received contact state matches this entry: the
    /// masked receipt must equal the stored state.
    ///
    /// Requirement `14-0563-19-A36-09`.
    #[must_use]
    pub const fn matches(self, received: u8) -> bool {
        received & self.contact_mask == self.contact_status
    }
}

/// One translation-table entry: GPD command to local-command mapping.
///
/// Requirement `14-0563-19-A36-07`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranslationTableEntry {
    /// Identity scheme.
    pub app: AppId,
    /// GPD identity (`GENERIC_SRC_ID` for generic translations).
    pub gpd: u64,
    /// Endpoint scope (`0x00`/`0xFF`/matching for IEEE identities).
    pub endpoint: u8,
    /// GPD command (`GENERIC_GPD_COMMAND` matches all,
    /// `COMPACT_SENSOR_GROUP_CMD` groups the sensor reports).
    pub gpd_command: u8,
    /// Target profile identifier.
    pub profile: u16,
    /// Target cluster (`0xFFFF` = use the triggering cluster field).
    pub cluster: u16,
    /// Target command identifier.
    pub command: u8,
    /// Payload formation rule.
    pub payload_mode: PayloadMode,
    /// Fixed template bytes (for `Fixed` mode).
    pub payload: [u8; MAX_TRANSLATION_PAYLOAD],
    /// Valid template bytes.
    pub payload_len: u8,
    /// Vector press/release contact option, if any.
    pub vector: Option<VectorOption>,
}

impl TranslationTableEntry {
    /// True for the wildcard generic translations.
    ///
    /// Requirement `14-0563-19-A36-07`.
    #[must_use]
    pub const fn is_generic(&self) -> bool {
        self.gpd == GENERIC_SRC_ID as u64
    }

    /// Command-match test: exact, all-commands, or compact-group
    /// (the compact group never matches compact attribute
    /// reporting).
    ///
    /// Requirement `14-0563-19-A36-08`.
    #[must_use]
    pub const fn command_matches(&self, command: u8) -> bool {
        if self.gpd_command == GENERIC_GPD_COMMAND {
            return true;
        }
        if self.gpd_command == COMPACT_SENSOR_GROUP_CMD {
            return command >= 0xA0 && command <= 0xA3;
        }
        self.gpd_command == command
    }

    /// Endpoint-match test for IEEE identities.
    ///
    /// Requirement `14-0563-19-A36-06` (matching, `0x00`, or `0xFF`).
    #[must_use]
    pub const fn endpoint_matches(&self, endpoint: u8) -> bool {
        self.endpoint == 0x00 || self.endpoint == 0xFF || self.endpoint == endpoint
    }

    /// Full match test for one received command: identity, endpoint,
    /// command, and contact option must all agree. Generic entries
    /// match any GPD.
    ///
    /// Requirements `14-0563-19-A36-07`, `-A36-08`, `-A36-09`.
    #[must_use]
    pub const fn matches(&self, id: GpdId, command: u8, contact: u8) -> bool {
        if !self.is_generic() && self.gpd != id.table_key() {
            return false;
        }
        let endpoint = match id {
            GpdId::SrcId(_) => 0x00,
            GpdId::Ieee { endpoint, .. } => endpoint,
        };
        if !self.endpoint_matches(endpoint) {
            return false;
        }
        if !self.command_matches(command) {
            return false;
        }
        match self.vector {
            Some(v) => v.matches(contact),
            None => true,
        }
    }
}

/// Bounded translation table: specific entries supersede generic
/// ones for the same command.
///
/// Requirement `14-0563-19-A36-07`.
#[derive(Debug)]
pub struct TranslationTable<const N: usize> {
    entries: [Option<TranslationTableEntry>; N],
}

impl<const N: usize> TranslationTable<N> {
    /// Empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    /// Number of populated rows.
    #[must_use]
    pub const fn len(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < N {
            if self.entries[i].is_some() {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// True when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert or overwrite; specific entries are preferred over
    /// generic ones only at lookup time, never by eviction.
    ///
    /// Requirement `14-0563-19-A36-07`.
    pub fn upsert(&mut self, entry: TranslationTableEntry) -> Result<(), GpError> {
        let mut i = 0;
        while i < N {
            let same = match self.entries[i] {
                Some(e) => {
                    e.app == entry.app
                        && e.gpd == entry.gpd
                        && e.endpoint == entry.endpoint
                        && e.gpd_command == entry.gpd_command
                }
                None => false,
            };
            if same {
                self.entries[i] = Some(entry);
                return Ok(());
            }
            i += 1;
        }
        let mut j = 0;
        while j < N {
            if self.entries[j].is_none() {
                self.entries[j] = Some(entry);
                return Ok(());
            }
            j += 1;
        }
        Err(GpError::TableFull)
    }

    /// Remove one entry by identity, endpoint, and command.
    pub fn remove(&mut self, gpd: u64, endpoint: u8, gpd_command: u8) -> Result<(), GpError> {
        let mut i = 0;
        while i < N {
            let hit = match self.entries[i] {
                Some(e) => e.gpd == gpd && e.endpoint == endpoint && e.gpd_command == gpd_command,
                None => false,
            };
            if hit {
                self.entries[i] = None;
                return Ok(());
            }
            i += 1;
        }
        Err(GpError::NotFound)
    }

    /// Look up the translation for one received command. A specific
    /// (non-generic) match supersedes a generic one.
    ///
    /// Requirement `14-0563-19-A36-07`.
    #[must_use]
    pub fn lookup(&self, id: GpdId, command: u8, contact: u8) -> Option<&TranslationTableEntry> {
        let mut generic: Option<&TranslationTableEntry> = None;
        for slot in self.entries.iter().flatten() {
            if !slot.matches(id, command, contact) {
                continue;
            }
            if slot.is_generic() {
                if generic.is_none() {
                    generic = Some(slot);
                }
            } else {
                return Some(slot);
            }
        }
        generic
    }
}

impl<const N: usize> Default for TranslationTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// One sink-table entry: per-GPD acceptance and forwarding state.
///
/// Requirement `14-0563-19-A36-06`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SinkTableEntry {
    /// Identity scheme.
    pub app: AppId,
    /// Canonical GPD key.
    pub id: u64,
    /// Endpoint scope (`0x00`/`0xFF`/matching).
    pub endpoint: u8,
    /// Required protection level.
    pub level: WireSecurityLevel,
    /// Required key-type wire bit.
    pub key_bit: bool,
    /// Last accepted security counter.
    pub counter: u32,
    /// GPD supports bidirectional operation in service.
    pub rx_on_capable: bool,
    /// Entry forwards groupcast traffic.
    pub group_forward: bool,
    /// Group addresses (bounded).
    pub groups: [u16; MAX_SINK_GROUPS],
    /// Valid group addresses.
    pub group_count: u8,
}

impl SinkTableEntry {
    /// Fresh entry accepting unsecured frames, no groups.
    #[must_use]
    pub const fn new(app: AppId, id: u64) -> Self {
        Self {
            app,
            id,
            endpoint: 0xFF,
            level: WireSecurityLevel::None,
            key_bit: false,
            counter: 0,
            rx_on_capable: false,
            group_forward: false,
            groups: [0xFFFF; MAX_SINK_GROUPS],
            group_count: 0,
        }
    }

    /// Endpoint-match test.
    ///
    /// Requirement `14-0563-19-A36-06`.
    #[must_use]
    pub const fn covers(&self, id: GpdId) -> bool {
        if self.id != id.table_key() {
            return false;
        }
        match id {
            GpdId::SrcId(_) => true,
            GpdId::Ieee { endpoint, .. } => {
                self.endpoint == 0x00 || self.endpoint == 0xFF || self.endpoint == endpoint
            }
        }
    }
}

/// Bounded sink table.
///
/// Requirement `14-0563-19-A36-06`.
#[derive(Debug)]
pub struct SinkTable<const N: usize> {
    entries: [Option<SinkTableEntry>; N],
}

impl<const N: usize> SinkTable<N> {
    /// Empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    /// Number of populated rows.
    #[must_use]
    pub const fn len(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < N {
            if self.entries[i].is_some() {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// True when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Find the entry covering one GPD identity.
    #[must_use]
    pub fn find(&self, id: GpdId) -> Option<&SinkTableEntry> {
        self.entries.iter().flatten().find(|e| e.covers(id))
    }

    /// Find the entry covering one GPD identity (mutable).
    pub fn find_mut(&mut self, id: GpdId) -> Option<&mut SinkTableEntry> {
        self.entries.iter_mut().flatten().find(|e| e.covers(id))
    }

    /// Insert or overwrite the entry for one GPD identity.
    ///
    /// Requirement `14-0563-19-A36-06`.
    pub fn upsert(&mut self, entry: SinkTableEntry) -> Result<(), GpError> {
        let mut i = 0;
        while i < N {
            let same = match self.entries[i] {
                Some(e) => e.id == entry.id && e.endpoint == entry.endpoint,
                None => false,
            };
            if same {
                self.entries[i] = Some(entry);
                return Ok(());
            }
            i += 1;
        }
        let mut j = 0;
        while j < N {
            if self.entries[j].is_none() {
                self.entries[j] = Some(entry);
                return Ok(());
            }
            j += 1;
        }
        Err(GpError::TableFull)
    }
}

impl<const N: usize> Default for SinkTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Translated command ready for a paired local endpoint.
///
/// Requirement `14-0563-19-A36-06` (translate and send to the paired
/// endpoints).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranslatedCommand {
    /// Paired local endpoint (`0xFC` = raw pass-up to the app,
    /// `0xFD` = no paired endpoints, `0xFF` = all matching).
    pub endpoint: u8,
    /// Target profile identifier.
    pub profile: u16,
    /// Target cluster identifier.
    pub cluster: u16,
    /// Target command identifier.
    pub command: u8,
    /// Payload formation rule.
    pub payload_mode: PayloadMode,
    /// Payload bytes (template or copied trigger payload).
    pub payload: [u8; MAX_TRANSLATION_PAYLOAD],
    /// Valid payload bytes.
    pub payload_len: u8,
}

impl TranslatedCommand {
    /// Payload slice.
    #[must_use]
    pub const fn payload_bytes(&self) -> &[u8] {
        self.payload.split_at(self.payload_len as usize).0
    }
}

/// Sink outcome for one accepted tunneled command.
///
/// Requirement `14-0563-19-A36-06`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkOutcome {
    /// Frame dropped with the recorded reason.
    Drop(GpError),
    /// Group-bound command re-emitted for the paired groups.
    ForwardGroup {
        /// Canonical GPD key.
        gpd: u64,
        /// Command identifier.
        command: u8,
        /// Group address index into the sink-table entry.
        group: u16,
    },
    /// Command translated for the paired local endpoints.
    Translate(TranslatedCommand),
}

/// Sink role machine: counter check, sink-table match, group
/// forwarding, and translation.
///
/// Requirement `14-0563-19-A36-06`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SinkMachine {
    /// Whether this sink supports bidirectional operation.
    pub bidir_capable: bool,
}

impl SinkMachine {
    /// Build the role machine.
    #[must_use]
    pub const fn new(bidir_capable: bool) -> Self {
        Self { bidir_capable }
    }

    /// Accept one tunneled command: security match, freshness check,
    /// then group forwarding and/or translation.
    ///
    /// Requirements `14-0563-19-A36-06`, `-A36-05`, `-A36-07`.
    #[allow(clippy::too_many_arguments)]
    pub fn accept<const ST: usize, const TT: usize, const RN: usize>(
        &self,
        id: GpdId,
        level: WireSecurityLevel,
        key_bit: bool,
        counter: Option<u32>,
        command: u8,
        command_payload: &[u8],
        contact: u8,
        sink_table: &mut SinkTable<ST>,
        translations: &TranslationTable<TT>,
        replay: &mut crate::security::GpReplay<RN>,
    ) -> SinkOutcome {
        let Some(entry) = sink_table.find_mut(id) else {
            return SinkOutcome::Drop(GpError::NoTableEntry);
        };
        if entry.level != level || entry.key_bit != key_bit {
            return SinkOutcome::Drop(GpError::SecurityFailed);
        }
        if let Some(c) = counter {
            if replay.check(id.table_key(), c).is_err() {
                return SinkOutcome::Drop(GpError::SecurityFailed);
            }
            entry.counter = c;
        }
        // Group-bound entries forward before translation.
        if entry.group_forward && entry.group_count > 0 {
            return SinkOutcome::ForwardGroup {
                gpd: id.table_key(),
                command,
                group: entry.groups[0],
            };
        }
        let Some(t) = translations.lookup(id, command, contact) else {
            // No translation covers this command: accepted but with
            // no local target — report as untranslatable drop so the
            // caller can account for it distinctly from security.
            return SinkOutcome::Drop(GpError::NotFound);
        };
        let mut out = TranslatedCommand {
            endpoint: t.endpoint,
            profile: t.profile,
            cluster: t.cluster,
            command: t.command,
            payload_mode: t.payload_mode,
            payload: [0u8; MAX_TRANSLATION_PAYLOAD],
            payload_len: 0,
        };
        match t.payload_mode {
            PayloadMode::None | PayloadMode::Parsed => {}
            PayloadMode::Fixed => {
                let n = t.payload_len as usize;
                out.payload[..n].copy_from_slice(&t.payload[..n]);
                out.payload_len = t.payload_len;
            }
            PayloadMode::VerbatimCopy => {
                let n = command_payload.len().min(MAX_TRANSLATION_PAYLOAD);
                out.payload[..n].copy_from_slice(&command_payload[..n]);
                out.payload_len = n as u8;
            }
        }
        SinkOutcome::Translate(out)
    }
}
