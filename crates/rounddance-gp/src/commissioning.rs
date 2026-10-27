//! Commissioning flows: mode entry points, translation-table
//! population, and bidirectional-completion stubs.
//!
//! Paraphrase-level model of doc `14-0563-19` §A.1.7.3 (GPD-side
//! commissioning; anchors p0069-L1906-L1934), §A.3.6.2.2 (table
//! growth on commissioning and pairing configuration; anchors
//! p0191-L5380-L5394) and §A.3.9 (commissioning behavior, entry
//! points). All wording here is paraphrase (D1, `SCOPE.md` §2).
//!
//! Translation-table commissioning lands in this wave: successful
//! unidirectional commissioning and pairing-configuration flows
//! populate [`crate::sink::TranslationTable`] entries. Bidirectional
//! completion (configuration replies delivered to the GPD) is
//! structures plus explicit stubs — the reply path is a follow-up
//! wave.
//!
//! Requirement IDs below are corpus-mined `14-0563-19-*`.

use crate::frame::{AppId, GpError};
use crate::sink::{TranslationTableEntry, COMPACT_SENSOR_GROUP_CMD};

/// First commissioning-range command identifier.
///
/// Requirement `14-0563-19-A152-03`.
pub const COMMISSIONING_RANGE_START: u8 = 0xF0;

/// Last commissioning-range command identifier.
///
/// Requirement `14-0563-19-A152-03`.
pub const COMMISSIONING_RANGE_END: u8 = 0xFF;

/// True for commissioning-range command identifiers.
///
/// Requirement `14-0563-19-A152-03`.
#[must_use]
pub const fn is_commissioning_command(command: u8) -> bool {
    // `COMMISSIONING_RANGE_END` is `u8::MAX`, so the lower bound is
    // the whole test.
    command >= COMMISSIONING_RANGE_START
}

/// Commissioning entry-point announcement decoded from a commissioning
/// frame: which follow-ups the GPD asks for.
///
/// Requirement `14-0563-19-A36-07` (commissioning drives table
/// population) plus GPD-side option semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommissioningAnnouncement {
    /// Identity scheme of the commissioning GPD.
    pub app: AppId,
    /// Canonical GPD key.
    pub gpd: u64,
    /// Endpoint (IEEE identities).
    pub endpoint: u8,
    /// GPD requests network parameters (PAN identifier, ...).
    pub pan_id_request: bool,
    /// GPD requests the network key.
    pub key_request: bool,
    /// GPD opens a receive window after transmitting.
    pub rx_after_tx: bool,
    /// Security level the GPD can support.
    pub security_capable: bool,
    /// Key carried in the clear inside the commissioning payload.
    pub key_present: bool,
}

/// Commissioning-mode entry point flavors.
///
/// Requirement `14-0563-19-A36-03` (commissioning behavior while
/// commissioned).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommissioningMode {
    /// One-way: GPD announces, network populates tables, no reply.
    Unidirectional,
    /// Two-way: GPD opens a receive window for configuration replies.
    Bidirectional,
}

/// Session state for one GPD commissioning exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommissioningState {
    /// No exchange in progress.
    Idle,
    /// Announcement received; tables being populated.
    Collecting,
    /// Unidirectional exchange complete.
    Commissioned,
    /// Bidirectional exchange waiting on the reply path (stub).
    AwaitingReply,
}

/// Typed failure for commissioning operations.
pub use crate::frame::GpError as CommissioningError;

/// Seed record describing one translation entry to create on
/// successful commissioning or pairing configuration.
///
/// Requirement `14-0563-19-A36-07`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranslationSeed {
    /// Identity scheme.
    pub app: AppId,
    /// GPD identity (wildcard for generic seeds).
    pub gpd: u64,
    /// Endpoint scope.
    pub endpoint: u8,
    /// GPD command covered (`0xFF` = all).
    pub gpd_command: u8,
    /// Target profile identifier.
    pub profile: u16,
    /// Target cluster identifier.
    pub cluster: u16,
    /// Target command identifier.
    pub command: u8,
}

impl TranslationSeed {
    /// Expand into a concrete translation-table entry with no
    /// payload template and no contact option.
    ///
    /// Requirement `14-0563-19-A36-07`.
    #[must_use]
    pub const fn materialize(self) -> TranslationTableEntry {
        TranslationTableEntry {
            app: self.app,
            gpd: self.gpd,
            endpoint: self.endpoint,
            gpd_command: self.gpd_command,
            profile: self.profile,
            cluster: self.cluster,
            command: self.command,
            payload_mode: crate::sink::PayloadMode::VerbatimCopy,
            payload: [0u8; crate::sink::MAX_TRANSLATION_PAYLOAD],
            payload_len: 0,
            vector: None,
        }
    }
}

/// Commissioning session machine for one GPD.
///
/// Unidirectional sessions run to completion and emit translation
/// seeds; bidirectional sessions park in [`CommissioningState::AwaitingReply`]
/// and report [`GpError::BidirectionalPending`] until the follow-up
/// reply path lands.
///
/// Requirement `14-0563-19-A36-07`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommissioningSession {
    state: CommissioningState,
    mode: CommissioningMode,
    gpd: u64,
    app: AppId,
    endpoint: u8,
}

impl CommissioningSession {
    /// Idle session.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: CommissioningState::Idle,
            mode: CommissioningMode::Unidirectional,
            gpd: 0,
            app: AppId::SrcId,
            endpoint: 0xFF,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> CommissioningState {
        self.state
    }

    /// Begin an exchange from a commissioning announcement.
    ///
    /// Requirement `14-0563-19-A36-07`.
    pub const fn begin(&mut self, ann: CommissioningAnnouncement) {
        self.gpd = ann.gpd;
        self.app = ann.app;
        self.endpoint = ann.endpoint;
        self.mode = if ann.rx_after_tx && (ann.pan_id_request || ann.key_request) {
            CommissioningMode::Bidirectional
        } else {
            CommissioningMode::Unidirectional
        };
        self.state = CommissioningState::Collecting;
    }

    /// Finish collection: unidirectional sessions commission and
    /// expose the seeds for one default translation entry
    /// (all-commands wildcard); bidirectional sessions park awaiting
    /// the reply path.
    ///
    /// Requirement `14-0563-19-A36-07`.
    pub const fn complete(&mut self) -> Result<Option<TranslationSeed>, GpError> {
        match self.state {
            CommissioningState::Collecting => match self.mode {
                CommissioningMode::Unidirectional => {
                    self.state = CommissioningState::Commissioned;
                    Ok(Some(TranslationSeed {
                        app: self.app,
                        gpd: self.gpd,
                        endpoint: self.endpoint,
                        gpd_command: crate::sink::GENERIC_GPD_COMMAND,
                        profile: 0x0104,
                        cluster: 0xFFFF,
                        command: 0x00,
                    }))
                }
                CommissioningMode::Bidirectional => {
                    self.state = CommissioningState::AwaitingReply;
                    Err(GpError::BidirectionalPending)
                }
            },
            _ => Err(GpError::BadState),
        }
    }

    /// Bidirectional reply builder (stub): the reply path is a
    /// follow-up wave; this always reports pending.
    pub const fn build_reply(&self, _out: &mut [u8]) -> Result<usize, GpError> {
        Err(GpError::BidirectionalPending)
    }

    /// Sensor-report helper: compact-group seed covering the
    /// sensor-report command set for one GPD.
    ///
    /// Requirement `14-0563-19-A36-08`.
    #[must_use]
    pub const fn sensor_group_seed(&self) -> TranslationSeed {
        TranslationSeed {
            app: self.app,
            gpd: self.gpd,
            endpoint: self.endpoint,
            gpd_command: COMPACT_SENSOR_GROUP_CMD,
            profile: 0x0104,
            cluster: 0xFFFF,
            command: 0x00,
        }
    }

    /// Reset to idle.
    pub const fn reset(&mut self) {
        self.state = CommissioningState::Idle;
    }
}

impl Default for CommissioningSession {
    fn default() -> Self {
        Self::new()
    }
}
