//! Commissioning flows: mode entry points, translation-table
//! population, and bidirectional-completion stubs.
//!
//! Paraphrase-level model of doc `14-0563-19` §A.1.7.3 (GPD-side
//! commissioning; anchors p0069-L1906-L1934), §A.3.6.2.2 (table
//! growth on commissioning and pairing configuration; anchors
//! p0191-L5380-L5394) and §A.3.9 (commissioning behavior, entry
//! points). All wording here is paraphrase (D1, `SCOPE.md` §2).
//!
//! Translation-table commissioning: successful unidirectional and
//! bidirectional commissioning flows populate
//! [`crate::sink::TranslationTable`] entries. The bidirectional reply
//! path (configuration replies delivered to the GPD inside its
//! receive window, completed by the GPD's Success frame) is fully
//! implemented here plus [`crate::reply`].
//!
//! Requirement IDs below are corpus-mined `14-0563-19-*`, plus
//! repo-minted `14-0563-19-A173-*` / `-A4212-*` (MINTED-pending-confirm).

use crate::frame::{AppId, GpError};
use crate::reply::CommissioningReply;
use crate::sink::{TranslationTableEntry, COMPACT_SENSOR_GROUP_CMD};

/// Bidirectional reply window in milliseconds: the exchange lapses
/// when no Success frame arrives within this bound after collection.
///
/// Requirement `14-0563-19-A173-02` (repo-minted).
pub const REPLY_TIMEOUT_MS: u64 = 5_000;

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

/// Check the GPD's request flags for reply deliverability: a key
/// request with no receive window, or with no security capability
/// behind it, can never be answered, so the exchange is refused.
///
/// Requirement `14-0563-19-A173-01` (repo-minted).
pub const fn check_bidir_capable(ann: CommissioningAnnouncement) -> Result<(), GpError> {
    if ann.key_request && (!ann.rx_after_tx || !ann.security_capable) {
        return Err(GpError::PeerIncapable);
    }
    Ok(())
}

/// Commissioning session machine for one GPD.
///
/// Unidirectional sessions run to completion and emit translation
/// seeds; bidirectional sessions park in [`CommissioningState::AwaitingReply`]
/// with a bounded reply window, serve one staged reply, and complete
/// when the GPD's Success frame arrives.
///
/// Requirements `14-0563-19-A36-07`, `-A173-01`, `-A173-02`,
/// `-A4212-02` (last three repo-minted).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommissioningSession {
    state: CommissioningState,
    mode: CommissioningMode,
    gpd: u64,
    app: AppId,
    endpoint: u8,
    key_request: bool,
    rx_after_tx: bool,
    security_capable: bool,
    pending: Option<CommissioningReply>,
    deadline_ms: u64,
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
            key_request: false,
            rx_after_tx: false,
            security_capable: false,
            pending: None,
            deadline_ms: 0,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> CommissioningState {
        self.state
    }

    /// Reply-window deadline in caller milliseconds (`u64::MAX` when
    /// no bidirectional exchange is parked).
    #[must_use]
    pub const fn deadline_ms(&self) -> u64 {
        match self.state {
            CommissioningState::AwaitingReply => self.deadline_ms,
            _ => u64::MAX,
        }
    }

    /// True when a reply is staged and ready to serve.
    #[must_use]
    pub const fn reply_staged(&self) -> bool {
        self.pending.is_some()
    }

    /// Begin an exchange from a commissioning announcement.
    ///
    /// Requirement `14-0563-19-A36-07`.
    pub const fn begin(&mut self, ann: CommissioningAnnouncement) {
        self.gpd = ann.gpd;
        self.app = ann.app;
        self.endpoint = ann.endpoint;
        self.key_request = ann.key_request;
        self.rx_after_tx = ann.rx_after_tx;
        self.security_capable = ann.security_capable;
        self.mode = if ann.rx_after_tx && (ann.pan_id_request || ann.key_request) {
            CommissioningMode::Bidirectional
        } else {
            CommissioningMode::Unidirectional
        };
        self.pending = None;
        self.deadline_ms = 0;
        self.state = CommissioningState::Collecting;
    }

    /// Finish collection at clock `now_ms`: unidirectional sessions
    /// commission and expose the seeds for one default translation
    /// entry (all-commands wildcard); bidirectional sessions park
    /// awaiting the reply path with a bounded window.
    ///
    /// A key request the GPD cannot receive (no window, or no
    /// security capability) refuses with [`GpError::PeerIncapable`]
    /// in either mode and the session returns to idle.
    ///
    /// Requirements `14-0563-19-A36-07`, `-A173-01`, `-A173-02`.
    pub const fn complete_at(&mut self, now_ms: u64) -> Result<Option<TranslationSeed>, GpError> {
        match self.state {
            CommissioningState::Collecting => {
                if self.key_request && (!self.rx_after_tx || !self.security_capable) {
                    self.state = CommissioningState::Idle;
                    return Err(GpError::PeerIncapable);
                }
                match self.mode {
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
                        self.deadline_ms = now_ms.saturating_add(REPLY_TIMEOUT_MS);
                        Err(GpError::BidirectionalPending)
                    }
                }
            }
            _ => Err(GpError::BadState),
        }
    }

    /// Finish collection at clock zero (see [`Self::complete_at`]).
    ///
    /// Requirement `14-0563-19-A36-07`.
    pub const fn complete(&mut self) -> Result<Option<TranslationSeed>, GpError> {
        self.complete_at(0)
    }

    /// Stage the reply to serve inside the GPD's receive window.
    /// Only valid while awaiting the reply; shape-checked on intake.
    ///
    /// Requirement `14-0563-19-A4212-02` (repo-minted).
    pub const fn stage_reply(&mut self, reply: CommissioningReply) -> Result<(), GpError> {
        match self.state {
            CommissioningState::AwaitingReply => match reply.check_shape() {
                Ok(()) => {
                    self.pending = Some(reply);
                    Ok(())
                }
                Err(e) => Err(e),
            },
            _ => Err(GpError::BadState),
        }
    }

    /// Encode the staged reply into the caller buffer for
    /// transmission inside the receive window. Reports pending while
    /// nothing is staged yet.
    ///
    /// Requirement `14-0563-19-A4212-02` (repo-minted).
    pub fn build_reply(&self, out: &mut [u8]) -> Result<usize, GpError> {
        match self.state {
            CommissioningState::AwaitingReply => match self.pending {
                Some(reply) => reply.encode_into(out),
                None => Err(GpError::BidirectionalPending),
            },
            _ => Err(GpError::BadState),
        }
    }

    /// Record the GPD's Success frame: identity must match the parked
    /// exchange, else the frame belongs to another transaction and is
    /// refused. On match the session commissions and emits the
    /// default translation seed.
    ///
    /// Requirement `14-0563-19-A4212-02` (repo-minted).
    pub const fn note_success(
        &mut self,
        gpd: u64,
        endpoint: u8,
    ) -> Result<Option<TranslationSeed>, GpError> {
        match self.state {
            CommissioningState::AwaitingReply => {
                if gpd != self.gpd || endpoint != self.endpoint {
                    return Err(GpError::TransactionMismatch);
                }
                self.state = CommissioningState::Commissioned;
                self.pending = None;
                self.deadline_ms = 0;
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
            _ => Err(GpError::BadState),
        }
    }

    /// Age the parked exchange against clock `now_ms`: past the reply
    /// window the session returns to idle and reports
    /// [`GpError::ReplyTimeout`].
    ///
    /// Requirement `14-0563-19-A173-02` (repo-minted).
    pub const fn tick(&mut self, now_ms: u64) -> Result<(), GpError> {
        match self.state {
            CommissioningState::AwaitingReply => {
                if now_ms >= self.deadline_ms {
                    self.state = CommissioningState::Idle;
                    self.pending = None;
                    self.deadline_ms = 0;
                    return Err(GpError::ReplyTimeout);
                }
                Ok(())
            }
            _ => Ok(()),
        }
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

    /// Reset to idle, dropping any staged reply, the reply window,
    /// and the parked exchange identity: outside the reply window no
    /// reply is owed and no window runs.
    pub const fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for CommissioningSession {
    fn default() -> Self {
        Self::new()
    }
}
