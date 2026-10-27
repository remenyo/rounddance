//! Finding and binding: initiator/target commissioning flows.
//!
//! Paraphrase-level model of doc `22-65816-030` BDB v3.1 §11 + §§11.1–11.2
//! (roles, target identify window, initiator query/respondent logging,
//! descriptor pull + cluster match, unicast/group binding; anchors
//! p0079-L1699-L1712, p0082-L1725-L1765). All wording here is paraphrase
//! (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are corpus-mined (`22-65816-030-111-01`
//! through `-111-04`).
//!
//! The flows are wired to [`rounddance_zdo`] discovery/binding types
//! (`Match_Desc_req`, `Bind_req` entries) so the APS binding tables
//! fill through the same [`rounddance_zdo::BindManager`] path the ZDO
//! layer owns — no parallel binding store here.

use rounddance_zdo::{BindDstMode, BindEntry, MatchDescReq};

/// Broadcast address the initiator's identify query goes to
/// (`22-65816-030-111-02`: all-nodes broadcast).
pub const IDENTIFY_QUERY_BROADCAST: u16 = 0xffff;
/// Largest respondent set the initiator logs (declared budget).
pub const MAX_RESPONDENTS: usize = 16;
/// Largest matched-cluster set per endpoint (declared budget; bounded
/// by the simple-descriptor cluster budget).
pub const MAX_MATCHED_CLUSTERS: usize = 16;

/// Finding/binding failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingError {
    /// Target must already be on-network to commission
    /// (`22-65816-030-111-01`).
    TargetOffNetwork,
    /// Initiator must be on-network to commission
    /// (`22-65816-030-111-02`).
    InitiatorOffNetwork,
    /// No respondent answered the identify queries
    /// (`22-65816-030-111-02`).
    NoRespondents,
    /// Respondent set is full.
    TableFull,
    /// Operation not allowed in the current state.
    BadState,
    /// Respondent long address is unknown and was not resolved first
    /// (`22-65816-030-111-04`).
    UnknownIeee,
    /// Binding table has no room (`22-65816-030-111-04`: a full table
    /// fails the procedure).
    BindingTableFull,
    /// No cluster matched for this endpoint; move to the next one
    /// (`22-65816-030-111-03`).
    NoMatch,
}

/// One logged respondent: network address from the network header plus
/// endpoint from the APS header (`22-65816-030-111-02`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Respondent {
    /// Network address read off the answering frame's network header.
    pub nwk_addr: u16,
    /// Endpoint read off the answering frame's APS header.
    pub endpoint: u8,
    /// Long address if already known (resolution is the initiator's
    /// job before binding; `None` until then).
    pub ieee: Option<u64>,
}

/// Target-side commissioning: identify window + follow-on service.
///
/// Requirement `22-65816-030-111-01`: roles follow cluster class; the
/// target must already be on-network, holds its identify timer at or
/// above the configured commissioning window, answers identify queries
/// while the timer runs, services follow-on descriptor requests
/// regardless of identify state, and finishes when the timer hits zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetState {
    /// Not commissioning.
    Idle,
    /// Identify timer running (`remaining_s` > 0).
    Identifying {
        /// Seconds left in the commissioning window.
        remaining_s: u32,
    },
    /// Window elapsed; procedure finished.
    Done,
}

/// Target-side driver.
#[derive(Debug, Clone, Copy)]
pub struct FinderTarget {
    state: TargetState,
}

impl FinderTarget {
    /// Create idle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: TargetState::Idle,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> TargetState {
        self.state
    }

    /// Start the commissioning window: fails off-network
    /// (`22-65816-030-111-01`).
    pub fn start(&mut self, on_network: bool, window_s: u32) -> Result<(), FindingError> {
        if !on_network {
            return Err(FindingError::TargetOffNetwork);
        }
        if window_s == 0 {
            return Err(FindingError::BadState);
        }
        self.state = TargetState::Identifying {
            remaining_s: window_s,
        };
        Ok(())
    }

    /// Whether an incoming identify query is answered (only while the
    /// timer runs).
    #[must_use]
    pub const fn answer_identify(&self) -> bool {
        matches!(self.state, TargetState::Identifying { .. })
    }

    /// Whether a follow-on descriptor request is serviced (always:
    /// descriptor answers are normal device behavior, independent of
    /// the identify timer).
    #[must_use]
    pub const fn serves_descriptors(&self) -> bool {
        let _ = self.state;
        true
    }

    /// Advance the identify timer by one second; ANS true when the
    /// window just hit zero (procedure finishes).
    pub fn tick_1s(&mut self) -> bool {
        match self.state {
            TargetState::Identifying { remaining_s } => {
                if remaining_s <= 1 {
                    self.state = TargetState::Done;
                    true
                } else {
                    self.state = TargetState::Identifying {
                        remaining_s: remaining_s - 1,
                    };
                    false
                }
            }
            _ => false,
        }
    }
}

impl Default for FinderTarget {
    fn default() -> Self {
        Self::new()
    }
}

/// Initiator sequencing.
///
/// Initiator requirements in brief:
///
/// - `22-65816-030-111-02`: off-network fails; broadcast identify
///   queries, repeatable; no answers fail; log network address and
///   endpoint per answer.
/// - `22-65816-030-111-03`: per-endpoint unicast simple-descriptor
///   pull; missing/unsuccessful answers advance to the next endpoint;
///   supported clusters advance, others skipped.
/// - `22-65816-030-111-04`: one binding-table entry per matched
///   cluster; unknown respondent long addresses resolved first; group
///   mode 0x01 plus group id pushed to the target; unicast mode 0x03
///   plus address/endpoint; full table fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiatorState {
    /// Created.
    Idle,
    /// Broadcasting identify queries.
    Querying,
    /// Queries closed; walking respondents/endpoints.
    Matching,
    /// At least one binding entry requested; more may follow.
    Binding,
    /// All matched endpoints bound.
    Done,
    /// Terminal failure (see [`FinderInitiator::error`]).
    Failed,
}

/// Initiator-side driver.
#[derive(Debug, Clone)]
pub struct FinderInitiator {
    state: InitiatorState,
    error: Option<FindingError>,
    respondents: [Option<Respondent>; MAX_RESPONDENTS],
    respondent_len: usize,
}

impl FinderInitiator {
    /// Create idle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: InitiatorState::Idle,
            error: None,
            respondents: [None; MAX_RESPONDENTS],
            respondent_len: 0,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> InitiatorState {
        self.state
    }

    /// Terminal failure cause, if any.
    #[must_use]
    pub const fn error(&self) -> Option<FindingError> {
        self.error
    }

    /// Logged respondents in answer order.
    pub fn respondents(&self) -> impl Iterator<Item = &Respondent> {
        self.respondents.iter().filter_map(|r| r.as_ref())
    }

    /// How many respondents are logged.
    #[must_use]
    pub const fn respondent_count(&self) -> usize {
        self.respondent_len
    }

    fn fail(&mut self, err: FindingError) {
        self.state = InitiatorState::Failed;
        self.error = Some(err);
    }

    /// Begin: an off-network initiator fails immediately
    /// (`22-65816-030-111-02`).
    pub fn begin(&mut self, on_network: bool) {
        if self.state != InitiatorState::Idle {
            self.fail(FindingError::BadState);
            return;
        }
        if !on_network {
            self.fail(FindingError::InitiatorOffNetwork);
            return;
        }
        self.state = InitiatorState::Querying;
    }

    /// Log one identify answer (network address from the network
    /// header, endpoint from the APS header). Repeatable while
    /// querying.
    pub fn note_answer(&mut self, nwk_addr: u16, endpoint: u8) {
        if self.state != InitiatorState::Querying {
            return;
        }
        if self.respondent_len >= MAX_RESPONDENTS {
            self.fail(FindingError::TableFull);
            return;
        }
        if let Some(slot) = self.respondents.iter_mut().find(|r| r.is_none()) {
            *slot = Some(Respondent {
                nwk_addr,
                endpoint,
                ieee: None,
            });
            self.respondent_len += 1;
        } else {
            self.fail(FindingError::TableFull);
        }
    }

    /// Close the query round: with no answers the procedure fails;
    /// otherwise matching begins (`22-65816-030-111-02`).
    pub fn finish_queries(&mut self) {
        if self.state != InitiatorState::Querying {
            self.fail(FindingError::BadState);
            return;
        }
        if self.respondent_len == 0 {
            self.fail(FindingError::NoRespondents);
        } else {
            self.state = InitiatorState::Matching;
        }
    }

    /// Attach a resolved long address to a logged respondent (the
    /// `22-65816-030-111-04` resolve-before-bind step).
    pub fn resolve_ieee(&mut self, nwk_addr: u16, endpoint: u8, ieee: u64) -> bool {
        let mut found = false;
        for slot in self.respondents.iter_mut().flatten() {
            if slot.nwk_addr == nwk_addr && slot.endpoint == endpoint {
                slot.ieee = Some(ieee);
                found = true;
            }
        }
        found
    }

    /// Build the per-endpoint unicast simple-descriptor pull for a
    /// respondent (`22-65816-030-111-03`: addressed by network address
    /// and endpoint).
    #[must_use]
    pub const fn match_request_for(
        tsn: u8,
        respondent: &Respondent,
        profile_id: u16,
    ) -> MatchDescReq {
        MatchDescReq {
            tsn,
            nwk_of_interest: respondent.nwk_addr,
            profile_id,
            in_clusters: [0; rounddance_zdo::MAX_SIMPLE_CLUSTERS],
            in_len: 0,
            out_clusters: [0; rounddance_zdo::MAX_SIMPLE_CLUSTERS],
            out_len: 0,
        }
    }

    /// Intersect one endpoint's application clusters with the
    /// initiator's supported set: supported clusters advance to binding
    /// (written to `matched`, returns the count), unsupported ones are
    /// skipped, and an empty intersection reports `NoMatch` so the
    /// initiator moves to the next endpoint
    /// (`22-65816-030-111-03`).
    pub fn match_clusters(
        &self,
        endpoint_clusters: &[u16],
        supported: &[u16],
        matched: &mut [u16],
    ) -> Result<usize, FindingError> {
        if !matches!(
            self.state,
            InitiatorState::Matching | InitiatorState::Binding
        ) {
            return Err(FindingError::BadState);
        }
        let mut n = 0;
        for &cluster in endpoint_clusters {
            if n >= matched.len() || n >= MAX_MATCHED_CLUSTERS {
                break;
            }
            if supported.contains(&cluster) && !matched[..n].contains(&cluster) {
                matched[n] = cluster;
                n += 1;
            }
        }
        if n == 0 {
            return Err(FindingError::NoMatch);
        }
        Ok(n)
    }

    /// Build the bind entry for one matched cluster: group bindings use
    /// mode 0x01 plus the group id (also pushed to the target via the
    /// returned `push_group_to_target` flag); unicast bindings use mode
    /// 0x03 plus the respondent address and endpoint, and require the
    /// long address to be resolved first (`22-65816-030-111-04`).
    pub fn bind_entry_for(
        &mut self,
        tsn: u8,
        local_ieee: u64,
        local_endpoint: u8,
        respondent: &Respondent,
        cluster_id: u16,
        group: Option<u16>,
    ) -> Result<(BindEntry, bool), FindingError> {
        if !matches!(
            self.state,
            InitiatorState::Matching | InitiatorState::Binding
        ) {
            return Err(FindingError::BadState);
        }
        let (dst, push_group_to_target) = match group {
            Some(group_addr) => (BindDstMode::Group { group_addr }, true),
            None => match respondent.ieee {
                Some(dst_ieee) => (
                    BindDstMode::Extended {
                        dst_ieee,
                        dst_endpoint: respondent.endpoint,
                    },
                    false,
                ),
                None => return Err(FindingError::UnknownIeee),
            },
        };
        self.state = InitiatorState::Binding;
        Ok((
            BindEntry {
                tsn,
                src_ieee: local_ieee,
                src_endpoint: local_endpoint,
                cluster_id,
                dst,
            },
            push_group_to_target,
        ))
    }

    /// Mark all matched endpoints bound: the procedure is done.
    pub fn finish_binding(&mut self) {
        if self.state == InitiatorState::Binding {
            self.state = InitiatorState::Done;
        } else {
            self.fail(FindingError::BadState);
        }
    }
}

impl Default for FinderInitiator {
    fn default() -> Self {
        Self::new()
    }
}
