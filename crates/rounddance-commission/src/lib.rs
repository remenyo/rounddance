//! Commissioning: network formation, steering, finding & binding,
//! Touchlink, and classical Trust-Center join.
//!
//! Paraphrase-level models of doc `22-65816-030` BDB v3.1 (§§5.6–5.7,
//! §6.1, §8, §9, §§11–12), doc `05-3474-23` R23.2 §3.6.1 family, and
//! doc `07-5123-08` ZCL §13.3. All wording here is paraphrase;
//! citations name document, revision, and clause/line only (D1,
//! `SCOPE.md` §2).
//!
//! # Design notes (mirror `rounddance-nwk` / `rounddance-aps` /
//! `rounddance-zdo` / `rounddance-security`)
//!
//! * `no_std` + `#![forbid(unsafe_code)]`, bounded + fallible +
//!   accountable: surveys, respondent sets, transcripts, and tables
//!   live in fixed-size arrays; every fallible path returns a typed
//!   error.
//! * Thin orchestration: key storage, counters, descriptors, and
//!   binding tables stay in their owning crates; this crate only
//!   sequences them.
//! * Time is never read: join windows and identify timers advance on
//!   caller ticks, so sim virtual time drives everything
//!   deterministically.
//! * Every public item cites the requirement ID it implements
//!   (corpus-mined `22-65816-030-*` or repo-minted
//!   `05-3474-23-<clause>-<seq>` / `07-5123-08-<clause>-<seq>`, dots
//!   stripped, MINTED-pending-confirm).
#![no_std]
#![forbid(unsafe_code)]

pub mod classical;
pub mod finding;
pub mod formation;
pub mod steering;
pub mod touchlink;

pub use classical::{
    EccJoinKdf, InstallCode, JoinError, JoinKdf, JoinMethod, JoinPolicy, JoinedDevice,
    JoinerMachine, JoinerState, KeyAttributes, LeaveMachine, RejoinMachine, RejoinState,
    TrustCenter, INSTALL_CODE_LENS, MAX_INSTALL_CODE_LEN, MAX_JOINED_DEVICES,
};
pub use finding::{
    FinderInitiator, FinderTarget, FindingError, InitiatorState, Respondent, TargetState,
    IDENTIFY_QUERY_BROADCAST, MAX_MATCHED_CLUSTERS, MAX_RESPONDENTS,
};
pub use formation::{
    ChannelMask, FirstFreePan, FormationConfig, FormationError, FormationMachine, FormationPolicy,
    FormationRequest, FormationState, LogicalType, PanChoice, CHANNEL_MAX, CHANNEL_MIN,
    FORMATION_BEACON_ORDER, FORMATION_SUPERFRAME_ORDER, MAX_SCAN_CHANNELS,
};
pub use steering::{
    BaselineSteeringPolicy, BeaconSurveyEntry, DiscoveryScan, SteeringMachine, SteeringPolicy,
    SteeringState, SurveyError, SurveyTable, MAX_SURVEY_ENTRIES,
};
pub use touchlink::{
    InterPanTx, ScanRequestPayload, TouchlinkError, TouchlinkFrame, TouchlinkInitiator,
    TouchlinkInitiatorState, TouchlinkTarget, TouchlinkTargetState, MAX_TOUCHLINK_FRAME,
    MAX_TOUCHLINK_PAYLOAD, TOUCHLINK_CLUSTER, TOUCHLINK_PROFILE, TOUCHLINK_UTILITY_PROFILE,
};

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-commission"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
    }
}
