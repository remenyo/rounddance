//! Zigbee Direct: GATT-service commissioning over BLE.
//!
//! Paraphrase-level model of doc `20-27688-041` Zigbee Direct v1.1
//! (roles §5.3/5.4, provisioning §§6.2–6.3, BLE security §§6.4–6.5,
//! discovery §§7.5–7.6, commissioning/tunnel services §§7.7.2–7.7.3).
//! All wording here is paraphrase; citations name document, revision,
//! and clause/page only (D1, `SCOPE.md` §2). Numeric identifiers
//! (service/characteristic UUIDs, TLV IDs, status domains) are
//! normative values cited by clause, matching repo practice for
//! cluster/profile IDs.
//!
//! Requirement IDs: corpus-mined `20-27688-041-*` (page+clause
//! anchored, `reconcile` for exact wording — the extraction carries
//! no printed body line numbers).
//!
//! # Design notes (mirror `rounddance-commission`)
//!
//! * `no_std` + `#![forbid(unsafe_code)]`, bounded + fallible +
//!   accountable: descriptors, TLV buffers, session slots, and
//!   transcripts live in fixed-size arrays; every fallible path
//!   returns a typed error.
//! * No BLE stack dependency: [`gatt`] describes the service model
//!   as data (service/characteristic descriptors a host or ESP BLE
//!   shim instantiates); the HAL owns the controller (radio-SDK
//!   ceiling, `SCOPE.md` §3).
//! * Key material stays in owning crates: install-code validation
//!   and derivation reuse `rounddance_commission`, key rotation
//!   reuses `rounddance_security::keyupdate`.
//! * Time is never read: advertisement, establishment, and
//!   commissioning timeouts advance on caller ticks, so sim virtual
//!   time drives everything deterministically.
//!
//! # Crate-vs-submodule justification
//!
//! Direct lives in its own crate (not a `rounddance-commission`
//! submodule) because it is a separate transport workstream with
//! its own bounded domain — GATT service descriptors, the TLV
//! attribute codec, BLE session/counter discipline, and BLE
//! advertisement records — none of which belong in the 15.4
//! commissioning crate. It depends on `rounddance-commission` for
//! install-code validation/derivation and finding handoff, and on
//! `rounddance-security` for key rotation, reusing rather than
//! duplicating those machines.
#![no_std]
#![forbid(unsafe_code)]

pub mod advert;
pub mod attr;
pub mod commission;
pub mod gatt;
pub mod session;

pub use advert::{AdvError, AdvExtension, AdvPolicy, AdvPolicyState, ADV_RECORD_LEN};
pub use attr::{
    AttrError, DeviceType, JoinMethod, LinkKeyFlags, LinkKeyTlv, NetStatusMap, StatusDomain,
    StatusReport, Tlv, TlvId, TLV_MAX_BODY,
};
pub use commission::{
    DirectCommission, DirectError, DirectEvent, DirectOp, DirectState, FindingHandoff,
    NetworkParams, COMMISSION_TIMEOUT_TICKS, MAX_STATUS_QUEUE,
};
pub use gatt::{
    AuthLevel, CharDesc, CharProps, ServiceDesc, COMMISSIONING_CHARS, COMMISSIONING_SERVICE_UUID,
    DIRECT_SERVICES, SECURITY_CHARS, SECURITY_SERVICE_UUID,
};
pub use session::{
    AdminKeySource, BleCounters, CounterError, PskKind, SessionError, SessionKind, SessionMachine,
    SessionState, ESTABLISH_TIMEOUT_TICKS,
};

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-direct"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
    }
}
