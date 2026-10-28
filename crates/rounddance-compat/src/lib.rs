//! 3.0-profile compatibility policy: audit + negotiation gates.
//!
//! Paraphrase-level model only (D1, `SCOPE.md` §2): this crate names
//! document numbers, revisions, and clause/line anchors, never spec
//! text. The 4.0-first stack (doc `05-3474-23` R23.2 core, doc
//! `07-5123-08` ZCL, doc `07-5356` SE, doc `22-65816-030` BDB) must
//! interoperate with 3.0-profile peers, so this crate records the
//! wire deltas that were audited and owns the admission/negotiation
//! policy that keeps a 3.0 peer able to join and run secured
//! transactions against us.
//!
//! # Audit outcome (4.0-first vs 3.0 wire deltas)
//!
//! * NWK frame control protocol-version sub-field: the 3.0 profile and
//!   the R23.2 core both carry value `2` on this sub-field
//!   (`NWK_VERSION_SHARED_30_40`). No translation is needed; any other
//!   value is not a 3.0/4.0 frame and is refused by
//!   [`negotiate::admit_nwk_version`].
//! * NWK frame-type `0b10` stays reserved and rejected on both sides;
//!   Inter-PAN `0b11` is recognized but never emitted by this stack.
//! * APS has no version field. The reserved delivery-mode value is
//!   rejected by the APS codec on both sides; nothing to negotiate.
//! * Security levels `0..=7` mean the same on both sides; level 5
//!   (encrypted + 32-bit integrity code) is the baseline this stack
//!   transmits. Level 0 (plaintext) is receivable only through the
//!   explicit level-0 path and never counts as secured.
//! * Key establishment: the preconfigured-key and install-code paths
//!   are common to 3.0 and 4.0. The authenticated-negotiation path
//!   needs a peer that speaks it; when the peer does not, the stack
//!   falls back to a symmetric path only if the application policy
//!   allows it ([`negotiate::KeyPolicy::allow_symmetric_fallback`]).
//! * Commissioning: beacons advertise the shared protocol version, so
//!   the steering gate admits version 2 with `min_version: 2`. The
//!   revision-gated symmetric exchange (`parent_is_r20_earlier`) is
//!   preserved, not bypassed.
//! * Green Power: protocol version `3` on both sides; anything else is
//!   already rejected by the GPDF codec and re-surfaced here by
//!   [`negotiate::admit_gp_version`].
//! * Touchlink scan-response `version` is a per-sub-device application
//!   version, not a stack version gate: carried verbatim, admitted for
//!   any value ([`negotiate::admit_touchlink_sub_version`]).
//! * ZCL frame control has no version field; reserved bits are ignored
//!   on receipt (forward-compatible by construction). ClusterRevision
//!   values above the 3.0 tip are tolerated: a 3.0 reader ignores
//!   attributes and commands it does not implement
//!   ([`negotiate::tolerates_cluster_revision`]).
//!
//! # PRO best-effort support (doc `22-65816-030` v3.1, tracked fallback)
//!
//! PRO-legacy peers are recognized — not fully commissioned — by
//! [`negotiate::admit_pro_peer`]: shared NWK version 2, PRO
//! stack-profile value ([`profile::PRO_STACK_PROFILE`]), open
//! joining permission, symmetric key path, baseline security
//! level. Full PRO commissioning (BDB procedures, Trust-Center PRO
//! policies) is an explicit non-goal; the boundary is documented at
//! the decision site. Requirements `RD-PRO-01..04`.
//!
//! # Downgrade policy (never silent)
//!
//! A fallback that lowers the security posture (a security level below
//! the application floor, or a symmetric key where negotiation was
//! mandatory) is refused with [`negotiate::CompatError`] — the caller
//! sees the refusal and the peer sees no traffic under the weaker
//! posture. Successful negotiation returns the agreed parameters so
//! both sides can log what was selected.

#![no_std]
#![forbid(unsafe_code)]

pub mod negotiate;
pub mod profile;

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-compat"
}
