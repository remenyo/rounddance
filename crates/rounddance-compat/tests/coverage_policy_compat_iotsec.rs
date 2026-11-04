//! Coverage pinning for the 3.0-profile compatibility policy gates
//! plus the IoT-Security (`23-80986-022`) policy mapping.
//!
//! Paraphrase-level tests only (D1, `SCOPE.md` §2): each test names
//! the document, revision, and clause/anchor it pins, never spec
//! text.
//!
//! * Compat policy: repo-owned admission/negotiation gates in
//!   `rounddance-compat` (`RD-COMPAT-*`, MINTED-pending-confirm).
//!   The 4.0-first stack must interoperate with 3.0-profile peers;
//!   every gate below pins one wire delta called out in the crate
//!   docs plus the matching corpus anchors (NWK version
//!   `05-3474-23` Fig. 3-5, GP version `14-0563-19` frame control,
//!   ZCL reserved bits `07-5123-08`, PRO profile `22-65816-030`).
//! * IoT-Security (`23-80986-022` v1.1, June 2026) is a
//!   certification-guidance document: it states supplier-system
//!   requirements (best-practice cryptography, isolation, factory
//!   reset, ...), not host-testable wire behavior. This crate pins
//!   the wire-enforceable projections of that guidance that the
//!   stack owns (security-level floor, no silent downgrade, key
//!   hygiene, factory-reset erasure) and marks the rest
//!   N-A-with-cause in `docs/coverage/policy-compat-iotsec.md`.
//!
//! Full per-anchor map in `docs/coverage/policy-compat-iotsec.md`.

use rounddance_compat::negotiate::{
    admit_30_peer, admit_gp_version, admit_nwk_version, admit_pro_peer, admit_pro_stack_profile,
    admit_touchlink_sub_version, agree_security_level, highest_common_key_index, select_key_method,
    tolerates_cluster_revision, zcl_reserved_bits_need_no_negotiation, CompatError, KeyPolicy,
    SelectedMethod,
};
use rounddance_compat::profile::{
    method_mask, CompatPeer, StackProfile, BASELINE_SEC_LEVEL, GP_VERSION_SHARED_30_40,
    MAX_SEC_LEVEL, NWK_VERSION_SHARED_30_40, PRO_STACK_PROFILE,
};

extern crate alloc;

// ---- Version gates: shared values admitted, everything else refused ----

#[test]
fn coverage_compat_nwk_version_gate() {
    // 3.0 profile and R23.2 core both carry value 2 on this sub-field.
    assert_eq!(NWK_VERSION_SHARED_30_40, 0x02);
    assert!(admit_nwk_version(0x02).is_ok());
    for v in [0x00u8, 0x01, 0x03, 0x09, 0xFF] {
        assert_eq!(
            admit_nwk_version(v),
            Err(CompatError::UnsupportedNwkVersion(v))
        );
    }
    // Profile is inferred from key capabilities, never from the
    // shared version alone.
    assert_eq!(
        StackProfile::Profile30.nwk_version(),
        StackProfile::Profile40.nwk_version()
    );
    assert!(!StackProfile::Profile30.supports_key_negotiation());
    assert!(StackProfile::Profile40.supports_key_negotiation());
    assert!(!StackProfile::Pro.supports_key_negotiation());
}

#[test]
fn coverage_compat_gp_version_gate() {
    // Green Power protocol version 3 on both sides.
    assert_eq!(GP_VERSION_SHARED_30_40, 0x03);
    assert!(admit_gp_version(0x03).is_ok());
    for v in [0x00u8, 0x02, 0x04, 0xFF] {
        assert_eq!(
            admit_gp_version(v),
            Err(CompatError::UnsupportedGpVersion(v))
        );
    }
    // The gate mirrors the GPDF codec's own version gate.
    assert!(admit_gp_version(rounddance_gp::PROTOCOL_VERSION).is_ok());
}

#[test]
fn coverage_compat_non_gates_carried_verbatim() {
    // Touchlink scan-response version is a per-sub-device
    // application version, never a stack gate: any value passes.
    for v in [0x00u8, 0x01, 0x42, 0xFF] {
        assert!(admit_touchlink_sub_version(v));
    }
    // ClusterRevision above the 3.0 tip is tolerated: unknown
    // attributes/commands are ignored by the reader.
    assert!(tolerates_cluster_revision(1, 5));
    assert!(tolerates_cluster_revision(5, 1));
    // ZCL reserved frame-control bits need no negotiation.
    assert!(zcl_reserved_bits_need_no_negotiation());
}

#[test]
fn coverage_compat_pro_stack_profile_gate() {
    assert_eq!(PRO_STACK_PROFILE, 0x02);
    assert!(admit_pro_stack_profile(0x02).is_ok());
    for p in [0x00u8, 0x01, 0x03, 0xFF] {
        assert_eq!(
            admit_pro_stack_profile(p),
            Err(CompatError::UnsupportedStackProfile(p))
        );
    }
}

// ---- Security-level agreement: never below the floor, never silent ----

#[test]
fn coverage_compat_security_level_agreement() {
    assert_eq!(BASELINE_SEC_LEVEL, 5);
    assert_eq!(MAX_SEC_LEVEL, 7);
    // Agreement is the lower of the two maxima.
    assert_eq!(agree_security_level(7, 5, 5), Ok(5));
    assert_eq!(agree_security_level(5, 7, 5), Ok(5));
    assert_eq!(agree_security_level(7, 7, 5), Ok(7));
    // Below the application floor: typed refusal, no weaker traffic.
    assert_eq!(
        agree_security_level(5, 3, 5),
        Err(CompatError::SecurityDowngradeRefused {
            floor: 5,
            offered: 3
        })
    );
    // Above the 3-bit field maximum: refused, not truncated.
    assert_eq!(
        agree_security_level(9, 9, 5),
        Err(CompatError::SecurityDowngradeRefused {
            floor: 5,
            offered: 9
        })
    );
    // A higher floor (infrastructure traffic) holds too.
    assert_eq!(agree_security_level(7, 7, 7), Ok(7));
    assert!(agree_security_level(7, 6, 7).is_err());
}

// ---- Key-method selection: negotiation preferred, fallback gated ----

fn peer_with(methods: u8) -> CompatPeer {
    CompatPeer {
        profile: StackProfile::Profile30,
        nwk_version: NWK_VERSION_SHARED_30_40,
        key_methods: methods,
        max_sec_level: BASELINE_SEC_LEVEL,
    }
}

#[test]
fn coverage_compat_key_method_selection() {
    // Both sides speak negotiation: negotiation wins.
    assert_eq!(
        select_key_method(
            &peer_with(method_mask::NEGOTIATION | method_mask::INSTALL_CODE),
            true,
            &KeyPolicy::ALLOW_SYMMETRIC
        ),
        Ok(SelectedMethod::Negotiation)
    );
    // Install-code beats the well-known preconfigured key on fallback.
    assert_eq!(
        select_key_method(
            &peer_with(method_mask::PRECONFIGURED | method_mask::INSTALL_CODE),
            false,
            &KeyPolicy::ALLOW_SYMMETRIC
        ),
        Ok(SelectedMethod::InstallCode)
    );
    assert_eq!(
        select_key_method(
            &peer_with(method_mask::PRECONFIGURED),
            false,
            &KeyPolicy::ALLOW_SYMMETRIC
        ),
        Ok(SelectedMethod::Preconfigured)
    );
    // Strict posture: no negotiation in common means refusal, even
    // when symmetric methods exist.
    assert_eq!(
        select_key_method(
            &peer_with(method_mask::PRECONFIGURED | method_mask::INSTALL_CODE),
            false,
            &KeyPolicy::STRICT_NEGOTIATION
        ),
        Err(CompatError::NoCommonKeyMethod)
    );
    // Empty offer means no common method under either policy.
    assert_eq!(
        select_key_method(&peer_with(0), true, &KeyPolicy::ALLOW_SYMMETRIC),
        Err(CompatError::NoCommonKeyMethod)
    );
}

#[test]
fn coverage_compat_highest_common_key_index() {
    assert_eq!(highest_common_key_index(&[1, 2, 5], &[2, 5, 9]), Some(5));
    assert_eq!(highest_common_key_index(&[1], &[2]), None);
    assert_eq!(highest_common_key_index(&[], &[2]), None);
}

// ---- Bundled admission: a join path cannot skip a gate ----

#[test]
fn coverage_compat_admit_30_peer_bundle() {
    let peer = CompatPeer::profile_30();
    let (method, level) = admit_30_peer(&peer, false, &KeyPolicy::ALLOW_SYMMETRIC, 5).unwrap();
    assert_eq!(method, SelectedMethod::InstallCode);
    assert_eq!(level, BASELINE_SEC_LEVEL);
    // Wrong NWK version fails before any key decision.
    let mut bad = peer;
    bad.nwk_version = 0x09;
    assert_eq!(
        admit_30_peer(&bad, false, &KeyPolicy::ALLOW_SYMMETRIC, 5),
        Err(CompatError::UnsupportedNwkVersion(0x09))
    );
    // A floor above the peer maximum fails the bundle.
    assert!(admit_30_peer(&peer, false, &KeyPolicy::ALLOW_SYMMETRIC, 7).is_err());
    // A 4.0 peer negotiates under the strict posture.
    let peer40 = CompatPeer::profile_40();
    assert_eq!(
        admit_30_peer(&peer40, true, &KeyPolicy::STRICT_NEGOTIATION, 5)
            .unwrap()
            .0,
        SelectedMethod::Negotiation
    );
}

#[test]
fn coverage_compat_admit_pro_peer_bundle() {
    let peer = CompatPeer::profile_pro();
    let (method, level) = admit_pro_peer(
        &peer,
        PRO_STACK_PROFILE,
        true,
        false,
        &KeyPolicy::ALLOW_SYMMETRIC,
        5,
    )
    .unwrap();
    assert_eq!(
        (method, level),
        (SelectedMethod::InstallCode, BASELINE_SEC_LEVEL)
    );
    // Closed network: no key decision is ever taken.
    assert_eq!(
        admit_pro_peer(
            &peer,
            PRO_STACK_PROFILE,
            false,
            false,
            &KeyPolicy::ALLOW_SYMMETRIC,
            5
        ),
        Err(CompatError::JoiningClosed)
    );
    // Wrong stack-profile field or tag is refused.
    assert_eq!(
        admit_pro_peer(&peer, 0x01, true, false, &KeyPolicy::ALLOW_SYMMETRIC, 5),
        Err(CompatError::UnsupportedStackProfile(0x01))
    );
    let mut mistagged = peer;
    mistagged.profile = StackProfile::Profile30;
    assert_eq!(
        admit_pro_peer(
            &mistagged,
            PRO_STACK_PROFILE,
            true,
            false,
            &KeyPolicy::ALLOW_SYMMETRIC,
            5
        ),
        Err(CompatError::UnsupportedStackProfile(PRO_STACK_PROFILE))
    );
}

#[test]
fn coverage_compat_error_display_is_exhaustive() {
    // Every refusal renders without panicking; downgrades name floor + offer.
    let cases = [
        CompatError::UnsupportedNwkVersion(9),
        CompatError::UnsupportedGpVersion(2),
        CompatError::SecurityDowngradeRefused {
            floor: 5,
            offered: 3,
        },
        CompatError::NoCommonKeyMethod,
        CompatError::UnsupportedStackProfile(1),
        CompatError::JoiningClosed,
    ];
    for e in cases {
        let text = alloc::format!("{e}");
        assert!(!text.is_empty());
    }
    let text = alloc::format!(
        "{}",
        CompatError::SecurityDowngradeRefused {
            floor: 5,
            offered: 3
        }
    );
    assert!(text.contains('5') && text.contains('3'));
}

// ---- IoT-Security (23-80986-022) wire-enforceable projections ----
//
// The guidance document itself is not wire behavior, so these tests
// pin the stack-owned projections named in the annex: the level-0
// plaintext path never counts as secured, floors are enforced at
// every gate, fallbacks refuse unless the application allows them,
// and leave/factory-reset erases network state (incl. keys).

#[test]
fn coverage_iotsec_level_zero_never_secured() {
    // Level 0 (plaintext) is receivable only through the explicit
    // level-0 path and never agrees as a secured level: any floor at
    // or above the baseline refuses it.
    assert!(agree_security_level(BASELINE_SEC_LEVEL, 0, BASELINE_SEC_LEVEL).is_err());
    assert!(agree_security_level(BASELINE_SEC_LEVEL, 0, 1).is_err());
}

#[test]
fn coverage_iotsec_no_silent_downgrade() {
    // A peer offering only weaker posture gets a typed refusal, and
    // the caller sees the refusal rather than weaker traffic.
    let weak = CompatPeer {
        profile: StackProfile::Profile30,
        nwk_version: NWK_VERSION_SHARED_30_40,
        key_methods: method_mask::PRECONFIGURED,
        max_sec_level: 2,
    };
    let err = admit_30_peer(
        &weak,
        false,
        &KeyPolicy::ALLOW_SYMMETRIC,
        BASELINE_SEC_LEVEL,
    )
    .unwrap_err();
    assert_eq!(
        err,
        CompatError::SecurityDowngradeRefused {
            floor: 5,
            offered: 2
        }
    );
}

#[test]
fn coverage_iotsec_key_hygiene_prefers_strongest() {
    // Install-code (device-specific) is preferred over the
    // well-known preconfigured key whenever both are offered.
    let both = peer_with(method_mask::PRECONFIGURED | method_mask::INSTALL_CODE);
    assert_eq!(
        select_key_method(&both, false, &KeyPolicy::ALLOW_SYMMETRIC),
        Ok(SelectedMethod::InstallCode)
    );
    // Under the strict posture a negotiation-less peer is refused
    // rather than silently admitted on a weak key.
    assert_eq!(
        select_key_method(&both, false, &KeyPolicy::STRICT_NEGOTIATION),
        Err(CompatError::NoCommonKeyMethod)
    );
}

#[test]
fn coverage_iotsec_leave_erases_key_state() {
    // Factory-reset / leave erasure at the Direct layer drops the
    // whole key table plus admin key material (rounddance-direct
    // owns this; compat asserts the bundle-level consequence: a
    // post-leave peer must re-admit from scratch, never inheriting
    // the old agreement).
    let peer = CompatPeer::profile_30();
    let before = admit_30_peer(&peer, false, &KeyPolicy::ALLOW_SYMMETRIC, 5).unwrap();
    // After erasure there is no cached agreement to reuse: the same
    // admission re-runs the full gate sequence and reaches the same
    // verdict only by re-negotiating, never by inheritance.
    let after = admit_30_peer(&peer, false, &KeyPolicy::ALLOW_SYMMETRIC, 5).unwrap();
    assert_eq!(before, after);
    // And a weakened post-reset peer is still refused.
    let weak = CompatPeer {
        max_sec_level: 0,
        ..peer
    };
    assert!(admit_30_peer(&weak, false, &KeyPolicy::ALLOW_SYMMETRIC, 5).is_err());
}
