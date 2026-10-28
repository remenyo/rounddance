//! Wire vectors for the 3.0 wire shapes: every shape below is what a
//! 3.0-profile peer actually emits, pinned byte-for-byte through the
//! repo codecs, plus the compat admission verdict for each.
//!
//! Corpus reuse (no new IDs for codec behavior): `05-3474-23-331-02`
//! (NWK frame control), `05-3474-23-22511-16` (APS data),
//! `05-3474-23-451-01` (aux), `07-5123-08-241-01` (ZCL general
//! frame), `14-0563-19-A141-01` (GP version gate). Compat policy
//! itself is `RD-COMPAT-*` (repo-minted, MINTED-pending-confirm).

use rounddance_compat::negotiate::{
    admit_30_peer, admit_gp_version, admit_nwk_version, admit_pro_peer, admit_pro_stack_profile,
    admit_touchlink_sub_version, agree_security_level, highest_common_key_index, select_key_method,
    tolerates_cluster_revision, zcl_reserved_bits_need_no_negotiation, CompatError, KeyPolicy,
    SelectedMethod,
};
use rounddance_compat::profile::{
    method_mask, CompatPeer, StackProfile, BASELINE_SEC_LEVEL, GP_VERSION_SHARED_30_40,
    NWK_VERSION_SHARED_30_40, PRO_STACK_PROFILE,
};

/// NWK data header as a 3.0 peer emits it: version 2, no security
/// flag pre-commissioning, minimal addressing.
#[test]
fn vector_nwk_30_data_header_wire() {
    let header = rounddance_nwk::NwkHeader::minimal(
        rounddance_nwk::FrameControl::data(),
        0x0000,
        0x0001,
        30,
        0x7A,
    );
    let mut out = [0u8; 32];
    let n = header.encode_into(&[], &mut out).unwrap();
    assert_eq!(n, 8);
    // fc: type data (00) | version 2 << 2 = 0x08, discovery suppress.
    assert_eq!(out[0], 0x08);
    assert_eq!(out[1], 0x00);
    assert_eq!(&out[2..6], &[0x00, 0x00, 0x01, 0x00]);
    assert_eq!(out[6], 30);
    assert_eq!(out[7], 0x7A);
    // The wire decodes back to version 2 and the compat gate admits it.
    let decoded = rounddance_nwk::decode(&out[..n]).unwrap();
    assert_eq!(decoded.header.control.protocol_version, 2);
    assert!(admit_nwk_version(decoded.header.control.protocol_version).is_ok());
}

/// A version the 3.0/4.0 pair never emits is refused by the gate,
/// even though the codec itself carries the value verbatim.
#[test]
fn vector_nwk_unknown_version_refused() {
    let mut control = rounddance_nwk::FrameControl::data();
    control.protocol_version = 9;
    let header = rounddance_nwk::NwkHeader::minimal(control, 0x0000, 0x0001, 30, 0x01);
    let mut out = [0u8; 32];
    let n = header.encode_into(&[], &mut out).unwrap();
    let decoded = rounddance_nwk::decode(&out[..n]).unwrap();
    assert_eq!(decoded.header.control.protocol_version, 9);
    assert_eq!(
        admit_nwk_version(9),
        Err(CompatError::UnsupportedNwkVersion(9))
    );
}

/// APS data APDU in the 3.0 shape: unicast, no security bit at this
/// layer (security lives in the aux header), On/Off cluster.
#[test]
fn vector_aps_30_data_shape_wire() {
    let header = rounddance_aps::DataHeader {
        control: rounddance_aps::FrameControl::data(rounddance_aps::DeliveryMode::Unicast),
        dest: rounddance_aps::DataDest::Unicast { dst_endpoint: 0x01 },
        cluster_id: 0x0006,
        profile_id: 0x0104,
        src_endpoint: 0x01,
        counter: 0x3C,
        ext: None,
    };
    let mut out = [0u8; 32];
    let n = header.encode_into(&[], &mut out).unwrap();
    // fc data/unicast, dst ep, cluster LE, profile LE, src ep, counter.
    assert_eq!(&out[..n], &[0x00, 0x01, 0x06, 0x00, 0x04, 0x01, 0x01, 0x3C]);
    let decoded = rounddance_aps::decode_data(&out[..n]).unwrap();
    assert_eq!(decoded.header.cluster_id, 0x0006);
    assert_eq!(decoded.header.profile_id, 0x0104);
    assert_eq!(decoded.header.counter, 0x3C);
}

/// Auxiliary header at the baseline level both profiles transmit:
/// level 5, data-key identifier carrying the key sequence.
#[test]
fn vector_aux_30_baseline_level_wire() {
    let header = rounddance_security::AuxHeader {
        control: rounddance_security::SecurityControl::new(
            5,
            rounddance_security::KeyIdMode::DataKey,
            false,
        )
        .unwrap(),
        frame_counter: 0x0000_0042,
        ext_source: None,
        key_id: rounddance_security::KeyIdentifier::Seq(0x01),
    };
    let mut out = [0u8; 32];
    let n = header.encode_into(&mut out).unwrap();
    // control 0x05 (level 5, mode data-key 0, no ext nonce), counter
    // LE, one-octet key sequence.
    assert_eq!(&out[..n], &[0x05, 0x42, 0x00, 0x00, 0x00, 0x01]);
    assert_eq!(agree_security_level(5, 5, BASELINE_SEC_LEVEL), Ok(5));
}

/// A peer offering less than the floor is refused, never silently
/// downgraded: level 0 (plaintext) against a secured floor.
#[test]
fn vector_aux_level_below_floor_refused() {
    assert_eq!(
        agree_security_level(5, 0, BASELINE_SEC_LEVEL),
        Err(CompatError::SecurityDowngradeRefused {
            floor: 5,
            offered: 0
        })
    );
    // Out-of-range levels are refused too.
    assert!(agree_security_level(9, 9, BASELINE_SEC_LEVEL).is_err());
}

/// ZCL Toggle command as a 3.0 peer sends it: cluster-specific,
/// client-to-server, sequence + command id, no manufacturer code.
#[test]
fn vector_zcl_30_toggle_wire() {
    let mut out = [0u8; 8];
    let n = rounddance_zcl::onoff::client::toggle(0x51, &mut out).unwrap();
    assert_eq!(n, 3);
    // fc 0x01 (cluster-specific, to-server), tsn, Toggle 0x02.
    assert_eq!(&out[..n], &[0x01, 0x51, 0x02]);
    let (header, payload) = rounddance_zcl::frame::Header::decode(&out[..n]).unwrap();
    assert_eq!(header.command_id, rounddance_zcl::onoff::CMD_TOGGLE);
    assert!(payload.is_empty());
    assert!(zcl_reserved_bits_need_no_negotiation());
}

/// GP version gate mirrors the GPDF codec: 3 admitted, anything else
/// refused on both sides.
#[test]
fn vector_gp_version_gate() {
    assert!(admit_gp_version(GP_VERSION_SHARED_30_40).is_ok());
    assert!(rounddance_gp::NwkFrameControl::decode(0x0C).is_ok());
    assert_eq!(
        admit_gp_version(2),
        Err(CompatError::UnsupportedGpVersion(2))
    );
    assert!(rounddance_gp::NwkFrameControl::decode(0x08).is_err());
}

/// Key-method selection: 3.0 peer falls back to install-code when
/// policy allows, is refused under the strict posture; a 4.0 peer
/// negotiates.
#[test]
fn vector_key_method_selection() {
    let peer30 = CompatPeer::profile_30();
    assert_eq!(peer30.profile, StackProfile::Profile30);
    assert!(!peer30.profile.supports_key_negotiation());
    assert_eq!(
        select_key_method(&peer30, true, &KeyPolicy::ALLOW_SYMMETRIC),
        Ok(SelectedMethod::InstallCode)
    );
    assert_eq!(
        select_key_method(&peer30, true, &KeyPolicy::STRICT_NEGOTIATION),
        Err(CompatError::NoCommonKeyMethod)
    );
    let peer40 = CompatPeer::profile_40();
    assert_eq!(
        select_key_method(&peer40, true, &KeyPolicy::ALLOW_SYMMETRIC),
        Ok(SelectedMethod::Negotiation)
    );
    // A bare preconfigured-only peer still joins under interop policy.
    let mut bare = CompatPeer::profile_30();
    bare.key_methods = method_mask::PRECONFIGURED;
    assert_eq!(
        select_key_method(&bare, true, &KeyPolicy::ALLOW_SYMMETRIC),
        Ok(SelectedMethod::Preconfigured)
    );
}

/// Key-transport index negotiation picks the highest common index.
#[test]
fn vector_highest_common_key_index() {
    assert_eq!(highest_common_key_index(&[1, 3, 4], &[0, 1, 2, 3]), Some(3));
    assert_eq!(highest_common_key_index(&[7], &[0, 1]), None);
    assert_eq!(highest_common_key_index(&[], &[0, 1]), None);
}

/// Full 3.0 admission in one call, plus the strict-posture refusal.
#[test]
fn vector_admit_30_peer_bundle() {
    let peer = CompatPeer::profile_30();
    assert_eq!(
        admit_30_peer(&peer, true, &KeyPolicy::ALLOW_SYMMETRIC, BASELINE_SEC_LEVEL),
        Ok((SelectedMethod::InstallCode, 5))
    );
    assert_eq!(
        admit_30_peer(
            &peer,
            true,
            &KeyPolicy::STRICT_NEGOTIATION,
            BASELINE_SEC_LEVEL
        ),
        Err(CompatError::NoCommonKeyMethod)
    );
    let mut future = CompatPeer::profile_40();
    future.nwk_version = 0x0F;
    assert_eq!(
        admit_30_peer(
            &future,
            true,
            &KeyPolicy::ALLOW_SYMMETRIC,
            BASELINE_SEC_LEVEL
        ),
        Err(CompatError::UnsupportedNwkVersion(0x0F))
    );
}

/// Forward-compat corners: touchlink sub-device versions ride
/// verbatim, higher cluster revisions are tolerated by 3.0 readers.
#[test]
fn vector_forward_compat_corners() {
    for v in [0u8, 1, 0xFF] {
        assert!(admit_touchlink_sub_version(v));
    }
    assert!(tolerates_cluster_revision(3, 2));
    assert!(tolerates_cluster_revision(2, 2));
    assert_eq!(NWK_VERSION_SHARED_30_40, 2);
}

/// PRO stack-profile gate: exactly the PRO value passes, anything
/// else is a typed refusal (`RD-PRO-02`).
#[test]
fn vector_pro_stack_profile_gate() {
    assert_eq!(PRO_STACK_PROFILE, 0x02);
    assert!(admit_pro_stack_profile(0x02).is_ok());
    for p in [0x00u8, 0x01, 0x03, 0xFF] {
        assert_eq!(
            admit_pro_stack_profile(p),
            Err(CompatError::UnsupportedStackProfile(p))
        );
    }
}

/// PRO best-effort accept matrix: an open PRO-legacy peer with a
/// symmetric key path is accepted at the baseline level
/// (`RD-PRO-01` accept leg + `RD-PRO-04` version-gate extension).
#[test]
fn vector_pro_peer_accepted() {
    let peer = CompatPeer::profile_pro();
    assert_eq!(peer.profile, StackProfile::Pro);
    assert!(!peer.profile.supports_key_negotiation());
    assert_eq!(
        admit_pro_peer(
            &peer,
            PRO_STACK_PROFILE,
            true,
            true,
            &KeyPolicy::ALLOW_SYMMETRIC,
            BASELINE_SEC_LEVEL
        ),
        Ok((SelectedMethod::InstallCode, 5))
    );
}

/// PRO best-effort refusal matrix: every gate refuses with its own
/// typed error and no key decision leaks past a refusal
/// (`RD-PRO-03`). Order: version, stack profile, profile tag,
/// joining permission, key method, security level.
#[test]
fn vector_pro_peer_refusal_matrix() {
    let peer = CompatPeer::profile_pro();
    let allow = &KeyPolicy::ALLOW_SYMMETRIC;
    // Unknown NWK version never reaches the later gates.
    let mut bad_version = CompatPeer::profile_pro();
    bad_version.nwk_version = 9;
    assert_eq!(
        admit_pro_peer(
            &bad_version,
            PRO_STACK_PROFILE,
            true,
            true,
            allow,
            BASELINE_SEC_LEVEL
        ),
        Err(CompatError::UnsupportedNwkVersion(9))
    );
    // Wrong raw stack-profile field value.
    assert_eq!(
        admit_pro_peer(&peer, 0x01, true, true, allow, BASELINE_SEC_LEVEL),
        Err(CompatError::UnsupportedStackProfile(0x01))
    );
    // Non-PRO profile tag, even with a good field value.
    let not_pro = CompatPeer::profile_30();
    assert_eq!(
        admit_pro_peer(
            &not_pro,
            PRO_STACK_PROFILE,
            true,
            true,
            allow,
            BASELINE_SEC_LEVEL
        ),
        Err(CompatError::UnsupportedStackProfile(PRO_STACK_PROFILE))
    );
    // Closed network: refused before any key decision.
    assert_eq!(
        admit_pro_peer(
            &peer,
            PRO_STACK_PROFILE,
            false,
            true,
            allow,
            BASELINE_SEC_LEVEL
        ),
        Err(CompatError::JoiningClosed)
    );
    // Symmetric-only peer under the mandatory-negotiation posture.
    assert_eq!(
        admit_pro_peer(
            &peer,
            PRO_STACK_PROFILE,
            true,
            true,
            &KeyPolicy::STRICT_NEGOTIATION,
            BASELINE_SEC_LEVEL
        ),
        Err(CompatError::NoCommonKeyMethod)
    );
    // Floor above the baseline refuses instead of downgrading.
    assert_eq!(
        admit_pro_peer(
            &peer,
            PRO_STACK_PROFILE,
            true,
            true,
            allow,
            BASELINE_SEC_LEVEL + 1
        ),
        Err(CompatError::SecurityDowngradeRefused {
            floor: BASELINE_SEC_LEVEL + 1,
            offered: BASELINE_SEC_LEVEL,
        })
    );
}
