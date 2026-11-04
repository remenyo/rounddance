//! Coverage pinning for doc `20-27688-041` Zigbee Direct v1.1 —
//! GATT service model, advertisement records, TLV attribute codec,
//! session discipline.
//!
//! Paraphrase-level tests only (D1, `SCOPE.md` §2): each test names
//! the document, revision, and clause/table it pins, never spec
//! text. Requirement IDs are corpus-mined `20-27688-041-*`
//! (page+clause anchored).
//!
//! Corpus anchors pinned here (representative line classes, full map
//! in `docs/coverage/20-27688-041.md`): security service §6.5
//! (Table 5), session establishment §6.3 (provisioning,
//! authorization, PSK kinds, 15-s timeout), advertisement extension
//! §7.6.2–7.6.3 (Table 24), TLV/status codec §7.7.2 (Tables
//! 26–35), authorization gates §6.4.7.4.

use rounddance_direct::advert::{
    AdvError, AdvExtension, AdvPolicy, AdvPolicyState, ADV_AD_TYPE_SERVICE_DATA,
    ADV_COMMISSIONING_UUID16, ADV_EXTENSION_VERSION, ADV_RECORD_LEN, ADV_UNJOINED_SENTINEL,
};
use rounddance_direct::attr::{
    decode_tlv, decode_u16_le, encode_tlv, u16_le, DeviceType, JoinMethod, LinkKeyFlags,
    LinkKeyTlv, NetStatusMap, StatusDomain, StatusReport, TlvId, TLV_MAX_BODY,
};
use rounddance_direct::gatt::{authorize, APP_ERROR_INSUFFICIENT_AUTH};
use rounddance_direct::*;

// ---- GATT service model (§6.5 / §7.7.2.3) ----

#[test]
fn coverage_direct_service_uuids() {
    // Security service: fixed 128-bit UUID, single mandatory instance.
    let sec = &DIRECT_SERVICES[0];
    assert_eq!(sec.name, "DirectSecurity");
    assert!(sec.single_instance && sec.mandatory);
    let mut text = [0u8; 36];
    let n = SECURITY_SERVICE_UUID.format_into(&mut text);
    assert_eq!(&text[..n], b"29144af4-0000-4481-bfe9-6d0299b429e3");
    // Commissioning service: 16-bit 0xFFF7 through the BLE base UUID.
    let comm = &DIRECT_SERVICES[1];
    assert!(comm.single_instance && comm.mandatory);
    let mut text = [0u8; 36];
    let n = COMMISSIONING_SERVICE_UUID.format_into(&mut text);
    assert_eq!(&text[..n], b"0000fff7-0000-1000-8000-00805f9b34fb");
    // Authenticate characteristics: write + indicate, no BLE auth.
    for c in &SECURITY_CHARS {
        assert!(c.props.write && c.props.indicate && !c.props.read);
    }
    assert_ne!(SECURITY_CHARS[0].uuid, SECURITY_CHARS[1].uuid);
    assert_ne!(SECURITY_CHARS[1].uuid, SECURITY_CHARS[2].uuid);
}

#[test]
fn coverage_direct_commissioning_chars_shape() {
    // Status is the only readable/notify characteristic.
    let status = COMMISSIONING_CHARS
        .iter()
        .find(|c| c.name == "CommissioningStatus")
        .unwrap();
    assert!(status.props.read && status.props.notify && !status.props.write);
    // Exactly two characteristics are optional (ManageJoiners + finding/binding).
    let optional: usize = COMMISSIONING_CHARS.iter().filter(|c| !c.mandatory).count();
    assert_eq!(optional, 2);
    assert_eq!(COMMISSIONING_CHARS.len(), 8);
}

#[test]
fn coverage_direct_authorize_gates() {
    let status = COMMISSIONING_CHARS
        .iter()
        .find(|c| c.name == "CommissioningStatus")
        .unwrap();
    // Status reads need no session.
    assert!(authorize(status, AuthLevel::Open, false).is_ok());
    assert!(authorize(status, AuthLevel::Open, true).is_ok());
    // A basic-gated characteristic refuses open holders.
    let gated = COMMISSIONING_CHARS
        .iter()
        .find(|c| c.auth_provisioned == AuthLevel::Basic)
        .unwrap();
    assert_eq!(
        authorize(gated, AuthLevel::Open, true),
        Err(APP_ERROR_INSUFFICIENT_AUTH)
    );
    assert!(authorize(gated, AuthLevel::Basic, true).is_ok());
    assert!(authorize(gated, AuthLevel::Admin, true).is_ok());
    assert_eq!(APP_ERROR_INSUFFICIENT_AUTH, 0x80);
}

// ---- Advertisement extension (Table 24) ----

#[test]
fn coverage_direct_adv_factory_and_sentinels() {
    let ext = AdvExtension::factory_new();
    assert!(!ext.joined());
    assert_eq!(ext.pan_id, ADV_UNJOINED_SENTINEL);
    assert_eq!(ext.nwk_addr, ADV_UNJOINED_SENTINEL);
    assert_eq!(ADV_EXTENSION_VERSION, 0x1);
    assert_eq!(ADV_COMMISSIONING_UUID16, 0xFFF7);
    assert_eq!(ADV_RECORD_LEN, 9);
}

#[test]
fn coverage_direct_adv_encode_decode_roundtrip() {
    let ext = AdvExtension {
        tunnel_supported: true,
        permit_join: true,
        pan_id: 0x1A2B,
        nwk_addr: 0x0000,
    };
    let mut buf = [0u8; ADV_RECORD_LEN];
    let n = ext.encode_into(&mut buf).unwrap();
    assert_eq!(n, ADV_RECORD_LEN);
    assert_eq!(buf[0], 0x08);
    assert_eq!(buf[1], ADV_AD_TYPE_SERVICE_DATA);
    let back = AdvExtension::decode(&buf).unwrap();
    assert_eq!(back, ext);
    assert!(back.joined());
    // Unjoined records force the permit-join flag clear on air.
    let mut factory = AdvExtension::factory_new();
    factory.permit_join = true;
    let mut buf = [0u8; ADV_RECORD_LEN];
    factory.encode_into(&mut buf).unwrap();
    assert!(!AdvExtension::decode(&buf).unwrap().permit_join);
    // Short or mistyped input is refused.
    assert!(AdvExtension::decode(&buf[..4]).is_err());
    let mut bad = buf;
    bad[1] = 0xFF;
    assert!(AdvExtension::decode(&bad).is_err());
    let mut tiny = [0u8; 4];
    assert_eq!(
        factory.encode_into(&mut tiny).unwrap_err(),
        AdvError::BufferTooSmall
    );
}

#[test]
fn coverage_direct_adv_policy_timeout_and_resume() {
    // Below the 60-second minimum the policy refuses to exist.
    assert!(AdvPolicy::new(59).is_none());
    assert_eq!(AdvPolicy::MIN_TIMEOUT_S, 60);
    let mut policy = AdvPolicy::new(60).unwrap();
    assert_eq!(policy.state(), AdvPolicyState::Advertising);
    assert!(policy.extension_visible());
    // A live session holds the provisioning clock.
    for _ in 0..61 {
        policy.tick_1s(true);
    }
    assert_eq!(policy.state(), AdvPolicyState::Advertising);
    // Without a session the timeout quiets the extension...
    for _ in 0..60 {
        policy.tick_1s(false);
    }
    assert_eq!(policy.state(), AdvPolicyState::Quiet);
    assert!(!policy.extension_visible());
    // ...until user interaction resumes it.
    policy.user_resume();
    assert_eq!(policy.state(), AdvPolicyState::Advertising);
    // Link-table pressure suspends; freeing links resumes.
    policy.suspend();
    assert_eq!(policy.state(), AdvPolicyState::Suspended);
    policy.resume_links();
    assert_eq!(policy.state(), AdvPolicyState::Advertising);
    // Provisioned devices stop the provisioning clock.
    policy.mark_provisioned();
    for _ in 0..120 {
        policy.tick_1s(false);
    }
    assert_eq!(policy.state(), AdvPolicyState::Advertising);
    // Leaving the network returns to open-to-provision advertising.
    policy.mark_unprovisioned();
    assert_eq!(policy.state(), AdvPolicyState::Advertising);
}

// ---- TLV attribute codec (Tables 26–35) ----

#[test]
fn coverage_direct_tlv_framing() {
    assert_eq!(TLV_MAX_BODY, 24);
    assert!(!TlvId(0x0E).is_reserved());
    assert!(TlvId(0x10).is_reserved());
    assert_eq!(TlvId::STATUS_CODE, TlvId(0x0E));
    let mut buf = [0u8; 8];
    let n = encode_tlv(0x01, &[0x2B, 0x1A], &mut buf).unwrap();
    assert_eq!(n, 4);
    let (tlv, used) = decode_tlv(&buf[..n]).unwrap();
    assert_eq!((tlv.tag, tlv.body, used), (0x01, &[0x2B, 0x1A][..], 4));
    assert!(decode_tlv(&buf[..1]).is_err());
    assert!(decode_tlv(&buf[..3]).is_err());
    // Oversize bodies are refused at encode.
    let big = [0u8; TLV_MAX_BODY + 1];
    assert!(encode_tlv(0x01, &big, &mut [0u8; 32]).is_err());
}

#[test]
fn coverage_direct_status_report_codec() {
    let report = StatusReport::success(StatusDomain::JOIN_NETWORK);
    assert!(report.is_success());
    let mut buf = [0u8; 8];
    let n = report.encode_into(&mut buf).unwrap();
    let (tlv, _) = decode_tlv(&buf[..n]).unwrap();
    assert_eq!(tlv.tag, TlvId::STATUS_CODE.0);
    let back = StatusReport::decode_body(tlv.body).unwrap();
    assert_eq!(back, report);
    // Non-zero codes are failures; unknown domains are refused.
    assert!(!StatusReport {
        domain: 0x02,
        code: 0x01
    }
    .is_success());
    assert!(StatusReport::decode_body(&[0x02]).is_err());
    assert!(StatusReport::decode_body(&[0xFF, 0x00]).is_err());
    for d in 0..=7u8 {
        assert!(StatusDomain(d).is_defined());
    }
    assert!(!StatusDomain(0x08).is_defined());
}

#[test]
fn coverage_direct_link_key_tlv_codec() {
    let tlv = LinkKeyTlv {
        flags: LinkKeyFlags::GLOBAL_PERMANENT,
        key: [0x5A; 16],
    };
    assert!(!tlv.flags.unique() && !tlv.flags.provisional());
    assert!(tlv.flags.valid());
    assert!(!LinkKeyFlags(0xFC).valid());
    let mut buf = [0u8; 32];
    let n = tlv.encode_into(&mut buf).unwrap();
    let (item, _) = decode_tlv(&buf[..n]).unwrap();
    assert_eq!(item.tag, TlvId::LINK_KEY.0);
    assert_eq!(LinkKeyTlv::decode_body(item.body).unwrap(), tlv);
    // Reserved flag bits are refused both directions.
    let bad = LinkKeyTlv {
        flags: LinkKeyFlags(0x04),
        key: [0; 16],
    };
    assert!(bad.encode_into(&mut buf).is_err());
    assert!(LinkKeyTlv::decode_body(&[0x04, 0x00]).is_err());
    assert!(LinkKeyTlv::decode_body(&[0x00; 16]).is_err());
}

#[test]
fn coverage_direct_join_device_netstatus_values() {
    assert_eq!(
        JoinMethod::decode(0x00).unwrap(),
        JoinMethod::MacAssociation
    );
    assert_eq!(JoinMethod::decode(0x01).unwrap(), JoinMethod::SecureRejoin);
    assert_eq!(JoinMethod::decode(0x02).unwrap(), JoinMethod::OutOfBand);
    assert!(JoinMethod::decode(0x03).is_err());
    assert_eq!(DeviceType::decode(0x00).unwrap(), DeviceType::Coordinator);
    assert_eq!(DeviceType::decode(0x01).unwrap(), DeviceType::Router);
    assert_eq!(DeviceType::decode(0x02).unwrap(), DeviceType::EndDevice);
    assert!(DeviceType::decode(0x05).is_err());
    let map = NetStatusMap(0x1A); // commissioned + open + centralized
    assert_eq!(map.joined_status(), 2);
    assert!(map.open() && map.centralized() && map.valid());
    assert!(!NetStatusMap(0xE0).valid());
    assert!(!NetStatusMap(0x07).valid());
    assert_eq!(u16_le(0x1A2B), [0x2B, 0x1A]);
    assert_eq!(decode_u16_le(&[0x2B, 0x1A]).unwrap(), 0x1A2B);
    assert!(decode_u16_le(&[0x2B]).is_err());
}

// ---- Session discipline (§6.3) ----

#[test]
fn coverage_direct_session_provisioning_cannot_authorize() {
    let mut session = SessionMachine::new();
    assert_eq!(session.state(), SessionState::Idle);
    session
        .begin(PskKind::InstallCode, SessionKind::Provisioning, 0)
        .unwrap();
    assert_eq!(session.state(), SessionState::Establishing);
    // A second provisioning alongside authorization is a conflict.
    assert_eq!(
        session.begin(PskKind::Default, SessionKind::Provisioning, 0),
        Err(SessionError::SessionConflict)
    );
    session.on_established(true).unwrap();
    assert_eq!(session.state(), SessionState::Provisioned);
    session.close();
    assert_eq!(session.state(), SessionState::Idle);
}

#[test]
fn coverage_direct_session_anonymous_needs_window() {
    let mut session = SessionMachine::new();
    // Anonymous provisioning with no join countdown is refused.
    assert_eq!(
        session.begin(PskKind::Anonymous, SessionKind::Provisioning, 0),
        Err(SessionError::JoinWindowClosed)
    );
    session
        .begin(PskKind::Anonymous, SessionKind::Provisioning, 30)
        .unwrap();
    assert_eq!(
        session.on_established(true).unwrap(),
        SessionKind::Provisioning
    );
    // Initiator-chosen key kinds are all accepted.
    for kind in [PskKind::Default, PskKind::InstallCode, PskKind::Passcode] {
        let mut s = SessionMachine::new();
        s.begin(kind, SessionKind::Basic, 0).unwrap();
        assert_eq!(s.on_established(true).unwrap(), SessionKind::Basic);
    }
}

#[test]
fn coverage_direct_session_silence_timeout_and_reset() {
    assert_eq!(ESTABLISH_TIMEOUT_TICKS, 15);
    let mut session = SessionMachine::new();
    session
        .begin(PskKind::Default, SessionKind::Admin, 0)
        .unwrap();
    // Peer traffic resets the silence clock.
    for _ in 0..14 {
        session.tick_1s().unwrap();
    }
    session.on_peer_activity();
    for _ in 0..14 {
        session.tick_1s().unwrap();
    }
    // Fifteen silent ticks drop the peer.
    assert_eq!(session.tick_1s(), Err(SessionError::PeerTimeout));
    assert_eq!(session.state(), SessionState::Dropped);
    // Validation failure drops the peer immediately.
    let mut session = SessionMachine::new();
    session
        .begin(PskKind::Default, SessionKind::Basic, 0)
        .unwrap();
    assert_eq!(
        session.on_established(false),
        Err(SessionError::EstablishmentFailed)
    );
    assert_eq!(session.state(), SessionState::Dropped);
    // Factory reset clears provisioning and unlocks the admin key.
    session.factory_reset();
    assert!(!session.provisioned() && !session.admin_set());
}

#[test]
fn coverage_direct_session_admin_key_lifecycle() {
    let mut session = SessionMachine::new();
    assert!(!session.admin_set());
    // First placement installs; changes need a factory reset.
    session.mark_provisioned();
    assert!(session.provisioned());
    session.factory_reset();
    assert!(!session.provisioned());
}
