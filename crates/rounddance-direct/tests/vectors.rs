//! Direct transcripts: service descriptors, advertisement records,
//! TLV vectors, session discipline, and commissioning flows.
//!
//! Byte strings and transcripts below are hand-computed from the
//! paraphrased layouts — never spec text (D1, `SCOPE.md` §2).
//! Requirement IDs: corpus-mined `20-27688-041-*`
//! (page+clause anchored, reconcile for exact wording).

use rounddance_direct::attr::decode_tlv;
use rounddance_direct::*;

fn tlv_body(input: &[u8]) -> &[u8] {
    let (tlv, _) = decode_tlv(input).unwrap();
    tlv.body
}

// ---- 20-27688-041-65-01: security service is fixed single-instance. ----

#[test]
fn vector_security_service_shape_20_27688_041_65_01() {
    let svc = &DIRECT_SERVICES[0];
    assert_eq!(svc.name, "DirectSecurity");
    assert!(svc.single_instance && svc.mandatory);
    let mut text = [0u8; 36];
    let n = SECURITY_SERVICE_UUID.format_into(&mut text);
    assert_eq!(&text[..n], b"29144af4-0000-4481-bfe9-6d0299b429e3");
    assert_eq!(SECURITY_CHARS.len(), 3);
    for c in &SECURITY_CHARS {
        assert!(c.props.write && c.props.indicate && !c.props.read);
    }
    // Distinctive UUIDs per method (counter suffixes 0001/0002/0003).
    assert_ne!(SECURITY_CHARS[0].uuid, SECURITY_CHARS[1].uuid);
    assert_ne!(SECURITY_CHARS[1].uuid, SECURITY_CHARS[2].uuid);
}

// ---- 20-27688-041-772-01: commissioning service discipline. ----

#[test]
fn vector_commissioning_service_shape_20_27688_041_772_01() {
    let svc = &DIRECT_SERVICES[1];
    assert!(svc.single_instance && svc.mandatory);
    let mut text = [0u8; 36];
    let n = COMMISSIONING_SERVICE_UUID.format_into(&mut text);
    assert_eq!(&text[..n], b"0000fff7-0000-1000-8000-00805f9b34fb");
    assert_eq!(COMMISSIONING_CHARS.len(), 8);
    // Status is the only readable/notify characteristic.
    let status = &COMMISSIONING_CHARS[4];
    assert_eq!(status.name, "CommissioningStatus");
    assert!(status.props.read && status.props.notify && !status.props.write);
    // Identify is the only read+write characteristic.
    let id = &COMMISSIONING_CHARS[6];
    assert!(id.props.read && id.props.write);
    // Optional characteristics are exactly ManageJoiners + FindingBinding.
    let optional: usize = COMMISSIONING_CHARS.iter().filter(|c| !c.mandatory).count();
    assert_eq!(optional, 2);
}

// ---- 20-27688-041-63-01: session access control. ----

#[test]
fn vector_access_control_20_27688_041_63_01() {
    let form = &COMMISSIONING_CHARS[0];
    let status = &COMMISSIONING_CHARS[4];
    let finding = &COMMISSIONING_CHARS[7];
    // Unprovisioned: any session at/above the gate passes.
    assert!(gatt::authorize(form, AuthLevel::Provisioning, false).is_ok());
    assert!(gatt::authorize(status, AuthLevel::Open, false).is_ok());
    // Provisioned: status reads excepted, form needs admin.
    assert!(gatt::authorize(status, AuthLevel::Open, true).is_ok());
    assert_eq!(gatt::authorize(form, AuthLevel::Basic, true), Err(0x80));
    assert!(gatt::authorize(form, AuthLevel::Admin, true).is_ok());
    // Finding & binding admits basic sessions on provisioned devices.
    assert!(gatt::authorize(finding, AuthLevel::Basic, true).is_ok());
    assert_eq!(gatt::authorize(finding, AuthLevel::Open, true), Err(0x80));
}

// ---- 20-27688-041-76-01: advertisement records. ----

#[test]
fn vector_adv_factory_new_record_20_27688_041_76_01() {
    let adv = AdvExtension::factory_new();
    assert!(!adv.joined());
    let mut buf = [0u8; ADV_RECORD_LEN];
    let n = adv.encode_into(&mut buf).unwrap();
    assert_eq!(n, ADV_RECORD_LEN);
    // AD length 0x08, type 0x16, UUID F7 FF, version nibble 0x1.
    assert_eq!(buf[0], 0x08);
    assert_eq!(buf[1], 0x16);
    assert_eq!(&buf[2..4], &[0xF7, 0xFF]);
    assert_eq!(buf[4] & 0x0F, 0x01);
    assert_eq!(&buf[5..9], &[0xFF, 0xFF, 0xFF, 0xFF]);
    let back = AdvExtension::decode(&buf).unwrap();
    assert_eq!(back, adv);
}

#[test]
fn vector_adv_joined_record_20_27688_041_76_01() {
    let adv = AdvExtension {
        tunnel_supported: true,
        permit_join: true,
        pan_id: 0x1A2B,
        nwk_addr: 0x0001,
    };
    let mut buf = [0u8; ADV_RECORD_LEN];
    adv.encode_into(&mut buf).unwrap();
    // Flags nibble: bit4 tunnel, bit5 permit-join.
    assert_eq!(buf[4] >> 4, 0b11);
    assert_eq!(&buf[5..7], &[0x2B, 0x1A]);
    assert_eq!(&buf[7..9], &[0x01, 0x00]);
    let back = AdvExtension::decode(&buf).unwrap();
    assert_eq!(back, adv);
    // Permit-join flag forced clear while unjoined.
    let mut sneaky = AdvExtension::factory_new();
    sneaky.permit_join = true;
    let mut buf2 = [0u8; ADV_RECORD_LEN];
    sneaky.encode_into(&mut buf2).unwrap();
    assert_eq!(buf2[4] >> 4, 0);
}

// ---- 20-27688-041-62-01: provisioning-timeout quiet. ----

#[test]
fn vector_adv_provisioning_timeout_20_27688_041_62_01() {
    assert!(AdvPolicy::new(59).is_none());
    let mut p = AdvPolicy::new(60).unwrap();
    assert!(p.extension_visible());
    for _ in 0..59 {
        p.tick_1s(false);
        assert!(p.extension_visible());
    }
    p.tick_1s(false);
    assert_eq!(p.state(), AdvPolicyState::Quiet);
    assert!(!p.extension_visible());
    // A live session holds the clock.
    let mut q = AdvPolicy::new(60).unwrap();
    for _ in 0..3600 {
        q.tick_1s(true);
    }
    assert!(q.extension_visible());
    // User interaction resumes.
    p.user_resume();
    assert!(p.extension_visible());
    // Link-table pressure suspends the extension; freed links resume it.
    p.suspend();
    assert_eq!(p.state(), AdvPolicyState::Suspended);
    assert!(!p.extension_visible());
    p.resume_links();
    assert!(p.extension_visible());
    // Leaving the network returns to open-to-provision.
    p.mark_provisioned();
    p.mark_unprovisioned();
    assert!(p.extension_visible());
}

// ---- 20-27688-041-772-01: TLV + status codec vectors. ----

#[test]
fn vector_status_report_codec_20_27688_041_772_01() {
    let ok = StatusReport::success(StatusDomain::FORM_NETWORK);
    assert!(ok.is_success());
    let mut buf = [0u8; 8];
    let n = ok.encode_into(&mut buf).unwrap();
    assert_eq!(&buf[..n], &[0x0E, 0x02, 0x01, 0x00]);
    let (tlv, used) = decode_tlv(&buf).unwrap();
    assert_eq!(used, n);
    let back = StatusReport::decode_body(tlv.body).unwrap();
    assert_eq!(back, ok);
    // Non-zero is failure; reserved domains rejected.
    let fail = StatusReport {
        domain: 0x02,
        code: 0x01,
    };
    assert!(!fail.is_success());
    assert!(StatusReport::decode_body(&[0x08, 0x00]).is_err());
}

#[test]
fn vector_link_key_tlv_codec_20_27688_041_772_02() {
    let tlv = LinkKeyTlv {
        flags: LinkKeyFlags(0b11),
        key: [0x5Au8; 16],
    };
    assert!(tlv.flags.unique() && tlv.flags.provisional());
    let mut buf = [0u8; 32];
    let n = tlv.encode_into(&mut buf).unwrap();
    assert_eq!(n, 2 + 17);
    assert_eq!(buf[0], 0x04);
    assert_eq!(buf[1], 17);
    let back = LinkKeyTlv::decode_body(tlv_body(&buf)).unwrap();
    assert_eq!(back, tlv);
    // Reserved flag bits rejected.
    assert!(LinkKeyTlv::decode_body(&[&[0x04], &[0x00u8; 16][..]].concat()).is_err());
    assert!(JoinMethod::decode(0x02).is_ok());
    assert!(JoinMethod::decode(0x03).is_err());
    assert!(DeviceType::decode(0x01).is_ok());
    assert!(DeviceType::decode(0x09).is_err());
}

// ---- 20-27688-041-646-01: monotonic counters. ----

#[test]
fn vector_counters_20_27688_041_646_01() {
    let mut c = BleCounters::new();
    assert_eq!(c.next_tx().unwrap(), 0);
    assert_eq!(c.next_tx().unwrap(), 1);
    assert!(c.accept_rx(0).is_ok());
    // Stale counter dropped without advancing: next accept needs >= 1.
    assert_eq!(c.accept_rx(0), Err(CounterError::Stale));
    assert!(c.accept_rx(5).is_ok());
    assert_eq!(c.accept_rx(5), Err(CounterError::Stale));
}

// ---- 20-27688-041-65-03: establishment robustness. ----

#[test]
fn vector_establishment_timeout_20_27688_041_65_03() {
    let mut s = SessionMachine::new();
    s.begin(PskKind::InstallCode, SessionKind::Provisioning, 0)
        .unwrap();
    for _ in 0..14 {
        s.tick_1s().unwrap();
    }
    assert_eq!(s.tick_1s(), Err(SessionError::PeerTimeout));
    assert_eq!(s.state(), SessionState::Dropped);
    // Validation failure disconnects promptly.
    let mut t = SessionMachine::new();
    t.begin(PskKind::Default, SessionKind::Provisioning, 0)
        .unwrap();
    assert_eq!(
        t.on_established(false),
        Err(SessionError::EstablishmentFailed)
    );
    assert_eq!(t.state(), SessionState::Dropped);
}

// ---- 20-27688-041-63-03/63-04: anonymous guard + admin lifecycle. ----

#[test]
fn vector_anonymous_guard_and_admin_lifecycle() {
    let mut s = SessionMachine::new();
    assert_eq!(
        s.begin(PskKind::Anonymous, SessionKind::Provisioning, 0),
        Err(SessionError::JoinWindowClosed)
    );
    s.begin(PskKind::Anonymous, SessionKind::Provisioning, 30)
        .unwrap();
    // No second provisioning session alongside the live one.
    assert_eq!(
        s.begin(PskKind::Default, SessionKind::Provisioning, 0),
        Err(SessionError::SessionConflict)
    );
    // Admin key set once by the placing commissioner.
    s.close();
    let key = s
        .set_admin_key(AdminKeySource::Supplied([0xA5; 16]))
        .unwrap();
    assert_eq!(key, [0xA5; 16]);
    assert_eq!(
        s.set_admin_key(AdminKeySource::Supplied([0x00; 16])),
        Err(SessionError::AdminKeyLocked)
    );
    // Factory reset unlocks; join-time default derives from TC key.
    s.factory_reset();
    let derived = s.derive_admin_key(&[0x11u8; 16]).unwrap();
    assert_ne!(derived, [0x11u8; 16]);
    assert_eq!(
        s.derive_admin_key(&[0x11u8; 16]),
        Err(SessionError::AdminKeyLocked)
    );
}

// ---- 20-27688-041-772-01/772-02: commissioning transcripts. ----

fn form_params() -> NetworkParams {
    NetworkParams {
        ext_pan: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
        pan_id: 0x1A2B,
        channel: 15,
        nwk_addr: 0x0000,
        device_type: DeviceType::Coordinator,
        network_key: [0x77u8; 16],
    }
}

fn install_code_bytes() -> [u8; 10] {
    let mut out = [0u8; 10];
    let n = rounddance_commission::InstallCode::with_crc(&[0x83u8; 8], &mut out).unwrap();
    assert_eq!(n, 10);
    out
}

#[test]
fn vector_form_starts_closed_20_27688_041_772_02() {
    let mut d = DirectCommission::new();
    d.submit(DirectOp::Form).unwrap();
    // Single-flight: second submit is busy.
    assert_eq!(d.submit(DirectOp::Join), Err(DirectError::Busy));
    let ev = d.complete_form(form_params(), Some([0x01; 16])).unwrap();
    assert_eq!(ev, DirectEvent::StatusPending);
    assert!(d.joined());
    assert_eq!(d.permit_remaining(), 0);
    let mut notes = [StatusReport::success(StatusDomain::GENERAL); 4];
    let n = d.take_notifications(&mut notes);
    assert_eq!(n, 1);
    assert_eq!(notes[0], StatusReport::success(StatusDomain::FORM_NETWORK));
    // Bad PAN range fails with a failure notification.
    let mut d2 = DirectCommission::new();
    d2.submit(DirectOp::Form).unwrap();
    let mut bad = form_params();
    bad.pan_id = 0xFFFF;
    assert_eq!(d2.complete_form(bad, None), Err(DirectError::BadParams));
    let mut notes2 = [StatusReport::success(StatusDomain::GENERAL); 4];
    let n2 = d2.take_notifications(&mut notes2);
    assert_eq!(n2, 1);
    assert!(!notes2[0].is_success());
}

#[test]
fn vector_join_bad_key_rejected() {
    let mut d = DirectCommission::new();
    d.submit(DirectOp::Form).unwrap();
    d.complete_form(form_params(), None).unwrap();
    d.take_notifications(&mut [StatusReport::success(StatusDomain::GENERAL); 4]);
    d.submit(DirectOp::Join).unwrap();
    // Corrupt check field: rejected before any state changes.
    let mut code = install_code_bytes();
    code[9] ^= 0xFF;
    assert_eq!(
        d.complete_join(
            JoinMethod::MacAssociation,
            0x0200_0000_0000_0002,
            0x0001,
            Some(&code),
            None
        ),
        Err(DirectError::BadParams)
    );
    assert!(d.joined());
}

#[test]
fn vector_commissioning_timeout_20_27688_041_772_01() {
    let mut d = DirectCommission::new();
    d.submit(DirectOp::Join).unwrap();
    d.tick_1s();
    d.tick_1s();
    assert_eq!(d.state(), DirectState::Busy);
    d.tick_1s();
    assert_eq!(d.state(), DirectState::Failed);
    let mut notes = [StatusReport::success(StatusDomain::GENERAL); 4];
    let n = d.take_notifications(&mut notes);
    assert_eq!(n, 1);
    assert_eq!(notes[0].domain, StatusDomain::JOIN_NETWORK.0);
    assert!(!notes[0].is_success());
    d.recover();
    assert_eq!(d.state(), DirectState::Idle);
}

#[test]
fn vector_leave_erases_everything_20_27688_041_772_02() {
    let mut d = DirectCommission::new();
    d.submit(DirectOp::Form).unwrap();
    d.complete_form(form_params(), Some([0x01; 16])).unwrap();
    d.take_notifications(&mut [StatusReport::success(StatusDomain::GENERAL); 4]);
    d.submit(DirectOp::Leave).unwrap();
    assert_eq!(d.complete_leave().unwrap(), DirectEvent::NetworkErased);
    assert!(!d.joined());
    assert!(d.network().is_none());
}
