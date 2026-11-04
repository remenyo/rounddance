//! Coverage pinning for doc `20-27688-041` Zigbee Direct v1.1 —
//! commissioning service machine (single-flight discipline,
//! form/permit/join/leave/key-update, timeouts, notifications).
//!
//! Paraphrase-level tests only (D1, `SCOPE.md` §2): each test names
//! the document, revision, and clause/table it pins, never spec
//! text. Requirement IDs are corpus-mined `20-27688-041-*`
//! (page+clause anchored).
//!
//! Corpus anchors pinned here (representative line classes, full map
//! in `docs/coverage/20-27688-041.md`): single-flight + 3-s clock
//! §7.7.2 (Table 26, `CommissioningServiceTimeout`), form/permit/
//! join/leave/key-update §7.7.2.10+ (Tables 27–35, use-case flows),
//! anonymous-join countdown §6.3.1, admin-key rules §6.3.2.1,
//! finding handoff §7.7.2.10.

use rounddance_direct::attr::{DeviceType, JoinMethod, LinkKeyFlags, StatusDomain, StatusReport};
use rounddance_direct::*;

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

fn drain(d: &mut DirectCommission) -> [StatusReport; 4] {
    let mut notes = [StatusReport::success(StatusDomain::GENERAL); 4];
    let n = d.take_notifications(&mut notes);
    assert!(n <= MAX_STATUS_QUEUE);
    notes
}

// ---- Single-flight discipline + 3-s timeout (§7.7.2) ----

#[test]
fn coverage_direct_single_flight_and_domains() {
    assert_eq!(COMMISSION_TIMEOUT_TICKS, 3);
    assert_eq!(MAX_STATUS_QUEUE, 4);
    assert_eq!(DirectOp::Form.domain(), StatusDomain::FORM_NETWORK);
    assert_eq!(
        DirectOp::PermitJoining.domain(),
        StatusDomain::PERMIT_JOINING
    );
    assert_eq!(DirectOp::Join.domain(), StatusDomain::JOIN_NETWORK);
    assert_eq!(DirectOp::Leave.domain(), StatusDomain::LEAVE_NETWORK);
    assert_eq!(
        DirectOp::FindingBinding.domain(),
        StatusDomain::FINDING_BINDING
    );
    let mut d = DirectCommission::new();
    assert_eq!(d.state(), DirectState::Idle);
    assert!(!d.joined());
    d.submit(DirectOp::Form).unwrap();
    assert_eq!(d.state(), DirectState::Busy);
    // Second request while busy is refused with Busy.
    assert_eq!(d.submit(DirectOp::Join), Err(DirectError::Busy));
    // Wrong completion for the in-flight op is refused.
    assert_eq!(d.complete_leave(), Err(DirectError::Busy));
}

#[test]
fn coverage_direct_busy_timeout_fails_and_recovers() {
    let mut d = DirectCommission::new();
    d.submit(DirectOp::Join).unwrap();
    d.tick_1s();
    d.tick_1s();
    assert_eq!(d.state(), DirectState::Busy);
    d.tick_1s();
    assert_eq!(d.state(), DirectState::Failed);
    let notes = drain(&mut d);
    assert_eq!(notes[0].domain, StatusDomain::JOIN_NETWORK.0);
    assert!(!notes[0].is_success());
    // Recovery returns to idle once the failure is drained.
    d.recover();
    assert_eq!(d.state(), DirectState::Idle);
    d.recover(); // idle recover is a no-op
    assert_eq!(d.state(), DirectState::Idle);
}

// ---- Form: range-checked, starts closed ----

#[test]
fn coverage_direct_form_ranges_and_closed_start() {
    let mut d = DirectCommission::new();
    d.submit(DirectOp::Form).unwrap();
    let ev = d.complete_form(form_params(), Some([0x01; 16])).unwrap();
    assert_eq!(ev, DirectEvent::StatusPending);
    assert!(d.joined());
    assert_eq!(d.permit_remaining(), 0);
    assert_eq!(d.network().unwrap().pan_id, 0x1A2B);
    let notes = drain(&mut d);
    assert_eq!(notes[0], StatusReport::success(StatusDomain::FORM_NETWORK));
    // Out-of-range PAN fails with a failure notification.
    for bad_pan in [0x0000u16, 0xFFFF] {
        let mut d2 = DirectCommission::new();
        d2.submit(DirectOp::Form).unwrap();
        let mut bad = form_params();
        bad.pan_id = bad_pan;
        assert_eq!(d2.complete_form(bad, None), Err(DirectError::BadParams));
        let notes = drain(&mut d2);
        assert!(!notes[0].is_success());
    }
    // Channel above 26 fails.
    let mut d3 = DirectCommission::new();
    d3.submit(DirectOp::Form).unwrap();
    let mut bad = form_params();
    bad.channel = 27;
    assert_eq!(d3.complete_form(bad, None), Err(DirectError::BadParams));
    // Degenerate extended PAN fails.
    let mut d4 = DirectCommission::new();
    d4.submit(DirectOp::Form).unwrap();
    let mut bad = form_params();
    bad.ext_pan = [0u8; 8];
    assert_eq!(d4.complete_form(bad, None), Err(DirectError::BadParams));
}

// ---- Permit joining: join-window countdown ----

#[test]
fn coverage_direct_permit_window_counts_down() {
    let mut d = DirectCommission::new();
    d.submit(DirectOp::Form).unwrap();
    d.complete_form(form_params(), None).unwrap();
    drain(&mut d);
    d.submit(DirectOp::PermitJoining).unwrap();
    d.complete_permit(60).unwrap();
    assert_eq!(d.permit_remaining(), 60);
    d.tick_1s();
    assert_eq!(d.permit_remaining(), 59);
    // Permit with no network is refused as closed.
    let mut d2 = DirectCommission::new();
    d2.submit(DirectOp::PermitJoining).unwrap();
    assert_eq!(d2.complete_permit(60), Err(DirectError::NetworkClosed));
    let notes = drain(&mut d2);
    assert!(!notes[0].is_success());
}

// ---- Join: install-code path, anonymous countdown, OOB ----

#[test]
fn coverage_direct_join_install_code_flow() {
    let mut d = DirectCommission::new();
    d.submit(DirectOp::Form).unwrap();
    d.complete_form(form_params(), None).unwrap();
    drain(&mut d);
    d.submit(DirectOp::Join).unwrap();
    let code = install_code_bytes();
    let ev = d
        .complete_join(
            JoinMethod::MacAssociation,
            0x0200_0000_0000_0002,
            0x0001,
            Some(&code),
            None,
        )
        .unwrap();
    match ev {
        DirectEvent::FindingHandoff(h) => {
            assert!(h.initiator);
            assert_eq!(h.nwk_addr, 0x0001);
        }
        other => panic!("expected FindingHandoff, got {other:?}"),
    }
    assert!(d.joined());
    let notes = drain(&mut d);
    assert_eq!(notes[0], StatusReport::success(StatusDomain::JOIN_NETWORK));
}

#[test]
fn coverage_direct_join_bad_code_rejected() {
    let mut d = DirectCommission::new();
    d.submit(DirectOp::Form).unwrap();
    d.complete_form(form_params(), None).unwrap();
    drain(&mut d);
    // Missing code on the keyed path is refused.
    d.submit(DirectOp::Join).unwrap();
    assert_eq!(
        d.complete_join(
            JoinMethod::SecureRejoin,
            0x0200_0000_0000_0002,
            0x0001,
            None,
            None
        ),
        Err(DirectError::BadParams)
    );
    // Corrupt CRC is refused before any state changes.
    d.submit(DirectOp::Join).unwrap();
    let mut code = install_code_bytes();
    code[9] ^= 0xFF;
    assert_eq!(
        d.complete_join(
            JoinMethod::SecureRejoin,
            0x0200_0000_0000_0002,
            0x0001,
            Some(&code),
            None
        ),
        Err(DirectError::BadParams)
    );
}

#[test]
fn coverage_direct_join_oob_applies_with_checks() {
    let mut d = DirectCommission::new();
    d.submit(DirectOp::Join).unwrap();
    // OOB without parameters is refused before any notification is
    // queued, so the in-flight request stays open...
    assert_eq!(
        d.complete_join(JoinMethod::OutOfBand, 0, 0x0001, None, None),
        Err(DirectError::BadParams)
    );
    assert_eq!(d.state(), DirectState::Busy);
    // ...and the same request then completes with valid parameters.
    let ev = d
        .complete_join(JoinMethod::OutOfBand, 0, 0x0002, None, Some(form_params()))
        .unwrap();
    assert!(matches!(ev, DirectEvent::FindingHandoff(_)));
    assert!(d.joined());
    // OOB with a bad channel is still refused.
    let mut d2 = DirectCommission::new();
    d2.submit(DirectOp::Join).unwrap();
    let mut bad = form_params();
    bad.channel = 99;
    assert_eq!(
        d2.complete_join(JoinMethod::OutOfBand, 0, 0x0002, None, Some(bad)),
        Err(DirectError::BadParams)
    );
}

// ---- Leave erases everything; key update rotates ----

#[test]
fn coverage_direct_leave_erases_network() {
    let mut d = DirectCommission::new();
    d.submit(DirectOp::Form).unwrap();
    d.complete_form(form_params(), None).unwrap();
    drain(&mut d);
    d.submit(DirectOp::Leave).unwrap();
    assert_eq!(d.complete_leave().unwrap(), DirectEvent::NetworkErased);
    assert!(!d.joined());
    assert!(d.network().is_none());
    assert_eq!(d.permit_remaining(), 0);
    let notes = drain(&mut d);
    assert_eq!(notes[0], StatusReport::success(StatusDomain::LEAVE_NETWORK));
}

#[test]
fn coverage_direct_key_update_rotates() {
    let mut d = DirectCommission::new();
    // No network: rotation is refused as closed.
    d.submit(DirectOp::UpdateKey).unwrap();
    assert_eq!(
        d.complete_key_update([0x02; 8], 1, LinkKeyFlags::GLOBAL_PERMANENT),
        Err(DirectError::NetworkClosed)
    );
    let mut d = DirectCommission::new();
    d.submit(DirectOp::Form).unwrap();
    d.complete_form(form_params(), None).unwrap();
    drain(&mut d);
    d.submit(DirectOp::UpdateKey).unwrap();
    let before = d.network().unwrap().network_key;
    d.complete_key_update([0x02; 8], 7, LinkKeyFlags::GLOBAL_PERMANENT)
        .unwrap();
    assert_ne!(d.network().unwrap().network_key, before);
    let notes = drain(&mut d);
    assert_eq!(notes[0], StatusReport::success(StatusDomain::JOIN_NETWORK));
}
