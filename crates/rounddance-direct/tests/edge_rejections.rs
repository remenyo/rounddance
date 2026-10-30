//! Rejection-edge pins for the Direct session/advertisement APIs.
//!
//! The happy paths live in `vectors.rs`; this file pins the exact
//! error variants of the refusal arms that had no `Err(..)` pin:
//! every `AdvError` decode/encode refusal, and the three live
//! `SessionError::BadState` arms. Provenance: synthetic.
//!
//! Requirement IDs: `20-27688-041-76-01` (advertisement records),
//! `20-27688-041-63-01`/`63-02` (session access control),
//! `20-27688-041-63-04`/`63-05` (admin-key lifecycle).

use rounddance_direct::{
    AdminKeySource, AdvError, AdvExtension, AdvPolicy, AdvPolicyState, BleCounters, CounterError,
    PskKind, SessionError, SessionKind, SessionMachine, SessionState, ADV_RECORD_LEN,
};

fn valid_record() -> [u8; ADV_RECORD_LEN] {
    let adv = AdvExtension {
        tunnel_supported: true,
        permit_join: true,
        pan_id: 0x1A2B,
        nwk_addr: 0x0001,
    };
    let mut buf = [0u8; ADV_RECORD_LEN];
    adv.encode_into(&mut buf).unwrap();
    buf
}

#[test]
fn adv_decode_rejects_non_records() {
    // Short buffer refuses before touching any field.
    assert_eq!(
        AdvExtension::decode(&valid_record()[..8]),
        Err(AdvError::BadRecord)
    );
    assert_eq!(AdvExtension::decode(&[]), Err(AdvError::BadRecord));
    // Each header field is checked; one bad octet fails the record.
    let mut bad_len = valid_record();
    bad_len[0] = 0x07;
    assert_eq!(AdvExtension::decode(&bad_len), Err(AdvError::BadRecord));
    let mut bad_type = valid_record();
    bad_type[1] = 0xFF;
    assert_eq!(AdvExtension::decode(&bad_type), Err(AdvError::BadRecord));
    let mut bad_uuid = valid_record();
    bad_uuid[2] ^= 0xFF;
    assert_eq!(AdvExtension::decode(&bad_uuid), Err(AdvError::BadRecord));
    let mut bad_version = valid_record();
    bad_version[4] = (bad_version[4] & 0xF0) | 0x02;
    assert_eq!(AdvExtension::decode(&bad_version), Err(AdvError::BadRecord));
    // The untouched record still decodes.
    assert_eq!(
        AdvExtension::decode(&valid_record()).unwrap(),
        AdvExtension {
            tunnel_supported: true,
            permit_join: true,
            pan_id: 0x1A2B,
            nwk_addr: 0x0001,
        }
    );
}

#[test]
fn adv_encode_rejects_small_buffer() {
    let adv = AdvExtension::factory_new();
    let mut short = [0u8; ADV_RECORD_LEN - 1];
    assert_eq!(adv.encode_into(&mut short), Err(AdvError::BufferTooSmall));
    // Exact-fit buffer succeeds with the unjoined sentinels.
    let mut exact = [0u8; ADV_RECORD_LEN];
    assert_eq!(adv.encode_into(&mut exact), Ok(ADV_RECORD_LEN));
    assert_eq!(&exact[5..9], &[0xFF, 0xFF, 0xFF, 0xFF]);
}

#[test]
fn adv_decode_reads_leading_record() {
    // Decode consumes the leading record; trailing bytes belong to
    // the caller (framing is the scanner's job, not the codec's).
    let mut framed = [0xAAu8; ADV_RECORD_LEN + 3];
    framed[..ADV_RECORD_LEN].copy_from_slice(&valid_record());
    assert_eq!(AdvExtension::decode(&framed).unwrap().pan_id, 0x1A2B);
}

#[test]
fn session_second_begin_while_live_is_bad_state() {
    let mut s = SessionMachine::new();
    s.begin(PskKind::InstallCode, SessionKind::Basic, 0)
        .unwrap();
    s.on_established(true).unwrap();
    assert_eq!(s.state(), SessionState::Basic);
    // A live authorization session rejects any second begin; only a
    // second *provisioning* begin reports the sharing conflict.
    assert_eq!(
        s.begin(PskKind::Default, SessionKind::Admin, 0),
        Err(SessionError::BadState)
    );
    assert_eq!(s.state(), SessionState::Basic);
}

#[test]
fn session_on_established_outside_establishing_is_bad_state() {
    // Fresh machine: nothing in flight.
    let mut s = SessionMachine::new();
    assert_eq!(s.on_established(true), Err(SessionError::BadState));
    // Dropped machine (timed-out establishment): still nothing to
    // confirm; the caller must begin again.
    let mut t = SessionMachine::new();
    t.begin(PskKind::Default, SessionKind::Provisioning, 0)
        .unwrap();
    for _ in 0..15 {
        let _ = t.tick_1s();
    }
    assert_eq!(t.state(), SessionState::Dropped);
    assert_eq!(t.on_established(true), Err(SessionError::BadState));
}

#[test]
fn session_trust_center_default_needs_derive_path() {
    // The TC-key default cannot be installed through the placing
    // path; `derive_admin_key` is the only TC-key entry point.
    let mut s = SessionMachine::new();
    assert_eq!(
        s.set_admin_key(AdminKeySource::FromTrustCenterKey),
        Err(SessionError::BadState)
    );
    assert!(!s.admin_set());
    let derived = s.derive_admin_key(&[0xAA; 16]).unwrap();
    assert!(s.admin_set());
    assert_eq!(s.admin_key(), Some(derived));
    // Installed is installed: re-derive locks like re-supply.
    assert_eq!(
        s.derive_admin_key(&[0xBB; 16]),
        Err(SessionError::AdminKeyLocked)
    );
    assert_eq!(s.admin_key(), Some(derived));
}

#[test]
fn adv_policy_resume_links_only_leaves_suspended() {
    // `resume_links` is a no-op outside `Suspended`: quiet stays
    // quiet until user interaction, and advertising stays put.
    let mut p = AdvPolicy::new(60).unwrap();
    p.resume_links();
    assert_eq!(p.state(), AdvPolicyState::Advertising);
    for _ in 0..60 {
        p.tick_1s(false);
    }
    assert_eq!(p.state(), AdvPolicyState::Quiet);
    p.resume_links();
    assert_eq!(p.state(), AdvPolicyState::Quiet);
    assert!(!p.extension_visible());
    p.user_resume();
    assert!(p.extension_visible());
}

#[test]
fn counters_tx_sequence_starts_at_zero() {
    // First counter of a fresh session is zero and advances by one;
    // a gap on receive jumps the window forward (loss-tolerant).
    let mut c = BleCounters::new();
    assert!(!c.retired());
    assert_eq!(c.next_tx(), Ok(0));
    assert_eq!(c.next_tx(), Ok(1));
    assert!(c.accept_rx(41).is_ok());
    assert_eq!(c.accept_rx(41), Err(CounterError::Stale));
    assert!(c.accept_rx(42).is_ok());
}
