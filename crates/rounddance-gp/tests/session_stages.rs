//! Session stage-transition invariants: no staged state leaks across
//! transitions out of the bidirectional reply window.
//!
//! Wave-68 B6 STAGE anomaly: `CommissioningSession::reset` returned the
//! session to `Idle` but left the staged reply parked, so
//! `reply_staged()` still reported a reply owed to an exchange that no
//! longer exists. Every other transition out of the reply window
//! (`begin`, `note_success`, `tick`-timeout) drops the staged reply;
//! `reset` was the odd one out.
//!
//! Requirement traceability: RD-GP-07 (repo-minted,
//! MINTED-pending-confirm).

use rounddance_gp::*;

fn bidir_announcement() -> CommissioningAnnouncement {
    CommissioningAnnouncement {
        app: AppId::SrcId,
        gpd: 0x1234_5678,
        endpoint: 0x00,
        pan_id_request: true,
        key_request: false,
        rx_after_tx: true,
        security_capable: true,
        key_present: false,
    }
}

fn pan_id_reply() -> CommissioningReply {
    CommissioningReply {
        options: ReplyOptions {
            pan_id_present: true,
            key_present: false,
            key_encrypted: false,
            level: 0,
            key_type: 0,
        },
        pan_id: Some(0xa4d3),
        key: None,
        key_mic: None,
        frame_counter: None,
    }
}

/// Park one bidirectional exchange with a staged reply.
fn parked_session() -> CommissioningSession {
    let mut session = CommissioningSession::new();
    session.begin(bidir_announcement());
    assert_eq!(
        session.complete_at(0).unwrap_err(),
        GpError::BidirectionalPending
    );
    assert_eq!(session.state(), CommissioningState::AwaitingReply);
    session.stage_reply(pan_id_reply()).unwrap();
    assert!(session.reply_staged());
    session
}

// RD-GP-07: resetting a parked exchange drops the staged reply and
// the reply window — the idle session owes no reply.
#[test]
fn repro_reset_clears_staged_reply_and_window() {
    let mut session = parked_session();
    session.reset();
    assert_eq!(session.state(), CommissioningState::Idle);
    assert!(
        !session.reply_staged(),
        "B6 STAGE: staged reply leaked across reset to Idle"
    );
    assert_eq!(session.deadline_ms(), u64::MAX);
    // A fresh exchange parks clean: with nothing staged, the window
    // reports pending rather than serving stale bytes.
    session.begin(bidir_announcement());
    assert_eq!(
        session.complete_at(100).unwrap_err(),
        GpError::BidirectionalPending
    );
    assert!(!session.reply_staged());
    let mut buf = [0u8; CommissioningReply::MAX_LEN];
    assert_eq!(
        session.build_reply(&mut buf).unwrap_err(),
        GpError::BidirectionalPending
    );
}

// RD-GP-07: the timeout path keeps the same invariant — past the
// window the session is idle with no reply owed.
#[test]
fn timeout_clears_staged_reply_and_window() {
    let mut session = parked_session();
    assert_eq!(
        session.tick(REPLY_TIMEOUT_MS).unwrap_err(),
        GpError::ReplyTimeout
    );
    assert_eq!(session.state(), CommissioningState::Idle);
    assert!(!session.reply_staged());
    assert_eq!(session.deadline_ms(), u64::MAX);
}
