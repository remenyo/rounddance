//! Secured APS data path: counter-managed send headers plus
//! receive-side security and duplicate checks.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `05-3474-23-22845-01` (send path), `05-3474-23-22845-02`
//! (receive path).

use rounddance_aps::{ApsStatus, DataDest, DataHeader, DeliveryMode, FrameControl, SecureDataLink};

// 05-3474-23-22845-01: secured sends set the security flag, take
// sequential counters, and record a unicast ack expectation only.
#[test]
fn secured_send_advances_counter_and_expects_ack() {
    let mut link = SecureDataLink::new();
    assert_eq!(link.peek_counter(), 0x00);
    let (h0, expect0) = link.send_header(
        DataDest::Unicast { dst_endpoint: 0x01 },
        0x0006,
        0x0104,
        0x01,
        true,
    );
    assert!(h0.control.security);
    assert!(h0.control.ack_request);
    assert_eq!(h0.counter, 0x00);
    assert_eq!(link.peek_counter(), 0x01);
    let expect0 = expect0.unwrap();
    assert_eq!(link.pending_ack(), Some(expect0));

    // Matching ack clears the expectation.
    assert!(link.note_ack(0x0006, 0x00, 0x01));
    assert_eq!(link.pending_ack(), None);
    // Wrong cluster/counter/endpoint leaves it outstanding.
    let (_, _) = link.send_header(
        DataDest::Unicast { dst_endpoint: 0x02 },
        0x0006,
        0x0104,
        0x01,
        true,
    );
    assert!(!link.note_ack(0x0008, 0x01, 0x02));
    assert!(!link.note_ack(0x0006, 0x00, 0x02));
    assert!(!link.note_ack(0x0006, 0x01, 0x01));
    assert!(link.pending_ack().is_some());

    // Broadcast sends take a counter too but record no ack; the ack
    // request flag is forced clear off-unicast.
    let (hb, expectb) = link.send_header(
        DataDest::Broadcast { dst_endpoint: 0xff },
        0x0006,
        0x0104,
        0x01,
        true,
    );
    assert!(hb.control.security);
    assert!(!hb.control.ack_request);
    assert_eq!(hb.control.delivery_mode, DeliveryMode::Broadcast);
    assert_eq!(expectb, None);
}

// 05-3474-23-22845-02: receives refuse unsecured and non-data frames,
// deliver each source + counter once, and name the ack owed back.
#[test]
fn secured_receive_checks_flag_dup_and_ack() {
    let mut link = SecureDataLink::new();
    let secured = |counter: u8| DataHeader {
        control: FrameControl {
            security: true,
            ack_request: true,
            ..FrameControl::data(DeliveryMode::Unicast)
        },
        dest: DataDest::Unicast { dst_endpoint: 0x01 },
        cluster_id: 0x0006,
        profile_id: 0x0104,
        src_endpoint: 0x01,
        counter,
        ext: None,
    };
    // First delivery succeeds and names the ack back.
    let ack = link.accept(&secured(0x09), 0x0002).unwrap().unwrap();
    assert_eq!(ack.counter, 0x09);
    assert_eq!(ack.cluster_id, 0x0006);
    // Same source + counter again: replay, refused.
    assert_eq!(link.accept(&secured(0x09), 0x0002), Err(ApsStatus::NoAck));
    // Same counter from a different source: fresh, accepted.
    assert!(link.accept(&secured(0x09), 0x0003).is_ok());
    // Next counter from the first source: accepted.
    assert!(link.accept(&secured(0x0a), 0x0002).is_ok());

    // Unsecured frames are refused even with a fresh counter.
    let mut plain = secured(0x0b);
    plain.control.security = false;
    assert_eq!(link.accept(&plain, 0x0002), Err(ApsStatus::Unsecured));

    // Group frames accept without an ack owed back.
    let mut group = secured(0x0c);
    group.control.delivery_mode = DeliveryMode::Group;
    group.dest = DataDest::Group { group_addr: 0x1234 };
    assert_eq!(link.accept(&group, 0x0002), Ok(None));
}

// 05-3474-23-22845-01: the counter wraps without stalling the path.
#[test]
fn secured_counter_wraps() {
    let mut link = SecureDataLink::new();
    for _ in 0..256 {
        let _ = link.send_header(
            DataDest::Unicast { dst_endpoint: 0x01 },
            0x0006,
            0x0104,
            0x01,
            false,
        );
    }
    assert_eq!(link.peek_counter(), 0x00);
    let (h, _) = link.send_header(
        DataDest::Unicast { dst_endpoint: 0x01 },
        0x0006,
        0x0104,
        0x01,
        false,
    );
    assert_eq!(h.counter, 0x00);
}
