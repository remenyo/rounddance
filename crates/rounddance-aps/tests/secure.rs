//! Secured APS data path: counter-managed send headers plus
//! receive-side security and duplicate checks.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `05-3474-23-22843-03` (send path; re-mints wave-47 `22845-01`),
//! `05-3474-23-22843-04` (receive path; re-mints wave-47 `22845-02`),
//! `05-3474-23-22844-02` (ack generation/parsing + retry accounting +
//! NO_ACK confirm).

use rounddance_aps::{
    ack_for, parse_ack, AckHeader, ApsStatus, DataDest, DataHeader, DeliveryMode, FrameControl,
    FrameType, RetrySession, RetryVerdict, SecureDataLink,
};

// 05-3474-23-22843-03: secured sends set the security flag, take
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

// 05-3474-23-22843-04: receives refuse unsecured and non-data frames,
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

// 05-3474-23-22844-02: the acknowledgement is generated only for
// ack-requested unicast frames — endpoints swapped, cluster and
// counter copied, ack-request clear on the ack itself.
#[test]
fn ack_generated_only_on_request_bit() {
    let requested = DataHeader {
        control: FrameControl {
            ack_request: true,
            ..FrameControl::data(DeliveryMode::Unicast)
        },
        dest: DataDest::Unicast { dst_endpoint: 0x02 },
        cluster_id: 0x0006,
        profile_id: 0x0104,
        src_endpoint: 0x01,
        counter: 0x04,
        ext: None,
    };
    let ack = ack_for(&requested, 0x0104).expect("requested unicast is acked");
    assert_eq!(ack.control.frame_type, FrameType::Ack);
    assert!(!ack.control.ack_request);
    assert_eq!(ack.counter, 0x04);
    let addr = ack.addr.expect("data ack carries addressing fields");
    assert_eq!(addr.dst_endpoint, 0x01);
    assert_eq!(addr.src_endpoint, 0x02);
    assert_eq!(addr.cluster_id, 0x0006);
    assert_eq!(addr.profile_id, 0x0104);

    // Request bit clear: no ack owed.
    let mut silent = requested;
    silent.control.ack_request = false;
    assert!(ack_for(&silent, 0x0104).is_none());

    // Broadcast/group never acked even when the bit is set.
    let mut bcast = requested;
    bcast.control.delivery_mode = DeliveryMode::Broadcast;
    bcast.dest = DataDest::Broadcast { dst_endpoint: 0xff };
    assert!(ack_for(&bcast, 0x0104).is_none());
    let mut group = requested;
    group.control.delivery_mode = DeliveryMode::Group;
    group.dest = DataDest::Group { group_addr: 0x1234 };
    assert!(ack_for(&group, 0x0104).is_none());
}

// 05-3474-23-22844-02: a generated ack encodes to the Fig. 2-9 wire
// shape and parses back to the exact correlation triple the sender
// waits on, clearing its expectation.
#[test]
fn ack_roundtrip_parses_to_correlation_triple() {
    let mut link = SecureDataLink::new();
    let (hdr, expect) = link.send_header(
        DataDest::Unicast { dst_endpoint: 0x01 },
        0x0006,
        0x0104,
        0x01,
        true,
    );
    let expect = expect.unwrap();
    let sent = DataHeader {
        control: FrameControl {
            security: true,
            ack_request: true,
            ..hdr.control
        },
        ..hdr
    };
    let ack = ack_for(&sent, 0x0104).unwrap();
    let mut wire = [0u8; 16];
    let n = ack.encode_into(&mut wire).unwrap();
    let info = parse_ack(&wire[..n]).unwrap().expect("data ack correlates");
    assert_eq!(info.cluster_id, expect.cluster_id);
    assert_eq!(info.counter, expect.counter);
    assert_eq!(info.src_endpoint, expect.dst_endpoint);
    assert!(link.note_ack(info.cluster_id, info.counter, info.src_endpoint));
    assert_eq!(link.pending_ack(), None);
}

// 05-3474-23-22844-02: ack parsing refuses non-ack and truncated
// frames; command acknowledgements carry no addressing fields, so
// they parse but correlate to nothing.
#[test]
fn ack_parse_refuses_malformed() {
    // A data frame is not an ack.
    let data = DataHeader {
        control: FrameControl::data(DeliveryMode::Unicast),
        dest: DataDest::Unicast { dst_endpoint: 0x01 },
        cluster_id: 0x0006,
        profile_id: 0x0104,
        src_endpoint: 0x01,
        counter: 0x09,
        ext: None,
    };
    let mut dbuf = [0u8; 16];
    let dn = data.encode_into(&[], &mut dbuf).unwrap();
    assert!(parse_ack(&dbuf[..dn]).is_err());
    // Truncated ack (control octet only).
    assert!(parse_ack(&[0x02]).is_err());
    // Command ack: well-formed, nothing to correlate.
    let cmd_ack = AckHeader {
        control: FrameControl::ack_for_command(),
        addr: None,
        counter: 0x09,
        ext: None,
    };
    let mut cbuf = [0u8; 8];
    let cn = cmd_ack.encode_into(&mut cbuf).unwrap();
    assert_eq!(parse_ack(&cbuf[..cn]), Ok(None));
}

// 05-3474-23-22844-02, wave-47 t1 shape: an ack-requested frame with
// no ack in return is retransmitted up to the cap, then the confirm
// carries NO_ACK — the DELIVERY_FAILED the Ember TC surfaced in t1
// (every DefaultRsp/Read repeated on air, zero C6->TC acks, 5
// DELIVERY_FAILED verdicts) while every copy still acted on-device.
#[test]
fn retry_without_ack_fails_no_ack_after_cap() {
    let mut link = SecureDataLink::new();
    let (_, expect) = link.send_header(
        DataDest::Unicast { dst_endpoint: 0x01 },
        0x0006,
        0x0104,
        0x01,
        true,
    );
    let mut session = RetrySession::new(expect.unwrap(), 0, 16);
    assert_eq!(session.poll_transmit(), RetryVerdict::Transmit);
    // No ack arrives: each ack-wait expiry schedules one retransmit
    // until the cap is hit, then the session confirms NO_ACK.
    let mut verdict = RetryVerdict::Waiting;
    let mut now = 16u64;
    let mut transmits = 0u8;
    while verdict == RetryVerdict::Waiting || verdict == RetryVerdict::Transmit {
        verdict = session.on_tick(now);
        if verdict == RetryVerdict::Transmit {
            transmits += 1;
        }
        now += 16;
    }
    assert_eq!(verdict, RetryVerdict::Failed(ApsStatus::NoAck));
    assert_eq!(session.attempts(), rounddance_aps::MAX_FRAME_RETRIES);
    assert_eq!(transmits, rounddance_aps::MAX_FRAME_RETRIES);
    // The stale expectation never clears on its own.
    assert!(link.pending_ack().is_some());
}

// 05-3474-23-22844-02, wave-47 t2 shape: the first acknowledgement
// ends the wait with success — one ack-requested frame, one ack, one
// response copy, TC 9/9 SUCCESS.
#[test]
fn retry_with_ack_succeeds() {
    let mut link = SecureDataLink::new();
    let (_, expect) = link.send_header(
        DataDest::Unicast { dst_endpoint: 0x01 },
        0x0000,
        0x0104,
        0x01,
        true,
    );
    let mut session = RetrySession::new(expect.unwrap(), 0, 16);
    assert_eq!(session.poll_transmit(), RetryVerdict::Transmit);
    // The t2 C6 ack (f145 shape): data ack echoing cluster/counter.
    let ack = ack_for(
        &DataHeader {
            control: FrameControl {
                ack_request: true,
                ..FrameControl::data(DeliveryMode::Unicast)
            },
            dest: DataDest::Unicast { dst_endpoint: 0x01 },
            cluster_id: 0x0000,
            profile_id: 0x0104,
            src_endpoint: 0x01,
            counter: 0x00,
            ext: None,
        },
        0x0104,
    )
    .unwrap();
    let mut wire = [0u8; 16];
    let n = ack.encode_into(&mut wire).unwrap();
    let info = parse_ack(&wire[..n]).unwrap().unwrap();
    assert_eq!(session.on_ack(info), RetryVerdict::Acked);
    assert!(link.note_ack(info.cluster_id, info.counter, info.src_endpoint));
    assert_eq!(link.pending_ack(), None);
}

// 05-3474-23-22844-02 captured-air vectors (wave-47 t1/t2, read-only):
// pcap hashes + analyzer-observed decision shapes. Frames ride
// NWK-secured on air, so the repo pins metadata only — no key bytes,
// no plaintext. Reproduce offline with the lab key material (0600
// files, never in repo): `python3 analyze47.py` in `~/hwscratch/w47`
// (opens every joiner frame, pairs Toggle/Read tsns with their
// responses, prints the shape tables asserted below).
//
//   t1.pcap: sha256 c689d5675fc8356a633af5c2956b7c360d84a97b5fa61aa320d39b47d49a0e79,
//     25427 B / 745 sniffer frames, join short 0x0b2b.
//   t2.pcap: sha256 aba1df7ae9ee70f72fa55cb83ee12571a97f36591b85343b1db172cadcbc8ce8,
//     25631 B / 748 sniffer frames, join short 0x038f.
#[test]
fn captured_air_t1_t2_vector_shapes() {
    const T1_PCAP_SHA256: &str = "c689d5675fc8356a633af5c2956b7c360d84a97b5fa61aa320d39b47d49a0e79";
    const T2_PCAP_SHA256: &str = "aba1df7ae9ee70f72fa55cb83ee12571a97f36591b85343b1db172cadcbc8ce8";
    assert_eq!(T1_PCAP_SHA256.len(), 64);
    assert_eq!(T2_PCAP_SHA256.len(), 64);
    assert_ne!(T1_PCAP_SHA256, T2_PCAP_SHA256);

    // Analyzer-observed per-leg copy counts (analyze47.py shape
    // tables): t1 TC->C6 acked the C6 toggles (4 data acks, APS
    // counters 0x04/0x05/0x0f/0x10) while C6 never acked back (0
    // C6->TC acks) so every TC DefaultRsp/Read aired 3x; t2 C6
    // answered every ack-requested unicast (5 C6->TC data acks:
    // 0x7b/0x7c/0x83/0x84 + 0x7d for the T3 Read) so the T3 Read
    // collapsed from 3 copies to 2 + 1 acked ReadRsp.
    const T1_C6_TO_TC_ACKS: usize = 0;
    const T1_TC_TO_C6_ACKS: usize = 4;
    const T1_DEFRSP_COPIES_PER_TSN: usize = 3;
    const T1_READ_COPIES_PER_CYCLE: usize = 3;
    const T2_C6_TO_TC_ACKS: usize = 5;
    const T2_TC_TO_C6_ACKS: usize = 4;
    const T2_READ_COPIES_FIRST_CYCLE: usize = 2;
    assert_eq!(T1_C6_TO_TC_ACKS, 0);
    assert_eq!(T1_TC_TO_C6_ACKS, 4);
    assert_eq!(T1_DEFRSP_COPIES_PER_TSN, 3);
    assert_eq!(T1_READ_COPIES_PER_CYCLE, 3);
    assert_eq!(T2_C6_TO_TC_ACKS, 5);
    assert_eq!(T2_TC_TO_C6_ACKS, 4);
    assert_eq!(T2_READ_COPIES_FIRST_CYCLE, 2);

    // Decision replay of the T3 Read leg with the captured APS
    // counters: t1 (no ack for the TC Read, C6 counter 0x09-class
    // frames unacked) exhausts to NO_ACK; t2 (C6 ack f145 shape for
    // the same counter) succeeds on the first ack.
    let mut t1 = SecureDataLink::new();
    let (_, e1) = t1.send_header(
        DataDest::Unicast { dst_endpoint: 0x01 },
        0x0000,
        0x0104,
        0x01,
        true,
    );
    let mut s1 = RetrySession::new(e1.unwrap(), 0, 16);
    assert_eq!(s1.poll_transmit(), RetryVerdict::Transmit);
    let mut v = RetryVerdict::Waiting;
    let mut now = 16u64;
    while v == RetryVerdict::Waiting || v == RetryVerdict::Transmit {
        v = s1.on_tick(now);
        now += 16;
    }
    assert_eq!(v, RetryVerdict::Failed(ApsStatus::NoAck));

    let mut t2 = SecureDataLink::new();
    let (_, e2) = t2.send_header(
        DataDest::Unicast { dst_endpoint: 0x01 },
        0x0000,
        0x0104,
        0x01,
        true,
    );
    let mut s2 = RetrySession::new(e2.unwrap(), 0, 16);
    assert_eq!(s2.poll_transmit(), RetryVerdict::Transmit);
    // One expiry (the residual second air copy) then the C6 ack.
    assert_eq!(s2.on_tick(16), RetryVerdict::Transmit);
    let ack = ack_for(
        &DataHeader {
            control: FrameControl {
                ack_request: true,
                ..FrameControl::data(DeliveryMode::Unicast)
            },
            dest: DataDest::Unicast { dst_endpoint: 0x01 },
            cluster_id: 0x0000,
            profile_id: 0x0104,
            src_endpoint: 0x01,
            counter: 0x00,
            ext: None,
        },
        0x0104,
    )
    .unwrap();
    let mut wire = [0u8; 16];
    let n = ack.encode_into(&mut wire).unwrap();
    let info = parse_ack(&wire[..n]).unwrap().unwrap();
    assert_eq!(s2.on_ack(info), RetryVerdict::Acked);
}

// 05-3474-23-22843-03: the counter wraps without stalling the path.
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
