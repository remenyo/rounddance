//! Bidirectional GP commissioning across the scripted medium with
//! deterministic replay.
//!
//! A GPD commissioning announcement asking for network parameters
//! parks the sink session; the sink stages a Commissioning Reply,
//! serves it inside the GPD's receive window over the radio, and the
//! GPD's Success frame completes the exchange and populates the
//! translation table. A mismatched Success and a lapsed window are
//! refused. Replaying the same seed + script yields the identical
//! trace.
//!
//! Requirement traceability: `14-0563-19-A173-01` (capable-peer gate),
//! `14-0563-19-A173-02` (bounded reply window), `14-0563-19-A4212-01`
//! (reply codec), `14-0563-19-A4212-02` (stage/serve/Success flow),
//! `14-0563-19-A152-01` (one queued frame per GPD),
//! `14-0563-19-A152-02` (20–25 ms serve window).

use rounddance_gp::*;
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap, MacMgmtSap, TxOptions, TxRequest, TxStatus,
};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};

const PAN: u16 = 0xa4d3;
const SINK: u16 = 0x0002;
const GPD_NODE: u16 = 0x0003;
const SRCID: u32 = 0x1234_5678;

/// Serve offset in milliseconds: inside the 20–25 ms window.
const SERVE_AT_MS: u64 = 22;

fn gpdf_for(cmd: u8, payload: &[u8]) -> Vec<u8> {
    let frame = Gpdf {
        fc: NwkFrameControl {
            frame_type: FrameType::Data,
            auto_commissioning: false,
            ext_present: true,
        },
        ext: Some(ExtFrameControl {
            app_id: AppId::SrcId,
            level: WireSecurityLevel::None,
            key_bit: false,
            rx_after_tx: false,
            direction_proxy: true,
        }),
        id: Some(GpdId::SrcId(SRCID)),
        frame_counter: None,
        body: GpdfBody::Gp {
            command: cmd,
            payload,
        },
        mic: None,
    };
    let mut buf = [0u8; MAX_GPDF];
    let n = frame.encode_into(&mut buf).unwrap();
    buf[..n].to_vec()
}

fn deliver(seed: u64, from: u16, to: u16, msdu: &[u8]) -> (Vec<String>, Vec<u8>) {
    let mut radio = ScriptedRadio::new(
        Seed(seed),
        vec![ScriptAction::Delay {
            base_us: 320,
            jitter_us: 100,
        }],
    );
    radio.reset(true);
    radio.set_channel(Channel::new(15).unwrap()).unwrap();
    radio.set_pan_id(PAN);
    radio.set_short_addr(from);
    let req = TxRequest {
        dst: MacAddress::short(PAN, to),
        msdu: FramePayload::from_slice(msdu).expect("GPDF fits one MSDU"),
        options: TxOptions::ACK,
    };
    radio.data_request(req).expect("queue has room");
    radio.run_until_idle(16);
    let confirm = radio.poll_confirm().expect("script always confirms");
    assert_eq!(confirm.status, TxStatus::Delivered);
    let got = radio
        .poll_indication()
        .expect("delivery implies indication")
        .msdu
        .as_slice()
        .to_vec();
    (
        radio.trace_lines().iter().map(|s| s.to_string()).collect(),
        got,
    )
}

fn bidir_ann() -> CommissioningAnnouncement {
    CommissioningAnnouncement {
        app: AppId::SrcId,
        gpd: SRCID as u64,
        endpoint: 0xFF,
        pan_id_request: true,
        key_request: false,
        rx_after_tx: true,
        security_capable: false,
        key_present: false,
    }
}

/// One full scenario run: returns the medium traces plus the
/// commissioned PAN identifier the GPD accepted.
fn scenario(seed: u64) -> (Vec<String>, u16) {
    let mut trace = Vec::new();

    // Sink side: announcement parks the session with a deadline.
    let mut session = CommissioningSession::new();
    session.begin(bidir_ann());
    assert_eq!(
        session.complete_at(0).unwrap_err(),
        GpError::BidirectionalPending
    );
    assert_eq!(session.state(), CommissioningState::AwaitingReply);

    // Sink stages the PANID-only reply and queues it for the window.
    session
        .stage_reply(CommissioningReply {
            options: ReplyOptions {
                pan_id_present: true,
                key_present: false,
                key_encrypted: false,
                level: 0,
                key_type: 0,
            },
            pan_id: Some(PAN),
            key: None,
            key_mic: None,
            frame_counter: None,
        })
        .unwrap();
    let mut reply_buf = [0u8; CommissioningReply::MAX_LEN];
    let reply_len = session.build_reply(&mut reply_buf).unwrap();
    let mut queue = GpTxQueue::<1>::new();
    queue
        .enqueue(GpTxQueueEntry {
            id: SRCID as u64,
            endpoint: 0xFF,
            frame: {
                let mut f = [0u8; MAX_GPDF];
                f[..reply_len].copy_from_slice(&reply_buf[..reply_len]);
                f
            },
            frame_len: reply_len as u8,
            lifetime: 5_000,
        })
        .unwrap();

    // Serve inside the 20–25 ms window: the queued reply goes over
    // the radio addressed to the GPD as command 0xF0.
    assert!((TX_OFFSET_MS..=TX_OFFSET_MAX_MS).contains(&SERVE_AT_MS));
    session.tick(SERVE_AT_MS).unwrap();
    let queued = queue.find(SRCID as u64, 0xFF).unwrap();
    let air = gpdf_for(
        CMD_COMMISSIONING_REPLY,
        &queued.frame[..queued.frame_len as usize],
    );
    let (t1, got) = deliver(seed, SINK, GPD_NODE, &air);
    trace.extend(t1);
    assert_eq!(got, air);

    // GPD side: reply decodes and names our PAN.
    let (frame, _) = Gpdf::decode(&got).unwrap();
    match frame.body {
        GpdfBody::Gp { command, payload } => {
            assert_eq!(command, CMD_COMMISSIONING_REPLY);
            let (reply, _) = CommissioningReply::decode(payload).unwrap();
            assert_eq!(reply.pan_id, Some(PAN));
        }
        GpdfBody::LpedOpaque(_) => panic!("expected GP reply body"),
    }
    queue.remove(SRCID as u64).unwrap();

    // GPD answers Success; the sink commissions and seeds translation.
    let success = gpdf_for(CMD_SUCCESS, &[]);
    let (t2, got2) = deliver(seed.wrapping_add(1), GPD_NODE, SINK, &success);
    trace.extend(t2);
    assert_eq!(got2, success);
    let (sframe, _) = Gpdf::decode(&got2).unwrap();
    match sframe.body {
        GpdfBody::Gp { command, payload } => {
            assert_eq!(command, CMD_SUCCESS);
            assert!(payload.is_empty());
        }
        GpdfBody::LpedOpaque(_) => panic!("expected GP success body"),
    }
    let seed_entry = session.note_success(SRCID as u64, 0xFF).unwrap().unwrap();
    assert_eq!(session.state(), CommissioningState::Commissioned);
    let mut translations = TranslationTable::<4>::new();
    translations.upsert(seed_entry.materialize()).unwrap();
    assert!(translations.lookup(GpdId::SrcId(SRCID), 0x20, 0).is_some());
    (trace, PAN)
}

// 14-0563-19-A4212-02 + A152-01 + A152-02: reply staged, queued,
// served in-window over the radio, Success commissions.
#[test]
fn gp_bidir_commissioning_reply_two_node() {
    let (_, pan) = scenario(0xB1D1);
    assert_eq!(pan, PAN);
}

// Decision determinism: the same seed + script replays the identical
// trace and the identical accepted PAN.
#[test]
fn gp_bidir_replay_is_deterministic() {
    let (trace_a, pan_a) = scenario(0x2222);
    let (trace_b, pan_b) = scenario(0x2222);
    assert_eq!(trace_a, trace_b);
    assert_eq!(pan_a, pan_b);
    assert!(!trace_a.is_empty());
}

// 14-0563-19-A173-02 + mismatch edge: a foreign Success is refused
// and a lapsed window times out instead of completing.
#[test]
fn gp_bidir_mismatch_and_timeout_edges() {
    let mut session = CommissioningSession::new();
    session.begin(bidir_ann());
    assert_eq!(
        session.complete_at(0).unwrap_err(),
        GpError::BidirectionalPending
    );
    assert_eq!(
        session.note_success(0x9999_9999, 0xFF).unwrap_err(),
        GpError::TransactionMismatch
    );
    assert_eq!(
        session.tick(REPLY_TIMEOUT_MS).unwrap_err(),
        GpError::ReplyTimeout
    );
    assert_eq!(session.state(), CommissioningState::Idle);
}
