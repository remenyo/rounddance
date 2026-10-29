//! Bidirectional GP commissioning through the unified sink intake
//! across the scripted medium, with deterministic replay.
//!
//! Decision match to the proven air behavior (w65 4/4 + sink 8/8
//! with PAIRED → HANDOFF → DEDUP-DROP; GPDF shape census): every leg
//! of the timeline runs through `receive::receive`, so the sink
//! transitions and the counter-window dedup rule are the same code
//! path the air proofs exercised —
//!
//! * commission: a secured receive-after-transmit commissioning
//!   announcement admits while the mode is open and parks the
//!   bidirectional session;
//! * reply: the staged PANID reply is served inside the 20–25 ms
//!   window over the radio;
//! * pairing: the GPD's secured Success frame commissions through
//!   the same intake (PAIRED);
//! * data: the paired GPD's secured data hands off to NWK (HANDOFF);
//! * dedup-drop: the replayed counter drops with `SecurityFailed`
//!   and the advanced counter hands off again (DEDUP-DROP).
//!
//! Replaying the same seed + script yields the identical trace and
//! decision log.
//!
//! Requirement traceability: RD-SIM-03 (repo-minted) over RD-GP-02
//! (intake decisions), RD-GP-05 (Success pairing),
//! `14-0563-19-A36-05` (dedup), `-A173-02` (reply window),
//! `-A4212-02` (stage/serve/Success flow).

use rounddance_gp::*;
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap, MacMgmtSap, TxOptions, TxRequest, TxStatus,
};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};

const PAN: u16 = 0xa4d3;
const SINK: u16 = 0x0002;
const GPD_NODE: u16 = 0x0003;
const SRCID: u32 = 0x1234_5678;

/// Test-only GP key (committed; lab keys stay local-only).
const TEST_KEY: [u8; 16] = [0x5au8; 16];

/// Serve offset in milliseconds: inside the 20–25 ms window.
const SERVE_AT_MS: u64 = 22;

fn test_nonce(srcid: u32, ctr: u32) -> [u8; 13] {
    let id = srcid.to_le_bytes();
    let c = ctr.to_le_bytes();
    [
        id[0], id[1], id[2], id[3], id[0], id[1], id[2], id[3], c[0], c[1], c[2], c[3], 0x05,
    ]
}

fn test_ks(nonce: &[u8; 13], ctr: u32) -> [u8; 16] {
    use rounddance_security::encrypt_block_aes128;
    let mut blk = [0u8; 16];
    blk[0] = 0x01;
    blk[1..14].copy_from_slice(nonce);
    blk[14..16].copy_from_slice(&(ctr as u16).to_be_bytes());
    encrypt_block_aes128(&TEST_KEY, &blk)
}

fn test_tag(nonce: &[u8; 13], aad_extra: &[u8], msg: &[u8]) -> [u8; 4] {
    use rounddance_security::encrypt_block_aes128;
    let mut b0 = [0u8; 16];
    b0[0] = 0x40 | 0x08 | 0x01;
    b0[1..14].copy_from_slice(nonce);
    b0[14..16].copy_from_slice(&(msg.len() as u16).to_be_bytes());
    let mut mac_in = Vec::new();
    mac_in.extend_from_slice(&(aad_extra.len() as u16).to_be_bytes());
    mac_in.extend_from_slice(aad_extra);
    while mac_in.len() % 16 != 0 {
        mac_in.push(0);
    }
    mac_in.extend_from_slice(msg);
    while mac_in.len() % 16 != 0 {
        mac_in.push(0);
    }
    let mut x = encrypt_block_aes128(&TEST_KEY, &b0);
    for blk in mac_in.chunks(16) {
        let mut mix = [0u8; 16];
        for (i, b) in blk.iter().enumerate() {
            mix[i] = x[i] ^ b;
        }
        x = encrypt_block_aes128(&TEST_KEY, &mix);
    }
    let s0 = test_ks(nonce, 0);
    [x[0] ^ s0[0], x[1] ^ s0[1], x[2] ^ s0[2], x[3] ^ s0[3]]
}

/// Seal one MicOnly GPDF under the test key: header + cleartext
/// section + MIC.
fn seal(srcid: u32, ctr: u32, rx_after_tx: bool, section: &[u8]) -> Vec<u8> {
    let mut ext = 0x30u8;
    if rx_after_tx {
        ext |= 0x40;
    }
    let mut header = vec![0x8cu8, ext];
    header.extend_from_slice(&srcid.to_le_bytes());
    header.extend_from_slice(&ctr.to_le_bytes());
    let nonce = test_nonce(srcid, ctr);
    let mut aad_extra = header.clone();
    aad_extra.extend_from_slice(section);
    let tag = test_tag(&nonce, &aad_extra, &[]);
    let mut out = header;
    out.extend_from_slice(section);
    out.extend_from_slice(&tag);
    out
}

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

struct SinkSide {
    keys: GpKeySlots,
    session: CommissioningSession,
    sinks: SinkTable<8>,
    translations: TranslationTable<8>,
    replay: GpReplay<8>,
    opened: [u8; MAX_GP_OPEN],
}

impl SinkSide {
    fn new() -> Self {
        let mut keys = GpKeySlots::new();
        keys.set(TEST_KEY, true);
        Self {
            keys,
            session: CommissioningSession::new(),
            sinks: SinkTable::<8>::new(),
            translations: TranslationTable::<8>::new(),
            replay: GpReplay::<8>::new(),
            opened: [0u8; MAX_GP_OPEN],
        }
    }

    fn receive(&mut self, air: &[u8], commissioning_open: bool) -> SinkDecision {
        receive(
            air,
            &self.keys,
            commissioning_open,
            &mut self.session,
            &mut self.sinks,
            &mut self.translations,
            &mut self.replay,
            &mut self.opened,
        )
    }
}

/// One full scenario run: returns the medium traces plus the sink's
/// decision log, decision-for-decision against the air model
/// (PAIRED → HANDOFF → DEDUP-DROP).
fn scenario(seed: u64) -> (Vec<String>, Vec<String>) {
    let mut trace = Vec::new();
    let mut decisions = Vec::new();
    let mut sink = SinkSide::new();

    // Leg 1 — commission: the secured receive-after-transmit
    // announcement admits while the mode is open and parks the
    // bidirectional session.
    let ask = seal(SRCID, 1, true, &[0xe0, 0x02, 0xf3, 0x32]);
    let (t, air) = deliver(seed, GPD_NODE, SINK, &ask);
    trace.extend(t);
    assert_eq!(
        sink.receive(&air, true),
        SinkDecision::AdmitCommissioning {
            gpd: SRCID as u64,
            endpoint: 0x00,
            command: 0xe0,
        },
    );
    decisions.push("ask:admit".to_string());
    sink.session.begin(CommissioningAnnouncement {
        app: AppId::SrcId,
        gpd: SRCID as u64,
        endpoint: 0x00,
        pan_id_request: true,
        key_request: false,
        rx_after_tx: true,
        security_capable: true,
        key_present: false,
    });
    assert_eq!(
        sink.session.complete_at(0).unwrap_err(),
        GpError::BidirectionalPending
    );
    assert_eq!(sink.session.state(), CommissioningState::AwaitingReply);

    // Leg 2 — reply: the staged PANID reply serves inside the
    // 20–25 ms window over the radio and names our PAN.
    sink.session
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
    let reply_len = sink.session.build_reply(&mut reply_buf).unwrap();
    assert!((TX_OFFSET_MS..=TX_OFFSET_MAX_MS).contains(&SERVE_AT_MS));
    sink.session.tick(SERVE_AT_MS).unwrap();
    let served = gpdf_for(CMD_COMMISSIONING_REPLY, &reply_buf[..reply_len]);
    let (t, got) = deliver(seed.wrapping_add(1), SINK, GPD_NODE, &served);
    trace.extend(t);
    assert_eq!(got, served);
    let (frame, _) = Gpdf::decode(&got).unwrap();
    match frame.body {
        GpdfBody::Gp { command, payload } => {
            assert_eq!(command, CMD_COMMISSIONING_REPLY);
            let (reply, _) = CommissioningReply::decode(payload).unwrap();
            assert_eq!(reply.pan_id, Some(PAN));
        }
        GpdfBody::LpedOpaque(_) => panic!("expected GP reply body"),
    }
    decisions.push("reply:served".to_string());

    // Leg 3 — pairing: the GPD's secured Success frame commissions
    // through the same intake (PAIRED).
    let success = seal(SRCID, 2, false, &[CMD_SUCCESS]);
    let (t, air) = deliver(seed.wrapping_add(2), GPD_NODE, SINK, &success);
    trace.extend(t);
    assert_eq!(
        sink.receive(&air, false),
        SinkDecision::Commissioned {
            gpd: SRCID as u64,
            endpoint: 0x00,
        },
    );
    decisions.push("success:commissioned".to_string());
    assert!(sink.sinks.find(GpdId::SrcId(SRCID)).is_some());

    // Leg 4 — data: the paired GPD's secured data hands off to NWK
    // (HANDOFF).
    let data = seal(SRCID, 3, false, &[0x20, 0x01]);
    let (t, air) = deliver(seed.wrapping_add(3), GPD_NODE, SINK, &data);
    trace.extend(t);
    match sink.receive(&air, false) {
        SinkDecision::Handoff(h) => {
            assert_eq!((h.profile, h.cluster, h.command), (0x0104, 0xFFFF, 0x00));
            assert_eq!(h.route, NwkRoute::PairedEndpoints);
            decisions.push("data:handoff:0104/ffff/00".to_string());
        }
        other => panic!("expected handoff, got {:?}", other),
    }

    // Leg 5 — dedup-drop: the replayed counter drops, the advanced
    // counter hands off again (DEDUP-DROP).
    let (t, air) = deliver(seed.wrapping_add(4), GPD_NODE, SINK, &data);
    trace.extend(t);
    assert_eq!(
        sink.receive(&air, false),
        SinkDecision::Drop(GpError::SecurityFailed),
    );
    decisions.push("replay:drop:SecurityFailed".to_string());
    let data_next = seal(SRCID, 4, false, &[0x20, 0x01]);
    let (t, air) = deliver(seed.wrapping_add(5), GPD_NODE, SINK, &data_next);
    trace.extend(t);
    assert!(matches!(
        sink.receive(&air, false),
        SinkDecision::Handoff(_)
    ));
    decisions.push("data:handoff:advanced".to_string());

    (trace, decisions)
}

// RD-SIM-03: the bidirectional timeline runs commission → reply →
// pairing → data → dedup-drop with the air-model decision at every
// leg (PAIRED → HANDOFF → DEDUP-DROP).
#[test]
fn gp_bidir_intake_timeline_pairs_hands_off_and_dedups() {
    let (_, decisions) = scenario(0xB1D1);
    assert_eq!(
        decisions,
        vec![
            "ask:admit",
            "reply:served",
            "success:commissioned",
            "data:handoff:0104/ffff/00",
            "replay:drop:SecurityFailed",
            "data:handoff:advanced",
        ],
    );
}

// Decision determinism: the same seed + script replays the identical
// trace and the identical decision log.
#[test]
fn gp_bidir_replay_is_deterministic() {
    let (trace_a, decisions_a) = scenario(0x2222);
    let (trace_b, decisions_b) = scenario(0x2222);
    assert_eq!(trace_a, trace_b);
    assert_eq!(decisions_a, decisions_b);
    assert!(!trace_a.is_empty());
    assert_eq!(decisions_a.len(), 6);
}

// Mismatch + timeout edges: a foreign Success is refused and a
// lapsed window times out instead of completing.
#[test]
fn gp_bidir_mismatch_and_timeout_edges() {
    let mut sink = SinkSide::new();
    let ask = seal(SRCID, 1, true, &[0xe0, 0x02, 0xf3, 0x32]);
    assert_eq!(
        sink.receive(&ask, true),
        SinkDecision::AdmitCommissioning {
            gpd: SRCID as u64,
            endpoint: 0x00,
            command: 0xe0,
        },
    );
    sink.session.begin(CommissioningAnnouncement {
        app: AppId::SrcId,
        gpd: SRCID as u64,
        endpoint: 0x00,
        pan_id_request: true,
        key_request: false,
        rx_after_tx: true,
        security_capable: true,
        key_present: false,
    });
    assert_eq!(
        sink.session.complete_at(0).unwrap_err(),
        GpError::BidirectionalPending
    );
    // A secured Success from another GPD refuses as a transaction
    // mismatch (counter 1 is fresh for the foreign GPD, so the
    // refusal names the transaction, not the replay window).
    let foreign = seal(0x9999_9999, 1, false, &[CMD_SUCCESS]);
    assert_eq!(
        sink.receive(&foreign, false),
        SinkDecision::Drop(GpError::TransactionMismatch)
    );
    assert_eq!(
        sink.session.tick(REPLY_TIMEOUT_MS).unwrap_err(),
        GpError::ReplyTimeout
    );
    assert_eq!(sink.session.state(), CommissioningState::Idle);
}
