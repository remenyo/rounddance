//! GP sink scenario: commission → data → dedup-drop → reply across
//! the scripted medium with deterministic replay.
//!
//! A secured commissioning announcement from an unknown GPD admits
//! through the unified sink intake while the commissioning mode is
//! open; the session commissions and pairs the GPD, whose secured
//! data hands off to NWK, whose replayed counter drops, and whose
//! advanced counter hands off again. A second GPD's secured
//! receive-after-transmit ask parks a bidirectional session; the sink
//! serves the staged reply over the radio and the GPD's Success
//! frame commissions it through the same intake. Replaying the same
//! seed + script yields the identical trace and decision log.
//!
//! Decision match to the air model: every leg's sink decision equals
//! the `analyze52_gp.py` classifier outcome for that shape
//! (unsecured data accepts, unprotected reply-path range refuses,
//! protected shapes decide by slot + freshness), and the embedded
//! census pins sum to the 519-GPDF oracle total across the ten w51
//! lane-1 captures (metadata, first pinned in
//! `rounddance-inspect/tests/live_air.rs`).
//!
//! Requirement traceability: RD-GP-02..06 (intake decisions),
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
const SRCID_A: u32 = 0x1111_1111;
const SRCID_B: u32 = 0x2222_2222;

/// Test-only GP key (committed; lab keys stay local-only).
const TEST_KEY: [u8; 16] = [0x5au8; 16];

const SERVE_AT_MS: u64 = 22;

// Air-model census pins (metadata): per-shape GPDF counts across
// the ten w51 lane-1 captures, summing to the oracle total.
const PLAIN_DATA: usize = 46;
const PLAIN_COMM_LONG: usize = 162;
const PLAIN_COMM_COMPACT: usize = 20;
const SEC_DATA: usize = 193;
const SEC_DECOMM: usize = 42;
const SEC_COMM_LONG: usize = 10;
const RX_AFTER_TX_COMM: usize = 10;
const ENCRYPTED: usize = 36;

#[test]
fn census_pins_sum_to_oracle_total() {
    assert_eq!(
        PLAIN_DATA
            + PLAIN_COMM_LONG
            + PLAIN_COMM_COMPACT
            + SEC_DATA
            + SEC_DECOMM
            + SEC_COMM_LONG
            + RX_AFTER_TX_COMM
            + ENCRYPTED,
        519,
        "w51 oracle: 519 GPDFs across 10 pcaps"
    );
}

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
        id: Some(GpdId::SrcId(SRCID_B)),
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
        let mut translations = TranslationTable::<8>::new();
        translations
            .upsert(
                TranslationSeed {
                    app: AppId::SrcId,
                    gpd: GENERIC_SRC_ID as u64,
                    endpoint: 0xFF,
                    gpd_command: GENERIC_GPD_COMMAND,
                    profile: 0x0104,
                    cluster: 0x0006,
                    command: 0x01,
                }
                .materialize(),
            )
            .unwrap();
        Self {
            keys,
            session: CommissioningSession::new(),
            sinks: SinkTable::<8>::new(),
            translations,
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
/// decision log, decision-for-decision against the air model.
fn scenario(seed: u64) -> (Vec<String>, Vec<String>) {
    let mut trace = Vec::new();
    let mut decisions = Vec::new();
    let mut sink = SinkSide::new();

    // Leg 1 — commission: secured announcement from the unknown GPD
    // admits while the mode is open; the session commissions and the
    // pairing installs (entry names the secured level + key class).
    let ann = seal(SRCID_A, 3, false, &[0xe0, 0x02, 0x43]);
    let (t, air) = deliver(seed, GPD_NODE, SINK, &ann);
    trace.extend(t);
    assert_eq!(
        sink.receive(&air, true),
        SinkDecision::AdmitCommissioning {
            gpd: SRCID_A as u64,
            endpoint: 0x00,
            command: 0xe0,
        },
    );
    decisions.push("commission:admit".to_string());
    sink.session.begin(CommissioningAnnouncement {
        app: AppId::SrcId,
        gpd: SRCID_A as u64,
        endpoint: 0x00,
        pan_id_request: false,
        key_request: false,
        rx_after_tx: false,
        security_capable: true,
        key_present: false,
    });
    let planted = sink.session.complete().unwrap().unwrap();
    let mut entry = SinkTableEntry::new(AppId::SrcId, SRCID_A as u64);
    entry.endpoint = 0x00;
    entry.level = WireSecurityLevel::MicOnly;
    entry.key_bit = true;
    sink.sinks.upsert(entry).unwrap();
    sink.translations.upsert(planted.materialize()).unwrap();
    assert_eq!(sink.session.state(), CommissioningState::Commissioned);

    // Leg 2 — data: secured toggle hands off to the paired
    // endpoints with the translated On/Off-cluster command.
    let data = seal(SRCID_A, 4, false, &[0x20, 0x01]);
    let (t, air) = deliver(seed.wrapping_add(1), GPD_NODE, SINK, &data);
    trace.extend(t);
    match sink.receive(&air, false) {
        SinkDecision::Handoff(h) => {
            // The commission-installed specific entry supersedes the
            // generic fixture entry: default profile, triggering
            // cluster, command zero.
            assert_eq!((h.profile, h.cluster, h.command), (0x0104, 0xFFFF, 0x00));
            assert_eq!(h.route, NwkRoute::PairedEndpoints);
            decisions.push("data:handoff:0104/ffff/00".to_string());
        }
        other => panic!("expected handoff, got {:?}", other),
    }

    // Leg 3 — dedup-drop: the replayed counter drops, the advanced
    // counter hands off again.
    let (t, air) = deliver(seed.wrapping_add(2), GPD_NODE, SINK, &data);
    trace.extend(t);
    assert_eq!(
        sink.receive(&air, false),
        SinkDecision::Drop(GpError::SecurityFailed),
    );
    decisions.push("replay:drop:SecurityFailed".to_string());
    let data_next = seal(SRCID_A, 5, false, &[0x20, 0x01]);
    let (t, air) = deliver(seed.wrapping_add(3), GPD_NODE, SINK, &data_next);
    trace.extend(t);
    assert!(matches!(
        sink.receive(&air, false),
        SinkDecision::Handoff(_)
    ));
    decisions.push("data:handoff:advanced".to_string());

    // Leg 4 — reply: a second GPD's secured receive-after-transmit
    // ask admits and parks a bidirectional session; the sink stages
    // the PANID reply, serves it inside the 20–25 ms window over the
    // radio, and the GPD's Success frame commissions it through the
    // same intake.
    let ask = seal(SRCID_B, 1, true, &[0xe0, 0x02, 0xf3, 0x32]);
    let (t, air) = deliver(seed.wrapping_add(4), GPD_NODE, SINK, &ask);
    trace.extend(t);
    assert_eq!(
        sink.receive(&air, true),
        SinkDecision::AdmitCommissioning {
            gpd: SRCID_B as u64,
            endpoint: 0x00,
            command: 0xe0,
        },
    );
    decisions.push("ask:admit".to_string());
    sink.session.begin(CommissioningAnnouncement {
        app: AppId::SrcId,
        gpd: SRCID_B as u64,
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
    let (t, got) = deliver(seed.wrapping_add(5), SINK, GPD_NODE, &served);
    trace.extend(t);
    assert_eq!(got, served);
    decisions.push("reply:served".to_string());
    let success = [0x8cu8, 0x00, 0x22, 0x22, 0x22, 0x22, 0xe2];
    let (t, air) = deliver(seed.wrapping_add(6), GPD_NODE, SINK, &success);
    trace.extend(t);
    assert_eq!(
        sink.receive(&air, false),
        SinkDecision::Commissioned {
            gpd: SRCID_B as u64,
            endpoint: 0x00,
        },
    );
    decisions.push("success:commissioned".to_string());
    assert!(sink.sinks.find(GpdId::SrcId(SRCID_B)).is_some());

    // The paired GPD's unsecured data now hands off (its Success
    // frame paired the no-security level).
    let plain_b = [0x8cu8, 0x00, 0x22, 0x22, 0x22, 0x22, 0x20, 0x01];
    let (t, air) = deliver(seed.wrapping_add(7), GPD_NODE, SINK, &plain_b);
    trace.extend(t);
    assert!(matches!(
        sink.receive(&air, false),
        SinkDecision::Handoff(_)
    ));
    decisions.push("data-b:handoff".to_string());

    (trace, decisions)
}

// RD-GP-02..06: the sink scenario runs commission → data →
// dedup-drop → reply with the air-model decision at every leg.
#[test]
fn gp_sink_commission_data_dedup_reply() {
    let (_, decisions) = scenario(0x51A6);
    assert_eq!(
        decisions,
        vec![
            "commission:admit",
            "data:handoff:0104/ffff/00",
            "replay:drop:SecurityFailed",
            "data:handoff:advanced",
            "ask:admit",
            "reply:served",
            "success:commissioned",
            "data-b:handoff",
        ],
    );
}

// Decision determinism: the same seed + script replays the identical
// trace and the identical decision log.
#[test]
fn gp_sink_replay_is_deterministic() {
    let (trace_a, decisions_a) = scenario(0x2222);
    let (trace_b, decisions_b) = scenario(0x2222);
    assert_eq!(trace_a, trace_b);
    assert_eq!(decisions_a, decisions_b);
    assert!(!trace_a.is_empty());
    assert_eq!(decisions_a.len(), 8);
}

// RD-GP intake (matrix): sink decisions are timing-independent. Four
// seeds incl. the 0/u64::MAX edges — per-seed double runs replay the
// identical trace + decision log, and every seed decides the proven
// 8-decision intake timeline (same timing-vs-decision split as the
// RD-SIM-03 matrix: jitter moves timestamps, never decisions).
#[test]
fn gp_sink_matrix_seeds_share_decisions() {
    const SEEDS: [u64; 4] = [0x0000, 0x51A6, 0x2222, u64::MAX];
    const PIN: [&str; 8] = [
        "commission:admit",
        "data:handoff:0104/ffff/00",
        "replay:drop:SecurityFailed",
        "data:handoff:advanced",
        "ask:admit",
        "reply:served",
        "success:commissioned",
        "data-b:handoff",
    ];
    for &seed in &SEEDS {
        let (trace_a, decisions_a) = scenario(seed);
        let (trace_b, decisions_b) = scenario(seed);
        assert_eq!(trace_a, trace_b, "per-seed trace replay, seed {seed:#x}");
        assert_eq!(
            decisions_a, decisions_b,
            "per-seed decision replay, seed {seed:#x}"
        );
        assert_eq!(
            decisions_a,
            PIN.map(str::to_string),
            "cross-seed decision pin, seed {seed:#x}"
        );
        assert!(!trace_a.is_empty());
    }
}
