//! GPDF proxy→sink forwarding across the scripted medium with
//! deterministic replay.
//!
//! A GPD-originated GPDF travels GPD→proxy over the radio; the proxy
//! validates it (table, then security/freshness) and tunnels the
//! command proxy→sink over the radio; the sink accepts and translates
//! it. Replaying the same seed + script yields the identical trace.
//!
//! Requirement traceability: `14-0563-19-A38-01` (proxy flow),
//! `14-0563-19-A36-04` (tunneling), `14-0563-19-A36-05` (replay
//! protection), `14-0563-19-A36-06`/`-A36-07` (sink accept +
//! translate).

use rounddance_gp::*;
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap, MacMgmtSap, TxOptions, TxRequest, TxStatus,
};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};

const PAN: u16 = 0x1a2b;
const PROXY: u16 = 0x0001;
const SINK: u16 = 0x0002;
const SRCID: u32 = 0x1234_5678;

/// Hand-computed unsecured toggle frame: data / version 3 /
/// extension; SrcId identity; command 0x20 + payload 0x01.
fn gpdf_bytes() -> Vec<u8> {
    vec![0x8C, 0x00, 0x78, 0x56, 0x34, 0x12, 0x20, 0x01]
}

/// Tunneled record proxy→sink: canonical GPD key (LE u64), endpoint,
/// command, payload. The command travels in the clear with no MIC;
/// the stack layers protect the tunnel.
fn tunnel_bytes(note: &ProxyNotification) -> Vec<u8> {
    let mut out = vec![0u8; 8 + 1 + 1 + note.payload_bytes().len()];
    out[..8].copy_from_slice(&note.gpd.to_le_bytes());
    out[8] = note.endpoint;
    out[9] = note.command;
    out[10..].copy_from_slice(note.payload_bytes());
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

fn proxy_table() -> ProxyTable<4> {
    let mut table = ProxyTable::<4>::new();
    let mut e = ProxyTableEntry::new(AppId::SrcId, SRCID as u64);
    e.push_sink(SinkTarget::Group(0xABCD));
    table.upsert(e).unwrap();
    table
}

fn sink_side() -> (SinkTable<4>, TranslationTable<4>) {
    let mut sinks = SinkTable::<4>::new();
    sinks
        .upsert(SinkTableEntry::new(AppId::SrcId, SRCID as u64))
        .unwrap();
    let mut translations = TranslationTable::<4>::new();
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
    (sinks, translations)
}

/// One full scenario run: returns the medium traces plus the sink's
/// translated command triple.
fn scenario(seed: u64) -> (Vec<String>, (u16, u16, u8)) {
    let proxy = BasicProxy::new(false);
    let sink = SinkMachine::new(false);
    let mut table = proxy_table();
    let mut replay_p = GpReplay::<4>::new();
    let queue = GpTxQueue::<1>::new();

    // Leg 1: GPD→proxy.
    let (trace1, air1) = deliver(seed, PROXY, PROXY, &gpdf_bytes());
    assert_eq!(air1, gpdf_bytes());
    let (frame, _) = Gpdf::decode(&air1).unwrap();
    let note = match proxy.process(&frame, &mut table, &mut replay_p, &queue) {
        ProxyOutcome::Notify(n) => n,
        ProxyOutcome::Drop(r) => panic!("proxy dropped: {:?}", r),
    };

    // Leg 2: proxy→sink carries the tunneled command.
    let tunneled = tunnel_bytes(&note);
    let (trace2, air2) = deliver(seed.wrapping_add(1), PROXY, SINK, &tunneled);
    assert_eq!(air2, tunneled);

    // Sink side: accept + translate.
    let (mut sinks, translations) = sink_side();
    let mut replay_s = GpReplay::<4>::new();
    let mut gpd_raw = [0u8; 8];
    gpd_raw.copy_from_slice(&air2[..8]);
    let translated = match sink.accept(
        GpdId::SrcId(u64::from_le_bytes(gpd_raw) as u32),
        WireSecurityLevel::None,
        false,
        None,
        air2[9],
        &air2[10..],
        0,
        &mut sinks,
        &translations,
        &mut replay_s,
    ) {
        SinkOutcome::Translate(t) => t,
        SinkOutcome::Drop(e) => panic!("sink dropped: {:?}", e),
        SinkOutcome::ForwardGroup { .. } => panic!("unexpected group forward"),
    };

    let mut trace = trace1;
    trace.extend(trace2);
    (
        trace,
        (translated.profile, translated.cluster, translated.command),
    )
}

// 14-0563-19-A38-01 + A36-04 + A36-06 + A36-07: GPDF proxy→sink
// forwarding end to end — the sink translates the tunneled toggle
// into On/Off-cluster command 0x01.
#[test]
fn gp_proxy_sink_forwarding_two_node() {
    let (_, triple) = scenario(0x6A0D);
    assert_eq!(triple, (0x0104, 0x0006, 0x01));
}

// Decision determinism: the same seed + script replays the identical
// trace and the identical translated command.
#[test]
fn gp_forwarding_replay_is_deterministic() {
    let (trace_a, triple_a) = scenario(0x1234);
    let (trace_b, triple_b) = scenario(0x1234);
    assert_eq!(trace_a, trace_b);
    assert_eq!(triple_a, triple_b);
    assert!(!trace_a.is_empty());
}

// Proxy→sink forwarding (matrix): the translated triple is
// timing-independent. Four seeds incl. the 0/u64::MAX edges —
// per-seed double runs replay the identical trace + triple, and every
// seed translates the tunneled toggle into the On/Off-cluster command
// 0x01 (same timing-vs-decision split as the RD-SIM-03 / RD-GP-intake
// matrices: Delay jitter moves `queued_us` timestamps, never the
// translated triple — the naive cross-seed trace pin fails on those
// timestamps only).
#[test]
fn gp_forwarding_matrix_seeds_share_triple() {
    const SEEDS: [u64; 4] = [0x0000, 0x6A0D, 0x1234, u64::MAX];
    for &seed in &SEEDS {
        let (trace_a, triple_a) = scenario(seed);
        let (trace_b, triple_b) = scenario(seed);
        assert_eq!(trace_a, trace_b, "per-seed trace replay, seed {seed:#x}");
        assert_eq!(triple_a, triple_b, "per-seed triple replay, seed {seed:#x}");
        assert_eq!(
            triple_a,
            (0x0104, 0x0006, 0x01),
            "cross-seed triple pin, seed {seed:#x}"
        );
        assert!(!trace_a.is_empty());
    }
}
