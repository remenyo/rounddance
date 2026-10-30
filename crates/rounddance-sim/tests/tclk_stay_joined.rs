//! Joiner-initiated TCLK stay-joined scenario over scripted media:
//! Request-Key (key type `0x04`) → TC link-key transport → Verify-Key
//! → Confirm-Key (status `0x00`) → stay-joined with no Leave from
//! either side.
//!
//! Decision-matched to the wave-61 air timelines
//! (`~/hwscratch/w61/lane1/SUMMARY.md`, 3/3 cycles vs ZBOSS, first-try
//! CONFIRM `0x00`, `DEVICE_AUTHORIZED` type 1 status 0, zero
//! TC→joiner Leaves): latch→CONFIRM ~3.6 s inside the ~13.6 s eject
//! budget, joined ~78.8 s, no-Leave invariant. Replaying the same
//! seed + script yields the identical trace (decision determinism).
//!
//! Crypto stays opaque by construction (the same discipline as
//! `join_tc_first.rs`): the medium carries one-octet leg tags, never
//! key material or sealed bodies. The classified decision fields
//! (command id, key type, MIC outcome, confirm status) are handed to
//! the machines exactly as the hwscratch offline open hands the
//! decrypted fields to its battery — established there, cited here,
//! never re-proved here.
//!
//! Requirement traceability: `RD-SIM-01` (joiner-initiated TCLK update
//! sequencing), `RD-SIM-02` (this stay-joined sim scenario with the
//! w61 decision-matched timeline, the no-Leave invariant, and
//! determinism replay).

use rounddance_commission::{
    JoinError, JoinMethod, JoinPolicy, JoinerMachine, JoinerState, KeyAttributes, TclkState,
    TclkUpdate, TrustCenter, CONFIRM_KEY_STATUS_SUCCESS, TRANSPORT_KEY_CMD,
    TRANSPORT_KEY_TYPE_TCLK,
};
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap, MacMgmtSap, TxOptions, TxRequest, TxStatus,
};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};

const PAN: u16 = 0x1a2b;
const TC_SHORT: u16 = 0x0000;
const JOINER_SHORT: u16 = 0x3bce;
const JOINER_IEEE: u64 = 0x0200_0000_0000_0007;

// Opaque leg tags on the scripted medium: one octet per TCLK leg.
// Stand-ins for the sealed frames, NOT wire claims — the crypto and
// command encoding stay off-repo (see module docs).
const LEG_REQUEST: u8 = 0x01;
const LEG_TRANSPORT: u8 = 0x02;
const LEG_VERIFY: u8 = 0x03;
const LEG_CONFIRM: u8 = 0x04;
// Stay-joined poll while authorized (air: 12–36 acked polls per
// cycle, SUMMARY.md §4): proves the medium still serves the device
// long after CONFIRM with no eject.
const LEG_POLL: u8 = 0x05;

// w61 cycle-1 air deltas, microseconds (SUMMARY.md §4: latch 2.21,
// req 3.45, tclk 3.67, verify 5.45, confirm 5.83; joined 78.75 s).
// Each leg send consumes one scripted delay, so the gaps below are
// cumulative send-to-send spacings: req is sent at the latch, the
// transport 1.46 s later (1.24 + 0.22), verify 1.78 s after that,
// confirm 0.38 s after that — latch→CONFIRM ~3.62 s, cited ~3.6 s.
const LATCH_TO_TRANSPORT_US: u64 = 1_460_000;
const TRANSPORT_TO_VERIFY_US: u64 = 1_780_000;
const VERIFY_TO_CONFIRM_US: u64 = 380_000;
const LATCH_TO_CONFIRM_US: u64 =
    LATCH_TO_TRANSPORT_US + TRANSPORT_TO_VERIFY_US + VERIFY_TO_CONFIRM_US;
// The w60-measured eject budget the update must fit inside (§0:
/// ~13.6 s post-commission ZBOSS `R21_TCLK` TIMEOUT → NWK Leave).
const TCLK_EJECT_BUDGET_US: u64 = 13_600_000;
// w61 cycle-1 joined span, latch→done (78.75 s, cited as ~78.8 s).
const JOINED_SPAN_US: u64 = 78_750_000;

fn policy() -> JoinPolicy {
    JoinPolicy {
        cbke_supported: false,
        cbke_required: false,
        interview_tc: false,
        parent_is_r20_earlier: false,
    }
}

/// One scripted TCLK leg: send the opaque tag, drain, and require the
/// delivery confirm. Returns the virtual send instant.
fn send_leg(radio: &mut ScriptedRadio, tag: u8) -> u64 {
    let sent_us = radio.now_us();
    radio
        .data_request(TxRequest {
            dst: MacAddress::short(PAN, TC_SHORT),
            msdu: FramePayload::from_slice(&[tag]).expect("leg tag fits"),
            options: TxOptions::ACK,
        })
        .expect("queue has room");
    radio.run_until_idle(8);
    let confirm = radio.poll_confirm().expect("script always confirms");
    assert_eq!(confirm.status, TxStatus::Delivered, "leg {tag:#04x}");
    let heard = radio
        .poll_indication()
        .expect("delivery implies indication");
    assert_eq!(heard.msdu.as_slice(), &[tag], "medium preserves leg");
    sent_us
}

/// Full stay-joined run. Returns the decision log plus the air
/// timeline markers (latch, confirm, end) and the medium trace.
fn stay_joined(seed: u64) -> (Vec<String>, u64, u64, u64, Vec<String>) {
    let mut log = Vec::new();

    // Phase 0: the device is already joined (TC-first path, same
    // shape as `join_tc_first.rs` without the captured envelope).
    let mut tc = TrustCenter::new();
    tc.open();
    tc.set_allow_list(&[JOINER_IEEE]);
    let mut joiner = JoinerMachine::new(JoinMethod::InstallCode, policy());
    joiner.on_candidate();
    joiner.on_assoc_confirm(true);
    joiner.note_transport_frame(TRANSPORT_KEY_CMD, 0x01);
    joiner.on_transport_open(true, 0x0001_0400);
    joiner.on_verify_confirm(true, KeyAttributes::SYMMETRIC);
    joiner.close_out(false);
    assert_eq!(joiner.state(), JoinerState::Joined);
    log.push("phase0-joined".to_string());

    tc.admit(
        JOINER_IEEE,
        JOINER_SHORT,
        JoinMethod::InstallCode,
        1_000_000,
    )
    .unwrap();
    let initial = [0x11u8; 16];
    tc.exchange_key(JOINER_IEEE, &[0x22u8; 16], &initial, 0x04)
        .unwrap();
    tc.on_verify_confirm(JOINER_IEEE, true).unwrap();
    assert!(tc.find(JOINER_IEEE).is_some_and(|d| d.verified));

    // Phase 1: the joiner-initiated TCLK update, four legs over one
    // scripted medium. Each leg send consumes one scripted delay, so
    // the send-to-send spacings replay the w61 air gaps exactly.
    let mut radio = ScriptedRadio::new(
        Seed(seed),
        vec![
            ScriptAction::Delay {
                base_us: 0,
                jitter_us: 0,
            },
            ScriptAction::Delay {
                base_us: LATCH_TO_TRANSPORT_US,
                jitter_us: 0,
            },
            ScriptAction::Delay {
                base_us: TRANSPORT_TO_VERIFY_US,
                jitter_us: 0,
            },
            ScriptAction::Delay {
                base_us: VERIFY_TO_CONFIRM_US,
                jitter_us: 0,
            },
            ScriptAction::Delay {
                base_us: JOINED_SPAN_US - LATCH_TO_CONFIRM_US,
                jitter_us: 0,
            },
        ],
    );
    radio.reset(true);
    radio.set_channel(Channel::new(15).unwrap()).unwrap();
    radio.set_pan_id(PAN);
    radio.set_short_addr(JOINER_SHORT);

    let mut tclk = TclkUpdate::new();
    tclk.begin();
    assert_eq!(tclk.state(), TclkState::RequestSent);

    // Latch instant: the transport open, air t=2.21 (auxctr 0x400).
    let latch_us = radio.now_us();
    log.push(format!("latch t={latch_us}"));
    let _ = send_leg(&mut radio, LEG_REQUEST);

    // Wrong-type-first is tolerated mid-update, exactly as at join:
    // a network-key-typed transport names no TCLK and latches nothing.
    tclk.note_transport_frame(TRANSPORT_KEY_CMD, 0x01);
    assert_eq!(tclk.state(), TclkState::RequestSent);
    assert!(!tclk.tclk_latched());
    log.push("foreign-type-tolerated".to_string());

    // The genuine TCLK transport (0x05/0x04), opened under the
    // key-load key per the hwscratch battery (MIC valid, fresh key
    // differs from the stored one on the TC side).
    let _ = send_leg(&mut radio, LEG_TRANSPORT);
    tclk.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_TCLK);
    assert_eq!(tclk.state(), TclkState::KeyWait);
    let fresh = [0x33u8; 16];
    tc.exchange_key(JOINER_IEEE, &fresh, &initial, 0x04)
        .unwrap();
    tclk.on_transport_open(true);
    assert!(tclk.tclk_latched());
    log.push("transport-open-tclk-latched".to_string());

    // Verify-Key, then Confirm-Key status 0x00 opened under the
    // fresh TCLK (air t=5.83) — the TC authorizes on success.
    let _ = send_leg(&mut radio, LEG_VERIFY);
    tclk.note_verify_sent();
    assert_eq!(tclk.state(), TclkState::VerifySent);
    let _ = send_leg(&mut radio, LEG_CONFIRM);
    let confirm_us = radio.now_us();
    tclk.on_confirm(CONFIRM_KEY_STATUS_SUCCESS);
    tc.on_verify_confirm(JOINER_IEEE, true).unwrap();
    assert_eq!(tclk.state(), TclkState::Authorized);
    log.push(format!("confirm-ok t={confirm_us} state=Authorized"));

    // Decision-matched timeline: latch→CONFIRM ~3.6 s, inside the
    // ~13.6 s eject budget with ~10 s to spare (w61 §0).
    assert_eq!(confirm_us - latch_us, LATCH_TO_CONFIRM_US);
    assert!(confirm_us - latch_us < TCLK_EJECT_BUDGET_US);
    // ~10 s to spare at the scripted deltas (9.98 s: 13.6 − 3.62).
    assert!(TCLK_EJECT_BUDGET_US - (confirm_us - latch_us) >= 9_900_000);
    log.push("timeline-latch-confirm-3.6s-in-budget".to_string());

    // Stay-joined: one acked poll at the far end of the joined span
    // — no Leave is ever emitted on either side (w61: zero
    // TC→joiner Leaves in 300 s; the 6 joiner→TC legs were our own
    // removals, out of scope here). The TC deadline window is
    // generous, so a `tick` that reported an eviction would fail the
    // invariant.
    let _ = send_leg(&mut radio, LEG_POLL);
    let end_us = radio.now_us();
    assert!(end_us - latch_us >= JOINED_SPAN_US);
    let mut evicted = [0u64; 4];
    assert_eq!(tc.tick(&mut evicted), 0, "no TC eviction while joined");
    assert_eq!(tclk.state(), TclkState::Authorized);
    assert!(tc.find(JOINER_IEEE).is_some_and(|d| d.verified));
    log.push(format!("stay-joined t={end_us} no-leave"));

    // The trace carries every leg delivery and no leave-shaped stop.
    let trace = radio.trace_lines().to_vec();
    assert!(
        trace.iter().filter(|l| l.contains("confirm")).count() >= 5,
        "five legs confirmed, trace:\n{}",
        trace.join("\n")
    );
    assert!(
        !trace.iter().any(|l| l.contains("leave")),
        "no leave leg on the medium"
    );
    (log, latch_us, confirm_us, end_us, trace)
}

// RD-SIM-02 (matrix): the stay-joined decision log, the air timeline
// markers, and the medium trace are seed-independent — four seeds
// incl. the 0/u64::MAX edges, double-run per seed. Exact scripted
// delays (jitter 0) make even the trace cross-seed identical, unlike
// the jittered GP timelines where only decisions pin across seeds.
#[test]
fn tclk_matrix_seeds_share_log_and_trace() {
    const SEEDS: [u64; 4] = [0x0000, 0x7C1C, 0xBEEF, u64::MAX];
    for &seed in &SEEDS {
        let run_a = stay_joined(seed);
        let run_b = stay_joined(seed);
        assert_eq!(run_a, run_b, "per-seed replay, seed {seed:#x}");
        assert_eq!(
            run_a.0,
            vec![
                "phase0-joined".to_string(),
                format!("latch t={}", run_a.1),
                "foreign-type-tolerated".to_string(),
                "transport-open-tclk-latched".to_string(),
                format!("confirm-ok t={} state=Authorized", run_a.2),
                "timeline-latch-confirm-3.6s-in-budget".to_string(),
                format!("stay-joined t={} no-leave", run_a.3),
            ],
            "cross-seed decision pin, seed {seed:#x}"
        );
        assert_eq!(run_a.2 - run_a.1, LATCH_TO_CONFIRM_US);
    }
    // Exact delays: the first and last seeds share one trace.
    assert_eq!(stay_joined(SEEDS[0]).4, stay_joined(SEEDS[3]).4);
}

// RD-SIM-02: the full stay-joined run, first-try confirm, ~78.8 s
// joined, no-Leave invariant, budget margin pinned.
#[test]
fn tclk_stay_joined_first_try_no_leave() {
    let (log, latch_us, confirm_us, end_us, _trace) = stay_joined(0x7C1C);
    assert_eq!(confirm_us - latch_us, LATCH_TO_CONFIRM_US);
    assert!(end_us - latch_us >= JOINED_SPAN_US);
    assert_eq!(
        log,
        vec![
            "phase0-joined".to_string(),
            format!("latch t={latch_us}"),
            "foreign-type-tolerated".to_string(),
            "transport-open-tclk-latched".to_string(),
            format!("confirm-ok t={confirm_us} state=Authorized"),
            "timeline-latch-confirm-3.6s-in-budget".to_string(),
            format!("stay-joined t={end_us} no-leave"),
        ]
    );
}

// RD-SIM-02: decision determinism — same seed + script replays the
// identical decision log and the identical trace.
#[test]
fn tclk_stay_joined_replay_is_deterministic() {
    let (log_a, latch_a, confirm_a, end_a, trace_a) = stay_joined(0x7C1C);
    let (log_b, latch_b, confirm_b, end_b, trace_b) = stay_joined(0x7C1C);
    assert_eq!(
        (&log_a, latch_a, confirm_a, end_a),
        (&log_b, latch_b, confirm_b, end_b)
    );
    assert_eq!(trace_a, trace_b);
    // A different seed still decides identically (delays are exact,
    // not seeded) while the RNG stream differs — the log is
    // seed-independent by construction.
    let (log_c, _, _, _, _) = stay_joined(0xBEEF);
    assert_eq!(log_c, log_b);
}

// RD-SIM-01 (sim side): a TC eject received mid-update ends the
// attempt with `JoinTimeout` instead of authorizing — the invariant
// is load-bearing, not decorative.
#[test]
fn tclk_eject_mid_update_never_authorizes() {
    let mut update = TclkUpdate::new();
    update.begin();
    update.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_TCLK);
    update.on_transport_open(true);
    update.on_leave();
    assert_eq!(update.state(), TclkState::Failed);
    assert_eq!(update.error(), Some(JoinError::JoinTimeout));
    assert!(update.tclk_latched());
}
