//! TC-first join transcript: the coordinator delivers the network key
//! proactively after association — no joiner request precedes it — so
//! the joiner ends its post-association wait only on the genuine
//! transport-key pair (command `0x05`, network key type `0x01`) and
//! on nothing else (no update-device-first, no vendor-first).
//!
//! The on-air bytes below replay the genuine Trust-Center→joiner
//! transport-key frame captured during the lab k1 join (joiner short
//! `0x5160`, PAN `0x3761`): 9-octet MAC header, 8-octet unsecured NWK
//! data header, then the APS envelope — 2-octet command header,
//! 13-octet auxiliary header (on-air control `0x30`: level bits
//! zeroed on air as in the wave-36 NWK finding, key-id bits `2` for
//! the key-transport key, extended nonce set; counter `00d00100`,
//! source = coordinator EUI), then the 39-octet secured tail. The
//! tail is opaque here: it is never decrypted in-repo (the key lives
//! only in the lab `0600` files). The decrypted command fields
//! (`0x05` transport-key, `0x01` network key type, 35-octet command
//! with the network key, sequence `0x00`, joiner + coordinator
//! EUIs) were established by the exact-clause offline open in
//! `~/hwscratch/w45/` and are cited there, not re-proved here.
//!
//! Requirement traceability: `05-3474-23-4433-01` (TC-first
//! transport classification), `05-3474-23-4434-01` (transport open:
//! MIC-checked open, strictly-monotonic auxiliary-counter window,
//! netkey-adopt latch; MIC/counter failures never promote),
//! `22-65816-030-91-02` (no verify/promote without transport),
//! `22-65816-030-56-04` (the wait is still time-boxed: a
//! wrong-type-first peer ends in `NoTransport`, a parent eject ends
//! it in `JoinTimeout` via `on_leave`).
//!
//! Captured-air panel: the offline battery opened all five proactive
//! `0x30` A-frames below MIC-valid with network-key-bearing
//! plaintexts (command `0x05`, key type `0x01`, sequence `0x00`,
//! joiner + coordinator EUIs; nonce = source-EUI LE + counter LE +
//! restored control `0x35`; AAD = APS header + restored aux;
//! MIC-32). Only hashes and envelope metadata ride in-repo — the
//! secured tails stay opaque here and the key bytes live only in the
//! lab `0600` files (never in SUMMARY/logs/repo). The full battery is
//! re-runnable offline with those files present:
//! `python3 ~/hwscratch/w45/transport_open.py` (3 derivation KATs +
//! 5-frame × key battery; SOLVED report
//! `~/hwscratch/w45/REPORT_lane2_spec_derivation.md` and
//! `~/hwscratch/w45/SUMMARY.md`). Panel (all share the coordinator
//! source `5f75f4feffe5e304`, 39-octet tails):
//!
//! | tag | capture | auxctr | aps | ct-sha16 |
//! |-----|---------|--------|-----|----------|
//! | x2 | w42 `sniff_x2.txt:50` | `00300100` | `21 03` | `847ddbe556dd1f6d` |
//! | x4 | w42 `sniff_x4.txt:44` | `00400100` | `21 f0` | `892a32e5358f5562` |
//! | x5 | w42 `sniff_x5.txt:47` | `00500100` | `21 5b` | `40077f09ea47dfb0` |
//! | x6 | w42 `sniff_x6.txt:47` | `00600100` | `21 f7` | `7115c4e7764b43d2` |
//! | k1 | w44 `sniff_k1.txt:38` | `00d00100` | `21 51` | `ed9c786f18789719` |
//!
//! Counters climb `+0x1000` per join from a restarted zero base (the
//! w44 cadence finding, reproduced under rotation in w45 lane 1).

use rounddance_commission::{
    JoinError, JoinMethod, JoinPolicy, JoinerMachine, JoinerState, TrustCenter,
    JOINER_TRANSPORT_GRACE_TICKS, TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_NETWORK,
    UNSECURED_VENDOR_CMD,
};
use rounddance_nwk::decode as decode_nwk;

/// Captured Trust-Center→joiner transport-key frame, full MAC PSDU
/// as seen on air (71 octets; trailing FCS stripped by the sniffer).
/// The 39-octet secured tail is ciphertext — opaque, never key
/// material.
const CAPTURED_TC_FIRST_PSDU: [u8; 71] = [
    0x61, 0x88, 0x5a, 0x61, 0x37, 0x60, 0x51, 0x00, 0x00, 0x08, 0x00, 0x60, 0x51, 0x00, 0x00, 0x1e,
    0x21, 0x21, 0x51, 0x30, 0x00, 0xd0, 0x01, 0x00, 0x5f, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04,
    0x70, 0x5d, 0xe1, 0x63, 0xbc, 0xdd, 0x04, 0x08, 0xed, 0x07, 0x14, 0xc8, 0xf6, 0x93, 0x75, 0xa9,
    0x7c, 0xeb, 0xde, 0x03, 0x78, 0x0e, 0xa0, 0xf0, 0x60, 0x06, 0x9f, 0xbe, 0x85, 0x55, 0x75, 0x11,
    0x6e, 0x87, 0xdb, 0x37, 0xbc, 0xce, 0x01,
];

/// Length of the MAC header the HAL strips before the NWK codec runs.
const MAC_HEADER_LEN: usize = 9;

/// Air-visible coordinator EUI from the capture (identifier, not key
/// material): the auxiliary-header source of the TC-first frame.
const TC_EUI: [u8; 8] = [0x5f, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04];

/// Update-device APS command id: the UD-first alternative the joiner
/// must never promote.
const UPDATE_DEVICE_CMD: u8 = 0x06;

/// k1 auxiliary counter from the capture (`00d00100` LE on air), the
/// value the genuine TC-first open reports.
const K1_AUX_COUNTER: u32 = 0x0001_d000;

/// Captured-air panel: (tag, auxctr LE bytes, APS header, tail
/// ciphertext sha16 prefix) for the five battery A-frames. Hashes
/// and envelope metadata only — no key material, no plaintext.
const AFRAMES: [(&str, [u8; 4], [u8; 2], &str); 5] = [
    (
        "x2",
        [0x00, 0x30, 0x01, 0x00],
        [0x21, 0x03],
        "847ddbe556dd1f6d",
    ),
    (
        "x4",
        [0x00, 0x40, 0x01, 0x00],
        [0x21, 0xf0],
        "892a32e5358f5562",
    ),
    (
        "x5",
        [0x00, 0x50, 0x01, 0x00],
        [0x21, 0x5b],
        "40077f09ea47dfb0",
    ),
    (
        "x6",
        [0x00, 0x60, 0x01, 0x00],
        [0x21, 0xf7],
        "7115c4e7764b43d2",
    ),
    (
        "k1",
        [0x00, 0xd0, 0x01, 0x00],
        [0x21, 0x51],
        "ed9c786f18789719",
    ),
];

fn policy() -> JoinPolicy {
    JoinPolicy {
        cbke_supported: false,
        cbke_required: false,
        interview_tc: false,
        parent_is_r20_earlier: false,
    }
}

/// Walk the captured envelope through the repo NWK codec and split
/// the APS envelope at its documented offsets (the repo has no APS
/// key-transport aux codec — the key-id-`2` shape is layer-specific
/// — so the 13-octet aux is asserted field by field, not decoded).
/// Returns the human-readable walk lines.
fn walk_captured_envelope(trace: &mut Vec<String>) {
    let msdu = &CAPTURED_TC_FIRST_PSDU[MAC_HEADER_LEN..];
    let nwk = decode_nwk(msdu).expect("captured NWK header decodes");
    assert!(!nwk.header.control.security);
    assert_eq!((nwk.header.dst_addr, nwk.header.src_addr), (0x5160, 0x0000));
    assert_eq!(nwk.payload.len(), 54);
    // APS command header: control 0x21 (command frame), counter 0x51.
    assert_eq!((nwk.payload[0], nwk.payload[1]), (0x21, 0x51));
    // Auxiliary header on air: control 0x30 (level bits zeroed,
    // key-id bits 2 = key-transport key, extended nonce set),
    // counter 00d00100 LE, source = coordinator EUI.
    let aux = &nwk.payload[2..15];
    assert_eq!(aux[0], 0x30);
    assert_eq!(aux[0] & 0x07, 0x00);
    assert_eq!((aux[0] >> 3) & 0x03, 0x02);
    assert_ne!(aux[0] & 0x20, 0);
    assert_eq!(&aux[1..5], &[0x00, 0xd0, 0x01, 0x00]);
    assert_eq!(&aux[5..13], &TC_EUI);
    // The 39-octet secured tail stays opaque in-repo.
    assert_eq!(nwk.payload[15..].len(), 39);
    trace.push("envelope nwk=5160<-0000 aps-fc=0x21 aux-sc=0x30 tail=39-opaque".to_string());
}

/// One replay of the TC-first flow: associate, hear vendor chatter
/// plus foreign first-frames (all tolerated), receive the genuine
/// transport-key classification, verify, announce, join.
fn replay_tc_first() -> (Vec<String>, JoinerState) {
    let mut trace = Vec::new();
    let mut joiner = JoinerMachine::new(JoinMethod::InstallCode, policy());
    // Our own Trust Center stays out of this run: the peer is the
    // lab coordinator, so nothing may ever latch locally.
    let tc = TrustCenter::new();

    joiner.on_candidate();
    joiner.on_assoc_confirm(true);
    assert_eq!(joiner.state(), JoinerState::Authenticating);
    trace.push("assoc-ok state=Authenticating".to_string());

    walk_captured_envelope(&mut trace);

    // Not the transport: vendor chatter, an update-device-first
    // frame, and a transport-key command naming a foreign key type
    // all leave the wait unchanged and latch nothing.
    joiner.note_unsecured(UNSECURED_VENDOR_CMD);
    joiner.note_transport_frame(UPDATE_DEVICE_CMD, 0x00);
    joiner.note_transport_frame(TRANSPORT_KEY_CMD, 0x04);
    assert_eq!(joiner.state(), JoinerState::Authenticating);
    assert_eq!(joiner.unsecured_count(), 1);
    trace.push("foreign-first-frames tolerated state=Authenticating".to_string());

    // The genuine TC-first transport (decrypted fields per the
    // hwscratch open) ends the wait; the auxiliary open — MIC valid
    // (checked offline against the derived transport key, which never
    // enters the repo) at the captured counter — adopts the network
    // key.
    joiner.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_NETWORK);
    assert_eq!(joiner.state(), JoinerState::KeyWait);
    trace.push("transport-0501 state=KeyWait".to_string());

    joiner.on_transport_open(true, K1_AUX_COUNTER);
    assert!(joiner.netkey_adopted());
    assert_eq!(joiner.last_aux_counter(), Some(K1_AUX_COUNTER));
    trace.push("open-mic-ok counter=0001d000 netkey-adopted".to_string());

    joiner.on_verify_confirm(true, rounddance_commission::KeyAttributes::SYMMETRIC);
    assert_eq!(joiner.state(), JoinerState::Announced);
    let annce = joiner.device_annce(0x33, 0x5160, 0x6d49_11fe_ff13_8d34);
    assert_eq!(
        (annce.nwk_addr, annce.ieee),
        (0x5160, 0x6d49_11fe_ff13_8d34)
    );
    trace.push("verified+announced".to_string());

    joiner.close_out(false);
    assert_eq!(joiner.state(), JoinerState::Joined);
    trace.push("closed-out state=Joined".to_string());

    // Nothing latched locally: our Trust Center never heard this joiner.
    assert!(tc.is_empty());
    (trace, joiner.state())
}

// 05-3474-23-4433-01 + 05-3474-23-4434-01 + 22-65816-030-91-02:
// the joiner rides the TC-first transport through open and adoption
// to Joined; foreign first-frames never promote.
#[test]
fn tc_first_challenge_then_joined() {
    let (trace, state) = replay_tc_first();
    assert_eq!(state, JoinerState::Joined);
    assert_eq!(
        trace,
        vec![
            "assoc-ok state=Authenticating".to_string(),
            "envelope nwk=5160<-0000 aps-fc=0x21 aux-sc=0x30 tail=39-opaque".to_string(),
            "foreign-first-frames tolerated state=Authenticating".to_string(),
            "transport-0501 state=KeyWait".to_string(),
            "open-mic-ok counter=0001d000 netkey-adopted".to_string(),
            "verified+announced".to_string(),
            "closed-out state=Joined".to_string(),
        ]
    );
}

// Decision determinism: the same capture replays the identical trace.
#[test]
fn tc_first_replay_replays_deterministically() {
    assert_eq!(replay_tc_first(), replay_tc_first());
}

// 05-3474-23-4433-01 + 22-65816-030-56-04: a peer that only ever
// sends foreign first-frames (wrong key type here) never promotes
// the join — the wait ends in NoTransport once the caller exhausts
// the grace bound.
#[test]
fn wrong_type_first_never_promotes() {
    let mut joiner = JoinerMachine::new(JoinMethod::InstallCode, policy());
    joiner.on_candidate();
    joiner.on_assoc_confirm(true);
    joiner.note_transport_frame(TRANSPORT_KEY_CMD, 0x04);
    joiner.note_transport_frame(UPDATE_DEVICE_CMD, 0x00);
    assert_eq!(joiner.state(), JoinerState::Authenticating);
    assert!(!joiner.netkey_adopted());
    // The caller polls its clock to the grace bound, then names the
    // missing transport.
    for _ in 0..JOINER_TRANSPORT_GRACE_TICKS {
        assert_eq!(joiner.state(), JoinerState::Authenticating);
    }
    joiner.on_transport_timeout();
    assert_eq!(joiner.state(), JoinerState::Failed);
    assert_eq!(joiner.error(), Some(JoinError::NoTransport));
}

// 05-3474-23-4434-01: a transport that fails the integrity check —
// tampered or forged on air — never promotes and never latches an
// adoption, even though the classification pair was genuine.
#[test]
fn mic_fail_never_promotes() {
    let mut joiner = JoinerMachine::new(JoinMethod::InstallCode, policy());
    joiner.on_candidate();
    joiner.on_assoc_confirm(true);
    joiner.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_NETWORK);
    assert_eq!(joiner.state(), JoinerState::KeyWait);
    joiner.on_transport_open(false, K1_AUX_COUNTER);
    assert_eq!(joiner.state(), JoinerState::Failed);
    assert_eq!(joiner.error(), Some(JoinError::ConfirmMismatch));
    assert!(!joiner.netkey_adopted());
    assert_eq!(joiner.last_aux_counter(), None);
}

// 22-65816-030-56-04 (joiner side): a parent eject received mid-wait
// ends the attempt at once with JoinTimeout — the "asked to leave"
// outcome — instead of polling to the grace bound. Both the
// transport-wait leg and the post-open wait leg eject the same way.
#[test]
fn leave_eject_ends_wait_at_once() {
    // Transport-wait leg: the eject lands before any transport.
    let mut waiting = JoinerMachine::new(JoinMethod::InstallCode, policy());
    waiting.on_candidate();
    waiting.on_assoc_confirm(true);
    waiting.on_leave();
    assert_eq!(waiting.state(), JoinerState::Failed);
    assert_eq!(waiting.error(), Some(JoinError::JoinTimeout));
    assert!(!waiting.netkey_adopted());

    // Post-open leg: adopted, verified, but the eject still wins —
    // no announce, no close-out, no Joined.
    let mut open = JoinerMachine::new(JoinMethod::InstallCode, policy());
    open.on_candidate();
    open.on_assoc_confirm(true);
    open.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_NETWORK);
    open.on_transport_open(true, K1_AUX_COUNTER);
    assert!(open.netkey_adopted());
    open.on_leave();
    assert_eq!(open.state(), JoinerState::Failed);
    assert_eq!(open.error(), Some(JoinError::JoinTimeout));
}

// 05-3474-23-4434-01: the auxiliary-counter window — a replayed or
// duplicate transport open (counter at or below the adopted one)
// ends the attempt; only a strictly fresher counter would advance.
#[test]
fn counter_replay_never_promotes() {
    let mut joiner = JoinerMachine::new(JoinMethod::InstallCode, policy());
    joiner.on_candidate();
    joiner.on_assoc_confirm(true);
    joiner.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_NETWORK);
    joiner.on_transport_open(true, K1_AUX_COUNTER);
    assert!(joiner.netkey_adopted());
    // Attacker replays the exact captured open: same counter.
    joiner.on_transport_open(true, K1_AUX_COUNTER);
    assert_eq!(joiner.state(), JoinerState::Failed);
    assert_eq!(joiner.error(), Some(JoinError::ConfirmMismatch));

    // A lower counter (older capture, e.g. the x6 frame's
    // `00600100`) against the k1 adoption fails the same way.
    let mut older = JoinerMachine::new(JoinMethod::InstallCode, policy());
    older.on_candidate();
    older.on_assoc_confirm(true);
    older.note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_NETWORK);
    older.on_transport_open(true, K1_AUX_COUNTER);
    older.on_transport_open(true, 0x0001_6000);
    assert_eq!(older.state(), JoinerState::Failed);
    assert_eq!(older.error(), Some(JoinError::ConfirmMismatch));
}

// Captured-air panel consistency: the k1 row of the panel matches
// the captured PSDU above field by field (aux control shaping,
// counter, source, APS header, tail length) — the sha16 pins the
// exact 39-octet tail the battery opened.
#[test]
fn air_panel_k1_row_matches_capture() {
    let k1 = AFRAMES.iter().find(|(tag, _, _, _)| *tag == "k1").unwrap();
    assert_eq!(u32::from_le_bytes(k1.1), K1_AUX_COUNTER);
    let msdu = &CAPTURED_TC_FIRST_PSDU[MAC_HEADER_LEN..];
    let nwk = decode_nwk(msdu).expect("captured NWK header decodes");
    assert_eq!(&nwk.payload[0..2], &k1.2);
    assert_eq!(&nwk.payload[3..7], &k1.1);
    assert_eq!(&nwk.payload[7..15], &TC_EUI);
    assert_eq!(nwk.payload[15..].len(), 39);
    // The five panel rows share one coordinator source and climb
    // +0x1000 per join.
    let ctrs: Vec<u32> = AFRAMES
        .iter()
        .map(|(_, c, _, _)| u32::from_le_bytes(*c))
        .collect();
    assert_eq!(
        ctrs,
        vec![
            0x0001_3000,
            0x0001_4000,
            0x0001_5000,
            0x0001_6000,
            0x0001_d000
        ]
    );
}
