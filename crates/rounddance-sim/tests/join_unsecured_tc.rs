//! Join transcript against an unsecured-talking coordinator: the joiner
//! associates, then hears only level-0 (plaintext, counter-less)
//! vendor APS commands and never receives the standard transport-key
//! command, so the post-association wait ends with `NoTransport` and
//! no key material is latched anywhere.
//!
//! The on-air bytes below replay a captured post-association
//! coordinator frame (joiner short 0x66e2): NWK data, plaintext APS
//! command id 0x30, level-0 auxiliary header. The walk
//! NWK → APS command → aux runs entirely through the repo codecs, so
//! this test pins the wire shape the RX path must tolerate.
//!
//! Requirement traceability: `05-3474-23-451-01` (level-0 aux RX),
//! `05-3474-23-4312-01` (counter-less frames take no replay slot),
//! `22-65816-030-91-02` (no verify/promote without transport),
//! `22-65816-030-56-04` (the wait is still time-boxed: it ends).

use rounddance_aps::decode_command;
use rounddance_commission::{
    JoinError, JoinMethod, JoinPolicy, JoinerMachine, JoinerState, TrustCenter,
    UNSECURED_VENDOR_CMD,
};
use rounddance_nwk::decode as decode_nwk;
use rounddance_security::AuxReception;

/// Captured coordinator→joiner frame, full MAC PSDU as seen on air:
/// 9-octet MAC header, 8-octet NWK data header (dst 0x66e2, src
/// 0x0000, radius 30), then the APS command + level-0 aux + plaintext.
const CAPTURED_PSDU: [u8; 71] = [
    0x61, 0x88, 0x52, 0xd3, 0xa4, 0xe2, 0x66, 0x00, 0x00, 0x08, 0x00, 0xe2, 0x66, 0x00, 0x00, 0x1e,
    0xfb, 0x21, 0x90, 0x30, 0x00, 0x10, 0x00, 0x00, 0x6d, 0x49, 0x11, 0xfe, 0xff, 0x13, 0x8d, 0x34,
    0x52, 0x98, 0xd2, 0x8c, 0x21, 0xe4, 0xf9, 0xe5, 0xb7, 0xd4, 0x56, 0x0c, 0x5b, 0xaa, 0xec, 0x1c,
    0x0b, 0xdb, 0xa7, 0x1b, 0xec, 0x94, 0xb5, 0xa2, 0x77, 0x53, 0xab, 0xa1, 0x0d, 0xda, 0x1c, 0x27,
    0x7a, 0x04, 0xfd, 0xf9, 0x42, 0x9d, 0x87,
];

/// Length of the MAC header the HAL strips before the NWK codec runs.
const MAC_HEADER_LEN: usize = 9;

fn policy() -> JoinPolicy {
    JoinPolicy {
        cbke_supported: false,
        cbke_required: false,
        interview_tc: false,
        parent_is_r20_earlier: false,
    }
}

/// One replay of the observed coordinator behavior: associate, hear
/// two unsecured vendor commands (decoded byte-for-byte from the
/// capture both times), never hear transport, time out. Returns the
/// human-readable trace plus the terminal error.
fn replay_unsecured_tc() -> (Vec<String>, Option<JoinError>) {
    let mut trace = Vec::new();
    let mut joiner = JoinerMachine::new(JoinMethod::PreconfiguredKey, policy());
    // Our own Trust Center stays out of this run: the peer is the
    // stock coordinator, so nothing may ever latch locally.
    let tc = TrustCenter::new();

    joiner.on_candidate();
    joiner.on_assoc_confirm(true);
    assert_eq!(joiner.state(), JoinerState::Authenticating);
    trace.push("assoc-ok state=Authenticating".to_string());

    // Two poll cycles, same captured frame on air each time.
    for cycle in 0..2 {
        let msdu = &CAPTURED_PSDU[MAC_HEADER_LEN..];
        let nwk = decode_nwk(msdu).expect("captured NWK header decodes");
        assert!(!nwk.header.control.security);
        assert_eq!((nwk.header.dst_addr, nwk.header.src_addr), (0x66e2, 0x0000));
        let aps = decode_command(nwk.payload).expect("captured APS command decodes");
        assert_eq!(aps.header.command_id, UNSECURED_VENDOR_CMD);
        let (rx, used) = AuxReception::decode(aps.payload).expect("level-0 aux decodes");
        assert!(rx.is_plaintext());
        trace.push(format!(
            "cycle={cycle} aps-ctr={} cmd=0x{:02x} aux-used={used} plaintext",
            aps.header.counter, aps.header.command_id,
        ));
        joiner.note_unsecured(aps.header.command_id);
    }
    assert_eq!(joiner.state(), JoinerState::Authenticating);
    assert_eq!(joiner.unsecured_count(), 2);
    assert_eq!(joiner.last_unsecured_cmd(), Some(UNSECURED_VENDOR_CMD));
    trace.push("tolerated state=Authenticating unsecured=2".to_string());

    // The wait ends with no transport-key frame ever seen.
    joiner.on_transport_timeout();
    assert_eq!(joiner.state(), JoinerState::Failed);
    let err = joiner.error();
    assert_eq!(err, Some(JoinError::NoTransport));
    trace.push("timeout error=NoTransport".to_string());

    // Nothing latched: our Trust Center never heard this joiner.
    assert!(tc.find(0x0200_0000_0000_0002).is_none());
    assert!(tc.is_empty());
    (trace, err)
}

// 05-3474-23-451-01 + 22-65816-030-91-02: the joiner survives the
// unsecured-talking coordinator and names the missing transport.
#[test]
fn unsecured_tc_challenge_then_no_transport() {
    let (trace, err) = replay_unsecured_tc();
    assert_eq!(err, Some(JoinError::NoTransport));
    assert_eq!(
        trace,
        vec![
            "assoc-ok state=Authenticating".to_string(),
            "cycle=0 aps-ctr=144 cmd=0x30 aux-used=1 plaintext".to_string(),
            "cycle=1 aps-ctr=144 cmd=0x30 aux-used=1 plaintext".to_string(),
            "tolerated state=Authenticating unsecured=2".to_string(),
            "timeout error=NoTransport".to_string(),
        ]
    );
}

// Decision determinism: the same capture replays the identical trace.
#[test]
fn unsecured_tc_replay_replays_deterministically() {
    let first = replay_unsecured_tc();
    let second = replay_unsecured_tc();
    assert_eq!(first, second);
}
