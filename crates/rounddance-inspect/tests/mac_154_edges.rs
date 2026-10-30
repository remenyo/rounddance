//! MAC 802.15.4 edge-shape pins (promoted from w84 scratch verification).
//!
//! Proves dissector/SAP arms that the main vector suites never feed, so the
//! RD-154 mint rows stay honest. Deterministic, offline, no hardware.

//! Scratch verification for w84-goal-r7 mint rows.
//! Read-only against the public repo (path deps only); proves dissector/SAP
//! arms that repo tests do not pin, so mint-row states stay honest.

use rounddance_inspect::mac;
use rounddance_inspect::tree;
use rounddance_mac_sap as sap;

// --- disassoc (0x03) + pan-conflict (0x05) arms repo tests never feed ---

#[test]
fn disassoc_and_panconflict_name_fixed_shapes() {
    let d = mac::decode_command(0x03, &[0x03, 0x01]).unwrap();
    assert_eq!(d.kind, tree::MacCmdKind::Disassoc { reason: 0x01 });
    let p = mac::decode_command(0x05, &[0x05]).unwrap();
    assert_eq!(p.kind, tree::MacCmdKind::PanConflict);
    // Wrong lengths are typed refusals, never guesses.
    assert!(mac::decode_command(0x03, &[0x03]).is_err());
    assert!(mac::decode_command(0x05, &[0x05, 0x00]).is_err());
}

// --- ack branch: immediate 3-octet shape + seq-suppressed variant ---

#[test]
fn ack_branch_shapes() {
    // type=2, AR clear, no addr: FC 0x0002, seq 0x5a.
    let (d, tail) = mac::decode(&[0x02, 0x00, 0x5a]).unwrap();
    assert_eq!(d.node.frame_type, 2);
    assert_eq!(d.node.seq, 0x5a);
    assert!(d.node.seq_present);
    assert!(tail.is_empty());
    // Seq-suppressed ack: FC bit8 set -> no seq octet.
    let (d2, tail2) = mac::decode(&[0x02, 0x01]).unwrap();
    assert!(!d2.node.seq_present);
    assert!(tail2.is_empty());
    // Secured bit on an ack still parses the branch (opacity, no aux read).
    let (d3, _) = mac::decode(&[0x0a, 0x00, 0x11]).unwrap();
    assert!(d3.node.security_enabled);
}

// --- mode-1 refusal + truncation taxonomy ---

#[test]
fn mode1_and_truncation_are_typed() {
    // dst mode 1: FC bits10-11 = 01 -> 0x0400, type data.
    assert!(mac::decode(&[0x01, 0x04, 0x00]).is_err());
    // src mode 1: bits14-15 = 01 -> 0x4000.
    assert!(mac::decode(&[0x01, 0x40, 0x00]).is_err());
    assert_eq!(mac::decode(&[]), Err(mac::MacError::Empty));
    assert_eq!(mac::decode(&[0x41]), Err(mac::MacError::Empty));
}

// --- coordinator realignment: 8-octet no-page shape names; page form refuses ---

#[test]
fn realign_page_form_is_length_refused() {
    // cmd + pan(2) + coord(2) + channel(1) + short(2) = 8: named.
    let ok = [0x08, 0x61, 0x37, 0x00, 0x00, 0x19, 0x10, 0x69];
    let n = mac::decode_command(0x08, &ok).unwrap();
    assert_eq!(
        n.kind,
        tree::MacCmdKind::CoordRealign {
            pan: 0x3761,
            coord: 0x0000,
            channel: 0x19,
            short_addr: 0x6910,
        }
    );
    // A trailing channel-page octet (page-present variant) is not the
    // dissector's shape: typed Length refusal, never a misparse.
    let paged = [0x08, 0x61, 0x37, 0x00, 0x00, 0x19, 0x10, 0x69, 0x00];
    assert!(matches!(
        mac::decode_command(0x08, &paged),
        Err(mac::MacCmdError::Length {
            command_id: 0x08,
            ..
        })
    ));
}

// --- unknown command ids stay UnknownCommand ---

#[test]
fn unmodeled_ids_stay_unknown() {
    for cmd in [0x00u8, 0x09, 0x0a, 0x1f, 0xff] {
        assert!(matches!(
            mac::decode_command(cmd, &[cmd]),
            Err(mac::MacCmdError::UnknownCommand(_))
        ));
    }
}

// --- secured command opacity: first octet never read as command id ---

#[test]
fn secured_command_id_stays_none() {
    // Data-frame FC with security bit set + minimal addressing; the byte
    // after the header must NOT surface as a command id on type-3 either.
    // type=3 secured, dst short + src short, pan compressed: FC 0x68E3?
    // Build: type 3 | sec 0x08 | pan_compress 0x40 | dstmode2 0x0800 | ver1 0x1000 | srcmode2 0x8000 = 0x984B.
    let f = [0x4bu8, 0x98, 0xAA, 0xFF, 0xFF, 0x34, 0x12, 0x78, 0x56, 0x01];
    let (d, _) = mac::decode(&f).unwrap();
    assert_eq!(d.node.frame_type, 3);
    assert!(d.node.security_enabled);
    assert_eq!(d.node.command_id, None);
    // Same header without the security bit names command 0x01.
    let g = [0x43u8, 0x98, 0xAA, 0xFF, 0xFF, 0x34, 0x12, 0x78, 0x56, 0x01];
    let (d2, _) = mac::decode(&g).unwrap();
    assert_eq!(d2.node.command_id, Some(0x01));
}

// --- None/None destination-PAN rule across versions (7229/72210) ---

#[test]
fn nonenone_pan_tracks_version() {
    // Version 1 (00/01 family): None/None still carries the dst PAN.
    // FC type data (1) | ver 0x1000 -> 0x1001; dst PAN 0x1234.
    let (d, tail) = mac::decode(&[0x01, 0x10, 0xAA, 0x34, 0x12]).unwrap();
    assert_eq!(d.node.dst_pan, Some(0x1234));
    assert_eq!(d.node.seq, 0xAA);
    assert_eq!(tail, &[] as &[u8]);
    // Version 2 (10): None/None carries no PAN at all.
    let (e, _) = mac::decode(&[0x01, 0x20, 0xBB]).unwrap();
    assert_eq!(e.node.dst_pan, None);
    assert_eq!(e.node.seq, 0xBB);
}

// --- SAP constants and constructors backing the ceiling/range rows ---

#[test]
fn sap_bounds_and_options() {
    assert_eq!(sap::MAX_PHY_PSDU_LEN, 127);
    assert_eq!(sap::MAX_MSDU_LEN, 116);
    const _: () = assert!(sap::MAX_MSDU_LEN < sap::MAX_PHY_PSDU_LEN);
    assert!(sap::Channel::new(10).is_err());
    assert_eq!(sap::Channel::new(11).unwrap().number(), 11);
    assert_eq!(sap::Channel::new(26).unwrap().number(), 26);
    assert!(sap::Channel::new(27).is_err());
    assert!(!sap::TxOptions::NONE.wants_ack());
    assert!(sap::TxOptions::ACK.wants_ack());
    let p = sap::FramePayload::from_slice(&[0u8; 116]).unwrap();
    assert_eq!(p.len(), 116);
    assert!(sap::FramePayload::from_slice(&[0u8; 117]).is_err());
}
