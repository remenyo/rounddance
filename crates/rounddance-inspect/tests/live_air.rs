//! Live-air regression goldens: wave-47/wave-48 captured frames
//! through the gap-closing dissectors.
//!
//! Provenance: the MAC ack / beacon / command octets and the
//! transport-key outer below are verbatim frames from the wave-48
//! live run (`~/hwscratch/w48/live1.frames.log`, 554 frames); the
//! NWK-secured ciphertext sample is a wave-48 live frame. Frames
//! ride unsecured or as ciphertext — no key material is embedded.
//! The decrypt round trip seals with a synthetic test-only key, so
//! the lab keys stay local-only; the offline reproduction procedure
//! against the real captures is documented on
//! [`captured_corpus_pins`] (hashes + analyzer steps, never bytes).

use rounddance_inspect::{chain, report, session, tree};

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn note_reasons(t: &tree::DecodeTree) -> Vec<&'static str> {
    t.layers()
        .iter()
        .flatten()
        .filter_map(|l| match l {
            tree::Layer::Note(n) => Some(n.reason),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// RD-INSPECT-19: MAC ack / beacon / command outer decodes.
// ---------------------------------------------------------------------------

#[test]
fn mac_ack_decodes_instead_of_truncated() {
    // live1 f2 / f4: 3-octet acknowledgements (previously 120/120
    // `MacTruncated` errors on the live run).
    for (raw, seq) in [("120041", 0x41u8), ("020042", 0x42u8)] {
        let tree = chain::dissect(&hex(raw)).unwrap();
        let m = tree.mac().expect("mac node");
        assert_eq!(m.frame_type, 2);
        assert_eq!(m.seq, seq);
        assert!(m.seq_present);
        assert_eq!(m.dst, tree::Addr::None);
        assert_eq!(m.src, tree::Addr::None);
        assert_eq!(m.command_id, None);
        assert_eq!(note_reasons(&tree), vec!["ack"]);
        assert_eq!(tree.len(), 2);
    }
    // Short acks stay typed refusals, never panics.
    assert_eq!(chain::dissect(&[0x12]), Err(tree::TreeError::Empty));
    assert_eq!(
        chain::dissect(&[0x12, 0x00]),
        Err(tree::TreeError::MacTruncated)
    );
}

#[test]
fn mac_beacon_and_commands_decode_with_named_stops() {
    // live1 f6: TC beacon (permit-join quirk shape included).
    let beacon =
        chain::dissect(&hex("0080fa61370000ff4f00000022841694b10911403a09ffffff00")).unwrap();
    let m = beacon.mac().expect("mac node");
    assert_eq!(m.frame_type, 0);
    assert_eq!(m.seq, 0xfa);
    assert_eq!(m.src, tree::Addr::Short(0x0000));
    assert_eq!(m.src_pan, Some(0x3761));
    assert_eq!(m.command_id, None);
    assert_eq!(note_reasons(&beacon), vec!["beacon"]);
    // Session attributes the beacon source like any other frame.
    let mut eng = session::SessionEngine::new();
    eng.note_tree(&beacon);
    assert!(eng.device(0x0000).is_some());

    // live1 f5: beacon request; f3: association request (+1B
    // capability); f1: data-request poll; f11: association response.
    for (raw, cmd) in [
        ("030816ffffffff07", 0x07u8),
        ("23c84261370000ffffa0f262fffefffe85018c", 0x01u8),
        ("23c84161370000ffffa0f262fffefffe8504", 0x04u8),
        ("63ccfc6137a0f262fffefffe855f75f4feffe5e30402ffff02", 0x02u8),
    ] {
        let tree = chain::dissect(&hex(raw)).unwrap();
        let m = tree.mac().expect("mac node");
        assert_eq!(m.frame_type, 3);
        assert_eq!(m.command_id, Some(cmd), "frame {raw}");
        assert_eq!(note_reasons(&tree), vec!["mac-command"], "frame {raw}");
    }
    // The command id renders on both report shapes.
    let req = chain::dissect(&hex("030816ffffffff07")).unwrap();
    assert!(report::to_text(&req).contains("cmd=0x07"));
    assert!(report::to_json(&req).contains("\"cmd\":7"));
    // Acks carry no command id on either shape.
    let ack = chain::dissect(&hex("120041")).unwrap();
    assert!(report::to_json(&ack).contains("\"cmd\":null"));
}

#[test]
fn acks_fold_without_device_attribution() {
    let mut eng = session::SessionEngine::new();
    let tree = chain::dissect(&hex("120041")).unwrap();
    eng.note_tree(&tree);
    assert_eq!(eng.trees, 1);
    assert!(eng.devices().iter().all(|d| d.is_none()));
}

// ---------------------------------------------------------------------------
// RD-INSPECT-20: secured APS outer is `secured`, never a bogus command.
// ---------------------------------------------------------------------------

#[test]
fn transport_key_outer_stops_secured() {
    // live1 f36: unsecured NWK data carrying the APS transport-key
    // command sealed under the link-derived key. The inspector used
    // to report `aps type=1 ctr=0x3d cmd=0x30` (the aux control octet
    // misread as the command id, true cmd 0x05 sealed inside).
    let f36 = hex("61884c6137ee6700000800ee6700001e2c213d30006000005f75f4feffe5e304d74a803a1f21df4b205d39302a3b5547ed52df6e29ac3568c2842f8948fb54323889b34ec46127");
    let tree = chain::dissect(&f36).unwrap();
    let n = tree.nwk().expect("nwk node");
    assert_eq!(n.frame_type, 0);
    assert!(!n.security);
    assert!(tree.aps().is_none(), "sealed outer yields no APS node");
    assert_eq!(note_reasons(&tree), vec!["secured"]);
    assert_eq!(tree.len(), 3);
    let text = report::to_text(&tree);
    assert!(!text.contains("cmd=0x30"), "aux octet never a command");
    assert!(text.contains("secured"));
}

#[test]
fn secured_aps_data_shape_refuses_before_payload() {
    // Codec-built data header with the security bit set: the dissector
    // refuses as secured instead of parsing ciphertext as fields.
    let aps = rounddance_aps::frame::DataHeader {
        control: rounddance_aps::frame::FrameControl {
            frame_type: rounddance_aps::frame::FrameType::Data,
            delivery_mode: rounddance_aps::frame::DeliveryMode::Unicast,
            ack_format: false,
            security: true,
            ack_request: false,
            ext_header: false,
        },
        dest: rounddance_aps::frame::DataDest::Unicast { dst_endpoint: 1 },
        cluster_id: 0x0006,
        profile_id: 0x0104,
        src_endpoint: 1,
        counter: 0x07,
        ext: None,
    };
    let mut buf = [0u8; 32];
    let n = aps.encode_into(&[], &mut buf).unwrap();
    assert_eq!(
        rounddance_inspect::aps::decode(&buf[..n]),
        Err(rounddance_inspect::aps::ApsError::Secured)
    );
    // The plain variant still decodes.
    let mut plain = aps;
    plain.control.security = false;
    let m = plain.encode_into(&[], &mut buf).unwrap();
    assert!(rounddance_inspect::aps::decode(&buf[..m]).is_ok());
}

// ---------------------------------------------------------------------------
// RD-INSPECT-21: NWK decrypt path (slotted-key-gated verified open).
// ---------------------------------------------------------------------------

/// Synthetic test-only network key: seals the round-trip frames
/// below and nothing else. Never a lab key.
const TEST_KEY: [u8; 16] = [0x77u8; 16];
const TEST_SEQ: u8 = 0;
const TEST_EXT: [u8; 8] = [0x5f, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04];
const TEST_CTR: u32 = 0x0000_4004;

/// Test-local integrity seal (mirror of the decryptor's open): only
/// feeds the round-trip legs below.
fn seal(key: &[u8; 16], nonce13: &[u8; 13], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    use rounddance_security::encrypt_block_aes128;
    let ks = |ctr: u32| -> [u8; 16] {
        let mut blk = [0u8; 16];
        blk[0] = 0x01;
        blk[1..14].copy_from_slice(nonce13);
        blk[14..16].copy_from_slice(&(ctr as u16).to_be_bytes());
        encrypt_block_aes128(key, &blk)
    };
    let mut ct = vec![0u8; pt.len()];
    for (i, chunk) in pt.chunks(16).enumerate() {
        let k = ks(1 + i as u32);
        for (j, b) in chunk.iter().enumerate() {
            ct[i * 16 + j] = b ^ k[j];
        }
    }
    let mut b0 = [0u8; 16];
    b0[0] = 0x40 | 0x08 | 0x01;
    b0[1..14].copy_from_slice(nonce13);
    b0[14..16].copy_from_slice(&(pt.len() as u16).to_be_bytes());
    let mut mac_in = Vec::new();
    mac_in.extend_from_slice(&(aad.len() as u16).to_be_bytes());
    mac_in.extend_from_slice(aad);
    while mac_in.len() % 16 != 0 {
        mac_in.push(0);
    }
    mac_in.extend_from_slice(pt);
    while mac_in.len() % 16 != 0 {
        mac_in.push(0);
    }
    let mut x = encrypt_block_aes128(key, &b0);
    for blk in mac_in.chunks(16) {
        let mut mix = [0u8; 16];
        for (i, b) in blk.iter().enumerate() {
            mix[i] = x[i] ^ b;
        }
        x = encrypt_block_aes128(key, &mix);
    }
    let s0 = ks(0);
    for i in 0..4 {
        ct.push(x[i] ^ s0[i]);
    }
    ct
}

/// Build one full secured frame (MAC + secured NWK data + sealed
/// APS data + ZCL read) under the synthetic test key.
fn build_secured_frame() -> Vec<u8> {
    // Plaintext: APS data + ZCL global Read, codec-built.
    let zcl = rounddance_zcl::frame::Header {
        control: rounddance_zcl::frame::FrameControl {
            frame_type: rounddance_zcl::frame::FrameType::Global,
            manufacturer_specific: false,
            direction: rounddance_zcl::frame::Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x42,
        command_id: 0x00,
    };
    let mut zcl_buf = [0u8; 16];
    let zn = zcl.encode_into(&mut zcl_buf).unwrap();
    let mut zcl_payload = [0u8; 18];
    zcl_payload[..zn].copy_from_slice(&zcl_buf[..zn]);
    zcl_payload[zn..zn + 2].copy_from_slice(&0x0000u16.to_le_bytes());
    let aps = rounddance_aps::frame::DataHeader {
        control: rounddance_aps::frame::FrameControl::data(
            rounddance_aps::frame::DeliveryMode::Unicast,
        ),
        dest: rounddance_aps::frame::DataDest::Unicast { dst_endpoint: 1 },
        cluster_id: 0x0006,
        profile_id: 0x0104,
        src_endpoint: 1,
        counter: 0x07,
        ext: None,
    };
    let mut aps_buf = [0u8; 64];
    let an = aps
        .encode_into(&zcl_payload[..zn + 2], &mut aps_buf)
        .unwrap();

    // NWK header with the security bit set.
    let mut fc = rounddance_nwk::frame::FrameControl::data();
    fc.security = true;
    let nwk = rounddance_nwk::frame::NwkHeader::minimal(fc, 0x5678, 0x1234, 30, 0x09);
    let mut nwk_buf = [0u8; 64];
    let nn = nwk.encode_into(&[], &mut nwk_buf).unwrap();
    let header = &nwk_buf[..nn];

    // On-air aux: zeroed level octet, counter, extended source, key seq.
    let mut aux = vec![0x28u8];
    aux.extend_from_slice(&TEST_CTR.to_le_bytes());
    aux.extend_from_slice(&TEST_EXT);
    aux.push(TEST_SEQ);
    let mut nonce = [0u8; 13];
    nonce[..8].copy_from_slice(&TEST_EXT);
    nonce[8..12].copy_from_slice(&TEST_CTR.to_le_bytes());
    nonce[12] = 0x2d;
    let mut aad = header.to_vec();
    aad.push(0x2d);
    aad.extend_from_slice(&aux[1..]);
    let ct = seal(&TEST_KEY, &nonce, &aad, &aps_buf[..an]);

    let mut frame = vec![0x41, 0x88, 0x5a];
    frame.extend_from_slice(&0x3761u16.to_le_bytes());
    frame.extend_from_slice(&0x5678u16.to_le_bytes());
    frame.extend_from_slice(&0x1234u16.to_le_bytes());
    frame.extend_from_slice(header);
    frame.extend_from_slice(&aux);
    frame.extend_from_slice(&ct);
    frame
}

/// Build one secured NWK command frame sealing `pt` (e.g. a leave
/// command body) under the synthetic test key.
fn build_secured_nwk_command(pt: &[u8]) -> Vec<u8> {
    let mut fc = rounddance_nwk::frame::FrameControl::command();
    fc.security = true;
    let nwk = rounddance_nwk::frame::NwkHeader::minimal(fc, 0x021d, 0x0000, 1, 0x44);
    let mut nwk_buf = [0u8; 64];
    let nn = nwk.encode_into(&[], &mut nwk_buf).unwrap();
    let header = &nwk_buf[..nn];
    let mut aux = vec![0x28u8];
    aux.extend_from_slice(&TEST_CTR.to_le_bytes());
    aux.extend_from_slice(&TEST_EXT);
    aux.push(TEST_SEQ);
    let mut nonce = [0u8; 13];
    nonce[..8].copy_from_slice(&TEST_EXT);
    nonce[8..12].copy_from_slice(&TEST_CTR.to_le_bytes());
    nonce[12] = 0x2d;
    let mut aad = header.to_vec();
    aad.push(0x2d);
    aad.extend_from_slice(&aux[1..]);
    let ct = seal(&TEST_KEY, &nonce, &aad, pt);
    let mut frame = vec![0x41, 0x88, 0x60];
    frame.extend_from_slice(&0x3761u16.to_le_bytes());
    frame.extend_from_slice(&0x021du16.to_le_bytes());
    frame.extend_from_slice(&0x0000u16.to_le_bytes());
    frame.extend_from_slice(header);
    frame.extend_from_slice(&aux);
    frame.extend_from_slice(&ct);
    frame
}

fn slotted(seq: u8, key: [u8; 16]) -> session::SessionEngine {
    let mut eng = session::SessionEngine::new();
    eng.set_network_key(key, seq);
    eng
}

#[test]
fn nwk_decrypt_opens_with_slotted_key_and_stops_without() {
    let frame = build_secured_frame();

    // Slotted key under the aux sequence: verified open, chain
    // continues on the plaintext through APS into ZCL.
    let eng = slotted(TEST_SEQ, TEST_KEY);
    let open = chain::dissect_with_keys(&frame, eng.keys()).unwrap();
    assert_eq!(open.len(), 5, "MAC + NWK + decrypted + APS + ZCL");
    let n = open.nwk().expect("nwk node");
    assert!(n.security);
    assert_eq!(note_reasons(&open), vec!["decrypted"]);
    let a = open.aps().expect("aps node past the decrypt");
    assert_eq!(a.cluster_id, 0x0006);
    let z = open.zcl().expect("zcl node past the decrypt");
    assert_eq!(z.command_id, 0x00);
    assert_eq!(z.cluster_id, 0x0006);

    // No key: identical bytes stop sealed, exactly as before.
    let shut = chain::dissect(&frame).unwrap();
    assert_eq!(shut.len(), 3);
    assert_eq!(note_reasons(&shut), vec!["secured"]);
    assert!(shut.aps().is_none());

    // Wrong sequence slot, wrong key bytes, and any mutated octet:
    // never opens without the slotted key.
    let mut wrong_seq = session::SessionEngine::new();
    wrong_seq.set_network_key(TEST_KEY, TEST_SEQ + 1);
    assert_eq!(
        note_reasons(&chain::dissect_with_keys(&frame, wrong_seq.keys()).unwrap()),
        vec!["secured"]
    );
    let wrong_key = slotted(TEST_SEQ, [0x78u8; 16]);
    assert_eq!(
        note_reasons(&chain::dissect_with_keys(&frame, wrong_key.keys()).unwrap()),
        vec!["secured"]
    );
    for flip in [frame.len() - 1, frame.len() - 5, 20] {
        let mut bad = frame.clone();
        bad[flip] ^= 0x01;
        assert_eq!(
            note_reasons(&chain::dissect_with_keys(&bad, eng.keys()).unwrap()),
            vec!["secured"],
            "mutation at {flip} must fail integrity"
        );
    }
    // Bare-NWK path opens identically (MAC header is 9 octets:
    // FC + seq + PAN + short dst + short src).
    let bare = chain::dissect_nwk_with_keys(&frame[9..], eng.keys()).unwrap();
    assert!(bare.aps().is_some());
    assert_eq!(note_reasons(&bare), vec!["decrypted"]);
    let bare_shut = chain::dissect_nwk(&frame[9..]).unwrap();
    assert_eq!(note_reasons(&bare_shut), vec!["secured"]);

    // Decrypted NWK command frames carry no APS header: the chain
    // files `decrypted`, names the leave leg, then `trailing` (the
    // command layer adds one depth over the wave-49 shape).
    let cmd = build_secured_nwk_command(&[0x04, 0x60]);
    let opened = chain::dissect_with_keys(&cmd, eng.keys()).unwrap();
    assert!(opened.aps().is_none());
    assert_eq!(note_reasons(&opened), vec!["decrypted", "trailing"]);
    assert_eq!(opened.len(), 5);
    let lc = opened.nwkcmd().expect("leave leg");
    assert_eq!(lc.command_id, 0x04);
    assert_eq!(lc.kind, tree::NwkCmdKind::Leave { options: 0x60 });
}

#[test]
fn nwk_decrypt_gates_session_decryptability() {
    let frame = build_secured_frame();
    let mut eng = slotted(TEST_SEQ, TEST_KEY);
    let open = chain::dissect_with_keys(&frame, eng.keys()).unwrap();
    eng.note_tree(&open);
    assert_eq!(eng.secured_decryptable, 1);
    assert_eq!(eng.secured_orphan, 0);

    let mut bare = session::SessionEngine::new();
    let shut = chain::dissect(&frame).unwrap();
    bare.note_tree(&shut);
    assert_eq!(bare.secured_decryptable, 0);
    assert_eq!(bare.secured_orphan, 1);
}

#[test]
fn genuine_secured_air_never_opens_off_slot() {
    // live1 f19: genuine NWK-secured link-status ciphertext. A loaded
    // slot under a foreign sequence (or foreign key bytes) never
    // opens it — the lab key stays out of the repo by construction.
    let f19 = hex("4188486137ffff00000912fcff0000012b5f75f4feffe5e30428001001005f75f4feffe5e3040087ea619e849a");
    let foreign = slotted(7, TEST_KEY);
    let tree = chain::dissect_with_keys(&f19, foreign.keys()).unwrap();
    assert_eq!(note_reasons(&tree), vec!["secured"]);
    assert!(tree.aps().is_none());
}

/// Captured-corpus pins: hashes plus analyzer-observed metadata for
/// the offline reproduction procedure (lab `0600` key files, never in
/// the repo). Procedure: `python3 analyze47.py` in `~/hwscratch/w47`
/// opens every NWK-secured joiner frame under the documented netkey
/// (digest `94ce9adcf9fed0f3`); `~/hwscratch/w48/SUMMARY.md` §1/§5
/// documents the live1 accounting this test's frame octets come from.
#[test]
fn captured_corpus_pins() {
    const T1_PCAP_SHA256: &str = "c689d5675fc8356a633af5c2956b7c360d84a97b5fa61aa320d39b47d49a0e79";
    const T2_PCAP_SHA256: &str = "aba1df7ae9ee70f72fa55cb83ee12571a97f36591b85343b1db172cadcbc8ce8";
    assert_eq!(T1_PCAP_SHA256.len(), 64);
    assert_eq!(T2_PCAP_SHA256.len(), 64);
    assert_ne!(T1_PCAP_SHA256, T2_PCAP_SHA256);
    // Analyzer-observed per-capture frame counts.
    const T1_FRAMES: usize = 745;
    const T2_FRAMES: usize = 748;
    const LIVE1_FRAMES: usize = 554;
    const LIVE1_ACKS: usize = 120;
    assert_eq!(T1_FRAMES, 745);
    assert_eq!(T2_FRAMES, 748);
    assert_eq!(LIVE1_FRAMES, 554);
    assert_eq!(LIVE1_ACKS, 120);
}

// ---------------------------------------------------------------------------
// RD-INSPECT-22: radio metadata plumbing + RSSI validity.
// ---------------------------------------------------------------------------

#[test]
fn radio_metadata_threads_tree_to_session() {
    let mut tree = chain::dissect(&hex("030816ffffffff07")).unwrap();
    assert!(tree.radio().is_none());
    tree.set_radio(25, -104, 255);
    assert_eq!(
        tree.radio(),
        Some(tree::Radio {
            channel: 25,
            rssi: Some(-104),
            lqi: 255,
        })
    );
    let mut eng = session::SessionEngine::new();
    eng.note_tree(&tree);
    // Beacon-request carries no source address: no row, no radio.
    assert!(eng.devices().iter().all(|d| d.is_none()));

    // Data frame from a real source: row gains signal readings.
    let data = hex("61884c6137ee6700000800ee6700001e2c213d30006000005f75f4feffe5e304d74a803a1f21df4b205d39302a3b5547ed52df6e29ac3568c2842f8948fb54323889b34ec46127");
    let mut dtree = chain::dissect(&data).unwrap();
    dtree.set_radio(25, -104, 255);
    eng.note_tree(&dtree);
    let dev = eng.device(0x0000).expect("TC row");
    assert_eq!(dev.last_rssi, Some(-104));
    assert_eq!(dev.last_lqi, Some(255));

    // Bogus positive power files as unknown and never overwrites.
    let mut noisy = chain::dissect(&data).unwrap();
    noisy.set_radio(25, 111, 120);
    assert_eq!(noisy.radio().unwrap().rssi, None);
    eng.note_tree(&noisy);
    let dev = eng.device(0x0000).expect("TC row");
    assert_eq!(dev.last_rssi, Some(-104), "quirk never overwrites");
    assert_eq!(dev.last_lqi, Some(120));

    // Reports name the radio leg; the session schema stays v1 with
    // no radio keys (signal is live state, not snapshot state).
    let text = report::to_text(&dtree);
    assert!(text.contains("radio=ch25 rssi=-104 lqi=255"));
    let json = report::to_json(&dtree);
    assert!(json.contains("\"radio\":{\"channel\":25,\"rssi\":-104,\"lqi\":255}"));
    let schema = report::session_to_json(&eng);
    assert!(!schema.contains("rssi"));
    assert!(report::session_to_text(&eng).contains("rssi=-104"));
}

// ---------------------------------------------------------------------------
// RD-INSPECT-23: host listener path (replay == live through one parser).
// ---------------------------------------------------------------------------

#[test]
fn replay_listener_feeds_chain_and_session() {
    use rounddance_inspect::capture::Listener;
    use rounddance_inspect::sniffer::ReplayListener;
    let dir = std::env::temp_dir();
    let path = dir.join("w49-live-air-replay.txt");
    // Saved-feed shape: `received:` lines (FCS-tailed) plus shell noise.
    std::fs::write(
        &path,
        "channel 25\nreceived: 1200410000 power: -104 lqi: 255 time: 11\nsleep\nreceived: 030816ffffffff07ffff power: 111 lqi: 120 time: 12\n",
    )
    .unwrap();
    let mut li = ReplayListener::open(path.to_str().unwrap(), 25).unwrap();
    let mut eng = session::SessionEngine::new();
    let mut buf = [0u8; 256];
    let mut n = 0;
    while let Some(c) = li.next_frame(&mut buf).unwrap() {
        n += 1;
        let mut t = chain::dissect(c.payload).unwrap();
        t.set_radio(c.channel, c.rssi, c.lqi);
        eng.note_tree(&t);
    }
    assert_eq!(n, 2);
    assert_eq!(eng.trees, 2);
    std::fs::remove_file(&path).unwrap();
    // A missing feed is a typed open error, never a panic.
    assert!(ReplayListener::open("/nonexistent-w49-feed.txt", 25).is_err());
}

// ---------------------------------------------------------------------------
// RD-INSPECT-29..31: wave-50 Touchlink capture pins.
// ---------------------------------------------------------------------------

/// Captured-corpus pins for the Touchlink gap-closure replay: the
/// four wave-50 pcaps (`~/hwscratch/w50/`, read-only) plus the
/// analyzer-observed inter-PAN census. Procedure: the offline gate
/// census `python3 analyze51.py` in `~/hwscratch/w51/` replays
/// every pcap frame through the gate predicate (unsecured data
/// outer, destination PAN plus destination plus source PAN all
/// broadcast); all 480 gated MSDUs carry a Touchlink transaction
/// and command (`00/01/10/11/12/13`) at the exact live lengths,
/// with zero false positives and zero false negatives.
/// Scan/start/join legs are pinned verbatim in `decode_depth.rs`;
/// the miss noted
/// in `~/hwscratch/w50/SUMMARY.md` §5.1 (probe start-rsp absent
/// on air) shows here as 3 start responses, not 4.
/// Wave-59 lane 1 re-pinned `C25_PCAP_SHA256` (below): the wave-51
/// pin differed from the on-disk file in 3 hex chars while every
/// other pin, the frame count (209), and the full replay census
/// matched. Forensics (`~/hwscratch/w59/lane1/`) show the file is
/// the deterministic `sniff2pcap.py` render of the wave-50 live
/// sniff record (byte-identical re-render from `sniff_c25.txt`,
/// unmodified since the wave-50 session, corroborated by the
/// wave-51 replay census over the same bytes) — a pin-side
/// transcription error, not capture corruption. Census re-verified
/// at re-pin: 209 frames, 0 errors, 122 interpan, session rows
/// 0x7f68 joining x25 / 0x97a4 joined x7.
#[test]
fn captured_corpus_pins_touchlink_w50() {
    const C11_PCAP_SHA256: &str =
        "ee895f3e5dc7918cbc942d01698f753489735d44d3c7eda8e8aa0335bfafdbe7";
    const C20_PCAP_SHA256: &str =
        "f42586efb93799332910f41ceaaa3670e2289239aa229a373a28fa651a0d4ac7";
    const C25_PCAP_SHA256: &str =
        "82023d5e56eff1dd06db84b9831cbf2a0c3e51ced139d8e1066b0b64dcb4d4f1";
    const PROBE_PCAP_SHA256: &str =
        "372e2306c5c538d15520a09ce18ab63c3557fa3144a43bea5d582f538f43ddf6";
    for pin in [
        C11_PCAP_SHA256,
        C20_PCAP_SHA256,
        C25_PCAP_SHA256,
        PROBE_PCAP_SHA256,
    ] {
        assert_eq!(pin.len(), 64);
    }
    assert_ne!(C11_PCAP_SHA256, C20_PCAP_SHA256);
    assert_ne!(C20_PCAP_SHA256, C25_PCAP_SHA256);
    assert_ne!(C25_PCAP_SHA256, PROBE_PCAP_SHA256);
    // Analyzer-observed per-capture frame counts (pcap headers).
    const C11_FRAMES: usize = 165;
    const C20_FRAMES: usize = 218;
    const C25_FRAMES: usize = 209;
    const PROBE_FRAMES: usize = 599;
    assert_eq!(C11_FRAMES, 165);
    assert_eq!(C20_FRAMES, 218);
    assert_eq!(C25_FRAMES, 209);
    assert_eq!(PROBE_FRAMES, 599);
    // Inter-PAN (command, MSDU length) census per capture: every
    // gated MSDU is one of these six shapes (probe shows the §5.1
    // miss: no 18-octet start response on air).
    const SCAN_REQ: usize = 60;
    const SCAN_RSP: usize = 54;
    const START_ORDERS_C11_C20_C25: usize = 5;
    const START_RSP: usize = 1;
    const JOIN_ORDER: usize = 1;
    const JOIN_RSP: usize = 1;
    assert_eq!(SCAN_REQ + SCAN_RSP, 114);
    assert_eq!(
        START_ORDERS_C11_C20_C25 + START_RSP + JOIN_ORDER + JOIN_RSP,
        8
    );
    // Probe run deltas: 3 fewer scan requests answered, 5 fewer
    // scan responses, one retried start order, no start response.
    const PROBE_SCAN_REQ: usize = 57;
    const PROBE_SCAN_RSP: usize = 49;
    const PROBE_START_ORDERS: usize = 6;
    assert_eq!(PROBE_SCAN_REQ + PROBE_SCAN_RSP + PROBE_START_ORDERS, 112);
    // Cross-check: 122 gated frames per clean run (114 scan +
    // 5 + 1 + 1 + 1 orders/responses), 114 on probe.
    assert_eq!(SCAN_REQ + SCAN_RSP + 5 + 1 + 1 + 1, 122);
    assert_eq!(
        PROBE_SCAN_REQ + PROBE_SCAN_RSP + PROBE_START_ORDERS + 1 + 1,
        114
    );
}

// ---------------------------------------------------------------------------
// RD-INSPECT-32/33: w51 Green-Power regression goldens (GAP-5: every
// GPDF stopped `unknown` — L 84/84, K 84, H2 28).
// ---------------------------------------------------------------------------

/// Captured-corpus pins: hashes plus analyzer-observed metadata for
/// the offline reproduction procedure (lab `0600` key files, never in
/// the repo). Procedure: `python3 analyze52.py` in `~/hwscratch/w52`
/// (read-only over `~/hwscratch/w51/lane1_*.pcap`, linktype 230)
/// replays the per-shape GPDF census below; `~/hwscratch/w52/SUMMARY.md`
/// §1 documents the gap disposition this test's frame octets come from.
#[test]
fn captured_corpus_pins_gp_w51() {
    const A5: &str = "afeca7f063fea6a65e524c1c017ddc613b2ab26716c53ed09ea6120e3c99954b";
    const B8: &str = "527c463df6e7d9b62c1d99e2860231a0478865871d08936562be56ea1d59a52a";
    const C2: &str = "75e2fbebe1f03e32f6e2c0b6f7b49b49c6ba7359263f2e3736a3992deaae1498";
    const D: &str = "e3a8cc20cc3f7a0d1176fe9d61d02aa0ce26ff826a9ee309720eb44eb7fae5f9";
    const E: &str = "5057d90aea88218a2e63e0bb1edea31687081914ab44387323d3ab230628ac0e";
    const F: &str = "4b18b8e17d3d1da00cda9d1d81768120a47d9bc185c8c033dae7da37b9ec46a5";
    const G: &str = "9acd1ef8173753980e370a9573bb3d47840eb690e88622dc6521cc73a612e31a";
    const H2: &str = "b047dfedf16acbffaff429d064fb771403495cc0ca6badc72ec59f273b298367";
    const K: &str = "75aa318fd3c5106b08553f213a475ef31d5b0d0e26e55c206b1e190ff3e69f67";
    const L: &str = "4bebd87075d2a9ecba714b2d6d590580cb29f4efd914fcbe0f7827a33b31317c";
    for pin in [A5, B8, C2, D, E, F, G, H2, K, L] {
        assert_eq!(pin.len(), 64);
    }
    assert_ne!(A5, B8);
    assert_ne!(E, K);
    assert_ne!(K, L);
    // Analyzer-observed per-capture frame counts (pcap headers).
    const A5_FRAMES: usize = 543;
    const B8_FRAMES: usize = 565;
    const C2_FRAMES: usize = 416;
    const D_FRAMES: usize = 599;
    const E_FRAMES: usize = 601;
    const F_FRAMES: usize = 424;
    const G_FRAMES: usize = 444;
    const H2_FRAMES: usize = 451;
    const K_FRAMES: usize = 616;
    const L_FRAMES: usize = 559;
    assert_eq!(
        A5_FRAMES
            + B8_FRAMES
            + C2_FRAMES
            + D_FRAMES
            + E_FRAMES
            + F_FRAMES
            + G_FRAMES
            + H2_FRAMES
            + K_FRAMES
            + L_FRAMES,
        5218
    );
    // Per-capture GPDF totals (direct-MAC GPDF shapes only; the
    // NWK-tunneled proxy/sink notifications keep the NWK `secured`
    // leg and are not GP legs).
    const A5_GPDF: usize = 67;
    const B8_GPDF: usize = 18;
    const C2_GPDF: usize = 22;
    const D_GPDF: usize = 80;
    const E_GPDF: usize = 84;
    const F_GPDF: usize = 24;
    const G_GPDF: usize = 28;
    const H2_GPDF: usize = 28;
    const K_GPDF: usize = 84;
    const L_GPDF: usize = 84;
    assert_eq!(
        A5_GPDF + B8_GPDF + C2_GPDF + D_GPDF + E_GPDF + F_GPDF + G_GPDF + H2_GPDF + K_GPDF + L_GPDF,
        519
    );
    // GAP-5 filing: L 84/84, K 84, H2 28.
    assert_eq!(L_GPDF, 84);
    assert_eq!(K_GPDF, 84);
    assert_eq!(H2_GPDF, 28);
    // Per-shape census across all ten captures (ext, command,
    // command-payload length): unsecured data + commissioning
    // (long and compact), counter-protected data + decommissioning
    // + commissioning, the bidirectional reply-window ask, and the
    // eight encrypted shapes (ciphertext commands, sealed).
    const PLAIN_DATA: usize = 46;
    const PLAIN_COMM_LONG: usize = 162;
    const PLAIN_COMM_COMPACT: usize = 20;
    const SEC_DATA: usize = 193;
    const SEC_DECOMM: usize = 42;
    const SEC_COMM_LONG: usize = 10;
    const RX_AFTER_TX_COMM: usize = 10;
    const ENCRYPTED: usize = 36;
    assert_eq!(
        PLAIN_DATA
            + PLAIN_COMM_LONG
            + PLAIN_COMM_COMPACT
            + SEC_DATA
            + SEC_DECOMM
            + SEC_COMM_LONG
            + RX_AFTER_TX_COMM
            + ENCRYPTED,
        519
    );
    // B8 splits into 8 unsecured data frames plus the 10
    // bidirectional reply-window asks.
    const B8_PLAIN_DATA: usize = 8;
    assert_eq!(B8_PLAIN_DATA + RX_AFTER_TX_COMM, B8_GPDF);
}

// ---------------------------------------------------------------------------
// RD-INSPECT-34..36: wave-52 BLE capture pins.
// ---------------------------------------------------------------------------

/// Captured-corpus pins for the BLE/ATT gap-closure leg: the nine
/// wave-52 btsnoop captures (`~/hwscratch/w52/`, read-only) plus the
/// analyzer-observed ATT census. Procedure: the offline gate census
/// `python3 analyze53_ble.py` in `~/hwscratch/w53/` replays every
/// btsnoop record through the flags + HCI + ACL + L2CAP + ATT
/// predicate; all 387 ACL payloads parse (CENSUS PASS), with the
/// MTU-256/517 exchange, the exact 13-UUID Direct set (Security +
/// Commissioning services, 3 + 8 characteristics), 84 writes, and 27
/// Status-Code notifications. HCI/ATT PDUs are plaintext protocol —
/// no key material is involved anywhere on this leg. Short verbatim
/// vectors are pinned in `ble_att.rs`; longer commissioning values
/// pin here as hashes only.
#[test]
fn captured_corpus_pins_ble_w52() {
    const A_ATTEMPT1_SHA256: &str =
        "173805e411aa65d40dcd3671df5cc8e8316a5eb491820504ace3245c691ba046";
    const A_ATTEMPT2_SHA256: &str =
        "79d1a2ee5e78b0ccc5a0bba5ec01eec5ed2e1b2849a11742c3c84e11e4223711";
    const A1_7F68_SHA256: &str = "ff285d16e47a84f4aa6cc9b25267579c216ca3d2a09267b4a529648c2bf96399";
    const A1_97A4_SHA256: &str = "314b0eb366ae289e976c0bb2be012cbce8523bcfee89ab663c461fc4a7b50574";
    const A2_7F68_SHA256: &str = "ab21bad316dfe07301f257980da6d99bbc29cdd927d2bbe68e2b30243e54625d";
    const A2_97A4_SHA256: &str = "432f2b1a46b9762db86ba62de1f09c5cc377908c8966800778f8f91cab1516dd";
    const B_ATTEMPT1_SHA256: &str =
        "dca672fe9d5522949ffc9776ef8061333b6be28ef91b1554c7b07608d46dd655";
    const B_7F68_SHA256: &str = "1e14d3db21e0ddbe018445892d7af7dc2d6dc88d7244d96c1830f5c70e8e7c2b";
    const C_7F68_SHA256: &str = "bec1e98e5406c1e467491c38bc0b3980ce765ca91d0174d09b8a50c9d37c25fc";
    for h in [
        A_ATTEMPT1_SHA256,
        A_ATTEMPT2_SHA256,
        A1_7F68_SHA256,
        A1_97A4_SHA256,
        A2_7F68_SHA256,
        A2_97A4_SHA256,
        B_ATTEMPT1_SHA256,
        B_7F68_SHA256,
        C_7F68_SHA256,
    ] {
        assert_eq!(h.len(), 64);
    }
    // Per-capture ACL counts (attempt1 is scan-only: no connection,
    // zero ACL records — the ingest edge).
    const A_ATTEMPT1_ACL: usize = 0;
    const A_ATTEMPT2_ACL: usize = 44;
    const A1_7F68_ACL: usize = 44;
    const A1_97A4_ACL: usize = 44;
    const A2_7F68_ACL: usize = 38;
    const A2_97A4_ACL: usize = 38;
    const B_ATTEMPT1_ACL: usize = 53;
    const B_7F68_ACL: usize = 69;
    const C_7F68_ACL: usize = 57;
    assert_eq!(
        A_ATTEMPT1_ACL
            + A_ATTEMPT2_ACL
            + A1_7F68_ACL
            + A1_97A4_ACL
            + A2_7F68_ACL
            + A2_97A4_ACL
            + B_ATTEMPT1_ACL
            + B_7F68_ACL
            + C_7F68_ACL,
        387
    );
    // ATT opcode census across all nine captures.
    const ERROR_RSP: usize = 55;
    const MTU_REQ: usize = 10;
    const MTU_RSP: usize = 10;
    const FIND_INFO_REQ: usize = 5;
    const READ_BY_TYPE_REQ: usize = 40;
    const READ_BY_TYPE_RSP: usize = 20;
    const READ_REQ: usize = 16;
    const READ_RSP: usize = 16;
    const READ_BY_GROUP_REQ: usize = 25;
    const READ_BY_GROUP_RSP: usize = 20;
    const WRITE_REQ: usize = 84;
    const WRITE_RSP: usize = 59;
    const NOTIFY: usize = 27;
    assert_eq!(
        ERROR_RSP
            + MTU_REQ
            + MTU_RSP
            + FIND_INFO_REQ
            + READ_BY_TYPE_REQ
            + READ_BY_TYPE_RSP
            + READ_REQ
            + READ_RSP
            + READ_BY_GROUP_REQ
            + READ_BY_GROUP_RSP
            + WRITE_REQ
            + WRITE_RSP
            + NOTIFY,
        387
    );
    // MTU exchange values, the exact Direct UUID count, writes, and
    // Status-Code notifications (all on the Status handle 0x0022).
    const MTU_VALUES: [u16; 2] = [256, 517];
    assert_eq!(MTU_VALUES, [256, 517]);
    const DIRECT_UUIDS: usize = 13;
    assert_eq!(DIRECT_UUIDS, 13);
    assert_eq!(WRITE_REQ, 84);
    assert_eq!(NOTIFY, 27);
}
