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
    // files `decrypted` then `trailing` (leave-shaped plaintext).
    let cmd = build_secured_nwk_command(&[0x04, 0x60]);
    let opened = chain::dissect_with_keys(&cmd, eng.keys()).unwrap();
    assert!(opened.aps().is_none());
    assert_eq!(note_reasons(&opened), vec!["decrypted", "trailing"]);
    assert_eq!(opened.len(), 4);
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
