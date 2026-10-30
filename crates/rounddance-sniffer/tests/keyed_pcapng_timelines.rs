//! W3 (RD-SNIFF-* staged): keyed decrypt + timelines + pcapng SPB, offline only.
//!
//! Provenance: verbatim w82 `sniff_w82ch25.txt:3` sealed leg (parsed via
//! `parse_received`, never re-derived); synthetic sealed legs sealed with
//! test-only keys (`0x77` NWK, `0x5a` GP) in the same class as the
//! committed Ember U1/B1 vectors and the `live_air` / `decode_depth`
//! round trips — never lab key material. The w82 pcaps stay
//! sealed-golden: no slotted test key opens them (never force-decrypt).
//! pcapng Simple Packet Blocks are the new read capability: the
//! reference bytes below are crafted here (SHB + IDB + SPB, no options),
//! not a full spec.

use rounddance_inspect::sniffer::parse_received;
use rounddance_inspect::{chain, keys::KeySlots, pcap, report, session};
use rounddance_sniffer::{lease::lease_id_for_run, run};

// ---------------------------------------------------------------------------
// Synthetic test-only NWK seal (mirror of the decryptor open, same class
// as `live_air.rs`; feeds only the round-trip legs below).
// ---------------------------------------------------------------------------

const TEST_KEY: [u8; 16] = [0x77u8; 16];
const TEST_SEQ: u8 = 0;
const TEST_EXT: [u8; 8] = [0x5f, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04];
const TEST_CTR: u32 = 0x0000_4004;

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

/// Full secured MAC + NWK data + APS data + ZCL read under the test key.
fn build_secured_frame() -> Vec<u8> {
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
    let mut fc = rounddance_nwk::frame::FrameControl::data();
    fc.security = true;
    let nwk = rounddance_nwk::frame::NwkHeader::minimal(fc, 0x5678, 0x1234, 30, 0x09);
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

fn note_reasons(tree: &rounddance_inspect::tree::DecodeTree) -> Vec<&'static str> {
    tree.layers()
        .iter()
        .flatten()
        .filter_map(|l| match l {
            rounddance_inspect::tree::Layer::Note(n) => Some(n.reason),
            _ => None,
        })
        .collect()
}

// Verbatim w82 ch25 sealed leg (sniff_w82ch25.txt:3): MG21 NWK-secured
// maintenance frame, 0x0000 -> 0xfffc.
const CH25_SECURED: &str = "\u{1b}[Jreceived: 4188756137ffff00000912fcff0000011b5f75f4feffe5e30428057005005f75f4feffe5e304006c02be58bd3b4900 power: -102 lqi: 255 time: 5167725293";

fn packets_of(frames: &[Vec<u8>], ts: u64) -> Vec<pcap::Packet> {
    frames
        .iter()
        .map(|f| pcap::Packet {
            ts_us: ts,
            linktype: pcap::LINKTYPE_IEEE802_15_4,
            data: f.clone(),
        })
        .collect()
}

#[test]
fn nwk_keyed_open_success_wrong_key_refusal_unslotted_stays_sealed() {
    let frame = build_secured_frame();
    let lease = lease_id_for_run("w3-offline", "keyed-open", 25, 0);
    // Unslotted: stays sealed, orphan, no APS/ZCL legs.
    let shut = run::run_packets(
        &packets_of(std::slice::from_ref(&frame), 1),
        25,
        &KeySlots::new(),
        "keyed",
        lease,
    );
    assert_eq!(shut.frames.len(), 1);
    assert_eq!(shut.dissect_errors, 0);
    assert_eq!(shut.engine.secured_orphan, 1);
    assert_eq!(shut.engine.secured_decryptable, 0);
    let shut_tree = shut.frames[0].outcome.as_ref().unwrap();
    assert_eq!(note_reasons(shut_tree), vec!["secured"]);
    assert!(shut_tree.aps().is_none());
    assert!(shut_tree.zcl().is_none());
    // Slotted under the aux sequence: verified open, chain continues
    // through APS into ZCL, decryptable accounting flips.
    let mut slotted = KeySlots::new();
    slotted.set_network_key(TEST_KEY, TEST_SEQ);
    let open = run::run_packets(
        &packets_of(std::slice::from_ref(&frame), 1),
        25,
        &slotted,
        "keyed",
        lease,
    );
    assert_eq!(open.engine.secured_decryptable, 1);
    assert_eq!(open.engine.secured_orphan, 0);
    let open_tree = open.frames[0].outcome.as_ref().unwrap();
    assert_eq!(note_reasons(open_tree), vec!["decrypted"]);
    assert_eq!(
        open_tree.aps().expect("aps past decrypt").cluster_id,
        0x0006
    );
    assert_eq!(open_tree.zcl().expect("zcl past decrypt").command_id, 0x00);
    assert!(open_tree.zcl().expect("zcl").payload_len == 2);
    // Wrong sequence slot: tree stays sealed (strict seq resolve), but
    // the slot-loaded domain still counts decryptable (W1 pin: any
    // loaded slot marks the domain decryptable-offline).
    let mut wrong_seq = KeySlots::new();
    wrong_seq.set_network_key(TEST_KEY, TEST_SEQ + 1);
    let wrong = run::run_packets(
        &packets_of(std::slice::from_ref(&frame), 1),
        25,
        &wrong_seq,
        "keyed",
        lease,
    );
    assert_eq!(wrong.engine.secured_orphan, 0);
    assert_eq!(wrong.engine.secured_decryptable, 1);
    assert_eq!(
        note_reasons(wrong.frames[0].outcome.as_ref().unwrap()),
        vec!["secured"]
    );
    // Wrong key bytes: tree stays sealed, accounting still decryptable.
    let mut wrong_key = KeySlots::new();
    wrong_key.set_network_key([0x78u8; 16], TEST_SEQ);
    let wrong2 = run::run_packets(
        &packets_of(std::slice::from_ref(&frame), 1),
        25,
        &wrong_key,
        "keyed",
        lease,
    );
    assert_eq!(
        note_reasons(wrong2.frames[0].outcome.as_ref().unwrap()),
        vec!["secured"]
    );
    assert_eq!(wrong2.engine.secured_decryptable, 1);
    // Any mutated octet fails integrity: tree stays sealed (accounting
    // stays decryptable under the loaded slot).
    for flip in [frame.len() - 1, frame.len() - 5, 20] {
        let mut bad = frame.clone();
        bad[flip] ^= 0x01;
        let bad_rep = run::run_packets(&packets_of(&[bad], 1), 25, &slotted, "keyed", lease);
        assert_eq!(
            note_reasons(bad_rep.frames[0].outcome.as_ref().unwrap()),
            vec!["secured"],
            "mutation at {flip} must fail integrity"
        );
        assert_eq!(bad_rep.engine.secured_decryptable, 1);
        assert_eq!(bad_rep.engine.secured_orphan, 0);
    }
}

#[test]
fn w82_verbatim_stays_sealed_under_test_key_never_force_decrypt() {
    let (raw, _, _) = parse_received(CH25_SECURED).expect("verbatim w82 line parses");
    assert_eq!(raw.len(), 45);
    let lease = lease_id_for_run("w3-offline", "w82-sealed", 25, 0);
    let plain = run::run_packets(
        &packets_of(std::slice::from_ref(&raw), 1),
        25,
        &KeySlots::new(),
        "w82",
        lease,
    );
    assert_eq!(plain.engine.secured_orphan, 1);
    assert_eq!(plain.engine.secured_decryptable, 0);
    // A synthetic test-only slot flips the accounting domain without
    // opening anything: the tree is byte-identical (no force-decrypt).
    let mut slotted = KeySlots::new();
    slotted.set_network_key(TEST_KEY, TEST_SEQ);
    let keyed = run::run_packets(
        &packets_of(std::slice::from_ref(&raw), 1),
        25,
        &slotted,
        "w82",
        lease,
    );
    assert_eq!(keyed.engine.secured_decryptable, 1);
    assert_eq!(keyed.engine.secured_orphan, 0);
    let plain_json = report::to_json(plain.frames[0].outcome.as_ref().unwrap());
    let keyed_json = report::to_json(keyed.frames[0].outcome.as_ref().unwrap());
    assert_eq!(plain_json, keyed_json, "no lab key: tree never changes");
    assert_eq!(
        note_reasons(keyed.frames[0].outcome.as_ref().unwrap()),
        vec!["secured"]
    );
    assert!(keyed.frames[0].outcome.as_ref().unwrap().aps().is_none());
}

// ---------------------------------------------------------------------------
// Timelines fed by a keyed-open leg: join -> accept -> decrypted data.
// ---------------------------------------------------------------------------

fn mac_cmd(cmd: u8, payload: &[u8], src: u16, dst: u16, seq: u8) -> Vec<u8> {
    let mut frame = vec![0x63, 0x88, seq];
    frame.extend_from_slice(&0x3761u16.to_le_bytes());
    frame.extend_from_slice(&dst.to_le_bytes());
    frame.extend_from_slice(&src.to_le_bytes());
    frame.push(cmd);
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn keyed_decrypted_data_feeds_timeline_and_v2_round_trip() {
    // Join request + accept are MAC-plain; the data leg arrives sealed
    // and only classifies after a verified open.
    let mut slotted = KeySlots::new();
    slotted.set_network_key(TEST_KEY, TEST_SEQ);
    let lease = lease_id_for_run("w3-offline", "keyed-timeline", 25, 0);
    // The sealed frame already sources from the joiner (MAC + NWK
    // short 0x1234), so the (PAN, short) key links all three legs. The
    // MAC short is not in the CCM* associated data (the nonce binds the
    // extended source), so no rewrite is needed and the seal verifies.
    let frames = [
        mac_cmd(0x01, &[0x8c], 0x1234, 0xffff, 0x10),
        mac_cmd(0x02, &[0x34, 0x12, 0x00], 0x0000, 0x1234, 0x11),
        build_secured_frame(),
    ];
    let packets = packets_of(&frames, 1000);
    // Unslotted: the sealed leg never classifies, timeline stops joined.
    let shut = run::run_packets(&packets, 25, &KeySlots::new(), "tl", lease);
    let shut_tl = shut
        .engine
        .timeline(0x3761, 0x1234)
        .expect("timeline opens");
    assert_eq!(shut_tl.events(), 2);
    assert_eq!(shut_tl.stage, session::TimelineStage::Joined);
    // Slotted: the decrypted data leg classifies, stage advances active.
    let open = run::run_packets(&packets, 25, &slotted, "tl", lease);
    assert_eq!(open.engine.secured_decryptable, 1);
    let tl = open
        .engine
        .timeline(0x3761, 0x1234)
        .expect("timeline opens");
    assert_eq!(tl.stage, session::TimelineStage::Active);
    assert_eq!(tl.anomalies, 0);
    assert_eq!(tl.events(), 3);
    assert_eq!(tl.log[0], Some((1, 1)));
    assert_eq!(tl.log[1], Some((2, 2)));
    assert_eq!(tl.log[2], Some((7, 3)));
    // Exact v2 shape carries the keyed timeline; save/load round trips
    // byte-identically (both shapes), v1 projection matches direct v1.
    let v2 = report::session_to_json_v2(&open.engine);
    assert!(v2.contains("\"stage\":\"active\""), "{v2}");
    assert!(v2.contains("\"ev\":7"), "{v2}");
    let back = report::session_v2_from_json(&v2).expect("v2 loads");
    assert_eq!(report::session_to_json_v2(&back), v2);
    assert_eq!(
        report::session_to_json(&back),
        report::session_to_json(&open.engine)
    );
    // Reports carry the timeline table.
    let text = run::text_report(&open);
    assert!(text.contains("== timelines =="));
    assert!(text.contains("stage=active") || text.contains("active"));
    let json = run::json_report(&open);
    assert!(json.contains("\"timelines\":["));
}

// ---------------------------------------------------------------------------
// GP keyed legs through the sniffer fold (same class as decode_depth).
// ---------------------------------------------------------------------------

const GP_TEST_KEY: [u8; 16] = [0x5au8; 16];

fn gp_test_nonce(srcid: u32, ctr: u32) -> [u8; 13] {
    let id = srcid.to_le_bytes();
    let c = ctr.to_le_bytes();
    [
        id[0], id[1], id[2], id[3], id[0], id[1], id[2], id[3], c[0], c[1], c[2], c[3], 0x05,
    ]
}

fn gp_test_ks(key: &[u8; 16], nonce: &[u8; 13], ctr: u32) -> [u8; 16] {
    use rounddance_security::encrypt_block_aes128;
    let mut blk = [0u8; 16];
    blk[0] = 0x01;
    blk[1..14].copy_from_slice(nonce);
    blk[14..16].copy_from_slice(&(ctr as u16).to_be_bytes());
    encrypt_block_aes128(key, &blk)
}

fn gp_test_tag(key: &[u8; 16], nonce: &[u8; 13], aad_extra: &[u8], msg: &[u8]) -> [u8; 4] {
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
    let mut x = encrypt_block_aes128(key, &b0);
    for blk in mac_in.chunks(16) {
        let mut mix = [0u8; 16];
        for (i, b) in blk.iter().enumerate() {
            mix[i] = x[i] ^ b;
        }
        x = encrypt_block_aes128(key, &mix);
    }
    let s0 = gp_test_ks(key, nonce, 0);
    [x[0] ^ s0[0], x[1] ^ s0[1], x[2] ^ s0[2], x[3] ^ s0[3]]
}

fn gp_wrap(msdu: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x01u8, 0x08, 0x5a, 0x61, 0x37, 0xff, 0xff];
    frame.extend_from_slice(msdu);
    frame
}

fn gp_mic_only_frame() -> Vec<u8> {
    let srcid = 0x517f_6811u32;
    let ctr = 7u32;
    let section = [0x20u8, 0x01];
    let mut header = vec![0x8cu8, 0x30];
    header.extend_from_slice(&srcid.to_le_bytes());
    header.extend_from_slice(&ctr.to_le_bytes());
    let nonce = gp_test_nonce(srcid, ctr);
    let mut aad_extra = header.clone();
    aad_extra.extend_from_slice(&section);
    let tag = gp_test_tag(&GP_TEST_KEY, &nonce, &aad_extra, &[]);
    let mut msdu = header.clone();
    msdu.extend_from_slice(&section);
    msdu.extend_from_slice(&tag);
    gp_wrap(&msdu)
}

#[test]
fn gp_keyed_open_success_and_domain_gating() {
    let frame = gp_mic_only_frame();
    let lease = lease_id_for_run("w3-offline", "gp-keyed", 25, 0);
    // Unslotted: sealed, orphan, command still named from the clear.
    let shut = run::run_packets(
        &packets_of(std::slice::from_ref(&frame), 1),
        25,
        &KeySlots::new(),
        "gp",
        lease,
    );
    assert_eq!(shut.engine.secured_orphan, 1);
    assert_eq!(shut.engine.secured_decryptable, 0);
    assert_eq!(
        note_reasons(shut.frames[0].outcome.as_ref().unwrap()),
        vec!["secured"]
    );
    // Slotted GP class: verified open, `decrypted`, decryptable.
    let mut slotted = KeySlots::new();
    slotted.set_gp_key(GP_TEST_KEY, true);
    let open = run::run_packets(
        &packets_of(std::slice::from_ref(&frame), 1),
        25,
        &slotted,
        "gp",
        lease,
    );
    assert_eq!(open.engine.secured_decryptable, 1);
    assert_eq!(open.engine.secured_orphan, 0);
    assert_eq!(
        note_reasons(open.frames[0].outcome.as_ref().unwrap()),
        vec!["decrypted"]
    );
    assert_eq!(
        open.frames[0]
            .outcome
            .as_ref()
            .unwrap()
            .gp()
            .expect("gp leg")
            .command_id,
        Some(0x20)
    );
    // Wrong key-bit class: tree stays sealed (strict bit resolve), but
    // the loaded GP domain still counts decryptable (coarse slot gate;
    // only cross-domain NWK slots stay orphan — see below).
    let mut wrong_bit = KeySlots::new();
    wrong_bit.set_gp_key(GP_TEST_KEY, false);
    let wrong = run::run_packets(
        &packets_of(std::slice::from_ref(&frame), 1),
        25,
        &wrong_bit,
        "gp",
        lease,
    );
    assert_eq!(
        note_reasons(wrong.frames[0].outcome.as_ref().unwrap()),
        vec!["secured"]
    );
    assert_eq!(wrong.engine.secured_decryptable, 1);
    assert_eq!(wrong.engine.secured_orphan, 0);
    // Wrong key bytes: tree stays sealed, accounting decryptable.
    let mut wrong_key = KeySlots::new();
    wrong_key.set_gp_key([0x11u8; 16], true);
    let wrong2 = run::run_packets(
        &packets_of(std::slice::from_ref(&frame), 1),
        25,
        &wrong_key,
        "gp",
        lease,
    );
    assert_eq!(
        note_reasons(wrong2.frames[0].outcome.as_ref().unwrap()),
        vec!["secured"]
    );
    assert_eq!(wrong2.engine.secured_decryptable, 1);
    // NWK-only slots never cover GP legs (per-domain gating).
    let mut nwk_only = KeySlots::new();
    nwk_only.set_network_key([0x77u8; 16], 0);
    let nwk = run::run_packets(
        &packets_of(std::slice::from_ref(&frame), 1),
        25,
        &nwk_only,
        "gp",
        lease,
    );
    assert_eq!(nwk.engine.secured_decryptable, 0);
    assert_eq!(nwk.engine.secured_orphan, 1);
}

// ---------------------------------------------------------------------------
// pcapng Simple Packet Blocks: crafted reference (SHB + IDB + SPB).
// ---------------------------------------------------------------------------

fn shb() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
    b.extend_from_slice(&28u32.to_le_bytes());
    b.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&(-1i64).to_le_bytes());
    b.extend_from_slice(&28u32.to_le_bytes());
    b
}

fn idb(linktype: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&20u32.to_le_bytes());
    b.extend_from_slice(&linktype.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&262144u32.to_le_bytes());
    b.extend_from_slice(&20u32.to_le_bytes());
    b
}

fn spb(data: &[u8]) -> Vec<u8> {
    let pad = (4 - (data.len() % 4)) % 4;
    let total = (16 + data.len() + pad) as u32;
    let mut b = Vec::new();
    b.extend_from_slice(&3u32.to_le_bytes());
    b.extend_from_slice(&total.to_le_bytes());
    b.extend_from_slice(&(data.len() as u32).to_le_bytes());
    b.extend_from_slice(data);
    b.extend(std::iter::repeat_n(0u8, pad));
    b.extend_from_slice(&total.to_le_bytes());
    b
}

fn epb(data: &[u8], ts_us: u64) -> Vec<u8> {
    let pad = (4 - (data.len() % 4)) % 4;
    let total = (32 + data.len() + pad) as u32;
    let mut b = Vec::new();
    b.extend_from_slice(&6u32.to_le_bytes());
    b.extend_from_slice(&total.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&(ts_us as u32).to_le_bytes());
    b.extend_from_slice(&((ts_us >> 32) as u32).to_le_bytes());
    b.extend_from_slice(&(data.len() as u32).to_le_bytes());
    b.extend_from_slice(&(data.len() as u32).to_le_bytes());
    b.extend_from_slice(data);
    b.extend(std::iter::repeat_n(0u8, pad));
    b.extend_from_slice(&total.to_le_bytes());
    b
}

#[test]
fn pcapng_spb_reads_reference_blocks_with_zero_timestamp() {
    // Reference file crafted here: SHB + IDB(195) + two SPBs (beacon-req
    // verbatim bare + one synthetic secured frame).
    let (beacon, _, _) = parse_received(
        "\u{1b}[Jreceived: 0308adffffffff071600 power: 103 lqi: 88 time: 5167374343",
    )
    .expect("verbatim beacon-req parses");
    let sealed = build_secured_frame();
    let mut buf = shb();
    buf.extend_from_slice(&idb(195));
    buf.extend_from_slice(&spb(&beacon));
    buf.extend_from_slice(&spb(&sealed));
    let packets = pcap::read_all(&mut &buf[..]).expect("SPB reference reads");
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].data, beacon);
    assert_eq!(packets[1].data, sealed);
    assert_eq!(packets[0].linktype, 195);
    assert_eq!(packets[1].linktype, 195);
    // SPBs carry no timestamp: ingested with ts_us = 0.
    assert_eq!(packets[0].ts_us, 0);
    assert_eq!(packets[1].ts_us, 0);
    // Same bytes through the sniffer fold dissect identically to the
    // direct chain legs (radio attached by the fold leg).
    let lease = lease_id_for_run("w3-offline", "spb", 25, 0);
    let rep = run::run_packets(&packets, 25, &KeySlots::new(), "spb", lease);
    assert_eq!(rep.frames.len(), 2);
    assert_eq!(rep.frames[0].ts_us, 0);
    assert_eq!(rep.dissect_errors, 0);
    let mut direct = chain::dissect(&beacon).unwrap();
    direct.set_radio(25, 0, 0);
    assert_eq!(
        report::to_json(rep.frames[0].outcome.as_ref().unwrap()),
        report::to_json(&direct)
    );
}

#[test]
fn pcapng_spb_mixes_with_epb_and_honors_idb_linktype() {
    let (beacon, _, _) = parse_received(
        "\u{1b}[Jreceived: 0308adffffffff071600 power: 103 lqi: 88 time: 5167374343",
    )
    .expect("verbatim beacon-req parses");
    let sealed = build_secured_frame();
    // EPB carries a µs timestamp; SPB carries none. IDB 230 exercises
    // the Wireshark-native no-FCS linktype through the SPB path.
    let mut buf = shb();
    buf.extend_from_slice(&idb(230));
    buf.extend_from_slice(&epb(&beacon, 1_700_000_000_000_001));
    buf.extend_from_slice(&spb(&sealed));
    let packets = pcap::read_all(&mut &buf[..]).expect("mixed EPB+SPB reads");
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].ts_us, 1_700_000_000_000_001);
    assert_eq!(packets[0].linktype, 230);
    assert_eq!(packets[1].ts_us, 0);
    assert_eq!(packets[1].linktype, 230);
    // Folding the mixed file matches folding the same frames from a
    // uniform source (trees byte-identical; session identical).
    let lease = lease_id_for_run("w3-offline", "mixed", 25, 0);
    let rep = run::run_packets(&packets, 25, &KeySlots::new(), "mixed", lease);
    assert_eq!(rep.frames.len(), 2);
    assert_eq!(rep.frames[0].ts_us, 1_700_000_000_000_001);
    assert_eq!(rep.frames[1].ts_us, 0);
}

#[test]
fn pcapng_spb_rejects_truncated_and_bad_lengths() {
    let (beacon, _, _) = parse_received(
        "\u{1b}[Jreceived: 0308adffffffff071600 power: 103 lqi: 88 time: 5167374343",
    )
    .expect("verbatim beacon-req parses");
    let mut good = shb();
    good.extend_from_slice(&idb(195));
    good.extend_from_slice(&spb(&beacon));
    // Truncated tail.
    let mut trunc = good.clone();
    trunc.pop();
    assert!(matches!(
        pcap::read_all(&mut &trunc[..]),
        Err(pcap::IngestError::Truncated)
    ));
    // Corrupt trailing total.
    let mut bad = good.clone();
    let n = bad.len();
    bad[n - 1] ^= 0x01;
    assert!(matches!(
        pcap::read_all(&mut &bad[..]),
        Err(pcap::IngestError::BadBlockLen(_))
    ));
    // Declared original length past the block end.
    let mut over = shb();
    over.extend_from_slice(&idb(195));
    let mut block = spb(&beacon);
    // Patch orig_len to 100 (block only carries 8).
    block[8..12].copy_from_slice(&100u32.to_le_bytes());
    over.extend_from_slice(&block);
    assert!(matches!(
        pcap::read_all(&mut &over[..]),
        Err(pcap::IngestError::Truncated)
    ));
}
