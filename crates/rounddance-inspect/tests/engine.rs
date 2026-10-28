//! Wave-41 engine tests: ZCL payload decodes, stateful session tables,
//! key-slot reporting, session schema, and parser robustness.
//!
//! All frames are built with the repo's own codecs or hand-assembled
//! from documented layouts; no new captures were taken.

use rounddance_inspect::{chain, report, session, tree};

// ---------------------------------------------------------------------------
// Builders.
// ---------------------------------------------------------------------------

/// Wrap a ZCL payload in APS + NWK + MAC (short->short, PAN 0x3761).
fn wrap_full_frame(
    zcl: &[u8],
    cluster_id: u16,
    nwk_seq: u8,
    aps_ctr: u8,
    src: u16,
    dst: u16,
) -> Vec<u8> {
    let aps = rounddance_aps::frame::DataHeader {
        control: rounddance_aps::frame::FrameControl::data(
            rounddance_aps::frame::DeliveryMode::Unicast,
        ),
        dest: rounddance_aps::frame::DataDest::Unicast { dst_endpoint: 1 },
        cluster_id,
        profile_id: 0x0104,
        src_endpoint: 1,
        counter: aps_ctr,
        ext: None,
    };
    let mut aps_buf = [0u8; 256];
    let an = aps.encode_into(zcl, &mut aps_buf).unwrap();

    let nwk = rounddance_nwk::frame::NwkHeader::minimal(
        rounddance_nwk::frame::FrameControl::data(),
        dst,
        src,
        30,
        nwk_seq,
    );
    let mut nwk_buf = [0u8; 320];
    let nn = nwk.encode_into(&aps_buf[..an], &mut nwk_buf).unwrap();

    let mut frame = vec![0x41, 0x88, 0x5a];
    frame.extend_from_slice(&0x3761u16.to_le_bytes());
    frame.extend_from_slice(&dst.to_le_bytes());
    frame.extend_from_slice(&src.to_le_bytes());
    frame.extend_from_slice(&nwk_buf[..nn]);
    frame
}

/// Global Read Attributes request for `attrs`.
fn zcl_read(tsn: u8, attrs: &[u16]) -> Vec<u8> {
    let h = rounddance_zcl::frame::Header {
        control: rounddance_zcl::frame::FrameControl {
            frame_type: rounddance_zcl::frame::FrameType::Global,
            manufacturer_specific: false,
            direction: rounddance_zcl::frame::Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn,
        command_id: rounddance_zcl::general::cmd::READ,
    };
    let mut buf = [0u8; 64];
    let n = h.encode_into(&mut buf).unwrap();
    let mut out = buf[..n].to_vec();
    for a in attrs {
        out.extend_from_slice(&a.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// ZCL payload decodes.
// ---------------------------------------------------------------------------

#[test]
fn detail_global_read_two_attrs() {
    let frame = wrap_full_frame(
        &zcl_read(0x42, &[0x0000, 0x0001]),
        0x0006,
        9,
        7,
        0x1234,
        0x5678,
    );
    let tree = chain::dissect(&frame).unwrap();
    let z = tree.zcl().expect("zcl node");
    assert_eq!(z.cluster_id, 0x0006);
    assert_eq!(z.profile_id, 0x0104);
    assert_eq!(
        z.detail,
        tree::ZclDetail::Global {
            cmd: 0x00,
            records: 2,
            first_id: 0x0000,
            status: 0xff,
        }
    );
    let text = report::to_text(&tree);
    assert!(text.contains("global cmd=0x00"));
    let json = report::to_json(&tree);
    assert!(json.contains("\"kind\":\"global\""));
    assert!(json.contains("\"cluster\":6"));
}

#[test]
fn detail_onoff_toggle() {
    let mut zcl = [0u8; 16];
    let n = rounddance_zcl::onoff::client::toggle(0x05, &mut zcl).unwrap();
    let frame = wrap_full_frame(&zcl[..n], 0x0006, 9, 7, 0x1234, 0x5678);
    let tree = chain::dissect(&frame).unwrap();
    let z = tree.zcl().expect("zcl node");
    assert_eq!(z.detail, tree::ZclDetail::OnOff { cmd: 0x02 });
    assert!(report::to_text(&tree).contains("onoff cmd=0x02"));
}

#[test]
fn detail_level_move_to_level() {
    let mut zcl = [0u8; 16];
    let n = rounddance_zcl::level::client::move_to_level(0x06, false, 0xfe, 10, None, &mut zcl)
        .unwrap();
    let frame = wrap_full_frame(&zcl[..n], 0x0008, 9, 7, 0x1234, 0x5678);
    let tree = chain::dissect(&frame).unwrap();
    let z = tree.zcl().expect("zcl node");
    assert_eq!(
        z.detail,
        tree::ZclDetail::Level {
            cmd: 0x00,
            arg0: 0xfe,
            arg1: 10,
        }
    );
    let json = report::to_json(&tree);
    assert!(json.contains("\"kind\":\"level\""));
}

#[test]
fn detail_global_report_and_default_rsp() {
    // Report: attribute 0x0000, Bool true. Frame control 0x00 =
    // global, client->server; then tsn, then command 0x0a.
    let mut payload = vec![0x00u8, 0x11, 0x0a];
    payload.extend_from_slice(&0x0000u16.to_le_bytes());
    payload.push(0x10); // Bool datatype
    payload.push(0x01); // true
    let frame = wrap_full_frame(&payload, 0x0006, 9, 7, 0x1234, 0x5678);
    let tree = chain::dissect(&frame).unwrap();
    let z = tree.zcl().expect("zcl node");
    assert_eq!(
        z.detail,
        tree::ZclDetail::Global {
            cmd: 0x0a,
            records: 1,
            first_id: 0x0000,
            status: 0xff,
        }
    );

    // Default Response: echoes cmd 0x02 with success.
    let payload = vec![0x08u8, 0x33, 0x0b, 0x02, 0x00];
    let frame = wrap_full_frame(&payload, 0x0006, 9, 7, 0x1234, 0x5678);
    let tree = chain::dissect(&frame).unwrap();
    let z = tree.zcl().expect("zcl node");
    assert_eq!(
        z.detail,
        tree::ZclDetail::Global {
            cmd: 0x0b,
            records: 1,
            first_id: 0x0002,
            status: 0x00,
        }
    );
}

#[test]
fn detail_unknown_cluster_and_truncated_payload() {
    // Cluster-specific command on an unmodeled cluster.
    let payload = vec![0x01u8, 0x44, 0x77, 0xaa, 0xbb];
    let frame = wrap_full_frame(&payload, 0x0402, 9, 7, 0x1234, 0x5678);
    let tree = chain::dissect(&frame).unwrap();
    let z = tree.zcl().expect("zcl node");
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x77 });

    // Truncated global Read (dangling attr octet): graceful zero-count.
    let payload = vec![0x00u8, 0x55, 0x00, 0x12];
    let frame = wrap_full_frame(&payload, 0x0006, 9, 7, 0x1234, 0x5678);
    let tree = chain::dissect(&frame).unwrap();
    let z = tree.zcl().expect("zcl node");
    assert_eq!(
        z.detail,
        tree::ZclDetail::Global {
            cmd: 0x00,
            records: 0,
            first_id: 0xffff,
            status: 0xff,
        }
    );
}

// ---------------------------------------------------------------------------
// Session tables.
// ---------------------------------------------------------------------------

#[test]
fn engine_windows_replay_gap_late() {
    let mut eng = session::SessionEngine::new();
    // NWK seqs: 10, 11, 12, 11(dup), 14(gap), 2(late).
    for seq in [10u8, 11, 12, 11, 14, 2] {
        let frame = wrap_full_frame(&zcl_read(0x01, &[0x0000]), 0x0006, seq, seq, 0x1234, 0x5678);
        let tree = chain::dissect(&frame).unwrap();
        eng.note_tree(&tree);
    }
    let dev = eng.device(0x1234).expect("device row");
    let w = dev.nwk_window.expect("nwk window");
    // The window stays anchored at the highest accepted seq (14); the
    // trailing seq 2 counts late without moving the base.
    assert_eq!(w.base, 14);
    assert_eq!(w.replays, 1, "one duplicate of 11");
    assert_eq!(w.gaps, 1, "13 skipped");
    assert_eq!(w.late, 1, "seq 2 arrives behind the window");
    let a = dev.aps_window.expect("aps window");
    assert_eq!(a.base, 14);
    assert_eq!(a.replays, 1);
    assert_eq!(a.gaps, 1);
    assert_eq!(a.late, 1);
}

#[test]
fn engine_rejoin_merges_by_ieee_and_counts_pan() {
    let mut eng = session::SessionEngine::new();
    // Same IEEE source under two NWK shorts (rejoin): bare NWK PDUs
    // built with the repo codec, folded via dissect_nwk.
    let ieee = 0x00124b0025abcd12u64;
    for (src, seq) in [(0x1111u16, 1u8), (0x2222u16, 2u8)] {
        let mut fc = rounddance_nwk::frame::FrameControl::data();
        fc.src_ieee = true;
        let hdr = rounddance_nwk::frame::NwkHeader {
            control: fc,
            dst_addr: 0x0000,
            src_addr: src,
            radius: 30,
            seq,
            dst_ieee: None,
            src_ieee: Some(ieee),
            source_route: None,
        };
        let mut buf = [0u8; 64];
        let n = hdr.encode_into(&[], &mut buf).unwrap();
        let tree = chain::dissect_nwk(&buf[..n]).unwrap();
        eng.note_tree(&tree);
    }
    // One row (merged), newest short wins, ieee lookup works.
    let by_ieee = eng.device_by_ieee(ieee).expect("ieee lookup");
    assert_eq!(by_ieee.short_addr, 0x2222);
    assert_eq!(by_ieee.frames, 2);
    assert!(eng.device(0x1111).is_none(), "old short merged away");
    // PAN 0 (NWK-only trees): two distinct shorts were seen.
    let net = eng.network(0).expect("pan 0 row");
    assert_eq!(net.devices, 2);
}

// ---------------------------------------------------------------------------
// Key slots + secured-frame reporting.
// ---------------------------------------------------------------------------

/// Genuine captured-air secured NWK frame (pinned octets, wave-36).
const EMBER_U1: [u8; 45] = [
    0x61, 0x88, 0x60, 0x1d, 0xb2, 0x1d, 0x02, 0x00, 0x00, 0x09, 0x12, 0x1d, 0x02, 0x00, 0x00, 0x01,
    0x44, 0x5f, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04, 0x28, 0x04, 0x40, 0x00, 0x00, 0x5f, 0x75,
    0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04, 0x00, 0x00, 0xab, 0x53, 0x68, 0xca, 0xee,
];

#[test]
fn engine_key_slots_gate_decryptability() {
    let mut eng = session::SessionEngine::new();
    let tree = chain::dissect(&EMBER_U1).unwrap();
    assert!(tree.nwk().map(|n| n.security).unwrap_or(false));

    // No key loaded: secured frames count as orphans.
    eng.note_tree(&tree);
    assert_eq!(eng.secured_orphan, 1);
    assert_eq!(eng.secured_decryptable, 0);
    assert_eq!(eng.keys().loaded(), 0);

    // Load a lab key: the same frame now counts as decryptable.
    eng.set_network_key([0xabu8; 16], 0);
    assert_eq!(eng.keys().loaded(), 1);
    assert!(eng.keys().has_key());
    eng.note_tree(&tree);
    assert_eq!(eng.secured_decryptable, 1);

    // Rotation replaces by sequence number without growing past cap.
    eng.set_network_key([0xcdu8; 16], 0);
    eng.set_network_key([0xefu8; 16], 1);
    eng.set_network_key([0x01u8; 16], 2);
    assert_eq!(eng.keys().loaded(), 2);
    eng.clear_keys();
    assert_eq!(eng.keys().loaded(), 0);

    let text = report::session_to_text(&eng);
    assert!(text.contains("secured_orphan=1"));
    assert!(text.contains("key_slots=0"));
    let json = report::session_to_json(&eng);
    assert!(json.contains("\"orphan\":1"));
    assert!(json.contains("\"decryptable\":1"));
}

// ---------------------------------------------------------------------------
// Session schema.
// ---------------------------------------------------------------------------

#[test]
fn session_schema_empty_engine_exact() {
    let eng = session::SessionEngine::new();
    assert_eq!(
        report::session_to_json(&eng),
        "{\"v\":1,\"trees\":0,\"devices\":[],\"networks\":[],\"sec\":{\"decryptable\":0,\"orphan\":0,\"slots\":0}}"
    );
    assert_eq!(report::SESSION_SCHEMA, 1);
}

#[test]
fn session_schema_one_tree_shape() {
    let mut eng = session::SessionEngine::new();
    let frame = wrap_full_frame(&zcl_read(0x42, &[0x0000]), 0x0006, 9, 7, 0x1234, 0x5678);
    let tree = chain::dissect(&frame).unwrap();
    eng.note_tree(&tree);
    let json = report::session_to_json(&eng);
    // Exact single-device / single-network snapshot.
    assert_eq!(
        json,
        "{\"v\":1,\"trees\":1,\"devices\":[{\"short\":4660,\"ieee\":null,\"last_seq\":90,\"frames\":1,\"secured\":0,\"nwk\":{\"base\":9,\"replays\":0,\"gaps\":0,\"late\":0},\"aps\":{\"base\":7,\"replays\":0,\"gaps\":0,\"late\":0}}],\"networks\":[{\"pan\":14177,\"frames\":1,\"devices\":1,\"secured\":0}],\"sec\":{\"decryptable\":0,\"orphan\":0,\"slots\":0}}"
    );
    let text = report::session_to_text(&eng);
    assert!(text.contains("session: trees=1"));
    assert!(text.contains("dev: short=0x1234"));
    assert!(text.contains("net: pan=0x3761"));
}

// ---------------------------------------------------------------------------
// Robustness: truncated / adversarial inputs, typed errors only.
// ---------------------------------------------------------------------------

/// Deterministic xorshift32 for reproducible mutation sweeps.
struct Rng(u32);

impl Rng {
    fn next(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }
}

#[test]
fn robustness_truncations_are_typed() {
    let frame = wrap_full_frame(
        &zcl_read(0x42, &[0x0000, 0x0001]),
        0x0006,
        9,
        7,
        0x1234,
        0x5678,
    );
    // Every prefix: either a sub-tree (MAC-only keeps MAC) or a typed
    // refusal — never a panic.
    for len in 0..frame.len() {
        let r = chain::dissect(&frame[..len]);
        match r {
            Ok(tree) => {
                assert!(!tree.is_empty(), "ok tree holds at least the MAC node");
            }
            Err(e) => {
                assert!(matches!(
                    e,
                    tree::TreeError::Empty
                        | tree::TreeError::MacTruncated
                        | tree::TreeError::MacMalformed
                ));
            }
        }
        // The session engine folds whatever comes out without panic.
        let mut eng = session::SessionEngine::new();
        if let Ok(tree) = chain::dissect(&frame[..len]) {
            eng.note_tree(&tree);
        }
    }
}

#[test]
fn robustness_mutation_sweep_no_panics() {
    let base = wrap_full_frame(&zcl_read(0x42, &[0x0000]), 0x0006, 9, 7, 0x1234, 0x5678);
    let mut rng = Rng(0x12345678);
    let mut eng = session::SessionEngine::new();
    for _ in 0..3000 {
        let mut frame = base.clone();
        // 1-3 random byte mutations.
        for _ in 0..1 + rng.next() % 3 {
            let i = (rng.next() as usize) % frame.len();
            frame[i] = (rng.next() & 0xff) as u8;
        }
        // Occasionally truncate.
        if rng.next().is_multiple_of(4) {
            let len = (rng.next() as usize) % (frame.len() + 1);
            frame.truncate(len);
        }
        match chain::dissect(&frame) {
            Ok(tree) => {
                eng.note_tree(&tree);
                let _ = report::to_text(&tree);
                let _ = report::to_json(&tree);
            }
            Err(e) => {
                assert!(matches!(
                    e,
                    tree::TreeError::Empty
                        | tree::TreeError::MacTruncated
                        | tree::TreeError::MacMalformed
                ));
            }
        }
    }
    // Engine stayed bounded through 3000 adversarial folds.
    assert!(eng.devices().len() <= session::MAX_DEVICES);
    assert!(eng.networks().len() <= session::MAX_NETWORKS);
    let _ = report::session_to_text(&eng);
    let _ = report::session_to_json(&eng);
}

#[test]
fn robustness_zcl_byte_sweep_typed() {
    // Exhaustive 1- and 2-byte inputs over zcl::decode: typed refusal
    // or a graceful summary, never a panic.
    let mut buf = [0u8; 2];
    for a in 0..=255u16 {
        buf[0] = a as u8;
        let r = rounddance_inspect::zcl::decode(&buf[..1], 0x0006, 0x0104);
        assert!(r.is_ok() || r.is_err());
        for b in 0..=255u16 {
            buf[1] = b as u8;
            let r = rounddance_inspect::zcl::decode(&buf[..], 0x0006, 0x0104);
            match r {
                Ok(_) => {}
                Err(e) => assert!(matches!(e, rounddance_inspect::zcl::ZclError::Codec(_))),
            }
        }
    }
    // Constant fills at every length: no panics through the chain.
    for fill in [0x00u8, 0xffu8, 0x61u8] {
        for len in 0..64 {
            let frame = vec![fill; len];
            let _ = chain::dissect(&frame);
        }
    }
}
