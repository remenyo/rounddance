//! W1 (RD-SNIFF-*): Listener-vs-Ingest invariant, reports, pcap-out.
//!
//! The load-bearing rule: a saved feed replayed through
//! [`ReplayListener`](rounddance_inspect::sniffer::ReplayListener)
//! and the same bytes streamed through the
//! [`Ingest`](rounddance_inspect::stream::Ingest) pipe produce
//! byte-identical trees and sessions. The subset below reuses the
//! verbatim w82 lines from `ota_vectors.rs` (plus shell noise and a
//! short line the parser must skip), framed exactly as the serial
//! feed carries them (`\x1b[J` prefix, `\r\n` terminator).

use rounddance_inspect::sniffer::ReplayListener;
use rounddance_inspect::{keys::KeySlots, report};
use rounddance_sniffer::{
    lease::{lease_id_for_run, lease_id_hex},
    run,
};

/// Verbatim w82 subset: beacon-req (quirk) + beacon + sealed NWK +
/// MAC-secured + ch20 beacon-req, with shell noise and a short line.
const LINES: &[&str] = &[
    "\u{1b}[Jreceived: 0308adffffffff071600 power: 103 lqi: 88 time: 5167374343",
    "sleep",
    "\u{1b}[Jreceived: 00807461370000ff4f00000022841694b10911403a09ffffff004900 power: -102 lqi: 255 time: 5167461593",
    "\u{1b}[Jreceived: 4188756137ffff00000912fcff0000011b5f75f4feffe5e30428057005005f75f4feffe5e304006c02be58bd3b4900 power: -102 lqi: 255 time: 5167725293",
    "channel 25",
    "\u{1b}[Jreceived: 6b98f15966009001900d0e3505001604d5117aec0309 power: 87 lqi: 12 time: 5178227991",
    "\u{1b}[Jreceived: 030839ffffffff070400 power: 85 lqi: 16 time: 5262186082",
    "received: 12 power: -90 lqi: 200 time: 1",
];

fn wire_bytes() -> Vec<u8> {
    let mut v = Vec::new();
    for l in LINES {
        v.extend_from_slice(l.as_bytes());
        v.extend_from_slice(b"\r\n");
    }
    v
}

fn write_feed(path: &std::path::Path) {
    let mut text = String::new();
    for l in LINES {
        text.push_str(l);
        text.push('\n');
    }
    std::fs::write(path, text).unwrap();
}

fn per_frame_json(rep: &run::RunReport) -> Vec<String> {
    rep.frames
        .iter()
        .map(|f| match &f.outcome {
            Ok(t) => report::to_json(t),
            Err(e) => format!("ERR:{e:?}"),
        })
        .collect()
}

#[test]
fn listener_and_stream_folds_are_byte_identical() {
    let dir = std::env::temp_dir();
    let path = dir.join("w1-sniff-invariant.txt");
    write_feed(&path);
    let keys = KeySlots::new();
    let lease = lease_id_for_run("w1-offline", "invariant", 25, 0);

    let mut li = ReplayListener::open(path.to_str().unwrap(), 25).unwrap();
    let via_listener = run::run_listener(&mut li, 25, &keys, "invariant", lease);
    std::fs::remove_file(&path).unwrap();
    assert_eq!(via_listener.frames.len(), 5, "5 frame lines, 3 skipped");
    assert_eq!(via_listener.dissect_errors, 0);
    assert_eq!(via_listener.listener_errors, 0);

    let wire = wire_bytes();
    // Odd chunk sizes split every line boundary shape alike (each
    // push stays within the drain discipline, so nothing sheds).
    for chunk in [1usize, 7, 64, 200, 512] {
        let (via_stream, stats) = run::run_stream(&wire, chunk, 25, &keys, "invariant", lease);
        assert_eq!(stats.frames, 5, "chunk {chunk}");
        assert_eq!(stats.ignored, 3, "chunk {chunk}: sleep/channel/short");
        assert_eq!(stats.oversize, 0, "chunk {chunk}");
        assert_eq!(stats.dissect_errors, 0, "chunk {chunk}");
        assert_eq!(
            per_frame_json(&via_stream),
            per_frame_json(&via_listener),
            "chunk {chunk}: trees byte-identical"
        );
        assert_eq!(
            report::session_to_json_v2(&via_stream.engine),
            report::session_to_json_v2(&via_listener.engine),
            "chunk {chunk}: sessions byte-identical"
        );
        assert_eq!(
            run::text_report(&via_stream),
            run::text_report(&via_listener),
            "chunk {chunk}: text reports byte-identical"
        );
        assert_eq!(
            run::json_report(&via_stream),
            run::json_report(&via_listener),
            "chunk {chunk}: json reports byte-identical"
        );
    }
}

#[test]
fn bulk_push_without_drain_sheds_and_counts() {
    // The framer discipline: a bulk push wider than the pipe sheds
    // the straddling line at resync and counts it — never silently
    // fed downstream. Callers drain after every small read (as the
    // loop above and the live reader do).
    let wire = wire_bytes();
    assert!(wire.len() > rounddance_inspect::stream::LINE_CAP);
    let keys = KeySlots::new();
    let lease = lease_id_for_run("w1-offline", "shed", 25, 0);
    let (rep, stats) = run::run_stream(&wire, wire.len(), 25, &keys, "shed", lease);
    assert_eq!(stats.framer_dropped, 1);
    assert!(rep.frames.len() + stats.framer_dropped as usize >= 5);
}

#[test]
fn reports_carry_run_envelope_and_v2_session() {
    let dir = std::env::temp_dir();
    let path = dir.join("w1-sniff-reports.txt");
    write_feed(&path);
    let keys = KeySlots::new();
    let lease = lease_id_for_run("w1-offline", "reports", 25, 0);
    let mut lease_hex = [0u8; 16];
    lease_id_hex(lease, &mut lease_hex);
    let lease_hex = String::from_utf8(lease_hex.to_vec()).unwrap();
    // Independent FNV-1a cross-check (python3 reference):
    // a9d05b9574fc070a is ("w1-offline","ch25",25,0); the ("reports")
    // tag value below is pinned by this run's own determinism plus
    // the byte-shape asserts — the cross-implementation agreement is
    // proven in `lease_id_matches_independent_fnv`.
    let mut li = ReplayListener::open(path.to_str().unwrap(), 25).unwrap();
    let rep = run::run_listener(&mut li, 25, &keys, "reports", lease);
    std::fs::remove_file(&path).unwrap();

    let text = run::text_report(&rep);
    assert!(text.starts_with(&format!(
        "run: lease={lease_hex} tag=reports channel=25 frames=5 dissect_errors=0 listener_errors=0\n"
    )), "{text}");
    assert!(text.contains("== session =="));
    assert!(text.contains("== timelines =="));

    let json = run::json_report(&rep);
    assert!(
        json.contains(&format!("\"lease\":\"{lease_hex}\"")),
        "{json}"
    );
    assert!(
        json.contains("\"tag\":\"reports\",\"channel\":25"),
        "{json}"
    );
    assert!(json.contains("\"frames\":[{"), "{json}");
    // v2 session embedded: same body as v1 (schema octet swapped),
    // then the timelines table appended.
    let v1 = report::session_to_json(&rep.engine);
    let v2 = report::session_to_json_v2(&rep.engine);
    assert!(v1.starts_with("{\"v\":1,"));
    assert!(v2.starts_with("{\"v\":2,"));
    let v1_body = v1
        .strip_prefix("{\"v\":1,")
        .unwrap()
        .strip_suffix('}')
        .unwrap();
    let v2_body = v2.strip_prefix("{\"v\":2,").unwrap();
    assert!(v2_body.starts_with(v1_body));
    assert!(v2_body[v1_body.len()..].starts_with(",\"timelines\":"));
    assert!(v2.ends_with(",\"timelines\":[]}"), "{v2}");
    assert!(json.ends_with(&format!("\"session\":{v2}}}")), "{json}");

    // v2 save/load round trip re-renders byte-identically (both shapes).
    let back = report::session_v2_from_json(&v2).expect("v2 loads");
    assert_eq!(report::session_to_json_v2(&back), v2);
    assert_eq!(report::session_to_json(&back), v1);
}

#[test]
fn lease_id_matches_independent_fnv() {
    // Reference values from an independent python3 FNV-1a-64 over
    // worker + 0xff + tag + 0xff + channel + seq-LE (see SUMMARY).
    assert_eq!(
        lease_id_for_run("w1-offline", "ch25", 25, 0),
        0xa9d05b9574fc070a
    );
    assert_eq!(
        lease_id_for_run("w1-offline", "w82ch25", 25, 0),
        0x7ec428f38abb1755
    );
    assert_eq!(
        lease_id_for_run("w1-offline", "w82ch20", 20, 0),
        0xa2bf51eb13d1843d
    );
    let mut out = [0u8; 16];
    lease_id_hex(0x7ec428f38abb1755, &mut out);
    assert_eq!(&out, b"7ec428f38abb1755");
}

#[test]
fn session_v2_schema_pins_and_load_gates() {
    use rounddance_inspect::session::SessionEngine;
    // Empty engine: exact v2 shape.
    let eng = SessionEngine::new();
    assert_eq!(
        report::session_to_json_v2(&eng),
        "{\"v\":2,\"trees\":0,\"devices\":[],\"networks\":[],\"sec\":{\"decryptable\":0,\"orphan\":0,\"slots\":0},\"timelines\":[]}"
    );
    assert_eq!(report::SESSION_SCHEMA_V2, 2);
    // A v1 document is BadSchema for the v2 loader (never misread).
    assert_eq!(
        load_err(&report::session_to_json(&eng)),
        report::SessionLoadError::BadSchema
    );
    // Truncated / mistyped / unknown-stage / duplicate-flag v2 rejects.
    let v2 = report::session_to_json_v2(&eng);
    assert_eq!(
        load_err(&v2[..v2.len() - 1]),
        report::SessionLoadError::Malformed
    );
    assert_eq!(load_err("{\"v\":3}"), report::SessionLoadError::BadSchema);
    let bad_stage = v2.replace("\"timelines\":[]", "\"timelines\":[{\"pan\":1,\"short\":2,\"ieee\":null,\"stage\":\"nope\",\"left\":false,\"events\":0,\"anomalies\":0,\"flags\":[],\"log\":[]}]");
    assert_eq!(load_err(&bad_stage), report::SessionLoadError::Malformed);
    let dup_flags = v2.replace("\"timelines\":[]", "\"timelines\":[{\"pan\":1,\"short\":2,\"ieee\":null,\"stage\":\"absent\",\"left\":false,\"events\":0,\"anomalies\":1,\"flags\":[\"gap\",\"gap\"],\"log\":[]}]");
    assert_eq!(load_err(&dup_flags), report::SessionLoadError::Malformed);
}

fn load_err(s: &str) -> report::SessionLoadError {
    report::session_v2_from_json(s).expect_err("v2 load must reject")
}

#[test]
fn pcap_out_round_trips_both_dlts() {
    use rounddance_inspect::pcap;
    let dir = std::env::temp_dir();
    let path = dir.join("w1-sniff-pcap.txt");
    write_feed(&path);
    let keys = KeySlots::new();
    let lease = lease_id_for_run("w1-offline", "pcap", 25, 0);
    let mut li = ReplayListener::open(path.to_str().unwrap(), 25).unwrap();
    let rep = run::run_listener(&mut li, 25, &keys, "pcap", lease);
    std::fs::remove_file(&path).unwrap();

    // 195 leg: untouched writer, bare frames, ordinal timestamps.
    let mut raw195 = Vec::new();
    run::write_pcap_195(&rep, &mut raw195).unwrap();
    let pkts = pcap::read_all(&mut &raw195[..]).unwrap();
    assert_eq!(pkts.len(), 5);
    for (p, f) in pkts.iter().zip(rep.frames.iter()) {
        assert_eq!(p.linktype, pcap::LINKTYPE_IEEE802_15_4);
        assert_eq!(p.data, f.data);
        assert_eq!(p.ts_us, f.ts_us);
    }

    // Radio leg (147): header + bare frame, radio bytes preserved —
    // including the positive-RSSI quirk, honest in the file.
    let mut raw_radio = Vec::new();
    run::write_pcap_radio(&rep, &mut raw_radio).unwrap();
    let radio = run::read_pcap_radio(&mut &raw_radio[..]).unwrap();
    assert_eq!(radio.len(), 5);
    for (r, f) in radio.iter().zip(rep.frames.iter()) {
        assert_eq!(r.channel, 25);
        assert_eq!(r.rssi, f.rssi);
        assert_eq!(r.lqi, f.lqi);
        assert_eq!(r.data, f.data);
        assert_eq!(r.ts_us, f.ts_us);
    }
    assert_eq!(radio[0].rssi, 103, "quirk byte survives the file");
    // Cross-leg payload identity.
    for (p, r) in pkts.iter().zip(radio.iter()) {
        assert_eq!(p.data, r.data);
    }
    // Guards: a 195 file is not a radio file; bad version refused
    // (radio header opens at global-header 24 + record-header 16).
    assert!(run::read_pcap_radio(&mut &raw195[..]).is_err());
    let mut bad = raw_radio.clone();
    bad[24 + 16] = 0x7f;
    assert!(run::read_pcap_radio(&mut &bad[..]).is_err());
}

#[test]
fn synthetic_key_flips_orphan_accounting_not_trees() {
    let dir = std::env::temp_dir();
    let path = dir.join("w1-sniff-keyed.txt");
    write_feed(&path);
    let lease = lease_id_for_run("w1-offline", "keyed", 25, 0);
    let mut li = ReplayListener::open(path.to_str().unwrap(), 25).unwrap();
    let plain = run::run_listener(&mut li, 25, &KeySlots::new(), "keyed", lease);
    assert_eq!(plain.engine.secured_orphan, 1);
    assert_eq!(plain.engine.secured_decryptable, 0);

    let mut li = ReplayListener::open(path.to_str().unwrap(), 25).unwrap();
    let mut keys = KeySlots::new();
    keys.set_network_key([0x77u8; 16], 0);
    let keyed = run::run_listener(&mut li, 25, &keys, "keyed", lease);
    std::fs::remove_file(&path).unwrap();
    // Slot-loaded domain counts decryptable; nothing opens under a
    // test-only key, so every tree is unchanged.
    assert_eq!(keyed.engine.secured_decryptable, 1);
    assert_eq!(keyed.engine.secured_orphan, 0);
    assert_eq!(per_frame_json(&keyed), per_frame_json(&plain));
}

// ---------------------------------------------------------------------------
// Session v2 with a live timeline table: join -> accept -> data.
// ---------------------------------------------------------------------------

/// Short->short MAC command frame (PAN 0x3761, intra-PAN).
fn mac_cmd(cmd: u8, payload: &[u8], src: u16, dst: u16, seq: u8) -> Vec<u8> {
    let mut frame = vec![0x63, 0x88, seq];
    frame.extend_from_slice(&0x3761u16.to_le_bytes());
    frame.extend_from_slice(&dst.to_le_bytes());
    frame.extend_from_slice(&src.to_le_bytes());
    frame.push(cmd);
    frame.extend_from_slice(payload);
    frame
}

fn zcl_read(tsn: u8) -> Vec<u8> {
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
    out.extend_from_slice(&0x0000u16.to_le_bytes());
    out
}

/// Full MAC+NWK+APS+ZCL data frame (short->short, PAN 0x3761).
fn wrap_full_frame(zcl: &[u8], nwk_seq: u8, aps_ctr: u8, src: u16, dst: u16) -> Vec<u8> {
    let aps = rounddance_aps::frame::DataHeader {
        control: rounddance_aps::frame::FrameControl::data(
            rounddance_aps::frame::DeliveryMode::Unicast,
        ),
        dest: rounddance_aps::frame::DataDest::Unicast { dst_endpoint: 1 },
        cluster_id: 0x0006,
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

#[test]
fn session_v2_round_trips_nonempty_timelines() {
    use rounddance_inspect::pcap::Packet;
    // Join request -> accept -> application data through the packet
    // leg (synthetic frames, repo codecs, no captures needed).
    let frames = [
        mac_cmd(0x01, &[0x8c], 0x1234, 0xffff, 0x10),
        mac_cmd(0x02, &[0x34, 0x12, 0x00], 0x0000, 0x1234, 0x11),
        wrap_full_frame(&zcl_read(0x42), 0x01, 0x01, 0x1234, 0x0000),
    ];
    let packets: Vec<Packet> = frames
        .iter()
        .enumerate()
        .map(|(i, f)| Packet {
            ts_us: (i as u64 + 1) * 1000,
            linktype: rounddance_inspect::pcap::LINKTYPE_IEEE802_15_4,
            data: f.clone(),
        })
        .collect();
    let lease = lease_id_for_run("w1-offline", "timeline", 25, 0);
    let rep = run::run_packets(&packets, 25, &KeySlots::new(), "timeline", lease);
    assert_eq!(rep.frames.len(), 3);
    assert_eq!(rep.dissect_errors, 0);

    // The session timeline links the three frames; stages advance
    // Joining -> Joined -> Active with no anomaly flags.
    let tl = rep
        .engine
        .timeline(0x3761, 0x1234)
        .expect("session timeline");
    assert_eq!(tl.stage, rounddance_inspect::session::TimelineStage::Active);
    assert_eq!(tl.anomalies, 0);
    assert_eq!(tl.events(), 3);

    // Exact timeline-table shape inside v2.
    let v2 = report::session_to_json_v2(&rep.engine);
    assert!(v2.contains("\"timelines\":[{\"pan\":14177,\"short\":4660,\"ieee\":null,\"stage\":\"active\",\"left\":false,\"events\":3,\"anomalies\":0,\"flags\":[],\"log\":[{\"ev\":1,\"tree\":1},{\"ev\":2,\"tree\":2},{\"ev\":7,\"tree\":3}]}]"), "{v2}");

    // v2 save/load restores devices, networks, sec, and timelines —
    // a re-render is byte-identical, and the v1 projection matches
    // the direct v1 rendering exactly.
    let back = report::session_v2_from_json(&v2).expect("v2 loads");
    assert_eq!(report::session_to_json_v2(&back), v2);
    assert_eq!(
        report::session_to_json(&back),
        report::session_to_json(&rep.engine)
    );
    let back_tl = back.timeline(0x3761, 0x1234).expect("restored timeline");
    assert_eq!(
        back_tl.stage,
        rounddance_inspect::session::TimelineStage::Active
    );
    assert_eq!(back_tl.log[0], Some((1, 1)));
    assert_eq!(back_tl.log[2], Some((7, 3)));
}
