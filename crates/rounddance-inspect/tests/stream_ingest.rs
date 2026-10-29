//! Wave-65 lane 2 (RD-INSPECT-39..40): live-stream ingest goldens.
//!
//! The inspector so far only replays saved feeds line-at-a-time
//! (`ReplayListener`): no byte-pipe ingest exists that a running
//! sniffer can feed in arbitrary chunks. These tests are the
//! failing-first repros: they name the `stream` module API
//! (resyncing byte framer, no-alloc line parser, incremental
//! session ingest) that does not exist yet.
//!
//! Provenance: the line bodies below are verbatim `received:` lines
//! (hex + radio metadata only) from the wave-50 live run
//! (`~/hwscratch/w50/sniff_c25.txt`, channel 25: beacon-request
//! noise with the positive-RSSI quirk, TC beacons, one
//! NWK-secured frame sealed under the lab key, and two
//! Touchlink scan-req/scan-rsp pairs). The wire framing (the
//! sniffer's `\x1b[J` prefix and the `\r\n` terminator) wraps them
//! in-test exactly as the serial feed carries it. No key material
//! anywhere: the sealed frame stays sealed (orphan leg), and the
//! one frame that opens is sealed in-test under a synthetic
//! test-only key, never a lab key.

use rounddance_inspect::stream::{Framer, Ingest, Parse, Step};
use rounddance_inspect::{chain, report, session, stream};

// Verbatim `received:` line bodies (c25 line numbers in comments).
const BODIES: &[&str] = &[
    // c25:1 beacon-request noise, bogus positive power quirk.
    "received: 03081fffffffff071e00 power: 111 lqi: 120 time: 154787879918",
    // c25:2 TC beacon.
    "received: 0080af61370000ff4f00000022841694b10911403a09ffffff004700 power: -104 lqi: 255 time: 154787989365",
    // c25:3 beacon-request noise.
    "received: 030826ffffffff071800 power: 106 lqi: 96 time: 154789500688",
    // c25:4 TC beacon.
    "received: 0080b061370000ff4f00000022841694b10911403a09ffffff004700 power: -104 lqi: 255 time: 154789609456",
    // Shell noise interleaved on the live feed: never a frame.
    "sleep",
    // c25:15 NWK-secured frame (lab-key sealed: stays sealed here).
    "received: 4188b66137ffff00000912fcff000001f65f75f4feffe5e304284e9001005f75f4feffe5e30400c1094465067f4701 power: -104 lqi: 255 time: 154795158691",
    // c25:22 Touchlink scan request.
    "received: 018800ffffffffffff687f1921aa3e0005834340 power: -108 lqi: 255 time: 154799420430",
    // c25:23 Touchlink scan response.
    "received: 018800ffffffffffffa4971921aa3e010505831080b12f7688000000000000000000000000ffff00003a65 power: -117 lqi: 232 time: 154799427853",
    // More shell noise.
    "channel 25",
    // c25:25 TC beacon.
    "received: 0080ba61370000ff4f00000022841694b10911403a09ffffff004700 power: -104 lqi: 255 time: 154799618331",
    // c25:26/27 second scan-req/scan-rsp pair (transaction +1).
    "received: 018801ffffffffffff687f1921aa3e0005834340 power: -108 lqi: 255 time: 154799721740",
    "received: 018801ffffffffffffa4971921aa3e010505831080b12f7688000000000000000000000000ffff00003965 power: -117 lqi: 228 time: 154799725213",
    // c25:28/29 third pair.
    "received: 018802ffffffffffff687f1921aa3e0005834340 power: -108 lqi: 255 time: 154800025761",
    "received: 018802ffffffffffffa4971921aa3e010505831080b12f7688000000000000000000000000ffff00003a65 power: -117 lqi: 232 time: 154800030529",
];

/// Wire bytes for the bodies: the sniffer's `\x1b[J` line prefix and
/// the `\r\n` terminator wrap every line exactly as the serial feed
/// carries them.
fn wire_bytes() -> Vec<u8> {
    let mut v = Vec::new();
    for b in BODIES {
        v.extend_from_slice(b"\x1b[J");
        v.extend_from_slice(b.as_bytes());
        v.extend_from_slice(b"\r\n");
    }
    v
}

// ---------------------------------------------------------------------------
// RD-INSPECT-39 repro: no streaming byte-pipe framer exists.
// ---------------------------------------------------------------------------

#[test]
fn repro_no_streaming_framer() {
    let mut f = Framer::new();
    f.push(b"\x1b[Jreceived: 1200419a7b power: -104 lqi: 255 time: 1\r\n");
    let mut scratch = [0u8; 512];
    let n = f.pop_line(&mut scratch).expect("one complete wire line");
    assert!(scratch[..n].windows(9).any(|w| w == b"received:"));
    assert!(f.pop_line(&mut scratch).is_none());
}

#[test]
fn framer_reassembles_split_lines_identically() {
    let wire = wire_bytes();
    // Baseline: drained chunks within the buffer discipline reassemble
    // every line losslessly (a bulk push with no drain would shed by
    // design — covered below — so the baseline drains as it goes).
    let whole = {
        let mut f = Framer::new();
        let mut out = Vec::new();
        for piece in wire.chunks(200) {
            f.push(piece);
            out.extend(drain_lines(&mut f));
        }
        assert!(f.dropped == 0);
        out
    };
    assert_eq!(whole.len(), BODIES.len());
    // Byte-at-a-time feed reassembles the identical line sequence.
    let mut f = Framer::new();
    let mut bytewise = Vec::new();
    for b in &wire {
        f.push(std::slice::from_ref(b));
        bytewise.extend(drain_lines(&mut f));
    }
    assert_eq!(bytewise, whole);
    // Drained chunks of every smaller size split every line
    // boundary shape alike (each push stays within the drain
    // discipline, so nothing is shed).
    for chunk in [2usize, 3, 5, 7, 13, 64, 200] {
        let mut f = Framer::new();
        let mut lines = Vec::new();
        for piece in wire.chunks(chunk) {
            f.push(piece);
            lines.extend(drain_lines(&mut f));
        }
        assert_eq!(lines, whole, "chunk {chunk}");
    }
    // An undrained bulk push sheds only straddling lines, and every
    // pushed line is accounted: delivered or dropped, never lost.
    let mut f = Framer::new();
    f.push(&wire);
    f.push(&wire);
    let got = drain_lines(&mut f).len();
    assert_eq!(got + f.dropped as usize, 2 * BODIES.len());
    assert!(got > 0, "framed lines survive the shed");
    assert!(f.dropped > 0, "bulk overflow sheds the straddlers");
}

fn drain_lines(f: &mut Framer) -> Vec<Vec<u8>> {
    let mut scratch = [0u8; 512];
    let mut out = Vec::new();
    while let Some(n) = f.pop_line(&mut scratch) {
        out.push(scratch[..n].to_vec());
    }
    out
}

#[test]
fn framer_strips_cr_and_holds_partial_tails() {
    let mut f = Framer::new();
    let mut scratch = [0u8; 512];
    f.push(b"received: 1200419a7b power: 0 lqi: 0 time: 1\r");
    assert!(
        f.pop_line(&mut scratch).is_none(),
        "no newline yet: tail held"
    );
    f.push(b"\nreceived: 1200429a7b power: 0 lqi: 0 time: 2\r\n");
    let n = f.pop_line(&mut scratch).expect("completed line");
    assert!(!scratch[..n].ends_with(b"\r"), "CR stripped");
    assert!(scratch[..n].starts_with(b"received:"));
    assert!(f.pop_line(&mut scratch).is_some());
    assert!(f.pop_line(&mut scratch).is_none());
    // A bare terminator still delivers an (empty, skippable) line.
    let mut g = Framer::new();
    g.push(b"\r\n");
    assert_eq!(g.pop_line(&mut scratch), Some(0));
}

#[test]
fn framer_resyncs_after_overlong_noise() {
    let mut f = Framer::new();
    // 600 noise bytes with no newline: past the bounded buffer, so
    // the framer drops through to the next terminator and resyncs.
    let mut scratch = [0u8; 512];
    let mut noise = vec![b'A'; 600];
    noise.extend_from_slice(b"\r\n");
    f.push(&noise);
    assert_eq!(f.dropped, 1);
    f.push(b"\x1b[Jreceived: 1200419a7b power: -104 lqi: 255 time: 1\r\n");
    let n = f.pop_line(&mut scratch).expect("resynced line");
    assert!(scratch[..n].windows(9).any(|w| w == b"received:"));
    assert_eq!(f.dropped, 1, "good line is never a drop");
    // Overlong spans split across pushes still count exactly once.
    let mut g = Framer::new();
    g.push(&vec![b'B'; 400]);
    assert_eq!(g.dropped, 0, "no terminator yet: nothing decided");
    assert!(g.pop_line(&mut scratch).is_none());
    g.push(&vec![b'B'; 400]);
    g.push(b"\n");
    assert_eq!(g.dropped, 1);
}

// ---------------------------------------------------------------------------
// RD-INSPECT-39: no-alloc line parser matches the shared parser.
// ---------------------------------------------------------------------------

#[test]
fn line_parser_matches_shared_parser_on_recorded_lines() {
    use rounddance_inspect::sniffer::parse_received;
    let mut scratch = [0u8; 256];
    for b in BODIES {
        let wire = format!("\x1b[J{b}\r");
        let from_shared = parse_received(&wire);
        let parsed = stream::parse_line(wire.as_bytes(), &mut scratch);
        match from_shared {
            Some((raw, rssi, lqi)) => {
                // FCS already stripped by both: the ack vector pins it.
                let meta = assert_frame(parsed);
                assert_eq!(&scratch[..meta.len], raw.as_slice(), "{b}");
                assert_eq!(meta.rssi, rssi, "{b}");
                assert_eq!(meta.lqi, lqi, "{b}");
            }
            None => assert_eq!(parsed, Parse::Skip, "{b}"),
        }
    }
    // The live ack shape: the 2-octet FCS goes, never dissected.
    let meta = assert_frame(stream::parse_line(
        b"\x1b[Jreceived: 1200419a7b power: -104 lqi: 255 time: 1",
        &mut scratch,
    ));
    assert_eq!(&scratch[..meta.len], &[0x12, 0x00, 0x41]);
    assert_eq!((meta.rssi, meta.lqi), (-104, 255));
    // Shell noise and short/odd hex never frame.
    for junk in [
        "sleep".as_bytes(),
        "channel 25".as_bytes(),
        "".as_bytes(),
        b"received: 12 power: -90 lqi: 200 time: 1",
        b"received: 123 power: -90 lqi: 200 time: 1",
        b"no marker here",
    ] {
        assert_eq!(stream::parse_line(junk, &mut scratch), Parse::Skip);
    }
    // Missing radio fields default exactly like the shared parser.
    let meta = assert_frame(stream::parse_line(b"received: 1200419a7b", &mut scratch));
    assert_eq!((meta.rssi, meta.lqi), (0, 0));
    // A frame hex larger than the scratch is TooLong, never silent.
    let mut big = b"received: ".to_vec();
    big.extend_from_slice(&vec![b'a'; 600]);
    assert!(matches!(
        stream::parse_line(&big, &mut scratch),
        Parse::TooLong { .. }
    ));
}

fn assert_frame(p: Parse) -> stream::LineFrame {
    match p {
        Parse::Frame(m) => m,
        other => panic!("expected a frame, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// RD-INSPECT-40 repro: no incremental session ingest exists.
// ---------------------------------------------------------------------------

/// Synthetic test-only key: seals the round-trip frame below and
/// nothing else. Never a lab key.
const TEST_KEY: [u8; 16] = [0x77u8; 16];
const TEST_SEQ: u8 = 0;
const TEST_EXT: [u8; 8] = [0x5f, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04];
const TEST_CTR: u32 = 0x0000_4004;

/// Test-local integrity seal (mirror of the decryptor's open): only
/// feeds the keyed leg below.
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

/// One full MAC + secured-NWK + APS-data + ZCL-read frame sealed
/// under the synthetic test key, rendered as a sniffer line (the
/// trailing `0000` stands in for the sniffer FCS the parser strips).
fn sealed_line() -> String {
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
    frame.extend_from_slice(&[0x00, 0x00]); // sniffer-FCS stand-in
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(frame.len() * 2);
    for b in &frame {
        hex.push(H[(b >> 4) as usize] as char);
        hex.push(H[(b & 15) as usize] as char);
    }
    format!("received: {hex} power: -90 lqi: 200 time: 99")
}

/// Snapshot the full session state: any ingest-path divergence shows
/// here (device/network tables, secured accounting, timelines).
fn snapshot(eng: &session::SessionEngine) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        report::session_to_text(eng),
        report::session_to_json(eng),
        report::timelines_to_text(eng),
        report::timelines_to_json(eng),
    )
}

fn slotted() -> session::SessionEngine {
    let mut eng = session::SessionEngine::new();
    eng.set_network_key(TEST_KEY, TEST_SEQ);
    eng
}

#[test]
fn repro_no_incremental_session_ingest() {
    // A byte pipe fed in arbitrary chunks folds framed lines into
    // the session engine; a snapshot after any frame matches the
    // line-at-a-time batch replay exactly.
    let mut eng = slotted();
    let keys = *eng.keys();
    let mut ingest = Ingest::new(25);
    let wire = wire_bytes();
    for piece in wire.chunks(7) {
        ingest.push(piece);
        let mut scratch = [0u8; 256];
        while let Some(step) = ingest.next_step(&mut eng, &keys, &mut scratch) {
            assert!(!matches!(step, Step::Oversize { .. }));
        }
    }
    assert!(eng.trees > 0);
}

/// Streaming ingest over the recorded c25 excerpt plus the sealed
/// keyed leg proves byte-identical timelines vs batch replay: same
/// trees in the same order, same snapshot after every frame.
#[test]
fn stream_ingest_matches_batch_frame_for_frame() {
    use rounddance_inspect::sniffer::parse_received;
    let sealed = sealed_line();
    let mut bodies: Vec<String> = BODIES.iter().map(|s| s.to_string()).collect();
    bodies.push(sealed);
    let mut wire = Vec::new();
    for b in &bodies {
        wire.extend_from_slice(b"\x1b[J");
        wire.extend_from_slice(b.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }

    // Batch arm: line-at-a-time through the shared parser.
    let keys = slotted();
    let mut batch_eng = slotted();
    let mut batch_trees = Vec::new();
    let mut batch_snaps = Vec::new();
    for b in &bodies {
        let rendered = format!("\x1b[J{b}\r");
        if let Some((raw, rssi, lqi)) = parse_received(&rendered) {
            let mut t = chain::dissect_with_keys(&raw, keys.keys()).unwrap();
            t.set_radio(25, rssi, lqi);
            batch_eng.note_tree(&t);
            batch_trees.push(t);
            batch_snaps.push(snapshot(&batch_eng));
        }
    }
    assert!(!batch_trees.is_empty());

    // Stream arm: arbitrary byte chunks through the ingest path
    // (drained after every push, so nothing is shed).
    for chunks in [
        [1usize, 7, 64, 200],
        [7usize, 7, 7, 7],
        [3usize, 5, 13, 129],
    ] {
        let mut eng = slotted();
        let mut ingest = Ingest::new(25);
        let mut trees = Vec::new();
        let mut snaps = Vec::new();
        let mut off = 0;
        let mut ci = 0;
        let mut scratch = [0u8; 256];
        while off < wire.len() {
            let n = chunks[ci % chunks.len()].min(wire.len() - off);
            ingest.push(&wire[off..off + n]);
            off += n;
            ci += 1;
            while let Some(step) = ingest.next_step(&mut eng, keys.keys(), &mut scratch) {
                match step {
                    Step::Frame { outcome, .. } => {
                        trees.push(outcome.unwrap());
                        snaps.push(snapshot(&eng));
                    }
                    Step::Ignored => {}
                    Step::Oversize { .. } => panic!("recorded stream never oversizes"),
                }
            }
        }
        assert_eq!(trees, batch_trees, "chunk schedule {chunks:?}");
        assert_eq!(snaps, batch_snaps, "chunk schedule {chunks:?}");
        // The recorded excerpt exercises every stop class plus the
        // keyed legs: the synthetic sealed frame verifies open (one
        // `decrypted` leg), and the lab-sealed frame counts
        // decryptable-offline too — a slot is loaded for its domain,
        // exactly the `engine_key_slots_gate_decryptability`
        // semantics — with zero orphans on either arm.
        assert_eq!(eng.secured_decryptable, 2);
        assert_eq!(eng.secured_orphan, 0);
        assert_eq!(eng.trees, batch_eng.trees);
    }
}

/// Noise around the recorded stream never reaches the session: shell
/// lines are ignored, an overlong burst resyncs, and a held tail
/// delivers once completed.
#[test]
fn stream_ingest_isolates_noise_from_the_session() {
    let keys = slotted();
    let mut eng = slotted();
    let mut ingest = Ingest::new(25);
    let mut scratch = [0u8; 256];
    let mut frames = 0;
    // Shell noise plus a bare line: ignored, never folded.
    ingest.push(b"shell echo off\r\nchannel 25\r\n\r\n");
    while let Some(step) = ingest.next_step(&mut eng, keys.keys(), &mut scratch) {
        assert!(matches!(step, Step::Ignored));
    }
    assert_eq!(eng.trees, 0);
    // An overlong burst: dropped at resync, session untouched.
    let mut burst = vec![b'Z'; 700];
    burst.extend_from_slice(b"\r\n");
    ingest.push(&burst);
    assert!(ingest
        .next_step(&mut eng, keys.keys(), &mut scratch)
        .is_none());
    assert_eq!(ingest.framer().dropped, 1);
    assert_eq!(eng.trees, 0);
    // A frame split across the noise: held tail, then one fold.
    ingest.push(b"\x1b[Jreceived: 1200419a7b power: -104 lqi: 255");
    assert!(ingest
        .next_step(&mut eng, keys.keys(), &mut scratch)
        .is_none());
    ingest.push(b" time: 1\r\n");
    while let Some(step) = ingest.next_step(&mut eng, keys.keys(), &mut scratch) {
        if let Step::Frame { outcome, .. } = step {
            outcome.unwrap();
            frames += 1;
        }
    }
    assert_eq!(frames, 1);
    assert_eq!(eng.trees, 1);
}
