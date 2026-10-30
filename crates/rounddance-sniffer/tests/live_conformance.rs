//! W2 (RD-SNIFF live): front-end conformance + channel gate.
//!
//! Offline (no hardware): the live [`NrfListener`] leg over an
//! in-memory fake port agrees byte-for-byte with the replay path's
//! shared [`parse_received`] parser on verbatim w82 wire lines, and
//! a radio-header pcap replays to byte-identical text/JSON reports
//! ([`run_radio_packets`]). The binary's live usage errors need no
//! hardware either (`--live` without `--port` is a usage error; a
//! missing port fails fast without hanging).
//!
//! Live (needs `RD_SNIFF_LIVE_PORT`; the binary acquires its own
//! per-run arbitrator lease — do NOT pre-reserve the port, an outer
//! lease would contend and the run would refuse): `live_capture_matches_its_radio_file` captures N seconds
//! of air with the shipped `rd-sniff --live` binary, then replays
//! the run's radio pcap through the offline leg and asserts
//! byte-identical reports. Empty air passes structurally (0 frames
//! is a completed run; equality holds trivially) — the test never
//! asserts specific frame counts.

use rounddance_inspect::capture::Listener;
use rounddance_inspect::keys::KeySlots;
use rounddance_inspect::sniffer::parse_received;
use rounddance_sniffer::lease::lease_id_for_run;
use rounddance_sniffer::live::{check_channel, FrontEnd, NrfListener};
use rounddance_sniffer::run;
use std::collections::VecDeque;
use std::io::{self, Read, Write};

/// Verbatim w82 subset (see `tests/ota_vectors.rs` for provenance):
/// beacon-req (quirk) + MG21 beacon + sealed NWK + MAC-secured +
/// ch20 beacon-req, with shell noise and a short line the parser
/// must skip. Framed exactly as the serial feed carries them.
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

/// In-memory serial stand-in: reads from `rx`, appends writes to
/// `tx`. Empty `rx` reads `Ok(0)` (idle tick, like a VTIME expiry).
struct FakePort {
    rx: VecDeque<u8>,
    tx: Vec<u8>,
}

impl FakePort {
    fn feed(bytes: &[u8]) -> Self {
        Self {
            rx: bytes.iter().copied().collect(),
            tx: Vec::new(),
        }
    }
}

impl Read for FakePort {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match self.rx.pop_front() {
            Some(b) => {
                buf[0] = b;
                Ok(1)
            }
            None => Ok(0),
        }
    }
}

impl Write for FakePort {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn wire_bytes() -> Vec<u8> {
    let mut v = Vec::new();
    for l in LINES {
        v.extend_from_slice(l.as_bytes());
        v.extend_from_slice(b"\r\n");
    }
    v
}

#[test]
fn channel_gate_admits_only_11_to_26() {
    for bad in [0u8, 1, 10, 27, 255] {
        assert!(check_channel(bad).is_err(), "{bad}");
        assert!(
            NrfListener::<FakePort>::open(FakePort::feed(&[]), bad).is_err(),
            "{bad}"
        );
    }
    for good in [11u8, 20, 25, 26] {
        assert_eq!(check_channel(good), Ok(good));
    }
    // `set_channel` gates the same way on a live listener.
    let mut li = NrfListener::open(FakePort::feed(&[]), 25).unwrap();
    assert!(li.set_channel(10).is_err());
    assert!(li.set_channel(27).is_err());
    li.set_channel(20).expect("reseeds");
    assert_eq!(li.channel(), 20);
}

#[test]
fn live_wire_parser_matches_replay_parser() {
    // Live leg: `NrfListener` over the fake port, byte-wise like
    // serial (the handshake writes land in `tx`, reads drain `rx`).
    let mut li = NrfListener::open(FakePort::feed(&wire_bytes()), 25).unwrap();
    let mut buf = [0u8; 256];
    let mut live_frames = Vec::new();
    while let Some(c) = li.next_frame(&mut buf).unwrap() {
        live_frames.push((c.payload.to_vec(), c.rssi, c.lqi, c.channel));
    }
    drop(li);
    // Replay leg: the shared line parser over the same lines.
    let mut replay_frames = Vec::new();
    for l in LINES {
        if let Some((raw, rssi, lqi)) = parse_received(l) {
            replay_frames.push((raw, rssi, lqi, 25u8));
        }
    }
    assert_eq!(live_frames.len(), 5, "5 frame lines, 3 skipped");
    assert_eq!(live_frames, replay_frames, "live == replay byte-for-byte");
}

#[test]
fn radio_file_replay_is_report_identical() {
    let dir = std::env::temp_dir();
    let path = dir.join("w2-live-radio-feed.txt");
    let mut text = String::new();
    for l in LINES {
        text.push_str(l);
        text.push('\n');
    }
    std::fs::write(&path, text).unwrap();
    let keys = KeySlots::new();
    let worker = "w2-live";
    let tag = "w2radio";
    let lease = lease_id_for_run(worker, tag, 25, 0);

    let mut li =
        rounddance_inspect::sniffer::ReplayListener::open(path.to_str().unwrap(), 25).unwrap();
    let live_shaped = run::run_listener(&mut li, 25, &keys, tag, lease);
    std::fs::remove_file(&path).unwrap();
    assert_eq!(live_shaped.frames.len(), 5);
    assert_eq!(live_shaped.dissect_errors, 0);

    // The live run's file form: radio-header pcap out, read back in.
    let mut raw_radio = Vec::new();
    run::write_pcap_radio(&live_shaped, &mut raw_radio).unwrap();
    let radio = run::read_pcap_radio(&mut &raw_radio[..]).unwrap();
    assert_eq!(radio.len(), 5);
    let replayed = run::run_radio_packets(&radio, 25, &keys, tag, lease);
    assert_eq!(
        run::text_report(&replayed),
        run::text_report(&live_shaped),
        "live == file: text reports byte-identical"
    );
    assert_eq!(
        run::json_report(&replayed),
        run::json_report(&live_shaped),
        "live == file: JSON reports byte-identical"
    );
    // Radio bytes survive the file round trip, quirks included.
    for (r, f) in radio.iter().zip(live_shaped.frames.iter()) {
        assert_eq!((r.channel, r.rssi, r.lqi), (f.channel, f.rssi, f.lqi));
        assert_eq!((r.ts_us, &r.data), (f.ts_us, &f.data));
    }
}

#[test]
fn live_usage_errors_need_no_hardware() {
    let bin = env!("CARGO_BIN_EXE_rd-sniff");
    // `--live` without `--port` is a usage error (exit 2), no
    // hardware touched.
    let out = std::process::Command::new(bin)
        .args(["--live", "--channel", "25", "--secs", "1"])
        .output()
        .expect("run rd-sniff");
    assert_eq!(out.status.code(), Some(2));
    // A channel outside 11..=26 is a usage error before any open.
    let out = std::process::Command::new(bin)
        .args([
            "--live",
            "--port",
            "/nonexistent-tty-sniff",
            "--channel",
            "10",
            "--secs",
            "1",
        ])
        .output()
        .expect("run rd-sniff");
    assert_eq!(out.status.code(), Some(2));
    // A missing port fails fast (exit 1), never hangs: `open`
    // rejects a nonexistent path immediately.
    let out = std::process::Command::new(bin)
        .args([
            "--live",
            "--port",
            "/nonexistent-tty-sniff",
            "--channel",
            "25",
            "--secs",
            "1",
            "--tag",
            "noport",
            "--out",
            &std::env::temp_dir()
                .join("rd-sniff-noport")
                .to_string_lossy(),
        ])
        .output()
        .expect("run rd-sniff");
    assert_eq!(out.status.code(), Some(1));
}

/// Live conformance: capture air with the shipped binary, replay the
/// run's radio pcap, assert byte-identical reports.
///
/// Needs `RD_SNIFF_LIVE_PORT` (the binary acquires its own per-run
/// lease — do NOT pre-reserve the port); without it the test skips.
/// Knobs: `RD_SNIFF_LIVE_CHANNEL`
/// (default 25), `RD_SNIFF_LIVE_SECS` (default 20),
/// `RD_SNIFF_LIVE_TAG` (default `liveconf`),
/// `RD_SNIFF_LIVE_WORKER` (default `sniff-w2`). Empty air passes
/// structurally: 0 frames is a completed run, and the replay
/// equality holds trivially.
#[test]
fn live_capture_matches_its_radio_file() {
    let port = match std::env::var("RD_SNIFF_LIVE_PORT") {
        Ok(p) if !p.trim().is_empty() => p,
        _ => {
            eprintln!("SKIP live_capture_matches_its_radio_file: set RD_SNIFF_LIVE_PORT");
            return;
        }
    };
    let channel: u8 = std::env::var("RD_SNIFF_LIVE_CHANNEL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(25);
    let secs: u64 = std::env::var("RD_SNIFF_LIVE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let tag = std::env::var("RD_SNIFF_LIVE_TAG").unwrap_or_else(|_| String::from("liveconf"));
    let worker = std::env::var("RD_SNIFF_LIVE_WORKER").unwrap_or_else(|_| String::from("sniff-w2"));
    check_channel(channel).expect("live channel in 11..=26");

    let dir = std::env::temp_dir().join(format!("rd-sniff-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bin = env!("CARGO_BIN_EXE_rd-sniff");
    let out = std::process::Command::new(bin)
        .args([
            "--live",
            "--port",
            &port,
            "--channel",
            &channel.to_string(),
            "--secs",
            &secs.to_string(),
            "--tag",
            &tag,
            "--worker",
            &worker,
            "--out",
            &dir.to_string_lossy(),
        ])
        .output()
        .expect("run rd-sniff --live");
    assert!(
        out.status.success(),
        "live run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("frames="), "{stdout}");

    let text = std::fs::read_to_string(dir.join(format!("{tag}.report.txt"))).unwrap();
    let json = std::fs::read_to_string(dir.join(format!("{tag}.report.json"))).unwrap();
    let raw_radio = std::fs::read(dir.join(format!("{tag}.radio.pcap"))).unwrap();

    // Replay the run's radio file with the same tag/lease/keys.
    let radio = run::read_pcap_radio(&mut &raw_radio[..]).unwrap();
    let keys = KeySlots::new();
    let lease = lease_id_for_run(&worker, &tag, channel, 0);
    let replayed = run::run_radio_packets(&radio, channel, &keys, &tag, lease);
    assert_eq!(
        run::text_report(&replayed),
        text,
        "live == file: text reports byte-identical"
    );
    assert_eq!(
        run::json_report(&replayed),
        json,
        "live == file: JSON reports byte-identical"
    );

    // Structural asserts only (empty-air tolerant): frame counts
    // agree, every captured frame carries the requested channel, and
    // a non-empty run folds a non-empty session.
    assert_eq!(replayed.frames.len(), radio.len());
    for f in &replayed.frames {
        assert_eq!(f.channel, channel);
    }
    if replayed.frames.is_empty() {
        eprintln!("live air was empty (0 frames): conformance holds trivially");
    } else {
        assert!(json.contains("\"trees\":"), "{json}");
    }
    std::fs::remove_dir_all(&dir).unwrap_or(());
}
