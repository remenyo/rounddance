//! `rd-sniff`: 802.15.4 capture → dissect → report + pcap-out.
//!
//! File input: a `.pcap`/`.pcapng` recording (bare 15.4 link types
//! 195/230, or the sniffer radio-header variant 147), or a saved
//! `sniff_*.txt` text feed. Live input (`--live`): the lab nRF
//! sniffer on a serial port, captured passively for `--secs`.
//! Every input goes through the shared dissect + fold legs, and the
//! run lands as a text report, a JSON report (session v2 snapshot
//! with timelines), and two pcap-out files (link type 195 bare
//! frames plus the radio-header variant) next to each other under
//! `--out`.
//!
//! Live discipline (structural): the run is RX-only — the only
//! serial writes are shell text lines (`sleep` / `shell echo off` /
//! `channel N` / `receive`); the listener's `Drop` parks the sniffer
//! back to sleep before any file IO. The port lease itself is an
//! operator step (`lab-arbitrator reserve` on a `/dev/serial/by-id`
//! path); the run stamps the same per-run worker lease ID as
//! offline runs (default worker `w2-live` for live captures).
//! Reproduce a live run from its radio pcap with the same
//! `--channel/--tag/--worker/--lease-seq/--net-key/--key-seq`: the
//! text and JSON reports are byte-identical (live == file).
//!
//! Usage:
//! ```text
//! rd-sniff --in w82ch25.pcap --channel 25 [--tag ch25] [--out DIR]
//!          [--net-key HEX32 --key-seq N] [--worker NAME] [--lease-seq N]
//! rd-sniff --live --port /dev/serial/by-id/... --channel 25 --secs 60
//!          [--tag live25] [--out DIR] [--worker NAME] [--lease-seq N]
//!          [--net-key HEX32 --key-seq N]
//! ```
//!
//! Exit 0 on a completed run (dissect refusals are counted, never
//! fatal — an empty-air capture is a completed run with 0 frames);
//! 1 on IO errors; 2 on usage errors.

use rounddance_inspect::{keys::KeySlots, pcap, sniffer::ReplayListener};
use rounddance_sniffer::{lease::lease_id_for_run, run};
use std::fs::File;
use std::io::{BufWriter, Write};

// ---------------------------------------------------------------------------
// Raw serial port (unix only): 115200 8N1 raw, VTIME-paced reads.
// Mirrors the proven `inspect-live` driver. Every `unsafe` block
// carries a SAFETY note; teardown closes the fd exactly once.
// ---------------------------------------------------------------------------

/// Minimal raw serial port over `libc` termios. `read` returning
/// `Ok(0)` is a VTIME tick with no data yet (idle), not EOF — the
/// caller treats it as an idle tick and keeps polling.
#[cfg(unix)]
struct RawSerial {
    fd: std::os::fd::RawFd,
}

#[cfg(unix)]
impl RawSerial {
    fn open(path: &str) -> Result<Self, String> {
        use std::ffi::CString;
        use std::os::fd::RawFd;
        let c = CString::new(path).map_err(|e| format!("path: {e}"))?;
        // SAFETY: opened with a valid C string; O_NOCTTY keeps the
        // tty detached from our session.
        let fd: RawFd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        if fd < 0 {
            return Err(format!("open {path}: {}", std::io::Error::last_os_error()));
        }
        // SAFETY: `fd` is open; the termios calls below touch only
        // the stack `tio` plus `fd`, and the fd is closed on every
        // error path before returning.
        unsafe {
            let mut tio: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut tio) != 0 {
                libc::close(fd);
                return Err(String::from("tcgetattr failed"));
            }
            libc::cfmakeraw(&mut tio);
            libc::cfsetspeed(&mut tio, libc::B115200);
            tio.c_cc[libc::VMIN] = 0; // VTIME-only read: 1.2 s tick
            tio.c_cc[libc::VTIME] = 12;
            if libc::tcsetattr(fd, libc::TCSANOW, &tio) != 0 {
                libc::close(fd);
                return Err(String::from("tcsetattr failed"));
            }
            libc::tcflush(fd, libc::TCIOFLUSH);
        }
        Ok(Self { fd })
    }
}

#[cfg(unix)]
impl std::io::Read for RawSerial {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // SAFETY: fd open, `buf` valid for `buf.len()` bytes; a
        // single syscall, return value checked.
        let r = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if r < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(r as usize)
        }
    }
}

#[cfg(unix)]
impl std::io::Write for RawSerial {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // SAFETY: fd open, `buf` valid for `buf.len()` bytes; a
        // single syscall, return value checked.
        let r = unsafe { libc::write(self.fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
        if r < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(r as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for RawSerial {
    fn drop(&mut self) {
        // SAFETY: fd open; every owner closes exactly once.
        unsafe {
            libc::close(self.fd);
        }
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn usage() -> ! {
    eprintln!("usage: rd-sniff --in FILE.pcap|FILE.txt --channel CH [--tag TAG] [--out DIR]");
    eprintln!("       [--net-key HEX32 --key-seq N] [--worker NAME] [--lease-seq N]");
    eprintln!("       [--text NAME] [--json NAME] [--pcap195 NAME] [--pcap-radio NAME]");
    eprintln!("       rd-sniff --live --port DEV --channel CH --secs S [--tag TAG] [--out DIR]");
    eprintln!("       [--net-key HEX32 --key-seq N] [--worker NAME] [--lease-seq N]");
    eprintln!("       [--text NAME] [--json NAME] [--pcap195 NAME] [--pcap-radio NAME]");
    std::process::exit(2);
}

fn fail(msg: &str) -> ! {
    eprintln!("rd-sniff: {msg}");
    std::process::exit(1);
}

fn parse_channel(s: &str) -> u8 {
    match s.parse::<u8>() {
        Ok(ch) if (11..=26).contains(&ch) => ch,
        _ => {
            eprintln!("rd-sniff: channel must be 11..=26, got {s:?}");
            std::process::exit(2);
        }
    }
}

fn parse_hex32(s: &str) -> [u8; 16] {
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        eprintln!("rd-sniff: --net-key must be 32 hex chars (16 key octets)");
        std::process::exit(2);
    }
    let mut key = [0u8; 16];
    for (i, k) in key.iter_mut().enumerate() {
        *k = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or_else(|_| usage());
    }
    key
}

fn file_stem(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    match base.rfind('.') {
        Some(i) => String::from(&base[..i]),
        None => String::from(base),
    }
}

fn emit(
    rep: &run::RunReport,
    out: &str,
    text_name: Option<String>,
    json_name: Option<String>,
    pcap195_name: Option<String>,
    pcap_radio_name: Option<String>,
) {
    let text_path = format!(
        "{out}/{}",
        text_name.unwrap_or_else(|| format!("{}.report.txt", rep.tag))
    );
    let json_path = format!(
        "{out}/{}",
        json_name.unwrap_or_else(|| format!("{}.report.json", rep.tag))
    );
    let p195_path = format!(
        "{out}/{}",
        pcap195_name.unwrap_or_else(|| format!("{}.195.pcap", rep.tag))
    );
    let radio_path = format!(
        "{out}/{}",
        pcap_radio_name.unwrap_or_else(|| format!("{}.radio.pcap", rep.tag))
    );

    let mut tf = BufWriter::new(
        File::create(&text_path).unwrap_or_else(|e| fail(&format!("create {text_path}: {e}"))),
    );
    tf.write_all(run::text_report(rep).as_bytes())
        .unwrap_or_else(|e| fail(&format!("write {text_path}: {e}")));
    let mut jf = BufWriter::new(
        File::create(&json_path).unwrap_or_else(|e| fail(&format!("create {json_path}: {e}"))),
    );
    jf.write_all(run::json_report(rep).as_bytes())
        .unwrap_or_else(|e| fail(&format!("write {json_path}: {e}")));
    let mut p195 = BufWriter::new(
        File::create(&p195_path).unwrap_or_else(|e| fail(&format!("create {p195_path}: {e}"))),
    );
    run::write_pcap_195(rep, &mut p195)
        .unwrap_or_else(|e| fail(&format!("write {p195_path}: {e}")));
    let mut prad = BufWriter::new(
        File::create(&radio_path).unwrap_or_else(|e| fail(&format!("create {radio_path}: {e}"))),
    );
    run::write_pcap_radio(rep, &mut prad)
        .unwrap_or_else(|e| fail(&format!("write {radio_path}: {e}")));

    let mut lease_hex = [0u8; 16];
    rounddance_sniffer::lease::lease_id_hex(rep.lease, &mut lease_hex);
    println!(
        "run: lease={} tag={} channel={} frames={} dissect_errors={} listener_errors={}",
        String::from_utf8_lossy(&lease_hex),
        rep.tag,
        rep.channel,
        rep.frames.len(),
        rep.dissect_errors,
        rep.listener_errors,
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut input: Option<String> = None;
    let mut live = false;
    let mut port: Option<String> = None;
    let mut secs: u64 = 60;
    let mut channel: Option<u8> = None;
    let mut tag: Option<String> = None;
    let mut out = String::from(".");
    let mut net_key: Option<[u8; 16]> = None;
    let mut key_seq: u8 = 0;
    let mut worker: Option<String> = None;
    let mut lease_seq: u32 = 0;
    let mut text_name: Option<String> = None;
    let mut json_name: Option<String> = None;
    let mut pcap195_name: Option<String> = None;
    let mut pcap_radio_name: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--in" => {
                i += 1;
                input = Some(args.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--live" => {
                live = true;
            }
            "--port" => {
                i += 1;
                port = Some(args.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--secs" => {
                i += 1;
                secs = args
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| usage())
                    .parse()
                    .unwrap_or_else(|_| usage());
            }
            "--channel" => {
                i += 1;
                channel = Some(parse_channel(
                    &args.get(i).cloned().unwrap_or_else(|| usage()),
                ));
            }
            "--tag" => {
                i += 1;
                tag = Some(args.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--out" => {
                i += 1;
                out = args.get(i).cloned().unwrap_or_else(|| usage());
            }
            "--net-key" => {
                i += 1;
                net_key = Some(parse_hex32(
                    &args.get(i).cloned().unwrap_or_else(|| usage()),
                ));
            }
            "--key-seq" => {
                i += 1;
                key_seq = args
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| usage())
                    .parse()
                    .unwrap_or_else(|_| usage());
            }
            "--worker" => {
                i += 1;
                worker = Some(args.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--lease-seq" => {
                i += 1;
                lease_seq = args
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| usage())
                    .parse()
                    .unwrap_or_else(|_| usage());
            }
            "--text" => {
                i += 1;
                text_name = Some(args.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--json" => {
                i += 1;
                json_name = Some(args.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--pcap195" => {
                i += 1;
                pcap195_name = Some(args.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--pcap-radio" => {
                i += 1;
                pcap_radio_name = Some(args.get(i).cloned().unwrap_or_else(|| usage()));
            }
            _ => usage(),
        }
        i += 1;
    }
    let channel = channel.unwrap_or_else(|| usage());
    let worker = worker.unwrap_or_else(|| {
        if live {
            String::from("w2-live")
        } else {
            String::from("w1-offline")
        }
    });
    let mut keys = KeySlots::new();
    if let Some(k) = net_key {
        keys.set_network_key(k, key_seq);
    }

    if live {
        if input.is_some() {
            eprintln!("rd-sniff: --live takes no --in");
            std::process::exit(2);
        }
        let port_path = port.unwrap_or_else(|| usage());
        let tag = tag.unwrap_or_else(|| format!("live{channel}"));
        let lease = lease_id_for_run(&worker, &tag, channel, lease_seq);
        run_live(
            &port_path,
            channel,
            secs,
            &keys,
            &tag,
            lease,
            &out,
            text_name,
            json_name,
            pcap195_name,
            pcap_radio_name,
        );
        return;
    }

    let input = input.unwrap_or_else(|| usage());
    let tag = tag.unwrap_or_else(|| file_stem(&input));
    let lease = lease_id_for_run(&worker, &tag, channel, lease_seq);

    let rep = if input.ends_with(".pcap") || input.ends_with(".pcapng") {
        let mut f = File::open(&input).unwrap_or_else(|e| fail(&format!("open {input}: {e}")));
        let packets =
            pcap::read_all(&mut f).unwrap_or_else(|e| fail(&format!("ingest {input}: {e:?}")));
        if packets
            .iter()
            .all(|p| p.linktype == rounddance_sniffer::radio::LINKTYPE_SNIFFER_RADIO)
            && !packets.is_empty()
        {
            // Radio-header recording: replay with per-record radio
            // metadata (the live == file conformance path).
            drop(f);
            let mut rf = File::open(&input).unwrap_or_else(|e| fail(&format!("open {input}: {e}")));
            let radio = run::read_pcap_radio(&mut rf)
                .unwrap_or_else(|e| fail(&format!("ingest {input}: {e}")));
            run::run_radio_packets(&radio, channel, &keys, &tag, lease)
        } else {
            if packets
                .iter()
                .any(|p| p.linktype == rounddance_sniffer::radio::LINKTYPE_SNIFFER_RADIO)
            {
                fail(&format!(
                    "ingest {input}: mixed radio-header (147) and bare-frame records — not replayable as one run"
                ));
            }
            let non_154 = packets
                .iter()
                .filter(|p| {
                    p.linktype != pcap::LINKTYPE_IEEE802_15_4
                        && p.linktype != pcap::LINKTYPE_IEEE802_15_4_NOFCS
                })
                .count();
            if non_154 > 0 {
                eprintln!("rd-sniff: note: {non_154} packet(s) with non-15.4 linktype (dissected as 15.4 anyway)");
            }
            run::run_packets(&packets, channel, &keys, &tag, lease)
        }
    } else {
        let mut li = ReplayListener::open(&input, channel)
            .unwrap_or_else(|e| fail(&format!("replay {input}: {e}")));
        run::run_listener(&mut li, channel, &keys, &tag, lease)
    };

    emit(
        &rep,
        &out,
        text_name,
        json_name,
        pcap195_name,
        pcap_radio_name,
    );
}

/// Passive live capture for `secs` seconds, then the shared outputs.
///
/// The time-bounded poll loop folds every frame through the same
/// [`run::RunReport::push_frame`] leg as the offline paths (text
/// feeds carry no timestamps, so live `ts_us` is the 1-based frame
/// ordinal — deterministic across replays). After the deadline the
/// framer is drained without touching the port, the listener is
/// dropped (parks the hardware to sleep), and only then are the
/// output files written.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn run_live(
    port_path: &str,
    channel: u8,
    secs: u64,
    keys: &KeySlots,
    tag: &str,
    lease: u64,
    out: &str,
    text_name: Option<String>,
    json_name: Option<String>,
    pcap195_name: Option<String>,
    pcap_radio_name: Option<String>,
) {
    use rounddance_inspect::capture::Listener;
    use rounddance_sniffer::live::NrfListener;
    use std::time::{Duration, Instant};

    let serial = RawSerial::open(port_path).unwrap_or_else(|e| fail(&e));
    let mut li = NrfListener::open(serial, channel).unwrap_or_else(|e| fail(&e));
    eprintln!("live: {port_path} ch{channel} {secs}s tag={tag}");
    let mut rep = run::RunReport::new(tag, channel, lease, keys);
    let mut buf = [0u8; 256];
    let t0 = Instant::now();
    let budget = Duration::from_secs(secs);
    while t0.elapsed() < budget {
        match li.next_frame(&mut buf) {
            Ok(Some(c)) => {
                let ts_us = rep.frames.len() as u64 + 1;
                rep.push_frame(keys, c.channel, c.rssi, c.lqi, ts_us, c.payload);
            }
            Ok(None) => {} // idle tick
            Err(e) => {
                rep.listener_errors = rep.listener_errors.saturating_add(1);
                eprintln!("listener err: {e}");
            }
        }
    }
    // Drain already-framed lines without touching the port, then park
    // the hardware before any file IO.
    loop {
        match li.pop_ready(&mut buf) {
            Ok(Some(c)) => {
                let ts_us = rep.frames.len() as u64 + 1;
                rep.push_frame(keys, c.channel, c.rssi, c.lqi, ts_us, c.payload);
            }
            Ok(None) => break,
            Err(e) => {
                rep.listener_errors = rep.listener_errors.saturating_add(1);
                eprintln!("listener err: {e}");
            }
        }
    }
    drop(li);
    emit(
        &rep,
        out,
        text_name,
        json_name,
        pcap195_name,
        pcap_radio_name,
    );
}

/// Live capture needs a unix host (raw termios serial driver).
#[cfg(not(unix))]
#[allow(clippy::too_many_arguments)]
fn run_live(
    _port_path: &str,
    _channel: u8,
    _secs: u64,
    _keys: &KeySlots,
    _tag: &str,
    _lease: u64,
    _out: &str,
    _text_name: Option<String>,
    _json_name: Option<String>,
    _pcap195_name: Option<String>,
    _pcap_radio_name: Option<String>,
) {
    eprintln!("rd-sniff: --live needs a unix host");
    std::process::exit(1);
}
