//! `inspect-live`: host-side live listener for `rounddance-inspect`.
//!
//! Wires the lab nRF 802.15.4 sniffer's live serial feed into the
//! inspector's [`Listener`](rounddance_inspect::capture::Listener)
//! seam: [`NrfListener`] opens the sniffer shell port at 115200 8N1
//! raw, sends `sleep` / `shell echo off` / `channel N` / `receive`,
//! and parses each `received:` line with the shared
//! [`sniffer`](rounddance_inspect::sniffer) parser (FCS stripped).
//! Every frame goes through [`chain::dissect`](rounddance_inspect::chain::dissect)
//! plus [`SessionEngine::note_tree`](rounddance_inspect::session::SessionEngine::note_tree)
//! with its radio metadata attached, exactly like the offline
//! harness, with per-frame accounting.
//!
//! The raw termios serial driver lives here — not in the library —
//! because the `rounddance-inspect` core is `#![forbid(unsafe_code)]`.
//! Only `std` plus `libc` are used (the `serialport` crate needs a
//! system libudev this lab box does not carry).
//!
//! Usage:
//! ```text
//! inspect-live --port /dev/ttyACM1 --channel 25 --secs 60 [--tag idle25] [--out DIR]
//! inspect-live --replay sniff_t1.txt --channel 25 [--tag t1] [--out DIR]
//! ```
//!
//! Standard output carries the depth histogram, stop reasons, error
//! table, session text, and spot trees; the per-frame log lands in
//! `<out>/<tag>.frames.log` as
//! `fNNN len= RSSI= LQI= CH= depth stop= hex=`.
//!
//! Conformance: `--replay` over a saved feed must reproduce the live
//! run byte-identically (frames log, histogram, session) — any
//! backend change keeps live == replay or it does not land.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::time::{Duration, Instant};

use rounddance_inspect::capture::{Captured, Listener};
use rounddance_inspect::sniffer::{self, ReplayListener};
use rounddance_inspect::{chain, report, session::SessionEngine, tree::Layer};

/// Minimal raw serial port over `libc` termios (115200 8N1, raw,
/// VTIME-paced reads). `Drop` closes the file descriptor; the
/// listener's `Drop` parks the sniffer back to sleep first.
struct RawSerial {
    fd: std::os::fd::RawFd,
}

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

    fn write_all(&self, data: &[u8]) -> Result<(), String> {
        let mut off = 0;
        while off < data.len() {
            // SAFETY: fd open, slice bounds respected.
            let r = unsafe {
                libc::write(
                    self.fd,
                    data[off..].as_ptr().cast::<libc::c_void>(),
                    data.len() - off,
                )
            };
            if r <= 0 {
                return Err(format!("write: {}", std::io::Error::last_os_error()));
            }
            off += r as usize;
        }
        Ok(())
    }

    /// Read up to one byte; `Ok(None)` = VTIME tick, no data yet.
    fn read_byte(&self) -> Result<Option<u8>, String> {
        let mut b = [0u8; 1];
        // SAFETY: fd open, 1-byte buffer valid.
        let r = unsafe { libc::read(self.fd, b.as_mut_ptr().cast::<libc::c_void>(), 1) };
        if r < 0 {
            return Err(format!("read: {}", std::io::Error::last_os_error()));
        }
        Ok(if r == 1 { Some(b[0]) } else { None })
    }

    fn flush_input(&self) {
        // SAFETY: fd open; flush takes no buffers.
        unsafe {
            libc::tcflush(self.fd, libc::TCIFLUSH);
        }
    }
}

impl Drop for RawSerial {
    fn drop(&mut self) {
        // SAFETY: fd open; every owner closes exactly once.
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Live nRF-sniffer backend implementing the inspector `Listener`
/// trait over the shared [`sniffer::parse_received`] line parser.
struct NrfListener {
    port: RawSerial,
    channel: u8,
    line: String,
}

impl NrfListener {
    fn open(path: &str, channel: u8) -> Result<Self, String> {
        let port = RawSerial::open(path)?;
        std::thread::sleep(Duration::from_millis(500));
        for cmd in ["sleep\n", "shell echo off\n"] {
            port.write_all(cmd.as_bytes())?;
            std::thread::sleep(Duration::from_millis(300));
        }
        port.write_all(format!("channel {channel}\n").as_bytes())?;
        std::thread::sleep(Duration::from_millis(300));
        port.flush_input();
        port.write_all(b"receive\n")?;
        Ok(Self {
            port,
            channel,
            line: String::new(),
        })
    }

    /// Read one line; `Ok(None)` = idle tick with no bytes yet.
    fn read_line(&mut self) -> Result<Option<String>, String> {
        self.line.clear();
        loop {
            match self.port.read_byte()? {
                Some(b) => {
                    if b == b'\n' {
                        return Ok(Some(std::mem::take(&mut self.line)));
                    }
                    self.line.push(b as char);
                    if self.line.len() > 4096 {
                        return Ok(Some(std::mem::take(&mut self.line)));
                    }
                }
                None => {
                    if self.line.is_empty() {
                        return Ok(None);
                    }
                    return Ok(Some(std::mem::take(&mut self.line)));
                }
            }
        }
    }
}

impl Listener for NrfListener {
    type Error = String;
    fn next_frame<'b>(&mut self, buf: &'b mut [u8]) -> Result<Option<Captured<'b>>, Self::Error> {
        loop {
            let line = match self.read_line()? {
                Some(l) => l,
                None => return Ok(None), // timeout tick, no frame now
            };
            if let Some((raw, rssi, lqi)) = sniffer::parse_received(&line) {
                if raw.len() > buf.len() {
                    return Err(format!("frame {}B > buf {}B", raw.len(), buf.len()));
                }
                buf[..raw.len()].copy_from_slice(&raw);
                return Ok(Some(Captured {
                    channel: self.channel,
                    rssi,
                    lqi,
                    payload: &buf[..raw.len()],
                }));
            }
            // Non-frame shell line: keep polling within this call.
        }
    }
}

impl Drop for NrfListener {
    fn drop(&mut self) {
        let _ = self.port.write_all(b"sleep\n");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn depth_key(t: &rounddance_inspect::tree::DecodeTree) -> (String, String) {
    let mut names: Vec<&str> = Vec::new();
    let mut stop = String::from("full");
    for slot in t.layers().iter().flatten() {
        match slot {
            Layer::Mac(_) => names.push("mac"),
            Layer::MacCmd(_) => names.push("maccmd"),
            Layer::Nwk(_) => names.push("nwk"),
            Layer::NwkCmd(_) => names.push("nwkcmd"),
            Layer::Aps(_) => names.push("aps"),
            Layer::Zcl(_) => names.push("zcl"),
            Layer::Zdo(_) => names.push("zdo"),
            Layer::Touchlink(_) => names.push("touchlink"),
            Layer::Gp(_) => names.push("gp"),
            Layer::Hci(_) => names.push("hci"),
            Layer::Att(_) => names.push("att"),
            Layer::Direct(_) => names.push("direct"),
            Layer::Note(n) => {
                names.push("note");
                stop = n.reason.to_string();
            }
        }
    }
    (names.join("+"), stop)
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

fn usage() -> ! {
    eprintln!("usage: inspect-live --port DEV --channel CH --secs S [--tag T] [--out DIR]");
    eprintln!("       inspect-live --replay SNIFF.TXT --channel CH [--tag T] [--out DIR]");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut port: Option<String> = None;
    let mut replay: Option<String> = None;
    let mut channel: u8 = 25;
    let mut secs: u64 = 60;
    let mut tag = String::from("live");
    let mut out = String::from(".");
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                port = Some(args.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--replay" => {
                i += 1;
                replay = Some(args.get(i).cloned().unwrap_or_else(|| usage()));
            }
            "--channel" => {
                i += 1;
                channel = args
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| usage())
                    .parse()
                    .unwrap_or_else(|_| usage());
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
            "--tag" => {
                i += 1;
                tag = args.get(i).cloned().unwrap_or_else(|| usage());
            }
            "--out" => {
                i += 1;
                out = args.get(i).cloned().unwrap_or_else(|| usage());
            }
            _ => usage(),
        }
        i += 1;
    }

    let mut eng = SessionEngine::new();
    let mut depth: BTreeMap<String, u64> = BTreeMap::new();
    let mut stops: BTreeMap<String, u64> = BTreeMap::new();
    let mut errs: BTreeMap<String, u64> = BTreeMap::new();
    let mut shown: BTreeMap<String, String> = BTreeMap::new();
    let mut n: u64 = 0;
    let mut n_err: u64 = 0;
    let mut n_listen_err: u64 = 0;
    let flog = File::create(format!("{out}/{tag}.frames.log")).expect("create frames log");
    let mut flog = std::io::BufWriter::new(flog);
    let mut buf = vec![0u8; 256];

    macro_rules! account {
        ($cap:expr) => {{
            n += 1;
            let c = $cap;
            match chain::dissect(c.payload) {
                Ok(mut t) => {
                    // Thread the listener's radio metadata into the
                    // tree before folding: session rows gain
                    // per-device signal stats (positive-RSSI quirks
                    // file as unknown inside `set_radio`).
                    t.set_radio(c.channel, c.rssi, c.lqi);
                    eng.note_tree(&t);
                    let (key, stop) = depth_key(&t);
                    *depth.entry(key.clone()).or_insert(0) += 1;
                    *stops.entry(stop.clone()).or_insert(0) += 1;
                    if !shown.contains_key(&key) && shown.len() < 12 {
                        shown.insert(key.clone(), report::to_text(&t));
                    }
                    writeln!(
                        flog,
                        "f{} len={} rssi={} lqi={} ch={} {} stop={} {}",
                        n,
                        c.payload.len(),
                        c.rssi,
                        c.lqi,
                        c.channel,
                        key,
                        stop,
                        hex(c.payload)
                    )
                    .unwrap();
                }
                Err(e) => {
                    n_err += 1;
                    let k = format!("{e:?}");
                    *errs.entry(k.clone()).or_insert(0) += 1;
                    writeln!(
                        flog,
                        "f{} len={} rssi={} lqi={} ch={} ERROR {} {}",
                        n,
                        c.payload.len(),
                        c.rssi,
                        c.lqi,
                        c.channel,
                        k,
                        hex(c.payload)
                    )
                    .unwrap();
                }
            }
        }};
    }

    if let Some(rp) = replay {
        let mut li = ReplayListener::open(&rp, channel).unwrap_or_else(|e| {
            eprintln!("replay: {e}");
            std::process::exit(1);
        });
        loop {
            match li.next_frame(&mut buf) {
                Ok(Some(c)) => {
                    account!(c);
                }
                Ok(None) => break,
                Err(e) => {
                    n_listen_err += 1;
                    eprintln!("listener err: {e}");
                }
            }
        }
    } else if let Some(p) = port {
        let mut li = NrfListener::open(&p, channel).unwrap_or_else(|e| {
            eprintln!("sniffer: {e}");
            std::process::exit(1);
        });
        eprintln!("live: {p} ch{channel} {secs}s tag={tag}");
        let t0 = Instant::now();
        let budget = Duration::from_secs(secs);
        while t0.elapsed() < budget {
            match li.next_frame(&mut buf) {
                Ok(Some(c)) => {
                    account!(c);
                }
                Ok(None) => {} // idle tick
                Err(e) => {
                    n_listen_err += 1;
                    eprintln!("listener err: {e}");
                }
            }
        }
    } else {
        usage();
    }
    drop(flog);

    println!("== {tag}: {n} frames, {n_err} dissect errors, {n_listen_err} listener errors");
    println!("-- depth histogram --");
    for (k, v) in &depth {
        println!("  {k:28} {v}");
    }
    println!("-- stop reasons --");
    for (k, v) in &stops {
        println!("  {k:12} {v}");
    }
    if n_err > 0 {
        println!("-- errors --");
        for (k, v) in &errs {
            println!("  {k:20} {v}");
        }
    }
    println!("-- session --");
    println!("{}", report::session_to_text(&eng));
    println!("-- spot trees (first of each depth) --");
    for (k, t) in &shown {
        println!("== {k} ==\n{t}");
    }
}
