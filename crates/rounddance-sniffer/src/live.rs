//! Live nRF 802.15.4 front-end (wave 2): serial sniffer → [`Listener`].
//!
//! Reference [`FrontEnd`] productized from the `inspect-live` binary's
//! `NrfListener` (`rounddance-inspect/src/bin/inspect-live.rs`): the
//! lab nRF sniffer firmware speaks a line protocol over 115200 8N1
//! serial, and this module frames that byte stream with the streaming
//! [`Framer`](rounddance_inspect::stream::Framer) pipe and decodes
//! lines with [`parse_line`](rounddance_inspect::stream::parse_line) —
//! the exact field semantics of the replay path's shared
//! [`parse_received`](rounddance_inspect::sniffer::parse_received)
//! parser (FCS stripped, missing radio fields defaulting to zero).
//! Live and replay therefore stay byte-identical by construction, and
//! the live == file invariant is pinned by test, never assumed.
//!
//! Discipline (structural, not procedural):
//!
//! * RX-only by design: the only serial writes are shell text lines
//!   (`sleep`, `shell echo off`, `channel N`, `receive`). The sniffer
//!   firmware exposes no TX API on this path, so passive capture is a
//!   property of the code, never of operator care.
//! * Channel gate: [`check_channel`] admits only 11..=26, checked
//!   before any port write in both [`NrfListener::open`] and
//!   [`set_channel`](FrontEnd::set_channel).
//! * [`Drop`] parks the hardware: the listener sends `sleep` on drop
//!   (errors ignored — teardown never panics), like the reference.
//! * Lease discipline: capture runs stamp the same per-run worker
//!   lease IDs as offline runs
//!   ([`lease_id_for_run`](crate::lease::lease_id_for_run)); the
//!   arbitrator port lease itself stays an operator step (no
//!   arbitrator calls from this crate).
//!
//! Portability: this module is `std`-gated (host side) and
//! `#![forbid(unsafe_code)]`-clean — it is generic over any
//! [`Read`](std::io::Read) + [`Write`](std::io::Write) port. The raw
//! termios serial driver (which needs `unsafe`) lives in the
//! `rd-sniff` binary, mirroring the `inspect-live` split; unit tests
//! drive the listener over an in-memory fake port.
//!
//! Wave 4 seam: [`FrontEnd`] is the trait an ESP promiscuous backend
//! would implement; nothing here assumes nRF beyond the shell lines.

use rounddance_inspect::capture::{Captured, Listener};
use rounddance_inspect::stream::{parse_line, Framer, LineFrame, Parse, LINE_CAP};
use std::io::{self, Read, Write};
use std::time::Duration;

/// Admit only 802.15.4 channels 11..=26, before any port write.
pub fn check_channel(channel: u8) -> Result<u8, String> {
    if (11..=26).contains(&channel) {
        Ok(channel)
    } else {
        Err(format!("channel must be 11..=26, got {channel}"))
    }
}

/// Live capture front-end: the [`Listener`] seam plus lifecycle.
///
/// `open` runs the shell handshake on an already-open port;
/// [`set_channel`](FrontEnd::set_channel) reseeds the sniffer;
/// [`Drop`] parks the hardware back to sleep.
pub trait FrontEnd: Listener<Error = String> {
    /// Already-open byte port (serial handle, pipe, or test fake).
    type Port: Read + Write;
    /// Run the shell handshake (`sleep` / `shell echo off` /
    /// `channel N` / `receive`) on `port`. The channel gate runs
    /// first: a bad channel fails before any port write.
    fn open(port: Self::Port, channel: u8) -> Result<Self, String>
    where
        Self: Sized;
    /// Reseed the sniffer to `channel` (gated 11..=26) and resume
    /// receiving. The only writes are shell text lines — never
    /// transmits.
    fn set_channel(&mut self, channel: u8) -> Result<(), String>;
}

/// Live nRF-sniffer backend over a generic byte port.
///
/// Frames the port's byte stream with [`Framer`] and decodes lines
/// with [`parse_line`] (same field semantics as the replay path).
/// `Ok(None)` from [`next_frame`](Listener::next_frame) is an idle
/// tick with no complete line yet — a held tail is never emitted —
/// exactly the framer discipline the streaming ingest tests pin.
pub struct NrfListener<P: Write> {
    port: P,
    channel: u8,
    framer: Framer,
    line: [u8; LINE_CAP],
    /// Last staged frame bytes (parsed from `line`, FCS stripped).
    /// Staging keeps the caller buffer out of the poll loop: port
    /// pumping and line parsing never borrow it, so the single copy
    /// out happens once a frame is certain.
    staged: [u8; 256],
}

impl<P: Read + Write> NrfListener<P> {
    /// Run the shell handshake on `port` (channel gated first).
    pub fn open(port: P, channel: u8) -> Result<Self, String> {
        let channel = check_channel(channel)?;
        let mut li = Self {
            port,
            channel,
            framer: Framer::new(),
            line: [0u8; LINE_CAP],
            staged: [0u8; 256],
        };
        // Settle delays mirror the proven `inspect-live` handshake
        // (USB CDC needs them; the shell echoes nothing after
        // `shell echo off`, and any stray bytes are skipped by the
        // line parser, never framed).
        std::thread::sleep(Duration::from_millis(500));
        for cmd in ["sleep\n", "shell echo off\n"] {
            li.port
                .write_all(cmd.as_bytes())
                .map_err(|e| format!("sniffer handshake: {e}"))?;
            std::thread::sleep(Duration::from_millis(300));
        }
        li.set_channel(channel)?;
        Ok(li)
    }

    /// 802.15.4 channel the sniffer is seeded to.
    #[must_use]
    pub fn channel(&self) -> u8 {
        self.channel
    }

    /// Pop one already-framed line without touching the port:
    /// `Ok(None)` when no complete line is buffered. The live loop
    /// drains this after its deadline so framed-but-unpolled lines
    /// are folded, not dropped.
    pub fn pop_ready<'b>(&mut self, buf: &'b mut [u8]) -> Result<Option<Captured<'b>>, String> {
        match self.stage_frame()? {
            None => Ok(None),
            Some(m) => Ok(Some(self.emit_staged(buf, m)?)),
        }
    }

    /// Parse buffered framer lines into [`Self::staged`], skipping
    /// shell noise: `Ok(None)` when no complete line is buffered.
    /// Never touches the port or the caller buffer, so poll loops
    /// can stage without borrowing either.
    fn stage_frame(&mut self) -> Result<Option<LineFrame>, String> {
        loop {
            let n = match self.framer.pop_line(&mut self.line) {
                Some(n) => n,
                None => return Ok(None),
            };
            // Copy the line out of the framer scratch before parsing
            // (both borrows are disjoint).
            let mut wire = [0u8; LINE_CAP];
            wire[..n].copy_from_slice(&self.line[..n]);
            // Wire lines are at most `LINE_CAP` octets, so a frame
            // (half the hex run at most, minus FCS) always fits the
            // 256-octet staging area; anything wider is a listener
            // error, never silent loss.
            match parse_line(&wire[..n], &mut self.staged) {
                Parse::Frame(m) => return Ok(Some(m)),
                Parse::TooLong { need } => {
                    return Err(format!("frame {need}B > staged 256B"));
                }
                // Non-frame shell line: keep draining.
                Parse::Skip => {}
            }
        }
    }

    /// Copy the staged frame into the caller buffer. Single borrow
    /// of `buf`: a short caller scratch is a listener error, exactly
    /// like the replay path's oversize accounting.
    fn emit_staged<'b>(&self, buf: &'b mut [u8], m: LineFrame) -> Result<Captured<'b>, String> {
        if m.len > buf.len() {
            return Err(format!("frame {}B > buf {}B", m.len, buf.len()));
        }
        buf[..m.len].copy_from_slice(&self.staged[..m.len]);
        Ok(Captured {
            channel: self.channel,
            rssi: m.rssi,
            lqi: m.lqi,
            payload: &buf[..m.len],
        })
    }
}

impl<P: Read + Write> FrontEnd for NrfListener<P> {
    type Port = P;

    fn open(port: Self::Port, channel: u8) -> Result<Self, String>
    where
        Self: Sized,
    {
        NrfListener::open(port, channel)
    }

    fn set_channel(&mut self, channel: u8) -> Result<(), String> {
        let channel = check_channel(channel)?;
        self.port
            .write_all(format!("channel {channel}\n").as_bytes())
            .map_err(|e| format!("sniffer set_channel: {e}"))?;
        std::thread::sleep(Duration::from_millis(300));
        self.port
            .write_all(b"receive\n")
            .map_err(|e| format!("sniffer receive: {e}"))?;
        self.channel = channel;
        Ok(())
    }
}

impl<P: Read + Write> Listener for NrfListener<P> {
    type Error = String;

    fn next_frame<'b>(&mut self, buf: &'b mut [u8]) -> Result<Option<Captured<'b>>, Self::Error> {
        // Pump the port until a frame is staged (or the port idles):
        // staging never borrows the caller buffer, so the loop can
        // poll freely; the single copy out happens below.
        let meta = loop {
            if let Some(m) = self.stage_frame()? {
                break m;
            }
            let mut one = [0u8; 1];
            match self.port.read(&mut one) {
                Ok(0) => return Ok(None), // Idle tick: no data right now.
                Ok(_) => self.framer.push(&one),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(e) => return Err(format!("serial read: {e}")),
            }
        };
        Ok(Some(self.emit_staged(buf, meta)?))
    }
}

impl<P: Write> Drop for NrfListener<P> {
    fn drop(&mut self) {
        // Park the hardware: teardown never fails and never panics.
        let _ = self.port.write_all(b"sleep\n");
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// In-memory serial stand-in: reads from `rx`, appends writes to
    /// `tx`. Empty `rx` reads `Ok(0)` (idle tick, like a VTIME
    /// expiry on the real port).
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

    /// Shared-ownership serial stand-in: lets tests read `tx` after
    /// the listener (and its port) has been dropped.
    struct SharedPort {
        rx: VecDeque<u8>,
        tx: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl SharedPort {
        fn fresh() -> (Self, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
            let tx = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                Self {
                    rx: VecDeque::new(),
                    tx: std::sync::Arc::clone(&tx),
                },
                tx,
            )
        }
    }

    impl Read for SharedPort {
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

    impl Write for SharedPort {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.tx.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn channel_gate_rejects_before_touching_port() {
        for bad in [0u8, 10, 27, 255] {
            assert!(check_channel(bad).is_err());
            // A bad channel fails before any port write.
            let (port, tx) = SharedPort::fresh();
            let err = NrfListener::open(port, bad).err().expect("gated");
            assert!(err.contains("11..=26"), "{err}");
            assert!(tx.lock().unwrap().is_empty(), "no write before gate");
        }
        assert_eq!(check_channel(11), Ok(11));
        assert_eq!(check_channel(26), Ok(26));
        // `set_channel` on a live listener gates the same way (needs
        // a valid open first; the drop below parks the fake).
        let mut li = NrfListener::open(FakePort::feed(&[]), 25).unwrap();
        let before = li.channel();
        assert!(li.set_channel(10).is_err());
        assert_eq!(li.channel(), before);
    }

    #[test]
    fn open_handshake_writes_shell_sequence() {
        let port = FakePort::feed(&[]);
        let li = NrfListener::open(port, 25).unwrap();
        assert_eq!(li.channel(), 25);
        // Handshake bytes are shell text only — never frame bytes.
        let tx = li.port.tx.clone();
        assert_eq!(tx, b"sleep\nshell echo off\nchannel 25\nreceive\n");
    }

    #[test]
    fn set_channel_reseeds_and_resumes_receive() {
        let mut li = NrfListener::open(FakePort::feed(&[]), 25).unwrap();
        li.set_channel(20).unwrap();
        assert_eq!(li.channel(), 20);
        assert!(li.port.tx.ends_with(b"channel 20\nreceive\n"));
    }

    #[test]
    fn drop_parks_hardware_with_sleep() {
        // The sleep line must be the last write, after the
        // handshake bytes.
        let (port, tx) = SharedPort::fresh();
        {
            let _li = NrfListener::open(port, 25).unwrap();
        }
        let tx = tx.lock().unwrap();
        assert!(tx.starts_with(b"sleep\nshell echo off\n"), "{tx:?}");
        assert!(tx.ends_with(b"sleep\n"), "{tx:?}");
    }

    #[test]
    fn next_frame_delivers_received_lines_and_skips_noise() {
        // Verbatim w82 ch25 line 1 (beacon-req with the positive
        // power quirk) plus shell noise, fed byte-wise like serial.
        let wire = b"\x1b[Jreceived: 0308adffffffff071600 power: 103 lqi: 88 time: 5167374343\r\nsleep\r\n";
        let mut li = NrfListener::open(FakePort::feed(wire), 25).unwrap();
        let mut buf = [0u8; 256];
        let c = li.next_frame(&mut buf).unwrap().expect("one frame");
        assert_eq!(c.channel, 25);
        assert_eq!(c.rssi, 103);
        assert_eq!(c.lqi, 88);
        assert_eq!(c.payload, &[0x03, 0x08, 0xad, 0xff, 0xff, 0xff, 0xff, 0x07]);
        // Cross-check against the replay path's shared parser: the
        // live leg and the replay leg agree on the same line.
        let line = "\u{1b}[Jreceived: 0308adffffffff071600 power: 103 lqi: 88 time: 5167374343";
        let (raw, rssi, lqi) =
            rounddance_inspect::sniffer::parse_received(line).expect("replay parses");
        assert_eq!(raw, c.payload);
        assert_eq!((rssi, lqi), (c.rssi, c.lqi));
        // Noise drains to idle; held tails are never emitted.
        assert!(li.next_frame(&mut buf).unwrap().is_none());
    }
}
