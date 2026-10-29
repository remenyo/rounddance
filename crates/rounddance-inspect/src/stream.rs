//! Streaming byte-pipe ingest: live sniffer bytes into the session engine.
//!
//! A live sniffer is a byte pipe, not a line printer: bytes arrive in
//! arbitrary chunks, shell noise interleaves, and lines split
//! mid-frame. [`Framer`] reassembles `received:` wire lines from
//! arbitrary pushes with bounded buffering and resync-on-noise (an
//! overlong burst is dropped at its terminator and counted, never
//! fed downstream). [`parse_line`] decodes one wire line into frame
//! bytes without allocating, with the exact field semantics of the
//! shared [`sniffer`](crate::sniffer) line parser (FCS stripped,
//! missing radio fields defaulting to zero). [`Ingest`] folds framed
//! lines through the dissect legs plus [`SessionEngine`](crate::session::SessionEngine)
//! incrementally, so a session snapshot after any frame matches the
//! line-at-a-time batch replay exactly.
//!
//! The whole module is `no_std` + `#![forbid(unsafe_code)]` with no
//! allocator: every buffer is caller-owned or fixed-size.

use crate::chain;
use crate::keys::KeySlots;
use crate::session::SessionEngine;
use crate::tree::{DecodeTree, TreeError};

/// Longest wire line the framer buffers. Live sniffer lines peak near
/// 250 octets (a full 127-octet frame in hex plus the `received:` /
/// power / lqi / time wrapping), so 512 leaves better than 2x headroom.
pub const LINE_CAP: usize = 512;

/// Byte-pipe line framer: arbitrary pushes in, newline-terminated
/// wire lines out. A line that outgrows the buffer arms the
/// overlong latch; bytes (including the offending line) are dropped
/// until the next newline resyncs, counting exactly one drop. A lone
/// trailing `\r` is stripped at pop; a tail without its newline is
/// held, never emitted.
#[derive(Clone, Debug)]
pub struct Framer {
    buf: [u8; LINE_CAP],
    len: usize,
    overlong: bool,
    /// Complete lines delivered so far.
    pub lines: u32,
    /// Lines dropped: overlong bursts at resync, plus lines wider
    /// than a `pop_line` caller scratch (size it at [`LINE_CAP`]).
    pub dropped: u32,
}

impl Default for Framer {
    fn default() -> Self {
        Self::new()
    }
}

impl Framer {
    /// Empty framer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0u8; LINE_CAP],
            len: 0,
            overlong: false,
            lines: 0,
            dropped: 0,
        }
    }

    /// Push arbitrary pipe bytes into the buffer. Backpressure sheds:
    /// when a push would overflow the buffer, only the straddling
    /// (newest, incomplete) line is shed — already-framed lines stay
    /// queued — and the shed line is counted in [`Framer::dropped`]
    /// at its terminator. Under the intended discipline (drain after
    /// every small read) nothing legit is ever shed: live lines peak
    /// near 250 octets against 512 of buffer.
    pub fn push(&mut self, chunk: &[u8]) {
        for &b in chunk {
            if self.overlong {
                // Draining past the shed line: its newline resyncs.
                if b == b'\n' {
                    self.overlong = false;
                    self.dropped = self.dropped.saturating_add(1);
                }
                continue;
            }
            if self.len < LINE_CAP {
                // The newline stays in-buffer as the readiness mark
                // `pop_line` scans for.
                self.buf[self.len] = b;
                self.len += 1;
                continue;
            }
            // Buffer full: shed the straddling line back to its
            // start (the last readiness mark), keeping framed lines.
            match self.buf[..self.len].iter().rposition(|&x| x == b'\n') {
                Some(at) => self.len = at + 1,
                None => self.len = 0,
            }
            if b == b'\n' {
                // The shed line just terminated: resync is done.
                self.dropped = self.dropped.saturating_add(1);
            } else {
                // The shed line continues: discard to its terminator.
                self.overlong = true;
            }
        }
    }

    /// Pop the oldest complete wire line into `out` (without its
    /// terminator), returning its length — or `None` when no newline
    /// has arrived yet. The copy keeps the borrow checker (and the
    /// `forbid(unsafe_code)` core) out of the picture; lines are
    /// short and the copy is bounded. A line wider than `out` is
    /// dropped and counted (size `out` at [`LINE_CAP`] for lossless
    /// framing).
    pub fn pop_line(&mut self, out: &mut [u8]) -> Option<usize> {
        let at = self.buf[..self.len].iter().position(|&b| b == b'\n')?;
        let mut end = at;
        if end > 0 && self.buf[end - 1] == b'\r' {
            end -= 1;
        }
        if end > out.len() {
            // Caller scratch too small: drop the line, keep framing.
            let rest = self.len - (at + 1);
            self.buf.copy_within(at + 1.., 0);
            self.len = rest;
            self.dropped = self.dropped.saturating_add(1);
            return self.pop_line(out);
        }
        out[..end].copy_from_slice(&self.buf[..end]);
        let rest = self.len - (at + 1);
        self.buf.copy_within(at + 1.., 0);
        self.len = rest;
        self.lines = self.lines.saturating_add(1);
        Some(end)
    }
}

/// One parsed sniffer wire line: frame bytes (FCS already stripped)
/// live in the caller's scratch at `out[..len]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineFrame {
    /// Frame octets in the caller buffer (FCS stripped).
    pub len: usize,
    /// Raw power reading (positive values stay quirks downstream).
    pub rssi: i8,
    /// Link quality indicator.
    pub lqi: u8,
}

/// Outcome of decoding one wire line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parse {
    /// Not a frame line (shell noise, empty, short/odd hex): skip.
    Skip,
    /// Frame hex larger than the caller scratch: needs `need` octets.
    TooLong {
        /// Frame octets the line carries (FCS stripped).
        need: usize,
    },
    /// A frame line decoded into the caller scratch.
    Frame(LineFrame),
}

/// Decode one sniffer wire line into `out` without allocating.
///
/// Field semantics match the shared [`sniffer`](crate::sniffer) line
/// parser exactly: the first `received:` marker opens a hex run
/// (whitespace-skipped, hex digits only) that must carry at least 5
/// octets at an even length, with the trailing 2-octet FCS stripped;
/// `power:` / `lqi:` default to zero when absent or unparsable.
pub fn parse_line(line: &[u8], out: &mut [u8]) -> Parse {
    const MARKER: &[u8] = b"received:";
    let start = match find_marker(line, MARKER) {
        Some(i) => i + MARKER.len(),
        None => return Parse::Skip,
    };
    let mut hex = &line[start..];
    // Skip leading whitespace like the shared parser.
    while hex.first().is_some_and(|b| is_space(*b)) {
        hex = &hex[1..];
    }
    let mut nibbles = 0usize;
    while hex.get(nibbles).is_some_and(|b| b.is_ascii_hexdigit()) {
        nibbles += 1;
    }
    if nibbles < 10 || !nibbles.is_multiple_of(2) {
        return Parse::Skip;
    }
    let need = nibbles / 2 - 2;
    if need > out.len() {
        return Parse::TooLong { need };
    }
    if need < 3 {
        // Fewer than 5 on-air octets once the FCS goes (need + 2).
        return Parse::Skip;
    }
    let mut i = 0;
    while i < nibbles {
        let hi = unhex(hex[i]);
        let lo = unhex(hex[i + 1]);
        if i / 2 < need {
            out[i / 2] = hi << 4 | lo;
        }
        i += 2;
    }
    Parse::Frame(LineFrame {
        len: need,
        rssi: parse_field(line, b"power:").unwrap_or(0),
        lqi: parse_field(line, b"lqi:").unwrap_or(0),
    })
}

/// One incremental ingest step produced by [`Ingest::next_step`].
///
/// The `Frame` leg carries the dissected tree by value: the core is
/// `no_std` without an allocator, so the tree cannot ride behind a
/// pointer — the enum stays stack-sized like every tree handoff.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug)]
pub enum Step {
    /// A non-frame wire line consumed (shell noise, empty line):
    /// the session is untouched.
    Ignored,
    /// A frame line wider than the caller scratch: counted and
    /// skipped, like a listener error on the replay path.
    Oversize {
        /// Frame octets the line carries.
        need: usize,
    },
    /// A frame line dissected (or refused) and, on success, folded
    /// into the session engine with its radio metadata attached.
    Frame {
        /// Parsed line metadata.
        meta: LineFrame,
        /// Dissection outcome (`Err` on a MAC-level refusal, exactly
        /// as [`chain::dissect`] reports it).
        outcome: Result<DecodeTree, TreeError>,
    },
}

/// Streaming ingest: a byte pipe feeding the dissect legs and one
/// session engine incrementally. Push arbitrary chunks, drain steps;
/// after any [`Step::Frame`] the caller's session snapshot matches
/// the line-at-a-time batch replay over the same bytes exactly.
#[derive(Clone, Debug)]
pub struct Ingest {
    framer: Framer,
    line: [u8; LINE_CAP],
    channel: u8,
    /// Frame lines dissected (successes and refusals alike).
    pub frames: u32,
    /// MAC-level dissect refusals.
    pub dissect_errors: u32,
    /// Non-frame lines consumed.
    pub ignored: u32,
    /// Oversize frame lines skipped.
    pub oversize: u32,
}

impl Ingest {
    /// Empty ingest tagging folded trees with `channel`.
    #[must_use]
    pub const fn new(channel: u8) -> Self {
        Self {
            framer: Framer::new(),
            line: [0u8; LINE_CAP],
            channel,
            frames: 0,
            dissect_errors: 0,
            ignored: 0,
            oversize: 0,
        }
    }

    /// Push arbitrary pipe bytes into the framer.
    pub fn push(&mut self, chunk: &[u8]) {
        self.framer.push(chunk);
    }

    /// The underlying framer (line/drop accounting).
    #[must_use]
    pub const fn framer(&self) -> &Framer {
        &self.framer
    }

    /// Drain one ingest step: the next complete wire line is parsed,
    /// dissected against `keys`, and on success folded into `eng`
    /// with its radio metadata attached. Returns `None` when no
    /// complete line is pending.
    pub fn next_step(
        &mut self,
        eng: &mut SessionEngine,
        keys: &KeySlots,
        frame: &mut [u8],
    ) -> Option<Step> {
        let n = self.framer.pop_line(&mut self.line)?;
        let parsed = parse_line(&self.line[..n], frame);
        match parsed {
            Parse::Skip => {
                self.ignored = self.ignored.saturating_add(1);
                Some(Step::Ignored)
            }
            Parse::TooLong { need } => {
                self.oversize = self.oversize.saturating_add(1);
                Some(Step::Oversize { need })
            }
            Parse::Frame(meta) => {
                self.frames = self.frames.saturating_add(1);
                let payload = frame.get(..meta.len).unwrap_or(&[]);
                // The tree borrows nothing: dissect, attach radio,
                // and fold before the scratch is reused.
                let outcome = chain::dissect_with_keys(payload, keys);
                match outcome {
                    Ok(mut tree) => {
                        tree.set_radio(self.channel, meta.rssi, meta.lqi);
                        eng.note_tree(&tree);
                        Some(Step::Frame {
                            meta,
                            outcome: Ok(tree),
                        })
                    }
                    Err(e) => {
                        self.dissect_errors = self.dissect_errors.saturating_add(1);
                        Some(Step::Frame {
                            meta,
                            outcome: Err(e),
                        })
                    }
                }
            }
        }
    }
}

/// First occurrence of `needle` in `haystack` (byte-wise).
fn find_marker(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| haystack[i..].starts_with(needle))
}

const fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0c)
}

fn unhex(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Parse the whitespace-separated integer token after `marker`
/// (`power:` → `i8`, `lqi:` → `u8` via the saturating-fallback
/// wrappers below): absent marker, empty token, or any malformed
/// token yields `None` and the caller defaults to zero — exactly the
/// shared parser's `unwrap_or(0)`.
fn parse_field<T>(line: &[u8], marker: &[u8]) -> Option<T>
where
    T: ParseInt,
{
    let at = find_marker(line, marker)? + marker.len();
    let mut rest = &line[at..];
    while rest.first().is_some_and(|b| is_space(*b)) {
        rest = &rest[1..];
    }
    let mut n = 0;
    while rest.get(n).is_some_and(|b| !is_space(*b)) {
        n += 1;
    }
    T::parse(&rest[..n])
}

/// Integer token shapes the radio fields accept.
trait ParseInt: Sized {
    fn parse(token: &[u8]) -> Option<Self>;
}

impl ParseInt for i8 {
    fn parse(token: &[u8]) -> Option<Self> {
        let (neg, digits) = match token.first() {
            Some(b'+') => (false, &token[1..]),
            Some(b'-') => (true, &token[1..]),
            Some(_) => (false, token),
            None => return None,
        };
        if digits.is_empty() || !digits.iter().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut v: i16 = 0;
        for &b in digits {
            v = v.checked_mul(10)?.checked_add(i16::from(b - b'0'))?;
        }
        if neg {
            v = -v;
        }
        i8::try_from(v).ok()
    }
}

impl ParseInt for u8 {
    fn parse(token: &[u8]) -> Option<Self> {
        let digits = match token.first() {
            Some(b'+') => &token[1..],
            Some(_) => token,
            None => return None,
        };
        if digits.is_empty() || !digits.iter().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut v: u16 = 0;
        for &b in digits {
            v = v.checked_mul(10)?.checked_add(u16::from(b - b'0'))?;
        }
        u8::try_from(v).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wire_line_shape() {
        let mut scratch = [0u8; 256];
        let meta = match parse_line(
            b"\x1b[Jreceived: 1200419a7b power: -104 lqi: 255 time: 1",
            &mut scratch,
        ) {
            Parse::Frame(m) => m,
            other => panic!("expected frame, got {other:?}"),
        };
        assert_eq!(&scratch[..meta.len], &[0x12, 0x00, 0x41]);
        assert_eq!((meta.rssi, meta.lqi), (-104, 255));
    }

    #[test]
    fn framer_lines_and_resync() {
        let mut f = Framer::new();
        let mut scratch = [0u8; LINE_CAP];
        f.push(b"ab\r\ncd");
        assert_eq!(f.pop_line(&mut scratch), Some(2));
        assert_eq!(&scratch[..2], b"ab");
        assert_eq!(f.pop_line(&mut scratch), None);
        f.push(b"ef\r\n");
        assert_eq!(f.pop_line(&mut scratch), Some(4));
        assert_eq!(&scratch[..4], b"cdef");
        // Overlong: dropped once at the terminator.
        f.push(&[b'X'; LINE_CAP + 40]);
        f.push(b"\nnext\r\n");
        assert_eq!(f.dropped, 1);
        assert_eq!(f.pop_line(&mut scratch), Some(4));
        assert_eq!(&scratch[..4], b"next");
    }

    #[test]
    fn overflow_sheds_only_the_straddling_line() {
        let mut f = Framer::new();
        let mut scratch = [0u8; LINE_CAP];
        // Four framed lines, then a tail that overflows the buffer:
        // the framed lines survive, only the tail is shed.
        f.push(b"one\ntwo\nthree\nfour\n");
        f.push(&[b'Y'; LINE_CAP]);
        f.push(b"tail-continued\nfive\n");
        assert_eq!(f.dropped, 1);
        let mut got = Vec::new();
        while let Some(n) = f.pop_line(&mut scratch) {
            got.push(scratch[..n].to_vec());
        }
        assert_eq!(
            got,
            vec![
                b"one".to_vec(),
                b"two".to_vec(),
                b"three".to_vec(),
                b"four".to_vec(),
                b"five".to_vec()
            ]
        );
    }

    #[test]
    fn int_tokens_match_shared_parser_edges() {
        // Out-of-range, signed, and malformed tokens all fall back.
        assert_eq!(parse_field::<i8>(b"power: 999", b"power:"), None);
        assert_eq!(parse_field::<i8>(b"power: -129", b"power:"), None);
        assert_eq!(parse_field::<i8>(b"power: +12", b"power:"), Some(12));
        assert_eq!(parse_field::<u8>(b"lqi: 256", b"lqi:"), None);
        assert_eq!(parse_field::<u8>(b"lqi: -1", b"lqi:"), None);
        assert_eq!(parse_field::<u8>(b"lqi: 0", b"lqi:"), Some(0));
        assert_eq!(parse_field::<i8>(b"power:", b"power:"), None);
        assert_eq!(parse_field::<i8>(b"nop", b"power:"), None);
    }
}
