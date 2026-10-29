//! Host-side sniffer ingest (`std` only): the lab nRF 802.15.4
//! sniffer's shell feed parsed into the inspector's
//! [`Listener`](crate::capture::Listener) seam.
//!
//! The sniffer speaks a line protocol over 115200 8N1 serial: after
//! `channel N` + `receive` it prints one line per received frame,
//! `received: <hex> power: <rssi> lqi: <lqi> time: <us>` (note the
//! space after `received:`), hex carrying the 2-octet FCS at the
//! end. [`parse_received`] implements exactly that line shape (FCS
//! stripped, frame copied into the caller buffer by the listener);
//! the raw termios serial driver lives in the `inspect-live` binary
//! (crate-level `#![forbid(unsafe_code)]` keeps `unsafe` out of this
//! module), while [`ReplayListener`] replays saved `sniff_*.txt`
//! captures through the same parser for deterministic re-runs.
//!
//! Conformance rule: any backend change must keep live and replay
//! byte-identical (same parser, same accounting) — replay a saved
//! feed and `diff` the per-frame log, depth histogram, and session
//! text against the live run.
//!
//! RSSI note: the parser passes the sniffer's reading through
//! unchanged (honest capture); validity is a downstream concern —
//! see [`crate::capture::Captured::rssi`]. Positive readings are
//! unphysical sniffer-side quirks (bogus power on short background
//! frames) and file as unknown past the seam.

use crate::capture::{Captured, Listener};
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Parse one sniffer `received:` line: returns the FCS-stripped frame
/// bytes plus the raw `(rssi, lqi)` readings. Non-frame shell lines
/// yield `None` (callers skip them, never surfacing them as frames
/// or errors). Short (< 5-octet) or odd-length hex yields `None`.
pub fn parse_received(line: &str) -> Option<(Vec<u8>, i8, u8)> {
    let rx = line.find("received:")?;
    let hex: String = line[rx + "received:".len()..]
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    if hex.len() < 10 || !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut raw = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        raw.push(u8::from_str_radix(&hex[i..i + 2], 16).ok()?);
    }
    if raw.len() < 5 {
        return None;
    }
    // Strip the trailing 2-octet FCS: the inspector dissects MAC
    // header onward without it.
    raw.truncate(raw.len() - 2);
    let rssi: i8 = line
        .find("power:")
        .and_then(|p| {
            line[p + "power:".len()..]
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .unwrap_or(0);
    let lqi: u8 = line
        .find("lqi:")
        .and_then(|p| {
            line[p + "lqi:".len()..]
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .unwrap_or(0);
    Some((raw, rssi, lqi))
}

/// Offline replay backend over a saved `sniff_*.txt` capture: feeds
/// the same [`parse_received`] lines a live sniffer would, so replay
/// runs exercise the identical listener path.
pub struct ReplayListener {
    lines: std::vec::IntoIter<String>,
    channel: u8,
}

impl ReplayListener {
    /// Load every line of the saved feed; the channel labels the
    /// capture (the text feed carries no channel of its own).
    pub fn open(path: &str, channel: u8) -> Result<Self, String> {
        let f = File::open(path).map_err(|e| format!("open {path}: {e}"))?;
        let lines: Vec<String> = BufReader::new(f).lines().map_while(Result::ok).collect();
        Ok(Self {
            lines: lines.into_iter(),
            channel,
        })
    }
}

impl Listener for ReplayListener {
    type Error = String;
    fn next_frame<'b>(&mut self, buf: &'b mut [u8]) -> Result<Option<Captured<'b>>, Self::Error> {
        for line in self.lines.by_ref() {
            if let Some((raw, rssi, lqi)) = parse_received(&line) {
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
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_live_line_shape_with_fcs_strip() {
        // Live shape incl. the space after `received:`; the `120041`
        // ack rides with a 2-octet FCS (`9a7b`) that must go.
        let (raw, rssi, lqi) =
            parse_received("received: 1200419a7b power: -104 lqi: 255 time: 12345").unwrap();
        assert_eq!(raw, vec![0x12, 0x00, 0x41]);
        assert_eq!(rssi, -104);
        assert_eq!(lqi, 255);
    }

    #[test]
    fn bogus_positive_power_passes_through_raw() {
        // Parser honesty: the +111 quirk on beacon-req noise is
        // passed through; the tree/session file it as unknown.
        let (raw, rssi, lqi) =
            parse_received("received: 030816ffffffff07ffff power: 111 lqi: 120 time: 7").unwrap();
        assert_eq!(raw.len(), 8);
        assert_eq!(rssi, 111);
        assert_eq!(lqi, 120);
    }

    #[test]
    fn non_frame_and_short_lines_are_none() {
        assert!(parse_received("sleep").is_none());
        assert!(parse_received("channel 25").is_none());
        assert!(parse_received("received: 12 power: -90 lqi: 200 time: 1").is_none());
        assert!(parse_received("received: 123 power: -90 lqi: 200 time: 1").is_none());
        assert!(parse_received("no marker here").is_none());
    }
}
