//! Capture hooks: nRF sniffer `decode.py` integration + tcpdump-on-wlan0 stub.
//!
//! The sniffer path shells out to `/tmp/sniffer/decode.py` when present and
//! reports a structured `DecodeScriptMissing` otherwise (stub interface: same
//! types, no silent no-op). The tcpdump path is a stub plan builder —
//! executing it needs sudo on wlan0 and is left to the operator.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default location of the sniffer decode helper (sibling worker's output).
pub const DEFAULT_DECODE_PY: &str = "/tmp/sniffer/decode.py";

/// One 802.15.4 frame parsed from `decode.py --summary` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnifferFrame {
    pub index: usize,
    pub kind: String,
    pub fc: u16,
    pub seq: u8,
    pub len: usize,
    pub rssi: i32,
    pub lqi: u32,
    pub ts: i64,
}

/// Capture-hook errors.
#[derive(Debug)]
pub enum CaptureError {
    DecodeScriptMissing { expected: PathBuf },
    DecodeFailed(String),
    Io(io::Error),
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureError::DecodeScriptMissing { expected } => write!(
                f,
                "decode.py not found at {} (sniffer worker has not produced it yet)",
                expected.display()
            ),
            CaptureError::DecodeFailed(e) => write!(f, "decode.py failed: {e}"),
            CaptureError::Io(e) => write!(f, "capture i/o: {e}"),
        }
    }
}

impl std::error::Error for CaptureError {}

impl From<io::Error> for CaptureError {
    fn from(e: io::Error) -> Self {
        CaptureError::Io(e)
    }
}

/// Parse `decode.py` summary lines:
/// `[3] data fc=0x8841 seq=12 len=27 rssi=-61 lqi=200 t=12345 fcs=abcd psdu=...`
pub fn parse_summary(output: &str) -> Vec<SnifferFrame> {
    let mut frames = Vec::new();
    for line in output.lines() {
        if let Some(fr) = parse_summary_line(line) {
            frames.push(fr);
        }
    }
    frames
}

fn parse_summary_line(line: &str) -> Option<SnifferFrame> {
    // `[<idx>] <kind> fc=<hex> seq=<n> len=<n> rssi=<n> lqi=<n> t=<n> ...`
    let line = line.trim();
    if !line.starts_with('[') {
        return None;
    }
    let end = line.find(']')?;
    let index: usize = line[1..end].parse().ok()?;
    let rest = &line[end + 1..];
    let mut parts = rest.split_whitespace();
    let kind = parts.next()?.to_string();
    let mut fc = None;
    let mut seq = None;
    let mut len = None;
    let mut rssi = None;
    let mut lqi = None;
    let mut ts = None;
    for tok in parts {
        let (k, v) = tok.split_once('=')?;
        match k {
            "fc" => fc = u16::from_str_radix(v.trim_start_matches("0x"), 16).ok(),
            "seq" => seq = v.parse().ok(),
            "len" => len = v.parse().ok(),
            "rssi" => rssi = v.parse().ok(),
            "lqi" => lqi = v.parse().ok(),
            "t" => ts = v.parse().ok(),
            _ => {}
        }
    }
    Some(SnifferFrame {
        index,
        kind,
        fc: fc?,
        seq: seq?,
        len: len?,
        rssi: rssi?,
        lqi: lqi?,
        ts: ts?,
    })
}

/// Decode a raw sniffer capture via `decode.py`.
///
/// Runs `decode.py <capture> --summary` (plus `--pcap <out>` when given)
/// with a timeout and parses the summary into frames. Returns
/// [`CaptureError::DecodeScriptMissing`] when the helper is absent — the
/// stub path: callers record the gap in run evidence instead of failing
/// silently.
pub fn decode_capture(
    capture_bin: &Path,
    decode_py: &Path,
    pcap_out: Option<&Path>,
    timeout: Duration,
) -> Result<Vec<SnifferFrame>, CaptureError> {
    if !decode_py.exists() {
        return Err(CaptureError::DecodeScriptMissing {
            expected: decode_py.to_path_buf(),
        });
    }
    let mut args = vec![
        capture_bin.to_string_lossy().into_owned(),
        "--summary".into(),
    ];
    if let Some(pcap) = pcap_out {
        args.push("--pcap".into());
        args.push(pcap.to_string_lossy().into_owned());
    }
    let plan = crate::flash::ExecPlan {
        program: "python3".into(),
        args: std::iter::once(decode_py.to_string_lossy().into_owned())
            .chain(args)
            .collect(),
        timeout,
        log_path: capture_bin.with_extension("decode.log"),
        description: format!("decode {}", capture_bin.display()),
    };
    let outcome = crate::flash::run_plan(&plan)?;
    if outcome.timed_out {
        return Err(CaptureError::DecodeFailed("decode.py timed out".into()));
    }
    if outcome.exit_code != Some(0) {
        return Err(CaptureError::DecodeFailed(format!(
            "exit {:?}, see {}",
            outcome.exit_code,
            outcome.log_path.display()
        )));
    }
    let body = std::fs::read_to_string(&outcome.log_path)?;
    Ok(parse_summary(&body))
}

/// A planned `tcpdump -i wlan0` capture. STUB: executing 802.15.4-unaware
/// Wi-Fi capture needs sudo + a fixed channel; this builder records intent
/// so the runner can log it as a skipped/deferred stage.
#[derive(Debug, Clone)]
pub struct TcpdumpPlan {
    pub interface: String,
    pub channel: u8,
    pub pcap_out: PathBuf,
    pub duration: Duration,
}

impl TcpdumpPlan {
    pub fn new(channel: u8, pcap_out: &Path, duration: Duration) -> Self {
        Self {
            interface: "wlan0".into(),
            channel,
            pcap_out: pcap_out.to_path_buf(),
            duration,
        }
    }

    /// Render the shell command an operator would run (needs sudo).
    pub fn command_line(&self) -> String {
        format!(
            "sudo-dev tcpdump -i {} -w {} & sleep {}; kill %1",
            self.interface,
            self.pcap_out.display(),
            self.duration.as_secs()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decode_summary_lines() {
        let out =
            "[0] data fc=0x8841 seq=12 len=27 rssi=-61 lqi=200 t=12345 fcs=abcd psdu=4188deff\n\
                   total=1 shown=1\n";
        let frames = parse_summary(out);
        assert_eq!(frames.len(), 1);
        let f = &frames[0];
        assert_eq!(f.kind, "data");
        assert_eq!(f.fc, 0x8841);
        assert_eq!(f.seq, 12);
        assert_eq!(f.rssi, -61);
        assert_eq!(f.ts, 12345);
    }

    #[test]
    fn ignores_non_frame_lines() {
        assert!(parse_summary("total=0 shown=0\nwrote 0 NOFCS frames -> x.pcap\n").is_empty());
    }

    #[test]
    fn missing_decode_script_is_structured_stub() {
        let err = decode_capture(
            Path::new("/tmp/nope.bin"),
            Path::new("/tmp/definitely-not-decode.py"),
            None,
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(
            matches!(err, CaptureError::DecodeScriptMissing { .. }),
            "unexpected: {err}"
        );
    }

    #[test]
    fn tcpdump_plan_renders_sudo_command() {
        let p = TcpdumpPlan::new(15, Path::new("/tmp/x.pcap"), Duration::from_secs(10));
        assert!(p.command_line().contains("wlan0"));
    }
}
