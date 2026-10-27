//! Flash / reset / run helpers: per-chip command builders with timeout + kill.
//!
//! Nothing here executes on import. Builders produce an [`ExecPlan`]
//! (program + argv + timeout) that [`run_plan`] executes with a polling
//! wait, `kill` on timeout, and output tee'd to a per-run log file.
//! Tests assert on builders only — no hardware is touched by tests.

use crate::inventory::Chip;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Per-chip flash profile (from toolchain knowledge, IDF v6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChipProfile {
    /// `idf.py` target name.
    pub idf_target: &'static str,
    /// `esptool --chip` name.
    pub esptool_chip: &'static str,
    /// Default serial baud for flash + monitor.
    pub baud: u32,
    /// Extra notes (e.g. S31 needs `--preview set-target` at build time).
    pub note: &'static str,
}

/// Profile for a chip. Returns `None` for non-flashable nodes
/// (sniffer, Sonoff) — the arbitrator never flashes those.
pub fn profile(chip: Chip) -> Option<ChipProfile> {
    match chip {
        Chip::C6 => Some(ChipProfile {
            idf_target: "esp32c6",
            esptool_chip: "esp32c6",
            baud: 460800,
            note: "Xiao C6 antenna: GPIO3 LOW + GPIO14 LOW (fw keeps).",
        }),
        Chip::H2 => Some(ChipProfile {
            idf_target: "esp32h2",
            esptool_chip: "esp32h2",
            baud: 460800,
            note: "No Wi-Fi; RCP/UART role. SOC_IEEE802154_BLE_ONLY coexistence flag.",
        }),
        Chip::C5 => Some(ChipProfile {
            idf_target: "esp32c5",
            esptool_chip: "esp32c5",
            baud: 460800,
            note: "",
        }),
        Chip::S3 => Some(ChipProfile {
            idf_target: "esp32s3",
            esptool_chip: "esp32s3",
            baud: 460800,
            note: "",
        }),
        Chip::S31 => Some(ChipProfile {
            idf_target: "esp32s31",
            esptool_chip: "esp32s31",
            baud: 921600,
            note: "Build needs `idf.py --preview set-target esp32s31`; erase needs stub (omit --no-stub).",
        }),
        Chip::NordicSniffer | Chip::Sonoff => None,
    }
}

/// What to execute: program + argv + timeout + log path.
#[derive(Debug, Clone)]
pub struct ExecPlan {
    pub program: String,
    pub args: Vec<String>,
    pub timeout: Duration,
    pub log_path: PathBuf,
    pub description: String,
}

impl fmt::Display for ExecPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.program, self.args.join(" "))
    }
}

/// Outcome of [`run_plan`].
#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub timed_out: bool,
    pub exit_code: Option<i32>,
    pub log_path: PathBuf,
}

/// Build an `esptool write_flash` plan for a raw `.bin`.
pub fn esptool_flash_plan(
    chip: Chip,
    port: &str,
    bin: &Path,
    offset: &str,
    log_path: &Path,
    timeout: Duration,
) -> Option<ExecPlan> {
    let p = profile(chip)?;
    Some(ExecPlan {
        program: "esptool".into(),
        args: vec![
            "--chip".into(),
            p.esptool_chip.into(),
            "--port".into(),
            port.into(),
            "--baud".into(),
            p.baud.to_string(),
            "write_flash".into(),
            offset.into(),
            bin.to_string_lossy().into_owned(),
        ],
        timeout,
        log_path: log_path.to_path_buf(),
        description: format!("esptool flash {chip} on {port}"),
    })
}

/// Build an `idf.py -p <port> flash` plan for a project dir.
pub fn idf_flash_plan(
    project_dir: &Path,
    port: &str,
    log_path: &Path,
    timeout: Duration,
) -> ExecPlan {
    ExecPlan {
        program: "idf.py".into(),
        args: vec![
            "-C".into(),
            project_dir.to_string_lossy().into_owned(),
            "-p".into(),
            port.into(),
            "flash".into(),
        ],
        timeout,
        log_path: log_path.to_path_buf(),
        description: format!("idf.py flash {} on {port}", project_dir.display()),
    }
}

/// Build an `idf.py -p <port> monitor` plan (always bounded by `timeout`).
pub fn idf_monitor_plan(
    project_dir: &Path,
    port: &str,
    log_path: &Path,
    timeout: Duration,
) -> ExecPlan {
    ExecPlan {
        program: "idf.py".into(),
        args: vec![
            "-C".into(),
            project_dir.to_string_lossy().into_owned(),
            "-p".into(),
            port.into(),
            "monitor".into(),
        ],
        timeout,
        log_path: log_path.to_path_buf(),
        description: format!("idf.py monitor {} on {port}", project_dir.display()),
    }
}

/// Execute a plan: spawn, poll with `try_wait`, kill on timeout, tee all
/// output to `log_path`. Never blocks past `timeout` + a small grace.
pub fn run_plan(plan: &ExecPlan) -> io::Result<RunOutcome> {
    if let Some(parent) = plan.log_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut child = Command::new(&plan.program)
        .args(&plan.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let deadline = Instant::now() + plan.timeout;
    let timed_out = loop {
        match child.try_wait()? {
            Some(_) => break false,
            None => {
                if Instant::now() >= deadline {
                    // Kill discipline: kill, then reap.
                    let _ = child.kill();
                    let _ = child.wait();
                    break true;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };
    // Drain whatever the child wrote before exit/kill.
    let mut out_bytes = Vec::new();
    let mut err_bytes = Vec::new();
    if let Some(o) = stdout.as_mut() {
        let _ = o.read_to_end(&mut out_bytes);
    }
    if let Some(e) = stderr.as_mut() {
        let _ = e.read_to_end(&mut err_bytes);
    }
    let exit_code = child.try_wait()?.and_then(|s| s.code());

    let mut log = File::create(&plan.log_path)?;
    writeln!(log, "# {}", plan.description)?;
    writeln!(log, "# cmd: {plan}")?;
    writeln!(log, "# timed_out: {timed_out}")?;
    log.write_all(&out_bytes)?;
    log.write_all(&err_bytes)?;
    Ok(RunOutcome {
        timed_out,
        exit_code,
        log_path: plan.log_path.clone(),
    })
}

/// Capture raw serial bytes from an already-open reader into `log_path` for
/// up to `duration`. Used with pty loopbacks in tests and with serial ports
/// in production (caller opens the port; this only bounds the capture).
#[cfg(unix)]
pub fn capture_stream<R: Read + std::os::unix::io::AsRawFd>(
    reader: &mut R,
    log_path: &Path,
    duration: Duration,
) -> io::Result<u64> {
    let mut log = open_log(log_path)?;
    drain_loop(reader, &mut log, Instant::now() + duration)
}

#[cfg(not(unix))]
pub fn capture_stream<R: Read>(
    reader: &mut R,
    log_path: &Path,
    duration: Duration,
) -> io::Result<u64> {
    // No select(): bounded blocking reads; stops at the next EOF or read
    // past the deadline.
    let mut log = open_log(log_path)?;
    let deadline = Instant::now() + duration;
    let mut total = 0u64;
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        log.write_all(&buf[..n])?;
        total += n as u64;
    }
    Ok(total)
}

fn open_log(log_path: &Path) -> io::Result<File> {
    if let Some(parent) = log_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    File::create(log_path)
}

#[cfg(unix)]
fn drain_loop<R: Read + std::os::unix::io::AsRawFd>(
    reader: &mut R,
    log: &mut File,
    deadline: Instant,
) -> io::Result<u64> {
    let mut total = 0u64;
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        // Short poll so we stop near the deadline even on quiet ports.
        let n = read_available(reader, &mut buf, Duration::from_millis(50))?;
        if n > 0 {
            log.write_all(&buf[..n])?;
            total += n as u64;
        }
    }
    Ok(total)
}

#[cfg(unix)]
fn read_available<R: Read + std::os::unix::io::AsRawFd>(
    r: &mut R,
    buf: &mut [u8],
    wait: Duration,
) -> io::Result<usize> {
    // NOTE: no trait import needed — the `AsRawFd` bound on `R` brings
    // `as_raw_fd` into scope for the generic body.
    let fd = r.as_raw_fd();
    let mut fds: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe {
        libc::FD_SET(fd, &mut fds);
        let mut tv = libc::timeval {
            tv_sec: wait.as_secs() as libc::time_t,
            tv_usec: wait.subsec_micros() as libc::suseconds_t,
        };
        let rc = libc::select(
            fd + 1,
            &mut fds,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut tv,
        );
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if rc == 0 {
            return Ok(0);
        }
    }
    r.read(buf)
}

#[cfg(not(unix))]
fn read_available<R: Read>(r: &mut R, buf: &mut [u8], _wait: Duration) -> io::Result<usize> {
    r.read(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_cover_all_esp_chips() {
        for chip in [Chip::C5, Chip::S3, Chip::H2, Chip::C6, Chip::S31] {
            assert!(profile(chip).is_some(), "{chip} needs a profile");
        }
        assert!(profile(Chip::NordicSniffer).is_none());
        assert!(profile(Chip::Sonoff).is_none());
    }

    #[test]
    fn esptool_plan_pins_chip_and_port() {
        let plan = esptool_flash_plan(
            Chip::C6,
            "/dev/ttyACM7",
            Path::new("fw.bin"),
            "0x0",
            Path::new("/tmp/x.log"),
            Duration::from_secs(120),
        )
        .unwrap();
        assert!(plan.args.contains(&"esp32c6".to_string()));
        assert!(plan.args.contains(&"/dev/ttyACM7".to_string()));
    }

    #[test]
    fn run_plan_times_out_and_kills() {
        let dir = std::env::temp_dir();
        let log = dir.join(format!("arb-sleep-{}.log", std::process::id()));
        let plan = ExecPlan {
            program: "sleep".into(),
            args: vec!["30".into()],
            timeout: Duration::from_millis(300),
            log_path: log.clone(),
            description: "sleep must be killed".into(),
        };
        let out = run_plan(&plan).unwrap();
        assert!(out.timed_out, "sleep 30 should time out at 300ms");
        assert!(log.exists());
        let _ = fs::remove_file(&log);
    }

    #[test]
    fn run_plan_captures_output_to_log() {
        let dir = std::env::temp_dir();
        let log = dir.join(format!("arb-echo-{}.log", std::process::id()));
        let plan = ExecPlan {
            program: "echo".into(),
            args: vec!["hello-lab".into()],
            timeout: Duration::from_secs(10),
            log_path: log.clone(),
            description: "echo".into(),
        };
        let out = run_plan(&plan).unwrap();
        assert!(!out.timed_out);
        assert_eq!(out.exit_code, Some(0));
        let body = fs::read_to_string(&log).unwrap();
        assert!(body.contains("hello-lab"));
        let _ = fs::remove_file(&log);
    }

    #[test]
    fn capture_stream_collects_bytes_with_deadline() {
        use crate::pty::open_pty_pair;
        use std::io::Write as _;

        let data = b"boot log line 1\nline 2\n".to_vec();
        let mut pair = open_pty_pair().unwrap();
        pair.controller.write_all(&data).unwrap();
        let mut replica = std::fs::File::open(&pair.replica_path).unwrap();
        let log = std::env::temp_dir().join(format!("arb-cap-{}.log", std::process::id()));
        let n = capture_stream(&mut replica, &log, Duration::from_secs(2)).unwrap();
        assert_eq!(n, data.len() as u64);
        assert_eq!(fs::read(&log).unwrap(), data);
        let _ = fs::remove_file(&log);
    }
}
