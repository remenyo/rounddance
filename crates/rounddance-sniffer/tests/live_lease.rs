//! STUB-LEASE job (RD-SNIFF real lease): live runs must hold a real
//! arbitrator port lease, acquired before the port opens and released
//! after (including failure paths). These tests drive the shipped
//! `rd-sniff --live` binary against a mock `lab-arbitrator` CLI
//! (pointed to by `RD_SNIFF_ARBITRATOR_BIN`) — no real serial, no real
//! arbitrator state, no hardware.
//!
//! Mock contract (`mock-arb.sh`, written per test into a temp dir):
//! logs every argv line to `$MOCK_ARB_LOG`; `reserve` exits 1 with a
//! `held by` complaint when `$MOCK_ARB_MODE` is `deny`, else exit 0;
//! `release` always exits 0.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

const MOCK_SCRIPT: &str = r#"#!/bin/sh
log="$MOCK_ARB_LOG"
printf 'argv:' >> "$log"
for a in "$@"; do printf ' <%s>' "$a" >> "$log"; done
printf '\n' >> "$log"
case "$1" in
  reserve)
    if [ "$MOCK_ARB_MODE" = deny ]; then
      echo "reserve: port held by other; queued at position 0" >&2
      exit 1
    fi
    echo "reserved $3 for $5"
    exit 0
    ;;
  release)
    echo "released $3"
    exit 0
    ;;
  *)
    echo "mock-arbitrator: unknown command $1" >&2
    exit 2
    ;;
esac
"#;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rd-sniff-lease-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_mock(dir: &Path) -> PathBuf {
    let p = dir.join("mock-arb.sh");
    std::fs::write(&p, MOCK_SCRIPT).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    let mut perms = std::fs::metadata(&p).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&p, perms).unwrap();
    p
}

fn bin() -> String {
    env!("CARGO_BIN_EXE_rd-sniff").to_string()
}

fn run_live(dir: &Path, mock: &Path, mode: &str, extra: &[&str]) -> (i32, String, String) {
    let log = dir.join("arb.log");
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let mut cmd = Command::new(bin());
    cmd.env("RD_SNIFF_ARBITRATOR_BIN", mock)
        .env("MOCK_ARB_MODE", mode)
        .env("MOCK_ARB_LOG", &log)
        .env("ARBITRATOR_STATE", dir.join("state.json"))
        .args([
            "--live",
            "--port",
            "/nonexistent-tty-sniff-lease",
            "--channel",
            "25",
            "--secs",
            "1",
            "--tag",
            "leasetest",
            "--out",
        ])
        .arg(&out)
        .args(extra);
    let o = cmd.output().expect("run rd-sniff --live");
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn arb_log(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("arb.log")).unwrap_or_default()
}

fn out_files(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir.join("out"))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn live_open_without_lease_must_refuse() {
    // The stub opens the port with no arbitrator contact at all: the
    // mock log proves it (no `reserve` line). The real lease refuses
    // before any open when the port is held elsewhere.
    let dir = scratch("deny");
    let mock = write_mock(&dir);
    let (code, stdout, stderr) = run_live(&dir, &mock, "deny", &[]);
    assert_eq!(code, 1, "held port must refuse with exit 1\n{stderr}");
    assert!(
        stderr.contains("lease") || stderr.contains("held"),
        "refusal must name the lease\n{stderr}"
    );
    let log = arb_log(&dir);
    assert!(
        log.contains("reserve"),
        "acquire-before-open: binary must attempt reserve\nlog={log:?}\nstderr={stderr}"
    );
    assert!(
        !log.contains("release"),
        "nothing held, nothing to release\nlog={log:?}"
    );
    assert!(
        !stdout.contains("frames="),
        "refused run must not capture\n{stdout}"
    );
    assert!(
        out_files(&dir).is_empty(),
        "refused run must not emit reports"
    );
    std::fs::remove_dir_all(&dir).unwrap_or(());
}

#[test]
fn live_open_failure_releases_lease() {
    // Reserve succeeds but the port open fails: the lease must still
    // be released (no leak on the failure path).
    let dir = scratch("openfail");
    let mock = write_mock(&dir);
    let (code, _stdout, _stderr) = run_live(&dir, &mock, "allow", &[]);
    assert_eq!(code, 1, "missing port must fail fast");
    let log = arb_log(&dir);
    let reserve = log.find("reserve").unwrap_or(usize::MAX);
    let release = log.find("release").unwrap_or(usize::MAX);
    assert!(
        reserve != usize::MAX && release != usize::MAX && reserve < release,
        "reserve-then-release on open failure\nlog={log:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap_or(());
}

#[test]
fn live_lease_owner_is_stable_worker_base() {
    // The arbitrator owner is the stable `--worker` base (default
    // `w2-live`): a refused run queues its owner as head and the
    // same-owner retry acquires, which is what keeps the arbitrator
    // FIFO live. Per-run identity travels in the reserve purpose
    // (tag) and the report lease ID, not the owner string.
    let dir = scratch("owner");
    let mock = write_mock(&dir);
    let (_code, _stdout, _stderr) = run_live(&dir, &mock, "allow", &[]);
    let log = arb_log(&dir);
    let reserve = log
        .lines()
        .find(|l| l.contains("reserve"))
        .unwrap_or_default();
    assert!(
        reserve.contains("<--owner> <w2-live>"),
        "stable worker owner, got {reserve:?}\nlog={log:?}"
    );
    assert!(
        reserve.contains("tag=leasetest"),
        "purpose names the run tag, got {reserve:?}\nlog={log:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap_or(());
}

#[test]
fn live_usage_errors_never_touch_arbitrator() {
    // Usage errors stay exit 2 and must not attempt any lease: the
    // channel gate and flag checks run before arbitrator contact.
    let dir = scratch("usage");
    let mock = write_mock(&dir);
    let log = dir.join("arb.log");
    // No --port.
    let o = Command::new(bin())
        .env("RD_SNIFF_ARBITRATOR_BIN", &mock)
        .env("MOCK_ARB_LOG", &log)
        .env("ARBITRATOR_STATE", dir.join("state.json"))
        .args(["--live", "--channel", "25", "--secs", "1"])
        .output()
        .expect("run rd-sniff");
    assert_eq!(o.status.code(), Some(2));
    // Bad channel.
    let o = Command::new(bin())
        .env("RD_SNIFF_ARBITRATOR_BIN", &mock)
        .env("MOCK_ARB_LOG", &log)
        .env("ARBITRATOR_STATE", dir.join("state.json"))
        .args([
            "--live",
            "--port",
            "/nonexistent-tty-sniff-lease",
            "--channel",
            "10",
            "--secs",
            "1",
        ])
        .output()
        .expect("run rd-sniff");
    assert_eq!(o.status.code(), Some(2));
    assert!(
        !log.exists() || arb_log(&dir).is_empty(),
        "usage errors must not contact the arbitrator"
    );
    std::fs::remove_dir_all(&dir).unwrap_or(());
}
