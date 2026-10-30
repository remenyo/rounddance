//! Real arbitrator port lease for `rd-sniff --live` (binary-side only).
//!
//! The library stays `no_std`-compatible with zero arbitrator calls:
//! this module shells out to the lab `arbitrator` CLI (`reserve` /
//! `release` over the shared JSON state file), so no new crate
//! dependency is needed and the `wasm32` gates are unaffected.
//!
//! Discipline enforced here, in order:
//!
//! * usage errors (missing `--port`, bad channel) exit before any
//!   arbitrator contact (checked by the caller during arg parsing);
//! * the lease names the canonical port: `/dev/serial/by-id/...`
//!   symlinks resolve to the pinned `/dev/ttyACM*` node, so a lease
//!   on either spelling covers the same hardware and two spellings
//!   can never hold the port twice;
//! * `reserve` runs before the port opens — a held, quarantined, or
//!   otherwise unreservable port refuses with exit 1 and the port is
//!   never touched;
//! * `release` runs after the listener is dropped (hardware parked,
//!   port closed) and before any file IO, so even an emit failure
//!   cannot leak the lease; the open-failure path releases too.
//!
//! Stable owners, per-run identity: the arbitrator owner is the stable
//! `--worker` base (`w2-live` by default). Stable owners are what the
//! arbitrator FIFO assumes — a refused run queues its owner as head,
//! and the *same* owner retrying later acquires as head; unique
//! per-run owners would wedge the queue behind a dead head entry
//! until the waiter TTL. Per-run identity lives where it is
//! replayable: the report `lease` field still derives from
//! (`--worker`, `--tag`, `--channel`, `--lease-seq`) via
//! [`lease_id_for_run`](rounddance_sniffer::lease::lease_id_for_run),
//! so replaying a run with the same flags renders byte-identical
//! reports, and the reserve `--purpose` names the tag.
//!
//! Knobs: `RD_SNIFF_ARBITRATOR_BIN` overrides the CLI path (tests
//! point it at a mock); the CLI itself reads `ARBITRATOR_STATE`.

/// CLI path: `RD_SNIFF_ARBITRATOR_BIN`, else the lab default.
pub fn arbitrator_bin() -> String {
    std::env::var("RD_SNIFF_ARBITRATOR_BIN").unwrap_or_else(|_| String::from("lab-arbitrator"))
}

/// Arbitrator owner for a run: the stable `--worker` base unchanged.
/// Stable owners keep the arbitrator FIFO live (a refused run queues
/// its owner as head and the same-owner retry acquires); the run is
/// told apart by its `--purpose` tag and its report lease ID.
#[must_use]
pub fn lease_owner(base: &str) -> String {
    String::from(base)
}

/// Lease timeout covering a `capture_secs` run plus park/release
/// margin (floor 300 s, saturating).
#[must_use]
pub fn lease_timeout_secs(capture_secs: u64) -> u64 {
    capture_secs.saturating_add(300).max(300)
}

/// Canonical lease name for a `--port` path: symlinks (by-id) resolve
/// to the pinned node; a missing path falls back to the raw spelling
/// so the open still fails fast with the usual error.
#[must_use]
pub fn lease_port(port: &str) -> String {
    match std::fs::canonicalize(port) {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(_) => String::from(port),
    }
}

/// Run the arbitrator CLI; `Ok(stdout)` on exit 0, `Err(detail)` with
/// the trimmed stderr line otherwise. Falls back from
/// `lab-arbitrator` to `arbitrator` (the cargo bin name) when the
/// default is not on `PATH`.
fn run_arbitrator(bin: &str, args: &[&str]) -> Result<String, String> {
    let out = match std::process::Command::new(bin).args(args).output() {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && bin == "lab-arbitrator" => {
            return run_arbitrator("arbitrator", args);
        }
        Err(e) => return Err(format!("spawn {bin}: {e}")),
    };
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(if detail.is_empty() {
            format!("{bin} {} failed with exit {}", args.join(" "), out.status)
        } else {
            detail
        })
    }
}

/// Held arbitrator lease: acquire-before-open, release-after.
/// `Drop` releases as a backstop (best-effort, silent); prefer
/// explicit [`Guard::release`] so failures are visible.
pub struct Guard {
    bin: String,
    port: String,
    owner: String,
    held: bool,
}

impl Guard {
    /// `reserve --port PORT --owner OWNER --purpose PURPOSE
    /// --timeout-secs N`. On error the port was not touched.
    pub fn acquire(
        port: &str,
        owner: &str,
        purpose: &str,
        timeout_secs: u64,
    ) -> Result<Self, String> {
        Self::acquire_with_bin(&arbitrator_bin(), port, owner, purpose, timeout_secs)
    }

    /// [`Guard::acquire`] with an explicit CLI path (tests point this
    /// at a mock; production passes [`arbitrator_bin`]).
    pub fn acquire_with_bin(
        bin: &str,
        port: &str,
        owner: &str,
        purpose: &str,
        timeout_secs: u64,
    ) -> Result<Self, String> {
        let timeout = timeout_secs.max(1).to_string();
        run_arbitrator(
            bin,
            &[
                "reserve",
                "--port",
                port,
                "--owner",
                owner,
                "--purpose",
                purpose,
                "--timeout-secs",
                &timeout,
            ],
        )?;
        Ok(Self {
            bin: String::from(bin),
            port: String::from(port),
            owner: String::from(owner),
            held: true,
        })
    }

    /// Release our lease (idempotent). Warns are the caller's job.
    pub fn release(&mut self) -> Result<(), String> {
        if !self.held {
            return Ok(());
        }
        let r = run_arbitrator(
            &self.bin,
            &["release", "--port", &self.port, "--owner", &self.owner],
        );
        self.held = false;
        r.map(|_| ())
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if self.held {
            let _ = run_arbitrator(
                &self.bin,
                &["release", "--port", &self.port, "--owner", &self.owner],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_is_the_stable_worker_base() {
        // Stable owners keep the arbitrator FIFO live: a refused run
        // queues its owner as head and the same-owner retry acquires.
        assert_eq!(lease_owner("w2-live"), "w2-live");
        assert_eq!(lease_owner("sniff-w2"), "sniff-w2");
    }

    #[test]
    fn timeout_covers_run_with_margin() {
        assert_eq!(lease_timeout_secs(60), 360);
        assert_eq!(lease_timeout_secs(0), 300);
        assert_eq!(lease_timeout_secs(u64::MAX), u64::MAX);
    }

    #[test]
    fn lease_port_resolves_symlinks_and_falls_back() {
        // Missing path: raw spelling, so the open fails fast as before.
        assert_eq!(
            lease_port("/nonexistent-tty-sniff-lease"),
            "/nonexistent-tty-sniff-lease"
        );
        // A by-id-style symlink resolves to its target node.
        let dir = std::env::temp_dir().join(format!("rd-sniff-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("ttyACM9");
        std::fs::write(&target, b"").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, dir.join("by-id-link")).unwrap();
        #[cfg(unix)]
        assert_eq!(
            lease_port(&dir.join("by-id-link").to_string_lossy()),
            target.to_string_lossy()
        );
        std::fs::remove_dir_all(&dir).unwrap_or(());
    }

    /// Mock arbitrator CLI for guard tests (see `tests/live_lease.rs`
    /// for the binary-level contract). Hermetic under parallel tests:
    /// the mode (`allow`/`deny`) and log path are baked into the
    /// script, so no process-global env is touched.
    #[cfg(unix)]
    fn mock_bin(dir: &std::path::Path, mode: &str) -> (String, std::path::PathBuf) {
        let log = dir.join("arb.log");
        let p = dir.join("mock-arb.sh");
        let script = format!(
            "#!/bin/sh\nlog=\"{log}\"\nmode=\"{mode}\"\nprintf 'argv:' >> \"$log\"\nfor a in \"$@\"; do printf ' <%s>' \"$a\" >> \"$log\"; done\nprintf '\\n' >> \"$log\"\ncase \"$1\" in\n  reserve) if [ \"$mode\" = deny ]; then echo \"reserve: port held by other; queued at position 0\" >&2; exit 1; fi; echo ok; exit 0;;\n  release) echo ok; exit 0;;\nesac\nexit 2\n",
            log = log.to_string_lossy(),
            mode = mode,
        );
        std::fs::write(&p, script).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&p, perms).unwrap();
        (p.to_string_lossy().into_owned(), log)
    }

    #[cfg(unix)]
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rd-sniff-guard-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    #[cfg(unix)]
    fn acquire_refuses_when_held_and_touches_nothing_else() {
        let dir = scratch("deny");
        let (bin, log) = mock_bin(&dir, "deny");
        let err = Guard::acquire_with_bin(&bin, "/dev/ttyACM9", "w2-live", "test", 300)
            .err()
            .expect("denied");
        assert!(err.contains("held by"), "{err}");
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(logged.contains("reserve"), "{logged}");
        assert!(!logged.contains("release"), "{logged}");
        std::fs::remove_dir_all(&dir).unwrap_or(());
    }

    #[test]
    #[cfg(unix)]
    fn acquire_then_release_round_trip() {
        let dir = scratch("ok");
        let (bin, log) = mock_bin(&dir, "allow");
        let mut g = Guard::acquire_with_bin(&bin, "/dev/ttyACM9", "w2-live", "test", 360).unwrap();
        g.release().unwrap();
        // Explicit release is idempotent: Drop after release is silent.
        g.release().unwrap();
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(logged.contains("--timeout-secs> <360"), "{logged}");
        assert_eq!(logged.matches("release").count(), 1, "{logged}");
        std::fs::remove_dir_all(&dir).unwrap_or(());
    }

    #[test]
    #[cfg(unix)]
    fn drop_releases_an_unreleased_guard() {
        let dir = scratch("drop");
        let (bin, log) = mock_bin(&dir, "allow");
        {
            let _g = Guard::acquire_with_bin(&bin, "/dev/ttyACM9", "w2-live", "test", 300).unwrap();
        }
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(
            logged.contains("release"),
            "Drop backstop must release\n{logged}"
        );
        std::fs::remove_dir_all(&dir).unwrap_or(());
    }
}
