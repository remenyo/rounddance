//! Clean-lifecycle runner: reserve -> baseline -> flash -> capture -> run
//! -> collect -> restore-verify -> release-or-quarantine.
//!
//! Every stage appends a [`StageEvidence`] record. A failed
//! restore-verify quarantines the device instead of releasing it, so the
//! next worker cannot pick up a dirty node. The runner is generic over
//! [`LabOps`] so tests inject fakes; [`ShellOps`] is the real hardware
//! implementation (unused by tests).

use crate::flash::RunOutcome;
use crate::leases::{LeaseManager, SystemClock};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Lifecycle stages, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Reserve,
    BaselineCheck,
    Flash,
    CaptureStart,
    Run,
    Collect,
    RestoreVerify,
    Release,
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Stage::Reserve => "reserve",
            Stage::BaselineCheck => "baseline-check",
            Stage::Flash => "flash",
            Stage::CaptureStart => "capture-start",
            Stage::Run => "run",
            Stage::Collect => "collect",
            Stage::RestoreVerify => "restore-verify",
            Stage::Release => "release",
        };
        f.write_str(s)
    }
}

/// One stage's evidence record.
#[derive(Debug, Clone)]
pub struct StageEvidence {
    pub stage: Stage,
    pub ok: bool,
    pub detail: String,
    pub log_path: Option<PathBuf>,
}

/// Final verdict for a lifecycle run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Device restored and lease released.
    Clean,
    /// Restore failed; device quarantined with the reason.
    Quarantined(String),
    /// Aborted before/at a stage; device released if it was ours.
    Aborted(String),
}

/// Full report for one lifecycle run.
#[derive(Debug, Clone)]
pub struct RunReport {
    pub port: String,
    pub stages: Vec<StageEvidence>,
    pub verdict: Verdict,
}

impl RunReport {
    pub fn ok(&self) -> bool {
        matches!(self.verdict, Verdict::Clean)
    }
}

/// What to do on a port.
#[derive(Debug, Clone)]
pub struct LifecycleRequest {
    pub port: String,
    pub owner: String,
    pub purpose: String,
    pub lease_timeout: Duration,
    /// Optional flash plan; `None` skips the flash stage (run-only).
    pub flash: Option<crate::flash::ExecPlan>,
    /// Optional run plan; `None` skips the run stage.
    pub run: Option<crate::flash::ExecPlan>,
}

/// Hardware operations, injectable for tests.
pub trait LabOps {
    fn baseline_check(&self, port: &str) -> Result<String, String>;
    fn flash(&self, plan: &crate::flash::ExecPlan) -> Result<RunOutcome, String>;
    fn capture_start(&self, port: &str) -> Result<String, String>;
    fn run(&self, plan: &crate::flash::ExecPlan) -> Result<RunOutcome, String>;
    fn collect(&self, port: &str) -> Result<String, String>;
    fn restore_verify(&self, port: &str) -> Result<String, String>;
}

/// Real hardware ops: shell out to the flash helpers.
pub struct ShellOps;

impl LabOps for ShellOps {
    fn baseline_check(&self, port: &str) -> Result<String, String> {
        if crate::inventory::lookup(port).is_none() {
            return Err(format!("{port} not in pinned inventory"));
        }
        if !Path::new(port).exists() {
            return Err(format!("{port} absent from /dev"));
        }
        let holders = crate::inventory::port_holders(port);
        if holders.is_empty() {
            Ok("pinned + present + no local holders".into())
        } else {
            Err(format!("port held by local pids: {holders:?}"))
        }
    }

    fn flash(&self, plan: &crate::flash::ExecPlan) -> Result<RunOutcome, String> {
        crate::flash::run_plan(plan)
            .map_err(|e| e.to_string())
            .and_then(|o| {
                if o.timed_out {
                    Err(format!("flash timed out; log {}", o.log_path.display()))
                } else if o.exit_code == Some(0) {
                    Ok(o)
                } else {
                    Err(format!(
                        "flash exit {:?}; log {}",
                        o.exit_code,
                        o.log_path.display()
                    ))
                }
            })
    }

    fn capture_start(&self, _port: &str) -> Result<String, String> {
        // Sniffer/tcpdump orchestration is operator-driven in v0; record the
        // hook point so reports show the stage was considered.
        Ok("capture hooks logged; see capture::TcpdumpPlan / decode_capture".into())
    }

    fn run(&self, plan: &crate::flash::ExecPlan) -> Result<RunOutcome, String> {
        crate::flash::run_plan(plan).map_err(|e| e.to_string())
    }

    fn collect(&self, _port: &str) -> Result<String, String> {
        Ok("per-run logs under run dir; see ExecPlan.log_path entries".into())
    }

    fn restore_verify(&self, port: &str) -> Result<String, String> {
        // v0: restore = port reappears in /dev and is not locally held.
        if !Path::new(port).exists() {
            return Err(format!("{port} missing from /dev after run"));
        }
        let holders = crate::inventory::port_holders(port);
        if holders.is_empty() {
            Ok("port present, no stray holders".into())
        } else {
            Err(format!("stray holders after run: {holders:?}"))
        }
    }
}

/// Run the full lifecycle against `ops`, holding the lease in `leases`.
pub fn run_lifecycle<O: LabOps>(
    leases: &mut LeaseManager<SystemClock>,
    ops: &O,
    req: &LifecycleRequest,
) -> RunReport {
    let mut stages: Vec<StageEvidence> = Vec::new();
    let mut push = |stage: Stage, ok: bool, detail: String, log: Option<PathBuf>| {
        stages.push(StageEvidence {
            stage,
            ok,
            detail,
            log_path: log,
        });
    };

    // --- reserve ---
    match leases.acquire(&req.port, &req.owner, &req.purpose, req.lease_timeout) {
        Ok(_) => push(
            Stage::Reserve,
            true,
            format!("leased to {}", req.owner),
            None,
        ),
        Err(e) => {
            push(Stage::Reserve, false, e.to_string(), None);
            return RunReport {
                port: req.port.clone(),
                stages,
                verdict: Verdict::Aborted(format!("reserve failed: {e}")),
            };
        }
    }

    // From here on the lease is ours; every exit releases or quarantines.
    let release_or_quarantine = |leases: &mut LeaseManager<SystemClock>,
                                 stages: Vec<StageEvidence>,
                                 verdict: Verdict|
     -> RunReport {
        match &verdict {
            Verdict::Clean | Verdict::Aborted(_) => {
                let _ = leases.release(&req.port, &req.owner);
            }
            Verdict::Quarantined(reason) => {
                let _ = leases.quarantine(&req.port, reason);
            }
        }
        RunReport {
            port: req.port.clone(),
            stages,
            verdict,
        }
    };

    // --- baseline-check ---
    match ops.baseline_check(&req.port) {
        Ok(d) => push(Stage::BaselineCheck, true, d, None),
        Err(e) => {
            push(Stage::BaselineCheck, false, e.clone(), None);
            return release_or_quarantine(
                leases,
                stages,
                Verdict::Aborted(format!("baseline failed: {e}")),
            );
        }
    }

    // --- flash (optional) ---
    if let Some(plan) = &req.flash {
        match ops.flash(plan) {
            Ok(o) => push(
                Stage::Flash,
                true,
                format!("exit {:?}", o.exit_code),
                Some(o.log_path.clone()),
            ),
            Err(e) => {
                push(Stage::Flash, false, e.clone(), None);
                return release_or_quarantine(
                    leases,
                    stages,
                    Verdict::Aborted(format!("flash failed: {e}")),
                );
            }
        }
    }

    // --- capture-start ---
    match ops.capture_start(&req.port) {
        Ok(d) => push(Stage::CaptureStart, true, d, None),
        Err(e) => {
            push(Stage::CaptureStart, false, e.clone(), None);
            return release_or_quarantine(
                leases,
                stages,
                Verdict::Aborted(format!("capture-start failed: {e}")),
            );
        }
    }

    // --- run (optional) ---
    if let Some(plan) = &req.run {
        match ops.run(plan) {
            Ok(o) => push(
                Stage::Run,
                !o.timed_out,
                format!("timed_out={} exit={:?}", o.timed_out, o.exit_code),
                Some(o.log_path.clone()),
            ),
            Err(e) => {
                push(Stage::Run, false, e.clone(), None);
                return release_or_quarantine(
                    leases,
                    stages,
                    Verdict::Aborted(format!("run failed: {e}")),
                );
            }
        }
    }

    // --- collect ---
    match ops.collect(&req.port) {
        Ok(d) => push(Stage::Collect, true, d, None),
        Err(e) => {
            push(Stage::Collect, false, e.clone(), None);
            return release_or_quarantine(
                leases,
                stages,
                Verdict::Aborted(format!("collect failed: {e}")),
            );
        }
    }

    // --- restore-verify -> release-or-quarantine ---
    match ops.restore_verify(&req.port) {
        Ok(d) => {
            push(Stage::RestoreVerify, true, d, None);
            push(Stage::Release, true, "lease released".into(), None);
            release_or_quarantine(leases, stages, Verdict::Clean)
        }
        Err(e) => {
            push(Stage::RestoreVerify, false, e.clone(), None);
            push(
                Stage::Release,
                false,
                "quarantined, not released".into(),
                None,
            );
            release_or_quarantine(leases, stages, Verdict::Quarantined(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leases::LeaseManager;
    use std::fs;

    struct FakeOps {
        restore_ok: bool,
    }

    impl LabOps for FakeOps {
        fn baseline_check(&self, _port: &str) -> Result<String, String> {
            Ok("fake baseline ok".into())
        }
        fn flash(&self, _plan: &crate::flash::ExecPlan) -> Result<RunOutcome, String> {
            Ok(RunOutcome {
                timed_out: false,
                exit_code: Some(0),
                log_path: PathBuf::from("/tmp/fake-flash.log"),
            })
        }
        fn capture_start(&self, _port: &str) -> Result<String, String> {
            Ok("fake capture".into())
        }
        fn run(&self, _plan: &crate::flash::ExecPlan) -> Result<RunOutcome, String> {
            Ok(RunOutcome {
                timed_out: false,
                exit_code: Some(0),
                log_path: PathBuf::from("/tmp/fake-run.log"),
            })
        }
        fn collect(&self, _port: &str) -> Result<String, String> {
            Ok("fake collect".into())
        }
        fn restore_verify(&self, _port: &str) -> Result<String, String> {
            if self.restore_ok {
                Ok("fake restore ok".into())
            } else {
                Err("fake restore FAILED".into())
            }
        }
    }

    fn req(port: &str) -> LifecycleRequest {
        LifecycleRequest {
            port: port.into(),
            owner: "test-worker".into(),
            purpose: "integration".into(),
            lease_timeout: Duration::from_secs(300),
            flash: None,
            run: None,
        }
    }

    fn tmp_state(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("arb-run-{tag}-{}.json", std::process::id()))
    }

    #[test]
    fn clean_run_releases_lease() {
        let s = tmp_state("clean");
        let mut leases = LeaseManager::load(s.as_path()).unwrap();
        let report = run_lifecycle(
            &mut leases,
            &FakeOps { restore_ok: true },
            &req("/dev/ttyFAKE0"),
        );
        assert!(report.ok(), "report: {:?}", report.verdict);
        assert_eq!(report.stages.len(), 6); // reserve, baseline, capture, collect, restore, release
        assert!(leases.lease("/dev/ttyFAKE0").is_none(), "lease released");
        assert!(leases.quarantined().is_empty());
        let _ = fs::remove_file(&s);
    }

    #[test]
    fn failed_restore_quarantines() {
        let s = tmp_state("quar");
        let mut leases = LeaseManager::load(s.as_path()).unwrap();
        let report = run_lifecycle(
            &mut leases,
            &FakeOps { restore_ok: false },
            &req("/dev/ttyFAKE1"),
        );
        assert_eq!(
            report.verdict,
            Verdict::Quarantined("fake restore FAILED".into())
        );
        assert!(leases.quarantined().contains_key("/dev/ttyFAKE1"));
        let _ = fs::remove_file(&s);
    }

    #[test]
    fn contended_port_aborts_before_touching_hardware() {
        use std::cell::Cell;
        struct CountingOps {
            calls: Cell<u32>,
        }
        impl LabOps for CountingOps {
            fn baseline_check(&self, _p: &str) -> Result<String, String> {
                self.calls.set(self.calls.get() + 1);
                Ok("x".into())
            }
            fn flash(&self, _p: &crate::flash::ExecPlan) -> Result<RunOutcome, String> {
                self.calls.set(self.calls.get() + 1);
                unreachable!()
            }
            fn capture_start(&self, _p: &str) -> Result<String, String> {
                self.calls.set(self.calls.get() + 1);
                Ok("x".into())
            }
            fn run(&self, _p: &crate::flash::ExecPlan) -> Result<RunOutcome, String> {
                self.calls.set(self.calls.get() + 1);
                unreachable!()
            }
            fn collect(&self, _p: &str) -> Result<String, String> {
                self.calls.set(self.calls.get() + 1);
                Ok("x".into())
            }
            fn restore_verify(&self, _p: &str) -> Result<String, String> {
                self.calls.set(self.calls.get() + 1);
                Ok("x".into())
            }
        }
        let s = tmp_state("cont");
        let mut leases = LeaseManager::load(s.as_path()).unwrap();
        leases
            .acquire(
                "/dev/ttyFAKE2",
                "someone-else",
                "busy",
                Duration::from_secs(600),
            )
            .unwrap();
        let ops = CountingOps {
            calls: Cell::new(0),
        };
        let report = run_lifecycle(&mut leases, &ops, &req("/dev/ttyFAKE2"));
        assert!(matches!(report.verdict, Verdict::Aborted(_)));
        assert_eq!(ops.calls.get(), 0, "no hardware touched on contention");
        let _ = fs::remove_file(&s);
    }
}
