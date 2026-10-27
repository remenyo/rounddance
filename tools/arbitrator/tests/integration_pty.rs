//! Integration: pty loopbacks stand in for serial hardware.
//!
//! No real hardware is flashed, opened (beyond the pty pair itself), or
//! reserved here. The pty replica path plays the role of `/dev/ttyACM*`:
//! leases bind to it, and the capture path reads bytes the test injects on
//! the controller side.

use lab_arbitrator::flash::capture_stream;
use lab_arbitrator::leases::LeaseManager;
use lab_arbitrator::pty::open_pty_pair;
use std::fs::File;
use std::io::Write;
use std::time::Duration;

fn tmp_state(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("arb-pty-{tag}-{}.json", std::process::id()))
}

/// Lease a pty replica path, inject bytes on the controller, capture from
/// the replica, and confirm the log holds exactly what was injected.
#[test]
fn pty_loopback_lease_and_capture() {
    let mut pair = open_pty_pair().expect("openpty");
    let port = pair.replica_path.to_string_lossy().into_owned();
    let state = tmp_state("cap");

    let mut leases = LeaseManager::load(&state).unwrap();
    leases
        .acquire(
            &port,
            "pty-worker",
            "loopback-capture",
            Duration::from_secs(300),
        )
        .expect("lease pty port");

    // Simulate firmware boot output on the controller side.
    let boot = b"rst:0x1 (POWERON),boot:0x13 (SPI_FAST_FLASH_BOOT)\nhello-lab\n";
    pair.controller.write_all(boot).unwrap();

    let log = std::env::temp_dir().join(format!("arb-pty-{}.log", std::process::id()));
    let mut replica = File::open(&pair.replica_path).expect("open replica");
    let n = capture_stream(&mut replica, &log, Duration::from_secs(2)).expect("capture");
    assert_eq!(n, boot.len() as u64, "captured every injected byte");
    assert_eq!(std::fs::read(&log).unwrap(), boot);

    // Release works on the pty path like a real port.
    assert!(leases.release(&port, "pty-worker").unwrap().is_none());

    let _ = std::fs::remove_file(&state);
    let _ = std::fs::remove_file(&log);
}

/// Full lifecycle against a pty port with hardware ops faked except the
/// lease itself: proves reserve -> stages -> release works end to end.
#[test]
fn pty_lifecycle_clean_releases() {
    use lab_arbitrator::flash::RunOutcome;
    use lab_arbitrator::runner::{run_lifecycle, LabOps, LifecycleRequest};

    struct PtyOps;
    impl LabOps for PtyOps {
        fn baseline_check(&self, port: &str) -> Result<String, String> {
            // Real check shape: the pty replica path must exist.
            if std::path::Path::new(port).exists() {
                Ok("pty present".into())
            } else {
                Err(format!("{port} missing"))
            }
        }
        fn flash(&self, _p: &lab_arbitrator::flash::ExecPlan) -> Result<RunOutcome, String> {
            Ok(RunOutcome {
                timed_out: false,
                exit_code: Some(0),
                log_path: "/tmp/pty-flash.log".into(),
            })
        }
        fn capture_start(&self, _p: &str) -> Result<String, String> {
            Ok("pty capture hook".into())
        }
        fn run(&self, _p: &lab_arbitrator::flash::ExecPlan) -> Result<RunOutcome, String> {
            Ok(RunOutcome {
                timed_out: false,
                exit_code: Some(0),
                log_path: "/tmp/pty-run.log".into(),
            })
        }
        fn collect(&self, _p: &str) -> Result<String, String> {
            Ok("pty collect".into())
        }
        fn restore_verify(&self, port: &str) -> Result<String, String> {
            if std::path::Path::new(port).exists() {
                Ok("pty still present".into())
            } else {
                Err(format!("{port} gone"))
            }
        }
    }

    let pair = open_pty_pair().expect("openpty");
    let port = pair.replica_path.to_string_lossy().into_owned();
    let state = tmp_state("life");
    let mut leases = LeaseManager::load(&state).unwrap();
    let req = LifecycleRequest {
        port: port.clone(),
        owner: "pty-worker".into(),
        purpose: "loopback-lifecycle".into(),
        lease_timeout: Duration::from_secs(300),
        flash: None,
        run: None,
    };
    let report = run_lifecycle(&mut leases, &PtyOps, &req);
    assert!(report.ok(), "verdict: {:?}", report.verdict);
    assert!(
        report.stages.iter().all(|s| s.ok),
        "all stages ok: {:?}",
        report.stages
    );
    assert!(leases.lease(&port).is_none(), "lease released");
    let _ = std::fs::remove_file(&state);
}
