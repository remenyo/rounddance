//! `arbitrator` CLI: inventory, leases, flash plans, lifecycle runs.
//!
//! State file: `$ARBITRATOR_STATE`, else
//! `$HOME/.local/share/lab-arbitrator/state.json`.

use lab_arbitrator::leases::Clock as _;
use lab_arbitrator::{capture, flash, inventory, leases, runner};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn state_path() -> PathBuf {
    if let Ok(p) = std::env::var("ARBITRATOR_STATE") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".local/share/lab-arbitrator/state.json")
}

fn usage() -> ! {
    eprintln!(
        "usage:\n\
        arbitrator inventory [--live]\n\
        arbitrator status\n\
        arbitrator reserve --port P --owner O --purpose U [--timeout-secs N]\n\
        arbitrator renew --port P --owner O [--extra-secs N]\n\
        arbitrator release --port P --owner O\n\
        arbitrator force-expire --port P\n\
        arbitrator quarantine --port P --reason R\n\
        arbitrator clear-quarantine --port P\n\
        arbitrator decode --capture BIN [--decode-py PATH] [--pcap OUT]\n\
        arbitrator tcpdump-plan --channel CH --pcap OUT [--secs N]\n\
        arbitrator lifecycle --port P --owner O --purpose U [--timeout-secs N]\n\
                    [--project-dir D --monitor-secs S | --no-flash]"
    );
    std::process::exit(2);
}

fn get(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn has(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn secs(args: &[String], flag: &str, default: u64) -> u64 {
    get(args, flag)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    let code = match args[0].as_str() {
        "inventory" => cmd_inventory(&args),
        "status" => cmd_status(),
        "reserve" => cmd_reserve(&args),
        "renew" => cmd_renew(&args),
        "release" => cmd_release(&args),
        "force-expire" => cmd_force_expire(&args),
        "quarantine" => cmd_quarantine(&args),
        "clear-quarantine" => cmd_clear_quarantine(&args),
        "decode" => cmd_decode(&args),
        "tcpdump-plan" => cmd_tcpdump_plan(&args),
        "lifecycle" => cmd_lifecycle(&args),
        _ => usage(),
    };
    std::process::exit(code);
}

fn cmd_inventory(args: &[String]) -> i32 {
    let known = inventory::known_inventory();
    println!("{:<14} {:<12} {:<18} ROLE", "PORT", "CHIP", "MAC");
    for d in &known {
        println!("{:<14} {:<12} {:<18} {}", d.port, d.chip, d.mac, d.role);
    }
    if has(args, "--live") {
        println!("\n-- live /dev nodes --");
        match inventory::discover_ports(Path::new("/dev")) {
            Ok(ports) => {
                for p in &ports {
                    let s = p.to_string_lossy();
                    let pinned = inventory::lookup(&s)
                        .map(|d| d.chip.to_string())
                        .unwrap_or_else(|| "UNPINNED".into());
                    let holders = inventory::port_holders(&s);
                    let held = if holders.is_empty() {
                        "free".to_string()
                    } else {
                        format!("held by {holders:?}")
                    };
                    println!("{s} [{pinned}] {held}");
                }
                // Warn about pinned ports missing from /dev.
                for d in &known {
                    if !ports.iter().any(|p| p.to_string_lossy() == d.port) {
                        println!("{} [{}] MISSING from /dev", d.port, d.chip);
                    }
                }
            }
            Err(e) => {
                eprintln!("discover: {e}");
                return 1;
            }
        }
    }
    0
}

fn cmd_status() -> i32 {
    let path = state_path();
    let mut m = match leases::LeaseManager::load(&path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("load state: {e}");
            return 1;
        }
    };
    println!("state: {}", path.display());
    let live = m.all_leases();
    if live.is_empty() {
        println!("leases: none");
    } else {
        println!("leases:");
        for l in &live {
            println!(
                "  {} owner={} purpose={} remaining={}s",
                l.port,
                l.owner,
                l.purpose,
                l.remaining(leases::SystemClock.now_epoch()).as_secs()
            );
        }
    }
    // Warn-before-expiry: leases inside the horizon are surfaced
    // with an explicit renew command instead of expiring silently.
    let warn = Duration::from_secs(leases::EXPIRY_WARN_SECS);
    for (l, ttl) in m.expiring_soon(warn) {
        println!(
            "  WARNING {} (owner={}) expires in {}s — renew with: arbitrator renew --port {} --owner {}",
            l.port,
            l.owner,
            ttl.as_secs(),
            l.port,
            l.owner
        );
    }
    let mut depths: Vec<_> = m.queue_depths().into_iter().collect();
    depths.sort();
    if depths.iter().any(|(_, n)| *n > 0) {
        println!("queues:");
        for (p, n) in depths.into_iter().filter(|(_, n)| *n > 0) {
            println!("  {p}: {n} waiter(s)");
        }
    }
    let mut q: Vec<_> = m.quarantined().into_iter().collect();
    q.sort();
    if q.is_empty() {
        println!("quarantine: none");
    } else {
        println!("quarantine:");
        for (p, r) in q {
            println!("  {p}: {r}");
        }
    }
    0
}

fn open_mgr() -> Result<leases::LeaseManager, i32> {
    leases::LeaseManager::load(&state_path()).map_err(|e| {
        eprintln!("load state: {e}");
        1
    })
}

fn cmd_reserve(args: &[String]) -> i32 {
    let (Some(port), Some(owner), Some(purpose)) = (
        get(args, "--port"),
        get(args, "--owner"),
        get(args, "--purpose"),
    ) else {
        usage();
    };
    let timeout = Duration::from_secs(secs(args, "--timeout-secs", 1800).max(1));
    let mut m = match open_mgr() {
        Ok(m) => m,
        Err(c) => return c,
    };
    match m.acquire(&port, &owner, &purpose, timeout) {
        Ok(_) => {
            println!("reserved {port} for {owner} ({}s)", timeout.as_secs());
            0
        }
        Err(e) => {
            eprintln!("reserve: {e}");
            1
        }
    }
}

fn cmd_renew(args: &[String]) -> i32 {
    let (Some(port), Some(owner)) = (get(args, "--port"), get(args, "--owner")) else {
        usage();
    };
    let extra = Duration::from_secs(secs(args, "--extra-secs", 1800).max(1));
    let mut m = match open_mgr() {
        Ok(m) => m,
        Err(c) => return c,
    };
    match m.renew(&port, &owner, extra) {
        Ok(l) => {
            println!("renewed {port}: expires @ {}", l.expires_epoch);
            0
        }
        Err(e) => {
            eprintln!("renew: {e}");
            1
        }
    }
}

fn cmd_release(args: &[String]) -> i32 {
    let (Some(port), Some(owner)) = (get(args, "--port"), get(args, "--owner")) else {
        usage();
    };
    let mut m = match open_mgr() {
        Ok(m) => m,
        Err(c) => return c,
    };
    match m.release(&port, &owner) {
        Ok(next) => {
            println!("released {port}");
            if let Some(w) = next {
                println!("next waiter: {} ({})", w.owner, w.purpose);
            }
            0
        }
        Err(e) => {
            eprintln!("release: {e}");
            1
        }
    }
}

fn cmd_force_expire(args: &[String]) -> i32 {
    let Some(port) = get(args, "--port") else {
        usage();
    };
    let mut m = match open_mgr() {
        Ok(m) => m,
        Err(c) => return c,
    };
    match m.force_expire(&port) {
        Ok(Some(l)) => {
            println!("force-expired {} (was {})", port, l.owner);
            0
        }
        Ok(None) => {
            println!("no lease on {port}");
            0
        }
        Err(e) => {
            eprintln!("force-expire: {e}");
            1
        }
    }
}

fn cmd_quarantine(args: &[String]) -> i32 {
    let (Some(port), Some(reason)) = (get(args, "--port"), get(args, "--reason")) else {
        usage();
    };
    let mut m = match open_mgr() {
        Ok(m) => m,
        Err(c) => return c,
    };
    match m.quarantine(&port, &reason) {
        Ok(()) => {
            println!("quarantined {port}: {reason}");
            0
        }
        Err(e) => {
            eprintln!("quarantine: {e}");
            1
        }
    }
}

fn cmd_clear_quarantine(args: &[String]) -> i32 {
    let Some(port) = get(args, "--port") else {
        usage();
    };
    let mut m = match open_mgr() {
        Ok(m) => m,
        Err(c) => return c,
    };
    match m.clear_quarantine(&port) {
        Ok(true) => {
            println!("cleared quarantine on {port}");
            0
        }
        Ok(false) => {
            println!("{port} was not quarantined");
            0
        }
        Err(e) => {
            eprintln!("clear-quarantine: {e}");
            1
        }
    }
}

fn cmd_decode(args: &[String]) -> i32 {
    let Some(cap) = get(args, "--capture") else {
        usage();
    };
    let decode_py = get(args, "--decode-py")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(capture::DEFAULT_DECODE_PY));
    let pcap = get(args, "--pcap").map(PathBuf::from);
    match capture::decode_capture(
        Path::new(&cap),
        &decode_py,
        pcap.as_deref(),
        Duration::from_secs(120),
    ) {
        Ok(frames) => {
            for f in &frames {
                println!(
                    "[{}] {} fc={:#06x} seq={} len={} rssi={} lqi={} t={}",
                    f.index, f.kind, f.fc, f.seq, f.len, f.rssi, f.lqi, f.ts
                );
            }
            println!("total={}", frames.len());
            0
        }
        Err(e) => {
            eprintln!("decode: {e}");
            1
        }
    }
}

fn cmd_tcpdump_plan(args: &[String]) -> i32 {
    let (Some(pcap), Some(ch)) = (get(args, "--pcap"), get(args, "--channel")) else {
        usage();
    };
    let ch: u8 = match ch.parse() {
        Ok(c) => c,
        Err(_) => {
            eprintln!("bad --channel {ch}");
            return 2;
        }
    };
    let plan = capture::TcpdumpPlan::new(
        ch,
        Path::new(&pcap),
        Duration::from_secs(secs(args, "--secs", 60)),
    );
    println!("STUB (needs sudo on wlan0):\n  {}", plan.command_line());
    0
}

fn cmd_lifecycle(args: &[String]) -> i32 {
    let (Some(port), Some(owner), Some(purpose)) = (
        get(args, "--port"),
        get(args, "--owner"),
        get(args, "--purpose"),
    ) else {
        usage();
    };
    let timeout = Duration::from_secs(secs(args, "--timeout-secs", 1800).max(1));
    let run_dir = std::env::temp_dir().join(format!(
        "arb-run-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    ));

    // Optional flash+monitor pair; --no-flash means run-only/baseline.
    let (flash_plan, run_plan) = if has(args, "--no-flash") {
        (None, None)
    } else {
        let Some(dir) = get(args, "--project-dir") else {
            eprintln!("lifecycle needs --project-dir or --no-flash");
            return 2;
        };
        let monitor_secs = secs(args, "--monitor-secs", 30).max(1);
        (
            Some(flash::idf_flash_plan(
                Path::new(&dir),
                &port,
                &run_dir.join("flash.log"),
                Duration::from_secs(600),
            )),
            Some(flash::idf_monitor_plan(
                Path::new(&dir),
                &port,
                &run_dir.join("monitor.log"),
                Duration::from_secs(monitor_secs),
            )),
        )
    };

    let req = runner::LifecycleRequest {
        port: port.clone(),
        owner,
        purpose,
        lease_timeout: timeout,
        flash: flash_plan,
        run: run_plan,
    };
    let mut m = match open_mgr() {
        Ok(m) => m,
        Err(c) => return c,
    };
    let report = runner::run_lifecycle(&mut m, &runner::ShellOps, &req);
    println!("run dir: {}", run_dir.display());
    for s in &report.stages {
        let mark = if s.ok { "ok  " } else { "FAIL" };
        let log = s
            .log_path
            .as_ref()
            .map(|p| format!(" log={}", p.display()))
            .unwrap_or_default();
        println!("  [{mark}] {:<14} {}{log}", s.stage.to_string(), s.detail);
    }
    match &report.verdict {
        runner::Verdict::Clean => {
            println!("verdict: CLEAN");
            0
        }
        runner::Verdict::Quarantined(r) => {
            println!("verdict: QUARANTINED: {r}");
            3
        }
        runner::Verdict::Aborted(r) => {
            println!("verdict: ABORTED: {r}");
            1
        }
    }
}
