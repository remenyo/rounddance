# Lab arbitrator v0

Exclusive serial-port leases, flash/reset/run helpers, capture hooks, and a
clean-lifecycle runner for the rounddance hardware lab (Track H).

Host tooling: `std` allowed. This crate never ships on ESP. It is a member
of the workspace so `cargo build/test --workspace` covers it; its extra
dependencies (`serde`, `serde_json`, `libc`) are confined to this crate.

## Quick start

```sh
cargo run -p lab-arbitrator -- inventory --live
ARBITRATOR_STATE=/tmp/arb-state.json cargo run -p lab-arbitrator -- status
```

State file: `$ARBITRATOR_STATE`, else
`$HOME/.local/share/lab-arbitrator/state.json`.

## Commands

| Command | Effect |
|---|---|
| `inventory [--live]` | Pinned device table (from `esp-inventory.md`); `--live` also lists current `/dev/ttyACM*`/`ttyUSB*` nodes, who holds them, and flags missing pinned ports. Opens no ports, probes nothing. |
| `status` | Live leases, queue depths, quarantine list. |
| `reserve --port P --owner O --purpose U [--timeout-secs N]` | Exclusive lease (default 1800 s). Contended → queued, exit 1 with `holder + position`. |
| `renew --port P --owner O [--extra-secs N]` | Extend your lease from now. Non-owners are rejected. |
| `release --port P --owner O` | Release your lease; names the head waiter (who must still `acquire`). |
| `force-expire --port P` | Drop any lease regardless of owner (stuck/crashed worker). |
| `quarantine --port P --reason R` / `clear-quarantine --port P` | Block / unblock a device that failed restore-verify. |
| `decode --capture BIN [--decode-py PATH] [--pcap OUT]` | Run the nRF `decode.py` summary (default `/tmp/sniffer/decode.py`); structured error when the helper is absent. |
| `tcpdump-plan --channel CH --pcap OUT [--secs N]` | Print the operator-run sudo tcpdump stub for wlan0. |
| `lifecycle --port P --owner O --purpose U [--timeout-secs N] [--project-dir D --monitor-secs S \| --no-flash]` | Full clean lifecycle via `ShellOps`; exit 0 clean, 3 quarantined, 1 aborted. |

## Reservation protocol (for future workers)

1. **Read before you touch.** `arbitrator inventory --live` shows which
   pinned ports exist right now and whether a local process holds them.
   Never flash or open a port owned by someone else — verify with
   `/dev` locks / `port_holders` first. ACM0/ACM1 (nRF sniffer) belong to
   the sniffer worker; USB0/USB1 are Sonoffs, not ESP flash targets.
2. **Reserve first.** `reserve --port ... --owner <your-worker-id>
   --purpose <what+why>`. One owner per port; contention queues you FIFO.
3. **Heartbeat long jobs.** `renew` before your lease expires. Expired
   leases are swept on every operation — expiry is silent, so renew early.
4. **Use the lifecycle for flash runs.** Reserve → baseline-check → flash
   → capture-start → run → collect → restore-verify → release-or-quarantine.
   Per-run logs go to per-run log files (`run_plan` tees stdout+stderr).
5. **Restore or quarantine.** If restore-verify fails, the runner
   quarantines the device and later workers get `Quarantined` instead of a
   dirty node. Clear quarantine only after a human (or a verified restore)
   confirms the device is healthy.
6. **Release when done.** Crashed workers leave stale leases; those expire
   automatically on load/sweep (crash recovery). `force-expire` is for a
   lease you can prove is stuck.

## Modules

- `inventory` — typed pinned map (port/chip/role/capabilities), live
  `/dev` discovery, `port_holders` via `/proc` scan, on-request `esptool
  chip-id` probe.
- `leases` — exclusive leases + FIFO queues + quarantine, JSON state file
  with atomic replace, stale leases expire on load. Time via `Clock`
  (`SystemClock` / `ManualClock` for tests); waiters older than
  `WAITER_TTL_SECS` (1 h) are pruned so a crashed waiter cannot wedge a queue.
- `flash` — per-chip profiles (C6/H2/C5/S3/S31; S31 notes the
  `--preview set-target esp32s31` build step), `esptool`/`idf.py` plan
  builders, `run_plan` with timeout + kill discipline, bounded
  `capture_stream` serial capture.
- `capture` — `decode.py` integration (summary parse + `--pcap`), structured
  `DecodeScriptMissing` stub when the helper is absent; `TcpdumpPlan` stub
  for wlan0.
- `runner` — `run_lifecycle` over the injectable `LabOps` trait
  (`ShellOps` = real hardware), per-stage evidence + `RunReport`
  (`Clean` / `Quarantined` / `Aborted`).
- `pty` — `openpty` pair helper (raw mode, `/proc/self/fd` naming — robust
  where `ptsname()` fails) so tests exercise capture code with zero hardware.

## Tests

Unit (lease expiry/queue/persist-recover/renew/force-expire/quarantine,
profile builders, timeout+kill, summary parsing) plus `tests/integration_pty.rs`
(pty loopback lease+capture, full lifecycle on a pty port). No test touches
real hardware.
