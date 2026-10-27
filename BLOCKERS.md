# BLOCKERS.md — human-only blocker queue

Policy: PARK-AND-CONTINUE with active alleviation. Workers must
attempt legitimate workarounds first; park an item here with full
context only when it is truly human-gated, release any held
hardware, and keep all other streams moving.

## Queue

### B-001 (2026-10-27): C6 wifi-deafness on ACM7 + ACM8 — physical replug protocol + quarantine approval
Status: NEEDS-HUMAN (remote diagnosis exhausted).
- Symptom: wifi scans 0 APs / reason 201 (NO_AP_FOUND) on both Xiao C6 units (ttyACM7 A0:F2:62:86:7F:68, ttyACM8 A0:F2:62:85:97:A4), across 3 firmwares. Onset in wave-6 antenna-sweep window (non-LOW/LOW combos driven; ACM9 without sweep stays healthy).
- Proven good: 15.4 TX/RX OTA-verified on ACM8 (10/10 byte-match + 97 ambient RX); RF/LNA/antenna functional.
- Excluded remotely: antenna GPIO, NVS (erase+fresh cal), phy partition (byte-identical to healthy ACM9), efuse, RTC/RAM (survives uhubctl VBUS power-cycle), firmware (same binary works on ACM9), Kconfig, AP-side. Evidence: /tmp/c6diag/ (31 files, on Pi, ephemeral — ask for re-capture if stale).
- Needed from human: (1) with leases free, physically unplug ACM7+ACM8 USB cables, wait 10s, replug (preferably different free hub ports), then report — a worker will re-run the scan probe. (2) If still deaf after replug, approve quarantining both as RF-damaged for wifi duty (do NOT discard: 15.4 path still good for 802.15.4-only experiments).
- Lab policy meanwhile: ACM7/ACM8 are 15.4-ONLY units; no wifi-node duty. No AP/NM action needed — esp-lab healthy.
- Non-LOW/LOW antenna combos on Xiao C6 are banned without human approval (suspected cause).
