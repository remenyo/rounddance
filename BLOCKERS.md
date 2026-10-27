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
- DIAGNOSTIC UPDATE (2026-10-27, BLE spike): deaf ACM7 hears 28 ambient BLE advertisers/60s + peer ESP OTA both directions (RSSI -35..-43). 2.4GHz RX path is fine — damage is wifi-path-specific. BLE is usable on deaf units, so they remain fully useful for 15.4 + BLE (Zigbee-Direct) work. Evidence: ~/hwscratch/ble/ (durable).

### B-002 (2026-10-27): C5 wifi-deaf on ACM2 — replug protocol + quarantine approval + txpower-cap ratification
Status: NEEDS-HUMAN (remote recovery ladder exhausted: reflash x2, full erase_flash+reflash, uhubctl power-cycle).
- Symptom: ESP32-C5 (ttyACM2, 30:ED:A0:E4:1A:30) wifi STA stuck `disconnected, retrying`, never associates, after 15.4 bring-up session. 15.4 fully alive (TX OTA byte-match 15/15 + 7/7, RX ambient excellent). Same signature class as B-001 (wifi-dead/15.4-alive, survives erase+power-cycle) but NO antenna GPIOs were driven — differentiator is ~1hr of +20dBm 15.4 TX. S31 in the same wave is fully healthy (wifi helloing .112).
- Proven good: 15.4 TX/RX/ED on C5; SDK ceiling clean (zero banned symbols). Evidence: ~/hwscratch/c5s31/ (durable).
- Needed from human: (1) physically unplug ACM2 USB, wait 10s, replug (different free port if possible), report — a worker will re-run wifi-scan. (2) If still deaf, approve 15.4-ONLY quarantine (no wifi-node duty; keep for 15.4 experiments). (3) Ratify or lift the standing +10dBm 15.4 TX cap imposed lab-wide after this third unit (H2 precedent at 10dBm is clean).
- Lab policy meanwhile: ACM2 is 15.4-ONLY. TX power capped at +10dBm on all units; keep TX sessions short.
