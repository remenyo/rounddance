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
- DIAGNOSTIC UPDATE (2026-10-28, repocode wave): 97A4 REJOINED post-restore and is helloing fresh (.47, rssi -50/-52, uptime counting). Deafness is INTERMITTENT, not permanent — a marginal/flaky wifi path now leads over the RF-death theory (consistent with e510's pre-death flake history). Policy unchanged (15.4-ONLY until human review — intermittent is not reliable); hello continuity under monitoring.

### B-002 (2026-10-27): C5 wifi-deaf on ACM2 — replug protocol + quarantine approval + txpower-cap ratification
Status: NEEDS-HUMAN (remote recovery ladder exhausted: reflash x2, full erase_flash+reflash, uhubctl power-cycle).
- Symptom: ESP32-C5 (ttyACM2, 30:ED:A0:E4:1A:30) wifi STA stuck `disconnected, retrying`, never associates, after 15.4 bring-up session. 15.4 fully alive (TX OTA byte-match 15/15 + 7/7, RX ambient excellent). Same signature class as B-001 (wifi-dead/15.4-alive, survives erase+power-cycle) but NO antenna GPIOs were driven — differentiator is ~1hr of +20dBm 15.4 TX. S31 in the same wave is fully healthy (wifi helloing .112).
- Proven good: 15.4 TX/RX/ED on C5; SDK ceiling clean (zero banned symbols). Evidence: ~/hwscratch/c5s31/ (durable).
- Needed from human: (1) physically unplug ACM2 USB, wait 10s, replug (different free port if possible), report — a worker will re-run wifi-scan. (2) If still deaf, approve 15.4-ONLY quarantine (no wifi-node duty; keep for 15.4 experiments). (3) Ratify or lift the standing +10dBm 15.4 TX cap imposed lab-wide after this third unit (H2 precedent at 10dBm is clean).
- Lab policy meanwhile: ACM2 is 15.4-ONLY. TX power capped at +10dBm on all units; keep TX sessions short.

### B-003 (2026-10-27): healthy C6 e510 went wifi-deaf after cap-compliant 15.4 session — replug protocol + quarantine approval + correlation review
Status: NEEDS-HUMAN (remote recovery ladder exhausted).
- Symptom: ESP32-C6 e510 (post-restart /dev/ttyACM5, A0:F2:62:86:E5:10) helloing healthy at 22:01 (rssi -49) → after a 15.4-only interop session it never rejoined: `disconnected, retrying` loop, ACTIVE scan 0 APs, PASSIVE (RX-only, 13ch x2) scan 0 APs, zero AP-side auth attempts, zero packets on tcpdump. 15.4 RX/TX proven good minutes earlier on the same radio (bidirectional MG24 exchange + sniffer captures).
- Excluded remotely: antenna abuse (LOW/LOW verified in both firmwares' consoles), high-power TX (only brief cap-compliant +10dBm / 0dBm traffic: ~40 MG24 frames + 247 C6 frames), flash (2x hash-verified backup restores), NVS (region erase/regen), phy partition (byte-identical to backup — RF cal intact), power (uhubctl VBUS cycle, stable re-enumeration), AP-side (3 other STAs connected, no ghost entry). Evidence: ~/hwscratch/sonoff/ (durable: backups, c6_*.log, sniff_*.txt, exchange_run*.log).
- Significance: 4th wifi-deaf unit (joins B-001 pair + B-002 C5) and the FIRST with no antenna abuse and no high-power TX — weakens the +20dBm theory. e510 had a prior intermittent join-flake (wave-15 restore saga); leading theory is spontaneous/marginal failure, but 4/4 deaf units had 15.4 sessions in-window, so a session-correlated factor cannot be excluded.
- Needed from human: (1) physically unplug ACM5 USB, wait 10s, replug, report — a worker will re-run wifi-scan. (2) If still deaf, approve 15.4-ONLY quarantine (already recorded in arbitrator quarantine for /dev/ttyACM5; unit left in canonical retrying state so it rejoins on its own if it recovers). (3) Review the 15.4-TX/deafness correlation across B-001/B-002/B-003 and advise: no remaining unit has both wifi+15.4 (risk moot for planning), but root-cause guidance affects how hard we push 15.4 duty on the deaf units.
- Lab policy meanwhile: e510 is 15.4-ONLY. ZERO healthy C6 remain — all C6 work is 15.4/BLE-only (BLE expected alive per 7F68 precedent; confirm with a BLE-scan diagnostic when convenient). Wifi fleet = 2x S3 + S31.

### B-004 (2026-10-28): MG24 coordinator in persistent stealth after transient-key import — factory-reset/reflash approval + peer hygiene
Status: NEEDS-HUMAN (only known clear is destructive).
- Symptom: MG24 (USB0, stock EmberZNet 7.4.5 coordinator, ch15 PAN 0xA4D3) went persistent-stealthy after a transient-key import during join-interop (run 6): beacons permit-CLOSED during open windows (537+517+351 OTA proofs, 0 open; control run showed 126 open), MAC assocs DENIED 0xffff/0x02 OTA (92 reqs → 181 denies), TC pre-fires phantom handlers for our EUI ~5s after every permit with ZERO OTA trigger (8 consecutive runs, sniffer-proven). Survives resetNode (RESET_SOFTWARE confirmed) + USB deauth/reauth. ALL v13-readable state pristine (bellows info identical x3 snapshots, policies/tables empty) — stealth lives in token-or-deeper state with no v13 read/erase primitive. Secondary finding: TC answers assoc with an UNSECURED vendor APS CMD 0x30 (level-0 aux, plaintext) and never sends 0x05 transport — repo work queued to model level-0 RX.
- Impact: MG24 unusable as interop peer until cleared; v8 probe ladder is built/flashed and ready for RUN12 after restore. No join completed (11 runs + 2 verifies, honest partial). C6 + repo untouched (97A4 restored, tree clean). Evidence: ~/hwscratch/zbjoin/ (durable: run logs, captures, 7 MG24 snapshots, triage scripts).
- Needed from human: (1) approve MG24 tokenFactoryReset and/or reflash — DESTRUCTIVE: kills PAN A4D3 including our own MG21-dongle membership (0x9766, confirmed pre-existing lab gear, not foreign) — confirm acceptable, or provide an alternate clear procedure. (2) Peer hygiene: after reset, advise whether to rejoin the MG21 dongle to the PAN or leave the coordinator clean for interop.
- Lab policy meanwhile: NO further join attempts against MG24 until human clears (avoid deeper state); MG24 left powered, network unmodified. Interop pivots to C6↔C6 classical join meanwhile.
