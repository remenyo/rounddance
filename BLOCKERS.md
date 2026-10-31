# BLOCKERS.md — human-only blocker queue

Policy: PARK-AND-CONTINUE with active alleviation. Workers must
attempt legitimate workarounds first; park an item here with full
context only when it is truly human-gated, release any held
hardware, and keep all other streams moving.

## Queue

### B-001 (2026-10-27): C6 wifi-deafness on ACM7 + ACM8 — physical replug protocol + quarantine approval
Status: CLOSED (diagnosed wave-34 — see verdict bullet).
- Symptom: wifi scans 0 APs / reason 201 (NO_AP_FOUND) on both Xiao C6 units (ttyACM7 A0:F2:62:86:7F:68, ttyACM8 A0:F2:62:85:97:A4), across 3 firmwares. Onset in wave-6 antenna-sweep window (non-LOW/LOW combos driven; ACM9 without sweep stays healthy).
- Proven good: 15.4 TX/RX OTA-verified on ACM8 (10/10 byte-match + 97 ambient RX); RF/LNA/antenna functional.
- Excluded remotely: antenna GPIO, NVS (erase+fresh cal), phy partition (byte-identical to healthy ACM9), efuse, RTC/RAM (survives uhubctl VBUS power-cycle), firmware (same binary works on ACM9), Kconfig, AP-side. Evidence: /tmp/c6diag/ (31 files, on Pi, ephemeral — ask for re-capture if stale).
- Needed from human: (1) with leases free, physically unplug ACM7+ACM8 USB cables, wait 10s, replug (preferably different free hub ports), then report — a worker will re-run the scan probe. (2) If still deaf after replug, approve quarantining both as RF-damaged for wifi duty (do NOT discard: 15.4 path still good for 802.15.4-only experiments).
- Lab policy meanwhile: ACM7/ACM8 are 15.4-ONLY units; no wifi-node duty. No AP/NM action needed — esp-lab healthy.
- Non-LOW/LOW antenna combos on Xiao C6 are banned without human approval (suspected cause).
- DIAGNOSTIC UPDATE (2026-10-27, BLE spike): deaf ACM7 hears 28 ambient BLE advertisers/60s + peer ESP OTA both directions (RSSI -35..-43). 2.4GHz RX path is fine — damage is wifi-path-specific. BLE is usable on deaf units, so they remain fully useful for 15.4 + BLE (Zigbee-Direct) work. Evidence: ~/hwscratch/ble/ (durable).
- DIAGNOSTIC UPDATE (2026-10-28, repocode wave): 97A4 REJOINED post-restore and is helloing fresh (.47, rssi -50/-52, uptime counting). Deafness is INTERMITTENT, not permanent — a marginal/flaky wifi path now leads over the RF-death theory (consistent with e510's pre-death flake history). Policy unchanged (15.4-ONLY until human review — intermittent is not reliable); hello continuity under monitoring.
- Verdict 2026-10-28 (head, wave-34): UNIT-HW (wifi subsystem). 7F68 scan-proven wifi-RX-dead (stock IDF after FULL chip erase: 0 APs; same-fw S3 same-bench: 19-20 APs), 97A4 log-proven deaf 5h+ post-restore (06:06 restore, zero hellos after; earlier rejoins unexplained/marginal). NVS/cal/efuse excluded, Pi-AP excluded, 15.4 alive on both. C6 wifi not functional per role ruling. Evidence: ~/hwscratch/deaf/.
- UPDATE 2026-10-30 (wave-77 lane 1): verdict SUPERSEDED for 7F68 — associated + helloing (rssi -53) + pingable on `esp-lab` (live `iw station dump`, /tmp/nodes-listen.log; evidence ~/hwscratch/w77/lane1/). 97A4 still dark (joined neither wlan0 nor wlan1 AP while 5/5 healthy units joined). 7F68 returns to normal wifi duty; 97A4 stays 15.4-ONLY pending human replug/re-test.

### B-002 (2026-10-27): C5 wifi-deaf on ACM2 — replug protocol + quarantine approval + txpower-cap ratification
Status: CLOSED (recovered wave-34 — see verdict bullet).
- Symptom: ESP32-C5 (ttyACM2, 30:ED:A0:E4:1A:30) wifi STA stuck `disconnected, retrying`, never associates, after 15.4 bring-up session. 15.4 fully alive (TX OTA byte-match 15/15 + 7/7, RX ambient excellent). Same signature class as B-001 (wifi-dead/15.4-alive, survives erase+power-cycle) but NO antenna GPIOs were driven — differentiator is ~1hr of +20dBm 15.4 TX. S31 in the same wave is fully healthy (wifi helloing .112).
- Proven good: 15.4 TX/RX/ED on C5; SDK ceiling clean (zero banned symbols). Evidence: ~/hwscratch/c5s31/ (durable).
- Needed from human: (1) physically unplug ACM2 USB, wait 10s, replug (different free port if possible), report — a worker will re-run wifi-scan. (2) If still deaf, approve 15.4-ONLY quarantine (no wifi-node duty; keep for 15.4 experiments). (3) Ratify or lift the standing +10dBm 15.4 TX cap imposed lab-wide after this third unit (H2 precedent at 10dBm is clean).
- Lab policy meanwhile: ACM2 is 15.4-ONLY. TX power capped at +10dBm on all units; keep TX sessions short.
- Verdict 2026-10-28 (head, wave-34): RECOVERED, cause unattributed. C5 observed healthy and helloing (up=19367 at 11:19 on 2026-10-28); prior deafness episode never reproduced under test. Reopen on recurrence with fresh scan evidence. Evidence: wifi-hello.log + ~/hwscratch/deaf/ (4th-unit census).

### B-003 (2026-10-27): healthy C6 e510 went wifi-deaf after cap-compliant 15.4 session — replug protocol + quarantine approval + correlation review
Status: CLOSED (diagnosed wave-34 — see verdict bullet).
- Symptom: ESP32-C6 e510 (post-restart /dev/ttyACM5, A0:F2:62:86:E5:10) helloing healthy at 22:01 (rssi -49) → after a 15.4-only interop session it never rejoined: `disconnected, retrying` loop, ACTIVE scan 0 APs, PASSIVE (RX-only, 13ch x2) scan 0 APs, zero AP-side auth attempts, zero packets on tcpdump. 15.4 RX/TX proven good minutes earlier on the same radio (bidirectional MG24 exchange + sniffer captures).
- Excluded remotely: antenna abuse (LOW/LOW verified in both firmwares' consoles), high-power TX (only brief cap-compliant +10dBm / 0dBm traffic: ~40 MG24 frames + 247 C6 frames), flash (2x hash-verified backup restores), NVS (region erase/regen), phy partition (byte-identical to backup — RF cal intact), power (uhubctl VBUS cycle, stable re-enumeration), AP-side (3 other STAs connected, no ghost entry). Evidence: ~/hwscratch/sonoff/ (durable: backups, c6_*.log, sniff_*.txt, exchange_run*.log).
- Significance: 4th wifi-deaf unit (joins B-001 pair + B-002 C5) and the FIRST with no antenna abuse and no high-power TX — weakens the +20dBm theory. e510 had a prior intermittent join-flake (wave-15 restore saga); leading theory is spontaneous/marginal failure, but 4/4 deaf units had 15.4 sessions in-window, so a session-correlated factor cannot be excluded.
- Needed from human: (1) physically unplug ACM5 USB, wait 10s, replug, report — a worker will re-run wifi-scan. (2) If still deaf, approve 15.4-ONLY quarantine (already recorded in arbitrator quarantine for /dev/ttyACM5; unit left in canonical retrying state so it rejoins on its own if it recovers). (3) Review the 15.4-TX/deafness correlation across B-001/B-002/B-003 and advise: no remaining unit has both wifi+15.4 (risk moot for planning), but root-cause guidance affects how hard we push 15.4 duty on the deaf units.
- Lab policy meanwhile: e510 is 15.4-ONLY. ZERO healthy C6 remain — all C6 work is 15.4/BLE-only (BLE expected alive per 7F68 precedent; confirm with a BLE-scan diagnostic when convenient). Wifi fleet = 2x S3 + S31.
- Verdict 2026-10-28 (head, wave-34): UNIT-HW (wifi subsystem). e510 wifi TX+RX dead (stock scan after full erase 0 APs; fails vs live ESP-AP too; e510-as-softAP invisible to S3 across 16/18/6-AP scans), 15.4 two-way alive. NVS/cal/efuse bit-identical healthy-vs-dead, Pi-AP excluded. C6 wifi not functional per role ruling; unit returned to service for 15.4/BLE-only roles (currently c6-blink). Evidence: ~/hwscratch/deaf/.

### B-004 (2026-10-28): MG24 coordinator in persistent stealth after transient-key import — factory-reset/reflash approval + peer hygiene
Status: CLOSED (recovered wave-37 — see verdict bullet).
- Symptom: MG24 (USB0, stock EmberZNet 7.4.5 coordinator, ch15 PAN 0xA4D3) went persistent-stealthy after a transient-key import during join-interop (run 6): beacons permit-CLOSED during open windows (537+517+351 OTA proofs, 0 open; control run showed 126 open), MAC assocs DENIED 0xffff/0x02 OTA (92 reqs → 181 denies), TC pre-fires phantom handlers for our EUI ~5s after every permit with ZERO OTA trigger (8 consecutive runs, sniffer-proven). Survives resetNode (RESET_SOFTWARE confirmed) + USB deauth/reauth. ALL v13-readable state pristine (bellows info identical x3 snapshots, policies/tables empty) — stealth lives in token-or-deeper state with no v13 read/erase primitive. Secondary finding: TC answers assoc with an UNSECURED vendor APS CMD 0x30 (level-0 aux, plaintext) and never sends 0x05 transport — repo work queued to model level-0 RX.
- Impact: MG24 unusable as interop peer until cleared; v8 probe ladder is built/flashed and ready for RUN12 after restore. No join completed (11 runs + 2 verifies, honest partial). C6 + repo untouched (97A4 restored, tree clean). Evidence: ~/hwscratch/zbjoin/ (durable: run logs, captures, 7 MG24 snapshots, triage scripts).
- Needed from human: (1) approve MG24 tokenFactoryReset and/or reflash — DESTRUCTIVE: kills PAN A4D3 including our own MG21-dongle membership (0x9766, confirmed pre-existing lab gear, not foreign) — confirm acceptable, or provide an alternate clear procedure. (2) Peer hygiene: after reset, advise whether to rejoin the MG21 dongle to the PAN or leave the coordinator clean for interop.
- Lab policy meanwhile: NO further join attempts against MG24 until human clears (avoid deeper state); MG24 left powered, network unmodified. Interop pivots to C6↔C6 classical join meanwhile.
- Update 2026-10-28 (head, wave-32): 0x9766 attribution now CONTESTED — MG21 tokens read empty on 3 independent v13 probes (nodeType 0x81 unconfigured, PAN 0x0000, key_set=false, NOT_JOINED; before/verify sha256 ae9c6513 identical) yet 0x9766 was overheard on A4D3 the same day (route3 beacons 06:56, gpota macsrc 08:08); either attribution was wrong (0x9766 = another bench device) or tokens were cleared by an unrecorded event. Follow-up: sniffer-capture 0x9766 DeviceAnnce/assoc EUI. MG21 itself is a clean healthy formation-capable EZSP-v13 NCP (EmberZNet 7.4.4, EUI 04:e3:e5:ff:fe:f4:75:5f) — real-coordinator join pivots to MG21 with form+leave, MG24 stays untouched. Evidence: ~/hwscratch/mg21join/.
- Correction 2026-10-28 (head, wave-33): 0x9766 attribution DISPROVEN — passive ch15 capture resolved 0x9766 to EUI b4:89:31:ff:fe:94:62:89, an established ROUTER with child 0xcb2f on PAN A4D3; it is neither our MG21 (EUI 04:e3:e5:ff:fe:f4:75:5f, tokens empty) nor any lab C6. A foreign/bench Zigbee device shares A4D3. The MG24-reset approval stands and now additionally clears this unknown member. Evidence: ~/hwscratch/mg21form/sniff_ch15.txt.
- Update 2026-10-28 (head, wave-35): approved tokenFactoryReset EXECUTED (exit 0, empty bar met: 0xFFFE/NO_NETWORK/PAN0/NOT_JOINED/key_set=false) but stealth SURVIVES at firmware level — clean-formed PAN 0xC1EA ch20 still emits permit-closed beacons (624+ across run12a/b/c2), 56/56 assoc denies 0x02, phantom trustCenterJoinHandlers. Cure now = reflash with known-good stock NCP .gbl (none on hand; procurement queued wave-36). MG24 left EMPTY (leave+reset verified). Evidence: ~/hwscratch/mg24run12/.
- Verdict 2026-10-28 (head, wave-37): RECOVERED, trigger undetermined. Both sticks factory-reset via bellows + clean-formed (MG21 PAN 0x3761/ch25, MG24 PAN 0x3764/ch20) and PASS open-beacon checks (50+/70 OPEN each, 0 phantoms) — wave-35/36 stealth verdicts SUPERSEDED. Recovery-trigger candidates: this wave's reset+form sequence, ASH-reset accumulation, idle-time NCP recovery. Both left FORMED-CLEAN as lab TCs (record: ~/hwscratch/w37/networks.txt, 0600). H1/H2/H1H2 fired and KILLED against the clean MG21 (0x05 never sent, tkey in=0/out=0); new hypothesis (c) (TC never evaluates joiner APS) needs NCP-side probing. Evidence: ~/hwscratch/w37/. Reopen on stealth recurrence.

### B-005 (2026-10-30): Beacon superframe/TxOffset vs Ember scan parser
Status: CLOSED (fixed w92 — first Ember discovery 2026-10-31, see verdict).
- Symptom: MG24 never discovers PAN 0xC601 (6 active scans, 0 hits incl. a 16 s scan with ~13 permit-open C601 beacons provably on air). Ember scan parser drops our beacons deterministically.
- Root cause (rung-3 evidence ~/hwscratch/w87-rung3/): our beacon mixes nonbeacon markers (BO=15) with beaconed-network fields (SO=0, TxOffset=0x000000); all foreign beacons carry SO=15 + TxOffset=0xFFFFFF. Fix: superframe 0xCF0F → 0xCFFF, TxOffset → 0xFFFFFF (both in `rounddance-inspect/src/mac.rs` beacon builder + `hal-esp` mirror + goldens).
- Note: report says "somebody reflashed 7F68 after w87" — that was the head-side rung-2 re-climb flash (rd-coord-w87d, 1f0439fc…), not a third party.
- Verdict 2026-10-31 (head, w92): FIXED. Standalone active scans report `panId=0xC601 ... allowingJoin=true, stackProfile=2, LQI 255, -35 dBm` repeatedly (stack byte 0x02 → 0x22 also landed). Evidence ~/hwscratch/w92-rung3c/ (`mg24_scan_ch15*.log`, prescan hits). Discovery no longer the gate; join now fails later (see B-006).

### B-006 (2026-10-31): Ember post-assoc JOIN_FAILED + NCP scan flakiness
Status: CLOSED (join path proven 2026-10-31, w94 — see verdict).
- w94 root causes, all fixed + air-verified: (1) assoc-rsp short-source
  (`63 8c`) rejected post-association → long-source `63 cc` (`152e2bd`,
  MG21 wire bytes pinned); (2) no Transport-Key → implemented
  (`c5c9882`: CCM* MIC-32 + HA-derived key, golden pinned from the
  independent Python model, app pending/take/rearm, fw TX branch).
- Verdict: NCP reports `NETWORK_UP (144)`, `END_DEVICE`, C601, short
  0x0002, `JOINED_NETWORK` — 4× (join2/joinR/joinS/joinT). Coord serial
  shows RX-ASSOCREQ → TX-ASSOC-RSP → TX-TRANSPORT-KEY (+Delivered);
  sniffer confirms req (+HW ACK ~1 ms), RSP, transport on air; the NCP's
  post-join uplink is NWK-secured with our key (key adoption proven).
  Evidence ~/hwscratch/w94/SUMMARY.md + coord/sniff/join logs.
- NCP internal-scan flakiness stands (mitigated by pre-scan retry loop).

### B-007 (2026-10-31): joined NCP drops within minutes (retention)
Status: QUARANTINED 2026-10-31 (stick-level verdict — join itself is proven; post-join loss is the unit under test).
- Symptom: all 6 joins this campaign drop to `NO_NETWORK/0xFFFE`
  (key retained: `network_key_set=true`) within minutes, then silence:
  exactly one NWK-secured uplink ~85 ms post-transport, then zero polls,
  zero rejoin scans, nothing addressed to the joiner (660 s audit).
- Excluded: host contact (zero-touch 4-min + 10-min watches),
  USB power/events (no dmesg USB lines, no by-id re-enumeration,
  autosuspend already `on`), our coordinator (control arm: identical
  drop from the reference MG21 TC after a textbook join with annce +
  follow-ups), NCP state dirt (factory-reset before each run).
- Leading hypothesis CONFIRMED as NCP-side (w95+w96): drop window pinned
  <13 s post-NETWORK_UP (EMPTY at first 5 s dump); zero-touch watches
  exclude observer effect; reference-TC control drops identically;
  no rejoin scan ever (local reset-to-empty signature, not a protocol
  path). w96 update: RSP source now wire-order on air (MG21-identical,
  `68 7f...`); NCP still drops identically → source order was never
  the retention cause (closes that candidate). Confirm-driven TX retry
  added (NoAck/ChannelBusy re-pend, bounded 4x) after a proven w96
  NoAck-transport + JOIN_FAILED instance. Next: reflash prepared
  (~/hwscratch/w96/b007-reflash-prep.md — target identity, image
  options, exact procedure; DO NOT EXECUTE without explicit user
  approval of the image + the destructive flash).

- VERDICT b007 (NCP reflash executed under destructive approval):
  official Sonoff `dongle-pmg24_zigbee_ncp_8.2.2.0_460800_sw_flow.gbl`
  (sha256-pinned, tool-validated NCP-UART image) flashed cleanly;
  EUI preserved, EZSP v18 live. Result: joins fine (NETWORK_UP,
  holds 32–60 s vs <13 s on 7.4.5.0) then drops IDENTICALLY —
  against our C601 (2x) AND against the reference MG21 TC (10-min
  zero-touch watch, EMPTY t+1..t+10, textbook join with annce + MG21
  follow-up). 2 firmwares x 2 coordinators: the NCP image is ruled
  out, our stack is ruled out as sole cause. Unit quarantined
  (this MG24 stick; MG21 + C6 coordinators hold their networks
  indefinitely). Pivot interop to the next peer (MG21-as-joiner vs
  C601 per Phase 5). Evidence ~/hwscratch/b007/.
- Lab at w96 closeout: 7F68 restored byte-identical to preflash backup
  (0 diff bytes); MG24 factory-reset EMPTY; MG21 left FORMED
  (documented lab-TC state); leases none, quarantine none. Evidence:
  ~/hwscratch/w96/ (observed join with full callbacks, RSP wire-order
  air proof, retry fw, reflash prep).

### B-008 (2026-10-31): coordinator fw crash — ESP-IDF 15.4 driver assert
Status: CLOSED 2026-10-31 (fix air-proven; mechanism root-caused in IDF source + our hook).
- Symptom (4× in b007, zero in all prior waves): `assert failed:
  isr_handle_tx_abort esp_ieee802154_dev.c:711
  (s_ieee802154_state == IEEE802154_STATE_RX_ACK)` → `rst:0xc
  (SW_CPU)` reboot. Each crash lands in the post-join beacon phase
  (beacon-req → TX-BEACON → confirm → assert); beacon volume in b007
  (300 reqs) was LOWER than crash-free w98/w99 (560+), and the NCP
  sends zero polls on either firmware — not a TX storm.
- Suspect: ESP-IDF driver ISR race (beacon TX abort colliding with an
  in-flight ACK RX). Deltas in b007 vs crash-free runs: NCP peer on
  8.2.2.0 (different ACK timing?) and a rebuilt fw image (code-layout
  shift moving the race window). Both unproven — needs driver-level
  investigation (backoff/pacing experiments around beacon TX), not a
  blind retry-loop change.
- Impact: every crash reboots the coordinator (replay table, aux
  counter, permit state all reset), which INVALIDATES any multi-join
  air proof attempted in a crash window (b007 joinNEW2 join4 Annce is
  void for the replay fix for exactly this reason).
- Evidence: ~/hwscratch/b007/coord3.log (4 assert+dump+`rst:0xc`+reboot
  cycles at lines ~70/124, ~434/488, ~1127/1239, ~1482/1594).


- CLOSED b008: our `transmit_done` hook never released the driver ACK
  buffer (header-mandated `receive_handle_done`), leaking one RX slot
  per ACKed TX into the abort path that asserted. One-line ISR fix;
  air proof: 2 joins same boot + 10-min beacon soak, zero asserts
  (was 4/4), auxctr chain 0x1000→0x1004 proves one boot. The same
  run air-proved the replay fix (join-2 Annce classifies).
  Evidence ~/hwscratch/b008/.