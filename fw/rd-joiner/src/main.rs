//! rd-joiner: C6-standalone joiner firmware (Phase 3 leg 1: scan + assoc).
//!
//! The repo [`JoinerApp`](rounddance_hal_esp::JoinerApp) composed over
//! [`EspIdfDriver`](rounddance_hal_esp::EspIdfDriver) via
//! [`EspAdapter`](rounddance_hal_esp::EspAdapter), flashed as one C6
//! image onto the joiner unit (97A4). This leg scans (beacon-req TX,
//! beacon survey through [`JoinerApp::on_mac_psdu`]) and associates
//! (assoc-req TX, assoc-rsp handoff). Transport-key open, annce, and
//! data live in follow-up legs; after the assoc-rsp the image idles
//! (still pumping + logging) so the air proof stays clean.
//!
//! Phase 2 owns flashing (backup-first, lease, by-id); this crate only
//! builds the image.

use esp_idf_hal::gpio::PinDriver;
use esp_idf_hal::peripherals::Peripherals;
use rounddance_hal_esp::app::{
    eui_from_mac, log_air, role_from_mac, JoinerNwkOutcome, UNASSOC_SHORT,
};
use rounddance_hal_esp::mac_cmd::Incoming as MacIncoming;
use rounddance_hal_esp::{AppRole, EspAdapter, EspIdfDriver, JoinerApp, SerialLog};
use rounddance_mac_sap::{Channel, MacDataSap, MacMgmtSap, TxHandle, TxStatus};
use rounddance_zcl::onoff;
use std::time::Instant;

// Scan channel: default C601 lab network (ch15); override at build
// time with `RD_JOINER_SCAN_CHANNEL=<11-26>` (no source edit, no
// second constant to drift — the MG21-reference leg builds 25).
// Invalid values fail the build loudly, never silently mistune.
const fn parse_channel(s: &str) -> u8 {
    let b = s.as_bytes();
    let mut i = 0;
    let mut v: u8 = 0;
    while i < b.len() {
        assert!(
            b[i] >= b'0' && b[i] <= b'9',
            "RD_JOINER_SCAN_CHANNEL not decimal"
        );
        v = v * 10 + (b[i] - b'0');
        i += 1;
    }
    assert!(v >= 11 && v <= 26, "RD_JOINER_SCAN_CHANNEL out of 11-26");
    v
}
const JOINER_SCAN_CHANNEL: u8 = match option_env!("RD_JOINER_SCAN_CHANNEL") {
    Some(s) => parse_channel(s),
    None => 15,
};
// Beacon-req / assoc-req retry cadence while unassociated.
const REQ_INTERVAL_MS: u64 = 2_000;
// Stop re-transmitting the assoc-req after this many tries (the
// coordinator answers in one when healthy; silence past this bound
// is evidence, not a reason to burn the band).
const ASSOC_RETRIES_MAX: u32 = 30;

// See rd-coord for the `esp_read_mac` rationale (never
// `esp_efuse_mac_get_default` on 802.15.4 chips).
const ESP_MAC_BASE: u32 = 5;
unsafe extern "C" {
    fn esp_read_mac(mac: *mut u8, type_: u32) -> i32;
}

/// [`SerialLog`] over the IDF console (USB-Serial-JTAG on the C6).
struct ConsoleLog;

impl SerialLog for ConsoleLog {
    fn log(&mut self, line: &str) {
        println!("{line}");
    }
}

static LAMP_DEF: onoff::ServerDef = onoff::ServerDef;

fn main() {
    let peripherals = Peripherals::take().expect("peripherals");
    let mut ant3 = PinDriver::output(peripherals.pins.gpio3).expect("gpio3");
    let mut ant14 = PinDriver::output(peripherals.pins.gpio14).expect("gpio14");
    ant3.set_low().expect("ant3 low");
    ant14.set_low().expect("ant14 low");

    // Role gate BEFORE the radio: only the verified lab joiner unit
    // (97A4) boots this image; anything else refuses silently.
    let mut mac = [0u8; 6];
    let rc = unsafe { esp_read_mac(mac.as_mut_ptr(), ESP_MAC_BASE) };
    assert!(rc == 0, "esp_read_mac BASE rc={rc}");
    let eui = eui_from_mac(&mac);
    println!("RDJOIN ident mac={mac:02x?} eui={eui:02x?}");
    println!("RDJOIN scan ch={JOINER_SCAN_CHANNEL}");
    if role_from_mac(&mac) != Some(AppRole::Joiner) {
        println!("RDJOIN refuse: not the joiner unit, radio untouched");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }

    let mut log = ConsoleLog;
    // Heap-box the two giants: EspAdapter (~7.5 K) + JoinerApp
    // (~4.8 K) together overflow the 16 K main-task stack when both
    // sit in main's frame (w97 joiner boot-loop: stack protection
    // fault at app_main entry; the coordinator's smaller app just
    // fits). Box::leak gives 'static refs with no lifetime juggling;
    // peak stack drops to one construction at a time.
    let adapter: &'static mut EspAdapter<EspIdfDriver> =
        Box::leak(Box::new(EspAdapter::new(EspIdfDriver::new())));
    // Unassociated identity: no PAN, no short, our long address (so
    // the coordinator's long-addressed assoc-rsp passes the filter
    // with hardware auto-ACK, same as the NCP path).
    adapter.set_pan_id(0xFFFF);
    adapter.set_short_addr(UNASSOC_SHORT);
    // Radio address match compares arrival order (LSB-first on air):
    // program the EUI in wire order, not display order. Display order
    // here silently disables HW ACKs for long-addressed inbound
    // frames (w97 C601 leg: coordinator RSPs got NoAck).
    let mut ext = eui;
    ext.reverse();
    adapter.set_extended_addr(u64::from_le_bytes(ext));
    adapter.set_tx_power(10).expect("standing +10 dBm cap");
    adapter.init().expect("radio init");
    let ch = Channel::new(JOINER_SCAN_CHANNEL).expect("scan channel 11-26");
    adapter.set_channel(ch).expect("tune scan channel");

    let app: &'static mut JoinerApp<'static> =
        Box::leak(Box::new(JoinerApp::new(&LAMP_DEF).expect("joiner app")));
    app.begin_scan(&mut log).expect("begin scan");
    // The startup window is open from here (expect() above guarantees
    // it); the loop closes it after the first collection interval.
    let mut scan_open = true;

    let mut tx_buf = [0u8; 160];
    // 160 B: the largest single frame this leg builds is a secured
    // NWK data frame (9 MAC + 8 NWK + 14 aux + ~100 payload + 4 MIC).
    let mut mac_seq: u8 = 0;
    // Scan-cycle state: begin_scan opens a window, beacons ingest
    // through on_mac_psdu, and finish_scan elects once the window
    // elapses (w97: finishing per-beacon parks the table on the first
    // non-permit neighbour). A window with no candidate re-opens
    // immediately — the joiner scans until it elects.
    // Window protocol (w103: open and close must BRACKET a collection
    // interval — calling begin+finish back-to-back finishes an empty
    // table every window and wedges unelected forever, as 51
    // zero-election windows on air proved). `scan_open` tracks which
    // half of the protocol we are in (starts true: the startup window
    // above is already collecting).
    let mut last_scan_ms: u64 = 0;
    const SCAN_WINDOW_MS: u64 = 4_000;
    let mut last_req_ms: u64 = 0;
    let mut assoc_tries: u32 = 0;
    let mut assoc_done_logged = false;
    // PAN adopted from the elected candidate (0xFFFF until then).
    // The radio's hardware filter drops unicast frames for a foreign
    // PAN — without this the coordinator's assoc-rsp never reaches
    // the app (w97 C601 leg: RSPs on air, joiner deaf, NoAck storm).
    let mut adopted_pan: Option<u16> = None;
    // Short address adopted from the assoc-rsp (0xFFFF until then).
    // Same filter class as the PAN: the Trust-Center transport-key
    // is unicast to the assigned short, so the radio must learn it
    // or the key delivery never arrives (w98 leg 2).
    let mut adopted_short: Option<u16> = None;
    // Announce once the Trust-Center key is adopted.
    let mut annce_pending = false;
    // Joiner ZDO-answer retry state (Phase 4, mirrors the annce and
    // coordinator patterns): the Node_desc_rsp is unicast to the TC,
    // so a non-Delivered confirm means the TC never saw it — rebuild
    // (fresh auxctr + same echoed TSN) and re-TX, bounded.
    let mut rsp_pending: Option<(u16, u8, u16)> = None;
    // Last request params (rebuild source for retries: same echoed
    // TSN, fresh auxctr — never an identical re-TX).
    let mut rsp_req: Option<(u16, u8, u16)> = None;
    let mut rsp_handle: Option<TxHandle> = None;
    let mut rsp_tries: u8 = 0;
    const RSP_RETRIES_MAX: u8 = 4;
    // Announce retry state (w103: broadcasts report radiation via
    // confirms too — two consecutive annces vanished on a congested
    // channel with no FAILED line because the fw dropped confirms
    // unread. Bounded re-TX on any non-Delivered outcome).
    let mut annce_handle: Option<TxHandle> = None;
    let mut annce_tries: u8 = 0;
    const ANNCE_RETRIES_MAX: u8 = 4;
    let start = Instant::now();
    loop {
        adapter.pump();
        let now_ms = start.elapsed().as_millis() as u64;
        // Windowed scan: open the window, collect beacons across
        // loop iterations, then finish + elect once the window
        // elapses. Open and close are opposite halves of one window
        // (see `scan_open`): finishing in the same iteration as
        // opening would always rank an empty table.
        if app.candidate_pan().is_none() {
            if !scan_open && now_ms.wrapping_sub(last_scan_ms) >= SCAN_WINDOW_MS {
                last_scan_ms = now_ms;
                match app.begin_scan(&mut log) {
                    Ok(()) => scan_open = true,
                    // Already scanning (steering still holds the window
                    // this flag desynced from): treat as open so the
                    // close half still runs on schedule.
                    Err(_) => scan_open = true,
                }
            } else if scan_open && now_ms.wrapping_sub(last_scan_ms) >= SCAN_WINDOW_MS {
                last_scan_ms = now_ms;
                scan_open = false;
                if let Some(pan) = app.finish_scan(&mut log) {
                    println!("RDJOIN CANDIDATE pan={pan:#06x}");
                }
            }
        }
        // MAC-command RX: beacon survey + assoc-rsp handoff, logged.
        while let Some(ind) = adapter.poll_mac_indication() {
            let psdu = ind.psdu();
            log_air(&mut log, "RDJOIN RX-MAC", psdu);
            match app.on_mac_psdu(&mut log, psdu, ind.channel_number(), ind.rssi(), ind.lqi()) {
                MacIncoming::Beacon(bi) => {
                    println!(
                        "RDJOIN RX-BEACON pan={:#06x} permit={} rssi={} lqi={}",
                        bi.src_pan,
                        bi.assoc_permit,
                        ind.rssi(),
                        ind.lqi()
                    );
                    if let Some(pan) = app.candidate_pan() {
                        println!("RDJOIN CANDIDATE pan={pan:#06x}");
                    }
                }
                MacIncoming::AssocRsp(rsp) => {
                    println!(
                        "RDJOIN RX-ASSOC-RSP short={:#06x} status={:#04x}",
                        rsp.short, rsp.status
                    );
                }
                _ => {}
            }
        }
        if app.assoc_short().is_none()
            && assoc_tries < ASSOC_RETRIES_MAX
            && now_ms.wrapping_sub(last_req_ms) >= REQ_INTERVAL_MS
        {
            last_req_ms = now_ms;
            if let Some(pan) = app.candidate_pan() {
                // Adopt the elected PAN first: without this the radio
                // filters out the unicast assoc-rsp (w97 C601 leg).
                if adopted_pan != Some(pan) {
                    adapter.set_pan_id(pan);
                    adopted_pan = Some(pan);
                    println!("RDJOIN ADOPTED pan={pan:#06x}");
                }
                // Associated-candidate known: ask to join it.
                match app.take_assoc_req(&mut tx_buf, pan) {
                    Ok(n) if n > 0 => {
                        log_air(&mut log, "RDJOIN TX-ASSOC-REQ", &tx_buf[..n]);
                        if let Err(e) = adapter.transmit_mac(&tx_buf[..n]) {
                            println!("RDJOIN TX-ASSOC-FAILED {e:?}");
                        } else {
                            assoc_tries += 1;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => println!("RDJOIN ASSOC-BUILD-FAILED {e:?}"),
                }
            } else {
                // No candidate yet: keep soliciting beacons.
                mac_seq = mac_seq.wrapping_add(1);
                match rounddance_hal_esp::mac_cmd::build_beacon_req(mac_seq, &mut tx_buf) {
                    Ok(n) => {
                        log_air(&mut log, "RDJOIN TX-BEACON-REQ", &tx_buf[..n]);
                        if let Err(e) = adapter.transmit_mac(&tx_buf[..n]) {
                            println!("RDJOIN TX-BEACON-REQ-FAILED {e:?}");
                        }
                    }
                    Err(e) => println!("RDJOIN BEACON-REQ-BUILD-FAILED {e:?}"),
                }
            }
        } else if let Some(short) = app.assoc_short() {
            if adopted_short != Some(short) {
                adopted_short = Some(short);
                adapter.set_short_addr(short);
                println!("RDJOIN ADOPTED-SHORT short={short:#06x}");
            }
            if !assoc_done_logged {
                assoc_done_logged = true;
                println!("RDJOIN ASSOC-DONE short={short:#06x} (waiting for Trust-Center key)");
            }
        }
        // NWK RX: Trust-Center key open (adopt) + post-adoption
        // dispatch (ZDO answers). Sealed frames only; anything else
        // is counted, never latched.
        while let Some(ind) = adapter.poll_indication() {
            log_air(&mut log, "RDJOIN RX-NWK", ind.msdu.as_slice());
            match app.on_nwk_joiner(ind.msdu.as_slice()) {
                JoinerNwkOutcome::TransportAccepted { auxctr } => {
                    println!("RDJOIN TRANSPORT-OPEN auxctr={auxctr:#010x}");
                    annce_pending = true;
                    // Fresh delivery, fresh announce budget (a rejoin
                    // later in this boot must not inherit exhaustion).
                    annce_handle = None;
                    annce_tries = 0;
                }
                JoinerNwkOutcome::NodeDescReq {
                    src_short,
                    tsn,
                    subject,
                } => {
                    println!("RDJOIN RX-NODE-DESC-REQ tsn={tsn}");
                    // Queue (do not build inline): the send block
                    // below transmits, and the confirm arm re-queues
                    // on non-Delivered so a ChannelBusy loss on this
                    // congested channel is retried, not silent.
                    rsp_req = Some((src_short, tsn, subject));
                    rsp_pending = rsp_req;
                    rsp_handle = None;
                    rsp_tries = 0;
                }
                JoinerNwkOutcome::Data { cluster, profile } => {
                    println!("RDJOIN RX-NWK-DATA cluster={cluster:#06x} profile={profile:#06x}");
                }
                JoinerNwkOutcome::NwkCommand { id } => {
                    println!("RDJOIN RX-NWK-CMD id={id:#04x}");
                }
                JoinerNwkOutcome::Ignored(why) => {
                    println!("RDJOIN RX-NWK-IGNORED {why:?}");
                }
            }
        }
        // Announce while the key is adopted: build once per attempt,
        // transmit, and retire only on a Delivered confirm (or the
        // retry budget). Close-out is gated on radiated proof, not on
        // submit success (w103: two submits Ok'd yet nothing reached
        // air on a congested channel — confirms were dropped unread).
        if annce_pending && annce_handle.is_none() {
            if annce_tries >= ANNCE_RETRIES_MAX {
                println!("RDJOIN ANNCE-GIVEUP tries={annce_tries} (proceeding joined-locally)");
                annce_pending = false;
                app.verify_confirm(&mut log);
                app.close_out(&mut log);
            } else {
                match app.take_annce(&mut tx_buf) {
                    Ok(n) if n > 0 => {
                        log_air(&mut log, "RDJOIN TX-ANNCE", &tx_buf[..n]);
                        match adapter.transmit_mac(&tx_buf[..n]) {
                            Ok(h) => {
                                annce_handle = Some(h);
                                annce_tries += 1;
                            }
                            Err(e) => println!("RDJOIN TX-ANNCE-FAILED {e:?}"),
                        }
                    }
                    Ok(_) => {
                        // Nothing to announce (key or short missing).
                        annce_pending = false;
                    }
                    Err(e) => println!("RDJOIN ANNCE-BUILD-FAILED {e:?}"),
                }
            }
        }
        // ZDO answer transmit: build once per attempt from the queued
        // request, retire only on a Delivered confirm (or the retry
        // budget). Same pattern as the annce block above.
        if let Some((dst_short, tsn, subject)) = rsp_pending {
            if rsp_handle.is_none() {
                if rsp_tries >= RSP_RETRIES_MAX {
                    println!("RDJOIN TX-RSP-GIVEUP tsn={tsn} (budget exhausted)");
                    rsp_pending = None;
                } else {
                    match app.take_node_desc_rsp(&mut tx_buf, dst_short, tsn, subject) {
                        Ok(n) if n > 0 => {
                            log_air(&mut log, "RDJOIN TX-NODE-DESC-RSP", &tx_buf[..n]);
                            match adapter.transmit_mac(&tx_buf[..n]) {
                                Ok(h) => {
                                    rsp_handle = Some(h);
                                    rsp_tries += 1;
                                }
                                // Submit-time refusal re-pends (mirrors
                                // the transport path): the confirm path
                                // drives the retry budget, not this arm.
                                Err(e) => {
                                    println!("RDJOIN TX-RSP-FAILED {e:?}; re-armed");
                                    rsp_pending = Some((dst_short, tsn, subject));
                                }
                            }
                        }
                        Ok(_) => {
                            // Nothing to answer with (key or short
                            // missing); do not spin.
                            rsp_pending = None;
                        }
                        Err(e) => println!("RDJOIN RSP-BUILD-FAILED {e:?}"),
                    }
                }
            }
        }
        // TX confirms drain (shared queue): match our annce handle so
        // a non-Delivered broadcast is retried above instead of lost,
        // and our RSP handle so a lost ZDO answer is rebuilt.
        while let Some(c) = adapter.poll_confirm() {
            if Some(c.handle) == annce_handle {
                println!("RDJOIN ANNCE-CONFIRM {:?} tries={annce_tries}", c.status);
                annce_handle = None;
                if c.status == TxStatus::Delivered {
                    annce_pending = false;
                    app.verify_confirm(&mut log);
                    app.close_out(&mut log);
                }
            }
            if Some(c.handle) == rsp_handle {
                println!("RDJOIN RSP-CONFIRM {:?} tries={rsp_tries}", c.status);
                rsp_handle = None;
                if c.status == TxStatus::Delivered {
                    // Answered and radiated: retire (a duplicate
                    // answer would only triple-count on air).
                    rsp_pending = None;
                    rsp_req = None;
                } else if rsp_tries > 0 {
                    rsp_tries -= 1;
                    println!("RDJOIN TX-RSP-NOACK; re-armed ({rsp_tries} left)");
                    rsp_pending = rsp_req;
                } else {
                    println!("RDJOIN TX-RSP-GIVEUP (budget exhausted)");
                    rsp_req = None;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
