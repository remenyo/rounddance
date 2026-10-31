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
use rounddance_hal_esp::app::{eui_from_mac, log_air, role_from_mac, UNASSOC_SHORT};
use rounddance_hal_esp::mac_cmd::Incoming as MacIncoming;
use rounddance_hal_esp::{AppRole, EspAdapter, EspIdfDriver, JoinerApp, SerialLog};
use rounddance_mac_sap::{Channel, MacDataSap, MacMgmtSap};
use rounddance_zcl::onoff;
use std::time::Instant;

// Scan channel: C601 lab network (ch15). Rebuild with 25 for an
// MG21-reference attempt.
const JOINER_SCAN_CHANNEL: u8 = 15;
// Beacon-req / assoc-req retry cadence while unassociated.
const REQ_INTERVAL_MS: u64 = 2_000;
// Re-scan cadence while unelected: the first beacons may arrive
// with permit closed (or park the table NoSuitableNetwork); without
// this the joiner latches onto the first scan forever and ignores
// later open beacons (w97 MG21 leg).
const SCAN_RETRY_MS: u64 = 10_000;
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
    adapter
        .set_tx_power(10)
        .expect("standing +10 dBm cap");
    adapter.init().expect("radio init");
    let ch = Channel::new(JOINER_SCAN_CHANNEL).expect("scan channel 11-26");
    adapter.set_channel(ch).expect("tune scan channel");

    let app: &'static mut JoinerApp<'static> =
        Box::leak(Box::new(JoinerApp::new(&LAMP_DEF).expect("joiner app")));
    app.begin_scan(&mut log).expect("begin scan");

    let mut tx_buf = [0u8; 32];
    let mut mac_seq: u8 = 0;
    let mut last_req_ms: u64 = 0;
    let mut last_scan_ms: u64 = 0;
    let mut assoc_tries: u32 = 0;
    let mut assoc_done_logged = false;
    // PAN adopted from the elected candidate (0xFFFF until then).
    // The radio's hardware filter drops unicast frames for a foreign
    // PAN — without this the coordinator's assoc-rsp never reaches
    // the app (w97 C601 leg: RSPs on air, joiner deaf, NoAck storm).
    let mut adopted_pan: Option<u16> = None;
    let start = Instant::now();
    loop {
        adapter.pump();
        let now_ms = start.elapsed().as_millis() as u64;
        // Periodic rescan while unelected (see SCAN_RETRY_MS): safe
        // from any parked state; a no-op while already scanning.
        if app.candidate_pan().is_none()
            && now_ms.wrapping_sub(last_scan_ms) >= SCAN_RETRY_MS
        {
            last_scan_ms = now_ms;
            match app.begin_scan(&mut log) {
                Ok(()) => println!("RDJOIN RESCAN"),
                Err(_) => {} // already scanning; keep collecting
            }
        }
        // MAC-command RX: beacon survey + assoc-rsp handoff, logged.
        while let Some(ind) = adapter.poll_mac_indication() {
            let psdu = ind.psdu();
            log_air(&mut log, "RDJOIN RX-MAC", psdu);
            match app.on_mac_psdu(
                &mut log,
                psdu,
                ind.channel_number(),
                ind.rssi(),
                ind.lqi(),
            ) {
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
            if !assoc_done_logged {
                assoc_done_logged = true;
                println!(
                    "RDJOIN ASSOC-DONE short={short:#06x} (transport open is the next leg)"
                );
            }
        }
        // TX confirms drain (shared queue); joiner ignores outcomes
        // this leg, but the queue must not wedge.
        while adapter.poll_confirm().is_some() {}
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
