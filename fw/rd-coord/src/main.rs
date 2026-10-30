//! rd-coord: C6-standalone coordinator firmware.
//!
//! Rung-2 radiate binding (MVP FIX): the repo
//! [`CoordinatorApp`](rounddance_hal_esp::CoordinatorApp) composed over
//! [`EspIdfDriver`](rounddance_hal_esp::EspIdfDriver) via
//! [`EspAdapter`](rounddance_hal_esp::EspAdapter), flashed as one C6
//! image. Host proof of the app logic lives in
//! `crates/rounddance-hal-esp/tests/coord_radiate.rs` (adapter MAC
//! routing + app permit/allow + pacing) and `c6_standalone.rs`
//! (mock-to-mock air); this crate only binds it to the board:
//! NVS-first radio init, onboard-ceramic antenna select, role gate on
//! the verified lab pair, formation, permit window, promiscuous MAC
//! RX, and the radiate pump (solicited beacon / assoc-response TX
//! plus gratuitous beacons while unassociated).
//!
//! Phase 2 owns flashing (backup-first, lease, by-id); this crate only
//! builds the image.

use esp_idf_hal::gpio::PinDriver;
use esp_idf_hal::peripherals::Peripherals;
use rounddance_hal_esp::app::{
    eui_from_mac, log_air, role_from_mac, APP_CHANNEL, APP_PAN, COORD_SHORT,
};
use rounddance_hal_esp::mac_cmd::{gratuitous_due, GRATUITOUS_BEACON_INTERVAL_MS};
use rounddance_hal_esp::{AppRole, CoordinatorApp, EspAdapter, EspIdfDriver, SerialLog};
use rounddance_mac_sap::{Channel, MacDataSap, MacMgmtSap};
use std::time::Instant;

// esp-idf-sys 0.38 ships no binding for this symbol (same reason the
// scratch image declares the 15.4 externs itself); signature matches
// the IDF v6.1 `esp_efuse.h` header.
unsafe extern "C" {
    fn esp_efuse_mac_get_default(mac: *mut u8) -> i32;
}

/// [`SerialLog`] over the IDF console (USB-Serial-JTAG on the Xiao C6).
struct ConsoleLog;

impl SerialLog for ConsoleLog {
    fn log(&mut self, line: &str) {
        println!("{line}");
    }
}

fn main() {
    // `EspIdfDriver::init` runs `link_patches` + NVS-first init before
    // touching the radio; antenna select stays board-side here.
    let peripherals = Peripherals::take().expect("peripherals");
    let mut ant3 = PinDriver::output(peripherals.pins.gpio3).expect("gpio3");
    let mut ant14 = PinDriver::output(peripherals.pins.gpio14).expect("gpio14");
    ant3.set_low().expect("ant3 low");
    ant14.set_low().expect("ant14 low");

    // Role gate BEFORE the radio: only the verified lab coordinator
    // unit (healthy 7F68, full base-MAC compare) boots this image;
    // anything else refuses without transmitting.
    let mut mac = [0u8; 6];
    let rc = unsafe { esp_efuse_mac_get_default(mac.as_mut_ptr()) };
    assert!(rc == 0, "efuse mac rc={rc}");
    let eui = eui_from_mac(&mac);
    println!("RDCOORD ident mac={mac:02x?} eui={eui:02x?}");
    if role_from_mac(&mac) != Some(AppRole::Coordinator) {
        println!("RDCOORD refuse: not the coordinator unit, radio untouched");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }

    let mut log = ConsoleLog;
    let mut adapter = EspAdapter::new(EspIdfDriver::new());
    // Staged pre-init; `init` programs them into the driver in the
    // NVS-first order (filtering ON, RX-when-idle, receiver running).
    adapter.set_pan_id(APP_PAN);
    adapter.set_short_addr(COORD_SHORT);
    adapter.set_extended_addr(u64::from_le_bytes(eui));
    adapter
        .set_tx_power(10)
        .expect("standing +10 dBm cap");
    adapter.init().expect("radio init");
    // `set_channel` needs a live driver: retune explicitly post-init
    // even though the default already matches, so the air channel is
    // asserted, not assumed.
    let ch = Channel::new(APP_CHANNEL).expect("app channel 11-26");
    adapter.set_channel(ch).expect("tune ch15");
    // Coordinator RX must be promiscuous: broadcast beacon-requests
    // never pass the hardware filter.
    adapter.set_promiscuous(true).expect("promiscuous");

    // Formation conflict-check: ED scan first, then mark formed.
    match adapter.energy_scan(ch) {
        Ok(ed) => println!("RDCOORD ed ch15={ed}"),
        Err(e) => println!("RDCOORD ed-failed {e:?}"),
    }
    let mut app = CoordinatorApp::new();
    app.begin_formation(&mut log).expect("formation");
    app.formation_done(&mut log, true);
    // Bounded permit window; the MAC responder permit + allow-list are
    // wired inside the app (`open_permit` / `admit_joiner`).
    app.open_permit(&mut log, 600_000).expect("permit");

    let start = Instant::now();
    let mut last_grat_ms: u64 = 0;
    let mut last_tick_ms: u64 = 0;
    let mut tx_buf = [0u8; 32];
    loop {
        adapter.pump();
        let now_ms = start.elapsed().as_millis() as u64;
        // Age the permit window (keeps the MAC permit bit in sync).
        let elapsed = now_ms.wrapping_sub(last_tick_ms);
        if elapsed > 0 {
            app.tick(now_ms, elapsed);
            last_tick_ms = now_ms;
        }
        // MAC-command RX: classify + responder update, logged.
        while let Some(ind) = adapter.poll_mac_indication() {
            let psdu = ind.psdu();
            log_air(&mut log, "RDCOORD RX-MAC", psdu);
            match app.on_mac_psdu(psdu) {
                rounddance_hal_esp::mac_cmd::Incoming::BeaconReq { seq } => {
                    println!("RDCOORD RX-BEACONREQ seq={seq}");
                }
                rounddance_hal_esp::mac_cmd::Incoming::AssocReq(req) => {
                    println!(
                        "RDCOORD RX-ASSOCREQ seq={} eui={:02x?}",
                        req.seq, req.src_eui
                    );
                }
                rounddance_hal_esp::mac_cmd::Incoming::DataPoll(poll) => {
                    println!("RDCOORD RX-POLL seq={} eui={:02x?}", poll.seq, poll.src_eui);
                }
                rounddance_hal_esp::mac_cmd::Incoming::Other => {}
            }
        }
        // Data RX (NWK and above): log air bytes for the sniffer leg.
        while let Some(ind) = adapter.poll_indication() {
            log_air(&mut log, "RDCOORD RX", ind.msdu.as_slice());
        }
        // Drain TX confirms (shared data + MAC queue).
        while let Some(c) = adapter.poll_confirm() {
            println!("RDCOORD TX-CONFIRM status={:?}", c.status);
        }
        // Radiate: assoc-response first, then solicited beacons, then
        // gratuitous beacons while unassociated (passive-capture leg).
        if app.assoc_pending() {
            match app.take_assoc_rsp(&mut tx_buf) {
                Ok(n) if n > 0 => {
                    log_air(&mut log, "RDCOORD TX-ASSOC-RSP", &tx_buf[..n]);
                    if let Err(e) = adapter.transmit_mac(&tx_buf[..n]) {
                        println!("RDCOORD TX-ASSOC-FAILED {e:?}");
                    }
                }
                Ok(_) => {}
                Err(e) => println!("RDCOORD ASSOC-BUILD-FAILED {e:?}"),
            }
        } else if app.beacon_pending() > 0 {
            match app.take_beacon(&mut tx_buf) {
                Ok(n) if n > 0 => {
                    log_air(&mut log, "RDCOORD TX-BEACON", &tx_buf[..n]);
                    if let Err(e) = adapter.transmit_mac(&tx_buf[..n]) {
                        println!("RDCOORD TX-BEACON-FAILED {e:?}");
                    } else {
                        last_grat_ms = now_ms;
                    }
                }
                Ok(_) => {}
                Err(e) => println!("RDCOORD BEACON-BUILD-FAILED {e:?}"),
            }
        } else if !app.is_associated()
            && gratuitous_due(last_grat_ms, now_ms, GRATUITOUS_BEACON_INTERVAL_MS)
        {
            match app.build_gratuitous_beacon(&mut tx_buf) {
                Ok(n) => {
                    log_air(&mut log, "RDCOORD TX-BEACON-GRAT", &tx_buf[..n]);
                    if let Err(e) = adapter.transmit_mac(&tx_buf[..n]) {
                        println!("RDCOORD TX-GRAT-FAILED {e:?}");
                    } else {
                        last_grat_ms = now_ms;
                    }
                }
                Err(e) => println!("RDCOORD GRAT-BUILD-FAILED {e:?}"),
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
