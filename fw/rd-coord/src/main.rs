//! rd-coord: C6-standalone coordinator firmware.
//!
//! G-02 binding (`~/hwscratch/w84-goal-lab/LADDER.md` rung 2): the repo
//! [`CoordinatorApp`](rounddance_hal_esp::CoordinatorApp) composed over
//! [`EspIdfDriver`](rounddance_hal_esp::EspIdfDriver) via
//! [`EspAdapter`](rounddance_hal_esp::EspAdapter), flashed as one C6
//! image. Host proof of the app logic lives in
//! `crates/rounddance-hal-esp/tests/c6_standalone.rs` (mock-to-mock
//! air); this crate only binds it to the board: NVS-first radio init,
//! onboard-ceramic antenna select, role gate, formation, permit window,
//! and an RX pump that logs air bytes for the sniffer leg.
//!
//! MAC-association primitives (beacon-TX / assoc-indication-response)
//! are G-01 follow-up (`hal-esp/README.md:132-140`, `app.rs:512-549`):
//! incoming indications are logged here, the response path is an
//! explicit hook, and no child is admitted without air evidence.
//! Phase 2 owns flashing (backup-first, lease, by-id); this crate only
//! builds the image.

use esp_idf_hal::gpio::PinDriver;
use esp_idf_hal::peripherals::Peripherals;
use rounddance_hal_esp::app::{
    eui_from_mac, log_air, role_from_mac, APP_CHANNEL, APP_PAN, COORD_SHORT,
};
use rounddance_hal_esp::{AppRole, CoordinatorApp, EspAdapter, EspIdfDriver, SerialLog};
use rounddance_mac_sap::{Channel, MacDataSap, MacMgmtSap};

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

    // Role gate BEFORE the radio: only the OTA-proven coordinator unit
    // boots this image; anything else refuses without transmitting.
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

    // Formation conflict-check: ED scan first, then mark formed.
    match adapter.energy_scan(ch) {
        Ok(ed) => println!("RDCOORD ed ch15={ed}"),
        Err(e) => println!("RDCOORD ed-failed {e:?}"),
    }
    let mut app = CoordinatorApp::new();
    app.begin_formation(&mut log).expect("formation");
    app.formation_done(&mut log, true);
    // Bounded permit window; child admit stays air-gated (G-01 hook
    // below): no assoc-indication response exists in repo code yet.
    app.open_permit(&mut log, 600_000).expect("permit");

    loop {
        adapter.pump();
        // G-01 hook: assoc indications arrive here; until the repo
        // gains beacon-TX / assoc-response primitives, log only and
        // admit nothing.
        while let Some(ind) = adapter.poll_indication() {
            log_air(&mut log, "RDCOORD RX", ind.msdu.as_slice());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
