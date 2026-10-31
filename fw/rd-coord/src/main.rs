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
    eui_from_mac, log_air, role_from_mac, NwkRxOutcome, APP_CHANNEL, APP_PAN, COORD_SHORT,
    TC_EUI_WIRE,
};
use rounddance_hal_esp::mac_cmd::{gratuitous_due, GRATUITOUS_BEACON_INTERVAL_MS};
use rounddance_hal_esp::{AppRole, CoordinatorApp, EspAdapter, EspIdfDriver, SerialLog};
use rounddance_commission::ha_transport_key;
use rounddance_security::{KeySet, NetworkKey};
use rounddance_mac_sap::{Channel, MacDataSap, MacMgmtSap, TxHandle, TxStatus};
use std::time::Instant;

// esp-idf-sys 0.38 ships no binding for this symbol (same reason the
// scratch image declares the 15.4 externs itself); signature matches
// the IDF v6.1 `esp_mac.h` header. NOTE: do NOT use
// `esp_efuse_mac_get_default` here: on 802.15.4 chips (C6) it splices
// the efuse MAC_EXT (`ff:fe`) into the returned bytes (and overruns a
// 6-byte buffer), so the full base-MAC compare in `role_from_mac`
// could never match. `ESP_MAC_BASE` (5) returns the raw 6-byte
// factory MAC (`get_efuse_factory_mac`, verified in IDF v6.1
// `components/esp_hw_support/mac_addr.c`) — the same value
// `esptool read-mac` reports as BASE MAC.
const ESP_MAC_BASE: u32 = 5;
unsafe extern "C" {
    fn esp_read_mac(mac: *mut u8, type_: u32) -> i32;
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
    let rc = unsafe { esp_read_mac(mac.as_mut_ptr(), ESP_MAC_BASE) };
    assert!(rc == 0, "esp_read_mac BASE rc={rc}");
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
    // Radio address match compares arrival order (LSB-first on air):
    // program the EUI in wire order (`TC_EUI_WIRE`), not display
    // order, or HW ACKs for long-addressed inbound frames never match
    // (w97 joiner leg: RSPs to the joiner got NoAck for exactly this
    // reason on the other side).
    adapter.set_extended_addr(u64::from_le_bytes(TC_EUI_WIRE));
    adapter
        .set_tx_power(10)
        .expect("standing +10 dBm cap");
    adapter.init().expect("radio init");
    // `set_channel` needs a live driver: retune explicitly post-init
    // even though the default already matches, so the air channel is
    // asserted, not assumed.
    let ch = Channel::new(APP_CHANNEL).expect("app channel 11-26");
    adapter.set_channel(ch).expect("tune ch15");
    // Addressed receive (filtering ON, as programmed above): broadcast
    // beacon-requests pass the hardware filter (broadcast dst), and
    // unicast association requests to our short pass too — with
    // hardware auto-ACK. Promiscuous mode must stay OFF: it disables
    // HW ACK, and unacked assoc-reqs make the joiner retry-then-fail
    // (w92 air proof: 8 unacked `23 c8` retries, zero ACKs).

    // Formation conflict-check: ED scan first, then mark formed.
    match adapter.energy_scan(ch) {
        Ok(ed) => println!("RDCOORD ed ch15={ed}"),
        Err(e) => println!("RDCOORD ed-failed {e:?}"),
    }
    let mut app = CoordinatorApp::new();
    app.begin_formation(&mut log).expect("formation");
    app.formation_done(&mut log, true);
    // Bounded permit window (1 h lab bound: comfortably covers paced
    // manual join experiments; the 600 s bound kept expiring mid-run
    // and made in-window assoc-reqs look like app silence on air).
    // The MAC responder permit + allow-list are wired inside the app
    // (`open_permit` / `admit_joiner` + rung-3 MG24 `admit_extra` so
    // the NCP-side joiner's assoc-req is answered instead of denied).
    app.open_permit(&mut log, 3_600_000).expect("permit");
    app.admit_joiner(&mut log, 0).expect("admit 97A4");
    app.admit_extra(&mut log, [0x34, 0x8d, 0x13, 0xff, 0xfe, 0x11, 0x49, 0x6d], 0x0002)
        .expect("admit MG24");

    let start = Instant::now();
    let mut last_grat_ms: u64 = 0;
    let mut last_tick_ms: u64 = 0;
    let mut tx_buf = [0u8; 128];
    // Join-critical in-flight tracking: confirm-driven retransmit
    // (bounded) for the assoc answer + transport key.
    let mut assoc_handle: Option<TxHandle> = None;
    let mut transport_handle: Option<TxHandle> = None;
    let mut assoc_retries: u8 = 4;
    let mut transport_retries: u8 = 4;
    // Lab network key (OUR C601 network; deployment-owned test key,
    // documented: production must randomize + persist the aux counter
    // in NVS instead of rebooting from the fixed base).
    const C6_NETKEY: [u8; 16] = *b"C6JOIN01LABTEST!";
    // Key-transport key from the public HA preconfigured link key;
    // the NCP derives the same from its provisioned HA key.
    let transport_key = ha_transport_key().expect("HA transport key");
    // Network key store for opening inbound secured NWK frames
    // (Phase 1 leg RX-1: Device_annce + NWK-command classification).
    let nwk_keys = KeySet::new(NetworkKey::new(C6_NETKEY, 0));
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
                    // Fresh join: reset the confirm-retry budgets.
                    assoc_handle = None;
                    transport_handle = None;
                    assoc_retries = 4;
                    transport_retries = 4;
                }
                rounddance_hal_esp::mac_cmd::Incoming::DataPoll(poll) => {
                    println!("RDCOORD RX-POLL seq={} eui={:02x?}", poll.seq, poll.src_eui);
                }
                rounddance_hal_esp::mac_cmd::Incoming::ShortPoll(poll) => {
                    println!(
                        "RDCOORD RX-SHORTPOLL seq={} src={:#06x}",
                        poll.seq, poll.src_short
                    );
                }
                rounddance_hal_esp::mac_cmd::Incoming::Other => {}
                // Beacons/assoc-responses are joiner-side input; the
                // coordinator logs its own answers, never receives them.
                rounddance_hal_esp::mac_cmd::Incoming::Beacon(_)
                | rounddance_hal_esp::mac_cmd::Incoming::AssocRsp(_) => {}
            }
        }
        // Data RX (NWK and above): log air bytes for the sniffer leg.
        while let Some(ind) = adapter.poll_indication() {
            log_air(&mut log, "RDCOORD RX", ind.msdu.as_slice());
            // Phase 1 leg RX-1/RSP-1: open + classify inbound NWK frames.
            let outcome = app.on_nwk_data(ind.msdu.as_slice(), &nwk_keys, now_ms);
            println!("RDCOORD RX-NWK {:?}", outcome);
            // Reference-TC follow-through (w97 joinCTL): answer each
            // Device_annce with a Node_desc_req to the announcer.
            if let NwkRxOutcome::Annce { short, .. } = outcome {
                match app.take_node_desc_req(&mut tx_buf, short, &C6_NETKEY) {
                    Ok(n) if n > 0 => {
                        log_air(&mut log, "RDCOORD TX-NODE-DESC-REQ", &tx_buf[..n]);
                        println!("RDCOORD ZDO-PENDING {}", app.zdo_pending_open());
                        if let Err(e) = adapter.transmit_mac(&tx_buf[..n]) {
                            println!("RDCOORD TX-NODE-DESC-FAILED {e:?}");
                        }
                    }
                    Ok(_) => {}
                    Err(e) => println!("RDCOORD NODE-DESC-BUILD-FAILED {e:?}"),
                }
            }
        }
        // Drain TX confirms (shared data + MAC queue). A NoAck /
        // ChannelBusy confirm for a join-critical frame re-pends it:
        // the NCP never saw it, and the join window is seconds long
        // (w96: delivered RSP + NoAck transport + JOIN_FAILED).
        // Bounded: 4 retries each, then the answer lapses.
        while let Some(c) = adapter.poll_confirm() {
            println!("RDCOORD TX-CONFIRM status={:?}", c.status);
            if Some(c.handle) == assoc_handle {
                assoc_handle = None;
                if c.status != TxStatus::Delivered && assoc_retries > 0 {
                    assoc_retries -= 1;
                    println!("RDCOORD TX-ASSOC-NOACK; re-armed ({assoc_retries} left)");
                    app.rearm_assoc();
                }
            }
            if Some(c.handle) == transport_handle {
                transport_handle = None;
                if c.status != TxStatus::Delivered && transport_retries > 0 {
                    transport_retries -= 1;
                    println!("RDCOORD TX-TRANSPORT-NOACK; re-armed ({transport_retries} left)");
                    app.rearm_transport();
                }
            }
        }
        // Radiate: assoc-response first, then solicited beacons, then
        // gratuitous beacons while unassociated (passive-capture leg).
        if app.assoc_pending() {
            match app.take_assoc_rsp(&mut tx_buf) {
                Ok(n) if n > 0 => {
                    log_air(&mut log, "RDCOORD TX-ASSOC-RSP", &tx_buf[..n]);
                    match adapter.transmit_mac(&tx_buf[..n]) {
                        Ok(h) => assoc_handle = Some(h),
                        Err(e) => {
                        // Single-flight busy on a congested band must not
                        // drop the one answer: re-pend, retry next loop
                        // (confirms drain meanwhile). w92 f1 class.
                        println!("RDCOORD TX-ASSOC-FAILED {e:?}; re-armed");
                        app.rearm_assoc();
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => println!("RDCOORD ASSOC-BUILD-FAILED {e:?}"),
            }
        } else if app.transport_pending() {
            match app.take_transport_key(&mut tx_buf, &C6_NETKEY, &transport_key) {
                Ok(n) if n > 0 => {
                    log_air(&mut log, "RDCOORD TX-TRANSPORT-KEY", &tx_buf[..n]);
                    match adapter.transmit_mac(&tx_buf[..n]) {
                        Ok(h) => transport_handle = Some(h),
                        Err(e) => {
                        // Same single-flight hazard as the assoc answer:
                        // re-pend, retry next loop (w93 f1 class).
                        println!("RDCOORD TX-TRANSPORT-FAILED {e:?}; re-armed");
                        app.rearm_transport();
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => println!("RDCOORD TRANSPORT-BUILD-FAILED {e:?}"),
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
