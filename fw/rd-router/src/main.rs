//! rd-router: C6-standalone router firmware.
//!
//! The missing C6-router binding the audit flagged: a real uplink
//! join ([`JoinerApp`] scan → assoc → install-code key → annce, the
//! same commissioning as the end-device leg) gates [`RouterDevice`]
//! activation — the device routes only on an observed `Joined`
//! state, never on an unconditional flag. Past the gate it routes
//! (NWK next-hop + route discovery), serves children (child table +
//! indirect hold + poll service), and hosts its own application
//! endpoints under the fairness rule (SCOPE §5 thermostat-that-routes,
//! one identity).
//!
//! Phase 2 owns flashing (backup-first, lease, by-id); this crate only
//! builds the image.

use esp_idf_hal::gpio::PinDriver;
use esp_idf_hal::peripherals::Peripherals;
use rounddance_hal_esp::app::{
    eui_from_mac, log_air, JoinerNwkOutcome, APP_PAN, EXT_PAN_ID, HA_PROFILE, UNASSOC_SHORT,
    COORD_SHORT,
};
use rounddance_hal_esp::board::BoardConfig;
use rounddance_hal_esp::mac_cmd::{
    classify, gratuitous_due, CoordAssoc, Incoming as MacIncoming, GRATUITOUS_BEACON_INTERVAL_MS,
};
use rounddance_hal_esp::{EspAdapter, EspIdfDriver, JoinerApp, RouterDevice, SerialLog};
use rounddance_mac_sap::{Channel, MacDataSap, MacMgmtSap, TxHandle, TxStatus};
use rounddance_roles::{AgingPolicy, AppEndpoint, CommandError};
use rounddance_zcl::onoff;
use std::time::Instant;

const ESP_MAC_BASE: u32 = 5;
unsafe extern "C" {
    fn esp_read_mac(mac: *mut u8, type_: u32) -> i32;
}

struct ConsoleLog;
impl SerialLog for ConsoleLog {
    fn log(&mut self, line: &str) {
        println!("{line}");
    }
}

/// Minimal local endpoint for the router image: On/Off-class toggle
/// sink proving router+app simultaneity on one identity.
struct RouterLamp {
    on: bool,
}
impl AppEndpoint for RouterLamp {
    fn endpoint_id(&self) -> u8 {
        1
    }
    fn profile_id(&self) -> u16 {
        0x0104
    }
    fn handle_command(
        &mut self,
        payload: &[u8],
        response: &mut [u8],
    ) -> Result<usize, CommandError> {
        if payload == [0x01] {
            self.on = true;
            response[0] = 0x06;
            Ok(1)
        } else if payload == [0x00] {
            self.on = false;
            response[0] = 0x06;
            Ok(1)
        } else {
            Err(CommandError::BadCommand)
        }
    }
}

static UPLINK_DEF: onoff::ServerDef = onoff::ServerDef;

// Uplink join bounds (same discipline as rd-joiner: bounded retries,
// then refuse to route unjoined).
const REQ_INTERVAL_MS: u64 = 2_000;
const ASSOC_RETRIES_MAX: u32 = 30;
const SCAN_WINDOW_MS: u64 = 4_000;
const ANNCE_RETRIES_MAX: u8 = 4;

// Router-assigned child short (our own pool; the TC owns 0x0000–0x0002).
const ROUTER_CHILD_SHORT: u16 = 0x0003;

/// Provisioned child base MAC: `RD_ROUTER_CHILD` (12 hex digits, e.g.
/// the downstream unit's base MAC) bakes the child identity in at
/// build time; unset falls back to the lab joiner MAC (harmless until
/// overridden — the mechanism is host-proven either way, the air leg
/// needs the real child unit here).
const fn parse_mac(s: &str) -> [u8; 6] {
    let b = s.as_bytes();
    let mut out = [0u8; 6];
    let mut i = 0;
    while i < 6 {
        let h = (hex_val(b[2 * i]) << 4) | hex_val(b[2 * i + 1]);
        out[i] = h;
        i += 1;
    }
    out
}
const fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("RD_ROUTER_CHILD not hex"),
    }
}
const PROVISIONED_CHILD_MAC: [u8; 6] = match option_env!("RD_ROUTER_CHILD") {
    Some(s) => parse_mac(s),
    None => [0xa0, 0xf2, 0x62, 0x85, 0x97, 0xa4],
};

fn main() {
    let peripherals = Peripherals::take().expect("peripherals");
    let mut ant3 = PinDriver::output(peripherals.pins.gpio3).expect("gpio3");
    let mut ant14 = PinDriver::output(peripherals.pins.gpio14).expect("gpio14");
    ant3.set_low().expect("ant3 low");
    ant14.set_low().expect("ant14 low");

    let mut mac = [0u8; 6];
    let rc = unsafe { esp_read_mac(mac.as_mut_ptr(), ESP_MAC_BASE) };
    assert!(rc == 0, "esp_read_mac BASE rc={rc}");
    let cfg = BoardConfig::c6_router(mac, 0xC601, 15);
    println!(
        "RDROUTER ident mac={mac:02x?} target={} pan={:#06x} ch={}",
        cfg.target.idf_target(),
        cfg.pan,
        cfg.channel
    );

    let mut log = ConsoleLog;
    let adapter: &'static mut EspAdapter<EspIdfDriver> =
        Box::leak(Box::new(EspAdapter::new(EspIdfDriver::new())));
    adapter.set_pan_id(0xFFFF);
    adapter.set_short_addr(UNASSOC_SHORT);
    let eui = eui_from_mac(&mac);
    let mut ext = eui;
    ext.reverse();
    adapter.set_extended_addr(u64::from_le_bytes(ext));
    adapter.set_tx_power(10).expect("standing +10 dBm cap");
    adapter.init().expect("radio init");
    let ch = Channel::new(cfg.channel).expect("channel 11-26");
    adapter.set_channel(ch).expect("tune");

    // Uplink join (same exchange as rd-joiner): scan → assoc →
    // install-code transport → annce → joined. The uplink provisions
    // the router's OWN EUI (not the lab joiner's): the TC answers the
    // uplink under the router identity and the radio filter matches.
    // The router role below activates only on the observed Joined state.
    let uplink: &'static mut JoinerApp<'static> =
        Box::leak(Box::new(JoinerApp::new_with_ieee(&UPLINK_DEF, eui).expect("uplink app")));
    uplink.begin_scan(&mut log).expect("begin scan");
    let mut scan_open = true;
    let mut tx_buf = [0u8; 160];
    let mut mac_seq: u8 = 0;
    let mut last_scan_ms: u64 = 0;
    let mut last_req_ms: u64 = 0;
    let mut assoc_tries: u32 = 0;
    let mut adopted_pan: Option<u16> = None;
    let mut adopted_short: Option<u16> = None;
    let mut assoc_done_logged = false;
    let mut annce_pending = false;
    let mut annce_handle: Option<TxHandle> = None;
    let mut annce_tries: u8 = 0;
    let start = Instant::now();
    let mut joined = false;
    // Join phase: bounded assoc attempts, then refuse (never route
    // unjoined). The loop below exits on Joined or on budget
    // exhaustion; the routing pump afterwards runs only when joined.
    while !joined {
        adapter.pump();
        let now_ms = start.elapsed().as_millis() as u64;
        if assoc_tries >= ASSOC_RETRIES_MAX && uplink.assoc_short().is_none() {
            println!("RDROUTER JOIN-GIVEUP assoc budget exhausted (not routing)");
            break;
        }
        if uplink.candidate_pan().is_none() {
            if !scan_open && now_ms.wrapping_sub(last_scan_ms) >= SCAN_WINDOW_MS {
                last_scan_ms = now_ms;
                scan_open = uplink.begin_scan(&mut log).is_ok();
            } else if scan_open && now_ms.wrapping_sub(last_scan_ms) >= SCAN_WINDOW_MS {
                last_scan_ms = now_ms;
                scan_open = false;
                if let Some(pan) = uplink.finish_scan(&mut log) {
                    println!("RDROUTER CANDIDATE pan={pan:#06x}");
                }
            }
        }
        while let Some(ind) = adapter.poll_mac_indication() {
            log_air(&mut log, "RDROUTER RX-MAC", ind.psdu());
            match uplink.on_mac_psdu(
                &mut log,
                ind.psdu(),
                ind.channel_number(),
                ind.rssi(),
                ind.lqi(),
            ) {
                MacIncoming::Beacon(bi) => {
                    println!("RDROUTER RX-BEACON pan={:#06x}", bi.src_pan);
                }
                MacIncoming::AssocRsp(rsp) => {
                    println!(
                        "RDROUTER RX-ASSOC-RSP short={:#06x} status={:#04x}",
                        rsp.short, rsp.status
                    );
                }
                _ => {}
            }
        }
        if uplink.assoc_short().is_none()
            && assoc_tries < ASSOC_RETRIES_MAX
            && now_ms.wrapping_sub(last_req_ms) >= REQ_INTERVAL_MS
        {
            last_req_ms = now_ms;
            if let Some(pan) = uplink.candidate_pan() {
                if adopted_pan != Some(pan) {
                    adapter.set_pan_id(pan);
                    adopted_pan = Some(pan);
                    println!("RDROUTER ADOPTED pan={pan:#06x}");
                }
                match uplink.take_assoc_req(&mut tx_buf, pan, COORD_SHORT) {
                    Ok(n) if n > 0 => {
                        log_air(&mut log, "RDROUTER TX-ASSOC-REQ", &tx_buf[..n]);
                        if adapter.transmit_mac(&tx_buf[..n]).is_ok() {
                            assoc_tries += 1;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => println!("RDROUTER ASSOC-BUILD-FAILED {e:?}"),
                }
            } else {
                mac_seq = mac_seq.wrapping_add(1);
                match rounddance_hal_esp::mac_cmd::build_beacon_req(mac_seq, &mut tx_buf) {
                    Ok(n) => {
                        let _ = adapter.transmit_mac(&tx_buf[..n]);
                    }
                    Err(e) => println!("RDROUTER BEACON-REQ-FAILED {e:?}"),
                }
            }
        } else if let Some(short) = uplink.assoc_short() {
            if adopted_short != Some(short) {
                adopted_short = Some(short);
                adapter.set_short_addr(short);
                println!("RDROUTER ADOPTED-SHORT short={short:#06x}");
            }
            if !assoc_done_logged {
                assoc_done_logged = true;
                println!("RDROUTER ASSOC-DONE short={short:#06x}");
            }
        }
        while let Some(ind) = adapter.poll_indication() {
            log_air(&mut log, "RDROUTER RX-NWK", ind.msdu.as_slice());
            match uplink.on_nwk_joiner(ind.msdu.as_slice()) {
                JoinerNwkOutcome::TransportAccepted { auxctr } => {
                    println!("RDROUTER TRANSPORT-OPEN auxctr={auxctr:#010x}");
                    annce_pending = true;
                    annce_handle = None;
                    annce_tries = 0;
                }
                JoinerNwkOutcome::Data { cluster, profile }
                    if cluster == onoff::CLUSTER_ID && profile == HA_PROFILE =>
                {
                    // Uplink answers no application traffic; the lamp
                    // leg lives on the hosted endpoint, below.
                }
                JoinerNwkOutcome::Data { cluster, profile } => {
                    println!("RDROUTER RX-NWK-DATA cluster={cluster:#06x} profile={profile:#06x}");
                }
                JoinerNwkOutcome::NwkCommand { id } => {
                    println!("RDROUTER RX-NWK-CMD id={id:#04x}");
                }
                JoinerNwkOutcome::Ignored(why) => {
                    println!("RDROUTER RX-NWK-IGNORED {why:?}");
                }
                JoinerNwkOutcome::NodeDescReq { tsn, .. } => {
                    // Uplink answers no ZDO while joining; the hosted
                    // endpoint leg below owns post-join answers.
                    println!("RDROUTER RX-NODE-DESC-REQ tsn={tsn} (deferred)");
                }
            }
        }
        if annce_pending && annce_handle.is_none() {
            if annce_tries >= ANNCE_RETRIES_MAX {
                println!("RDROUTER ANNCE-GIVEUP (joined-locally)");
                annce_pending = false;
                uplink.verify_confirm(&mut log);
                uplink.close_out(&mut log);
            } else {
                match uplink.take_annce(&mut tx_buf) {
                    Ok(n) if n > 0 => match adapter.transmit_mac(&tx_buf[..n]) {
                        Ok(h) => {
                            annce_handle = Some(h);
                            annce_tries += 1;
                        }
                        Err(e) => println!("RDROUTER TX-ANNCE-FAILED {e:?}"),
                    },
                    Ok(_) => annce_pending = false,
                    Err(e) => println!("RDROUTER ANNCE-BUILD-FAILED {e:?}"),
                }
            }
        }
        while let Some(c) = adapter.poll_confirm() {
            if Some(c.handle) == annce_handle {
                annce_handle = None;
                if c.status == TxStatus::Delivered {
                    annce_pending = false;
                    uplink.verify_confirm(&mut log);
                    uplink.close_out(&mut log);
                }
            }
        }
        joined = uplink.state() == rounddance_commission::JoinerState::Joined;
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !joined {
        println!("RDROUTER refuse: uplink never joined, radio idle");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }
    println!("RDROUTER UPLINK-JOINED lamp-hosted, activating router");

    // Router duties activate ONLY on the observed join above.
    let mut router = RouterDevice::new(AgingPolicy::default(), 60_000);
    router.begin_join().expect("begin join");
    let mut lamp = RouterLamp { on: false };
    router.register_endpoint(&lamp).expect("register ep1");
    router.join_done(joined);
    assert_eq!(router.state(), rounddance_roles::RouterState::Active);
    println!("RDROUTER state Active (routing + endpoint ep1)");

    // Child service (goal RTR-02): answer beacon-reqs + assoc-reqs as a
    // router parent. Allow-list + child-table admission are provisioned
    // up front (same order as the TC leg); the child short comes from
    // our own pool (`ROUTER_CHILD_SHORT`), never the TC's.
    let child_eui = eui_from_mac(&PROVISIONED_CHILD_MAC);
    let mut child_ext = child_eui;
    child_ext.reverse();
    let mut assoc = CoordAssoc::new();
    let mut own_ext = eui;
    own_ext.reverse();
    assoc.provision(
        APP_PAN,
        adopted_short.unwrap_or(0x0002),
        &own_ext,
    );
    assoc.set_permit(true);
    assoc.allow(child_eui).expect("allow child");
    router
        .admit_child(
            ROUTER_CHILD_SHORT,
            u64::from_le_bytes(child_eui),
            true,
            start.elapsed().as_millis() as u64,
        )
        .expect("admit child");
    println!("RDROUTER CHILD-SERVICE open (child short={ROUTER_CHILD_SHORT:#06x})");
    let mut last_grat_ms: u64 = 0;
    let mut assoc_handle: Option<TxHandle> = None;

    let mut fwd_out = [(0u16, [0u8; 128], 0usize); 8];
    loop {
        adapter.pump();
        let now_ms = start.elapsed().as_millis() as u64;
        // Data RX: relay toward the next hop when a route covers the
        // NWK destination (verbatim-MSDU relay contract), else hold
        // for a sleepy child, originate discovery, or queue locally.
        // NWK dst comes from the repo codec — the first two MSDU
        // octets are the NWK frame control, not the destination.
        while let Some(ind) = adapter.poll_indication() {
            let msdu = ind.msdu.as_slice();
            let Some(dst) = rounddance_hal_esp::nwk_dst_of(msdu) else {
                println!("RDROUTER RX-NWK-UNDECODABLE len={}", msdu.len());
                continue;
            };
            if dst != 0x0000 {
                if let Some(nh) = router.relay_for(msdu, now_ms) {
                    println!("RDROUTER RX-RELAY dst={dst:#06x} via={nh:#06x}");
                } else if router.hold_for_child(dst, msdu, now_ms).is_ok() {
                    println!("RDROUTER RX-HOLD dst={dst:#06x}");
                } else {
                    // No leg covers the destination: originate
                    // discovery (single-flight) so a later frame can
                    // relay instead of dropping silently.
                    match router.start_discovery(dst, adopted_short.unwrap_or(0x0002), now_ms) {
                        Ok(id) => println!("RDROUTER DISCOVER dst={dst:#06x} id={id}"),
                        Err(_) => println!("RDROUTER DISCOVER-PENDING dst={dst:#06x}"),
                    }
                }
            } else {
                let _ = router.deliver_to_endpoint(1, msdu);
            }
        }
        // Child polls: serve held frames. Command frames are
        // classified first so beacon/assoc requests reach the
        // responder instead of the poll parser.
        while let Some(mac_ind) = adapter.poll_mac_indication() {
            let psdu = mac_ind.psdu();
            match classify(psdu) {
                MacIncoming::BeaconReq { seq } => {
                    log_air(&mut log, "RDROUTER RX-BEACONREQ", psdu);
                    println!("RDROUTER RX-BEACONREQ seq={seq}");
                    assoc.on_beacon_req();
                }
                MacIncoming::AssocReq(req) => {
                    log_air(&mut log, "RDROUTER RX-ASSOCREQ", psdu);
                    if assoc.on_assoc_req(&req) {
                        println!(
                            "RDROUTER RX-ASSOCREQ seq={} eui={:02x?}",
                            req.seq, req.src_eui
                        );
                    }
                }
                MacIncoming::DataPoll(poll) => {
                    // Long-form poll: resolve the enrolled child by EUI
                    // (no short rides in this frame).
                    if poll.src_eui == child_eui {
                        match router.serve_poll(ROUTER_CHILD_SHORT, now_ms) {
                            Ok(Some(_frame)) => println!(
                                "RDROUTER POLL-SERVED short={ROUTER_CHILD_SHORT:#06x}"
                            ),
                            Ok(None) => println!(
                                "RDROUTER POLL-EMPTY short={ROUTER_CHILD_SHORT:#06x}"
                            ),
                            Err(e) => println!("RDROUTER POLL-FAILED {e:?}"),
                        }
                    } else {
                        println!("RDROUTER POLL-STRANGER eui={:02x?}", poll.src_eui);
                    }
                }
                MacIncoming::ShortPoll(poll) => {
                    match router.serve_poll(poll.src_short, now_ms) {
                        Ok(Some(_frame)) => {
                            println!("RDROUTER POLL-SERVED short={:#06x}", poll.src_short)
                        }
                        Ok(None) => {
                            println!("RDROUTER POLL-EMPTY short={:#06x}", poll.src_short)
                        }
                        Err(e) => println!("RDROUTER POLL-FAILED {e:?}"),
                    }
                }
                _ => {
                    if psdu.len() >= 2 {
                        let short =
                            u16::from_le_bytes([psdu[psdu.len() - 2], psdu[psdu.len() - 1]]);
                        match router.serve_poll(short, now_ms) {
                            Ok(Some(_frame)) => {
                                println!("RDROUTER POLL-SERVED short={short:#06x}")
                            }
                            Ok(None) => {}
                            Err(e) => println!("RDROUTER POLL-FAILED {e:?}"),
                        }
                    }
                }
            }
        }
        // TX confirms drain (shared queue): log the child assoc
        // answer outcome (the child retries assoc-reqs itself, so no
        // re-arm here — a lost answer just costs one retry).
        while let Some(c) = adapter.poll_confirm() {
            println!("RDROUTER TX-CONFIRM status={:?}", c.status);
            if Some(c.handle) == assoc_handle {
                assoc_handle = None;
            }
        }
        // Radiate: child assoc-response first, then solicited beacons,
        // then gratuitous beacons while active (routers beacon so
        // children can find them without soliciting).
        if assoc.assoc_pending() {
            match assoc.take_assoc_rsp(mac_seq, ROUTER_CHILD_SHORT, 0x00, &mut tx_buf) {
                Ok(n) if n > 0 => {
                    log_air(&mut log, "RDROUTER TX-ASSOC-RSP", &tx_buf[..n]);
                    mac_seq = mac_seq.wrapping_add(1);
                    match adapter.transmit_mac(&tx_buf[..n]) {
                        Ok(h) => assoc_handle = Some(h),
                        Err(e) => println!("RDROUTER TX-ASSOC-FAILED {e:?}"),
                    }
                }
                Ok(_) => {}
                Err(e) => println!("RDROUTER ASSOC-BUILD-FAILED {e:?}"),
            }
        } else if assoc.pending_beacon() > 0 {
            match assoc.take_beacon(mac_seq, &EXT_PAN_ID, &mut tx_buf) {
                Ok(n) if n > 0 => {
                    log_air(&mut log, "RDROUTER TX-BEACON", &tx_buf[..n]);
                    mac_seq = mac_seq.wrapping_add(1);
                    if adapter.transmit_mac(&tx_buf[..n]).is_ok() {
                        last_grat_ms = now_ms;
                    }
                }
                Ok(_) => {}
                Err(e) => println!("RDROUTER BEACON-BUILD-FAILED {e:?}"),
            }
        } else if gratuitous_due(last_grat_ms, now_ms, GRATUITOUS_BEACON_INTERVAL_MS) {
            assoc.on_beacon_req();
        }
        let mut eps: [&mut RouterLamp; 1] = [&mut lamp];
        let (f, a) = router.tick(&mut eps, |e| e.endpoint_id(), &mut fwd_out, now_ms);
        if f > 0 || a > 0 {
            println!("RDROUTER TICK fwd={f} app={a} lamp={}", lamp.on);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
