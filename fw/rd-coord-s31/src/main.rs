//! rd-coord-s31: S31 standalone coordinator firmware.
//!
//! Port of `fw/rd-coord` (C6) to the ESP32-S31 target. The portable
//! core is unchanged: [`CoordinatorApp`] over [`EspAdapter`] with the
//! identical 15.4 driver API (S31 `SOC_IEEE802154_SUPPORTED=1`, same
//! as C6). Board deltas live here only:
//! * `CONFIG_IDF_TARGET="esp32s31"` (see `sdkconfig.defaults`);
//! * NO Xiao-C6 antenna GPIO drive (GPIO3/14 LOW/LOW is a C6-Xiao
//!   front-end select; S31 boards must not touch those pins);
//! * role comes from generic [`BoardConfig`] provisioning
//!   (`RD_COORD_MAC` build-time base MAC, defaulting to the lab S31
//!   unit), not from the two hardcoded C6 lab MACs.
//!
//! Phase 2 owns flashing (backup-first, lease, by-id); this crate only
//! builds the image.

use rounddance_commission::ha_transport_key;
use rounddance_hal_esp::app::{
    log_air, role_from_mac, NwkRxOutcome, APP_CHANNEL, APP_PAN, COORD_SHORT, TC_EUI_WIRE,
};
use rounddance_hal_esp::board::{BoardConfig, EspTarget};
use rounddance_hal_esp::mac_cmd::{gratuitous_due, GRATUITOUS_BEACON_INTERVAL_MS};
use rounddance_hal_esp::{CoordinatorApp, EspAdapter, EspIdfDriver, SerialLog};
use rounddance_mac_sap::{Channel, MacDataSap, MacMgmtSap, TxHandle, TxStatus};
use rounddance_security::{KeySet, NetworkKey};
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

const NVS_NS_AUX: &[u8] = b"rdcoord\0";
const NVS_KEY_AUXCHUNK: &[u8] = b"aux_chunk\0";

fn nvs_aux_read() -> Option<u32> {
    unsafe {
        let mut handle: esp_idf_sys::nvs_handle_t = 0;
        if esp_idf_sys::nvs_open(
            NVS_NS_AUX.as_ptr().cast(),
            esp_idf_sys::nvs_open_mode_t_NVS_READONLY,
            &mut handle,
        ) != esp_idf_sys::ESP_OK
        {
            return None;
        }
        let mut val: u32 = 0;
        let rc = esp_idf_sys::nvs_get_u32(handle, NVS_KEY_AUXCHUNK.as_ptr().cast(), &mut val);
        esp_idf_sys::nvs_close(handle);
        if rc == esp_idf_sys::ESP_OK {
            Some(val)
        } else {
            None
        }
    }
}

fn nvs_aux_write(chunk: u32) {
    unsafe {
        let mut handle: esp_idf_sys::nvs_handle_t = 0;
        if esp_idf_sys::nvs_open(
            NVS_NS_AUX.as_ptr().cast(),
            esp_idf_sys::nvs_open_mode_t_NVS_READWRITE,
            &mut handle,
        ) != esp_idf_sys::ESP_OK
        {
            println!("RDCOORD-S31 NVS-WRITE-FAILED open chunk={chunk}");
            return;
        }
        let rc = esp_idf_sys::nvs_set_u32(handle, NVS_KEY_AUXCHUNK.as_ptr().cast(), chunk);
        if rc == esp_idf_sys::ESP_OK {
            let rc = esp_idf_sys::nvs_commit(handle);
            if rc != esp_idf_sys::ESP_OK {
                println!("RDCOORD-S31 NVS-WRITE-FAILED commit chunk={chunk} rc={rc}");
            } else {
                println!("RDCOORD-S31 NVS-WROTE aux_chunk={chunk}");
            }
        } else {
            println!("RDCOORD-S31 NVS-WRITE-FAILED set chunk={chunk} rc={rc}");
        }
        esp_idf_sys::nvs_close(handle);
    }
}

fn persist_aux_chunk(app: &mut CoordinatorApp) {
    if let Some(chunk) = app.aux_checkpoint() {
        nvs_aux_write(chunk);
    }
}

/// Provisioned coordinator base MAC: `RD_COORD_MAC` (12 hex digits,
/// e.g. `a0f262867f68`) bakes the S31 unit identity in at build time;
/// unset falls back to the C6 lab coordinator MAC for host-sim parity
/// (the S31 lab unit MAC is provisioned at flash time).
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
        _ => panic!("RD_COORD_MAC not hex"),
    }
}
const PROVISIONED_COORD_MAC: [u8; 6] = match option_env!("RD_COORD_MAC") {
    Some(s) => parse_mac(s),
    None => [0xa0, 0xf2, 0x62, 0x86, 0x7f, 0x68],
};

fn main() {
    // No antenna-GPIO drive on S31 (C6-Xiao-only front-end select).
    // Target check: this image is the S31 port.
    let cfg = BoardConfig::s31_coordinator(PROVISIONED_COORD_MAC, APP_PAN, APP_CHANNEL);
    assert_eq!(cfg.target, EspTarget::S31);
    assert_eq!(cfg.target.idf_target(), "esp32s31");
    println!("RDCOORD-S31 target={} pan={:#06x} ch={}", cfg.target.idf_target(), cfg.pan, cfg.channel);

    let mut mac = [0u8; 6];
    let rc = unsafe { esp_read_mac(mac.as_mut_ptr(), ESP_MAC_BASE) };
    assert!(rc == 0, "esp_read_mac BASE rc={rc}");
    println!("RDCOORD-S31 ident mac={mac:02x?}");
    // Generic provisioning gate: this unit must match the provisioned
    // coordinator MAC; the two-C6 lab gate stays as a fallback accept.
    let generic_ok = BoardConfig::s31_coordinator(mac, APP_PAN, APP_CHANNEL)
        .identity
        .role()
        .is_some()
        || role_from_mac(&mac).is_some();
    if !generic_ok {
        println!("RDCOORD-S31 refuse: not the provisioned coordinator unit");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }

    let mut log = ConsoleLog;
    let mut adapter = EspAdapter::new(EspIdfDriver::new());
    adapter.set_pan_id(APP_PAN);
    adapter.set_short_addr(COORD_SHORT);
    adapter.set_extended_addr(u64::from_le_bytes(TC_EUI_WIRE));
    adapter.set_tx_power(10).expect("standing +10 dBm cap");
    adapter.init().expect("radio init");
    let ch = Channel::new(APP_CHANNEL).expect("app channel 11-26");
    adapter.set_channel(ch).expect("tune ch15");

    match adapter.energy_scan(ch) {
        Ok(ed) => println!("RDCOORD-S31 ed ch15={ed}"),
        Err(e) => println!("RDCOORD-S31 ed-failed {e:?}"),
    }
    let mut app = CoordinatorApp::new();
    let aux_saved = nvs_aux_read();
    app.resume_auxctr(aux_saved);
    match aux_saved {
        Some(c) => println!("RDCOORD-S31 AUX-RESUME chunk={c}"),
        None => println!("RDCOORD-S31 AUX-RESUME fresh"),
    }
    app.begin_formation(&mut log).expect("formation");
    app.formation_done(&mut log, true);
    if option_env!("RD_NETKEY_HEX").is_some() {
        println!("RDCOORD-S31 NETKEY custom");
    } else {
        println!("RDCOORD-S31 NETKEY lab-default (set RD_NETKEY_HEX for deployment)");
    }
    // Permit window: 1 h lab bound; admissions are provisioned by the
    // deployment (lab pair admitted here for bring-up parity).
    app.open_permit(&mut log, 3_600_000).expect("permit");
    app.admit_joiner(&mut log, 0).expect("admit joiner");
    // Router leg: admit the C6 router unit (E510) as short 0x0002.
    app.admit_extra(&mut log, [0xa0, 0xf2, 0x62, 0xff, 0xfe, 0x86, 0xe5, 0x10], 0x0002)
        .expect("admit router E510");

    let start = Instant::now();
    let mut last_grat_ms: u64 = 0;
    let mut last_tick_ms: u64 = 0;
    let mut tx_buf = [0u8; 128];
    let mut assoc_handle: Option<TxHandle> = None;
    let mut transport_handle: Option<TxHandle> = None;
    let mut assoc_retries: u8 = 4;
    let mut transport_retries: u8 = 4;
    // Post-join follow-through (ported from fw/rd-coord for S31 parity):
    // confirm-driven retransmit (bounded) for the coordinator-initiated
    // Node_desc_req + joiner-lamp toggle. Without these the S31 admits
    // and secures but never converses (observed: Annce + NodeDescRsp
    // received, zero ZDO/toggle transmitted).
    let mut node_desc_handle: Option<TxHandle> = None;
    let mut node_desc_retries: u8 = 4;
    let mut node_desc_short: Option<u16> = None;
    let mut node_desc_pending: Option<u16> = None;
    let mut tog_pending = false;
    let mut tog_handle: Option<TxHandle> = None;
    let mut tog_tries: u8 = 0;
    const TOG_RETRIES: u8 = 4;
    let mut tog_done = false;
    let mut last_policy_th: u32 = 0;
    let mut last_policy_dn: u32 = 0;
    const C6_NETKEY: [u8; 16] = match option_env!("RD_NETKEY_HEX") {
        Some(s) => rounddance_commission::parse_hex_netkey(s),
        None => *b"C6JOIN01LABTEST!",
    };
    let transport_key = ha_transport_key().expect("HA transport key");
    let nwk_keys = KeySet::new(NetworkKey::new(C6_NETKEY, 0));
    loop {
        adapter.pump();
        let now_ms = start.elapsed().as_millis() as u64;
        let elapsed = now_ms.wrapping_sub(last_tick_ms);
        if elapsed > 0 {
            app.tick(now_ms, elapsed);
            last_tick_ms = now_ms;
        }
        while let Some(ind) = adapter.poll_mac_indication() {
            log_air(&mut log, "RDCOORD-S31 RX-MAC", ind.psdu());
            if let rounddance_hal_esp::mac_cmd::Incoming::AssocReq(req) = app.on_mac_psdu(ind.psdu()) {
                println!("RDCOORD-S31 RX-ASSOCREQ seq={} eui={:02x?}", req.seq, req.src_eui);
                assoc_handle = None;
                transport_handle = None;
                assoc_retries = 4;
                transport_retries = 4;
                node_desc_handle = None;
                node_desc_short = None;
                node_desc_pending = None;
                node_desc_retries = 4;
            }
        }
        while let Some(ind) = adapter.poll_indication() {
            log_air(&mut log, "RDCOORD-S31 RX", ind.msdu.as_slice());
            let outcome = app.on_nwk_data(ind.msdu.as_slice(), &nwk_keys, now_ms);
            println!("RDCOORD-S31 RX-NWK {:?}", outcome);
            if let NwkRxOutcome::Data { cluster, profile } = outcome {
                if cluster == 0x0006 && profile == 0x0104 {
                    match app.verify_defrsp(&mut log, &nwk_keys, ind.msdu.as_slice()) {
                        Ok(true) => println!("RDCOORD-S31 DEFRSP-OK toggle applied"),
                        Ok(false) => {}
                        Err(e) => println!("RDCOORD-S31 DEFRSP-FAILED {e:?}"),
                    }
                }
            }
            if let NwkRxOutcome::Annce { short, .. } = outcome {
                node_desc_short = Some(short);
                node_desc_pending = Some(short);
                node_desc_handle = None;
                node_desc_retries = 4;
            }
            if let NwkRxOutcome::ZdoResponse { status: Some(0), .. } = outcome {
                if !tog_done {
                    tog_done = true;
                    tog_pending = true;
                    tog_handle = None;
                    tog_tries = 0;
                    app.new_toggle();
                    println!("RDCOORD-S31 TX-TOGGLE-QUEUED");
                }
            }
        }
        while let Some(c) = adapter.poll_confirm() {
            println!("RDCOORD-S31 TX-CONFIRM status={:?}", c.status);
            if Some(c.handle) == assoc_handle {
                assoc_handle = None;
                if c.status != TxStatus::Delivered && assoc_retries > 0 {
                    assoc_retries -= 1;
                    println!("RDCOORD-S31 TX-ASSOC-NOACK; re-armed ({assoc_retries} left)");
                    app.rearm_assoc();
                }
            }
            if Some(c.handle) == transport_handle {
                transport_handle = None;
                if c.status != TxStatus::Delivered && transport_retries > 0 {
                    transport_retries -= 1;
                    println!("RDCOORD-S31 TX-TRANSPORT-NOACK; re-armed ({transport_retries} left)");
                    app.rearm_transport();
                }
            }
            if Some(c.handle) == node_desc_handle {
                node_desc_handle = None;
                if c.status != TxStatus::Delivered {
                    if node_desc_retries > 0 {
                        node_desc_retries -= 1;
                        println!("RDCOORD-S31 TX-NODE-DESC-NOACK; re-armed ({node_desc_retries} left)");
                        node_desc_pending = node_desc_short;
                    } else {
                        println!("RDCOORD-S31 TX-NODE-DESC-GIVEUP (budget exhausted)");
                    }
                }
            }
            if Some(c.handle) == tog_handle {
                tog_handle = None;
                if c.status == TxStatus::Delivered {
                    tog_pending = false;
                } else if tog_tries >= TOG_RETRIES {
                    println!("RDCOORD-S31 TX-TOGGLE-GIVEUP (budget exhausted)");
                    tog_pending = false;
                } else {
                    println!("RDCOORD-S31 TX-TOGGLE-NOACK; re-armed");
                    tog_pending = true;
                }
            }
        }
        if let Some(short) = node_desc_pending.take() {
            match app.take_node_desc_req(&mut tx_buf, short, &C6_NETKEY) {
                Ok(n) if n > 0 => {
                    log_air(&mut log, "RDCOORD-S31 TX-NODE-DESC-REQ", &tx_buf[..n]);
                    println!("RDCOORD-S31 ZDO-PENDING {}", app.zdo_pending_open());
                    persist_aux_chunk(&mut app);
                    match adapter.transmit_mac(&tx_buf[..n]) {
                        Ok(h) => node_desc_handle = Some(h),
                        Err(e) => println!("RDCOORD-S31 TX-NODE-DESC-FAILED {e:?}"),
                    }
                }
                Ok(_) => {}
                Err(e) => println!("RDCOORD-S31 NODE-DESC-BUILD-FAILED {e:?}"),
            }
        }
        if tog_pending && tog_handle.is_none() {
            if tog_tries >= TOG_RETRIES {
                println!("RDCOORD-S31 TX-TOGGLE-GIVEUP (budget exhausted)");
                tog_pending = false;
            } else {
                match app.build_toggle_request(&mut log, &C6_NETKEY, &mut tx_buf) {
                    Ok(n) if n > 0 => {
                        persist_aux_chunk(&mut app);
                        match adapter.transmit_mac(&tx_buf[..n]) {
                            Ok(h) => {
                                tog_handle = Some(h);
                                tog_tries += 1;
                            }
                            Err(e) => {
                                println!("RDCOORD-S31 TX-TOGGLE-FAILED {e:?}; re-armed");
                                tog_pending = true;
                            }
                        }
                    }
                    Ok(_) => {
                        tog_pending = false;
                    }
                    Err(e) => println!("RDCOORD-S31 TOGGLE-BUILD-FAILED {e:?}"),
                }
            }
        }
        if app.assoc_pending() {
            if let Ok(n) = app.take_assoc_rsp(&mut tx_buf) {
                if n > 0 {
                    log_air(&mut log, "RDCOORD-S31 TX-ASSOC-RSP", &tx_buf[..n]);
                    match adapter.transmit_mac(&tx_buf[..n]) {
                        Ok(h) => assoc_handle = Some(h),
                        Err(e) => {
                            println!("RDCOORD-S31 TX-ASSOC-FAILED {e:?}");
                            app.rearm_assoc();
                        }
                    }
                }
            }
        } else if app.transport_pending() {
            if let Ok(n) = app.take_transport_key(&mut tx_buf, &C6_NETKEY, &transport_key) {
                if n > 0 {
                    persist_aux_chunk(&mut app);
                    match adapter.transmit_mac(&tx_buf[..n]) {
                        Ok(h) => transport_handle = Some(h),
                        Err(e) => {
                            println!("RDCOORD-S31 TX-TRANSPORT-FAILED {e:?}");
                            app.rearm_transport();
                        }
                    }
                }
            }
        } else if app.beacon_pending() > 0 {
            if let Ok(n) = app.take_beacon(&mut tx_buf) {
                if n > 0 {
                    log_air(&mut log, "RDCOORD-S31 TX-BEACON", &tx_buf[..n]);
                    if adapter.transmit_mac(&tx_buf[..n]).is_ok() {
                        last_grat_ms = now_ms;
                    }
                }
            }
        } else if !app.is_associated()
            && gratuitous_due(last_grat_ms, now_ms, GRATUITOUS_BEACON_INTERVAL_MS)
        {
            if let Ok(n) = app.build_gratuitous_beacon(&mut tx_buf) {
                log_air(&mut log, "RDCOORD-S31 TX-BEACON-GRAT", &tx_buf[..n]);
                if adapter.transmit_mac(&tx_buf[..n]).is_ok() {
                    last_grat_ms = now_ms;
                }
            }
        }
        {
            let th = app.assoc_throttled();
            let dn = app.assoc_denied();
            if th != last_policy_th || dn != last_policy_dn {
                println!("RDCOORD-S31 ASSOC-POLICY throttled={th} denied={dn}");
                last_policy_th = th;
                last_policy_dn = dn;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
