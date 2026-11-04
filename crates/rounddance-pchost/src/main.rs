//! `rd-pchost`: the PC drives the rounddance stack with the chip
//! as radio (RCP mode) or half-host (NCP mode) over a serial UART.
//!
//! ```text
//! rd-pchost --port /dev/ttyUSB1 --mode rcp --role coord [--target s31]
//! rd-pchost --port /dev/ttyUSB1 --mode ncp --role coord --admit a0f262fffe8597a4:0001
//! ```
//!
//! RCP mode owns the full stack on the PC (`CoordinatorApp` or
//! `JoinerApp` over `RcpDriver<SerialUart>`, the same apps the
//! standalone images run): probe → provision → form/permit/admit →
//! MAC-command exchange (beacon/assoc via the MAC queue) →
//! transport-key → announce → Node_desc → Toggle → Default Response.
//! NCP mode commissions a half-host chip (form → permit → admit)
//! and drives its lamp (toggle → attribute report).
//!
//! Exit 0 on the verified end state (coordinator: `DEFRSP-OK` after
//! the toggle applies; joiner: lamp on; NCP: `Attr value=1`),
//! 1 on budget exhaustion, 2 on usage/probe-gate failures. Every
//! air frame is logged as `<TAG> <hex…>` for the sniffer +
//! dual-serial evidence leg; `--capture FILE` additionally tees raw
//! UART bytes both directions.

use rounddance_hal_esp::app::{
    JoinerNwkOutcome, NwkRxOutcome, APP_CHANNEL, APP_PAN, COORD_SHORT, JOINER_EUI, JOINER_SHORT,
    TC_EUI_WIRE, UNASSOC_SHORT,
};
use rounddance_hal_esp::mac_cmd::Incoming as MacIncoming;
use rounddance_hal_esp::{CoordinatorApp, JoinerApp, SerialLog};
use rounddance_mac_sap::{MacDataSap as _, TxStatus};
use rounddance_pchost::{log_air, wait_ready, wait_version, NcpRunner, PcRunner, RunnerError};
use rounddance_rcp::{NcpEvent, Uart};
use std::io::Write as _;

struct ConsoleLog;

impl SerialLog for ConsoleLog {
    fn log(&mut self, line: &str) {
        println!("{line}");
    }
}

/// UART tee: logs every byte both directions to a capture file
/// (dual-serial evidence) while delegating to the real port.
struct TeeUart {
    inner: rounddance_pchost::SerialUart,
    cap: Option<std::fs::File>,
}

impl TeeUart {
    fn cap_write(&mut self, dir: &str, bytes: &[u8]) {
        if let Some(f) = self.cap.as_mut() {
            let mut line = String::with_capacity(16 + 3 * bytes.len());
            line.push_str(dir);
            for b in bytes {
                line.push(' ');
                line.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('?'));
                line.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('?'));
            }
            line.push('\n');
            let _ = f.write_all(line.as_bytes());
        }
    }
}

impl Uart for TeeUart {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), rounddance_rcp::RcpError> {
        let r = self.inner.write_bytes(bytes);
        if r.is_ok() {
            self.cap_write("W", bytes);
        }
        r
    }

    fn read_byte(&mut self) -> Option<u8> {
        let b = self.inner.read_byte()?;
        self.cap_write("R", &[b]);
        Some(b)
    }
}

#[derive(Debug)]
struct Config {
    port: String,
    mode: String,
    role: String,
    target: Option<String>,
    channel: u8,
    pan: u16,
    capture: Option<String>,
    budget_secs: u64,
    admit: Vec<(String, u16)>,
}

fn usage() -> ! {
    eprintln!(
        "usage: rd-pchost --port PATH [--mode rcp|ncp] [--role coord|joiner] \
         [--target h2|c6|s31] [--channel N] [--pan HEX] [--capture FILE] \
         [--budget-secs N] [--admit EUI:SHORT ...]"
    );
    std::process::exit(2);
}

fn parse_hex_u16(s: &str) -> Option<u16> {
    let s = s.strip_prefix("0x").or(Some(s))?;
    if s.len() != 4 {
        return None;
    }
    u16::from_str_radix(s, 16).ok()
}

fn parse_eui(s: &str) -> Option<[u8; 8]> {
    if s.len() != 16 {
        return None;
    }
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn parse_args() -> Config {
    let mut port: Option<String> = None;
    let mut mode = "rcp".to_string();
    let mut role = "coord".to_string();
    let mut target: Option<String> = None;
    let mut channel: u8 = APP_CHANNEL;
    let mut pan: u16 = APP_PAN;
    let mut capture: Option<String> = None;
    let mut budget_secs: u64 = 180;
    let mut admit: Vec<(String, u16)> = Vec::new();
    let mut args = std::env::args().skip(1).peekable();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--port" => port = args.next(),
            "--mode" => mode = args.next().unwrap_or_default(),
            "--role" => role = args.next().unwrap_or_default(),
            "--target" => target = args.next(),
            "--channel" => {
                channel = args.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            }
            "--pan" => {
                pan = args.next().and_then(|v| parse_hex_u16(&v)).unwrap_or(0);
            }
            "--capture" => capture = args.next(),
            "--budget-secs" => {
                budget_secs = args.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            }
            "--admit" => {
                if let Some(v) = args.next() {
                    let mut it = v.split(':');
                    if let (Some(e), Some(s)) = (it.next(), it.next()) {
                        if let (Some(_), Some(short)) = (parse_eui(e), parse_hex_u16(s)) {
                            if admit.len() < 8 {
                                admit.push((e.to_string(), short));
                            }
                        }
                    }
                }
            }
            _ => usage(),
        }
    }
    let Some(port) = port else { usage() };
    if mode != "rcp" && mode != "ncp" {
        usage();
    }
    if role != "coord" && role != "joiner" {
        usage();
    }
    if !(11..=26).contains(&channel) || budget_secs == 0 {
        usage();
    }
    Config {
        port,
        mode,
        role,
        target,
        channel,
        pan,
        capture,
        budget_secs,
        admit,
    }
}

fn open_runner(cfg: &Config) -> Result<PcRunner<TeeUart>, RunnerError> {
    let inner = rounddance_pchost::SerialUart::open(&cfg.port, 460_800).map_err(|e| {
        eprintln!("RDHOST serial open failed: {e}");
        RunnerError::Timeout
    })?;
    let cap = cfg.capture.as_ref().and_then(|p| {
        std::fs::File::create(p)
            .map_err(|e| eprintln!("RDHOST capture open failed: {e}"))
            .ok()
    });
    Ok(PcRunner::new(TeeUart { inner, cap }))
}

fn probe_and_provision(
    runner: &mut PcRunner<TeeUart>,
    cfg: &Config,
    short: u16,
    ext: u64,
) -> Result<(), RunnerError> {
    use rounddance_mac_sap::MacMgmtSap as _;
    runner.driver_mut().reset(true);
    wait_ready(runner, 5_000, || {})?;
    let info = wait_version(runner, 5_000, || {})?;
    println!(
        "RDHOST PROBE fw={:#04x} proto={:#04x} caps={:#06x} eui={:02x?} target={}",
        info.fw_version,
        info.proto_version,
        info.caps,
        info.eui,
        info.target.unwrap_or("generic")
    );
    if let Some(want) = cfg.target.as_deref() {
        if info.target != Some(want) {
            eprintln!(
                "RDHOST target mismatch: want {want}, probed {:?}",
                info.target
            );
            return Err(RunnerError::WrongTarget);
        }
    }
    runner.provision(cfg.channel, cfg.pan, short, ext, 10)?;
    // Drain the provision writes before the app starts.
    for _ in 0..4 {
        runner.advance_wall();
        runner.driver_mut().poll();
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Ok(())
}

fn run_rcp_coord(cfg: &Config) -> Result<(), RunnerError> {
    use rounddance_hal_esp::mac_cmd::{gratuitous_due, GRATUITOUS_BEACON_INTERVAL_MS};
    let mut runner = open_runner(cfg)?;
    probe_and_provision(
        &mut runner,
        cfg,
        COORD_SHORT,
        u64::from_le_bytes(TC_EUI_WIRE),
    )?;
    let mut log = ConsoleLog;
    let mut app = CoordinatorApp::new();
    app.resume_auxctr(None);
    app.begin_formation(&mut log)
        .map_err(|_| RunnerError::Timeout)?;
    app.formation_done(&mut log, true);
    println!("RDHOST NETKEY lab-default (set RD_NETKEY_HEX for deployment)");
    app.open_permit(&mut log, 3_600_000)
        .map_err(|_| RunnerError::Timeout)?;
    app.admit_joiner(&mut log, 0)
        .map_err(|_| RunnerError::Timeout)?;
    for (eui_s, short) in &cfg.admit {
        if let Some(eui) = parse_eui(eui_s) {
            let _ = app.admit_extra(&mut log, eui, *short);
        }
    }
    const NETKEY: [u8; 16] = *b"C6JOIN01LABTEST!";
    let transport_key =
        rounddance_commission::ha_transport_key().map_err(|_| RunnerError::Timeout)?;
    let nwk_keys =
        rounddance_security::KeySet::new(rounddance_security::NetworkKey::new(NETKEY, 0));
    let start = std::time::Instant::now();
    let budget = std::time::Duration::from_secs(cfg.budget_secs);
    let mut tx_buf = [0u8; 128];
    let mut assoc_handle = None;
    let mut transport_handle = None;
    let mut assoc_retries: u8 = 4;
    let mut transport_retries: u8 = 4;
    let mut node_desc_handle = None;
    let mut node_desc_retries: u8 = 4;
    let mut node_desc_short = None;
    let mut node_desc_pending = None;
    let mut tog_pending = false;
    let mut tog_handle = None;
    let mut tog_tries: u8 = 0;
    let mut tog_done = false;
    let mut last_grat_ms = 0u64;
    let mut last_tick_ms = 0u64;
    loop {
        if start.elapsed() > budget {
            eprintln!("RDHOST coord budget exhausted (no verified toggle)");
            return Err(RunnerError::Timeout);
        }
        runner.advance_wall();
        let d = runner.driver_mut();
        d.poll();
        let now_ms = start.elapsed().as_millis() as u64;
        let elapsed = now_ms.wrapping_sub(last_tick_ms);
        if elapsed > 0 {
            app.tick(now_ms, elapsed);
            last_tick_ms = now_ms;
        }
        while let Some(ind) = d.poll_mac_indication() {
            println!("{}", log_air("RDHOST RX-MAC", ind.psdu()));
            if let MacIncoming::AssocReq(req) = app.on_mac_psdu(ind.psdu()) {
                println!(
                    "RDHOST RX-ASSOCREQ seq={} eui={:02x?}",
                    req.seq, req.src_eui
                );
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
        while let Some(ind) = d.poll_indication() {
            println!("{}", log_air("RDHOST RX", ind.msdu.as_slice()));
            let outcome = app.on_nwk_data(ind.msdu.as_slice(), &nwk_keys, now_ms);
            println!("RDHOST RX-NWK {outcome:?}");
            if let NwkRxOutcome::Data { cluster, profile } = outcome {
                if cluster == 0x0006 && profile == 0x0104 {
                    match app.verify_defrsp(&mut log, &nwk_keys, ind.msdu.as_slice()) {
                        Ok(true) => {
                            println!("RDHOST DEFRSP-OK toggle applied");
                            return Ok(());
                        }
                        Ok(false) => {}
                        Err(e) => println!("RDHOST DEFRSP-FAILED {e:?}"),
                    }
                }
            }
            if let NwkRxOutcome::Annce { short, .. } = outcome {
                node_desc_short = Some(short);
                node_desc_pending = Some(short);
                node_desc_handle = None;
                node_desc_retries = 4;
            }
            if let NwkRxOutcome::ZdoResponse {
                status: Some(0), ..
            } = outcome
            {
                if !tog_done {
                    tog_done = true;
                    tog_pending = true;
                    tog_handle = None;
                    tog_tries = 0;
                    app.new_toggle();
                    println!("RDHOST TX-TOGGLE-QUEUED");
                }
            }
        }
        while let Some(c) = d.poll_confirm() {
            println!("RDHOST TX-CONFIRM status={:?}", c.status);
            if Some(c.handle) == assoc_handle {
                assoc_handle = None;
                if c.status != TxStatus::Delivered && assoc_retries > 0 {
                    assoc_retries -= 1;
                    app.rearm_assoc();
                }
            }
            if Some(c.handle) == transport_handle {
                transport_handle = None;
                if c.status != TxStatus::Delivered && transport_retries > 0 {
                    transport_retries -= 1;
                    app.rearm_transport();
                }
            }
            if Some(c.handle) == node_desc_handle {
                node_desc_handle = None;
                if c.status != TxStatus::Delivered {
                    if node_desc_retries > 0 {
                        node_desc_retries -= 1;
                        node_desc_pending = node_desc_short;
                    } else {
                        println!("RDHOST TX-NODE-DESC-GIVEUP (budget exhausted)");
                    }
                }
            }
            if Some(c.handle) == tog_handle {
                tog_handle = None;
                if c.status == TxStatus::Delivered {
                    tog_pending = false;
                } else if tog_tries >= 4 {
                    println!("RDHOST TX-TOGGLE-GIVEUP (budget exhausted)");
                    tog_pending = false;
                } else {
                    tog_pending = true;
                }
            }
        }
        if let Some(short) = node_desc_pending.take() {
            match app.take_node_desc_req(&mut tx_buf, short, &NETKEY) {
                Ok(n) if n > 0 => {
                    println!("{}", log_air("RDHOST TX-NODE-DESC-REQ", &tx_buf[..n]));
                    match d.transmit_mac(&tx_buf[..n]) {
                        Ok(h) => node_desc_handle = Some(h),
                        Err(e) => println!("RDHOST TX-NODE-DESC-FAILED {e:?}"),
                    }
                }
                Ok(_) => {}
                Err(e) => println!("RDHOST NODE-DESC-BUILD-FAILED {e:?}"),
            }
        }
        if tog_pending && tog_handle.is_none() {
            if tog_tries >= 4 {
                println!("RDHOST TX-TOGGLE-GIVEUP (budget exhausted)");
                tog_pending = false;
            } else {
                match app.build_toggle_request(&mut log, &NETKEY, &mut tx_buf) {
                    Ok(n) if n > 0 => match d.transmit_mac(&tx_buf[..n]) {
                        Ok(h) => {
                            tog_handle = Some(h);
                            tog_tries += 1;
                        }
                        Err(e) => println!("RDHOST TX-TOGGLE-FAILED {e:?}; re-armed"),
                    },
                    Ok(_) => tog_pending = false,
                    Err(e) => println!("RDHOST TOGGLE-BUILD-FAILED {e:?}"),
                }
            }
        }
        if app.assoc_pending() {
            match app.take_assoc_rsp(&mut tx_buf) {
                Ok(n) if n > 0 => {
                    println!("{}", log_air("RDHOST TX-ASSOC-RSP", &tx_buf[..n]));
                    // SHORT-SNOOP second copy: confirm the assigned
                    // short to the RCP immediately, before any slow
                    // path (the firmware latched the first copy).
                    // The response shape carries (short, status) at
                    // the tail; status 0x00 is the success gate.
                    if n >= 4 && tx_buf[n - 1] == 0x00 {
                        let short = u16::from_le_bytes([tx_buf[n - 3], tx_buf[n - 2]]);
                        d.note_assoc_response(short, 0x00);
                    }
                    match d.transmit_mac(&tx_buf[..n]) {
                        Ok(h) => assoc_handle = Some(h),
                        Err(e) => {
                            println!("RDHOST TX-ASSOC-FAILED {e:?}; re-armed");
                            app.rearm_assoc();
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => println!("RDHOST ASSOC-BUILD-FAILED {e:?}"),
            }
        } else if app.transport_pending() {
            match app.take_transport_key(&mut tx_buf, &NETKEY, &transport_key) {
                Ok(n) if n > 0 => {
                    println!("{}", log_air("RDHOST TX-TRANSPORT-KEY", &tx_buf[..n]));
                    match d.transmit_mac(&tx_buf[..n]) {
                        Ok(h) => transport_handle = Some(h),
                        Err(e) => {
                            println!("RDHOST TX-TRANSPORT-FAILED {e:?}; re-armed");
                            app.rearm_transport();
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => println!("RDHOST TRANSPORT-BUILD-FAILED {e:?}"),
            }
        } else if app.beacon_pending() > 0 {
            match app.take_beacon(&mut tx_buf) {
                Ok(n) if n > 0 => {
                    println!("{}", log_air("RDHOST TX-BEACON", &tx_buf[..n]));
                    if d.transmit_mac(&tx_buf[..n]).is_ok() {
                        last_grat_ms = now_ms;
                    }
                }
                Ok(_) => {}
                Err(e) => println!("RDHOST BEACON-BUILD-FAILED {e:?}"),
            }
        } else if !app.is_associated()
            && gratuitous_due(last_grat_ms, now_ms, GRATUITOUS_BEACON_INTERVAL_MS)
        {
            match app.build_gratuitous_beacon(&mut tx_buf) {
                Ok(n) => {
                    println!("{}", log_air("RDHOST TX-BEACON-GRAT", &tx_buf[..n]));
                    if d.transmit_mac(&tx_buf[..n]).is_ok() {
                        last_grat_ms = now_ms;
                    }
                }
                Err(e) => println!("RDHOST GRAT-BUILD-FAILED {e:?}"),
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn run_rcp_joiner(cfg: &Config) -> Result<(), RunnerError> {
    use rounddance_hal_esp::mac_cmd::build_beacon_req;
    use rounddance_mac_sap::MacMgmtSap as _;
    static LAMP_DEF: rounddance_zcl::onoff::ServerDef = rounddance_zcl::onoff::ServerDef;
    let mut runner = open_runner(cfg)?;
    probe_and_provision(
        &mut runner,
        cfg,
        UNASSOC_SHORT,
        u64::from_le_bytes(JOINER_EUI),
    )?;
    let mut log = ConsoleLog;
    let mut app = JoinerApp::new(&LAMP_DEF).map_err(|_| RunnerError::Timeout)?;
    app.resume_auxctr(None);
    app.begin_scan(&mut log).map_err(|_| RunnerError::Timeout)?;
    let start = std::time::Instant::now();
    let budget = std::time::Duration::from_secs(cfg.budget_secs);
    let mut tx_buf = [0u8; 160];
    let mut mac_seq: u8 = 0;
    let mut scan_open = true;
    let mut last_scan_ms = 0u64;
    const SCAN_WINDOW_MS: u64 = 4_000;
    let mut last_req_ms = 0u64;
    const REQ_INTERVAL_MS: u64 = 2_000;
    let mut assoc_tries: u32 = 0;
    const ASSOC_RETRIES_MAX: u32 = 30;
    let mut adopted_pan = None;
    let mut adopted_short = None;
    let mut annce_pending = false;
    let mut annce_handle = None;
    let mut annce_tries: u8 = 0;
    let mut tog_pending = false;
    let mut tog_handle = None;
    let mut tog_tries: u8 = 0;
    let mut tog_buf = [0u8; 160];
    let mut tog_len = 0usize;
    loop {
        if start.elapsed() > budget {
            eprintln!("RDHOST joiner budget exhausted (lamp off)");
            return Err(RunnerError::Timeout);
        }
        runner.advance_wall();
        let d = runner.driver_mut();
        d.poll();
        let now_ms = start.elapsed().as_millis() as u64;
        if app.candidate_pan().is_none() {
            if !scan_open && now_ms.wrapping_sub(last_scan_ms) >= SCAN_WINDOW_MS {
                last_scan_ms = now_ms;
                scan_open = app.begin_scan(&mut log).is_ok();
            } else if scan_open && now_ms.wrapping_sub(last_scan_ms) >= SCAN_WINDOW_MS {
                last_scan_ms = now_ms;
                scan_open = false;
                if let Some(pan) = app.finish_scan(&mut log) {
                    println!("RDHOST CANDIDATE pan={pan:#06x}");
                }
            }
        }
        while let Some(ind) = d.poll_mac_indication() {
            println!("{}", log_air("RDHOST RX-MAC", ind.psdu()));
            match app.on_mac_psdu(
                &mut log,
                ind.psdu(),
                ind.channel_number(),
                ind.rssi(),
                ind.lqi(),
            ) {
                MacIncoming::Beacon(bi) => {
                    println!(
                        "RDHOST RX-BEACON pan={:#06x} permit={}",
                        bi.src_pan, bi.assoc_permit
                    );
                }
                MacIncoming::AssocRsp(rsp) => {
                    println!(
                        "RDHOST RX-ASSOC-RSP short={:#06x} status={:#04x}",
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
                if adopted_pan != Some(pan) {
                    d.set_pan_id(pan);
                    adopted_pan = Some(pan);
                    println!("RDHOST ADOPTED pan={pan:#06x}");
                }
                match app.take_assoc_req(&mut tx_buf, pan, COORD_SHORT) {
                    Ok(n) if n > 0 => {
                        println!("{}", log_air("RDHOST TX-ASSOC-REQ", &tx_buf[..n]));
                        if d.transmit_mac(&tx_buf[..n]).is_ok() {
                            assoc_tries += 1;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => println!("RDHOST ASSOC-BUILD-FAILED {e:?}"),
                }
            } else {
                mac_seq = mac_seq.wrapping_add(1);
                match build_beacon_req(mac_seq, &mut tx_buf) {
                    Ok(n) => {
                        println!("{}", log_air("RDHOST TX-BEACON-REQ", &tx_buf[..n]));
                        let _ = d.transmit_mac(&tx_buf[..n]);
                    }
                    Err(e) => println!("RDHOST BEACON-REQ-BUILD-FAILED {e:?}"),
                }
            }
        } else if let Some(short) = app.assoc_short() {
            if adopted_short != Some(short) {
                adopted_short = Some(short);
                d.set_short_addr(short);
                d.note_assoc_response(short, 0x00);
                println!("RDHOST ADOPTED-SHORT short={short:#06x}");
            }
        }
        while let Some(ind) = d.poll_indication() {
            println!("{}", log_air("RDHOST RX-NWK", ind.msdu.as_slice()));
            match app.on_nwk_joiner(ind.msdu.as_slice()) {
                JoinerNwkOutcome::TransportAccepted { auxctr } => {
                    println!("RDHOST TRANSPORT-OPEN auxctr={auxctr:#010x}");
                    annce_pending = true;
                    annce_handle = None;
                    annce_tries = 0;
                }
                JoinerNwkOutcome::NodeDescReq { .. } => {}
                JoinerNwkOutcome::Data { .. } => {
                    let m = ind.msdu.as_slice();
                    if m.len() <= tog_buf.len() {
                        tog_buf[..m.len()].copy_from_slice(m);
                        tog_len = m.len();
                        tog_pending = true;
                        tog_handle = None;
                        tog_tries = 0;
                    }
                }
                JoinerNwkOutcome::NwkCommand { id } => {
                    println!("RDHOST RX-NWK-CMD id={id:#04x}");
                }
                JoinerNwkOutcome::Ignored(why) => {
                    println!("RDHOST RX-NWK-IGNORED {why:?}");
                }
            }
        }
        if annce_pending && annce_handle.is_none() {
            if annce_tries >= 4 {
                annce_pending = false;
                app.verify_confirm(&mut log);
                app.close_out(&mut log);
            } else {
                match app.take_annce(&mut tx_buf) {
                    Ok(n) if n > 0 => {
                        println!("{}", log_air("RDHOST TX-ANNCE", &tx_buf[..n]));
                        match d.transmit_mac(&tx_buf[..n]) {
                            Ok(h) => {
                                annce_handle = Some(h);
                                annce_tries += 1;
                            }
                            Err(e) => println!("RDHOST TX-ANNCE-FAILED {e:?}"),
                        }
                    }
                    Ok(_) => annce_pending = false,
                    Err(e) => println!("RDHOST ANNCE-BUILD-FAILED {e:?}"),
                }
            }
        }
        if tog_pending && tog_handle.is_none() {
            if tog_tries >= 4 {
                tog_pending = false;
            } else {
                match app.answer_toggle(&mut log, &tog_buf[..tog_len], &mut tx_buf) {
                    Ok(n) if n > 0 => {
                        println!("{}", log_air("RDHOST TX-TOG", &tx_buf[..n]));
                        match d.transmit_mac(&tx_buf[..n]) {
                            Ok(h) => {
                                tog_handle = Some(h);
                                tog_tries += 1;
                            }
                            Err(e) => println!("RDHOST TX-TOG-FAILED {e:?}"),
                        }
                    }
                    Ok(_) => tog_pending = false,
                    Err(e) => println!("RDHOST TOG-BUILD-FAILED {e:?}"),
                }
            }
        }
        while let Some(c) = d.poll_confirm() {
            if Some(c.handle) == annce_handle {
                annce_handle = None;
                if c.status == TxStatus::Delivered {
                    annce_pending = false;
                    app.verify_confirm(&mut log);
                    app.close_out(&mut log);
                    println!("RDHOST JOINED announced");
                }
            }
            if Some(c.handle) == tog_handle {
                tog_handle = None;
                if c.status == TxStatus::Delivered {
                    println!("RDHOST LAMP on={} (toggle answered)", app.lamp());
                    if app.lamp() {
                        return Ok(());
                    }
                    tog_pending = false;
                } else {
                    tog_pending = tog_tries < 4;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn run_ncp(cfg: &Config) -> Result<(), RunnerError> {
    let inner = rounddance_pchost::SerialUart::open(&cfg.port, 460_800).map_err(|e| {
        eprintln!("RDHOST serial open failed: {e}");
        RunnerError::Timeout
    })?;
    let cap = cfg.capture.as_ref().and_then(|p| {
        std::fs::File::create(p)
            .map_err(|e| eprintln!("RDHOST capture open failed: {e}"))
            .ok()
    });
    let mut runner = NcpRunner::new(TeeUart { inner, cap });
    runner.host_mut().reset(true).map_err(RunnerError::Ncp)?;
    std::thread::sleep(std::time::Duration::from_millis(200));
    runner.advance_wall();
    runner
        .host_mut()
        .form(cfg.channel, cfg.pan, 10)
        .map_err(RunnerError::Ncp)?;
    runner.host_mut().permit(3_600).map_err(RunnerError::Ncp)?;
    // Admit the lab joiner by default (plus any --admit entries).
    let mut admits: Vec<([u8; 8], u16)> = vec![(JOINER_EUI, JOINER_SHORT)];
    for (eui_s, short) in &cfg.admit {
        if let Some(eui) = parse_eui(eui_s) {
            admits.push((eui, *short));
        }
    }
    for (eui, short) in &admits {
        runner
            .host_mut()
            .admit(*eui, *short)
            .map_err(RunnerError::Ncp)?;
    }
    let start = std::time::Instant::now();
    let budget = std::time::Duration::from_secs(cfg.budget_secs);
    // Drive: poll events, toggle once the first join lands.
    let mut toggled = false;
    loop {
        if start.elapsed() > budget {
            eprintln!("RDHOST NCP budget exhausted (no Attr value=1)");
            return Err(RunnerError::Timeout);
        }
        runner.advance_wall();
        std::thread::sleep(std::time::Duration::from_millis(10));
        for ev in runner.events() {
            match ev {
                NcpEvent::Ready { fw_version } => {
                    println!("RDHOST NCP READY fw={fw_version:#04x}");
                }
                NcpEvent::Status { state, joined } => {
                    println!("RDHOST NCP STATUS state={state:#04x} joined={joined}");
                }
                NcpEvent::Joined { short, eui } => {
                    println!("RDHOST NCP JOINED short={short:#06x} eui={eui:02x?}");
                    if !toggled {
                        toggled = true;
                        runner.host_mut().toggle(short).map_err(RunnerError::Ncp)?;
                        println!("RDHOST NCP TX-TOGGLE short={short:#06x}");
                    }
                }
                NcpEvent::Attr {
                    short,
                    cluster,
                    value,
                } => {
                    println!(
                        "RDHOST NCP ATTR short={short:#06x} cluster={cluster:#06x} value={value}"
                    );
                    if value == 1 {
                        println!("RDHOST NCP LAMP-ON verified");
                        return Ok(());
                    }
                    // Toggle again until the lamp reports on.
                    runner.host_mut().toggle(short).map_err(RunnerError::Ncp)?;
                }
                NcpEvent::Error { code } => {
                    println!("RDHOST NCP ERROR code={code:#04x}");
                }
            }
        }
    }
}

fn main() {
    let cfg = parse_args();
    if cfg.port.is_empty() {
        usage();
    }
    let rc = match (cfg.mode.as_str(), cfg.role.as_str()) {
        ("rcp", "coord") => run_rcp_coord(&cfg),
        ("rcp", "joiner") => run_rcp_joiner(&cfg),
        ("ncp", _) => run_ncp(&cfg),
        _ => usage(),
    };
    match rc {
        Ok(()) => {
            println!("RDHOST DONE ok");
            std::process::exit(0);
        }
        Err(RunnerError::WrongTarget) => std::process::exit(2),
        Err(e) => {
            eprintln!("RDHOST FAIL {e}");
            std::process::exit(1);
        }
    }
}
