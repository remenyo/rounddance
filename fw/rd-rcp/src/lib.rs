//! `rd-rcp`: universal RCP radio firmware engine (H2 + C6 + S31).
//!
//! The chip is a bare 15.4 radio speaking the `otbr` RCP wire
//! (`docs/otbr/protocol.md`, crate `rounddance-rcp`): the PC owns
//! the full Zigbee stack and drives this firmware over a 460800 8N1
//! UART. Three thin image crates (`fw/rd-rcp-h2`, `fw/rd-rcp-c6`,
//! `fw/rd-rcp-s31`) bind this engine to per-target pins, UART, and
//! capability bits; all radio logic lives here, once.
//!
//! # Role split
//!
//! * 15.4 via [`EspIdfDriver`](rounddance_hal_esp::EspIdfDriver)
//!   (NVS-first init, filtering, TX-DONE/RX pump, energy scan — the
//!   proven `hal-esp` driver, used raw, not through `EspAdapter`:
//!   the PC builds MAC headers itself, so the firmware radiates and
//!   forwards complete PSDUs verbatim and never classifies).
//! * UART via the local [`uart`] module (IDF `driver/uart.h` FFI,
//!   460800 8N1 raw, no flow control).
//! * Command apply + event emit mirrors
//!   [`EmulatedRcp`](rounddance_rcp::EmulatedRcp) (the contract pin)
//!   including the SHORT-SNOOP short latch — same
//!   [`snoop_assoc_short`](rounddance_rcp::mac::snoop_assoc_short)
//!   function both ends share, so sim and air agree on the latch.
//!
//! # Portability notes
//!
//! This crate links IDF `std` like every `fw/*` image (the 15.4
//! driver and NVS live there) — `no_std` is not applicable at this
//! layer. `unsafe` is confined to [`ffi`] (extern declarations, each
//! citing its header) and [`uart`] (register-contract calls, each
//! with a `SAFETY` comment), on the `hal-esp` precedent; the engine
//! logic itself is safe. Crate root carries
//! `#![deny(unsafe_code)]`, the two FFI modules carry the inner
//! `allow`.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-RCP-NCP-06` (RCP firmware images).

#![deny(unsafe_code)]

use rounddance_hal_esp::{Driver as _, EspIdfDriver};
use rounddance_rcp::cmd::{
    Command, Event, TxOutcome, CAPS_TARGET_C6, CAPS_TARGET_H2, CAPS_TARGET_S31, E_BAD_CHANNEL,
    E_BAD_COMMAND, E_NOT_READY, E_POWER_CAPPED, MAX_PSDU,
};
use rounddance_rcp::frame::{Decoder, Outcome};
use rounddance_rcp::{mac, MAX_TX_POWER_DBM, RCP_CAPS, RCP_FW_VERSION, RCP_PROTO_VERSION};

pub mod ffi;
pub mod uart;

/// Which radio this image drives (pins + caps bit in the image).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// ESP32-H2 minimal-radio unit.
    H2,
    /// ESP32-C6 unit.
    C6,
    /// ESP32-S31 unit.
    S31,
}

impl Target {
    /// Short console tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::H2 => "H2",
            Self::C6 => "C6",
            Self::S31 => "S31",
        }
    }

    /// Capability bit this target reports in the version handshake
    /// (the universal PC runner names the radio from it).
    #[must_use]
    pub const fn caps_bit(self) -> u16 {
        match self {
            Self::H2 => CAPS_TARGET_H2,
            Self::C6 => CAPS_TARGET_C6,
            Self::S31 => CAPS_TARGET_S31,
        }
    }
}

/// Board wiring for one image. Pin numbers are the image's UART1
/// pair; the image bakes them from `RD_RCP_RX_PIN`/`RD_RCP_TX_PIN`
/// (decimal, build-time) over the target defaults below via
/// [`pin_or`]. Defaults are the lab record (`docs/otbr/topology.md`):
/// H2 verified through the S3 link, C6/S31 pending the air proof and
/// adjustable without source edits.
#[derive(Clone, Copy, Debug)]
pub struct Board {
    /// Radio target (console tag + caps bit).
    pub target: Target,
    /// IDF UART number carrying the RCP wire (default 1).
    pub uart_num: i32,
    /// UART RX pin (receives host-TX).
    pub rx_pin: i32,
    /// UART TX pin (drives host-RX).
    pub tx_pin: i32,
}

impl Board {
    /// H2 image wiring: the proven S3↔H2 pair (H2-GPIO23 RX from
    /// S3-TX, H2-GPIO24 TX to S3-RX).
    #[must_use]
    pub const fn h2() -> Self {
        Self {
            target: Target::H2,
            uart_num: 1,
            rx_pin: 23,
            tx_pin: 24,
        }
    }

    /// C6 image wiring: UART1 on GPIO16/17 (lab record pending the
    /// air proof; override with `RD_RCP_RX_PIN`/`RD_RCP_TX_PIN`).
    #[must_use]
    pub const fn c6() -> Self {
        Self {
            target: Target::C6,
            uart_num: 1,
            rx_pin: 16,
            tx_pin: 17,
        }
    }

    /// S31 image wiring: UART1 on GPIO15/16 (lab record pending the
    /// air proof; override with `RD_RCP_RX_PIN`/`RD_RCP_TX_PIN`).
    #[must_use]
    pub const fn s31() -> Self {
        Self {
            target: Target::S31,
            uart_num: 1,
            rx_pin: 15,
            tx_pin: 16,
        }
    }

    /// Capability bit for the version handshake.
    #[must_use]
    pub const fn caps_bit(self) -> u16 {
        self.target.caps_bit()
    }
}

/// Build-time pin override: decimal `RD_RCP_*_PIN` env over a target
/// default. Non-decimal values fail the build loudly (a mistuned pin
/// wedges the wire silently otherwise).
#[must_use]
pub const fn pin_or(env: Option<&str>, default: i32) -> i32 {
    match env {
        None => default,
        Some(s) => parse_pin(s),
    }
}

const fn parse_pin(s: &str) -> i32 {
    let b = s.as_bytes();
    let mut i = 0;
    let mut v: i32 = 0;
    while i < b.len() {
        assert!(b[i] >= b'0' && b[i] <= b'9', "RD_RCP pin not decimal");
        v = v * 10 + (b[i] - b'0') as i32;
        i += 1;
    }
    v
}

/// Firmware state: programmed radio identity + one in-flight TX.
struct State {
    channel: Option<u8>,
    power_dbm: i8,
    pan: Option<u16>,
    short: Option<u16>,
    ext: Option<u64>,
    promiscuous: bool,
    pending_tx_seq: Option<u8>,
    eui: [u8; 8],
    tx_count: u32,
    rx_count: u32,
}

/// Run the RCP firmware on `board`: init 15.4 + UART, emit `Ready`,
/// then serve the wire forever.
pub fn run(board: Board) -> ! {
    println!(
        "RD-RCP-{} boot uart={} rx={} tx={} baud=460800",
        board.target.tag(),
        board.uart_num,
        board.rx_pin,
        board.tx_pin
    );
    let mut radio = EspIdfDriver::new();
    radio.init().expect("15.4 init");
    radio.start_rx().expect("receiver running");
    // Boot posture mirrors the scripted peer: promiscuous (all
    // frames, no HW ACK) until the host engages filtered + HW
    // auto-ACK for association.
    let _ = radio.set_promiscuous(true);
    let eui = board_eui();
    println!("RD-RCP-{} eui={eui:02x?}", board.target.tag());
    uart::init(board.uart_num, board.rx_pin, board.tx_pin);
    let mut state = State {
        channel: None,
        power_dbm: 0,
        pan: None,
        short: None,
        ext: None,
        promiscuous: true,
        pending_tx_seq: None,
        eui,
        tx_count: 0,
        rx_count: 0,
    };
    emit(&Event::Ready {
        fw_version: RCP_FW_VERSION,
    });
    let mut dec = Decoder::new();
    let mut rxb = [0u8; 256];
    loop {
        // UART → commands.
        let n = uart::read(board.uart_num, &mut rxb);
        for b in &rxb[..n] {
            match dec.push_byte(*b) {
                Some(Outcome::Frame(f)) => handle_cmd(&mut radio, &mut state, board, &f),
                Some(Outcome::Dropped(_)) => emit(&Event::Error {
                    code: E_BAD_COMMAND,
                }),
                None => {}
            }
        }
        // 15.4 TX reports → confirms.
        for _ in 0..4 {
            let Some(ev) = radio.poll_tx() else { break };
            if let Some(seq) = state.pending_tx_seq.take() {
                let status = match ev {
                    rounddance_hal_esp::TxEvent::Done => TxOutcome::Delivered,
                    rounddance_hal_esp::TxEvent::Failed(rounddance_hal_esp::TxFail::CcaBusy) => {
                        TxOutcome::ChannelBusy
                    }
                    rounddance_hal_esp::TxEvent::Failed(_) => TxOutcome::NoAck,
                };
                state.tx_count += 1;
                emit(&Event::TxConfirm { seq, status });
            }
        }
        // 15.4 RX → channel-tagged events (+ SHORT-SNOOP latch).
        for _ in 0..4 {
            let Some(rx) = radio.poll_rx() else { break };
            handle_air(&mut radio, &mut state, &rx);
        }
        if n == 0 {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
}

/// Read the unit base MAC and expand it to the 15.4 EUI-64
/// (`ff:fe` rule, same as the standalone images).
fn board_eui() -> [u8; 8] {
    let mut mac = [0u8; 6];
    let rc = ffi::read_base_mac(&mut mac);
    assert!(rc == 0, "esp_read_mac BASE rc={rc}");
    rounddance_hal_esp::app::eui_from_mac(&mac)
}

/// Emit one RCP event on the wire (bounded; drops under UART
/// backpressure are counted on the console, never silent).
fn emit(ev: &Event) {
    let mut wire = [0u8; 160];
    let n = ev.encode(0, &mut wire).unwrap_or(0);
    if n > 0 {
        uart::write_all(&wire[..n]);
    }
}

/// Apply one host command frame.
fn handle_cmd(
    radio: &mut EspIdfDriver,
    state: &mut State,
    board: Board,
    frame: &rounddance_rcp::Frame,
) {
    let cmd = match Command::decode(frame) {
        Ok(c) => c,
        Err(_) => {
            emit(&Event::Error {
                code: E_BAD_COMMAND,
            });
            return;
        }
    };
    match cmd {
        Command::Reset { cold } => {
            if cold {
                state.channel = None;
                state.pan = None;
                state.short = None;
                state.ext = None;
                state.promiscuous = true;
                let _ = radio.set_promiscuous(true);
            }
            state.pending_tx_seq = None;
            println!("RD-RCP-{} reset cold={cold}", board.target.tag());
            emit(&Event::Ready {
                fw_version: RCP_FW_VERSION,
            });
        }
        Command::SetChannel { channel } => {
            if !(11..=26).contains(&channel) {
                emit(&Event::Error {
                    code: E_BAD_CHANNEL,
                });
                return;
            }
            match radio.set_channel(channel) {
                Ok(()) => {
                    state.channel = Some(channel);
                    println!("RD-RCP-{} ch={channel}", board.target.tag());
                }
                Err(_) => emit(&Event::Error {
                    code: E_BAD_CHANNEL,
                }),
            }
        }
        Command::SetTxPower { dbm } => {
            if dbm > MAX_TX_POWER_DBM {
                // Standing lab policy, mirrored in firmware: hotter
                // requests are refused, never applied.
                emit(&Event::Error {
                    code: E_POWER_CAPPED,
                });
                return;
            }
            match radio.set_tx_power(dbm) {
                Ok(()) => state.power_dbm = dbm,
                Err(_) => emit(&Event::Error {
                    code: E_POWER_CAPPED,
                }),
            }
        }
        Command::SetPanId { pan } => {
            state.pan = Some(pan);
            program_addrs(radio, state);
            println!("RD-RCP-{} pan={pan:#06x}", board.target.tag());
        }
        Command::SetShortAddr { addr } => {
            state.short = Some(addr);
            program_addrs(radio, state);
            println!("RD-RCP-{} short={addr:#06x}", board.target.tag());
        }
        Command::SetExtAddr { addr } => {
            state.ext = Some(addr);
            program_addrs(radio, state);
            println!("RD-RCP-{} ext set", board.target.tag());
        }
        Command::TxFrame {
            inter_pan: _,
            len,
            psdu,
        } => {
            if state.pending_tx_seq.is_some() {
                // Host-firmware single-flight contract broken: say
                // so instead of silently queuing.
                emit(&Event::Error { code: E_NOT_READY });
                return;
            }
            let mut air = [0u8; 128];
            air[0] = len.wrapping_add(2);
            air[1..1 + len as usize].copy_from_slice(&psdu[..len as usize]);
            match radio.transmit(&air[..1 + len as usize]) {
                Ok(()) => state.pending_tx_seq = Some(frame.seq),
                Err(_) => emit(&Event::Error { code: E_NOT_READY }),
            }
        }
        Command::EnergyScan { channel } => {
            if !(11..=26).contains(&channel) {
                emit(&Event::Error {
                    code: E_BAD_CHANNEL,
                });
                return;
            }
            match radio.energy_scan(channel) {
                Ok(dbm) => emit(&Event::EnergyResult {
                    channel,
                    energy: dbm as u8,
                }),
                Err(_) => emit(&Event::Error {
                    code: E_BAD_CHANNEL,
                }),
            }
        }
        Command::GetVersion => emit(&Event::Version {
            fw_version: RCP_FW_VERSION,
            proto_version: RCP_PROTO_VERSION,
            caps: RCP_CAPS | board.caps_bit(),
            eui: state.eui,
        }),
        Command::SetPromiscuous { promiscuous } => match radio.set_promiscuous(promiscuous) {
            Ok(()) => {
                state.promiscuous = promiscuous;
                println!("RD-RCP-{} promiscuous={promiscuous}", board.target.tag());
            }
            Err(_) => emit(&Event::Error {
                code: E_BAD_COMMAND,
            }),
        },
    }
}

/// Program PAN + short + extended addresses into the radio filter
/// (partial state programs what is known; unknown fields keep the
/// driver's current match).
fn program_addrs(radio: &mut EspIdfDriver, state: &State) {
    let pan = state.pan.unwrap_or(0xFFFF);
    let short = state.short.unwrap_or(0xFFFF);
    let ext = state.ext.unwrap_or(0);
    let _ = radio.set_addrs(pan, short, &ext.to_le_bytes());
}

/// Handle one received air frame: SHORT-SNOOP latch (programs the
/// radio filter immediately) + channel-tagged forward.
fn handle_air(radio: &mut EspIdfDriver, state: &mut State, rx: &rounddance_hal_esp::RxFrame) {
    let air = rx.as_slice();
    if air.is_empty() {
        return;
    }
    // Len+2: air[0] counts itself + PSDU + 2 FCS octets.
    let total = air[0] as usize;
    if total < 1 + 2 || total > air.len() {
        return;
    }
    let psdu = &air[1..total - 1];
    if psdu.len() > MAX_PSDU {
        return;
    }
    // SHORT-SNOOP first (microseconds, before any slow path): the
    // assigned short programs the filter so the transport-key frame
    // that follows within milliseconds still matches.
    if let Some(short) = mac::snoop_assoc_short(state.pan, state.ext, psdu, state.short) {
        state.short = Some(short);
        program_addrs(radio, state);
        println!("RD-RCP-SNOOP short={short:#06x}");
    }
    let mut buf = [0u8; MAX_PSDU];
    buf[..psdu.len()].copy_from_slice(psdu);
    let inter_pan = mac::parse_inter_pan_psdu(psdu).is_some();
    state.rx_count += 1;
    if state.rx_count % 128 == 0 {
        println!("RD-RCP-RX count={} tx={}", state.rx_count, state.tx_count);
    }
    emit(&Event::MacFrame {
        inter_pan,
        rssi: rx.rssi,
        lqi: rx.lqi,
        channel: rx.channel,
        len: psdu.len() as u8,
        psdu: buf,
    });
}
