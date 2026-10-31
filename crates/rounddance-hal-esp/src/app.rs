//! C6-standalone full-stack app: coordinator + joiner roles composed
//! from the repo crates over [`EspAdapter`](crate::adapter::EspAdapter).
//!
//! This is the productized shape of the wave-23 OTA run (`rd-c6join` in
//! scratch `~/hwscratch/c6join`): the same form → permit → admit →
//! install-code join → DeviceAnnce → secured ZCL Toggle sequence, now
//! as first-class repo code with role selection, serial-log
//! discipline, and a [`MockDriver`](crate::mock::MockDriver)-backed
//! proof that runs on host.
//!
//! Stack order (both roles): `EspAdapter` (MAC SAP) → `rounddance-nwk`
//! → `rounddance-aps` + `rounddance-security` aux → `rounddance-zdo`
//! (announce) / `rounddance-zcl` (toggle). Role orchestration reuses
//! `rounddance-roles` (`CoordinatorMachine`) and
//! `rounddance-commission` (formation, steering, classical join,
//! `TrustCenter`). Nothing here re-implements those layers; this crate
//! only binds them to the two C6 images and the radio.
//!
//! Radio facts inherited from the OTA proof (no hardware is touched by
//! this crate's tests — they run over [`MockDriver`]):
//! * channel 15, PAN `0xC601`, TX `+10` dBm (standing cap);
//! * coordinator short `0x0000`, joiner short `0x0001` (placeholder
//!   `0xFFFF` until association, as on device);
//! * role from the full 6-octet unit base MAC: coordinator
//!   `a0:f2:62:86:7f:68` (healthy lab C6 7F68, efuse-verified),
//!   joiner `a0:f2:62:85:97:a4` (lab C6 97A4); anything else refuses
//!   to start before touching the radio, exactly like the scratch
//!   image did (which gated on the last octet of a now-absent pair).
//!
//! Requirement IDs: corpus role/commission IDs are reused inline;
//! `RD-APP-C6-*` rows are repo-minted (MINTED-pending-confirm).

use crate::mac_cmd::{
    eui_matches, CoordAssoc, DataPoll, Incoming as MacIncoming, MacCmdError,
    SUPERFRAME_ASSOC_PERMIT,
};
use rounddance_aps::{decode_data, DataDest, DataHeader, DeliveryMode, FrameControl as ApsFc};
use rounddance_commission::{
    BeaconSurveyEntry, ChannelMask, FormationConfig, FormationState, InstallCode, JoinError,
    JoinMethod, JoinPolicy, JoinerMachine, JoinerState, KeyAttributes, LinkEvidencePolicy,
    LogicalType, MmoJoinKdf, PanChoice, SteeringMachine, SteeringState, TrustCenter,
    TRANSPORT_AUX_BASE,
};
use rounddance_nwk::{decode as nwk_decode, FrameControl as NwkFc, NwkHeader};
use rounddance_roles::{AgingPolicy, CoordinatorMachine, CoordinatorState};
use rounddance_security::{
    AuxHeader, FrameCounter, KeyIdMode, KeyIdentifier, ReplayTable, SecurityControl,
};
use rounddance_zcl::{
    behavior::{Ctx, EventQueue},
    dispatch,
    frame::{Direction, FrameControl as ZclFrameControl, FrameType, Header as ZclHeader},
    general::{cmd::DEFAULT_RSP, DefaultRsp},
    onoff, should_default_respond,
    status::ZclStatus,
    DispatchOutcome, Endpoint, ReportingEngine,
};

/// Application channel (OTA-proven).
pub const APP_CHANNEL: u8 = 15;
/// Application PAN identifier (OTA-proven fresh network).
pub const APP_PAN: u16 = 0xC601;
/// Coordinator short address.
pub const COORD_SHORT: u16 = 0x0000;
/// Joiner short address assigned at association.
pub const JOINER_SHORT: u16 = 0x0001;
/// Short address placeholder before association.
pub const UNASSOC_SHORT: u16 = 0xFFFF;
/// Unit-MAC last octet selecting the coordinator role (low byte of
/// [`COORD_BASE_MAC`]; kept for log/discipline continuity, NOT used
/// for selection — selection compares the full base MAC).
pub const COORD_MAC_LAST: u8 = 0x68;
/// Unit-MAC last octet selecting the joiner role (low byte of
/// [`JOINER_BASE_MAC`]; see above).
pub const JOINER_MAC_LAST: u8 = 0xa4;
/// Coordinator unit base MAC (healthy lab C6 7F68): `esptool
/// read-mac` BASE MAC `a0:f2:62:86:7f:68` (efuse, verified under
/// lease; USB by-id MAC matches BASE MAC). Preferred coordinator per
/// LADDER rung 2 (healthy unit for first light).
pub const COORD_BASE_MAC: [u8; 6] = [0xa0, 0xf2, 0x62, 0x86, 0x7f, 0x68];
/// Joiner unit base MAC (lab C6 97A4): `esptool read-mac` BASE MAC
/// `a0:f2:62:85:97:a4` (efuse, verified under lease).
pub const JOINER_BASE_MAC: [u8; 6] = [0xa0, 0xf2, 0x62, 0x85, 0x97, 0xa4];
/// Extended PAN identifier carried on the formed network.
pub const EXT_PAN_ID: [u8; 8] = [0x43, 0x36, 0x4a, 0x4f, 0x49, 0x4e, 0x30, 0x31];
/// Coordinator long address: [`COORD_BASE_MAC`] expanded with the
/// proven `ff:fe` rule (matches `esptool read-mac` EUI
/// `a0:f2:62:ff:fe:86:7f:68`).
pub const TC_EUI: [u8; 8] = [0xa0, 0xf2, 0x62, 0xff, 0xfe, 0x86, 0x7f, 0x68];
/// Joiner long address: [`JOINER_BASE_MAC`] expanded the same way
/// (`a0:f2:62:ff:fe:85:97:a4` on the air).
pub const JOINER_EUI: [u8; 8] = [0xa0, 0xf2, 0x62, 0xff, 0xfe, 0x85, 0x97, 0xa4];
/// Rung-3 MG24 joiner long address on the air
/// (`34:8d:13:ff:fe:11:49:6d`): NCP-side scanner that selects C601
/// post-network_init and sends 4x assoc-req with this EUI.
pub const MG24_EUI: [u8; 8] = [0x34, 0x8d, 0x13, 0xff, 0xfe, 0x11, 0x49, 0x6d];
/// Short address assigned to the MG24 at association.
pub const MG24_SHORT: u16 = 0x0002;
/// Joiner MAC capability octet: end device, mains powered, receiver
/// stays on while idle, short address requested (OTA-proven).
pub const MAC_CAPS: u8 = 0x8c;
/// Home-automation profile for the ZCL leg.
pub const HA_PROFILE: u16 = 0x0104;
/// Application endpoint hosting the On/Off server (joiner side).
pub const ZCL_ENDPOINT: u8 = 0x01;
/// Fixed transaction number of the first ZCL exchange (both ends log
/// it for continuity, as on device).
pub const ZCL_TSN: u8 = 0xa1;
/// Largest NPDU this app builds (headers + aux + ZCL, bounded).
pub const MAX_NPDU: usize = 128;

/// Joiner IEEE address as an integer (little-endian of
/// [`JOINER_EUI`]).
#[must_use]
pub fn joiner_ieee() -> u64 {
    u64::from_le_bytes(JOINER_EUI)
}

/// Coordinator IEEE address as an integer (little-endian of
/// [`TC_EUI`]).
#[must_use]
pub fn tc_ieee() -> u64 {
    u64::from_le_bytes(TC_EUI)
}

/// Which full-stack image runs on this unit.
///
/// Requirement `22-65816-030-61-01` (corpus-mined, BDB roles).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppRole {
    /// Forms the network, admits the joiner, serves the Toggle.
    Coordinator,
    /// Scans, associates, joins, announces, hosts the ZCL endpoint.
    Joiner,
}

/// Select the role from a unit base MAC (full 6-octet compare).
///
///
/// Mirrors the OTA proof's shape (coordinator vs joiner by unit), but
/// retargeted to the real lab units: the OTA pair's last-octet rule
/// (`0x86`/`0x85`) matches no lab efuse MAC (all eight lab units
/// verified absent that octet), so the gate now compares the full
/// base MAC against [`COORD_BASE_MAC`] (healthy 7F68, preferred per
/// LADDER) and [`JOINER_BASE_MAC`] (97A4). Any other unit refuses
/// before touching the radio. Firmware may override this with its
/// own selection, but the default is the verified lab pair.
#[must_use]
pub fn role_from_mac(mac: &[u8; 6]) -> Option<AppRole> {
    if mac == &COORD_BASE_MAC {
        Some(AppRole::Coordinator)
    } else if mac == &JOINER_BASE_MAC {
        Some(AppRole::Joiner)
    } else {
        None
    }
}

/// Expand a 6-octet base MAC to the 8-octet EUI used on the air
/// (`ff:fe` inserted mid-address, the rule both OTA units follow).
#[must_use]
pub fn eui_from_mac(mac: &[u8; 6]) -> [u8; 8] {
    [mac[0], mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]]
}

/// Serial-log sink: the app's only output channel.
///
/// Firmware implements this over UART/USB (line discipline below);
/// tests collect lines for assertions. `no_std`-clean: `&str` only,
/// no allocation, never called from ISR context (the ISR rule stays
/// in the driver — this trait is only invoked from task context).
pub trait SerialLog {
    /// Emit one complete log line (no trailing newline required).
    fn log(&mut self, line: &str);
}

/// Log sink that drops everything (default before firmware wires a
/// real backend).
pub struct NullLog;

impl SerialLog for NullLog {
    fn log(&mut self, _line: &str) {}
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Log one air frame as `<prefix> <hex...>` through `log`.
///
/// Discipline ported from the OTA image: every sealed frame's first
/// flight is reproducible, so both ends log full air bytes and the
/// sniffer leg can be matched offline. Bounded: truncates at the
/// 512-octet line buffer (air frames are at most 128 octets, so a
/// full frame always fits).
pub fn log_air<L: SerialLog>(log: &mut L, prefix: &str, bytes: &[u8]) {
    let mut line = [0u8; 512];
    let mut n = 0usize;
    for &b in prefix.as_bytes() {
        if n >= line.len() {
            break;
        }
        line[n] = b;
        n += 1;
    }
    for &b in bytes {
        if n + 3 > line.len() {
            break;
        }
        line[n] = b' ';
        line[n + 1] = HEX[(b >> 4) as usize];
        line[n + 2] = HEX[(b & 0x0f) as usize];
        n += 3;
    }
    if let Ok(s) = core::str::from_utf8(&line[..n]) {
        log.log(s);
    }
}

/// Failures from the app layer (bounded + fallible throughout, D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppError {
    /// Caller buffer too small for the frame under construction.
    BufferTooSmall,
    /// Operation not allowed in the current role/state.
    BadRole,
    /// Formation layer rejected the request.
    Formation,
    /// Classical-join layer rejected the request.
    Join(JoinError),
    /// Frame failed to decode at one of the stack layers.
    BadFrame,
    /// Security gate refused the frame (replay or counter).
    Replay,
    /// Wrong cluster or command for this endpoint.
    WrongCluster,
    /// Default Response carried a non-success status.
    BadStatus(u8),
}

/// Coordinator app: form + permit + admit + serve.
///
/// Thin orchestration over [`CoordinatorMachine`] (formation,
/// permit, child table) and [`TrustCenter`] (install-code join);
/// frame building for the ZCL leg reuses the repo codecs directly.
///
/// Requirement `05-3474-23-3612-06` + `-07` (roles, reused) and
/// `22-65816-030-56-03` + `-91-02` (install-code join, reused).
pub struct CoordinatorApp {
    machine: CoordinatorMachine,
    tc: TrustCenter,
    assoc: CoordAssoc,
    /// Extra EUI→short admissions beyond [`JOINER_EUI`]/[`JOINER_SHORT`]
    /// (rung-3 MG24 leg). [`admit_joiner`](CoordinatorApp::admit_joiner)
    /// stays byte-identical and implicit (`JOINER_SHORT` fallback in
    /// [`take_assoc_rsp`](CoordinatorApp::take_assoc_rsp)); this table
    /// only carries `admit_extra` entries so the assoc response can
    /// echo the right short per latched EUI.
    extra_shorts: [Option<([u8; 8], u16)>; 8],
    mac_seq: u8,
    nwk_seq: u8,
    aps_counter: u8,
    /// Trust-Center key-transport owed (set on every accepted
    /// association; the NCP waits for the 0x05 frame after the RSP).
    transport_pending: bool,
    /// Auxiliary frame counter for transport delivery (strictly
    /// monotonic per network key; starts at the lab base).
    transport_auxctr: u32,
    tx_counter: FrameCounter,
    rx_replay: ReplayTable<8>,
    toggle_tsn: u8,
    /// Toggles served (requests built).
    pub toggles_sent: u32,
    /// Successful Default Responses verified.
    pub defrsp_ok: u32,
}

impl CoordinatorApp {
    /// New unformed coordinator.
    #[must_use]
    pub fn new() -> Self {
        let mut assoc = CoordAssoc::new();
        assoc.provision(APP_PAN, COORD_SHORT, &TC_EUI);
        Self {
            machine: CoordinatorMachine::new(AgingPolicy::default()),
            tc: TrustCenter::new(),
            assoc,
            extra_shorts: [None; 8],
            mac_seq: 0,
            nwk_seq: 0,
            aps_counter: 0,
            transport_pending: false,
            transport_auxctr: TRANSPORT_AUX_BASE,
            tx_counter: FrameCounter::new(100, 4),
            rx_replay: ReplayTable::<8>::new(),
            toggle_tsn: ZCL_TSN,
            toggles_sent: 0,
            defrsp_ok: 0,
        }
    }

    /// Current formation state.
    #[must_use]
    pub fn state(&self) -> CoordinatorState {
        self.machine.state()
    }

    /// Begin formation on the application channel/PAN.
    ///
    /// Requirement `05-3474-23-3611-01` (reused): centralized
    /// formation as coordinator.
    pub fn begin_formation<L: SerialLog>(
        &mut self,
        log: &mut L,
    ) -> Result<FormationState, AppError> {
        let primary = ChannelMask::from_list(&[APP_CHANNEL]).map_err(|_| AppError::Formation)?;
        let config = FormationConfig {
            role: LogicalType::Coordinator,
            primary,
            secondary: ChannelMask::from_list(&[]).map_err(|_| AppError::Formation)?,
            scan_duration: 3,
            pan: PanChoice::Fixed(APP_PAN),
            extended_pan: EXT_PAN_ID,
            router_short_addr: COORD_SHORT,
        };
        let state = self
            .machine
            .begin_formation(config)
            .map_err(|_| AppError::Formation)?;
        log.log("C6APP FORM scan ch15 conflict-check pan=0xc601");
        Ok(state)
    }

    /// Formation primitive outcome: success marks the network formed.
    pub fn formation_done<L: SerialLog>(&mut self, log: &mut L, success: bool) {
        let state = self.machine.formation_done(success);
        if success {
            log.log("C6APP FORMED pan=0xc601 ch=15 extpan=C6JOIN01");
            self.tc.open();
            self.tc.set_allow_list(&[joiner_ieee()]);
        } else {
            log.log("C6APP FORM-FAILED");
        }
        let _ = state;
    }

    /// Open the permit-joining window.
    pub fn open_permit<L: SerialLog>(
        &mut self,
        log: &mut L,
        window_ms: u64,
    ) -> Result<(), AppError> {
        self.machine
            .open_permit(window_ms)
            .map_err(|_| AppError::BadRole)?;
        self.assoc.set_permit(true);
        log.log("C6APP PERMIT open (allow-list 1/1)");
        Ok(())
    }

    /// Admit the joiner at both layers (child table + Trust Center).
    ///
    /// Requirements `05-3474-23-3612-07` (reused) +
    /// `22-65816-030-91-02` (reused).
    pub fn admit_joiner<L: SerialLog>(&mut self, log: &mut L, now_ms: u64) -> Result<(), AppError> {
        if self.state() != CoordinatorState::Formed || !self.machine.permit_open() {
            return Err(AppError::BadRole);
        }
        self.machine
            .admit_child(JOINER_SHORT, joiner_ieee(), false, now_ms)
            .map_err(|_| AppError::BadRole)?;
        self.tc
            .admit(joiner_ieee(), JOINER_SHORT, JoinMethod::InstallCode, 100)
            .map_err(AppError::Join)?;
        let _ = self.assoc.allow(JOINER_EUI);
        log.log("C6APP ADMIT ieee=a0f262fffe8597a4 short=0x0001");
        Ok(())
    }

    /// Admit an extra joiner at both layers (child table + Trust Center).
    ///
    /// Mirrors [`CoordinatorApp::admit_joiner`] for the rung-3 MG24 leg
    /// (EUI `34:8d:13:ff:fe:11:49:6d`, short `0x0002`): child-table
    /// admit + Trust-Center admit with [`JoinMethod::InstallCode`] +
    /// MAC [`CoordAssoc::allow`](crate::mac_cmd::CoordAssoc::allow) +
    /// `C6APP ADMIT ieee=<hex> short=....` log line. The short is
    /// remembered so [`CoordinatorApp::take_assoc_rsp`] echoes the
    /// right assigned short per latched EUI (97A4 keeps its
    /// `JOINER_SHORT` fallback; co-admission holds both EUIs).
    pub fn admit_extra<L: SerialLog>(
        &mut self,
        log: &mut L,
        eui: [u8; 8],
        short: u16,
    ) -> Result<(), AppError> {
        if self.state() != CoordinatorState::Formed || !self.machine.permit_open() {
            return Err(AppError::BadRole);
        }
        let ieee = u64::from_le_bytes(eui);
        self.machine
            .admit_child(short, ieee, false, 0)
            .map_err(|_| AppError::BadRole)?;
        self.tc
            .admit(ieee, short, JoinMethod::InstallCode, 100)
            .map_err(AppError::Join)?;
        let _ = self.assoc.allow(eui);
        if !self.extra_shorts.contains(&Some((eui, short))) {
            if let Some(slot) = self.extra_shorts.iter_mut().find(|s| s.is_none()) {
                *slot = Some((eui, short));
            }
        }
        let mut line = [0u8; 64];
        let mut n = 0usize;
        for &b in b"C6APP ADMIT ieee=".iter() {
            line[n] = b;
            n += 1;
        }
        for &b in eui.iter() {
            line[n] = HEX[(b >> 4) as usize];
            line[n + 1] = HEX[(b & 0x0f) as usize];
            n += 2;
        }
        for &b in b" short=0x".iter() {
            line[n] = b;
            n += 1;
        }
        for shift in [12u16, 8, 4, 0] {
            line[n] = HEX[((short >> shift) & 0x0f) as usize];
            n += 1;
        }
        if let Ok(s) = core::str::from_utf8(&line[..n]) {
            log.log(s);
        }
        Ok(())
    }

    /// True while the roles permit window is open (child-table gate).
    #[must_use]
    pub fn permit_open(&self) -> bool {
        self.machine.permit_open()
    }

    /// True while the MAC responder permit bit is set (mirrors
    /// [`CoordinatorApp::open_permit`] / [`CoordinatorApp::tick`]).
    #[must_use]
    pub fn is_mac_permit(&self) -> bool {
        self.assoc.permit()
    }

    /// Whether `eui` is in the MAC responder allow-list (mirrors the
    /// Trust-Center / child-table admission from
    /// [`CoordinatorApp::admit_joiner`]).
    #[must_use]
    pub fn is_mac_allowed(&self, eui: &[u8; 8]) -> bool {
        self.assoc.is_allowed(eui)
    }

    /// Whether an association response is currently owed.
    #[must_use]
    pub fn assoc_pending(&self) -> bool {
        self.assoc.assoc_pending()
    }

    /// Resolve an assigned short to its admitted EUI (the reverse of
    /// the [`CoordinatorApp::take_assoc_rsp`] short selection): extra
    /// admissions first, then the [`JOINER_SHORT`] fallback. Unknown
    /// shorts resolve to nothing, so stray polls re-arm nothing.
    fn short_to_eui(&self, short: u16) -> Option<[u8; 8]> {
        if let Some((eui, _)) = self
            .extra_shorts
            .iter()
            .flatten()
            .find(|(_, s)| *s == short)
        {
            return Some(*eui);
        }
        if short == JOINER_SHORT {
            return Some(JOINER_EUI);
        }
        None
    }

    /// Pending beacon-answer count.
    #[must_use]
    pub fn beacon_pending(&self) -> u32 {
        self.assoc.pending_beacon()
    }

    /// Whether a joiner EUI has latched (associated at the MAC leg).
    #[must_use]
    pub fn is_associated(&self) -> bool {
        self.assoc.device_eui().is_some()
    }

    /// Advance the permit window and child aging, keeping the MAC
    /// responder permit bit in sync (closed on expiry).
    pub fn tick(&mut self, now_ms: u64, elapsed_ms: u64) {
        self.machine.tick(now_ms, elapsed_ms);
        self.assoc.set_permit(self.machine.permit_open());
    }

    fn take_mac_seq(&mut self) -> u8 {
        let s = self.mac_seq;
        self.mac_seq = self.mac_seq.wrapping_add(1);
        s
    }

    /// Feed one inbound MAC-command PSDU to the responder: beacon-req
    /// pends a beacon, allow-listed assoc-req under an open window
    /// latches + pends a response (denied with no response otherwise),
    /// long poll re-arms for the latched EUI, short poll re-arms for
    /// the EUI holding the polled short. Returns the
    /// classification for the serial-log leg.
    pub fn on_mac_psdu(&mut self, psdu: &[u8]) -> MacIncoming {
        let inc = crate::mac_cmd::classify(psdu);
        match inc {
            MacIncoming::BeaconReq { .. } => self.assoc.on_beacon_req(),
            MacIncoming::AssocReq(ref req) => {
                if self.assoc.on_assoc_req(req) {
                    // Latched: the Trust-Center key delivery is owed too
                    // (the NCP waits for the 0x05 frame after the RSP).
                    self.transport_pending = true;
                }
            }
            MacIncoming::DataPoll(ref poll) => {
                let _ = self.assoc.on_data_poll(poll);
            }
            MacIncoming::ShortPoll(ref poll) => {
                if let Some(eui) = self.short_to_eui(poll.src_short) {
                    let _ = self.assoc.on_data_poll(&DataPoll {
                        seq: poll.seq,
                        src_eui: eui,
                    });
                }
            }
            MacIncoming::Other => {}
        }
        inc
    }

    /// Build one pending beacon answer into `out` (consumes one
    /// pending; `Ok(0)` when idle). Sequence comes from the app MAC
    /// counter; PAN/short/ext-PAN are the provisioned app identity.
    ///
    /// # Errors
    ///
    /// [`MacCmdError::BufferTooSmall`] when an answer is owed but
    /// `out` is short.
    pub fn take_beacon(&mut self, out: &mut [u8]) -> Result<usize, MacCmdError> {
        if self.assoc.pending_beacon() == 0 {
            return Ok(0);
        }
        let seq = self.take_mac_seq();
        self.assoc.take_beacon(seq, &EXT_PAN_ID, out)
    }

    /// Build the pending association-response into `out` (consumes the
    /// pending answer; `Ok(0)` when idle). Always success status with
    /// the assigned short for the latched EUI: denied requests never
    /// pend, so no failure response is radiated. The 97A4 joiner keeps
    /// [`JOINER_SHORT`]; extra admissions (rung-3 MG24) echo their
    /// admitted short from the `admit_extra` table.
    ///
    /// # Errors
    ///
    /// [`MacCmdError::BufferTooSmall`] when an answer is owed but
    /// `out` is short.
    pub fn take_assoc_rsp(&mut self, out: &mut [u8]) -> Result<usize, MacCmdError> {
        if !self.assoc.assoc_pending() {
            return Ok(0);
        }
        let seq = self.take_mac_seq();
        let short = match self.assoc.device_eui() {
            Some(eui) => self
                .extra_shorts
                .iter()
                .flatten()
                .find(|(a, _)| eui_matches(a, &eui))
                .map(|(_, s)| *s)
                .unwrap_or(JOINER_SHORT),
            None => JOINER_SHORT,
        };
        self.assoc.take_assoc_rsp(seq, short, 0x00, out)
    }

    /// Re-pend the association answer for the latched EUI (TX-loss
    /// recovery). Call when a built response could not be queued
    /// (single-flight busy on a congested band) so the next loop
    /// iteration rebuilds + retries instead of silently dropping the
    /// one answer (w92 f1: acked assoc-req, no RSP on air). No-op
    /// when no EUI is latched.
    pub fn rearm_assoc(&mut self) {
        if let Some(eui) = self.assoc.device_eui() {
            let _ = self.assoc.on_data_poll(&DataPoll {
                seq: self.mac_seq,
                src_eui: eui,
            });
        }
    }

    /// Build one gratuitous beacon into `out` (unsolicited, does not
    /// consume the solicited pending count). Firmware calls this when
    /// [`crate::mac_cmd::gratuitous_due`] fires while unassociated so
    /// a passive sniffer sees beacons with no solicitation.
    ///
    /// # Errors
    ///
    /// [`MacCmdError::BufferTooSmall`] when `out` holds fewer than
    /// the beacon length.
    pub fn build_gratuitous_beacon(&mut self, out: &mut [u8]) -> Result<usize, MacCmdError> {
        let seq = self.take_mac_seq();
        crate::mac_cmd::build_beacon(
            seq,
            APP_PAN,
            COORD_SHORT,
            SUPERFRAME_ASSOC_PERMIT,
            &EXT_PAN_ID,
            out,
        )
    }

    /// Whether a Trust-Center key-transport frame is owed (set on
    /// every accepted association; the NCP waits for the 0x05 frame
    /// after the association response).
    #[must_use]
    pub fn transport_pending(&self) -> bool {
        self.transport_pending
    }

    /// Re-pend the key-transport answer for the latched EUI
    /// (TX-loss recovery, mirror of [`rearm_assoc`](Self::rearm_assoc)).
    /// No-op when no EUI is latched.
    pub fn rearm_transport(&mut self) {
        if self.assoc.device_eui().is_some() {
            self.transport_pending = true;
        }
    }

    /// Build the pending Trust-Center→joiner transport-key frame
    /// into `out` (71 octets; consumes the pending flag on success,
    /// keeps it on build refusal so firmware can retry with a bigger
    /// buffer). `netkey` is the coordinator's deployment-owned
    /// network key; `transport_key` its HA-derived key-transport key.
    /// Always success status with the assigned short for the latched
    /// EUI, echoing the association short selection.
    ///
    /// # Errors
    ///
    /// [`MacCmdError::BufferTooSmall`] when `out` holds fewer than
    /// [`TRANSPORT_FRAME_LEN`](rounddance_commission::TRANSPORT_FRAME_LEN)
    /// octets.
    pub fn take_transport_key(
        &mut self,
        out: &mut [u8],
        netkey: &[u8; 16],
        transport_key: &[u8; 16],
    ) -> Result<usize, MacCmdError> {
        use rounddance_commission::{build_transport_key_frame, TransportKeyParams};
        if !self.transport_pending {
            return Ok(0);
        }
        let Some(eui) = self.assoc.device_eui() else {
            return Ok(0);
        };
        let short = self
            .extra_shorts
            .iter()
            .flatten()
            .find(|(a, _)| eui_matches(a, &eui))
            .map(|(_, s)| *s)
            .unwrap_or(JOINER_SHORT);
        // Source EUI goes on air LSB-first (wire order), like every
        // other EUI field the NCP parses (w93: MG21's aux source is
        // the LE bytes of its EUI); the TC_EUI const is display
        // order, so reverse it here.
        let mut src_wire = TC_EUI;
        src_wire.reverse();
        let auxctr = self.transport_auxctr;
        let params = TransportKeyParams {
            dst_pan: APP_PAN,
            dst_short: short,
            dst_eui: eui,
            src_eui: src_wire,
            mac_seq: self.take_mac_seq(),
            nwk_seq: self.take_nwk_seq(),
            nwk_radius: 0x1e,
            aps_ctr: self.take_aps_counter(),
            auxctr,
            seq_no: 0x00,
            netkey: *netkey,
            transport_key: *transport_key,
        };
        match build_transport_key_frame(&params, out) {
            Ok(n) => {
                self.transport_pending = false;
                self.transport_auxctr = auxctr.wrapping_add(1);
                Ok(n)
            }
            Err(_) => Err(MacCmdError::BufferTooSmall),
        }
    }

    /// Run the install-code key exchange for the admitted joiner.
    ///
    /// Requirement `22-65816-030-56-03` (reused): the initial link
    /// key is really derived (MMO KDF over the install code), never
    /// a mock constant.
    pub fn exchange_join_key(
        &mut self,
        code: &InstallCode,
        initial_key: &mut [u8; 16],
    ) -> Result<KeyAttributes, AppError> {
        TrustCenter::install_code_key(&MmoJoinKdf, code, &joiner_ieee().to_be_bytes(), initial_key)
            .map_err(AppError::Join)?;
        let stored = [0x00u8; 16];
        let attrs = self
            .tc
            .exchange_key(joiner_ieee(), initial_key, &stored, 0x04)
            .map_err(AppError::Join)?;
        self.tc
            .on_verify_confirm(joiner_ieee(), true)
            .map_err(AppError::Join)?;
        Ok(attrs)
    }

    /// Record traffic from the joiner (child keepalive).
    pub fn joiner_heard(&mut self, now_ms: u64) -> Result<(), AppError> {
        self.machine
            .child_heard(JOINER_SHORT, now_ms)
            .map_err(|_| AppError::BadRole)
    }

    fn take_nwk_seq(&mut self) -> u8 {
        let s = self.nwk_seq;
        self.nwk_seq = self.nwk_seq.wrapping_add(1);
        s
    }

    fn take_aps_counter(&mut self) -> u8 {
        let c = self.aps_counter;
        self.aps_counter = self.aps_counter.wrapping_add(1);
        c
    }

    /// Build the secured ZCL Toggle request NPDU into `out`.
    ///
    /// Layout mirrors the OTA first flight: NWK data (secured,
    /// radius 1), then APS data (secured, HA profile, On/Off
    /// cluster), then aux (level 5, data key), then the ZCL Toggle.
    /// Returns the NPDU length.
    ///
    /// Requirement `07-5123-08-241-01` (ZCL frame, reused).
    pub fn build_toggle_request<L: SerialLog>(
        &mut self,
        log: &mut L,
        out: &mut [u8],
    ) -> Result<usize, AppError> {
        let mut zcl = [0u8; 8];
        let zlen = onoff::client::toggle(self.toggle_tsn, &mut zcl)
            .map_err(|_| AppError::BufferTooSmall)?;
        let npdu = build_secured_npdu(
            COORD_SHORT,
            JOINER_SHORT,
            0x01,
            self.take_nwk_seq(),
            ZCL_ENDPOINT,
            ZCL_ENDPOINT,
            onoff::CLUSTER_ID,
            HA_PROFILE,
            self.take_aps_counter(),
            &mut self.tx_counter,
            &zcl[..zlen],
            out,
        )?;
        self.toggles_sent += 1;
        log_air(log, "C6APP TX-TOGGLE", &out[..npdu]);
        Ok(npdu)
    }

    /// Verify a Default Response NPDU from the joiner.
    ///
    /// Decodes NWK → APS → aux (replay-checked) → ZCL and requires
    /// command `0x0b` with the toggle echoed plus success status.
    /// Returns `true` on success and counts it.
    pub fn handle_defrsp<L: SerialLog>(
        &mut self,
        log: &mut L,
        npdu: &[u8],
    ) -> Result<bool, AppError> {
        let zcl_body = decode_secured_npdu(
            npdu,
            JOINER_SHORT,
            COORD_SHORT,
            &mut self.rx_replay,
            joiner_ieee(),
        )?;
        let (hdr, body) = ZclHeader::decode(zcl_body).map_err(|_| AppError::BadFrame)?;
        if hdr.command_id != DEFAULT_RSP {
            return Err(AppError::WrongCluster);
        }
        let rsp = DefaultRsp::decode(body).map_err(|_| AppError::BadFrame)?;
        if rsp.cmd != onoff::CMD_TOGGLE {
            return Err(AppError::WrongCluster);
        }
        if rsp.status != rounddance_zcl::status::ZclStatus::Success {
            return Err(AppError::BadStatus(rsp.status.as_u8()));
        }
        self.defrsp_ok += 1;
        log.log("C6APP DEFRSP ok toggle success");
        Ok(true)
    }
}

impl Default for CoordinatorApp {
    fn default() -> Self {
        Self::new()
    }
}

/// Joiner app: scan → associate → join → announce → ZCL endpoint.
///
/// Thin orchestration over [`SteeringMachine`] (survey) and
/// [`JoinerMachine`] (associate/authenticate/key/announce/joined),
/// with a live On/Off server endpoint (`rounddance-zcl` dispatch over
/// a real attribute store) for the ZCL leg.
///
/// Requirements `22-65816-030-91-01` (survey, reused) + `-91-03`
/// (symmetric join, reused) + `05-3474-23-32214-01` /
/// `-32215-01` (join indication/confirm, reused).
pub struct JoinerApp<'a> {
    steering: SteeringMachine,
    joiner: JoinerMachine,
    endpoint: Endpoint<'a>,
    store: rounddance_zcl::attrs::AttrStore,
    reporting: ReportingEngine,
    events: EventQueue,
    behavior: onoff::ServerBehavior,
    tx_counter: FrameCounter,
    rx_replay: ReplayTable<8>,
    nwk_seq: u8,
    aps_counter: u8,
    /// Frames answered with a Default Response.
    pub defrsp_sent: u32,
    /// Unsecured vendor frames tolerated post-association (wave-23
    /// behavior, counted for the log).
    pub unsecured_tolerated: u32,
}

impl<'a> JoinerApp<'a> {
    /// New joiner hosting an On/Off server on `def`.
    pub fn new(def: &'a onoff::ServerDef) -> Result<Self, AppError> {
        let mut endpoint = Endpoint::new();
        endpoint.add(def).map_err(|_| AppError::BadRole)?;
        let store = onoff::server_store().map_err(|_| AppError::BadRole)?;
        Ok(Self {
            steering: SteeringMachine::new(),
            joiner: JoinerMachine::new(
                JoinMethod::InstallCode,
                JoinPolicy {
                    cbke_supported: false,
                    cbke_required: false,
                    interview_tc: true,
                    parent_is_r20_earlier: false,
                },
            ),
            endpoint,
            store,
            reporting: ReportingEngine::new(),
            events: EventQueue::new(),
            behavior: onoff::ServerBehavior,
            tx_counter: FrameCounter::new(200, 4),
            rx_replay: ReplayTable::<8>::new(),
            nwk_seq: 0,
            aps_counter: 0,
            defrsp_sent: 0,
            unsecured_tolerated: 0,
        })
    }

    /// Current join state.
    #[must_use]
    pub fn state(&self) -> JoinerState {
        self.joiner.state()
    }

    /// Current lamp (OnOff attribute) value.
    #[must_use]
    pub fn lamp(&self) -> bool {
        onoff::onoff(&self.store)
    }

    /// Begin the beacon survey on the application channel.
    pub fn begin_scan<L: SerialLog>(&mut self, log: &mut L) -> Result<(), AppError> {
        let mask = ChannelMask::from_list(&[APP_CHANNEL]).map_err(|_| AppError::BadRole)?;
        self.steering
            .begin_scan(mask, 3)
            .map_err(|_| AppError::BadRole)?;
        log.log("C6APP SCAN ch15");
        Ok(())
    }

    /// Ingest one survey entry (the coordinator's beacon).
    pub fn survey<L: SerialLog>(
        &mut self,
        log: &mut L,
        entry: BeaconSurveyEntry,
    ) -> Result<SteeringState, AppError> {
        self.steering.ingest(entry).map_err(|_| AppError::BadRole)?;
        // Field admission: decode success + RSSI sanity, no absolute
        // LQI gate (C6 LQI reads flat 9–11 on ~100%-decode links —
        // wave-27 — so `min_lqi = 100` could never pass on this
        // hardware; see `LinkEvidencePolicy`).
        self.steering.finish_scan(&LinkEvidencePolicy::default());
        let state = self.steering.state();
        if state == SteeringState::CandidateSelected {
            log.log("C6APP SURVEY candidate pan=0xc601");
            self.joiner.on_candidate();
        }
        Ok(state)
    }

    /// Association confirm from the MAC layer.
    pub fn assoc_confirm<L: SerialLog>(&mut self, log: &mut L, success: bool) {
        self.joiner.on_assoc_confirm(success);
        if success {
            log.log("C6APP ASSOC ok short=0x0001");
        } else {
            log.log("C6APP ASSOC failed");
        }
    }

    /// Tolerate one post-association unsecured vendor frame.
    ///
    /// Wave-23 behavior (`note_unsecured`): counted and classified,
    /// never transitions the machine. Takes only the command id so
    /// latching is impossible by construction.
    pub fn tolerate_unsecured(&mut self, cmd: u8) {
        self.joiner.note_unsecured(cmd);
        self.unsecured_tolerated += 1;
    }

    /// Key-transport confirm.
    pub fn key_transport<L: SerialLog>(&mut self, log: &mut L, success: bool) {
        self.joiner.on_key_transport(success);
        if success {
            log.log("C6APP KEY ok");
        }
    }

    /// Verification confirm from the Trust Center.
    pub fn verify_confirm<L: SerialLog>(&mut self, log: &mut L) {
        self.joiner
            .on_verify_confirm(true, KeyAttributes::SYMMETRIC);
        if self.joiner.state() == JoinerState::Announced {
            log.log("C6APP JOINED announced");
        }
    }

    /// Build the DeviceAnnce payload into `out`.
    ///
    /// Requirement `05-3474-23-24311-11` (reused).
    pub fn build_annce(&self, out: &mut [u8]) -> Result<usize, AppError> {
        let annce = self
            .joiner
            .device_annce(ZCL_TSN, JOINER_SHORT, joiner_ieee());
        annce.encode_into(out).map_err(|_| AppError::BufferTooSmall)
    }

    /// Close out the join (post-announce).
    pub fn close_out<L: SerialLog>(&mut self, log: &mut L) {
        self.joiner.close_out(false);
        if self.joiner.state() == JoinerState::Joined {
            log.log("C6APP JOIN-COMPLETE lamp-hosted ep=1");
        }
    }

    fn take_nwk_seq(&mut self) -> u8 {
        let s = self.nwk_seq;
        self.nwk_seq = self.nwk_seq.wrapping_add(1);
        s
    }

    fn take_aps_counter(&mut self) -> u8 {
        let c = self.aps_counter;
        self.aps_counter = self.aps_counter.wrapping_add(1);
        c
    }

    /// Handle a Toggle request NPDU; build the response NPDU into
    /// `out`.
    ///
    /// Decodes NWK → APS → aux (replay-checked) → ZCL, applies the
    /// Toggle on the live server behavior (the lamp flips), and
    /// wraps the dispatch-generated Default Response as a secured
    /// NPDU. A replayed request is refused with [`AppError::Replay`].
    ///
    /// Requirements `07-5123-08-383-01..04` (server behavior,
    /// reused) + `05-3474-23-4312-01` (replay, reused).
    pub fn handle_toggle<L: SerialLog>(
        &mut self,
        log: &mut L,
        npdu: &[u8],
        out: &mut [u8],
    ) -> Result<usize, AppError> {
        let zcl_wire = decode_secured_npdu(
            npdu,
            COORD_SHORT,
            JOINER_SHORT,
            &mut self.rx_replay,
            tc_ieee(),
        )?;
        let (hdr, body) = ZclHeader::decode(zcl_wire).map_err(|_| AppError::BadFrame)?;
        if hdr.command_id != onoff::CMD_TOGGLE {
            return Err(AppError::WrongCluster);
        }
        let mut zcl_out = [0u8; 64];
        let mut ctx = Ctx {
            store: &mut self.store,
            reporting: &mut self.reporting,
            events: &mut self.events,
            now_s: 0,
            peer_onoff: None,
            sender_ieee: Some(tc_ieee()),
        };
        // `dispatch` executes the command; Default Response triage
        // stays with the caller (`should_default_respond`): a clean
        // Toggle answers success, a dispatch error answers its
        // status when the rules say to.
        let outcome = dispatch(
            &self.endpoint,
            Some(&mut self.behavior),
            &mut ctx,
            &hdr,
            body,
            onoff::CLUSTER_ID,
            None,
            &[],
            &mut zcl_out,
        );
        let reply_len = match outcome {
            Ok(DispatchOutcome::Respond(n)) => n,
            Ok(DispatchOutcome::Silent) => {
                if !should_default_respond(&hdr, true, false, false) {
                    return Err(AppError::BadStatus(0xff));
                }
                encode_default_rsp(hdr.tsn, hdr.command_id, ZclStatus::Success, &mut zcl_out)?
            }
            Err(status) => {
                if !should_default_respond(&hdr, true, false, true) {
                    return Err(AppError::BadStatus(status.as_u8()));
                }
                encode_default_rsp(hdr.tsn, hdr.command_id, status, &mut zcl_out)?
            }
        };
        let npdu_len = build_secured_npdu(
            JOINER_SHORT,
            COORD_SHORT,
            0x01,
            self.take_nwk_seq(),
            ZCL_ENDPOINT,
            ZCL_ENDPOINT,
            onoff::CLUSTER_ID,
            HA_PROFILE,
            self.take_aps_counter(),
            &mut self.tx_counter,
            &zcl_out[..reply_len],
            out,
        )?;
        self.defrsp_sent += 1;
        log_air(log, "C6APP TX-DEFRSP", &out[..npdu_len]);
        Ok(npdu_len)
    }
}

/// Encode one Default Response frame (header + body) into `out`.
///
/// Requirement `07-5123-08-2512-01` (reused): global frame,
/// server-to-client, no further Default Response, echoing the
/// request command plus the outcome status.
fn encode_default_rsp(
    tsn: u8,
    cmd: u8,
    status: ZclStatus,
    out: &mut [u8],
) -> Result<usize, AppError> {
    let hdr = ZclHeader {
        control: ZclFrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: false,
            direction: Direction::ToClient,
            disable_default_response: true,
        },
        manufacturer_code: None,
        tsn,
        command_id: DEFAULT_RSP,
    };
    let hn = hdr.encode_into(out).map_err(|_| AppError::BadFrame)?;
    let rsp = DefaultRsp { cmd, status };
    let bn = rsp
        .encode_into(&mut out[hn..])
        .map_err(|_| AppError::BadFrame)?;
    Ok(hn + bn)
}

/// Build one structurally-secured data NPDU into `out`.
///
/// NWK data (security flag, radius, sequence) | APS data (security
/// flag, endpoints, cluster, profile, counter) | aux (level 5, data
/// key, sequence mode) | `zcl`. The payload transform itself is out
/// of scope for this wave (keys are agreed for real via the
/// install-code KDF; structural headers + counters + replay carry
/// the determinism proof, as in the sim legs).
#[allow(clippy::too_many_arguments)]
fn build_secured_npdu(
    src: u16,
    dst: u16,
    radius: u8,
    nwk_seq: u8,
    src_ep: u8,
    dst_ep: u8,
    cluster: u16,
    profile: u16,
    aps_counter: u8,
    tx_counter: &mut FrameCounter,
    zcl: &[u8],
    out: &mut [u8],
) -> Result<usize, AppError> {
    let aux = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::Index, false).ok_or(AppError::BadFrame)?,
        frame_counter: tx_counter.take().map_err(|_| AppError::Replay)?,
        ext_source: None,
        key_id: KeyIdentifier::Index(0x01),
    };
    let alen = aux.header_len().ok_or(AppError::BadFrame)?;
    let mut ctl = ApsFc::data(DeliveryMode::Unicast);
    ctl.security = true;
    let aps = DataHeader {
        control: ctl,
        dest: DataDest::Unicast {
            dst_endpoint: dst_ep,
        },
        cluster_id: cluster,
        profile_id: profile,
        src_endpoint: src_ep,
        counter: aps_counter,
        ext: None,
    };
    let ahlen = aps.header_len();
    let total = ahlen + alen + zcl.len();
    if out.len() < total {
        return Err(AppError::BufferTooSmall);
    }
    let mut tmp = [0u8; MAX_NPDU];
    if ahlen + alen + zcl.len() > tmp.len() {
        return Err(AppError::BufferTooSmall);
    }
    aps.encode_into(zcl, &mut tmp)
        .map_err(|_| AppError::BufferTooSmall)?;
    let mut frame = [0u8; MAX_NPDU];
    frame[..ahlen].copy_from_slice(&tmp[..ahlen]);
    let auxn = aux
        .encode_into(&mut frame[ahlen..])
        .map_err(|_| AppError::BadFrame)?;
    debug_assert_eq!(auxn, alen);
    frame[ahlen + alen..ahlen + alen + zcl.len()].copy_from_slice(zcl);
    let mut nwk_ctl = NwkFc::data();
    nwk_ctl.security = true;
    let nwk = NwkHeader::minimal(nwk_ctl, dst, src, radius, nwk_seq);
    nwk.encode_into(&frame[..total], out)
        .map_err(|_| AppError::BufferTooSmall)
}

/// Decode one structurally-secured data NPDU, returning the ZCL tail.
///
/// Checks: NWK decodes with the security flag and the expected
/// source/destination, APS decodes secured, aux decodes at level 5
/// and passes the replay table under `sender_ieee`. Errors name the
/// failing layer through [`AppError`] without leaking key material.
fn decode_secured_npdu<'n>(
    npdu: &'n [u8],
    expect_src: u16,
    expect_dst: u16,
    replay: &mut ReplayTable<8>,
    sender_ieee: u64,
) -> Result<&'n [u8], AppError> {
    let nwk = nwk_decode(npdu).map_err(|_| AppError::BadFrame)?;
    if !nwk.header.control.security {
        return Err(AppError::BadFrame);
    }
    if nwk.header.src_addr != expect_src || nwk.header.dst_addr != expect_dst {
        return Err(AppError::BadFrame);
    }
    let aps = decode_data(nwk.payload).map_err(|_| AppError::BadFrame)?;
    if !aps.header.control.security {
        return Err(AppError::BadFrame);
    }
    let (aux, used) = AuxHeader::decode(aps.payload).map_err(|_| AppError::BadFrame)?;
    if aux.control.level != 5 {
        return Err(AppError::BadFrame);
    }
    replay
        .check(sender_ieee, aux.frame_counter)
        .map_err(|_| AppError::Replay)?;
    if used > aps.payload.len() {
        return Err(AppError::BadFrame);
    }
    Ok(&aps.payload[used..])
}
