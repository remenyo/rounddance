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
//! this crate's tests — they run over [`crate::mock::MockDriver`]):
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

pub use crate::auxctr::{AuxCounter, AUX_CHUNK};
use crate::mac_cmd::{
    beacon_net_caps, build_assoc_req, eui_matches, CoordAssoc, DataPoll, Incoming as MacIncoming,
    MacCmdError, SUPERFRAME_ASSOC_PERMIT,
};
use rounddance_aps::{decode_data, DataDest, DataHeader, DeliveryMode, FrameControl as ApsFc};
use rounddance_commission::{
    BeaconSurveyEntry, ChannelMask, FormationConfig, FormationState, InstallCode, JoinError,
    JoinMethod, JoinPolicy, JoinerMachine, JoinerState, KeyAttributes, LinkEvidencePolicy,
    LogicalType, MmoJoinKdf, PanChoice, SteeringMachine, SteeringState, TrustCenter,
    TRANSPORT_AUX_BASE,
};
use rounddance_nwk::{
    decode as nwk_decode, DiscoveryTable, FrameType as NwkFrameType, RouteTable, ROUTE_LIFETIME_MS,
};
use rounddance_roles::{AgingPolicy, CoordinatorMachine, CoordinatorState};
use rounddance_security::{
    ccm_star_open_into, AuxHeader, KeyIdentifier, KeySet, NwkNonce, ReplayTable, CCM_NONCE_LEN,
    CCM_TAG_LEN,
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
use rounddance_zdo::zdp::DeviceAnnce;
use rounddance_zdo::PendingTable;

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
/// Starting auxiliary counter for joiner-secured frames (lab
/// value; disjoint from the coordinator's `TRANSPORT_AUX_BASE` range
/// so captures attribute direction unambiguously).
pub const JOINER_AUX_BASE: u32 = 0x0000_2000;
/// Join-rate policy window: new-EUI associations accepted per
/// window before throttling (Phase 4 hardening). Re-assocs from the
/// latched EUI never consume budget (legit retry/rejoin); the lab
/// pair joins at most twice per boot, so 4/60 s is generous headroom
/// with real churn protection (each accept burns a transport build +
/// an aux counter + an NVS write).
pub const ASSOC_WINDOW_MS: u64 = 60_000;
/// New-EUI association accepts per [`ASSOC_WINDOW_MS`].
pub const ASSOC_NEW_MAX: u8 = 4;
/// Indirect-queue depth: at most this many shorts hold queued
/// frames (Phase 1 leg 1b; leg 1c transmits them post-poll).
pub const INDIRECT_DEPTH: usize = 4;
/// Why an inbound NWK frame was refused without action (Phase 1
/// leg RX-1: every refusal is counted, never silent).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NwkIgnore {
    /// NWK header undecodable (truncated, reserved bits, broadcast
    /// with destination IEEE).
    BadHeader,
    /// Source-route subframe present (leg deferred: our NCP never
    /// sends it; counted, not parsed).
    SourceRoute,
    /// Secured frame with a non-Index key identifier (only the
    /// network-key shape is implemented).
    BadKeyId,
    /// Auxiliary header truncated or key sequence unknown.
    BadAux,
    /// No extended source and no short to key the replay table on.
    NoSource,
    /// CCM* MIC failure (wrong key or tampered frame).
    MicFailed,
    /// Frame counter does not advance (replay or duplicate).
    Replay,
    /// Command frame with an empty payload (no id octet).
    EmptyCommand,
    /// Unsecured NWK data (the secured join legs never accept it;
    /// tolerated vendor traffic is classified at the MAC layer).
    Unsecured,
    /// Secured with a key this unit does not hold (no adopted network
    /// key yet, or sequence mismatch).
    UnknownKey,
    /// Frame arrived in a join state that cannot accept it (e.g. a
    /// transport-key delivery outside the post-association wait).
    WrongState,
    /// APS data undecodable and not the tolerated annce class.
    BadAps,
    /// ZDO payload undecodable.
    BadZdo,
}

/// Outcome of one inbound NWK frame (Phase 1 leg RX-1: the
/// coordinator's post-join conversation entry point).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NwkRxOutcome {
    /// Frame refused without action (counted in
    /// [`nwk_rx_ignored`](CoordinatorApp::nwk_rx_ignored)).
    Ignored(NwkIgnore),
    /// ZDO Device_annce handled (child marked heard when known).
    Annce {
        /// Announced short address.
        short: u16,
        /// Announced long address (wire order, as on air).
        eui: [u8; 8],
        /// Announced capability byte.
        capability: u8,
    },
    /// NWK command frame (secured or open): id reported for the
    /// response legs; unknown ids are counted here, not dropped
    /// silently.
    NwkCommand {
        /// Command identifier (first payload octet).
        id: u8,
    },
    /// APS data frame outside the annce class (cluster/profile
    /// reported; payload handling is a later leg).
    Data {
        /// APS cluster identifier.
        cluster: u16,
        /// APS profile identifier.
        profile: u16,
    },
    /// ZDO response matched to an open transaction (entry consumed).
    ZdoResponse {
        /// Response cluster identifier.
        cluster: u16,
        /// Echoed transaction sequence.
        tsn: u8,
        /// Response status octet, when present.
        status: Option<u8>,
        /// Request cluster the response correlates to.
        req_cluster: u16,
    },
}

/// Outcome of one inbound NWK frame on the JOINER (Phase 3 leg 2:
/// the mirror of [`NwkRxOutcome`] for the joining side).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinerNwkOutcome {
    /// Frame refused without action (counted, never silent).
    Ignored(NwkIgnore),
    /// Trust-Center transport-key delivery opened and adopted (the
    /// fw sends the Device_annce next).
    TransportAccepted {
        /// Auxiliary counter of the adopted delivery.
        auxctr: u32,
    },
    /// ZDO Node_desc_req addressed to us (answer with
    /// [`take_node_desc_rsp`](JoinerApp::take_node_desc_rsp)).
    NodeDescReq {
        /// NWK source short to answer.
        src_short: u16,
        /// ZDO transaction sequence to echo.
        tsn: u8,
        /// Network address the request names.
        subject: u16,
    },
    /// APS data outside the handled classes (cluster/profile
    /// reported; no silent drops).
    Data {
        /// APS cluster identifier.
        cluster: u16,
        /// APS profile identifier.
        profile: u16,
    },
    /// NWK command frame: id reported for later legs.
    NwkCommand {
        /// Command identifier (first payload octet).
        id: u8,
    },
}

/// Restored NWK security-control level (base level 5: the sender
/// zeroes the on-air level bits after protecting, wave-33/wave-36
/// pattern; the receiver restores before nonce/AAD work).
const NWK_SEC_LEVEL: u8 = 5;
/// Largest single indirect payload in octets (covers a NWK-secured
/// ZDO frame with margin; full MAC PSDU assembly happens at TX).
pub const INDIRECT_MAX: usize = 96;

/// One queued indirect payload, keyed by destination short.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IndirectSlot {
    short: u16,
    len: usize,
    buf: [u8; INDIRECT_MAX],
}
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
/// Coordinator long address on the air: LSB-first wire order (as the
/// MG21 reference emits its aux source and assoc-rsp source). NCPs
/// parse address fields in wire order; the display-order [`TC_EUI`]
/// is only for logs and host-side matching.
pub const TC_EUI_WIRE: [u8; 8] = [0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
/// Joiner long address: [`JOINER_BASE_MAC`] expanded the same way
/// (`a0:f2:62:ff:fe:85:97:a4` on the air).
pub const JOINER_EUI: [u8; 8] = [0xa0, 0xf2, 0x62, 0xff, 0xfe, 0x85, 0x97, 0xa4];
/// Rung-3 MG24 joiner long address on the air
/// (`34:8d:13:ff:fe:11:49:6d`): NCP-side scanner that selects C601
/// post-network_init and sends 4x assoc-req with this EUI.
pub const MG24_EUI: [u8; 8] = [0x34, 0x8d, 0x13, 0xff, 0xfe, 0x11, 0x49, 0x6d];
/// Short address assigned to the MG24 at association.
pub const MG24_SHORT: u16 = 0x0002;
/// Phase-5 MG21-as-joiner long address on the air
/// (`04:e3:e5:ff:fe:f4:75:5f`, live-probed via bellows getEui64):
/// healthy Ember NCP peer that joins C601 to prove retention on
/// non-suspect hardware (B-007 isolation arm).
pub const MG21_EUI: [u8; 8] = [0x04, 0xe3, 0xe5, 0xff, 0xfe, 0xf4, 0x75, 0x5f];
/// Short address assigned to the MG21 at association.
pub const MG21_SHORT: u16 = 0x0003;
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
    /// Joins as a router, forwards, serves children + own endpoints.
    /// Selected by image (`rd-router`) or generic board provisioning,
    /// not by the two-MAC lab gate below.
    Router,
    /// Joins as a non-routing end device, polls, hosts endpoints.
    /// Selected by image or generic board provisioning.
    EndDevice,
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
    /// Set once a transport frame has been built for the latched
    /// joiner (cleared on every new association accept). Gates the
    /// *unsolicited* short-poll re-arm: after the joiner moved past
    /// association, stray polls must not re-pend stale answers.
    /// Explicit TX-loss recovery (`rearm_assoc`, `rearm_transport`)
    /// is unaffected by this flag.
    transport_sent: bool,
    /// Auxiliary frame counter for NWK-secured transmission (strictly
    /// monotonic per network key). One counter space per sender per
    /// key: the transport delivery and all later secured frames (ZDO
    /// requests, ...) share it. NVM-backed (Phase 4): the firmware
    /// resumes it from the persisted chunk at boot so a reboot never
    /// rewinds into a live peer's replay window.
    nwk_auxctr: AuxCounter,
    /// Bounded indirect-message queue (Phase 1 leg 1b): payloads held
    /// per destination short until the device polls (leg 1c transmits
    /// them). While a short holds an entry it stays OUT of the
    /// hardware source-match table, so its Data-Request ACKs carry
    /// frame-pending=1; shorts with no entry are programmed IN
    /// (pending=0). Table programming itself lands with leg 1c's fw
    /// wiring + air proof.
    indirect: [Option<IndirectSlot>; INDIRECT_DEPTH],
    rx_replay: ReplayTable<8>,
    toggle_tsn: u8,
    /// Toggles served (requests built).
    pub toggles_sent: u32,
    /// Successful Default Responses verified.
    pub defrsp_ok: u32,
    /// Open ZDO transactions (request cluster + TSN) awaiting their
    /// response; closed on match, never grows past 8.
    zdo_pending: PendingTable<8>,
    /// NWK/ZDO frames classified (annce/command/data).
    pub nwk_rx_classified: u32,
    /// NWK frames refused without action (bad header, bad key,
    /// MIC failure, replay, truncation). Never silent: every refusal
    /// increments this counter (Phase 1 leg RX-1).
    pub nwk_rx_ignored: u32,
    /// Last timestamp seen by [`tick`](CoordinatorApp::tick): the
    /// join-rate window clock (association input carries no time).
    last_tick_ms: u64,
    /// Start of the current join-rate window (`None` until the first
    /// policed association).
    assoc_window_start: Option<u64>,
    /// New-EUI associations accepted inside the current window.
    assoc_new_in_window: u8,
    /// New-EUI associations refused by the rate policy (counted,
    /// never answered — the fw logs the total on change).
    pub assoc_throttled: u32,
    /// Association requests denied without answer (unlisted EUI or
    /// closed window). Previously silent; counted since the Phase 4
    /// permit-policy leg.
    pub assoc_denied: u32,
    /// Installed routes toward grandchildren (e.g. 0x0003 via the
    /// router): the TC-side half of relayed delivery. One routing
    /// path only — `next_hop` answers where `take_*_via` sends.
    routes: RouteTable,
    /// Outgoing discovery sessions for unresolved grandchildren.
    discovery: DiscoveryTable,
    /// Grandchild EUI→short map learned via relayed annce or
    /// child-table sync (wire-order EUIs, like `extra_shorts`).
    /// Direct children live in the child table; these never do.
    grandchildren: [Option<([u8; 8], u16)>; 8],
    /// Last route-request identifier stamped by our own discoveries.
    rreq_seq: u8,
}

impl CoordinatorApp {
    /// New unformed coordinator.
    #[must_use]
    pub fn new() -> Self {
        let mut assoc = CoordAssoc::new();
        assoc.provision(APP_PAN, COORD_SHORT, &TC_EUI_WIRE);
        Self {
            machine: CoordinatorMachine::new(AgingPolicy::default()),
            tc: TrustCenter::new(),
            assoc,
            extra_shorts: [None; 8],
            mac_seq: 0,
            nwk_seq: 0,
            aps_counter: 0,
            transport_pending: false,
            transport_sent: false,
            nwk_auxctr: AuxCounter::fresh(TRANSPORT_AUX_BASE),
            indirect: [None; INDIRECT_DEPTH],
            rx_replay: ReplayTable::<8>::new(),
            toggle_tsn: ZCL_TSN,
            toggles_sent: 0,
            defrsp_ok: 0,
            zdo_pending: PendingTable::new(),
            nwk_rx_classified: 0,
            nwk_rx_ignored: 0,
            last_tick_ms: 0,
            assoc_window_start: None,
            assoc_new_in_window: 0,
            assoc_throttled: 0,
            assoc_denied: 0,
            routes: RouteTable::new(),
            discovery: DiscoveryTable::new(),
            grandchildren: [None; 8],
            rreq_seq: 0,
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

    /// Admit a grandchild through its router parent (child-table sync).
    ///
    /// The grandchild never enters the direct child table: it is
    /// admitted at the Trust Center (joined devices) and given a
    /// route via `via` (e.g. `0x0003` via `0x0002`). The EUI→short
    /// map is remembered for transport building, and the short poll
    /// / assoc latch is untouched (the router owns the MAC leg).
    ///
    /// Requirement `05-3474-23-3661-03` (repo-minted,
    /// MINTED-pending-confirm).
    pub fn admit_grandchild<L: SerialLog>(
        &mut self,
        log: &mut L,
        eui: [u8; 8],
        short: u16,
        via: u16,
        now_ms: u64,
    ) -> Result<(), AppError> {
        if self.state() != CoordinatorState::Formed || !self.machine.permit_open() {
            return Err(AppError::BadRole);
        }
        let ieee = u64::from_le_bytes(eui);
        self.tc
            .admit(ieee, short, JoinMethod::InstallCode, 100)
            .map_err(AppError::Join)?;
        if !self.grandchildren.contains(&Some((eui, short))) {
            if let Some(slot) = self.grandchildren.iter_mut().find(|s| s.is_none()) {
                *slot = Some((eui, short));
            }
        }
        // EUI orientation tolerance: match either wire order.
        if !self.extra_shorts.contains(&Some((eui, short))) {
            let mut rev = eui;
            rev.reverse();
            if !self.extra_shorts.contains(&Some((rev, short))) {
                if let Some(slot) = self.extra_shorts.iter_mut().find(|s| s.is_none()) {
                    *slot = Some((eui, short));
                }
            }
        }
        let _ = self.assoc.allow(eui);
        self.routes
            .install(short, via, 1, now_ms, ROUTE_LIFETIME_MS)
            .map_err(|_| AppError::BadRole)?;
        let mut line = [0u8; 80];
        let mut n = 0usize;
        for &b in b"C6APP ADMIT-GRANDCHILD ieee=".iter() {
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
        for &b in b" via=0x".iter() {
            line[n] = b;
            n += 1;
        }
        for shift in [12u16, 8, 4, 0] {
            line[n] = HEX[((via >> shift) & 0x0f) as usize];
            n += 1;
        }
        if let Ok(s) = core::str::from_utf8(&line[..n]) {
            log.log(s);
        }
        Ok(())
    }

    /// Next hop toward `dst` from the TC route table, if live.
    ///
    /// Requirement `05-3474-23-3661-04` (repo-minted,
    /// MINTED-pending-confirm).
    #[must_use]
    pub fn next_hop(&self, dst: u16, now_ms: u64) -> Option<u16> {
        self.routes.next_hop(dst, now_ms)
    }

    /// Open route discovery for `dst` (single-flight per dst).
    ///
    /// Requirement `05-3474-23-3661-04` (repo-minted,
    /// MINTED-pending-confirm).
    pub fn start_discovery(&mut self, dst: u16, now_ms: u64) -> Result<u8, AppError> {
        if dst == COORD_SHORT {
            return Err(AppError::BadRole);
        }
        self.rreq_seq = self.rreq_seq.wrapping_add(1);
        self.discovery
            .start(dst, self.rreq_seq, now_ms)
            .map(|s| s.rreq_id)
            .map_err(|_| AppError::BadRole)
    }

    /// Fold an inbound route reply: resolves the pending session and
    /// installs the route. Stray replies return `false` and install
    /// nothing.
    ///
    /// Requirement `05-3474-23-3661-04` (repo-minted,
    /// MINTED-pending-confirm).
    pub fn note_discovery_reply(
        &mut self,
        rreq_id: u8,
        dst: u16,
        next_hop: u16,
        cost: u8,
        now_ms: u64,
    ) -> Result<bool, AppError> {
        use rounddance_nwk::RoutingError;
        match self.discovery.resolve(rreq_id, now_ms) {
            Ok(_) => {
                self.routes
                    .install(dst, next_hop, cost, now_ms, ROUTE_LIFETIME_MS)
                    .map_err(|_| AppError::BadRole)?;
                Ok(true)
            }
            Err(RoutingError::UnknownReply) => Ok(false),
            Err(_) => Err(AppError::BadRole),
        }
    }

    /// Install a relay-learned route leg (reverse leg from a relayed
    /// request, forward leg from a transiting reply).
    ///
    /// Requirement `05-3474-23-3661-03` (repo-minted,
    /// MINTED-pending-confirm).
    pub fn install_route(
        &mut self,
        dst: u16,
        next_hop: u16,
        cost: u8,
        now_ms: u64,
    ) -> Result<(), AppError> {
        self.routes
            .install(dst, next_hop, cost, now_ms, ROUTE_LIFETIME_MS)
            .map_err(|_| AppError::BadRole)
    }

    /// Authorize a discovery retransmit for `dst`.
    pub fn authorize_discovery_retry(&mut self, dst: u16, now_ms: u64) -> Result<bool, AppError> {
        self.discovery
            .authorize_retry(dst, now_ms)
            .map_err(|_| AppError::BadRole)
    }

    /// Age installed routes + retire dead discovery sessions.
    /// Returns `(routes_expired, sessions_retired)`.
    pub fn tick_routing(&mut self, now_ms: u64) -> (usize, usize) {
        let r = self.routes.expire(now_ms);
        let d = self.discovery.sweep(now_ms);
        (r, d)
    }

    /// EUI for a grandchild short, if learned.
    fn grandchild_eui(&self, short: u16) -> Option<[u8; 8]> {
        self.grandchildren
            .iter()
            .flatten()
            .find(|(_, s)| *s == short)
            .map(|(e, _)| *e)
            .or_else(|| {
                self.extra_shorts
                    .iter()
                    .flatten()
                    .find(|(_, s)| *s == short)
                    .map(|(e, _)| *e)
            })
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

    /// New-EUI associations refused by the join-rate policy so far.
    #[must_use]
    pub fn assoc_throttled(&self) -> u32 {
        self.assoc_throttled
    }

    /// Associations denied without answer so far (unlisted EUI or
    /// closed permit window).
    #[must_use]
    pub fn assoc_denied(&self) -> u32 {
        self.assoc_denied
    }

    /// Whether `req` comes from the currently latched EUI
    /// (re-assoc: retry/rejoin path, always free of budget).
    fn is_latched_reassoc(&self, req: &crate::mac_cmd::AssocReq) -> bool {
        match self.assoc.device_eui() {
            Some(latched) => eui_matches(&latched, &req.src_eui),
            None => false,
        }
    }

    /// Join-rate police for one assoc-req: true when the request must
    /// be dropped answered-nothing (budget exhausted for a NEW EUI).
    /// Re-assocs from the latched EUI always pass (legit retry/rejoin
    /// path); requests that would be denied anyway (closed window,
    /// misaddressed, unlisted EUI) are NOT throttled — they fall
    /// through to the normal deny path and count as denied. Callers
    /// must invoke [`note_assoc_accept`](CoordinatorApp::note_assoc_accept)
    /// with the pre-accept [`is_latched_reassoc`](CoordinatorApp::is_latched_reassoc)
    /// verdict when the request is subsequently accepted.
    fn police_assoc(&mut self, req: &crate::mac_cmd::AssocReq) -> bool {
        // Re-assoc from the latched EUI: free (retry/rejoin path).
        if self.is_latched_reassoc(req) {
            return false;
        }
        // Mirror the CoordAssoc accept gate so only would-be accepts
        // consume budget; denials stay denials.
        if !self.machine.permit_open() {
            return false;
        }
        if req.dst_pan != APP_PAN || req.dst_short != COORD_SHORT {
            return false;
        }
        if !self.assoc.is_allowed(&req.src_eui) {
            return false;
        }
        // Roll the window on the tick clock.
        let start = self.assoc_window_start.unwrap_or(self.last_tick_ms);
        if self.last_tick_ms.wrapping_sub(start) >= ASSOC_WINDOW_MS {
            self.assoc_window_start = Some(self.last_tick_ms);
            self.assoc_new_in_window = 0;
        } else if self.assoc_window_start.is_none() {
            self.assoc_window_start = Some(self.last_tick_ms);
        }
        self.assoc_new_in_window >= ASSOC_NEW_MAX
    }

    /// Record one accepted association against the rate budget (only
    /// NEW EUIs consume; call with the latch state from BEFORE the
    /// accept — [`CoordAssoc::on_assoc_req`](crate::mac_cmd::CoordAssoc::on_assoc_req)
    /// overwrites it).
    fn note_assoc_accept(&mut self, was_latched_same: bool) {
        if !was_latched_same {
            self.assoc_new_in_window = self.assoc_new_in_window.saturating_add(1);
        }
    }

    /// Resolve an assigned short to its admitted EUI (the reverse of
    /// the [`CoordinatorApp::take_assoc_rsp`] short selection): extra
    /// admissions first, grandchildren next, then the [`JOINER_SHORT`]
    /// fallback. Unknown shorts resolve to nothing, so stray polls
    /// re-arm nothing.
    fn short_to_eui(&self, short: u16) -> Option<[u8; 8]> {
        if let Some((eui, _)) = self
            .extra_shorts
            .iter()
            .flatten()
            .find(|(_, s)| *s == short)
        {
            return Some(*eui);
        }
        if let Some((eui, _)) = self
            .grandchildren
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
    /// responder permit bit in sync (closed on expiry). Also advances
    /// the join-rate window clock (association input is untimed).
    pub fn tick(&mut self, now_ms: u64, elapsed_ms: u64) {
        self.last_tick_ms = now_ms;
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
                // Capture the pre-accept latch verdict FIRST:
                // `on_assoc_req` overwrites the latch, after which a
                // new EUI and a repeat are indistinguishable.
                let repeat = self.is_latched_reassoc(req);
                if self.police_assoc(req) {
                    // Rate-throttled new EUI: counted, never answered
                    // (no latch, no pend, no transport — the churn that
                    // burns transport builds + aux counters + NVS
                    // writes stops here).
                    self.assoc_throttled = self.assoc_throttled.saturating_add(1);
                } else if self.assoc.on_assoc_req(req) {
                    // Latched: the Trust-Center key delivery is owed too
                    // (the NCP waits for the 0x05 frame after the RSP).
                    // New cycle: a later transport no longer counts.
                    self.transport_pending = true;
                    self.transport_sent = false;
                    // Only NEW EUIs consume rate budget; repeats (the
                    // retry/rejoin path) ride free.
                    self.note_assoc_accept(repeat);
                } else {
                    // Denied without answer (closed window, misaddress,
                    // unlisted EUI): counted since the permit-policy leg
                    // (previously silent).
                    self.assoc_denied = self.assoc_denied.saturating_add(1);
                }
            }
            MacIncoming::DataPoll(ref poll) => {
                let _ = self.assoc.on_data_poll(poll);
            }
            MacIncoming::ShortPoll(ref poll) => {
                // No unsolicited re-arm once this latch moved past
                // association (transport built): stray polls from a
                // joined device must not re-pend stale answers. The
                // explicit TX-loss path (`rearm_assoc`) is unaffected.
                if !self.transport_sent {
                    if let Some(eui) = self.short_to_eui(poll.src_short) {
                        let _ = self.assoc.on_data_poll(&DataPoll {
                            seq: poll.seq,
                            src_eui: eui,
                        });
                    }
                }
            }
            MacIncoming::Other => {}
            // Beacons are joiner-side input; the coordinator ignores
            // its own (and neighbours') beacons.
            MacIncoming::Beacon(_) => {}
            // Association responses are joiner-side input; the
            // coordinator never receives its own answers.
            MacIncoming::AssocRsp(_) => {}
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

    /// Resume the NWK aux counter from the NVS-persisted chunk (Phase
    /// 4: the firmware reads the chunk at boot and calls this before
    /// any secured frame goes on air; without it a reboot rewinds
    /// into live peers' replay windows). `None` on a fresh part
    /// starts at the deployment floor.
    pub fn resume_auxctr(&mut self, saved_chunk: Option<u32>) {
        self.nwk_auxctr = AuxCounter::resume(saved_chunk, TRANSPORT_AUX_BASE);
    }

    /// Chunk index due for NVS persistence, if any (Phase 4:
    /// persist-before-use — call after every secured-frame build and
    /// write the returned chunk to NVS *before* transmitting).
    /// Returns `None` when the current chunk is already reported.
    pub fn aux_checkpoint(&mut self) -> Option<u32> {
        self.nwk_auxctr.poll_checkpoint()
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
        // Source EUI rides LSB-first (wire order, `TC_EUI_WIRE`),
        // like every other address field the NCP parses (w93: MG21's
        // aux source is the LE bytes of its EUI).
        let auxctr = self.nwk_auxctr.take();
        let params = TransportKeyParams {
            dst_pan: APP_PAN,
            dst_short: short,
            dst_eui: eui,
            src_eui: TC_EUI_WIRE,
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
                self.transport_sent = true;

                // Fresh key = fresh counter space: the (re)joining
                // device restarts its frame counter (factory reset
                // wipes NVM). Without this, post-join frames after
                // any same-boot rejoin misclassify as replays (b007).
                self.rx_replay.remove(u64::from_le_bytes(eui));
                Ok(n)
            }
            Err(_) => Err(MacCmdError::BufferTooSmall),
        }
    }

    /// Build a Trust-Center→grandchild transport-key frame for an
    /// explicit destination (routed delivery to `dst_short`).
    ///
    /// Unlike [`take_transport_key`](Self::take_transport_key) this
    /// does not consume the assoc-latch pending flag: the grandchild
    /// never latched at the MAC leg (the router owns it). The MAC
    /// destination is the installed next hop when one covers
    /// `dst_short` (relay leg), else `dst_short` itself (direct
    /// radio-reachable leg). The NWK destination is always
    /// `dst_short`; the MSDU is byte identical either way (relay
    /// contract). Consumes one NWK aux counter + one APS counter and
    /// resets that source's replay state (fresh key = fresh counter
    /// space, b007 rule).
    ///
    /// Requirement `05-3474-23-3661-01` + `-3661-03` (repo-minted,
    /// MINTED-pending-confirm).
    pub fn take_transport_key_to(
        &mut self,
        out: &mut [u8],
        netkey: &[u8; 16],
        transport_key: &[u8; 16],
        dst_short: u16,
        now_ms: u64,
    ) -> Result<usize, MacCmdError> {
        use rounddance_commission::{
            build_transport_key_frame_via, TransportKeyParams, TRANSPORT_FRAME_LEN,
        };
        if out.len() < TRANSPORT_FRAME_LEN {
            return Err(MacCmdError::BufferTooSmall);
        }
        let Some(dst_eui) = self
            .grandchild_eui(dst_short)
            .or_else(|| self.short_to_eui(dst_short))
        else {
            return Err(MacCmdError::BufferTooSmall);
        };
        let mac_dst = self.next_hop(dst_short, now_ms).unwrap_or(dst_short);
        let auxctr = self.nwk_auxctr.take();
        let params = TransportKeyParams {
            dst_pan: APP_PAN,
            dst_short,
            dst_eui,
            src_eui: TC_EUI_WIRE,
            mac_seq: self.take_mac_seq(),
            nwk_seq: self.take_nwk_seq(),
            nwk_radius: 0x1e,
            aps_ctr: self.take_aps_counter(),
            auxctr,
            seq_no: 0x00,
            netkey: *netkey,
            transport_key: *transport_key,
        };
        match build_transport_key_frame_via(&params, mac_dst, out) {
            Ok(n) => {
                self.rx_replay.remove(u64::from_le_bytes(dst_eui));
                Ok(n)
            }
            Err(_) => Err(MacCmdError::BufferTooSmall),
        }
    }

    /// Whether `short` holds a queued indirect payload (Phase 1 leg
    /// 1b). The fw poll handler uses this to program the hardware
    /// source-match table: entries present → leave OUT (ACK
    /// frame-pending=1, "data waiting"); absent → program IN
    /// (pending=0, "nothing queued").
    #[must_use]
    pub fn has_indirect(&self, short: u16) -> bool {
        self.indirect
            .iter()
            .flatten()
            .any(|slot| slot.short == short)
    }

    /// Queue an indirect payload for `short` (overwrites any existing
    /// entry for that short without consuming a new slot).
    ///
    /// # Errors
    ///
    /// [`MacCmdError::BufferTooSmall`] when the payload exceeds
    /// [`INDIRECT_MAX`] octets; [`MacCmdError::TableFull`] when no
    /// slot is free.
    pub fn indirect_enqueue(&mut self, short: u16, payload: &[u8]) -> Result<(), MacCmdError> {
        if payload.len() > INDIRECT_MAX {
            return Err(MacCmdError::BufferTooSmall);
        }
        if let Some(slot) = self
            .indirect
            .iter_mut()
            .flatten()
            .find(|slot| slot.short == short)
        {
            slot.len = payload.len();
            slot.buf[..payload.len()].copy_from_slice(payload);
            return Ok(());
        }
        let Some(free) = self.indirect.iter_mut().find(|slot| slot.is_none()) else {
            return Err(MacCmdError::TableFull);
        };
        let mut buf = [0u8; INDIRECT_MAX];
        buf[..payload.len()].copy_from_slice(payload);
        *free = Some(IndirectSlot {
            short,
            len: payload.len(),
            buf,
        });
        Ok(())
    }

    /// Take (and free) the queued indirect payload for `short`,
    /// copying it into `out`. Returns `Ok(0)` when no entry is
    /// queued — the same idle convention as
    /// [`take_assoc_rsp`](Self::take_assoc_rsp).
    ///
    /// # Errors
    ///
    /// [`MacCmdError::BufferTooSmall`] when `out` is shorter than the
    /// queued payload (the entry is retained for retry with a bigger
    /// buffer).
    pub fn indirect_take(&mut self, short: u16, out: &mut [u8]) -> Result<usize, MacCmdError> {
        let Some(pos) = self
            .indirect
            .iter()
            .position(|slot| slot.is_some_and(|s| s.short == short))
        else {
            return Ok(0);
        };
        let slot = self.indirect[pos].expect("position names a live slot");
        if out.len() < slot.len {
            return Err(MacCmdError::BufferTooSmall);
        }
        out[..slot.len].copy_from_slice(&slot.buf[..slot.len]);
        let n = slot.len;
        self.indirect[pos] = None;
        Ok(n)
    }

    /// Build a coordinator→joiner Node_desc_req (ZDO cluster `0x0002`,
    /// profile `0x0000`, unicast endpoint 0) as an NWK-secured data
    /// frame into `out`; consumes one APS counter (used as both the
    /// APS counter and the ZDO TSN) and one NWK aux counter. The fw
    /// sends this once per handled Device_annce (the reference Ember
    /// TC's follow-through, w97 joinCTL).
    ///
    /// # Errors
    ///
    /// [`MacCmdError::BufferTooSmall`] when `out` cannot hold the
    /// frame.
    pub fn take_node_desc_req(
        &mut self,
        out: &mut [u8],
        dst_short: u16,
        netkey: &[u8; 16],
    ) -> Result<usize, MacCmdError> {
        use rounddance_commission::{build_secured_nwk_frame_via, SecuredNwkParams};
        use rounddance_zdo::zdp::NodeDescReq;
        let c = self.take_aps_counter();
        if self.zdo_pending.open(0x0002, c).is_err() {
            // Eight unanswered requests outstanding: refuse a ninth
            // rather than send a transaction that can never correlate.
            return Err(MacCmdError::TableFull);
        }
        let zdo = NodeDescReq {
            tsn: c,
            nwk_of_interest: dst_short,
        };
        let mut zbuf = [0u8; NodeDescReq::LEN];
        zdo.encode_into(&mut zbuf)
            .map_err(|_| MacCmdError::BufferTooSmall)?;
        let aps = rounddance_aps::DataHeader {
            control: rounddance_aps::FrameControl::data(rounddance_aps::DeliveryMode::Unicast),
            dest: rounddance_aps::DataDest::Unicast { dst_endpoint: 0 },
            cluster_id: 0x0002,
            profile_id: 0x0000,
            src_endpoint: 0,
            counter: c,
            ext: None,
        };
        let mut abuf = [0u8; 16];
        let alen = aps
            .encode_into(&zbuf, &mut abuf)
            .map_err(|_| MacCmdError::BufferTooSmall)?;
        let auxctr = self.nwk_auxctr.take();
        // Routed leg: MAC goes to the next hop when one covers the
        // dst; NWK dst stays final (same relay contract as the
        // transport and toggle legs). Direct when unrouted.
        let mac_dst = self
            .routes
            .next_hop(dst_short, self.last_tick_ms)
            .unwrap_or(dst_short);
        let params = SecuredNwkParams {
            dst_pan: APP_PAN,
            dst_short,
            src_short: COORD_SHORT,
            broadcast: false,
            src_eui: TC_EUI_WIRE,
            mac_seq: self.take_mac_seq(),
            nwk_seq: self.take_nwk_seq(),
            nwk_radius: 0x1e,
            auxctr,
            netkey: *netkey,
        };
        // last_tick_ms is the TC tick clock; routing uses caller ms.
        // For host/sim determinism the caller ticks before building,
        // so this resolves the installed leg.
        match build_secured_nwk_frame_via(&abuf[..alen], &params, mac_dst, out) {
            Ok(n) => Ok(n),
            Err(_) => Err(MacCmdError::BufferTooSmall),
        }
    }

    /// Feed one inbound NWK frame (MAC header already stripped by the
    /// driver/adapter path) to the coordinator responder: secured
    /// frames are opened with `keys`, replay-checked, then dispatched
    /// by NWK frame type — ZDO Device_annce marks the child heard,
    /// NWK commands report their id (response legs follow), other
    /// APS data reports cluster/profile. Every refusal is counted in
    /// [`nwk_rx_ignored`](Self::nwk_rx_ignored); nothing drops
    /// silently.
    #[must_use]
    pub fn on_nwk_data(&mut self, msdu: &[u8], keys: &KeySet, now_ms: u64) -> NwkRxOutcome {
        let outcome = self.classify_nwk(msdu, keys, now_ms);
        match outcome {
            NwkRxOutcome::Ignored(_) => self.nwk_rx_ignored += 1,
            _ => self.nwk_rx_classified += 1,
        }
        outcome
    }

    fn classify_nwk(&mut self, msdu: &[u8], keys: &KeySet, now_ms: u64) -> NwkRxOutcome {
        use NwkIgnore as Ig;
        let dec = match nwk_decode(msdu) {
            Ok(d) => d,
            Err(_) => return NwkRxOutcome::Ignored(Ig::BadHeader),
        };
        if dec.header.control.source_route {
            return NwkRxOutcome::Ignored(Ig::SourceRoute);
        }
        // Header length: fixed part + extended addresses present.
        let mut hdr_len = 8;
        if dec.header.control.dst_ieee {
            hdr_len += 8;
        }
        if dec.header.control.src_ieee {
            hdr_len += 8;
        }
        let mut pt_buf = [0u8; 160];
        let pt: &[u8] = if dec.header.control.security {
            // Decode with the base level restored (the sender zeroes
            // the on-air level bits; wave-33/wave-36 pattern): the
            // nonce builder and the re-encoded AAD both need the
            // restored control octet.
            let (aux, aux_len) = match AuxHeader::decode_with_level(dec.payload, NWK_SEC_LEVEL) {
                Ok(v) => v,
                Err(_) => return NwkRxOutcome::Ignored(Ig::BadAux),
            };
            let seq = match aux.key_id {
                KeyIdentifier::Index(s) => s,
                _ => return NwkRxOutcome::Ignored(Ig::BadKeyId),
            };
            let key = match keys.select(seq) {
                Some(k) => k,
                None => return NwkRxOutcome::Ignored(Ig::BadAux),
            };
            let nonce = match NwkNonce::from_header(&aux) {
                Ok(n) => n,
                Err(_) => return NwkRxOutcome::Ignored(Ig::BadAux),
            };
            let Some(restored_ctl) = aux.control.with_level(NWK_SEC_LEVEL) else {
                return NwkRxOutcome::Ignored(Ig::BadAux);
            };
            let restored = AuxHeader {
                control: restored_ctl,
                frame_counter: aux.frame_counter,
                ext_source: aux.ext_source,
                key_id: aux.key_id,
            };
            let mut rbuf = [0u8; 16];
            let rlen = match restored.encode_into(&mut rbuf) {
                Ok(n) => n,
                Err(_) => return NwkRxOutcome::Ignored(Ig::BadAux),
            };
            if dec.payload.len() < aux_len + CCM_TAG_LEN {
                return NwkRxOutcome::Ignored(Ig::BadAux);
            }
            let mut aad = [0u8; 64];
            if hdr_len + rlen > aad.len() {
                return NwkRxOutcome::Ignored(Ig::BadHeader);
            }
            aad[..hdr_len].copy_from_slice(&msdu[..hdr_len]);
            aad[hdr_len..hdr_len + rlen].copy_from_slice(&rbuf[..rlen]);
            let ct_end = dec.payload.len() - CCM_TAG_LEN;
            let mut tag = [0u8; CCM_TAG_LEN];
            tag.copy_from_slice(&dec.payload[ct_end..]);
            let n = match ccm_star_open_into(
                &key.key,
                &nonce.bytes,
                &aad[..hdr_len + rlen],
                &dec.payload[aux_len..ct_end],
                &tag,
                &mut pt_buf,
            ) {
                Ok(n) => n,
                Err(_) => return NwkRxOutcome::Ignored(Ig::MicFailed),
            };
            // Replay check after authentication (counter untrusted
            // before the MIC verifies).
            let src_u64 = aux
                .ext_source
                .map(u64::from_le_bytes)
                .unwrap_or(dec.header.src_addr as u64);
            if self.rx_replay.check(src_u64, aux.frame_counter).is_err() {
                return NwkRxOutcome::Ignored(Ig::Replay);
            }
            &pt_buf[..n]
        } else {
            dec.payload
        };
        match dec.header.control.frame_type {
            NwkFrameType::Command => match pt.first() {
                Some(&id) => NwkRxOutcome::NwkCommand { id },
                None => NwkRxOutcome::Ignored(Ig::EmptyCommand),
            },
            NwkFrameType::Data => self.classify_aps(pt, now_ms),
            _ => NwkRxOutcome::Ignored(Ig::BadHeader),
        }
    }

    /// Dispatch one decrypted/open NWK-data payload as APS.
    fn classify_aps(&mut self, pt: &[u8], now_ms: u64) -> NwkRxOutcome {
        match decode_data(pt) {
            Ok(d) => {
                if d.header.profile_id == 0x0000 && d.header.cluster_id == 0x0013 {
                    return self.on_annce(d.payload, now_ms);
                }
                if d.header.profile_id == 0x0000 && d.header.cluster_id & 0x8000 != 0 {
                    return self.on_zdo_response(d.header.cluster_id, d.payload);
                }
                NwkRxOutcome::Data {
                    cluster: d.header.cluster_id,
                    profile: d.header.profile_id,
                }
            }
            // Receiver tolerance: live Ember NCPs announce with APS
            // broadcast + destination endpoint 0x00 (MIC-verified on
            // air, w96 joinS), which `decode_data` refuses per
            // §2.2.5.1.2. Accept exactly that class here — strict on
            // transmit (we never emit it), tolerant on receive.
            Err(_) => self.classify_annce_broadcast(pt, now_ms),
        }
    }

    /// Tolerated annce class: `FC 08` + ep `00` + cluster `0x0013` +
    /// profile `0x0000`, then the standard ZDO payload.
    fn classify_annce_broadcast(&mut self, pt: &[u8], now_ms: u64) -> NwkRxOutcome {
        use NwkIgnore as Ig;
        if pt.len() < 8 + DeviceAnnce::LEN
            || pt[0] != 0x08
            || pt[1] != 0x00
            || u16::from_le_bytes([pt[2], pt[3]]) != 0x0013
            || u16::from_le_bytes([pt[4], pt[5]]) != 0x0000
        {
            return NwkRxOutcome::Ignored(Ig::BadAps);
        }
        self.on_annce(&pt[8..], now_ms)
    }

    /// Handle one ZDO Device_annce payload (TSN first): mark the
    /// announced child heard when it is a direct child; otherwise
    /// learn it as a grandchild (relayed assoc/annce or child-table
    /// sync): remember the EUI→short map and install a direct route
    /// leg when none covers the short yet. Unknown shorts still
    /// report the annce — learning is best-effort, never a refusal.
    ///
    /// Requirement `05-3474-23-3661-03` (repo-minted,
    /// MINTED-pending-confirm).
    fn on_annce(&mut self, zdp: &[u8], now_ms: u64) -> NwkRxOutcome {
        use NwkIgnore as Ig;
        let ann = match DeviceAnnce::decode(zdp) {
            Ok(a) => a,
            Err(_) => return NwkRxOutcome::Ignored(Ig::BadZdo),
        };
        let mut eui = [0u8; 8];
        eui.copy_from_slice(&ann.ieee.to_le_bytes());
        if self.machine.child_heard(ann.nwk_addr, now_ms).is_err() {
            // Not a direct child: learn as grandchild when space
            // remains. Direct leg first (radio-reachable lab); the
            // router leg from `admit_grandchild` / discovery wins
            // when it was installed cheaper-or-equal.
            if !self.grandchildren.contains(&Some((eui, ann.nwk_addr))) {
                if let Some(slot) = self.grandchildren.iter_mut().find(|s| s.is_none()) {
                    *slot = Some((eui, ann.nwk_addr));
                }
            }
            if self.routes.next_hop(ann.nwk_addr, now_ms).is_none() {
                let _ =
                    self.routes
                        .install(ann.nwk_addr, ann.nwk_addr, 1, now_ms, ROUTE_LIFETIME_MS);
            }
        }
        NwkRxOutcome::Annce {
            short: ann.nwk_addr,
            eui,
            capability: ann.capability,
        }
    }

    /// Match one ZDO response payload (TSN first) against the open
    /// transactions: a hit consumes the entry and reports the
    /// correlation; a stray TSN stays a counted `Data` (pending
    /// entries retained); an empty payload is counted Ignored.
    fn on_zdo_response(&mut self, cluster: u16, zdp: &[u8]) -> NwkRxOutcome {
        use NwkIgnore as Ig;
        let &[tsn, ..] = zdp else {
            return NwkRxOutcome::Ignored(Ig::BadZdo);
        };
        let status = zdp.get(1).copied();
        match self.zdo_pending.close(cluster, tsn) {
            Some(req_cluster) => NwkRxOutcome::ZdoResponse {
                cluster,
                tsn,
                status,
                req_cluster,
            },
            None => NwkRxOutcome::Data {
                cluster,
                profile: 0x0000,
            },
        }
    }

    /// Open ZDO transactions currently awaiting a response.
    #[must_use]
    pub fn zdo_pending_open(&self) -> usize {
        self.zdo_pending.len()
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

    /// Start a new toggle intent: advance the ZCL transaction number
    /// and hand it out. The fw calls this once per toggle it decides
    /// to send (not per confirm-driven rebuild — retries of one
    /// intent MUST share the TSN so the joiner's duplicate-answer
    /// suppression can tell retries apart from new toggles).
    /// Distinct intents always carry distinct TSNs (wrapping).
    pub fn new_toggle(&mut self) -> u8 {
        self.toggle_tsn = self.toggle_tsn.wrapping_add(1);
        self.toggle_tsn
    }

    /// Build the secured ZCL Toggle request frame into `out`.
    ///
    /// Same wire shape as every other secured frame we radiate
    /// (Node_desc_req, transport, annce): MAC + NWK-secured data
    /// (aux with ext source + key-sequence octet, CCM* seal under
    /// `netkey`) carrying a unicast APS header (ep1, On/Off cluster,
    /// HA profile) + the ZCL Toggle. One aux counter per build from
    /// the NVM-backed space (the fw persists it after every build,
    /// like the node_desc path). Returns the frame length.
    ///
    /// Requirement `07-5123-08-241-01` (ZCL frame, reused).
    pub fn build_toggle_request<L: SerialLog>(
        &mut self,
        log: &mut L,
        netkey: &[u8; 16],
        out: &mut [u8],
    ) -> Result<usize, AppError> {
        self.build_toggle_request_to(log, netkey, JOINER_SHORT, out)
    }

    /// Build a routed secured ZCL Toggle to an explicit destination
    /// (grandchild via the installed next hop, direct when unrouted).
    ///
    /// The MAC destination is the next hop covering `dst_short`;
    /// the NWK/APS/ZCL destinations stay `dst_short`/ep1. The MSDU
    /// is byte identical to the direct frame for the same counters
    /// (relay contract), so the router re-wraps it verbatim and the
    /// grandchild opens it with the normal nonce/AAD.
    ///
    /// Requirement `05-3474-23-3661-02` (repo-minted,
    /// MINTED-pending-confirm).
    pub fn build_toggle_request_to<L: SerialLog>(
        &mut self,
        log: &mut L,
        netkey: &[u8; 16],
        dst_short: u16,
        out: &mut [u8],
    ) -> Result<usize, AppError> {
        let mut zcl = [0u8; 8];
        let zlen = onoff::client::toggle(self.toggle_tsn, &mut zcl)
            .map_err(|_| AppError::BufferTooSmall)?;
        let c = self.take_aps_counter();
        let aps = rounddance_aps::DataHeader {
            control: rounddance_aps::FrameControl::data(rounddance_aps::DeliveryMode::Unicast),
            dest: rounddance_aps::DataDest::Unicast {
                dst_endpoint: ZCL_ENDPOINT,
            },
            cluster_id: onoff::CLUSTER_ID,
            profile_id: HA_PROFILE,
            src_endpoint: ZCL_ENDPOINT,
            counter: c,
            ext: None,
        };
        let mut abuf = [0u8; 32];
        let alen = aps
            .encode_into(&zcl[..zlen], &mut abuf)
            .map_err(|_| AppError::BufferTooSmall)?;
        let auxctr = self.nwk_auxctr.take();
        let mac_dst = self
            .routes
            .next_hop(dst_short, self.last_tick_ms)
            .unwrap_or(dst_short);
        let params = rounddance_commission::SecuredNwkParams {
            dst_pan: APP_PAN,
            dst_short,
            src_short: COORD_SHORT,
            broadcast: false,
            src_eui: TC_EUI_WIRE,
            mac_seq: self.take_mac_seq(),
            nwk_seq: self.take_nwk_seq(),
            nwk_radius: 0x1e,
            auxctr,
            netkey: *netkey,
        };
        match rounddance_commission::build_secured_nwk_frame_via(
            &abuf[..alen],
            &params,
            mac_dst,
            out,
        ) {
            Ok(n) => {
                self.toggles_sent += 1;
                log_air(log, "C6APP TX-TOGGLE", &out[..n]);
                Ok(n)
            }
            Err(_) => Err(AppError::BufferTooSmall),
        }
    }

    /// Verify a Default Response NPDU from the joiner.
    ///
    /// Decodes NWK → APS → aux (replay-checked) → ZCL and requires
    /// command `0x0b` with the toggle echoed plus success status.
    /// Returns `true` on success and counts it.
    /// Verify a secured Default Response that was already classified
    /// by [`on_nwk_data`](CoordinatorApp::on_nwk_data) (which consumed
    /// the replay check for these bytes): decodes without
    /// re-checking (re-checking would refuse a legitimate first
    /// delivery as its own replay), then verifies. The fw confirmation
    /// path calls this for `NwkRxOutcome::Data` with the On/Off
    /// cluster; anything else must not reach here (it was counted,
    /// never answered).
    pub fn verify_defrsp<L: SerialLog>(
        &mut self,
        log: &mut L,
        keys: &KeySet,
        msdu: &[u8],
    ) -> Result<bool, AppError> {
        // Same open as `classify_nwk` (NWK|AUX|CT, ext source,
        // key-sequence octet, CCM* seal), minus the replay check:
        // the caller classified these exact bytes first, which
        // consumed it — re-checking would refuse a legitimate first
        // delivery as its own replay.
        let dec = nwk_decode(msdu).map_err(|_| AppError::BadFrame)?;
        if dec.header.control.source_route {
            return Err(AppError::BadFrame);
        }
        let mut hdr_len = 8;
        if dec.header.control.dst_ieee {
            hdr_len += 8;
        }
        if dec.header.control.src_ieee {
            hdr_len += 8;
        }
        let (aux, aux_len) = match AuxHeader::decode_with_level(dec.payload, NWK_SEC_LEVEL) {
            Ok(v) => v,
            Err(_) => return Err(AppError::BadFrame),
        };
        let seq = match aux.key_id {
            KeyIdentifier::Index(s) => s,
            _ => return Err(AppError::BadFrame),
        };
        let key = match keys.select(seq) {
            Some(k) => k,
            None => return Err(AppError::BadFrame),
        };
        let nonce = match NwkNonce::from_header(&aux) {
            Ok(n) => n,
            Err(_) => return Err(AppError::BadFrame),
        };
        let Some(restored_ctl) = aux.control.with_level(NWK_SEC_LEVEL) else {
            return Err(AppError::BadFrame);
        };
        let restored = AuxHeader {
            control: restored_ctl,
            frame_counter: aux.frame_counter,
            ext_source: aux.ext_source,
            key_id: aux.key_id,
        };
        let mut rbuf = [0u8; 16];
        let rlen = match restored.encode_into(&mut rbuf) {
            Ok(n) => n,
            Err(_) => return Err(AppError::BadFrame),
        };
        if dec.payload.len() < aux_len + CCM_TAG_LEN {
            return Err(AppError::BadFrame);
        }
        let mut aad = [0u8; 64];
        if hdr_len + rlen > aad.len() {
            return Err(AppError::BadFrame);
        }
        aad[..hdr_len].copy_from_slice(&msdu[..hdr_len]);
        aad[hdr_len..hdr_len + rlen].copy_from_slice(&rbuf[..rlen]);
        let ct_end = dec.payload.len() - CCM_TAG_LEN;
        let mut tag = [0u8; CCM_TAG_LEN];
        tag.copy_from_slice(&dec.payload[ct_end..]);
        let mut pt_buf = [0u8; 160];
        let n = match ccm_star_open_into(
            &key.key,
            &nonce.bytes,
            &aad[..hdr_len + rlen],
            &dec.payload[aux_len..ct_end],
            &tag,
            &mut pt_buf,
        ) {
            Ok(n) => n,
            Err(_) => return Err(AppError::BadFrame),
        };
        let zcl_body = {
            let pt = &pt_buf[..n];
            let aps = decode_data(pt).map_err(|_| AppError::BadFrame)?;
            if aps.header.cluster_id != onoff::CLUSTER_ID || aps.header.profile_id != HA_PROFILE {
                return Err(AppError::WrongCluster);
            }
            aps.payload
        };
        self.note_defrsp(log, zcl_body)
    }

    /// Shared Default Response verification tail: ZCL decode, toggle
    /// echo + success checks, count, log.
    fn note_defrsp<L: SerialLog>(
        &mut self,
        log: &mut L,
        zcl_body: &[u8],
    ) -> Result<bool, AppError> {
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
    rx_replay: ReplayTable<8>,
    nwk_seq: u8,
    aps_counter: u8,
    mac_seq: u8,
    /// Short address assigned by the coordinator's assoc-rsp (set on
    /// the joiner-side handoff; `None` until associated).
    assoc_short: Option<u16>,
    /// This unit's own EUI in display order (the [`JOINER_EUI`] layout:
    /// base MAC with `ff:fe` inserted mid-address). The lab joiner
    /// image uses [`JOINER_EUI`]; the router uplink (`rd-router`)
    /// provisions its own EUI here so its assoc-req, transport-key
    /// match, annce, and secured frames carry the router identity
    /// instead of the joiner's (previously hardcoded, which made the
    /// TC answer a stranger the router's radio filter then dropped).
    ieee: [u8; 8],
    /// Adopted network key + sequence (set by the transport-key open;
    /// secures all later joiner traffic).
    netkey: Option<([u8; 16], u8)>,
    /// Joiner-side NWK auxiliary counter space (strictly monotonic
    /// per key, disjoint from the coordinator's range so captures
    /// attribute cleanly). NVM-backed like the coordinator side
    /// (fw resumes it at boot, persists per chunk before TX).
    join_auxctr: AuxCounter,
    /// Last answered ZCL request TSN, if any (duplicate-answer
    /// suppression: a confirm-lost coordinator retry re-seals the
    /// cached answer instead of re-dispatching, so the lamp flips
    /// exactly once per toggle intent).
    tog_last_tsn: Option<u8>,
    /// Cached DefRsp ZCL plaintext for the last answered TSN
    /// (re-sealed verbatim on same-TSN redelivery, fresh auxctr).
    tog_last_zcl: [u8; 32],
    /// Valid length of [`tog_last_zcl`](JoinerApp::tog_last_zcl).
    tog_last_len: usize,
    /// Frames answered with a Default Response.
    pub defrsp_sent: u32,
    /// NWK/ZDO frames classified (joiner side).
    pub nwk_rx_classified: u32,
    /// NWK frames refused without action (joiner side).
    pub nwk_rx_ignored: u32,
    /// Unsecured vendor frames tolerated post-association (wave-23
    /// behavior, counted for the log).
    pub unsecured_tolerated: u32,
}

impl<'a> JoinerApp<'a> {
    /// New joiner hosting an On/Off server on `def`, with the lab
    /// joiner identity ([`JOINER_EUI`]).
    pub fn new(def: &'a onoff::ServerDef) -> Result<Self, AppError> {
        Self::new_with_ieee(def, JOINER_EUI)
    }

    /// New joiner hosting an On/Off server on `def` with an explicit
    /// unit identity (display-order EUI, [`eui_from_mac`] layout).
    /// The router uplink provisions its own EUI; all other behavior
    /// is identical to [`new`](Self::new).
    pub fn new_with_ieee(def: &'a onoff::ServerDef, ieee: [u8; 8]) -> Result<Self, AppError> {
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
            rx_replay: ReplayTable::<8>::new(),
            nwk_seq: 0,
            aps_counter: 0,
            mac_seq: 0,
            assoc_short: None,
            ieee,
            netkey: None,
            join_auxctr: AuxCounter::fresh(JOINER_AUX_BASE),
            tog_last_tsn: None,
            tog_last_zcl: [0; 32],
            tog_last_len: 0,
            defrsp_sent: 0,
            nwk_rx_classified: 0,
            nwk_rx_ignored: 0,
            unsecured_tolerated: 0,
        })
    }

    /// This unit's EUI in wire order (LSB-first on air).
    fn ieee_wire(&self) -> [u8; 8] {
        let mut w = self.ieee;
        w.reverse();
        w
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

    /// Begin the beacon survey.
    pub fn begin_scan<L: SerialLog>(&mut self, log: &mut L) -> Result<(), AppError> {
        let mask = ChannelMask::from_list(&[APP_CHANNEL]).map_err(|_| AppError::BadRole)?;
        self.steering
            .begin_scan(mask, 3)
            .map_err(|_| AppError::BadRole)?;
        // No channel in this line (`no_std`): the firmware logs the
        // tuned channel at boot; the scan mask is ch15 (lab C601).
        // A ch25-tuned joiner still surveys here — the entry carries
        // the arrival channel, and the mask only bounds rescan loops.
        log.log("C6APP SCAN");
        Ok(())
    }

    /// Ingest one survey entry (the coordinator's beacon).
    ///
    /// Collection only: the caller runs [`finish_scan`](Self::finish_scan)
    /// when the scan window elapses, then acts on the elected
    /// candidate. Finishing per-beacon would park the table on the
    /// first heard network (usually a non-permitting neighbour) and
    /// drop every later beacon — the w97 C601 air failure.
    pub fn ingest_beacon(&mut self, entry: BeaconSurveyEntry) -> Result<(), AppError> {
        self.steering.ingest(entry).map_err(|_| AppError::BadRole)?;
        Ok(())
    }

    /// Close the scan window: rank acceptable rows and elect the
    /// winner. Returns the elected PAN, if any. Election requires
    /// [`rounddance_commission::MIN_ELECTION_SIGHTINGS`]
    /// acceptable rows for the winning PAN in this window (Phase 4:
    /// a lone phantom beacon can never elect, while any live network
    /// clears the bar in its first window).
    pub fn finish_scan<L: SerialLog>(&mut self, log: &mut L) -> Option<u16> {
        self.steering.finish_scan(&LinkEvidencePolicy::default());
        // Forward the election once per join attempt: a repeat
        // finish while already AwaitingCandidate must not re-fire
        // on_candidate (BadState wedge); the joiner only moves
        // Unjoined → AwaitingCandidate here.
        if self.steering.state() == SteeringState::CandidateSelected {
            if let Some(c) = self.steering.candidate() {
                log.log("C6APP SURVEY candidate");
                if self.joiner.state() == JoinerState::Unjoined {
                    self.joiner.on_candidate();
                }
                return Some(c.pan_id);
            }
        }
        None
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

    /// Feed one inbound MAC PSDU to the joiner: beacons feed the
    /// survey (channel/RSSI/LQI come from the indication, not the
    /// PSDU), association responses complete the handoff (short
    /// adopted, machine advanced). Anything else is ignored —
    /// a joiner answers nothing on the air at this leg.
    pub fn on_mac_psdu<L: SerialLog>(
        &mut self,
        log: &mut L,
        psdu: &[u8],
        channel: u8,
        rssi: i8,
        lqi: u8,
    ) -> MacIncoming {
        let inc = crate::mac_cmd::classify(psdu);
        match inc {
            MacIncoming::Beacon(ref bi) => {
                let payload = match psdu.get(bi.payload_off..) {
                    Some(p) => p,
                    None => return inc,
                };
                let (version, router_capacity, end_device_capacity) = match beacon_net_caps(payload)
                {
                    Some(v) => v,
                    None => return inc,
                };
                let entry = BeaconSurveyEntry {
                    pan_id: bi.src_pan,
                    channel,
                    lqi,
                    rssi,
                    permit_joining: bi.assoc_permit,
                    router_capacity,
                    end_device_capacity,
                    protocol_version: version,
                };
                // Collection only (windowed finish in finish_scan):
                // per-beacon finish would park the table on the first
                // heard network; survey errors (full table, bad
                // channel, wrong state) just skip this beacon.
                let _ = self.ingest_beacon(entry);
            }
            MacIncoming::AssocRsp(ref rsp) => {
                // EUI orientation-insensitive, like the coordinator
                // admission path.
                if !eui_matches(&self.ieee, &rsp.dst_eui) {
                    return inc;
                }
                self.assoc_short = Some(rsp.short);
                self.assoc_confirm(log, rsp.status == 0x00);
            }
            _ => {}
        }
        inc
    }

    /// Short address assigned by the coordinator's assoc-rsp (`None`
    /// until the handoff above runs).
    #[must_use]
    pub fn assoc_short(&self) -> Option<u16> {
        self.assoc_short
    }

    /// Adopted network key + sequence (`None` until the transport-key
    /// open adopts it).
    #[must_use]
    pub fn adopted_netkey(&self) -> Option<([u8; 16], u8)> {
        self.netkey
    }

    /// Resume the joiner aux counter from NVS (same contract as
    /// [`resume_auxctr`](CoordinatorApp::resume_auxctr); joiner-side
    /// NVS wiring is a parked follow-up, the type already supports
    /// it).
    pub fn resume_auxctr(&mut self, saved_chunk: Option<u32>) {
        self.join_auxctr = AuxCounter::resume(saved_chunk, JOINER_AUX_BASE);
    }

    /// Joiner-side checkpoint, mirroring
    /// [`aux_checkpoint`](CoordinatorApp::aux_checkpoint).
    pub fn aux_checkpoint(&mut self) -> Option<u32> {
        self.join_auxctr.poll_checkpoint()
    }

    /// Selected candidate PAN (valid once the survey elects one).
    #[must_use]
    pub fn candidate_pan(&self) -> Option<u16> {
        self.steering.candidate().map(|c| c.pan_id)
    }

    /// Feed one inbound NWK frame (MAC header already stripped) to the
    /// joiner responder: the Trust-Center transport-key delivery opens
    /// with the HA-derived key and adopts the network key; later
    /// network-key-secured frames dispatch (ZDO requests surface for
    /// answers). Every refusal is counted; nothing drops silently.
    pub fn on_nwk_joiner(&mut self, msdu: &[u8]) -> JoinerNwkOutcome {
        use JoinerNwkOutcome as O;
        let outcome = self.classify_joiner_nwk(msdu);
        match outcome {
            O::Ignored(_) => self.nwk_rx_ignored += 1,
            _ => self.nwk_rx_classified += 1,
        }
        outcome
    }

    fn classify_joiner_nwk(&mut self, msdu: &[u8]) -> JoinerNwkOutcome {
        use JoinerNwkOutcome as O;
        use NwkIgnore as Ig;
        let dec = match nwk_decode(msdu) {
            Ok(d) => d,
            Err(_) => return O::Ignored(Ig::BadHeader),
        };
        if dec.header.control.source_route {
            return O::Ignored(Ig::SourceRoute);
        }
        let mut hdr_len = 8;
        if dec.header.control.dst_ieee {
            hdr_len += 8;
        }
        if dec.header.control.src_ieee {
            hdr_len += 8;
        }
        // Transport-key delivery: NWK-open data + APS-sealed command
        // (the proactive Trust-Center shape our coordinator emits;
        // key-id mode 2 names the key-transport key). Anything else
        // unsecured is counted, never opened.
        if !dec.header.control.security {
            return match dec.header.control.frame_type {
                NwkFrameType::Command => match dec.payload.first() {
                    Some(&id) => O::NwkCommand { id },
                    None => O::Ignored(Ig::EmptyCommand),
                },
                NwkFrameType::Data => self.open_transport_key(msdu, hdr_len),
                _ => O::Ignored(Ig::BadHeader),
            };
        }
        let (aux, aux_len) = match AuxHeader::decode_with_level(dec.payload, NWK_SEC_LEVEL) {
            Ok(v) => v,
            Err(_) => return O::Ignored(Ig::BadAux),
        };
        match aux.key_id {
            KeyIdentifier::Index(seq) => self.open_network_data(msdu, hdr_len, &aux, aux_len, seq),
            _ => O::Ignored(Ig::BadKeyId),
        }
    }

    /// Open one Trust-Center transport-key delivery (NWK-open header,
    /// APS auxiliary with the key-transport key id): derive the
    /// transport key from the preconfigured HA link key, verify the
    /// MIC, check the command pair, and adopt the network key.
    /// Duplicates (aux counter at/below the adopted one — e.g. a
    /// coordinator retransmit after a lost ACK) are idempotent, never
    /// fatal: the key is already adopted.
    fn open_transport_key(&mut self, msdu: &[u8], hdr_len: usize) -> JoinerNwkOutcome {
        use rounddance_commission::{
            ha_transport_key, TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_NETWORK,
        };
        use JoinerNwkOutcome as O;
        use NwkIgnore as Ig;
        // NWK header (8, unsecured) + APS header (2: 0x21 + counter) +
        // 13-octet APS auxiliary (no key-identifier octets on air for
        // the key-transport shape) + MIC-32 tail.
        if msdu.len() < hdr_len + 2 + 13 + CCM_TAG_LEN || hdr_len != 8 {
            return O::Ignored(Ig::BadHeader);
        }
        let aps = &msdu[hdr_len..hdr_len + 2];
        if aps[0] != 0x21 || msdu[hdr_len + 2] != 0x30 {
            // Wrong APS command header or aux control: not our
            // proactive transport-key shape.
            return O::Ignored(Ig::BadAps);
        }
        // Fixed 13-octet aux layout: control, LE counter, 8-octet
        // source EUI. (The generic aux decoder is not used here: it
        // would name the key id Source4 and consume 5 key-id octets
        // that do not exist on air for this shape.)
        let auxctr = u32::from_le_bytes([
            msdu[hdr_len + 3],
            msdu[hdr_len + 4],
            msdu[hdr_len + 5],
            msdu[hdr_len + 6],
        ]);
        let mut ext = [0u8; 8];
        ext.copy_from_slice(&msdu[hdr_len + 7..hdr_len + 15]);
        let tkey = match ha_transport_key() {
            Ok(k) => k,
            Err(_) => return O::Ignored(Ig::UnknownKey),
        };
        let mut aad = [0u8; 15];
        aad[..2].copy_from_slice(&msdu[hdr_len..hdr_len + 2]);
        let mut restored = [0u8; 14];
        restored[0] = 0x35;
        restored[1..5].copy_from_slice(&auxctr.to_le_bytes());
        restored[5..13].copy_from_slice(&ext);
        // No key-identifier octet: TransportKey encodes to zero bytes
        // (matches the committed transport builder + golden vector).
        // APS-level AAD covers only the APS header + restored aux
        // (w45 battery); the unsecured NWK header is not authenticated.
        aad[2..15].copy_from_slice(&restored[..13]);
        let mut nonce = [0u8; CCM_NONCE_LEN];
        nonce[..8].copy_from_slice(&ext);
        nonce[8..12].copy_from_slice(&auxctr.to_le_bytes());
        nonce[12] = 0x35;
        let tail_at = hdr_len + 2 + 13;
        let ct_end = msdu.len() - CCM_TAG_LEN;
        if ct_end <= tail_at {
            return O::Ignored(Ig::BadAux);
        }
        let mut tag = [0u8; CCM_TAG_LEN];
        tag.copy_from_slice(&msdu[ct_end..]);
        let ct = &msdu[tail_at..ct_end];
        let mut pt = [0u8; 64];
        let n = match ccm_star_open_into(&tkey, &nonce, &aad, ct, &tag, &mut pt) {
            Ok(n) => n,
            Err(_) => return O::Ignored(Ig::MicFailed),
        };
        if n != 35 || pt[0] != TRANSPORT_KEY_CMD || pt[1] != TRANSPORT_KEY_TYPE_NETWORK {
            return O::Ignored(Ig::BadAps);
        }
        // Destination must be us (wire order, orientation-tolerant).
        let mut dst = [0u8; 8];
        dst.copy_from_slice(&pt[19..27]);
        if !eui_matches(&self.ieee_wire(), &dst) {
            return O::Ignored(Ig::BadAps);
        }
        let mut key = [0u8; 16];
        key.copy_from_slice(&pt[2..18]);
        let seq_no = pt[18];
        // Duplicate delivery (coordinator retransmit): already adopted,
        // counter not advancing — idempotent, never fatal.
        if let Some(last) = self.joiner.last_aux_counter() {
            if auxctr <= last {
                return O::TransportAccepted { auxctr };
            }
        }
        if self.joiner.state() != JoinerState::Authenticating {
            return O::Ignored(Ig::WrongState);
        }
        self.joiner
            .note_transport_frame(TRANSPORT_KEY_CMD, TRANSPORT_KEY_TYPE_NETWORK);
        self.joiner.on_transport_open(true, auxctr);
        if self.joiner.state() == JoinerState::Failed {
            return O::Ignored(Ig::WrongState);
        }
        self.netkey = Some((key, seq_no));
        // Replay window for the adopted network key starts here
        // (same rule as the coordinator side: the counter is trusted
        // only after its first MIC-verified sighting).
        let src_u64 = u64::from_le_bytes(ext);
        let _ = self.rx_replay.check(src_u64, auxctr);
        O::TransportAccepted { auxctr }
    }

    /// Open one network-key-secured NWK data frame with the adopted
    /// key: ZDO Node_desc_req surfaces for answers, other APS data
    /// classifies, NWK commands report their id.
    fn open_network_data(
        &mut self,
        msdu: &[u8],
        hdr_len: usize,
        aux: &AuxHeader,
        aux_len: usize,
        seq: u8,
    ) -> JoinerNwkOutcome {
        use JoinerNwkOutcome as O;
        use NwkIgnore as Ig;
        let dec = match nwk_decode(msdu) {
            Ok(d) => d,
            Err(_) => return O::Ignored(Ig::BadHeader),
        };
        let (key, key_seq) = match self.netkey {
            Some((k, s)) if s == seq => (k, s),
            _ => return O::Ignored(Ig::UnknownKey),
        };
        let _ = key_seq;
        let Some(ext) = aux.ext_source else {
            return O::Ignored(Ig::NoSource);
        };
        let mut restored = [0u8; 16];
        restored[0] = 0x2d;
        restored[1..5].copy_from_slice(&aux.frame_counter.to_le_bytes());
        restored[5..13].copy_from_slice(&ext);
        restored[13] = seq;
        let rlen = 14;
        let mut aad = [0u8; 64];
        if hdr_len + rlen > aad.len() {
            return O::Ignored(Ig::BadHeader);
        }
        aad[..hdr_len].copy_from_slice(&msdu[..hdr_len]);
        aad[hdr_len..hdr_len + rlen].copy_from_slice(&restored[..rlen]);
        let mut nonce = [0u8; CCM_NONCE_LEN];
        nonce[..8].copy_from_slice(&ext);
        nonce[8..12].copy_from_slice(&aux.frame_counter.to_le_bytes());
        nonce[12] = 0x2d;
        let tail_at = hdr_len + aux_len;
        let ct_end = msdu.len() - CCM_TAG_LEN;
        if ct_end <= tail_at {
            return O::Ignored(Ig::BadAux);
        }
        let mut tag = [0u8; CCM_TAG_LEN];
        tag.copy_from_slice(&msdu[ct_end..]);
        let ct = &msdu[tail_at..ct_end];
        let mut pt_buf = [0u8; 160];
        let n =
            match ccm_star_open_into(&key, &nonce, &aad[..hdr_len + rlen], ct, &tag, &mut pt_buf) {
                Ok(n) => n,
                Err(_) => return O::Ignored(Ig::MicFailed),
            };
        let src_u64 = u64::from_le_bytes(ext);
        if self.rx_replay.check(src_u64, aux.frame_counter).is_err() {
            return O::Ignored(Ig::Replay);
        }
        let pt = &pt_buf[..n];
        match dec.header.control.frame_type {
            NwkFrameType::Command => match pt.first() {
                Some(&id) => O::NwkCommand { id },
                None => O::Ignored(Ig::EmptyCommand),
            },
            NwkFrameType::Data => match decode_data(pt) {
                Ok(d) if d.header.profile_id == 0x0000 && d.header.cluster_id == 0x0002 => {
                    self.on_node_desc_req(dec.header.src_addr, d.payload)
                }
                Ok(d) => O::Data {
                    cluster: d.header.cluster_id,
                    profile: d.header.profile_id,
                },
                Err(_) => O::Ignored(Ig::BadAps),
            },
            _ => O::Ignored(Ig::BadHeader),
        }
    }

    /// Handle one ZDO Node_desc_req payload (TSN + subject short):
    /// report it for the answer path. Anything shorter than the
    /// 3-octet request is counted, never acted on.
    fn on_node_desc_req(&mut self, src_short: u16, zdp: &[u8]) -> JoinerNwkOutcome {
        use JoinerNwkOutcome as O;
        use NwkIgnore as Ig;
        if zdp.len() < 3 {
            return O::Ignored(Ig::BadZdo);
        }
        O::NodeDescReq {
            src_short,
            tsn: zdp[0],
            subject: u16::from_le_bytes([zdp[1], zdp[2]]),
        }
    }

    fn take_mac_seq(&mut self) -> u8 {
        let s = self.mac_seq;
        self.mac_seq = self.mac_seq.wrapping_add(1);
        s
    }

    /// Build one association-request PSDU into `out` for `dst_pan`
    /// (parent short `dst_short`, normally the coordinator short
    /// `0x0000`; a child joining through a router targets the router
    /// short instead), with our MAC sequence + EUI.
    ///
    /// # Errors
    ///
    /// [`MacCmdError::BufferTooSmall`] when `out` is short.
    pub fn take_assoc_req(
        &mut self,
        out: &mut [u8],
        dst_pan: u16,
        dst_short: u16,
    ) -> Result<usize, MacCmdError> {
        let seq = self.take_mac_seq();
        // EUI rides LSB-first (wire order), as the NCP-verified
        // handshake shape requires (w93 MG21 reference):
        // `joiner_ieee` is little-endian of the display-order const,
        // so big-endian bytes are the wire order.
        build_assoc_req(seq, dst_pan, dst_short, &self.ieee_wire(), MAC_CAPS, out)
    }

    /// Build the joiner's Device_annce broadcast into `out` (MAC +
    /// NWK-secured NWK broadcast + open APS broadcast + ZDO payload):
    /// the announcement the Trust Center waits for after delivering
    /// the network key. Consumes one NWK aux counter + one APS
    /// counter (dual-used as the ZDO TSN, as in `take_node_desc_req`).
    /// Returns `Ok(0)` when no short is assigned or no key adopted
    /// yet (nothing to announce as).
    ///
    /// # Errors
    ///
    /// [`MacCmdError::BufferTooSmall`] when `out` is short.
    pub fn take_annce(&mut self, out: &mut [u8]) -> Result<usize, MacCmdError> {
        use rounddance_commission::{build_secured_nwk_frame, SecuredNwkParams};
        use rounddance_zdo::zdp::DeviceAnnce;
        let (short, (netkey, _seq)) = match (self.assoc_short, self.netkey) {
            (Some(s), Some(k)) => (s, k),
            _ => return Ok(0),
        };
        let c = self.take_aps_counter();
        // APS broadcast to ZDO (live shape per w97 RX-1: FC 08, ep 0,
        // cluster 0x0013, profile 0x0000, no ack/security/extension).
        let mut abuf = [0u8; 8];
        abuf[..8].copy_from_slice(&[0x08, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, c]);
        let annce = DeviceAnnce {
            tsn: c,
            nwk_addr: short,
            ieee: u64::from_le_bytes(self.ieee_wire()),
            capability: MAC_CAPS,
        };
        let mut zbuf = [0u8; DeviceAnnce::LEN];
        annce
            .encode_into(&mut zbuf)
            .map_err(|_| MacCmdError::BufferTooSmall)?;
        let mut pt = [0u8; 32];
        pt[..8].copy_from_slice(&abuf);
        pt[8..8 + DeviceAnnce::LEN].copy_from_slice(&zbuf);
        let pt = &pt[..8 + DeviceAnnce::LEN];
        let auxctr = self.join_auxctr.take();
        let params = SecuredNwkParams {
            dst_pan: APP_PAN,
            dst_short: 0xFFFD,
            src_short: short,
            broadcast: true,
            src_eui: self.ieee_wire(),
            mac_seq: self.take_mac_seq(),
            nwk_seq: self.take_nwk_seq(),
            nwk_radius: 0x1e,
            auxctr,
            netkey,
        };
        match build_secured_nwk_frame(pt, &params, out) {
            Ok(n) => Ok(n),
            Err(_) => Err(MacCmdError::BufferTooSmall),
        }
    }

    /// Answer one ZDO Node_desc_req with a Node_desc_rsp (`status`
    /// success + our lab descriptor) into `out`, NWK-secured with the
    /// adopted key to `dst_short`. Returns `Ok(0)` when no key/short
    /// is held yet.
    ///
    /// # Errors
    ///
    /// [`MacCmdError::BufferTooSmall`] when `out` is short.
    pub fn take_node_desc_rsp(
        &mut self,
        out: &mut [u8],
        dst_short: u16,
        tsn: u8,
        subject: u16,
    ) -> Result<usize, MacCmdError> {
        use rounddance_commission::{build_secured_nwk_frame, SecuredNwkParams};
        use rounddance_zdo::desc::NodeDescriptor;
        use rounddance_zdo::status::ZdpStatus;
        use rounddance_zdo::zdp::NodeDescRsp;
        let (short, (netkey, _)) = match (self.assoc_short, self.netkey) {
            (Some(s), Some(k)) => (s, k),
            _ => return Ok(0),
        };
        let desc = NodeDescriptor {
            flags0: 0x02,
            aps_flags: 0x00,
            freq_band: 0x08,
            mac_cap: MAC_CAPS,
            mfr_code: 0x0000,
            max_buf: 82,
            max_in_transfer: 82,
            server_mask: 0x0000,
            max_out_transfer: 82,
            desc_cap: 0x00,
        };
        let rsp = NodeDescRsp {
            tsn,
            status: ZdpStatus::Success,
            nwk_of_interest: subject,
            descriptor: Some(desc),
            tlvs: &[],
        };
        let mut zbuf = [0u8; 64];
        let zlen = rsp
            .encode_into(&mut zbuf)
            .map_err(|_| MacCmdError::BufferTooSmall)?;
        let c = self.take_aps_counter();
        let aps = DataHeader {
            control: ApsFc::data(DeliveryMode::Unicast),
            dest: DataDest::Unicast { dst_endpoint: 0 },
            cluster_id: 0x8002,
            profile_id: 0x0000,
            src_endpoint: 0,
            counter: c,
            ext: None,
        };
        let mut abuf = [0u8; 64];
        let alen = aps
            .encode_into(&zbuf[..zlen], &mut abuf)
            .map_err(|_| MacCmdError::BufferTooSmall)?;
        let auxctr = self.join_auxctr.take();
        let params = SecuredNwkParams {
            dst_pan: APP_PAN,
            dst_short,
            src_short: short,
            broadcast: false,
            src_eui: self.ieee_wire(),
            mac_seq: self.take_mac_seq(),
            nwk_seq: self.take_nwk_seq(),
            nwk_radius: 0x1e,
            auxctr,
            netkey,
        };
        match build_secured_nwk_frame(&abuf[..alen], &params, out) {
            Ok(n) => Ok(n),
            Err(_) => Err(MacCmdError::BufferTooSmall),
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
            .device_annce(ZCL_TSN, JOINER_SHORT, u64::from_le_bytes(self.ieee));
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
    /// Answer a Toggle request frame that was already classified by
    /// [`on_nwk_joiner`](JoinerApp::on_nwk_joiner) (which consumed the
    /// replay check for these bytes): decodes without re-checking
    /// (re-checking would refuse a legitimate first delivery as its
    /// own replay), then answers like a fresh Toggle. A same-TSN
    /// redelivery (confirm-lost coordinator retry, fresh aux counter)
    /// re-seals the cached answer WITHOUT re-dispatching, so the
    /// lamp flips exactly once per toggle intent. The fw calls this
    /// for `JoinerNwkOutcome::Data` with the On/Off cluster; anything
    /// else must not reach here.
    pub fn answer_toggle<L: SerialLog>(
        &mut self,
        log: &mut L,
        msdu: &[u8],
        out: &mut [u8],
    ) -> Result<usize, AppError> {
        // Same open as `open_network_data` (NWK|AUX|CT, ext source,
        // key-sequence octet, CCM* seal), minus the replay check:
        // the caller classified these exact bytes first, which
        // consumed it — re-checking would refuse a legitimate first
        // delivery as its own replay.
        let dec = nwk_decode(msdu).map_err(|_| AppError::BadFrame)?;
        if dec.header.control.frame_type != NwkFrameType::Data {
            return Err(AppError::BadFrame);
        }
        let mut hdr_len = 8usize;
        if dec.header.control.dst_ieee {
            hdr_len += 8;
        }
        if dec.header.control.src_ieee {
            hdr_len += 8;
        }
        let (aux, aux_len) =
            match rounddance_security::AuxHeader::decode_with_level(dec.payload, NWK_SEC_LEVEL) {
                Ok(v) => v,
                Err(_) => return Err(AppError::BadFrame),
            };
        let seq = match aux.key_id {
            rounddance_security::KeyIdentifier::Index(s) => s,
            _ => return Err(AppError::BadFrame),
        };
        let (netkey, _) = match self.netkey {
            Some((k, s)) if s == seq => (k, s),
            _ => return Err(AppError::BadFrame),
        };
        let Some(ext) = aux.ext_source else {
            return Err(AppError::BadFrame);
        };
        let mut restored = [0u8; 16];
        restored[0] = 0x2d;
        restored[1..5].copy_from_slice(&aux.frame_counter.to_le_bytes());
        restored[5..13].copy_from_slice(&ext);
        restored[13] = seq;
        let mut aad = [0u8; 64];
        if hdr_len + 14 > aad.len() {
            return Err(AppError::BadFrame);
        }
        aad[..hdr_len].copy_from_slice(&msdu[..hdr_len]);
        aad[hdr_len..hdr_len + 14].copy_from_slice(&restored[..14]);
        let mut nonce = [0u8; CCM_NONCE_LEN];
        nonce[..8].copy_from_slice(&ext);
        nonce[8..12].copy_from_slice(&aux.frame_counter.to_le_bytes());
        nonce[12] = 0x2d;
        let tail_at = hdr_len + aux_len;
        let ct_end = msdu.len() - CCM_TAG_LEN;
        if ct_end <= tail_at {
            return Err(AppError::BadFrame);
        }
        let mut tag = [0u8; CCM_TAG_LEN];
        tag.copy_from_slice(&msdu[ct_end..]);
        let mut pt_buf = [0u8; 160];
        let n = match ccm_star_open_into(
            &netkey,
            &nonce,
            &aad[..hdr_len + 14],
            &msdu[tail_at..ct_end],
            &tag,
            &mut pt_buf,
        ) {
            Ok(n) => n,
            Err(_) => return Err(AppError::BadFrame),
        };
        let pt = &pt_buf[..n];
        let aps = decode_data(pt).map_err(|_| AppError::BadFrame)?;
        if aps.header.cluster_id != onoff::CLUSTER_ID || aps.header.profile_id != HA_PROFILE {
            return Err(AppError::WrongCluster);
        }
        let zcl_wire = aps.payload;
        let (hdr, body) = ZclHeader::decode(zcl_wire).map_err(|_| AppError::BadFrame)?;
        if hdr.command_id != onoff::CMD_TOGGLE {
            return Err(AppError::WrongCluster);
        }
        let mut zcl_out = [0u8; 64];
        let reply_len = if self.tog_last_tsn == Some(hdr.tsn) && self.tog_last_len > 0 {
            // Confirm-lost duplicate: re-seal the cached answer;
            // the lamp already flipped for this TSN.
            let n = self.tog_last_len.min(zcl_out.len());
            zcl_out[..n].copy_from_slice(&self.tog_last_zcl[..n]);
            n
        } else {
            let n = self.run_toggle_dispatch(&hdr, body, &mut zcl_out)?;
            self.tog_last_tsn = Some(hdr.tsn);
            self.tog_last_zcl[..n.min(32)].copy_from_slice(&zcl_out[..n.min(32)]);
            self.tog_last_len = n.min(32);
            n
        };
        self.seal_defrsp_answer(log, &zcl_out[..reply_len], out)
    }

    /// Run the ZCL Toggle through dispatch + Default Response triage
    /// into `zcl_out`; returns the reply length. Dispatch flips the
    /// lamp (server behavior); callers needing exactly-once semantics
    /// must gate on the request TSN first (see `answer_toggle`).
    fn run_toggle_dispatch(
        &mut self,
        hdr: &ZclHeader,
        body: &[u8],
        zcl_out: &mut [u8; 64],
    ) -> Result<usize, AppError> {
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
            hdr,
            body,
            onoff::CLUSTER_ID,
            None,
            &[],
            zcl_out,
        );
        match outcome {
            Ok(DispatchOutcome::Respond(n)) => Ok(n),
            Ok(DispatchOutcome::Silent) => {
                if !should_default_respond(hdr, true, false, false) {
                    return Err(AppError::BadStatus(0xff));
                }
                encode_default_rsp(hdr.tsn, hdr.command_id, ZclStatus::Success, zcl_out)
            }
            Err(status) => {
                if !should_default_respond(hdr, true, false, true) {
                    return Err(AppError::BadStatus(status.as_u8()));
                }
                encode_default_rsp(hdr.tsn, hdr.command_id, status, zcl_out)
            }
        }
    }

    /// Seal a DefRsp ZCL payload as a secured NPDU (fresh aux
    /// counter + frame counters every build: never re-radiate
    /// identical secured bytes), count and log it.
    /// Seal a DefRsp ZCL payload as a secured frame, same wire shape
    /// as every other secured frame we radiate (MAC + NWK-secured
    /// data with ext source + key-sequence octet, CCM* seal under the
    /// adopted key): unicast APS (ep1, On/Off, HA) + payload. One aux
    /// counter per build from the NVM-backed space (never re-radiate
    /// identical secured bytes: a confirm-lost first copy would trip
    /// the coordinator's replay check).
    fn seal_defrsp_answer<L: SerialLog>(
        &mut self,
        log: &mut L,
        zcl: &[u8],
        out: &mut [u8],
    ) -> Result<usize, AppError> {
        use rounddance_aps::{DataHeader, DeliveryMode};
        use rounddance_commission::{build_secured_nwk_frame, SecuredNwkParams};
        // Unassociated joiners have nothing to answer with. The short
        // falls back to JOINER_SHORT (same as take_assoc_rsp: the
        // mock/sim path never latched one, but the fw path always
        // has the adopted short by the time it answers).
        let short = self.assoc_short.unwrap_or(JOINER_SHORT);
        let (netkey, _) = match self.netkey {
            Some(k) => k,
            None => return Ok(0),
        };
        let c = self.take_aps_counter();
        let aps = DataHeader {
            control: rounddance_aps::FrameControl::data(DeliveryMode::Unicast),
            dest: rounddance_aps::DataDest::Unicast {
                dst_endpoint: ZCL_ENDPOINT,
            },
            cluster_id: onoff::CLUSTER_ID,
            profile_id: HA_PROFILE,
            src_endpoint: ZCL_ENDPOINT,
            counter: c,
            ext: None,
        };
        let mut abuf = [0u8; 32];
        let alen = aps
            .encode_into(zcl, &mut abuf)
            .map_err(|_| AppError::BufferTooSmall)?;
        let auxctr = self.join_auxctr.take();
        let params = SecuredNwkParams {
            dst_pan: APP_PAN,
            dst_short: COORD_SHORT,
            src_short: short,
            broadcast: false,
            src_eui: self.ieee_wire(),
            mac_seq: self.take_mac_seq(),
            nwk_seq: self.take_nwk_seq(),
            nwk_radius: 0x1e,
            auxctr,
            netkey,
        };
        match build_secured_nwk_frame(&abuf[..alen], &params, out) {
            Ok(n) => {
                self.defrsp_sent += 1;
                log_air(log, "C6APP TX-DEFRSP", &out[..n]);
                Ok(n)
            }
            Err(_) => Err(AppError::BufferTooSmall),
        }
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
