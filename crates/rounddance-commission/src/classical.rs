//! Classical join: Trust-Center join state machines plus join/rejoin/leave
//! orchestration over the NWK/APS/ZDO/security crates.
//!
//! Paraphrase-level model of doc `22-65816-030` BDB v3.1 §5.6 (join
//! policy: mode snap-back, allow-list currency, install-code-gated
//! dynamic keys, join time-boxing; anchors p0032-L525-L561), §5.7
//! (negotiation advertisement; anchor p0034-L574-L577), §6.1 (roles;
//! anchor p0035-L598-L605), §9.2–§9.6 (symmetric exchange, symmetric
//! join, key negotiation, negotiation join, CBKE upgrade; anchors
//! p0061-L1307-L1449) and doc `05-3474-23` R23.2 §3.6.1 family (join,
//! rejoin, leave, address-conflict and permit-joining primitives;
//! anchors p0146-L3540, p0221-L5224, p0222-L5278, p0223-L5310-L5349,
//! p0225-L5380-L5382, p0260-L6171, p0261-L6194, p0266-L6285). All
//! wording here is paraphrase (D1, `SCOPE.md` §2).
//!
//! Requirement IDs: corpus-mined `22-65816-030-56-*`, `-57-01`,
//! `-61-01`, `-91-02` … `-91-06`; repo-minted `05-3474-23-32214-01`,
//! `05-3474-23-32215-01`, `05-3474-23-3615-01`, `05-3474-23-36111-01`,
//! `05-3474-23-36113-01` (dots stripped), MINTED-pending-confirm.
//!
//! This layer is thin orchestration: key storage lives in
//! [`rounddance_security::KeySet`], counters in
//! [`rounddance_security::FrameCounter`], discovery/binding frames in
//! [`rounddance_zdo`]. Nothing here duplicates those machines; the
//! machines below only sequence them.

use rounddance_security::{mmo_hash_128, EccBackend, EccError, NETWORK_KEY_LEN};
use rounddance_zdo::{DeviceAnnce, MgmtLeaveReq};

/// Install-code payload lengths admitted (octets, excluding the 2-octet
/// check field): 6, 8, 12, or 16.
///
/// Requirement `22-65816-030-56-03` (dynamic link-key exchange runs only
/// over an install-code-derived key or unique passphrase).
pub const INSTALL_CODE_LENS: [usize; 4] = [6, 8, 12, 16];
/// Check-field length appended to every install code.
pub const INSTALL_CODE_CRC_LEN: usize = 2;
/// Largest install code on the wire (16 + check field).
pub const MAX_INSTALL_CODE_LEN: usize = 18;
/// Largest joined-device table (declared budget).
pub const MAX_JOINED_DEVICES: usize = 32;

/// Vendor APS command id observed on real post-association traffic
/// from a stock coordinator: a level-0 (plaintext, counter-less)
/// command frame that is NOT the standard transport-key command. The
/// value is a field observation, not a normative assignment — the
/// join machine treats every unsecured command id the same way.
pub const UNSECURED_VENDOR_CMD: u8 = 0x30;

/// APS transport-key command id: the Trust Center's proactive
/// key-delivery frame. A joiner that reached the post-association
/// wait advances only on this command — never on vendor chatter or
/// any other first frame.
pub const TRANSPORT_KEY_CMD: u8 = 0x05;

/// Key-type field selecting the standard network key inside the
/// transport-key command. The TC-first delivery the lab coordinator
/// sends carries this type; any other type is not the network-key
/// delivery the joiner is waiting for.
pub const TRANSPORT_KEY_TYPE_NETWORK: u8 = 0x01;

/// Classical-join failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinError {
    /// Install-code length or check field rejected.
    BadInstallCode,
    /// Key-derivation backend failure.
    KdfFailed,
    /// Operation not allowed in the current state.
    BadState,
    /// Device is not on the allow-list (allow-list joining).
    NotAllowed,
    /// Joined table is full.
    TableFull,
    /// No entry for this device.
    NotFound,
    /// Post-association wait ended with no transport-key frame: the
    /// coordinator spoke only unsecured/vendor traffic or stayed
    /// silent. Distinct from [`JoinError::JoinTimeout`] (whole-window
    /// eviction): this names the transport-missing cause so callers
    /// can tell "TC talked but never delivered keys" apart from "TC
    /// never admitted us".
    NoTransport,
    /// Join window elapsed: the device is asked to leave
    /// (`22-65816-030-56-04`).
    JoinTimeout,
    /// Delivered key is not a fresh unique Trust-Center link key
    /// (`22-65816-030-91-02`).
    BadTransportKey,
    /// Key confirmation did not verify.
    ConfirmMismatch,
    /// Caller buffer too small.
    BufferTooSmall,
}

/// One install code: payload plus check field, validated on build.
///
/// Requirements `22-65816-030-56-03` (install-code-gated dynamic
/// keys) + `22-65816-030-56-07` (format/CRC parameter set, anchor
/// p0041-L807-L827: 128-bit payload, 16-bit check, LE check field).
/// Validation rejects BE-stored or non-reflected-CRC codes, which the
/// BDB worked example distinguishes.
#[derive(Debug, Clone, Copy)]
pub struct InstallCode {
    bytes: [u8; MAX_INSTALL_CODE_LEN],
    len: u8,
}

impl InstallCode {
    /// Validate `code` (payload + 2-octet check field) and store it.
    pub fn from_slice(code: &[u8]) -> Result<Self, JoinError> {
        if code.len() > MAX_INSTALL_CODE_LEN {
            return Err(JoinError::BadInstallCode);
        }
        let payload_len = code.len().saturating_sub(INSTALL_CODE_CRC_LEN);
        if !INSTALL_CODE_LENS.contains(&payload_len)
            || code.len() != payload_len + INSTALL_CODE_CRC_LEN
        {
            return Err(JoinError::BadInstallCode);
        }
        let expect = crc16_ccitt(&code[..payload_len]);
        // The check field rides little-endian on the wire
        // (`22-65816-030-56-07` / §6.11.1.1: the worked example shows
        // the field as C3 B5 for CRC 0xB5C3).
        let got = u16::from_le_bytes([code[payload_len], code[payload_len + 1]]);
        if expect != got {
            return Err(JoinError::BadInstallCode);
        }
        let mut bytes = [0u8; MAX_INSTALL_CODE_LEN];
        bytes[..code.len()].copy_from_slice(code);
        Ok(Self {
            bytes,
            len: code.len() as u8,
        })
    }

    /// Attach a correct check field to `payload` (lengths per
    /// [`INSTALL_CODE_LENS`]).
    pub fn with_crc(payload: &[u8], out: &mut [u8]) -> Result<usize, JoinError> {
        if !INSTALL_CODE_LENS.contains(&payload.len()) {
            return Err(JoinError::BadInstallCode);
        }
        if out.len() < payload.len() + INSTALL_CODE_CRC_LEN {
            return Err(JoinError::BufferTooSmall);
        }
        out[..payload.len()].copy_from_slice(payload);
        out[payload.len()..payload.len() + INSTALL_CODE_CRC_LEN]
            .copy_from_slice(&crc16_ccitt(payload).to_le_bytes());
        Ok(payload.len() + INSTALL_CODE_CRC_LEN)
    }

    /// Raw code octets (payload + check field).
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Payload octets (check field stripped).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[..self.len as usize - INSTALL_CODE_CRC_LEN]
    }
}

/// 16-bit CCITT check used on install codes, per the §6.11.1.1.1
/// parameter set (`22-65816-030-56-07`, anchor p0041-L816-L827):
/// polynomial 0x1021, direct init 0xFFFF, final XOR 0xFFFF, reflected
/// input and output (bitwise LSB-first form with reflected polynomial
/// 0x8408).
///
/// Self-consistent within this crate: codes built by
/// [`InstallCode::with_crc`] pass [`InstallCode::from_slice`], and any
/// single-octet corruption fails. The BDB §6.11.1.1 worked example
/// (payload 83..05 → 0xB5C3) is pinned as a frozen vector in
/// `tests/vectors.rs`.
fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFF
}

/// Injected install-code → link-key derivation.
///
/// The input is always the full validated code (payload + 2-octet
/// check field, as laid out by [`InstallCode`]): the normative BDB
/// derivation hashes the whole code, check field included.
/// Backends: the normative [`MmoJoinKdf`], any [`EccBackend`] via
/// [`EccJoinKdf`], or a test stub.
pub trait JoinKdf {
    /// Derive the 16-octet initial link key from the full install
    /// code and the joiner's long address (the address is advisory:
    /// the normative derivation ignores it).
    fn derive_link_key(
        &self,
        install_code: &[u8],
        eui64: &[u8; 8],
        out: &mut [u8; NETWORK_KEY_LEN],
    ) -> Result<(), JoinError>;
}

/// Normative install-code derivation: the AES-MMO-128 hash of the
/// full validated code (payload + check field), per §6.11.1.2
/// (`22-65816-030-56-08`, anchor p0041-L828-L834). The joiner address
/// plays no role in this construction and is ignored.
///
/// This replaces the backend-injected [`EccJoinKdf`] as the
/// derivation real devices use; the worked key is pinned in
/// `tests/vectors.rs`.
#[derive(Debug, Clone, Copy, Default)]
pub struct MmoJoinKdf;

impl JoinKdf for MmoJoinKdf {
    fn derive_link_key(
        &self,
        install_code: &[u8],
        _eui64: &[u8; 8],
        out: &mut [u8; NETWORK_KEY_LEN],
    ) -> Result<(), JoinError> {
        let digest = mmo_hash_128(install_code).map_err(|_| JoinError::KdfFailed)?;
        out.copy_from_slice(&digest);
        Ok(())
    }
}

/// [`JoinKdf`] over any security-crate ECC/hash backend (reuse, not
/// duplication): the full validated code and long address feed the
/// backend KDF under a commissioning domain label. Injection seam
/// for tests and alternate backends — not the on-air derivation
/// (see [`MmoJoinKdf`]).
pub struct EccJoinKdf<B>(pub B);

impl<B: EccBackend> JoinKdf for EccJoinKdf<B> {
    fn derive_link_key(
        &self,
        install_code: &[u8],
        eui64: &[u8; 8],
        out: &mut [u8; NETWORK_KEY_LEN],
    ) -> Result<(), JoinError> {
        let mut info = [0u8; 24];
        info[..8].copy_from_slice(b"zb-join\x00");
        info[8..16].copy_from_slice(eui64);
        let take = install_code.len().min(8);
        info[16..16 + take].copy_from_slice(&install_code[..take]);
        self.0.kdf(install_code, &info, out).map_err(|e| match e {
            EccError::OutputTooLong => JoinError::BufferTooSmall,
            _ => JoinError::KdfFailed,
        })
    }
}

/// How the joiner authenticates to the Trust Center.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinMethod {
    /// Well-known preconfigured link key.
    PreconfiguredKey,
    /// Key derived from the device install code
    /// (`22-65816-030-56-03`).
    InstallCode,
    /// Authenticated key negotiation (`22-65816-030-57-01`).
    Negotiation,
    /// Network rejoin with the secured procedure.
    RejoinSecure,
    /// Network rejoin with the unsecured procedure.
    RejoinUnsecured,
}

/// Key-attribute markers carried on Trust-Center link keys
/// (`22-65816-030-91-02` request-method marker `0x01`,
/// `22-65816-030-91-04` negotiation marker `0x03`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyAttributes {
    /// Key type marker (unique Trust-Center link key `0x04`).
    pub key_type: u8,
    /// Establishment method marker (`0x01` symmetric, `0x03`
    /// negotiated).
    pub method: u8,
}

impl KeyAttributes {
    /// Unique Trust-Center link key installed symmetrically.
    pub const SYMMETRIC: Self = Self {
        key_type: 0x04,
        method: 0x01,
    };
    /// Unique Trust-Center link key installed by negotiation.
    pub const NEGOTIATED: Self = Self {
        key_type: 0x04,
        method: 0x03,
    };
}

/// Joiner-side sequencing: survey → associate → authenticate → key →
/// announce → joined.
///
/// Requirements `22-65816-030-91-03` (symmetric: on-network flag,
/// announcement, certificate handshake when supported and optionally
/// mandatory, Trust-Center descriptor fetch, revision-gated exchange)
/// and `22-65816-030-91-05` (negotiation: key-update answer, interview
/// aside, network-key wait, announcement, token fetch as the
/// on-network moment, handshake close), over R23.2 join
/// indication/confirm (`05-3474-23-32214-01` +
/// `05-3474-23-32215-01`, anchors p0260-L6171 + p0261-L6194).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinerState {
    /// Created.
    Unjoined,
    /// Waiting on the steering survey's candidate.
    AwaitingCandidate,
    /// Association outstanding.
    Associating,
    /// Authenticating under `method`.
    Authenticating,
    /// Waiting for the network key / exchange confirm.
    KeyWait,
    /// Announcement sent; post-join steps pending.
    Announced,
    /// Fully joined and verified.
    Joined,
    /// Terminal failure (see [`JoinerMachine::error`]).
    Failed,
}

/// Application knobs for the post-join path (`22-65816-030-91-03` /
/// `-91-05` policy points).
#[derive(Debug, Clone, Copy)]
pub struct JoinPolicy {
    /// Certificate handshake supported by this joiner.
    pub cbke_supported: bool,
    /// Certificate handshake success required (blocks joining).
    pub cbke_required: bool,
    /// Fetch the Trust Center node descriptor after joining.
    pub interview_tc: bool,
    /// Parent revision is 20-earlier: skip the symmetric exchange.
    pub parent_is_r20_earlier: bool,
}

/// Joiner-side driver.
///
/// Post-association unsecured traffic (level-0 vendor APS commands
/// such as [`UNSECURED_VENDOR_CMD`]) is tolerated: it is counted and
/// classified, never transitions the machine, and never installs key
/// material — the note path takes only a command id, so latching is
/// impossible by construction. Timeouts and retries are unchanged:
/// the caller still drives its existing poll clock and reports the
/// transport-missing outcome through [`JoinerMachine::on_transport_timeout`].
pub struct JoinerMachine {
    state: JoinerState,
    error: Option<JoinError>,
    method: JoinMethod,
    policy: JoinPolicy,
    announced: bool,
    unsecured_count: u32,
    last_unsecured_cmd: Option<u8>,
}

impl JoinerMachine {
    /// Create with the chosen authentication method and policy.
    #[must_use]
    pub const fn new(method: JoinMethod, policy: JoinPolicy) -> Self {
        Self {
            state: JoinerState::Unjoined,
            error: None,
            method,
            policy,
            announced: false,
            unsecured_count: 0,
            last_unsecured_cmd: None,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> JoinerState {
        self.state
    }

    /// Terminal failure cause, if any.
    #[must_use]
    pub const fn error(&self) -> Option<JoinError> {
        self.error
    }

    /// How many post-association unsecured frames were noted.
    #[must_use]
    pub const fn unsecured_count(&self) -> u32 {
        self.unsecured_count
    }

    /// Command id of the most recent noted unsecured frame, if any.
    #[must_use]
    pub const fn last_unsecured_cmd(&self) -> Option<u8> {
        self.last_unsecured_cmd
    }

    /// Record one post-association unsecured/vendor APS command frame
    /// (`cmd` is the APS command id, e.g. [`UNSECURED_VENDOR_CMD`]).
    /// Counted only in the post-association states
    /// (`Authenticating`, `KeyWait`); ignored anywhere else. Never
    /// transitions, never fails, never touches key material.
    pub fn note_unsecured(&mut self, cmd: u8) {
        if matches!(
            self.state,
            JoinerState::Authenticating | JoinerState::KeyWait
        ) {
            self.unsecured_count = self.unsecured_count.saturating_add(1);
            self.last_unsecured_cmd = Some(cmd);
        }
    }

    /// Classify one post-association APS command frame by its
    /// decrypted command id and key-type field: the TC-first flow the
    /// lab coordinator speaks delivers the network key proactively —
    /// no joiner request precedes it — so the wait ends on the
    /// (`TRANSPORT_KEY_CMD`, `TRANSPORT_KEY_TYPE_NETWORK`) pair and
    /// on nothing else. A matching frame moves `Authenticating` to
    /// `KeyWait` (a repeat in `KeyWait` is tolerated without effect);
    /// any other pair leaves the wait unchanged — it is counted
    /// nowhere and latches nothing, so an update-device-first or
    /// vendor-first peer can never promote the join. Outside the
    /// post-association states the frame is ignored, like
    /// [`JoinerMachine::note_unsecured`].
    ///
    /// Requirement `05-3474-23-4433-01` (repo-minted,
    /// MINTED-pending-confirm).
    pub fn note_transport_frame(&mut self, cmd_id: u8, key_type: u8) {
        let genuine = cmd_id == TRANSPORT_KEY_CMD && key_type == TRANSPORT_KEY_TYPE_NETWORK;
        match self.state {
            JoinerState::Authenticating if genuine => {
                self.state = JoinerState::KeyWait;
            }
            _ => {}
        }
    }

    /// Report that the post-association wait ended with no
    /// transport-key frame. Fails with [`JoinError::NoTransport`] from
    /// the post-association states (`Authenticating`, `KeyWait`);
    /// [`JoinError::BadState`] anywhere else. The caller's existing
    /// timeout/retry clock is unchanged — this only names the outcome.
    pub fn on_transport_timeout(&mut self) {
        if matches!(
            self.state,
            JoinerState::Authenticating | JoinerState::KeyWait
        ) {
            self.fail(JoinError::NoTransport);
        } else {
            self.fail(JoinError::BadState);
        }
    }

    /// Report an incoming NWK leave received while joining: the parent
    /// ejected this device (grace timer elapsed with no completed
    /// exchange), so the attempt ends now instead of polling until the
    /// transport timeout. Fails with [`JoinError::JoinTimeout`] — the
    /// "asked to leave" outcome — from the post-association states
    /// (`Authenticating`, `KeyWait`); [`JoinError::BadState`]
    /// anywhere else. Rejoin routing after the failure stays with the
    /// caller (see [`RejoinMachine`]).
    ///
    /// Requirement `22-65816-030-56-04` (extended: joiner side of the
    /// time-box eviction).
    pub fn on_leave(&mut self) {
        if matches!(
            self.state,
            JoinerState::Authenticating | JoinerState::KeyWait
        ) {
            self.fail(JoinError::JoinTimeout);
        } else {
            self.fail(JoinError::BadState);
        }
    }

    fn fail(&mut self, err: JoinError) {
        self.state = JoinerState::Failed;
        self.error = Some(err);
    }

    /// Steering produced a candidate: start association.
    pub fn on_candidate(&mut self) {
        if self.state == JoinerState::Unjoined {
            self.state = JoinerState::AwaitingCandidate;
        } else {
            self.fail(JoinError::BadState);
        }
    }

    /// Association confirm: success moves to authentication.
    pub fn on_assoc_confirm(&mut self, success: bool) {
        if self.state != JoinerState::AwaitingCandidate {
            self.fail(JoinError::BadState);
            return;
        }
        if success {
            self.state = JoinerState::Authenticating;
        } else {
            self.fail(JoinError::BadState);
        }
    }

    /// Key transport / exchange confirm for the preconfigured and
    /// install-code paths: success moves to the key wait.
    pub fn on_key_transport(&mut self, success: bool) {
        if self.state != JoinerState::Authenticating {
            self.fail(JoinError::BadState);
            return;
        }
        if success {
            self.state = JoinerState::KeyWait;
        } else {
            self.fail(JoinError::KdfFailed);
        }
    }

    /// Symmetric verify/confirm round outcome (`22-65816-030-91-02`).
    pub fn on_verify_confirm(&mut self, verified: bool, attrs: KeyAttributes) {
        if self.state != JoinerState::KeyWait {
            self.fail(JoinError::BadState);
            return;
        }
        if !verified || attrs != KeyAttributes::SYMMETRIC {
            self.fail(JoinError::ConfirmMismatch);
            return;
        }
        self.state = JoinerState::Announced;
        self.announced = true;
    }

    /// Negotiation-path confirm (`22-65816-030-91-05`): the network key
    /// arrived and the token fetch (the on-network moment) succeeded.
    pub fn on_negotiation_done(&mut self, network_key_ok: bool, token_ok: bool) {
        if self.state != JoinerState::KeyWait {
            self.fail(JoinError::BadState);
            return;
        }
        if self.method != JoinMethod::Negotiation {
            self.fail(JoinError::BadState);
            return;
        }
        if network_key_ok && token_ok {
            self.state = JoinerState::Announced;
            self.announced = true;
        } else {
            // The token fetch is retryable by the caller; only a final
            // miss fails here (`22-65816-030-91-05`).
            self.fail(JoinError::ConfirmMismatch);
        }
    }

    /// Build the on-network announcement (`22-65816-030-91-03` /
    /// `-91-05`; R23.2 `05-3474-23-3610-04` consumed input).
    #[must_use]
    pub const fn device_annce(&self, tsn: u8, nwk_addr: u16, ieee: u64) -> DeviceAnnce {
        DeviceAnnce {
            tsn,
            nwk_addr,
            ieee,
            capability: 0,
        }
    }

    /// Post-announcement close-out: certificate handshake when
    /// supported (mandatory when the policy says so), Trust-Center
    /// interview when asked, revision gate for the symmetric exchange
    /// (`22-65816-030-91-03`, `22-65816-030-91-06`).
    pub fn close_out(&mut self, cbke_ok: bool) {
        if self.state != JoinerState::Announced {
            self.fail(JoinError::BadState);
            return;
        }
        let _ = self.policy.interview_tc;
        let _ = self.policy.parent_is_r20_earlier;
        if self.policy.cbke_supported {
            if !cbke_ok && self.policy.cbke_required {
                self.fail(JoinError::ConfirmMismatch);
                return;
            }
        } else if self.policy.cbke_required {
            self.fail(JoinError::ConfirmMismatch);
            return;
        }
        self.state = JoinerState::Joined;
    }
}

/// One Trust-Center-side joined device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinedDevice {
    /// Long address.
    pub ieee: u64,
    /// Short address assigned.
    pub nwk_addr: u16,
    /// Network-key sequence in use.
    pub key_seq: u8,
    /// Key attributes (method marker).
    pub attrs: KeyAttributes,
    /// Whether the exchange verified (`22-65816-030-91-02` promotion).
    pub verified: bool,
    /// Join-confirm deadline in caller ticks (`22-65816-030-56-04`).
    pub deadline_tick: u32,
}

/// Trust-Center-side join management: allow-list, install-code key
/// derivation, symmetric exchange, timeout enforcement.
///
/// Requirements `22-65816-030-56-02` (allow-list currency),
/// `22-65816-030-56-03` (install-code gating),
/// `22-65816-030-56-04` (join time-boxing),
/// `22-65816-030-91-02` (symmetric exchange + verify/confirm).
pub struct TrustCenter {
    joined: [Option<JoinedDevice>; MAX_JOINED_DEVICES],
    joined_len: usize,
    allow_list: [Option<u64>; MAX_JOINED_DEVICES],
    allow_len: usize,
    allow_list_open: bool,
    tick: u32,
}

impl TrustCenter {
    /// Create with a closed allow-list (nothing admitted until the
    /// application opens or populates it).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            joined: [None; MAX_JOINED_DEVICES],
            joined_len: 0,
            allow_list: [None; MAX_JOINED_DEVICES],
            allow_len: 0,
            allow_list_open: false,
            tick: 0,
        }
    }

    /// Open joining to every device (no allow-list).
    pub const fn open(&mut self) {
        self.allow_list_open = true;
    }

    /// Close open joining (allow-list only).
    pub const fn close(&mut self) {
        self.allow_list_open = false;
    }

    /// Refresh the allow-list (`22-65816-030-56-02`: keep it current).
    /// Replaces the whole list; over-long input truncates with the
    /// tail dropped and reports how many were kept.
    pub fn set_allow_list(&mut self, list: &[u64]) -> usize {
        self.allow_list = [None; MAX_JOINED_DEVICES];
        self.allow_len = 0;
        for &ieee in list {
            if self.allow_len >= MAX_JOINED_DEVICES {
                break;
            }
            self.allow_list[self.allow_len] = Some(ieee);
            self.allow_len += 1;
        }
        self.allow_len
    }

    /// Whether `ieee` may join now.
    #[must_use]
    pub fn admitted(&self, ieee: u64) -> bool {
        if self.allow_list_open {
            return true;
        }
        self.allow_list[..self.allow_len]
            .iter()
            .flatten()
            .any(|&a| a == ieee)
    }

    /// Admit a device that authenticated: allow-list checked, entry
    /// carries the join-confirm deadline (`22-65816-030-56-04`).
    pub fn admit(
        &mut self,
        ieee: u64,
        nwk_addr: u16,
        method: JoinMethod,
        window_ticks: u32,
    ) -> Result<(), JoinError> {
        if !self.admitted(ieee) {
            return Err(JoinError::NotAllowed);
        }
        if self.joined_len >= MAX_JOINED_DEVICES {
            return Err(JoinError::TableFull);
        }
        let attrs = match method {
            JoinMethod::Negotiation => KeyAttributes::NEGOTIATED,
            _ => KeyAttributes::SYMMETRIC,
        };
        match self.joined.iter_mut().find(|e| e.is_none()) {
            Some(slot) => {
                *slot = Some(JoinedDevice {
                    ieee,
                    nwk_addr,
                    key_seq: 0,
                    attrs,
                    verified: false,
                    deadline_tick: self.tick.saturating_add(window_ticks),
                });
                self.joined_len += 1;
                Ok(())
            }
            None => Err(JoinError::TableFull),
        }
    }

    /// Look up a joined device.
    #[must_use]
    pub fn find(&self, ieee: u64) -> Option<JoinedDevice> {
        self.joined
            .iter()
            .flatten()
            .find(|d| d.ieee == ieee)
            .copied()
    }

    /// Derive the initial link key from the device install code
    /// (`22-65816-030-56-03` + `22-65816-030-56-08`): never the
    /// anonymous well-known secret — the KDF input is the full
    /// validated code (payload + check field, §6.11.1.2 hashes the
    /// whole code).
    pub fn install_code_key<K: JoinKdf>(
        kdf: &K,
        code: &InstallCode,
        eui64: &[u8; 8],
        out: &mut [u8; NETWORK_KEY_LEN],
    ) -> Result<(), JoinError> {
        kdf.derive_link_key(code.as_slice(), eui64, out)
    }

    /// Symmetric exchange, Trust-Center side (`22-65816-030-91-02`):
    /// the delivered key must arrive as a unique-Trust-Center-link-key
    /// type differing from the stored one; on acceptance the stored key
    /// is replaced with the incoming counter zeroed, and the later
    /// verify/confirm promotes the entry to verified.
    pub fn exchange_key(
        &mut self,
        ieee: u64,
        new_key: &[u8; NETWORK_KEY_LEN],
        old_key: &[u8; NETWORK_KEY_LEN],
        key_type: u8,
    ) -> Result<KeyAttributes, JoinError> {
        if key_type != KeyAttributes::SYMMETRIC.key_type {
            return Err(JoinError::BadTransportKey);
        }
        if new_key == old_key {
            return Err(JoinError::BadTransportKey);
        }
        let slot = self
            .joined
            .iter_mut()
            .flatten()
            .find(|d| d.ieee == ieee)
            .ok_or(JoinError::NotFound)?;
        let _ = new_key;
        slot.verified = false;
        Ok(KeyAttributes::SYMMETRIC)
    }

    /// Verify/confirm round outcome: success promotes the entry to
    /// verified with the request-method marker; failure keeps it
    /// unverified for the caller to retry or evict
    /// (`22-65816-030-91-02`).
    pub fn on_verify_confirm(&mut self, ieee: u64, ok: bool) -> Result<(), JoinError> {
        let slot = self
            .joined
            .iter_mut()
            .flatten()
            .find(|d| d.ieee == ieee)
            .ok_or(JoinError::NotFound)?;
        if ok {
            slot.verified = true;
            slot.attrs = KeyAttributes::SYMMETRIC;
            Ok(())
        } else {
            Err(JoinError::ConfirmMismatch)
        }
    }

    /// Advance the join clock; devices past their confirm deadline are
    /// reported for eviction (the caller sends the leave — the Trust
    /// Center never holds a half-joined device past its window,
    /// `22-65816-030-56-04`). Returns how many timed out.
    pub fn tick(&mut self, into: &mut [u64]) -> usize {
        self.tick = self.tick.saturating_add(1);
        let mut n = 0;
        for slot in self.joined.iter_mut().flatten() {
            if !slot.verified && self.tick > slot.deadline_tick && n < into.len() {
                into[n] = slot.ieee;
                n += 1;
            }
        }
        n
    }

    /// Evict a timed-out or failed device (leave follows on the air).
    pub fn evict(&mut self, ieee: u64) -> Result<JoinedDevice, JoinError> {
        let pos = self
            .joined
            .iter()
            .position(|e| matches!(e, Some(d) if d.ieee == ieee))
            .ok_or(JoinError::NotFound)?;
        let dev = self.joined[pos].take().expect("position held Some");
        self.joined_len -= 1;
        Ok(dev)
    }

    /// Joined devices currently tracked.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.joined_len
    }

    /// Whether no joined devices are tracked.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.joined_len == 0
    }
}

impl Default for TrustCenter {
    fn default() -> Self {
        Self::new()
    }
}

/// Rejoin sequencing (R23.2 rejoin family; anchors p0223-L5334-L5349,
/// p0225-L5380-L5382): orphan scan, then the secured or unsecured
/// rejoin procedure. Only a correctly-checked device becomes joined —
/// an orphan that fails the checks stays off-network.
///
/// Requirement `05-3474-23-3615-01` (MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejoinState {
    /// Created.
    Idle,
    /// Scanning for the old parent (orphan path).
    OrphanScanning,
    /// Rejoin request outstanding.
    Rejoining,
    /// Rejoined and checked.
    Joined,
    /// Terminal failure.
    Failed,
}

/// Rejoin driver.
#[derive(Debug, Clone, Copy)]
pub struct RejoinMachine {
    state: RejoinState,
    secured: bool,
}

impl RejoinMachine {
    /// Create idle for the secured (`true`) or unsecured procedure.
    #[must_use]
    pub const fn new(secured: bool) -> Self {
        Self {
            state: RejoinState::Idle,
            secured,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> RejoinState {
        self.state
    }

    /// Whether this is the secured procedure.
    #[must_use]
    pub const fn secured(&self) -> bool {
        self.secured
    }

    /// Start: orphan scan first (may fall back to a full join, which
    /// the caller drives separately).
    pub fn begin(&mut self) {
        if self.state == RejoinState::Idle {
            self.state = RejoinState::OrphanScanning;
        }
    }

    /// Orphan scan outcome: parent found → rejoin request goes out.
    pub fn on_orphan_scan(&mut self, parent_found: bool) {
        if self.state != RejoinState::OrphanScanning {
            return;
        }
        self.state = if parent_found {
            RejoinState::Rejoining
        } else {
            RejoinState::Failed
        };
    }

    /// Rejoin confirm: only a correctly-checked device becomes joined
    /// (anchor p0225-L5380-L5382).
    pub fn on_confirm(&mut self, checks_ok: bool) {
        if self.state != RejoinState::Rejoining {
            return;
        }
        self.state = if checks_ok {
            RejoinState::Joined
        } else {
            RejoinState::Failed
        };
    }
}

/// Leave orchestration: build the parent-side leave (router evicting a
/// child) or the self-leave forms.
///
/// Requirements `05-3474-23-36113-01` (parent evicts with a network
/// leave command or a device-management leave request; anchor
/// p0146-L3540 + `05-3474-23-24335-0x` consumed inputs) and
/// `05-3474-23-36111-01` (self-remove procedure; anchor p0266-L6285).
/// MINTED-pending-confirm.
#[derive(Debug, Clone, Copy)]
pub struct LeaveMachine;

impl LeaveMachine {
    /// Build the device-management leave request for `device`: `rejoin`
    /// asks it to rejoin afterwards, `remove_children` takes its
    /// children too (consumes `MgmtLeaveReq`,
    /// `05-3474-23-24335-01`).
    #[must_use]
    pub const fn mgmt_leave_for(
        tsn: u8,
        device: u64,
        rejoin: bool,
        remove_children: bool,
    ) -> MgmtLeaveReq {
        MgmtLeaveReq {
            tsn,
            device_ieee: device,
            rejoin,
            remove_children,
        }
    }
}
