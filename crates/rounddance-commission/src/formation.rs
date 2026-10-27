//! Network formation: channel/PAN selection structures plus policy hooks.
//!
//! Paraphrase-level model of doc `22-65816-030` BDB v3.1 §8 (formation
//! roles and flow; anchors p0055-L1204-L1212, p0057-L1217-L1241,
//! p0057-L1242-L1256) and doc `05-3474-23` R23.2 §3.6.1.1 (network
//! formation primitive; anchor p0221-L5224). All wording here is
//! paraphrase; citations name document, revision, and clause/line only
//! (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are corpus-mined for BDB (`22-65816-030-81-*`)
//! and repo-minted for R23.2 (`05-3474-23-3611-*`, dots stripped),
//! MINTED-pending-confirm.
//!
//! The structures here decide *what* to form (channels, PAN, role).
//! Emitting MAC/NWK primitives stays with the HAL wave; this crate
//! hands it a fully-parameterized [`FormationRequest`].

/// Beacon order placed on every formation attempt (`22-65816-030-81-02`).
pub const FORMATION_BEACON_ORDER: u8 = 0x0f;
/// Superframe order placed on every formation attempt (same source).
pub const FORMATION_SUPERFRAME_ORDER: u8 = 0x00;
/// Lowest 2.4 GHz channel number this crate admits.
pub const CHANNEL_MIN: u8 = 11;
/// Highest 2.4 GHz channel number this crate admits.
pub const CHANNEL_MAX: u8 = 26;
/// How many channel numbers fit one scan list (11–26 inclusive).
pub const MAX_SCAN_CHANNELS: usize = 16;

/// Failures from formation configuration and sequencing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormationError {
    /// Channel number outside 11–26.
    BadChannel,
    /// Caller buffer too small for the channel list.
    BufferTooSmall,
    /// No channels selected for the current scan phase.
    NoChannels,
    /// Logical type may not form (end device, or already-on-network
    /// without a factory reset first).
    BadRole,
    /// Node is already on a network and was not factory-reset first.
    AlreadyOnNetwork,
    /// Operation not allowed in the current machine state.
    BadState,
    /// Every scan phase exhausted with no usable result.
    ScanExhausted,
    /// PAN selection found no free identifier.
    PanConflict,
}

/// Bitmask of 2.4 GHz channels 11–26 (bit `ch` set means selected).
///
/// Requirement `22-65816-030-81-01` (primary list first, then
/// secondary) + `22-65816-030-81-02` (current scan list per attempt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelMask(pub u32);

impl ChannelMask {
    /// Empty selection.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// All 2.4 GHz channels 11–26.
    #[must_use]
    pub const fn all_24g() -> Self {
        let mut mask = 0u32;
        let mut ch = CHANNEL_MIN;
        while ch <= CHANNEL_MAX {
            mask |= 1u32 << ch;
            ch += 1;
        }
        Self(mask)
    }

    /// Build from a channel list; rejects anything outside 11–26.
    pub fn from_list(channels: &[u8]) -> Result<Self, FormationError> {
        let mut mask = 0u32;
        for &ch in channels {
            if !(CHANNEL_MIN..=CHANNEL_MAX).contains(&ch) {
                return Err(FormationError::BadChannel);
            }
            mask |= 1u32 << ch;
        }
        Ok(Self(mask))
    }

    /// Whether `ch` is selected.
    #[must_use]
    pub const fn contains(self, ch: u8) -> bool {
        if ch < 32 {
            self.0 & (1u32 << ch) != 0
        } else {
            false
        }
    }

    /// Whether nothing is selected.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Intersection of two selections.
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// How many channels are selected.
    #[must_use]
    pub const fn count(self) -> usize {
        self.0.count_ones() as usize
    }

    /// Copy the selected channels, ascending, into `out`; returns how
    /// many were written. Truncates when `out` is short (callers size
    /// it with [`MAX_SCAN_CHANNELS`]).
    pub fn to_list(self, out: &mut [u8]) -> usize {
        let mut n = 0;
        let mut ch = CHANNEL_MIN;
        while ch <= CHANNEL_MAX && n < out.len() {
            if self.contains(ch) {
                out[n] = ch;
                n += 1;
            }
            ch += 1;
        }
        n
    }
}

/// Logical device type asking to form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicalType {
    /// Forms a centralized-security network, then starts Trust Center
    /// duties (`22-65816-030-81-01`, `22-65816-030-61-01`).
    Coordinator,
    /// Forms a distributed-security network as fallback; joins either
    /// model otherwise (same sources).
    Router,
    /// Never forms; joining only (`22-65816-030-61-01`).
    EndDevice,
}

/// PAN identifier selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanChoice {
    /// Pick a free identifier at formation time (conflict-checked).
    Auto,
    /// Use this identifier (still conflict-checked on the air).
    Fixed(u16),
}

/// What to form: role, channels, PAN, and identity seed.
#[derive(Debug, Clone, Copy)]
pub struct FormationConfig {
    /// Which logical type is forming (gates centralized vs
    /// distributed, `22-65816-030-81-01`).
    pub role: LogicalType,
    /// Channels scanned first (`22-65816-030-81-01`).
    pub primary: ChannelMask,
    /// Channels scanned after the primary set exhausts (same source).
    pub secondary: ChannelMask,
    /// Scan duration exponent per attempt (`22-65816-030-81-02`).
    pub scan_duration: u8,
    /// PAN selection (`22-65816-030-81-02` address-field rules feed
    /// off the role, not this choice).
    pub pan: PanChoice,
    /// Extended PAN identifier carried on the formed network.
    pub extended_pan: [u8; 8],
    /// Short address the router claims when forming distributed
    /// (`22-65816-030-81-02`).
    pub router_short_addr: u16,
}

impl FormationConfig {
    /// Validate: a former may be coordinator or router (never end
    /// device), and at least one scan phase must name channels.
    pub fn validate(&self) -> Result<(), FormationError> {
        if self.role == LogicalType::EndDevice {
            return Err(FormationError::BadRole);
        }
        if self.primary.is_empty() && self.secondary.is_empty() {
            return Err(FormationError::NoChannels);
        }
        Ok(())
    }
}

/// Fully-parameterized network-formation primitive invocation.
///
/// Requirement `22-65816-030-81-02`: each attempt carries the current
/// scan channel list, the configured scan duration, beacon order
/// `0x0f`, superframe order `0x00`, no battery-life extension, and a
/// centralized/distributed marker (coordinators centralized with no
/// address field; routers distributed with their chosen short
/// address). R23.2 §3.6.1.1 carries the primitive itself
/// (`05-3474-23-3611-01`, anchor p0221-L5224).
#[derive(Debug, Clone, Copy)]
pub struct FormationRequest {
    /// Channels for this attempt.
    pub scan_channels: ChannelMask,
    /// Scan duration exponent.
    pub scan_duration: u8,
    /// Always [`FORMATION_BEACON_ORDER`].
    pub beacon_order: u8,
    /// Always [`FORMATION_SUPERFRAME_ORDER`].
    pub superframe_order: u8,
    /// Always false on formation attempts.
    pub battery_life_extension: bool,
    /// True for router-formed (distributed) networks.
    pub distributed: bool,
    /// Short address attached for distributed formation; ignored for
    /// centralized formation (no address field).
    pub short_addr: u16,
    /// Extended PAN identifier for the new network.
    pub extended_pan: [u8; 8],
    /// PAN identifier for the new network (resolved before invoke).
    pub pan_id: u16,
}

/// Policy hooks the application (or a later auto-selection pass)
/// provides; the machine never invents addresses or channels itself.
pub trait FormationPolicy {
    /// Pick a PAN identifier avoiding every entry of `in_use`
    /// (broadcast/zero excluded by the implementor). `None` means the
    /// air is full → [`FormationError::PanConflict`].
    fn pick_pan(&self, in_use: &[u16]) -> Option<u16>;
    /// Decide whether the scan results admit forming now (e.g. energy
    /// threshold); false moves to the next phase.
    fn scan_usable(&self, channels: ChannelMask) -> bool;
}

/// Trivial policy for tests: first free PAN ascending from `0x0001`,
/// every scan usable.
#[derive(Debug, Clone, Copy)]
pub struct FirstFreePan;

impl FormationPolicy for FirstFreePan {
    fn pick_pan(&self, in_use: &[u16]) -> Option<u16> {
        let mut cand = 0x0001u16;
        while cand < 0xffff {
            if !in_use.contains(&cand) {
                return Some(cand);
            }
            cand += 1;
        }
        None
    }

    fn scan_usable(&self, channels: ChannelMask) -> bool {
        !channels.is_empty()
    }
}

/// Formation sequencing: role gating, primary-then-secondary scan,
/// PAN resolution, confirm.
///
/// Requirements `22-65816-030-81-01` (roles, factory-reset-first,
/// primary-then-secondary) and `22-65816-030-81-03` (success confirm
/// raises on-network; coordinator additionally starts Trust Center
/// duties; exhausted channels fail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormationState {
    /// Created; [`FormationMachine::begin`] not yet called.
    Idle,
    /// Scanning the primary channel set.
    ScanningPrimary,
    /// Primary exhausted; scanning the secondary set.
    ScanningSecondary,
    /// Scan found room; resolving the PAN identifier.
    ResolvingPan,
    /// Formation primitive invoked; awaiting confirm.
    AwaitingConfirm,
    /// Confirm succeeded; on-network (coordinator additionally owes
    /// Trust Center startup, signalled by
    /// [`FormationMachine::trust_center_startup_due`]).
    OnNetwork,
    /// Terminal failure (see [`FormationMachine::error`]).
    Failed,
}

/// Role-gated formation driver over a [`FormationConfig`].
#[derive(Debug)]
pub struct FormationMachine {
    config: FormationConfig,
    state: FormationState,
    error: Option<FormationError>,
    pan_id: Option<u16>,
    tc_startup_due: bool,
    resolved_secondary: bool,
}

impl FormationMachine {
    /// Create from a validated config.
    pub fn new(config: FormationConfig) -> Result<Self, FormationError> {
        config.validate()?;
        Ok(Self {
            config,
            state: FormationState::Idle,
            error: None,
            pan_id: None,
            tc_startup_due: false,
            resolved_secondary: false,
        })
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> FormationState {
        self.state
    }

    /// Terminal failure cause, if any.
    #[must_use]
    pub const fn error(&self) -> Option<FormationError> {
        self.error
    }

    /// Resolved PAN identifier (set once `ResolvingPan` succeeds).
    #[must_use]
    pub const fn pan_id(&self) -> Option<u16> {
        self.pan_id
    }

    /// Whether Trust Center startup is owed (coordinator that reached
    /// `OnNetwork`; `22-65816-030-81-03`).
    #[must_use]
    pub const fn trust_center_startup_due(&self) -> bool {
        self.tc_startup_due
    }

    fn fail(&mut self, err: FormationError) {
        self.state = FormationState::Failed;
        self.error = Some(err);
    }

    /// Begin: rejects an already-on-network node that was not
    /// factory-reset first and non-former roles
    /// (`22-65816-030-81-01`); otherwise enters `ScanningPrimary`.
    pub fn begin(&mut self, factory_new: bool, on_network: bool) {
        if self.state != FormationState::Idle {
            self.fail(FormationError::BadState);
            return;
        }
        if on_network && !factory_new {
            self.fail(FormationError::AlreadyOnNetwork);
            return;
        }
        if self.config.primary.is_empty() && !self.config.secondary.is_empty() {
            self.state = FormationState::ScanningSecondary;
        } else {
            self.state = FormationState::ScanningPrimary;
        }
    }

    /// Channels for the current scan phase (`None` outside scanning).
    #[must_use]
    pub const fn scan_phase_channels(&self) -> Option<ChannelMask> {
        match self.state {
            FormationState::ScanningPrimary => Some(self.config.primary),
            FormationState::ScanningSecondary => Some(self.config.secondary),
            _ => None,
        }
    }

    /// Report the current phase scan outcome: `usable == true` moves to
    /// PAN resolution; false advances primary → secondary → failure
    /// (`22-65816-030-81-01`, `22-65816-030-81-03`).
    pub fn on_scan_complete<P: FormationPolicy>(
        &mut self,
        policy: &P,
        usable: bool,
        pans_in_use: &[u16],
    ) {
        match self.state {
            FormationState::ScanningPrimary => {
                if usable && policy.scan_usable(self.config.primary) {
                    self.resolve_pan(policy, pans_in_use);
                } else if !self.config.secondary.is_empty() {
                    self.state = FormationState::ScanningSecondary;
                } else {
                    self.fail(FormationError::ScanExhausted);
                }
            }
            FormationState::ScanningSecondary => {
                if usable && policy.scan_usable(self.config.secondary) {
                    self.resolved_secondary = true;
                    self.resolve_pan(policy, pans_in_use);
                } else {
                    self.fail(FormationError::ScanExhausted);
                }
            }
            _ => self.fail(FormationError::BadState),
        }
    }

    fn resolve_pan<P: FormationPolicy>(&mut self, policy: &P, pans_in_use: &[u16]) {
        let choice = match self.config.pan {
            PanChoice::Fixed(id) => {
                if pans_in_use.contains(&id) {
                    None
                } else {
                    Some(id)
                }
            }
            PanChoice::Auto => policy.pick_pan(pans_in_use),
        };
        match choice {
            Some(id) => {
                self.pan_id = Some(id);
                self.state = FormationState::ResolvingPan;
            }
            None => self.fail(FormationError::PanConflict),
        }
    }

    /// Build the primitive invocation once the PAN is resolved
    /// (`22-65816-030-81-02`).
    #[must_use]
    pub fn primitive_params(&self) -> Option<FormationRequest> {
        if self.state != FormationState::ResolvingPan {
            return None;
        }
        let pan_id = self.pan_id?;
        let scan_channels = if self.resolved_secondary {
            self.config.secondary
        } else {
            self.config.primary
        };
        let (channels, distributed, short_addr) = match self.config.role {
            LogicalType::Coordinator => (scan_channels, false, 0),
            LogicalType::Router => (scan_channels, true, self.config.router_short_addr),
            LogicalType::EndDevice => return None,
        };
        Some(FormationRequest {
            scan_channels: channels,
            scan_duration: self.config.scan_duration,
            beacon_order: FORMATION_BEACON_ORDER,
            superframe_order: FORMATION_SUPERFRAME_ORDER,
            battery_life_extension: false,
            distributed,
            short_addr,
            extended_pan: self.config.extended_pan,
            pan_id,
        })
    }

    /// Mark the primitive invoked; waits for the confirm.
    pub fn on_invoked(&mut self) {
        if self.state == FormationState::ResolvingPan {
            self.state = FormationState::AwaitingConfirm;
        } else {
            self.fail(FormationError::BadState);
        }
    }

    /// Confirm outcome: success ends scanning, sets on-network, and
    /// queues Trust Center startup for coordinators
    /// (`22-65816-030-81-03`); failure fails the procedure.
    pub fn on_confirm(&mut self, success: bool) {
        if self.state != FormationState::AwaitingConfirm {
            self.fail(FormationError::BadState);
            return;
        }
        if success {
            self.state = FormationState::OnNetwork;
            self.tc_startup_due = self.config.role == LogicalType::Coordinator;
        } else {
            self.fail(FormationError::ScanExhausted);
        }
    }
}
