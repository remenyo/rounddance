//! Direct session discipline: provisioning vs. authorization
//! sessions, pre-shared-key kinds, BLE replay counters, and the
//! admin-key lifecycle.
//!
//! Paraphrase-level model of doc `20-27688-041` §6.3.1 (session
//! access control, PSK baseline, anonymous guards), §6.3.2.1
//! (admin-key lifecycle), §6.4.6–6.4.7.1 (32-bit monotonic
//! counters), §6.5.1 (method negotiation + establishment
//! robustness), §7.7.2.7 (admin-key default on join).
//!
//! Requirement IDs: `20-27688-041-63-01` … `20-27688-041-63-05`,
//! `20-27688-041-646-01`, `20-27688-041-65-02`,
//! `20-27688-041-65-03`.

/// Session failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// Operation not allowed in the current state.
    BadState,
    /// A second provisioning session was requested alongside an
    /// authorization session (`20-27688-041-63-01`).
    SessionConflict,
    /// Provisioning sessions never grant network access
    /// (`20-27688-041-63-01`).
    ProvisioningCannotAuthorize,
    /// Anonymous provisioning needs a positive join countdown
    /// (`20-27688-041-63-03`).
    JoinWindowClosed,
    /// Admin key may only be set by the placing commissioner;
    /// later changes need a factory reset (`20-27688-041-63-04`).
    AdminKeyLocked,
    /// Peer silent past the establishment timeout
    /// (`20-27688-041-65-03`).
    PeerTimeout,
    /// Establishment validation failed: disconnect promptly
    /// (`20-27688-041-65-03`).
    EstablishmentFailed,
}

/// Pre-shared-key kinds for session establishment
/// (`20-27688-041-63-02`): every implementation supports the
/// well-known default and installation-code keys; the variable
/// passcode is reserved for the SPEKE exchange, with the
/// initiator choosing the key and naming it first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PskKind {
    /// Well-known default key.
    Default,
    /// Installation-code-derived key.
    InstallCode,
    /// Anonymous-secret key (countdown-gated).
    Anonymous,
    /// Variable passcode for the SPEKE exchange.
    Passcode,
}

/// Session kinds: provisioning sessions never grant network
/// access — that needs a separate basic/admin authorization
/// session (`20-27688-041-63-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// Provisioning session (commissioning access only).
    Provisioning,
    /// Basic-level authorization session.
    Basic,
    /// Admin-level authorization session.
    Admin,
}

/// Session-machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// No session.
    Idle,
    /// Establishment exchange in flight (peer-silence clocked).
    Establishing,
    /// Live provisioning session.
    Provisioned,
    /// Live basic authorization session.
    Basic,
    /// Live admin authorization session.
    Admin,
    /// Dropped after failure or timeout (caller must reconnect).
    Dropped,
}

/// Ticks of peer silence that fail establishment
/// (`20-27688-041-65-03`: fifteen seconds; one tick = one
/// second on the injected clock).
pub const ESTABLISH_TIMEOUT_TICKS: u32 = 15;

/// Where a missing admin key comes from. The Trust-Center-key
/// default (`20-27688-041-63-05`) is a repo-defined MMO
/// construction over the Trust-Center link key under a
/// Direct domain label — self-consistent only
/// (MINTED-pending-confirm), never claimed as interop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminKeySource {
    /// Set by the placing commissioner (`20-27688-041-63-04`).
    Supplied([u8; 16]),
    /// Derived from the Trust-Center link key at join
    /// (`20-27688-041-63-05`).
    FromTrustCenterKey,
}

/// Provisioning/authorization session machine on an injected
/// tick clock (one tick = one second).
#[derive(Debug, Clone, Copy)]
pub struct SessionMachine {
    state: SessionState,
    kind: Option<SessionKind>,
    psk: Option<PskKind>,
    silent_ticks: u32,
    admin_set: bool,
    admin_key: [u8; 16],
    provisioned: bool,
}

impl SessionMachine {
    /// New machine: idle, no admin key, unprovisioned.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: SessionState::Idle,
            kind: None,
            psk: None,
            silent_ticks: 0,
            admin_set: false,
            admin_key: [0u8; 16],
            provisioned: false,
        }
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Whether the device is provisioned (post-commissioning).
    #[must_use]
    pub fn provisioned(&self) -> bool {
        self.provisioned
    }

    /// Whether an admin key is installed.
    #[must_use]
    pub fn admin_set(&self) -> bool {
        self.admin_set
    }

    /// Begin establishment with the initiator-chosen key kind
    /// (`20-27688-041-63-02`: the initiator chooses and names
    /// the key in the first message). Anonymous keys additionally
    /// need `join_countdown > 0` (`20-27688-041-63-03`). The
    /// machine holds one session: any live or establishing
    /// session rejects a second begin, which is how "no second
    /// provisioning session alongside an authorization session"
    /// (`20-27688-041-63-01`) is enforced here.
    pub fn begin(
        &mut self,
        psk: PskKind,
        kind: SessionKind,
        join_countdown: u32,
    ) -> Result<(), SessionError> {
        match self.state {
            SessionState::Idle | SessionState::Dropped => {}
            SessionState::Establishing
            | SessionState::Provisioned
            | SessionState::Basic
            | SessionState::Admin => {
                if kind == SessionKind::Provisioning {
                    return Err(SessionError::SessionConflict);
                }
                return Err(SessionError::BadState);
            }
        }
        if psk == PskKind::Anonymous && join_countdown == 0 {
            return Err(SessionError::JoinWindowClosed);
        }
        self.state = SessionState::Establishing;
        self.kind = Some(kind);
        self.psk = Some(psk);
        self.silent_ticks = 0;
        Ok(())
    }

    /// Establishment exchange completed: any validation error
    /// drops the peer immediately (`20-27688-041-65-03`).
    pub fn on_established(&mut self, ok: bool) -> Result<SessionKind, SessionError> {
        if self.state != SessionState::Establishing {
            return Err(SessionError::BadState);
        }
        if !ok {
            self.drop_session();
            return Err(SessionError::EstablishmentFailed);
        }
        let kind = self.kind.unwrap_or(SessionKind::Provisioning);
        self.state = match kind {
            SessionKind::Provisioning => SessionState::Provisioned,
            SessionKind::Basic => SessionState::Basic,
            SessionKind::Admin => SessionState::Admin,
        };
        Ok(kind)
    }

    /// Peer traffic resets the silence clock; call on every
    /// valid establishment message.
    pub fn on_peer_activity(&mut self) {
        self.silent_ticks = 0;
    }

    /// Advance one second: fifteen silent ticks in
    /// `Establishing` disconnect the peer (`20-27688-041-65-03`).
    pub fn tick_1s(&mut self) -> Result<(), SessionError> {
        if self.state == SessionState::Establishing {
            self.silent_ticks = self.silent_ticks.saturating_add(1);
            if self.silent_ticks >= ESTABLISH_TIMEOUT_TICKS {
                self.drop_session();
                return Err(SessionError::PeerTimeout);
            }
        }
        Ok(())
    }

    /// Drop the session (failure or timeout path).
    pub fn drop_session(&mut self) {
        self.state = SessionState::Dropped;
        self.kind = None;
        self.psk = None;
        self.silent_ticks = 0;
    }

    /// Close a live session cleanly (back to idle).
    pub fn close(&mut self) {
        self.state = SessionState::Idle;
        self.kind = None;
        self.psk = None;
        self.silent_ticks = 0;
    }

    /// Mark the device provisioned (driven by the commissioning
    /// machine on network join).
    pub fn mark_provisioned(&mut self) {
        self.provisioned = true;
    }

    /// Mark the device factory-new (driven by leave/factory
    /// reset): clears provisioning and unlocks the admin key
    /// (`20-27688-041-63-04`).
    pub fn factory_reset(&mut self) {
        self.provisioned = false;
        self.admin_set = false;
        self.admin_key = [0u8; 16];
        self.close();
    }

    /// Install the admin key. Only the placing commissioner may
    /// set it, and only before one is installed; changing it
    /// later needs a factory reset (`20-27688-041-63-04`).
    pub fn set_admin_key(&mut self, key: AdminKeySource) -> Result<[u8; 16], SessionError> {
        if self.admin_set {
            return Err(SessionError::AdminKeyLocked);
        }
        let key = match key {
            AdminKeySource::Supplied(k) => k,
            AdminKeySource::FromTrustCenterKey => {
                return Err(SessionError::BadState);
            }
        };
        self.admin_key = key;
        self.admin_set = true;
        Ok(key)
    }

    /// Join-time admin-key default (`20-27688-041-63-05`):
    /// derive from the Trust-Center link key through the
    /// repo-defined MMO construction. The label keeps Direct
    /// derivation disjoint from the BDB install-code KDF.
    pub fn derive_admin_key(&mut self, tc_key: &[u8; 16]) -> Result<[u8; 16], SessionError> {
        if self.admin_set {
            return Err(SessionError::AdminKeyLocked);
        }
        let mut msg = [0u8; 25];
        msg[..9].copy_from_slice(b"zb-direct");
        msg[9..25].copy_from_slice(tc_key);
        let digest = rounddance_security::mmo::mmo_hash_128(&msg)
            .map_err(|_| SessionError::EstablishmentFailed)?;
        self.admin_key = digest;
        self.admin_set = true;
        Ok(digest)
    }

    /// Current admin key (for authorization-session checks).
    #[must_use]
    pub fn admin_key(&self) -> Option<[u8; 16]> {
        self.admin_set.then_some(self.admin_key)
    }
}

impl Default for SessionMachine {
    fn default() -> Self {
        Self::new()
    }
}

/// Counter failures (`20-27688-041-646-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterError {
    /// Stale or replayed incoming counter: dropped without
    /// advancing state.
    Stale,
    /// Counter at maximum: retire the connection.
    Retired,
}

/// Per-session 32-bit BLE replay counters, reset per session
/// (`20-27688-041-646-01`): the sender increments before
/// encrypting and echoes the value; receivers drop
/// freshness/authentication failures and stale counters without
/// advancing state; senders retire the connection at maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BleCounters {
    rx_next: u32,
    tx_next: u32,
    retired: bool,
}

impl BleCounters {
    /// Fresh per-session counters (both start at zero).
    #[must_use]
    pub fn new() -> Self {
        Self {
            rx_next: 0,
            tx_next: 0,
            retired: false,
        }
    }

    /// Next outgoing counter: increments before encrypting.
    /// At maximum the connection must retire.
    pub fn next_tx(&mut self) -> Result<u32, CounterError> {
        if self.retired || self.tx_next == u32::MAX {
            self.retired = true;
            return Err(CounterError::Retired);
        }
        let v = self.tx_next;
        self.tx_next = self.tx_next.saturating_add(1);
        Ok(v)
    }

    /// Accept an incoming counter: strictly greater than the
    /// last accepted value advances state; anything else is
    /// dropped without advancing.
    pub fn accept_rx(&mut self, counter: u32) -> Result<(), CounterError> {
        if self.retired {
            return Err(CounterError::Retired);
        }
        if counter < self.rx_next {
            return Err(CounterError::Stale);
        }
        self.rx_next = counter.saturating_add(1);
        Ok(())
    }

    /// Whether the connection retired (counter maximum).
    #[must_use]
    pub fn retired(&self) -> bool {
        self.retired
    }
}

impl Default for BleCounters {
    fn default() -> Self {
        Self::new()
    }
}
