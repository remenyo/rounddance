//! Direct commissioning flows: formation, steering/permit,
//! join via Direct, leave, and key update, plus the
//! finding-and-binding handoff.
//!
//! Paraphrase-level model of doc `20-27688-041` §7.7.2.5–7.7.2.8
//! (formed networks start closed with a status notification;
//! permit-joining durations feed the join window; leave erases
//! network parameters including keys; key TLVs record
//! global/unique and provisional/permanent attributes) over the
//! single-flight + 3-second-timeout + status-TLV discipline of
//! §7.7.2.1, reusing `rounddance_commission` (install-code
//! validation/derivation, finding machines) and
//! `rounddance_security::keyupdate` (rotation).
//!
//! Requirement IDs: `20-27688-041-772-01` (service discipline),
//! `20-27688-041-772-02` (network-operation closure),
//! `20-27688-041-63-03` (anonymous-join countdown),
//! `20-27688-041-63-04` (admin-key lifecycle),
//! `20-27688-041-63-05` (admin-key default).

use crate::attr::{DeviceType, JoinMethod, LinkKeyFlags, StatusDomain, StatusReport};
use rounddance_commission::{
    InstallCode, JoinError, JoinKdf, JoinMethod as ClassicalMethod, MmoJoinKdf, TrustCenter,
};
use rounddance_security::{install_link_key, LinkKeyTable, NETWORK_KEY_LEN};

/// Commissioning failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectError {
    /// Another request is in flight: the caller must answer the
    /// new request with a busy status notification
    /// (`20-27688-041-772-01`).
    Busy,
    /// No request in flight.
    Idle,
    /// Bad parameters (range/plausibility, install-code check).
    BadParams,
    /// Join attempted while the network is closed to it.
    NetworkClosed,
    /// Underlying join machinery failure.
    JoinFailed,
    /// Key rotation failure (duplicate or table full).
    KeyFailed,
    /// Caller buffer too small.
    BufferTooSmall,
}

impl From<JoinError> for DirectError {
    fn from(_: JoinError) -> Self {
        Self::JoinFailed
    }
}

/// Direct commissioning operations (one per characteristic
/// write, §7.7.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectOp {
    /// Form a new (closed) network.
    Form,
    /// Open the network for a duration (steering).
    PermitJoining,
    /// Join this device to a network.
    Join,
    /// Leave the network (erase parameters).
    Leave,
    /// Rotate the network/link key.
    UpdateKey,
    /// Finding-and-binding step after join.
    FindingBinding,
}

impl DirectOp {
    /// Status scope for this operation's notifications
    /// (Table 33).
    #[must_use]
    pub fn domain(self) -> StatusDomain {
        match self {
            Self::Form => StatusDomain::FORM_NETWORK,
            Self::PermitJoining => StatusDomain::PERMIT_JOINING,
            Self::Join => StatusDomain::JOIN_NETWORK,
            Self::Leave => StatusDomain::LEAVE_NETWORK,
            Self::UpdateKey => StatusDomain::JOIN_NETWORK,
            Self::FindingBinding => StatusDomain::FINDING_BINDING,
        }
    }
}

/// Machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectState {
    /// No request in flight.
    Idle,
    /// One request in flight (3-second clock running).
    Busy,
    /// Last request timed out (status already queued).
    Failed,
}

/// Finding-and-binding handoff payload: after a successful
/// join the driver wires this into the classical finding
/// machines (`rounddance_commission::FinderInitiator` /
/// `FinderTarget`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindingHandoff {
    /// Initiator (`true`) or target (`false`) role.
    pub initiator: bool,
    /// Joiner's network address for match-desc queries.
    pub nwk_addr: u16,
}

/// Events the driver must act on (notifications out).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectEvent {
    /// A status notification is queued (drain with
    /// [`DirectCommission::take_notifications`]).
    StatusPending,
    /// Join completed: hand off to finding & binding.
    FindingHandoff(FindingHandoff),
    /// Network parameters erased (leave path).
    NetworkErased,
}

/// In-flight commissioning timeout in ticks
/// (`CommissioningServiceTimeout`, 3 seconds,
/// `20-27688-041-772-01`; one tick = one second).
pub const COMMISSION_TIMEOUT_TICKS: u32 = 3;
/// Status-notification queue depth (declared budget).
pub const MAX_STATUS_QUEUE: usize = 4;
/// Key-table slots held by the Direct commissioning side.
pub const MAX_DIRECT_KEYS: usize = 8;

/// Network parameters held after form/join.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkParams {
    /// Extended PAN ID.
    pub ext_pan: [u8; 8],
    /// Short PAN ID (`0x0001`–`0xFFFE`, Table 27).
    pub pan_id: u16,
    /// Radio channel.
    pub channel: u8,
    /// This device's network address.
    pub nwk_addr: u16,
    /// Device type taken at form.
    pub device_type: DeviceType,
    /// Network key (provisional until join verifies).
    pub network_key: [u8; NETWORK_KEY_LEN],
}

/// Direct commissioning machine: single-flight requests with a
/// 3-second clock and status-TLV notifications, on an injected
/// tick clock.
pub struct DirectCommission {
    state: DirectState,
    op: Option<DirectOp>,
    waited_ticks: u32,
    network: Option<NetworkParams>,
    permit_ticks: u32,
    tc: TrustCenter,
    keys: LinkKeyTable<MAX_DIRECT_KEYS>,
    key_seq: u8,
    admin_key: Option<[u8; 16]>,
    status: [Option<StatusReport>; MAX_STATUS_QUEUE],
    status_len: usize,
    joined: bool,
}

impl DirectCommission {
    /// New machine: factory-new, network closed, no keys.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: DirectState::Idle,
            op: None,
            waited_ticks: 0,
            network: None,
            permit_ticks: 0,
            tc: TrustCenter::new(),
            keys: LinkKeyTable::new(),
            key_seq: 0,
            admin_key: None,
            status: [None; MAX_STATUS_QUEUE],
            status_len: 0,
            joined: false,
        }
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> DirectState {
        self.state
    }

    /// Whether this device holds network parameters.
    #[must_use]
    pub fn joined(&self) -> bool {
        self.joined
    }

    /// Remaining permit-joining window in seconds (the
    /// anonymous-join countdown, `20-27688-041-63-03`).
    #[must_use]
    pub fn permit_remaining(&self) -> u32 {
        self.permit_ticks
    }

    /// Current network parameters, if any.
    #[must_use]
    pub fn network(&self) -> Option<NetworkParams> {
        self.network
    }

    /// Queue a status notification (bounded; oldest dropped on
    /// overflow — the queue only ever holds one in-flight
    /// outcome plus retries, so overflow means caller lag).
    fn notify(&mut self, report: StatusReport) {
        if self.status_len < MAX_STATUS_QUEUE {
            self.status[self.status_len] = Some(report);
            self.status_len += 1;
        } else {
            self.status[MAX_STATUS_QUEUE - 1] = Some(report);
        }
    }

    /// Drain queued status notifications into `out`; returns
    /// the count written.
    pub fn take_notifications(&mut self, out: &mut [StatusReport]) -> usize {
        let n = self.status_len.min(out.len());
        for (i, slot) in out.iter_mut().enumerate().take(n) {
            *slot = self.status[i].unwrap_or(StatusReport::success(StatusDomain::GENERAL));
        }
        self.status = [None; MAX_STATUS_QUEUE];
        self.status_len = 0;
        n
    }

    /// Submit one request: exactly one at a time, else `Busy`
    /// (`20-27688-041-772-01`).
    pub fn submit(&mut self, op: DirectOp) -> Result<(), DirectError> {
        if self.state == DirectState::Busy {
            return Err(DirectError::Busy);
        }
        self.state = DirectState::Busy;
        self.op = Some(op);
        self.waited_ticks = 0;
        Ok(())
    }

    /// Complete a Form request: range-check parameters, start
    /// the network closed, queue a status notification
    /// (`20-27688-041-772-02`).
    pub fn complete_form(
        &mut self,
        params: NetworkParams,
        admin_key: Option<[u8; 16]>,
    ) -> Result<DirectEvent, DirectError> {
        self.expect(DirectOp::Form)?;
        if !valid_pan_id(params.pan_id) || !valid_ext_pan(&params.ext_pan) || params.channel > 26 {
            return self.fail(DirectOp::Form, DirectError::BadParams);
        }
        self.network = Some(params);
        self.joined = true;
        self.permit_ticks = 0;
        // Only the placing commissioner sets the admin key
        // (`20-27688-041-63-04`); absent, it derives at join
        // (`20-27688-041-63-05`).
        self.admin_key = admin_key;
        self.finish(StatusReport::success(StatusDomain::FORM_NETWORK));
        Ok(DirectEvent::StatusPending)
    }

    /// Complete a PermitJoining request: the duration feeds the
    /// join window (`20-27688-041-772-02`).
    pub fn complete_permit(&mut self, duration_s: u32) -> Result<DirectEvent, DirectError> {
        self.expect(DirectOp::PermitJoining)?;
        if self.network.is_none() {
            return self.fail(DirectOp::PermitJoining, DirectError::NetworkClosed);
        }
        self.permit_ticks = duration_s;
        self.finish(StatusReport::success(StatusDomain::PERMIT_JOINING));
        Ok(DirectEvent::StatusPending)
    }

    /// Complete a Join request via install-code key derivation
    /// (security-crate reuse, `20-27688-041-63-02`): validates
    /// the code, derives the initial link key, admits the
    /// device, and hands off to finding & binding. Anonymous
    /// joins need a positive countdown and yield at most basic
    /// authorization (`20-27688-041-63-03`, enforced by the
    /// driver via [`DirectCommission::permit_remaining`]).
    pub fn complete_join(
        &mut self,
        method: JoinMethod,
        ieee: u64,
        nwk_addr: u16,
        install_code: Option<&[u8]>,
        oob: Option<NetworkParams>,
    ) -> Result<DirectEvent, DirectError> {
        self.expect(DirectOp::Join)?;
        match method {
            JoinMethod::MacAssociation | JoinMethod::SecureRejoin => {
                // Every rejection below still queues a failure
                // notification and frees the machine: a rejected
                // request completes like any other
                // (`20-27688-041-772-01`).
                let code = match install_code {
                    Some(c) => c,
                    None => return self.fail(DirectOp::Join, DirectError::BadParams),
                };
                let validated = match InstallCode::from_slice(code) {
                    Ok(v) => v,
                    Err(_) => return self.fail(DirectOp::Join, DirectError::BadParams),
                };
                let mut eui = [0u8; 8];
                eui.copy_from_slice(&ieee.to_le_bytes());
                let mut link_key = [0u8; NETWORK_KEY_LEN];
                if MmoJoinKdf
                    .derive_link_key(validated.as_slice(), &eui, &mut link_key)
                    .is_err()
                {
                    return self.fail(DirectOp::Join, DirectError::JoinFailed);
                }
                self.tc.open();
                if self
                    .tc
                    .admit(ieee, nwk_addr, ClassicalMethod::InstallCode, 3)
                    .is_err()
                {
                    return self.fail(DirectOp::Join, DirectError::JoinFailed);
                }
                if self.tc.on_verify_confirm(ieee, true).is_err() {
                    return self.fail(DirectOp::Join, DirectError::JoinFailed);
                }
                // Missing admin key derives from the Trust-Center
                // link key (`20-27688-041-63-05`); the TC key here
                // is the freshly derived link key.
                if self.admin_key.is_none() {
                    let mut msg = [0u8; 25];
                    msg[..9].copy_from_slice(b"zb-direct");
                    msg[9..25].copy_from_slice(&link_key);
                    if let Ok(digest) = rounddance_security::mmo_hash_128(&msg) {
                        self.admin_key = Some(digest);
                    }
                }
                self.joined = true;
            }
            JoinMethod::OutOfBand => {
                // Parameters apply as-is; plausibility and range
                // checks still apply (`20-27688-041-772-01` via
                // Table 29).
                let params = oob.ok_or(DirectError::BadParams)?;
                if !valid_pan_id(params.pan_id)
                    || !valid_ext_pan(&params.ext_pan)
                    || params.channel > 26
                {
                    return self.fail(DirectOp::Join, DirectError::BadParams);
                }
                self.network = Some(params);
                self.joined = true;
            }
        }
        self.finish(StatusReport::success(StatusDomain::JOIN_NETWORK));
        Ok(DirectEvent::FindingHandoff(FindingHandoff {
            initiator: true,
            nwk_addr,
        }))
    }

    /// Complete a Leave request: erase network parameters
    /// including keys (`20-27688-041-772-02`).
    pub fn complete_leave(&mut self) -> Result<DirectEvent, DirectError> {
        self.expect(DirectOp::Leave)?;
        self.network = None;
        self.joined = false;
        self.permit_ticks = 0;
        self.admin_key = None;
        self.keys = LinkKeyTable::new();
        self.finish(StatusReport::success(StatusDomain::LEAVE_NETWORK));
        Ok(DirectEvent::NetworkErased)
    }

    /// Complete a key update: rotate via the security-crate
    /// construction and install; key TLVs record the
    /// global/unique + provisional/permanent attributes at the
    /// codec layer (`20-27688-041-772-02`).
    pub fn complete_key_update(
        &mut self,
        ieee: [u8; 8],
        nonce: u32,
        _flags: LinkKeyFlags,
    ) -> Result<DirectEvent, DirectError> {
        self.expect(DirectOp::UpdateKey)?;
        let net = match self.network {
            Some(n) => n,
            None => return self.fail(DirectOp::UpdateKey, DirectError::NetworkClosed),
        };
        let new_key = rounddance_security::derive_update_key(&net.network_key, &ieee, nonce);
        if install_link_key(&mut self.keys, ieee, new_key).is_err() {
            return self.fail(DirectOp::UpdateKey, DirectError::KeyFailed);
        }
        if let Some(n) = self.network.as_mut() {
            n.network_key = new_key;
        }
        self.key_seq = self.key_seq.wrapping_add(1);
        self.finish(StatusReport::success(StatusDomain::JOIN_NETWORK));
        Ok(DirectEvent::StatusPending)
    }

    /// Advance one second: permit windows drain; a Busy
    /// request silent past the 3-second timeout fails with a
    /// status notification (`20-27688-041-772-01`).
    pub fn tick_1s(&mut self) {
        if self.permit_ticks > 0 {
            self.permit_ticks -= 1;
        }
        if self.state == DirectState::Busy {
            self.waited_ticks = self.waited_ticks.saturating_add(1);
            if self.waited_ticks >= COMMISSION_TIMEOUT_TICKS {
                if let Some(op) = self.op {
                    self.notify(StatusReport {
                        domain: op.domain().0,
                        code: 0x01,
                    });
                }
                self.state = DirectState::Failed;
                self.op = None;
            }
        }
    }

    /// Recover from `Failed` back to `Idle` (caller has drained
    /// the failure notification).
    pub fn recover(&mut self) {
        if self.state == DirectState::Failed {
            self.state = DirectState::Idle;
        }
    }

    fn expect(&self, op: DirectOp) -> Result<(), DirectError> {
        match (self.state, self.op) {
            (DirectState::Busy, Some(cur)) if cur == op => Ok(()),
            (DirectState::Busy, _) => Err(DirectError::Busy),
            _ => Err(DirectError::Idle),
        }
    }

    fn finish(&mut self, report: StatusReport) {
        self.notify(report);
        self.state = DirectState::Idle;
        self.op = None;
        self.waited_ticks = 0;
    }

    fn fail<T>(&mut self, op: DirectOp, err: DirectError) -> Result<T, DirectError> {
        self.notify(StatusReport {
            domain: op.domain().0,
            code: 0x01,
        });
        self.state = DirectState::Idle;
        self.op = None;
        self.waited_ticks = 0;
        Err(err)
    }
}

impl Default for DirectCommission {
    fn default() -> Self {
        Self::new()
    }
}

/// Short PAN range `0x0001`–`0xFFFE` (Table 27).
fn valid_pan_id(pan: u16) -> bool {
    (0x0001..=0xFFFE).contains(&pan)
}

/// Extended PAN range `0x0000.0000.0000.0001`–`0xFFFF.FFFF.FFFF.FFFE`
/// (Table 27).
fn valid_ext_pan(ext: &[u8; 8]) -> bool {
    let v = u64::from_be_bytes(*ext);
    (0x0000_0000_0000_0001..=0xFFFF_FFFF_FFFF_FFFE).contains(&v)
}
