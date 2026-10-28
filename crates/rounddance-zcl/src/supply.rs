//! Metering supply control (cluster 0x0702): ChangeSupply family
//! codecs plus the bounded supply machine (delayed-command
//! serialisation, acknowledgement, event-state table, flow-meter
//! guard, and load-limit reset tracking).
//!
//! Paraphrase-level model of doc `07-5123-08` §10.4.3.3.1.11
//! (load-limit reset), §10.4.3.3.1.12 (ChangeSupply: immediate,
//! delayed, overriding, and cancelled commands), §10.4.3.3.1.13
//! (local change: the two remote states, no response),
//! §10.4.3.3.1.14 (event-state table), §10.4.3.3.1.15
//! (flow-threshold guard), and §10.4.2.3.1.13 (SupplyStatusResponse
//! after an acknowledged execution). Ordering follows corpus row
//! `17-05019-012-423-03` (reused verbatim): delayed commands
//! serialize by issuer, immediate commands never auto-cancel, and
//! stale-dated requests fail typed errors. All wording here is
//! paraphrase (D1).
//!
//! Requirement IDs below are repo-minted (`07-5123-08-1048-*`, dots
//! stripped), MINTED-pending-confirm, except the reused `423-03` row.
//!
//! Out of scope on purpose (rarer shapes stay bounded-opaque —
//! `metering::ServerBehavior` answers `UnsupCommand` for them, never
//! silent misbehavior): the notification-scheme machinery behind
//! `ConfigureMirror` / `ConfigureNotificationScheme` /
//! `ConfigureNotificationFlag` / `GetNotifiedMessage`.

use crate::{Error, ZclStatus};

/// Client generated (server receives): ResetLoadLimitCounter.
///
/// Requirement `07-5123-08-1048-05` (MINTED-pending-confirm).
pub const CMD_RESET_LOAD_LIMIT: u8 = 0x0A;
/// Client generated (server receives): ChangeSupply.
///
/// Requirement `07-5123-08-1048-01` (MINTED-pending-confirm).
pub const CMD_CHANGE_SUPPLY: u8 = 0x0B;
/// Client generated (server receives): LocalChangeSupply.
///
/// Requirement `07-5123-08-1048-02` (MINTED-pending-confirm).
pub const CMD_LOCAL_CHANGE_SUPPLY: u8 = 0x0C;
/// Client generated (server receives): SetSupplyStatus.
///
/// Requirement `07-5123-08-1048-03` (MINTED-pending-confirm).
pub const CMD_SET_SUPPLY_STATUS: u8 = 0x0D;
/// Client generated (server receives): SetUncontrolledFlowThreshold.
///
/// Requirement `07-5123-08-1048-04` (MINTED-pending-confirm).
pub const CMD_SET_UNCONTROLLED_FLOW: u8 = 0x0E;
/// Server generated: SupplyStatusResponse (after an acknowledged
/// execution).
///
/// Requirement `07-5123-08-1048-01` (MINTED-pending-confirm).
pub const CMD_SUPPLY_STATUS_RESPONSE: u8 = 0x0C;

/// Supply status: supply cut.
///
/// Requirement `07-5123-08-1048-01` (MINTED-pending-confirm).
pub const SUPPLY_OFF: u8 = 0x00;
/// Supply status: supply cut, reconnect armed.
pub const SUPPLY_ARMED: u8 = 0x01;
/// Supply status: supply flowing.
pub const SUPPLY_ON: u8 = 0x02;
/// Event-state entry: leave the supply as it is.
pub const SUPPLY_UNCHANGED: u8 = 0x03;

/// ChangeSupply control bit: the originator wants a SupplyStatus
/// response once the command executes.
///
/// Requirement `07-5123-08-1048-01` (MINTED-pending-confirm).
pub const CONTROL_ACK_REQUIRED: u8 = 0x01;
/// Implementation time executing the command at once (never cancels
/// a pending delayed command).
///
/// Requirement `17-05019-012-423-03` (corpus-reused).
pub const IMPL_IMMEDIATE: u32 = 0x0000_0000;
/// Implementation time cancelling the pending command filed under
/// the same provider + issuer.
///
/// Requirement `17-05019-012-423-03` (corpus-reused).
pub const IMPL_CANCEL: u32 = 0xFFFF_FFFF;

/// Whether a supply-status value names a real state.
#[must_use]
pub const fn supply_status_known(status: u8) -> bool {
    status <= SUPPLY_ON
}

/// ChangeSupply request: head-end/ESI-ordered supply change.
///
/// Requirement `07-5123-08-1048-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChangeSupply {
    /// Commodity provider the command relates to.
    pub provider: u32,
    /// Provider sequence (newer information replaces older).
    pub issuer: u32,
    /// When the change was requested.
    pub request_time: u32,
    /// When to apply (immediate / future / cancel encodings above).
    pub impl_time: u32,
    /// Status after implementation (`SUPPLY_*`).
    pub proposed: u8,
    /// Control bitmap (`CONTROL_ACK_REQUIRED` bit).
    pub control: u8,
}

/// Decode a ChangeSupply body: exactly 18 octets.
pub fn decode_change_supply(buf: &[u8]) -> Result<ChangeSupply, Error> {
    if buf.len() != 18 {
        return Err(Error::Truncated);
    }
    Ok(ChangeSupply {
        provider: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        issuer: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        request_time: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        impl_time: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
        proposed: buf[16],
        control: buf[17],
    })
}

/// Encode a ChangeSupply body into `out` (18 octets).
pub fn encode_change_supply(req: &ChangeSupply, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 18 {
        return Err(Error::BufferTooSmall);
    }
    out[..4].copy_from_slice(&req.provider.to_le_bytes());
    out[4..8].copy_from_slice(&req.issuer.to_le_bytes());
    out[8..12].copy_from_slice(&req.request_time.to_le_bytes());
    out[12..16].copy_from_slice(&req.impl_time.to_le_bytes());
    out[16] = req.proposed;
    out[17] = req.control;
    Ok(18)
}

/// SupplyStatusResponse body: the executed change, echoed.
///
/// Requirement `07-5123-08-1048-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupplyStatusResponse {
    /// Provider echoed from the executed command.
    pub provider: u32,
    /// Issuer echoed from the executed command.
    pub issuer: u32,
    /// Implementation time of the executed command.
    pub impl_time: u32,
    /// Status after implementation.
    pub status: u8,
}

/// Decode a SupplyStatusResponse body: exactly 13 octets.
pub fn decode_supply_status_response(buf: &[u8]) -> Result<SupplyStatusResponse, Error> {
    if buf.len() != 13 {
        return Err(Error::Truncated);
    }
    Ok(SupplyStatusResponse {
        provider: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        issuer: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        impl_time: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        status: buf[12],
    })
}

/// Encode a SupplyStatusResponse body into `out` (13 octets).
pub fn encode_supply_status_response(
    rsp: &SupplyStatusResponse,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < 13 {
        return Err(Error::BufferTooSmall);
    }
    out[..4].copy_from_slice(&rsp.provider.to_le_bytes());
    out[4..8].copy_from_slice(&rsp.issuer.to_le_bytes());
    out[8..12].copy_from_slice(&rsp.impl_time.to_le_bytes());
    out[12] = rsp.status;
    Ok(13)
}

/// Decode a LocalChangeSupply body: exactly 1 octet (the proposed
/// remote state, `SUPPLY_ARMED` or `SUPPLY_ON`).
///
/// Requirement `07-5123-08-1048-02` (MINTED-pending-confirm).
pub fn decode_local_change_supply(buf: &[u8]) -> Result<u8, Error> {
    if buf.len() != 1 {
        return Err(Error::Truncated);
    }
    Ok(buf[0])
}

/// Encode a LocalChangeSupply body into `out` (1 octet).
pub fn encode_local_change_supply(proposed: u8, out: &mut [u8]) -> Result<usize, Error> {
    let slot = out.first_mut().ok_or(Error::BufferTooSmall)?;
    *slot = proposed;
    Ok(1)
}

/// SetSupplyStatus request: required supply per meter event.
///
/// Requirement `07-5123-08-1048-03` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetSupplyStatus {
    /// Provider sequence (stale values are ignored, never applied).
    pub issuer: u32,
    /// Required status after a tamper event.
    pub tamper: u8,
    /// Required status after battery depletion.
    pub depletion: u8,
    /// Required status after uncontrolled flow.
    pub uncontrolled: u8,
    /// Required status in load-limit state.
    pub load_limit: u8,
}

/// Decode a SetSupplyStatus body: exactly 8 octets.
pub fn decode_set_supply_status(buf: &[u8]) -> Result<SetSupplyStatus, Error> {
    if buf.len() != 8 {
        return Err(Error::Truncated);
    }
    Ok(SetSupplyStatus {
        issuer: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        tamper: buf[4],
        depletion: buf[5],
        uncontrolled: buf[6],
        load_limit: buf[7],
    })
}

/// Encode a SetSupplyStatus body into `out` (8 octets).
pub fn encode_set_supply_status(req: &SetSupplyStatus, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 8 {
        return Err(Error::BufferTooSmall);
    }
    out[..4].copy_from_slice(&req.issuer.to_le_bytes());
    out[4] = req.tamper;
    out[5] = req.depletion;
    out[6] = req.uncontrolled;
    out[7] = req.load_limit;
    Ok(8)
}

/// Whether an event-state entry names a real directive (a concrete
/// state or leave-unchanged).
#[must_use]
pub const fn event_state_known(state: u8) -> bool {
    state <= SUPPLY_UNCHANGED
}

/// Meter event selecting an event-state entry.
///
/// Requirement `07-5123-08-1048-03` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupplyEvent {
    /// Tamper detected.
    Tamper,
    /// Battery depleted.
    Depletion,
    /// Uncontrolled flow detected.
    UncontrolledFlow,
    /// Load-limit state entered.
    LoadLimit,
}

/// Flow-meter guard configuration.
///
/// Requirement `07-5123-08-1048-04` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowThreshold {
    /// Commodity provider the guard relates to.
    pub provider: u32,
    /// Provider sequence (stale values are ignored, never applied).
    pub issuer: u32,
    /// Guard trip point (0 disables the guard).
    pub threshold: u16,
    /// Unit of measure for the trip point.
    pub unit: u8,
    /// Scale multiplier (never 0 on the wire).
    pub multiplier: u16,
    /// Scale divisor (never 0 on the wire).
    pub divisor: u16,
    /// Flow-settle allowance in tenths of a second.
    pub stabilization: u8,
    /// Measurement window in seconds.
    pub measurement: u16,
}

/// Decode a SetUncontrolledFlowThreshold body: exactly 18 octets.
/// Zero multipliers/divisors are field errors, never stored.
pub fn decode_flow_threshold(buf: &[u8]) -> Result<FlowThreshold, Error> {
    if buf.len() != 18 {
        return Err(Error::Truncated);
    }
    let multiplier = u16::from_le_bytes([buf[11], buf[12]]);
    let divisor = u16::from_le_bytes([buf[13], buf[14]]);
    if multiplier == 0 || divisor == 0 {
        return Err(Error::InvalidValue(0));
    }
    Ok(FlowThreshold {
        provider: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        issuer: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        threshold: u16::from_le_bytes([buf[8], buf[9]]),
        unit: buf[10],
        multiplier,
        divisor,
        stabilization: buf[15],
        measurement: u16::from_le_bytes([buf[16], buf[17]]),
    })
}

/// Encode a SetUncontrolledFlowThreshold body into `out` (18
/// octets). Zero multipliers/divisors are field errors, never
/// emitted.
pub fn encode_flow_threshold(cfg: &FlowThreshold, out: &mut [u8]) -> Result<usize, Error> {
    if cfg.multiplier == 0 || cfg.divisor == 0 {
        return Err(Error::InvalidValue(0));
    }
    if out.len() < 18 {
        return Err(Error::BufferTooSmall);
    }
    out[..4].copy_from_slice(&cfg.provider.to_le_bytes());
    out[4..8].copy_from_slice(&cfg.issuer.to_le_bytes());
    out[8..10].copy_from_slice(&cfg.threshold.to_le_bytes());
    out[10] = cfg.unit;
    out[11..13].copy_from_slice(&cfg.multiplier.to_le_bytes());
    out[13..15].copy_from_slice(&cfg.divisor.to_le_bytes());
    out[15] = cfg.stabilization;
    out[16..18].copy_from_slice(&cfg.measurement.to_le_bytes());
    Ok(18)
}

/// Decode a ResetLoadLimitCounter body: provider + issuer, exactly 8
/// octets.
///
/// Requirement `07-5123-08-1048-05` (MINTED-pending-confirm).
pub fn decode_reset_load_limit(buf: &[u8]) -> Result<(u32, u32), Error> {
    if buf.len() != 8 {
        return Err(Error::Truncated);
    }
    Ok((
        u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
    ))
}

/// Encode a ResetLoadLimitCounter body into `out` (8 octets).
pub fn encode_reset_load_limit(provider: u32, issuer: u32, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 8 {
        return Err(Error::BufferTooSmall);
    }
    out[..4].copy_from_slice(&provider.to_le_bytes());
    out[4..8].copy_from_slice(&issuer.to_le_bytes());
    Ok(8)
}

/// One delayed supply command waiting for its implementation time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingSupply {
    provider: u32,
    issuer: u32,
    impl_time: u32,
    proposed: u8,
    ack: bool,
}

/// Outcome of a supply command the behavior maps onto its reply and
/// event paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupplyOutcome {
    /// Status applied now; a response is owed when `ack` is set.
    Applied {
        /// Emit the SupplyStatusResponse with these fields.
        ack: bool,
    },
    /// Delayed command filed; the tick applies it at `impl_time`.
    Delayed,
    /// Pending command cancelled; status untouched, proposed
    /// implementation time reset.
    Cancelled,
}

/// Bounded supply machine: current status, one pending delayed
/// command, the event-state table, the flow guard, and load-limit
/// reset tracking.
///
/// Requirement `17-05019-012-423-03` (corpus-reused) + repo-minted
/// `07-5123-08-1048-*`: a newer delayed command overrides the older
/// one; an immediate command applies without cancelling the pending
/// one; cancellation names the exact provider + issuer; past-dated
/// non-zero times, unauthorized origins, and incapable devices fail
/// with typed errors instead of acting.
#[derive(Clone, Copy, Debug)]
pub struct SupplyMachine {
    status: u8,
    pending: Option<PendingSupply>,
    tamper: u8,
    depletion: u8,
    uncontrolled: u8,
    load_limit: u8,
    flow: Option<FlowThreshold>,
    load_limit_count: u32,
    last_reset_issuer: u32,
    last_set_issuer: u32,
    seen_set_issuer: bool,
    capable: bool,
    authorized: bool,
}

impl Default for SupplyMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl SupplyMachine {
    /// Flowing supply, no pending command, leave-unchanged event
    /// states, capable and authorized (test/sim default; products
    /// narrow the policy flags before serving).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            status: SUPPLY_ON,
            pending: None,
            tamper: SUPPLY_UNCHANGED,
            depletion: SUPPLY_UNCHANGED,
            uncontrolled: SUPPLY_UNCHANGED,
            load_limit: SUPPLY_UNCHANGED,
            flow: None,
            load_limit_count: 0,
            last_reset_issuer: 0,
            last_set_issuer: 0,
            seen_set_issuer: false,
            capable: true,
            authorized: true,
        }
    }

    /// Current supply status.
    #[must_use]
    pub const fn status(&self) -> u8 {
        self.status
    }

    /// Pending delayed command, if any.
    #[must_use]
    pub const fn pending(&self) -> Option<(u32, u32, u32, u8)> {
        match self.pending {
            Some(p) => Some((p.provider, p.issuer, p.impl_time, p.proposed)),
            None => None,
        }
    }

    /// Flow-meter guard, if configured.
    #[must_use]
    pub const fn flow(&self) -> Option<FlowThreshold> {
        self.flow
    }

    /// Load-limit counter (resets through `reset_load_limit`).
    #[must_use]
    pub const fn load_limit_count(&self) -> u32 {
        self.load_limit_count
    }

    /// Whether the device can act on supply commands at all.
    pub const fn set_capable(&mut self, capable: bool) {
        self.capable = capable;
    }

    /// Whether the originator class may order supply changes.
    pub const fn set_authorized(&mut self, authorized: bool) {
        self.authorized = authorized;
    }

    /// Test/sim helper: advance the load-limit counter.
    pub const fn note_load(&mut self, count: u32) {
        self.load_limit_count = count;
    }

    /// Apply one ChangeSupply command at caller time `now`.
    pub fn apply_change(
        &mut self,
        req: &ChangeSupply,
        now: u32,
    ) -> Result<SupplyOutcome, ZclStatus> {
        if !self.authorized {
            return Err(ZclStatus::NotAuthorized);
        }
        if !self.capable {
            return Err(ZclStatus::UnsupCommand);
        }
        if !supply_status_known(req.proposed) {
            return Err(ZclStatus::InvalidField);
        }
        if req.impl_time == IMPL_CANCEL {
            match self.pending {
                Some(p) if p.provider == req.provider && p.issuer == req.issuer => {
                    self.pending = None;
                    Ok(SupplyOutcome::Cancelled)
                }
                _ => Err(ZclStatus::InvalidValue),
            }
        } else if req.impl_time == IMPL_IMMEDIATE {
            self.status = req.proposed;
            Ok(SupplyOutcome::Applied {
                ack: req.control & CONTROL_ACK_REQUIRED != 0,
            })
        } else if req.impl_time <= now {
            Err(ZclStatus::InvalidValue)
        } else {
            // Delayed: overrides any older delayed command.
            self.pending = Some(PendingSupply {
                provider: req.provider,
                issuer: req.issuer,
                impl_time: req.impl_time,
                proposed: req.proposed,
                ack: req.control & CONTROL_ACK_REQUIRED != 0,
            });
            Ok(SupplyOutcome::Delayed)
        }
    }

    /// Fire a due delayed command; returns the executed fields plus
    /// whether the originator asked for acknowledgement.
    pub fn tick(&mut self, now: u32) -> Option<(SupplyStatusResponse, bool)> {
        match self.pending {
            Some(p) if now >= p.impl_time => {
                self.pending = None;
                self.status = p.proposed;
                let rsp = SupplyStatusResponse {
                    provider: p.provider,
                    issuer: p.issuer,
                    impl_time: p.impl_time,
                    status: p.proposed,
                };
                Some((rsp, p.ack))
            }
            _ => None,
        }
    }

    /// Apply one LocalChangeSupply (remote states only, no response
    /// ever; incapable devices refuse).
    pub fn apply_local(&mut self, proposed: u8) -> Result<(), ZclStatus> {
        if !self.capable {
            return Err(ZclStatus::UnsupCommand);
        }
        if proposed != SUPPLY_ARMED && proposed != SUPPLY_ON {
            return Err(ZclStatus::InvalidField);
        }
        self.status = proposed;
        Ok(())
    }

    /// File one SetSupplyStatus table (newer issuers win; stale
    /// tables are ignored).
    pub fn apply_set_status(&mut self, req: &SetSupplyStatus) -> Result<bool, ZclStatus> {
        if !event_state_known(req.tamper)
            || !event_state_known(req.depletion)
            || !event_state_known(req.uncontrolled)
            || !event_state_known(req.load_limit)
        {
            return Err(ZclStatus::InvalidField);
        }
        if self.seen_set_issuer && req.issuer <= self.last_set_issuer {
            return Ok(false);
        }
        self.tamper = req.tamper;
        self.depletion = req.depletion;
        self.uncontrolled = req.uncontrolled;
        self.load_limit = req.load_limit;
        self.last_set_issuer = req.issuer;
        self.seen_set_issuer = true;
        Ok(true)
    }

    /// Apply the event-state entry for one meter event; returns the
    /// new status, or `None` for leave-unchanged.
    pub fn apply_event(&mut self, event: SupplyEvent) -> Option<u8> {
        let directive = match event {
            SupplyEvent::Tamper => self.tamper,
            SupplyEvent::Depletion => self.depletion,
            SupplyEvent::UncontrolledFlow => self.uncontrolled,
            SupplyEvent::LoadLimit => self.load_limit,
        };
        if directive == SUPPLY_UNCHANGED {
            None
        } else {
            self.status = directive;
            Some(directive)
        }
    }

    /// File one flow-threshold guard (newer issuers win; a zero
    /// threshold disables the guard).
    pub fn apply_flow(&mut self, cfg: &FlowThreshold) -> bool {
        if let Some(cur) = self.flow {
            if cfg.issuer <= cur.issuer {
                return false;
            }
        }
        self.flow = Some(*cfg);
        true
    }

    /// True flow-trip value in unit-of-measure counts (threshold ×
    /// multiplier ÷ divisor; the codec already refuses zero scales).
    #[must_use]
    pub fn flow_trip_value(&self) -> Option<u64> {
        self.flow.map(|f| {
            if f.threshold == 0 {
                return 0;
            }
            u64::from(f.threshold)
                .saturating_mul(u64::from(f.multiplier))
                .saturating_div(u64::from(f.divisor))
        })
    }

    /// Reset the load-limit counter (newer issuers win; stale resets
    /// are ignored).
    pub fn reset_load_limit(&mut self, provider: u32, issuer: u32) -> bool {
        let _ = provider;
        if issuer <= self.last_reset_issuer {
            return false;
        }
        self.last_reset_issuer = issuer;
        self.load_limit_count = 0;
        true
    }
}
