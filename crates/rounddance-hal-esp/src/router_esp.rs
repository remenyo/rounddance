//! C6 router device: join + forward + host app endpoints over `EspAdapter`.
//!
//! `rounddance-roles` already carries sim-proven `RouterMachine`
//! (join/forward/serve-poll/rejoin), `EndDeviceMachine`
//! (poll/loss/rejoin/leave), `EndpointTable`, and `RouterApp`
//! (route/app fairness). This module is the missing ESP binding the
//! prior audit flagged: it composes those machines for firmware so a
//! C6 can route while hosting full application endpoints (SCOPE §5
//! thermostat-that-routes, one identity), instead of the
//! coordinator/end-device-only `app.rs` pair.
//!
//! `no_std`-clean, bounded, fallible; time is an injected `u64` tick.
//! Paraphrase-level model; no spec text (D1).

use rounddance_roles::{
    endpoint::{EndpointError, EndpointHandle, EndpointTable},
    AgingPolicy, AppEndpoint, RouterApp, RouterError, RouterMachine, RouterState, MAX_APP_PAYLOAD,
};

/// C6 router device: lifecycle + child service + forwarding + local
/// endpoint hosting under the fairness rule.
pub struct RouterDevice {
    machine: RouterMachine,
    endpoints: EndpointTable,
    fairness: RouterApp,
}

impl RouterDevice {
    /// New unjoined router. `hold_ms` bounds indirect hold for sleepy
    /// children; `policy` bounds child-table aging.
    #[must_use]
    pub fn new(policy: AgingPolicy, hold_ms: u64) -> Self {
        Self {
            machine: RouterMachine::new(policy, hold_ms),
            endpoints: EndpointTable::new(),
            fairness: RouterApp::new(),
        }
    }

    /// Current router lifecycle state.
    #[must_use]
    pub fn state(&self) -> RouterState {
        self.machine.state()
    }

    /// Begin joining (caller runs the commission join exchange, same
    /// shape as `JoinerApp` scan→assoc→key→annce).
    pub fn begin_join(&mut self) -> Result<(), RouterError> {
        self.machine.begin_join()
    }

    /// Join outcome: success activates routing duties.
    pub fn join_done(&mut self, success: bool) -> RouterState {
        self.machine.join_done(success)
    }

    /// Parent lost → rejoin.
    pub fn parent_lost(&mut self) -> Result<(), RouterError> {
        self.machine.parent_lost()
    }

    /// Rejoin outcome.
    pub fn rejoin_done(&mut self, success: bool) -> RouterState {
        self.machine.rejoin_done(success)
    }

    /// Register one hosted endpoint (On/Off server, etc.).
    pub fn register_endpoint<E: AppEndpoint>(
        &mut self,
        endpoint: &E,
    ) -> Result<EndpointHandle, EndpointError> {
        self.endpoints.register(endpoint)
    }

    /// Admit a child (router serves children like a coordinator).
    pub fn admit_child(
        &mut self,
        short_addr: u16,
        ieee_addr: u64,
        sleepy: bool,
        now_ms: u64,
    ) -> Result<(), RouterError> {
        self.machine
            .admit_child(short_addr, ieee_addr, sleepy, now_ms)
    }

    /// Forward one frame: counts the machine forward and queues the
    /// bytes through the fairness queue. Caller moves the bytes.
    pub fn forward(&mut self, dest: u16, payload: &[u8]) -> Result<(), RouterError> {
        self.machine.forward()?;
        self.fairness
            .queue_route(dest, payload)
            .map_err(|e| match e {
                EndpointError::TableFull => {
                    RouterError::Indirect(rounddance_roles::IndirectError::QueueFull)
                }
                EndpointError::PayloadTooLarge => {
                    RouterError::Indirect(rounddance_roles::IndirectError::PayloadTooLarge)
                }
                _ => RouterError::BadState,
            })
    }

    /// Queue an incoming command for a local endpoint.
    pub fn deliver_to_endpoint(
        &mut self,
        endpoint_id: u8,
        payload: &[u8],
    ) -> Result<EndpointHandle, EndpointError> {
        self.endpoints.deliver(endpoint_id, payload)
    }

    /// Next hop toward `dst`, if a live route is installed.
    #[must_use]
    pub fn next_hop(&self, dst: u16, now_ms: u64) -> Option<u16> {
        self.machine.next_hop(dst, now_ms)
    }

    /// Open route discovery for `dst`.
    pub fn start_discovery(
        &mut self,
        dst: u16,
        local: u16,
        now_ms: u64,
    ) -> Result<u8, RouterError> {
        self.machine.start_discovery(dst, local, now_ms)
    }

    /// Fold an inbound route reply.
    pub fn note_discovery_reply(
        &mut self,
        rreq_id: u8,
        dst: u16,
        next_hop: u16,
        cost: u8,
        now_ms: u64,
    ) -> Result<bool, RouterError> {
        self.machine
            .note_discovery_reply(rreq_id, dst, next_hop, cost, now_ms)
    }

    /// Install a relay-learned route leg.
    pub fn install_route(
        &mut self,
        dst: u16,
        next_hop: u16,
        cost: u8,
        now_ms: u64,
    ) -> Result<(), RouterError> {
        self.machine.install_route(dst, next_hop, cost, now_ms)
    }

    /// Hold a frame for a sleepy child until it polls.
    pub fn hold_for_child(
        &mut self,
        child_short: u16,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<(), RouterError> {
        self.machine.hold_for_child(child_short, payload, now_ms)
    }

    /// Authorize a discovery retransmit for `dst`.
    pub fn authorize_discovery_retry(
        &mut self,
        dst: u16,
        now_ms: u64,
    ) -> Result<bool, RouterError> {
        self.machine.authorize_discovery_retry(dst, now_ms)
    }

    /// Age routing state: expires routes, retires dead sessions.
    pub fn tick_routing(&mut self, now_ms: u64) -> (usize, usize, usize) {
        self.machine.tick_routing(now_ms)
    }

    /// Loop-suppression for flooded requests (relay side).
    pub fn should_suppress_request(&mut self, originator: u16, rreq_id: u8, now_ms: u64) -> bool {
        self.machine
            .should_suppress_request(originator, rreq_id, now_ms)
    }

    /// Resolve the next hop for one inbound NWK MSDU (MAC already
    /// stripped) under the relay contract, counting the forward when
    /// a leg covers the destination.
    ///
    /// The MSDU (NWK header + payload) is preserved verbatim in
    /// transit: only the MAC header changes per hop, so the secured
    /// nonce/AAD and the transport auxiliary open accept the relayed
    /// copy. Direct children resolve to themselves when no route
    /// covers them yet; otherwise the installed route wins. Returns
    /// `None` when no leg covers the destination — the caller should
    /// originate discovery instead of dropping silently.
    ///
    /// Requirement `05-3474-23-3661-02` (repo-minted,
    /// MINTED-pending-confirm).
    pub fn relay_for(&mut self, msdu: &[u8], now_ms: u64) -> Option<u16> {
        let dst = nwk_dst_of(msdu)?;
        if let Some(nh) = self.machine.next_hop(dst, now_ms) {
            if self.machine.forward().is_ok() {
                return Some(nh);
            }
            return None;
        }
        // Direct-child shortcut: a known child is one hop away even
        // before any discovery installed a route leg.
        if self.machine.children().get(dst).is_some() && self.machine.forward().is_ok() {
            return Some(dst);
        }
        None
    }

    /// Serve a child poll.
    pub fn serve_poll(
        &mut self,
        child_short: u16,
        now_ms: u64,
    ) -> Result<Option<rounddance_roles::PendingFrame>, RouterError> {
        self.machine.serve_poll(child_short, now_ms)
    }

    /// Service one tick: route queue first, then local endpoints.
    /// Returns `(forwarded, app_served)`.
    pub fn tick<E: AppEndpoint>(
        &mut self,
        endpoints: &mut [&mut E],
        lookup: impl Fn(&E) -> u8,
        forwarded_out: &mut [(u16, [u8; MAX_APP_PAYLOAD], usize)],
        now_ms: u64,
    ) -> (usize, usize) {
        let (f, a) = self
            .fairness
            .tick(&mut self.endpoints, endpoints, lookup, forwarded_out);
        let _ = self.machine.tick(now_ms);
        let _ = self.machine.tick_routing(now_ms);
        (f, a)
    }

    /// Lifetime forwarded count (machine side).
    #[must_use]
    pub fn forwarded(&self) -> u32 {
        self.machine.forwarded
    }

    /// Queued route frames awaiting forward.
    #[must_use]
    pub fn route_pending(&self) -> usize {
        self.fairness.route_pending()
    }
}

/// Extract the NWK destination short from one NWK MSDU (MAC already
/// stripped) via the repo NWK codec. `None` on undecodable input —
/// the caller counts the refusal, never forwards a guess.
///
/// Requirement `05-3474-23-3661-02` (repo-minted,
/// MINTED-pending-confirm).
#[must_use]
pub fn nwk_dst_of(msdu: &[u8]) -> Option<u16> {
    rounddance_nwk::decode(msdu).ok().map(|d| d.header.dst_addr)
}
