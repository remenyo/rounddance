//! Application-endpoint hosting on any role + router/app simultaneity.
//!
//! Core scope requirement (founding note; `SCOPE.md`): one network
//! identity MUST route while hosting full application endpoints
//! (thermostat-that-routes). App modules run identically on router
//! or end device, so this layer is role-agnostic: endpoints attach
//! through the [`AppEndpoint`] host interface and a [`RouterApp`]
//! pairs any router with its local endpoints under a fairness rule.
//!
//! # Fairness rule (starvation prevention)
//!
//! Each [`RouterApp::tick`] services at most [`MAX_ROUTE_PER_TICK`]
//! routed frames and at most [`MAX_APP_PER_TICK`] local-endpoint
//! frames. Routing goes first (it carries other nodes' latency
//! budget), but the app side always keeps its own guaranteed slice:
//! a flood in either direction cannot starve the other beyond one
//! tick. The budgets are compile-time constants so the split is
//! auditable and identical on every target.
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-2325-ROLES-<seq>`), MINTED-pending-confirm.

/// Bound on app endpoints hosted by one device (declared budget).
///
/// Requirement `05-3474-23-2325-ROLES-01` (MINTED-pending-confirm).
pub const MAX_APP_ENDPOINTS: usize = 8;

/// Routed frames serviced per [`RouterApp::tick`] at most.
///
/// Requirement `05-3474-23-2325-ROLES-02` (MINTED-pending-confirm).
pub const MAX_ROUTE_PER_TICK: usize = 8;

/// Local-endpoint frames serviced per [`RouterApp::tick`] at most.
///
/// Requirement `05-3474-23-2325-ROLES-02` (MINTED-pending-confirm).
pub const MAX_APP_PER_TICK: usize = 4;

/// Largest single endpoint payload in octets (declared budget).
///
/// Requirement `05-3474-23-2325-ROLES-01` (MINTED-pending-confirm).
pub const MAX_APP_PAYLOAD: usize = 128;

/// Failures from endpoint hosting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointError {
    /// Endpoint id out of range (must be 1..=254).
    BadEndpointId,
    /// Endpoint id already registered.
    DuplicateEndpoint,
    /// No room for another endpoint.
    TableFull,
    /// No endpoint with this id.
    NoSuchEndpoint,
    /// Payload exceeds [`MAX_APP_PAYLOAD`].
    PayloadTooLarge,
}

/// Failures from one app-command invocation (typed so the stack can
/// map them to status codes without guessing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandError {
    /// Command id or payload malformed for this endpoint.
    BadCommand,
    /// Caller response buffer too small.
    ResponseTooSmall,
    /// Application declined the command.
    Rejected,
}

/// Handle identifying one hosted endpoint.
///
/// Requirement `05-3474-23-2325-ROLES-01` (MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointHandle {
    endpoint_id: u8,
}

impl EndpointHandle {
    /// Identifier on the wire (1..=254).
    #[must_use]
    pub const fn id(self) -> u8 {
        self.endpoint_id
    }
}

/// Host interface for one application endpoint.
///
/// The stack owns addressing, retries, and routing; the app owns
/// cluster semantics. `handle_command` receives the incoming payload
/// and writes any response into `response`, returning the response
/// length. A return of `Ok(0)` means "handled, no response".
///
/// Requirement `05-3474-23-2325-ROLES-01` (MINTED-pending-confirm).
pub trait AppEndpoint {
    /// Endpoint id this implementation serves (1..=254).
    fn endpoint_id(&self) -> u8;
    /// Profile id this implementation serves.
    fn profile_id(&self) -> u16;
    /// Handle one incoming command payload.
    fn handle_command(
        &mut self,
        payload: &[u8],
        response: &mut [u8],
    ) -> Result<usize, CommandError>;
}

/// One registered endpoint: id/profile plus a pending-command slot.
///
/// The pending slot is the stack-side mailbox; `RouterApp::tick`
/// drains it. This keeps the trait object-free (`no_std`-friendly:
// `&mut dyn AppEndpoint` would need no allocation but complicates
/// the tick borrow; instead the table stores routing metadata and
/// the caller pairs it with its endpoint impls).
#[derive(Debug, Clone, Copy)]
struct EndpointSlot {
    endpoint_id: u8,
    profile_id: u16,
    pending_len: u8,
    pending: [u8; MAX_APP_PAYLOAD],
    response_len: u8,
    response: [u8; MAX_APP_PAYLOAD],
}

/// Role-agnostic table of hosted application endpoints.
///
/// Requirement `05-3474-23-2325-ROLES-01` (MINTED-pending-confirm):
/// attach to coordinator, router, end device, or sleepy end device
/// identically.
#[derive(Debug, Clone)]
pub struct EndpointTable {
    slots: [Option<EndpointSlot>; MAX_APP_ENDPOINTS],
    len: usize,
}

impl Default for EndpointTable {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointTable {
    /// Empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_APP_ENDPOINTS],
            len: 0,
        }
    }

    /// Number of registered endpoints.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True when no endpoint is registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Register one endpoint implementation's identity.
    pub fn register<E: AppEndpoint>(
        &mut self,
        endpoint: &E,
    ) -> Result<EndpointHandle, EndpointError> {
        let id = endpoint.endpoint_id();
        if id == 0 || id == 0xFF {
            return Err(EndpointError::BadEndpointId);
        }
        if self.find(id).is_some() {
            return Err(EndpointError::DuplicateEndpoint);
        }
        if self.len >= MAX_APP_ENDPOINTS {
            return Err(EndpointError::TableFull);
        }
        for slot in self.slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(EndpointSlot {
                    endpoint_id: id,
                    profile_id: endpoint.profile_id(),
                    pending_len: 0,
                    pending: [0u8; MAX_APP_PAYLOAD],
                    response_len: 0,
                    response: [0u8; MAX_APP_PAYLOAD],
                });
                self.len += 1;
                return Ok(EndpointHandle { endpoint_id: id });
            }
        }
        Err(EndpointError::TableFull)
    }

    /// Queue an incoming command for `endpoint_id`.
    pub fn deliver(
        &mut self,
        endpoint_id: u8,
        payload: &[u8],
    ) -> Result<EndpointHandle, EndpointError> {
        if payload.len() > MAX_APP_PAYLOAD {
            return Err(EndpointError::PayloadTooLarge);
        }
        let i = self
            .find(endpoint_id)
            .ok_or(EndpointError::NoSuchEndpoint)?;
        let slot = self.slots[i].as_mut().unwrap();
        slot.pending[..payload.len()].copy_from_slice(payload);
        slot.pending_len = payload.len() as u8;
        Ok(EndpointHandle { endpoint_id })
    }

    /// Dispatch every pending command through its endpoint impl.
    ///
    /// `lookup` maps an endpoint id to its implementation. Returns
    /// the number of commands dispatched. At most
    /// [`MAX_APP_PER_TICK`] per call: the caller (see
    /// [`RouterApp::tick`]) enforces the app-side budget.
    pub fn dispatch<E: AppEndpoint>(
        &mut self,
        endpoints: &mut [&mut E],
        lookup: impl Fn(&E) -> u8,
        budget: usize,
    ) -> usize {
        let mut done = 0;
        for slot in self.slots.iter_mut().flatten() {
            if done >= budget || slot.pending_len == 0 {
                continue;
            }
            let mut pending = [0u8; MAX_APP_PAYLOAD];
            let plen = usize::from(slot.pending_len);
            pending[..plen].copy_from_slice(&slot.pending[..plen]);
            for ep in endpoints.iter_mut() {
                if lookup(ep) == slot.endpoint_id {
                    let mut out = [0u8; MAX_APP_PAYLOAD];
                    match ep.handle_command(&pending[..plen], &mut out) {
                        Ok(n) => {
                            let n = n.min(MAX_APP_PAYLOAD);
                            slot.response[..n].copy_from_slice(&out[..n]);
                            slot.response_len = n as u8;
                        }
                        Err(_) => slot.response_len = 0,
                    }
                    slot.pending_len = 0;
                    done += 1;
                    break;
                }
            }
        }
        done
    }

    /// Profile id registered for `endpoint_id`, if present.
    #[must_use]
    pub fn profile_id(&self, endpoint_id: u8) -> Option<u16> {
        self.find(endpoint_id)
            .map(|i| self.slots[i].as_ref().unwrap().profile_id)
    }

    /// Take the last response produced for `endpoint_id`.
    pub fn take_response(&mut self, endpoint_id: u8) -> Option<([u8; MAX_APP_PAYLOAD], usize)> {
        let i = self.find(endpoint_id)?;
        let slot = self.slots[i].as_mut().unwrap();
        if slot.pending_len != 0 {
            return None;
        }
        let n = usize::from(slot.response_len);
        slot.response_len = 0;
        Some((slot.response, n))
    }

    fn find(&self, endpoint_id: u8) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| matches!(slot, Some(s) if s.endpoint_id == endpoint_id))
    }
}

/// Router paired with its locally hosted endpoints: proves
/// router+app simultaneity structurally.
///
/// The router owns a bounded route queue (frames to forward) and an
/// [`EndpointTable`] (frames to serve locally). [`RouterApp::tick`]
/// services both under the fairness rule: routing first up to
/// [`MAX_ROUTE_PER_TICK`], then app commands up to
/// [`MAX_APP_PER_TICK`]. Either side keeps flowing when the other is
/// saturated.
///
/// Requirement `05-3474-23-2325-ROLES-02` (MINTED-pending-confirm).
#[derive(Debug, Clone)]
pub struct RouterApp {
    /// Frames awaiting forward: (destination short, payload).
    route_queue: [Option<([u8; MAX_APP_PAYLOAD], u8, u16)>; MAX_ROUTE_PER_TICK],
    route_len: usize,
    /// Frames forwarded so far (lifetime counter).
    pub forwarded: u32,
    /// App commands served so far (lifetime counter).
    pub app_served: u32,
    /// Ticks where the route side hit its budget.
    pub route_saturated_ticks: u32,
    /// Ticks where the app side hit its budget.
    pub app_saturated_ticks: u32,
}

impl Default for RouterApp {
    fn default() -> Self {
        Self::new()
    }
}

impl RouterApp {
    /// Empty router/app pair.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            route_queue: [None; MAX_ROUTE_PER_TICK],
            route_len: 0,
            forwarded: 0,
            app_served: 0,
            route_saturated_ticks: 0,
            app_saturated_ticks: 0,
        }
    }

    /// Queued route frames awaiting forward.
    #[must_use]
    pub const fn route_pending(&self) -> usize {
        self.route_len
    }

    /// Queue one frame for forwarding; refuses when the per-tick
    /// queue is full (backpressure, never silent drop).
    ///
    /// Requirement `05-3474-23-2325-ROLES-02`
    /// (MINTED-pending-confirm).
    pub fn queue_route(&mut self, dest: u16, payload: &[u8]) -> Result<(), EndpointError> {
        if payload.len() > MAX_APP_PAYLOAD {
            return Err(EndpointError::PayloadTooLarge);
        }
        if self.route_len >= MAX_ROUTE_PER_TICK {
            return Err(EndpointError::TableFull);
        }
        for slot in self.route_queue.iter_mut() {
            if slot.is_none() {
                let mut bytes = [0u8; MAX_APP_PAYLOAD];
                bytes[..payload.len()].copy_from_slice(payload);
                *slot = Some((bytes, payload.len() as u8, dest));
                self.route_len += 1;
                return Ok(());
            }
        }
        Err(EndpointError::TableFull)
    }

    /// Service one tick: forward up to [`MAX_ROUTE_PER_TICK`] routed
    /// frames into `forwarded_out`, then dispatch up to
    /// [`MAX_APP_PER_TICK`] app commands.
    ///
    /// Returns `(forwarded, app_served)` for this tick. The route
    /// side can never consume the app side's slice and vice versa.
    ///
    /// Requirement `05-3474-23-2325-ROLES-02`
    /// (MINTED-pending-confirm).
    pub fn tick<E: AppEndpoint>(
        &mut self,
        app_table: &mut EndpointTable,
        endpoints: &mut [&mut E],
        lookup: impl Fn(&E) -> u8,
        forwarded_out: &mut [(u16, [u8; MAX_APP_PAYLOAD], usize)],
    ) -> (usize, usize) {
        let mut forwarded = 0;
        for slot in self.route_queue.iter_mut() {
            if forwarded >= MAX_ROUTE_PER_TICK {
                break;
            }
            if forwarded >= forwarded_out.len() {
                break;
            }
            if let Some((bytes, len, dest)) = slot.take() {
                forwarded_out[forwarded] = (dest, bytes, usize::from(len));
                forwarded += 1;
            }
        }
        self.route_len -= forwarded;
        self.forwarded += forwarded as u32;
        if forwarded == MAX_ROUTE_PER_TICK {
            self.route_saturated_ticks += 1;
        }
        let served = app_table.dispatch(endpoints, lookup, MAX_APP_PER_TICK);
        self.app_served += served as u32;
        if served == MAX_APP_PER_TICK {
            self.app_saturated_ticks += 1;
        }
        (forwarded, served)
    }
}
