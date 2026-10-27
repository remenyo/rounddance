//! Touchlink commissioning: cluster frame stubs plus state skeleton.
//!
//! Paraphrase-level model of the Touchlink Commissioning cluster layout
//! in doc `07-5123-08` ZCL §13.3 (cluster `0x1000`, profile `0xc05e`,
//! command sets and identifier tables; anchors p1130-L25894-L25899,
//! p1130-L25917-L25919, p1132-L25931-L25932, p1144-L26292-L26295) and
//! the BDB v3.1 touchpoint procedures in doc `22-65816-030` §§12.1–12.2
//! (initiator scan/start/join flow, field settings, target rules;
//! anchors p0085-L1787+, p0087-L1821-L1835, p0091-L2007-L2012,
//! p0092-L2054-L2064). All wording here is paraphrase (D1).
//!
//! Requirement IDs below are repo-minted (`07-5123-08-133-*` and
//! `22-65816-030-12-*`, dots stripped), MINTED-pending-confirm.
//!
//! Inter-PAN transmit rides the MAC SAP inter-PAN service
//! ([`rounddance_mac_sap::MacInterPanSap`]) through the [`InterPanTx`]
//! seam: this module owns the cluster identifier, the command codecs,
//! both role state skeletons, and the TX drivers
//! ([`TouchlinkInitiator::broadcast_scan`],
//! [`TouchlinkTarget::respond`]), with the SAP adapter at
//! [`SapInterPan`].

/// Touchlink Commissioning cluster identifier (`07-5123-08-133-01`,
/// anchor p1130-L25917).
pub const TOUCHLINK_CLUSTER: u16 = 0x1000;
/// Profile for the touchlink (inter-PAN) command set (same source).
pub const TOUCHLINK_PROFILE: u16 = 0xc05e;
/// Profile for the utility (unicast) command set (same source).
pub const TOUCHLINK_UTILITY_PROFILE: u16 = 0x0104;

/// Server-received (client-to-server) command identifiers, Table 13-13
/// (`07-5123-08-13322-01`, anchor p1132-L25931-L25932).
pub mod rx {
    /// Scan request.
    pub const SCAN_REQ: u8 = 0x00;
    /// Device information request.
    pub const DEVICE_INFO_REQ: u8 = 0x02;
    /// Identify request.
    pub const IDENTIFY_REQ: u8 = 0x06;
    /// Reset to factory-new request.
    pub const RESET_FACTORY_REQ: u8 = 0x07;
    /// Network start request.
    pub const NWK_START_REQ: u8 = 0x10;
    /// Network join router request.
    pub const NWK_JOIN_ROUTER_REQ: u8 = 0x12;
    /// Network join end-device request.
    pub const NWK_JOIN_ED_REQ: u8 = 0x14;
    /// Network update request.
    pub const NWK_UPDATE_REQ: u8 = 0x16;
    /// Utility: get group identifiers request.
    pub const UTIL_GET_GROUP_REQ: u8 = 0x41;
    /// Utility: get endpoint list request.
    pub const UTIL_GET_ENDPOINT_REQ: u8 = 0x42;
}

/// Server-generated (server-to-client) command identifiers, §13.3.2.3
/// (`07-5123-08-13323-01`, anchor p1144-L26292-L26295).
pub mod tx {
    /// Scan response.
    pub const SCAN_RSP: u8 = 0x01;
    /// Device information response.
    pub const DEVICE_INFO_RSP: u8 = 0x03;
    /// Network start response.
    pub const NWK_START_RSP: u8 = 0x11;
    /// Network join router response.
    pub const NWK_JOIN_ROUTER_RSP: u8 = 0x13;
    /// Network join end-device response.
    pub const NWK_JOIN_ED_RSP: u8 = 0x15;
    /// Utility: endpoint information.
    pub const UTIL_ENDPOINT_INFO: u8 = 0x40;
    /// Utility: get group identifiers response.
    pub const UTIL_GET_GROUP_RSP: u8 = 0x41;
    /// Utility: get endpoint list response.
    pub const UTIL_GET_ENDPOINT_RSP: u8 = 0x42;
}

/// Largest touchlink frame this codec accepts (declared budget: 4-octet
/// transaction + 1-octet command + payload).
pub const MAX_TOUCHLINK_FRAME: usize = 96;
/// Largest command payload in octets.
pub const MAX_TOUCHLINK_PAYLOAD: usize = MAX_TOUCHLINK_FRAME - 5;

/// Touchlink frame failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchlinkError {
    /// Input shorter than transaction + command.
    Truncated,
    /// Caller buffer too small.
    BufferTooSmall,
    /// Payload exceeds the declared budget.
    PayloadTooLong,
    /// Operation not allowed in the current state.
    BadState,
    /// Underlying inter-PAN transport failed.
    Transport,
    /// Order/response carries a transaction identifier that does not
    /// match the latched exchange (`22-65816-030-1211-02`: the caller
    /// discards the frame and stays in state).
    StaleTransaction,
    /// No usable key index: out of range, or no common key between
    /// the initiator and target bitmasks (`07-5123-08-1333411-01`).
    BadKeyIndex,
    /// Operation attempted after the transaction lifetime expired
    /// (`22-65816-030-122-03`).
    Expired,
    /// Role mismatch: a network start order needs a router target; a
    /// join order kind must match the target logical type
    /// (`22-65816-030-122-03`).
    WrongRole,
    /// A builder field is outside its legal range (channel, PAN
    /// identifier, key index, sub-device count).
    InvalidField,
}

impl From<rounddance_mac_sap::MacError> for TouchlinkError {
    fn from(_: rounddance_mac_sap::MacError) -> Self {
        Self::Transport
    }
}

/// One touchlink commissioning frame: the inter-PAN transaction
/// identifier (BDB §12.1.1.1, anchor p0091-L2007-L2012) plus the
/// cluster command and its payload.
///
/// Requirement `22-65816-030-1211-01` (transaction binds the whole
/// exchange) + `07-5123-08-13322-01` / `07-5123-08-13323-01`
/// (command identifiers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TouchlinkFrame {
    /// Inter-PAN transaction identifier shared by the exchange.
    pub transaction: u32,
    /// Cluster command identifier (`rx::` / `tx::` consts).
    pub command: u8,
    /// Command payload octets, first `payload_len` valid.
    pub payload: [u8; MAX_TOUCHLINK_PAYLOAD],
    /// Payload length.
    pub payload_len: u8,
}

impl TouchlinkFrame {
    /// Shortest wire length (transaction + command, empty payload).
    pub const MIN_LEN: usize = 5;

    /// Build a frame from parts.
    pub fn new(transaction: u32, command: u8, payload: &[u8]) -> Result<Self, TouchlinkError> {
        if payload.len() > MAX_TOUCHLINK_PAYLOAD {
            return Err(TouchlinkError::PayloadTooLong);
        }
        let mut frame = Self {
            transaction,
            command,
            payload: [0; MAX_TOUCHLINK_PAYLOAD],
            payload_len: payload.len() as u8,
        };
        frame.payload[..payload.len()].copy_from_slice(payload);
        Ok(frame)
    }

    /// Decode a received frame.
    pub fn decode(buf: &[u8]) -> Result<Self, TouchlinkError> {
        if buf.len() < Self::MIN_LEN {
            return Err(TouchlinkError::Truncated);
        }
        let payload_len = buf.len() - Self::MIN_LEN;
        if payload_len > MAX_TOUCHLINK_PAYLOAD {
            return Err(TouchlinkError::PayloadTooLong);
        }
        let mut frame = Self {
            transaction: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            command: buf[4],
            payload: [0; MAX_TOUCHLINK_PAYLOAD],
            payload_len: payload_len as u8,
        };
        frame.payload[..payload_len].copy_from_slice(&buf[5..]);
        Ok(frame)
    }

    /// Encode into `out`; returns the wire length.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, TouchlinkError> {
        let n = Self::MIN_LEN + self.payload_len as usize;
        if out.len() < n {
            return Err(TouchlinkError::BufferTooSmall);
        }
        out[0..4].copy_from_slice(&self.transaction.to_le_bytes());
        out[4] = self.command;
        out[5..n].copy_from_slice(&self.payload[..self.payload_len as usize]);
        Ok(n)
    }

    /// Payload bytes.
    #[must_use]
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }
}

/// Scan-request application payload carried inside a
/// [`TouchlinkFrame`] with command [`rx::SCAN_REQ`]: the initiator's
/// touchlink capability bits plus the key index it offers.
///
/// Requirement `22-65816-030-121-02` (initiator scan broadcast per
/// channel; anchor p0087-L1821-L1835).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanRequestPayload {
    /// Touchlink information bitmask (address-assignment capable,
    /// link-initiator, etc., as cluster bits).
    pub touchlink_info: u8,
    /// Key index offered for the network key transport.
    pub key_index: u8,
}

impl ScanRequestPayload {
    /// Wire length.
    pub const LEN: usize = 2;

    /// Decode from a scan-request frame payload.
    pub fn decode(buf: &[u8]) -> Result<Self, TouchlinkError> {
        if buf.len() < Self::LEN {
            return Err(TouchlinkError::Truncated);
        }
        Ok(Self {
            touchlink_info: buf[0],
            key_index: buf[1],
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, TouchlinkError> {
        if out.len() < Self::LEN {
            return Err(TouchlinkError::BufferTooSmall);
        }
        out[0] = self.touchlink_info;
        out[1] = self.key_index;
        Ok(Self::LEN)
    }
}

/// Inter-PAN transmit seam: broadcast one touchlink frame per scan
/// channel. Implemented by the MAC SAP adapter ([`SapInterPan`]) and
/// by test/sim media.
pub trait InterPanTx {
    /// Transmit error for the seam.
    type Error;
    /// Queue one touchlink frame on `channel` (broadcast inter-PAN).
    fn send(&mut self, channel: u8, frame: &TouchlinkFrame) -> Result<(), Self::Error>;
}

/// [`InterPanTx`] over the MAC SAP inter-PAN service: encodes each
/// touchlink frame into one inter-PAN payload on the requested
/// channel (`22-65816-030-121-03` + `122-02`, repo-minted,
/// MINTED-pending-confirm).
pub struct SapInterPan<'a, S: rounddance_mac_sap::MacInterPanSap + ?Sized> {
    sap: &'a mut S,
}

impl<'a, S: rounddance_mac_sap::MacInterPanSap + ?Sized> SapInterPan<'a, S> {
    /// Wrap a live inter-PAN SAP.
    #[must_use]
    pub fn new(sap: &'a mut S) -> Self {
        Self { sap }
    }
}

impl<S: rounddance_mac_sap::MacInterPanSap + ?Sized> InterPanTx for SapInterPan<'_, S> {
    type Error = rounddance_mac_sap::MacError;

    fn send(&mut self, channel: u8, frame: &TouchlinkFrame) -> Result<(), Self::Error> {
        use rounddance_mac_sap::{Channel, FramePayload};
        let on = Channel::new(channel).map_err(|_| Self::Error::InvalidChannel)?;
        let mut buf = [0u8; MAX_TOUCHLINK_FRAME];
        let n = frame
            .encode_into(&mut buf)
            .map_err(|_| Self::Error::FrameTooLong)?;
        let msdu = FramePayload::from_slice(&buf[..n]).map_err(|_| Self::Error::FrameTooLong)?;
        self.sap.interpan_request(on, &msdu).map(|_| ())
    }
}

/// Initiator sequencing skeleton (`22-65816-030-121-01`: scan each
/// channel, select, then network start or join; field settings per
/// §12.1.1, anchor p0091-L2007-L2012; response wait, startup delay,
/// and handoff per `22-65816-030-121-04`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchlinkInitiatorState {
    /// Created.
    Idle,
    /// Broadcasting scan requests across the scan channels.
    Scanning,
    /// At least one scan response heard; choosing the target.
    Selecting,
    /// Starting a new network on the target.
    StartingNetwork,
    /// Having the target join the initiator's network.
    JoiningNetwork,
    /// Start order sent; waiting for the start response inside the
    /// receive window (`22-65816-030-121-04`).
    AwaitingStartResponse,
    /// Join order sent; waiting for the join response inside the
    /// receive window (`22-65816-030-121-04`).
    AwaitingJoinResponse,
    /// Success response received; holding the startup delay before
    /// the handoff to classical operation (`22-65816-030-121-04`).
    StartupWait,
    /// Exchange complete.
    Done,
    /// Terminal failure.
    Failed,
}

/// Target sequencing skeleton (`22-65816-030-122-01`: respond to scan,
/// start or join, never change address except on leave/join or
/// conflict; anchor p0092-L2054-L2064; orders, update, and lifetime
/// per `22-65816-030-122-03` + `22-65816-030-122-04`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchlinkTargetState {
    /// Created.
    Idle,
    /// Scan request received; response pending.
    ScanReceived,
    /// Scan response sent; awaiting start/join.
    Responded,
    /// Ordered to start or join; applying.
    Applying,
    /// Exchange complete.
    Done,
    /// Discarded (duplicate scan restarted the procedure, refused
    /// order terminated it, or reset accepted).
    Restarted,
    /// Transaction lifetime elapsed with no completing order; the
    /// exchange is abandoned (`22-65816-030-122-03`).
    Expired,
}

/// Initiator-side skeleton driver.
#[derive(Debug, Clone, Copy)]
pub struct TouchlinkInitiator {
    state: TouchlinkInitiatorState,
    transaction: u32,
    responses: u8,
    /// Milliseconds spent in the current wait state (receive window
    /// or startup delay); reset on every state entry.
    wait_ms: u32,
    /// Milliseconds since the scan began; bounds the whole exchange
    /// to the transaction lifetime.
    age_ms: u32,
    /// Network parameters latched at order time; handed to classical
    /// operation once the startup delay completes.
    handoff: Option<CommissionedNetwork>,
}

impl TouchlinkInitiator {
    /// Create idle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: TouchlinkInitiatorState::Idle,
            transaction: 0,
            responses: 0,
            wait_ms: 0,
            age_ms: 0,
            handoff: None,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> TouchlinkInitiatorState {
        self.state
    }

    /// Active transaction identifier.
    #[must_use]
    pub const fn transaction(&self) -> u32 {
        self.transaction
    }

    /// Begin scanning with a fresh transaction identifier.
    pub fn begin_scan(&mut self, transaction: u32) -> Result<(), TouchlinkError> {
        if self.state != TouchlinkInitiatorState::Idle {
            return Err(TouchlinkError::BadState);
        }
        if transaction == 0 {
            return Err(TouchlinkError::InvalidField);
        }
        self.transaction = transaction;
        self.responses = 0;
        self.wait_ms = 0;
        self.age_ms = 0;
        self.handoff = None;
        self.state = TouchlinkInitiatorState::Scanning;
        Ok(())
    }

    /// Build the scan-request frame for `channel` (the caller transmits
    /// it via [`InterPanTx`]; `22-65816-030-121-02`).
    #[must_use]
    pub fn scan_request(&self, touchlink_info: u8, key_index: u8) -> TouchlinkFrame {
        let mut payload = [0u8; MAX_TOUCHLINK_PAYLOAD];
        payload[0] = touchlink_info;
        payload[1] = key_index;
        TouchlinkFrame {
            transaction: self.transaction,
            command: rx::SCAN_REQ,
            payload,
            payload_len: ScanRequestPayload::LEN as u8,
        }
    }

    /// Broadcast the scan request on every scan channel through the
    /// inter-PAN seam (`22-65816-030-121-03`, repo-minted,
    /// MINTED-pending-confirm; scan broadcast per §12.1,
    /// anchor p0087-L1821-L1835). Only valid while scanning;
    /// returns the channel count sent.
    pub fn broadcast_scan<Tx: InterPanTx>(
        &self,
        tx: &mut Tx,
        channels: &[u8],
        touchlink_info: u8,
        key_index: u8,
    ) -> Result<usize, TouchlinkError>
    where
        Tx::Error: Into<TouchlinkError>,
    {
        if self.state != TouchlinkInitiatorState::Scanning {
            return Err(TouchlinkError::BadState);
        }
        let frame = self.scan_request(touchlink_info, key_index);
        let mut sent = 0usize;
        for &channel in channels {
            tx.send(channel, &frame).map_err(Into::into)?;
            sent += 1;
        }
        Ok(sent)
    }

    /// Note one scan response on this transaction (identifier match is
    /// the caller's check per §12.1.1.1).
    pub fn note_response(&mut self, matching_transaction: bool) {
        if self.state == TouchlinkInitiatorState::Scanning && matching_transaction {
            self.responses = self.responses.saturating_add(1);
            self.state = TouchlinkInitiatorState::Selecting;
        }
    }

    /// Move to network start (target starts a new network) or join
    /// (target joins ours).
    pub fn proceed(&mut self, start_new: bool) -> Result<(), TouchlinkError> {
        if self.state != TouchlinkInitiatorState::Selecting {
            return Err(TouchlinkError::BadState);
        }
        self.state = if start_new {
            TouchlinkInitiatorState::StartingNetwork
        } else {
            TouchlinkInitiatorState::JoiningNetwork
        };
        Ok(())
    }

    /// Close the exchange.
    pub fn finish(&mut self, ok: bool) {
        match self.state {
            TouchlinkInitiatorState::StartingNetwork
            | TouchlinkInitiatorState::JoiningNetwork
            | TouchlinkInitiatorState::StartupWait => {
                self.state = if ok {
                    TouchlinkInitiatorState::Done
                } else {
                    TouchlinkInitiatorState::Failed
                };
            }
            _ => self.state = TouchlinkInitiatorState::Failed,
        }
    }

    /// Take the latched handoff parameters (classical network data
    /// once the exchange completed).
    pub fn take_handoff(&mut self) -> Option<CommissionedNetwork> {
        self.handoff.take()
    }
}

impl Default for TouchlinkInitiator {
    fn default() -> Self {
        Self::new()
    }
}

/// Target-side skeleton driver.
#[derive(Debug, Clone, Copy)]
pub struct TouchlinkTarget {
    state: TouchlinkTargetState,
    transaction: u32,
    /// Response identifier latched when the scan response goes out;
    /// feeds the network-key transport derivation.
    response_id: u32,
    /// Milliseconds since the scan latched; bounds the exchange to
    /// the transaction lifetime.
    age_ms: u32,
    /// Accepted network parameters, applied by the caller through
    /// the classical layer once the order exchange completes.
    pending: Option<CommissionedNetwork>,
    /// Accepted channel-update parameters (network update order).
    pending_update: Option<PendingUpdate>,
}

impl TouchlinkTarget {
    /// Create idle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: TouchlinkTargetState::Idle,
            transaction: 0,
            response_id: 0,
            age_ms: 0,
            pending: None,
            pending_update: None,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> TouchlinkTargetState {
        self.state
    }

    /// Receive a scan request: a second scan before the transaction
    /// completes restarts the procedure (or may discard the frame —
    /// this driver restarts; `22-65816-030-122-01`). A fresh latch
    /// clears the lifetime clock and any latched orders.
    pub fn on_scan_request(&mut self, frame: &TouchlinkFrame) {
        match self.state {
            TouchlinkTargetState::Idle
            | TouchlinkTargetState::ScanReceived
            | TouchlinkTargetState::Responded => {
                self.transaction = frame.transaction;
                self.response_id = 0;
                self.age_ms = 0;
                self.pending = None;
                self.pending_update = None;
                self.state = TouchlinkTargetState::ScanReceived;
            }
            _ => self.state = TouchlinkTargetState::Restarted,
        }
    }

    /// Mark the scan response sent.
    pub fn on_response_sent(&mut self) {
        if self.state == TouchlinkTargetState::ScanReceived {
            self.state = TouchlinkTargetState::Responded;
        }
    }

    /// Build the scan-response frame for the latched transaction
    /// (`tx::SCAN_RSP`, `07-5123-08-13323-01`): the target's own
    /// touchlink information plus the key index it accepts. Fuller
    /// response application fields are a follow-up; the transaction
    /// binding and command identifier are the frozen parts.
    #[must_use]
    pub fn scan_response(&self, touchlink_info: u8, key_index: u8) -> TouchlinkFrame {
        let mut payload = [0u8; MAX_TOUCHLINK_PAYLOAD];
        payload[0] = touchlink_info;
        payload[1] = key_index;
        TouchlinkFrame {
            transaction: self.transaction,
            command: tx::SCAN_RSP,
            payload,
            payload_len: ScanRequestPayload::LEN as u8,
        }
    }

    /// Transmit the scan response on `channel` through the inter-PAN
    /// seam and latch it sent (`22-65816-030-122-02`, repo-minted,
    /// MINTED-pending-confirm; target rules per §12.2,
    /// anchor p0092-L2054-L2064). Only valid after a scan request.
    pub fn respond<Tx: InterPanTx>(
        &mut self,
        tx: &mut Tx,
        channel: u8,
        touchlink_info: u8,
        key_index: u8,
    ) -> Result<(), TouchlinkError>
    where
        Tx::Error: Into<TouchlinkError>,
    {
        match self.state {
            TouchlinkTargetState::ScanReceived | TouchlinkTargetState::Responded => {}
            _ => return Err(TouchlinkError::BadState),
        }
        let frame = self.scan_response(touchlink_info, key_index);
        tx.send(channel, &frame).map_err(Into::into)?;
        self.on_response_sent();
        Ok(())
    }

    /// Apply an incoming network start/join order on this transaction.
    pub fn on_network_order(&mut self, matching_transaction: bool) {
        if self.state == TouchlinkTargetState::Responded && matching_transaction {
            self.state = TouchlinkTargetState::Applying;
        }
    }

    /// Close the exchange.
    pub fn finish(&mut self, ok: bool) {
        if self.state == TouchlinkTargetState::Applying {
            self.state = if ok {
                TouchlinkTargetState::Done
            } else {
                TouchlinkTargetState::Restarted
            };
        }
    }

    /// Take the accepted network parameters latched by a start/join
    /// order (classical layer applies them to the NIB).
    pub fn take_pending(&mut self) -> Option<CommissionedNetwork> {
        self.pending.take()
    }

    /// Take the accepted channel-update parameters latched by a
    /// network update order.
    pub fn take_update(&mut self) -> Option<PendingUpdate> {
        self.pending_update.take()
    }
}

impl Default for TouchlinkTarget {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Completion: network start/join/update flows, key transport, timeout and
// abandon rules, touchlink-to-classical handoff.
// ---------------------------------------------------------------------------
//
// Paraphrase-level models of the touchlink commissioning payload layouts
// in doc `07-5123-08` ZCL §13.3.2.2 (request frames) / §13.3.2.3
// (response frames) / §13.3.4.6 + §13.3.4.11 (transaction scope, key
// transport) and the initiator/target procedures in doc `22-65816-030`
// BDB v3.1 §12.1 (initiator steps, anchors p0085-L1787+ .. p0091-L2007+)
// / §12.2 (target steps, anchors p0092-L2054+ .. p0098-L2250+). All
// wording here is paraphrase (D1). Requirement IDs below reuse the
// corpus touchlink IDs where the corpus pins them (`07-5123-08-133*`,
// `22-65816-030-121*` / `122*` / `1211*`) and are otherwise repo-minted
// (`07-5123-08-133225-*` … `1333411-*`, `22-65816-030-121-04`,
// `122-03`, `122-04`, dots stripped), MINTED-pending-confirm.

/// How long an inter-PAN transaction identifier stays valid: the
/// initiator abandons the exchange and the target stops accepting
/// orders past this age (`22-65816-030-121-04` / `122-03`).
pub const TRANSACTION_LIFETIME_MS: u32 = 8_000;
/// How long the initiator waits for a start/join response after its
/// order before failing that leg (`22-65816-030-121-04`).
pub const RX_WINDOW_MS: u32 = 5_000;
/// How long the initiator holds after a success response so the
/// target can start/join before the classical handoff
/// (`22-65816-030-121-04`).
pub const MIN_STARTUP_DELAY_MS: u32 = 2_000;
/// Base per-channel scan dwell (`22-65816-030-121-04`).
pub const SCAN_BASE_MS: u32 = 250;

/// Success status carried by start/join responses
/// (`07-5123-08-133233-01` / `133234-01` / `133235-01`).
pub const STATUS_SUCCESS: u8 = 0x00;
/// Failure status carried by start/join responses (refused steal,
/// bad key index).
pub const STATUS_FAILURE: u8 = 0x01;

/// Key index naming the development protection
/// (`07-5123-08-1333411-01`).
pub const KEY_INDEX_DEVELOPMENT: u8 = 0;
/// Key index naming the shared master protection (normal operation).
pub const KEY_INDEX_MASTER: u8 = 4;
/// Key index naming the certification protection (testing only).
pub const KEY_INDEX_CERTIFICATION: u8 = 15;
/// Highest legal key index value.
pub const MAX_KEY_INDEX: u8 = 15;

/// Certification protection key, test and certification use only;
/// its octets are published for interop checking
/// (`07-5123-08-1333411-01`).
pub const CERTIFICATION_KEY: [u8; 16] = [
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
];

/// Key material the target holds for the transport derivation
/// (`07-5123-08-1333411-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchlinkKey {
    /// Development protection (index 0).
    Development,
    /// Shared master protection (index 4); the caller injects the
    /// confidential key — it is never stored here.
    Master([u8; 16]),
    /// Certification protection (index 15).
    Certification,
}

impl TouchlinkKey {
    /// Key index naming this material.
    #[must_use]
    pub const fn index(self) -> u8 {
        match self {
            Self::Development => KEY_INDEX_DEVELOPMENT,
            Self::Master(_) => KEY_INDEX_MASTER,
            Self::Certification => KEY_INDEX_CERTIFICATION,
        }
    }
}

/// Pick the protection both sides share: the highest key index set
/// in both bitmasks. No common key is a hard stop — the initiator
/// must not select that target (`07-5123-08-1333411-01`).
pub fn select_key_index(local_mask: u16, peer_mask: u16) -> Result<u8, TouchlinkError> {
    let common = local_mask & peer_mask;
    if common == 0 {
        return Err(TouchlinkError::BadKeyIndex);
    }
    let mut index = MAX_KEY_INDEX;
    loop {
        if common & (1u16 << index) != 0 {
            return Ok(index);
        }
        if index == 0 {
            break;
        }
        index -= 1;
    }
    Err(TouchlinkError::BadKeyIndex)
}

/// Expand the transaction and response identifiers into the 128-bit
/// transport-derivation input: each identifier twice, value octets
/// most significant first (pinned by the worked certification
/// vector in `07-5123-08-1333411-01`).
#[must_use]
pub fn transport_block(transaction: u32, response_id: u32) -> [u8; 16] {
    let t = transaction.to_be_bytes();
    let r = response_id.to_be_bytes();
    [
        t[0], t[1], t[2], t[3], t[0], t[1], t[2], t[3], r[0], r[1], r[2], r[3], r[0], r[1], r[2],
        r[3],
    ]
}

/// Development-protection input: the two fixed markers wrapped around
/// the identifiers, value octets most significant first
/// (`07-5123-08-1333411-01`).
#[must_use]
pub fn development_block(transaction: u32, response_id: u32) -> [u8; 16] {
    let t = transaction.to_be_bytes();
    let r = response_id.to_be_bytes();
    [
        b'P', b'h', b'L', b'i', t[0], t[1], t[2], t[3], b'C', b'L', b'S', b'N', r[0], r[1], r[2],
        r[3],
    ]
}

/// Derive the one-shot transport key for `index`: development input
/// used directly (index 0), otherwise the derivation input encrypted
/// under the master (index 4, caller-supplied) or certification
/// (index 15) key (`07-5123-08-1333411-01`).
pub fn transport_key_for(
    index: u8,
    transaction: u32,
    response_id: u32,
    master: &[u8; 16],
) -> Result<[u8; 16], TouchlinkError> {
    match index {
        KEY_INDEX_DEVELOPMENT => Ok(development_block(transaction, response_id)),
        KEY_INDEX_MASTER => Ok(rounddance_security::encrypt_block_aes128(
            master,
            &transport_block(transaction, response_id),
        )),
        KEY_INDEX_CERTIFICATION => Ok(rounddance_security::encrypt_block_aes128(
            &CERTIFICATION_KEY,
            &transport_block(transaction, response_id),
        )),
        _ => Err(TouchlinkError::BadKeyIndex),
    }
}

/// Wrap the network key for transport (initiator side): one ECB
/// encryption under the derived transport key
/// (`07-5123-08-1333411-01`).
#[must_use]
pub fn encrypt_network_key(transport: &[u8; 16], network_key: &[u8; 16]) -> [u8; 16] {
    rounddance_security::encrypt_block_aes128(transport, network_key)
}

/// Unwrap the transported network key (target side): one ECB
/// decryption under the derived transport key
/// (`07-5123-08-1333411-01`).
#[must_use]
pub fn decrypt_network_key(transport: &[u8; 16], encrypted: &[u8; 16]) -> [u8; 16] {
    aes128_decrypt_block(transport, encrypted)
}

/// Inverse substitution box for the local ECB decryption below
/// (target-side key unwrap only; encryption rides the security
/// crate). Pure integer code, `no_std` compatible.
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// Galois multiply used by the inverse mix step.
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// Expand a 128-bit key into 11 round keys (same schedule as the
/// security-crate encryption side so the pair agrees).
fn expand_key_local(key: &[u8; 16], out: &mut [u8; 176]) {
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    const SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];
    out[..16].copy_from_slice(key);
    let mut i = 16usize;
    let mut rcon = 0usize;
    while i < 176 {
        let mut t = [0u8; 4];
        t.copy_from_slice(&out[i - 4..i]);
        if i.is_multiple_of(16) {
            let u0 = t[0];
            t[0] = SBOX[t[1] as usize] ^ RCON[rcon];
            t[1] = SBOX[t[2] as usize];
            t[2] = SBOX[t[3] as usize];
            t[3] = SBOX[u0 as usize];
            rcon += 1;
        }
        let mut j = 0usize;
        while j < 4 {
            out[i + j] = out[i - 16 + j] ^ t[j];
            j += 1;
        }
        i += 4;
    }
}

/// Single-block ECB decryption (target-side unwrap). Pinned by the
/// published cipher check (decrypt of the reference ciphertext
/// returns the reference plaintext) and by round-trip agreement with
/// the security-crate encryption side.
fn aes128_decrypt_block(key: &[u8; 16], ciphertext: &[u8; 16]) -> [u8; 16] {
    let mut expanded = [0u8; 176];
    expand_key_local(key, &mut expanded);
    let mut s = *ciphertext;
    let add_key = |s: &mut [u8; 16], rk: &[u8]| {
        for (b, k) in s.iter_mut().zip(rk.iter()) {
            *b ^= *k;
        }
    };
    add_key(&mut s, &expanded[160..176]);
    for round in (1..10).rev() {
        // Inverse shift rows.
        let t = s;
        s[1] = t[13];
        s[2] = t[10];
        s[3] = t[7];
        s[5] = t[1];
        s[6] = t[14];
        s[7] = t[11];
        s[9] = t[5];
        s[10] = t[2];
        s[11] = t[15];
        s[13] = t[9];
        s[14] = t[6];
        s[15] = t[3];
        // Inverse sub bytes.
        for b in s.iter_mut() {
            *b = INV_SBOX[*b as usize];
        }
        add_key(&mut s, &expanded[round * 16..round * 16 + 16]);
        // Inverse mix columns.
        for c in 0..4 {
            let a0 = s[c * 4];
            let a1 = s[c * 4 + 1];
            let a2 = s[c * 4 + 2];
            let a3 = s[c * 4 + 3];
            s[c * 4] = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
            s[c * 4 + 1] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
            s[c * 4 + 2] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
            s[c * 4 + 3] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
        }
    }
    // Final round (no mix columns).
    let t = s;
    s[1] = t[13];
    s[2] = t[10];
    s[3] = t[7];
    s[5] = t[1];
    s[6] = t[14];
    s[7] = t[11];
    s[9] = t[5];
    s[10] = t[2];
    s[11] = t[15];
    s[13] = t[9];
    s[14] = t[6];
    s[15] = t[3];
    for b in s.iter_mut() {
        *b = INV_SBOX[*b as usize];
    }
    add_key(&mut s, &expanded[0..16]);
    s
}

// ---------------------------------------------------------------------------
// Payload codecs: network start/join/update, full scan request/response.
// ---------------------------------------------------------------------------

/// Write a little-endian 16-bit value.
fn put_u16(out: &mut [u8], off: usize, v: u16) {
    out[off] = v as u8;
    out[off + 1] = (v >> 8) as u8;
}

/// Read a little-endian 16-bit value.
fn get_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

/// Lowest legal touchlink channel number (mirrors the formation
/// crate bound under a touchlink-scoped name).
pub const TOUCHLINK_CHANNEL_MIN: u8 = 11;
/// Highest legal touchlink channel number.
pub const TOUCHLINK_CHANNEL_MAX: u8 = 26;

/// Check an order channel: the start order may carry zero (the target
/// picks), every other order names a real channel
/// (`22-65816-030-121-04`).
fn check_channel(channel: u8, allow_zero: bool) -> Result<(), TouchlinkError> {
    if channel == 0 {
        if allow_zero {
            return Ok(());
        }
        return Err(TouchlinkError::InvalidField);
    }
    if (TOUCHLINK_CHANNEL_MIN..=TOUCHLINK_CHANNEL_MAX).contains(&channel) {
        Ok(())
    } else {
        Err(TouchlinkError::InvalidField)
    }
}

/// Check a key index is in range (`07-5123-08-1333411-01`).
fn check_key_index(index: u8) -> Result<(), TouchlinkError> {
    if index <= MAX_KEY_INDEX {
        Ok(())
    } else {
        Err(TouchlinkError::BadKeyIndex)
    }
}

/// Full scan-request body: the two information octets in wire order
/// (`07-5123-08-13322-01`, scan request layout). The wave-10
/// [`ScanRequestPayload`] skeleton stays byte-compatible for the
/// existing seal; new flows use this field-correct form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanRequestBody {
    /// Logical type + receiver-on-when-idle octet.
    pub zigbee_info: u8,
    /// Factory-new, address-assignment, link-initiator and profile
    /// bits octet.
    pub touchlink_info: u8,
}

impl ScanRequestBody {
    /// Wire length.
    pub const LEN: usize = 2;

    /// Decode a scan-request body.
    pub fn decode(buf: &[u8]) -> Result<Self, TouchlinkError> {
        if buf.len() < Self::LEN {
            return Err(TouchlinkError::Truncated);
        }
        if buf.len() > Self::LEN {
            return Err(TouchlinkError::PayloadTooLong);
        }
        Ok(Self {
            zigbee_info: buf[0],
            touchlink_info: buf[1],
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, TouchlinkError> {
        if out.len() < Self::LEN {
            return Err(TouchlinkError::BufferTooSmall);
        }
        out[0] = self.zigbee_info;
        out[1] = self.touchlink_info;
        Ok(Self::LEN)
    }
}

/// Touchlink information octet builders (scan request and response
/// share the low bits; `07-5123-08-13322-01`).
pub mod info {
    /// Factory-new device bit.
    pub const FACTORY_NEW: u8 = 0x01;
    /// Address-assignment capable bit.
    pub const ADDRESS_ASSIGNMENT: u8 = 0x02;
    /// Link-initiator capable bit (scan request) / touchlink
    /// initiator bit (scan response).
    pub const LINK_INITIATOR: u8 = 0x10;
    /// Priority-request bit (scan response).
    pub const PRIORITY_REQUEST: u8 = 0x20;
    /// Profile-interop bit (set for current profiles).
    pub const PROFILE_INTEROP: u8 = 0x80;
}

/// Zigbee information octet builders (`07-5123-08-13322-01`).
pub mod zigbee {
    /// Logical type: coordinator.
    pub const COORDINATOR: u8 = 0x00;
    /// Logical type: router.
    pub const ROUTER: u8 = 0x01;
    /// Logical type: end device.
    pub const END_DEVICE: u8 = 0x02;
    /// Receiver left on when idle.
    pub const RX_ON_WHEN_IDLE: u8 = 0x04;
}

/// Full scan-response body: signal correction, both information
/// octets, supported-key bitmask, random response identifier, and the
/// network fields the initiator decides on, plus the single
/// sub-device tail when exactly one sub-device is reported
/// (`07-5123-08-133231-01`, repo-minted, MINTED-pending-confirm).
/// Multi-sub-device targets are out of scope for this bounded codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanResponseBody {
    /// Product-specific RSSI correction offset.
    pub rssi_correction: u8,
    /// Logical type + receiver-on-when-idle octet.
    pub zigbee_info: u8,
    /// Factory-new, address-assignment, priority and profile bits.
    pub touchlink_info: u8,
    /// Supported key indices as a bitmask (bit `i` = index `i`).
    pub key_bitmask: u16,
    /// Random response identifier feeding the key transport.
    pub response_id: u32,
    /// Current extended PAN (zero when factory new with no proposal).
    pub extended_pan: [u8; 8],
    /// Current network update identifier (zero when factory new).
    pub network_update_id: u8,
    /// Current logical channel.
    pub channel: u8,
    /// Current PAN identifier.
    pub pan_id: u16,
    /// Current short address (`0xffff` when factory new).
    pub network_address: u16,
    /// Sub-device count: 0 or 1 in this codec.
    pub sub_devices: u8,
    /// Group identifiers the device needs.
    pub total_groups: u8,
    /// Tail, present only when `sub_devices == 1`.
    pub endpoint: u8,
    /// Tail, present only when `sub_devices == 1`.
    pub profile_id: u16,
    /// Tail, present only when `sub_devices == 1`.
    pub device_id: u16,
    /// Tail, present only when `sub_devices == 1`.
    pub version: u8,
    /// Tail, present only when `sub_devices == 1`.
    pub group_count: u8,
}

impl ScanResponseBody {
    /// Wire length without the sub-device tail.
    pub const BASE_LEN: usize = 25;
    /// Tail length for exactly one sub-device.
    pub const SUB_LEN: usize = 7;

    /// Decode a scan-response body.
    pub fn decode(buf: &[u8]) -> Result<Self, TouchlinkError> {
        if buf.len() < Self::BASE_LEN {
            return Err(TouchlinkError::Truncated);
        }
        let sub_devices = buf[23];
        if sub_devices > 1 {
            return Err(TouchlinkError::InvalidField);
        }
        let want = if sub_devices == 1 {
            Self::BASE_LEN + Self::SUB_LEN
        } else {
            Self::BASE_LEN
        };
        if buf.len() < want {
            return Err(TouchlinkError::Truncated);
        }
        if buf.len() > want {
            return Err(TouchlinkError::PayloadTooLong);
        }
        let mut extended_pan = [0u8; 8];
        extended_pan.copy_from_slice(&buf[9..17]);
        let mut body = Self {
            rssi_correction: buf[0],
            zigbee_info: buf[1],
            touchlink_info: buf[2],
            key_bitmask: get_u16(buf, 3),
            response_id: u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]),
            extended_pan,
            network_update_id: buf[17],
            channel: buf[18],
            pan_id: get_u16(buf, 19),
            network_address: get_u16(buf, 21),
            sub_devices,
            total_groups: buf[24],
            endpoint: 0,
            profile_id: 0,
            device_id: 0,
            version: 0,
            group_count: 0,
        };
        if sub_devices == 1 {
            body.endpoint = buf[25];
            body.profile_id = get_u16(buf, 26);
            body.device_id = get_u16(buf, 28);
            body.version = buf[30];
            body.group_count = buf[31];
        }
        Ok(body)
    }

    /// Encode into `out`; returns the wire length.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, TouchlinkError> {
        if self.sub_devices > 1 {
            return Err(TouchlinkError::InvalidField);
        }
        let n = if self.sub_devices == 1 {
            Self::BASE_LEN + Self::SUB_LEN
        } else {
            Self::BASE_LEN
        };
        if out.len() < n {
            return Err(TouchlinkError::BufferTooSmall);
        }
        out[0] = self.rssi_correction;
        out[1] = self.zigbee_info;
        out[2] = self.touchlink_info;
        put_u16(out, 3, self.key_bitmask);
        out[5..9].copy_from_slice(&self.response_id.to_le_bytes());
        out[9..17].copy_from_slice(&self.extended_pan);
        out[17] = self.network_update_id;
        out[18] = self.channel;
        put_u16(out, 19, self.pan_id);
        put_u16(out, 21, self.network_address);
        out[23] = self.sub_devices;
        out[24] = self.total_groups;
        if self.sub_devices == 1 {
            out[25] = self.endpoint;
            put_u16(out, 26, self.profile_id);
            put_u16(out, 28, self.device_id);
            out[30] = self.version;
            out[31] = self.group_count;
        }
        Ok(n)
    }
}

/// Network start request body: the new-network parameters plus the
/// wrapped network key and the initiator identity
/// (`07-5123-08-133225-01`, repo-minted, MINTED-pending-confirm).
/// Multi-octet integers ride little-endian; the two addresses are
/// opaque octet strings carried in on-air order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkStartRequest {
    /// Extended PAN of the new network (zero: the target picks).
    pub extended_pan: [u8; 8],
    /// Protection index used for `encrypted_key`.
    pub key_index: u8,
    /// Network key wrapped under the transport key.
    pub encrypted_key: [u8; 16],
    /// Channel for the new network (zero: the target picks).
    pub channel: u8,
    /// PAN identifier (zero: the target picks).
    pub pan_id: u16,
    /// Short address assigned to the target.
    pub network_address: u16,
    /// First group identifier assigned to the target.
    pub group_begin: u16,
    /// Last group identifier assigned to the target.
    pub group_end: u16,
    /// First free network address the target may assign onward.
    pub free_nwk_begin: u16,
    /// Last free network address the target may assign onward.
    pub free_nwk_end: u16,
    /// First free group identifier the target may assign onward.
    pub free_group_begin: u16,
    /// Last free group identifier the target may assign onward.
    pub free_group_end: u16,
    /// Long address of the initiator.
    pub initiator_ieee: [u8; 8],
    /// Short address the initiator will use on the new network.
    pub initiator_nwk: u16,
}

impl NetworkStartRequest {
    /// Wire length.
    pub const LEN: usize = 52;

    /// Decode a network start request body.
    pub fn decode(buf: &[u8]) -> Result<Self, TouchlinkError> {
        if buf.len() < Self::LEN {
            return Err(TouchlinkError::Truncated);
        }
        if buf.len() > Self::LEN {
            return Err(TouchlinkError::PayloadTooLong);
        }
        let mut extended_pan = [0u8; 8];
        extended_pan.copy_from_slice(&buf[0..8]);
        let mut encrypted_key = [0u8; 16];
        encrypted_key.copy_from_slice(&buf[9..25]);
        let mut initiator_ieee = [0u8; 8];
        initiator_ieee.copy_from_slice(&buf[42..50]);
        Ok(Self {
            extended_pan,
            key_index: buf[8],
            encrypted_key,
            channel: buf[25],
            pan_id: get_u16(buf, 26),
            network_address: get_u16(buf, 28),
            group_begin: get_u16(buf, 30),
            group_end: get_u16(buf, 32),
            free_nwk_begin: get_u16(buf, 34),
            free_nwk_end: get_u16(buf, 36),
            free_group_begin: get_u16(buf, 38),
            free_group_end: get_u16(buf, 40),
            initiator_ieee,
            initiator_nwk: get_u16(buf, 50),
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, TouchlinkError> {
        if out.len() < Self::LEN {
            return Err(TouchlinkError::BufferTooSmall);
        }
        out[0..8].copy_from_slice(&self.extended_pan);
        out[8] = self.key_index;
        out[9..25].copy_from_slice(&self.encrypted_key);
        out[25] = self.channel;
        put_u16(out, 26, self.pan_id);
        put_u16(out, 28, self.network_address);
        put_u16(out, 30, self.group_begin);
        put_u16(out, 32, self.group_end);
        put_u16(out, 34, self.free_nwk_begin);
        put_u16(out, 36, self.free_nwk_end);
        put_u16(out, 38, self.free_group_begin);
        put_u16(out, 40, self.free_group_end);
        out[42..50].copy_from_slice(&self.initiator_ieee);
        put_u16(out, 50, self.initiator_nwk);
        Ok(Self::LEN)
    }
}

/// Network join request body (router `0x12` and end-device `0x14`
/// share the layout; [`JoinKind`] picks the command): the
/// initiator's network parameters plus the wrapped network key
/// (`07-5123-08-133226-01` / `133227-01`, repo-minted,
/// MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkJoinRequest {
    /// Extended PAN of the initiator's network.
    pub extended_pan: [u8; 8],
    /// Protection index used for `encrypted_key`.
    pub key_index: u8,
    /// Network key wrapped under the transport key.
    pub encrypted_key: [u8; 16],
    /// Initiator's network update identifier.
    pub network_update_id: u8,
    /// Channel of the initiator's network.
    pub channel: u8,
    /// PAN identifier of the initiator's network.
    pub pan_id: u16,
    /// Short address assigned to the target.
    pub network_address: u16,
    /// First group identifier assigned to the target.
    pub group_begin: u16,
    /// Last group identifier assigned to the target.
    pub group_end: u16,
    /// First free network address the target may assign onward.
    pub free_nwk_begin: u16,
    /// Last free network address the target may assign onward.
    pub free_nwk_end: u16,
    /// First free group identifier the target may assign onward.
    pub free_group_begin: u16,
    /// Last free group identifier the target may assign onward.
    pub free_group_end: u16,
}

impl NetworkJoinRequest {
    /// Wire length.
    pub const LEN: usize = 43;

    /// Decode a network join request body.
    pub fn decode(buf: &[u8]) -> Result<Self, TouchlinkError> {
        if buf.len() < Self::LEN {
            return Err(TouchlinkError::Truncated);
        }
        if buf.len() > Self::LEN {
            return Err(TouchlinkError::PayloadTooLong);
        }
        let mut extended_pan = [0u8; 8];
        extended_pan.copy_from_slice(&buf[0..8]);
        let mut encrypted_key = [0u8; 16];
        encrypted_key.copy_from_slice(&buf[9..25]);
        Ok(Self {
            extended_pan,
            key_index: buf[8],
            encrypted_key,
            network_update_id: buf[25],
            channel: buf[26],
            pan_id: get_u16(buf, 27),
            network_address: get_u16(buf, 29),
            group_begin: get_u16(buf, 31),
            group_end: get_u16(buf, 33),
            free_nwk_begin: get_u16(buf, 35),
            free_nwk_end: get_u16(buf, 37),
            free_group_begin: get_u16(buf, 39),
            free_group_end: get_u16(buf, 41),
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, TouchlinkError> {
        if out.len() < Self::LEN {
            return Err(TouchlinkError::BufferTooSmall);
        }
        out[0..8].copy_from_slice(&self.extended_pan);
        out[8] = self.key_index;
        out[9..25].copy_from_slice(&self.encrypted_key);
        out[25] = self.network_update_id;
        out[26] = self.channel;
        put_u16(out, 27, self.pan_id);
        put_u16(out, 29, self.network_address);
        put_u16(out, 31, self.group_begin);
        put_u16(out, 33, self.group_end);
        put_u16(out, 35, self.free_nwk_begin);
        put_u16(out, 37, self.free_nwk_end);
        put_u16(out, 39, self.free_group_begin);
        put_u16(out, 41, self.free_group_end);
        Ok(Self::LEN)
    }
}

/// Network start response body: status plus the verified network
/// parameters (`07-5123-08-133233-01`, repo-minted,
/// MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkStartResponse {
    /// `STATUS_SUCCESS` or `STATUS_FAILURE`.
    pub status: u8,
    /// Extended PAN of the started network.
    pub extended_pan: [u8; 8],
    /// Update identifier (zero in this revision).
    pub network_update_id: u8,
    /// Channel of the started network.
    pub channel: u8,
    /// PAN identifier of the started network.
    pub pan_id: u16,
}

impl NetworkStartResponse {
    /// Wire length.
    pub const LEN: usize = 13;

    /// Success response echoing the started parameters.
    #[must_use]
    pub const fn success(
        extended_pan: [u8; 8],
        network_update_id: u8,
        channel: u8,
        pan_id: u16,
    ) -> Self {
        Self {
            status: STATUS_SUCCESS,
            extended_pan,
            network_update_id,
            channel,
            pan_id,
        }
    }

    /// Failure response (refused steal, bad key index).
    #[must_use]
    pub const fn failure() -> Self {
        Self {
            status: STATUS_FAILURE,
            extended_pan: [0; 8],
            network_update_id: 0,
            channel: 0,
            pan_id: 0,
        }
    }

    /// Whether this response reports success.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.status == STATUS_SUCCESS
    }

    /// Decode a network start response body.
    pub fn decode(buf: &[u8]) -> Result<Self, TouchlinkError> {
        if buf.len() < Self::LEN {
            return Err(TouchlinkError::Truncated);
        }
        if buf.len() > Self::LEN {
            return Err(TouchlinkError::PayloadTooLong);
        }
        let mut extended_pan = [0u8; 8];
        extended_pan.copy_from_slice(&buf[1..9]);
        Ok(Self {
            status: buf[0],
            extended_pan,
            network_update_id: buf[9],
            channel: buf[10],
            pan_id: get_u16(buf, 11),
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, TouchlinkError> {
        if out.len() < Self::LEN {
            return Err(TouchlinkError::BufferTooSmall);
        }
        out[0] = self.status;
        out[1..9].copy_from_slice(&self.extended_pan);
        out[9] = self.network_update_id;
        out[10] = self.channel;
        put_u16(out, 11, self.pan_id);
        Ok(Self::LEN)
    }
}

/// Network join response body (router `0x13` and end-device `0x15`
/// share the single-octet layout; [`JoinKind`] picks the command):
/// status only (`07-5123-08-133234-01` / `133235-01`, repo-minted,
/// MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkJoinResponse {
    /// `STATUS_SUCCESS` or `STATUS_FAILURE`.
    pub status: u8,
}

impl NetworkJoinResponse {
    /// Wire length.
    pub const LEN: usize = 1;

    /// Success response.
    #[must_use]
    pub const fn success() -> Self {
        Self {
            status: STATUS_SUCCESS,
        }
    }

    /// Failure response (refused steal, bad key index).
    #[must_use]
    pub const fn failure() -> Self {
        Self {
            status: STATUS_FAILURE,
        }
    }

    /// Whether this response reports success.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.status == STATUS_SUCCESS
    }

    /// Decode a network join response body.
    pub fn decode(buf: &[u8]) -> Result<Self, TouchlinkError> {
        if buf.len() < Self::LEN {
            return Err(TouchlinkError::Truncated);
        }
        if buf.len() > Self::LEN {
            return Err(TouchlinkError::PayloadTooLong);
        }
        Ok(Self { status: buf[0] })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, TouchlinkError> {
        if out.is_empty() {
            return Err(TouchlinkError::BufferTooSmall);
        }
        out[0] = self.status;
        Ok(Self::LEN)
    }
}

/// Network update request body: the current network identity plus the
/// newer update identifier and channel the target should adopt
/// (`07-5123-08-133228-01`, repo-minted, MINTED-pending-confirm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkUpdateRequest {
    /// Extended PAN of the initiator's network.
    pub extended_pan: [u8; 8],
    /// Initiator's network update identifier.
    pub network_update_id: u8,
    /// Channel the target should move to.
    pub channel: u8,
    /// PAN identifier of the initiator's network.
    pub pan_id: u16,
    /// Short address assigned to the target.
    pub network_address: u16,
}

impl NetworkUpdateRequest {
    /// Wire length.
    pub const LEN: usize = 14;

    /// Decode a network update request body.
    pub fn decode(buf: &[u8]) -> Result<Self, TouchlinkError> {
        if buf.len() < Self::LEN {
            return Err(TouchlinkError::Truncated);
        }
        if buf.len() > Self::LEN {
            return Err(TouchlinkError::PayloadTooLong);
        }
        let mut extended_pan = [0u8; 8];
        extended_pan.copy_from_slice(&buf[0..8]);
        Ok(Self {
            extended_pan,
            network_update_id: buf[8],
            channel: buf[9],
            pan_id: get_u16(buf, 10),
            network_address: get_u16(buf, 12),
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, TouchlinkError> {
        if out.len() < Self::LEN {
            return Err(TouchlinkError::BufferTooSmall);
        }
        out[0..8].copy_from_slice(&self.extended_pan);
        out[8] = self.network_update_id;
        out[9] = self.channel;
        put_u16(out, 10, self.pan_id);
        put_u16(out, 12, self.network_address);
        Ok(Self::LEN)
    }
}

/// Device information request body: start index into the target
/// device table (`07-5123-08-13322-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceInfoRequest {
    /// Starting index (from zero) into the device table.
    pub start_index: u8,
}

impl DeviceInfoRequest {
    /// Wire length.
    pub const LEN: usize = 1;

    /// Decode a device information request body.
    pub fn decode(buf: &[u8]) -> Result<Self, TouchlinkError> {
        if buf.len() != Self::LEN {
            if buf.is_empty() {
                return Err(TouchlinkError::Truncated);
            }
            return Err(TouchlinkError::PayloadTooLong);
        }
        Ok(Self {
            start_index: buf[0],
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, TouchlinkError> {
        if out.is_empty() {
            return Err(TouchlinkError::BufferTooSmall);
        }
        out[0] = self.start_index;
        Ok(Self::LEN)
    }
}

/// Identify request body: how long the target stays noticeable
/// (`07-5123-08-13322-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentifyRequest {
    /// Seconds to remain noticeable (`0` exits, `0xffff` is the
    /// receiver-default stay).
    pub duration_s: u16,
}

impl IdentifyRequest {
    /// Wire length.
    pub const LEN: usize = 2;

    /// Decode an identify request body.
    pub fn decode(buf: &[u8]) -> Result<Self, TouchlinkError> {
        if buf.len() < Self::LEN {
            return Err(TouchlinkError::Truncated);
        }
        if buf.len() > Self::LEN {
            return Err(TouchlinkError::PayloadTooLong);
        }
        Ok(Self {
            duration_s: get_u16(buf, 0),
        })
    }

    /// Encode into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, TouchlinkError> {
        if out.len() < Self::LEN {
            return Err(TouchlinkError::BufferTooSmall);
        }
        put_u16(out, 0, self.duration_s);
        Ok(Self::LEN)
    }
}

/// Which join order the initiator sends and which response it
/// awaits (`07-5123-08-13322-01` / `13323-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinKind {
    /// Router join: request `0x12`, response `0x13`.
    Router,
    /// End-device join: request `0x14`, response `0x15`.
    EndDevice,
}

impl JoinKind {
    /// Request command identifier for this kind.
    #[must_use]
    pub const fn request_command(self) -> u8 {
        match self {
            Self::Router => rx::NWK_JOIN_ROUTER_REQ,
            Self::EndDevice => rx::NWK_JOIN_ED_REQ,
        }
    }

    /// Response command identifier for this kind.
    #[must_use]
    pub const fn response_command(self) -> u8 {
        match self {
            Self::Router => tx::NWK_JOIN_ROUTER_RSP,
            Self::EndDevice => tx::NWK_JOIN_ED_RSP,
        }
    }
}

/// Commissioned network parameters: the touchlink-to-classical
/// handoff state. Both machines latch the same values — the
/// initiator from its own order, the target by unwrapping the
/// transported key — and the caller applies them through the
/// classical layer: set the on-network flag, install the network key
/// as active, and record the distributed-link-key entry (type `0x01`,
/// counters zero) (`22-65816-030-121-04` / `122-03`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommissionedNetwork {
    /// Extended PAN of the commissioned network.
    pub extended_pan: [u8; 8],
    /// PAN identifier of the commissioned network.
    pub pan_id: u16,
    /// Logical channel of the commissioned network.
    pub channel: u8,
    /// Short address this device uses on the network.
    pub network_address: u16,
    /// Network update identifier installed with the network.
    pub network_update_id: u8,
    /// Unwrapped network key, installed as the active key.
    pub network_key: [u8; 16],
    /// Protection index the key arrived under.
    pub key_index: u8,
    /// True when this device formed/started the network, false when
    /// it joined an existing one.
    pub formed_new: bool,
}

/// Channel-update parameters latched from an accepted network update
/// order (`22-65816-030-122-04`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingUpdate {
    /// Adopted network update identifier.
    pub network_update_id: u8,
    /// Adopted logical channel.
    pub channel: u8,
}

/// How the target disposes of a network update order
/// (`22-65816-030-122-04`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateDisposition {
    /// Ignored: stale transaction, identity mismatch, or no newer
    /// update identifier. The exchange stays waiting.
    Ignored,
    /// Accepted: the caller moves to the latched channel and update
    /// identifier through the classical layer.
    Applied(PendingUpdate),
}

/// Product policy plus key material the target checks an order
/// against (`22-65816-030-122-03`).
#[derive(Debug, Clone, Copy)]
pub struct TargetOrderCtx {
    /// Whether this target is a router (only routers start).
    pub is_router: bool,
    /// Whether the product accepts leaving for another network
    /// (refusing answers failure and terminates).
    pub accept: bool,
    /// Key material for the transport derivation.
    pub key: TouchlinkKey,
    /// Key indices this target supports (bit `i` = index `i`).
    pub supported_keys: u16,
}

impl TargetOrderCtx {
    /// Whether `index` names this target's held material and is
    /// advertised as supported.
    #[must_use]
    pub fn key_usable(&self, index: u8) -> bool {
        if index > MAX_KEY_INDEX {
            return false;
        }
        if self.supported_keys & (1u16 << index) == 0 {
            return false;
        }
        self.key.index() == index
    }

    /// Master octets for the derivation (certification and
    /// development need none).
    #[must_use]
    pub const fn master_octets(&self) -> [u8; 16] {
        match self.key {
            TouchlinkKey::Master(m) => m,
            _ => [0u8; 16],
        }
    }
}

// ---------------------------------------------------------------------------
// Initiator flow extensions.
// ---------------------------------------------------------------------------

impl TouchlinkInitiator {
    /// Encode a start order and send it on `channel` through the
    /// inter-PAN seam, latching the classical handoff parameters.
    /// Only valid while starting a network; the channel may be zero
    /// (the target picks) or a real channel
    /// (`22-65816-030-121-04`).
    pub fn send_start<Tx: InterPanTx>(
        &mut self,
        tx: &mut Tx,
        channel: u8,
        req: &NetworkStartRequest,
        network_key: &[u8; 16],
    ) -> Result<(), TouchlinkError>
    where
        Tx::Error: Into<TouchlinkError>,
    {
        if self.state != TouchlinkInitiatorState::StartingNetwork {
            return Err(TouchlinkError::BadState);
        }
        check_channel(req.channel, true)?;
        if req.pan_id == 0xffff {
            return Err(TouchlinkError::InvalidField);
        }
        check_key_index(req.key_index)?;
        let mut payload = [0u8; NetworkStartRequest::LEN];
        req.encode_into(&mut payload)?;
        let frame = TouchlinkFrame::new(self.transaction, rx::NWK_START_REQ, &payload)?;
        tx.send(channel, &frame).map_err(Into::into)?;
        self.handoff = Some(CommissionedNetwork {
            extended_pan: req.extended_pan,
            pan_id: req.pan_id,
            channel: req.channel,
            network_address: req.initiator_nwk,
            network_update_id: 0,
            network_key: *network_key,
            key_index: req.key_index,
            formed_new: true,
        });
        self.wait_ms = 0;
        self.state = TouchlinkInitiatorState::AwaitingStartResponse;
        Ok(())
    }

    /// Encode a join order and send it on `channel` through the
    /// inter-PAN seam, latching the classical handoff parameters.
    /// Only valid while joining (`22-65816-030-121-04`).
    pub fn send_join<Tx: InterPanTx>(
        &mut self,
        tx: &mut Tx,
        channel: u8,
        kind: JoinKind,
        req: &NetworkJoinRequest,
        network_key: &[u8; 16],
    ) -> Result<(), TouchlinkError>
    where
        Tx::Error: Into<TouchlinkError>,
    {
        if self.state != TouchlinkInitiatorState::JoiningNetwork {
            return Err(TouchlinkError::BadState);
        }
        check_channel(req.channel, false)?;
        if req.pan_id == 0x0000 || req.pan_id == 0xffff {
            return Err(TouchlinkError::InvalidField);
        }
        check_key_index(req.key_index)?;
        let mut payload = [0u8; NetworkJoinRequest::LEN];
        req.encode_into(&mut payload)?;
        let frame = TouchlinkFrame::new(self.transaction, kind.request_command(), &payload)?;
        tx.send(channel, &frame).map_err(Into::into)?;
        self.handoff = Some(CommissionedNetwork {
            extended_pan: req.extended_pan,
            pan_id: req.pan_id,
            channel: req.channel,
            network_address: req.network_address,
            network_update_id: req.network_update_id,
            network_key: *network_key,
            key_index: req.key_index,
            formed_new: false,
        });
        let _ = channel;
        self.wait_ms = 0;
        self.state = TouchlinkInitiatorState::AwaitingJoinResponse;
        Ok(())
    }

    /// Encode a network update order and send it on `channel`.
    /// Valid while selecting or joining (`22-65816-030-121-04`).
    pub fn send_update<Tx: InterPanTx>(
        &mut self,
        tx: &mut Tx,
        channel: u8,
        req: &NetworkUpdateRequest,
    ) -> Result<(), TouchlinkError>
    where
        Tx::Error: Into<TouchlinkError>,
    {
        match self.state {
            TouchlinkInitiatorState::Selecting | TouchlinkInitiatorState::JoiningNetwork => {}
            _ => return Err(TouchlinkError::BadState),
        }
        check_channel(req.channel, false)?;
        let mut payload = [0u8; NetworkUpdateRequest::LEN];
        req.encode_into(&mut payload)?;
        let frame = TouchlinkFrame::new(self.transaction, rx::NWK_UPDATE_REQ, &payload)?;
        tx.send(channel, &frame).map_err(Into::into)?;
        Ok(())
    }

    /// Handle a start response: stale transactions never advance the
    /// machine; a failure status fails the leg; success opens the
    /// startup wait (`22-65816-030-121-04`).
    pub fn on_start_response(
        &mut self,
        rsp: &NetworkStartResponse,
        transaction: u32,
    ) -> Result<(), TouchlinkError> {
        if self.state != TouchlinkInitiatorState::AwaitingStartResponse {
            return Err(TouchlinkError::BadState);
        }
        if transaction != self.transaction {
            return Err(TouchlinkError::StaleTransaction);
        }
        if !rsp.is_success() {
            self.handoff = None;
            self.state = TouchlinkInitiatorState::Failed;
            return Ok(());
        }
        self.wait_ms = 0;
        self.state = TouchlinkInitiatorState::StartupWait;
        Ok(())
    }

    /// Handle a join response: same discipline as the start leg
    /// (`22-65816-030-121-04`).
    pub fn on_join_response(
        &mut self,
        rsp: &NetworkJoinResponse,
        transaction: u32,
    ) -> Result<(), TouchlinkError> {
        if self.state != TouchlinkInitiatorState::AwaitingJoinResponse {
            return Err(TouchlinkError::BadState);
        }
        if transaction != self.transaction {
            return Err(TouchlinkError::StaleTransaction);
        }
        if !rsp.is_success() {
            self.handoff = None;
            self.state = TouchlinkInitiatorState::Failed;
            return Ok(());
        }
        self.wait_ms = 0;
        self.state = TouchlinkInitiatorState::StartupWait;
        Ok(())
    }

    /// Advance the injected clock by `elapsed_ms`. Returns true when
    /// a terminal transition fired: receive-window expiry fails the
    /// order leg, startup-delay expiry completes the exchange, and
    /// transaction-lifetime expiry abandons it
    /// (`22-65816-030-121-04`).
    pub fn tick_ms(&mut self, elapsed_ms: u32) -> bool {
        match self.state {
            TouchlinkInitiatorState::Done
            | TouchlinkInitiatorState::Failed
            | TouchlinkInitiatorState::Idle => return false,
            _ => {}
        }
        self.age_ms = self.age_ms.saturating_add(elapsed_ms);
        if self.age_ms >= TRANSACTION_LIFETIME_MS {
            self.handoff = None;
            self.state = TouchlinkInitiatorState::Failed;
            return true;
        }
        match self.state {
            TouchlinkInitiatorState::AwaitingStartResponse
            | TouchlinkInitiatorState::AwaitingJoinResponse => {
                self.wait_ms = self.wait_ms.saturating_add(elapsed_ms);
                if self.wait_ms >= RX_WINDOW_MS {
                    self.handoff = None;
                    self.state = TouchlinkInitiatorState::Failed;
                    true
                } else {
                    false
                }
            }
            TouchlinkInitiatorState::StartupWait => {
                self.wait_ms = self.wait_ms.saturating_add(elapsed_ms);
                if self.wait_ms >= MIN_STARTUP_DELAY_MS {
                    self.state = TouchlinkInitiatorState::Done;
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Target flow extensions.
// ---------------------------------------------------------------------------

impl TouchlinkTarget {
    /// Transmit the full scan response on `channel` through the
    /// inter-PAN seam and latch the response identifier for the key
    /// transport. Only valid after a scan request
    /// (`22-65816-030-122-02` + `122-03`).
    pub fn respond_full<Tx: InterPanTx>(
        &mut self,
        tx: &mut Tx,
        channel: u8,
        rsp: &ScanResponseBody,
    ) -> Result<(), TouchlinkError>
    where
        Tx::Error: Into<TouchlinkError>,
    {
        if self.state != TouchlinkTargetState::ScanReceived {
            return Err(TouchlinkError::BadState);
        }
        let mut payload = [0u8; ScanResponseBody::BASE_LEN + ScanResponseBody::SUB_LEN];
        let n = rsp.encode_into(&mut payload)?;
        let frame = TouchlinkFrame::new(self.transaction, tx::SCAN_RSP, &payload[..n])?;
        tx.send(channel, &frame).map_err(Into::into)?;
        self.response_id = rsp.response_id;
        self.state = TouchlinkTargetState::Responded;
        Ok(())
    }

    /// Handle a network start order. A foreign transaction or a
    /// non-router target discards the frame (no reply, exchange stays
    /// waiting); a refused steal or an unusable key index answers
    /// failure and terminates; otherwise the unwrapped key latches
    /// the handoff and success answers (`22-65816-030-122-03`).
    pub fn on_network_start(
        &mut self,
        req: &NetworkStartRequest,
        transaction: u32,
        ctx: &TargetOrderCtx,
    ) -> Result<NetworkStartResponse, TouchlinkError> {
        if self.state != TouchlinkTargetState::Responded {
            return Err(TouchlinkError::BadState);
        }
        if transaction != self.transaction {
            return Err(TouchlinkError::StaleTransaction);
        }
        if !ctx.is_router {
            return Err(TouchlinkError::WrongRole);
        }
        if !ctx.accept || !ctx.key_usable(req.key_index) {
            self.pending = None;
            self.state = TouchlinkTargetState::Restarted;
            return Ok(NetworkStartResponse::failure());
        }
        let master = ctx.master_octets();
        let transport = transport_key_for(req.key_index, transaction, self.response_id, &master)?;
        let network_key = decrypt_network_key(&transport, &req.encrypted_key);
        let ext_pan = req.extended_pan;
        self.pending = Some(CommissionedNetwork {
            extended_pan: ext_pan,
            pan_id: req.pan_id,
            channel: req.channel,
            network_address: req.network_address,
            network_update_id: 0,
            network_key,
            key_index: req.key_index,
            formed_new: true,
        });
        self.state = TouchlinkTargetState::Applying;
        Ok(NetworkStartResponse::success(
            ext_pan,
            0,
            req.channel,
            req.pan_id,
        ))
    }

    /// Handle a network join order: same discipline as the start leg,
    /// plus the order kind must match the target logical type
    /// (`22-65816-030-122-03`).
    pub fn on_network_join(
        &mut self,
        req: &NetworkJoinRequest,
        transaction: u32,
        kind: JoinKind,
        logical_ok: bool,
        ctx: &TargetOrderCtx,
    ) -> Result<NetworkJoinResponse, TouchlinkError> {
        if self.state != TouchlinkTargetState::Responded {
            return Err(TouchlinkError::BadState);
        }
        if transaction != self.transaction {
            return Err(TouchlinkError::StaleTransaction);
        }
        if !logical_ok {
            let _ = kind;
            return Err(TouchlinkError::WrongRole);
        }
        if !ctx.accept || !ctx.key_usable(req.key_index) {
            self.pending = None;
            self.state = TouchlinkTargetState::Restarted;
            return Ok(NetworkJoinResponse::failure());
        }
        let master = ctx.master_octets();
        let transport = transport_key_for(req.key_index, transaction, self.response_id, &master)?;
        let network_key = decrypt_network_key(&transport, &req.encrypted_key);
        self.pending = Some(CommissionedNetwork {
            extended_pan: req.extended_pan,
            pan_id: req.pan_id,
            channel: req.channel,
            network_address: req.network_address,
            network_update_id: req.network_update_id,
            network_key,
            key_index: req.key_index,
            formed_new: false,
        });
        self.state = TouchlinkTargetState::Applying;
        Ok(NetworkJoinResponse::success())
    }

    /// Handle a network update order while waiting: same-network
    /// identity with a newer update identifier adopts the channel and
    /// identifier; anything else is ignored and the exchange stays
    /// waiting (`22-65816-030-122-04`).
    pub fn on_network_update(
        &mut self,
        req: &NetworkUpdateRequest,
        transaction: u32,
        stored_ext_pan: &[u8; 8],
        stored_pan: u16,
        current_update: u8,
    ) -> UpdateDisposition {
        if self.state != TouchlinkTargetState::Responded {
            return UpdateDisposition::Ignored;
        }
        if transaction != self.transaction {
            return UpdateDisposition::Ignored;
        }
        if req.extended_pan != *stored_ext_pan || req.pan_id != stored_pan {
            return UpdateDisposition::Ignored;
        }
        if req.network_update_id <= current_update {
            return UpdateDisposition::Ignored;
        }
        let update = PendingUpdate {
            network_update_id: req.network_update_id,
            channel: req.channel,
        };
        self.pending_update = Some(update);
        UpdateDisposition::Applied(update)
    }

    /// Handle a reset-to-factory order: a matching transaction
    /// terminates the procedure for the reset; anything else is
    /// ignored (`22-65816-030-122-03`).
    pub fn on_reset(&mut self, transaction: u32) -> bool {
        if self.state != TouchlinkTargetState::Responded {
            return false;
        }
        if transaction != self.transaction {
            return false;
        }
        self.pending = None;
        self.pending_update = None;
        self.state = TouchlinkTargetState::Restarted;
        true
    }

    /// Handle an identify order: matching transactions are accepted
    /// with no reply and no state change (the operation never blocks
    /// the exchange); foreign transactions are refused
    /// (`22-65816-030-122-03`).
    pub fn on_identify(
        &self,
        transaction: u32,
        req: &IdentifyRequest,
    ) -> Result<u16, TouchlinkError> {
        if self.state != TouchlinkTargetState::Responded {
            return Err(TouchlinkError::BadState);
        }
        if transaction != self.transaction {
            return Err(TouchlinkError::StaleTransaction);
        }
        Ok(req.duration_s)
    }

    /// Handle a device-information order: matching transactions are
    /// accepted (the response itself is product data); foreign
    /// transactions are refused (`22-65816-030-122-03`).
    pub fn on_device_info(
        &self,
        transaction: u32,
        req: &DeviceInfoRequest,
    ) -> Result<u8, TouchlinkError> {
        if self.state != TouchlinkTargetState::Responded {
            return Err(TouchlinkError::BadState);
        }
        if transaction != self.transaction {
            return Err(TouchlinkError::StaleTransaction);
        }
        Ok(req.start_index)
    }

    /// Advance the injected clock by `elapsed_ms`. Returns true when
    /// the transaction lifetime elapsed with no completing order —
    /// the exchange is abandoned (`22-65816-030-122-03`).
    pub fn tick_ms(&mut self, elapsed_ms: u32) -> bool {
        match self.state {
            TouchlinkTargetState::ScanReceived | TouchlinkTargetState::Responded => {}
            _ => return false,
        }
        self.age_ms = self.age_ms.saturating_add(elapsed_ms);
        if self.age_ms >= TRANSACTION_LIFETIME_MS {
            self.pending = None;
            self.pending_update = None;
            self.state = TouchlinkTargetState::Expired;
            true
        } else {
            false
        }
    }
}
