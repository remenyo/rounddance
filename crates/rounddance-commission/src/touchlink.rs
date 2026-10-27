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
/// §12.1.1, anchor p0091-L2007-L2012).
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
    /// Exchange complete.
    Done,
    /// Terminal failure.
    Failed,
}

/// Target sequencing skeleton (`22-65816-030-122-01`: respond to scan,
/// start or join, never change address except on leave/join or
/// conflict; anchor p0092-L2054-L2064).
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
    /// Discarded (duplicate scan restarted the procedure, or done
    /// without orders).
    Restarted,
}

/// Initiator-side skeleton driver.
#[derive(Debug, Clone, Copy)]
pub struct TouchlinkInitiator {
    state: TouchlinkInitiatorState,
    transaction: u32,
    responses: u8,
}

impl TouchlinkInitiator {
    /// Create idle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: TouchlinkInitiatorState::Idle,
            transaction: 0,
            responses: 0,
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
        self.transaction = transaction;
        self.responses = 0;
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
            TouchlinkInitiatorState::StartingNetwork | TouchlinkInitiatorState::JoiningNetwork => {
                self.state = if ok {
                    TouchlinkInitiatorState::Done
                } else {
                    TouchlinkInitiatorState::Failed
                };
            }
            _ => self.state = TouchlinkInitiatorState::Failed,
        }
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
}

impl TouchlinkTarget {
    /// Create idle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: TouchlinkTargetState::Idle,
            transaction: 0,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> TouchlinkTargetState {
        self.state
    }

    /// Receive a scan request: a second scan before the transaction
    /// completes restarts the procedure (or may discard the frame —
    /// this driver restarts; `22-65816-030-122-01`).
    pub fn on_scan_request(&mut self, frame: &TouchlinkFrame) {
        match self.state {
            TouchlinkTargetState::Idle
            | TouchlinkTargetState::ScanReceived
            | TouchlinkTargetState::Responded => {
                self.transaction = frame.transaction;
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
}

impl Default for TouchlinkTarget {
    fn default() -> Self {
        Self::new()
    }
}
