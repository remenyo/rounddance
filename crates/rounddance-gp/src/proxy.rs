//! Proxy role: proxy table, transmit queue, commissioning mode, and
//! the operational frame-processing flow.
//!
//! Paraphrase-level model of doc `14-0563-19` §A.1.5.2.1.1 (queue;
//! anchors p0046-L959-L972), §A.1.5.2.1.2–1.4 (timing; anchors
//! p0046-L974-L997), §A.3.4.2.6–2.7 (capability/blocklist reporting;
//! anchors p0150-L4019-L4028), §A.3.4.4.2.1 (table reads; anchors
//! p0155-L4147-L4168), §A.3.5.2.3 (basic-proxy operation; anchors
//! p0168-L4601-L4632), §A.3.6.3 (proxy operation incl. pairing,
//! commissioning mode, notification; anchors p0158-L4222-L4262,
//! p0161-L4352-L4384) and §A.3.8.1 (basic-proxy SDL; anchor
//! p0213-Fig97). All wording here is paraphrase (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are corpus-mined `14-0563-19-*`.

use crate::frame::{AppId, GpError, GpdId, Gpdf, GpdfBody, WireSecurityLevel};
use crate::security::{GpKey, GpReplay};

/// Minimum transmit-queue depth on basic proxy/sink devices.
///
/// Requirement `14-0563-19-A152-01`.
pub const MIN_BASIC_TX_QUEUE: usize = 1;

/// Minimum transmit-queue depth on full-function devices.
///
/// Requirement `14-0563-19-A152-01`.
pub const MIN_FULL_TX_QUEUE: usize = 5;

/// Default queue depth for the basic proxy/sink machines here.
pub const BASIC_TX_QUEUE_LEN: usize = MIN_BASIC_TX_QUEUE;

/// Default queue depth for full-function machines here.
pub const FULL_TX_QUEUE_LEN: usize = MIN_FULL_TX_QUEUE;

/// Minimum blocklist capacity on proxies that support it.
///
/// Requirement `14-0563-19-A34-01`.
pub const MIN_BLOCKLIST_LEN: usize = 10;

/// Blocklist capacity carried by the machines here.
pub const MAX_BLOCKED_IDS: usize = MIN_BLOCKLIST_LEN;

/// Largest sink list held per proxy-table entry (bounded budget).
pub const MAX_PROXY_SINKS: usize = 4;

/// Largest tunneled command payload carried in a notification record.
pub const MAX_NOTIFICATION_PAYLOAD: usize = 64;

/// Earliest response offset after a triggering frame (milliseconds).
///
/// Requirement `14-0563-19-A152-02`.
pub const TX_OFFSET_MS: u64 = 20;

/// Latest response offset after a triggering frame (milliseconds).
///
/// Requirement `14-0563-19-A152-02`.
pub const TX_OFFSET_MAX_MS: u64 = 25;

/// Maximum response transmission duration (milliseconds).
///
/// Requirement `14-0563-19-A152-02`.
pub const TX_DURATION_MS: u64 = 10;

/// Capability flags advertised by a basic proxy (fixed mandatory
/// subset: GP feature, direct reception, both groupcast modes,
/// lightweight unicast, both commissioning modes, no/low/high
/// security levels, IEEE addressing).
///
/// Requirement `14-0563-19-A34-01`.
pub const BASIC_PROXY_FUNCTIONALITY: u32 = 0x9_AC2F;

/// Typed failure for proxy-table and queue operations.
pub use crate::frame::GpError as ProxyError;

/// Communication mode stored per proxy-table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyCommMode {
    /// Pre-commissioned groupcast.
    PrecommissionedGroup,
    /// Derived groupcast.
    DerivedGroup,
    /// Lightweight unicast.
    LightweightUnicast,
    /// Full unicast.
    FullUnicast,
}

/// Sink address target for one tunneled notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkTarget {
    /// Group address.
    Group(u16),
    /// Short address of one sink.
    Unicast(u16),
}

/// One proxy-table entry: per-GPD forwarding state.
///
/// Requirement `14-0563-19-A36-02` (pairing-driven lifecycle).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProxyTableEntry {
    /// Identity scheme.
    pub app: AppId,
    /// Canonical GPD key (source id zero-extended or IEEE
    /// little-endian).
    pub id: u64,
    /// Endpoint scope for IEEE-addressed GPDs (`0xFF` = all).
    pub endpoint: u8,
    /// Required protection level for this GPD's frames.
    pub level: WireSecurityLevel,
    /// Required key-type wire bit.
    pub key_bit: bool,
    /// Last accepted security counter.
    pub counter: u32,
    /// Installed key material, if any.
    pub key: Option<GpKey>,
    /// Forwarding mode.
    pub comm_mode: ProxyCommMode,
    /// Sink targets (bounded).
    pub sinks: [SinkTarget; MAX_PROXY_SINKS],
    /// Number of valid sink targets.
    pub sink_count: u8,
    /// Assigned alias source address.
    pub alias: u16,
    /// Entry active (pairing deactivation clears this instead of
    /// removing the row on maintenance-capable devices).
    pub active: bool,
}

impl ProxyTableEntry {
    /// Fresh active entry with no sinks.
    #[must_use]
    pub const fn new(app: AppId, id: u64) -> Self {
        Self {
            app,
            id,
            endpoint: 0xFF,
            level: WireSecurityLevel::None,
            key_bit: false,
            counter: 0,
            key: None,
            comm_mode: ProxyCommMode::DerivedGroup,
            sinks: [SinkTarget::Group(0xFFFF); MAX_PROXY_SINKS],
            sink_count: 0,
            alias: 0xFFFF,
            active: true,
        }
    }

    /// True when this entry covers the frame's GPD identity
    /// (endpoint-scoped for IEEE-addressed GPDs).
    ///
    /// Requirement `14-0563-19-A36-02`.
    #[must_use]
    pub const fn covers(&self, id: GpdId) -> bool {
        if self.id != id.table_key() {
            return false;
        }
        match id {
            GpdId::SrcId(_) => true,
            GpdId::Ieee { endpoint, .. } => self.endpoint == 0xFF || self.endpoint == endpoint,
        }
    }

    /// Push a sink target; returns false when the bounded list is full.
    pub fn push_sink(&mut self, target: SinkTarget) -> bool {
        if (self.sink_count as usize) >= MAX_PROXY_SINKS {
            return false;
        }
        self.sinks[self.sink_count as usize] = target;
        self.sink_count += 1;
        true
    }

    /// Remove all sink targets.
    pub fn clear_sinks(&mut self) {
        self.sink_count = 0;
    }
}

/// Bounded proxy table with pairing-driven lifecycle.
///
/// Requirement `14-0563-19-A36-02`.
#[derive(Debug)]
pub struct ProxyTable<const N: usize> {
    entries: [Option<ProxyTableEntry>; N],
}

impl<const N: usize> ProxyTable<N> {
    /// Empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    /// Number of populated rows.
    #[must_use]
    pub const fn len(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < N {
            if self.entries[i].is_some() {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// True when no row is populated.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Capacity in rows.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Find the active entry covering one GPD identity.
    #[must_use]
    pub fn find(&self, id: GpdId) -> Option<&ProxyTableEntry> {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.active && e.covers(id))
    }

    /// Find the active entry covering one GPD identity (mutable).
    pub fn find_mut(&mut self, id: GpdId) -> Option<&mut ProxyTableEntry> {
        self.entries
            .iter_mut()
            .flatten()
            .find(|e| e.active && e.covers(id))
    }

    /// Insert or overwrite the entry for one GPD identity.
    ///
    /// Requirement `14-0563-19-A36-02` (pairing add/update).
    pub fn upsert(&mut self, entry: ProxyTableEntry) -> Result<(), GpError> {
        // Prefer the existing row for this identity.
        let mut i = 0;
        while i < N {
            let same = match self.entries[i] {
                Some(e) => {
                    e.id == entry.id && (e.endpoint == entry.endpoint || entry.endpoint == 0xFF)
                }
                None => false,
            };
            if same {
                self.entries[i] = Some(entry);
                return Ok(());
            }
            i += 1;
        }
        let mut j = 0;
        while j < N {
            if self.entries[j].is_none() {
                self.entries[j] = Some(entry);
                return Ok(());
            }
            j += 1;
        }
        Err(GpError::TableFull)
    }

    /// Pairing removal: endpoint-scoped for IEEE-addressed GPDs
    /// (`0xFF` removes every row for the GPD); maintenance-capable
    /// devices deactivate instead when `deactivate` is set.
    ///
    /// Requirement `14-0563-19-A36-02`.
    pub fn pair_remove(&mut self, id: u64, endpoint: u8, deactivate: bool) -> Result<(), GpError> {
        let mut removed = false;
        let mut i = 0;
        while i < N {
            let hit = match self.entries[i] {
                Some(e) => {
                    e.id == id && (endpoint == 0xFF || e.endpoint == 0xFF || e.endpoint == endpoint)
                }
                None => false,
            };
            if hit {
                if deactivate {
                    if let Some(e) = self.entries[i].as_mut() {
                        e.active = false;
                    }
                } else {
                    self.entries[i] = None;
                }
                removed = true;
            }
            i += 1;
        }
        if removed {
            Ok(())
        } else {
            Err(GpError::NotFound)
        }
    }

    /// Paginated table read: only complete entries that fully fit are
    /// reported; holes are skipped; empty tables answer NOT_FOUND.
    ///
    /// Requirement `14-0563-19-A34-02`.
    pub fn read_page(&self, start_index: usize, out: &mut [ProxyTableEntry]) -> PageResult {
        let total = self.len();
        if total == 0 {
            return PageResult {
                total: 0,
                filled: 0,
                done: true,
            };
        }
        let mut skipped = 0;
        let mut filled = 0;
        let mut i = 0;
        while i < N && filled < out.len() {
            if let Some(e) = self.entries[i] {
                if skipped < start_index {
                    skipped += 1;
                } else {
                    out[filled] = e;
                    filled += 1;
                }
            }
            i += 1;
        }
        PageResult {
            total,
            filled,
            done: filled + skipped >= total,
        }
    }
}

impl<const N: usize> Default for ProxyTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of a paginated table read.
///
/// Requirement `14-0563-19-A34-02`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageResult {
    /// Populated rows in the whole table.
    pub total: usize,
    /// Rows written to the caller buffer.
    pub filled: usize,
    /// True when no further rows remain after this page.
    pub done: bool,
}

/// Blocklist of GPD identities refused pairing.
///
/// Requirement `14-0563-19-A34-01` (at least ten entries where
/// supported).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blocklist {
    ids: [u64; MAX_BLOCKED_IDS],
    len: u8,
}

impl Blocklist {
    /// Empty blocklist.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ids: [0; MAX_BLOCKED_IDS],
            len: 0,
        }
    }

    /// True when the identity is listed.
    #[must_use]
    pub const fn contains(&self, id: u64) -> bool {
        let mut i = 0;
        while i < self.len as usize {
            if self.ids[i] == id {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Add an identity; false when already listed or full.
    pub fn add(&mut self, id: u64) -> bool {
        if self.contains(id) {
            return false;
        }
        if (self.len as usize) >= MAX_BLOCKED_IDS {
            return false;
        }
        self.ids[self.len as usize] = id;
        self.len += 1;
        true
    }

    /// Number of listed identities.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// True when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for Blocklist {
    fn default() -> Self {
        Self::new()
    }
}

/// One queued outbound frame per GPD identity with a bounded lifetime.
///
/// Requirement `14-0563-19-A152-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpTxQueueEntry {
    /// Canonical GPD key.
    pub id: u64,
    /// Endpoint scope (`0xFF` = any endpoint).
    pub endpoint: u8,
    /// Queued GPDF octets.
    pub frame: [u8; crate::frame::MAX_GPDF],
    /// Valid octets in `frame`.
    pub frame_len: u8,
    /// Remaining lifetime in caller ticks (cleared at zero).
    pub lifetime: u32,
}

impl GpTxQueueEntry {
    /// True when this entry serves the GPD identity (endpoint-aware).
    #[must_use]
    pub const fn serves(&self, id: u64, endpoint: u8) -> bool {
        self.id == id && (self.endpoint == 0xFF || endpoint == 0xFF || self.endpoint == endpoint)
    }
}

/// Bounded transmit queue: at most one pending frame per GPD.
///
/// Requirement `14-0563-19-A152-01`.
#[derive(Debug)]
pub struct GpTxQueue<const N: usize> {
    entries: [Option<GpTxQueueEntry>; N],
}

impl<const N: usize> GpTxQueue<N> {
    /// Empty queue.
    #[must_use]
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    /// Number of queued frames.
    #[must_use]
    pub const fn len(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < N {
            if self.entries[i].is_some() {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// True when empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Queue-full as reported in tunneled notifications: full means no
    /// entry for this GPD and no empty slot.
    ///
    /// Requirement `14-0563-19-A36-04`.
    #[must_use]
    pub const fn full_for(&self, id: u64) -> bool {
        let mut i = 0;
        while i < N {
            match self.entries[i] {
                Some(e) if e.id == id => return false,
                None => return false,
                _ => {}
            }
            i += 1;
        }
        true
    }

    /// Queue one frame, replacing any previous entry for the GPD.
    ///
    /// Requirement `14-0563-19-A152-01`.
    pub fn enqueue(&mut self, entry: GpTxQueueEntry) -> Result<(), GpError> {
        let mut i = 0;
        while i < N {
            if let Some(e) = self.entries[i] {
                if e.id == entry.id {
                    self.entries[i] = Some(entry);
                    return Ok(());
                }
            }
            i += 1;
        }
        let mut j = 0;
        while j < N {
            if self.entries[j].is_none() {
                self.entries[j] = Some(entry);
                return Ok(());
            }
            j += 1;
        }
        Err(GpError::TableFull)
    }

    /// Remove the entry for one GPD (sent or explicitly cancelled).
    pub fn remove(&mut self, id: u64) -> Result<(), GpError> {
        let mut i = 0;
        while i < N {
            if let Some(e) = self.entries[i] {
                if e.id == id {
                    self.entries[i] = None;
                    return Ok(());
                }
            }
            i += 1;
        }
        Err(GpError::NotFound)
    }

    /// Find the queued entry serving one GPD.
    #[must_use]
    pub fn find(&self, id: u64, endpoint: u8) -> Option<&GpTxQueueEntry> {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.serves(id, endpoint))
    }

    /// Age every entry by `ticks`; expired entries clear.
    ///
    /// Requirement `14-0563-19-A152-01` (bounded lifetime).
    pub fn tick(&mut self, ticks: u32) {
        let mut i = 0;
        while i < N {
            if let Some(mut e) = self.entries[i] {
                e.lifetime = e.lifetime.saturating_sub(ticks);
                if e.lifetime == 0 {
                    self.entries[i] = None;
                } else {
                    self.entries[i] = Some(e);
                }
            }
            i += 1;
        }
    }
}

impl<const N: usize> Default for GpTxQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Proxy commissioning-mode command parameters.
///
/// Requirement `14-0563-19-A36-03`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommissioningModeCmd {
    /// Enter (`true`) or leave (`false`) commissioning mode.
    pub enter: bool,
    /// Channel to listen on while commissioned.
    pub channel: u8,
    /// Exit on the first pairing success.
    pub exit_on_first_pairing: bool,
    /// Commissioning window in caller ticks (zero = no timeout).
    pub window_ticks: u32,
}

/// Proxy commissioning-mode state machine (tick-clocked window).
///
/// Requirement `14-0563-19-A36-03`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyState {
    /// Normal operational mode.
    Operational,
    /// Commissioning mode with remaining window ticks.
    Commissioning {
        /// Remaining window (`u32::MAX` = no timeout).
        remaining: u32,
        /// Exit on the first pairing success.
        exit_on_first_pairing: bool,
    },
}

/// Commissioning-mode handler shared by proxy flavors.
///
/// Requirement `14-0563-19-A36-03`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProxyCommissioning {
    state: ProxyState,
    channel: u8,
}

impl ProxyCommissioning {
    /// Start in operational mode on the given channel.
    #[must_use]
    pub const fn new(channel: u8) -> Self {
        Self {
            state: ProxyState::Operational,
            channel,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> ProxyState {
        self.state
    }

    /// Commissioning channel.
    #[must_use]
    pub const fn channel(&self) -> u8 {
        self.channel
    }

    /// True while commissioned.
    #[must_use]
    pub const fn in_commissioning(&self) -> bool {
        matches!(self.state, ProxyState::Commissioning { .. })
    }

    /// Apply a commissioning-mode command.
    ///
    /// Requirement `14-0563-19-A36-03`.
    pub const fn on_command(&mut self, cmd: CommissioningModeCmd) {
        if !cmd.enter {
            self.state = ProxyState::Operational;
            return;
        }
        self.channel = cmd.channel;
        let remaining = if cmd.window_ticks == 0 {
            u32::MAX
        } else {
            cmd.window_ticks
        };
        self.state = ProxyState::Commissioning {
            remaining,
            exit_on_first_pairing: cmd.exit_on_first_pairing,
        };
    }

    /// Report one pairing event; exits commissioning mode when the
    /// first-pairing-success exit mode is armed.
    ///
    /// Requirement `14-0563-19-A36-03`.
    pub const fn on_pairing(&mut self) {
        if let ProxyState::Commissioning {
            exit_on_first_pairing: true,
            ..
        } = self.state
        {
            self.state = ProxyState::Operational;
        }
    }

    /// Age the commissioning window; expiry returns to operational.
    ///
    /// Requirement `14-0563-19-A36-03`.
    pub const fn tick(&mut self, ticks: u32) {
        if let ProxyState::Commissioning { remaining, .. } = self.state {
            if remaining != u32::MAX {
                let left = remaining.saturating_sub(ticks);
                if left == 0 {
                    self.state = ProxyState::Operational;
                } else {
                    self.state = ProxyState::Commissioning {
                        remaining: left,
                        exit_on_first_pairing: matches!(
                            self.state,
                            ProxyState::Commissioning {
                                exit_on_first_pairing: true,
                                ..
                            }
                        ),
                    };
                }
            }
        }
    }
}

/// Tunneled notification record: the GPD command travels in the
/// clear with no MIC; lower stack layers protect the tunnel.
///
/// Requirement `14-0563-19-A36-04`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProxyNotification {
    /// Canonical GPD key the notification is about.
    pub gpd: u64,
    /// Endpoint from the triggering frame (IEEE identities).
    pub endpoint: u8,
    /// GPD command identifier, in the clear.
    pub command: u8,
    /// Command payload octets, in the clear.
    pub payload: [u8; MAX_NOTIFICATION_PAYLOAD],
    /// Valid payload octets.
    pub payload_len: u8,
    /// Triggering frame asked for a receive window.
    pub rx_after_tx: bool,
    /// This proxy supports bidirectional operation.
    pub bidir_capable: bool,
    /// Queue-full flag as seen for this GPD.
    pub queue_full: bool,
    /// Sink target for this notification copy.
    pub target: SinkTarget,
    /// Alias source address for groupcast copies.
    pub alias: u16,
}

impl ProxyNotification {
    /// Options octet: receive-after-transmit echo, bidirectional
    /// capability, and queue-full status.
    ///
    /// Requirement `14-0563-19-A36-04`.
    #[must_use]
    pub const fn options_byte(&self) -> u8 {
        (self.rx_after_tx as u8)
            | ((self.bidir_capable as u8) << 1)
            | ((self.queue_full as u8) << 2)
    }

    /// Command payload slice.
    #[must_use]
    pub const fn payload_bytes(&self) -> &[u8] {
        self.payload.split_at(self.payload_len as usize).0
    }
}

/// Why the proxy dropped a frame (caller drops silently).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// Codec or ingress-filter rejection.
    Malformed(GpError),
    /// No proxy-table entry covers the GPD.
    NoEntry,
    /// Blocklisted GPD identity.
    Blocked,
    /// Unsupported or mismatching security level/key.
    UnsupportedSecurity,
    /// Replay or duplicate counter.
    Replay,
}

/// Proxy outcome for one received GPDF.
///
/// Requirement `14-0563-19-A38-01` (table, then security, then
/// notify).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyOutcome {
    /// Frame dropped with the recorded reason.
    Drop(DropReason),
    /// Tunneled notification copy ready for the sink target.
    Notify(ProxyNotification),
}

/// Basic proxy role machine: stateless frame processor over the
/// table, replay tracker, and transmit queue.
///
/// Requirement `14-0563-19-A38-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BasicProxy {
    /// Whether this proxy supports bidirectional operation.
    pub bidir_capable: bool,
}

impl BasicProxy {
    /// Build the role machine.
    #[must_use]
    pub const fn new(bidir_capable: bool) -> Self {
        Self { bidir_capable }
    }

    /// Process one decoded GPDF: table lookup, then security and
    /// freshness, then notification construction.
    ///
    /// Requirements `14-0563-19-A38-01`, `-A36-04`, `-A36-05`.
    pub fn process<const PT: usize, const QN: usize, const RN: usize>(
        &self,
        frame: &Gpdf<'_>,
        table: &mut ProxyTable<PT>,
        replay: &mut GpReplay<RN>,
        queue: &GpTxQueue<QN>,
    ) -> ProxyOutcome {
        if let Err(e) = frame.ingress_check() {
            return ProxyOutcome::Drop(DropReason::Malformed(e));
        }
        let (id, command, payload) = match frame.body {
            GpdfBody::Gp { command, payload } => match frame.id {
                Some(id) => (id, command, payload),
                None => {
                    return ProxyOutcome::Drop(DropReason::Malformed(GpError::MissingExtControl));
                }
            },
            GpdfBody::LpedOpaque(_) => {
                return ProxyOutcome::Drop(DropReason::Malformed(GpError::ForeignAppId(
                    AppId::Lped.bits(),
                )));
            }
        };
        let Some(entry) = table.find_mut(id) else {
            return ProxyOutcome::Drop(DropReason::NoEntry);
        };
        // Security gate: level and key must match the table, then the
        // counter must advance.
        let wire = frame
            .ext
            .map_or((WireSecurityLevel::None, false), |e| (e.level, e.key_bit));
        if entry.level != wire.0 || entry.key_bit != wire.1 {
            return ProxyOutcome::Drop(DropReason::UnsupportedSecurity);
        }
        if let Some(counter) = frame.frame_counter {
            if replay.check(id.table_key(), counter).is_err() {
                return ProxyOutcome::Drop(DropReason::Replay);
            }
            entry.counter = counter;
        }
        let rx_after_tx = frame.ext.is_some_and(|e| e.rx_after_tx);
        let mut note = ProxyNotification {
            gpd: id.table_key(),
            endpoint: match id {
                GpdId::SrcId(_) => 0x00,
                GpdId::Ieee { endpoint, .. } => endpoint,
            },
            command,
            payload: [0u8; MAX_NOTIFICATION_PAYLOAD],
            payload_len: 0,
            rx_after_tx,
            bidir_capable: self.bidir_capable,
            queue_full: queue.full_for(id.table_key()),
            target: SinkTarget::Group(0xFFFF),
            alias: entry.alias,
        };
        let take = payload.len().min(MAX_NOTIFICATION_PAYLOAD);
        note.payload[..take].copy_from_slice(&payload[..take]);
        note.payload_len = take as u8;
        // First sink target wins for this notification copy; group
        // fan-out is the caller's loop over `entry` sinks.
        if entry.sink_count > 0 {
            note.target = entry.sinks[0];
        }
        ProxyOutcome::Notify(note)
    }
}
