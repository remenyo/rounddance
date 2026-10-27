//! Price cluster (0x0700): server + client definitions, command
//! codecs, and the server event-backlog behavior.
//!
//! Paraphrase-level model of doc `07-5123-08` §10.2 (cluster id
//! anchor p0618-L13901, tier-label set p0620-L13919-L13926, received
//! commands p0640-L14267-L14269, get-current effect p0641-L14290-L14292,
//! scheduled-prices p0641-L14294-L14307, price ack p0642-L14318-L14334,
//! publish-price generation rules p0652-L14615-L14633 with payload
//! figure p0652-L14634-L14638, price-control bit p0657-L14754-L14755,
//! tier-labels request p0647-L14487-L14492 and publish
//! p0671-L15134-L15140). All wording here is paraphrase (D1).
//!
//! Requirement IDs: `07-5123-08-102-03` corpus-mined and reused
//! (minimum-five backlog + `NOT_FOUND` when empty, verified by the
//! table tests); the rest below are repo-minted
//! (`07-5123-08-<clause>-<seq>`, dots stripped),
//! MINTED-pending-confirm. Block-period / threshold / TOU-shape
//! commands (`102-01/02` territory) are explicitly follow-up, not
//! silent scope.

use crate::attrs::{access, AttrDef, AttrStore, ATTR_CLUSTER_REVISION};
use crate::behavior::{AppEvent, Behavior, Ctx, HandleOutcome};
use crate::cluster::{ClusterDef, ClusterRole, CmdDef};
use crate::frame::Header;
use crate::types::{DataType, Value};
use crate::{Error, ZclStatus};

/// Cluster identifier.
///
/// Requirement `07-5123-08-1021-01` (MINTED-pending-confirm).
pub const CLUSTER_ID: u16 = 0x0700;
/// Implemented specification revision (rev table tip).
///
/// Requirement `07-5123-08-1021-02` (MINTED-pending-confirm).
pub const REVISION: u16 = 2;

/// First tier-label attribute (Tier1PriceLabel, octet string).
pub const ATTR_TIER_LABEL_FIRST: u16 = 0x0000;
/// Tier-label attribute count carried here (Tier1..Tier8).
pub const TIER_LABEL_COUNT: usize = 8;
/// Longest rate/tier label text this codec carries (on-wire cap).
pub const MAX_LABEL: usize = 12;

/// Server received: GetCurrentPrice (1-octet options).
pub const CMD_GET_CURRENT_PRICE: u8 = 0x00;
/// Server received: GetScheduledPrices (start + count).
pub const CMD_GET_SCHEDULED_PRICES: u8 = 0x01;
/// Server received: PriceAcknowledgement (provider + issuer + time).
pub const CMD_PRICE_ACK: u8 = 0x02;
/// Server received: GetTierLabels (issuer tariff id).
pub const CMD_GET_TIER_LABELS: u8 = 0x0A;
/// Server generated: PublishPrice (mandatory prefix here).
pub const CMD_PUBLISH_PRICE: u8 = 0x00;
/// Server generated: PublishTierLabels (bounded label list here).
pub const CMD_PUBLISH_TIER_LABELS: u8 = 0x08;

/// GetCurrentPrice options bit: requestor receiver stays on.
pub const OPT_RX_ON_IDLE: u8 = 0x01;
/// Price-control bit: acknowledgement required.
pub const PRICE_CTRL_ACK_REQUIRED: u8 = 0x01;
/// Duration value meaning "until changed".
pub const DURATION_UNTIL_CHANGED: u16 = 0xffff;
/// Largest price-event backlog held (at least five required).
pub const MAX_PRICE_EVENTS: usize = 8;
/// Largest tier-label list one PublishTierLabels carries here.
pub const MAX_TIER_LABELS: usize = 4;

/// Server attribute table: Tier1..Tier8 labels + revision.
///
/// Requirement `07-5123-08-1021-03` (MINTED-pending-confirm). Labels
/// are read-only here: write attempts are refused with `ReadOnly`
/// (the allowed refusal shape; peers must already provision for a
/// `NOT_AUTHORIZED` form, which this build never emits).
pub static SERVER_ATTRS: &[AttrDef] = &[
    AttrDef {
        id: 0x0000,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: 0x0001,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: 0x0002,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: 0x0003,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: 0x0004,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: 0x0005,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: 0x0006,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: 0x0007,
        datatype: DataType::OctetStr.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_CLUSTER_REVISION,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ,
        reportable: false,
    },
];

/// Server received commands, ascending.
pub static SERVER_RX: &[CmdDef] = &[
    CmdDef {
        id: CMD_GET_CURRENT_PRICE,
        name: "get-current-price",
    },
    CmdDef {
        id: CMD_GET_SCHEDULED_PRICES,
        name: "get-scheduled-prices",
    },
    CmdDef {
        id: CMD_PRICE_ACK,
        name: "price-ack",
    },
    CmdDef {
        id: CMD_GET_TIER_LABELS,
        name: "get-tier-labels",
    },
];

/// Server generated commands, ascending.
pub static SERVER_TX: &[CmdDef] = &[
    CmdDef {
        id: CMD_PUBLISH_PRICE,
        name: "publish-price",
    },
    CmdDef {
        id: CMD_PUBLISH_TIER_LABELS,
        name: "publish-tier-labels",
    },
];

/// Server definition.
pub struct ServerDef;
impl ClusterDef for ServerDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "price-server"
    }
    fn revision(&self) -> u16 {
        REVISION
    }
    fn role(&self) -> ClusterRole {
        ClusterRole::Server
    }
    fn attributes(&self) -> &'static [AttrDef] {
        SERVER_ATTRS
    }
    fn received_commands(&self) -> &'static [CmdDef] {
        SERVER_RX
    }
    fn generated_commands(&self) -> &'static [CmdDef] {
        SERVER_TX
    }
}

/// Client definition (no client-side attributes here).
pub struct ClientDef;
impl ClusterDef for ClientDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "price-client"
    }
    fn revision(&self) -> u16 {
        REVISION
    }
    fn role(&self) -> ClusterRole {
        ClusterRole::Client
    }
    fn attributes(&self) -> &'static [AttrDef] {
        &[]
    }
    fn received_commands(&self) -> &'static [CmdDef] {
        SERVER_TX
    }
    fn generated_commands(&self) -> &'static [CmdDef] {
        SERVER_RX
    }
}

/// Default tier-label texts ("Tier 1" .. "Tier 8").
pub const DEFAULT_TIER_LABELS: [&str; TIER_LABEL_COUNT] = [
    "Tier 1", "Tier 2", "Tier 3", "Tier 4", "Tier 5", "Tier 6", "Tier 7", "Tier 8",
];

/// Build a fresh server store with default tier labels.
///
/// Requirement `07-5123-08-1021-03` (MINTED-pending-confirm).
pub fn server_store() -> Result<AttrStore, Error> {
    let mut store = AttrStore::new(None);
    let mut i = 0;
    while i < TIER_LABEL_COUNT {
        let text = DEFAULT_TIER_LABELS[i].as_bytes();
        let mut bytes = [0u8; crate::types::MAX_STR_LEN];
        bytes[..text.len()].copy_from_slice(text);
        store.add(
            SERVER_ATTRS[i],
            Value::OctetStr {
                len: text.len() as u8,
                bytes,
            },
        )?;
        i += 1;
    }
    store.add_globals(REVISION)?;
    Ok(store)
}

/// Read a tier label (0-based index into the carried set).
pub fn tier_label(
    store: &AttrStore,
    index: usize,
) -> Option<(u8, [u8; crate::types::MAX_STR_LEN])> {
    if index >= TIER_LABEL_COUNT {
        return None;
    }
    match store.get(ATTR_TIER_LABEL_FIRST + index as u16) {
        Some(Value::OctetStr { len, bytes }) => Some((len, bytes)),
        _ => None,
    }
}

/// Mandatory PublishPrice prefix (optional command tail is carried
/// as `tail_len`, never interpreted here).
///
/// Requirement `07-5123-08-1024-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishPrice {
    /// Commodity provider identifier.
    pub provider_id: u32,
    /// Rate label text length.
    pub rate_len: u8,
    /// Rate label text bytes.
    pub rate_label: [u8; MAX_LABEL],
    /// Provider-side event identifier (supersession order).
    pub issuer_event_id: u32,
    /// Time the payload was assembled.
    pub current_time: u32,
    /// Unit-of-measure enumeration (mirrors metering coding).
    pub unit_of_measure: u8,
    /// Currency code.
    pub currency: u16,
    /// Price trailing digit (high nibble) + price tier (low nibble).
    pub trailing_tier: u8,
    /// Tier count (high nibble) + register tier (low nibble).
    pub tiers_register: u8,
    /// Event start (0 = immediate).
    pub start_time: u32,
    /// Duration in minutes (`0xffff` = until changed).
    pub duration_min: u16,
    /// Price in currency sub-units scaled by the trailing digit.
    pub price: u32,
}

impl PublishPrice {
    /// Price tier sub-field (low nibble).
    #[must_use]
    pub const fn price_tier(self) -> u8 {
        self.trailing_tier & 0x0f
    }

    /// Trailing-digit sub-field (high nibble).
    #[must_use]
    pub const fn trailing_digit(self) -> u8 {
        self.trailing_tier >> 4
    }

    /// Whether the publisher asks for a PriceAcknowledgement.
    #[must_use]
    pub const fn ack_required(self, control_tail: u8) -> bool {
        control_tail & PRICE_CTRL_ACK_REQUIRED != 0
    }
}

/// Decode the mandatory PublishPrice prefix; `Ok((event, tail))`
/// where `tail` is the unparsed optional-command-tail length.
pub fn decode_publish_price(buf: &[u8]) -> Result<(PublishPrice, usize), Error> {
    if buf.len() < 5 {
        return Err(Error::Truncated);
    }
    let rate_len = buf[4] as usize;
    if rate_len > MAX_LABEL {
        return Err(Error::StringTooLong);
    }
    // 4 provider + 1 len + label + 4 issuer + 4 time + 1 unit + 2
    // currency + 1 trailing + 1 tiers + 4 start + 2 duration + 4 price.
    let need = 28 + rate_len;
    if buf.len() < need {
        return Err(Error::Truncated);
    }
    let mut rate_label = [0u8; MAX_LABEL];
    rate_label[..rate_len].copy_from_slice(&buf[5..5 + rate_len]);
    let b = &buf[5 + rate_len..];
    let ev = PublishPrice {
        provider_id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        rate_len: rate_len as u8,
        rate_label,
        issuer_event_id: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        current_time: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        unit_of_measure: b[8],
        currency: u16::from_le_bytes([b[9], b[10]]),
        trailing_tier: b[11],
        tiers_register: b[12],
        start_time: u32::from_le_bytes([b[13], b[14], b[15], b[16]]),
        duration_min: u16::from_le_bytes([b[17], b[18]]),
        price: u32::from_le_bytes([b[19], b[20], b[21], b[22]]),
    };
    Ok((ev, buf.len() - need))
}

/// Encode the mandatory PublishPrice prefix (no optional tail).
pub fn encode_publish_price(ev: &PublishPrice, out: &mut [u8]) -> Result<usize, Error> {
    let rate_len = ev.rate_len as usize;
    if rate_len > MAX_LABEL {
        return Err(Error::StringTooLong);
    }
    // 28 fixed octets around the label (see decode): 4 + 1 + 4 + 4 +
    // 1 + 2 + 1 + 1 + 4 + 2 + 4.
    let need = 28 + rate_len;
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&ev.provider_id.to_le_bytes());
    out[4] = rate_len as u8;
    out[5..5 + rate_len].copy_from_slice(&ev.rate_label[..rate_len]);
    let b = &mut out[5 + rate_len..];
    b[0..4].copy_from_slice(&ev.issuer_event_id.to_le_bytes());
    b[4..8].copy_from_slice(&ev.current_time.to_le_bytes());
    b[8] = ev.unit_of_measure;
    b[9..11].copy_from_slice(&ev.currency.to_le_bytes());
    b[11] = ev.trailing_tier;
    b[12] = ev.tiers_register;
    b[13..17].copy_from_slice(&ev.start_time.to_le_bytes());
    b[17..19].copy_from_slice(&ev.duration_min.to_le_bytes());
    b[19..23].copy_from_slice(&ev.price.to_le_bytes());
    Ok(need)
}

/// Decode a GetScheduledPrices body (start + count).
pub fn decode_get_scheduled(buf: &[u8]) -> Result<(u32, u8), Error> {
    if buf.len() != 5 {
        return Err(Error::Truncated);
    }
    Ok((u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), buf[4]))
}

/// Decode a PriceAcknowledgement body.
pub fn decode_price_ack(buf: &[u8]) -> Result<(u32, u32, u32, u8), Error> {
    if buf.len() != 13 {
        return Err(Error::Truncated);
    }
    Ok((
        u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        buf[12],
    ))
}

/// Encode a PriceAcknowledgement body (13 octets).
pub fn encode_price_ack(
    provider: u32,
    issuer: u32,
    ack_time: u32,
    control: u8,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < 13 {
        return Err(Error::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&provider.to_le_bytes());
    out[4..8].copy_from_slice(&issuer.to_le_bytes());
    out[8..12].copy_from_slice(&ack_time.to_le_bytes());
    out[12] = control;
    Ok(13)
}

/// Split a price into (whole, divisor) via the trailing digit:
/// value = whole + frac/divisor. Trailing digits above 9 are
/// refused (no 10^10 in `u64` display math here).
pub fn display_parts(price: u32, trailing: u8) -> Option<(u64, u64)> {
    if trailing > 9 {
        return None;
    }
    let mut divisor = 1u64;
    let mut i = 0;
    while i < trailing {
        divisor *= 10;
        i += 1;
    }
    Some((price as u64 / divisor, divisor))
}

/// One tier-label entry of PublishTierLabels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TierLabelEntry {
    /// Tier identifier.
    pub tier_id: u8,
    /// Label length.
    pub len: u8,
    /// Label bytes.
    pub label: [u8; MAX_LABEL],
}

/// Decode PublishTierLabels into caller storage: returns
/// (provider, issuer event, issuer tariff, command index, count).
pub fn decode_publish_tier_labels(
    buf: &[u8],
    out: &mut [TierLabelEntry],
) -> Result<(u32, u32, u32, u8, usize), Error> {
    if buf.len() < 15 {
        return Err(Error::Truncated);
    }
    let provider = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let issuer = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let tariff = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let index = buf[12];
    let _total = buf[13];
    let count = buf[14] as usize;
    if count > MAX_TIER_LABELS || out.len() < count {
        return Err(Error::TooManyRecords);
    }
    let mut off = 15;
    let mut i = 0;
    while i < count {
        if off + 2 > buf.len() {
            return Err(Error::Truncated);
        }
        let tier_id = buf[off];
        let len = buf[off + 1] as usize;
        if len > MAX_LABEL || off + 2 + len > buf.len() {
            return Err(Error::StringTooLong);
        }
        let mut label = [0u8; MAX_LABEL];
        label[..len].copy_from_slice(&buf[off + 2..off + 2 + len]);
        out[i] = TierLabelEntry {
            tier_id,
            len: len as u8,
            label,
        };
        off += 2 + len;
        i += 1;
    }
    Ok((provider, issuer, tariff, index, count))
}

/// Encode PublishTierLabels from caller entries.
pub fn encode_publish_tier_labels(
    provider: u32,
    issuer: u32,
    tariff: u32,
    index: u8,
    total: u8,
    entries: &[TierLabelEntry],
    out: &mut [u8],
) -> Result<usize, Error> {
    if entries.len() > MAX_TIER_LABELS {
        return Err(Error::TooManyRecords);
    }
    if out.len() < 15 {
        return Err(Error::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&provider.to_le_bytes());
    out[4..8].copy_from_slice(&issuer.to_le_bytes());
    out[8..12].copy_from_slice(&tariff.to_le_bytes());
    out[12] = index;
    out[13] = total;
    out[14] = entries.len() as u8;
    let mut off = 15;
    for e in entries {
        let len = e.len as usize;
        if len > MAX_LABEL || out.len() < off + 2 + len {
            return Err(Error::BufferTooSmall);
        }
        out[off] = e.tier_id;
        out[off + 1] = e.len;
        out[off + 2..off + 2 + len].copy_from_slice(&e.label[..len]);
        off += 2 + len;
    }
    Ok(off)
}

/// Server event backlog: newest-first bounded price events with
/// IssuerEventID-ordered supersession.
///
/// Requirements `07-5123-08-102-03` (corpus-mined: at least five
/// events retained, `NOT_FOUND` when empty) + `07-5123-08-1024-02`
/// (MINTED-pending-confirm: the newer issuer id wins overlapping
/// events; an active event overlapped-only-at-its-tail keeps running
/// with `until-changed` duration).
#[derive(Clone, Copy, Debug)]
pub struct PriceTable {
    events: [Option<PublishPrice>; MAX_PRICE_EVENTS],
    last_ack: Option<(u32, u32)>,
}

impl Default for PriceTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PriceTable {
    /// Empty backlog.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: [None; MAX_PRICE_EVENTS],
            last_ack: None,
        }
    }

    /// Event count held.
    #[must_use]
    pub fn len(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < MAX_PRICE_EVENTS {
            if self.events[i].is_some() {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// Whether the backlog is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Event end time, saturating (`until-changed` never ends).
    fn ends(ev: &PublishPrice) -> u64 {
        if ev.duration_min == DURATION_UNTIL_CHANGED {
            u64::MAX
        } else {
            ev.start_time as u64 + ev.duration_min as u64 * 60
        }
    }

    /// Whether two same-provider events overlap in time.
    fn overlaps(a: &PublishPrice, b: &PublishPrice) -> bool {
        if a.provider_id != b.provider_id {
            return false;
        }
        let (s1, e1) = (a.start_time as u64, Self::ends(a));
        let (s2, e2) = (b.start_time as u64, Self::ends(b));
        s1 < e2 && s2 < e1
    }

    /// Publish (or schedule) an event: overlapping same-provider
    /// events with an older-or-equal issuer id are dropped; an event
    /// with a newer issuer id keeps its slot (the newcomer is
    /// dropped instead). When the table is full, the oldest issuer
    /// id is evicted.
    pub fn insert(&mut self, ev: PublishPrice) {
        let mut i = 0;
        while i < MAX_PRICE_EVENTS {
            match self.events[i] {
                Some(old) if Self::overlaps(&old, &ev) => {
                    if ev.issuer_event_id > old.issuer_event_id {
                        // Newer wins; an active predecessor that only
                        // overlaps at its tail keeps running until
                        // the newcomer starts.
                        let active_tail = old.start_time < ev.start_time
                            && Self::ends(&old) > ev.start_time as u64;
                        if active_tail {
                            let mut shortened = old;
                            shortened.duration_min = DURATION_UNTIL_CHANGED;
                            self.events[i] = Some(shortened);
                        } else {
                            self.events[i] = None;
                        }
                    } else {
                        // An equal-or-newer event already covers this
                        // window; the newcomer loses.
                        return;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        // Store into the first free slot, else evict the oldest id.
        let mut j = 0;
        while j < MAX_PRICE_EVENTS {
            if self.events[j].is_none() {
                self.events[j] = Some(ev);
                return;
            }
            j += 1;
        }
        let mut oldest = 0;
        let mut k = 1;
        while k < MAX_PRICE_EVENTS {
            let a = self.events[oldest]
                .map(|e| e.issuer_event_id)
                .unwrap_or(u32::MAX);
            let b = self.events[k]
                .map(|e| e.issuer_event_id)
                .unwrap_or(u32::MAX);
            if b < a {
                oldest = k;
            }
            k += 1;
        }
        self.events[oldest] = Some(ev);
    }

    /// Current event for `now`: the covering event with the newest
    /// issuer id, if any.
    pub fn current(&self, now: u32) -> Option<PublishPrice> {
        let mut best: Option<PublishPrice> = None;
        let mut i = 0;
        while i < MAX_PRICE_EVENTS {
            if let Some(ev) = self.events[i] {
                if ev.start_time <= now && (now as u64) < Self::ends(&ev) {
                    let newer = best
                        .map(|b| ev.issuer_event_id > b.issuer_event_id)
                        .unwrap_or(true);
                    if newer {
                        best = Some(ev);
                    }
                }
            }
            i += 1;
        }
        best
    }

    /// First event ending at or after `start` (scheduled query).
    pub fn first_ending_after(&self, start: u32) -> Option<PublishPrice> {
        let mut best: Option<PublishPrice> = None;
        let mut i = 0;
        while i < MAX_PRICE_EVENTS {
            if let Some(ev) = self.events[i] {
                if Self::ends(&ev) >= start as u64 {
                    let earlier = best
                        .map(|b: PublishPrice| Self::ends(&ev) < Self::ends(&b))
                        .unwrap_or(true);
                    if earlier {
                        best = Some(ev);
                    }
                }
            }
            i += 1;
        }
        best
    }

    /// Record a PriceAcknowledgement (newest ack wins).
    pub fn note_ack(&mut self, provider: u32, issuer: u32) {
        self.last_ack = Some((provider, issuer));
    }

    /// Newest acknowledged (provider, issuer) pair, if any.
    #[must_use]
    pub const fn last_ack(&self) -> Option<(u32, u32)> {
        self.last_ack
    }
}

/// Server behavior: backlog-backed GetCurrentPrice / scheduled /
/// tier-label queries plus ack recording.
pub struct ServerBehavior {
    table: PriceTable,
}

impl Default for ServerBehavior {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBehavior {
    /// Fresh behavior: empty backlog.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            table: PriceTable::new(),
        }
    }

    /// Borrow the backlog (tests/sim preload it).
    pub const fn table(&self) -> &PriceTable {
        &self.table
    }

    /// Mutable backlog.
    pub fn table_mut(&mut self) -> &mut PriceTable {
        &mut self.table
    }
}

impl Behavior for ServerBehavior {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }

    fn handle_cluster_command(
        &mut self,
        ctx: &mut Ctx<'_>,
        _header: &Header,
        command_id: u8,
        payload: &[u8],
    ) -> Result<HandleOutcome, ZclStatus> {
        match command_id {
            CMD_GET_CURRENT_PRICE => {
                if payload.len() != 1 {
                    return Err(ZclStatus::MalformedCommand);
                }
                match self.table.current(ctx.now_s as u32) {
                    Some(ev) => {
                        let mut body = [0u8; 28 + MAX_LABEL];
                        let n = encode_publish_price(&ev, &mut body)
                            .map_err(|_| ZclStatus::InsufficientSpace)?;
                        let mut event_payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
                        event_payload[..n].copy_from_slice(&body[..n]);
                        ctx.events.push(AppEvent::OutboundCommand {
                            cluster: CLUSTER_ID,
                            cmd: CMD_PUBLISH_PRICE,
                            tsn: 0,
                            len: n as u8,
                            payload: event_payload,
                        });
                        Ok(HandleOutcome::no_reply())
                    }
                    None => Err(ZclStatus::NotFound),
                }
            }
            CMD_GET_SCHEDULED_PRICES => {
                let (mut start, count) =
                    decode_get_scheduled(payload).map_err(|_| ZclStatus::MalformedCommand)?;
                if start == 0 {
                    start = ctx.now_s as u32;
                }
                let _ = count;
                match self.table.first_ending_after(start) {
                    Some(ev) => {
                        let mut body = [0u8; 28 + MAX_LABEL];
                        let n = encode_publish_price(&ev, &mut body)
                            .map_err(|_| ZclStatus::InsufficientSpace)?;
                        let mut event_payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
                        event_payload[..n].copy_from_slice(&body[..n]);
                        ctx.events.push(AppEvent::OutboundCommand {
                            cluster: CLUSTER_ID,
                            cmd: CMD_PUBLISH_PRICE,
                            tsn: 0,
                            len: n as u8,
                            payload: event_payload,
                        });
                        Ok(HandleOutcome::no_reply())
                    }
                    None => Err(ZclStatus::NotFound),
                }
            }
            CMD_PRICE_ACK => {
                let (provider, issuer, _time, _control) =
                    decode_price_ack(payload).map_err(|_| ZclStatus::MalformedCommand)?;
                self.table.note_ack(provider, issuer);
                ctx.events.push(AppEvent::StateChanged {
                    cluster: CLUSTER_ID,
                    from: 0,
                    to: 1,
                });
                Ok(HandleOutcome::no_reply())
            }
            CMD_GET_TIER_LABELS => {
                if payload.len() != 4 {
                    return Err(ZclStatus::MalformedCommand);
                }
                let tariff = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let mut entries = [TierLabelEntry {
                    tier_id: 0,
                    len: 0,
                    label: [0; MAX_LABEL],
                }; MAX_TIER_LABELS];
                let mut i = 0;
                while i < MAX_TIER_LABELS {
                    if let Some((len, bytes)) = tier_label(ctx.store, i) {
                        let mut label = [0u8; MAX_LABEL];
                        let n = (len as usize).min(MAX_LABEL);
                        label[..n].copy_from_slice(&bytes[..n]);
                        entries[i] = TierLabelEntry {
                            tier_id: (i + 1) as u8,
                            len: n as u8,
                            label,
                        };
                    }
                    i += 1;
                }
                let mut body = [0u8; 15 + MAX_TIER_LABELS * (2 + MAX_LABEL)];
                let n = encode_publish_tier_labels(1, 1, tariff, 0, 1, &entries, &mut body)
                    .map_err(|_| ZclStatus::InsufficientSpace)?;
                let mut event_payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
                let m = n.min(event_payload.len());
                event_payload[..m].copy_from_slice(&body[..m]);
                ctx.events.push(AppEvent::OutboundCommand {
                    cluster: CLUSTER_ID,
                    cmd: CMD_PUBLISH_TIER_LABELS,
                    tsn: 0,
                    len: m as u8,
                    payload: event_payload,
                });
                Ok(HandleOutcome::no_reply())
            }
            _ => Err(ZclStatus::UnsupCommand),
        }
    }
}
