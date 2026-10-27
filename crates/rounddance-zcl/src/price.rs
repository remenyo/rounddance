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
//! table tests); `07-5123-08-102-01/02` corpus-mined and reused
//! (table readiness + threshold-count shape); `07-5123-08-104-02`
//! corpus-mined and reused (threshold multiplier/divisor pairing);
//! the rest below are repo-minted (`07-5123-08-<clause>-<seq>`,
//! dots stripped), MINTED-pending-confirm. Tariff-information /
//! price-matrix / conversion-factor / calorific / billing /
//! consolidated-bill / CPP / credit-payment / currency-conversion
//! commands stay explicitly follow-up, not silent scope.

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
/// Server received: Get Block Period(s) (start + count [+ tariff]).
pub const CMD_GET_BLOCK_PERIODS: u8 = 0x03;
/// Server received: GetBlockThresholds (issuer tariff id).
pub const CMD_GET_BLOCK_THRESHOLDS: u8 = 0x08;
/// Server generated: PublishPrice (mandatory prefix here).
pub const CMD_PUBLISH_PRICE: u8 = 0x00;
/// Server generated: PublishTierLabels (bounded label list here).
pub const CMD_PUBLISH_TIER_LABELS: u8 = 0x08;
/// Server generated: PublishBlockPeriod (19-octet body here).
pub const CMD_PUBLISH_BLOCK_PERIOD: u8 = 0x01;
/// Server generated: PublishBlockThresholds (header + tier sets).
pub const CMD_PUBLISH_BLOCK_THRESHOLDS: u8 = 0x06;

/// Tariff-type low nibble meaning delivered (request default).
pub const TARIFF_DELIVERED: u8 = 0x00;
/// Tariff-type low nibble meaning received (generation meters).
pub const TARIFF_RECEIVED: u8 = 0x01;

/// Block Period attribute set: start of the current block tariff
/// period (UTC).
pub const ATTR_BLOCK_START: u16 = 0x0200;
/// Block Period attribute set: current period duration (units per
/// duration type).
pub const ATTR_BLOCK_DURATION: u16 = 0x0201;
/// Block Period attribute set: duration timebase + control map.
pub const ATTR_BLOCK_DURATION_TYPE: u16 = 0x0204;

/// Duration timebase: minutes (default; the only base this
/// build advances in clock math).
pub const DUR_BASE_MINUTES: u8 = 0x0;
/// Duration timebase: days.
pub const DUR_BASE_DAYS: u8 = 0x1;
/// Duration timebase: weeks.
pub const DUR_BASE_WEEKS: u8 = 0x2;
/// Duration timebase: months.
pub const DUR_BASE_MONTHS: u8 = 0x3;
/// Duration value meaning "until changed" (24-bit, all set).
pub const BLOCK_DURATION_UNTIL_CHANGED: u32 = 0x00ff_ffff;
/// Start-time value cancelling the matching provider + issuer
/// event instead of scheduling it.
pub const BLOCK_START_CANCEL: u32 = 0xffff_ffff;

/// Largest block-period backlog held (at least two required:
/// current plus upcoming).
pub const MAX_BLOCK_PERIODS: usize = 4;
/// Most block thresholds one tier set carries here (single-set
/// tariffs hold one to fifteen).
pub const MAX_BLOCK_THRESHOLDS: usize = 15;
/// Most tier sets one PublishBlockThresholds carries here.
pub const MAX_TIER_SETS: usize = 4;
/// Most tariff slots the threshold store keeps (delivered +
/// received shapes).
pub const MAX_TARIFF_SLOTS: usize = 2;

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
    CmdDef {
        id: CMD_GET_BLOCK_PERIODS,
        name: "get-block-periods",
    },
    CmdDef {
        id: CMD_GET_BLOCK_THRESHOLDS,
        name: "get-block-thresholds",
    },
];

/// Server generated commands, ascending.
pub static SERVER_TX: &[CmdDef] = &[
    CmdDef {
        id: CMD_PUBLISH_PRICE,
        name: "publish-price",
    },
    CmdDef {
        id: CMD_PUBLISH_BLOCK_PERIOD,
        name: "publish-block-period",
    },
    CmdDef {
        id: CMD_PUBLISH_BLOCK_THRESHOLDS,
        name: "publish-block-thresholds",
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

/// One block-tariff period (19 octets on the wire: 4 + 4 + 4 +
/// 3 + 1 + 1 + 1 + 1).
///
/// Requirement `07-5123-08-1025-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockPeriod {
    /// Commodity provider identifier.
    pub provider_id: u32,
    /// Provider-side event identifier (supersession order).
    pub issuer_event_id: u32,
    /// Period start (`0` = now; `0xFFFFFFFF` = cancel).
    pub start_time: u32,
    /// Period duration in duration-type units (24-bit).
    pub duration: u32,
    /// Block Period Control map (bit 0 = ack required, bit 1 =
    /// repeating block).
    pub control: u8,
    /// Duration timebase (low nibble) + control (high nibble).
    pub duration_type: u8,
    /// Tariff-type bitmap (low nibble selects the tariff).
    pub tariff_type: u8,
    /// Tariff resolution period enumeration.
    pub tariff_resolution: u8,
}

impl BlockPeriod {
    /// Duration timebase sub-field (low nibble).
    #[must_use]
    pub const fn timebase(self) -> u8 {
        self.duration_type & 0x0f
    }

    /// Whether the publisher asks for a PriceAcknowledgement.
    #[must_use]
    pub const fn ack_required(self) -> bool {
        self.control & PRICE_CTRL_ACK_REQUIRED != 0
    }

    /// Whether the block repeats on expiry.
    #[must_use]
    pub const fn repeating(self) -> bool {
        self.control & 0x02 != 0
    }
}

/// Decode a PublishBlockPeriod body (exactly 19 octets).
///
/// Requirement `07-5123-08-1025-01` (MINTED-pending-confirm).
pub fn decode_publish_block_period(buf: &[u8]) -> Result<BlockPeriod, Error> {
    if buf.len() != 19 {
        return Err(Error::Truncated);
    }
    Ok(BlockPeriod {
        provider_id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        issuer_event_id: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        start_time: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        duration: u32::from_le_bytes([buf[12], buf[13], buf[14], 0]),
        control: buf[15],
        duration_type: buf[16],
        tariff_type: buf[17],
        tariff_resolution: buf[18],
    })
}

/// Encode a PublishBlockPeriod body (19 octets).
pub fn encode_publish_block_period(ev: &BlockPeriod, out: &mut [u8]) -> Result<usize, Error> {
    if ev.duration > BLOCK_DURATION_UNTIL_CHANGED {
        return Err(Error::InvalidValue(0xf0));
    }
    if out.len() < 19 {
        return Err(Error::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&ev.provider_id.to_le_bytes());
    out[4..8].copy_from_slice(&ev.issuer_event_id.to_le_bytes());
    out[8..12].copy_from_slice(&ev.start_time.to_le_bytes());
    out[12..15].copy_from_slice(&ev.duration.to_le_bytes()[..3]);
    out[15] = ev.control;
    out[16] = ev.duration_type;
    out[17] = ev.tariff_type;
    out[18] = ev.tariff_resolution;
    Ok(19)
}

/// Decoded Get Block Period(s) request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetBlockPeriods {
    /// Minimum end time to resend (`0` = now).
    pub start_time: u32,
    /// Maximum answers (`0` = no limit).
    pub max_events: u8,
    /// Tariff bitmap, if the client named one (absent =
    /// delivered tariff).
    pub tariff_type: Option<u8>,
}

/// Decode a Get Block Period(s) body (5 octets, or 6 with the
/// optional tariff byte).
///
/// Requirement `07-5123-08-1023-01` (MINTED-pending-confirm).
pub fn decode_get_block_periods(buf: &[u8]) -> Result<GetBlockPeriods, Error> {
    if buf.len() != 5 && buf.len() != 6 {
        return Err(Error::Truncated);
    }
    Ok(GetBlockPeriods {
        start_time: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        max_events: buf[4],
        tariff_type: if buf.len() == 6 { Some(buf[5]) } else { None },
    })
}

/// Period end in seconds, saturating. Only the minutes base
/// advances caller clock math here; other bases never expire in
/// this build (documented honest limit — ordering still applies).
fn block_ends(ev: &BlockPeriod) -> u64 {
    if ev.timebase() != DUR_BASE_MINUTES || ev.duration == BLOCK_DURATION_UNTIL_CHANGED {
        return u64::MAX;
    }
    ev.start_time as u64 + ev.duration as u64 * 60
}

/// Whether two same-provider periods contend for one schedule
/// slot (minutes-base overlap, or identical starts otherwise).
fn blocks_contend(a: &BlockPeriod, b: &BlockPeriod) -> bool {
    if a.provider_id != b.provider_id {
        return false;
    }
    if a.timebase() == DUR_BASE_MINUTES && b.timebase() == DUR_BASE_MINUTES {
        let (s1, e1) = (a.start_time as u64, block_ends(a));
        let (s2, e2) = (b.start_time as u64, block_ends(b));
        return s1 < e2 && s2 < e1;
    }
    a.start_time == b.start_time
}

/// Block-period backlog: current plus upcoming periods with
/// issuer-ordered supersession and provider + issuer cancel.
///
/// Requirements `07-5123-08-102-03` (corpus-mined: at least two
/// block-period commands retained, answered from the backlog) and
/// `07-5123-08-1025-02` (MINTED-pending-confirm: newer issuer id
/// wins; cancel removes the matching event).
#[derive(Clone, Copy, Debug)]
pub struct BlockTable {
    periods: [Option<BlockPeriod>; MAX_BLOCK_PERIODS],
}

impl Default for BlockTable {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockTable {
    /// Empty backlog.
    ///
    /// Requirement `07-5123-08-102-01` (corpus-mined: the table
    /// is ready before any publication goes out).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            periods: [None; MAX_BLOCK_PERIODS],
        }
    }

    /// Period count held.
    #[must_use]
    pub fn len(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < MAX_BLOCK_PERIODS {
            if self.periods[i].is_some() {
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

    /// Insert (or cancel) a period: a cancel start removes the
    /// matching provider + issuer event; a contending older (or
    /// equal) issuer event is dropped; a newer contender drops
    /// the newcomer. A full table evicts the oldest issuer id.
    pub fn insert(&mut self, ev: BlockPeriod) {
        if ev.start_time == BLOCK_START_CANCEL {
            let mut i = 0;
            while i < MAX_BLOCK_PERIODS {
                match self.periods[i] {
                    Some(old)
                        if old.provider_id == ev.provider_id
                            && old.issuer_event_id == ev.issuer_event_id =>
                    {
                        self.periods[i] = None;
                    }
                    _ => {}
                }
                i += 1;
            }
            return;
        }
        let mut i = 0;
        while i < MAX_BLOCK_PERIODS {
            match self.periods[i] {
                Some(old) if blocks_contend(&old, &ev) => {
                    if ev.issuer_event_id > old.issuer_event_id {
                        self.periods[i] = None;
                    } else {
                        return;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        let mut j = 0;
        while j < MAX_BLOCK_PERIODS {
            if self.periods[j].is_none() {
                self.periods[j] = Some(ev);
                return;
            }
            j += 1;
        }
        let mut oldest = 0;
        let mut k = 1;
        while k < MAX_BLOCK_PERIODS {
            let a = self.periods[oldest]
                .map(|e| e.issuer_event_id)
                .unwrap_or(u32::MAX);
            let b = self.periods[k]
                .map(|e| e.issuer_event_id)
                .unwrap_or(u32::MAX);
            if b < a {
                oldest = k;
            }
            k += 1;
        }
        self.periods[oldest] = Some(ev);
    }

    /// Whether `ev` answers tariff filter `want` (low-nibble
    /// compare; `None` wants the delivered tariff).
    fn tariff_matches(ev: &BlockPeriod, want: Option<u8>) -> bool {
        match want {
            Some(t) => ev.tariff_type & 0x0f == t & 0x0f,
            None => ev.tariff_type & 0x0f == TARIFF_DELIVERED,
        }
    }

    /// Periods ending at or after `start` and matching `tariff`,
    /// ascending by end, at most `max` (`0` = no limit).
    pub fn scheduled_since(
        &self,
        start: u32,
        max: u8,
        tariff: Option<u8>,
        out: &mut [BlockPeriod],
    ) -> usize {
        let mut hits: [Option<BlockPeriod>; MAX_BLOCK_PERIODS] = [None; MAX_BLOCK_PERIODS];
        let mut n = 0;
        let mut i = 0;
        while i < MAX_BLOCK_PERIODS {
            if let Some(ev) = self.periods[i] {
                if Self::tariff_matches(&ev, tariff) && block_ends(&ev) >= start as u64 {
                    hits[n] = Some(ev);
                    n += 1;
                }
            }
            i += 1;
        }
        // Insertion-ordered ascending by end (bounded, tiny).
        let mut a = 0;
        while a < n {
            let mut b = a + 1;
            while b < n {
                let ea = block_ends(&hits[a].unwrap_or(BlockPeriod {
                    provider_id: 0,
                    issuer_event_id: 0,
                    start_time: 0,
                    duration: 0,
                    control: 0,
                    duration_type: 0,
                    tariff_type: 0,
                    tariff_resolution: 0,
                }));
                let eb = block_ends(&hits[b].unwrap_or(BlockPeriod {
                    provider_id: 0,
                    issuer_event_id: 0,
                    start_time: 0,
                    duration: 0,
                    control: 0,
                    duration_type: 0,
                    tariff_type: 0,
                    tariff_resolution: 0,
                }));
                if eb < ea {
                    hits.swap(a, b);
                }
                b += 1;
            }
            a += 1;
        }
        let limit = if max == 0 { n } else { (max as usize).min(n) };
        let take = limit.min(out.len());
        let mut k = 0;
        while k < take {
            out[k] = hits[k].unwrap_or(BlockPeriod {
                provider_id: 0,
                issuer_event_id: 0,
                start_time: 0,
                duration: 0,
                control: 0,
                duration_type: 0,
                tariff_type: 0,
                tariff_resolution: 0,
            });
            k += 1;
        }
        take
    }

    /// Best mirror for the Block Period attribute set at `now`:
    /// the covering minutes-base period with the newest issuer
    /// id, else the earliest upcoming start, else anything held.
    pub fn mirror_for(&self, now: u32) -> Option<BlockPeriod> {
        let mut covering: Option<BlockPeriod> = None;
        let mut upcoming: Option<BlockPeriod> = None;
        let mut any: Option<BlockPeriod> = None;
        let mut i = 0;
        while i < MAX_BLOCK_PERIODS {
            if let Some(ev) = self.periods[i] {
                any = Some(ev);
                if ev.timebase() == DUR_BASE_MINUTES
                    && ev.start_time <= now
                    && (now as u64) < block_ends(&ev)
                {
                    let newer = covering
                        .map(|b| ev.issuer_event_id > b.issuer_event_id)
                        .unwrap_or(true);
                    if newer {
                        covering = Some(ev);
                    }
                } else if block_ends(&ev) >= now as u64 {
                    let earlier = upcoming
                        .map(|b| block_ends(&ev) < block_ends(&b))
                        .unwrap_or(true);
                    if earlier {
                        upcoming = Some(ev);
                    }
                }
            }
            i += 1;
        }
        covering.or(upcoming).or(any)
    }
}

/// One tier's block thresholds within a PublishBlockThresholds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TierThresholdSet {
    /// Tier selector map (bit 0 of the sub-payload control says
    /// whether sets name one tier or apply to all tiers).
    pub tier: u8,
    /// Threshold count (1..=15 per the tariff-shape rule).
    pub count: u8,
    /// Threshold values (uint48 each, absolute and increasing).
    pub values: [u64; MAX_BLOCK_THRESHOLDS],
}

impl TierThresholdSet {
    /// Empty set.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            tier: 0,
            count: 0,
            values: [0; MAX_BLOCK_THRESHOLDS],
        }
    }
}

/// Decoded PublishBlockThresholds: 16-octet fixed header plus
/// bounded tier sets.
///
/// Requirement `07-5123-08-1026-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockThresholds {
    /// Commodity provider identifier.
    pub provider_id: u32,
    /// Provider-side event identifier.
    pub issuer_event_id: u32,
    /// Time the payload becomes valid (`0` = immediate).
    pub start_time: u32,
    /// Tariff the thresholds belong to.
    pub issuer_tariff_id: u32,
    /// Fragment index (0-based; fragments share the issuer id).
    pub command_index: u8,
    /// Total fragment count.
    pub total_commands: u8,
    /// Sub-payload control (bit 0 = all-tiers/block-only).
    pub sub_control: u8,
    /// Tier sets carried in this fragment.
    pub set_count: u8,
    /// Tier sets carried in this fragment.
    pub sets: [TierThresholdSet; MAX_TIER_SETS],
}

/// Decode a PublishBlockThresholds body (19-octet fixed header
/// plus tier sets; each set is one Tier/Count octet — tier in
/// the high nibble, or zeroed when the all-tiers control bit is
/// set — followed by that many uint48 thresholds).
///
/// Requirement `07-5123-08-1026-01` (MINTED-pending-confirm).
pub fn decode_publish_block_thresholds(buf: &[u8]) -> Result<BlockThresholds, Error> {
    if buf.len() < 19 {
        return Err(Error::Truncated);
    }
    let index = buf[16];
    let total = buf[17];
    if total == 0 || index >= total {
        return Err(Error::InvalidValue(index));
    }
    let sub_control = buf[18];
    let all_tiers = sub_control & 0x01 != 0;
    let mut msg = BlockThresholds {
        provider_id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        issuer_event_id: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        start_time: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        issuer_tariff_id: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
        command_index: index,
        total_commands: total,
        sub_control,
        set_count: 0,
        sets: [TierThresholdSet::empty(); MAX_TIER_SETS],
    };
    let mut off = 19;
    let mut s = 0;
    while off < buf.len() {
        if s >= MAX_TIER_SETS {
            return Err(Error::TooManyRecords);
        }
        let tier_count = buf[off];
        let tier = tier_count >> 4;
        let count = (tier_count & 0x0f) as usize;
        if all_tiers && tier != 0 {
            return Err(Error::InvalidValue(tier_count));
        }
        // Counts above the tariff-shape ceiling (fifteen) never
        // survive the wire: single-set tariffs hold at most
        // fifteen thresholds.
        if count > MAX_BLOCK_THRESHOLDS || buf.len() < off + 1 + count * 6 {
            return Err(Error::MalformedList);
        }
        let mut set = TierThresholdSet::empty();
        set.tier = if all_tiers { 0 } else { tier };
        set.count = count as u8;
        let mut i = 0;
        while i < count {
            let b = &buf[off + 1 + i * 6..off + 7 + i * 6];
            let mut wide = [0u8; 8];
            wide[..6].copy_from_slice(b);
            set.values[i] = u64::from_le_bytes(wide);
            i += 1;
        }
        msg.sets[s] = set;
        s += 1;
        off += 1 + count * 6;
    }
    msg.set_count = s as u8;
    Ok(msg)
}

/// Encode a PublishBlockThresholds body into `out`.
pub fn encode_publish_block_thresholds(
    msg: &BlockThresholds,
    out: &mut [u8],
) -> Result<usize, Error> {
    if msg.total_commands == 0
        || msg.command_index >= msg.total_commands
        || msg.set_count as usize > MAX_TIER_SETS
    {
        return Err(Error::InvalidValue(msg.command_index));
    }
    let all_tiers = msg.sub_control & 0x01 != 0;
    let mut need = 19usize;
    let mut s = 0;
    while s < msg.set_count as usize {
        let set = &msg.sets[s];
        if set.count as usize > MAX_BLOCK_THRESHOLDS {
            return Err(Error::TooManyRecords);
        }
        if !all_tiers && set.tier > 15 {
            return Err(Error::InvalidValue(set.tier));
        }
        need += 1 + set.count as usize * 6;
        s += 1;
    }
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&msg.provider_id.to_le_bytes());
    out[4..8].copy_from_slice(&msg.issuer_event_id.to_le_bytes());
    out[8..12].copy_from_slice(&msg.start_time.to_le_bytes());
    out[12..16].copy_from_slice(&msg.issuer_tariff_id.to_le_bytes());
    out[16] = msg.command_index;
    out[17] = msg.total_commands;
    out[18] = msg.sub_control;
    let mut off = 19;
    let mut k = 0;
    while k < msg.set_count as usize {
        let set = &msg.sets[k];
        out[off] = if all_tiers {
            set.count & 0x0f
        } else {
            (set.tier << 4) | (set.count & 0x0f)
        };
        let mut i = 0;
        while i < set.count as usize {
            out[off + 1 + i * 6..off + 7 + i * 6]
                .copy_from_slice(&set.values[i].to_le_bytes()[..6]);
            i += 1;
        }
        off += 1 + set.count as usize * 6;
        k += 1;
    }
    Ok(off)
}

/// Threshold store: newest thresholds per tariff slot (current
/// plus next instance capacity per the retention rule).
///
/// Requirement `07-5123-08-1023-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug)]
pub struct ThresholdStore {
    slots: [Option<ThresholdEntry>; MAX_TARIFF_SLOTS],
}

/// One stored threshold instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThresholdEntry {
    /// Commodity provider identifier.
    pub provider_id: u32,
    /// Tariff the thresholds belong to.
    pub tariff_id: u32,
    /// Provider-side event identifier (newer wins).
    pub issuer_event_id: u32,
    /// Time the payload becomes valid.
    pub start_time: u32,
    /// Tier sets stored.
    pub set_count: u8,
    /// Tier sets stored.
    pub sets: [TierThresholdSet; MAX_TIER_SETS],
}

impl Default for ThresholdStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ThresholdStore {
    /// Empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [None, None],
        }
    }

    /// Store a decoded fragment set: same-tariff older-or-equal
    /// issuer ids lose; an unknown tariff takes a free slot, else
    /// evicts the oldest issuer id.
    pub fn insert(&mut self, msg: &BlockThresholds) {
        let mut i = 0;
        while i < MAX_TARIFF_SLOTS {
            match self.slots[i] {
                Some(old) if old.tariff_id == msg.issuer_tariff_id => {
                    if msg.issuer_event_id > old.issuer_event_id {
                        self.slots[i] = Some(ThresholdEntry {
                            provider_id: msg.provider_id,
                            tariff_id: msg.issuer_tariff_id,
                            issuer_event_id: msg.issuer_event_id,
                            start_time: msg.start_time,
                            set_count: msg.set_count,
                            sets: msg.sets,
                        });
                    }
                    return;
                }
                _ => {}
            }
            i += 1;
        }
        let entry = ThresholdEntry {
            provider_id: msg.provider_id,
            tariff_id: msg.issuer_tariff_id,
            issuer_event_id: msg.issuer_event_id,
            start_time: msg.start_time,
            set_count: msg.set_count,
            sets: msg.sets,
        };
        let mut j = 0;
        while j < MAX_TARIFF_SLOTS {
            if self.slots[j].is_none() {
                self.slots[j] = Some(entry);
                return;
            }
            j += 1;
        }
        let mut oldest = 0;
        let mut k = 1;
        while k < MAX_TARIFF_SLOTS {
            let a = self.slots[oldest]
                .map(|e| e.issuer_event_id)
                .unwrap_or(u32::MAX);
            let b = self.slots[k].map(|e| e.issuer_event_id).unwrap_or(u32::MAX);
            if b < a {
                oldest = k;
            }
            k += 1;
        }
        self.slots[oldest] = Some(entry);
    }

    /// Newest entry for `tariff_id`, if any.
    #[must_use]
    pub fn for_tariff(&self, tariff_id: u32) -> Option<ThresholdEntry> {
        let mut i = 0;
        while i < MAX_TARIFF_SLOTS {
            if let Some(e) = self.slots[i] {
                if e.tariff_id == tariff_id {
                    return Some(e);
                }
            }
            i += 1;
        }
        None
    }
}

/// Threshold count for a tariff shape: pure time-of-use tariffs
/// carry zero thresholds; single-set tariffs carry one to
/// fifteen (blocks equal thresholds plus one).
///
/// Requirement `07-5123-08-102-02` (corpus-mined).
#[must_use]
pub const fn threshold_count_for_tariff(tou_only: bool, configured: u8) -> u8 {
    if tou_only {
        return 0;
    }
    if configured == 0 {
        return 1;
    }
    if configured > MAX_BLOCK_THRESHOLDS as u8 {
        return MAX_BLOCK_THRESHOLDS as u8;
    }
    configured
}

/// Scale a raw block threshold by its multiplier/divisor pair
/// (a zero in either yields a unitary factor — the same pairing
/// rule as the metering scale attributes).
///
/// Requirement `07-5123-08-104-02` (corpus-mined).
#[must_use]
pub fn scaled_threshold(raw: u64, multiplier: u64, divisor: u64) -> u64 {
    crate::metering::scaled_value(raw, multiplier, divisor)
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
/// tier-label queries plus ack recording, with the block-period
/// backlog, threshold store, and Block Period attribute mirrors.
pub struct ServerBehavior {
    table: PriceTable,
    blocks: BlockTable,
    thresholds: ThresholdStore,
    block_start: u32,
    block_duration: u32,
    block_duration_type: u8,
}

impl Default for ServerBehavior {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBehavior {
    /// Fresh behavior: empty backlogs, zeroed block mirrors.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            table: PriceTable::new(),
            blocks: BlockTable::new(),
            thresholds: ThresholdStore::new(),
            block_start: 0,
            block_duration: 0,
            block_duration_type: 0,
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

    /// Borrow the block-period backlog.
    pub const fn blocks(&self) -> &BlockTable {
        &self.blocks
    }

    /// Mutable block-period backlog.
    pub fn blocks_mut(&mut self) -> &mut BlockTable {
        &mut self.blocks
    }

    /// Borrow the threshold store.
    pub const fn thresholds(&self) -> &ThresholdStore {
        &self.thresholds
    }

    /// Store a decoded PublishBlockThresholds fragment set
    /// (newer issuer ids win per tariff).
    pub fn thresholds_insert(&mut self, msg: &BlockThresholds) {
        self.thresholds.insert(msg);
    }

    /// Block Period attribute mirrors (`ATTR_BLOCK_START` /
    /// `ATTR_BLOCK_DURATION` / `ATTR_BLOCK_DURATION_TYPE`).
    #[must_use]
    pub const fn block_mirror(&self) -> (u32, u32, u8) {
        (
            self.block_start,
            self.block_duration,
            self.block_duration_type,
        )
    }

    /// Refresh the Block Period mirrors from the backlog at
    /// `now`.
    pub fn refresh_block_mirror(&mut self, now: u32) {
        match self.blocks.mirror_for(now) {
            Some(ev) => {
                self.block_start = ev.start_time;
                self.block_duration = ev.duration;
                self.block_duration_type = ev.duration_type;
            }
            None => {
                self.block_start = 0;
                self.block_duration = 0;
                self.block_duration_type = 0;
            }
        }
    }

    fn emit_block_period(&self, ctx: &mut Ctx<'_>, ev: &BlockPeriod) -> Result<(), ZclStatus> {
        let mut body = [0u8; 19];
        encode_publish_block_period(ev, &mut body).map_err(|_| ZclStatus::InsufficientSpace)?;
        let mut event_payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
        event_payload[..19].copy_from_slice(&body);
        ctx.events.push(AppEvent::OutboundCommand {
            cluster: CLUSTER_ID,
            cmd: CMD_PUBLISH_BLOCK_PERIOD,
            tsn: 0,
            len: 19,
            payload: event_payload,
        });
        Ok(())
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
            CMD_GET_BLOCK_PERIODS => {
                let req =
                    decode_get_block_periods(payload).map_err(|_| ZclStatus::MalformedCommand)?;
                let mut start = req.start_time;
                if start == 0 {
                    start = ctx.now_s as u32;
                }
                let mut hits = [BlockPeriod {
                    provider_id: 0,
                    issuer_event_id: 0,
                    start_time: 0,
                    duration: 0,
                    control: 0,
                    duration_type: 0,
                    tariff_type: 0,
                    tariff_resolution: 0,
                }; MAX_BLOCK_PERIODS];
                let n =
                    self.blocks
                        .scheduled_since(start, req.max_events, req.tariff_type, &mut hits);
                if n == 0 {
                    return Err(ZclStatus::NotFound);
                }
                let mut i = 0;
                while i < n {
                    self.emit_block_period(ctx, &hits[i])?;
                    i += 1;
                }
                Ok(HandleOutcome::no_reply())
            }
            CMD_GET_BLOCK_THRESHOLDS => {
                if payload.len() != 4 {
                    return Err(ZclStatus::MalformedCommand);
                }
                let tariff = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                match self.thresholds.for_tariff(tariff) {
                    Some(entry) => {
                        let msg = BlockThresholds {
                            provider_id: entry.provider_id,
                            issuer_event_id: entry.issuer_event_id,
                            start_time: entry.start_time,
                            issuer_tariff_id: entry.tariff_id,
                            command_index: 0,
                            total_commands: 1,
                            sub_control: 0,
                            set_count: entry.set_count,
                            sets: entry.sets,
                        };
                        let mut body = [0u8; 19 + MAX_TIER_SETS * (1 + MAX_BLOCK_THRESHOLDS * 6)];
                        let n = encode_publish_block_thresholds(&msg, &mut body)
                            .map_err(|_| ZclStatus::InsufficientSpace)?;
                        let mut event_payload = [0u8; crate::behavior::MAX_EVENT_PAYLOAD];
                        let m = n.min(event_payload.len());
                        event_payload[..m].copy_from_slice(&body[..m]);
                        ctx.events.push(AppEvent::OutboundCommand {
                            cluster: CLUSTER_ID,
                            cmd: CMD_PUBLISH_BLOCK_THRESHOLDS,
                            tsn: 0,
                            len: m as u8,
                            payload: event_payload,
                        });
                        Ok(HandleOutcome::no_reply())
                    }
                    None => Err(ZclStatus::NotFound),
                }
            }
            _ => Err(ZclStatus::UnsupCommand),
        }
    }
}
