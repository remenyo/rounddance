//! Metering two-way-mirror notification-scheme machinery (cluster
//! 0x0702): server-generated command codecs plus the mirror-side
//! pending-message engine and the meter-side fetch planner.
//!
//! Paraphrase-level model of doc `07-5123-08` §10.4.2.3.1.9/10/11/12
//! (server command table p0773), the notification attribute set
//! (§10.4.3.2.1), the scheme enumerations (Fig. 10-74, scheme A/B
//! §10.4.4.4.3.4/5), and the two-way-mirror guidelines (§10.4.4.4.3).
//!
//! Pin anchors (page + extraction line): ConfigureMirror payload
//! p0787-L17773-L17774, interval p0787-L17780-L17782, reporting
//! p0788-L17783-L17786, polling p0788-L17796-L17798, receipt effect
//! p0790-L17811-L17816; scheme p0790-L17818-L17828, order
//! p0790-L17830-L17842; flags p0791-L17854-L17864, receipt gating
//! p0792-L17888-L17894; fetch p0792-L17896-L17902, details
//! p0793-L17903-L17909, rules p0793-L17911-L17922; attribute set
//! p0795-L17966-L17980, functional bits p0796-L17983-L17988, price
//! Flags2 p0817-L18632-L18636; schemes Fig. 10-74 p0789-L17802-L17807,
//! scheme A p0817-L18614-L18622, scheme B p0817-L18624-L18634; cache
//! and flag p0815-L18544-L18552, originator tracking
//! p0816-L18567-L18583, timeout p0816-L18556-L18562, stay-awake push
//! p0814-L18526-L18535. All wording here is paraphrase (D1).
//!
//! Requirement IDs below are repo-minted (`07-5123-08-1049-*`, dots
//! stripped), MINTED-pending-confirm.
//!
//! Out of scope on purpose (bounded-opaque, never silent): non-TOU
//! publish shapes behind the waiting flags (calendar / prepayment /
//! device-management flag words and their payloads are carried as raw
//! bits/bytes, never built here); the reporting/poll cadence itself
//! (caller clocks, as everywhere in this crate).

use crate::{Error, ZclStatus};

/// Server generated: ConfigureMirror (two-way operational config).
///
/// Requirement `07-5123-08-1049-01` (MINTED-pending-confirm).
pub const CMD_CONFIGURE_MIRROR: u8 = 0x08;
/// Server generated: ConfigureNotificationScheme (flag-order map).
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
pub const CMD_CONFIGURE_SCHEME: u8 = 0x09;
/// Server generated: ConfigureNotificationFlag(s) (per-flag mapping).
///
/// Requirement `07-5123-08-1049-03` (MINTED-pending-confirm).
pub const CMD_CONFIGURE_FLAG: u8 = 0x0A;
/// Server generated: GetNotifiedMessage (fetch a buffered command).
///
/// Requirement `07-5123-08-1049-05` (MINTED-pending-confirm).
pub const CMD_GET_NOTIFIED_MESSAGE: u8 = 0x0B;

/// No notification scheme defined.
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
pub const SCHEME_NONE: u8 = 0x00;
/// Predefined scheme A (functional flags only).
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
pub const SCHEME_A: u8 = 0x01;
/// Predefined scheme B (functional + Flags2..Flags5).
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
pub const SCHEME_B: u8 = 0x02;
/// First generic (configurable) scheme value.
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
pub const SCHEME_GENERIC_MIN: u8 = 0x03;
/// Last generic (configurable) scheme value.
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
pub const SCHEME_GENERIC_MAX: u8 = 0x80;
/// First MSP-specific scheme value.
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
pub const SCHEME_MSP_MIN: u8 = 0x81;
/// Last MSP-specific scheme value.
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
pub const SCHEME_MSP_MAX: u8 = 0xFE;
/// Reserved scheme value: never configured.
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
pub const SCHEME_RESERVED: u8 = 0xFF;

/// Scheme A flag order: functional flags first, the rest blank.
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
pub const SCHEME_A_ORDER: u32 = 0x0FFF_FFFF;
/// Scheme B flag order: functional + Flags2..Flags5, the rest blank.
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
pub const SCHEME_B_ORDER: u32 = 0x0123_4FFF;

/// Flag-order nibble meaning "no flag in this position".
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
pub const ORDER_BLANK: u8 = 0x0F;
/// Notification flag attribute count (functional + Flags2..8).
///
/// Requirement `07-5123-08-1049-04` (MINTED-pending-confirm).
pub const MAX_FLAGS: usize = 8;
/// First notification-flag attribute (functional, map32).
///
/// Requirement `07-5123-08-1049-04` (MINTED-pending-confirm).
pub const ATTR_FUNCTIONAL: u16 = 0x0000;
/// Last notification-flag attribute (Flags8, map32).
///
/// Requirement `07-5123-08-1049-04` (MINTED-pending-confirm).
pub const ATTR_FLAG8: u16 = 0x0007;

/// Functional flag: stay-awake request (HAN side).
///
/// Requirement `07-5123-08-1049-04` (MINTED-pending-confirm).
pub const FUNC_STAY_AWAKE_HAN: u8 = 4;
/// Functional flag: stay-awake request (WAN side).
///
/// Requirement `07-5123-08-1049-04` (MINTED-pending-confirm).
pub const FUNC_STAY_AWAKE_WAN: u8 = 5;
/// Functional flag: waiting ChangeSupply.
///
/// Requirement `07-5123-08-1049-04` (MINTED-pending-confirm).
pub const FUNC_CHANGE_SUPPLY: u8 = 18;
/// Functional flag: waiting LocalChangeSupply.
///
/// Requirement `07-5123-08-1049-04` (MINTED-pending-confirm).
pub const FUNC_LOCAL_CHANGE_SUPPLY: u8 = 19;
/// Functional flag: waiting flow-threshold update.
///
/// Requirement `07-5123-08-1049-04` (MINTED-pending-confirm).
pub const FUNC_FLOW_THRESHOLD: u8 = 20;
/// Functional flag: waiting snapshot retrieval.
///
/// Requirement `07-5123-08-1049-04` (MINTED-pending-confirm).
pub const FUNC_GET_SNAPSHOT: u8 = 22;
/// Functional flag: waiting sampled-data retrieval.
///
/// Requirement `07-5123-08-1049-04` (MINTED-pending-confirm).
pub const FUNC_GET_SAMPLED_DATA: u8 = 23;

/// Price Flags2 bit: PublishPrice waiting.
///
/// Requirement `07-5123-08-1049-04` (MINTED-pending-confirm).
pub const PRICE2_PUBLISH_PRICE: u8 = 0;
/// Price Flags2 bit: PublishBlockPeriod waiting.
///
/// Requirement `07-5123-08-1049-04` (MINTED-pending-confirm).
pub const PRICE2_BLOCK_PERIOD: u8 = 1;
/// Price Flags2 bit: PublishBlockThresholds waiting.
///
/// Requirement `07-5123-08-1049-04` (MINTED-pending-confirm).
pub const PRICE2_BLOCK_THRESHOLDS: u8 = 9;
/// Price Flags2 bit: PublishTierLabels waiting.
///
/// Requirement `07-5123-08-1049-04` (MINTED-pending-confirm).
pub const PRICE2_TIER_LABELS: u8 = 14;
/// Price Flags2 bit: CancelTariff waiting.
///
/// Requirement `07-5123-08-1049-04` (MINTED-pending-confirm).
pub const PRICE2_CANCEL_TARIFF: u8 = 15;

/// Largest allocation records one ConfigureFlag carries here.
///
/// Requirement `07-5123-08-1049-03` (MINTED-pending-confirm).
pub const MAX_ALLOC_RECORDS: usize = 4;
/// Largest command ids one allocation record carries here.
///
/// Requirement `07-5123-08-1049-03` (MINTED-pending-confirm).
pub const MAX_ALLOC_CMDS: usize = 8;
/// Largest pending-message queue on the mirror here.
///
/// Requirement `07-5123-08-1049-05` (MINTED-pending-confirm).
pub const MAX_PENDING: usize = 4;
/// Largest buffered command payload kept per pending entry here.
///
/// Requirement `07-5123-08-1049-05` (MINTED-pending-confirm).
pub const MAX_PENDING_PAYLOAD: usize = 24;

/// Whether a scheme value names something configurable: predefined
/// A/B, generic, or MSP. `NONE` and `RESERVED` are refused.
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
#[must_use]
pub const fn scheme_usable(scheme: u8) -> bool {
    matches!(
        scheme,
        SCHEME_A
            | SCHEME_B
            | SCHEME_GENERIC_MIN..=SCHEME_GENERIC_MAX
            | SCHEME_MSP_MIN..=SCHEME_MSP_MAX
    )
}

/// Whether a scheme is predefined (immutable: scheme/flag commands
/// targeting it are refused).
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
#[must_use]
pub const fn scheme_predefined(scheme: u8) -> bool {
    matches!(scheme, SCHEME_A | SCHEME_B)
}

/// Classify one flag-order nibble: `0..=7` names flag attribute
/// `0..=7`, `ORDER_BLANK` names no flag, anything else is reserved.
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
#[must_use]
pub const fn order_flag(nibble: u8) -> Option<Option<u8>> {
    if nibble <= 0x07 {
        Some(Some(nibble))
    } else if nibble == ORDER_BLANK {
        Some(None)
    } else {
        None
    }
}

/// Whether a 32-bit flag-order word carries only defined nibbles.
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
#[must_use]
pub const fn order_valid(order: u32) -> bool {
    let mut i = 0;
    while i < 8 {
        let nibble = ((order >> (4 * i)) & 0x0F) as u8;
        if order_flag(nibble).is_none() {
            return false;
        }
        i += 1;
    }
    true
}

/// ConfigureMirror body: two-way operational configuration.
///
/// Requirement `07-5123-08-1049-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigureMirror {
    /// Issuer event id (newer information replaces older).
    pub issuer: u32,
    /// ReportAttribute cadence in seconds (uint24 on the wire).
    pub interval_s: u32,
    /// When set, the mirror answers reports with
    /// MirrorReportAttributeResponse; when clear, the meter polls
    /// the flag attributes with reads instead.
    pub reporting: bool,
    /// Notification scheme to use.
    pub scheme: u8,
}

/// Encode a ConfigureMirror body into `out` (9 octets).
pub fn encode_configure_mirror(cfg: &ConfigureMirror, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 9 {
        return Err(Error::BufferTooSmall);
    }
    if cfg.interval_s > 0x00FF_FFFF {
        return Err(Error::InvalidValue(0));
    }
    out[..4].copy_from_slice(&cfg.issuer.to_le_bytes());
    out[4..7].copy_from_slice(&cfg.interval_s.to_le_bytes()[..3]);
    out[7] = u8::from(cfg.reporting);
    out[8] = cfg.scheme;
    Ok(9)
}

/// Decode a ConfigureMirror body: exactly 9 octets.
pub fn decode_configure_mirror(buf: &[u8]) -> Result<ConfigureMirror, Error> {
    if buf.len() != 9 {
        return Err(Error::Truncated);
    }
    if buf[7] > 1 {
        return Err(Error::InvalidValue(buf[7]));
    }
    Ok(ConfigureMirror {
        issuer: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        interval_s: u32::from_le_bytes([buf[4], buf[5], buf[6], 0]),
        reporting: buf[7] != 0,
        scheme: buf[8],
    })
}

/// ConfigureNotificationScheme body: staged flag-order map.
///
/// Requirement `07-5123-08-1049-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigureScheme {
    /// Issuer event id (newer information replaces older).
    pub issuer: u32,
    /// Scheme the order applies to.
    pub scheme: u8,
    /// Flag order: 8 nibbles, each a flag index or blank.
    pub order: u32,
}

/// Encode a ConfigureNotificationScheme body into `out` (9 octets).
pub fn encode_configure_scheme(cfg: &ConfigureScheme, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 9 {
        return Err(Error::BufferTooSmall);
    }
    if !order_valid(cfg.order) {
        return Err(Error::InvalidValue(0));
    }
    out[..4].copy_from_slice(&cfg.issuer.to_le_bytes());
    out[4] = cfg.scheme;
    out[5..9].copy_from_slice(&cfg.order.to_le_bytes());
    Ok(9)
}

/// Decode a ConfigureNotificationScheme body: exactly 9 octets with
/// a defined-nibble order word.
pub fn decode_configure_scheme(buf: &[u8]) -> Result<ConfigureScheme, Error> {
    if buf.len() != 9 {
        return Err(Error::Truncated);
    }
    let order = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]);
    if !order_valid(order) {
        return Err(Error::InvalidValue(buf[8]));
    }
    Ok(ConfigureScheme {
        issuer: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        scheme: buf[4],
        order,
    })
}

/// One bit-field allocation record: the (cluster, manufacturer,
/// command) set behind one notification flag.
///
/// Requirement `07-5123-08-1049-03` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlagAlloc {
    /// Cluster the waiting commands belong to.
    pub cluster: u16,
    /// Manufacturer code used with these command ids.
    pub mfr: u16,
    /// Command ids mapped to the flag.
    pub cmds: [u8; MAX_ALLOC_CMDS],
    /// Significant command ids in `cmds`.
    pub cmd_count: u8,
}

impl FlagAlloc {
    /// Whether `cmd` is mapped by this record.
    #[must_use]
    pub const fn maps(&self, cmd: u8) -> bool {
        let mut i = 0;
        while i < self.cmd_count as usize {
            if self.cmds[i] == cmd {
                return true;
            }
            i += 1;
        }
        false
    }
}

/// ConfigureNotificationFlag body: issuer + scheme + flag attribute
/// plus the bit-field allocation records behind that flag.
///
/// Requirement `07-5123-08-1049-03` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigureFlag {
    /// Issuer event id (newer information replaces older).
    pub issuer: u32,
    /// Scheme the mapping applies to.
    pub scheme: u8,
    /// Flag attribute id configured (`0..=7`: functional..Flags8).
    pub flag_attr: u16,
    /// Allocation records behind the flag.
    pub allocs: [FlagAlloc; MAX_ALLOC_RECORDS],
    /// Significant records in `allocs`.
    pub alloc_count: u8,
}

const fn empty_alloc() -> FlagAlloc {
    FlagAlloc {
        cluster: 0,
        mfr: 0,
        cmds: [0; MAX_ALLOC_CMDS],
        cmd_count: 0,
    }
}

impl ConfigureFlag {
    /// Empty configuration for `flag_attr` under `scheme`.
    #[must_use]
    pub const fn new(issuer: u32, scheme: u8, flag_attr: u16) -> Self {
        Self {
            issuer,
            scheme,
            flag_attr,
            allocs: [empty_alloc(); MAX_ALLOC_RECORDS],
            alloc_count: 0,
        }
    }
}

/// Encode a ConfigureNotificationFlag body: 7-octet header plus
/// 5 octets per record plus its command ids.
pub fn encode_configure_flag(cfg: &ConfigureFlag, out: &mut [u8]) -> Result<usize, Error> {
    if cfg.flag_attr > ATTR_FLAG8 {
        return Err(Error::InvalidValue(0));
    }
    if cfg.alloc_count as usize > MAX_ALLOC_RECORDS || cfg.alloc_count == 0 {
        return Err(Error::InvalidValue(cfg.alloc_count));
    }
    let mut need = 7usize;
    let mut r = 0;
    while r < cfg.alloc_count as usize {
        let rec = &cfg.allocs[r];
        if rec.cmd_count as usize > MAX_ALLOC_CMDS || rec.cmd_count == 0 {
            return Err(Error::InvalidValue(rec.cmd_count));
        }
        need += 5 + rec.cmd_count as usize;
        r += 1;
    }
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    out[..4].copy_from_slice(&cfg.issuer.to_le_bytes());
    out[4] = cfg.scheme;
    out[5..7].copy_from_slice(&cfg.flag_attr.to_le_bytes());
    let mut off = 7;
    r = 0;
    while r < cfg.alloc_count as usize {
        let rec = &cfg.allocs[r];
        out[off..off + 2].copy_from_slice(&rec.cluster.to_le_bytes());
        out[off + 2..off + 4].copy_from_slice(&rec.mfr.to_le_bytes());
        out[off + 4] = rec.cmd_count;
        let n = rec.cmd_count as usize;
        out[off + 5..off + 5 + n].copy_from_slice(&rec.cmds[..n]);
        off += 5 + n;
        r += 1;
    }
    Ok(need)
}

/// Decode a ConfigureNotificationFlag body into `cfg`.
pub fn decode_configure_flag(buf: &[u8], cfg: &mut ConfigureFlag) -> Result<(), Error> {
    if buf.len() < 7 + 5 + 1 {
        return Err(Error::Truncated);
    }
    let flag_attr = u16::from_le_bytes([buf[5], buf[6]]);
    if flag_attr > ATTR_FLAG8 {
        return Err(Error::InvalidValue(buf[6]));
    }
    let mut allocs = [empty_alloc(); MAX_ALLOC_RECORDS];
    let mut count = 0usize;
    let mut off = 7;
    while off < buf.len() {
        if count >= MAX_ALLOC_RECORDS {
            return Err(Error::InvalidValue(count as u8));
        }
        if buf.len() - off < 6 {
            return Err(Error::Truncated);
        }
        let n = buf[off + 4] as usize;
        if n == 0 || n > MAX_ALLOC_CMDS {
            return Err(Error::InvalidValue(buf[off + 4]));
        }
        if buf.len() - off - 5 < n {
            return Err(Error::Truncated);
        }
        let mut cmds = [0u8; MAX_ALLOC_CMDS];
        cmds[..n].copy_from_slice(&buf[off + 5..off + 5 + n]);
        allocs[count] = FlagAlloc {
            cluster: u16::from_le_bytes([buf[off], buf[off + 1]]),
            mfr: u16::from_le_bytes([buf[off + 2], buf[off + 3]]),
            cmds,
            cmd_count: n as u8,
        };
        count += 1;
        off += 5 + n;
    }
    cfg.issuer = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    cfg.scheme = buf[4];
    cfg.flag_attr = flag_attr;
    cfg.allocs = allocs;
    cfg.alloc_count = count as u8;
    Ok(())
}

/// GetNotifiedMessage body: which buffered commands the BOMD wants.
///
/// Requirement `07-5123-08-1049-05` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetNotifiedMessage {
    /// Notification scheme in use.
    pub scheme: u8,
    /// Flag attribute id requested (`0..=7`).
    pub flag_attr: u16,
    /// Flag bits requested (commands being fetched).
    pub flags: u32,
}

/// Encode a GetNotifiedMessage body into `out` (7 octets).
pub fn encode_get_notified(msg: &GetNotifiedMessage, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 7 {
        return Err(Error::BufferTooSmall);
    }
    if msg.flag_attr > ATTR_FLAG8 {
        return Err(Error::InvalidValue(0));
    }
    out[0] = msg.scheme;
    out[1..3].copy_from_slice(&msg.flag_attr.to_le_bytes());
    out[3..7].copy_from_slice(&msg.flags.to_le_bytes());
    Ok(7)
}

/// Decode a GetNotifiedMessage body: exactly 7 octets.
pub fn decode_get_notified(buf: &[u8]) -> Result<GetNotifiedMessage, Error> {
    if buf.len() != 7 {
        return Err(Error::Truncated);
    }
    let flag_attr = u16::from_le_bytes([buf[1], buf[2]]);
    if flag_attr > ATTR_FLAG8 {
        return Err(Error::InvalidValue(buf[2]));
    }
    Ok(GetNotifiedMessage {
        scheme: buf[0],
        flag_attr,
        flags: u32::from_le_bytes([buf[3], buf[4], buf[5], buf[6]]),
    })
}

/// Originator record for one buffered command: the minimum the
/// mirror keeps to relay the BOMD's response back.
///
/// Requirement `07-5123-08-1049-05` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Originator {
    /// Originating device address.
    pub src: u64,
    /// Originating endpoint.
    pub endpoint: u8,
    /// Transaction sequence of the received command.
    pub tsn: u8,
    /// Cluster of the buffered command.
    pub cluster: u16,
    /// Command id of the buffered command.
    pub cmd: u8,
}

/// One mirror-cached command awaiting BOMD retrieval.
///
/// Requirement `07-5123-08-1049-05` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingEntry {
    /// Who sent the command (for response relay + timeout).
    pub origin: Originator,
    /// Buffered command payload (bounded; longer commands are a
    /// field error at cache time, never grown).
    pub payload: [u8; MAX_PENDING_PAYLOAD],
    /// Buffered payload length.
    pub len: u8,
    /// Caller seconds when cached (for timeout expiry).
    pub at_s: u64,
}

/// Cache verdict: the caller-facing Default Response for the
/// initiating device.
///
/// Requirement `07-5123-08-1049-05` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheVerdict {
    /// Buffered: the caller answers `NOTIFICATION_PENDING`.
    Pending,
    /// Queue full: the caller answers `INSUFFICIENT_SPACE`.
    Full,
}

impl CacheVerdict {
    /// Receipt-side status for this verdict.
    #[must_use]
    pub const fn status(self) -> ZclStatus {
        match self {
            Self::Pending => ZclStatus::NotificationPending,
            Self::Full => ZclStatus::InsufficientSpace,
        }
    }
}

/// Mirror-side notification engine: staged scheme configuration,
/// live flag words, and the bounded pending-message queue.
///
/// Requirement `07-5123-08-1049-05` (MINTED-pending-confirm): the
/// mirror caches HAN commands for a sleeping BOMD, sets the mapped
/// flag bit, and hands the oldest matching command to each
/// GetNotifiedMessage; bits clear once their commands drain; stale
/// entries expire for `TIMEOUT` answers.
#[derive(Clone, Copy, Debug)]
pub struct MirrorNotify {
    scheme: u8,
    interval_s: u32,
    reporting: bool,
    mirror_issuer: u32,
    staged_scheme: u8,
    staged_order: u32,
    staged_issuer: u32,
    staged_allocs: [[FlagAlloc; MAX_ALLOC_RECORDS]; MAX_FLAGS],
    staged_counts: [u8; MAX_FLAGS],
    enabled: bool,
    raised: [u32; MAX_FLAGS],
    pending: [Option<PendingEntry>; MAX_PENDING],
    pending_len: u8,
}

impl Default for MirrorNotify {
    fn default() -> Self {
        Self::new()
    }
}

impl MirrorNotify {
    /// Fresh engine: no scheme, no flags, empty queue.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            scheme: SCHEME_NONE,
            interval_s: 0,
            reporting: false,
            mirror_issuer: 0,
            staged_scheme: SCHEME_NONE,
            staged_order: 0xFFFF_FFFF,
            staged_issuer: 0,
            staged_allocs: [[empty_alloc(); MAX_ALLOC_RECORDS]; MAX_FLAGS],
            staged_counts: [0; MAX_FLAGS],
            enabled: false,
            raised: [0; MAX_FLAGS],
            pending: [None; MAX_PENDING],
            pending_len: 0,
        }
    }

    /// Active notification scheme.
    #[must_use]
    pub const fn scheme(&self) -> u8 {
        self.scheme
    }

    /// Whether two-way retrieval is currently enabled.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Configured reporting interval in seconds.
    #[must_use]
    pub const fn interval_s(&self) -> u32 {
        self.interval_s
    }

    /// Whether MirrorReportAttributeResponse is enabled (else the
    /// meter polls the flag attributes with reads).
    #[must_use]
    pub const fn reporting(&self) -> bool {
        self.reporting
    }

    /// Queued command count.
    #[must_use]
    pub const fn pending_len(&self) -> usize {
        self.pending_len as usize
    }

    /// Live flag words: raised event bits plus queue-derived bits.
    #[must_use]
    pub const fn flag_words(&self) -> [u32; MAX_FLAGS] {
        let mut out = [0u32; MAX_FLAGS];
        let mut i = 0;
        while i < MAX_FLAGS {
            out[i] = self.raised[i] | self.queued_bits(i);
            i += 1;
        }
        out
    }

    /// Queue-derived bits for flag word `idx` (recomputed from the
    /// live queue, so drained bits clear on their own).
    const fn queued_bits(&self, idx: usize) -> u32 {
        let mut bits = 0u32;
        let mut i = 0;
        while i < MAX_PENDING {
            if let Some(entry) = self.pending[i] {
                if let Some(bit) = self.entry_bit(idx, &entry) {
                    bits |= 1u32 << bit;
                }
            }
            i += 1;
        }
        bits
    }

    /// Flag bit carrying `entry` in word `idx`, if the active scheme
    /// maps it: predefined functional bits for the implemented
    /// server-on-BOMD commands, staged allocations for generic/MSP
    /// schemes, else the stay-awake fallback for non-specified
    /// transient commands.
    const fn entry_bit(&self, idx: usize, entry: &PendingEntry) -> Option<u8> {
        if idx != 0 && !self.generic_active() {
            return None;
        }
        if self.generic_active() {
            let flag = idx as u8;
            let mut r = 0;
            while r < self.staged_counts[flag as usize] as usize {
                let rec = &self.staged_allocs[flag as usize][r];
                if rec.cluster == entry.origin.cluster && rec.maps(entry.origin.cmd) {
                    // Bit position follows the mapped command's slot
                    // in the concatenated allocation lists (repo
                    // construction: the allocation order is the bit
                    // order).
                    let mut bit = 0usize;
                    let mut s = 0;
                    while s < r {
                        bit += self.staged_allocs[flag as usize][s].cmd_count as usize;
                        s += 1;
                    }
                    let mut k = 0;
                    while k < rec.cmd_count as usize {
                        if rec.cmds[k] == entry.origin.cmd {
                            return Some((bit + k) as u8);
                        }
                        k += 1;
                    }
                }
                r += 1;
            }
            return None;
        }
        if idx != 0 {
            return None;
        }
        // Predefined schemes: functional word only (scheme A carries
        // nothing else; scheme B's price words are raised by the
        // application as publish information appears).
        if entry.origin.cluster == crate::metering::CLUSTER_ID {
            match entry.origin.cmd {
                crate::supply::CMD_CHANGE_SUPPLY => Some(FUNC_CHANGE_SUPPLY),
                crate::supply::CMD_LOCAL_CHANGE_SUPPLY => Some(FUNC_LOCAL_CHANGE_SUPPLY),
                crate::supply::CMD_SET_UNCONTROLLED_FLOW => Some(FUNC_FLOW_THRESHOLD),
                _ => Some(FUNC_STAY_AWAKE_HAN),
            }
        } else {
            Some(FUNC_STAY_AWAKE_HAN)
        }
    }

    /// Whether a staged generic/MSP scheme is the active one.
    const fn generic_active(&self) -> bool {
        !scheme_predefined(self.scheme)
            && self.scheme != SCHEME_NONE
            && self.scheme == self.staged_scheme
    }

    /// Apply a ConfigureMirror: issuer-ordered; an unsupported
    /// scheme answers `INVALID_FIELD`; stale issuers are ignored.
    /// Predefined schemes enable two-way retrieval at once;
    /// generic/MSP schemes wait for their staged configuration.
    pub fn apply_configure_mirror(&mut self, cfg: &ConfigureMirror) -> Result<(), ZclStatus> {
        if !scheme_usable(cfg.scheme) {
            return Err(ZclStatus::InvalidField);
        }
        if cfg.issuer < self.mirror_issuer {
            return Ok(());
        }
        self.mirror_issuer = cfg.issuer;
        self.scheme = cfg.scheme;
        self.interval_s = cfg.interval_s;
        self.reporting = cfg.reporting;
        self.enabled = scheme_predefined(cfg.scheme) || self.staged_complete(cfg.scheme);
        Ok(())
    }

    /// Apply a ConfigureNotificationScheme: predefined schemes are
    /// immutable (`INVALID_FIELD`); otherwise the order is staged
    /// under issuer ordering.
    pub fn apply_scheme(&mut self, cfg: &ConfigureScheme) -> Result<(), ZclStatus> {
        if scheme_predefined(cfg.scheme) || !scheme_usable(cfg.scheme) {
            return Err(ZclStatus::InvalidField);
        }
        if cfg.issuer < self.staged_issuer {
            return Ok(());
        }
        self.staged_issuer = cfg.issuer;
        self.staged_scheme = cfg.scheme;
        self.staged_order = cfg.order;
        self.enabled = self.scheme == cfg.scheme && self.staged_complete(cfg.scheme);
        Ok(())
    }

    /// Apply a ConfigureNotificationFlag: predefined schemes are
    /// immutable; the flag attribute must name flags 1..8 and the
    /// staged scheme; issuer ordering is per flag attribute so
    /// retransmitted heads do not clobber newer mappings.
    pub fn apply_flag(&mut self, cfg: &ConfigureFlag) -> Result<(), ZclStatus> {
        if scheme_predefined(cfg.scheme) || !scheme_usable(cfg.scheme) {
            return Err(ZclStatus::InvalidField);
        }
        if cfg.flag_attr > ATTR_FLAG8 {
            return Err(ZclStatus::InvalidField);
        }
        if cfg.scheme != self.staged_scheme {
            return Err(ZclStatus::InvalidField);
        }
        if cfg.alloc_count as usize > MAX_ALLOC_RECORDS || cfg.alloc_count == 0 {
            return Err(ZclStatus::InvalidField);
        }
        let idx = cfg.flag_attr as usize;
        self.staged_allocs[idx] = cfg.allocs;
        self.staged_counts[idx] = cfg.alloc_count;
        self.enabled = self.scheme == cfg.scheme && self.staged_complete(cfg.scheme);
        Ok(())
    }

    /// Whether every non-blank flag in the staged order for `scheme`
    /// has at least one allocation record.
    fn staged_complete(&self, scheme: u8) -> bool {
        if scheme != self.staged_scheme {
            return false;
        }
        let mut i = 0;
        while i < 8 {
            let nibble = ((self.staged_order >> (4 * i)) & 0x0F) as u8;
            match order_flag(nibble) {
                None => return false,
                Some(Some(flag)) => {
                    if self.staged_counts[flag as usize] == 0 {
                        return false;
                    }
                }
                Some(None) => {}
            }
            i += 1;
        }
        true
    }

    /// Raise application event bits (publish information staged on
    /// the mirror, mechanism-two flows). Queue-derived bits are
    /// untouched.
    pub fn raise(&mut self, flag_attr: u16, mask: u32) -> Result<(), ZclStatus> {
        if flag_attr > ATTR_FLAG8 {
            return Err(ZclStatus::InvalidField);
        }
        self.raised[flag_attr as usize] |= mask;
        Ok(())
    }

    /// Lower application event bits once the BOMD retrieved them.
    pub fn lower(&mut self, flag_attr: u16, mask: u32) -> Result<(), ZclStatus> {
        if flag_attr > ATTR_FLAG8 {
            return Err(ZclStatus::InvalidField);
        }
        self.raised[flag_attr as usize] &= !mask;
        Ok(())
    }

    /// Cache one HAN command for the BOMD: idempotent on
    /// (source, endpoint, TSN, cluster, command); a full queue
    /// refuses. The mapped flag bit sets on success.
    pub fn cache(&mut self, origin: Originator, payload: &[u8], now_s: u64) -> CacheVerdict {
        if payload.len() > MAX_PENDING_PAYLOAD {
            return CacheVerdict::Full;
        }
        let mut i = 0;
        while i < MAX_PENDING {
            if let Some(entry) = &self.pending[i] {
                if entry.origin == origin {
                    return CacheVerdict::Pending;
                }
            }
            i += 1;
        }
        if self.pending_len as usize >= MAX_PENDING {
            return CacheVerdict::Full;
        }
        let mut body = [0u8; MAX_PENDING_PAYLOAD];
        body[..payload.len()].copy_from_slice(payload);
        let entry = PendingEntry {
            origin,
            payload: body,
            len: payload.len() as u8,
            at_s: now_s,
        };
        let mut i = 0;
        while i < MAX_PENDING {
            if self.pending[i].is_none() {
                self.pending[i] = Some(entry);
                self.pending_len += 1;
                break;
            }
            i += 1;
        }
        CacheVerdict::Pending
    }

    /// Fetch the oldest command matching `msg` (scheme + flag word +
    /// bits must agree with the active configuration). Queue-derived
    /// bits with no remaining commands clear on their own; a fetch
    /// naming only drained or unknown bits answers `NOT_FOUND`.
    pub fn fetch(&mut self, msg: &GetNotifiedMessage) -> Result<PendingEntry, ZclStatus> {
        if msg.scheme != self.scheme {
            return Err(ZclStatus::InvalidField);
        }
        if msg.flag_attr > ATTR_FLAG8 || msg.flags == 0 {
            return Err(ZclStatus::InvalidField);
        }
        let idx = msg.flag_attr as usize;
        let mut best: Option<usize> = None;
        let mut i = 0;
        while i < MAX_PENDING {
            if let Some(entry) = &self.pending[i] {
                if let Some(bit) = self.entry_bit(idx, entry) {
                    if msg.flags & (1u32 << bit) != 0 {
                        match best {
                            None => best = Some(i),
                            Some(b) => {
                                if let Some(prev) = &self.pending[b] {
                                    if entry.at_s < prev.at_s {
                                        best = Some(i);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            i += 1;
        }
        match best {
            Some(slot) => {
                let entry = self.pending[slot].take().expect("slot held an entry");
                self.pending_len -= 1;
                Ok(entry)
            }
            None => Err(ZclStatus::NotFound),
        }
    }

    /// Expire entries older than `timeout_s` (caller seconds; the
    /// timeout itself is operator policy, never prescribed here).
    /// Returns the originators owed a `TIMEOUT` Default Response,
    /// oldest first.
    pub fn expire(&mut self, now_s: u64, timeout_s: u64, out: &mut [Originator]) -> usize {
        let mut n = 0;
        // Collect-then-clear: two passes keep the slot scan simple
        // and bounded.
        let mut i = 0;
        while i < MAX_PENDING {
            let ripe = match &self.pending[i] {
                Some(entry) => now_s.saturating_sub(entry.at_s) > timeout_s,
                None => false,
            };
            if ripe && n < out.len() {
                if let Some(entry) = self.pending[i].take() {
                    out[n] = entry.origin;
                    n += 1;
                    self.pending_len -= 1;
                }
            }
            i += 1;
        }
        n
    }
}

/// Meter-side (BOMD) notification record: the scheme this meter
/// configured plus the latest flag report from the mirror.
///
/// Requirement `07-5123-08-1049-06` (MINTED-pending-confirm): the
/// BOMD stays in control of when it fetches — reports never
/// auto-fetch; the application plans `GetNotifiedMessage` commands
/// from the set flag bits it understands.
#[derive(Clone, Copy, Debug)]
pub struct BomdNotify {
    scheme: u8,
    issuer: u32,
    report: crate::mirror::MirrorReport,
}

impl Default for BomdNotify {
    fn default() -> Self {
        Self::new()
    }
}

impl BomdNotify {
    /// Fresh record: no scheme, no flags.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            scheme: SCHEME_NONE,
            issuer: 0,
            report: crate::mirror::MirrorReport::new(SCHEME_NONE),
        }
    }

    /// Scheme this meter last configured.
    #[must_use]
    pub const fn scheme(&self) -> u8 {
        self.scheme
    }

    /// Latest flag report from the mirror.
    #[must_use]
    pub const fn report(&self) -> &crate::mirror::MirrorReport {
        &self.report
    }

    /// Remember a ConfigureMirror this meter emitted (issuer-ordered;
    /// stale echoes never move the record backwards).
    pub fn note_configured(&mut self, cfg: &ConfigureMirror) {
        if cfg.issuer >= self.issuer {
            self.issuer = cfg.issuer;
            self.scheme = cfg.scheme;
        }
    }

    /// Stash the latest MirrorReportAttributeResponse flags.
    pub fn note_report(&mut self, report: &crate::mirror::MirrorReport) {
        self.report = *report;
    }

    /// Plan `GetNotifiedMessage` fetches for the set functional bits
    /// behind buffered server-on-BOMD commands (ChangeSupply,
    /// LocalChangeSupply, flow threshold). Returns the planned
    /// count; publish-information bits (price/calendar words) are
    /// fetched with their own Get commands by application policy,
    /// never here.
    pub fn plan_fetch(&self, out: &mut [GetNotifiedMessage]) -> usize {
        const FETCHABLE: u32 = (1u32 << FUNC_CHANGE_SUPPLY)
            | (1u32 << FUNC_LOCAL_CHANGE_SUPPLY)
            | (1u32 << FUNC_FLOW_THRESHOLD);
        if self.report.count == 0 || out.is_empty() {
            return 0;
        }
        let word = self.report.flags[0] & FETCHABLE;
        if word == 0 || self.report.scheme != self.scheme {
            return 0;
        }
        out[0] = GetNotifiedMessage {
            scheme: self.scheme,
            flag_attr: ATTR_FUNCTIONAL,
            flags: word,
        };
        1
    }
}
