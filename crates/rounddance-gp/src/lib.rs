//! Green Power (GP) proxy + sink: GPDF frame codec, security wiring,
//! translation-table commissioning first, proxy/sink role machines.
//!
//! Paraphrase-level model of doc `14-0563-19` Green Power Basic v1.1.2
//! (§A.1 frame formats, §A.1.5 stub processing, §A.1.6 GPD behavior,
//! §A.3.4 proxy/sink attributes, §A.3.5 basic proxy/combo operation,
//! §A.3.6 proxy/sink operation, §A.3.7 SDL behavior, §A.3.8 basic-proxy
//! flow, §A.3.9 commissioning). All wording here is paraphrase;
//! citations name document, revision, and clause/line only (D1,
//! `SCOPE.md` §2).
//!
//! # Design notes (mirror `rounddance-nwk` / `rounddance-aps` /
//! `rounddance-security` / `rounddance-commission`)
//!
//! * `no_std` + `#![forbid(unsafe_code)]`, bounded + fallible +
//!   accountable: decode is zero-copy (`command_payload` borrows the
//!   input), encode writes into caller buffers, tables and queues live
//!   in fixed-size arrays; every fallible path returns a typed error.
//! * Thin security layer: frame-counter tracking and replay protection
//!   reuse [`rounddance_security`] primitives (`ReplayTable`,
//!   `FrameCounter`); this crate only builds GP nonces, key-type
//!   records, and per-GPD counter slots on top of them.
//! * Time is always an injected tick (`u64`): queue lifetimes and
//!   commissioning windows never read a wall clock, so sim virtual
//!   time drives them deterministically.
//! * Every public item cites the requirement ID it implements
//!   (corpus-mined `14-0563-19-*`; repo-minted IDs would carry
//!   MINTED-pending-confirm — this wave mints none).
//! * Bidirectional commissioning completion (responses to the GPD)
//!   lives in [`commissioning`] (session) + [`reply`] (codecs): the
//!   sink stages a reply, serves it inside the receive window, and
//!   completes on the GPD's Success frame or a bounded timeout.
#![no_std]
#![forbid(unsafe_code)]

pub mod commissioning;
pub mod frame;
pub mod proxy;
pub mod receive;
pub mod reply;
pub mod security;
pub mod sink;

pub use commissioning::{
    check_bidir_capable, is_commissioning_command, CommissioningAnnouncement, CommissioningError,
    CommissioningSession, CommissioningState, TranslationSeed, COMMISSIONING_RANGE_END,
    COMMISSIONING_RANGE_START, REPLY_TIMEOUT_MS,
};
pub use frame::{
    AppId, ExtFrameControl, FrameType, GpError, GpdId, Gpdf, GpdfBody, NwkFrameControl,
    WireSecurityLevel, COUNT_MIC_LEN, FRAME_COUNTER_LEN, GP_ENDPOINT, MAX_GPDF, MAX_GPD_PAYLOAD,
    PROTOCOL_VERSION,
};
pub use proxy::{
    BasicProxy, Blocklist, CommissioningModeCmd, DropReason, GpTxQueue, GpTxQueueEntry,
    ProxyCommissioning, ProxyError, ProxyNotification, ProxyOutcome, ProxyState, ProxyTable,
    ProxyTableEntry, SinkTarget, BASIC_PROXY_FUNCTIONALITY, BASIC_TX_QUEUE_LEN, FULL_TX_QUEUE_LEN,
    MAX_BLOCKED_IDS, MAX_NOTIFICATION_PAYLOAD, MAX_PROXY_SINKS, MIN_BASIC_TX_QUEUE,
    MIN_BLOCKLIST_LEN, MIN_FULL_TX_QUEUE, TX_DURATION_MS, TX_OFFSET_MAX_MS, TX_OFFSET_MS,
};
pub use receive::{
    open_secured, receive, GpKeySlot, GpKeySlots, NwkHandoff, NwkRoute, SinkDecision, MAX_GP_OPEN,
    MAX_GP_SLOTS,
};
pub use reply::{
    is_payloadless_commissioning, ChannelConfig, ChannelRequest, CommissioningReply, ReplyOptions,
    CMD_CHANNEL_CONFIG, CMD_CHANNEL_REQUEST, CMD_COMMISSIONING, CMD_COMMISSIONING_REPLY,
    CMD_DECOMMISSIONING, CMD_SUCCESS,
};
pub use security::{
    GpKey, GpKeyType, GpNonce, GpReplay, GpSecurityLevel, NONCE_CONTROL_LEVEL, NONCE_LEN,
};
pub use sink::{
    PayloadMode, SinkError, SinkMachine, SinkOutcome, SinkTable, SinkTableEntry, TranslatedCommand,
    TranslationTable, TranslationTableEntry, VectorOption, COMPACT_ATTR_REPORT_CMD,
    COMPACT_SENSOR_GROUP_CMD, GENERIC_GPD_COMMAND, GENERIC_SRC_ID, MAX_TRANSLATION_PAYLOAD,
};

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-gp"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
    }
}
