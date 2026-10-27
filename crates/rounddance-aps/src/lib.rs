//! Application support sublayer (APS): APDU frame codec,
//! fragmentation/reassembly, acknowledged-transmission retries, and
//! binding/group table stubs.
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2 chapter 2. All
//! wording here is paraphrase; citations name document, revision, and
//! clause/line only (D1, `SCOPE.md` §2).
//!
//! # Design notes (mirror `rounddance-nwk`)
//!
//! * `no_std` + `#![forbid(unsafe_code)]`, no allocator: decode is
//!   zero-copy, encode writes into caller buffers, tables and
//!   reassembly slots live in fixed-size arrays.
//! * Every fallible path returns a typed error; nothing panics on
//!   adversarial input.
//! * Time is always an injected tick (`u64`): the retry machine and
//!   the reassembly window never read a wall clock, so sim virtual
//!   time drives them deterministically.
//! * Every public item cites the requirement ID it implements
//!   (`05-3474-23-<clause>-<seq>`, dots stripped — repo-minted pending
//!   seed extraction of chapter 2).
#![no_std]
#![forbid(unsafe_code)]

pub mod frag;
pub mod frame;
pub mod retry;
pub mod status;
pub mod tables;

pub use frag::{
    plan_transmit, rx_timeout_ticks, FeedOutcome, FragError, PeerFragCaps, Reassembler, TxBlocks,
    TxPlan, MAX_ASDU_OCTETS, MAX_BLOCKS_PER_RX, MAX_BLOCK_PAYLOAD, MAX_RX_TRANSACTIONS,
};
pub use frame::{
    decode_ack, decode_command, decode_data, peek_frame_type, AckAddr, AckHeader, CommandHeader,
    DataDest, DataHeader, DecodedAck, DecodedCommand, DecodedData, DeliveryMode, Error as ApsError,
    ExtHeader, Fragmentation, FrameControl, FrameType, ENDPOINT_BROADCAST_ALL, ENDPOINT_ZDO,
    MAX_APP_ENDPOINT,
};
pub use retry::{
    AckExpect, AckInfo, DupRejectTable, RetrySession, RetryVerdict, DUP_TABLE_SIZE,
    MAX_FRAME_RETRIES, MIN_DUP_TABLE_SIZE,
};
pub use status::{ApsStatus, StatusError};
pub use tables::{BindingDst, BindingEntry, BindingTable, GroupTable, MAX_BINDINGS, MAX_GROUPS};

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-aps"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
    }
}
