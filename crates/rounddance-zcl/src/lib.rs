//! Zigbee Cluster Library (ZCL): frame engine, data-type codec,
//! attribute store, command dispatch, reporting, discovery, cluster
//! definitions, behaviors, and the first clusters (On/Off, Level
//! Control, IAS Zone).
//!
//! Three layers: engine (`frame`, `types`, `attrs`, `general`,
//! `reporting`, `dispatch`, `discovery`), definitions (`cluster`),
//! behavior (`behavior`, `onoff`, `level`, `ias_zone`, `ace`, `wd`).
//!
//! Paraphrase-level model of doc `07-5123-08` (ZCL). All wording here
//! is paraphrase; citations name document, revision, and clause/line
//! only (D1, `SCOPE.md` §2).
//!
//! # Design notes (mirror `rounddance-nwk` / `rounddance-aps` /
//! `rounddance-zdo`)
//!
//! * `no_std` + `#![forbid(unsafe_code)]`, no allocator: decode
//!   validates into fixed-size arrays and bounded values (oversize
//!   counts/lengths are rejected instead of growing), encode writes
//!   into caller buffers.
//! * Every fallible path returns a typed error; nothing panics on
//!   adversarial input.
//! * Time is never read here; reporting ticks and behavior timers
//!   take caller seconds (e.g. sim virtual time).
//! * Every public item cites the requirement ID it implements
//!   (corpus-mined `07-5123-08-*` reused verbatim; engine gaps
//!   repo-minted `07-5123-08-<clause>-<seq>` pending mining confirm).
#![no_std]
#![forbid(unsafe_code)]

pub mod ace;
pub mod attrs;
pub mod behavior;
pub mod cluster;
pub mod discovery;
pub mod dispatch;
pub mod electrical;
pub mod frame;
pub mod general;
pub mod ias_zone;
pub mod keyest;
pub mod level;
pub mod metering;
pub mod mirror;
pub mod notify;
pub mod onoff;
pub mod price;
pub mod reporting;
pub mod sampling;
pub mod schedule;
pub mod snapshot;
pub mod status;
pub mod supply;
pub mod types;
pub mod wd;

pub use attrs::{
    access, AttrDef, AttrStore, WriteGuard, ATTR_CLUSTER_REVISION, ATTR_REPORTING_STATUS, MAX_ATTRS,
};
pub use behavior::{AppEvent, Behavior, Ctx, EventQueue, HandleOutcome, MAX_EVENTS};
pub use cluster::{find_generated, find_received, ClusterDef, ClusterRole, CmdDef};
pub use dispatch::{
    check_manufacturer, dispatch, should_default_respond, DispatchOutcome, Endpoint,
    MAX_ENDPOINT_CLUSTERS, MAX_ZCL_PAYLOAD,
};
pub use frame::{Direction, FrameControl, FrameType, Header};
pub use reporting::{change_qualifies, QueryAnswer, ReportSlot, ReportingEngine};
pub use status::ZclStatus;
pub use types::{DataType, Value, MAX_ARRAY_BYTES, MAX_ARRAY_ELEMS, MAX_STR_LEN};

/// Crate identifier.
pub fn name() -> &'static str {
    "rounddance-zcl"
}

/// Fallible-operation errors. Anything adversarial from the wire maps
/// onto these; callers translate to [`ZclStatus`] for responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Input ends before the fixed part of the structure.
    Truncated,
    /// The encode buffer has no room for the structure.
    BufferTooSmall,
    /// A fixed value (frame type, bool, completion flag, …) is out of range.
    InvalidValue(u8),
    /// Header flag and field presence disagree.
    PresenceMismatch,
    /// Unknown data-type identifier on the wire.
    UnknownDatatype(u8),
    /// Recognized type this codec does not carry (composites, …).
    UnsupportedType(u8),
    /// Value's type does not match the attribute/command field.
    TypeMismatch,
    /// A list body fails its structural rule (odd length, …).
    MalformedList,
    /// More records than the bounded output holds.
    TooManyRecords,
    /// String body exceeds [`MAX_STR_LEN`](crate::types::MAX_STR_LEN).
    StringTooLong,
    /// Array body/count exceeds the bounded codec.
    ArrayTooLong,
    /// More attributes than [`MAX_ATTRS`](crate::attrs::MAX_ATTRS).
    TooManyAttributes,
    /// Duplicate attribute registration.
    DuplicateAttribute,
    /// Unknown attribute identifier.
    UnknownAttribute(u16),
    /// More clusters than the endpoint registry holds.
    TooManyClusters,
}
