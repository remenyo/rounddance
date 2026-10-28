//! Network (NWK) layer frame codec.
//!
//! General NPDU header encode/decode for Zigbee doc `05-3474-23` R23.2.
//! All wording here is paraphrase; citations name document, revision, and
//! clause only (D1, `SCOPE.md` §2). Implements the fixed header order of
//! Fig. 3-4 (§3.3.1), the frame-control bit layout of Fig. 3-5
//! (§3.3.1.1), and the NLDE-DATA.request header-construction rules of
//! §3.2.1.1.3. Security transforms, routing, and command payloads are
//! out of scope for this codec: it covers header framing only.
//!
//! # Design notes
//!
//! * `no_std` + `#![forbid(unsafe_code)]`, no allocator: decode is
//!   zero-copy (`Decoded::payload` borrows the input), encode writes
//!   into a caller buffer, relay lists live in a fixed-size array.
//! * Every fallible path returns [`Error`]; nothing panics, including on
//!   adversarial input (short buffers, reserved discriminants).
//! * Reserved frame-control bits 14–15 are zeroed on encode and ignored
//!   on decode (reserved-field handling per §1.4.2).
#![no_std]
#![forbid(unsafe_code)]

pub mod commands;
pub mod frame;
pub mod nlde;
pub mod route;

pub use commands::{
    decode_leave, decode_link_status, decode_route_reply, decode_route_request, DecodedLeave,
    DecodedLinkStatus, DecodedRouteReply, DecodedRouteRequest, Error as CommandError, Leave,
    LeaveOptions, LinkStatus, LinkStatusEntry, LinkStatusOptions, ManyToOne, RouteReply,
    RouteReplyOptions, RouteRequest, RouteRequestOptions, CMD_LEAVE, CMD_LINK_STATUS,
    CMD_ROUTE_REPLY, CMD_ROUTE_REQUEST, LINK_COST_MAX_AGE_MS, MAX_LINK_STATUS_ENTRIES,
};
pub use frame::{
    decode, is_broadcast_addr, Decoded, DiscoverRoute, Error as NwkError, FrameControl, FrameType,
    NwkHeader, SourceRoute, BROADCAST_ALL_DEVICES, BROADCAST_LOW_POWER_ROUTERS,
    BROADCAST_RESERVED_HIGH, BROADCAST_RESERVED_LOW, BROADCAST_ROUTERS, BROADCAST_RX_ON_WHEN_IDLE,
    MAX_SOURCE_ROUTE_RELAYS, NWKC_PROTOCOL_VERSION, NWKC_PROTOCOL_VERSION_GP,
    PAN_BROADCAST_LOOPBACK,
};
pub use nlde::{
    build_data_header, indication_for_local, radius_for_request, Error as NldeError,
    NldeDataRequest, TxPipeline,
};
pub use route::{
    add_path_cost, DiscoverySession, DiscoveryTable, NeighborCosts, NeighborLink, RouteEntry,
    RouteError as RoutingError, RouteTable, SeenRequests, DISCOVERY_RETRY_INTERVAL_MS,
    DISCOVERY_TIMEOUT_MS, LINK_COST_AGE_MS, MAX_DISCOVERY_ATTEMPTS, MAX_NEIGHBOR_LINKS,
    MAX_PENDING_DISCOVERIES, MAX_ROUTES, MAX_SEEN_REQUESTS, ROUTE_LIFETIME_MS, SEEN_LIFETIME_MS,
};

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-nwk"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
    }
}
