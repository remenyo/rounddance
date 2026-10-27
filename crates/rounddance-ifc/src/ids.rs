//! Interface / op registry for IFC v0.
//!
//! Interface ids name the deployable function at the far end of the
//! envelope (`docs/ifc/v0/functions.md`). Op ids are per-interface.
//! Interface `0x00` is reserved for link management on every binding.

/// Link management (handshake, keepalive, close). Present on every link.
pub const IF_LINK: u8 = 0x00;
/// 802.15.4 MAC driver function (frames to/from the radio side).
pub const IF_MAC_DRIVER: u8 = 0x01;
/// Network layer function.
pub const IF_NWK: u8 = 0x02;
/// Application support sublayer function.
pub const IF_APS: u8 = 0x03;
/// Zigbee device object function.
pub const IF_ZDO: u8 = 0x04;
/// Security function (keys, counters, CBKE assist).
pub const IF_SECURITY: u8 = 0x05;
/// ZCL engine function (frames + attribute reports).
pub const IF_ZCL_ENGINE: u8 = 0x06;
/// Commissioning function (classical / Touchlink / Direct assists).
pub const IF_COMMISSION: u8 = 0x07;
/// Simulation media function (virtual time, scripted faults).
pub const IF_SIM_MEDIA: u8 = 0x08;
/// Management agent (state query, provisioning, diagnostics).
pub const IF_MGMT_AGENT: u8 = 0x09;

// ---- link-management ops (iface 0x00) ----

/// `HELLO { min_version: u8, max_version: u8 }`. Opens negotiation.
pub const LINK_HELLO: u8 = 0x01;
/// `ACCEPT { chosen: u8 }`. Closes negotiation, link is up.
pub const LINK_ACCEPT: u8 = 0x02;
/// `REJECT { max_supported: u8 }`. Closes negotiation, link stays down.
pub const LINK_REJECT: u8 = 0x03;
/// `PING { nonce: u16 }`. Keepalive probe.
pub const LINK_PING: u8 = 0x04;
/// `PONG { nonce: u16 }`. Keepalive answer, echoes `nonce`.
pub const LINK_PONG: u8 = 0x05;
/// `CLOSE { reason: u8 }`. Orderly shutdown; no reply expected.
pub const LINK_CLOSE: u8 = 0x06;
/// `RESUME { next_seq: u16 }`. Reconnect: "my next receive seq is this".
pub const LINK_RESUME: u8 = 0x07;
