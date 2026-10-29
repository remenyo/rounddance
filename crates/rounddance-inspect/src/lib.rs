//! Packet inspector: Wireshark-parity Zigbee dissection scaffold.
//!
//! The core (`tree`, `mac`, `nwk`, `aps`, `zcl`, `chain`, `session`,
//! `capture`, `keys`) is `no_std` + `#![forbid(unsafe_code)]` with no
//! allocator: every decode is bounded and fallible, mirroring the codec
//! crates it reuses. Host-only capture file IO (`pcap`) and
//! human/machine reports (`report`) sit behind the `std` feature.
//!
//! Layering: [`chain::dissect`] runs the 802.15.4 MAC dissector, then the
//! reused [`rounddance_nwk`], [`rounddance_aps`], and
//! [`rounddance_zcl`] codecs in order, pushing one [`tree::Layer`]
//! node per successfully parsed header into a [`tree::DecodeTree`]. A
//! secured NWK frame or an unknown cluster payload stops the chain with
//! a terminal node — the bytes are still shown, never silently dropped.
//! Fixed-shape MAC command payloads ([`mac`]), NWK command payloads
//! ([`nwkcmd`]), and the ZDO envelope on profile `0x0000` ([`zdo`])
//! earn named layers of their own.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub mod aps;
pub mod capture;
pub mod chain;
pub mod decrypt;
pub mod keys;
pub mod mac;
pub mod nwk;
pub mod nwkcmd;
pub mod session;
pub mod tree;
pub mod zcl;
pub mod zdo;

#[cfg(feature = "std")]
pub mod pcap;
#[cfg(feature = "std")]
pub mod report;
#[cfg(feature = "std")]
pub mod sniffer;
