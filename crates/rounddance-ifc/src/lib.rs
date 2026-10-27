//! Inter-module interface v0 (`docs/ifc/v0/`).
//!
//! Telco-style versioned function boundary shared by every split in the
//! stack: MAC driver vs core, core vs core over USB/UART or IP loopback,
//! sim media, and the management agent. One [`Envelope`] (CBOR-encoded,
//! framed by [`frame`]) crosses all bindings; [`handshake`] negotiates the
//! version once per link; [`credit`] carries backpressure the same way
//! [`MacDataSap`](https://github.com/remenyo/rounddance) queue-free
//! polling does on the MAC SAP.
//!
//! `no_std`, `#![forbid(unsafe_code)]`, zero dependencies. All fallible,
//! all bounded (D5: bounded + fallible + accountable).
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod cbor;
pub mod credit;
pub mod envelope;
pub mod frame;
pub mod handshake;
pub mod ids;
pub mod transport;

/// Interface protocol version negotiated by [`handshake`].
pub const IFC_VERSION: u8 = 0;

/// Largest CBOR envelope payload this revision accepts, in octets.
/// Fits one full 802.15.4 MSDU plus envelope overhead with margin.
pub const IFC_MAX_PAYLOAD: usize = 512;

/// Largest framed body (length field + CBOR + CRC) on the wire.
pub const IFC_MAX_FRAME_BODY: usize = 640;

/// Link-management interface id (iface `0x00`, see [`ids`]).
pub use ids::IF_LINK;

/// Every fallible operation in this crate reports one of these.
/// Variants are observable link/stack states only — never allocator
/// state (D5: no protocol decision depends on allocator state).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IfcError {
    /// Bounded send queue has no free slot (backpressure signal).
    QueueFull,
    /// Payload or frame exceeds [`IFC_MAX_PAYLOAD`] / [`IFC_MAX_FRAME_BODY`].
    FrameTooLong,
    /// Frame CRC mismatch (corrupt byte stream).
    BadCrc,
    /// Byte stream holds no complete frame yet, or framing is malformed.
    BadFrame,
    /// Peer version range does not cover ours (with rejection detail in
    /// the handshake message, not here).
    VersionMismatch,
    /// Envelope names an interface this endpoint does not serve.
    UnknownInterface,
    /// Envelope names an op this interface does not define.
    UnknownOp,
    /// CBOR input ends mid-item or violates the decode budget.
    Truncated,
    /// Transaction revoked before completion.
    Cancelled,
    /// No completion within the caller's timeout budget.
    Timeout,
    /// Link down, handshake incomplete, or endpoint not started.
    NotReady,
    /// Link closed by peer or by reset.
    Closed,
}

impl IfcError {
    /// Human-readable short description (log-safe, no payload bytes).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueueFull => "send queue full",
            Self::FrameTooLong => "frame exceeds maximum length",
            Self::BadCrc => "frame CRC mismatch",
            Self::BadFrame => "malformed frame",
            Self::VersionMismatch => "version negotiation failed",
            Self::UnknownInterface => "unknown interface id",
            Self::UnknownOp => "unknown op id",
            Self::Truncated => "CBOR input truncated",
            Self::Cancelled => "transaction cancelled",
            Self::Timeout => "operation timed out",
            Self::NotReady => "link not ready",
            Self::Closed => "link closed",
        }
    }
}

#[cfg(test)]
mod smoke {
    use super::*;

    const _MTU_ORDERING: () = {
        assert!(IFC_MAX_PAYLOAD <= IFC_MAX_FRAME_BODY);
    };

    #[test]
    fn version_is_zero() {
        assert_eq!(IFC_VERSION, 0);
    }

    #[test]
    fn errors_are_log_safe_words() {
        for e in [
            IfcError::QueueFull,
            IfcError::FrameTooLong,
            IfcError::BadCrc,
            IfcError::BadFrame,
            IfcError::VersionMismatch,
            IfcError::UnknownInterface,
            IfcError::UnknownOp,
            IfcError::Truncated,
            IfcError::Cancelled,
            IfcError::Timeout,
            IfcError::NotReady,
            IfcError::Closed,
        ] {
            assert!(!e.as_str().is_empty());
        }
    }
}
