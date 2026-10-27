//! Abstract 802.15.4 MAC boundary (service access point) traits.
//!
//! The SAP split lets the host path and the C6-standalone path share the
//! core from day one (D3): upper layers talk to these traits, per-target
//! adapters implement them.
#![no_std]
#![forbid(unsafe_code)]

/// Upper-layer view of the MAC data service.
pub trait MacDataSap {
    /// Transmit a frame payload; placeholder signature.
    fn request(&mut self, payload: &[u8]) -> bool;
}

/// Upper-layer view of the MAC management service.
pub trait MacMgmtSap {
    /// Reset the MAC; placeholder signature.
    fn reset(&mut self) -> bool;
}

/// Crate identifier placeholder until implementation lands.
pub fn name() -> &'static str {
    "rounddance-mac-sap"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
    }
}
