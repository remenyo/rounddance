//! Security layer scaffold: classical security plus Smart Energy / CBKE.
//!
//! Smart Energy + CBKE (certificate parsing, ECDSA, key agreement) is in
//! MVP scope per D4.
#![no_std]
#![forbid(unsafe_code)]

/// Classical Zigbee security (network/key-transport) stub.
pub mod classical {
    /// Stub marker; replaced by the real classical-security implementation.
    pub fn name() -> &'static str {
        "classical"
    }
}

/// Smart Energy / CBKE stub (cert parsing, ECDSA, key agreement).
pub mod cbke {
    /// Stub marker; replaced by the real CBKE implementation.
    pub fn name() -> &'static str {
        "cbke"
    }
}

/// Crate identifier placeholder until implementation lands.
pub fn name() -> &'static str {
    "rounddance-security"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
        assert!(!classical::name().is_empty());
        assert!(!cbke::name().is_empty());
    }
}
