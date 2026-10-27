//! Commissioning scaffold: classical, Touchlink, and Zigbee Direct.
//!
//! Zigbee Direct uses a BLE capability interface (ESP primary); this crate
//! never implements its own Bluetooth stack.
#![no_std]
#![forbid(unsafe_code)]

/// Classical commissioning stub.
pub mod classical {
    /// Stub marker; replaced by the real implementation.
    pub fn name() -> &'static str {
        "classical"
    }
}

/// Touchlink commissioning stub.
pub mod touchlink {
    /// Stub marker; replaced by the real implementation.
    pub fn name() -> &'static str {
        "touchlink"
    }
}

/// Zigbee Direct commissioning stub.
pub mod direct {
    /// Stub marker; replaced by the real implementation.
    pub fn name() -> &'static str {
        "direct"
    }
}

/// Crate identifier placeholder until implementation lands.
pub fn name() -> &'static str {
    "rounddance-commission"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
        assert!(!classical::name().is_empty());
        assert!(!touchlink::name().is_empty());
        assert!(!direct::name().is_empty());
    }
}
