//! Zigbee Cluster Library (ZCL) scaffold: engine plus cluster trait.
#![no_std]
#![forbid(unsafe_code)]

/// Minimal engine stub: dispatches frames to registered clusters.
pub mod engine {
    /// Stub marker; replaced by the real engine implementation.
    pub fn name() -> &'static str {
        "engine"
    }
}

/// Trait every cluster implementation must satisfy.
pub trait Cluster {
    /// Cluster identifier (e.g. On/Off = 0x0006).
    fn cluster_id(&self) -> u16;
}

/// Crate identifier placeholder until implementation lands.
pub fn name() -> &'static str {
    "rounddance-zcl"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
        assert!(!engine::name().is_empty());
    }
}
