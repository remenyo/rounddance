//! ESP HAL stub: per-target shim for ESP32 radios (C6/S3/H2, …).
//!
//! No ESP-IDF dependency yet; that arrives at hardware bring-up.
//! `unsafe` will live here behind SAFETY comments + checklist review,
//! so this crate is `no_std` but NOT `forbid(unsafe_code)`.
#![no_std]

/// Crate identifier placeholder until implementation lands.
pub fn name() -> &'static str {
    "rounddance-hal-esp"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
    }
}
