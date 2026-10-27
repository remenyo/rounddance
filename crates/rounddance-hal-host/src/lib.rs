//! Host HAL stub (Linux/Pi): implements the capability interfaces
//! (radio, clock, RNG, NVM, crypto, log, alloc-budget) for native runs.
//! `std` is allowed here.
#![deny(unsafe_code)]

/// Crate identifier placeholder until implementation lands.
pub fn name() -> &'static str {
    "rounddance-hal-host"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
    }
}
