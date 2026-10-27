//! Application support sublayer (APS) scaffold.
#![no_std]
#![forbid(unsafe_code)]

/// Crate identifier placeholder until implementation lands.
pub fn name() -> &'static str {
    "rounddance-aps"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
    }
}
