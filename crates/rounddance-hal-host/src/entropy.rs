//! Host entropy backend: seeded SplitMix64 for deterministic runs,
//! OS bytes for live tooling.
//!
//! The seeded stream uses the same SplitMix64 constants as
//! [`rounddance_sim::SeededRng`], so a host run with seed `s`
//! draws the identical values as a sim run with `Seed(s)` —
//! cross-harness replay agrees. Seeded draws are `no_std`-safe
//! integer ops only, so the WASM leg replays byte-for-byte.
//!
//! Seeded entropy is for harness decisions (jitter, transaction
//! numbers), never key material: production keys come from the
//! target RNG via the security-crate backend seam.

/// Deterministic host entropy source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostEntropy {
    state: u64,
}

impl HostEntropy {
    /// Entropy stream seeded from `seed`.
    #[must_use]
    pub const fn seeded(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Convenience: stream seeded from a run id.
    #[must_use]
    pub const fn from_run_id(run_id: u64) -> Self {
        Self { state: run_id }
    }

    /// Next `u64` of the stream (SplitMix64, same as sim).
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform value in `0..n` (`n == 0` yields `0`).
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.next_u64() % n
    }
}

/// Fill `buf` from the OS RNG (`/dev/urandom`).
///
/// Live tooling only (native). Deterministic runs — including the
/// WASM replay leg — must use [`HostEntropy::seeded`].
///
/// # Errors
///
/// Propagates file/read errors from the OS source.
#[cfg(not(target_arch = "wasm32"))]
pub fn fill_os(buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read as _;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)?;
    Ok(())
}

impl HostEntropy {
    /// Draw `buf.len()` OS bytes into `buf` (convenience over
    /// [`fill_os`]; live tooling only, native).
    ///
    /// # Errors
    ///
    /// Propagates OS source errors.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_os(buf: &mut [u8]) -> std::io::Result<()> {
        fill_os(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_stream_matches_sim_rng() {
        let mut host = HostEntropy::seeded(7);
        let mut sim = rounddance_sim::SeededRng::new(rounddance_sim::Seed(7));
        for _ in 0..16 {
            assert_eq!(host.next_u64(), sim.next_u64());
        }
    }

    #[test]
    fn below_bounds_and_zero() {
        let mut e = HostEntropy::seeded(1);
        assert_eq!(e.below(0), 0);
        for _ in 0..64 {
            assert!(e.below(100) < 100);
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn os_bytes_fill() {
        let mut buf = [0u8; 32];
        fill_os(&mut buf).unwrap();
        // Not all zero with overwhelming probability.
        assert!(buf.iter().any(|&b| b != 0));
    }
}
