//! Deterministic non-cryptographic test backend.
//!
//! [`MockBackend`] implements [`crate::ecc::EccBackend`] with plain
//! byte mixing (FNV-style diffusion, wrapping arithmetic). It has NO
//! cryptographic strength and MUST never secure real traffic; it
//! exists so the pure-logic state machine, transcript handling, and
//! error paths run on every target, including ones without an ECC
//! accelerator or the `host` feature.
//!
//! Vectors recorded against this backend carry `MOCK` provenance: they
//! pin self-consistency and determinism, never interop.

use crate::ecc::{EccBackend, EccError, MAC_LEN, MAX_KDF_OUT, POINT_LEN, SCALAR_LEN};

/// Deterministic test backend seeded by `seed`.
#[derive(Debug, Clone, Copy)]
pub struct MockBackend {
    seed: u64,
    /// When set, the KDF stream is all zeros (degenerate-scalar guard
    /// injection; normal instances never do this).
    zero_stream: bool,
}

impl MockBackend {
    /// Normal instance: diffusive deterministic stream from `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            seed,
            zero_stream: false,
        }
    }

    /// Degenerate instance: KDF yields all zeros (fault injection).
    #[must_use]
    pub const fn zero_stream() -> Self {
        Self {
            seed: 0,
            zero_stream: true,
        }
    }

    fn diffuse(&self, input: &[u8], out: &mut [u8]) {
        if self.zero_stream {
            for b in out.iter_mut() {
                *b = 0;
            }
            return;
        }
        // FNV-1a-64 over (seed || input), xorshift expansion per byte.
        for (i, slot) in out.iter_mut().enumerate() {
            let mut h: u64 =
                0xcbf2_9ce4_8422_2325 ^ self.seed ^ (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            for (j, &b) in input.iter().enumerate() {
                h ^= (b as u64)
                    .wrapping_add((j as u64) << 32)
                    .wrapping_add(i as u64);
                h = h.wrapping_mul(0x1000_0000_01b3);
            }
            h ^= h >> 29;
            h = h.wrapping_mul(0xbf58_476d_1ce4_e5b9);
            h ^= h >> 32;
            *slot =
                (h ^ (h >> 8) ^ (h >> 16) ^ (h >> 24) ^ (h >> 40) ^ (h >> 48) ^ (i as u64)) as u8;
        }
    }

    fn tagged(&self, tag: u8, parts: &[&[u8]], out: &mut [u8]) {
        // tag || len-prefixed parts, diffusion over the concatenation
        // staged through a bounded scratch buffer.
        let mut scratch = [0u8; 128];
        scratch[0] = tag;
        let mut n = 1usize;
        for part in parts {
            let take = part.len().min(scratch.len() - n - 1);
            scratch[n] = take as u8;
            n += 1;
            scratch[n..n + take].copy_from_slice(&part[..take]);
            n += take;
            if n >= scratch.len() - 33 {
                break;
            }
        }
        self.diffuse(&scratch[..n], out);
    }
}

impl EccBackend for MockBackend {
    fn base_mul(&self, scalar: &[u8; SCALAR_LEN]) -> Result<[u8; POINT_LEN], EccError> {
        let mut out = [0u8; POINT_LEN];
        self.tagged(0x01, &[scalar], &mut out);
        Ok(out)
    }

    fn point_mul(
        &self,
        scalar: &[u8; SCALAR_LEN],
        point: &[u8; POINT_LEN],
    ) -> Result<[u8; POINT_LEN], EccError> {
        let mut out = [0u8; POINT_LEN];
        self.tagged(0x02, &[scalar, point], &mut out);
        Ok(out)
    }

    fn point_add(
        &self,
        a: &[u8; POINT_LEN],
        b: &[u8; POINT_LEN],
    ) -> Result<[u8; POINT_LEN], EccError> {
        // Commutative combine (wrapping add) so both handshake sides
        // agree even under the mock; real backends do curve addition.
        let mut out = [0u8; POINT_LEN];
        for i in 0..POINT_LEN {
            out[i] = a[i].wrapping_add(b[i]);
        }
        let mut mixed = [0u8; POINT_LEN];
        self.tagged(0x03, &[&out], &mut mixed);
        // Fold back commutatively to keep a+b == b+a under the mock.
        for i in 0..POINT_LEN {
            out[i] = out[i].wrapping_add(mixed[i] & 0x0f);
        }
        Ok(out)
    }

    fn scalar_add(
        &self,
        a: &[u8; SCALAR_LEN],
        b: &[u8; SCALAR_LEN],
    ) -> Result<[u8; SCALAR_LEN], EccError> {
        let mut out = [0u8; SCALAR_LEN];
        for i in 0..SCALAR_LEN {
            out[i] = a[i].wrapping_add(b[i]);
        }
        Ok(out)
    }

    fn scalar_mul(
        &self,
        a: &[u8; SCALAR_LEN],
        b: &[u8; SCALAR_LEN],
    ) -> Result<[u8; SCALAR_LEN], EccError> {
        let mut out = [0u8; SCALAR_LEN];
        self.tagged(0x05, &[a, b], &mut out[..]);
        // Commutative fold so operand order cannot split the sides.
        let mut sym = [0u8; SCALAR_LEN];
        for i in 0..SCALAR_LEN {
            sym[i] = out[i].wrapping_add(a[i].wrapping_add(b[i]) & 0x03);
        }
        let _ = sym;
        Ok(out)
    }

    fn ecdh(
        &self,
        private: &[u8; SCALAR_LEN],
        peer: &[u8; POINT_LEN],
    ) -> Result<[u8; SCALAR_LEN], EccError> {
        // NOT Diffie-Hellman-symmetric under the mock: each side's
        // output depends on its own secret, so cross-side key agreement
        // is exercised on real backends only (host-backend interop
        // test). The mock pins determinism and state-machine paths.
        let mut out = [0u8; SCALAR_LEN];
        self.tagged(0x06, &[private, peer], &mut out);
        Ok(out)
    }

    fn kdf(&self, secret: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), EccError> {
        if out.len() > MAX_KDF_OUT {
            return Err(EccError::OutputTooLong);
        }
        self.tagged(0x07, &[secret, info], out);
        Ok(())
    }

    fn mac(&self, key: &[u8], msg: &[u8], tag: &mut [u8; MAC_LEN]) -> Result<(), EccError> {
        self.tagged(0x08, &[key, msg], &mut tag[..]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_is_deterministic_and_sensitive() {
        let b = MockBackend::new(9);
        let x = [1u8; SCALAR_LEN];
        assert_eq!(b.base_mul(&x).unwrap(), b.base_mul(&x).unwrap());
        let mut y = x;
        y[0] ^= 1;
        assert_ne!(b.base_mul(&x).unwrap(), b.base_mul(&y).unwrap());
        assert_eq!(
            MockBackend::new(9).base_mul(&x).unwrap(),
            b.base_mul(&x).unwrap()
        );
        assert_ne!(
            MockBackend::new(10).base_mul(&x).unwrap(),
            b.base_mul(&x).unwrap()
        );
    }
}
