//! Host reference backend: `p256` + `sha2` + `hmac`.
//!
//! Available only with the `host` feature (host/sim use). Production
//! targets plug their own [`crate::ecc::EccBackend`] (e.g. PSA on
//! ESP); the core never depends on this module.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::ff::PrimeField;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{ProjectivePoint, PublicKey, Scalar};
use sha2::{Digest, Sha256};

use crate::ecc::{EccBackend, EccError, MAC_LEN, MAX_KDF_OUT, POINT_LEN, SCALAR_LEN};

/// Reference backend over RustCrypto P-256.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostBackend;

impl HostBackend {
    /// Fresh instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

fn to_scalar(bytes: &[u8; SCALAR_LEN]) -> Result<Scalar, EccError> {
    // Zero is not a usable secret/exponent anywhere in this crate.
    if *bytes == [0u8; SCALAR_LEN] {
        return Err(EccError::InvalidScalar);
    }
    Option::<Scalar>::from(Scalar::from_repr((*bytes).into())).ok_or(EccError::InvalidScalar)
}

fn to_public(point: &[u8; POINT_LEN]) -> Result<PublicKey, EccError> {
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(point);
    PublicKey::from_sec1_bytes(&sec1).map_err(|_| EccError::InvalidPoint)
}

fn to_uncompressed(p: &ProjectivePoint) -> Result<[u8; POINT_LEN], EccError> {
    // Identity has no coordinates: report it instead of panicking on
    // adversarial input.
    let enc = p.to_affine().to_sec1_point(false);
    let (Some(x), Some(y)) = (enc.x(), enc.y()) else {
        return Err(EccError::InvalidPoint);
    };
    let mut out = [0u8; POINT_LEN];
    out[..32].copy_from_slice(x);
    out[32..].copy_from_slice(y);
    Ok(out)
}

impl EccBackend for HostBackend {
    fn base_mul(&self, scalar: &[u8; SCALAR_LEN]) -> Result<[u8; POINT_LEN], EccError> {
        let s = to_scalar(scalar)?;
        to_uncompressed(&(ProjectivePoint::GENERATOR * s))
    }

    fn point_mul(
        &self,
        scalar: &[u8; SCALAR_LEN],
        point: &[u8; POINT_LEN],
    ) -> Result<[u8; POINT_LEN], EccError> {
        let s = to_scalar(scalar)?;
        let p = ProjectivePoint::from(*to_public(point)?.as_affine());
        to_uncompressed(&(p * s))
    }

    fn point_add(
        &self,
        a: &[u8; POINT_LEN],
        b: &[u8; POINT_LEN],
    ) -> Result<[u8; POINT_LEN], EccError> {
        let pa = ProjectivePoint::from(*to_public(a)?.as_affine());
        let pb = ProjectivePoint::from(*to_public(b)?.as_affine());
        to_uncompressed(&(pa + pb))
    }

    fn scalar_add(
        &self,
        a: &[u8; SCALAR_LEN],
        b: &[u8; SCALAR_LEN],
    ) -> Result<[u8; SCALAR_LEN], EccError> {
        let sum = to_scalar(a)? + to_scalar(b)?;
        Ok(sum.to_bytes().into())
    }

    fn scalar_mul(
        &self,
        a: &[u8; SCALAR_LEN],
        b: &[u8; SCALAR_LEN],
    ) -> Result<[u8; SCALAR_LEN], EccError> {
        let prod = to_scalar(a)? * to_scalar(b)?;
        Ok(prod.to_bytes().into())
    }

    fn ecdh(
        &self,
        private: &[u8; SCALAR_LEN],
        peer: &[u8; POINT_LEN],
    ) -> Result<[u8; SCALAR_LEN], EccError> {
        // Shared secret is the x-coordinate of `private * peer`.
        let full = self.point_mul(private, peer)?;
        let mut out = [0u8; SCALAR_LEN];
        out.copy_from_slice(&full[..SCALAR_LEN]);
        Ok(out)
    }

    fn kdf(&self, secret: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), EccError> {
        if out.len() > MAX_KDF_OUT {
            return Err(EccError::OutputTooLong);
        }
        let mut pos = 0usize;
        let mut ctr: u8 = 1;
        while pos < out.len() {
            let mut h = Sha256::new();
            h.update(secret);
            h.update(info);
            h.update([ctr]);
            let digest = h.finalize();
            let take = (out.len() - pos).min(32);
            out[pos..pos + take].copy_from_slice(&digest[..take]);
            pos += take;
            ctr = ctr.wrapping_add(1);
        }
        Ok(())
    }

    fn mac(&self, key: &[u8], msg: &[u8], tag: &mut [u8; MAC_LEN]) -> Result<(), EccError> {
        let mut m =
            <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| EccError::InvalidScalar)?;
        Mac::update(&mut m, msg);
        let out = m.finalize().into_bytes();
        tag.copy_from_slice(&out[..MAC_LEN]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed P-256 base point (Gx, Gy) for smoke coverage.
    const GX: [u8; 32] = [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ];

    #[test]
    fn base_mul_one_is_generator() {
        let b = HostBackend::new();
        let mut one = [0u8; SCALAR_LEN];
        one[31] = 1;
        let p = b.base_mul(&one).unwrap();
        assert_eq!(&p[..32], &GX);
    }

    #[test]
    fn ecdh_agrees_both_directions() {
        let b = HostBackend::new();
        let (mut a, mut c) = ([0u8; SCALAR_LEN], [0u8; SCALAR_LEN]);
        a[31] = 3;
        c[31] = 5;
        let pa = b.base_mul(&a).unwrap();
        let pc = b.base_mul(&c).unwrap();
        assert_eq!(b.ecdh(&a, &pc).unwrap(), b.ecdh(&c, &pa).unwrap());
    }

    #[test]
    fn rejects_garbage() {
        let b = HostBackend::new();
        assert_eq!(b.base_mul(&[0u8; SCALAR_LEN]), Err(EccError::InvalidScalar));
        assert_eq!(
            b.point_mul(&[1u8; SCALAR_LEN], &[0u8; POINT_LEN]),
            Err(EccError::InvalidPoint)
        );
        let mut big = [0u8; MAX_KDF_OUT + 1];
        assert_eq!(b.kdf(b"x", b"y", &mut big), Err(EccError::OutputTooLong));
    }
}
