//! P-256 base-field arithmetic for point decompression.
//!
//! Pure integer code over fixed 32-octet big-endian values: no curve
//! backend, no allocation, no target hooks. It exists so compressed
//! points can be expanded anywhere the core runs — including on the
//! [`crate::mock`] backend and in `no_std` unit tests — which is what
//! makes the square root "mock-provable": the same routine the host
//! backend serves is pinned by backend-independent vectors here.
//!
//! Paraphrase-level context only (D1, `SCOPE.md` §2): the field prime
//! and curve coefficient below are public domain parameters of the
//! P-256 curve, not spec text. The prime shape (`p % 4 == 3`) is taken
//! from the crypto stack's own field source (`p256` 0.14
//! `arithmetic/field.rs`: modulus `ffffffff00000001…ffffffff`, i.e.
//! `p = 2^{224}(2^{32} - 1) + 2^{192} + 2^{96} - 1`, trailing octet
//! `0xFF`), and is re-pinned by [`tests::prime_is_three_mod_four`]
//! rather than assumed. Because that shape holds, a square root is a
//! single exponentiation to `(p + 1) / 4`; anything that is not a
//! quadratic residue is rejected as [`EccError::InvalidPoint`].

use crate::ecc::EccError;

/// P-256 field prime `p`, big-endian octets.
pub const FIELD_P: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// P-256 curve coefficient `b` (`y^2 = x^3 - 3x + b`), big-endian.
pub const CURVE_B: [u8; 32] = [
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B,
];

/// `(p + 1) / 4`, big-endian: the square-root exponent for a prime
/// with `p % 4 == 3`.
const SQRT_EXP: [u8; 32] = [
    0x3F, 0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Little-endian 256-bit limb value.
type Limbs = [u64; 4];

/// Prime limbs, computed once per call from [`FIELD_P`].
fn prime() -> Limbs {
    from_be(&FIELD_P)
}

/// Big-endian octets to limbs.
fn from_be(x: &[u8; 32]) -> Limbs {
    let mut out = [0u64; 4];
    let mut i = 0;
    while i < 4 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&x[(3 - i) * 8..(4 - i) * 8]);
        out[i] = u64::from_be_bytes(w);
        i += 1;
    }
    out
}

/// Limbs to big-endian octets.
fn to_be(a: &Limbs) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 4 {
        out[(3 - i) * 8..(4 - i) * 8].copy_from_slice(&a[i].to_be_bytes());
        i += 1;
    }
    out
}

/// Limb comparison.
fn cmp(a: &Limbs, b: &Limbs) -> core::cmp::Ordering {
    let mut i = 4;
    while i > 0 {
        i -= 1;
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    core::cmp::Ordering::Equal
}

/// Wrapping add with carry out.
fn add_raw(a: &Limbs, b: &Limbs) -> (Limbs, bool) {
    let mut out = [0u64; 4];
    let mut carry = false;
    let mut i = 0;
    while i < 4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(u64::from(carry));
        out[i] = s2;
        carry = c1 || c2;
        i += 1;
    }
    (out, carry)
}

/// Wrapping sub with borrow out.
fn sub_raw(a: &Limbs, b: &Limbs) -> (Limbs, bool) {
    let mut out = [0u64; 4];
    let mut borrow = false;
    let mut i = 0;
    while i < 4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(u64::from(borrow));
        out[i] = d2;
        borrow = b1 || b2;
        i += 1;
    }
    (out, borrow)
}

/// `(a + b) mod p`.
fn add_mod(a: &Limbs, b: &Limbs) -> Limbs {
    let p = prime();
    let (s, carry) = add_raw(a, b);
    if carry {
        // `a + b` overflowed 256 bits: `s` holds `a + b - 2^256`,
        // so complete the reduction by adding `2^256 - p`.
        let (neg_p, _) = sub_raw(&[0u64; 4], &p);
        let (back, _) = add_raw(&s, &neg_p);
        return back;
    }
    if cmp(&s, &p) != core::cmp::Ordering::Less {
        return sub_raw(&s, &p).0;
    }
    s
}

/// `(a - b) mod p`.
fn sub_mod(a: &Limbs, b: &Limbs) -> Limbs {
    let (d, borrow) = sub_raw(a, b);
    if borrow {
        // Wrapped below zero; adding `p` once lands back in range.
        let (back, _) = add_raw(&d, &prime());
        return back;
    }
    d
}

/// Logical right shift by one bit.
fn shr1(a: &Limbs) -> Limbs {
    let mut out = [0u64; 4];
    let mut carry = 0u64;
    let mut i = 4;
    while i > 0 {
        i -= 1;
        out[i] = (a[i] >> 1) | (carry << 63);
        carry = a[i] & 1;
    }
    out
}

/// `(a * b) mod p` via fixed 256-iteration double-and-add: no data
/// shaped branches beyond the accumulator add, bounded and reviewable.
fn mul_mod(a: &Limbs, b: &Limbs) -> Limbs {
    let mut acc = [0u64; 4];
    let mut base = *a;
    let mut exp = *b;
    let mut i = 0;
    while i < 256 {
        if exp[0] & 1 == 1 {
            acc = add_mod(&acc, &base);
        }
        base = add_mod(&base, &base);
        exp = shr1(&exp);
        i += 1;
    }
    acc
}

/// `base^exp mod p`, square-and-multiply over the 256 exponent bits.
fn pow_mod(base: &Limbs, exp: &[u8; 32]) -> Limbs {
    let mut acc = [1u64, 0, 0, 0]; // 1
    let mut bit = 0;
    while bit < 256 {
        acc = mul_mod(&acc, &acc);
        let byte = exp[(bit / 8) as usize];
        let mask = 0x80u8 >> (bit % 8);
        if byte & mask != 0 {
            acc = mul_mod(&acc, base);
        }
        bit += 1;
    }
    acc
}

/// Modular square root: `r` with `r^2 == n (mod p)`, or
/// [`EccError::InvalidPoint`] when `n` is not a quadratic residue.
/// Valid only because `p % 4 == 3` (pinned below, not assumed).
pub fn sqrt_mod(n_be: &[u8; 32]) -> Result<[u8; 32], EccError> {
    let n = from_be(n_be);
    let r = pow_mod(&n, &SQRT_EXP);
    if mul_mod(&r, &r) == n {
        Ok(to_be(&r))
    } else {
        Err(EccError::InvalidPoint)
    }
}

/// Recover the `y` coordinate for curve point `(x, y)` with the
/// requested oddness. Rejects `x >= p` and non-residues (no point with
/// that `x` exists) as [`EccError::InvalidPoint`].
pub fn y_from_x(x_be: &[u8; 32], odd: bool) -> Result<[u8; 32], EccError> {
    if cmp(&from_be(x_be), &prime()) != core::cmp::Ordering::Less {
        return Err(EccError::InvalidPoint);
    }
    let x = from_be(x_be);
    // `t = x^3 - 3x + b (mod p)`.
    let x2 = mul_mod(&x, &x);
    let x3 = mul_mod(&x2, &x);
    let three_x = add_mod(&x, &add_mod(&x, &x));
    let t = sub_mod(&add_mod(&x3, &from_be(&CURVE_B)), &three_x);
    let r = from_be(&sqrt_mod(&to_be(&t))?);
    // Select the root with the requested parity; `y` and `p - y`
    // are the two roots (they coincide only at `y == 0`, where the
    // parity is even either way).
    let r_be = to_be(&r);
    if (r_be[31] & 1 == 1) == odd {
        Ok(r_be)
    } else {
        Ok(to_be(&sub_mod(&prime(), &r)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prime_is_three_mod_four() {
        // The shortcut in `sqrt_mod` is valid only for this shape;
        // fail loudly here if the constant ever stops matching it.
        assert_eq!(FIELD_P[31] & 0x03, 0x03);
        // Trailing octet pins the stack modulus tail (`…ffffffff`).
        assert_eq!(&FIELD_P[24..], &[0xFF; 8]);
    }

    #[test]
    fn add_sub_mod_wrap() {
        let p = prime();
        let one = [1u64, 0, 0, 0];
        let p_minus1 = sub_mod(&p, &one);
        assert_eq!(add_mod(&p_minus1, &one), [0u64; 4]);
        assert_eq!(sub_mod(&[0u64; 4], &one), p_minus1);
        let two = [2u64, 0, 0, 0];
        let three = [3u64, 0, 0, 0];
        assert_eq!(add_mod(&one, &two), three);
    }

    #[test]
    fn mul_pow_small_values() {
        let two = [2u64, 0, 0, 0];
        let three = [3u64, 0, 0, 0];
        let six = [6u64, 0, 0, 0];
        assert_eq!(mul_mod(&two, &three), six);
        let mut exp = [0u8; 32];
        exp[31] = 8;
        let base = [2u64, 0, 0, 0];
        assert_eq!(pow_mod(&base, &exp), [256u64, 0, 0, 0]);
    }

    #[test]
    fn sqrt_accepts_residues_rejects_non_residues() {
        // 4 -> +-2.
        let mut four = [0u8; 32];
        four[31] = 4;
        let r = from_be(&sqrt_mod(&four).unwrap());
        let two = [2u64, 0, 0, 0];
        assert!(r == two || r == sub_mod(&prime(), &two));
        // x = 2 gives a non-residue for x^3 - 3x + b (pinned by an
        // independent big-integer probe): no curve point has x = 2.
        let mut x2 = [0u8; 32];
        x2[31] = 2;
        let x = from_be(&x2);
        let x2sq = mul_mod(&x, &x);
        let x3 = mul_mod(&x2sq, &x);
        let three_x = add_mod(&x, &add_mod(&x, &x));
        let t = to_be(&sub_mod(&add_mod(&x3, &from_be(&CURVE_B)), &three_x));
        assert_eq!(sqrt_mod(&t), Err(EccError::InvalidPoint));
        assert_eq!(y_from_x(&x2, false), Err(EccError::InvalidPoint));
        assert_eq!(y_from_x(&x2, true), Err(EccError::InvalidPoint));
    }

    #[test]
    fn sqrt_exponent_shape_guards_shortcut() {
        // `SQRT_EXP` must be exactly `(p + 1) / 4`: multiply back by
        // 4 in field arithmetic and compare against `p + 1 mod 2^256`.
        let e = from_be(&SQRT_EXP);
        // 4 * EXP = p + 1 as integers; both doublings and the
        // reference `p + 1` fit in 256 bits, so no carry may occur.
        let (l2, c1) = add_raw(&e, &e);
        let (l4, c2) = add_raw(&l2, &l2);
        let (p_plus1, c3) = add_raw(&prime(), &[1u64, 0, 0, 0]);
        assert_eq!((l4, c1, c2), (p_plus1, false, false));
        assert!(!c3);
        // `p + 1` itself wraps the low 64-bit word only.
        assert_eq!(&to_be(&p_plus1)[24..], &[0u8; 8]);
    }

    #[test]
    fn y_from_x_rejects_out_of_range() {
        assert_eq!(y_from_x(&FIELD_P, false), Err(EccError::InvalidPoint));
        assert_eq!(y_from_x(&[0xFF; 32], true), Err(EccError::InvalidPoint));
    }
}
