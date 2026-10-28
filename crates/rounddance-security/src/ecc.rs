//! Injected ECC backend trait plus pure-logic ECQV/CBKE primitives.
//!
//! The core holds NO concrete curve code: every group or hash operation
//! goes through [`EccBackend`], implemented per target (PSA on ESP,
//! `p256` on host via the `host` feature, [`crate::mock`] for tests).
//! Reconstruction (SEC4-style), the MQV-pattern shared-secret
//! combination (SEC1 §6.2-style two-pass), and session/MAC-key
//! derivation below are pure logic over that trait.
//!
//! Paraphrase-level model of doc `07-5356` SE 1.4a §5 key-agreement
//! steps. All wording here is paraphrase (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are repo-minted (`07-5356-<clause>-<seq>`,
//! dots stripped), MINTED-pending-confirm, with line anchors from the
//! private corpus: reconstruction point per SEC4 (anchor
//! p0169-L4370-L4372), shared-secret + implicit-authentication +
//! no-unilateral-control properties (anchors p0168-L4321-L4326),
//! key confirmation (anchor p0168-L4323-L4325).

use crate::cert::{ImplicitCert, PeerIdentity};
use crate::p256field;

/// P-256 scalar length in octets.
pub const SCALAR_LEN: usize = 32;
/// Uncompressed point length in octets (x || y).
pub const POINT_LEN: usize = 64;
/// Compressed point length in octets (parity tag || x).
pub const COMPRESSED_LEN: usize = 33;
/// Compressed-point tag naming an even `y`.
pub const COMPRESSED_EVEN: u8 = 0x02;
/// Compressed-point tag naming an odd `y`.
pub const COMPRESSED_ODD: u8 = 0x03;
/// Key-confirmation tag length in octets.
pub const MAC_LEN: usize = 16;
/// Largest KDF output this core ever requests in one call.
pub const MAX_KDF_OUT: usize = 64;

/// Failures from ECC operations. Backends map their native errors
/// onto these; no backend details leak through the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccError {
    /// Point input is not a valid curve point.
    InvalidPoint,
    /// Scalar input is zero, out of range, or malformed.
    InvalidScalar,
    /// Requested output exceeds [`MAX_KDF_OUT`].
    OutputTooLong,
    /// Backend-internal failure (media, session, transient).
    BackendFault,
}

/// Curve/hash operations the core needs, implemented per target.
///
/// The four primitives named in the wave brief — point multiply,
/// ECDH, KDF, MAC — are here, plus the point-addition and scalar
/// helpers the MQV-pattern combination is composed from. All points
/// are uncompressed x||y octet strings, all scalars fixed 32-octet
/// big-endian.
pub trait EccBackend {
    /// Generator multiple: `scalar * G`.
    fn base_mul(&self, scalar: &[u8; SCALAR_LEN]) -> Result<[u8; POINT_LEN], EccError>;
    /// General multiply: `scalar * point`.
    fn point_mul(
        &self,
        scalar: &[u8; SCALAR_LEN],
        point: &[u8; POINT_LEN],
    ) -> Result<[u8; POINT_LEN], EccError>;
    /// Point addition: `a + b`.
    fn point_add(
        &self,
        a: &[u8; POINT_LEN],
        b: &[u8; POINT_LEN],
    ) -> Result<[u8; POINT_LEN], EccError>;
    /// Scalar addition modulo the curve order.
    fn scalar_add(
        &self,
        a: &[u8; SCALAR_LEN],
        b: &[u8; SCALAR_LEN],
    ) -> Result<[u8; SCALAR_LEN], EccError>;
    /// Scalar multiplication modulo the curve order.
    fn scalar_mul(
        &self,
        a: &[u8; SCALAR_LEN],
        b: &[u8; SCALAR_LEN],
    ) -> Result<[u8; SCALAR_LEN], EccError>;
    /// Ephemeral-static Diffie-Hellman: x-coordinate of
    /// `private * peer`, 32 octets.
    fn ecdh(
        &self,
        private: &[u8; SCALAR_LEN],
        peer: &[u8; POINT_LEN],
    ) -> Result<[u8; SCALAR_LEN], EccError>;
    /// Counter-mode key derivation: fills `out` (bounded by
    /// [`MAX_KDF_OUT`]).
    fn kdf(&self, secret: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), EccError>;
    /// Message authentication: `MAC_LEN`-octet tag.
    fn mac(&self, key: &[u8], msg: &[u8], tag: &mut [u8; MAC_LEN]) -> Result<(), EccError>;
    /// Expand a compressed point (parity tag || x) to uncompressed
    /// x || y. The default body is the audited core routine
    /// ([`decompress_point`]): backend-independent, so the mock
    /// backend proves the same bytes the host backend serves.
    /// Backends with a stack decoder may override with it, but the
    /// override must agree byte-for-byte (pinned by vectors).
    fn point_decompress(
        &self,
        compressed: &[u8; COMPRESSED_LEN],
    ) -> Result<[u8; POINT_LEN], EccError> {
        decompress_point(compressed)
    }
}

/// Compress an uncompressed point to parity tag || x.
///
/// Infallible: any 64 octets compress (validity is established on
/// decompression, never here). The tag is [`COMPRESSED_ODD`] when the
/// low bit of `y` is set, else [`COMPRESSED_EVEN`].
///
/// Requirement `07-5123-08-1074-05`.
#[must_use]
pub fn compress_point(point: &[u8; POINT_LEN]) -> [u8; COMPRESSED_LEN] {
    let mut out = [0u8; COMPRESSED_LEN];
    out[0] = if point[63] & 1 == 1 {
        COMPRESSED_ODD
    } else {
        COMPRESSED_EVEN
    };
    out[1..].copy_from_slice(&point[..SCALAR_LEN]);
    out
}

/// Expand a compressed point (parity tag || x) to uncompressed x ||
/// y, recovering `y` through the field square root. Rejects unknown
/// tags (including the uncompressed-infinity marker `0x00`),
/// `x >= p`, and `x` values with no curve point (non-residues) as
/// [`EccError::InvalidPoint`]. On success `(x, y)` satisfies the curve
/// equation by construction, so membership needs no further check.
///
/// Requirement `07-5123-08-1074-05`.
pub fn decompress_point(compressed: &[u8; COMPRESSED_LEN]) -> Result<[u8; POINT_LEN], EccError> {
    let odd = match compressed[0] {
        COMPRESSED_EVEN => false,
        COMPRESSED_ODD => true,
        _ => return Err(EccError::InvalidPoint),
    };
    let mut x = [0u8; SCALAR_LEN];
    x.copy_from_slice(&compressed[1..]);
    let y = p256field::y_from_x(&x, odd)?;
    let mut out = [0u8; POINT_LEN];
    out[..SCALAR_LEN].copy_from_slice(&x);
    out[SCALAR_LEN..].copy_from_slice(&y);
    Ok(out)
}

/// Derive a curve scalar from arbitrary transcript material.
///
/// Hashes the concatenation of `parts` through the backend KDF and
/// truncates to 32 octets. An all-zero digest is rejected (it would
/// be a degenerate multiplier); callers treat that as a transcript
/// collision and abort the handshake.
///
/// Requirement `07-5356-C42-03`.
pub fn scalar_from_kdf<B: EccBackend>(
    backend: &B,
    parts: &[&[u8]],
    domain: &[u8],
) -> Result<[u8; SCALAR_LEN], EccError> {
    let mut buf = [0u8; SCALAR_LEN];
    // Simple, reviewable construction: absorb the domain label, then
    // each transcript piece in bounded chunks, into a 32-octet
    // accumulator via the backend KDF. No allocation is needed.
    let mut acc = [0u8; SCALAR_LEN];
    let mut tmp = [0u8; SCALAR_LEN];
    backend.kdf(domain, domain, &mut tmp)?;
    acc.copy_from_slice(&tmp);
    let mut acc_len = SCALAR_LEN;
    for part in parts {
        let mut off = 0usize;
        while off < part.len() {
            let chunk = &part[off..(off + MAX_KDF_OUT).min(part.len())];
            let mut mix = [0u8; MAX_KDF_OUT];
            backend.kdf(&acc[..acc_len], chunk, &mut mix[..SCALAR_LEN])?;
            acc.copy_from_slice(&mix[..SCALAR_LEN]);
            acc_len = SCALAR_LEN;
            off += chunk.len();
        }
    }
    buf.copy_from_slice(&acc);
    if buf == [0u8; SCALAR_LEN] {
        return Err(EccError::InvalidScalar);
    }
    Ok(buf)
}

/// Reconstruct a peer's static public key (SEC4-style): `Q = e*Qca + P`
/// where `e` binds certificate octets, subject, and reconstruction
/// point, `Qca` is the CA public key, and `P` is the carried point.
///
/// Requirement `07-5356-C42-03`.
pub fn reconstruct_static<B: EccBackend>(
    backend: &B,
    ca_pub: &[u8; POINT_LEN],
    peer: &PeerIdentity,
) -> Result<[u8; POINT_LEN], EccError> {
    let e = scalar_from_kdf(
        backend,
        &[peer.cert.as_bytes(), &peer.subject, &peer.point],
        b"ecqv-reconstruct",
    )?;
    let scaled = backend.point_mul(&e, ca_pub)?;
    backend.point_add(&scaled, &peer.point)
}

/// MQV-pattern shared secret (SEC1 §6.2-style two-pass combination),
/// pure logic:
///
/// `s = local_eph + e_local * local_static (mod n)`;
/// `peer_combined = peer_eph + e_peer * peer_static`;
/// `Z = ECDH(s, peer_combined)`.
///
/// The `e_*` implicit-signature scalars bind each side's ephemeral and
/// static material; both sides compute the same `Z` when they agree on
/// the transcript.
///
/// Requirement `07-5356-C42-04`.
#[allow(clippy::too_many_arguments)]
pub fn mqv_agree<B: EccBackend>(
    backend: &B,
    local_static: &[u8; SCALAR_LEN],
    local_eph: &[u8; SCALAR_LEN],
    peer_static: &[u8; POINT_LEN],
    peer_eph: &[u8; POINT_LEN],
    e_local: &[u8; SCALAR_LEN],
    e_peer: &[u8; SCALAR_LEN],
) -> Result<[u8; SCALAR_LEN], EccError> {
    let prod = backend.scalar_mul(e_local, local_static)?;
    let s = backend.scalar_add(local_eph, &prod)?;
    let peer_prod = backend.point_mul(e_peer, peer_static)?;
    let peer_combined = backend.point_add(peer_eph, &peer_prod)?;
    backend.ecdh(&s, &peer_combined)
}

/// Session and confirmation keys from the shared secret: a 16-octet
/// link key plus the two 16-octet directional confirmation keys, each
/// derived under its own domain label so key separation holds even
/// though all three come from one `Z`.
///
/// Requirement `07-5356-C42-05`.
pub fn session_keys<B: EccBackend>(
    backend: &B,
    z: &[u8; SCALAR_LEN],
    transcript: &[u8],
    link_key: &mut [u8; 16],
    mac_u: &mut [u8; 16],
    mac_v: &mut [u8; 16],
) -> Result<(), EccError> {
    let mut info = [0u8; 96];
    let tlen = transcript.len().min(64);
    info[..tlen].copy_from_slice(&transcript[..tlen]);
    let mut out = [0u8; 48];
    // Three labeled derivations; the label sits in the info tail so
    // each key stream is domain-separated.
    for (i, slot) in out.chunks_mut(16).enumerate() {
        info[64] = (i + 1) as u8;
        backend.kdf(z, &info[..65], slot)?;
    }
    link_key.copy_from_slice(&out[..16]);
    mac_u.copy_from_slice(&out[16..32]);
    mac_v.copy_from_slice(&out[32..48]);
    Ok(())
}

/// Compute a key-confirmation tag over the handshake transcript.
///
/// Requirement `07-5356-C42-05`.
pub fn confirm_tag<B: EccBackend>(
    backend: &B,
    mac_key: &[u8],
    transcript: &[u8],
    tag: &mut [u8; MAC_LEN],
) -> Result<(), EccError> {
    backend.mac(mac_key, transcript, tag)
}

/// The [`ImplicitCert`] octets contribute to reconstruction binding.
#[allow(dead_code)]
fn _cert_link(_c: &ImplicitCert) -> usize {
    crate::cert::IMPLICIT_CERT_LEN
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockBackend;

    #[test]
    fn scalar_rejects_degenerate_mock_digest() {
        // MockBackend::ZERO forces an all-zero KDF stream: the only
        // way to observe the degenerate-scalar guard deterministically.
        let b = MockBackend::zero_stream();
        let e = scalar_from_kdf(&b, &[b"anything"], b"dom");
        assert_eq!(e, Err(EccError::InvalidScalar));
    }

    #[test]
    fn reconstruct_and_mqv_run_on_mock() {
        let b = MockBackend::new(0x42);
        let ca = b.base_mul(&[7u8; SCALAR_LEN]).unwrap();
        let peer = PeerIdentity::new(
            ImplicitCert::from_bytes([9u8; crate::cert::IMPLICIT_CERT_LEN]),
            [3u8; 8],
            b.base_mul(&[11u8; SCALAR_LEN]).unwrap(),
        );
        let q = reconstruct_static(&b, &ca, &peer).unwrap();
        assert_ne!(q, [0u8; POINT_LEN]);
        // Same inputs reconstruct the same key (deterministic).
        assert_eq!(reconstruct_static(&b, &ca, &peer).unwrap(), q);

        let e_l = scalar_from_kdf(&b, &[b"local"], b"d").unwrap();
        let e_p = scalar_from_kdf(&b, &[b"peer"], b"d").unwrap();
        let z = mqv_agree(
            &b,
            &[1u8; SCALAR_LEN],
            &[2u8; SCALAR_LEN],
            &q,
            &b.base_mul(&[5u8; SCALAR_LEN]).unwrap(),
            &e_l,
            &e_p,
        )
        .unwrap();
        assert_ne!(z, [0u8; SCALAR_LEN]);
    }

    /// P-256 base point, big-endian halves (public curve parameter).
    const GX: [u8; 32] = [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ];
    const GY: [u8; 32] = [
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ];

    fn generator() -> [u8; POINT_LEN] {
        let mut p = [0u8; POINT_LEN];
        p[..32].copy_from_slice(&GX);
        p[32..].copy_from_slice(&GY);
        p
    }

    #[test]
    fn compress_names_parity_and_round_trips_generator() {
        // Gy is odd: the compressed generator carries 0x03.
        let g = generator();
        let c = compress_point(&g);
        assert_eq!(c[0], COMPRESSED_ODD);
        assert_eq!(&c[1..], &GX);
        assert_eq!(decompress_point(&c).unwrap(), g);
        // The wrong parity tag recovers the negated point, never G.
        let mut other = c;
        other[0] = COMPRESSED_EVEN;
        let neg = decompress_point(&other).unwrap();
        assert_eq!(&neg[..32], &GX);
        assert_ne!(&neg[32..], &GY);
        // An even-y twin compresses back to the even tag.
        assert_eq!(compress_point(&neg)[0], COMPRESSED_EVEN);
        assert_eq!(decompress_point(&compress_point(&neg)).unwrap(), neg);
    }

    #[test]
    fn decompress_via_backend_trait_on_mock() {
        // Mock-provable integration: the EccBackend seam serves the
        // same bytes with no host feature enabled.
        let b = MockBackend::new(0xC0);
        let g = generator();
        let c = compress_point(&g);
        assert_eq!(b.point_decompress(&c).unwrap(), g);
    }

    #[test]
    fn decompress_rejects_foreign_encodings() {
        let g = generator();
        let c = compress_point(&g);
        // Unknown tags, including the uncompressed-infinity marker.
        for tag in [0x00u8, 0x01, 0x04, 0x05, 0x06, 0x07, 0xFF] {
            let mut bad = c;
            bad[0] = tag;
            assert_eq!(decompress_point(&bad), Err(EccError::InvalidPoint));
        }
        // x == p and x > p are not field elements.
        let mut xp = c;
        xp[1..].copy_from_slice(&crate::p256field::FIELD_P);
        assert_eq!(decompress_point(&xp), Err(EccError::InvalidPoint));
        let mut big = c;
        big[1..].fill(0xFF);
        assert_eq!(decompress_point(&big), Err(EccError::InvalidPoint));
        // x = 2 admits no curve point (pinned non-residue).
        let mut x2 = c;
        x2[1..].fill(0);
        x2[32] = 2;
        assert_eq!(decompress_point(&x2), Err(EccError::InvalidPoint));
    }

    #[test]
    fn session_keys_are_domain_separated() {
        let b = MockBackend::new(1);
        let z = [0x77u8; SCALAR_LEN];
        let (mut k, mut u, mut v) = ([0u8; 16], [0u8; 16], [0u8; 16]);
        session_keys(&b, &z, b"transcript", &mut k, &mut u, &mut v).unwrap();
        assert_ne!(k, u);
        assert_ne!(k, v);
        assert_ne!(u, v);
    }
}
