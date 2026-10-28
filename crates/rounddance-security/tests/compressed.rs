//! Compressed-point vectors: SEC1 33-octet form (parity tag || x)
//! to expanded x || y.
//!
//! Provenance:
//! * `HOST` vectors pin real-curve agreement via the `host`
//!   reference backend, cross-checked against the stack's own SEC1
//!   decoder (`p256::PublicKey::from_sec1_bytes`) — never interop
//!   with another stack.
//! * The compressed encodings below are hand-derived from the pinned
//!   expanded points (`tests/vectors.rs` handshake pins + the public
//!   base point): tag from the low bit of `y`, `x` copied verbatim.
//! * The backend-independent fuzz legs run with no features enabled.

use rounddance_security::{compress_point, decompress_point, EccBackend, EccError, COMPRESSED_LEN};

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}

// 07-5123-08-1074-05: published points decompress exactly, both
// parities. G (odd y, 0x03) + the wave-8 handshake pins rec_r (odd
// y, 0x03) and rec_i (even y, 0x02); compressed forms are pinned
// byte-for-byte, then every consumer below decodes them.
#[cfg(feature = "host")]
#[test]
fn vector_compressed_published_points_07_5123_08_1074_05() {
    use rounddance_security::backend_host::HostBackend;

    // Base point: odd y.
    let g: [u8; 64] = unhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    let g33: [u8; 33] = unhex("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    // Wave-8 responder reconstruction pin: odd y.
    let rec_r: [u8; 64] = unhex("a6363902da41648c34ebf4f530f1d4ab5876875be2d2f9d5b90eef91f8a92fe4eff0511e284b535e7419b247b6ae478c42a94dce53746360870a8b7663ec69a1");
    let rec_r33: [u8; 33] =
        unhex("03a6363902da41648c34ebf4f530f1d4ab5876875be2d2f9d5b90eef91f8a92fe4");
    // Wave-8 initiator reconstruction pin: even y.
    let rec_i: [u8; 64] = unhex("068d0b8d65a02a1f9a8d10c29bebd204cac035f30e1bdfd78a3235d3f9ffa3e088a95cc4f8294eef198d170aa042164b8354d1454c037fdfef697f56409a187a");
    let rec_i33: [u8; 33] =
        unhex("02068d0b8d65a02a1f9a8d10c29bebd204cac035f30e1bdfd78a3235d3f9ffa3e0");

    assert_eq!(compress_point(&g), g33);
    assert_eq!(compress_point(&rec_r), rec_r33);
    assert_eq!(compress_point(&rec_i), rec_i33);

    let b = HostBackend::new();
    for (e, c) in [(g, g33), (rec_r, rec_r33), (rec_i, rec_i33)] {
        // Core routine and backend seam agree.
        assert_eq!(decompress_point(&c).unwrap(), e);
        assert_eq!(b.point_decompress(&c).unwrap(), e);
        // The audited stack decoder agrees on the same bytes.
        let stack = p256::PublicKey::from_sec1_bytes(&c).unwrap();
        let enc = stack.to_sec1_bytes();
        assert_eq!(enc.len(), 65);
        assert_eq!(&enc[1..33], &e[..32]);
        assert_eq!(&enc[33..65], &e[32..]);
    }
}

// 07-5123-08-1074-05: compress -> decompress round-trips on live
// backend points, covering both parities several times over.
#[cfg(feature = "host")]
#[test]
fn vector_compressed_round_trip_host_07_5123_08_1074_05() {
    use rounddance_security::backend_host::HostBackend;

    let b = HostBackend::new();
    let mut even_seen = false;
    let mut odd_seen = false;
    for s in 1u8..=12 {
        let mut scalar = [0u8; 32];
        scalar[31] = s;
        let p = b.base_mul(&scalar).unwrap();
        let c = compress_point(&p);
        assert_eq!(&c[1..], &p[..32]);
        assert_eq!((c[0] == 0x03), (p[63] & 1 == 1));
        if c[0] == 0x02 {
            even_seen = true;
        } else {
            odd_seen = true;
        }
        assert_eq!(b.point_decompress(&c).unwrap(), p);
    }
    assert!(even_seen && odd_seen);
    // The pinned handshake ephemeral scalars round-trip too.
    for s in [0x22u8, 0x55] {
        let p = b.base_mul(&[s; 32]).unwrap();
        assert_eq!(decompress_point(&compress_point(&p)).unwrap(), p);
    }
}

// 07-5123-08-1074-02/05: malformed compressed points are rejected as
// InvalidPoint — never a silent wrong point — on both the free
// function and the backend seam.
#[cfg(feature = "host")]
#[test]
fn vector_compressed_rejection_host_07_5123_08_1074_05() {
    use rounddance_security::backend_host::HostBackend;

    let b = HostBackend::new();
    let g33: [u8; 33] = unhex("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    // Bad tags (0x00 is the uncompressed-infinity marker).
    for tag in [0x00u8, 0x01, 0x04, 0x05, 0x06, 0x2A, 0xFF] {
        let mut bad = g33;
        bad[0] = tag;
        assert_eq!(decompress_point(&bad), Err(EccError::InvalidPoint));
        assert_eq!(b.point_decompress(&bad), Err(EccError::InvalidPoint));
    }
    // x == p and x > p are not field elements.
    let mut xp = g33;
    xp[1..].copy_from_slice(&rounddance_security::p256field::FIELD_P);
    assert_eq!(decompress_point(&xp), Err(EccError::InvalidPoint));
    let mut big = g33;
    big[1..].fill(0xFF);
    assert_eq!(decompress_point(&big), Err(EccError::InvalidPoint));
    assert_eq!(b.point_decompress(&big), Err(EccError::InvalidPoint));
    // x = 2 admits no curve point (non-residue, pinned by an
    // independent big-integer probe).
    let mut x2 = g33;
    x2[1..].fill(0);
    x2[32] = 2;
    assert_eq!(decompress_point(&x2), Err(EccError::InvalidPoint));
    assert_eq!(b.point_decompress(&x2), Err(EccError::InvalidPoint));
}

// Backend-independent fuzz (no host feature): arbitrary 33-octet
// inputs never panic; every accepted input is an involution
// (re-compressing recovers the input, parity included), and the mock
// seam matches the free function on all 8k cases.
#[test]
fn fuzz_compressed_never_panics_mock_matches() {
    use rounddance_security::mock::MockBackend;

    let b = MockBackend::new(0xC0);
    let mut rng = 0x005E_EDC0_DE33_u64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng = rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        rng
    };
    let mut ok_count = 0u32;
    for _ in 0..8000 {
        let mut c = [0u8; COMPRESSED_LEN];
        let mut i = 0;
        while i < COMPRESSED_LEN {
            let v = next().to_le_bytes();
            let take = (COMPRESSED_LEN - i).min(8);
            c[i..i + take].copy_from_slice(&v[..take]);
            i += take;
        }
        let free = decompress_point(&c);
        let seam = b.point_decompress(&c);
        assert_eq!(free, seam);
        if let Ok(p) = free {
            ok_count += 1;
            assert_eq!(compress_point(&p), c);
            assert_eq!(hex_of(&p[..32]), hex_of(&c[1..]));
        } else {
            assert_eq!(free, Err(EccError::InvalidPoint));
        }
    }
    // Random 33-octet strings almost never land on the curve, but
    // the generator tag + x must have been accepted at least once
    // (the 0x02/0x03 tags with small x hit residues over 8k draws
    // with overwhelming probability — this asserts the fuzzer is
    // not vacuously rejecting).
    assert!(ok_count > 0, "fuzz never accepted a point");
}
