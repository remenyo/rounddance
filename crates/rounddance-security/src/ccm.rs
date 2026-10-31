//! AES-CCM\* (MIC-32, L=2) seal/open over the crate block cipher.
//!
//! Production port of the construction the interop vectors pin
//! (`rounddance-security/tests/vectors.rs`, retired lab-capture key):
//! CTR keystream from counter blocks `01 || nonce || ctr BE-u16`
//! (counters from 1), CBC-MAC over B0 (flags adata/M/L, nonce,
//! message length) then length-prefixed AAD and the plaintext, each
//! padded separately to the block edge, masked with S0 (counter 0).
//! MIC-32 only (M=4): the length the Trust-Center key-transport leg
//! uses on air.
//!
//! `no_std` + `forbid(unsafe_code)`: caller-owned buffers, no alloc,
//! lengths checked before any indexing.

use crate::aes::{encrypt_block_aes128, BLOCK_LEN};

/// CCM\* nonce length in octets (13: 8 EUI + 4 counter + 1 control).
pub const NONCE_LEN: usize = 13;
/// CCM\* authentication tag length in octets (MIC-32).
pub const TAG_LEN: usize = 4;

/// Typed failure for CCM\* operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcmError {
    /// Caller buffer too small for the output.
    TooSmall,
    /// Tag mismatch on open: ciphertext or AAD not authentic.
    AuthFailed,
}

fn keystream_block(key: &[u8; BLOCK_LEN], nonce13: &[u8; NONCE_LEN], ctr: u16) -> [u8; BLOCK_LEN] {
    let mut blk = [0u8; BLOCK_LEN];
    blk[0] = 0x01;
    blk[1..14].copy_from_slice(nonce13);
    blk[14..16].copy_from_slice(&ctr.to_be_bytes());
    encrypt_block_aes128(key, &blk)
}

/// Seal `pt` under `key`/`nonce13` with `aad` authenticated alongside.
/// Writes ciphertext then the 4-octet tag into `out`; returns the
/// total octets (`pt.len() + TAG_LEN`).
///
/// # Errors
///
/// [`CcmError::TooSmall`] when `out` holds fewer than
/// `pt.len() + TAG_LEN` octets.
pub fn seal_into(
    key: &[u8; BLOCK_LEN],
    nonce13: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
    out: &mut [u8],
) -> Result<usize, CcmError> {
    let total = pt.len().checked_add(TAG_LEN).ok_or(CcmError::TooSmall)?;
    if out.len() < total {
        return Err(CcmError::TooSmall);
    }
    let (ct, tag) = out.split_at_mut(pt.len());
    for (i, chunk) in pt.chunks(BLOCK_LEN).enumerate() {
        let ks = keystream_block(key, nonce13, 1 + i as u16);
        for (j, b) in chunk.iter().enumerate() {
            ct[i * BLOCK_LEN + j] = b ^ ks[j];
        }
    }
    let tag_full = cbc_mac(key, nonce13, aad, pt);
    let s0 = keystream_block(key, nonce13, 0);
    for (i, t) in tag.iter_mut().take(TAG_LEN).enumerate() {
        *t = tag_full[i] ^ s0[i];
    }
    Ok(total)
}

/// Open `ct` (ciphertext) with `tag` under `key`/`nonce13` and `aad`,
/// writing plaintext into `out_pt`; returns the plaintext octets.
///
/// # Errors
///
/// [`CcmError::TooSmall`] when `out_pt` holds fewer than `ct.len()`
/// octets; [`CcmError::AuthFailed`] when the tag does not verify
/// (nothing is written on failure).
pub fn open_into(
    key: &[u8; BLOCK_LEN],
    nonce13: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; TAG_LEN],
    out_pt: &mut [u8],
) -> Result<usize, CcmError> {
    if out_pt.len() < ct.len() {
        return Err(CcmError::TooSmall);
    }
    for (i, chunk) in ct.chunks(BLOCK_LEN).enumerate() {
        let ks = keystream_block(key, nonce13, 1 + i as u16);
        for (j, b) in chunk.iter().enumerate() {
            out_pt[i * BLOCK_LEN + j] = b ^ ks[j];
        }
    }
    let pt = &out_pt[..ct.len()];
    let tag_full = cbc_mac(key, nonce13, aad, pt);
    let s0 = keystream_block(key, nonce13, 0);
    let mut expect = [0u8; TAG_LEN];
    for (i, e) in expect.iter_mut().enumerate() {
        *e = tag_full[i] ^ s0[i];
    }
    if &expect == tag {
        Ok(ct.len())
    } else {
        out_pt[..ct.len()].fill(0);
        Err(CcmError::AuthFailed)
    }
}

fn cbc_mac(
    key: &[u8; BLOCK_LEN],
    nonce13: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
) -> [u8; BLOCK_LEN] {
    // B0: adata flag | (M-2)/2=1 | L-1=1, nonce, message length BE.
    let mut b0 = [0u8; BLOCK_LEN];
    b0[0] = (if aad.is_empty() { 0 } else { 0x40 }) | 0x08 | 0x01;
    b0[1..14].copy_from_slice(nonce13);
    let len_be = (pt.len() as u16).to_be_bytes();
    b0[14..16].copy_from_slice(&len_be);
    // CBC-MAC over B0, then separately-padded AAD (length-prefixed)
    // and plaintext.
    let mut x = encrypt_block_aes128(key, &b0);
    if !aad.is_empty() {
        let mut hdr = [0u8; BLOCK_LEN];
        let aad_be = (aad.len() as u16).to_be_bytes();
        hdr[0..2].copy_from_slice(&aad_be);
        let first = aad.len().min(BLOCK_LEN - 2);
        hdr[2..2 + first].copy_from_slice(&aad[..first]);
        x = xor_block(&x, &hdr);
        x = encrypt_block_aes128(key, &x);
        for chunk in aad[first..].chunks(BLOCK_LEN) {
            let mut blk = [0u8; BLOCK_LEN];
            blk[..chunk.len()].copy_from_slice(chunk);
            x = xor_block(&x, &blk);
            x = encrypt_block_aes128(key, &x);
        }
    }
    for chunk in pt.chunks(BLOCK_LEN) {
        let mut blk = [0u8; BLOCK_LEN];
        blk[..chunk.len()].copy_from_slice(chunk);
        x = xor_block(&x, &blk);
        x = encrypt_block_aes128(key, &x);
    }
    x
}

fn xor_block(a: &[u8; BLOCK_LEN], b: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    let mut out = [0u8; BLOCK_LEN];
    for (i, o) in out.iter_mut().enumerate() {
        *o = a[i] ^ b[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const N: [u8; 13] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x35,
    ];

    #[test]
    fn roundtrip_with_and_without_aad() {
        let pt = [0xabu8; 35];
        for aad in [&[][..], &[0x21, 0x51, 0x30][..]] {
            let mut buf = [0u8; 64];
            let n = seal_into(&K, &N, aad, &pt, &mut buf).unwrap();
            assert_eq!(n, pt.len() + TAG_LEN);
            let (ct, tag) = buf[..n].split_at(pt.len());
            let mut tag4 = [0u8; 4];
            tag4.copy_from_slice(tag);
            let mut back = [0u8; 35];
            assert_eq!(open_into(&K, &N, aad, ct, &tag4, &mut back), Ok(35));
            assert_eq!(&back, &pt);
        }
    }

    #[test]
    fn tamper_rejected_everywhere() {
        let pt = [0x05u8, 0x01, 0x02];
        let aad: &[u8] = &[0x21, 0x51];
        let mut buf = [0u8; 16];
        let n = seal_into(&K, &N, aad, &pt, &mut buf).unwrap();
        let (ct, tag) = buf[..n].split_at(pt.len());
        let mut tag4 = [0u8; 4];
        tag4.copy_from_slice(tag);
        let mut out = [0u8; 3];
        // Flipped ciphertext byte.
        let mut bad = [0u8; 3];
        bad.copy_from_slice(ct);
        bad[0] ^= 0x01;
        assert_eq!(
            open_into(&K, &N, aad, &bad, &tag4, &mut out),
            Err(CcmError::AuthFailed)
        );
        // Flipped tag byte.
        let mut bad_tag = tag4;
        bad_tag[0] ^= 0x01;
        assert_eq!(
            open_into(&K, &N, aad, ct, &bad_tag, &mut out),
            Err(CcmError::AuthFailed)
        );
        // Flipped AAD byte.
        assert_eq!(
            open_into(&K, &N, &[0x20, 0x51], ct, &tag4, &mut out),
            Err(CcmError::AuthFailed)
        );
        // Short buffers.
        let mut tiny = [0u8; 2];
        assert_eq!(
            seal_into(&K, &N, aad, &pt, &mut tiny),
            Err(CcmError::TooSmall)
        );
        assert_eq!(
            open_into(&K, &N, aad, ct, &tag4, &mut tiny),
            Err(CcmError::TooSmall)
        );
    }
}
