//! AES-MMO-128 hash plus the HMAC built over it.
//!
//! Paraphrase-level model of the block-cipher hash feeding BDB
//! install-code key derivation: the digest starts from an all-zero
//! chaining block and folds each padded message block through the
//! cipher, mixing the plaintext back into the cipher output. Padding
//! appends a single marker bit, zero fill, then the bit length as a
//! trailing word. The long padding form only applies at or above the
//! 2^16-bit threshold, far above every input this crate accepts (all
//! callers hash at most 48 octets), so it is not instantiated here:
//! over-cap inputs are refused, never hashed with the wrong form.
//! Only the 128-bit digest form is provided.
//!
//! The keyed construction below is the generic HMAC built on that
//! hash with a 16-octet block: inner pad, hash, outer pad, hash.
//! The key-hierarchy derivation in [`crate::keyhierarchy`] applies
//! it to link keys; this module only supplies the primitive.
//!
//! Requirements: `22-65816-030-56-07` (CRC parameter set,
//! corpus-mined) and `22-65816-030-56-08` (repo-minted,
//! MINTED-pending-confirm) for the install-code digest;
//! `05-3474-23-B14-01` (repo-minted, MINTED-pending-confirm) for the
//! keyed form.
//!
//! Anchors: BDB p0041-L807-L834 (install-code format, CRC parameter
//! set, worked key), 05-3474-23 p0543-L13356-L13392 (hash padding
//! methods and block iteration), p0541-L13301-L13312 (keyed-hash
//! definition and block size), p0550-L13551-L13565 (short-form
//! vector), p0551-L13583-L13587 (long-form threshold: the second
//! method only applies at or above the 2^16-bit input), p0554-L13638
//! -L13667 + p0555-L13662-L13667 (keyed-hash vectors). All wording
//! here is paraphrase (D1, `SCOPE.md` §2).

use crate::aes::{encrypt_block_aes128, BLOCK_LEN};

/// AES-MMO-128 digest length in octets.
pub const MMO_DIGEST_LEN: usize = BLOCK_LEN;
/// Longest message this hash accepts: 64 octets. The bound covers the
/// derivation legs (a 17-octet inner preimage and a 32-octet outer
/// preimage) plus install codes, while keeping the padded schedule a
/// fixed-size stack array. Longer inputs are refused, never
/// truncated, per the out-of-range rule.
pub const MMO_MAX_MSG_LEN: usize = 64;
/// Scratch bound: the longest padded schedule under the cap (a
/// 64-octet message: 64 + 1 marker + 13 fill + 2 length octets =
/// 5 blocks).
const PAD_MAX: usize = 80;

/// Hash failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmoError {
    /// Message exceeds [`MMO_MAX_MSG_LEN`].
    TooLong,
}

/// AES-MMO-128 over `msg` (at most [`MMO_MAX_MSG_LEN`] octets).
///
/// Padding fills to the 14-octet residue with a 2-octet big-endian
/// bit length appended (the form for inputs below the 2^16-bit
/// threshold, which covers every input under the cap). For an
/// 18-octet install code that is 2 blocks: 18 message + 1 marker +
/// 11 zeros + 2 length octets.
///
/// Requirement `22-65816-030-56-08` (repo-minted,
/// MINTED-pending-confirm).
pub fn mmo_hash_128(msg: &[u8]) -> Result<[u8; MMO_DIGEST_LEN], MmoError> {
    let total = padded_len(msg.len())?;
    let mut chain = [0u8; BLOCK_LEN];
    let mut scratch = [0u8; PAD_MAX];
    scratch[..msg.len()].copy_from_slice(msg);
    scratch[msg.len()] = 0x80;
    let bit_len = msg.len() * 8;
    scratch[total - 2] = ((bit_len >> 8) & 0xFF) as u8;
    scratch[total - 1] = (bit_len & 0xFF) as u8;
    let mut off = 0usize;
    while off < total {
        let mut block = [0u8; BLOCK_LEN];
        block.copy_from_slice(&scratch[off..off + BLOCK_LEN]);
        let enc = encrypt_block_aes128(&chain, &block);
        let mut j = 0usize;
        while j < BLOCK_LEN {
            chain[j] = enc[j] ^ block[j];
            j += 1;
        }
        off += BLOCK_LEN;
    }
    Ok(chain)
}

/// Padded schedule length in octets for a `msg_len`-octet input.
fn padded_len(msg_len: usize) -> Result<usize, MmoError> {
    if msg_len > MMO_MAX_MSG_LEN {
        return Err(MmoError::TooLong);
    }
    let bit_len = msg_len * 8;
    // Suffix after the marker bit: the length as one word. All
    // capped inputs sit below the long-form threshold.
    Ok((bit_len + 1 + 16).div_ceil(128) * BLOCK_LEN)
}

/// Longest keyed-hash input this module accepts: 32 octets, so both
/// legs (`key ^ pad || msg` and `key ^ pad || digest`) fit the hash
/// cap above.
pub const HMAC_MAX_MSG_LEN: usize = MMO_MAX_MSG_LEN - BLOCK_LEN;

/// Keyed hash over `msg` under the 16-octet `key`: the generic HMAC
/// construction on the hash above (inner pad `0x36`, outer pad
/// `0x5C`, block length 16).
///
/// Requirement `05-3474-23-B14-01` (repo-minted,
/// MINTED-pending-confirm).
pub fn hmac_mmo_128(key: &[u8; BLOCK_LEN], msg: &[u8]) -> Result<[u8; MMO_DIGEST_LEN], MmoError> {
    if msg.len() > HMAC_MAX_MSG_LEN {
        return Err(MmoError::TooLong);
    }
    let mut inner = [0u8; MMO_MAX_MSG_LEN];
    let mut outer = [0u8; MMO_MAX_MSG_LEN];
    let mut i = 0usize;
    while i < BLOCK_LEN {
        inner[i] = key[i] ^ 0x36;
        outer[i] = key[i] ^ 0x5C;
        i += 1;
    }
    inner[BLOCK_LEN..BLOCK_LEN + msg.len()].copy_from_slice(msg);
    let hash1 = mmo_hash_128(&inner[..BLOCK_LEN + msg.len()])?;
    outer[BLOCK_LEN..BLOCK_LEN + MMO_DIGEST_LEN].copy_from_slice(&hash1);
    mmo_hash_128(&outer[..BLOCK_LEN + MMO_DIGEST_LEN])
}
