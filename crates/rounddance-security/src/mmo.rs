//! AES-MMO-128 hash and the install-code link-key derivation.
//!
//! Paraphrase-level model of the block-cipher hash feeding BDB
//! install-code key derivation: the digest starts from an all-zero
//! chaining block and folds each padded message block through the
//! cipher, mixing the plaintext back into the cipher output. Messages
//! shorter than two cipher blocks take the short padding (a single
//! marker bit, zero fill to the length field, then the bit-length as
//! a trailing block-sized word); longer messages take the long form.
//! Only the 128-bit digest form is provided.
//!
//! Requirements `22-65816-030-56-07` (CRC parameter set, corpus-mined)
//! + `22-65816-030-56-08` (repo-minted, MINTED-pending-confirm).
//!
//! The AES-128 key derives from the install code via this hash, pinned
//! by the BDB §6.11.1.2 worked key in `tests/vectors.rs`. Anchors
//! p0041-L807-L834. All wording here is paraphrase (D1, `SCOPE.md` §2).

use crate::aes::{encrypt_block_aes128, BLOCK_LEN};

/// AES-MMO-128 digest length in octets.
pub const MMO_DIGEST_LEN: usize = BLOCK_LEN;
/// Longest message this hash accepts in the short-padding form: under
/// two cipher blocks in bits (the B.4 short/long boundary), so an
/// 18-octet install code fits with room.
pub const MMO_MAX_MSG_LEN: usize = 31;
/// Scratch bound: the longest padded schedule under the cap above
/// (31-octet message → 48 octets / 3 blocks).
const PAD_MAX: usize = 48;

/// Hash failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmoError {
    /// Message too long for the short-padding form.
    TooLong,
}

/// AES-MMO-128 over `msg` (at most [`MMO_MAX_MSG_LEN`] octets).
///
/// Short-padding form: message, a marker octet, zero fill, then the
/// 2-octet big-endian bit length, sized to the smallest whole-block
/// schedule holding them all. For an 18-octet install code that is 2
/// blocks: 18 message + 1 marker + 11 zeros + 2 length octets.
///
/// Requirement `22-65816-030-56-08` (repo-minted,
/// MINTED-pending-confirm).
pub fn mmo_hash_128(msg: &[u8]) -> Result<[u8; MMO_DIGEST_LEN], MmoError> {
    if msg.len() > MMO_MAX_MSG_LEN {
        return Err(MmoError::TooLong);
    }
    let bit_len = msg.len() * 8;
    // Smallest multiple of the block holding message + marker +
    // 2-octet length word (the B.4 short-form schedule).
    let total = (bit_len + 1 + 16).div_ceil(128) * BLOCK_LEN;
    let mut chain = [0u8; BLOCK_LEN];
    let mut scratch = [0u8; PAD_MAX];
    scratch[..msg.len()].copy_from_slice(msg);
    scratch[msg.len()] = 0x80;
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
