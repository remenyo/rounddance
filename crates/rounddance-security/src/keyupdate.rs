//! Trust-center link-key update: MMO-derived rotation plus table
//! install after a completed CBKE handshake.
//!
//! Paraphrase-level model of the doc `07-5356` SE 1.4a §C.4.1 idea
//! that a CBKE-derived link key replaces the bootstrap key in the
//! Trust Center tables (anchor p0167-L4287-L4297), combined with the
//! doc `05-3474-23` key-table ownership in chapter 4 (anchors
//! p0421-L10119-L10123, p0425-L10232-L10236). The rotation formula
//! itself is a rounddance construction (NOT a spec algorithm): the
//! new key is the old key masked with an AES-MMO-128 digest bound to
//! the peer address and a fresh nonce. All wording here is
//! paraphrase (D1, `SCOPE.md` §2).
//!
//! Requirement ID below is repo-minted (`07-5356-<clause>-<seq>`,
//! dots stripped), MINTED-pending-confirm.
//!
//! # Design notes (mirror `classical` / `mmo`)
//!
//! * `no_std` + `#![forbid(unsafe_code)]`, bounded + fallible.
//! * One-shot [`mmo_hash_128`](crate::mmo::mmo_hash_128) only: the
//!   14-octet mask preimage fits the short-padding cap, so no
//!   streaming hash state is needed.

use crate::classical::{LinkKeyEntry, LinkKeyTable, SecError};
use crate::mmo::{mmo_hash_128, MmoError};

/// Two-octet domain label binding the mask to link-key rotation
/// (never collides with install-code derivation, which hashes the
/// code bytes directly).
pub const UPDATE_LABEL: [u8; 2] = [0x55, 0xAA];

/// Derive the 16-octet rotation mask for (`ieee`, `nonce`).
///
/// Requirement `07-5356-C41-02` (MINTED-pending-confirm).
pub fn derive_update_mask(ieee: &[u8; 8], nonce: u32) -> Result<[u8; 16], MmoError> {
    let mut msg = [0u8; 14];
    msg[0..2].copy_from_slice(&UPDATE_LABEL);
    msg[2..10].copy_from_slice(ieee);
    msg[10..14].copy_from_slice(&nonce.to_le_bytes());
    mmo_hash_128(&msg)
}

/// Rotate `old_key` for `ieee` under `nonce`: the new key is the old
/// key masked with the address-bound MMO digest. A repeat (`nonce`,
/// `old_key`) pair reproduces the same key, so callers must use a
/// fresh nonce per rotation; installing the identical key twice is
/// refused at the table step below.
///
/// Requirement `07-5356-C41-02` (MINTED-pending-confirm).
#[must_use]
pub fn derive_update_key(old_key: &[u8; 16], ieee: &[u8; 8], nonce: u32) -> [u8; 16] {
    let mask = derive_update_mask(ieee, nonce).unwrap_or([0u8; 16]);
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = old_key[i] ^ mask[i];
        i += 1;
    }
    out
}

/// Install (or replace) the link key for `ieee`, resetting both
/// counters: a rotated key restarts the frame-counter window.
/// Refuses a key identical to the installed one (`DuplicateKey`)
/// and reports `TableFull` when no slot is free.
///
/// Requirement `07-5356-C41-02` (MINTED-pending-confirm).
pub fn install_link_key<const N: usize>(
    table: &mut LinkKeyTable<N>,
    ieee: [u8; 8],
    key: [u8; 16],
) -> Result<(), SecError> {
    if let Some(existing) = table.find(&ieee) {
        if existing.key == key {
            return Err(SecError::DuplicateKey);
        }
    }
    table.insert(LinkKeyEntry {
        ieee,
        key,
        tx_counter: 0,
        rx_counter: 0,
        rx_seen: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_mask_is_address_and_nonce_bound() {
        let a = derive_update_mask(&[1; 8], 7).unwrap();
        assert_ne!(a, derive_update_mask(&[2; 8], 7).unwrap());
        assert_ne!(a, derive_update_mask(&[1; 8], 8).unwrap());
        assert_eq!(a, derive_update_mask(&[1; 8], 7).unwrap());
    }

    #[test]
    fn update_key_rotates_and_installs() {
        let old = [0x11u8; 16];
        let new = derive_update_key(&old, &[9; 8], 42);
        assert_ne!(new, old);
        let mut table = LinkKeyTable::<4>::new();
        install_link_key(&mut table, [9; 8], new).unwrap();
        assert_eq!(table.find(&[9; 8]).unwrap().key, new);
        // Reinstalling the identical key is refused.
        assert_eq!(
            install_link_key(&mut table, [9; 8], new),
            Err(SecError::DuplicateKey)
        );
        // Rotation replaces and resets counters.
        let newer = derive_update_key(&new, &[9; 8], 43);
        install_link_key(&mut table, [9; 8], newer).unwrap();
        let entry = table.find(&[9; 8]).unwrap();
        assert_eq!(entry.key, newer);
        assert_eq!(entry.tx_counter, 0);
    }
}
