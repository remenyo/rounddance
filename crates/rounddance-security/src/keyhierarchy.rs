//! Link-key hierarchy: the working keys derived from a link key.
//!
//! Paraphrase-level model of the clause naming the keys each link
//! key determines: the data key is the link key itself, while the
//! key-transport key and the key-load key are the outcomes of the
//! keyed hash (see [`crate::mmo`]) run under the link key with a
//! distinct one-octet domain input per purpose. The transport key is
//! the one that protects the over-the-air network-key delivery; the
//! load key protects transported link keys. Only the 128-bit key
//! form is provided.
//!
//! Requirement `05-3474-23-453-01` (repo-minted,
//! MINTED-pending-confirm). Anchor p0481-L11489-L11497 (hierarchy
//! clause). All wording here is paraphrase (D1, `SCOPE.md` §2).

use crate::mmo::{hmac_mmo_128, MmoError, MMO_DIGEST_LEN};

/// Domain input selecting the key-transport key from a link key.
pub const TRANSPORT_KEY_INPUT: [u8; 1] = [0x00];
/// Domain input selecting the key-load key from a link key.
pub const LOAD_KEY_INPUT: [u8; 1] = [0x02];

/// Derive the key-transport key: the keyed hash under `link_key`
/// with the transport domain input. The returned key is the one a
/// receiver rebuilds from its install-code-derived link key to open
/// the Trust Center's network-key delivery.
///
/// Requirement `05-3474-23-453-01` (repo-minted,
/// MINTED-pending-confirm).
pub fn derive_key_transport_key(
    link_key: &[u8; MMO_DIGEST_LEN],
) -> Result<[u8; MMO_DIGEST_LEN], MmoError> {
    hmac_mmo_128(link_key, &TRANSPORT_KEY_INPUT)
}

/// Derive the key-load key: the keyed hash under `link_key` with the
/// load domain input.
///
/// Requirement `05-3474-23-453-01` (repo-minted,
/// MINTED-pending-confirm).
pub fn derive_key_load_key(
    link_key: &[u8; MMO_DIGEST_LEN],
) -> Result<[u8; MMO_DIGEST_LEN], MmoError> {
    hmac_mmo_128(link_key, &LOAD_KEY_INPUT)
}

/// The data key is the link key itself (no derivation step).
///
/// Requirement `05-3474-23-453-01` (repo-minted,
/// MINTED-pending-confirm).
#[must_use]
pub const fn data_key_is_link_key(link_key: &[u8; MMO_DIGEST_LEN]) -> &[u8; MMO_DIGEST_LEN] {
    link_key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hierarchy_is_deterministic_and_domain_separated() {
        let link = [0x42u8; 16];
        assert_eq!(
            derive_key_transport_key(&link).unwrap(),
            derive_key_transport_key(&link).unwrap()
        );
        assert_eq!(
            derive_key_load_key(&link).unwrap(),
            derive_key_load_key(&link).unwrap()
        );
        assert_ne!(
            derive_key_transport_key(&link).unwrap(),
            derive_key_load_key(&link).unwrap()
        );
        assert_ne!(derive_key_transport_key(&link).unwrap(), link);
        assert_ne!(derive_key_load_key(&link).unwrap(), link);
        // Distinct link keys derive distinct working keys.
        let other = [0x43u8; 16];
        assert_ne!(
            derive_key_transport_key(&link).unwrap(),
            derive_key_transport_key(&other).unwrap()
        );
    }

    #[test]
    fn keyed_input_too_long_is_refused() {
        let link = [0x42u8; 16];
        assert_eq!(hmac_mmo_128(&link, &[0xAA; 49]), Err(MmoError::TooLong));
        assert!(hmac_mmo_128(&link, &[0xAA; 48]).is_ok());
    }
}
