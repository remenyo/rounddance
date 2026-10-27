//! Classical security plus ECQV/CBKE foundations.
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2 chapter 4
//! (classical network/link-key security, frame counters, auxiliary
//! headers; clause anchors: §4.3.1.1 p0421-L10119-L10123, §4.3.1.2
//! p0422-L10156-L10164, §4.3.4 p0425-L10232-L10236, §4.4.6
//! p0446-L10756-L10759, §4.4.10 p0463-L11197, §4.5.1 p0479-L11436-L11461,
//! §4.5.3 p0481-L11490, §4.6.2 p0482-L11530-L11534) and doc `07-5356`
//! SE 1.4a §§5/C.4.2 (CBKE with CA-signed implicit certificates,
//! ECQV-style; anchors: p0149-L3853-L3857, p0167-L4302-L4306,
//! p0168-L4321-L4329, p0169-L4365-L4374). All wording here is
//! paraphrase; citations name document, revision, and clause/line only
//! (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>` and `07-5356-<clause>-<seq>`, dots
//! stripped), MINTED-pending-confirm.
//!
//! # Design notes (mirror `rounddance-nwk` / `rounddance-aps`)
//!
//! * `no_std` + `#![forbid(unsafe_code)]`, bounded + fallible +
//!   accountable: counters, tables, and handshake transcripts live in
//!   fixed-size arrays; every fallible path returns a typed error.
//! * No concrete elliptic-curve code in the core: [`ecc::EccBackend`]
//!   injects point arithmetic, ECDH, KDF, and MAC per target (PSA on
//!   ESP, `p256` on host). Reconstruction, MQV-style agreement, and
//!   key confirmation are pure logic over that trait.
//! * Payload encryption (AES-CCM\*) stays a radio/HAL assist per the
//!   wave-2b contract; this crate owns key selection, nonces/counters,
//!   auxiliary-header framing, and the CBKE handshake that installs
//!   the keys.
//! * Time is never read: persistence watermarks are value-based, so
//!   sim virtual time drives everything deterministically.

#![no_std]
#![forbid(unsafe_code)]

pub mod aes;
#[cfg(feature = "host")]
pub mod backend_host;
pub mod cbke;
pub mod cert;
pub mod classical;
pub mod ecc;
pub mod mmo;
pub mod mock;
pub mod store;

pub use aes::{encrypt_block_aes128, BLOCK_LEN};
pub use cbke::{
    CbkeError, CbkeSession, CbkeState, Role, CONFIRM_LABEL_U, CONFIRM_LABEL_V, SESSION_KEY_LABEL,
};
pub use cert::{ImplicitCert, PeerIdentity, IMPLICIT_CERT_LEN};
pub use classical::{
    AuxHeader, FrameCounter, KeyIdMode, KeyIdentifier, KeySet, LinkKeyEntry, LinkKeyTable,
    NetworkKey, ReplayTable, SecError, SecurityControl, MAX_AUX_LEN, NETWORK_KEY_LEN,
};
pub use ecc::{
    mqv_agree, reconstruct_static, scalar_from_kdf, session_keys, EccBackend, EccError, MAC_LEN,
    MAX_KDF_OUT, POINT_LEN, SCALAR_LEN,
};
pub use mmo::{mmo_hash_128, MmoError, MMO_DIGEST_LEN, MMO_MAX_MSG_LEN};
pub use store::{NvmStore, PersistedState, RamStore, StoreError, COUNTER_STRIDE};

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-security"
}
