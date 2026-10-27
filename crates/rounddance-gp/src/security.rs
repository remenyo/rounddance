//! GP security: key-type records, AES-nonce construction, and
//! frame-counter tracking with replay protection wired to
//! [`rounddance_security`] primitives.
//!
//! Paraphrase-level model of doc `14-0563-19` §A.1.5.3 (security
//! operation; anchors p0048-L1061-L1073, p0049-L1075-L1109,
//! p0049-L1111-L1115) and §A.3.6.1.3 (counter advance; anchor
//! p0184-L5227-L5231). All wording here is paraphrase (D1,
//! `SCOPE.md` §2).
//!
//! Requirement IDs below are corpus-mined `14-0563-19-*`. Counter and
//! replay storage reuse `rounddance_security::{FrameCounter,
//! ReplayTable}` — nothing here duplicates those machines.

use rounddance_security::{FrameCounter, ReplayTable, SecError};

/// Length of the AES nonce consumed by GP security processing.
///
/// Requirement `14-0563-19-A153-01`.
pub const NONCE_LEN: usize = 13;

/// Security-control octet value pinned for GP nonce construction.
///
/// Requirement `14-0563-19-A153-01` (level/key-id/extended-nonce
/// values are fixed for interop, never exchanged on air).
pub const NONCE_CONTROL_LEVEL: u8 = 0b101;

/// Key-identifier sub-field value pinned for GP nonce construction.
///
/// Requirement `14-0563-19-A153-01`.
pub const NONCE_CONTROL_KEY_ID: u8 = 0b00;

/// Protection level selected for one GP frame.
///
/// Requirement `14-0563-19-A153-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpSecurityLevel {
    /// Unprotected frame.
    None,
    /// Counter plus integrity code.
    MicOnly,
    /// Encrypted payload plus counter plus integrity code.
    Encrypted,
}

/// Key-type record selecting the key that protects one GPD's frames.
///
/// The wire key bit follows the key-type mapping: the shared/group
/// key types map to bit `0b0`, the individual key types to `0b1`.
///
/// Requirement `14-0563-19-A153-01` (key selection per frame).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpKeyType(pub u8);

impl GpKeyType {
    /// No key installed.
    pub const NONE: Self = Self(0b000);
    /// Network-shared key.
    pub const SHARED: Self = Self(0b001);
    /// Preconfigured group key.
    pub const GROUP: Self = Self(0b010);
    /// Derived group key.
    pub const DERIVED: Self = Self(0b011);
    /// Individual (per-GPD) key.
    pub const INDIVIDUAL: Self = Self(0b100);
    /// Out-of-band commissioned individual key.
    pub const OOB: Self = Self(0b111);

    /// Wire key-bit value, or `None` for the reserved key types.
    ///
    /// Requirement `14-0563-19-A153-01`.
    #[must_use]
    pub const fn wire_bit(self) -> Option<bool> {
        match self.0 {
            0b000..=0b011 => Some(false),
            0b100 | 0b111 => Some(true),
            _ => None,
        }
    }
}

/// One installed GPD key plus its type tag.
///
/// Requirement `14-0563-19-A153-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpKey {
    /// Which key type this record holds.
    pub key_type: GpKeyType,
    /// 128-bit key octets.
    pub key: [u8; 16],
}

impl GpKey {
    /// Build a key record; reserved key types are refused.
    pub const fn new(key_type: GpKeyType, key: [u8; 16]) -> Option<Self> {
        if key_type.wire_bit().is_none() {
            return None;
        }
        Some(Self { key_type, key })
    }
}

/// Thirteen-octet AES nonce binding GPD identity to frame counter.
///
/// Requirement `14-0563-19-A153-01` (nonce packs source address plus
/// counter, all little-endian; endpoint excluded).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpNonce {
    /// Nonce octets, little-endian field order.
    pub bytes: [u8; NONCE_LEN],
}

impl GpNonce {
    /// Source-address half for a source-identifier GPD on an
    /// incoming frame: the identifier repeated in both words.
    ///
    /// Requirement `14-0563-19-A153-01`.
    #[must_use]
    pub const fn incoming_srcid_addr(srcid: u32) -> [u8; 8] {
        let lo = srcid.to_le_bytes();
        [lo[0], lo[1], lo[2], lo[3], lo[0], lo[1], lo[2], lo[3]]
    }

    /// Source-address half for a source-identifier GPD on an
    /// outgoing frame: the identifier in the high word, zero low.
    ///
    /// Requirement `14-0563-19-A153-01`.
    #[must_use]
    pub const fn outgoing_srcid_addr(srcid: u32) -> [u8; 8] {
        let hi = srcid.to_le_bytes();
        [0, 0, 0, 0, hi[0], hi[1], hi[2], hi[3]]
    }

    /// Source-address half for an IEEE-addressed GPD, either
    /// direction: the GPD address itself.
    ///
    /// Requirement `14-0563-19-A153-01`.
    #[must_use]
    pub const fn ieee_addr(addr: [u8; 8]) -> [u8; 8] {
        addr
    }

    /// Nonce control octet: fixed level/key-id values with the
    /// reserved bits set per direction and identity scheme
    /// (outgoing IEEE-addressed frames use `0b11`, all others
    /// `0b00`).
    ///
    /// Requirement `14-0563-19-A153-01`.
    #[must_use]
    pub const fn control_byte(outgoing_ieee: bool) -> u8 {
        let reserved = if outgoing_ieee { 0b11 } else { 0b00 };
        NONCE_CONTROL_LEVEL | (NONCE_CONTROL_KEY_ID << 3) | (reserved << 6)
    }

    /// Assemble a nonce from address half, counter, and control.
    ///
    /// Requirement `14-0563-19-A153-01`.
    #[must_use]
    pub const fn build(addr: [u8; 8], counter: u32, outgoing_ieee: bool) -> Self {
        let c = counter.to_le_bytes();
        let control = Self::control_byte(outgoing_ieee);
        Self {
            bytes: [
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], c[0], c[1],
                c[2], c[3], control,
            ],
        }
    }
}

/// Per-GPD frame-counter tracking with replay protection.
///
/// Accepted counters must strictly exceed the stored value; there is
/// no rollover support — reaching the top forces key/counter
/// maintenance outside this machine. Storage reuses
/// [`ReplayTable`]; keying is the [`crate::GpdId::table_key`].
///
/// Requirement `14-0563-19-A36-05`.
#[derive(Debug)]
pub struct GpReplay<const N: usize> {
    table: ReplayTable<N>,
}

impl<const N: usize> GpReplay<N> {
    /// Empty tracker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            table: ReplayTable::new(),
        }
    }

    /// Validate an incoming counter for one GPD table key.
    ///
    /// Requirement `14-0563-19-A36-05`.
    pub fn check(&mut self, table_key: u64, counter: u32) -> Result<(), SecError> {
        self.table.check(table_key, counter)
    }

    /// Last accepted counter for one GPD table key, if any.
    #[must_use]
    pub fn last(&self, table_key: u64) -> Option<u32> {
        self.table.last(table_key)
    }

    /// Number of tracked GPDs.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.table.len()
    }

    /// True when no GPD is tracked.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

impl<const N: usize> Default for GpReplay<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Outgoing GP frame-counter source: thin alias over the shared
/// [`FrameCounter`] so infrastructure devices advance one monotonic
/// counter per secured transmission.
///
/// Requirement `14-0563-19-A153-01` (outgoing frames reuse the last
/// GPD counter value as the nonce word).
pub type GpTxCounter = FrameCounter;
