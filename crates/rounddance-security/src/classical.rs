//! Classical security: network-key lifecycle, frame counters and replay
//! protection, Trust-Center link-key handling, and the auxiliary-header
//! frame codec.
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2 chapter 4
//! (outgoing §4.3.1.1 anchor p0421-L10119-L10123, incoming §4.3.1.2
//! anchor p0422-L10156-L10164, secured NPDU §4.3.2 anchor p0423-L10216,
//! counters §4.3.4 anchor p0425-L10232-L10236, switch-key §4.4.6 anchor
//! p0446-L10756-L10759, secured APDU §4.4.10 anchor p0463-L11197, aux
//! header §4.5.1 anchors p0479-L11436-L11461, key hierarchy §4.5.3
//! anchor p0481-L11490, Trust Center §4.6.2 anchor p0482-L11530-L11534).
//! All wording here is paraphrase (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped), MINTED-pending-confirm.

/// Length of a network/link key in octets.
///
/// Requirement `05-3474-23-453-01`.
pub const NETWORK_KEY_LEN: usize = 16;

/// Largest auxiliary-header encoding in octets: 1 control + 4 frame
/// counter + 8 extended-nonce source + 9 key identifier.
///
/// Requirement `05-3474-23-451-01`.
pub const MAX_AUX_LEN: usize = 22;

/// Largest frame-counter value; the counter never wraps — reaching it
/// forces a rekey instead.
///
/// Requirement `05-3474-23-4311-01`.
pub const MAX_FRAME_COUNTER: u32 = 0xffff_ffff;

/// Typed failure for classical-security operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecError {
    /// Caller buffer too small for the encoding.
    TooSmall,
    /// Input truncated: not enough octets for the declared fields.
    Truncated,
    /// Key-identifier mode bits name no implemented mode.
    BadKeyIdMode,
    /// Frame counter exhausted (`MAX_FRAME_COUNTER` reached): the
    /// management layer must rotate the key before sending more.
    CounterExhausted,
    /// Incoming counter does not advance the stored value: replay or
    /// duplicate.
    Replay,
    /// Neighbor table has no free slot.
    TableFull,
    /// No entry for this address or key sequence.
    NotFound,
    /// Refusing to install a key that duplicates the active one.
    DuplicateKey,
    /// Persisted state failed validation (rollback or corruption).
    BadPersisted,
}

/// One 128-bit network key plus the sequence number selecting it.
///
/// Requirement `05-3474-23-453-01`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkKey {
    /// Key octets.
    pub key: [u8; NETWORK_KEY_LEN],
    /// Sequence number carried in the auxiliary header.
    pub seq: u8,
}

impl NetworkKey {
    /// Build a key descriptor from octets and sequence number.
    #[must_use]
    pub const fn new(key: [u8; NETWORK_KEY_LEN], seq: u8) -> Self {
        Self { key, seq }
    }
}

/// Active network key plus at most one staged successor.
///
/// Rotation is two-phase: the successor is installed while the old key
/// stays active, then a single `activate_pending` flips traffic to it.
/// Only one pending key is ever tracked (bounded).
///
/// Requirement `05-3474-23-446-01`.
#[derive(Debug, Clone, Copy)]
pub struct KeySet {
    active: NetworkKey,
    pending: Option<NetworkKey>,
}

impl KeySet {
    /// Start with a single active key.
    #[must_use]
    pub const fn new(initial: NetworkKey) -> Self {
        Self {
            active: initial,
            pending: None,
        }
    }

    /// Current transmit key.
    #[must_use]
    pub const fn active(&self) -> &NetworkKey {
        &self.active
    }

    /// Staged successor, if any.
    #[must_use]
    pub const fn pending(&self) -> Option<&NetworkKey> {
        self.pending.as_ref()
    }

    /// Stage a successor key. Rejects a key identical to the active one
    /// (octets and sequence both equal); replacing an already-staged
    /// key is allowed and overwrites it.
    ///
    /// Requirement `05-3474-23-446-01`.
    pub fn install_pending(&mut self, key: NetworkKey) -> Result<(), SecError> {
        if key == self.active {
            return Err(SecError::DuplicateKey);
        }
        self.pending = Some(key);
        Ok(())
    }

    /// Flip traffic to the staged key. Errors when nothing is staged.
    ///
    /// Requirement `05-3474-23-446-01`.
    pub fn activate_pending(&mut self) -> Result<&NetworkKey, SecError> {
        match self.pending.take() {
            Some(next) => {
                self.active = next;
                Ok(&self.active)
            }
            None => Err(SecError::NotFound),
        }
    }

    /// Pick the key named by an incoming sequence number: active first,
    /// then pending (covers frames in flight across a rotation).
    ///
    /// Requirement `05-3474-23-446-01`.
    #[must_use]
    pub fn select(&self, seq: u8) -> Option<&NetworkKey> {
        if self.active.seq == seq {
            return Some(&self.active);
        }
        match &self.pending {
            Some(p) if p.seq == seq => Some(p),
            _ => None,
        }
    }
}

/// Outgoing frame counter: strictly monotonic, never wraps, with a
/// value-based persistence watermark hook.
///
/// The counter hands out `next` then advances. When `next` reaches
/// [`MAX_FRAME_COUNTER`] it stops with [`SecError::CounterExhausted`]
/// instead of wrapping; the management layer must rotate the network
/// key. `needs_persist` tells the caller when to checkpoint through
/// [`crate::store::NvmStore`]; see [`crate::store`] for the
/// rollback-safe resume rule.
///
/// Requirement `05-3474-23-4311-01`.
#[derive(Debug, Clone, Copy)]
pub struct FrameCounter {
    next: u32,
    last_persisted: u32,
    watermark: u32,
}

impl FrameCounter {
    /// Start from `start_next` (the next value to hand out). A zero
    /// `watermark` is normalized to 1.
    #[must_use]
    pub const fn new(start_next: u32, watermark: u32) -> Self {
        Self {
            next: start_next,
            last_persisted: start_next,
            watermark: if watermark == 0 { 1 } else { watermark },
        }
    }

    /// Next value to hand out (peek; does not advance).
    #[must_use]
    pub const fn peek(&self) -> u32 {
        self.next
    }

    /// Hand out the next counter value and advance. Fallible at the
    /// top of the range: never wraps.
    ///
    /// Requirement `05-3474-23-4311-01`.
    pub fn take(&mut self) -> Result<u32, SecError> {
        if self.next == MAX_FRAME_COUNTER {
            return Err(SecError::CounterExhausted);
        }
        let out = self.next;
        self.next += 1;
        Ok(out)
    }

    /// True once at least `watermark` values have been handed out
    /// since the last checkpoint.
    ///
    /// Requirement `05-3474-23-4311-01`.
    #[must_use]
    pub const fn needs_persist(&self) -> bool {
        self.next.wrapping_sub(self.last_persisted) >= self.watermark
    }

    /// Record that `value` was checkpointed to NVM. Rejects a value
    /// ahead of what was handed out (caller bug, not a rollback).
    pub fn mark_persisted(&mut self, value: u32) -> Result<(), SecError> {
        if value > self.next {
            return Err(SecError::BadPersisted);
        }
        self.last_persisted = value;
        Ok(())
    }

    /// Restore after boot; `resume_next` must come from
    /// [`crate::store::NvmStore`] via its stride rule.
    pub fn resume(&mut self, resume_next: u32) {
        self.next = resume_next;
        self.last_persisted = resume_next;
    }
}

/// Incoming replay guard: per-neighbor last-seen counter. A frame is
/// accepted only when its counter strictly advances the stored value
/// for its source; anything else is a replay or duplicate.
///
/// Bounded: at most `N` neighbors; when full, the entry holding the
/// smallest counter is evicted (documented bounded-table policy — size
/// `N` for at least the expected neighbor count).
///
/// Requirement `05-3474-23-4312-01`.
#[derive(Debug, Clone, Copy)]
pub struct ReplayTable<const N: usize> {
    entries: [(u64, u32); N],
    len: usize,
}

impl<const N: usize> Default for ReplayTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ReplayTable<N> {
    /// Empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [(0, 0); N],
            len: 0,
        }
    }

    /// Number of tracked neighbors.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True when no neighbor is tracked.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Last-seen counter for `addr`, if tracked.
    #[must_use]
    pub fn last(&self, addr: u64) -> Option<u32> {
        self.entries[..self.len]
            .iter()
            .find(|(a, _)| *a == addr)
            .map(|(_, c)| *c)
    }

    /// Validate an incoming `(addr, counter)` pair: accept and record
    /// when the counter advances, reject otherwise.
    ///
    /// Requirement `05-3474-23-4312-01`.
    pub fn check(&mut self, addr: u64, counter: u32) -> Result<(), SecError> {
        for (a, c) in self.entries[..self.len].iter_mut() {
            if *a == addr {
                if counter > *c {
                    *c = counter;
                    return Ok(());
                }
                return Err(SecError::Replay);
            }
        }
        // Unknown source: first frame from it is always accepted.
        if self.len < N {
            self.entries[self.len] = (addr, counter);
            self.len += 1;
            return Ok(());
        }
        // Bounded eviction: drop the stalest (smallest-counter) entry.
        // N == 0 cannot store anything, so a zero-size table rejects.
        if N == 0 {
            return Err(SecError::TableFull);
        }
        let mut victim = 0;
        for i in 1..self.len {
            if self.entries[i].1 < self.entries[victim].1 {
                victim = i;
            }
        }
        self.entries[victim] = (addr, counter);
        Ok(())
    }
}

/// One Trust-Center link key: the long address it belongs to, the key
/// octets, and per-direction counters so link-key frames get the same
/// monotonicity and replay protection as network-key frames.
///
/// Requirement `05-3474-23-462-01`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkKeyEntry {
    /// Owner long address (EUI-64, little-endian octets).
    pub ieee: [u8; 8],
    /// Key octets.
    pub key: [u8; NETWORK_KEY_LEN],
    /// Next outgoing counter for frames to this peer.
    pub tx_counter: u32,
    /// Last accepted incoming counter from this peer.
    pub rx_counter: u32,
    /// Whether any incoming frame has been accepted yet (so counter 0
    /// from a new peer is not mistaken for a replay).
    pub rx_seen: bool,
}

impl LinkKeyEntry {
    /// Fresh entry; counters start at zero, nothing received yet.
    #[must_use]
    pub const fn new(ieee: [u8; 8], key: [u8; NETWORK_KEY_LEN]) -> Self {
        Self {
            ieee,
            key,
            tx_counter: 0,
            rx_counter: 0,
            rx_seen: false,
        }
    }

    /// Hand out the next transmit counter (never wraps).
    pub fn tx_take(&mut self) -> Result<u32, SecError> {
        if self.tx_counter == MAX_FRAME_COUNTER {
            return Err(SecError::CounterExhausted);
        }
        let out = self.tx_counter;
        self.tx_counter += 1;
        Ok(out)
    }

    /// Accept an incoming counter only when it advances.
    pub fn rx_check(&mut self, counter: u32) -> Result<(), SecError> {
        if !self.rx_seen || counter > self.rx_counter {
            self.rx_counter = counter;
            self.rx_seen = true;
            Ok(())
        } else {
            Err(SecError::Replay)
        }
    }
}

/// Bounded Trust-Center link-key table: at most `N` device entries.
///
/// Requirement `05-3474-23-462-01`.
#[derive(Debug, Clone, Copy)]
pub struct LinkKeyTable<const N: usize> {
    entries: [Option<LinkKeyEntry>; N],
}

impl<const N: usize> Default for LinkKeyTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> LinkKeyTable<N> {
    /// Empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    /// Number of installed entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    /// True when no entry is installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert or replace the entry for `ieee`. Errors when full and
    /// the address is new.
    pub fn insert(&mut self, entry: LinkKeyEntry) -> Result<(), SecError> {
        for slot in self.entries.iter_mut() {
            if matches!(slot, Some(e) if e.ieee == entry.ieee) {
                *slot = Some(entry);
                return Ok(());
            }
        }
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                return Ok(());
            }
        }
        Err(SecError::TableFull)
    }

    /// Look up an entry by long address.
    #[must_use]
    pub fn find(&self, ieee: &[u8; 8]) -> Option<&LinkKeyEntry> {
        self.entries
            .iter()
            .filter_map(|e| e.as_ref())
            .find(|e| &e.ieee == ieee)
    }

    /// Mutable lookup (counter updates go through this).
    pub fn find_mut(&mut self, ieee: &[u8; 8]) -> Option<&mut LinkKeyEntry> {
        self.entries
            .iter_mut()
            .filter_map(|e| e.as_mut())
            .find(|e| &e.ieee == ieee)
    }

    /// Remove the entry for `ieee`; errors when absent.
    pub fn remove(&mut self, ieee: &[u8; 8]) -> Result<(), SecError> {
        for slot in self.entries.iter_mut() {
            if matches!(slot, Some(e) if &e.ieee == ieee) {
                *slot = None;
                return Ok(());
            }
        }
        Err(SecError::NotFound)
    }
}

/// How the auxiliary header names the key (2-bit selector).
///
/// Requirement `05-3474-23-451-02`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyIdMode {
    /// One-octet network-key sequence number follows.
    DataKey = 0,
    /// One-octet key index follows (link-key slot reference).
    Index = 1,
    /// Four-octet key source plus one-octet index follow.
    Source4 = 2,
    /// Eight-octet key source plus one-octet index follow.
    Source8 = 3,
}

impl KeyIdMode {
    /// Decode the 2-bit selector; all four values are implemented.
    pub const fn from_bits(bits: u8) -> Result<Self, SecError> {
        match bits & 0x03 {
            0 => Ok(Self::DataKey),
            1 => Ok(Self::Index),
            2 => Ok(Self::Source4),
            _ => Ok(Self::Source8),
        }
    }
}

/// Key identifier field following the frame counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyIdentifier {
    /// Network-key sequence number (`DataKey` mode).
    Seq(u8),
    /// Key index (`Index` mode).
    Index(u8),
    /// Four-octet source + index (`Source4` mode).
    Source4([u8; 4], u8),
    /// Eight-octet source + index (`Source8` mode).
    Source8([u8; 8], u8),
}

impl KeyIdentifier {
    /// Selector bits for this identifier shape.
    #[must_use]
    pub const fn mode(&self) -> KeyIdMode {
        match self {
            Self::Seq(_) => KeyIdMode::DataKey,
            Self::Index(_) => KeyIdMode::Index,
            Self::Source4(_, _) => KeyIdMode::Source4,
            Self::Source8(_, _) => KeyIdMode::Source8,
        }
    }

    /// Encoded length in octets.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        match self {
            Self::Seq(_) | Self::Index(_) => 1,
            Self::Source4(_, _) => 5,
            Self::Source8(_, _) => 9,
        }
    }
}

/// Security-control octet: protection level (3 bits), key-identifier
/// mode (2 bits), extended-nonce flag (1 bit).
///
/// The level value is opaque here (0..=7); payload protection itself
/// is a radio/HAL assist, this crate only carries the selector.
///
/// Requirement `05-3474-23-451-01`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityControl {
    /// Protection level selector, 3 bits.
    pub level: u8,
    /// Key-identifier mode.
    pub key_id: KeyIdMode,
    /// When set, an 8-octet source EUI follows the frame counter.
    pub extended_nonce: bool,
}

impl SecurityControl {
    /// Build; `None` when `level` exceeds 3 bits.
    #[must_use]
    pub const fn new(level: u8, key_id: KeyIdMode, extended_nonce: bool) -> Option<Self> {
        if level > 0x07 {
            return None;
        }
        Some(Self {
            level,
            key_id,
            extended_nonce,
        })
    }

    const fn encode(self) -> u8 {
        self.level | ((self.key_id as u8) << 3) | ((self.extended_nonce as u8) << 5)
    }

    const fn decode(byte: u8) -> Self {
        let mode = match (byte >> 3) & 0x03 {
            0 => KeyIdMode::DataKey,
            1 => KeyIdMode::Index,
            2 => KeyIdMode::Source4,
            _ => KeyIdMode::Source8,
        };
        Self {
            level: byte & 0x07,
            key_id: mode,
            extended_nonce: (byte & 0x20) != 0,
        }
    }
}

/// Auxiliary security header: control octet, 4-octet little-endian
/// frame counter, optional 8-octet extended-nonce source, then the key
/// identifier field selected by the mode bits.
///
/// Requirement `05-3474-23-451-01`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuxHeader {
    /// Control octet (level, mode, extended-nonce flag).
    pub control: SecurityControl,
    /// Frame counter (anti-replay nonce word).
    pub frame_counter: u32,
    /// Extended-nonce source; must be `Some` exactly when
    /// `control.extended_nonce` is set.
    pub ext_source: Option<[u8; 8]>,
    /// Key identifier; its shape must match `control.key_id`.
    pub key_id: KeyIdentifier,
}

impl AuxHeader {
    /// Encoded length in octets, or `None` when control octet and
    /// fields disagree (flag/shape mismatch).
    #[must_use]
    pub const fn header_len(&self) -> Option<usize> {
        if self.control.extended_nonce != self.ext_source.is_some() {
            return None;
        }
        if self.control.key_id as u8 != self.key_id.mode() as u8 {
            return None;
        }
        let mut len = 1 + 4 + self.key_id.encoded_len();
        if self.ext_source.is_some() {
            len += 8;
        }
        Some(len)
    }

    /// Encode into `out`; returns octets written.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, SecError> {
        let len = self.header_len().ok_or(SecError::BadKeyIdMode)?;
        if out.len() < len {
            return Err(SecError::TooSmall);
        }
        out[0] = self.control.encode();
        out[1..5].copy_from_slice(&self.frame_counter.to_le_bytes());
        let mut pos = 5;
        if let Some(src) = self.ext_source {
            out[pos..pos + 8].copy_from_slice(&src);
            pos += 8;
        }
        match self.key_id {
            KeyIdentifier::Seq(s) | KeyIdentifier::Index(s) => {
                out[pos] = s;
                pos += 1;
            }
            KeyIdentifier::Source4(src, idx) => {
                out[pos..pos + 4].copy_from_slice(&src);
                out[pos + 4] = idx;
                pos += 5;
            }
            KeyIdentifier::Source8(src, idx) => {
                out[pos..pos + 8].copy_from_slice(&src);
                out[pos + 8] = idx;
                pos += 9;
            }
        }
        debug_assert_eq!(pos, len);
        Ok(len)
    }

    /// Decode from the front of `buf`; returns the header plus octets
    /// consumed. Rejects truncated inputs and flag/shape mismatches.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), SecError> {
        if buf.len() < 5 {
            return Err(SecError::Truncated);
        }
        let control = SecurityControl::decode(buf[0]);
        let frame_counter = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let mut pos = 5;
        let ext_source = if control.extended_nonce {
            if buf.len() < pos + 8 {
                return Err(SecError::Truncated);
            }
            let mut src = [0u8; 8];
            src.copy_from_slice(&buf[pos..pos + 8]);
            pos += 8;
            Some(src)
        } else {
            None
        };
        let key_id = match control.key_id {
            KeyIdMode::DataKey => {
                if buf.len() < pos + 1 {
                    return Err(SecError::Truncated);
                }
                let id = KeyIdentifier::Seq(buf[pos]);
                pos += 1;
                id
            }
            KeyIdMode::Index => {
                if buf.len() < pos + 1 {
                    return Err(SecError::Truncated);
                }
                let id = KeyIdentifier::Index(buf[pos]);
                pos += 1;
                id
            }
            KeyIdMode::Source4 => {
                if buf.len() < pos + 5 {
                    return Err(SecError::Truncated);
                }
                let mut src = [0u8; 4];
                src.copy_from_slice(&buf[pos..pos + 4]);
                let id = KeyIdentifier::Source4(src, buf[pos + 4]);
                pos += 5;
                id
            }
            KeyIdMode::Source8 => {
                if buf.len() < pos + 9 {
                    return Err(SecError::Truncated);
                }
                let mut src = [0u8; 8];
                src.copy_from_slice(&buf[pos..pos + 8]);
                let id = KeyIdentifier::Source8(src, buf[pos + 8]);
                pos += 9;
                id
            }
        };
        Ok((
            Self {
                control,
                frame_counter,
                ext_source,
                key_id,
            },
            pos,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_rotation_two_phase() {
        let mut set = KeySet::new(NetworkKey::new([0xAA; 16], 1));
        assert!(set.activate_pending().is_err());
        assert_eq!(
            set.install_pending(NetworkKey::new([0xAA; 16], 1)),
            Err(SecError::DuplicateKey)
        );
        set.install_pending(NetworkKey::new([0xBB; 16], 2)).unwrap();
        // In-flight frames on the old key still resolve during staging.
        assert_eq!(set.select(1).unwrap().key, [0xAA; 16]);
        assert_eq!(set.select(2).unwrap().key, [0xBB; 16]);
        assert!(set.select(3).is_none());
        set.activate_pending().unwrap();
        assert_eq!(set.active().seq, 2);
        assert!(set.pending().is_none());
        assert!(set.select(1).is_none());
    }

    #[test]
    fn outgoing_counter_monotonic_and_exhausts() {
        let mut c = FrameCounter::new(0, 4);
        assert_eq!(c.take().unwrap(), 0);
        assert_eq!(c.take().unwrap(), 1);
        assert!(!c.needs_persist());
        c.take().unwrap();
        c.take().unwrap();
        assert!(c.needs_persist());
        c.mark_persisted(4).unwrap();
        assert!(!c.needs_persist());
        assert_eq!(c.mark_persisted(99), Err(SecError::BadPersisted));

        let mut edge = FrameCounter::new(MAX_FRAME_COUNTER - 1, 1);
        assert_eq!(edge.take().unwrap(), MAX_FRAME_COUNTER - 1);
        assert_eq!(edge.take(), Err(SecError::CounterExhausted));
    }

    #[test]
    fn replay_table_accepts_first_advance_only() {
        let mut t = ReplayTable::<4>::new();
        assert!(t.is_empty());
        t.check(0x1111, 7).unwrap();
        assert_eq!(t.last(0x1111), Some(7));
        assert_eq!(t.check(0x1111, 7), Err(SecError::Replay));
        assert_eq!(t.check(0x1111, 3), Err(SecError::Replay));
        t.check(0x1111, 8).unwrap();
        t.check(0x2222, 0).unwrap();
        assert_eq!(t.len(), 2);
    }
}
