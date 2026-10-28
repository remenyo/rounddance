//! Stateful session engine: per-device / per-network tables fed by trees.
//!
//! The engine never parses bytes itself; it folds [`DecodeTree`]s into
//! bounded tables (fixed-size arrays, LRU-by-counter eviction). All
//! bounds are compile-time constants; every insert path is fallible in
//! the sense that a full table evicts the stalest row rather than
//! growing.
//!
//! Per device the engine keeps: the short/long address binding (an
//! IEEE address seen under a new short merges the row — that is a
//! rejoin, not a new device), NWK sequence and APS counter replay
//! windows (32-deep each, with replay/gap/late accounting), and
//! secured-vs-plain frame counts. Per network: PAN id, distinct
//! device count, and the same secured/plain split. Key slots
//! ([`keys::KeySlots`]) record operator-loaded lab keys so secured
//! frames can be reported as decryptable-offline or not.

use crate::keys::KeySlots;
use crate::tree::DecodeTree;

/// Devices tracked per engine.
pub const MAX_DEVICES: usize = 32;
/// Networks (PANs) tracked per engine.
pub const MAX_NETWORKS: usize = 4;
/// Depth of each per-device replay window (bits).
pub const WINDOW_DEPTH: u32 = 32;

/// 32-deep rolling window over an 8-bit wrapping sequence (NWK seq or
/// APS counter). `base` is the highest sequence accepted so far and
/// bit `k` of `seen` marks `base - k` as received.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SeqWindow {
    /// Highest sequence accepted.
    pub base: u8,
    /// Receipt bitmap relative to `base`.
    pub seen: u32,
    /// Duplicates of already-seen values.
    pub replays: u16,
    /// Values skipped by forward jumps (saturating).
    pub gaps: u16,
    /// Values older than the window (stale retransmits).
    pub late: u16,
}

impl SeqWindow {
    /// Fold one sequence value into the window.
    ///
    /// Forward advances below 128 shift the bitmap and count skipped
    /// values as gaps; a repeat of any in-window value counts as a
    /// replay; anything else (older than the window, or an advance of
    /// 128+ which is indistinguishable from stale) counts as late.
    pub fn note(&mut self, seq: u8) {
        if self.seen == 0 {
            // First value: anchor the window.
            self.base = seq;
            self.seen = 1;
            return;
        }
        let delta = seq.wrapping_sub(self.base);
        if delta == 0 {
            self.replays = self.replays.saturating_add(1);
        } else if delta < 128 {
            if u32::from(delta) >= WINDOW_DEPTH {
                self.seen = 1;
            } else {
                self.seen = (self.seen << delta) | 1;
            }
            self.gaps = self.gaps.saturating_add(u16::from(delta.saturating_sub(1)));
            self.base = seq;
        } else {
            let back = self.base.wrapping_sub(seq);
            if u32::from(back) < WINDOW_DEPTH && self.seen & (1u32 << back) != 0 {
                self.replays = self.replays.saturating_add(1);
            } else {
                self.late = self.late.saturating_add(1);
            }
        }
    }
}

/// One observed device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceEntry {
    /// Short address last seen (MAC or NWK level).
    pub short_addr: u16,
    /// Extended address, once observed.
    pub ieee: Option<u64>,
    /// Last sequence number seen (MAC seq preferred).
    pub last_seq: u8,
    /// Frames attributed to this device.
    pub frames: u32,
    /// NWK-secured frames attributed here.
    pub secured: u32,
    /// NWK sequence replay window (once a NWK header is seen).
    pub nwk_window: Option<SeqWindow>,
    /// APS counter replay window (once an APS header is seen).
    pub aps_window: Option<SeqWindow>,
    /// Recency counter (eviction order).
    pub last_seen: u32,
}

/// Short addresses cached per network for distinct-device counting.
pub const MEMBERS_PER_NETWORK: usize = 8;
/// Empty member sentinel: never a valid source short address.
pub const EMPTY_MEMBER: u16 = 0xffff;

/// One observed network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkEntry {
    /// PAN identifier.
    pub pan_id: u16,
    /// Frames attributed to this PAN.
    pub frames: u32,
    /// Distinct short addresses seen on this PAN (saturates at 255).
    pub devices: u8,
    /// NWK-secured frames on this PAN.
    pub secured: u32,
    /// First-seen short addresses (dedup cache for [`Self::devices`];
    /// stops learning when full — the counter keeps saturating but a
    /// reseen short past capacity may count twice).
    pub members: [u16; MEMBERS_PER_NETWORK],
    /// Recency counter (eviction order).
    pub last_seen: u32,
}

/// Session engine: fold trees into device/network tables.
#[derive(Clone, Debug)]
pub struct SessionEngine {
    devices: [Option<DeviceEntry>; MAX_DEVICES],
    networks: [Option<NetworkEntry>; MAX_NETWORKS],
    keys: KeySlots,
    now: u32,
    /// Trees folded so far.
    pub trees: u32,
    /// Secured NWK frames seen while a key slot was loaded.
    pub secured_decryptable: u32,
    /// Secured NWK frames seen with no key slot loaded.
    pub secured_orphan: u32,
}

impl Default for SessionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionEngine {
    /// Empty engine.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            devices: [None; MAX_DEVICES],
            networks: [None; MAX_NETWORKS],
            keys: KeySlots::new(),
            now: 0,
            trees: 0,
            secured_decryptable: 0,
            secured_orphan: 0,
        }
    }

    /// Operator key loading: delegates to the key slots.
    pub fn set_network_key(&mut self, key: [u8; 16], seq: u8) {
        self.keys.set_network_key(key, seq);
    }

    /// Drop all loaded keys.
    pub fn clear_keys(&mut self) {
        self.keys.clear();
    }

    /// Key-slot state.
    #[must_use]
    pub const fn keys(&self) -> &KeySlots {
        &self.keys
    }

    /// Fold one dissected tree into the tables.
    pub fn note_tree(&mut self, tree: &DecodeTree) {
        self.now = self.now.wrapping_add(1);
        self.trees = self.trees.wrapping_add(1);
        let mac = tree.mac();
        let nwk = tree.nwk();
        let aps = tree.aps();
        let pan = mac.and_then(|m| m.dst_pan).unwrap_or(0);
        let secured = nwk.map(|n| n.security).unwrap_or(false);
        if secured {
            if self.keys.has_key() {
                self.secured_decryptable = self.secured_decryptable.saturating_add(1);
            } else {
                self.secured_orphan = self.secured_orphan.saturating_add(1);
            }
        }
        // Attribute to the most specific source address available.
        let mut row: Option<usize> = None;
        let mut short: Option<u16> = None;
        if let Some(m) = mac {
            use crate::tree::Addr as A;
            match m.src {
                A::Short(s) => {
                    short = Some(s);
                    row = self.note_device(s, None, m.seq, secured);
                }
                A::Extended(e) => {
                    let s = nwk.map(|n| n.src_addr).unwrap_or(0xffff);
                    short = Some(s);
                    row = self.note_device(s, Some(e), m.seq, secured);
                }
                A::None => {
                    if let Some(n) = nwk {
                        short = Some(n.src_addr);
                        row = self.note_device(n.src_addr, n.src_ieee, m.seq, secured);
                    }
                }
            }
        } else if let Some(n) = nwk {
            short = Some(n.src_addr);
            row = self.note_device(n.src_addr, n.src_ieee, n.seq, secured);
        }
        // Fold sequence windows into the attributed row.
        if let Some(idx) = row {
            if let Some(n) = nwk {
                let slot = self.devices[idx].as_mut();
                if let Some(en) = slot {
                    let mut w = en.nwk_window.unwrap_or_default();
                    w.note(n.seq);
                    en.nwk_window = Some(w);
                }
            }
            if let Some(a) = aps {
                let slot = self.devices[idx].as_mut();
                if let Some(en) = slot {
                    let mut w = en.aps_window.unwrap_or_default();
                    w.note(a.counter);
                    en.aps_window = Some(w);
                }
            }
        }
        self.note_network(pan, secured, short);
    }

    /// Device rows, densest first is NOT guaranteed; use [`Self::device`].
    #[must_use]
    pub fn devices(&self) -> &[Option<DeviceEntry>] {
        &self.devices
    }

    /// Network rows.
    #[must_use]
    pub fn networks(&self) -> &[Option<NetworkEntry>] {
        &self.networks
    }

    /// Look up a device by short address.
    #[must_use]
    pub fn device(&self, short: u16) -> Option<DeviceEntry> {
        self.devices
            .iter()
            .filter_map(|d| *d)
            .find(|d| d.short_addr == short)
    }

    /// Look up a device by extended address.
    #[must_use]
    pub fn device_by_ieee(&self, ieee: u64) -> Option<DeviceEntry> {
        self.devices
            .iter()
            .filter_map(|d| *d)
            .find(|d| d.ieee == Some(ieee))
    }

    /// Look up a network by PAN id.
    #[must_use]
    pub fn network(&self, pan: u16) -> Option<NetworkEntry> {
        self.networks
            .iter()
            .filter_map(|n| *n)
            .find(|n| n.pan_id == pan)
    }

    fn note_network(&mut self, pan: u16, secured: bool, short: Option<u16>) {
        self.now = self.now.wrapping_add(1);
        let now = self.now;
        if let Some(slot) = self
            .networks
            .iter_mut()
            .find(|n| matches!(n, Some(e) if e.pan_id == pan))
        {
            if let Some(e) = slot {
                e.frames = e.frames.saturating_add(1);
                if secured {
                    e.secured = e.secured.saturating_add(1);
                }
                if let Some(s) = short {
                    // 0xffff is the empty sentinel (never a valid
                    // source short), so members init to all-sentinel.
                    if !e.members.contains(&s) {
                        e.devices = e.devices.saturating_add(1);
                        if let Some(free) = e.members.iter_mut().find(|m| **m == EMPTY_MEMBER) {
                            *free = s;
                        }
                    }
                }
                e.last_seen = now;
            }
            return;
        }
        let mut entry = NetworkEntry {
            pan_id: pan,
            frames: 1,
            devices: 0,
            secured: u32::from(secured),
            members: [EMPTY_MEMBER; MEMBERS_PER_NETWORK],
            last_seen: now,
        };
        if let Some(s) = short {
            entry.devices = 1;
            entry.members[0] = s;
        }
        if let Some(slot) = self.networks.iter_mut().find(|n| n.is_none()) {
            *slot = Some(entry);
            return;
        }
        // Evict the stalest row.
        let mut oldest = 0;
        for (i, n) in self.networks.iter().enumerate() {
            if n.map(|e| e.last_seen).unwrap_or(0)
                < self.networks[oldest]
                    .map(|e| e.last_seen)
                    .unwrap_or(u32::MAX)
            {
                oldest = i;
            }
        }
        self.networks[oldest] = Some(entry);
    }

    /// Insert or refresh a device row. An IEEE address already filed
    /// under another short merges into that row (rejoin): the short
    /// follows the newest sighting. Returns the row index the frame
    /// was attributed to.
    fn note_device(
        &mut self,
        short: u16,
        ieee: Option<u64>,
        seq: u8,
        secured: bool,
    ) -> Option<usize> {
        self.now = self.now.wrapping_add(1);
        let now = self.now;
        // IEEE-first: a rejoining device keeps its row, short updated.
        let ieee_row = match ieee {
            Some(e) => self
                .devices
                .iter()
                .position(|d| matches!(d, Some(en) if en.ieee == Some(e))),
            None => None,
        };
        if let Some(idx) = ieee_row {
            if let Some(en) = self.devices[idx].as_mut() {
                en.short_addr = short;
                en.ieee = ieee;
                en.last_seq = seq;
                en.frames = en.frames.saturating_add(1);
                if secured {
                    en.secured = en.secured.saturating_add(1);
                }
                en.last_seen = now;
            }
            return Some(idx);
        }
        if let Some(idx) = self
            .devices
            .iter()
            .position(|d| matches!(d, Some(e) if e.short_addr == short))
        {
            if let Some(e) = self.devices[idx].as_mut() {
                if ieee.is_some() {
                    e.ieee = ieee;
                }
                e.last_seq = seq;
                e.frames = e.frames.saturating_add(1);
                if secured {
                    e.secured = e.secured.saturating_add(1);
                }
                e.last_seen = now;
            }
            return Some(idx);
        }
        let entry = DeviceEntry {
            short_addr: short,
            ieee,
            last_seq: seq,
            frames: 1,
            secured: u32::from(secured),
            nwk_window: None,
            aps_window: None,
            last_seen: now,
        };
        if let Some(idx) = self.devices.iter().position(|d| d.is_none()) {
            self.devices[idx] = Some(entry);
            return Some(idx);
        }
        let mut oldest = 0;
        for (i, d) in self.devices.iter().enumerate() {
            if d.map(|e| e.last_seen).unwrap_or(0)
                < self.devices[oldest]
                    .map(|e| e.last_seen)
                    .unwrap_or(u32::MAX)
            {
                oldest = i;
            }
        }
        self.devices[oldest] = Some(entry);
        Some(oldest)
    }
}
// NWK headers carry no PAN id; NWK-only trees key under PAN 0 (see
// `note_tree`'s `unwrap_or(0)`) until a MAC header binds the PAN.
