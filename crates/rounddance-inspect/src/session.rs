//! Stateful session engine: per-device / per-network tables fed by trees.
//!
//! The engine never parses bytes itself; it folds [`DecodeTree`]s into
//! bounded tables (fixed-size arrays, LRU-by-counter eviction). All
//! bounds are compile-time constants; every insert path is fallible in
//! the sense that a full table evicts the stalest row rather than
//! growing.

use crate::tree::DecodeTree;

/// Devices tracked per engine.
pub const MAX_DEVICES: usize = 32;
/// Networks (PANs) tracked per engine.
pub const MAX_NETWORKS: usize = 4;

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
    /// Recency counter (eviction order).
    pub last_seen: u32,
}

/// One observed network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkEntry {
    /// PAN identifier.
    pub pan_id: u16,
    /// Frames attributed to this PAN.
    pub frames: u32,
    /// Distinct short addresses seen on this PAN.
    pub devices: u8,
    /// Recency counter (eviction order).
    pub last_seen: u32,
}

/// Session engine: fold trees into device/network tables.
#[derive(Clone, Debug)]
pub struct SessionEngine {
    devices: [Option<DeviceEntry>; MAX_DEVICES],
    networks: [Option<NetworkEntry>; MAX_NETWORKS],
    now: u32,
    /// Trees folded so far.
    pub trees: u32,
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
            now: 0,
            trees: 0,
        }
    }

    /// Fold one dissected tree into the tables.
    pub fn note_tree(&mut self, tree: &DecodeTree) {
        self.now = self.now.wrapping_add(1);
        self.trees = self.trees.wrapping_add(1);
        let mac = tree.mac();
        let nwk = tree.nwk();
        let pan = mac.and_then(|m| m.dst_pan).unwrap_or(0);
        self.note_network(pan);
        // Attribute to the most specific source address available.
        if let Some(m) = mac {
            use crate::tree::Addr as A;
            match m.src {
                A::Short(s) => self.note_device(s, None, m.seq),
                A::Extended(e) => {
                    let short = nwk.map(|n| n.src_addr).unwrap_or(0xffff);
                    self.note_device(short, Some(e), m.seq);
                }
                A::None => {
                    if let Some(n) = nwk {
                        self.note_device(n.src_addr, n.src_ieee, n.seq);
                    }
                }
            }
        } else if let Some(n) = nwk {
            self.note_device(n.src_addr, n.src_ieee, n.seq);
        }
        if nwk.is_some() {
            // NWK headers carry no PAN id; NWK-only trees stay under the
            // PAN slot keyed above until a MAC header binds the PAN.
            // (One place to change for a future PAN-conflict dissector.)
            let _ = nwk_pan_of(0);
        }
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

    /// Look up a network by PAN id.
    #[must_use]
    pub fn network(&self, pan: u16) -> Option<NetworkEntry> {
        self.networks
            .iter()
            .filter_map(|n| *n)
            .find(|n| n.pan_id == pan)
    }

    fn note_network(&mut self, pan: u16) {
        self.now = self.now.wrapping_add(1);
        let now = self.now;
        if let Some(slot) = self
            .networks
            .iter_mut()
            .find(|n| matches!(n, Some(e) if e.pan_id == pan))
        {
            if let Some(e) = slot {
                e.frames = e.frames.saturating_add(1);
                e.last_seen = now;
            }
            return;
        }
        let entry = NetworkEntry {
            pan_id: pan,
            frames: 1,
            devices: 0,
            last_seen: now,
        };
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

    fn note_device(&mut self, short: u16, ieee: Option<u64>, seq: u8) {
        self.now = self.now.wrapping_add(1);
        let now = self.now;
        if let Some(slot) = self
            .devices
            .iter_mut()
            .find(|d| matches!(d, Some(e) if e.short_addr == short))
        {
            if let Some(e) = slot {
                if ieee.is_some() {
                    e.ieee = ieee;
                }
                e.last_seq = seq;
                e.frames = e.frames.saturating_add(1);
                e.last_seen = now;
            }
            return;
        }
        let entry = DeviceEntry {
            short_addr: short,
            ieee,
            last_seq: seq,
            frames: 1,
            last_seen: now,
        };
        if let Some(slot) = self.devices.iter_mut().find(|d| d.is_none()) {
            *slot = Some(entry);
            return;
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
    }
}

// NWK headers carry no PAN id; the engine keys NWK-only trees under PAN
// 0 until a MAC header binds the PAN. Kept explicit so a future
// PAN-ID-conflict dissector has one place to change.
fn nwk_pan_of(_dst_addr: u16) -> u16 {
    0
}
