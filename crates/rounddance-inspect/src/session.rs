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
//! frames can be reported as decryptable-offline or not. Per session
//! ([`SessionTimeline`]) the engine links join → transport → announce
//! → data legs into stage timelines with anomaly flags; the timeline
//! table keys on (PAN, short) exactly like the device rows, so a
//! timeline never follows an IEEE rejoin across shorts (documented,
//! pinned by test).

use crate::keys::KeySlots;
use crate::tree::{DecodeTree, GpKind, MacCmdKind, NwkCmdKind, TouchlinkKind};

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
    /// Key-protected (NWK- or GP-secured) frames attributed here.
    pub secured: u32,
    /// NWK sequence replay window (once a NWK header is seen).
    pub nwk_window: Option<SeqWindow>,
    /// APS counter replay window (once an APS header is seen).
    pub aps_window: Option<SeqWindow>,
    /// Last physically-plausible RSSI observed from this device
    /// (`None` until a tree with radio metadata arrives; positive
    /// sniffer readings file as unknown and never overwrite).
    pub last_rssi: Option<i8>,
    /// Last LQI observed from this device.
    pub last_lqi: Option<u8>,
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
    /// Key-protected (NWK- or GP-secured) frames on this PAN.
    pub secured: u32,
    /// First-seen short addresses (dedup cache for [`Self::devices`];
    /// stops learning when full — the counter keeps saturating but a
    /// reseen short past capacity may count twice).
    pub members: [u16; MEMBERS_PER_NETWORK],
    /// Recency counter (eviction order).
    pub last_seen: u32,
}

/// Session engine: fold trees into device/network/timeline tables.
#[derive(Clone, Debug)]
pub struct SessionEngine {
    devices: [Option<DeviceEntry>; MAX_DEVICES],
    networks: [Option<NetworkEntry>; MAX_NETWORKS],
    timelines: [Option<SessionTimeline>; MAX_TIMELINES],
    keys: KeySlots,
    now: u32,
    /// Trees folded so far.
    pub trees: u32,
    /// Key-protected frames seen while a slot for the sealed domain
    /// was loaded (or verified open at the dissector).
    pub secured_decryptable: u32,
    /// Key-protected frames seen with no slot for the sealed domain.
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
            timelines: [None; MAX_TIMELINES],
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

    /// Operator GP key loading: delegates to the GP key slots (live
    /// state only — a snapshot restore restarts with no GP key, and
    /// the schema stays at v1).
    pub fn set_gp_key(&mut self, key: [u8; 16], key_bit: bool) {
        self.keys.set_gp_key(key, key_bit);
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

    /// Rebuild an engine from saved snapshot fields (see
    /// [`crate::report::session_from_json`]). Table order is
    /// preserved; recency counters restart at zero and the key
    /// rotation counter restarts at the restored slot count — none
    /// of those are rendered, so a save/load round trip re-renders
    /// byte-identically.
    #[must_use]
    pub fn restore(
        trees: u32,
        devices: [Option<DeviceEntry>; MAX_DEVICES],
        networks: [Option<NetworkEntry>; MAX_NETWORKS],
        secured_decryptable: u32,
        secured_orphan: u32,
        key_slots: usize,
    ) -> Self {
        Self {
            devices,
            networks,
            // Snapshot schema v1 carries no timelines (see
            // `crate::report`): a restore restarts with an empty
            // timeline table, like the GP key slots.
            timelines: [None; MAX_TIMELINES],
            keys: KeySlots::restore(key_slots, key_slots.min(u32::MAX as usize) as u32),
            now: 0,
            trees,
            secured_decryptable,
            secured_orphan,
        }
    }

    /// Fold one dissected tree into the tables.
    pub fn note_tree(&mut self, tree: &DecodeTree) {
        self.now = self.now.wrapping_add(1);
        self.trees = self.trees.wrapping_add(1);
        let mac = tree.mac();
        let nwk = tree.nwk();
        let aps = tree.aps();
        // Attribute to the destination PAN when the header carries
        // one, else the source PAN (beacons name only their source
        // PAN), else PAN 0 (acknowledgements name no PAN at all).
        let pan = mac.and_then(|m| m.dst_pan.or(m.src_pan)).unwrap_or(0);
        let nwk_sec = nwk.map(|n| n.security).unwrap_or(false);
        let gp_sec = tree.gp().map(|g| g.secured).unwrap_or(false);
        let secured = nwk_sec || gp_sec;
        if secured {
            // A verified-open leg is decryptable from tree evidence
            // even when this engine holds no key slot itself (keys
            // may reach only the dissector, as in the keyed-glue
            // path); otherwise a slot loaded for the sealed domain
            // still marks the frame decryptable-offline — NWK slots
            // never cover GP legs, and GP slots never cover NWK
            // legs — exactly as before for NWK-only trees.
            let covered = tree.decrypted()
                || (nwk_sec && self.keys.has_key())
                || (gp_sec && self.keys.has_gp_key());
            if covered {
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
            // Fold radio metadata: LQI always, RSSI only when the
            // tree carries a physically-plausible reading (the tree
            // already files positive sniffer quirks as unknown).
            if let Some(radio) = tree.radio() {
                let slot = self.devices[idx].as_mut();
                if let Some(en) = slot {
                    if radio.rssi.is_some() {
                        en.last_rssi = radio.rssi;
                    }
                    en.last_lqi = Some(radio.lqi);
                }
            }
        }
        // Timeline fold: session-stage legs ride on the same (PAN,
        // short) key as the device row, so MAC-only join legs and
        // NWK-carried data legs meet in one row — except accepts and
        // transport-key legs, which the coordinator sends: those key
        // on the joiner (destination) short, never the coordinator
        // source, or every join would pollute the coordinator row.
        // Source-less trees (acks, beacon requests) and the 0xffff
        // sentinel short never open a timeline. A gap the replay
        // windows just counted is timeline evidence too: the session
        // saw frames go missing.
        if let Some(ev) = classify_tree(tree) {
            let key: Option<(u16, Option<u64>)> = match ev {
                TimelineEvent::JoinAccept | TimelineEvent::TransportKey => {
                    accept_key(tree).or(short).map(|s| (s, None))
                }
                _ => short.map(|s| (s, tree_ieee(tree))),
            };
            if let Some((s, ieee)) = key {
                if s != EMPTY_MEMBER {
                    let mut gaps = false;
                    if let Some(idx) = row {
                        if let Some(en) = self.devices[idx].as_ref() {
                            gaps = en.nwk_window.is_some_and(|w| w.gaps > 0)
                                || en.aps_window.is_some_and(|w| w.gaps > 0);
                        }
                    }
                    self.note_timeline(pan, s, ieee, ev, gaps);
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
            last_rssi: None,
            last_lqi: None,
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

// ---------------------------------------------------------------------------
// Session timelines: join → transport → announce → data per (PAN, short).
// ---------------------------------------------------------------------------

/// Sessions (join lifecycles) tracked per engine.
pub const MAX_TIMELINES: usize = 16;
/// Timeline event-log depth (oldest entries drop off past this).
pub const MAX_TIMELINE_EVENTS: usize = 8;

/// Anomaly flag: transport, announce, or data observed with no
/// join-accept on record for this session (frames from an unknown or
/// already-left device, or a capture that starts mid-session).
pub const DATA_BEFORE_JOIN: u8 = 0x01;
/// Anomaly flag: a fresh join request while the session was already
/// joined and never left (rejoin without a leave, or a duplicate
/// request storm).
pub const REJOIN_WITHOUT_LEAVE: u8 = 0x02;
/// Anomaly flag: transport, announce, or data observed after a leave
/// with no rejoin-accept since.
pub const DATA_AFTER_LEAVE: u8 = 0x04;
/// Observation flag: the session's device row counted an NWK or APS
/// sequence gap at some folded frame (frames went missing on air).
pub const GAP_OBSERVED: u8 = 0x08;

/// Lifecycle stage of one session. Stages advance monotonically
/// (partial captures may skip stages: data on a capture that starts
/// mid-session jumps straight to [`TimelineStage::Active`] and files
/// [`DATA_BEFORE_JOIN`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TimelineStage {
    /// No join leg seen yet.
    #[default]
    Absent,
    /// A join request is on record, no accept yet.
    Joining,
    /// An accept (status 0) is on record.
    Joined,
    /// A transport-key leg followed the accept.
    Keyed,
    /// A Device-annce followed the transport leg.
    Announced,
    /// Application data is flowing.
    Active,
}

/// One timeline-relevant leg, classified from a dissected tree.
///
/// Sealed frames never classify: a secured transport-key outer shows
/// no APS command leg without its key, so an invisible keying step
/// stays invisible rather than guessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimelineEvent {
    /// MAC association request, NWK rejoin request, Touchlink
    /// start/join request.
    JoinRequest,
    /// Accepted join (any accept leg with status 0).
    JoinAccept,
    /// Refused join (any accept leg with status != 0).
    JoinDeny,
    /// MAC disassociation or NWK leave.
    Leave,
    /// APS transport-key command (`0x05`).
    TransportKey,
    /// ZDO Device-annce (`0x0013` request).
    Announce,
    /// Application data (ZCL leg, non-ZDO APS data, GP data).
    Data,
}

impl TimelineEvent {
    /// Compact log discriminant (stable across releases).
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::JoinRequest => 1,
            Self::JoinAccept => 2,
            Self::JoinDeny => 3,
            Self::Leave => 4,
            Self::TransportKey => 5,
            Self::Announce => 6,
            Self::Data => 7,
        }
    }

    /// Short log/report name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::JoinRequest => "join-req",
            Self::JoinAccept => "join-accept",
            Self::JoinDeny => "join-deny",
            Self::Leave => "leave",
            Self::TransportKey => "transport-key",
            Self::Announce => "announce",
            Self::Data => "data",
        }
    }
}

/// One observed session: the linked join → transport → announce →
/// data chain for a single (PAN, short) key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionTimeline {
    /// PAN identifier the session lives on.
    pub pan_id: u16,
    /// Short address the session is keyed on.
    pub short_addr: u16,
    /// Extended address, once a leg carries it.
    pub ieee: Option<u64>,
    /// Highest lifecycle stage reached.
    pub stage: TimelineStage,
    /// Bitwise anomaly flags ([`DATA_BEFORE_JOIN`] et al).
    pub anomalies: u8,
    /// True once a leave leg folded with no rejoin-accept since.
    pub left: bool,
    /// Total timeline events folded (the log keeps the last
    /// [`MAX_TIMELINE_EVENTS`]).
    pub event_total: u32,
    /// Recent event log: (event code, tree number) pairs.
    pub log: [Option<(u8, u32)>; MAX_TIMELINE_EVENTS],
    /// Recency counter (eviction order).
    pub last_seen: u32,
}

impl SessionTimeline {
    /// Total timeline events folded into this session.
    #[must_use]
    pub const fn events(self) -> u32 {
        self.event_total
    }
}

/// Classify one dissected tree into its session-timeline event, if
/// any. Non-session legs (acks, beacons, polls, route/link-status
/// chatter, scan exchanges, sealed frames) yield `None` and never
/// open or touch a timeline.
#[must_use]
pub fn classify_tree(tree: &DecodeTree) -> Option<TimelineEvent> {
    // MAC join legs first: they ride on command frames with no NWK.
    if let Some(m) = tree.maccmd() {
        match m.kind {
            MacCmdKind::AssocReq { .. } => return Some(TimelineEvent::JoinRequest),
            MacCmdKind::AssocResp { status, .. } => {
                return Some(if status == 0 {
                    TimelineEvent::JoinAccept
                } else {
                    TimelineEvent::JoinDeny
                });
            }
            MacCmdKind::Disassoc { .. } => return Some(TimelineEvent::Leave),
            _ => return None,
        }
    }
    // NWK join/leave legs (unsecured or verified-open only: sealed
    // frames carry no `NwkCmd` layer).
    if let Some(n) = tree.nwkcmd() {
        match n.kind {
            NwkCmdKind::RejoinRequest { .. } => return Some(TimelineEvent::JoinRequest),
            NwkCmdKind::RejoinResponse { status, .. } => {
                return Some(if status == 0 {
                    TimelineEvent::JoinAccept
                } else {
                    TimelineEvent::JoinDeny
                });
            }
            NwkCmdKind::Leave { .. } => return Some(TimelineEvent::Leave),
            _ => return None,
        }
    }
    // Touchlink order legs (broadcast-PAN outers, never NWK).
    if let Some(t) = tree.touchlink() {
        match t.kind {
            TouchlinkKind::StartReq { .. } | TouchlinkKind::JoinReq { .. } => {
                return Some(TimelineEvent::JoinRequest)
            }
            TouchlinkKind::StartRsp { status } | TouchlinkKind::JoinRsp { status } => {
                return Some(if status == 0 {
                    TimelineEvent::JoinAccept
                } else {
                    TimelineEvent::JoinDeny
                });
            }
            _ => return None,
        }
    }
    // APS transport-key command (visible on unsecured or
    // verified-open legs only).
    if let Some(a) = tree.aps() {
        if a.frame_type == 1 {
            if a.command_id == Some(0x05) {
                return Some(TimelineEvent::TransportKey);
            }
            return None;
        }
    }
    // ZDO Device-annce request; every other envelope is chatter.
    if let Some(z) = tree.zdo() {
        if z.cluster_id == 0x0013 && !z.is_response {
            return Some(TimelineEvent::Announce);
        }
        return None;
    }
    // Application data: a ZCL leg, a non-ZDO APS data frame, or GP
    // application data.
    if tree.zcl().is_some() {
        return Some(TimelineEvent::Data);
    }
    if let Some(a) = tree.aps() {
        if a.frame_type == 0 && a.profile_id != 0x0000 {
            return Some(TimelineEvent::Data);
        }
    }
    if tree.gp().is_some_and(|g| g.kind == GpKind::Data) {
        return Some(TimelineEvent::Data);
    }
    None
}

/// Joiner short for coordinator-sourced legs: the unicast MAC
/// destination first (association responses name the assigned short
/// there), then the unicast NWK destination (rejoin responses and
/// transport-key outers). Broadcast destinations never key a
/// session; the caller falls back to the source short.
fn accept_key(tree: &DecodeTree) -> Option<u16> {
    use crate::tree::Addr as A;
    if let Some(m) = tree.mac() {
        if let A::Short(d) = m.dst {
            if d != EMPTY_MEMBER {
                return Some(d);
            }
        }
    }
    if let Some(n) = tree.nwk() {
        if n.dst_addr != EMPTY_MEMBER {
            return Some(n.dst_addr);
        }
    }
    None
}

/// Source IEEE address carried by a tree, if any leg names one.
fn tree_ieee(tree: &DecodeTree) -> Option<u64> {
    if let Some(m) = tree.mac() {
        if let crate::tree::Addr::Extended(e) = m.src {
            return Some(e);
        }
    }
    if let Some(n) = tree.nwk() {
        if let Some(e) = n.src_ieee {
            return Some(e);
        }
    }
    None
}

impl SessionEngine {
    /// Timeline rows (table order, dense-prefix not guaranteed).
    #[must_use]
    pub fn timelines(&self) -> &[Option<SessionTimeline>; MAX_TIMELINES] {
        &self.timelines
    }

    /// Look up a session timeline by (PAN, short).
    #[must_use]
    pub fn timeline(&self, pan: u16, short: u16) -> Option<SessionTimeline> {
        self.timelines
            .iter()
            .filter_map(|t| *t)
            .find(|t| t.pan_id == pan && t.short_addr == short)
    }

    /// Fold one timeline event into the (PAN, short) row, opening the
    /// row on first sight. `gaps` marks sequence gaps the device
    /// replay windows already counted for this frame.
    fn note_timeline(
        &mut self,
        pan: u16,
        short: u16,
        ieee: Option<u64>,
        ev: TimelineEvent,
        gaps: bool,
    ) {
        self.now = self.now.wrapping_add(1);
        let now = self.now;
        let tree_no = self.trees;
        let idx = if let Some(i) = self
            .timelines
            .iter()
            .position(|t| matches!(t, Some(e) if e.pan_id == pan && e.short_addr == short))
        {
            i
        } else if let Some(i) = self.timelines.iter().position(|t| t.is_none()) {
            self.timelines[i] = Some(SessionTimeline {
                pan_id: pan,
                short_addr: short,
                ieee,
                stage: TimelineStage::Absent,
                anomalies: 0,
                left: false,
                event_total: 0,
                log: [None; MAX_TIMELINE_EVENTS],
                last_seen: now,
            });
            i
        } else {
            // Evict the stalest row.
            let mut oldest = 0;
            for (i, t) in self.timelines.iter().enumerate() {
                if t.map(|e| e.last_seen).unwrap_or(0)
                    < self.timelines[oldest]
                        .map(|e| e.last_seen)
                        .unwrap_or(u32::MAX)
                {
                    oldest = i;
                }
            }
            self.timelines[oldest] = Some(SessionTimeline {
                pan_id: pan,
                short_addr: short,
                ieee,
                stage: TimelineStage::Absent,
                anomalies: 0,
                left: false,
                event_total: 0,
                log: [None; MAX_TIMELINE_EVENTS],
                last_seen: now,
            });
            oldest
        };
        if let Some(tl) = self.timelines[idx].as_mut() {
            if ieee.is_some() {
                tl.ieee = ieee;
            }
            let joined_or_beyond = match tl.stage {
                TimelineStage::Absent | TimelineStage::Joining => false,
                TimelineStage::Joined
                | TimelineStage::Keyed
                | TimelineStage::Announced
                | TimelineStage::Active => true,
            };
            match ev {
                TimelineEvent::JoinRequest => {
                    if joined_or_beyond && !tl.left {
                        tl.anomalies |= REJOIN_WITHOUT_LEAVE;
                    } else {
                        tl.stage = TimelineStage::Joining;
                        tl.left = false;
                    }
                }
                TimelineEvent::JoinAccept => {
                    if !joined_or_beyond {
                        tl.stage = TimelineStage::Joined;
                    }
                    tl.left = false;
                }
                TimelineEvent::JoinDeny => {}
                TimelineEvent::Leave => {
                    tl.left = true;
                }
                TimelineEvent::TransportKey => {
                    if !joined_or_beyond {
                        tl.anomalies |= DATA_BEFORE_JOIN;
                    } else if tl.left {
                        tl.anomalies |= DATA_AFTER_LEAVE;
                    } else if tl.stage == TimelineStage::Joined {
                        tl.stage = TimelineStage::Keyed;
                    }
                }
                TimelineEvent::Announce => {
                    if !joined_or_beyond {
                        tl.anomalies |= DATA_BEFORE_JOIN;
                    } else if tl.left {
                        tl.anomalies |= DATA_AFTER_LEAVE;
                    } else if tl.stage == TimelineStage::Joined || tl.stage == TimelineStage::Keyed
                    {
                        tl.stage = TimelineStage::Announced;
                    }
                }
                TimelineEvent::Data => {
                    if !joined_or_beyond {
                        tl.anomalies |= DATA_BEFORE_JOIN;
                    } else if tl.left {
                        tl.anomalies |= DATA_AFTER_LEAVE;
                    }
                    if !tl.left {
                        tl.stage = TimelineStage::Active;
                    }
                }
            }
            if gaps {
                tl.anomalies |= GAP_OBSERVED;
            }
            tl.event_total = tl.event_total.saturating_add(1);
            // Shift the log when full; the newest event lands last.
            if tl.log[MAX_TIMELINE_EVENTS - 1].is_some() {
                tl.log.copy_within(1.., 0);
                tl.log[MAX_TIMELINE_EVENTS - 1] = None;
            }
            if let Some(slot) = tl.log.iter_mut().find(|s| s.is_none()) {
                *slot = Some((ev.code(), tree_no));
            }
            tl.last_seen = now;
        }
    }
}
