//! Structured decode tree: one bounded, `Copy`-scalar node per layer.
//!
//! The tree carries owned scalars only (no borrows, no allocator) so a
//! dissected frame can be stored in session tables, logged, or rendered
//! later. Rendering to text/JSON lives in [`crate::report`] (`std`).

/// 802.15.4 short-or-extended address, owned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Addr {
    /// Absent (addressing mode `None`).
    None,
    /// 16-bit short address.
    Short(u16),
    /// 64-bit extended address.
    Extended(u64),
}

/// Radio capture metadata for one dissected frame: the listener's
/// channel plus signal readings. The dissector never uses these for
/// parsing; they travel with the tree so session tables and reports
/// can attribute signal quality per device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Radio {
    /// 802.15.4 channel the frame arrived on (11–26).
    pub channel: u8,
    /// Received signal strength in dBm, when physically plausible
    /// (see [`crate::capture`] for the validity range: positive
    /// readings are sniffer-side quirks and arrive here as `None`).
    pub rssi: Option<i8>,
    /// Link quality indicator (0–255, radio-defined).
    pub lqi: u8,
}

/// 802.15.4 MAC header summary (frame-control + sequencing + addressing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacNode {
    /// Frame type (bits 0–2): beacon / data / ack / command.
    pub frame_type: u8,
    /// MAC command identifier: the first MSDU octet of command
    /// frames (association, data-request poll, beacon request, ...),
    /// `None` on every other frame type and on empty command
    /// payloads.
    pub command_id: Option<u8>,
    /// Security enabled (bit 3).
    pub security_enabled: bool,
    /// Sequence number (suppressed variant records 0 + `seq_present`).
    pub seq: u8,
    /// Sequence number present on air.
    pub seq_present: bool,
    /// Destination PAN identifier, when present.
    pub dst_pan: Option<u16>,
    /// Destination address.
    pub dst: Addr,
    /// Source PAN identifier, when present on air.
    pub src_pan: Option<u16>,
    /// Source address.
    pub src: Addr,
    /// Header length in octets (offset of the MAC payload).
    pub header_len: u8,
}

/// NWK header summary (reused `rounddance-nwk` codec).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NwkNode {
    /// Frame type bits (0 = data, 1 = command, 3 = Inter-PAN).
    pub frame_type: u8,
    /// Protocol version on air.
    pub protocol_version: u8,
    /// NWK security enabled (bit 9).
    pub security: bool,
    /// Destination network address.
    pub dst_addr: u16,
    /// Source network address.
    pub src_addr: u16,
    /// Radius (hop budget).
    pub radius: u8,
    /// Per-source sequence number.
    pub seq: u8,
    /// Command identifier for NWK command frames.
    pub command_id: Option<u8>,
    /// Destination IEEE address, when present.
    pub dst_ieee: Option<u64>,
    /// Source IEEE address, when present.
    pub src_ieee: Option<u64>,
}

/// APS header summary (reused `rounddance-aps` codec).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApsNode {
    /// Frame type bits (0 = data, 1 = command, 2 = ack).
    pub frame_type: u8,
    /// Delivery mode bits.
    pub delivery_mode: u8,
    /// Destination endpoint.
    pub dst_endpoint: u8,
    /// Cluster identifier (data frames).
    pub cluster_id: u16,
    /// Profile identifier (data frames).
    pub profile_id: u16,
    /// Source endpoint (data frames).
    pub src_endpoint: u8,
    /// Per-originator counter.
    pub counter: u8,
    /// Command identifier (command frames).
    pub command_id: Option<u8>,
}

/// ZCL header summary (reused `rounddance-zcl` codec).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZclNode {
    /// Frame type bits (0 = global, 1 = cluster-specific).
    pub frame_type: u8,
    /// Manufacturer-specific flag.
    pub manufacturer_specific: bool,
    /// Direction bit (0 = client→server, 1 = server→client).
    pub direction: u8,
    /// Manufacturer code, when present.
    pub manufacturer_code: Option<u16>,
    /// Transaction sequence number.
    pub tsn: u8,
    /// Command identifier.
    pub command_id: u8,
    /// Trailing payload length in octets.
    pub payload_len: u16,
    /// APS cluster identifier this ZCL payload rode on
    /// (`0xffff` when the chain saw no APS header).
    pub cluster_id: u16,
    /// APS profile identifier (`0xffff` without an APS header).
    pub profile_id: u16,
    /// Bounded payload summary (foundation or top-cluster decode).
    pub detail: ZclDetail,
}

/// Bounded ZCL payload summary: owned `Copy` scalars only, no values.
///
/// Every variant degrades gracefully: short or unrecognized payloads
/// land in `Unknown` (or a zeroed family variant) rather than failing
/// the tree. Counts are capped at `u8` saturation; only the first
/// record's key is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZclDetail {
    /// No payload summary (empty payload, or secured/unknown stop
    /// before ZCL).
    None,
    /// Foundation (global) command summary.
    Global {
        /// Foundation command identifier.
        cmd: u8,
        /// Records decoded (saturates at 255).
        records: u8,
        /// First attribute identifier (`0xffff` when none / n/a).
        first_id: u16,
        /// First-record status, or Default Response status
        /// (`0xff` when the command carries no status).
        status: u8,
    },
    /// On/Off cluster (0x0006) cluster-specific command.
    OnOff {
        /// Command identifier.
        cmd: u8,
    },
    /// Level Control cluster (0x0008) command with first args.
    Level {
        /// Command identifier.
        cmd: u8,
        /// Move-to-Level: target level; Move: mode; Step: step size;
        /// Stop: 0.
        arg0: u8,
        /// Move-to-Level: transition time (1/10 s); Move: rate;
        /// Step: transition time; Stop: 0.
        arg1: u16,
    },
    /// IAS Zone cluster (0x0500) cluster-specific command.
    IasZone {
        /// Command identifier.
        cmd: u8,
    },
    /// Smart-Energy Metering cluster (0x0702) command summary.
    ///
    /// Direction-disambiguated: `cmd` 0x00 is GetProfile
    /// (client→server) or GetProfileResponse (server→client), 0x03
    /// is RequestFastPollMode or its response. Anything else on
    /// this cluster (mirror / snapshot / sampling / supply /
    /// notification-scheme commands) stays `Unknown`.
    Metering {
        /// Command identifier.
        cmd: u8,
        /// GetProfile: interval channel; GetProfileResponse: status;
        /// FastPoll request/response: period seconds; else 0.
        arg0: u8,
        /// GetProfile: requested period count; GetProfileResponse:
        /// interval count; FastPoll request: duration minutes; else 0.
        arg1: u8,
        /// GetProfile: end-time anchor; GetProfileResponse: newest
        /// interval end time; FastPoll response: fast-poll end time;
        /// else 0.
        arg2: u32,
    },
    /// Smart-Energy Price cluster (0x0700) command summary.
    ///
    /// Direction-disambiguated: `cmd` 0x00 is GetCurrentPrice
    /// (client→server, 1-octet options) or PublishPrice
    /// (server→client). Block-period (0x01), block-threshold (0x06),
    /// and tier-label (0x08) publishes keep their issuer / start
    /// fields; the matching client requests keep their start /
    /// tariff fields.
    Price {
        /// Command identifier.
        cmd: u8,
        /// PublishPrice / PriceAck / PublishBlockPeriod /
        /// PublishBlockThresholds / PublishTierLabels: issuer event
        /// id; GetScheduledPrices / GetBlockPeriods: start time;
        /// GetCurrentPrice: options; GetBlockThresholds /
        /// GetTierLabels: tariff id; else 0.
        arg0: u32,
        /// PublishPrice: price; PriceAck: ack time;
        /// PublishBlockPeriod / PublishBlockThresholds: start time;
        /// PublishTierLabels: label count; GetScheduledPrices:
        /// requested count; GetBlockPeriods: max events; else 0.
        arg1: u32,
    },
    /// Key Establishment cluster (0x0800) Initiate summary, either
    /// direction: the 52-octet suite negotiation body, validated
    /// only (no crypto, no certificate parsing).
    KeyInit {
        /// Negotiated suite mask.
        suite: u16,
        /// Peer ephemeral-generation hint.
        eph_time: u8,
        /// Peer confirm-generation hint.
        confirm_time: u8,
    },
    /// Key Establishment fixed-shape key-material flight, either
    /// direction: ephemeral point (0x01, 33- or 64-octet form) or
    /// confirm tag (0x02, 16 octets). Length-validated only; the
    /// point is never decompressed and the tag never checked here.
    KeyMsg {
        /// Command identifier (0x01 ephemeral, 0x02 confirm).
        cmd: u8,
        /// Validated payload length.
        len: u8,
    },
    /// Key Establishment Terminate summary, either direction.
    KeyTerminate {
        /// Terminate status (`TERM_*`).
        status: u8,
        /// Wait hint in seconds before retrying.
        wait_s: u8,
        /// Sender suite mask.
        suite: u16,
    },
    /// Anything else: unrecognized cluster or command.
    Unknown {
        /// Command identifier.
        cmd: u8,
    },
}

/// Terminal note: the chain stopped here with bytes left over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteNode {
    /// Machine-readable reason (`"secured"`, `"truncated"`, `"unknown"`,
    /// `"trailing"`, `"ack"`, `"beacon"`, `"mac-command"`,
    /// `"decrypted"`).
    pub reason: &'static str,
    /// Octets remaining at this layer.
    pub remaining: u16,
}

/// One decoded layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    /// 802.15.4 MAC header.
    Mac(MacNode),
    /// NWK header.
    Nwk(NwkNode),
    /// APS header.
    Aps(ApsNode),
    /// ZCL header.
    Zcl(ZclNode),
    /// Chain stop note.
    Note(NoteNode),
}

/// Maximum layers per tree: MAC + NWK + APS + ZCL + one stop note.
pub const MAX_LAYERS: usize = 5;

/// Bounded decode tree: the full dissector-chain result for one frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeTree {
    layers: [Option<Layer>; MAX_LAYERS],
    len: u8,
    radio: Option<Radio>,
}

/// Chain-level failure: nothing could be decoded at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeError {
    /// Empty input.
    Empty,
    /// MAC header truncated.
    MacTruncated,
    /// MAC header malformed (bad address modes / lengths).
    MacMalformed,
}

impl Default for DecodeTree {
    fn default() -> Self {
        Self::new()
    }
}

impl DecodeTree {
    /// Empty tree.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            layers: [None; MAX_LAYERS],
            len: 0,
            radio: None,
        }
    }

    /// Attach radio capture metadata (channel + signal readings).
    /// A positive RSSI is unphysical on the lab sniffer path (see
    /// [`crate::capture`]) and is stored as unknown (`None`); the
    /// channel and LQI pass through unchanged.
    pub fn set_radio(&mut self, channel: u8, rssi: i8, lqi: u8) {
        self.radio = Some(Radio {
            channel,
            rssi: if rssi <= 0 { Some(rssi) } else { None },
            lqi,
        });
    }

    /// Radio capture metadata, when attached.
    #[must_use]
    pub const fn radio(self) -> Option<Radio> {
        self.radio
    }

    /// Number of layers pushed.
    #[must_use]
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// No layers pushed.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Push one layer; `false` when the tree is full.
    pub fn push(&mut self, layer: Layer) -> bool {
        if self.len as usize >= MAX_LAYERS {
            return false;
        }
        self.layers[self.len as usize] = Some(layer);
        self.len += 1;
        true
    }

    /// Live layers in push order.
    #[must_use]
    pub fn layers(&self) -> &[Option<Layer>] {
        &self.layers[..self.len as usize]
    }

    /// First layer of a given discriminant, if present.
    #[must_use]
    pub fn mac(&self) -> Option<MacNode> {
        for slot in self.layers() {
            if let Some(Layer::Mac(m)) = slot {
                return Some(*m);
            }
        }
        None
    }

    /// First NWK layer, if present.
    #[must_use]
    pub fn nwk(&self) -> Option<NwkNode> {
        for slot in self.layers() {
            if let Some(Layer::Nwk(n)) = slot {
                return Some(*n);
            }
        }
        None
    }

    /// First APS layer, if present.
    #[must_use]
    pub fn aps(&self) -> Option<ApsNode> {
        for slot in self.layers() {
            if let Some(Layer::Aps(a)) = slot {
                return Some(*a);
            }
        }
        None
    }

    /// First ZCL layer, if present.
    #[must_use]
    pub fn zcl(&self) -> Option<ZclNode> {
        for slot in self.layers() {
            if let Some(Layer::Zcl(z)) = slot {
                return Some(*z);
            }
        }
        None
    }
}
