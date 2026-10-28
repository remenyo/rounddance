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

/// 802.15.4 MAC header summary (frame-control + sequencing + addressing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacNode {
    /// Frame type (bits 0–2): beacon / data / ack / command.
    pub frame_type: u8,
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
}

/// Terminal note: the chain stopped here with bytes left over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteNode {
    /// Machine-readable reason (`"secured"`, `"truncated"`, `"unknown"`,
    /// `"trailing"`).
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
        }
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
