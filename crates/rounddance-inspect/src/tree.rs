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

/// APS command payload summary: the named sub-dissector for APS
/// command frames, on unsecured as well as verified-open legs.
/// The transport-key, update-device, remove-device, request-key,
/// switch-key, and tunnel commands earn shaped names (key type over the live and
/// spec-agreed fixed shapes, key bytes stay sealed, never rendered;
/// device status + short over the spec-agreed fixed prefix, the 8-octet
/// EUI stays in the capture; the remove-device EUI alone stays in the
/// capture, never in the node; the request-key type alone names its
/// shape, the 8-octet partner EUI stays in the capture; the switch-key
/// sequence alone names its shape, no addresses ride it; the tunnel
/// destination EUI plus tunneled bytes stay in the capture, never in
/// the node); anything
/// else files as `Unknown` with its
/// command identifier, never a guess.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApsCmdNode {
    /// APS command identifier (APS header command octet).
    pub command_id: u8,
    /// Named payload shape.
    pub kind: ApsCmdKind,
    /// Full APS command payload length in octets (command identifier
    /// plus body).
    pub payload_len: u16,
}

/// Named APS command payload shapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApsCmdKind {
    /// Transport-key command: key type only (the transported key,
    /// sequence, addresses, and any TLVs stay in the capture, never
    /// in the node).
    TransportKey {
        /// Standard key type (`0x01` network, `0x03` application
        /// link, `0x04` Trust-Center link).
        key_type: u8,
    },
    /// Update-device command: device status + short address (the
    /// 8-octet device EUI and any R23 JoinerTLVs stay in the
    /// capture, never in the node — the network-report EPID
    /// precedent). Status semantics are the stack's, never
    /// validated here — the network-status precedent.
    UpdateDevice {
        /// Device status octet (Table 4-14: `0x00`-`0x03`
        /// assigned, `0x04`-`0x07` reserved).
        status: u8,
        /// 16-bit network address of the device whose status is
        /// being updated.
        short_addr: u16,
    },
    /// Remove-device command: the 8-octet device address stays in
    /// the capture, never in the node — the update-device EUI
    /// precedent. The shape is the address alone (no short, no
    /// status, no TLV tail), so the node carries no address bytes.
    RemoveDevice,
    /// Request-key command: the 1-octet key type plus the 8-octet
    /// partner address stay fixed (no TLV tail), so the exact 9-octet
    /// body gates the name. The partner EUI stays in the capture,
    /// never in the node — the update-device EUI precedent; the node
    /// carries the key type alone — the transport-key precedent.
    /// Key-type values are the stack's, never validated here — the
    /// update-device status precedent. No key material rides this
    /// command.
    RequestKey {
        /// Requested key type (first body octet).
        key_type: u8,
    },
    /// Switch-key command: the new-network-key sequence number alone
    /// (1 octet, no addresses, no key material), so the exact 1-octet
    /// body gates the name. The node carries the sequence alone — the
    /// request-key key-type precedent; sequence values are the
    /// stack's, never validated here — the update-device status
    /// precedent.
    SwitchKey {
        /// Key sequence number (sole body octet).
        key_seq: u8,
    },
    /// Tunnel command: the 8-octet destination address plus the
    /// tunneled frame stay in the capture, never in the node — the
    /// remove-device EUI precedent. The shape is the address prefix
    /// with at least one tunneled octet after it (no fixed length),
    /// so the node carries no address bytes and the tail rides
    /// unparsed — the update-device TLV-tail precedent.
    Tunnel,
    /// None of the named shapes: identifier filed, payload unparsed.
    Unknown,
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

/// MAC command payload summary: the named sub-dissector for MAC
/// command frames. Only exact fixed shapes are named (association,
/// disassociation, polls, orphan, beacon request, coordinator
/// realignment); any other length or identifier leaves the chain at
/// the `mac-command` stop with no layer here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacCmdNode {
    /// MAC command identifier (first MSDU octet).
    pub command_id: u8,
    /// Named payload shape.
    pub kind: MacCmdKind,
    /// Full MSDU length in octets (command identifier + payload).
    pub payload_len: u16,
}

/// Named MAC command payload shapes (2006 fixed layouts; the 2015
/// additions stay unmodeled by design).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacCmdKind {
    /// Association request: capability information octet.
    AssocReq {
        /// Capability flags.
        capabilities: u8,
    },
    /// Association response: assigned short plus status.
    AssocResp {
        /// Assigned short address (`0xffff` = denied).
        short_addr: u16,
        /// Association status.
        status: u8,
    },
    /// Disassociation notification: reason octet.
    Disassoc {
        /// Disassociation reason.
        reason: u8,
    },
    /// Data request (poll): empty payload.
    DataReq,
    /// PAN identifier conflict: empty payload.
    PanConflict,
    /// Orphan notification: empty payload.
    Orphan,
    /// Beacon request: empty payload.
    BeaconReq,
    /// Coordinator realignment: the 7-octet payload naming the
    /// network to rejoin.
    CoordRealign {
        /// PAN identifier.
        pan: u16,
        /// Coordinator short address.
        coord: u16,
        /// Logical channel.
        channel: u8,
        /// Device short address.
        short_addr: u16,
    },
}

/// NWK command payload summary: the named sub-dissector for NWK
/// command frames, on unsecured as well as verified-open legs.
/// Routing and leave shapes reuse the `rounddance-nwk` codecs;
/// network-status, route-record, network-report, network-update,
/// rejoin, and timeout shapes are length-gated names (no repo
/// codec covers them); anything else files as `Unknown` with
/// its command identifier, never a guess.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NwkCmdNode {
    /// NWK command identifier (first payload octet).
    pub command_id: u8,
    /// Named payload shape.
    pub kind: NwkCmdKind,
    /// Full NWK command payload length in octets.
    pub payload_len: u16,
}

/// Named NWK command payload shapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NwkCmdKind {
    /// Route request: per-originator identifier + destination.
    RouteRequest {
        /// Route-request identifier.
        rreq_id: u8,
        /// Destination network address.
        dst_addr: u16,
    },
    /// Route reply: request identifier + originator.
    RouteReply {
        /// Route-request identifier being answered.
        rreq_id: u8,
        /// Originator network address.
        originator: u16,
    },
    /// Route record: relay count plus the first relay hop (the hop
    /// list itself stays in the capture, never in the node — the
    /// link-status entry-list precedent).
    RouteRecord {
        /// Declared relay count.
        relays: u8,
        /// First listed relay (`0xffff` when the list is empty).
        first_relay: u16,
    },
    /// Network report: PAN-ID conflict count plus the first
    /// conflicting PAN ID (the EPID and the ID list itself stay in
    /// the capture, never in the node — the link-status entry-list
    /// precedent).
    NetworkReport {
        /// Declared report count (options bits 0-4).
        reports: u8,
        /// First listed PAN ID (`0xffff` when the list is empty).
        first_pan: u16,
    },
    /// Network update: new-PAN-ID count plus the first new PAN ID
    /// (the EPID, the update id, and the ID list itself stay in
    /// the capture, never in the node — the link-status entry-list
    /// precedent).
    NetworkUpdate {
        /// Declared update count (options bits 0-4).
        updates: u8,
        /// First listed new PAN ID (`0xffff` when the list is empty).
        first_pan: u16,
    },
    /// Link status: entry count plus the first neighbor (the entry
    /// list itself stays in the capture, never in the node).
    LinkStatus {
        /// Declared entry count.
        entries: u8,
        /// First listed neighbor (`0xffff` when the list is empty).
        first_neighbor: u16,
    },
    /// Leave: options octet (rejoin/request/remove-children bits).
    Leave {
        /// Raw options octet; bit layout is the codec's.
        options: u8,
    },
    /// Network status: status code plus the destination the status
    /// is reported against (fixed 4-octet shape).
    NetworkStatus {
        /// Status code octet (meaning is the stack's, never validated
        /// here).
        status: u8,
        /// Destination network address the status names.
        dst_addr: u16,
    },
    /// Secured rejoin request: capability information octet.
    RejoinRequest {
        /// Capability flags.
        capabilities: u8,
    },
    /// Secured rejoin response: re-admitted short plus status.
    RejoinResponse {
        /// Re-admitted short address.
        short_addr: u16,
        /// Rejoin status (`0x00` = accepted).
        status: u8,
    },
    /// End-device timeout request: layout unmodeled, bytes preserved.
    TimeoutRequest {
        /// Second payload octet.
        arg0: u8,
        /// Third payload octet.
        arg1: u8,
    },
    /// End-device timeout response: layout unmodeled, bytes preserved.
    TimeoutResponse {
        /// Second payload octet.
        arg0: u8,
        /// Third payload octet.
        arg1: u8,
    },
    /// None of the named shapes: identifier filed, payload unparsed.
    Unknown,
}

/// ZDO payload summary: the device-profile leg for APS payloads on
/// profile `0x0000`. ZDO frames are never ZCL — routing them here
/// keeps cluster `0x80xx` responses and `0x00xx` requests from
/// misparsing as ZCL commands. Per-cluster bodies stay unmodeled by
/// design (as with unmodeled ZCL clusters); the envelope —
/// request/response direction, transaction sequence, response
/// status — is always named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZdoNode {
    /// ZDO cluster identifier (`0x8000` bit = response).
    pub cluster_id: u16,
    /// True when the response bit is set.
    pub is_response: bool,
    /// Transaction sequence number (first payload octet).
    pub tsn: u8,
    /// Response status octet (second payload octet of responses).
    pub status: Option<u8>,
    /// Full ZDO payload length in octets.
    pub payload_len: u16,
}

/// Touchlink (inter-PAN) envelope summary: the named
/// sub-dissector for broadcast-PAN MAC outers, which carry no NWK
/// header. Transaction + command always name the leg; bodies are
/// exact-length fixed shapes (scan, start-order, join-order legs),
/// anything else files [`TouchlinkKind::Unknown`] with its
/// identifier. Wrapped keys inside order bodies stay sealed bytes,
/// never parsed or rendered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TouchlinkNode {
    /// Inter-PAN transaction identifier (first 4 MSDU octets, LE).
    pub tid: u32,
    /// Command identifier (fifth MSDU octet).
    pub command_id: u8,
    /// Named payload shape.
    pub kind: TouchlinkKind,
    /// Full MSDU length in octets (transaction + command + body).
    pub payload_len: u16,
}

/// Named Touchlink payload shapes (live wave-50 census; the one
/// exact length each).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchlinkKind {
    /// Scan request: 2-octet information body.
    ScanReq {
        /// Zigbee information octet.
        zigbee_info: u8,
        /// Touchlink information octet.
        touchlink_info: u8,
    },
    /// Scan response: 25-octet router-information body.
    ScanRsp {
        /// Key-index negotiation mask.
        key_mask: u16,
    },
    /// Network-start request: 52-octet wrapped-key order body.
    StartReq {
        /// Key index the order is sealed under.
        key_index: u8,
    },
    /// Network-start response: 13-octet status body.
    StartRsp {
        /// Response status (`0x00` = success).
        status: u8,
    },
    /// Network-join request: 43-octet wrapped-key order body.
    JoinReq {
        /// Key index the order is sealed under.
        key_index: u8,
    },
    /// Network-join response: 1-octet status body.
    JoinRsp {
        /// Response status (`0x00` = success).
        status: u8,
    },
    /// None of the named shapes: identifier filed, payload unparsed.
    Unknown,
}

/// Green-Power device-frame summary: the named sub-dissector for
/// MAC data payloads that refuse the stack NWK codec (stub NWK,
/// protocol version 3). Frame control, addressing, protection
/// level, the bidirectional-reply request bit, the security frame
/// counter, and the command envelope are always named; a sealed
/// (encrypted, unverified) command section files
/// [`GpKind::EncryptedSealed`] with no command identifier, and
/// command bodies stay unmodeled by design (as with ZDO envelopes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpNode {
    /// Data (0) vs maintenance (1) frame.
    pub frame_type: u8,
    /// Auto-commissioning sub-field.
    pub auto_commissioning: bool,
    /// Application identifier (0 source identifier, 1 LPED,
    /// 2 IEEE address plus endpoint).
    pub app_id: u8,
    /// Protection level (0 none, 2 counter plus MIC, 3 encrypted).
    pub level: u8,
    /// Key-type wire bit (group vs individual key classes).
    pub key_bit: bool,
    /// Receive-after-transmit request (bidirectional-reply window).
    pub rx_after_tx: bool,
    /// Sender side: clear = GPD, set = proxy.
    pub direction_proxy: bool,
    /// GPD source identifier (`0` for IEEE / LPED identities and
    /// maintenance frames).
    pub src_id: u32,
    /// GPD IEEE address, when the identity scheme carries one.
    pub ieee: Option<u64>,
    /// GPD endpoint, jointly identifying IEEE-addressed devices.
    pub endpoint: Option<u8>,
    /// Security frame counter (`Some` exactly when the level puts
    /// counter + MIC on air).
    pub frame_counter: Option<u32>,
    /// GPD command identifier (`None` for sealed sections and LPED
    /// bodies).
    pub command_id: Option<u8>,
    /// Named command shape.
    pub kind: GpKind,
    /// Command payload length in octets (integrity word excluded,
    /// `0` while sealed).
    pub payload_len: u16,
    /// True when the level puts counter + MIC on air; the session
    /// engine folds these frames into the secured accounting.
    pub secured: bool,
}

/// Named Green-Power command shapes. Data commands outside the six
/// reply-path identifiers file [`GpKind::Data`] with the identifier;
/// anything the codec refuses files no leg at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpKind {
    /// Application data command.
    Data,
    /// Commissioning (`0xE0`).
    Commissioning,
    /// Decommissioning (`0xE1`, payloadless).
    Decommissioning,
    /// Success (`0xE2`, payloadless).
    Success,
    /// Channel request (`0xE3`).
    ChannelRequest,
    /// Commissioning reply (`0xF0`, proxy side of the
    /// bidirectional exchange).
    CommissioningReply,
    /// Channel configuration (`0xF3`).
    ChannelConfig,
    /// Maintenance-frame command envelope.
    Maintenance,
    /// LPED body, kept opaque.
    LpedOpaque,
    /// Encrypted command section, sealed: no slotted key has
    /// verified it open, so no command identifier is named.
    EncryptedSealed,
}

/// HCI packet summary: the BLE-leg outer for one btsnoop record.
/// HCI commands and events file no ATT layer; ACL packets carrying
/// L2CAP CID `0x0004` continue to the ATT leg.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HciNode {
    /// Record direction and packet type.
    pub kind: HciKind,
    /// ACL connection handle (12-bit), `None` on commands/events.
    pub conn_handle: Option<u16>,
    /// HCI command opcode (little-endian on air), commands only.
    pub opcode: Option<u16>,
    /// HCI event code, events only.
    pub event: Option<u8>,
    /// LE Meta subevent (event `0x3e` with a parameter octet),
    /// `None` otherwise.
    pub subevent: Option<u8>,
    /// HCI parameter / ACL L2CAP payload length in octets.
    pub payload_len: u16,
}

/// HCI record shapes (btsnoop flags discriminate them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HciKind {
    /// Host-to-controller command (flags 2).
    Command,
    /// Controller-to-host event (flags 3).
    Event,
    /// Host-to-controller ACL data (flags 4).
    AclTx,
    /// Controller-to-host ACL data (flags 5).
    AclRx,
}

/// ATT PDU summary: the BLE-leg inner for one L2CAP CID-`0x0004`
/// payload. Handles are always decoded; values stay length-named
/// (Direct TLV envelopes earn a [`DirectNode`] leg, everything else
/// stays opaque bytes — key-carrying values are never rendered).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttNode {
    /// ATT opcode (first PDU octet).
    pub opcode: u8,
    /// Named opcode class (`Unknown` files the octet, never a guess).
    pub kind: AttKind,
    /// Primary attribute handle (request / response / notify /
    /// error handle), `None` on MTU exchanges which carry none.
    pub handle: Option<u16>,
    /// Discovery-request handle-range end, `None` otherwise.
    pub handle_end: Option<u16>,
    /// MTU value (exchange request/response only).
    pub mtu: Option<u16>,
    /// Requested 16-bit UUID (discovery by 16-bit type), `None`
    /// when the request carries a 128-bit UUID or no UUID.
    pub uuid16: Option<u16>,
    /// True when a discovery request carries a 128-bit UUID.
    pub uuid128: bool,
    /// Error response: the failed request's opcode.
    pub req_opcode: Option<u8>,
    /// Error response: the error code (e.g. `0x80` is the Direct
    /// insufficient-authorization application error, filed here as
    /// a code, never interpreted as a TLV).
    pub error: Option<u8>,
    /// ATT value / list bytes after the fixed header.
    pub payload_len: u16,
}

/// Named ATT opcode classes (observed live set plus the symmetric
/// request/response pairs the exchange needs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttKind {
    /// Error Response (`0x01`).
    Error,
    /// Exchange MTU Request / Response (`0x02` / `0x03`).
    Mtu,
    /// Find Information Request / Response (`0x04` / `0x05`).
    FindInfo,
    /// Read By Type Request / Response (`0x08` / `0x09`).
    ReadByType,
    /// Read Request / Response (`0x0a` / `0x0b`).
    Read,
    /// Read By Group Type Request / Response (`0x10` / `0x11`).
    ReadByGroup,
    /// Write Request (`0x12`).
    Write,
    /// Write Response (`0x13`, empty).
    WriteResult,
    /// Handle Value Notification (`0x1b`).
    Notify,
    /// Handle Value Indication / Confirmation (`0x1d` / `0x1e`).
    Indicate,
    /// None of the named opcodes: octet filed, payload unparsed.
    Unknown,
}

/// Direct (Zigbee Direct over BLE) summary: UUID attribution for
/// discovery responses plus the TLV envelope for Direct
/// write/notify values. Bodies are never carried (commissioning
/// values may seal key material) — only tags, counts, and the
/// status domain/code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectNode {
    /// Which Direct shape this leg names.
    pub kind: DirectKind,
    /// Discovery: service bitmap (bit 0 = Security service, bit 1
    /// = Commissioning service); `0` on non-discovery legs.
    pub services: u8,
    /// Discovery: Security Authenticate chars seen (bit `i` =
    /// `SECURITY_CHARS[i]`); `0` otherwise.
    pub sec_chars: u8,
    /// Discovery: Commissioning chars seen (bit `i` =
    /// `COMMISSIONING_CHARS[i]`); `0` otherwise.
    pub comm_chars: u8,
    /// Discovery entries scanned, or envelope TLV count
    /// (saturates at 255); status legs carry `1`.
    pub entries: u8,
    /// Envelope: first TLV tag (`0xff` when not an envelope).
    pub first_tag: u8,
    /// Status: TLV domain octet (`0xff` when not a status leg).
    pub domain: u8,
    /// Status: TLV code octet (`0xff` when not a status leg).
    pub code: u8,
    /// ATT value length in octets.
    pub payload_len: u16,
}

/// Named Direct shapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectKind {
    /// Discovery response carrying ≥1 Direct UUID.
    Discovery,
    /// Status-Code TLV notification (tag `0x0e`, 2-octet body).
    Status,
    /// Write value shaped as ≥2 complete defined-tag TLVs.
    Envelope,
}

/// Terminal note: the chain stopped here with bytes left over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteNode {
    /// Machine-readable reason (`"secured"` for an NWK/APS/GP
    /// key-domain miss, `"mac-secured"` for a MAC sealed outer,
    /// `"truncated"`, `"unknown"`, `"trailing"`, `"ack"`,
    /// `"beacon"`, `"mac-command"`, `"decrypted"`, `"interpan"` for
    /// a broadcast-PAN outer routed to the Touchlink leg,
    /// `"ble-unknown"` for an HCI record whose ATT payload names
    /// no leg).
    pub reason: &'static str,
    /// Octets remaining at this layer.
    pub remaining: u16,
}

/// One decoded layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    /// 802.15.4 MAC header.
    Mac(MacNode),
    /// Touchlink (inter-PAN) envelope (broadcast-PAN outers only,
    /// never beside an NWK layer).
    Touchlink(TouchlinkNode),
    /// MAC command payload (fixed shapes only).
    MacCmd(MacCmdNode),
    /// NWK header.
    Nwk(NwkNode),
    /// NWK command payload (unsecured or verified-open legs).
    NwkCmd(NwkCmdNode),
    /// APS header.
    Aps(ApsNode),
    /// APS command payload (unsecured or verified-open legs).
    ApsCmd(ApsCmdNode),
    /// ZCL header.
    Zcl(ZclNode),
    /// ZDO envelope (profile `0x0000`, never ZCL).
    Zdo(ZdoNode),
    /// Green-Power device frame (stub NWK, never beside NWK/APS).
    Gp(GpNode),
    /// HCI packet (BLE leg outer, never beside 15.4 layers).
    Hci(HciNode),
    /// ATT PDU (BLE leg inner, beside Hci only).
    Att(AttNode),
    /// Direct UUID/TLV envelope (BLE leg, beside Hci+Att only).
    Direct(DirectNode),
    /// Chain stop note.
    Note(NoteNode),
}

/// Maximum layers per tree: MAC + NWK + APS + ZCL/ZDO + one stop
/// note, MAC + NWK + command leg + one stop note, MAC + NWK + APS +
/// APS-command leg + one stop note, MAC + Touchlink + one stop note,
/// or MAC + GP + one stop note. Named command, profile, inter-PAN,
/// and Green-Power legs take a layer slot that an unnamed stop used
/// to fill alone, so depth grows by at most one per frame.
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
    /// HCI record truncated (short command / event / ACL header).
    BleTruncated,
    /// HCI record malformed (unknown btsnoop flags, L2CAP length
    /// mismatch, wrong parameter length).
    BleMalformed,
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

    /// First APS command layer, if present.
    #[must_use]
    pub fn apscmd(&self) -> Option<ApsCmdNode> {
        for slot in self.layers() {
            if let Some(Layer::ApsCmd(a)) = slot {
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

    /// First MAC command layer, if present.
    #[must_use]
    pub fn maccmd(&self) -> Option<MacCmdNode> {
        for slot in self.layers() {
            if let Some(Layer::MacCmd(m)) = slot {
                return Some(*m);
            }
        }
        None
    }

    /// First NWK command layer, if present.
    #[must_use]
    pub fn nwkcmd(&self) -> Option<NwkCmdNode> {
        for slot in self.layers() {
            if let Some(Layer::NwkCmd(n)) = slot {
                return Some(*n);
            }
        }
        None
    }

    /// First ZDO layer, if present.
    #[must_use]
    pub fn zdo(&self) -> Option<ZdoNode> {
        for slot in self.layers() {
            if let Some(Layer::Zdo(z)) = slot {
                return Some(*z);
            }
        }
        None
    }

    /// First Touchlink layer, if present.
    #[must_use]
    pub fn touchlink(&self) -> Option<TouchlinkNode> {
        for slot in self.layers() {
            if let Some(Layer::Touchlink(t)) = slot {
                return Some(*t);
            }
        }
        None
    }

    /// First Green-Power layer, if present.
    #[must_use]
    pub fn gp(&self) -> Option<GpNode> {
        for slot in self.layers() {
            if let Some(Layer::Gp(g)) = slot {
                return Some(*g);
            }
        }
        None
    }

    /// First HCI layer, if present.
    #[must_use]
    pub fn hci(&self) -> Option<HciNode> {
        for slot in self.layers() {
            if let Some(Layer::Hci(h)) = slot {
                return Some(*h);
            }
        }
        None
    }

    /// First ATT layer, if present.
    #[must_use]
    pub fn att(&self) -> Option<AttNode> {
        for slot in self.layers() {
            if let Some(Layer::Att(a)) = slot {
                return Some(*a);
            }
        }
        None
    }

    /// First Direct layer, if present.
    #[must_use]
    pub fn direct(&self) -> Option<DirectNode> {
        for slot in self.layers() {
            if let Some(Layer::Direct(d)) = slot {
                return Some(*d);
            }
        }
        None
    }

    /// True once a verified-open leg was pushed: the tree carries the
    /// `decrypted` stop note, so the session engine can count the
    /// frame decryptable from tree evidence even when it holds no
    /// key slot itself.
    #[must_use]
    pub fn decrypted(self) -> bool {
        for slot in self.layers() {
            if let Some(Layer::Note(n)) = slot {
                if n.reason == "decrypted" {
                    return true;
                }
            }
        }
        false
    }
}
