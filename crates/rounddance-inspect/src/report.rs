//! Text and JSON reports over [`DecodeTree`](crate::tree::DecodeTree) (`std` only).
//!
//! Reports render owned scalars only — no hexdumps of key material, no
//! payload bytes. A secured frame is reported as `secured` with its
//! remaining length, never decrypted.

use crate::tree::{
    Addr, ApsCmdKind, ApsCmdNode, AttKind, DecodeTree, DirectKind, GpKind, GpNode, HciKind, Layer,
    MacCmdKind, MacCmdNode, NwkCmdKind, NwkCmdNode, TouchlinkKind, TouchlinkNode,
};
use std::fmt::Write as _;

fn hci_text(k: HciKind) -> &'static str {
    match k {
        HciKind::Command => "cmd",
        HciKind::Event => "evt",
        HciKind::AclTx => "acl-tx",
        HciKind::AclRx => "acl-rx",
    }
}

fn att_text(k: AttKind) -> &'static str {
    match k {
        AttKind::Error => "error",
        AttKind::Mtu => "mtu",
        AttKind::FindInfo => "find-info",
        AttKind::ReadByType => "read-by-type",
        AttKind::Read => "read",
        AttKind::ReadByGroup => "read-by-group",
        AttKind::Write => "write",
        AttKind::WriteResult => "write-rsp",
        AttKind::Notify => "notify",
        AttKind::Indicate => "indicate",
        AttKind::Unknown => "unknown",
    }
}

fn direct_text(k: DirectKind) -> &'static str {
    match k {
        DirectKind::Discovery => "discovery",
        DirectKind::Status => "status",
        DirectKind::Envelope => "envelope",
    }
}

/// One-line human summary plus one indented line per layer.
pub fn to_text(tree: &DecodeTree) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "frame: {} layer(s){}",
        tree.len(),
        tree.radio()
            .map(|r| format!(
                " radio=ch{} rssi={} lqi={}",
                r.channel,
                r.rssi
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| String::from("-")),
                r.lqi,
            ))
            .unwrap_or_default(),
    );
    for layer in tree.layers().iter().flatten() {
        match layer {
            Layer::Mac(m) => {
                let _ = writeln!(
                    s,
                    "  mac: type={} seq={} dst_pan={} dst={} src={}{}{}",
                    m.frame_type,
                    if m.seq_present {
                        hex8(m.seq)
                    } else {
                        String::from("sup")
                    },
                    opt16(m.dst_pan),
                    addr(m.dst),
                    addr(m.src),
                    if m.security_enabled { " secured" } else { "" },
                    m.command_id
                        .map(|c| format!(" cmd={c:#04x}"))
                        .unwrap_or_default(),
                );
            }
            Layer::Nwk(n) => {
                let _ = writeln!(
                    s,
                    "  nwk: type={} ver={} {}->{} radius={} seq={}{}{}",
                    n.frame_type,
                    n.protocol_version,
                    hex16(n.src_addr),
                    hex16(n.dst_addr),
                    n.radius,
                    hex8(n.seq),
                    n.command_id
                        .map(|c| format!(" cmd={c:#04x}"))
                        .unwrap_or_default(),
                    if n.security { " secured" } else { "" },
                );
            }
            Layer::Aps(a) => {
                let _ = writeln!(
                    s,
                    "  aps: type={} mode={} {}:{:#06x} {}->{} ctr={}{}",
                    a.frame_type,
                    a.delivery_mode,
                    hex16(a.profile_id),
                    a.cluster_id,
                    hex8(a.src_endpoint),
                    hex8(a.dst_endpoint),
                    hex8(a.counter),
                    a.command_id
                        .map(|c| format!(" cmd={c:#04x}"))
                        .unwrap_or_default(),
                );
            }
            Layer::Zcl(z) => {
                let _ = writeln!(
                    s,
                    "  zcl: type={} dir={} tsn={} cmd={:#04x} payload={}B{} cluster={} profile={} {}",
                    z.frame_type,
                    z.direction,
                    hex8(z.tsn),
                    z.command_id,
                    z.payload_len,
                    z.manufacturer_code
                        .map(|c| format!(" mfr={c:#06x}"))
                        .unwrap_or_default(),
                    hex16(z.cluster_id),
                    hex16(z.profile_id),
                    detail_text(&z.detail),
                );
            }
            Layer::MacCmd(m) => {
                let _ = writeln!(
                    s,
                    "  maccmd: id={:#04x} {} len={}B",
                    m.command_id,
                    maccmd_text(&m.kind),
                    m.payload_len,
                );
            }
            Layer::NwkCmd(n) => {
                let _ = writeln!(
                    s,
                    "  nwkcmd: id={:#04x} {} len={}B",
                    n.command_id,
                    nwkcmd_text(&n.kind),
                    n.payload_len,
                );
            }
            Layer::ApsCmd(n) => {
                let _ = writeln!(
                    s,
                    "  apscmd: id={:#04x} {} len={}B",
                    n.command_id,
                    apscmd_text(&n.kind),
                    n.payload_len,
                );
            }
            Layer::Zdo(z) => {
                let _ = writeln!(
                    s,
                    "  zdo: cluster={} profile=0x0000 {} tsn={} status={} len={}B",
                    hex16(z.cluster_id),
                    if z.is_response { "resp" } else { "req" },
                    hex8(z.tsn),
                    z.status
                        .map(|v| format!("{v:#04x}"))
                        .unwrap_or_else(|| String::from("-")),
                    z.payload_len,
                );
            }
            Layer::Touchlink(t) => {
                let _ = writeln!(
                    s,
                    "  touchlink: tid={} cmd={} {} len={}B",
                    hex32(t.tid),
                    hex8(t.command_id),
                    touchlink_text(&t.kind),
                    t.payload_len,
                );
            }
            Layer::Gp(g) => {
                let _ = writeln!(
                    s,
                    "  gp: {} app={} lvl={} keybit={} {} cmd={} ctr={} len={}B{}",
                    if g.frame_type == 0 { "data" } else { "maint" },
                    g.app_id,
                    g.level,
                    if g.key_bit { 1 } else { 0 },
                    gp_text(&g.kind),
                    g.command_id
                        .map(|v| format!("{v:#04x}"))
                        .unwrap_or_else(|| String::from("-")),
                    g.frame_counter
                        .map(|v| format!("{v:#010x}"))
                        .unwrap_or_else(|| String::from("-")),
                    g.payload_len,
                    if g.rx_after_tx { " rx-after-tx" } else { "" },
                );
            }
            Layer::Hci(h) => {
                let _ = writeln!(
                    s,
                    "  hci: {} handle={} op={} evt={} sub={} len={}B",
                    hci_text(h.kind),
                    h.conn_handle
                        .map(|v| format!("{v:#06x}"))
                        .unwrap_or_else(|| String::from("-")),
                    h.opcode
                        .map(|v| format!("{v:#06x}"))
                        .unwrap_or_else(|| String::from("-")),
                    h.event
                        .map(|v| format!("{v:#04x}"))
                        .unwrap_or_else(|| String::from("-")),
                    h.subevent
                        .map(|v| format!("{v:#04x}"))
                        .unwrap_or_else(|| String::from("-")),
                    h.payload_len,
                );
            }
            Layer::Att(a) => {
                let _ = writeln!(
                    s,
                    "  att: op={:#04x} {} handle={} mtu={} err={} len={}B",
                    a.opcode,
                    att_text(a.kind),
                    a.handle
                        .map(|v| format!("{v:#06x}"))
                        .unwrap_or_else(|| String::from("-")),
                    a.mtu
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| String::from("-")),
                    a.error
                        .map(|v| format!("{v:#04x}"))
                        .unwrap_or_else(|| String::from("-")),
                    a.payload_len,
                );
            }
            Layer::Direct(d) => {
                let _ = writeln!(
                    s,
                    "  direct: {} svc={:#04x} sec={:#04x} comm={:#04x} entries={} first={} domain={} code={} len={}B",
                    direct_text(d.kind),
                    d.services,
                    d.sec_chars,
                    d.comm_chars,
                    d.entries,
                    if d.first_tag == 0xff {
                        String::from("-")
                    } else {
                        format!("{:#04x}", d.first_tag)
                    },
                    if d.domain == 0xff {
                        String::from("-")
                    } else {
                        format!("{:#04x}", d.domain)
                    },
                    if d.code == 0xff {
                        String::from("-")
                    } else {
                        format!("{:#04x}", d.code)
                    },
                    d.payload_len,
                );
            }
            Layer::Note(n) => {
                let _ = writeln!(s, "  …: {} ({}B left)", n.reason, n.remaining);
            }
        }
    }
    s
}

/// Minimal JSON rendering without third-party dependencies.
pub fn to_json(tree: &DecodeTree) -> String {
    let mut s = String::from("{\"layers\":[");
    let mut first = true;
    for layer in tree.layers().iter().flatten() {
        if !first {
            s.push(',');
        }
        first = false;
        match layer {
            Layer::Mac(m) => {
                s.push_str(&format!(
                    "{{\"mac\":{{\"type\":{},\"seq\":{},\"seq_present\":{},\"dst_pan\":{},\"dst\":\"{}\",\"src\":\"{}\",\"secured\":{},\"cmd\":{}}}}}",
                    m.frame_type,
                    m.seq,
                    m.seq_present,
                    opt_json_u16(m.dst_pan),
                    addr(m.dst),
                    addr(m.src),
                    m.security_enabled,
                    opt_json_u8(m.command_id),
                ));
            }
            Layer::Nwk(n) => {
                s.push_str(&format!(
                    "{{\"nwk\":{{\"type\":{},\"ver\":{},\"src\":{},\"dst\":{},\"radius\":{},\"seq\":{},\"cmd\":{},\"secured\":{}}}}}",
                    n.frame_type,
                    n.protocol_version,
                    n.src_addr,
                    n.dst_addr,
                    n.radius,
                    n.seq,
                    opt_json_u8(n.command_id),
                    n.security,
                ));
            }
            Layer::Aps(a) => {
                s.push_str(&format!(
                    "{{\"aps\":{{\"type\":{},\"mode\":{},\"profile\":{},\"cluster\":{},\"src_ep\":{},\"dst_ep\":{},\"ctr\":{},\"cmd\":{}}}}}",
                    a.frame_type,
                    a.delivery_mode,
                    a.profile_id,
                    a.cluster_id,
                    a.src_endpoint,
                    a.dst_endpoint,
                    a.counter,
                    opt_json_u8(a.command_id),
                ));
            }
            Layer::Zcl(z) => {
                s.push_str(&format!(
                    "{{\"zcl\":{{\"type\":{},\"dir\":{},\"tsn\":{},\"cmd\":{},\"payload_len\":{},\"mfr\":{},\"cluster\":{},\"profile\":{},\"detail\":{}}}}}",
                    z.frame_type,
                    z.direction,
                    z.tsn,
                    z.command_id,
                    z.payload_len,
                    opt_json_u16(z.manufacturer_code),
                    z.cluster_id,
                    z.profile_id,
                    detail_json(&z.detail),
                ));
            }
            Layer::MacCmd(m) => {
                s.push_str(&maccmd_json(m));
            }
            Layer::NwkCmd(n) => {
                s.push_str(&nwkcmd_json(n));
            }
            Layer::ApsCmd(n) => {
                s.push_str(&apscmd_json(n));
            }
            Layer::Zdo(z) => {
                s.push_str(&format!(
                    "{{\"zdo\":{{\"cluster\":{},\"resp\":{},\"tsn\":{},\"status\":{},\"len\":{}}}}}",
                    z.cluster_id,
                    z.is_response,
                    z.tsn,
                    z.status
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| String::from("null")),
                    z.payload_len,
                ));
            }
            Layer::Touchlink(t) => {
                s.push_str(&touchlink_json(t));
            }
            Layer::Gp(g) => {
                s.push_str(&gp_json(g));
            }
            Layer::Hci(h) => {
                s.push_str(&format!(
                    "{{\"hci\":{{\"kind\":\"{}\",\"handle\":{},\"opcode\":{},\"event\":{},\"subevent\":{},\"len\":{}}}}}",
                    hci_text(h.kind),
                    opt_json_u16(h.conn_handle),
                    opt_json_u16(h.opcode),
                    opt_json_u8(h.event),
                    opt_json_u8(h.subevent),
                    h.payload_len,
                ));
            }
            Layer::Att(a) => {
                s.push_str(&format!(
                    "{{\"att\":{{\"op\":{},\"kind\":\"{}\",\"handle\":{},\"end\":{},\"mtu\":{},\"uuid16\":{},\"uuid128\":{},\"req\":{},\"err\":{},\"len\":{}}}}}",
                    a.opcode,
                    att_text(a.kind),
                    opt_json_u16(a.handle),
                    opt_json_u16(a.handle_end),
                    opt_json_u16(a.mtu),
                    opt_json_u16(a.uuid16),
                    a.uuid128,
                    opt_json_u8(a.req_opcode),
                    opt_json_u8(a.error),
                    a.payload_len,
                ));
            }
            Layer::Direct(d) => {
                s.push_str(&format!(
                    "{{\"direct\":{{\"kind\":\"{}\",\"svc\":{},\"sec\":{},\"comm\":{},\"entries\":{},\"first\":{},\"domain\":{},\"code\":{},\"len\":{}}}}}",
                    direct_text(d.kind),
                    d.services,
                    d.sec_chars,
                    d.comm_chars,
                    d.entries,
                    if d.first_tag == 0xff {
                        String::from("null")
                    } else {
                        d.first_tag.to_string()
                    },
                    if d.domain == 0xff {
                        String::from("null")
                    } else {
                        d.domain.to_string()
                    },
                    if d.code == 0xff {
                        String::from("null")
                    } else {
                        d.code.to_string()
                    },
                    d.payload_len,
                ));
            }
            Layer::Note(n) => {
                s.push_str(&format!(
                    "{{\"note\":{{\"reason\":\"{}\",\"remaining\":{}}}}}",
                    n.reason, n.remaining
                ));
            }
        }
    }
    s.push_str("],\"radio\":");
    match tree.radio() {
        Some(r) => s.push_str(&format!(
            "{{\"channel\":{},\"rssi\":{},\"lqi\":{}}}",
            r.channel,
            r.rssi
                .map(|v| v.to_string())
                .unwrap_or_else(|| String::from("null")),
            r.lqi,
        )),
        None => s.push_str("null"),
    }
    s.push('}');
    s
}

/// Session schema version for [`session_to_json`].
pub const SESSION_SCHEMA: u8 = 1;

/// One-line-per-row human summary of a [`SessionEngine`](crate::session::SessionEngine).
pub fn session_to_text(eng: &crate::session::SessionEngine) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "session: trees={} secured_decryptable={} secured_orphan={} key_slots={}",
        eng.trees,
        eng.secured_decryptable,
        eng.secured_orphan,
        eng.keys().loaded(),
    );
    for d in eng.devices().iter().flatten() {
        let _ = writeln!(
            s,
            "  dev: short={} ieee={} last_seq={} frames={} secured={}{}{}{}{}",
            hex16(d.short_addr),
            d.ieee
                .map(|e| format!("{e:#018x}"))
                .unwrap_or_else(|| String::from("-")),
            hex8(d.last_seq),
            d.frames,
            d.secured,
            d.nwk_window
                .map(|w| format!(
                    " nwk(base={} replays={} gaps={} late={})",
                    hex8(w.base),
                    w.replays,
                    w.gaps,
                    w.late
                ))
                .unwrap_or_default(),
            d.aps_window
                .map(|w| format!(
                    " aps(base={} replays={} gaps={} late={})",
                    hex8(w.base),
                    w.replays,
                    w.gaps,
                    w.late
                ))
                .unwrap_or_default(),
            d.last_rssi
                .map(|r| format!(" rssi={r}"))
                .unwrap_or_default(),
            d.last_lqi.map(|l| format!(" lqi={l}")).unwrap_or_default(),
        );
    }
    for n in eng.networks().iter().flatten() {
        let _ = writeln!(
            s,
            "  net: pan={} frames={} devices={} secured={}",
            hex16(n.pan_id),
            n.frames,
            n.devices,
            n.secured,
        );
    }
    s
}

/// Stable machine-readable session snapshot (schema [`SESSION_SCHEMA`]).
///
/// Arrays are in table order (not sorted); absent windows render as
/// `null`. No key material is ever rendered.
pub fn session_to_json(eng: &crate::session::SessionEngine) -> String {
    let mut s = format!(
        "{{\"v\":{},\"trees\":{},\"devices\":[",
        SESSION_SCHEMA, eng.trees
    );
    let mut first = true;
    for d in eng.devices().iter().flatten() {
        if !first {
            s.push(',');
        }
        first = false;
        s.push_str(&format!(
            "{{\"short\":{},\"ieee\":{},\"last_seq\":{},\"frames\":{},\"secured\":{},\"nwk\":{},\"aps\":{}}}",
            d.short_addr,
            d.ieee.map(|e| e.to_string()).unwrap_or_else(|| String::from("null")),
            d.last_seq,
            d.frames,
            d.secured,
            window_json(d.nwk_window),
            window_json(d.aps_window),
        ));
    }
    s.push_str("],\"networks\":[");
    first = true;
    for n in eng.networks().iter().flatten() {
        if !first {
            s.push(',');
        }
        first = false;
        s.push_str(&format!(
            "{{\"pan\":{},\"frames\":{},\"devices\":{},\"secured\":{}}}",
            n.pan_id, n.frames, n.devices, n.secured,
        ));
    }
    s.push_str(&format!(
        "],\"sec\":{{\"decryptable\":{},\"orphan\":{},\"slots\":{}}}}}",
        eng.secured_decryptable,
        eng.secured_orphan,
        eng.keys().loaded(),
    ));
    s
}

/// Human-readable stage name for a session timeline.
fn timeline_stage_text(stage: crate::session::TimelineStage) -> &'static str {
    match stage {
        crate::session::TimelineStage::Absent => "absent",
        crate::session::TimelineStage::Joining => "joining",
        crate::session::TimelineStage::Joined => "joined",
        crate::session::TimelineStage::Keyed => "keyed",
        crate::session::TimelineStage::Announced => "announced",
        crate::session::TimelineStage::Active => "active",
    }
}

/// Human-readable anomaly names for a timeline flag word, `+`-joined.
fn timeline_anomaly_text(flags: u8) -> String {
    use crate::session::{DATA_AFTER_LEAVE, DATA_BEFORE_JOIN, GAP_OBSERVED, REJOIN_WITHOUT_LEAVE};
    let mut parts = Vec::new();
    if flags & DATA_BEFORE_JOIN != 0 {
        parts.push("data-before-join");
    }
    if flags & REJOIN_WITHOUT_LEAVE != 0 {
        parts.push("rejoin-without-leave");
    }
    if flags & DATA_AFTER_LEAVE != 0 {
        parts.push("data-after-leave");
    }
    if flags & GAP_OBSERVED != 0 {
        parts.push("gap");
    }
    if parts.is_empty() {
        String::from("none")
    } else {
        parts.join("+")
    }
}

/// One-line-per-session human summary of the engine timeline table.
///
/// Timelines render separately from [`session_to_text`]: the v1
/// session snapshot carries no timelines, and neither does its text
/// shape. Event codes follow [`TimelineEvent::code`](crate::session::TimelineEvent::code).
pub fn timelines_to_text(eng: &crate::session::SessionEngine) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "timelines:");
    for t in eng.timelines().iter().flatten() {
        let mut log = String::new();
        for (code, tree_no) in t.log.iter().flatten() {
            if !log.is_empty() {
                log.push(' ');
            }
            let _ = write!(log, "{code}@{tree_no}");
        }
        let _ = writeln!(
            s,
            "  session: pan={} short={} ieee={} stage={} left={} events={} anomalies={} log=[{}]",
            hex16(t.pan_id),
            hex16(t.short_addr),
            t.ieee
                .map(|e| format!("{e:#018x}"))
                .unwrap_or_else(|| String::from("-")),
            timeline_stage_text(t.stage),
            t.left,
            t.event_total,
            timeline_anomaly_text(t.anomalies),
            log,
        );
    }
    s
}

/// Machine-readable timeline table (standalone shape, not part of the
/// v1 session snapshot in [`session_to_json`]).
pub fn timelines_to_json(eng: &crate::session::SessionEngine) -> String {
    use crate::session::{DATA_AFTER_LEAVE, DATA_BEFORE_JOIN, GAP_OBSERVED, REJOIN_WITHOUT_LEAVE};
    let mut s = String::from("{\"timelines\":[");
    let mut first = true;
    for t in eng.timelines().iter().flatten() {
        if !first {
            s.push(',');
        }
        first = false;
        let mut flags = String::new();
        for (bit, name) in [
            (DATA_BEFORE_JOIN, "data-before-join"),
            (REJOIN_WITHOUT_LEAVE, "rejoin-without-leave"),
            (DATA_AFTER_LEAVE, "data-after-leave"),
            (GAP_OBSERVED, "gap"),
        ] {
            if t.anomalies & bit != 0 {
                if !flags.is_empty() {
                    flags.push(',');
                }
                flags.push_str(&format!("\"{name}\""));
            }
        }
        let mut log = String::new();
        for (code, tree_no) in t.log.iter().flatten() {
            if !log.is_empty() {
                log.push(',');
            }
            log.push_str(&format!("{{\"ev\":{code},\"tree\":{tree_no}}}"));
        }
        s.push_str(&format!(
            "{{\"pan\":{},\"short\":{},\"ieee\":{},\"stage\":\"{}\",\"left\":{},\"events\":{},\"anomalies\":{},\"flags\":[{}],\"log\":[{}]}}",
            t.pan_id,
            t.short_addr,
            t.ieee.map(|e| e.to_string()).unwrap_or_else(|| String::from("null")),
            timeline_stage_text(t.stage),
            t.left,
            t.event_total,
            t.anomalies,
            flags,
            log,
        ));
    }
    s.push_str("]}");
    s
}

/// Session snapshot load failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionLoadError {
    /// Schema version missing or not [`SESSION_SCHEMA`]: the
    /// snapshot comes from an incompatible writer.
    BadSchema,
    /// Truncated, mistyped, out-of-range, or over-capacity input.
    Malformed,
}

/// Load a session snapshot written by [`session_to_json`].
///
/// The schema version gates first: anything but [`SESSION_SCHEMA`]
/// is [`SessionLoadError::BadSchema`]. Key material is never in the
/// snapshot, so restored slots hold zeroed placeholders (see
/// [`crate::keys::KeySlots::restore`]); the network member caches
/// restart empty, which only affects future distinct-device counts,
/// never rendered state.
pub fn session_from_json(s: &str) -> Result<crate::session::SessionEngine, SessionLoadError> {
    Parser {
        b: s.as_bytes(),
        i: 0,
    }
    .parse_session()
}

/// Byte-cursor parser for exactly the [`session_to_json`] shape
/// (fixed key order, no duplicate or unknown keys).
struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn parse_session(mut self) -> Result<crate::session::SessionEngine, SessionLoadError> {
        use crate::session::SessionEngine;
        use crate::session::{MAX_DEVICES, MAX_NETWORKS};
        self.ch(b'{')?;
        self.key("v")?;
        let v = self.num()?;
        if v != u64::from(SESSION_SCHEMA) {
            return Err(SessionLoadError::BadSchema);
        }
        self.ch(b',')?;
        self.key("trees")?;
        let trees = self.num_u32()?;
        self.ch(b',')?;
        self.key("devices")?;
        self.ch(b'[')?;
        let mut devices = [None; MAX_DEVICES];
        let mut nd = 0usize;
        if !self.peek(b']') {
            loop {
                if nd >= MAX_DEVICES {
                    return Err(SessionLoadError::Malformed);
                }
                devices[nd] = Some(self.device()?);
                nd += 1;
                if self.consume(b',') {
                    continue;
                }
                break;
            }
        }
        self.ch(b']')?;
        self.ch(b',')?;
        self.key("networks")?;
        self.ch(b'[')?;
        let mut networks = [None; MAX_NETWORKS];
        let mut nn = 0usize;
        if !self.peek(b']') {
            loop {
                if nn >= MAX_NETWORKS {
                    return Err(SessionLoadError::Malformed);
                }
                networks[nn] = Some(self.network()?);
                nn += 1;
                if self.consume(b',') {
                    continue;
                }
                break;
            }
        }
        self.ch(b']')?;
        self.ch(b',')?;
        self.key("sec")?;
        self.ch(b'{')?;
        self.key("decryptable")?;
        let decryptable = self.num_u32()?;
        self.ch(b',')?;
        self.key("orphan")?;
        let orphan = self.num_u32()?;
        self.ch(b',')?;
        self.key("slots")?;
        let slots = self.num()?;
        if slots > crate::keys::MAX_NWK_KEYS as u64 {
            return Err(SessionLoadError::Malformed);
        }
        self.ch(b'}')?;
        self.ch(b'}')?;
        self.end()?;
        Ok(SessionEngine::restore(
            trees,
            devices,
            networks,
            decryptable,
            orphan,
            slots as usize,
        ))
    }

    fn device(&mut self) -> Result<crate::session::DeviceEntry, SessionLoadError> {
        self.ch(b'{')?;
        self.key("short")?;
        let short = self.num_u16()?;
        self.ch(b',')?;
        self.key("ieee")?;
        let ieee = if self.consume_str("null") {
            None
        } else {
            Some(self.num()?)
        };
        self.ch(b',')?;
        self.key("last_seq")?;
        let last_seq = self.num_u8()?;
        self.ch(b',')?;
        self.key("frames")?;
        let frames = self.num_u32()?;
        self.ch(b',')?;
        self.key("secured")?;
        let secured = self.num_u32()?;
        self.ch(b',')?;
        self.key("nwk")?;
        let nwk_window = self.window()?;
        self.ch(b',')?;
        self.key("aps")?;
        let aps_window = self.window()?;
        self.ch(b'}')?;
        Ok(crate::session::DeviceEntry {
            short_addr: short,
            ieee,
            last_seq,
            frames,
            secured,
            nwk_window,
            aps_window,
            // Radio readings are live-capture state, not snapshot
            // state: the schema carries no RSSI/LQI, so a restored
            // row restarts with unknown signal.
            last_rssi: None,
            last_lqi: None,
            last_seen: 0,
        })
    }

    fn network(&mut self) -> Result<crate::session::NetworkEntry, SessionLoadError> {
        use crate::session::EMPTY_MEMBER;
        self.ch(b'{')?;
        self.key("pan")?;
        let pan_id = self.num_u16()?;
        self.ch(b',')?;
        self.key("frames")?;
        let frames = self.num_u32()?;
        self.ch(b',')?;
        self.key("devices")?;
        let ndev = self.num_u8()?;
        self.ch(b',')?;
        self.key("secured")?;
        let secured = self.num_u32()?;
        self.ch(b'}')?;
        Ok(crate::session::NetworkEntry {
            pan_id,
            frames,
            devices: ndev,
            secured,
            members: [EMPTY_MEMBER; crate::session::MEMBERS_PER_NETWORK],
            last_seen: 0,
        })
    }

    fn window(&mut self) -> Result<Option<crate::session::SeqWindow>, SessionLoadError> {
        if self.consume_str("null") {
            return Ok(None);
        }
        self.ch(b'{')?;
        self.key("base")?;
        let base = self.num_u8()?;
        self.ch(b',')?;
        self.key("replays")?;
        let replays = self.num_u16()?;
        self.ch(b',')?;
        self.key("gaps")?;
        let gaps = self.num_u16()?;
        self.ch(b',')?;
        self.key("late")?;
        let late = self.num_u16()?;
        self.ch(b'}')?;
        // `seen` is not rendered; mark the restored base as received
        // so the next fold advances from it instead of re-anchoring.
        Ok(Some(crate::session::SeqWindow {
            base,
            seen: 1,
            replays,
            gaps,
            late,
        }))
    }

    fn skip_ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn peek(&mut self, c: u8) -> bool {
        self.skip_ws();
        self.b.get(self.i) == Some(&c)
    }

    fn consume(&mut self, c: u8) -> bool {
        if self.peek(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn ch(&mut self, c: u8) -> Result<(), SessionLoadError> {
        if self.consume(c) {
            Ok(())
        } else {
            Err(SessionLoadError::Malformed)
        }
    }

    fn consume_str(&mut self, s: &str) -> bool {
        self.skip_ws();
        if self.b.len() - self.i >= s.len() && &self.b[self.i..self.i + s.len()] == s.as_bytes() {
            self.i += s.len();
            true
        } else {
            false
        }
    }

    fn key(&mut self, k: &str) -> Result<(), SessionLoadError> {
        self.skip_ws();
        // Keys render as `"name":` with no gaps.
        let kb = k.as_bytes();
        if self.b.len() >= self.i + kb.len() + 3
            && self.b[self.i] == b'"'
            && &self.b[self.i + 1..self.i + 1 + kb.len()] == kb
            && self.b[self.i + 1 + kb.len()] == b'"'
            && self.b[self.i + 2 + kb.len()] == b':'
        {
            self.i += kb.len() + 3;
            Ok(())
        } else {
            Err(SessionLoadError::Malformed)
        }
    }

    /// Unsigned decimal, one or more digits, no sign.
    fn num(&mut self) -> Result<u64, SessionLoadError> {
        self.skip_ws();
        let start = self.i;
        let mut v: u64 = 0;
        while self.i < self.b.len() && self.b[self.i].is_ascii_digit() {
            let d = u64::from(self.b[self.i] - b'0');
            v = v
                .checked_mul(10)
                .and_then(|x| x.checked_add(d))
                .ok_or(SessionLoadError::Malformed)?;
            self.i += 1;
        }
        if self.i == start {
            return Err(SessionLoadError::Malformed);
        }
        Ok(v)
    }

    fn num_u8(&mut self) -> Result<u8, SessionLoadError> {
        let v = self.num()?;
        u8::try_from(v).map_err(|_| SessionLoadError::Malformed)
    }

    fn num_u16(&mut self) -> Result<u16, SessionLoadError> {
        let v = self.num()?;
        u16::try_from(v).map_err(|_| SessionLoadError::Malformed)
    }

    fn num_u32(&mut self) -> Result<u32, SessionLoadError> {
        let v = self.num()?;
        u32::try_from(v).map_err(|_| SessionLoadError::Malformed)
    }

    fn end(&mut self) -> Result<(), SessionLoadError> {
        self.skip_ws();
        if self.i == self.b.len() {
            Ok(())
        } else {
            Err(SessionLoadError::Malformed)
        }
    }
}

fn window_json(w: Option<crate::session::SeqWindow>) -> String {
    w.map(|v| {
        format!(
            "{{\"base\":{},\"replays\":{},\"gaps\":{},\"late\":{}}}",
            v.base, v.replays, v.gaps, v.late,
        )
    })
    .unwrap_or_else(|| String::from("null"))
}

fn maccmd_text(k: &MacCmdKind) -> String {
    match *k {
        MacCmdKind::AssocReq { capabilities } => {
            format!("assoc-req caps={capabilities:#04x}")
        }
        MacCmdKind::AssocResp { short_addr, status } => {
            format!(
                "assoc-resp short={} status={status:#04x}",
                hex16(short_addr)
            )
        }
        MacCmdKind::Disassoc { reason } => format!("disassoc reason={reason:#04x}"),
        MacCmdKind::DataReq => String::from("data-req"),
        MacCmdKind::PanConflict => String::from("pan-conflict"),
        MacCmdKind::Orphan => String::from("orphan"),
        MacCmdKind::BeaconReq => String::from("beacon-req"),
        MacCmdKind::CoordRealign {
            pan,
            coord,
            channel,
            short_addr,
        } => format!(
            "realign pan={} coord={} ch={channel} short={}",
            hex16(pan),
            hex16(coord),
            hex16(short_addr),
        ),
    }
}

fn nwkcmd_text(k: &NwkCmdKind) -> String {
    match *k {
        NwkCmdKind::RouteRequest { rreq_id, dst_addr } => {
            format!("route-req id={rreq_id:#04x} dst={}", hex16(dst_addr))
        }
        NwkCmdKind::RouteReply {
            rreq_id,
            originator,
        } => format!("route-rsp id={rreq_id:#04x} orig={}", hex16(originator)),
        NwkCmdKind::LinkStatus {
            entries,
            first_neighbor,
        } => format!(
            "link-status entries={entries} first={}",
            hex16(first_neighbor)
        ),
        NwkCmdKind::Leave { options } => format!("leave opts={options:#04x}"),
        NwkCmdKind::RouteRecord {
            relays,
            first_relay,
        } => format!("route-rec relays={relays} first={}", hex16(first_relay)),
        NwkCmdKind::NetworkReport { reports, first_pan } => {
            format!("net-report count={reports} first={}", hex16(first_pan))
        }
        NwkCmdKind::NetworkUpdate { updates, first_pan } => {
            format!("net-update count={updates} first={}", hex16(first_pan))
        }
        NwkCmdKind::NetworkStatus { status, dst_addr } => {
            format!("net-status status={status:#04x} dst={}", hex16(dst_addr))
        }
        NwkCmdKind::RejoinRequest { capabilities } => {
            format!("rejoin-req caps={capabilities:#04x}")
        }
        NwkCmdKind::RejoinResponse { short_addr, status } => format!(
            "rejoin-rsp short={} status={status:#04x}",
            hex16(short_addr)
        ),
        NwkCmdKind::TimeoutRequest { arg0, arg1 } => {
            format!("timeout-req arg0={arg0:#04x} arg1={arg1:#04x}")
        }
        NwkCmdKind::TimeoutResponse { arg0, arg1 } => {
            format!("timeout-rsp arg0={arg0:#04x} arg1={arg1:#04x}")
        }
        NwkCmdKind::Unknown => String::from("unknown"),
    }
}

fn touchlink_text(k: &TouchlinkKind) -> String {
    match *k {
        TouchlinkKind::ScanReq {
            zigbee_info,
            touchlink_info,
        } => format!("scan-req zb={zigbee_info:#04x} tl={touchlink_info:#04x}"),
        TouchlinkKind::ScanRsp { key_mask } => {
            format!("scan-rsp key_mask={key_mask:#06x}")
        }
        TouchlinkKind::StartReq { key_index } => {
            format!("start-req key_index={key_index:#04x}")
        }
        TouchlinkKind::StartRsp { status } => format!("start-rsp status={status:#04x}"),
        TouchlinkKind::JoinReq { key_index } => {
            format!("join-req key_index={key_index:#04x}")
        }
        TouchlinkKind::JoinRsp { status } => format!("join-rsp status={status:#04x}"),
        TouchlinkKind::Unknown => String::from("unknown"),
    }
}

fn touchlink_json(t: &TouchlinkNode) -> String {
    let (kind, extra) = match t.kind {
        TouchlinkKind::ScanReq {
            zigbee_info,
            touchlink_info,
        } => (
            "scan-req",
            format!(",\"zb\":{zigbee_info},\"tl\":{touchlink_info}"),
        ),
        TouchlinkKind::ScanRsp { key_mask } => ("scan-rsp", format!(",\"key_mask\":{key_mask}")),
        TouchlinkKind::StartReq { key_index } => {
            ("start-req", format!(",\"key_index\":{key_index}"))
        }
        TouchlinkKind::StartRsp { status } => ("start-rsp", format!(",\"status\":{status}")),
        TouchlinkKind::JoinReq { key_index } => ("join-req", format!(",\"key_index\":{key_index}")),
        TouchlinkKind::JoinRsp { status } => ("join-rsp", format!(",\"status\":{status}")),
        TouchlinkKind::Unknown => ("unknown", String::new()),
    };
    format!(
        "{{\"touchlink\":{{\"tid\":{},\"cmd\":{},\"kind\":\"{kind}\",\"len\":{}{extra}}}}}",
        t.tid, t.command_id, t.payload_len,
    )
}

fn gp_text(k: &GpKind) -> &'static str {
    match k {
        GpKind::Data => "data",
        GpKind::Commissioning => "commissioning",
        GpKind::Decommissioning => "decommissioning",
        GpKind::Success => "success",
        GpKind::ChannelRequest => "channel-request",
        GpKind::CommissioningReply => "commissioning-reply",
        GpKind::ChannelConfig => "channel-config",
        GpKind::Maintenance => "maintenance",
        GpKind::LpedOpaque => "lped-opaque",
        GpKind::EncryptedSealed => "encrypted-sealed",
    }
}

fn gp_json(g: &GpNode) -> String {
    format!(
        "{{\"gp\":{{\"type\":{},\"app\":{},\"lvl\":{},\"keybit\":{},\"rx\":{},\"proxy\":{},\"srcid\":{},\"ieee\":{},\"cmd\":{},\"kind\":\"{}\",\"ctr\":{},\"len\":{},\"secured\":{}}}}}",
        g.frame_type,
        g.app_id,
        g.level,
        g.key_bit,
        g.rx_after_tx,
        g.direction_proxy,
        g.src_id,
        g.ieee
            .map(|v| v.to_string())
            .unwrap_or_else(|| String::from("null")),
        g.command_id
            .map(|v| v.to_string())
            .unwrap_or_else(|| String::from("null")),
        gp_text(&g.kind),
        g.frame_counter
            .map(|v| v.to_string())
            .unwrap_or_else(|| String::from("null")),
        g.payload_len,
        g.secured,
    )
}

fn maccmd_json(m: &MacCmdNode) -> String {
    let (kind, extra) = match m.kind {
        MacCmdKind::AssocReq { capabilities } => ("assoc-req", format!(",\"caps\":{capabilities}")),
        MacCmdKind::AssocResp { short_addr, status } => (
            "assoc-resp",
            format!(",\"short\":{short_addr},\"status\":{status}"),
        ),
        MacCmdKind::Disassoc { reason } => ("disassoc", format!(",\"reason\":{reason}")),
        MacCmdKind::DataReq => ("data-req", String::new()),
        MacCmdKind::PanConflict => ("pan-conflict", String::new()),
        MacCmdKind::Orphan => ("orphan", String::new()),
        MacCmdKind::BeaconReq => ("beacon-req", String::new()),
        MacCmdKind::CoordRealign {
            pan,
            coord,
            channel,
            short_addr,
        } => (
            "realign",
            format!(",\"pan\":{pan},\"coord\":{coord},\"ch\":{channel},\"short\":{short_addr}"),
        ),
    };
    format!(
        "{{\"maccmd\":{{\"cmd\":{},\"kind\":\"{kind}\"{extra}}}}}",
        m.command_id
    )
}

fn nwkcmd_json(n: &NwkCmdNode) -> String {
    let (kind, extra) = match n.kind {
        NwkCmdKind::RouteRequest { rreq_id, dst_addr } => {
            ("route-req", format!(",\"id\":{rreq_id},\"dst\":{dst_addr}"))
        }
        NwkCmdKind::RouteReply {
            rreq_id,
            originator,
        } => (
            "route-rsp",
            format!(",\"id\":{rreq_id},\"orig\":{originator}"),
        ),
        NwkCmdKind::LinkStatus {
            entries,
            first_neighbor,
        } => (
            "link-status",
            format!(",\"entries\":{entries},\"first\":{first_neighbor}"),
        ),
        NwkCmdKind::Leave { options } => ("leave", format!(",\"opts\":{options}")),
        NwkCmdKind::RouteRecord {
            relays,
            first_relay,
        } => (
            "route-rec",
            format!(",\"relays\":{relays},\"first\":{first_relay}"),
        ),
        NwkCmdKind::NetworkReport { reports, first_pan } => (
            "net-report",
            format!(",\"count\":{reports},\"first\":{first_pan}"),
        ),
        NwkCmdKind::NetworkUpdate { updates, first_pan } => (
            "net-update",
            format!(",\"count\":{updates},\"first\":{first_pan}"),
        ),
        NwkCmdKind::NetworkStatus { status, dst_addr } => (
            "net-status",
            format!(",\"status\":{status},\"dst\":{dst_addr}"),
        ),
        NwkCmdKind::RejoinRequest { capabilities } => {
            ("rejoin-req", format!(",\"caps\":{capabilities}"))
        }
        NwkCmdKind::RejoinResponse { short_addr, status } => (
            "rejoin-rsp",
            format!(",\"short\":{short_addr},\"status\":{status}"),
        ),
        NwkCmdKind::TimeoutRequest { arg0, arg1 } => {
            ("timeout-req", format!(",\"arg0\":{arg0},\"arg1\":{arg1}"))
        }
        NwkCmdKind::TimeoutResponse { arg0, arg1 } => {
            ("timeout-rsp", format!(",\"arg0\":{arg0},\"arg1\":{arg1}"))
        }
        NwkCmdKind::Unknown => ("unknown", String::new()),
    };
    format!(
        "{{\"nwkcmd\":{{\"cmd\":{},\"kind\":\"{kind}\"{extra}}}}}",
        n.command_id
    )
}

fn apscmd_text(k: &ApsCmdKind) -> String {
    match *k {
        ApsCmdKind::TransportKey { key_type } => {
            format!("transport-key keytype={key_type:#04x}")
        }
        ApsCmdKind::UpdateDevice { status, short_addr } => {
            format!(
                "update-device status={status:#04x} short={}",
                hex16(short_addr)
            )
        }
        ApsCmdKind::RemoveDevice => String::from("remove-device"),
        ApsCmdKind::RequestKey { key_type } => {
            format!("request-key keytype={key_type:#04x}")
        }
        ApsCmdKind::SwitchKey { key_seq } => {
            format!("switch-key seq={key_seq:#04x}")
        }
        ApsCmdKind::Tunnel => String::from("tunnel"),
        ApsCmdKind::Unknown => String::from("unknown"),
    }
}

fn apscmd_json(n: &ApsCmdNode) -> String {
    let (kind, extra) = match n.kind {
        ApsCmdKind::TransportKey { key_type } => {
            ("transport-key", format!(",\"key_type\":{key_type}"))
        }
        ApsCmdKind::UpdateDevice { status, short_addr } => (
            "update-device",
            format!(",\"status\":{status},\"short\":{short_addr}"),
        ),
        ApsCmdKind::RemoveDevice => ("remove-device", String::new()),
        ApsCmdKind::RequestKey { key_type } => ("request-key", format!(",\"key_type\":{key_type}")),
        ApsCmdKind::SwitchKey { key_seq } => ("switch-key", format!(",\"key_seq\":{key_seq}")),
        ApsCmdKind::Tunnel => ("tunnel", String::new()),
        ApsCmdKind::Unknown => ("unknown", String::new()),
    };
    format!(
        "{{\"apscmd\":{{\"cmd\":{},\"kind\":\"{kind}\"{extra},\"len\":{}}}}}",
        n.command_id, n.payload_len
    )
}

fn detail_text(d: &crate::tree::ZclDetail) -> String {
    use crate::tree::ZclDetail as D;
    match *d {
        D::None => String::from("-"),
        D::Global {
            cmd,
            records,
            first_id,
            status,
        } => format!(
            "global cmd={cmd:#04x} rec={records} id={} status={status:#04x}",
            hex16(first_id)
        ),
        D::OnOff { cmd } => format!("onoff cmd={cmd:#04x}"),
        D::Level { cmd, arg0, arg1 } => {
            format!("level cmd={cmd:#04x} arg0={arg0:#04x} arg1={arg1:#06x}")
        }
        D::IasZone { cmd } => format!("iaszone cmd={cmd:#04x}"),
        D::Metering {
            cmd,
            arg0,
            arg1,
            arg2,
        } => format!("metering cmd={cmd:#04x} arg0={arg0:#04x} arg1={arg1:#04x} arg2={arg2:#010x}"),
        D::Price { cmd, arg0, arg1 } => {
            format!("price cmd={cmd:#04x} arg0={arg0:#010x} arg1={arg1:#010x}")
        }
        D::KeyInit {
            suite,
            eph_time,
            confirm_time,
        } => format!("keyinit suite={suite:#06x} eph={eph_time:#04x} confirm={confirm_time:#04x}"),
        D::KeyMsg { cmd, len } => format!("keymsg cmd={cmd:#04x} len={len}"),
        D::KeyTerminate {
            status,
            wait_s,
            suite,
        } => format!("keyterm status={status:#04x} wait={wait_s} suite={suite:#06x}"),
        D::Unknown { cmd } => format!("unknown cmd={cmd:#04x}"),
    }
}

fn detail_json(d: &crate::tree::ZclDetail) -> String {
    use crate::tree::ZclDetail as D;
    match *d {
        D::None => String::from("{\"kind\":\"none\"}"),
        D::Global {
            cmd,
            records,
            first_id,
            status,
        } => format!(
            "{{\"kind\":\"global\",\"cmd\":{cmd},\"records\":{records},\"first_id\":{first_id},\"status\":{status}}}"
        ),
        D::OnOff { cmd } => format!("{{\"kind\":\"onoff\",\"cmd\":{cmd}}}"),
        D::Level { cmd, arg0, arg1 } => {
            format!("{{\"kind\":\"level\",\"cmd\":{cmd},\"arg0\":{arg0},\"arg1\":{arg1}}}")
        }
        D::IasZone { cmd } => format!("{{\"kind\":\"iaszone\",\"cmd\":{cmd}}}"),
        D::Metering {
            cmd,
            arg0,
            arg1,
            arg2,
        } => format!(
            "{{\"kind\":\"metering\",\"cmd\":{cmd},\"arg0\":{arg0},\"arg1\":{arg1},\"arg2\":{arg2}}}"
        ),
        D::Price { cmd, arg0, arg1 } => {
            format!("{{\"kind\":\"price\",\"cmd\":{cmd},\"arg0\":{arg0},\"arg1\":{arg1}}}")
        }
        D::KeyInit {
            suite,
            eph_time,
            confirm_time,
        } => format!(
            "{{\"kind\":\"keyinit\",\"suite\":{suite},\"eph_time\":{eph_time},\"confirm_time\":{confirm_time}}}"
        ),
        D::KeyMsg { cmd, len } => format!("{{\"kind\":\"keymsg\",\"cmd\":{cmd},\"len\":{len}}}"),
        D::KeyTerminate {
            status,
            wait_s,
            suite,
        } => format!(
            "{{\"kind\":\"keyterm\",\"status\":{status},\"wait\":{wait_s},\"suite\":{suite}}}"
        ),
        D::Unknown { cmd } => format!("{{\"kind\":\"unknown\",\"cmd\":{cmd}}}"),
    }
}

fn hex8(v: u8) -> String {
    format!("{v:#04x}")
}

fn hex16(v: u16) -> String {
    format!("{v:#06x}")
}

fn hex32(v: u32) -> String {
    format!("{v:#010x}")
}

fn opt16(v: Option<u16>) -> String {
    v.map(hex16).unwrap_or_else(|| String::from("-"))
}

fn addr(a: Addr) -> String {
    match a {
        Addr::None => String::from("-"),
        Addr::Short(s) => hex16(s),
        Addr::Extended(e) => format!("{e:#018x}"),
    }
}

fn opt_json_u8(v: Option<u8>) -> String {
    v.map(|b| b.to_string())
        .unwrap_or_else(|| String::from("null"))
}

fn opt_json_u16(v: Option<u16>) -> String {
    v.map(|b| b.to_string())
        .unwrap_or_else(|| String::from("null"))
}
