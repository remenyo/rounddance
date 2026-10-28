//! Text and JSON reports over [`DecodeTree`](crate::tree::DecodeTree) (`std` only).
//!
//! Reports render owned scalars only — no hexdumps of key material, no
//! payload bytes. A secured frame is reported as `secured` with its
//! remaining length, never decrypted.

use crate::tree::{Addr, DecodeTree, Layer};
use std::fmt::Write as _;

/// One-line human summary plus one indented line per layer.
pub fn to_text(tree: &DecodeTree) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "frame: {} layer(s)", tree.len());
    for layer in tree.layers().iter().flatten() {
        match layer {
            Layer::Mac(m) => {
                let _ = writeln!(
                    s,
                    "  mac: type={} seq={} dst_pan={} dst={} src={}{}",
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
                    "  zcl: type={} dir={} tsn={} cmd={:#04x} payload={}B{}",
                    z.frame_type,
                    z.direction,
                    hex8(z.tsn),
                    z.command_id,
                    z.payload_len,
                    z.manufacturer_code
                        .map(|c| format!(" mfr={c:#06x}"))
                        .unwrap_or_default(),
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
                    "{{\"mac\":{{\"type\":{},\"seq\":{},\"seq_present\":{},\"dst_pan\":{},\"dst\":\"{}\",\"src\":\"{}\",\"secured\":{}}}}}",
                    m.frame_type,
                    m.seq,
                    m.seq_present,
                    opt_json_u16(m.dst_pan),
                    addr(m.dst),
                    addr(m.src),
                    m.security_enabled,
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
                    "{{\"zcl\":{{\"type\":{},\"dir\":{},\"tsn\":{},\"cmd\":{},\"payload_len\":{},\"mfr\":{}}}}}",
                    z.frame_type,
                    z.direction,
                    z.tsn,
                    z.command_id,
                    z.payload_len,
                    opt_json_u16(z.manufacturer_code),
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
    s.push_str("]}");
    s
}

fn hex8(v: u8) -> String {
    format!("{v:#04x}")
}

fn hex16(v: u16) -> String {
    format!("{v:#06x}")
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
