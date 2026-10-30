//! Offline run: Listener or pcap packets → dissect → fold → reports.
//!
//! Host-side (`std`) only: the decode legs themselves
//! ([`chain`](rounddance_inspect::chain),
//! [`SessionEngine`](rounddance_inspect::session::SessionEngine)) stay
//! `no_std` + `#![forbid(unsafe_code)]`; this module only owns file
//! IO, growable report buffers, and pcap-out writers.
//!
//! Funnel rule: every capture mode dissects with
//! [`dissect_with_keys`](rounddance_inspect::chain::dissect_with_keys),
//! attaches radio metadata with
//! [`set_radio`](rounddance_inspect::tree::DecodeTree::set_radio),
//! and folds with
//! [`note_tree`](rounddance_inspect::session::SessionEngine::note_tree).
//! [`run_listener`] covers any
//! [`Listener`](rounddance_inspect::capture::Listener) backend (the
//! offline golden path is
//! [`ReplayListener`](rounddance_inspect::sniffer::ReplayListener));
//! [`run_packets`] covers pcap/pcapng file input;
//! [`run_stream`] replays raw wire bytes through the streaming
//! [`Ingest`](rounddance_inspect::stream::Ingest) pipe. The
//! live == replay invariant is the byte-identity of the Listener and
//! Ingest legs over the same feed (pinned by test, never assumed).

use crate::radio::{self, LINKTYPE_SNIFFER_RADIO, RADIO_HDR_LEN};
use rounddance_inspect::capture::Listener;
use rounddance_inspect::stream::Ingest;
use rounddance_inspect::tree::{DecodeTree, TreeError};
use rounddance_inspect::{chain, keys::KeySlots, pcap, report, session::SessionEngine};
use std::fmt::Display;
use std::io::{self, Read, Write};

/// One folded frame: the raw bytes plus its dissection outcome.
#[derive(Clone, Debug)]
pub struct FrameRecord {
    /// 1-based frame ordinal (also the synthetic `ts_us` for text
    /// feeds, which carry no capture timestamps).
    pub index: u32,
    /// 802.15.4 channel the frame is labeled with.
    pub channel: u8,
    /// Raw RSSI reading in dBm (quirks included, honest bytes).
    pub rssi: i8,
    /// Link quality indicator (radio-defined).
    pub lqi: u8,
    /// Capture timestamp in microseconds (pcap records keep theirs;
    /// text-feed frames take the ordinal).
    pub ts_us: u64,
    /// Bare frame bytes (MAC header onward, no FCS).
    pub data: Vec<u8>,
    /// Dissection outcome (`Err` only on a MAC-level refusal).
    pub outcome: Result<DecodeTree, TreeError>,
}

/// One offline run: folded session plus every frame record.
#[derive(Debug)]
pub struct RunReport {
    /// Session, device, network, and timeline tables.
    pub engine: SessionEngine,
    /// Per-frame records in capture order.
    pub frames: Vec<FrameRecord>,
    /// Frames refused at the MAC level.
    pub dissect_errors: u32,
    /// Backend read failures (never frame data).
    pub listener_errors: u32,
    /// Per-run worker lease ID (pure derivation, see [`crate::lease`]).
    pub lease: u64,
    /// Operator tag naming the run (file stem by default).
    pub tag: String,
    /// 802.15.4 channel labeling the run.
    pub channel: u8,
}

/// Streaming-ingest counters for [`run_stream`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamStats {
    /// Frame lines dissected (successes and refusals alike).
    pub frames: u32,
    /// Non-frame wire lines consumed.
    pub ignored: u32,
    /// Frame lines wider than the caller scratch.
    pub oversize: u32,
    /// MAC-level dissect refusals.
    pub dissect_errors: u32,
    /// Framer lines dropped at resync.
    pub framer_dropped: u32,
}

impl RunReport {
    /// Start an empty run (public so the live binary loop can fold
    /// frames one at a time under its capture deadline).
    pub fn new(tag: &str, channel: u8, lease: u64, keys: &KeySlots) -> Self {
        let mut engine = SessionEngine::new();
        engine.set_keys(keys);
        Self {
            engine,
            frames: Vec::new(),
            dissect_errors: 0,
            listener_errors: 0,
            lease,
            tag: String::from(tag),
            channel,
        }
    }

    /// Fold one frame: dissect with `keys`, attach radio metadata,
    /// and note the tree in the session. Public so the live binary
    /// loop shares the exact offline fold leg (same trees, same
    /// session — the live == file invariant).
    pub fn push_frame(
        &mut self,
        keys: &KeySlots,
        channel: u8,
        rssi: i8,
        lqi: u8,
        ts_us: u64,
        payload: &[u8],
    ) {
        let index = self.frames.len() as u32 + 1;
        let outcome = match chain::dissect_with_keys(payload, keys) {
            Ok(mut tree) => {
                tree.set_radio(channel, rssi, lqi);
                self.engine.note_tree(&tree);
                Ok(tree)
            }
            Err(e) => {
                self.dissect_errors = self.dissect_errors.saturating_add(1);
                Err(e)
            }
        };
        self.frames.push(FrameRecord {
            index,
            channel,
            rssi,
            lqi,
            ts_us,
            data: payload.to_vec(),
            outcome,
        });
    }
}

/// Run one [`Listener`] backend to exhaustion (offline: a
/// [`ReplayListener`](rounddance_inspect::sniffer::ReplayListener)
/// over a saved `sniff_*.txt` feed; later: live front-ends).
///
/// Text feeds carry no capture timestamps, so `ts_us` is the
/// 1-based frame ordinal (deterministic across replays).
pub fn run_listener<L: Listener>(
    li: &mut L,
    channel: u8,
    keys: &KeySlots,
    tag: &str,
    lease: u64,
) -> RunReport
where
    L::Error: Display,
{
    let mut rep = RunReport::new(tag, channel, lease, keys);
    let mut buf = [0u8; 256];
    loop {
        match li.next_frame(&mut buf) {
            Ok(Some(c)) => {
                let ts_us = rep.frames.len() as u64 + 1;
                rep.push_frame(keys, channel, c.rssi, c.lqi, ts_us, c.payload);
            }
            Ok(None) => break,
            Err(_) => {
                rep.listener_errors = rep.listener_errors.saturating_add(1);
            }
        }
    }
    rep
}

/// Run pcap/pcapng packets (already ingested with
/// [`read_all`](rounddance_inspect::pcap::read_all)) through the
/// same dissect + fold legs. Packets keep their capture timestamps;
/// every packet is labeled with `channel` (pcap records carry no
/// channel of their own).
pub fn run_packets(
    packets: &[pcap::Packet],
    channel: u8,
    keys: &KeySlots,
    tag: &str,
    lease: u64,
) -> RunReport {
    let mut rep = RunReport::new(tag, channel, lease, keys);
    for p in packets {
        rep.push_frame(keys, channel, 0, 0, p.ts_us, &p.data);
    }
    rep
}

/// Replay radio-header pcap records (written by
/// [`write_pcap_radio`], read back with [`read_pcap_radio`])
/// through the same dissect + fold legs. Every record keeps its own
/// capture timestamp, channel, RSSI, and LQI; `channel` only labels
/// the run header. A live run's radio pcap replayed here with the
/// same tag/lease/keys renders byte-identical text and JSON reports
/// — the live == file conformance leg.
pub fn run_radio_packets(
    packets: &[RadioPacket],
    channel: u8,
    keys: &KeySlots,
    tag: &str,
    lease: u64,
) -> RunReport {
    let mut rep = RunReport::new(tag, channel, lease, keys);
    for p in packets {
        rep.push_frame(keys, p.channel, p.rssi, p.lqi, p.ts_us, &p.data);
    }
    rep
}

/// Replay raw sniffer wire bytes through the streaming
/// [`Ingest`](rounddance_inspect::stream::Ingest) pipe in
/// `chunk`-sized pushes (chunk `0` behaves as whole-input: a single
/// push, then drain). Returns the folded run plus the pipe counters.
///
/// The trees and session this produces must equal the
/// [`run_listener`] leg over the same feed byte-for-byte — that is
/// the live == replay invariant, pinned by test.
pub fn run_stream(
    wire: &[u8],
    chunk: usize,
    channel: u8,
    keys: &KeySlots,
    tag: &str,
    lease: u64,
) -> (RunReport, StreamStats) {
    let mut rep = RunReport::new(tag, channel, lease, keys);
    let mut ing = Ingest::new(channel);
    let mut frame_scratch = [0u8; 256];
    let mut stats = StreamStats::default();
    // Chunk 0 means whole-input in one push; otherwise the pipe is
    // fed in `chunk`-sized pieces.
    let step = if chunk == 0 { wire.len().max(1) } else { chunk };
    for piece in wire.chunks(step) {
        ing.push(piece);
        drain(
            &mut ing,
            &mut rep,
            keys,
            &mut frame_scratch,
            channel,
            &mut stats,
        );
    }
    // A tail without its newline is held, never emitted — exactly
    // the framer discipline; nothing further to drain.
    stats.framer_dropped = ing.framer().dropped;
    (rep, stats)
}

fn drain(
    ing: &mut Ingest,
    rep: &mut RunReport,
    keys: &KeySlots,
    frame: &mut [u8],
    channel: u8,
    stats: &mut StreamStats,
) {
    use rounddance_inspect::stream::Step;
    while let Some(s) = ing.next_step(&mut rep.engine, keys, frame) {
        match s {
            Step::Ignored => {
                stats.ignored = stats.ignored.saturating_add(1);
            }
            Step::Oversize { .. } => {
                stats.oversize = stats.oversize.saturating_add(1);
                rep.listener_errors = rep.listener_errors.saturating_add(1);
            }
            Step::Frame { meta, outcome } => {
                stats.frames = stats.frames.saturating_add(1);
                let ts_us = rep.frames.len() as u64 + 1;
                // The ingest pipe tags the folded tree with its own
                // construction channel (equal to `channel` by every
                // caller above); records carry the same label.
                match outcome {
                    Ok(tree) => {
                        rep.frames.push(FrameRecord {
                            index: rep.frames.len() as u32 + 1,
                            channel,
                            rssi: meta.rssi,
                            lqi: meta.lqi,
                            ts_us,
                            data: frame.get(..meta.len).unwrap_or(&[]).to_vec(),
                            outcome: Ok(tree),
                        });
                    }
                    Err(e) => {
                        stats.dissect_errors = stats.dissect_errors.saturating_add(1);
                        rep.dissect_errors = rep.dissect_errors.saturating_add(1);
                        rep.frames.push(FrameRecord {
                            index: rep.frames.len() as u32 + 1,
                            channel,
                            rssi: meta.rssi,
                            lqi: meta.lqi,
                            ts_us,
                            data: frame.get(..meta.len).unwrap_or(&[]).to_vec(),
                            outcome: Err(e),
                        });
                    }
                }
            }
        }
    }
}

/// Human-readable report: run header, every per-frame tree (or
/// refusal), then the session and timeline tables.
pub fn text_report(rep: &RunReport) -> String {
    use std::fmt::Write as _;
    let mut lease_hex = [0u8; 16];
    crate::lease::lease_id_hex(rep.lease, &mut lease_hex);
    let mut s = String::new();
    let _ = writeln!(
        s,
        "run: lease={} tag={} channel={} frames={} dissect_errors={} listener_errors={}",
        String::from_utf8_lossy(&lease_hex),
        rep.tag,
        rep.channel,
        rep.frames.len(),
        rep.dissect_errors,
        rep.listener_errors,
    );
    for f in &rep.frames {
        let _ = writeln!(
            s,
            "== f{} len={} rssi={} lqi={} ch={} ts={} ==",
            f.index,
            f.data.len(),
            f.rssi,
            f.lqi,
            f.channel,
            f.ts_us,
        );
        match &f.outcome {
            Ok(tree) => s.push_str(&report::to_text(tree)),
            Err(e) => {
                let _ = writeln!(s, "  ERROR {e:?}");
            }
        }
    }
    let _ = writeln!(s, "== session ==");
    s.push_str(&report::session_to_text(&rep.engine));
    let _ = writeln!(s, "== timelines ==");
    s.push_str(&report::timelines_to_text(&rep.engine));
    s
}

/// Machine-readable report: run envelope, every per-frame tree (or
/// refusal), and the session v2 snapshot (v1 bytes as its prefix,
/// timelines appended).
pub fn json_report(rep: &RunReport) -> String {
    let mut lease_hex = [0u8; 16];
    crate::lease::lease_id_hex(rep.lease, &mut lease_hex);
    let mut s = format!(
        "{{\"sniffer\":\"rounddance-sniffer {}\",\"lease\":\"{}\",\"tag\":\"{}\",\"channel\":{},\"frames\":[",
        env!("CARGO_PKG_VERSION"),
        String::from_utf8_lossy(&lease_hex),
        rep.tag,
        rep.channel,
    );
    let mut first = true;
    for f in &rep.frames {
        if !first {
            s.push(',');
        }
        first = false;
        match &f.outcome {
            Ok(tree) => {
                s.push_str(&format!(
                    "{{\"n\":{},\"len\":{},\"ts\":{},\"tree\":{}}}",
                    f.index,
                    f.data.len(),
                    f.ts_us,
                    report::to_json(tree),
                ));
            }
            Err(e) => {
                s.push_str(&format!(
                    "{{\"n\":{},\"len\":{},\"ts\":{},\"error\":\"{e:?}\"}}",
                    f.index,
                    f.data.len(),
                    f.ts_us,
                ));
            }
        }
    }
    s.push_str("],\"session\":");
    s.push_str(&report::session_to_json_v2(&rep.engine));
    s.push('}');
    s
}

/// pcap-out with the untouched 195 writer: bare frames, caller-chosen
/// timestamps (pcap originals, or ordinals for text feeds).
pub fn write_pcap_195<W: Write>(rep: &RunReport, w: &mut W) -> io::Result<()> {
    let packets: Vec<pcap::Packet> = rep
        .frames
        .iter()
        .map(|f| pcap::Packet {
            ts_us: f.ts_us,
            linktype: pcap::LINKTYPE_IEEE802_15_4,
            data: f.data.clone(),
        })
        .collect();
    pcap::write_pcap(w, pcap::LINKTYPE_IEEE802_15_4, &packets)
}

/// pcap-out with the radio-header DLT ([`LINKTYPE_SNIFFER_RADIO`]):
/// every packet payload is the 4-octet [`radio`] header plus the bare
/// frame, so channel/RSSI/LQI survive the capture.
pub fn write_pcap_radio<W: Write>(rep: &RunReport, w: &mut W) -> io::Result<()> {
    let mut packets: Vec<pcap::Packet> = Vec::with_capacity(rep.frames.len());
    for f in &rep.frames {
        let mut data = Vec::with_capacity(RADIO_HDR_LEN + f.data.len());
        data.extend_from_slice(&radio::encode_header(f.channel, f.rssi, f.lqi));
        data.extend_from_slice(&f.data);
        packets.push(pcap::Packet {
            ts_us: f.ts_us,
            linktype: LINKTYPE_SNIFFER_RADIO,
            data,
        });
    }
    pcap::write_pcap(w, LINKTYPE_SNIFFER_RADIO, &packets)
}

/// One radio-header pcap record (see [`crate::radio`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RadioPacket {
    /// Capture timestamp in microseconds.
    pub ts_us: u64,
    /// 802.15.4 channel the frame arrived on.
    pub channel: u8,
    /// Raw RSSI reading in dBm (honest bytes: quirks included).
    pub rssi: i8,
    /// Link quality indicator (radio-defined).
    pub lqi: u8,
    /// Bare frame bytes (MAC header onward, no FCS).
    pub data: Vec<u8>,
}

/// Read a radio-header pcap recording (written by
/// [`write_pcap_radio`]) back into records. A non-radio link type or
/// a bad header version is `InvalidData`, never a panic.
pub fn read_pcap_radio<R: Read>(r: &mut R) -> io::Result<Vec<RadioPacket>> {
    let packets = pcap::read_all(r).map_err(|e| match e {
        pcap::IngestError::Io(e) => e,
        other => io::Error::new(io::ErrorKind::InvalidData, format!("{other:?}")),
    })?;
    let mut out = Vec::with_capacity(packets.len());
    for p in packets {
        if p.linktype != LINKTYPE_SNIFFER_RADIO {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "linktype {} is not radio-header {}",
                    p.linktype, LINKTYPE_SNIFFER_RADIO
                ),
            ));
        }
        let fields = radio::decode_header(&p.data)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad radio header"))?;
        out.push(RadioPacket {
            ts_us: p.ts_us,
            channel: fields.channel,
            rssi: fields.rssi,
            lqi: fields.lqi,
            data: p.data.get(RADIO_HDR_LEN..).unwrap_or(&[]).to_vec(),
        });
    }
    Ok(out)
}
