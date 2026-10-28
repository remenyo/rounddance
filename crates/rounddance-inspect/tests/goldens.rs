//! Decode goldens: repo-codec-built frames + genuine captured-air NWK PDUs.
//!
//! Provenance: the full-chain frame is assembled with the repo's own
//! `rounddance-nwk` / `rounddance-aps` / `rounddance-zcl` encoders (the
//! same bytes the stack emits); the secured-NWK goldens are the genuine
//! Ember U1/B1 captures pinned in `rounddance-security/tests/vectors.rs`
//! (copied octets, never re-derived). No new captures were taken.

use rounddance_inspect::capture::Sender as _;
use rounddance_inspect::{capture, chain, pcap, report, session, tree};

// ---------------------------------------------------------------------------
// Helpers: build one full-chain frame with the repo codecs.
// ---------------------------------------------------------------------------

fn build_full_frame() -> Vec<u8> {
    // ZCL: global Read Attributes (0x00), client->server, tsn 0x42.
    let zcl = rounddance_zcl::frame::Header {
        control: rounddance_zcl::frame::FrameControl {
            frame_type: rounddance_zcl::frame::FrameType::Global,
            manufacturer_specific: false,
            direction: rounddance_zcl::frame::Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x42,
        command_id: 0x00,
    };
    let mut zcl_buf = [0u8; 16];
    let zn = zcl.encode_into(&mut zcl_buf).unwrap();
    // Attribute 0x0000 of On/Off.
    let mut zcl_payload = [0u8; 18];
    zcl_payload[..zn].copy_from_slice(&zcl_buf[..zn]);
    zcl_payload[zn..zn + 2].copy_from_slice(&0x0000u16.to_le_bytes());

    // APS data: HA profile, On/Off cluster, ep 1->1, counter 0x07.
    let aps = rounddance_aps::frame::DataHeader {
        control: rounddance_aps::frame::FrameControl::data(
            rounddance_aps::frame::DeliveryMode::Unicast,
        ),
        dest: rounddance_aps::frame::DataDest::Unicast { dst_endpoint: 1 },
        cluster_id: 0x0006,
        profile_id: 0x0104,
        src_endpoint: 1,
        counter: 0x07,
        ext: None,
    };
    let mut aps_buf = [0u8; 64];
    let an = aps
        .encode_into(&zcl_payload[..zn + 2], &mut aps_buf)
        .unwrap();

    // NWK data: 0x1234 -> 0x5678, radius 30, seq 0x09.
    let nwk = rounddance_nwk::frame::NwkHeader::minimal(
        rounddance_nwk::frame::FrameControl::data(),
        0x5678,
        0x1234,
        30,
        0x09,
    );
    let mut nwk_buf = [0u8; 128];
    let nn = nwk.encode_into(&aps_buf[..an], &mut nwk_buf).unwrap();

    // MAC: data, ack-req, PAN compression, short->short, PAN 0x3761.
    let mut frame = vec![0x41, 0x88, 0x5a];
    frame.extend_from_slice(&0x3761u16.to_le_bytes());
    frame.extend_from_slice(&0x5678u16.to_le_bytes());
    frame.extend_from_slice(&0x1234u16.to_le_bytes());
    frame.extend_from_slice(&nwk_buf[..nn]);
    frame
}

#[test]
fn golden_full_chain_mac_nwk_aps_zcl() {
    let frame = build_full_frame();
    let tree = chain::dissect(&frame).unwrap();
    assert_eq!(tree.len(), 4, "MAC+NWK+APS+ZCL, no stop note");

    let m = tree.mac().expect("mac node");
    assert_eq!(m.frame_type, 1);
    assert_eq!(m.seq, 0x5a);
    assert_eq!(m.dst_pan, Some(0x3761));
    assert_eq!(m.dst, tree::Addr::Short(0x5678));
    assert_eq!(m.src, tree::Addr::Short(0x1234));
    assert!(!m.security_enabled);

    let n = tree.nwk().expect("nwk node");
    assert_eq!(n.frame_type, 0);
    assert_eq!(n.dst_addr, 0x5678);
    assert_eq!(n.src_addr, 0x1234);
    assert_eq!(n.seq, 0x09);
    assert!(!n.security);

    let a = tree.aps().expect("aps node");
    assert_eq!(a.frame_type, 0);
    assert_eq!(a.cluster_id, 0x0006);
    assert_eq!(a.profile_id, 0x0104);
    assert_eq!(a.counter, 0x07);

    let z = tree.zcl().expect("zcl node");
    assert_eq!(z.frame_type, 0);
    assert_eq!(z.direction, 0);
    assert_eq!(z.tsn, 0x42);
    assert_eq!(z.command_id, 0x00);
    assert_eq!(z.payload_len, 2);
}

// ---------------------------------------------------------------------------
// Captured-air goldens: genuine Ember U1/B1 NWK PDUs (wave-36 provenance).
// ---------------------------------------------------------------------------

const EMBER_U1: [u8; 45] = [
    0x61, 0x88, 0x60, 0x1d, 0xb2, 0x1d, 0x02, 0x00, 0x00, 0x09, 0x12, 0x1d, 0x02, 0x00, 0x00, 0x01,
    0x44, 0x5f, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04, 0x28, 0x04, 0x40, 0x00, 0x00, 0x5f, 0x75,
    0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04, 0x00, 0x00, 0xab, 0x53, 0x68, 0xca, 0xee,
];

const EMBER_B1: [u8; 45] = [
    0x41, 0x88, 0x48, 0x1d, 0xb2, 0xff, 0xff, 0x00, 0x00, 0x09, 0x12, 0xfc, 0xff, 0x00, 0x00, 0x01,
    0x3d, 0x5f, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04, 0x28, 0x00, 0x40, 0x00, 0x00, 0x5f, 0x75,
    0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04, 0x00, 0xd9, 0x4f, 0xa2, 0xf7, 0x42, 0x4b,
];

#[test]
fn golden_captured_air_secured_nwk_stops_chain() {
    // Full 802.15.4 frames: MAC + secured NWK command + stop note.
    // U1: 0x0000 -> 0x021d unicast, NWK seq 0x44 (opens to leave 0x04);
    // B1: 0x0000 -> 0xfffc broadcast, NWK seq 0x3d (opens to 0x08).
    // B1 rides a MAC broadcast (0xffff) over a NWK low-power-routers
    // broadcast (0xfffc): the two headers name different scopes on air.
    for (frame, mac_dst, nwk_dst, seq) in [
        (&EMBER_U1[..], 0x021du16, 0x021du16, 0x44u8),
        (&EMBER_B1[..], 0xffffu16, 0xfffcu16, 0x3du8),
    ] {
        let tree = chain::dissect(frame).unwrap();
        let m = tree.mac().expect("mac node");
        assert_eq!(m.dst_pan, Some(0xb21d));
        assert_eq!(m.dst, tree::Addr::Short(mac_dst));
        let n = tree.nwk().expect("nwk node");
        assert_eq!(n.frame_type, 1, "NWK command");
        assert!(n.security, "captured frames are NWK-secured");
        assert_eq!(n.dst_addr, nwk_dst);
        assert_eq!(n.src_addr, 0x0000);
        assert_eq!(n.seq, seq);
        assert_eq!(
            n.command_id, None,
            "command id is inside the encrypted part"
        );
        assert_eq!(tree.len(), 3, "MAC + NWK + secured stop note");
        assert!(tree.aps().is_none());
        // Same PDU dissected bare (no MAC header) stops identically.
        let bare = chain::dissect_nwk(&frame[9..]).unwrap();
        assert_eq!(bare.nwk(), Some(n));
    }
}

#[test]
fn golden_empty_and_truncated_are_typed() {
    assert_eq!(chain::dissect(&[]), Err(tree::TreeError::Empty));
    assert_eq!(chain::dissect(&[0x41]), Err(tree::TreeError::Empty));
    assert_eq!(
        chain::dissect(&[0x41, 0x88]),
        Err(tree::TreeError::MacTruncated)
    );
    // MAC-only frame: chain stops with an `unknown` note, keeps MAC.
    let mac_only = [0x41u8, 0x88, 0x01, 0x61, 0x37, 0xff, 0xff, 0x34, 0x12];
    let tree = chain::dissect(&mac_only).unwrap();
    assert_eq!(tree.len(), 2);
    assert!(tree.nwk().is_none());
}

// ---------------------------------------------------------------------------
// pcap round-trip + session engine + reports.
// ---------------------------------------------------------------------------

#[test]
fn golden_pcap_write_read_dissect() {
    let frame = build_full_frame();
    let packets = vec![
        pcap::Packet {
            ts_us: 1_700_000_000_000_000,
            linktype: pcap::LINKTYPE_IEEE802_15_4,
            data: frame.clone(),
        },
        pcap::Packet {
            ts_us: 1_700_000_000_000_001,
            linktype: pcap::LINKTYPE_IEEE802_15_4,
            data: EMBER_U1.to_vec(),
        },
    ];
    let mut buf = Vec::new();
    pcap::write_pcap(&mut buf, pcap::LINKTYPE_IEEE802_15_4, &packets).unwrap();
    let back = pcap::read_all(&mut &buf[..]).unwrap();
    assert_eq!(back.len(), 2);
    assert_eq!(back[0].data, frame);
    assert_eq!(back[0].linktype, pcap::LINKTYPE_IEEE802_15_4);

    let t0 = chain::dissect(&back[0].data).unwrap();
    assert_eq!(t0.len(), 4);
    // Second packet is the captured Ember U1 frame: full MAC+NWK golden.
    let t1 = chain::dissect(&back[1].data).unwrap();
    assert_eq!(t1.len(), 3);
}

#[test]
fn golden_pcapng_ingest_minimal() {
    // Hand-built pcapng: SHB + IDB(195) + one EPB carrying the frame.
    let frame = build_full_frame();
    let mut buf = Vec::new();
    let shb_len = 28u32;
    buf.extend_from_slice(&0x0A0D0D0Au32.to_le_bytes());
    buf.extend_from_slice(&shb_len.to_le_bytes());
    buf.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(-1i64).to_le_bytes());
    buf.extend_from_slice(&shb_len.to_le_bytes());
    let idb_len = 20u32;
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&idb_len.to_le_bytes());
    buf.extend_from_slice(&195u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&262144u32.to_le_bytes());
    buf.extend_from_slice(&idb_len.to_le_bytes());
    let cap = frame.len();
    let pad = (4 - (cap % 4)) % 4;
    let epb_len = (32 + cap + pad) as u32;
    buf.extend_from_slice(&6u32.to_le_bytes());
    buf.extend_from_slice(&epb_len.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&1_700_000_000u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&(cap as u32).to_le_bytes());
    buf.extend_from_slice(&(cap as u32).to_le_bytes());
    buf.extend_from_slice(&frame);
    buf.extend(std::iter::repeat_n(0u8, pad));
    buf.extend_from_slice(&epb_len.to_le_bytes());

    let packets = pcap::read_all(&mut &buf[..]).unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].data, frame);
    assert_eq!(packets[0].linktype, 195);
    let tree = chain::dissect(&packets[0].data).unwrap();
    assert_eq!(tree.len(), 4);
}

struct Loopback {
    air: Vec<Vec<u8>>,
}

impl capture::Sender for Loopback {
    type Error = &'static str;
    fn send(&mut self, _channel: u8, frame: &[u8]) -> Result<(), Self::Error> {
        self.air.push(frame.to_vec());
        Ok(())
    }
}

#[test]
fn golden_sender_traits_and_session_engine() {
    let frame = build_full_frame();
    let mut lb = Loopback { air: Vec::new() };
    lb.send(25, &frame).unwrap();
    assert_eq!(lb.air.len(), 1);

    let mut eng = session::SessionEngine::new();
    let t0 = chain::dissect(&frame).unwrap();
    eng.note_tree(&t0);
    eng.note_tree(&t0);
    let dev = eng.device(0x1234).expect("src device tracked");
    assert_eq!(dev.frames, 2);
    assert_eq!(dev.last_seq, 0x5a);
    let net = eng.network(0x3761).expect("PAN tracked");
    assert_eq!(net.frames, 2);
    assert_eq!(eng.trees, 2);

    // Eviction is bounded: overfill devices (varying MAC src short at
    // octets 7..8), table stays capped.
    for i in 0..40u16 {
        let mut f = frame.clone();
        f[7] = (i & 0xff) as u8;
        f[8] = (i >> 8) as u8;
        let t = chain::dissect(&f).unwrap();
        eng.note_tree(&t);
    }
    assert!(eng.devices().len() <= session::MAX_DEVICES);

    let text = report::to_text(&t0);
    assert!(text.contains("mac:"));
    assert!(text.contains("nwk:"));
    assert!(text.contains("aps:"));
    assert!(text.contains("zcl:"));
    let json = report::to_json(&t0);
    assert!(json.contains("\"zcl\""));
    assert!(json.contains("\"layers\":["));
}

#[test]
fn golden_secured_report_names_stop() {
    let tree = chain::dissect(&EMBER_U1).unwrap();
    let text = report::to_text(&tree);
    assert!(text.contains("secured"));
    let json = report::to_json(&tree);
    assert!(json.contains("\"secured\":true"));
}
