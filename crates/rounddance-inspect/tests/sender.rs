//! Wave-58 lane 2 (RD-INSPECT-38): sender path.
//!
//! The `Sender` trait exists but no implementation does: frames can
//! be listened to but never crafted + transmitted. These tests are
//! the failing-first repros: a loopback/mock sender plus
//! encode→decode round trips verified decision-for-decision against
//! the dissector, with a pcap-out writer so crafted frames stay
//! Wireshark-inspectable.

use rounddance_inspect::capture::{Listener, Sender};
use rounddance_inspect::{chain, pcap, sender};

// ---------------------------------------------------------------------------
// Builders (repo codecs + hand-assembled MAC, no captures needed).
// ---------------------------------------------------------------------------

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Full MAC+NWK+APS+ZCL data frame (short->short, PAN 0x3761).
fn wrap_full_frame(
    zcl: &[u8],
    cluster_id: u16,
    profile_id: u16,
    nwk_seq: u8,
    aps_ctr: u8,
    src: u16,
    dst: u16,
) -> Vec<u8> {
    let aps = rounddance_aps::frame::DataHeader {
        control: rounddance_aps::frame::FrameControl::data(
            rounddance_aps::frame::DeliveryMode::Unicast,
        ),
        dest: rounddance_aps::frame::DataDest::Unicast { dst_endpoint: 1 },
        cluster_id,
        profile_id,
        src_endpoint: 1,
        counter: aps_ctr,
        ext: None,
    };
    let mut aps_buf = [0u8; 256];
    let an = aps.encode_into(zcl, &mut aps_buf).unwrap();

    let nwk = rounddance_nwk::frame::NwkHeader::minimal(
        rounddance_nwk::frame::FrameControl::data(),
        dst,
        src,
        30,
        nwk_seq,
    );
    let mut nwk_buf = [0u8; 320];
    let nn = nwk.encode_into(&aps_buf[..an], &mut nwk_buf).unwrap();

    let mut frame = vec![0x41, 0x88, 0x5a];
    frame.extend_from_slice(&0x3761u16.to_le_bytes());
    frame.extend_from_slice(&dst.to_le_bytes());
    frame.extend_from_slice(&src.to_le_bytes());
    frame.extend_from_slice(&nwk_buf[..nn]);
    frame
}

fn zcl_read(tsn: u8) -> Vec<u8> {
    let h = rounddance_zcl::frame::Header {
        control: rounddance_zcl::frame::FrameControl {
            frame_type: rounddance_zcl::frame::FrameType::Global,
            manufacturer_specific: false,
            direction: rounddance_zcl::frame::Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn,
        command_id: rounddance_zcl::general::cmd::READ,
    };
    let mut buf = [0u8; 64];
    let n = h.encode_into(&mut buf).unwrap();
    let mut out = buf[..n].to_vec();
    out.extend_from_slice(&0x0000u16.to_le_bytes());
    out
}

/// Send one frame through the loopback and dissect what comes back.
fn roundtrip(channel: u8, frame: &[u8]) -> rounddance_inspect::tree::DecodeTree {
    let mut lb = sender::LoopbackSender::new();
    lb.send(channel, frame).unwrap();
    let mut buf = [0u8; 256];
    let got = lb.next_frame(&mut buf).unwrap().expect("frame back");
    assert_eq!(got.channel, channel);
    assert_eq!(got.payload, frame);
    chain::dissect(got.payload).unwrap()
}

// ---------------------------------------------------------------------------
// RD-INSPECT-38 repro: no sender implementation exists.
// ---------------------------------------------------------------------------

#[test]
fn repro_no_loopback_sender() {
    let frame = wrap_full_frame(&zcl_read(0x42), 0x0006, 0x0104, 0x09, 0x07, 0x1234, 0x5678);
    let direct = chain::dissect(&frame).unwrap();
    let back = roundtrip(25, &frame);
    // Decision-for-decision: the transmitted frame dissects exactly
    // as the crafted one (same legs, same stops).
    assert_eq!(back, direct);
    assert!(back.zcl().is_some());
}

#[test]
fn roundtrip_names_every_leg_class() {
    // (frame bytes, channel, leg predicate name)
    let leave_nwk = {
        let nwk = rounddance_nwk::frame::NwkHeader::minimal(
            rounddance_nwk::frame::FrameControl::command(),
            0x0000,
            0x1234,
            1,
            0x44,
        );
        let mut nwk_buf = [0u8; 128];
        let nn = nwk.encode_into(&[0x04, 0x00], &mut nwk_buf).unwrap();
        let mut f = vec![0x41, 0x88, 0x60];
        f.extend_from_slice(&0x3761u16.to_le_bytes());
        f.extend_from_slice(&0x0000u16.to_le_bytes());
        f.extend_from_slice(&0x1234u16.to_le_bytes());
        f.extend_from_slice(&nwk_buf[..nn]);
        f
    };
    let transport_aps = {
        let hdr = rounddance_aps::frame::CommandHeader {
            control: rounddance_aps::frame::FrameControl::command(),
            counter: 0x3d,
            command_id: 0x05,
        };
        let mut aps_buf = [0u8; 64];
        let an = hdr.encode_into(&[0x01], &mut aps_buf).unwrap();
        let nwk = rounddance_nwk::frame::NwkHeader::minimal(
            rounddance_nwk::frame::FrameControl::data(),
            0x0000,
            0x1234,
            30,
            0x09,
        );
        let mut nwk_buf = [0u8; 320];
        let nn = nwk.encode_into(&aps_buf[..an], &mut nwk_buf).unwrap();
        let mut f = vec![0x41, 0x88, 0x5a];
        f.extend_from_slice(&0x3761u16.to_le_bytes());
        f.extend_from_slice(&0x0000u16.to_le_bytes());
        f.extend_from_slice(&0x1234u16.to_le_bytes());
        f.extend_from_slice(&nwk_buf[..nn]);
        f
    };
    let mut annce_body = vec![0x09u8];
    annce_body.extend_from_slice(&0x1122334455667788u64.to_le_bytes());
    annce_body.extend_from_slice(&0x1234u16.to_le_bytes());

    // Verbatim live-air MAC + Touchlink shapes (ciphertext-free protocol
    // bytes, same class as the committed Ember vectors).
    let cases: &[(&str, Vec<u8>, u8)] = &[
        (
            "zcl-data",
            wrap_full_frame(&zcl_read(0x42), 0x0006, 0x0104, 0x09, 0x07, 0x1234, 0x5678),
            25,
        ),
        (
            "zdo-annce",
            wrap_full_frame(&annce_body, 0x0013, 0x0000, 0x0a, 0x08, 0x1234, 0xfffd),
            25,
        ),
        ("nwk-leave", leave_nwk, 20),
        ("aps-transport", transport_aps, 25),
        ("mac-beacon-req", hex("030816ffffffff07"), 11),
        (
            "mac-assoc-req",
            hex("23c84261370000ffffa0f262fffefffe85018c"),
            11,
        ),
        (
            "touchlink-scan-req",
            hex("018800ffffffffffff687f1421aa3e000583"),
            20,
        ),
    ];
    for (name, frame, channel) in cases {
        let direct = chain::dissect(frame).unwrap();
        let back = roundtrip(*channel, frame);
        assert_eq!(back, direct, "leg {name}");
    }
    // Spot-check the legs the round trip must name.
    let t = roundtrip(
        25,
        &wrap_full_frame(&zcl_read(0x42), 0x0006, 0x0104, 0x09, 0x07, 0x1234, 0x5678),
    );
    assert!(t.zcl().is_some());
    let t = roundtrip(20, &hex("018800ffffffffffff687f1421aa3e000583"));
    assert!(t.touchlink().is_some());
}

#[test]
fn loopback_fifo_order_and_bounds() {
    let mut lb = sender::LoopbackSender::new();
    let a = wrap_full_frame(&zcl_read(0x01), 0x0006, 0x0104, 0x01, 0x01, 0x1111, 0x0000);
    let b = wrap_full_frame(&zcl_read(0x02), 0x0006, 0x0104, 0x02, 0x02, 0x2222, 0x0000);
    lb.send(11, &a).unwrap();
    lb.send(26, &b).unwrap();
    assert_eq!(lb.pending(), 2);

    let mut buf = [0u8; 256];
    let first = lb.next_frame(&mut buf).unwrap().expect("first");
    assert_eq!(first.channel, 11);
    assert_eq!(first.payload, a.as_slice());
    let second = lb.next_frame(&mut buf).unwrap().expect("second");
    assert_eq!(second.channel, 26);
    assert_eq!(second.payload, b.as_slice());
    assert!(lb.next_frame(&mut buf).unwrap().is_none());

    // Oversize frames never enter the queue.
    let big = [0xabu8; 300];
    assert_eq!(lb.send(11, &big), Err(sender::LoopbackError::TooLong));

    // A receive buffer smaller than the queued frame is a typed
    // error, and the frame stays queued.
    lb.send(11, &a).unwrap();
    let mut small = [0u8; 8];
    assert_eq!(
        lb.next_frame(&mut small),
        Err(sender::LoopbackError::SmallBuffer)
    );
    assert_eq!(lb.pending(), 1);

    // A full queue refuses with a saturating drop count.
    for _ in 0..sender::LOOPBACK_CAPACITY {
        let _ = lb.send(11, &a);
    }
    assert_eq!(lb.send(11, &a), Err(sender::LoopbackError::Full));
    assert!(lb.drops() >= 1);
}

#[test]
fn pcap_out_roundtrip_is_wireshark_readable() {
    let frames: Vec<(u8, Vec<u8>)> = vec![
        (
            25,
            wrap_full_frame(&zcl_read(0x42), 0x0006, 0x0104, 0x09, 0x07, 0x1234, 0x5678),
        ),
        (20, hex("018800ffffffffffff687f1421aa3e000583")),
        (11, hex("030816ffffffff07")),
    ];
    let mut lb = sender::LoopbackSender::new();
    for (ch, f) in &frames {
        lb.send(*ch, f).unwrap();
    }
    // Drain the loopback into pcap packets (one per sent frame).
    let mut buf = [0u8; 256];
    let mut packets = Vec::new();
    let mut ts = 1_700_000_000_000_000u64;
    while let Some(got) = lb.next_frame(&mut buf).unwrap() {
        packets.push(pcap::Packet {
            ts_us: ts,
            linktype: pcap::LINKTYPE_IEEE802_15_4,
            data: got.payload.to_vec(),
        });
        ts += 1_000;
    }
    let mut pcap_bytes = Vec::new();
    pcap::write_pcap(&mut pcap_bytes, pcap::LINKTYPE_IEEE802_15_4, &packets).unwrap();
    // The recording re-ingests byte-identically and every packet
    // dissects to the same decision as the crafted frame.
    let back = pcap::read_all(&mut &pcap_bytes[..]).unwrap();
    assert_eq!(back.len(), frames.len());
    for ((ch, frame), pkt) in frames.iter().zip(back.iter()) {
        assert_eq!(&pkt.data, frame, "channel {ch}");
        assert_eq!(pkt.linktype, pcap::LINKTYPE_IEEE802_15_4);
        let (direct, replayed) = (
            chain::dissect(frame).unwrap(),
            chain::dissect(&pkt.data).unwrap(),
        );
        assert_eq!(replayed, direct, "channel {ch}");
    }
}
