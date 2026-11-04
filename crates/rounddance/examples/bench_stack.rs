//! Portable stack benchmark: per-operation cost of every layer,
//! measured with the host clock only — no criterion, no engine, no
//! network. Each iteration takes an index and returns a checksum the
//! harness folds, so no iteration's work can be hoisted or dropped
//! (constant inputs benchmark the void, not the code). Same file runs
//! natively and (given a clock) anywhere else; compare runs, not
//! absolutes, across machines.
//!
//! Run: `cargo run --release -p rounddance --example bench_stack`

use std::hint::black_box;
use std::time::Instant;

use rounddance::aps::{BindingDst, BindingEntry, BindingTable, MAX_BINDINGS};
use rounddance::commission::{
    BeaconSurveyEntry, ChannelMask, LinkEvidencePolicy, SteeringMachine, TouchlinkFrame,
};
use rounddance::compat::negotiate::{admit_30_peer, KeyPolicy};
use rounddance::compat::profile::{CompatPeer, BASELINE_SEC_LEVEL};
use rounddance::gp::frame::{FrameType as GpFrameType, GpdId, Gpdf, GpdfBody, NwkFrameControl};
use rounddance::hal_esp::mac_cmd::{build_beacon_req, parse_beacon_req};
use rounddance::ifc::envelope::{Envelope, Payload};
use rounddance::ifc::{ids, IFC_VERSION};
use rounddance::inspect::chain::dissect;
use rounddance::nwk::{
    accumulate_path_cost, FrameControl as NwkFc, LinkEstimator, NwkHeader, PathCostMetric,
    RouteTable, ROUTE_LIFETIME_MS,
};
use rounddance::rcp::frame::{encode as rcp_encode, Decoder as RcpDecoder};
use rounddance::security::{ccm_star_open_into, ccm_star_seal_into, ReplayTable, CCM_TAG_LEN};
use rounddance::zcl::frame::{Direction, FrameControl as ZclFc, FrameType as ZclFt, Header};
use rounddance::zdo::desc::{LogicalType, NodeDescriptor, NODE_DESCRIPTOR_LEN};

const ITERS: usize = 200_000;

fn bench(name: &str, iters: usize, mut f: impl FnMut(usize) -> u64) {
    let mut sink = 0u64;
    for i in 0..1_000 {
        sink = sink.wrapping_add(f(black_box(i)));
    }
    let t0 = Instant::now();
    for i in 0..iters {
        sink = sink.wrapping_add(f(black_box(i)));
    }
    let ns = t0.elapsed().as_nanos() as f64 / iters as f64;
    println!(
        "{name:28} {ns:10.1} ns/op {:10.0} ops/s checksum={sink:#018x}",
        1e9 / ns
    );
}

fn main() {
    println!("-- rounddance bench_stack ({ITERS} iters, host clock) --");

    bench("mac.beacon_req", ITERS, |i| {
        let mut b = [0u8; 8];
        let n = build_beacon_req(i as u8, &mut b).unwrap();
        let r = parse_beacon_req(&b[..n]).unwrap();
        black_box(r.seq) as u64 + n as u64
    });

    bench("nwk.header_roundtrip", ITERS, |i| {
        let h = NwkHeader::minimal(NwkFc::data(), 0x0001, 0x0000, 30, i as u8);
        let mut b = [0u8; 32];
        let n = h.encode_into(&[1, 2, 3, 4], &mut b).unwrap();
        let back = rounddance::nwk::decode(&b[..n]).unwrap();
        black_box(back.header.seq) as u64 + n as u64
    });

    bench("aps.bind_lookup", ITERS, |i| {
        let mut t = BindingTable::new();
        t.bind(BindingEntry {
            src_ieee: 1,
            src_endpoint: 1,
            cluster_id: i as u16,
            dst: BindingDst::Group { group_addr: 1 },
        });
        let mut out = [BindingDst::Group { group_addr: 0 }; MAX_BINDINGS];
        let n = t.lookup(1, 1, i as u16, &mut out);
        black_box(n) as u64 + t.len() as u64
    });

    bench("zdo.node_desc", ITERS, |i| {
        let d = NodeDescriptor {
            flags0: 0x02,
            aps_flags: 0,
            freq_band: 8,
            mac_cap: 0x8c,
            mfr_code: 0,
            max_buf: i as u8,
            max_in_transfer: 82,
            server_mask: 0,
            max_out_transfer: 82,
            desc_cap: 0,
        };
        let mut b = [0u8; NODE_DESCRIPTOR_LEN];
        let n = d.encode_into(&mut b).unwrap();
        let back = NodeDescriptor::decode(&b).unwrap();
        black_box(back.logical_type().unwrap() == LogicalType::Router) as u64 + n as u64
    });

    bench("sec.ccm_star", 5_000, |i| {
        let k = [0x10u8; 16];
        let mut nonce = [0x22u8; 13];
        nonce[0] = i as u8;
        let mut pt = [0x01u8; 8];
        pt[0] = i as u8;
        let mut sealed = [0u8; 20];
        let n = ccm_star_seal_into(&k, &nonce, &[8u8; 7], &pt, &mut sealed).unwrap();
        let (ct, tag) = sealed[..n].split_at(8);
        let mut t4 = [0u8; CCM_TAG_LEN];
        t4.copy_from_slice(tag);
        let mut open = [0u8; 8];
        let m = ccm_star_open_into(&k, &nonce, &[8u8; 7], ct, &t4, &mut open).unwrap();
        black_box(open[0]) as u64 + m as u64
    });

    bench("sec.replay_check", ITERS, |i| {
        let mut t = ReplayTable::<8>::new();
        t.check(7, 0x1000 + i as u32).unwrap();
        let dup = t.check(7, 0x1000 + i as u32).is_err();
        black_box(dup) as u64 + t.len() as u64
    });

    bench("zcl.header", ITERS, |i| {
        let h = Header {
            control: ZclFc {
                frame_type: ZclFt::Global,
                manufacturer_specific: false,
                direction: Direction::ToServer,
                disable_default_response: false,
            },
            manufacturer_code: None,
            tsn: i as u8,
            command_id: 0,
        };
        let mut b = [0u8; 8];
        let n = h.encode_into(&mut b).unwrap();
        let (back, rest) = Header::decode(&b[..n]).unwrap();
        black_box(rest.is_empty()) as u64 + back.tsn as u64 + n as u64
    });

    bench("gp.gpdf", ITERS, |i| {
        let f = Gpdf {
            fc: NwkFrameControl {
                frame_type: GpFrameType::Data,
                auto_commissioning: false,
                ext_present: false,
            },
            ext: None,
            id: Some(GpdId::SrcId(0x1234_5000 + i as u32)),
            frame_counter: None,
            body: GpdfBody::LpedOpaque(&[0x20, 0x01]),
            mic: None,
        };
        let mut b = [0u8; 16];
        let n = f.encode_into(&mut b).unwrap();
        let (back, used) = Gpdf::decode(buf_trunc(&b, n)).unwrap();
        black_box(matches!(back.id, Some(GpdId::SrcId(_)))) as u64 + used as u64
    });

    bench("commission.elect", 2_000, |i| {
        let mut sm = SteeringMachine::new();
        sm.begin_scan(ChannelMask::from_list(&[15]).unwrap(), 3)
            .unwrap();
        for _ in 0..16 {
            sm.ingest(BeaconSurveyEntry {
                pan_id: 0xc601,
                channel: 15,
                lqi: 200,
                rssi: -40 - (i % 8) as i8,
                permit_joining: true,
                router_capacity: true,
                end_device_capacity: true,
                protocol_version: 2,
            })
            .unwrap();
        }
        sm.finish_scan(&LinkEvidencePolicy::default());
        black_box(sm.candidate().unwrap().pan_id) as u64
    });

    bench("touchlink.frame", ITERS, |i| {
        let f = TouchlinkFrame::new(0x0102_0000 + i as u32, 0x00, &[1, 2]).unwrap();
        let mut b = [0u8; 16];
        let n = f.encode_into(&mut b).unwrap();
        let back = TouchlinkFrame::decode(buf_trunc(&b, n)).unwrap();
        black_box(back.transaction) as u64 + n as u64
    });

    bench("compat.admit_30", ITERS, |i| {
        let peer = CompatPeer::profile_30();
        let (m, level) = admit_30_peer(
            &peer,
            i % 2 == 0,
            &KeyPolicy::ALLOW_SYMMETRIC,
            BASELINE_SEC_LEVEL,
        )
        .unwrap();
        black_box(m) as u64 + level as u64
    });

    bench("route.install_lookup", 5_000, |i| {
        let mut t = RouteTable::new();
        let mut sum = 0u64;
        for k in 0..16u16 {
            let _ = t.install(
                0x1000 + (i as u16).wrapping_add(k),
                0x0002,
                1 + (i % 7) as u8,
                0,
                ROUTE_LIFETIME_MS,
            );
        }
        sum += t.next_hop(0x1000 + (i % 16) as u16, 1).unwrap_or(0) as u64;
        sum += t.expire(ROUTE_LIFETIME_MS + 1) as u64;
        black_box(sum)
    });

    bench("route.estimator", ITERS, |i| {
        let mut e = LinkEstimator::new();
        e.note_result((i % 4) as u16, true);
        e.note_result((i % 4) as u16, i % 3 != 0);
        let c = e.cost((i % 4) as u16).unwrap_or(0);
        black_box(c) as u64
            + black_box(accumulate_path_cost(PathCostMetric::Bottleneck, 3, 5)) as u64
    });

    bench("rcp.encode_decode", ITERS, |i| {
        let mut wire = [0u8; 16];
        let n = rcp_encode(0x09, i as u8, &[i as u8], &mut wire).unwrap();
        let mut d = RcpDecoder::new();
        let mut got = 0u64;
        for b in &wire[..n] {
            if d.push_byte(*b).is_some() {
                got += 1;
            }
        }
        black_box(got) + n as u64
    });

    bench("ifc.envelope", ITERS, |i| {
        let e = Envelope {
            version: IFC_VERSION,
            if_id: ids::IF_NWK,
            op: 1,
            seq: i as u16,
            flags: 1,
            payload: Payload::from_slice(&[0xaa, 0xbb]).unwrap(),
        };
        let mut b = [0u8; 64];
        let n = e.encode(&mut b).unwrap();
        let back = Envelope::decode(buf_trunc(&b, n)).unwrap();
        black_box(back.seq) as u64 + n as u64
    });

    bench("inspect.beacon", 2_000, |i| {
        let mut frame = BEACON;
        frame[2] = i as u8;
        let tree = dissect(&frame).unwrap();
        black_box(std::mem::size_of_val(&tree) + i) as u64
    });

    println!("-- done --");
}

fn buf_trunc(b: &[u8], n: usize) -> &[u8] {
    &b[..n]
}

const BEACON: [u8; 26] = [
    0x00, 0x80, 0x00, 0x01, 0xc6, 0x00, 0x00, 0xff, 0xcf, 0x00, 0x00, 0x00, 0x22, 0x8c, 0x43, 0x36,
    0x4a, 0x4f, 0x49, 0x4e, 0x30, 0x31, 0xff, 0xff, 0xff, 0x00,
];
