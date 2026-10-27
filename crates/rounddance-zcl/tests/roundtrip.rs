//! Property tests: ZCL codec round-trip identity plus malformed-input
//! rejection. Hand-rolled bounded deterministic fuzz — a `SplitMix64`
//! stream driving a fixed case budget (same construction as the
//! NWK/APS/ZDO fuzz). No panics on any input: every decode returns
//! `Ok` or `Err`.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `07-5123-08-2411-*` (header round-trips),
//! `07-5123-08-262-*` (value round-trips),
//! `07-5123-08-25-*` (general-command round-trips),
//! `07-5123-08-232-01` (malformed rejection).

use rounddance_zcl::behavior::{AppEvent, EventQueue};
use rounddance_zcl::cluster::ClusterDef;
use rounddance_zcl::*;
use rounddance_zcl::{general, ias_zone, level, onoff};

/// Case budget: covers the field cross-product several times over.
const CASES: u32 = 8_000;

struct Fuzz(u64);

impl Fuzz {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.next() % n
    }

    fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let v = self.next();
            let mut k = 0;
            while k < 8 && i + k < buf.len() {
                buf[i + k] = (v >> (8 * k)) as u8;
                k += 1;
            }
            i += 8;
        }
    }
}

fn arb_value(f: &mut Fuzz) -> Value {
    match f.below(14) {
        0 => Value::Bool(f.below(2) == 1),
        1 => Value::UInt {
            width: 1,
            v: f.below(256),
        },
        2 => Value::UInt {
            width: 2,
            v: f.below(65536),
        },
        3 => Value::UInt {
            width: 4,
            v: f.next() & 0xffff_ffff,
        },
        4 => Value::Int {
            width: 1,
            v: (f.below(256) as i64) - 128,
        },
        5 => Value::Int {
            width: 2,
            v: (f.below(65536) as i64) - 32768,
        },
        6 => Value::Enum8(f.below(256) as u8),
        7 => Value::Enum16(f.below(65536) as u16),
        8 => Value::Map {
            width: 2,
            bytes: {
                let mut b = [0u8; 8];
                b[0] = f.below(256) as u8;
                b[1] = f.below(256) as u8;
                b
            },
        },
        9 => {
            let len = f.below(9) as u8;
            let mut bytes = [0u8; MAX_STR_LEN];
            let mut i = 0;
            while i < len as usize {
                bytes[i] = 0x20 + f.below(95) as u8;
                i += 1;
            }
            Value::CharStr { len, bytes }
        }
        10 => Value::Single((f.next() & 0xffff_ffff) as u32),
        11 => Value::Eui64({
            let mut b = [0u8; 8];
            let v = f.next();
            b.copy_from_slice(&v.to_le_bytes());
            b
        }),
        12 => Value::Time {
            tag: 0xe2,
            v: (f.next() & 0xffff_ffff) as u32,
        },
        _ => {
            // Canonical arrays zero the tail past count*each so the
            // decoded value compares equal.
            let count = f.below(5) as u8;
            let mut bytes = [0u8; MAX_ARRAY_BYTES];
            let mut i = 0;
            while i < count as usize {
                bytes[i] = f.below(256) as u8;
                i += 1;
            }
            Value::Array {
                elem: 0x20,
                count,
                bytes,
            }
        }
    }
}

// 07-5123-08-2411-*: header encode/decode identity over the flag
// cross-product, plus rejection of reserved frame types.
#[test]
fn fuzz_header_roundtrip() {
    let mut f = Fuzz(0x21c0_0001);
    let mut out = [0u8; 8];
    let mut i = 0;
    while i < CASES {
        let ft = if f.below(2) == 0 {
            FrameType::Global
        } else {
            FrameType::ClusterSpecific
        };
        let h = Header {
            control: FrameControl {
                frame_type: ft,
                manufacturer_specific: f.below(2) == 1,
                direction: if f.below(2) == 1 {
                    Direction::ToClient
                } else {
                    Direction::ToServer
                },
                disable_default_response: f.below(2) == 1,
            },
            manufacturer_code: if f.below(2) == 1 {
                Some(f.below(65536) as u16)
            } else {
                None
            },
            tsn: f.below(256) as u8,
            command_id: f.below(256) as u8,
        };
        // Repair flag/code agreement half the time at random; the
        // other half must fail (presence rule).
        let mut h = h;
        if f.below(2) == 0 {
            h.manufacturer_code = if h.control.manufacturer_specific {
                h.manufacturer_code
            } else {
                None
            };
            if h.control.manufacturer_specific && h.manufacturer_code.is_none() {
                h.manufacturer_code = Some(0);
            }
        }
        match h.encode_into(&mut out) {
            Ok(n) => {
                let (back, rest) = Header::decode(&out[..n]).unwrap();
                assert_eq!(back, h);
                assert!(rest.is_empty());
            }
            Err(_) => {
                assert_ne!(
                    h.control.manufacturer_specific,
                    h.manufacturer_code.is_some()
                );
            }
        }
        i += 1;
    }
    // Reserved frame types rejected on every high-bit pattern.
    for b in [0x02u8, 0x03, 0xe2, 0xff] {
        assert!(Header::decode(&[b, 0x00, 0x00]).is_err());
    }
}

// 07-5123-08-262-*: value encode/decode identity across the scalar +
// string + array population.
#[test]
fn fuzz_value_roundtrip() {
    let mut f = Fuzz(0x21c0_0002);
    let mut out = [0u8; 64];
    let mut i = 0;
    while i < CASES {
        let v = arb_value(&mut f);
        let n = v.encode_into(&mut out).unwrap();
        let (back, used) = Value::decode(v.datatype(), &out[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(back, v);
        i += 1;
    }
}

// 07-5123-08-25-*: general-command payload identity.
#[test]
fn fuzz_general_command_roundtrip() {
    let mut f = Fuzz(0x21c0_0003);
    let mut out = [0u8; 256];
    let mut i = 0;
    while i < CASES {
        match f.below(6) {
            0 => {
                // Read request id lists.
                let n_ids = 1 + f.below(8) as usize;
                let mut ids = [0u16; 8];
                let mut k = 0;
                while k < n_ids {
                    ids[k] = f.below(65536) as u16;
                    k += 1;
                }
                let n = general::encode_id_list(&ids[..n_ids], &mut out).unwrap();
                let mut back = [0u16; 8];
                assert_eq!(
                    general::decode_id_list(&out[..n], &mut back).unwrap(),
                    n_ids
                );
                assert_eq!(&back[..n_ids], &ids[..n_ids]);
            }
            1 => {
                // Report records.
                let n_recs = 1 + f.below(4) as usize;
                let mut recs = [general::ReportRecord {
                    id: 0,
                    dtype: 0,
                    value: Value::NoData,
                }; 4];
                let mut k = 0;
                while k < n_recs {
                    let v = arb_value(&mut f);
                    recs[k] = general::ReportRecord {
                        id: f.below(65536) as u16,
                        dtype: v.datatype().as_u8(),
                        value: v,
                    };
                    k += 1;
                }
                let n = general::encode_report(&recs[..n_recs], &mut out).unwrap();
                let mut back = [general::ReportRecord {
                    id: 0,
                    dtype: 0,
                    value: Value::NoData,
                }; 4];
                assert_eq!(
                    general::decode_report(&out[..n], &mut back).unwrap(),
                    n_recs
                );
                assert_eq!(&back[..n_recs], &recs[..n_recs]);
            }
            2 => {
                // Write records.
                let v = arb_value(&mut f);
                let rec = [general::WriteRecord {
                    id: f.below(65536) as u16,
                    dtype: v.datatype().as_u8(),
                    value: v,
                }];
                let mut tmp = [0u8; 64];
                // Hand-encode: id + dtype + body.
                tmp[..2].copy_from_slice(&rec[0].id.to_le_bytes());
                tmp[2] = rec[0].dtype;
                let bn = v.encode_into(&mut tmp[3..]).unwrap();
                let mut back = [general::WriteRecord {
                    id: 0,
                    dtype: 0,
                    value: Value::NoData,
                }; 2];
                assert_eq!(general::decode_write(&tmp[..3 + bn], &mut back).unwrap(), 1);
                assert_eq!(back[0], rec[0]);
            }
            3 => {
                // Discover attributes responses.
                let n_recs = f.below(5) as usize;
                let mut recs = [(0u16, 0u8); 5];
                let mut last = 0u16;
                let mut k = 0;
                while k < n_recs {
                    last = last.wrapping_add(1 + f.below(16) as u16);
                    recs[k] = (last, 0x20 + f.below(8) as u8);
                    k += 1;
                }
                let complete = f.below(2) == 1;
                let n = general::encode_discover_attrs_rsp(&recs[..n_recs], complete, &mut out)
                    .unwrap();
                let mut back = [(0u16, 0u8); 5];
                assert_eq!(
                    general::decode_discover_attrs_rsp(&out[..n], &mut back).unwrap(),
                    (complete, n_recs)
                );
                assert_eq!(&back[..n_recs], &recs[..n_recs]);
            }
            4 => {
                // Default responses.
                let rsp = general::DefaultRsp {
                    cmd: f.below(256) as u8,
                    status: ZclStatus::from_u8(f.below(256) as u8),
                };
                let n = rsp.encode_into(&mut out).unwrap();
                assert_eq!(general::DefaultRsp::decode(&out[..n]).unwrap().cmd, rsp.cmd);
                assert_eq!(
                    general::DefaultRsp::decode(&out[..n])
                        .unwrap()
                        .status
                        .as_u8(),
                    rsp.status.as_u8()
                );
            }
            _ => {
                // On/Off + Level + IAS client frames parse as headers.
                let mut frame = [0u8; 16];
                let n = match f.below(3) {
                    0 => onoff::client::toggle(f.below(256) as u8, &mut frame).unwrap(),
                    1 => level::client::move_to_level(
                        f.below(256) as u8,
                        false,
                        f.below(256) as u8,
                        f.below(65536) as u16,
                        None,
                        &mut frame,
                    )
                    .unwrap(),
                    _ => ias_zone::cie::enroll_response(
                        f.below(256) as u8,
                        0x00,
                        f.below(256) as u8,
                        &mut frame,
                    )
                    .unwrap(),
                };
                let (h, _) = Header::decode(&frame[..n]).unwrap();
                assert_eq!(h.tsn, frame[1]);
            }
        }
        i += 1;
    }
}

// 07-5123-08-232-01 + 251-02/253-01: malformed wire is rejected with
// typed errors, never panics — random garbage across every decoder.
#[test]
fn fuzz_malformed_rejection_no_panic() {
    let mut f = Fuzz(0x21c0_0004);
    let mut buf = [0u8; 40];
    let mut records: [general::ReportRecord; 4] = [general::ReportRecord {
        id: 0,
        dtype: 0,
        value: Value::NoData,
    }; 4];
    let mut i = 0;
    while i < CASES {
        let len = f.below(41) as usize;
        f.fill(&mut buf[..len.max(1)]);
        let len = len.min(40);
        let body = &buf[..len];
        let _ = Header::decode(body);
        let _ = general::decode_id_list(body, &mut [0u16; 4]);
        let _ = general::decode_report(body, &mut records);
        let mut wrecs = [general::WriteRecord {
            id: 0,
            dtype: 0,
            value: Value::NoData,
        }; 4];
        let _ = general::decode_write(body, &mut wrecs);
        let mut crecs = [general::ReportCfgRecord {
            direction: 0,
            id: 0,
            dtype: 0,
            min: 0,
            max: 0,
            change: None,
            timeout: 0,
        }; 4];
        let _ = general::decode_config_report(body, &mut crecs);
        let _ = general::DefaultRsp::decode(body);
        let _ = general::DiscoverAttrs::decode(body);
        let _ = general::DiscoverCmds::decode(body);
        for tag in [0x10u8, 0x20, 0x21, 0x28, 0x30, 0x31, 0x42, 0x48, 0xf0] {
            if let Ok(t) = DataType::from_u8(tag) {
                let _ = Value::decode(t, body);
            }
        }
        i += 1;
    }
}

// Cluster behaviors over the fuzzed command space: no panics, total
// over unknown commands (UnsupCommand) and malformed bodies
// (MalformedCommand/InvalidField/InvalidValue).
#[test]
fn fuzz_behaviors_total_no_panic() {
    let mut f = Fuzz(0x21c0_0005);
    let mut ostore = onoff::server_store().unwrap();
    let mut lstore = level::server_store().unwrap();
    let mut istore = ias_zone::server_store(0x000d).unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut obeh = onoff::ServerBehavior;
    let mut lbeh = level::ServerBehavior::new();
    let mut ibeh = ias_zone::ServerBehavior::new();
    let mut body = [0u8; 12];
    let mut i = 0;
    while i < CASES {
        let len = f.below(13) as usize;
        f.fill(&mut body[..len.max(1)]);
        let cmd = f.below(256) as u8;
        let hdr = Header {
            control: FrameControl {
                frame_type: FrameType::ClusterSpecific,
                manufacturer_specific: false,
                direction: Direction::ToServer,
                disable_default_response: false,
            },
            manufacturer_code: None,
            tsn: 0x01,
            command_id: cmd,
        };
        let peer = if f.below(2) == 1 {
            Some(f.below(2) == 1)
        } else {
            None
        };
        let mut ctx = Ctx {
            store: &mut ostore,
            reporting: &mut eng,
            events: &mut events,
            now_s: f.next(),
            peer_onoff: peer,
            sender_ieee: None,
        };
        let _ = obeh.handle_cluster_command(&mut ctx, &hdr, cmd, &body[..len]);
        let mut ctx = Ctx {
            store: &mut lstore,
            reporting: &mut eng,
            events: &mut events,
            now_s: 0,
            peer_onoff: peer,
            sender_ieee: None,
        };
        let _ = lbeh.handle_cluster_command(&mut ctx, &hdr, cmd, &body[..len]);
        let _ = lbeh.take_onoff_request();
        let mut ctx = Ctx {
            store: &mut istore,
            reporting: &mut eng,
            events: &mut events,
            now_s: 0,
            peer_onoff: None,
            sender_ieee: None,
        };
        let _ = ibeh.handle_cluster_command(&mut ctx, &hdr, cmd, &body[..len]);
        // Stores stay well-formed: globals readable after any battering.
        assert!(ostore.get(ATTR_CLUSTER_REVISION).is_some());
        assert!(lstore.get(ATTR_CLUSTER_REVISION).is_some());
        assert!(istore.get(ATTR_CLUSTER_REVISION).is_some());
        // Event queue drains (bounds the backlog across the run).
        while events.pop().is_some() {}
        i += 1;
    }
    // Definitions keep their contract after the storm.
    let odef = onoff::ServerDef;
    assert_eq!(odef.cluster_id(), 0x0006);
    let ldef = level::ServerDef;
    assert_eq!(ldef.cluster_id(), 0x0008);
    let idef = ias_zone::ServerDef;
    assert_eq!(idef.cluster_id(), 0x0500);
    let _ = AppEvent::StateChanged {
        cluster: 0,
        from: 0,
        to: 0,
    };
}
