//! Property tests: codec round-trips plus table/queue operation
//! fuzzing. Hand-rolled bounded deterministic fuzz — a `SplitMix64`
//! stream driving a fixed case budget (same construction as the
//! NWK/APS/ZDO/commissioning fuzz). No panics on any input: every
//! decode returns `Ok` or `Err`, every machine event is accepted or
//! rejected without panicking.
//!
//! Requirement traceability: `14-0563-19-A141-*` (codec rejection),
//! `14-0563-19-A36-02` (table lifecycle), `14-0563-19-A36-07`
//! (translation matching), `14-0563-19-A152-01` (queue bounds).

use rounddance_gp::*;

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
}

#[test]
fn fuzz_decode_never_panics() {
    let mut rng = Fuzz(0x6A0D);
    let mut buf = [0u8; MAX_GPDF + 8];
    for _ in 0..CASES {
        let len = rng.below(buf.len() as u64) as usize;
        for slot in buf[..len].iter_mut() {
            *slot = rng.below(0x100) as u8;
        }
        let _ = Gpdf::decode(&buf[..len]);
    }
}

#[test]
fn fuzz_frame_round_trip() {
    let mut rng = Fuzz(0x9A11);
    let mut buf = [0u8; MAX_GPDF];
    for _ in 0..CASES {
        let app = match rng.below(3) {
            0 => AppId::SrcId,
            1 => AppId::Ieee,
            _ => AppId::Lped,
        };
        let fc_byte = match rng.below(2) {
            0 => NwkFrameControl {
                frame_type: FrameType::Data,
                auto_commissioning: rng.below(2) == 0,
                ext_present: true,
            }
            .encode(),
            _ => NwkFrameControl {
                frame_type: FrameType::Maintenance,
                auto_commissioning: false,
                ext_present: false,
            }
            .encode(),
        };
        let fc = NwkFrameControl::decode(fc_byte).unwrap();
        let is_maint = matches!(fc.frame_type, FrameType::Maintenance);
        let ext = if is_maint {
            None
        } else {
            Some(ExtFrameControl {
                app_id: app,
                level: match rng.below(3) {
                    0 => WireSecurityLevel::None,
                    1 => WireSecurityLevel::MicOnly,
                    _ => WireSecurityLevel::Encrypted,
                },
                key_bit: rng.below(2) == 0,
                rx_after_tx: false,
                direction_proxy: false,
            })
        };
        if matches!(app, AppId::Lped) && !is_maint {
            // LPED bodies stay opaque: random trailer bytes. The
            // extension records recognition only (level None), since
            // LPED redefines bits 3–7.
            let raw_len = rng.below(17) as usize;
            let mut raw = [0u8; 16];
            for slot in raw[..raw_len].iter_mut() {
                *slot = rng.below(0x100) as u8;
            }
            let lped_ext = ext.map(|mut e| {
                e.level = WireSecurityLevel::None;
                e.key_bit = false;
                e.rx_after_tx = false;
                e.direction_proxy = false;
                e
            });
            let frame = Gpdf {
                fc,
                ext: lped_ext,
                id: None,
                frame_counter: None,
                body: GpdfBody::LpedOpaque(&raw[..raw_len]),
                mic: None,
            };
            let n = frame.encode_into(&mut buf).unwrap();
            let (back, used) = Gpdf::decode(&buf[..n]).unwrap();
            assert_eq!(used, n);
            assert_eq!(back, frame);
            continue;
        }
        if is_maint {
            let frame = Gpdf {
                fc,
                ext: None,
                id: None,
                frame_counter: None,
                body: GpdfBody::Gp {
                    command: rng.below(0xF0) as u8,
                    payload: &[],
                },
                mic: None,
            };
            let n = frame.encode_into(&mut buf).unwrap();
            let (back, used) = Gpdf::decode(&buf[..n]).unwrap();
            assert_eq!(used, n);
            assert_eq!(back, frame);
            continue;
        }
        let e = ext.unwrap();
        let id = match app {
            AppId::SrcId => {
                let mut id = (rng.next() & 0xFFFF_FFF8) as u32;
                if id == 0 {
                    id = 1;
                }
                GpdId::SrcId(id)
            }
            AppId::Ieee => {
                let mut addr = [0u8; 8];
                for slot in addr.iter_mut() {
                    *slot = rng.below(0x100) as u8;
                }
                if addr == [0u8; 8] {
                    addr[0] = 1;
                }
                GpdId::Ieee {
                    addr,
                    endpoint: rng.below(0x100) as u8,
                }
            }
            AppId::Lped => unreachable!(),
        };
        let protected = e.level.protected();
        let counter = protected.then(|| rng.next() as u32);
        let mic = protected.then_some([
            rng.below(0x100) as u8,
            rng.below(0x100) as u8,
            rng.below(0x100) as u8,
            rng.below(0x100) as u8,
        ]);
        let payload_len = rng.below(9) as usize;
        let mut payload = [0u8; 8];
        for slot in payload[..payload_len].iter_mut() {
            *slot = rng.below(0x100) as u8;
        }
        let command = if e.level == WireSecurityLevel::None {
            // Keep cleartext commands out of the commissioning range
            // so ingress stays well-formed.
            rng.below(0xF0) as u8
        } else {
            rng.below(0x100) as u8
        };
        // Leak the payload through a scratch copy so the borrowed
        // frame owns nothing.
        let owned = payload;
        let frame = Gpdf {
            fc,
            ext: Some(e),
            id: Some(id),
            frame_counter: counter,
            body: GpdfBody::Gp {
                command,
                payload: &owned[..payload_len],
            },
            mic,
        };
        let n = frame.encode_into(&mut buf).unwrap();
        let (back, used) = Gpdf::decode(&buf[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(back, frame);
        let _ = frame.ingress_check();
    }
}

#[test]
fn fuzz_table_ops_never_panic() {
    let mut rng = Fuzz(0x7AB1);
    let mut table = ProxyTable::<4>::new();
    let mut translations = TranslationTable::<4>::new();
    let mut sinks = SinkTable::<4>::new();
    let mut queue = GpTxQueue::<2>::new();
    for _ in 0..CASES {
        let id = rng.next();
        let app = if rng.below(2) == 0 {
            AppId::SrcId
        } else {
            AppId::Ieee
        };
        let mut entry = ProxyTableEntry::new(app, id);
        entry.endpoint = rng.below(0x100) as u8;
        entry.level = if rng.below(2) == 0 {
            WireSecurityLevel::None
        } else {
            WireSecurityLevel::MicOnly
        };
        let _ = table.upsert(entry);
        let gid = if app == AppId::SrcId {
            GpdId::SrcId((id & 0xFFFF_FFF8).max(1) as u32)
        } else {
            let addr = id.to_le_bytes();
            GpdId::Ieee {
                addr,
                endpoint: entry.endpoint,
            }
        };
        let _ = table.find(gid);
        let _ = table.find_mut(gid);
        let _ = table.pair_remove(id, 0xFF, rng.below(2) == 0);
        let t = TranslationSeed {
            app,
            gpd: id,
            endpoint: entry.endpoint,
            gpd_command: rng.below(0x100) as u8,
            profile: 0x0104,
            cluster: 0x0006,
            command: 0x01,
        }
        .materialize();
        let _ = translations.upsert(t);
        let _ = translations.lookup(gid, 0x20, 0);
        let _ = translations.remove(id, entry.endpoint, 0x20);
        let _ = sinks.upsert(SinkTableEntry::new(app, id));
        let _ = sinks.find(gid);
        let qe = GpTxQueueEntry {
            id,
            endpoint: entry.endpoint,
            frame: [0u8; MAX_GPDF],
            frame_len: 8,
            lifetime: (rng.below(20) + 1) as u32,
        };
        let _ = queue.enqueue(qe);
        let _ = queue.find(id, entry.endpoint);
        queue.tick(rng.below(5) as u32);
        let _ = queue.remove(id);
    }
}

#[test]
fn fuzz_commissioning_session_never_panics() {
    let mut rng = Fuzz(0xCE55);
    for _ in 0..CASES {
        let mut session = CommissioningSession::new();
        let ann = CommissioningAnnouncement {
            app: if rng.below(2) == 0 {
                AppId::SrcId
            } else {
                AppId::Ieee
            },
            gpd: rng.next(),
            endpoint: rng.below(0x100) as u8,
            pan_id_request: rng.below(2) == 0,
            key_request: rng.below(2) == 0,
            rx_after_tx: rng.below(2) == 0,
            security_capable: rng.below(2) == 0,
            key_present: rng.below(2) == 0,
        };
        session.begin(ann);
        let mut buf = [0u8; 16];
        match session.complete() {
            Ok(_) => {}
            Err(GpError::BidirectionalPending) => {
                let _ = session.build_reply(&mut buf);
            }
            Err(_) => {}
        }
        session.reset();
    }
}

#[test]
fn fuzz_reply_round_trip() {
    let mut rng = Fuzz(0xB1D1);
    let mut buf = [0u8; CommissioningReply::MAX_LEN + 8];
    for _ in 0..CASES {
        let level = [0, 2, 3][rng.below(3) as usize];
        // Level zero carries no key material: only nonzero levels
        // may set the key flag (see `ReplyOptions::check_shape`).
        let options = ReplyOptions {
            pan_id_present: rng.below(2) == 0,
            key_present: rng.below(2) == 0 && level != 0,
            key_encrypted: rng.below(2) == 0 && level != 0,
            level,
            key_type: if level == 0 { 0 } else { rng.below(8) as u8 },
        };
        let reply = CommissioningReply {
            options,
            pan_id: options.pan_id_present.then(|| rng.below(0x1_0000) as u16),
            key: options.key_present.then(|| {
                let mut k = [0u8; 16];
                for slot in k.iter_mut() {
                    *slot = rng.below(0x100) as u8;
                }
                k
            }),
            key_mic: (options.key_present && options.key_encrypted && options.level != 0).then(
                || {
                    let mut m = [0u8; 4];
                    for slot in m.iter_mut() {
                        *slot = rng.below(0x100) as u8;
                    }
                    m
                },
            ),
            frame_counter: (options.key_present && options.key_encrypted && options.level != 0)
                .then(|| rng.next() as u32),
        };
        reply.check_shape().unwrap();
        let n = reply.encode_into(&mut buf).unwrap();
        assert!(n <= CommissioningReply::MAX_LEN);
        let (back, used) = CommissioningReply::decode(&buf[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(back, reply);
        // Channel codecs are total over their octet (config drops
        // the reserved top bits on re-encode).
        let req_byte = rng.below(0x100) as u8;
        let req = ChannelRequest::decode(req_byte);
        assert_eq!(req.encode().unwrap(), req_byte);
        let cfg_byte = rng.below(0x100) as u8;
        let cfg = ChannelConfig::decode(cfg_byte);
        assert_eq!(cfg.encode().unwrap(), cfg_byte & 0x1F);
    }
}

#[test]
fn fuzz_reply_malformed_never_panics() {
    let mut rng = Fuzz(0xBE11);
    let mut buf = [0u8; CommissioningReply::MAX_LEN + 8];
    for _ in 0..CASES {
        let len = rng.below(buf.len() as u64) as usize;
        for slot in buf[..len].iter_mut() {
            *slot = rng.below(0x100) as u8;
        }
        if let Ok((reply, used)) = CommissioningReply::decode(&buf[..len]) {
            assert!(used <= len);
            let mut out = [0u8; CommissioningReply::MAX_LEN];
            let n = reply.encode_into(&mut out).unwrap();
            assert_eq!(&out[..n], &buf[..used]);
        }
    }
}
