//! Hand-computed GPDF vectors plus proxy/sink/commissioning
//! transcripts.
//!
//! Byte strings below are hand-computed from the paraphrased layouts
//! in `rounddance_gp` — never spec text (D1, `SCOPE.md` §2).
//! Requirement IDs: corpus-mined `14-0563-19-*`; no repo-minted IDs
//! this wave.

use rounddance_gp::*;

// ---- Frame codec vectors ------------------------------------------------

// 14-0563-19-A141-01 + A141-03 + A11-02: minimal unsecured SrcId data
// frame. FC 0x8C = data / version 3 / no auto-commissioning /
// extension present; ext 0x00 = SrcId, no security, GPD-originated.
const MINIMAL_DATA: [u8; 8] = [0x8C, 0x00, 0x78, 0x56, 0x34, 0x12, 0x20, 0x01];

#[test]
fn vector_minimal_data_srcid_14_0563_19_a141_01() {
    let (frame, used) = Gpdf::decode(&MINIMAL_DATA).unwrap();
    assert_eq!(used, MINIMAL_DATA.len());
    assert_eq!(frame.fc.frame_type, FrameType::Data);
    assert!(!frame.fc.auto_commissioning);
    assert!(frame.fc.ext_present);
    let ext = frame.ext.unwrap();
    assert_eq!(ext.app_id, AppId::SrcId);
    assert_eq!(ext.level, WireSecurityLevel::None);
    assert!(!ext.direction_proxy);
    assert_eq!(frame.id, Some(GpdId::SrcId(0x1234_5678)));
    assert_eq!(frame.frame_counter, None);
    assert_eq!(frame.mic, None);
    match frame.body {
        GpdfBody::Gp { command, payload } => {
            assert_eq!(command, 0x20);
            assert_eq!(payload, &[0x01]);
        }
        GpdfBody::LpedOpaque(_) => panic!("expected GP body"),
    }
    frame.ingress_check().unwrap();
    let mut buf = [0u8; MAX_GPDF];
    let n = frame.encode_into(&mut buf).unwrap();
    assert_eq!(&buf[..n], &MINIMAL_DATA);
}

// 14-0563-19-A141-04: maintenance frame travels bare — no identity,
// no endpoint, no security fields, no extension.
#[test]
fn vector_maintenance_travels_bare_14_0563_19_a141_04() {
    let raw = [0x0Du8, 0x10, 0xAA];
    let (frame, used) = Gpdf::decode(&raw).unwrap();
    assert_eq!(used, raw.len());
    assert_eq!(frame.fc.frame_type, FrameType::Maintenance);
    assert!(frame.ext.is_none());
    assert!(frame.id.is_none());
    assert!(frame.frame_counter.is_none());
    assert!(frame.mic.is_none());
    frame.ingress_check().unwrap();
}

// 14-0563-19-A141-01: reserved frame types are rejected.
#[test]
fn vector_reserved_frame_type_rejected_14_0563_19_a141_01() {
    // 0x8E = type 0b10, version 3, extension present.
    let raw = [0x8Eu8, 0x00, 0x78, 0x56, 0x34, 0x12, 0x20];
    assert_eq!(
        Gpdf::decode(&raw).unwrap_err(),
        GpError::ReservedFrameType(0x02)
    );
}

// 14-0563-19-A141-01: foreign application identifiers are dropped.
#[test]
fn vector_foreign_app_id_rejected_14_0563_19_a141_01() {
    // ext 0x03 = AppId 0b011 (foreign).
    let raw = [0x8Cu8, 0x03, 0x78, 0x56, 0x34, 0x12, 0x20];
    assert_eq!(Gpdf::decode(&raw).unwrap_err(), GpError::ForeignAppId(0x03));
}

// 14-0563-19-A152-03: reserved security level is rejected.
#[test]
fn vector_reserved_security_level_rejected_14_0563_19_a152_03() {
    // ext 0x08 = SrcId + level 0b01 (reserved).
    let raw = [0x8Cu8, 0x08, 0x78, 0x56, 0x34, 0x12, 0x20];
    assert_eq!(
        Gpdf::decode(&raw).unwrap_err(),
        GpError::ReservedSecurityLevel(0x01)
    );
}

// 14-0563-19-A141-*: wrong protocol version is rejected.
#[test]
fn vector_bad_version_rejected_14_0563_19_a141() {
    // 0x88 = data, version 2, extension present.
    let raw = [0x88u8, 0x00, 0x78, 0x56, 0x34, 0x12, 0x20];
    assert_eq!(Gpdf::decode(&raw).unwrap_err(), GpError::BadVersion(2));
}

// 14-0563-19-A162-01: reserved source identifiers are rejected.
#[test]
fn vector_reserved_srcid_rejected_14_0563_19_a162_01() {
    let raw = [0x8Cu8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20];
    assert_eq!(Gpdf::decode(&raw).unwrap_err(), GpError::BadIdentifier);
    let raw_all = [0x8Cu8, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x20];
    assert_eq!(Gpdf::decode(&raw_all).unwrap_err(), GpError::BadIdentifier);
}

// 14-0563-19-A141-03: proxy-originated direction is filtered on the
// GPD-side ingress path.
#[test]
fn vector_proxy_direction_dropped_14_0563_19_a141_03() {
    // ext 0x80 = SrcId + direction set.
    let raw = [0x8Cu8, 0x80, 0x78, 0x56, 0x34, 0x12, 0x20];
    let (frame, _) = Gpdf::decode(&raw).unwrap();
    assert_eq!(frame.ingress_check().unwrap_err(), GpError::ProxyOriginated);
}

// 14-0563-19-A141-02: RxAfterTx + auto-commissioning never combine.
#[test]
fn vector_rx_after_tx_auto_comm_conflict_14_0563_19_a141_02() {
    // FC 0xCC = data / version 3 / auto-commissioning / ext;
    // ext 0x40 = SrcId + RxAfterTx.
    let raw = [0xCCu8, 0x40, 0x78, 0x56, 0x34, 0x12, 0x20];
    let (frame, _) = Gpdf::decode(&raw).unwrap();
    assert_eq!(
        frame.ingress_check().unwrap_err(),
        GpError::ConflictingFlags
    );
}

// 14-0563-19-A152-03: commissioning-range command under no security
// is dropped before any table lookup.
#[test]
fn vector_unsecured_commissioning_dropped_14_0563_19_a152_03() {
    let raw = [0x8Cu8, 0x00, 0x78, 0x56, 0x34, 0x12, 0xF1];
    let (frame, _) = Gpdf::decode(&raw).unwrap();
    assert_eq!(
        frame.ingress_check().unwrap_err(),
        GpError::UnsecuredCommissioning
    );
}

// 14-0563-19-A152-03: commissioning-range maintenance commands drop.
#[test]
fn vector_maintenance_commissioning_range_dropped_14_0563_19_a152_03() {
    let raw = [0x0Du8, 0xF1];
    let (frame, _) = Gpdf::decode(&raw).unwrap();
    assert_eq!(
        frame.ingress_check().unwrap_err(),
        GpError::BadMaintenanceCommand
    );
}

// 14-0563-19-A141-*: secured frame geometry — counter + MIC on air,
// little-endian throughout.
#[test]
fn vector_secured_frame_geometry_14_0563_19_a141() {
    // ext 0x10 = SrcId + level 0b10 (counter + MIC).
    let raw = [
        0x8C, 0x10, 0x78, 0x56, 0x34, 0x12, 0x05, 0x00, 0x00, 0x00, 0x20, 0x01, 0xDE, 0xAD, 0xBE,
        0xEF,
    ];
    let (frame, used) = Gpdf::decode(&raw).unwrap();
    assert_eq!(used, raw.len());
    assert_eq!(frame.frame_counter, Some(5));
    assert_eq!(frame.mic, Some([0xDE, 0xAD, 0xBE, 0xEF]));
    match frame.body {
        GpdfBody::Gp { command, payload } => {
            assert_eq!(command, 0x20);
            assert_eq!(payload, &[0x01]);
        }
        GpdfBody::LpedOpaque(_) => panic!("expected GP body"),
    }
    let mut buf = [0u8; MAX_GPDF];
    let n = frame.encode_into(&mut buf).unwrap();
    assert_eq!(&buf[..n], &raw);
}

// 14-0563-19-A141-*: IEEE-addressed frame carries address + endpoint.
#[test]
fn vector_ieee_addressed_frame_14_0563_19_a141() {
    let raw = [
        0x8C, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x22,
    ];
    let (frame, used) = Gpdf::decode(&raw).unwrap();
    assert_eq!(used, raw.len());
    assert_eq!(
        frame.id,
        Some(GpdId::Ieee {
            addr: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            endpoint: 0x0A,
        })
    );
    frame.ingress_check().unwrap();
    let mut buf = [0u8; MAX_GPDF];
    let n = frame.encode_into(&mut buf).unwrap();
    assert_eq!(&buf[..n], &raw);
}

// 14-0563-19-A141-*: RxAfterTx request frame passes ingress.
#[test]
fn vector_rx_after_tx_request_passes_14_0563_19_a141() {
    let raw = [0x8Cu8, 0x40, 0x78, 0x56, 0x34, 0x12, 0x20];
    let (frame, _) = Gpdf::decode(&raw).unwrap();
    assert!(frame.ext.unwrap().rx_after_tx);
    frame.ingress_check().unwrap();
}

// ---- Security vectors ---------------------------------------------------

// 14-0563-19-A153-01: nonce packs identity + counter, LE throughout.
#[test]
fn vector_nonce_construction_14_0563_19_a153_01() {
    let addr = GpNonce::incoming_srcid_addr(0x8765_4321);
    assert_eq!(addr, [0x21, 0x43, 0x65, 0x87, 0x21, 0x43, 0x65, 0x87]);
    let nonce = GpNonce::build(addr, 0x0102_0304, false);
    assert_eq!(
        nonce.bytes,
        [0x21, 0x43, 0x65, 0x87, 0x21, 0x43, 0x65, 0x87, 0x04, 0x03, 0x02, 0x01, 0x05]
    );
    let out_addr = GpNonce::outgoing_srcid_addr(0x8765_4321);
    assert_eq!(out_addr, [0, 0, 0, 0, 0x21, 0x43, 0x65, 0x87]);
    // Outgoing IEEE-addressed frames pin the reserved bits to 0b11.
    assert_eq!(GpNonce::control_byte(true), 0xC0 | 0x05);
    assert_eq!(GpNonce::control_byte(false), 0x05);
}

// 14-0563-19-A153-01: key-type to wire-bit mapping.
#[test]
fn vector_key_type_wire_bits_14_0563_19_a153_01() {
    assert_eq!(GpKeyType::NONE.wire_bit(), Some(false));
    assert_eq!(GpKeyType::SHARED.wire_bit(), Some(false));
    assert_eq!(GpKeyType::GROUP.wire_bit(), Some(false));
    assert_eq!(GpKeyType::DERIVED.wire_bit(), Some(false));
    assert_eq!(GpKeyType::INDIVIDUAL.wire_bit(), Some(true));
    assert_eq!(GpKeyType::OOB.wire_bit(), Some(true));
    assert_eq!(GpKeyType(0b101).wire_bit(), None);
    assert!(GpKey::new(GpKeyType(0b101), [0u8; 16]).is_none());
    assert!(GpKey::new(GpKeyType::INDIVIDUAL, [0x77u8; 16]).is_some());
}

// 14-0563-19-A36-05: counters advance monotonically, no rollover.
#[test]
fn vector_counter_monotonic_no_rollover_14_0563_19_a36_05() {
    let mut replay = GpReplay::<4>::new();
    assert!(replay.is_empty());
    replay.check(0x1234_5678, 7).unwrap();
    assert_eq!(
        replay.check(0x1234_5678, 7).unwrap_err(),
        rounddance_security::SecError::Replay
    );
    assert!(replay.check(0x1234_5678, 3).is_err());
    replay.check(0x1234_5678, 8).unwrap();
    // A second GPD tracks independently.
    replay.check(0x9ABC, 0).unwrap();
    assert_eq!(replay.len(), 2);
}

// ---- Proxy vectors ------------------------------------------------------

fn proxy_entry_for_srcid() -> ProxyTableEntry {
    let mut e = ProxyTableEntry::new(AppId::SrcId, 0x1234_5678);
    e.push_sink(SinkTarget::Group(0xABCD));
    e
}

// 14-0563-19-A38-01 + A36-04: passing frame notifies in the clear.
#[test]
fn vector_proxy_passing_frame_notifies_14_0563_19_a38_01() {
    let proxy = BasicProxy::new(false);
    let mut table = ProxyTable::<4>::new();
    table.upsert(proxy_entry_for_srcid()).unwrap();
    let mut replay = GpReplay::<4>::new();
    let queue = GpTxQueue::<1>::new();
    let (frame, _) = Gpdf::decode(&MINIMAL_DATA).unwrap();
    match proxy.process(&frame, &mut table, &mut replay, &queue) {
        ProxyOutcome::Notify(note) => {
            assert_eq!(note.gpd, 0x1234_5678);
            assert_eq!(note.command, 0x20);
            assert_eq!(note.payload_bytes(), &[0x01]);
            assert_eq!(note.target, SinkTarget::Group(0xABCD));
            assert_eq!(note.options_byte(), 0x00);
        }
        ProxyOutcome::Drop(reason) => panic!("unexpected drop: {:?}", reason),
    }
}

// 14-0563-19-A38-01: no table entry drops before security.
#[test]
fn vector_proxy_no_entry_drops_14_0563_19_a38_01() {
    let proxy = BasicProxy::new(false);
    let mut table = ProxyTable::<4>::new();
    let mut replay = GpReplay::<4>::new();
    let queue = GpTxQueue::<1>::new();
    let (frame, _) = Gpdf::decode(&MINIMAL_DATA).unwrap();
    assert_eq!(
        proxy.process(&frame, &mut table, &mut replay, &queue),
        ProxyOutcome::Drop(DropReason::NoEntry)
    );
}

// 14-0563-19-A38-01: level/key mismatch drops as unsupported.
#[test]
fn vector_proxy_security_mismatch_drops_14_0563_19_a38_01() {
    let proxy = BasicProxy::new(false);
    let mut table = ProxyTable::<4>::new();
    table.upsert(proxy_entry_for_srcid()).unwrap();
    let mut replay = GpReplay::<4>::new();
    let queue = GpTxQueue::<1>::new();
    let raw = [
        0x8C, 0x10, 0x78, 0x56, 0x34, 0x12, 0x05, 0x00, 0x00, 0x00, 0x20, 0x01, 0xDE, 0xAD, 0xBE,
        0xEF,
    ];
    let (frame, _) = Gpdf::decode(&raw).unwrap();
    assert_eq!(
        proxy.process(&frame, &mut table, &mut replay, &queue),
        ProxyOutcome::Drop(DropReason::UnsupportedSecurity)
    );
}

// 14-0563-19-A36-05: replayed counters drop; fresh ones advance.
#[test]
fn vector_proxy_replay_drops_fresh_advances_14_0563_19_a36_05() {
    let proxy = BasicProxy::new(true);
    let mut table = ProxyTable::<4>::new();
    let mut e = proxy_entry_for_srcid();
    e.level = WireSecurityLevel::MicOnly;
    table.upsert(e).unwrap();
    let mut replay = GpReplay::<4>::new();
    let queue = GpTxQueue::<1>::new();
    let raw = [
        0x8C, 0x10, 0x78, 0x56, 0x34, 0x12, 0x05, 0x00, 0x00, 0x00, 0x20, 0x01, 0xDE, 0xAD, 0xBE,
        0xEF,
    ];
    let (frame, _) = Gpdf::decode(&raw).unwrap();
    match proxy.process(&frame, &mut table, &mut replay, &queue) {
        ProxyOutcome::Notify(note) => {
            assert!(note.bidir_capable);
            assert_eq!(note.options_byte(), 0x02);
        }
        ProxyOutcome::Drop(reason) => panic!("unexpected drop: {:?}", reason),
    }
    let (again, _) = Gpdf::decode(&raw).unwrap();
    assert_eq!(
        proxy.process(&again, &mut table, &mut replay, &queue),
        ProxyOutcome::Drop(DropReason::Replay)
    );
}

// 14-0563-19-A36-02: pairing lifecycle — add, endpoint-scoped
// removal, deactivation.
#[test]
fn vector_proxy_pairing_lifecycle_14_0563_19_a36_02() {
    let mut table = ProxyTable::<4>::new();
    let mut e = ProxyTableEntry::new(AppId::Ieee, u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8]));
    e.endpoint = 0x0A;
    table.upsert(e).unwrap();
    let id = GpdId::Ieee {
        addr: [1, 2, 3, 4, 5, 6, 7, 8],
        endpoint: 0x0A,
    };
    assert!(table.find(id).is_some());
    // Other endpoints are not covered by the endpoint-scoped row.
    let other = GpdId::Ieee {
        addr: [1, 2, 3, 4, 5, 6, 7, 8],
        endpoint: 0x0B,
    };
    assert!(table.find(other).is_none());
    // Wildcard pairing removal clears every row for the GPD.
    table.pair_remove(id.table_key(), 0xFF, false).unwrap();
    assert!(table.is_empty());
    // Deactivation keeps the row but hides it from lookup.
    table.upsert(e).unwrap();
    table.pair_remove(id.table_key(), 0x0A, true).unwrap();
    assert_eq!(table.len(), 1);
    assert!(table.find(id).is_none());
}

// 14-0563-19-A34-02: paginated reads skip holes, never split entries.
#[test]
fn vector_proxy_table_read_pages_14_0563_19_a34_02() {
    let mut table = ProxyTable::<4>::new();
    assert!(table.read_page(0, &mut []).done);
    for i in 1..=3u32 {
        table
            .upsert(ProxyTableEntry::new(AppId::SrcId, i as u64))
            .unwrap();
    }
    let mut page = [ProxyTableEntry::new(AppId::SrcId, 0); 2];
    let first = table.read_page(0, &mut page);
    assert_eq!((first.total, first.filled, first.done), (3, 2, false));
    let second = table.read_page(2, &mut page);
    assert_eq!((second.total, second.filled, second.done), (3, 1, true));
}

// 14-0563-19-A34-01: blocklist holds at least ten entries.
#[test]
fn vector_blocklist_capacity_14_0563_19_a34_01() {
    let mut list = Blocklist::new();
    for i in 0..MIN_BLOCKLIST_LEN as u64 {
        assert!(list.add(0x1000 + i));
    }
    assert_eq!(list.len(), MIN_BLOCKLIST_LEN);
    assert!(list.contains(0x1005));
    assert!(!list.contains(0x9999));
    assert_eq!(BASIC_PROXY_FUNCTIONALITY, 0x9_AC2F);
}

// 14-0563-19-A36-03: commissioning mode — commanded, windowed,
// pairing-sensitive.
#[test]
fn vector_proxy_commissioning_mode_14_0563_19_a36_03() {
    let mut m = ProxyCommissioning::new(15);
    assert!(!m.in_commissioning());
    m.on_command(CommissioningModeCmd {
        enter: true,
        channel: 20,
        exit_on_first_pairing: true,
        window_ticks: 100,
    });
    assert!(m.in_commissioning());
    assert_eq!(m.channel(), 20);
    m.on_pairing();
    assert!(!m.in_commissioning());
    // Without the exit flag, pairing does not exit; the window does.
    m.on_command(CommissioningModeCmd {
        enter: true,
        channel: 20,
        exit_on_first_pairing: false,
        window_ticks: 100,
    });
    m.on_pairing();
    assert!(m.in_commissioning());
    m.tick(50);
    assert!(m.in_commissioning());
    m.tick(50);
    assert!(!m.in_commissioning());
}

// 14-0563-19-A152-01: one pending frame per GPD, bounded lifetime.
#[test]
fn vector_tx_queue_single_per_gpd_14_0563_19_a152_01() {
    let mut q = GpTxQueue::<1>::new();
    assert!(q.is_empty());
    let entry = GpTxQueueEntry {
        id: 7,
        endpoint: 0xFF,
        frame: [0u8; MAX_GPDF],
        frame_len: 8,
        lifetime: 10,
    };
    q.enqueue(entry).unwrap();
    assert!(!q.full_for(7));
    // A second GPD has no room on a depth-1 basic queue.
    let other = GpTxQueueEntry { id: 8, ..entry };
    assert_eq!(q.enqueue(other).unwrap_err(), GpError::TableFull);
    // Same GPD replaces instead of failing.
    let replacement = GpTxQueueEntry {
        frame_len: 9,
        ..entry
    };
    q.enqueue(replacement).unwrap();
    assert_eq!(q.find(7, 0xFF).unwrap().frame_len, 9);
    q.tick(10);
    assert!(q.is_empty());
}

// ---- Sink vectors --------------------------------------------------------

fn sink_entry_with_translation() -> (SinkTable<4>, TranslationTable<4>) {
    let mut sinks = SinkTable::<4>::new();
    sinks
        .upsert(SinkTableEntry::new(AppId::SrcId, 0x1234_5678))
        .unwrap();
    let mut translations = TranslationTable::<4>::new();
    translations
        .upsert(TranslationTableEntry {
            app: AppId::SrcId,
            gpd: GENERIC_SRC_ID as u64,
            endpoint: 0xFF,
            gpd_command: GENERIC_GPD_COMMAND,
            profile: 0x0104,
            cluster: 0x0006,
            command: 0x01,
            payload_mode: PayloadMode::Fixed,
            payload: {
                let mut p = [0u8; MAX_TRANSLATION_PAYLOAD];
                p[0] = 0xAA;
                p
            },
            payload_len: 1,
            vector: None,
        })
        .unwrap();
    (sinks, translations)
}

// 14-0563-19-A36-06 + A36-07 + A36-08: generic translation applies.
#[test]
fn vector_sink_generic_translation_14_0563_19_a36_07() {
    let sink = SinkMachine::new(false);
    let (mut sinks, translations) = sink_entry_with_translation();
    let mut replay = GpReplay::<4>::new();
    match sink.accept(
        GpdId::SrcId(0x1234_5678),
        WireSecurityLevel::None,
        false,
        None,
        0x20,
        &[0x01],
        0,
        &mut sinks,
        &translations,
        &mut replay,
    ) {
        SinkOutcome::Translate(t) => {
            assert_eq!(t.profile, 0x0104);
            assert_eq!(t.cluster, 0x0006);
            assert_eq!(t.command, 0x01);
            assert_eq!(t.payload_bytes(), &[0xAA]);
        }
        SinkOutcome::Drop(e) => panic!("unexpected drop: {:?}", e),
        SinkOutcome::ForwardGroup { .. } => panic!("unexpected forward"),
    }
}

// 14-0563-19-A36-06: group-bound entries forward before translating.
#[test]
fn vector_sink_group_forward_14_0563_19_a36_06() {
    let sink = SinkMachine::new(false);
    let (mut sinks, translations) = sink_entry_with_translation();
    sinks
        .find_mut(GpdId::SrcId(0x1234_5678))
        .unwrap()
        .group_forward = true;
    sinks.find_mut(GpdId::SrcId(0x1234_5678)).unwrap().groups[0] = 0x1234;
    sinks
        .find_mut(GpdId::SrcId(0x1234_5678))
        .unwrap()
        .group_count = 1;
    let mut replay = GpReplay::<4>::new();
    assert_eq!(
        sink.accept(
            GpdId::SrcId(0x1234_5678),
            WireSecurityLevel::None,
            false,
            None,
            0x20,
            &[0x01],
            0,
            &mut sinks,
            &translations,
            &mut replay,
        ),
        SinkOutcome::ForwardGroup {
            gpd: 0x1234_5678,
            command: 0x20,
            group: 0x1234,
        }
    );
}

// 14-0563-19-A36-08: the compact marker never translates compact
// attribute reporting; specific entries supersede generic ones.
#[test]
fn vector_sink_compact_and_specific_rules_14_0563_19_a36_08() {
    let mut translations = TranslationTable::<4>::new();
    let generic = TranslationSeed {
        app: AppId::SrcId,
        gpd: GENERIC_SRC_ID as u64,
        endpoint: 0xFF,
        gpd_command: GENERIC_GPD_COMMAND,
        profile: 0x0104,
        cluster: 0x0006,
        command: 0x01,
    }
    .materialize();
    translations.upsert(generic).unwrap();
    let sensor = TranslationSeed {
        app: AppId::SrcId,
        gpd: 0x1234_5678,
        endpoint: 0xFF,
        gpd_command: COMPACT_SENSOR_GROUP_CMD,
        profile: 0x0104,
        cluster: 0x0402,
        command: 0x00,
    }
    .materialize();
    translations.upsert(sensor).unwrap();
    let id = GpdId::SrcId(0x1234_5678);
    // Compact reporting matches the generic entry, never the sensor
    // group.
    let hit = translations.lookup(id, COMPACT_ATTR_REPORT_CMD, 0).unwrap();
    assert_eq!(hit.gpd_command, GENERIC_GPD_COMMAND);
    // A sensor report matches the specific entry, not the generic.
    let hit = translations.lookup(id, 0xA1, 0).unwrap();
    assert_eq!(hit.cluster, 0x0402);
    // An unrelated GPD falls back to the generic entry.
    let stranger = translations.lookup(GpdId::SrcId(0x7777), 0x20, 0).unwrap();
    assert_eq!(stranger.cluster, 0x0006);
}

// 14-0563-19-A36-09: vector press/release uses masked contact match.
#[test]
fn vector_sink_contact_mask_match_14_0563_19_a36_09() {
    let mut translations = TranslationTable::<4>::new();
    translations
        .upsert(TranslationTableEntry {
            app: AppId::SrcId,
            gpd: 0x1234_5678,
            endpoint: 0xFF,
            gpd_command: 0x22,
            profile: 0x0104,
            cluster: 0x0006,
            command: 0x02,
            payload_mode: PayloadMode::None,
            payload: [0u8; MAX_TRANSLATION_PAYLOAD],
            payload_len: 0,
            vector: Some(VectorOption {
                contact_status: 0x03,
                contact_mask: 0x0F,
            }),
        })
        .unwrap();
    let id = GpdId::SrcId(0x1234_5678);
    assert!(translations.lookup(id, 0x22, 0x13).is_some());
    assert!(translations.lookup(id, 0x22, 0x10).is_none());
}

// ---- Commissioning vectors ------------------------------------------------

// 14-0563-19-A36-07: unidirectional commissioning populates the
// translation table.
#[test]
fn vector_uni_commissioning_populates_table_14_0563_19_a36_07() {
    let mut session = CommissioningSession::new();
    session.begin(CommissioningAnnouncement {
        app: AppId::SrcId,
        gpd: 0x1234_5678,
        endpoint: 0xFF,
        pan_id_request: false,
        key_request: false,
        rx_after_tx: false,
        security_capable: false,
        key_present: false,
    });
    assert_eq!(session.state(), CommissioningState::Collecting);
    let seed = session.complete().unwrap().unwrap();
    assert_eq!(session.state(), CommissioningState::Commissioned);
    assert_eq!(seed.gpd_command, GENERIC_GPD_COMMAND);
    let mut translations = TranslationTable::<4>::new();
    translations.upsert(seed.materialize()).unwrap();
    assert!(translations
        .lookup(GpdId::SrcId(0x1234_5678), 0x20, 0)
        .is_some());
}

// Bidirectional completion parks awaiting the reply: with nothing
// staged yet the reply builder reports pending.
#[test]
fn vector_bi_commissioning_parks_pending_reply() {
    let mut session = CommissioningSession::new();
    session.begin(CommissioningAnnouncement {
        app: AppId::SrcId,
        gpd: 0x1234_5678,
        endpoint: 0xFF,
        pan_id_request: true,
        key_request: true,
        rx_after_tx: true,
        security_capable: true,
        key_present: true,
    });
    assert_eq!(
        session.complete().unwrap_err(),
        GpError::BidirectionalPending
    );
    assert_eq!(session.state(), CommissioningState::AwaitingReply);
    let mut out = [0u8; 16];
    assert_eq!(
        session.build_reply(&mut out).unwrap_err(),
        GpError::BidirectionalPending
    );
    assert!(is_commissioning_command(0xF0));
    assert!(is_commissioning_command(0xFF));
    assert!(!is_commissioning_command(0x20));
}

// ---- Wave-34 bidirectional reply vectors ---------------------------------
// Requirement IDs: repo-minted `14-0563-19-A173-*` / `-A4211-*` /
// `-A4212-*` / `-A4214-*` / `-A4215-*` (MINTED-pending-confirm).

fn bidir_ann() -> CommissioningAnnouncement {
    CommissioningAnnouncement {
        app: AppId::SrcId,
        gpd: 0x1234_5678,
        endpoint: 0xFF,
        pan_id_request: true,
        key_request: true,
        rx_after_tx: true,
        security_capable: true,
        key_present: true,
    }
}

// 14-0563-19-A4211-01: commissioning command identifiers.
#[test]
fn vector_bidir_command_ids_14_0563_19_a4211_01() {
    assert_eq!(CMD_COMMISSIONING, 0xE0);
    assert_eq!(CMD_DECOMMISSIONING, 0xE1);
    assert_eq!(CMD_SUCCESS, 0xE2);
    assert_eq!(CMD_CHANNEL_REQUEST, 0xE3);
    assert_eq!(CMD_COMMISSIONING_REPLY, 0xF0);
    assert_eq!(CMD_CHANNEL_CONFIG, 0xF3);
    assert!(is_payloadless_commissioning(CMD_SUCCESS));
    assert!(is_payloadless_commissioning(CMD_DECOMMISSIONING));
    assert!(!is_payloadless_commissioning(CMD_COMMISSIONING));
    assert!(!is_payloadless_commissioning(CMD_COMMISSIONING_REPLY));
}

// 14-0563-19-A4212-01: PANID-only reply, level zero.
// Options 0x01 = PANID present; payload [0x01, 0x2B, 0x1A].
#[test]
fn vector_reply_panid_only_14_0563_19_a4212_01() {
    let wire = [0x01u8, 0x2B, 0x1A];
    let (reply, used) = CommissioningReply::decode(&wire).unwrap();
    assert_eq!(used, 3);
    assert_eq!(
        reply.options,
        ReplyOptions {
            pan_id_present: true,
            key_present: false,
            key_encrypted: false,
            level: 0,
            key_type: 0,
        }
    );
    assert_eq!(reply.pan_id, Some(0x1A2B));
    assert_eq!(reply.key, None);
    assert_eq!(reply.key_mic, None);
    assert_eq!(reply.frame_counter, None);
    let mut buf = [0u8; CommissioningReply::MAX_LEN];
    let n = reply.encode_into(&mut buf).unwrap();
    assert_eq!(&buf[..n], &wire);
}

// 14-0563-19-A4212-01: PANID + clear key reply.
// Options 0x33 = PANID + key present, level 0b10, key type 0b001.
#[test]
fn vector_reply_clear_key_14_0563_19_a4212_01() {
    let key = [0x77u8; 16];
    let mut wire = [0u8; 19];
    wire[0] = 0x33;
    wire[1] = 0x2B;
    wire[2] = 0x1A;
    wire[3..].copy_from_slice(&key);
    let (reply, used) = CommissioningReply::decode(&wire).unwrap();
    assert_eq!(used, 19);
    assert_eq!(reply.pan_id, Some(0x1A2B));
    assert_eq!(reply.key, Some(key));
    assert_eq!(reply.key_mic, None);
    assert_eq!(reply.frame_counter, None);
    let mut buf = [0u8; CommissioningReply::MAX_LEN];
    let n = reply.encode_into(&mut buf).unwrap();
    assert_eq!(&buf[..n], &wire);
}

// 14-0563-19-A4212-01: PANID + protected key reply (27 octets).
// Options 0x9F = PANID + key + encryption, level 0b11, type 0b100.
#[test]
fn vector_reply_protected_key_14_0563_19_a4212_01() {
    let key = [0xABu8; 16];
    let mic = [0x11u8, 0x22, 0x33, 0x44];
    let mut wire = [0u8; 27];
    wire[0] = 0x9F;
    wire[1] = 0x2B;
    wire[2] = 0x1A;
    wire[3..19].copy_from_slice(&key);
    wire[19..23].copy_from_slice(&mic);
    wire[23..27].copy_from_slice(&0x0000_0042u32.to_le_bytes());
    let (reply, used) = CommissioningReply::decode(&wire).unwrap();
    assert_eq!(used, 27);
    assert_eq!(reply.key_mic, Some(mic));
    assert_eq!(reply.frame_counter, Some(0x42));
    let mut buf = [0u8; CommissioningReply::MAX_LEN];
    let n = reply.encode_into(&mut buf).unwrap();
    assert_eq!(&buf[..n], &wire);
}

// 14-0563-19-A4212-01: reply rejection legs — truncated, reserved
// level 0b01, and level-zero carrying key flags.
#[test]
fn vector_reply_rejection_14_0563_19_a4212_01() {
    assert_eq!(
        CommissioningReply::decode(&[]).unwrap_err(),
        GpError::Truncated
    );
    // Options 0x0B: reserved level 0b01.
    assert_eq!(
        CommissioningReply::decode(&[0x0B]).unwrap_err(),
        GpError::ReservedSecurityLevel(0x01)
    );
    // Options 0x03: level zero with key present.
    assert_eq!(
        CommissioningReply::decode(&[0x03, 0x2B, 0x1A]).unwrap_err(),
        GpError::UnsecuredCommissioning
    );
    // Cut key: options promise 16 key octets, only 3 follow.
    assert_eq!(
        CommissioningReply::decode(&[0x33, 0x2B, 0x1A, 0x00]).unwrap_err(),
        GpError::Truncated
    );
    // Protected key missing its MIC/counter tail.
    let mut short = [0u8; 23];
    short[0] = 0x9F;
    short[1] = 0x2B;
    short[2] = 0x1A;
    assert_eq!(
        CommissioningReply::decode(&short).unwrap_err(),
        GpError::Truncated
    );
}

// 14-0563-19-A4214-01 + A4215-01: channel request/config octet shapes.
// Request 0x94 = next ch15 (low nibble), second ch20 (high nibble);
// config 0x04 = ch15 infra, 0x19 = ch20 basic-only.
#[test]
fn vector_channel_codecs_14_0563_19_a4214_01_a4215_01() {
    let req = ChannelRequest::decode(0x94);
    assert_eq!(req.rx_next, 15);
    assert_eq!(req.rx_second, 20);
    assert_eq!(req.encode().unwrap(), 0x94);
    let cfg = ChannelConfig::decode(0x04);
    assert_eq!(cfg.channel, 15);
    assert!(!cfg.basic);
    assert_eq!(cfg.encode().unwrap(), 0x04);
    let basic = ChannelConfig::decode(0x19);
    assert_eq!(basic.channel, 20);
    assert!(basic.basic);
    assert_eq!(basic.encode().unwrap(), 0x19);
    assert_eq!(
        ChannelConfig {
            channel: 27,
            basic: false
        }
        .encode()
        .unwrap_err(),
        GpError::BadIdentifier
    );
}

// 14-0563-19-A4212-02: full bidirectional exchange — park, stage,
// serve, Success completes with a translation seed.
#[test]
fn vector_bidir_full_exchange_14_0563_19_a4212_02() {
    let mut session = CommissioningSession::new();
    session.begin(bidir_ann());
    assert_eq!(
        session.complete_at(1_000).unwrap_err(),
        GpError::BidirectionalPending
    );
    assert_eq!(session.state(), CommissioningState::AwaitingReply);
    assert_eq!(session.deadline_ms(), 1_000 + REPLY_TIMEOUT_MS);
    assert!(!session.reply_staged());

    let reply = CommissioningReply {
        options: ReplyOptions {
            pan_id_present: true,
            key_present: false,
            key_encrypted: false,
            level: 0,
            key_type: 0,
        },
        pan_id: Some(0xA4D3),
        key: None,
        key_mic: None,
        frame_counter: None,
    };
    session.stage_reply(reply).unwrap();
    assert!(session.reply_staged());
    let mut buf = [0u8; CommissioningReply::MAX_LEN];
    let n = session.build_reply(&mut buf).unwrap();
    assert_eq!(&buf[..n], &[0x01, 0xD3, 0xA4]);

    // A Success frame for another GPD belongs to another transaction.
    assert_eq!(
        session.note_success(0xDEAD_BEEF, 0xFF).unwrap_err(),
        GpError::TransactionMismatch
    );
    assert_eq!(session.state(), CommissioningState::AwaitingReply);

    let seed = session.note_success(0x1234_5678, 0xFF).unwrap().unwrap();
    assert_eq!(session.state(), CommissioningState::Commissioned);
    let mut translations = TranslationTable::<4>::new();
    translations.upsert(seed.materialize()).unwrap();
    assert!(translations
        .lookup(GpdId::SrcId(0x1234_5678), 0x20, 0)
        .is_some());
    // Serving after completion is a state error.
    assert_eq!(
        session.build_reply(&mut buf).unwrap_err(),
        GpError::BadState
    );
}

// 14-0563-19-A173-02: parked exchange lapses past the window.
#[test]
fn vector_bidir_reply_timeout_14_0563_19_a173_02() {
    let mut session = CommissioningSession::new();
    session.begin(bidir_ann());
    assert_eq!(
        session.complete_at(0).unwrap_err(),
        GpError::BidirectionalPending
    );
    session.tick(REPLY_TIMEOUT_MS - 1).unwrap();
    assert_eq!(session.state(), CommissioningState::AwaitingReply);
    assert_eq!(
        session.tick(REPLY_TIMEOUT_MS).unwrap_err(),
        GpError::ReplyTimeout
    );
    assert_eq!(session.state(), CommissioningState::Idle);
    assert_eq!(session.deadline_ms(), u64::MAX);
}

// 14-0563-19-A173-01: incapable peer — key request with no receive
// window, or with no security capability, refuses.
#[test]
fn vector_bidir_incapable_peer_14_0563_19_a173_01() {
    // No receive window behind the key request.
    let mut ann = bidir_ann();
    ann.rx_after_tx = false;
    assert_eq!(
        check_bidir_capable(ann).unwrap_err(),
        GpError::PeerIncapable
    );
    let mut session = CommissioningSession::new();
    session.begin(ann);
    assert_eq!(session.complete().unwrap_err(), GpError::PeerIncapable);
    assert_eq!(session.state(), CommissioningState::Idle);

    // No security capability behind the key request.
    let mut ann = bidir_ann();
    ann.security_capable = false;
    assert_eq!(
        check_bidir_capable(ann).unwrap_err(),
        GpError::PeerIncapable
    );
    let mut session = CommissioningSession::new();
    session.begin(ann);
    assert_eq!(session.complete().unwrap_err(), GpError::PeerIncapable);

    // Capable peer passes the gate.
    assert!(check_bidir_capable(bidir_ann()).is_ok());
}

// Reply staging and Success are state-gated outside the window.
#[test]
fn vector_bidir_state_gates_14_0563_19_a4212_02() {
    let mut session = CommissioningSession::new();
    let reply = CommissioningReply {
        options: ReplyOptions {
            pan_id_present: false,
            key_present: false,
            key_encrypted: false,
            level: 0,
            key_type: 0,
        },
        pan_id: None,
        key: None,
        key_mic: None,
        frame_counter: None,
    };
    assert_eq!(session.stage_reply(reply).unwrap_err(), GpError::BadState);
    assert_eq!(
        session.note_success(0x1234_5678, 0xFF).unwrap_err(),
        GpError::BadState
    );
    let mut buf = [0u8; CommissioningReply::MAX_LEN];
    assert_eq!(
        session.build_reply(&mut buf).unwrap_err(),
        GpError::BadState
    );
}
