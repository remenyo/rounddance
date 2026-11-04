//! Coverage pinning for doc `14-0563-19` Green Power Basic v1.1.2 —
//! proxy / sink / receive intake paths.
//!
//! Paraphrase-level tests only (D1, `SCOPE.md` §2): each test names
//! the document, revision, and clause/anchor it pins, never spec
//! text. Requirement IDs are corpus-mined `14-0563-19-*` plus
//! repo-minted `RD-GP-*` (MINTED-pending-confirm).
//!
//! Corpus anchors pinned here (representative line classes, full map
//! in `docs/coverage/14-0563-19.md`):
//! frame format §A.1.4 (p0039-L737-L746, p0040-L752-L769,
//! p0040-L770-L777), queue/timing §A.1.5.2 (p0046-L959-L997),
//! blocklist/functionality §A.3.4.2 (p0150-L4019-L4028), proxy
//! operation §A.3.6.3 (p0160-L4309+), sink operation §A.3.6.2
//! (p0180-L5073+), translation table (p0189-L5314-L5331,
//! p0191-L5376+), pairing lifecycle (proxy/sink table upsert,
//! deactivation).

use rounddance_gp::*;

// ---- Frame-type / version gates (§A.1.4.1.2) ----

#[test]
fn coverage_gp_frame_type_reserved_rejected() {
    assert_eq!(FrameType::from_bits(0b00).unwrap(), FrameType::Data);
    assert_eq!(FrameType::from_bits(0b01).unwrap(), FrameType::Maintenance);
    assert!(FrameType::from_bits(0b10).is_err());
    assert!(FrameType::from_bits(0b11).is_err());
    assert_eq!(FrameType::Data.bits(), 0b00);
    assert_eq!(FrameType::Maintenance.bits(), 0b01);
}

#[test]
fn coverage_gp_protocol_version_gate() {
    assert_eq!(PROTOCOL_VERSION, 0x3);
    // Minimal data frame from the vectors module shape: version 3 required.
    let good: [u8; 8] = [0x8C, 0x00, 0x78, 0x56, 0x34, 0x12, 0x20, 0x01];
    let (frame, used) = Gpdf::decode(&good).unwrap();
    assert_eq!(used, good.len());
    assert_eq!(frame.fc.frame_type, FrameType::Data);
    assert!(frame.fc.ext_present);
    // Wrong protocol version never decodes: the codec rejects it.
    let mut bad = good;
    bad[0] = 0x88; // version field cleared
    assert!(Gpdf::decode(&bad).is_err());
}

#[test]
fn coverage_gp_app_id_gates() {
    assert_eq!(AppId::from_bits(0b000).unwrap(), AppId::SrcId);
    assert_eq!(AppId::from_bits(0b010).unwrap(), AppId::Ieee);
    assert!(AppId::from_bits(0b011).is_err());
    assert!(AppId::from_bits(0b111).is_err());
}

#[test]
fn coverage_gp_security_level_gates() {
    assert!(!WireSecurityLevel::None.protected());
    assert!(WireSecurityLevel::MicOnly.protected());
    assert!(WireSecurityLevel::Encrypted.protected());
    // Reserved 2-bit pattern 0b01 (already shifted to bits 3-4).
    assert!(WireSecurityLevel::from_bits(0b01 << 3).is_err());
    assert!(WireSecurityLevel::from_bits(0x00).is_ok());
    assert!(WireSecurityLevel::from_bits(WireSecurityLevel::Encrypted.bits()).is_ok());
}

#[test]
fn coverage_gp_endpoint_constant() {
    // GPD commands travel via the reserved endpoint.
    assert_eq!(GP_ENDPOINT, 0xF2);
    assert_eq!(MAX_GPDF, 128);
    assert_eq!(MAX_GPD_PAYLOAD, 64);
}

// ---- Proxy table lifecycle (pairing-driven) ----

fn srcid(id: u32) -> GpdId {
    GpdId::SrcId(id)
}

#[test]
fn coverage_gp_proxy_table_upsert_find_covers() {
    let mut table: ProxyTable<4> = ProxyTable::new();
    assert!(table.is_empty());
    let e = ProxyTableEntry::new(AppId::SrcId, 0x1234_5678);
    table.upsert(e).unwrap();
    assert_eq!(table.len(), 1);
    assert_eq!(table.capacity(), 4);
    let found = table.find(srcid(0x1234_5678)).unwrap();
    assert!(found.covers(srcid(0x1234_5678)));
    assert!(!found.covers(srcid(0x9)));
    // Sink list is bounded.
    let entry = table.find_mut(srcid(0x1234_5678)).unwrap();
    assert!(entry.push_sink(SinkTarget::Group(0x1234)));
    entry.clear_sinks();
    assert_eq!(table.find(srcid(0x1234_5678)).unwrap().sink_count, 0);
}

#[test]
fn coverage_gp_proxy_table_full_and_page_reads() {
    let mut table: ProxyTable<2> = ProxyTable::new();
    table.upsert(ProxyTableEntry::new(AppId::SrcId, 1)).unwrap();
    table.upsert(ProxyTableEntry::new(AppId::SrcId, 2)).unwrap();
    assert!(table.upsert(ProxyTableEntry::new(AppId::SrcId, 3)).is_err());
    let mut out = [ProxyTableEntry::new(AppId::SrcId, 0); 2];
    let page = table.read_page(0, &mut out);
    assert_eq!(page.total, 2);
    // Pairing removal drops the row.
    table.pair_remove(1, 0x00, false).unwrap();
    assert_eq!(table.len(), 1);
}

#[test]
fn coverage_gp_proxy_ieee_endpoint_scope() {
    let mut table: ProxyTable<4> = ProxyTable::new();
    let mut e = ProxyTableEntry::new(AppId::Ieee, 0x0102_0304_0506_0708);
    e.endpoint = 0x0A;
    table.upsert(e).unwrap();
    assert!(table
        .find(GpdId::Ieee {
            addr: [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
            endpoint: 0x0A
        })
        .is_some());
    assert!(table
        .find(GpdId::Ieee {
            addr: [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
            endpoint: 0x0B
        })
        .is_none());
}

// ---- Blocklist + functionality (§A.3.4.2) ----

#[test]
fn coverage_gp_blocklist_bounded() {
    let mut b = Blocklist::new();
    assert!(b.is_empty());
    assert!(b.add(0x1111));
    assert!(b.contains(0x1111));
    assert!(!b.contains(0x2222));
    assert_eq!(b.len(), 1);
    for i in 0..(MAX_BLOCKED_IDS as u64) {
        b.add(0x10_0000 + i);
    }
    assert_eq!(b.len(), MAX_BLOCKED_IDS);
    // Bounded: further distinct ids do not grow the list.
    b.add(0xFFFF_FFFF);
    assert_eq!(b.len(), MAX_BLOCKED_IDS);
    // The bound meets the specified minimum depth.
    assert_eq!(MIN_BLOCKLIST_LEN, MAX_BLOCKED_IDS);
    assert!(b.len() >= 10);
}

#[test]
fn coverage_gp_basic_proxy_functionality_bits() {
    // GP feature bit plus direct-reception bit are mandatory.
    assert_ne!(BASIC_PROXY_FUNCTIONALITY & 0x1, 0);
    assert_ne!(BASIC_PROXY_FUNCTIONALITY & 0x2, 0);
    assert_eq!(BASIC_PROXY_FUNCTIONALITY, 0x9_AC2F);
}

// ---- Transmit queue (§A.1.5.2.1) + timing ----

fn queue_entry(id: u64) -> GpTxQueueEntry {
    GpTxQueueEntry {
        id,
        endpoint: 0xFF,
        frame: [0xAA; MAX_GPDF],
        frame_len: 8,
        lifetime: 100,
    }
}

#[test]
fn coverage_gp_tx_queue_depths_and_replace() {
    assert_eq!(MIN_BASIC_TX_QUEUE, 1);
    assert_eq!(MIN_FULL_TX_QUEUE, 5);
    assert_eq!(BASIC_TX_QUEUE_LEN, MIN_BASIC_TX_QUEUE);
    assert_eq!(FULL_TX_QUEUE_LEN, MIN_FULL_TX_QUEUE);
    let mut q: GpTxQueue<2> = GpTxQueue::new();
    assert!(q.is_empty());
    q.enqueue(queue_entry(1)).unwrap();
    q.enqueue(queue_entry(2)).unwrap();
    assert_eq!(q.len(), 2);
    // Same-GPD replace does not grow the queue.
    q.enqueue(queue_entry(1)).unwrap();
    assert_eq!(q.len(), 2);
    // A new GPD on a full queue is refused.
    assert!(q.enqueue(queue_entry(3)).is_err());
    // queue-full reports per-GPD, not globally.
    assert!(!q.full_for(1));
    assert!(q.full_for(3));
    q.remove(1).unwrap();
    assert!(q.remove(1).is_err());
    assert_eq!(q.len(), 1);
}

#[test]
fn coverage_gp_tx_queue_lifetime_and_timing() {
    assert_eq!(
        (TX_OFFSET_MS, TX_OFFSET_MAX_MS, TX_DURATION_MS),
        (20, 25, 10)
    );
    let mut q: GpTxQueue<2> = GpTxQueue::new();
    q.enqueue(queue_entry(7)).unwrap();
    q.tick(50);
    assert_eq!(q.len(), 1);
    q.tick(50);
    assert!(q.is_empty());
    // Endpoint-scoped lookup.
    q.enqueue(queue_entry(9)).unwrap();
    assert!(q.find(9, 0xFF).is_some());
    assert!(q.find(0xBEEF, 0x00).is_none());
}

// ---- Basic proxy frame processor (§A.3.6.3 / §A.3.8.1 flow) ----

fn data_frame_for(id: u32, command: u8) -> [u8; 9] {
    let mut f = [0u8; 9];
    f[0] = 0x8C; // data, version 3, ext present
    f[1] = 0x00; // SrcId, no security, GPD-originated
    f[2..6].copy_from_slice(&id.to_le_bytes());
    f[6] = command;
    f[7] = 0x01;
    f[8] = 0x02;
    f
}

#[test]
fn coverage_gp_proxy_process_no_entry_drop() {
    let proxy = BasicProxy::new(false);
    let bytes = data_frame_for(0x1234_5678, 0x20);
    let (frame, _) = Gpdf::decode(&bytes).unwrap();
    let mut table: ProxyTable<4> = ProxyTable::new();
    let mut replay: GpReplay<4> = GpReplay::new();
    let queue: GpTxQueue<2> = GpTxQueue::new();
    assert_eq!(
        proxy.process(&frame, &mut table, &mut replay, &queue),
        ProxyOutcome::Drop(DropReason::NoEntry)
    );
}

#[test]
fn coverage_gp_proxy_process_notify_and_replay() {
    let proxy = BasicProxy::new(true);
    let mut table: ProxyTable<4> = ProxyTable::new();
    let mut entry = ProxyTableEntry::new(AppId::SrcId, 0x1234_5678);
    entry.alias = 0x4321;
    entry.push_sink(SinkTarget::Group(0x1234));
    table.upsert(entry).unwrap();
    let mut replay: GpReplay<4> = GpReplay::new();
    let queue: GpTxQueue<2> = GpTxQueue::new();
    let bytes = data_frame_for(0x1234_5678, 0x20);
    let (frame, _) = Gpdf::decode(&bytes).unwrap();
    match proxy.process(&frame, &mut table, &mut replay, &queue) {
        ProxyOutcome::Notify(n) => {
            assert_eq!(n.gpd, 0x1234_5678);
            assert_eq!(n.command, 0x20);
            assert_eq!(n.payload_bytes(), &[0x01, 0x02]);
            assert!(n.bidir_capable);
            assert_eq!(n.alias, 0x4321);
            assert_eq!(n.target, SinkTarget::Group(0x1234));
            assert_eq!(n.options_byte() & 0x02, 0x02);
        }
        other => panic!("expected Notify, got {other:?}"),
    }
}

#[test]
fn coverage_gp_proxy_process_security_mismatch_drops() {
    let proxy = BasicProxy::new(false);
    let mut table: ProxyTable<4> = ProxyTable::new();
    // Table demands a protected level; the frame is unprotected.
    let mut entry = ProxyTableEntry::new(AppId::SrcId, 0x1234_5678);
    entry.level = WireSecurityLevel::MicOnly;
    table.upsert(entry).unwrap();
    let mut replay: GpReplay<4> = GpReplay::new();
    let queue: GpTxQueue<2> = GpTxQueue::new();
    let bytes = data_frame_for(0x1234_5678, 0x20);
    let (frame, _) = Gpdf::decode(&bytes).unwrap();
    assert_eq!(
        proxy.process(&frame, &mut table, &mut replay, &queue),
        ProxyOutcome::Drop(DropReason::UnsupportedSecurity)
    );
}

// ---- Sink tables + translation (§A.3.6.2 / translation table) ----

#[test]
fn coverage_gp_sink_payload_modes() {
    assert_eq!(PayloadMode::from_length_byte(0x00), PayloadMode::None);
    assert_eq!(
        PayloadMode::from_length_byte(0xFF),
        PayloadMode::VerbatimCopy
    );
    assert_eq!(PayloadMode::from_length_byte(0xFE), PayloadMode::Parsed);
    assert_eq!(PayloadMode::from_length_byte(0x05), PayloadMode::Fixed);
}

#[test]
fn coverage_gp_translation_matching_rules() {
    // Generic entry matches every GPD and command.
    let generic = TranslationTableEntry {
        app: AppId::SrcId,
        gpd: GENERIC_SRC_ID as u64,
        endpoint: 0xFF,
        gpd_command: GENERIC_GPD_COMMAND,
        profile: 0x0104,
        cluster: 0x0006,
        command: 0x01,
        payload_mode: PayloadMode::None,
        payload: [0u8; MAX_TRANSLATION_PAYLOAD],
        payload_len: 0,
        vector: None,
    };
    assert!(generic.is_generic());
    assert!(generic.matches(srcid(0xAAAA), 0x20, 0));
    assert!(generic.matches(srcid(0xBBBB), 0x33, 0));
    // Compact sensor group covers 0xA0..=0xA3 only, never 0xA8.
    let group = TranslationTableEntry {
        gpd_command: COMPACT_SENSOR_GROUP_CMD,
        ..generic
    };
    assert!(group.command_matches(0xA0));
    assert!(group.command_matches(0xA3));
    assert!(!group.command_matches(0xA4));
    assert!(!group.command_matches(COMPACT_ATTR_REPORT_CMD));
    assert!(!group.command_matches(0x20));
    // Vector contact option gates matching.
    let vector = TranslationTableEntry {
        gpd_command: 0x20,
        vector: Some(VectorOption {
            contact_status: 0x01,
            contact_mask: 0x01,
        }),
        ..generic
    };
    assert!(vector.matches(srcid(0xAAAA), 0x20, 0x01));
    assert!(!vector.matches(srcid(0xAAAA), 0x20, 0x00));
}

#[test]
fn coverage_gp_translation_table_upsert_lookup_remove() {
    let mut tt: TranslationTable<4> = TranslationTable::new();
    assert!(tt.is_empty());
    let entry = TranslationTableEntry {
        app: AppId::SrcId,
        gpd: 0x1234_5678,
        endpoint: 0xFF,
        gpd_command: 0x20,
        profile: 0x0104,
        cluster: 0x0006,
        command: 0x01,
        payload_mode: PayloadMode::Fixed,
        payload: [0xAA; MAX_TRANSLATION_PAYLOAD],
        payload_len: 2,
        vector: None,
    };
    tt.upsert(entry).unwrap();
    assert_eq!(tt.len(), 1);
    assert!(tt.lookup(srcid(0x1234_5678), 0x20, 0).is_some());
    assert!(tt.lookup(srcid(0x1234_5678), 0x21, 0).is_none());
    tt.remove(0x1234_5678, 0xFF, 0x20).unwrap();
    assert!(tt.is_empty());
    assert!(tt.remove(0x1234_5678, 0xFF, 0x20).is_err());
}

#[test]
fn coverage_gp_sink_table_covers() {
    let mut st: SinkTable<4> = SinkTable::new();
    assert!(st.is_empty());
    let e = SinkTableEntry::new(AppId::SrcId, 0x1234_5678);
    st.upsert(e).unwrap();
    assert!(st.find(srcid(0x1234_5678)).is_some());
    assert!(st.find(srcid(0xDEAD)).is_none());
}

// ---- Sink intake `receive` (decode → filter → admit → route) ----

#[test]
fn coverage_gp_receive_unpaired_unprotected_drops() {
    let bytes = data_frame_for(0x1234_5678, 0x20);
    let keys = GpKeySlots::new();
    let mut session = CommissioningSession::new();
    let mut sink_table: SinkTable<4> = SinkTable::new();
    let mut translations: TranslationTable<4> = TranslationTable::new();
    let mut replay: GpReplay<4> = GpReplay::new();
    let mut opened = [0u8; MAX_GP_OPEN];
    match receive(
        &bytes,
        &keys,
        false,
        &mut session,
        &mut sink_table,
        &mut translations,
        &mut replay,
        &mut opened,
    ) {
        SinkDecision::Drop(_) => {}
        other => panic!("expected Drop, got {other:?}"),
    }
}

#[test]
fn coverage_gp_receive_commissioning_admission_while_open() {
    // Commissioning announcement 0xE0 from an unpaired GPD is
    // admitted only while the commissioning mode is open.
    let bytes = data_frame_for(0x1234_5678, CMD_COMMISSIONING);
    let keys = GpKeySlots::new();
    let mut session = CommissioningSession::new();
    let mut sink_table: SinkTable<4> = SinkTable::new();
    let mut translations: TranslationTable<4> = TranslationTable::new();
    let mut replay: GpReplay<4> = GpReplay::new();
    let mut opened = [0u8; MAX_GP_OPEN];
    match receive(
        &bytes,
        &keys,
        true,
        &mut session,
        &mut sink_table,
        &mut translations,
        &mut replay,
        &mut opened,
    ) {
        SinkDecision::AdmitCommissioning { gpd, command, .. } => {
            assert_eq!(gpd, 0x1234_5678);
            assert_eq!(command, CMD_COMMISSIONING);
        }
        other => panic!("expected AdmitCommissioning, got {other:?}"),
    }
    // Closed mode drops the same frame.
    let mut session2 = CommissioningSession::new();
    let mut st2: SinkTable<4> = SinkTable::new();
    let mut tt2: TranslationTable<4> = TranslationTable::new();
    let mut replay2: GpReplay<4> = GpReplay::new();
    let mut opened2 = [0u8; MAX_GP_OPEN];
    match receive(
        &bytes,
        &keys,
        false,
        &mut session2,
        &mut st2,
        &mut tt2,
        &mut replay2,
        &mut opened2,
    ) {
        SinkDecision::Drop(_) => {}
        other => panic!("expected Drop, got {other:?}"),
    }
}

#[test]
fn coverage_gp_receive_paired_groupcast_handoff() {
    let bytes = data_frame_for(0x1234_5678, 0x20);
    let keys = GpKeySlots::new();
    let mut session = CommissioningSession::new();
    let mut sink_table: SinkTable<4> = SinkTable::new();
    let mut entry = SinkTableEntry::new(AppId::SrcId, 0x1234_5678);
    entry.group_forward = true;
    entry.groups[0] = 0xBEEF;
    entry.group_count = 1;
    sink_table.upsert(entry).unwrap();
    let mut translations: TranslationTable<4> = TranslationTable::new();
    let mut replay: GpReplay<4> = GpReplay::new();
    let mut opened = [0u8; MAX_GP_OPEN];
    match receive(
        &bytes,
        &keys,
        false,
        &mut session,
        &mut sink_table,
        &mut translations,
        &mut replay,
        &mut opened,
    ) {
        SinkDecision::Handoff(h) => {
            assert_eq!(h.route, NwkRoute::Groupcast(0xBEEF));
            assert_eq!(h.command, 0x20);
            assert_eq!(h.payload_bytes(), &[0x01, 0x02]);
        }
        other => panic!("expected Handoff, got {other:?}"),
    }
}

#[test]
fn coverage_gp_receive_paired_translation_handoff() {
    let bytes = data_frame_for(0x1234_5678, 0x20);
    let keys = GpKeySlots::new();
    let mut session = CommissioningSession::new();
    let mut sink_table: SinkTable<4> = SinkTable::new();
    sink_table
        .upsert(SinkTableEntry::new(AppId::SrcId, 0x1234_5678))
        .unwrap();
    let mut translations: TranslationTable<4> = TranslationTable::new();
    translations
        .upsert(TranslationTableEntry {
            app: AppId::SrcId,
            gpd: 0x1234_5678,
            endpoint: 0xFF,
            gpd_command: 0x20,
            profile: 0x0104,
            cluster: 0x0006,
            command: 0x01,
            payload_mode: PayloadMode::Fixed,
            payload: [0xCC; MAX_TRANSLATION_PAYLOAD],
            payload_len: 1,
            vector: None,
        })
        .unwrap();
    let mut replay: GpReplay<4> = GpReplay::new();
    let mut opened = [0u8; MAX_GP_OPEN];
    match receive(
        &bytes,
        &keys,
        false,
        &mut session,
        &mut sink_table,
        &mut translations,
        &mut replay,
        &mut opened,
    ) {
        SinkDecision::Handoff(h) => {
            assert_eq!(h.route, NwkRoute::PairedEndpoints);
            assert_eq!((h.profile, h.cluster, h.command), (0x0104, 0x0006, 0x01));
            assert_eq!(h.payload_bytes(), &[0xCC]);
        }
        other => panic!("expected Handoff, got {other:?}"),
    }
}
