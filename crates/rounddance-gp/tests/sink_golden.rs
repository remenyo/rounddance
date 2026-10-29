//! Sink golden tests: the unified sink intake (`receive`) replayed
//! against the w51 GPDF census shapes.
//!
//! Provenance: the `8c ...` GPDF octets below are verbatim w51 lane-1
//! air MSDUs (MAC outer stripped), first pinned in
//! `rounddance-inspect/tests/decode_depth.rs` (GAP-5 closure); the
//! per-shape counts mirror `~/hwscratch/w52/gp_census.log`
//! (`analyze52_gp.py` CENSUS PASS, 519/519) as metadata. No key
//! material: protected shapes are re-sealed under a synthetic
//! test-only key for the open legs; the air MICs travel only on the
//! no-key drop legs (ciphertext/MIC class, wave-49 precedent).
//!
//! Requirement traceability: RD-GP-01..06 (wave-64 section).

use rounddance_gp::*;

// ---------------------------------------------------------------------------
// Census pins (metadata): per-shape GPDF counts across the ten w51
// lane-1 captures, summing to the 519-GPDF oracle total.
// ---------------------------------------------------------------------------

const PLAIN_DATA: usize = 46;
const PLAIN_COMM_LONG: usize = 162;
const PLAIN_COMM_COMPACT: usize = 20;
const SEC_DATA: usize = 193;
const SEC_DECOMM: usize = 42;
const SEC_COMM_LONG: usize = 10;
const RX_AFTER_TX_COMM: usize = 10;
const ENCRYPTED: usize = 36;

#[test]
fn census_pins_sum_to_oracle_total() {
    assert_eq!(
        PLAIN_DATA
            + PLAIN_COMM_LONG
            + PLAIN_COMM_COMPACT
            + SEC_DATA
            + SEC_DECOMM
            + SEC_COMM_LONG
            + RX_AFTER_TX_COMM
            + ENCRYPTED,
        519,
        "w51 oracle: 519 GPDFs across 10 pcaps"
    );
}

// ---------------------------------------------------------------------------
// Verbatim w51 MSDUs (MAC outer stripped).
// ---------------------------------------------------------------------------

/// Verbatim w51 L unsecured data: SrcId 0x517f6811, `20 01`.
const AIR_DATA_UNSECURED: [u8; 8] = [0x8c, 0x00, 0x11, 0x68, 0x7f, 0x51, 0x20, 0x01];

/// Verbatim w51 L unsecured commissioning, 23-octet body.
const AIR_COMM_LONG: [u8; 30] = [
    0x8c, 0x00, 0x11, 0x68, 0x7f, 0x51, 0xe0, 0x02, 0xc3, 0xb2, 0x6e, 0xe4, 0x56, 0x3f, 0xef, 0x39,
    0x19, 0x4b, 0x39, 0xb5, 0xd6, 0xb9, 0xb4, 0xfa, 0xc9, 0xf8, 0x0a, 0x00, 0x00, 0x00,
];

/// Verbatim w51 L compact commissioning body `02 43`, SrcId 0x517f6814.
const AIR_COMM_COMPACT: [u8; 9] = [0x8c, 0x00, 0x14, 0x68, 0x7f, 0x51, 0xe0, 0x02, 0x43];

/// Verbatim w51 B8 reply-window ask: rx-after-tx, 7-octet body.
const AIR_RX_AFTER_TX: [u8; 15] = [
    0x8c, 0x40, 0x16, 0x68, 0x7f, 0x51, 0xe0, 0x02, 0xf3, 0x32, 0x0a, 0x00, 0x00, 0x00, 0x00,
];

/// Verbatim w51 L counter-protected data (`ext 0x30`, counter 0x0f):
/// the section travels in the clear beside the air MIC.
const AIR_DATA_MIC_ONLY: [u8; 16] = [
    0x8c, 0x30, 0x11, 0x68, 0x7f, 0x51, 0x0f, 0x00, 0x00, 0x00, 0x20, 0x01, 0x7a, 0x87, 0x1a, 0xdc,
];

/// Verbatim w51 L encrypted section (command sealed, counter 0x13).
const AIR_DATA_ENCRYPTED: [u8; 16] = [
    0x8c, 0x38, 0x11, 0x68, 0x7f, 0x51, 0x13, 0x00, 0x00, 0x00, 0x51, 0x8b, 0x52, 0xae, 0xb0, 0x21,
];

/// Synthetic test-only key (committed; lab keys stay local-only).
const TEST_KEY: [u8; 16] = [0x5au8; 16];

// ---------------------------------------------------------------------------
// Test-only CCM* sealer (mirrors the crate's open math; lab keys never
// appear here).
// ---------------------------------------------------------------------------

fn test_nonce(srcid: u32, ctr: u32) -> [u8; 13] {
    let id = srcid.to_le_bytes();
    let c = ctr.to_le_bytes();
    [
        id[0], id[1], id[2], id[3], id[0], id[1], id[2], id[3], c[0], c[1], c[2], c[3], 0x05,
    ]
}

fn test_ks(key: &[u8; 16], nonce: &[u8; 13], ctr: u32) -> [u8; 16] {
    use rounddance_security::encrypt_block_aes128;
    let mut blk = [0u8; 16];
    blk[0] = 0x01;
    blk[1..14].copy_from_slice(nonce);
    blk[14..16].copy_from_slice(&(ctr as u16).to_be_bytes());
    encrypt_block_aes128(key, &blk)
}

fn test_tag(key: &[u8; 16], nonce: &[u8; 13], aad_extra: &[u8], msg: &[u8]) -> [u8; 4] {
    use rounddance_security::encrypt_block_aes128;
    let mut b0 = [0u8; 16];
    b0[0] = 0x40 | 0x08 | 0x01;
    b0[1..14].copy_from_slice(nonce);
    b0[14..16].copy_from_slice(&(msg.len() as u16).to_be_bytes());
    let mut mac_in = Vec::new();
    mac_in.extend_from_slice(&(aad_extra.len() as u16).to_be_bytes());
    mac_in.extend_from_slice(aad_extra);
    while mac_in.len() % 16 != 0 {
        mac_in.push(0);
    }
    mac_in.extend_from_slice(msg);
    while mac_in.len() % 16 != 0 {
        mac_in.push(0);
    }
    let mut x = encrypt_block_aes128(key, &b0);
    for blk in mac_in.chunks(16) {
        let mut mix = [0u8; 16];
        for (i, b) in blk.iter().enumerate() {
            mix[i] = x[i] ^ b;
        }
        x = encrypt_block_aes128(key, &mix);
    }
    let s0 = test_ks(key, nonce, 0);
    [x[0] ^ s0[0], x[1] ^ s0[1], x[2] ^ s0[2], x[3] ^ s0[3]]
}

/// Seal one MicOnly GPDF: header + cleartext section + MIC.
fn seal_mic_only(srcid: u32, ctr: u32, key_bit: bool, section: &[u8]) -> Vec<u8> {
    let ext = 0x10 | ((key_bit as u8) << 5);
    let mut header = vec![0x8cu8, ext];
    header.extend_from_slice(&srcid.to_le_bytes());
    header.extend_from_slice(&ctr.to_le_bytes());
    let nonce = test_nonce(srcid, ctr);
    let mut aad_extra = header.clone();
    aad_extra.extend_from_slice(section);
    let tag = test_tag(&TEST_KEY, &nonce, &aad_extra, &[]);
    let mut out = header;
    out.extend_from_slice(section);
    out.extend_from_slice(&tag);
    out
}

/// Seal one Encrypted GPDF: header + ciphertext + MIC.
fn seal_encrypted(srcid: u32, ctr: u32, key_bit: bool, section: &[u8]) -> Vec<u8> {
    let ext = 0x18 | ((key_bit as u8) << 5);
    let mut header = vec![0x8cu8, ext];
    header.extend_from_slice(&srcid.to_le_bytes());
    header.extend_from_slice(&ctr.to_le_bytes());
    let nonce = test_nonce(srcid, ctr);
    let mut ct = vec![0u8; section.len()];
    for (i, chunk) in section.chunks(16).enumerate() {
        let k = test_ks(&TEST_KEY, &nonce, 1 + i as u32);
        for (j, b) in chunk.iter().enumerate() {
            ct[i * 16 + j] = b ^ k[j];
        }
    }
    // The integrity word covers the header plus the plaintext
    // section (ciphertext only travels); the opener checks the same.
    let tag = test_tag(&TEST_KEY, &nonce, &header, section);
    let mut out = header;
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    out
}

fn paired_tables() -> (SinkTable<8>, TranslationTable<8>) {
    let mut sinks = SinkTable::<8>::new();
    sinks
        .upsert(SinkTableEntry::new(AppId::SrcId, 0x517f_6811))
        .unwrap();
    let mut translations = TranslationTable::<8>::new();
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

fn fresh_state() -> (
    GpKeySlots,
    CommissioningSession,
    SinkTable<8>,
    TranslationTable<8>,
    GpReplay<8>,
    [u8; MAX_GP_OPEN],
) {
    let (sinks, translations) = paired_tables();
    (
        GpKeySlots::new(),
        CommissioningSession::new(),
        sinks,
        translations,
        GpReplay::<8>::new(),
        [0u8; MAX_GP_OPEN],
    )
}

// RD-GP-02: verbatim unsecured data through the unified intake lands
// a route-to-NWK handoff for the paired endpoints.
#[test]
fn repro_sink_intake_hands_off_verbatim_data() {
    let (keys, mut session, mut sinks, mut translations, mut replay, mut opened) = fresh_state();
    match receive(
        &AIR_DATA_UNSECURED,
        &keys,
        false,
        &mut session,
        &mut sinks,
        &mut translations,
        &mut replay,
        &mut opened,
    ) {
        SinkDecision::Handoff(h) => {
            assert_eq!(h.gpd, 0x517f_6811);
            assert_eq!(h.profile, 0x0104);
            assert_eq!(h.cluster, 0x0006);
            assert_eq!(h.command, 0x01);
            assert_eq!(h.route, NwkRoute::PairedEndpoints);
        }
        other => panic!("expected handoff, got {:?}", other),
    }
}

// RD-GP-02: the air-model unsecured shapes replay through
// `receive` with the classifier-consistent decision: the
// announcement command sits below the level-gated range, so paired
// GPDs flow through translation while unpaired GPDs have no entry.
#[test]
fn air_model_unsecured_shapes_replay_with_pairing_decision() {
    // The long commissioning body names the paired SrcId: the
    // generic translation covers it like any data command.
    let (keys, mut session, mut sinks, mut translations, mut replay, mut opened) = fresh_state();
    assert!(matches!(
        receive(
            &AIR_COMM_LONG,
            &keys,
            true,
            &mut session,
            &mut sinks,
            &mut translations,
            &mut replay,
            &mut opened
        ),
        SinkDecision::Handoff(_),
    ));
    // The compact body and the reply-window ask name unpaired
    // SrcIds: no entry covers them, so the closed mode drops them
    // while the open mode admits them for commissioning.
    for (frame, gpd) in [
        (&AIR_COMM_COMPACT[..], 0x517f_6814u64),
        (&AIR_RX_AFTER_TX[..], 0x517f_6816u64),
    ] {
        let (keys, mut session, mut sinks, mut translations, mut replay, mut opened) =
            fresh_state();
        assert_eq!(
            receive(
                frame,
                &keys,
                false,
                &mut session,
                &mut sinks,
                &mut translations,
                &mut replay,
                &mut opened
            ),
            SinkDecision::Drop(GpError::NoTableEntry),
        );
        let (keys, mut session, mut sinks, mut translations, mut replay, mut opened) =
            fresh_state();
        assert_eq!(
            receive(
                frame,
                &keys,
                true,
                &mut session,
                &mut sinks,
                &mut translations,
                &mut replay,
                &mut opened
            ),
            SinkDecision::AdmitCommissioning {
                gpd,
                endpoint: 0x00,
                command: 0xe0,
            },
        );
    }
    // Protected shapes without a slotted key: the sink cannot
    // consume them (air-model `secured` stop).
    for frame in [&AIR_DATA_MIC_ONLY[..], &AIR_DATA_ENCRYPTED[..]] {
        let (keys, mut session, mut sinks, mut translations, mut replay, mut opened) =
            fresh_state();
        assert_eq!(
            receive(
                frame,
                &keys,
                false,
                &mut session,
                &mut sinks,
                &mut translations,
                &mut replay,
                &mut opened
            ),
            SinkDecision::Drop(GpError::SecurityFailed),
        );
    }
}

// RD-GP-01: slotted-key open of a MicOnly frame, then the intake
// hands it off; strict key-bit match, wrong key and mutated MIC
// refuse.
#[test]
fn repro_secured_open_hands_off_with_slotted_key() {
    let section = [0x20u8, 0x01];
    let air = seal_mic_only(0x517f_6811, 7, true, &section);
    // No slot: sealed.
    let (keys, mut session, mut sinks, mut translations, mut replay, mut opened) = fresh_state();
    assert_eq!(
        receive(
            &air,
            &keys,
            false,
            &mut session,
            &mut sinks,
            &mut translations,
            &mut replay,
            &mut opened
        ),
        SinkDecision::Drop(GpError::SecurityFailed),
    );
    // Wrong-bit slot only: still sealed.
    let mut keys = GpKeySlots::new();
    keys.set(TEST_KEY, false);
    let (_, mut session, mut sinks, mut translations, mut replay, mut opened) = fresh_state();
    assert_eq!(
        receive(
            &air,
            &keys,
            false,
            &mut session,
            &mut sinks,
            &mut translations,
            &mut replay,
            &mut opened
        ),
        SinkDecision::Drop(GpError::SecurityFailed),
    );
    // Right-bit slot: the paired sink table in the fixture names
    // no security, so the level gate refuses (admission pairs
    // level + key-bit with the table record).
    sinks.find_mut(GpdId::SrcId(0x517f_6811)).unwrap().level = WireSecurityLevel::MicOnly;
    sinks.find_mut(GpdId::SrcId(0x517f_6811)).unwrap().key_bit = true;
    let mut keys = GpKeySlots::new();
    keys.set(TEST_KEY, true);
    match receive(
        &air,
        &keys,
        false,
        &mut session,
        &mut sinks,
        &mut translations,
        &mut replay,
        &mut opened,
    ) {
        SinkDecision::Handoff(h) => assert_eq!(h.command, 0x01),
        other => panic!("expected handoff, got {:?}", other),
    }
    // Mutated MIC under the same slot: refuse.
    let mut bad = air.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    let mut replay2 = GpReplay::<8>::new();
    let mut session2 = CommissioningSession::new();
    assert_eq!(
        receive(
            &bad,
            &keys,
            false,
            &mut session2,
            &mut sinks,
            &mut translations,
            &mut replay2,
            &mut opened
        ),
        SinkDecision::Drop(GpError::SecurityFailed),
    );
}

// RD-GP-01: encrypted level decrypts-then-checks under the slot.
#[test]
fn encrypted_open_decrypts_then_checks() {
    let section = [0x20u8, 0x05];
    let air = seal_encrypted(0x517f_6811, 9, true, &section);
    let mut keys = GpKeySlots::new();
    keys.set(TEST_KEY, true);
    let mut opened = [0u8; MAX_GP_OPEN];
    let n = open_secured(&keys, &air, &mut opened).unwrap();
    assert_eq!(&opened[..n], &section);
    // Ciphertext names no command while sealed: decode alone sees
    // only opaque bytes, the open reveals `0x20`.
    let (frame, _) = Gpdf::decode(&air).unwrap();
    match frame.body {
        GpdfBody::Gp { command, .. } => assert_ne!(command, 0x20),
        GpdfBody::LpedOpaque(_) => panic!("expected GP body"),
    }
}

// RD-GP-02: counter-window dedup — first delivery hands off, the
// replayed counter drops, the advanced counter hands off again.
#[test]
fn repro_replayed_counter_drops_second_delivery() {
    let section = [0x20u8, 0x01];
    let air = seal_mic_only(0x517f_6811, 11, true, &section);
    let mut keys = GpKeySlots::new();
    keys.set(TEST_KEY, true);
    let (_, mut session, mut sinks, mut translations, mut replay, mut opened) = fresh_state();
    sinks.find_mut(GpdId::SrcId(0x517f_6811)).unwrap().level = WireSecurityLevel::MicOnly;
    sinks.find_mut(GpdId::SrcId(0x517f_6811)).unwrap().key_bit = true;
    assert!(matches!(
        receive(
            &air,
            &keys,
            false,
            &mut session,
            &mut sinks,
            &mut translations,
            &mut replay,
            &mut opened
        ),
        SinkDecision::Handoff(_)
    ));
    assert_eq!(
        receive(
            &air,
            &keys,
            false,
            &mut session,
            &mut sinks,
            &mut translations,
            &mut replay,
            &mut opened
        ),
        SinkDecision::Drop(GpError::SecurityFailed),
        "replayed counter drops"
    );
    let next = seal_mic_only(0x517f_6811, 12, true, &section);
    assert!(matches!(
        receive(
            &next,
            &keys,
            false,
            &mut session,
            &mut sinks,
            &mut translations,
            &mut replay,
            &mut opened
        ),
        SinkDecision::Handoff(_)
    ));
}

// RD-GP-03: secured commissioning from an unpaired GPD admits only
// while the commissioning mode is open (SrcId pairing).
#[test]
fn repro_commissioning_admits_only_with_mode_open() {
    let section = [0xe0u8, 0x02, 0x43];
    let air = seal_mic_only(0x517f_9999, 3, false, &section);
    let mut keys = GpKeySlots::new();
    keys.set(TEST_KEY, false);
    // Closed: unknown GPD drops.
    let (_, mut session, mut sinks, mut translations, mut replay, mut opened) = fresh_state();
    assert_eq!(
        receive(
            &air,
            &keys,
            false,
            &mut session,
            &mut sinks,
            &mut translations,
            &mut replay,
            &mut opened
        ),
        SinkDecision::Drop(GpError::NoTableEntry),
    );
    // Open: admits for commissioning.
    let (_, mut session, mut sinks, mut translations, mut replay, mut opened) = fresh_state();
    assert_eq!(
        receive(
            &air,
            &keys,
            true,
            &mut session,
            &mut sinks,
            &mut translations,
            &mut replay,
            &mut opened
        ),
        SinkDecision::AdmitCommissioning {
            gpd: 0x517f_9999,
            endpoint: 0x00,
            command: 0xe0,
        },
    );
    // A replayed commissioning counter still drops while open.
    assert_eq!(
        receive(
            &air,
            &keys,
            true,
            &mut session,
            &mut sinks,
            &mut translations,
            &mut replay,
            &mut opened
        ),
        SinkDecision::Drop(GpError::SecurityFailed),
    );
    // The reply-path range admits the same way once secured: a
    // sealed channel-configuration frame from another unpaired GPD.
    let reply_air = seal_mic_only(0x517f_7777, 1, false, &[0xf3, 0x04]);
    assert_eq!(
        receive(
            &reply_air,
            &keys,
            true,
            &mut session,
            &mut sinks,
            &mut translations,
            &mut replay,
            &mut opened
        ),
        SinkDecision::AdmitCommissioning {
            gpd: 0x517f_7777,
            endpoint: 0x00,
            command: 0xf3,
        },
    );
    // ... while the unsecured reply-path range never reaches
    // admission: the ingress level gate drops it first.
    let bare = [0x8cu8, 0x00, 0x77, 0x77, 0x7f, 0x51, 0xf3, 0x04];
    assert_eq!(
        receive(
            &bare,
            &keys,
            true,
            &mut session,
            &mut sinks,
            &mut translations,
            &mut replay,
            &mut opened
        ),
        SinkDecision::Drop(GpError::UnsecuredCommissioning),
    );
}

// RD-GP-03: IEEE pairing is endpoint-scoped.
#[test]
fn ieee_admission_is_endpoint_scoped() {
    let addr = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let frame = Gpdf {
        fc: NwkFrameControl {
            frame_type: FrameType::Data,
            auto_commissioning: false,
            ext_present: true,
        },
        ext: Some(ExtFrameControl {
            app_id: AppId::Ieee,
            level: WireSecurityLevel::None,
            key_bit: false,
            rx_after_tx: false,
            direction_proxy: false,
        }),
        id: Some(GpdId::Ieee {
            addr,
            endpoint: 0x0A,
        }),
        frame_counter: None,
        body: GpdfBody::Gp {
            command: 0x20,
            payload: &[0x01],
        },
        mic: None,
    };
    let mut buf = [0u8; MAX_GPDF];
    let n = frame.encode_into(&mut buf).unwrap();
    let mut sinks = SinkTable::<4>::new();
    let mut entry = SinkTableEntry::new(AppId::Ieee, u64::from_le_bytes(addr));
    entry.endpoint = 0x0A;
    sinks.upsert(entry).unwrap();
    let mut translations = TranslationTable::<4>::new();
    translations
        .upsert(TranslationTableEntry {
            app: AppId::Ieee,
            gpd: GENERIC_SRC_ID as u64,
            endpoint: 0xFF,
            gpd_command: GENERIC_GPD_COMMAND,
            profile: 0x0104,
            cluster: 0x0006,
            command: 0x01,
            payload_mode: PayloadMode::Fixed,
            payload: [0u8; MAX_TRANSLATION_PAYLOAD],
            payload_len: 0,
            vector: None,
        })
        .unwrap();
    let keys = GpKeySlots::new();
    let mut session = CommissioningSession::new();
    let mut replay = GpReplay::<4>::new();
    let mut opened = [0u8; MAX_GP_OPEN];
    assert!(matches!(
        receive(
            &buf[..n],
            &keys,
            false,
            &mut session,
            &mut sinks,
            &mut translations,
            &mut replay,
            &mut opened
        ),
        SinkDecision::Handoff(_)
    ));
    // A frame from the same address on another endpoint is unknown.
    let frame2 = Gpdf {
        id: Some(GpdId::Ieee {
            addr,
            endpoint: 0x0B,
        }),
        ..frame
    };
    let n2 = frame2.encode_into(&mut buf).unwrap();
    let mut replay2 = GpReplay::<4>::new();
    assert_eq!(
        receive(
            &buf[..n2],
            &keys,
            false,
            &mut session,
            &mut sinks,
            &mut translations,
            &mut replay2,
            &mut opened
        ),
        SinkDecision::Drop(GpError::NoTableEntry),
    );
}

// RD-GP-04: group-bound entries hand a groupcast route to NWK.
#[test]
fn group_forward_hands_groupcast_route() {
    let (keys, mut session, mut sinks, mut translations, mut replay, mut opened) = fresh_state();
    let entry = sinks.find_mut(GpdId::SrcId(0x517f_6811)).unwrap();
    entry.group_forward = true;
    entry.groups[0] = 0x1234;
    entry.group_count = 1;
    match receive(
        &AIR_DATA_UNSECURED,
        &keys,
        false,
        &mut session,
        &mut sinks,
        &mut translations,
        &mut replay,
        &mut opened,
    ) {
        SinkDecision::Handoff(h) => {
            assert_eq!(h.route, NwkRoute::Groupcast(0x1234));
            assert_eq!(h.command, 0x20);
            assert_eq!(h.payload_bytes(), &[0x01]);
        }
        other => panic!("expected groupcast handoff, got {:?}", other),
    }
}

// RD-GP-05: the GPD's Success frame completes a parked bidirectional
// session through the intake: tables install, then data hands off.
#[test]
fn repro_success_completes_parked_session() {
    let mut session = CommissioningSession::new();
    session.begin(CommissioningAnnouncement {
        app: AppId::SrcId,
        gpd: 0x517f_6811,
        endpoint: 0x00,
        pan_id_request: true,
        key_request: false,
        rx_after_tx: true,
        security_capable: false,
        key_present: false,
    });
    assert_eq!(
        session.complete_at(0).unwrap_err(),
        GpError::BidirectionalPending
    );
    session
        .stage_reply(CommissioningReply {
            options: ReplyOptions {
                pan_id_present: true,
                key_present: false,
                key_encrypted: false,
                level: 0,
                key_type: 0,
            },
            pan_id: Some(0x1a2b),
            key: None,
            key_mic: None,
            frame_counter: None,
        })
        .unwrap();
    // Success from a foreign GPD is refused ...
    let foreign = [0x8cu8, 0x00, 0x99, 0x99, 0x99, 0x99, 0xe2];
    let keys = GpKeySlots::new();
    let mut sinks = SinkTable::<8>::new();
    let mut translations = TranslationTable::<8>::new();
    let mut replay = GpReplay::<8>::new();
    let mut opened = [0u8; MAX_GP_OPEN];
    assert_eq!(
        receive(
            &foreign,
            &keys,
            true,
            &mut session,
            &mut sinks,
            &mut translations,
            &mut replay,
            &mut opened
        ),
        SinkDecision::Drop(GpError::TransactionMismatch),
    );
    // ... while the matching Success commissions and pairs.
    let success = [0x8cu8, 0x00, 0x11, 0x68, 0x7f, 0x51, 0xe2];
    assert_eq!(
        receive(
            &success,
            &keys,
            true,
            &mut session,
            &mut sinks,
            &mut translations,
            &mut replay,
            &mut opened
        ),
        SinkDecision::Commissioned {
            gpd: 0x517f_6811,
            endpoint: 0x00,
        },
    );
    assert!(sinks.find(GpdId::SrcId(0x517f_6811)).is_some());
    // The paired GPD's data now hands off via the seeded default.
    match receive(
        &AIR_DATA_UNSECURED,
        &keys,
        false,
        &mut session,
        &mut sinks,
        &mut translations,
        &mut replay,
        &mut opened,
    ) {
        SinkDecision::Handoff(h) => assert_eq!(h.route, NwkRoute::PairedEndpoints),
        other => panic!("expected handoff, got {:?}", other),
    }
}

// RD-GP-02: foreign shapes drop with the classifier's reason.
#[test]
fn foreign_shapes_drop_with_classifier_reason() {
    // LPED body: recognized, handled on its own path.
    let lped = [0x8cu8, 0x01, 0xAA, 0xBB];
    // Proxy-originated direction.
    let proxy = [0x8cu8, 0x80, 0x11, 0x68, 0x7f, 0x51, 0x20];
    // Bare maintenance frame: no identity to admit.
    let maint = [0x0du8, 0x10, 0xAA];
    // Truncated frame.
    let short = [0x8cu8];
    for (frame, want) in [
        (&lped[..], GpError::ForeignAppId(0x01)),
        (&proxy[..], GpError::ProxyOriginated),
        (&maint[..], GpError::NoTableEntry),
        (&short[..], GpError::Truncated),
    ] {
        let (keys, mut session, mut sinks, mut translations, mut replay, mut opened) =
            fresh_state();
        assert_eq!(
            receive(
                frame,
                &keys,
                true,
                &mut session,
                &mut sinks,
                &mut translations,
                &mut replay,
                &mut opened
            ),
            SinkDecision::Drop(want),
        );
    }
}
