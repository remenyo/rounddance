//! Requirement-anchored test vectors: classical auxiliary-header
//! codec, key lifecycle, counters, replay/link-key tables, NVM resume,
//! and CBKE known answers.
//!
//! Provenance:
//! * Classical vectors are hand-computed from the codec rules in
//!   `rounddance-security/src/classical.rs` (implementation-defined
//!   layout, paraphrase of doc `05-3474-23` R23.2 ch4).
//! * `HOST` vectors were derived 2026-10-27 from the `host` reference
//!   backend (p256 0.14 + sha2 + hmac) with ECQV-consistent
//!   provisioning `w = e*d_CA + k`; they pin real-curve agreement,
//!   never interop with another stack.
//! * `MOCK` vectors pin determinism of the mock backend only.

use rounddance_security::*;

// 05-3474-23-451-01 + 05-3474-23-4514-01: DataKey mode, level 5, counter 0x12345678. The data key is implicit, so no trailing
// octet follows: control 0x05 | counter LE, 5 octets total.
#[test]
fn vector_aux_data_key() {
    let header = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::DataKey, false).unwrap(),
        frame_counter: 0x1234_5678,
        ext_source: None,
        key_id: KeyIdentifier::DataKey,
    };
    assert_eq!(header.header_len(), Some(5));
    let mut out = [0u8; MAX_AUX_LEN];
    let n = header.encode_into(&mut out).unwrap();
    assert_eq!(n, 5);
    assert_eq!(&out[..n], &[0x05, 0x78, 0x56, 0x34, 0x12]);
    let (back, used) = AuxHeader::decode(&out[..n]).unwrap();
    assert_eq!((back, used), (header, n));
}

// 05-3474-23-4514-01: the key sequence number octet is present
// only under the network-key bits (§4.5.1.4 Figure 4-24: the aux is
// control + counter + source 0/8 + sequence-number 0/1). Data-key
// headers are 5 octets bare (13 with the extended-nonce source);
// network-key headers carry the one sequence octet (6 / 14).
// A trailing octet after a data-key header belongs to the payload.
#[test]
fn vector_aux_mode0_no_trailing_octet_05_3474_23_4514_01() {
    let bare = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::DataKey, false).unwrap(),
        frame_counter: 0x0102_0304,
        ext_source: None,
        key_id: KeyIdentifier::DataKey,
    };
    assert_eq!(bare.header_len(), Some(5));
    let mut out = [0u8; MAX_AUX_LEN];
    let n = bare.encode_into(&mut out).unwrap();
    assert_eq!(n, 5);
    assert_eq!(&out[..n], &[0x05, 0x04, 0x03, 0x02, 0x01]);
    let (back, used) = AuxHeader::decode(&out[..n]).unwrap();
    assert_eq!((back, used), (bare, 5));

    let ext = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::DataKey, true).unwrap(),
        frame_counter: 0x0102_0304,
        ext_source: Some([0x77; 8]),
        key_id: KeyIdentifier::DataKey,
    };
    assert_eq!(ext.header_len(), Some(13));
    let m = ext.encode_into(&mut out).unwrap();
    assert_eq!(m, 13);
    assert_eq!(out[0], 0x25);
    assert_eq!(&out[5..13], &[0x77; 8]);
    let (eback, eused) = AuxHeader::decode(&out[..m]).unwrap();
    assert_eq!((eback, eused), (ext, 13));

    // Network-key contrast: the same control/counter shape with
    // the mode-1 bits carries exactly one sequence octet.
    let net = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::Index, false).unwrap(),
        frame_counter: 0x0102_0304,
        ext_source: None,
        key_id: KeyIdentifier::Index(0x09),
    };
    assert_eq!(net.header_len(), Some(6));
    let k = net.encode_into(&mut out).unwrap();
    assert_eq!(k, 6);
    assert_eq!(&out[..k], &[0x0d, 0x04, 0x03, 0x02, 0x01, 0x09]);
    let (nback, nused) = AuxHeader::decode(&out[..k]).unwrap();
    assert_eq!((nback, nused), (net, 6));

    // Four octets are not a bare data-key header.
    assert_eq!(AuxHeader::decode(&out[..4]), Err(SecError::Truncated));
    // Data-key control bits with a network-key identifier disagree.
    let mixed = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::DataKey, false).unwrap(),
        frame_counter: 0,
        ext_source: None,
        key_id: KeyIdentifier::Index(0x09),
    };
    assert_eq!(mixed.header_len(), None);
}

// 05-3474-23-451-01: Index mode, level 1, counter 0, index 7.
#[test]
fn vector_aux_index() {
    let header = AuxHeader {
        control: SecurityControl::new(1, KeyIdMode::Index, false).unwrap(),
        frame_counter: 0,
        ext_source: None,
        key_id: KeyIdentifier::Index(0x07),
    };
    let mut out = [0u8; MAX_AUX_LEN];
    let n = header.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], &[0x09, 0x00, 0x00, 0x00, 0x00, 0x07]);
    let (back, used) = AuxHeader::decode(&out[..n]).unwrap();
    assert_eq!((back, used), (header, n));
}

// 05-3474-23-451-01: Source4 mode, level 3, counter 0xAABBCCDD.
#[test]
fn vector_aux_source4() {
    let header = AuxHeader {
        control: SecurityControl::new(3, KeyIdMode::Source4, false).unwrap(),
        frame_counter: 0xAABB_CCDD,
        ext_source: None,
        key_id: KeyIdentifier::Source4([0x11, 0x22, 0x33, 0x44], 0x09),
    };
    assert_eq!(header.header_len(), Some(10));
    let mut out = [0u8; MAX_AUX_LEN];
    let n = header.encode_into(&mut out).unwrap();
    assert_eq!(
        &out[..n],
        &[0x13, 0xDD, 0xCC, 0xBB, 0xAA, 0x11, 0x22, 0x33, 0x44, 0x09]
    );
    let (back, used) = AuxHeader::decode(&out[..n]).unwrap();
    assert_eq!((back, used), (header, n));
}

// 05-3474-23-451-01: Source8 mode + extended nonce, level 2.
// control = 2 | (3 << 3) | (1 << 5) = 0x3A; total 22 octets.
#[test]
fn vector_aux_source8_ext_nonce() {
    let header = AuxHeader {
        control: SecurityControl::new(2, KeyIdMode::Source8, true).unwrap(),
        frame_counter: 1,
        ext_source: Some([0xAA; 8]),
        key_id: KeyIdentifier::Source8([0xBB; 8], 0x02),
    };
    assert_eq!(header.header_len(), Some(22));
    let mut out = [0u8; MAX_AUX_LEN];
    let n = header.encode_into(&mut out).unwrap();
    assert_eq!(n, 22);
    assert_eq!(out[0], 0x3A);
    assert_eq!(&out[1..5], &[1, 0, 0, 0]);
    assert_eq!(&out[5..13], &[0xAA; 8]);
    assert_eq!(&out[13..21], &[0xBB; 8]);
    assert_eq!(out[21], 0x02);
    let (back, used) = AuxHeader::decode(&out[..n]).unwrap();
    assert_eq!((back, used), (header, n));
}

// 05-3474-23-451-01: truncated inputs are fallible, never panics.
#[test]
fn vector_aux_truncation() {
    let full = [0x3Au8; 22];
    for len in 0..22 {
        assert!(
            AuxHeader::decode(&full[..len]).is_err(),
            "len {len} must fail"
        );
    }
    // Flag/shape mismatch: control claims extended nonce, none given.
    let bad = AuxHeader {
        control: SecurityControl::new(0, KeyIdMode::DataKey, true).unwrap(),
        frame_counter: 0,
        ext_source: None,
        key_id: KeyIdentifier::DataKey,
    };
    assert_eq!(bad.header_len(), None);
    let mut out = [0u8; MAX_AUX_LEN];
    assert!(bad.encode_into(&mut out).is_err());
    // Level is 3 bits.
    assert!(SecurityControl::new(8, KeyIdMode::DataKey, false).is_none());
}

// 05-3474-23-453-01 + 05-3474-23-446-01: key lifecycle end to end.
#[test]
fn vector_key_lifecycle() {
    let mut set = KeySet::new(NetworkKey::new([0x10; NETWORK_KEY_LEN], 4));
    assert_eq!(set.active().seq, 4);
    set.install_pending(NetworkKey::new([0x20; NETWORK_KEY_LEN], 5))
        .unwrap();
    // Both resolve during staging; unknown resolves to nothing.
    assert_eq!(set.select(4).unwrap().key, [0x10; NETWORK_KEY_LEN]);
    assert_eq!(set.select(5).unwrap().key, [0x20; NETWORK_KEY_LEN]);
    assert!(set.select(6).is_none());
    set.activate_pending().unwrap();
    assert_eq!(set.active().seq, 5);
    assert!(set.select(4).is_none());
}

// 05-3474-23-4311-01 + 05-3474-23-4312-01: outgoing + incoming counters agree on ordering.
#[test]
fn vector_counter_replay_pair() {
    let mut tx = FrameCounter::new(100, 8);
    let mut rx = ReplayTable::<4>::new();
    for _ in 0..3 {
        let c = tx.take().unwrap();
        rx.check(0xDEAD_BEEF, c).unwrap();
    }
    // Replay of any accepted value fails; next fresh value passes.
    assert_eq!(rx.check(0xDEAD_BEEF, 101), Err(SecError::Replay));
    let c = tx.take().unwrap();
    assert_eq!(c, 103);
    rx.check(0xDEAD_BEEF, c).unwrap();
}

// 05-3474-23-4312-01: full neighbor table evicts the stalest entry.
#[test]
fn vector_replay_eviction() {
    let mut t = ReplayTable::<2>::new();
    t.check(1, 10).unwrap();
    t.check(2, 20).unwrap();
    // New neighbor evicts addr 1 (smallest counter 10).
    t.check(3, 30).unwrap();
    assert!(t.last(1).is_none());
    assert_eq!(t.last(2), Some(20));
    assert_eq!(t.last(3), Some(30));
}

// 05-3474-23-462-01: Trust-Center link-key table + per-peer counters.
#[test]
fn vector_link_key_table() {
    let mut table = LinkKeyTable::<2>::new();
    assert!(table.is_empty());
    table
        .insert(LinkKeyEntry::new([0x01; 8], [0xAA; NETWORK_KEY_LEN]))
        .unwrap();
    table
        .insert(LinkKeyEntry::new([0x02; 8], [0xBB; NETWORK_KEY_LEN]))
        .unwrap();
    assert_eq!(table.len(), 2);
    assert!(table
        .insert(LinkKeyEntry::new([0x03; 8], [0xCC; 16]))
        .is_err());
    let entry = table.find_mut(&[0x01; 8]).unwrap();
    assert_eq!(entry.tx_take().unwrap(), 0);
    assert_eq!(entry.tx_take().unwrap(), 1);
    entry.rx_check(9).unwrap();
    assert_eq!(entry.rx_check(9), Err(SecError::Replay));
    assert_eq!(entry.rx_check(4), Err(SecError::Replay));
    entry.rx_check(10).unwrap();
    table.remove(&[0x02; 8]).unwrap();
    assert!(table.find(&[0x02; 8]).is_none());
    assert_eq!(table.remove(&[0x02; 8]), Err(SecError::NotFound));
}

// 05-3474-23-434-01: boot resumes past the rollback stride.
#[test]
fn vector_nvm_resume_stride() {
    use rounddance_security::store::PersistedState;
    let saved = PersistedState {
        outgoing_next: 2048,
    };
    assert_eq!(saved.resume_next(), 2048 + COUNTER_STRIDE);
    // A counter resumed there hands out fresh values only.
    let mut tx = FrameCounter::new(0, 1);
    tx.resume(saved.resume_next());
    assert_eq!(tx.peek(), 2048 + COUNTER_STRIDE);
}

// 07-5356-C42-03/04/05/06 HOST: two-sided handshake known answers.
// Derived 2026-10-27 from the `host` reference backend (p256 0.14 +
// sha2 + hmac); ECQV-consistent provisioning w = e*d_CA + k with
// ca_priv=[0xC0;32], initiator cert=[0xA1;48] subj=[1;8] k=[0x11;32]
// eph=[0x22;32], responder cert=[0xB2;48] subj=[2;8] k=[0x33;32]
// eph=[0x55;32]. Pins real-curve agreement, not cross-stack interop.
#[cfg(feature = "host")]
#[test]
fn vector_host_handshake_known_answers() {
    use rounddance_security::backend_host::HostBackend;
    use rounddance_security::ecc::{reconstruct_static, scalar_from_kdf};

    fn fill(v: u8) -> [u8; 32] {
        [v; 32]
    }
    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }

    let b = HostBackend::new();
    let ca_priv = fill(0xC0);
    let ca_pub: [u8; 64] = unhex("9d795fd58f42ef03f85d46a6ef15d60f6b153dbd4cbc50b9cb239bfd687291f14ea44c94bc57388e4f0b92eafe1b11f3b9ee3551373d5494ae7e2e0d90200e40");
    assert_eq!(b.base_mul(&ca_priv).unwrap(), ca_pub);

    // ECQV-consistent device keys, recomputed here (not trusted).
    let device = |cert_byte: u8, subj: u8, k_byte: u8| {
        let cert = ImplicitCert::from_bytes([cert_byte; 48]);
        let k = fill(k_byte);
        let p = b.base_mul(&k).unwrap();
        let subj_arr = [subj; 8];
        let e =
            scalar_from_kdf(&b, &[cert.as_bytes(), &subj_arr, &p], b"ecqv-reconstruct").unwrap();
        let w = b
            .scalar_add(&b.scalar_mul(&e, &ca_priv).unwrap(), &k)
            .unwrap();
        (w, PeerIdentity::new(cert, subj_arr, p))
    };
    let (w_i, id_i) = device(0xA1, 0x01, 0x11);
    let (w_r, id_r) = device(0xB2, 0x02, 0x33);
    assert_eq!(
        hex_of(&w_i),
        "639da7c74c7f8dd6388597b5dffbbd19fe5acd587841a7cfa9dcf6986312374b"
    );
    assert_eq!(
        hex_of(&w_r),
        "91fe8f6f29088aa8bb0d743acb064e690b12b46b869c4f0500d9f4ff471a945a"
    );

    // Reconstruction reproduces the provisioned public keys.
    let rec_r: [u8; 64] = unhex("a6363902da41648c34ebf4f530f1d4ab5876875be2d2f9d5b90eef91f8a92fe4eff0511e284b535e7419b247b6ae478c42a94dce53746360870a8b7663ec69a1");
    let rec_i: [u8; 64] = unhex("068d0b8d65a02a1f9a8d10c29bebd204cac035f30e1bdfd78a3235d3f9ffa3e088a95cc4f8294eef198d170aa042164b8354d1454c037fdfef697f56409a187a");
    assert_eq!(reconstruct_static(&b, &ca_pub, &id_r).unwrap(), rec_r);
    assert_eq!(reconstruct_static(&b, &ca_pub, &id_i).unwrap(), rec_i);
    assert_eq!(b.base_mul(&w_r).unwrap(), rec_r);
    assert_eq!(b.base_mul(&w_i).unwrap(), rec_i);

    // Full two-sided handshake: identical session keys, known MACs.
    let e_i = fill(0x22);
    let e_r = fill(0x55);
    let q_i = b.base_mul(&e_i).unwrap();
    let q_r = b.base_mul(&e_r).unwrap();
    let mut si = CbkeSession::new(Role::Initiator, ca_pub, w_i, id_i);
    let mut sr = CbkeSession::new(Role::Responder, ca_pub, w_r, id_r);
    si.set_ephemeral(e_i, q_i).unwrap();
    sr.set_ephemeral(e_r, q_r).unwrap();
    si.receive_peer(id_r, q_r).unwrap();
    sr.receive_peer(id_i, q_i).unwrap();
    si.reconstruct(&b).unwrap();
    sr.reconstruct(&b).unwrap();
    si.derive(&b).unwrap();
    sr.derive(&b).unwrap();
    let mac_u = si.local_confirm(&b).unwrap();
    assert_eq!(hex_of(&mac_u), "51b8cf4784e88d767db6a0db14e0bc2a");
    sr.check_peer(&b, &mac_u).unwrap();
    let mac_v = sr.local_confirm(&b).unwrap();
    assert_eq!(hex_of(&mac_v), "06baeb9f1769b57df93dabad87160af8");
    si.check_peer(&b, &mac_v).unwrap();
    assert_eq!(si.state(), CbkeState::Done);
    assert_eq!(sr.state(), CbkeState::Done);
    let key_i = si.session_key().unwrap();
    let key_r = sr.session_key().unwrap();
    assert_eq!(key_i, key_r);
    assert_eq!(hex_of(&key_i), "38fe4c43f73d6263f6d2f69af15f9869");

    // A tampered tag fails confirmation and wipes the session.
    let mut bad = mac_u;
    bad[0] ^= 0x01;
    let mut si2 = CbkeSession::new(Role::Initiator, ca_pub, w_i, id_i);
    si2.set_ephemeral(e_i, q_i).unwrap();
    si2.receive_peer(id_r, q_r).unwrap();
    si2.reconstruct(&b).unwrap();
    si2.derive(&b).unwrap();
    si2.local_confirm(&b).unwrap();
    assert_eq!(si2.check_peer(&b, &bad), Err(CbkeError::ConfirmMismatch));
    assert_eq!(si2.state(), CbkeState::Failed);
}

#[cfg(feature = "host")]
fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{:02x}", x)).collect()
}

// MOCK: same handshake inputs always produce the same tags.
#[test]
fn vector_mock_determinism() {
    use rounddance_security::ecc::{confirm_tag, mqv_agree, reconstruct_static, scalar_from_kdf};
    use rounddance_security::mock::MockBackend;

    let b = MockBackend::new(0x1234);
    let run = || {
        let ca = b.base_mul(&[0xCA; 32]).unwrap();
        let peer = PeerIdentity::new(
            ImplicitCert::from_bytes([0x44; 48]),
            [0x44; 8],
            b.base_mul(&[0x44; 32]).unwrap(),
        );
        let q = reconstruct_static(&b, &ca, &peer).unwrap();
        let e = scalar_from_kdf(&b, &[b"side"], b"d").unwrap();
        let z = mqv_agree(
            &b,
            &[0x11; 32],
            &[0x22; 32],
            &q,
            &b.base_mul(&[0x55; 32]).unwrap(),
            &e,
            &e,
        )
        .unwrap();
        let mut link = [0u8; 16];
        let (mut u, mut v) = ([0u8; 16], [0u8; 16]);
        session_keys(&b, &z, b"mock-transcript", &mut link, &mut u, &mut v).unwrap();
        let mut tag = [0u8; 16];
        confirm_tag(&b, &u, b"mock-transcript", &mut tag).unwrap();
        (q, z, link, tag)
    };
    assert_eq!(run(), run());
    // A different seed must not collide (avalanche sanity).
    let other = MockBackend::new(0x5678);
    let ca = other.base_mul(&[0xCA; 32]).unwrap();
    let peer = PeerIdentity::new(
        ImplicitCert::from_bytes([0x44; 48]),
        [0x44; 8],
        other.base_mul(&[0x44; 32]).unwrap(),
    );
    let q2 = reconstruct_static(&other, &ca, &peer).unwrap();
    assert_ne!(run().0, q2);
}

// 05-3474-23-B11-01: published AES-128 cipher check. Key 00..0f,
// plaintext 001122..ffee → ciphertext 69c4e0d8 6a7b0430 d8cdb780 70b4c55a.
#[test]
fn vector_aes128_published_cipher_check() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let plain = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    assert_eq!(
        encrypt_block_aes128(&key, &plain),
        [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a
        ]
    );
}

// 22-65816-030-56-08: BDB §6.11.1.2 worked key. The AES-MMO-128 hash
// of the 18-octet install code 83FE..C3B5 (anchor p0041-L828-L834)
// must produce 66B6900981E1EE3CA4206B6B861C02BB.
#[test]
fn vector_install_code_mmo_worked_key_22_65816_030_56_08() {
    let code = [
        0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23, 0xA5, 0xC6, 0x39, 0xB2, 0x69, 0x16, 0xD5,
        0x05, 0xC3, 0xB5,
    ];
    assert_eq!(
        mmo_hash_128(&code).unwrap(),
        [
            0x66, 0xB6, 0x90, 0x09, 0x81, 0xE1, 0xEE, 0x3C, 0xA4, 0x20, 0x6B, 0x6B, 0x86, 0x1C,
            0x02, 0xBB
        ]
    );
    assert_eq!(mmo_hash_128(&[0u8; 65]).unwrap_err(), MmoError::TooLong);
}

// 07-5356-C41-02: MMO-derived link-key update. Mask for ieee [9;8],
// nonce 42 is pinned (AES-MMO-128 of 55 AA || ieee || nonce LE);
// rotation xors the old key, installs with reset counters, and a
// repeat install of the identical key is refused.
#[test]
fn vector_link_key_update_07_5356_c41_02() {
    let mask = derive_update_mask(&[9; 8], 42).unwrap();
    assert_eq!(
        mask,
        [
            0x61, 0xed, 0x53, 0xda, 0x9f, 0x04, 0xdd, 0x22, 0x76, 0x33, 0x40, 0xcd, 0x71, 0x78,
            0xba, 0x3f
        ]
    );
    let old = [0x11u8; 16];
    let new = derive_update_key(&old, &[9; 8], 42);
    let mut expect = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        expect[i] = old[i] ^ mask[i];
        i += 1;
    }
    assert_eq!(new, expect);
    assert_ne!(new, old);
    let mut table = LinkKeyTable::<4>::new();
    install_link_key(&mut table, [9; 8], new).unwrap();
    let entry = table.find(&[9; 8]).unwrap();
    assert_eq!(entry.key, new);
    assert_eq!((entry.tx_counter, entry.rx_counter), (0, 0));
    assert_eq!(
        install_link_key(&mut table, [9; 8], new),
        Err(SecError::DuplicateKey)
    );
}

// 05-3474-23-451-01: level-0 reception. Captured post-association
// coordinator traffic (NWK data frame, plaintext APS command id
// 0x30): the auxiliary header is the lone control octet 0x00 — no
// counter, no key identifier, no MIC — and the payload starts at the
// very next octet. `AuxReception::decode` consumes exactly one octet
// and routes to `Plaintext`; the secured-shape `AuxHeader::decode`
// would misread payload as a counter, so RX must not use it here.
#[test]
fn vector_aux_level0_plaintext_reception() {
    // Auxiliary header + plaintext exactly as captured on air: the
    // coordinator's post-association vendor command. Only the shape
    // (one control octet, then plaintext) is load-bearing below.
    let aux_and_plain: [u8; 51] = [
        0x00, 0x10, 0x00, 0x00, 0x6d, 0x49, 0x11, 0xfe, 0xff, 0x13, 0x8d, 0x34, 0x52, 0x98, 0xd2,
        0x8c, 0x21, 0xe4, 0xf9, 0xe5, 0xb7, 0xd4, 0x56, 0x0c, 0x5b, 0xaa, 0xec, 0x1c, 0x0b, 0xdb,
        0xa7, 0x1b, 0xec, 0x94, 0xb5, 0xa2, 0x77, 0x53, 0xab, 0xa1, 0x0d, 0xda, 0x1c, 0x27, 0x7a,
        0x04, 0xfd, 0xf9, 0x42, 0x9d, 0x87,
    ];
    let (rx, used) = AuxReception::decode(&aux_and_plain).unwrap();
    assert!(rx.is_plaintext());
    assert_eq!(used, 1);
    let control = rx.control();
    assert_eq!(control.level, UNSECURED_LEVEL);
    assert_eq!(control.key_id, KeyIdMode::DataKey);
    assert!(!control.extended_nonce);
    // The payload starts at the next octet (the tag octet the field
    // capture read at header+1); nothing was consumed as a counter
    // and 50 plaintext octets remain.
    assert_eq!(&aux_and_plain[used..used + 4], &[0x10, 0x00, 0x00, 0x6d]);
    assert_eq!(aux_and_plain.len() - used, 50);
}

// 05-3474-23-451-01: every level-0 control shape (level bits zero,
// any key-id/ext bits) decodes as one-octet plaintext; secured
// levels still take the full secured shape; empty input is truncated.
#[test]
fn vector_aux_level0_all_control_shapes() {
    for ctrl in [0x00u8, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38] {
        let buf = [ctrl, 0xAA, 0xBB];
        let (rx, used) = AuxReception::decode(&buf).unwrap();
        assert!(rx.is_plaintext(), "ctrl 0x{ctrl:02x}");
        assert_eq!(used, 1);
        assert_eq!(rx.control().level, UNSECURED_LEVEL);
    }
    // Secured shape still routes the long way: control 0x05 (level 5,
    // DataKey) + counter, 5 octets; the sixth octet is payload, not
    // a sequence number.
    let secured = [0x05u8, 0x78, 0x56, 0x34, 0x12, 0x03];
    let (rx, used) = AuxReception::decode(&secured).unwrap();
    assert!(!rx.is_plaintext());
    assert_eq!(used, 5);
    assert_eq!(secured[used], 0x03);
    assert_eq!(AuxReception::decode(&[]), Err(SecError::Truncated));
}

// Wave-36 NWK decrypt-gap vectors (new behavior `05-3474-23-431-01`
// + `05-3474-23-4522-01`).
//
// Provenance: genuine over-the-air Ember frames captured from the
// lab MG21 coordinator (PAN 0xB21D, channel 25) during formation
// traffic, with the lab network key captured alongside. U1 is a
// secured NWK command unicast (dst 0x021d, NWK seq 0x44); B1 is a
// secured NWK command broadcast (dst 0xfffc routers, NWK seq 0x3d).
// Both carry the on-air zeroed level octet 0x28 (network key,
// extended nonce): the wave-33 off-repo scripts fed 0x28 into the
// nonce/AAD and every open failed, which is the (b)-class gap this
// closes — receivers must restore the network-base level (5) first.
//
// The embedded key is the retired lab-capture key for PAN 0xB21D
// only; it pins this interop vector and must never ship as a
// default or test key elsewhere.
const EMBER_LAB_KEY: [u8; 16] = [
    0x86, 0x8e, 0x5c, 0xd4, 0x56, 0x98, 0x93, 0x1d, 0xf4, 0x95, 0xec, 0x8c, 0x66, 0x95, 0x70, 0xab,
];
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

fn ember_parts(frame: &[u8; 45]) -> (&[u8], &[u8], &[u8]) {
    (&frame[9..25], &frame[25..39], &frame[39..])
}

/// Test-local CCM\* open (MIC-32, 2-octet length field) over the
/// crate block cipher. Production keeps payload crypto in the radio
/// assist; this helper only lets the interop vector prove the
/// nonce/AAD construction end to end.
fn ccm_star_open(key: &[u8; 16], nonce13: &[u8; 13], aad: &[u8], ct_tag: &[u8]) -> Option<Vec<u8>> {
    if ct_tag.len() < 4 {
        return None;
    }
    let (ct, tag) = ct_tag.split_at(ct_tag.len() - 4);
    let keystream = |ctr: u32| -> [u8; 16] {
        let mut blk = [0u8; 16];
        blk[0] = 0x01;
        blk[1..14].copy_from_slice(nonce13);
        blk[14..16].copy_from_slice(&(ctr as u16).to_be_bytes());
        encrypt_block_aes128(key, &blk)
    };
    let mut pt = vec![0u8; ct.len()];
    for (i, chunk) in ct.chunks(16).enumerate() {
        let ks = keystream(1 + i as u32);
        for (j, b) in chunk.iter().enumerate() {
            pt[i * 16 + j] = b ^ ks[j];
        }
    }
    // CBC-MAC over: B0 (flags M=4 L=2, nonce, message length) then
    // length-prefixed AAD and the candidate plaintext, each padded
    // separately to the block edge.
    let mut b0 = [0u8; 16];
    b0[0] = 0x40 | 0x08 | 0x01;
    b0[1..14].copy_from_slice(nonce13);
    b0[14..16].copy_from_slice(&(pt.len() as u16).to_be_bytes());
    let mut mac_in = Vec::new();
    if !aad.is_empty() {
        mac_in.extend_from_slice(&(aad.len() as u16).to_be_bytes());
        mac_in.extend_from_slice(aad);
        while mac_in.len() % 16 != 0 {
            mac_in.push(0);
        }
    }
    mac_in.extend_from_slice(&pt);
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
    let s0 = keystream(0);
    let mut expect = [0u8; 4];
    for (i, e) in expect.iter_mut().enumerate() {
        *e = x[i] ^ s0[i];
    }
    if expect == tag {
        Some(pt)
    } else {
        None
    }
}

/// Test-local CCM\* seal, mirror of [`ccm_star_open`]: only feeds the
/// positive roundtrip leg below.
fn ccm_star_seal(key: &[u8; 16], nonce13: &[u8; 13], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let keystream = |ctr: u32| -> [u8; 16] {
        let mut blk = [0u8; 16];
        blk[0] = 0x01;
        blk[1..14].copy_from_slice(nonce13);
        blk[14..16].copy_from_slice(&(ctr as u16).to_be_bytes());
        encrypt_block_aes128(key, &blk)
    };
    let mut ct = vec![0u8; pt.len()];
    for (i, chunk) in pt.chunks(16).enumerate() {
        let ks = keystream(1 + i as u32);
        for (j, b) in chunk.iter().enumerate() {
            ct[i * 16 + j] = b ^ ks[j];
        }
    }
    let mut b0 = [0u8; 16];
    b0[0] = 0x40 | 0x08 | 0x01;
    b0[1..14].copy_from_slice(nonce13);
    b0[14..16].copy_from_slice(&(pt.len() as u16).to_be_bytes());
    let mut mac_in = Vec::new();
    if !aad.is_empty() {
        mac_in.extend_from_slice(&(aad.len() as u16).to_be_bytes());
        mac_in.extend_from_slice(aad);
        while mac_in.len() % 16 != 0 {
            mac_in.push(0);
        }
    }
    mac_in.extend_from_slice(pt);
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
    let s0 = keystream(0);
    for i in 0..4 {
        ct.push(x[i] ^ s0[i]);
    }
    ct
}

/// Restored aux header octets for AAD: the on-air aux with the
/// network-base level written back into the control octet.
fn restored_aux(aux: &[u8], level: u8, header: &AuxHeader) -> Vec<u8> {
    let mut out = aux.to_vec();
    out[0] = header.control.as_octet();
    assert_eq!(header.control.level, level);
    out
}

// 05-3474-23-431-01 + 05-3474-23-4522-01: the genuine Ember frames
// open with the lab network key once the zeroed on-air level is
// restored to the network-base level 5. Raw decode still sees the
// on-air level 0 (the wave-33 trap); `decode_with_level` + the
// 13-octet nonce builder close it.
#[test]
fn vector_nwk_ember_zeroed_level_opens() {
    let keys = KeySet::new(NetworkKey::new(EMBER_LAB_KEY, 0));
    for (frame, ctr, plain) in [
        (&EMBER_U1, 0x0000_4004u32, [0x04u8, 0x60]),
        (&EMBER_B1, 0x0000_4000u32, [0x08u8, 0x60]),
    ] {
        let (nwk, aux, ct) = ember_parts(frame);
        // On-air control 0x28 parses raw as level 0: level-routed
        // reception would file this as plaintext. That misroute is
        // exactly the gap; NWK must restore instead.
        let (raw, _) = AuxHeader::decode(aux).unwrap();
        assert_eq!(raw.control.level, 0);
        let (rx, used) = AuxReception::decode(aux).unwrap();
        assert!(rx.is_plaintext());
        assert_eq!(used, 1);

        let (header, used) = AuxHeader::decode_with_level(aux, 5).unwrap();
        assert_eq!(used, 14);
        assert_eq!(header.control.as_octet(), 0x2d);
        assert_eq!(header.frame_counter, ctr);
        assert_eq!(
            header.ext_source,
            Some([0x5f, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04])
        );
        // NWK names the network key: one trailing octet, the key
        // sequence number, which resolves against the key set.
        let seq = match header.key_id {
            KeyIdentifier::Index(s) => s,
            _ => panic!("NWK names a one-octet network key"),
        };
        assert_eq!(seq, 0);
        assert!(keys.select(seq).is_some());

        let nonce = NwkNonce::from_header(&header).unwrap();
        let mut expect_nonce = [0u8; 13];
        expect_nonce[..8].copy_from_slice(&[0x5f, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04]);
        expect_nonce[8..12].copy_from_slice(&ctr.to_le_bytes());
        expect_nonce[12] = 0x2d;
        assert_eq!(nonce.bytes, expect_nonce);

        let aad = [nwk, &restored_aux(aux, 5, &header)[..]].concat();
        assert_eq!(aad.len(), 30);
        let pt = ccm_star_open(&EMBER_LAB_KEY, &nonce.bytes, &aad, ct);
        assert_eq!(pt, Some(plain.to_vec()));
    }
}

// 05-3474-23-431-01 + 05-3474-23-4522-01 (fuzz leg): the genuine U1
// open is brittle in exactly the right way — every wrong level,
// counter knock, sender flip, key flip, and every single-octet
// mutation of nonce/AAD/ciphertext fails authentication.
#[test]
fn fuzz_nwk_ember_open_rejects_mutations() {
    let (nwk, aux, ct) = ember_parts(&EMBER_U1);
    let (header, _) = AuxHeader::decode_with_level(aux, 5).unwrap();
    let nonce = NwkNonce::from_header(&header).unwrap();
    let aad = [nwk, &restored_aux(aux, 5, &header)[..]].concat();
    let good = ccm_star_open(&EMBER_LAB_KEY, &nonce.bytes, &aad, ct);
    assert!(good.is_some());

    // Wrong network-base level: the restored control differs, so the
    // nonce and AAD both miss.
    for level in [0u8, 1, 2, 3, 4, 6, 7] {
        let (bad_h, _) = AuxHeader::decode_with_level(aux, level).unwrap();
        let bad_n = NwkNonce::from_header(&bad_h).unwrap();
        let bad_aad = [nwk, &restored_aux(aux, level, &bad_h)[..]].concat();
        assert!(
            ccm_star_open(&EMBER_LAB_KEY, &bad_n.bytes, &bad_aad, ct).is_none(),
            "level {level} must not open"
        );
    }
    assert_eq!(
        AuxHeader::decode_with_level(aux, 8),
        Err(SecError::BadKeyIdMode)
    );

    // Counter knock either side of the true value.
    for ctr in [0x0000_4003u32, 0x0000_4005u32, 0, u32::MAX] {
        let mut h = header;
        h.frame_counter = ctr;
        let n = NwkNonce::from_header(&h).unwrap();
        assert!(
            ccm_star_open(&EMBER_LAB_KEY, &n.bytes, &aad, ct).is_none(),
            "counter {ctr:#x} must not open"
        );
    }

    // Flipped sender, flipped key, truncated tag.
    let mut h = header;
    h.ext_source = Some([0x60, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04]);
    let n = NwkNonce::from_header(&h).unwrap();
    assert!(ccm_star_open(&EMBER_LAB_KEY, &n.bytes, &aad, ct).is_none());
    let mut bad_key = EMBER_LAB_KEY;
    bad_key[0] ^= 0x01;
    assert!(ccm_star_open(&bad_key, &nonce.bytes, &aad, ct).is_none());
    assert!(ccm_star_open(&EMBER_LAB_KEY, &nonce.bytes, &aad, &ct[..3]).is_none());

    // Exhaustive single-octet mutations of nonce, AAD, ciphertext:
    // every octet position times every nonzero delta.
    let mut mutated = 0u32;
    for (base, len, which) in [
        (nonce.bytes.to_vec(), 13usize, 0u8),
        (aad.clone(), aad.len(), 1u8),
        (ct.to_vec(), ct.len(), 2u8),
    ] {
        for i in 0..len {
            for delta in 1..=255u8 {
                let (nn, aa, cc) = match which {
                    0 => {
                        let mut v = base.clone();
                        v[i] ^= delta;
                        let mut n13 = [0u8; 13];
                        n13.copy_from_slice(&v);
                        (n13, aad.clone(), ct.to_vec())
                    }
                    1 => {
                        let mut v = base.clone();
                        v[i] ^= delta;
                        (nonce.bytes, v, ct.to_vec())
                    }
                    _ => {
                        let mut v = base.clone();
                        v[i] ^= delta;
                        (nonce.bytes, aad.clone(), v)
                    }
                };
                assert!(
                    ccm_star_open(&EMBER_LAB_KEY, &nn, &aa, &cc).is_none(),
                    "mutation {which}:{i}:{delta:#x} must not open"
                );
                mutated += 1;
            }
        }
    }
    assert_eq!(mutated, (13 + 30 + 6) * 255);
}

// 05-3474-23-4522-01: the production nonce builder stays
// self-consistent across counters/senders through a seal/open
// roundtrip (the genuine-frame test above is the independent oracle;
// this leg pins the plumbing over varied inputs).
#[test]
fn vector_nwk_nonce_roundtrip_seal_open() {
    let key = [0x42u8; 16];
    let aad = [0x09u8, 0x12, 0x1d, 0x02];
    for ctr in [0u32, 1, 0x0000_4004, u32::MAX - 1] {
        for sender in [[0x5fu8, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04], [0u8; 8]] {
            let header = AuxHeader {
                control: SecurityControl::new(5, KeyIdMode::Index, true).unwrap(),
                frame_counter: ctr,
                ext_source: Some(sender),
                key_id: KeyIdentifier::Index(0x02),
            };
            let nonce = NwkNonce::from_header(&header).unwrap();
            assert_eq!(&nonce.bytes[..8], &sender);
            assert_eq!(&nonce.bytes[8..12], &ctr.to_le_bytes());
            assert_eq!(nonce.bytes[12], header.control.as_octet());
            let pt = [0x04u8, 0x60];
            let sealed = ccm_star_seal(&key, &nonce.bytes, &aad, &pt);
            assert_eq!(
                ccm_star_open(&key, &nonce.bytes, &aad, &sealed),
                Some(pt.to_vec())
            );
        }
    }
    // No extended source: no nonce to build.
    let nosrc = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::DataKey, false).unwrap(),
        frame_counter: 1,
        ext_source: None,
        key_id: KeyIdentifier::DataKey,
    };
    assert_eq!(NwkNonce::from_header(&nosrc), Err(SecError::Truncated));
}

// 05-3474-23-451-01 + 05-3474-23-451-02 + 05-3474-23-4514-01:
// APS seal-shape proof from captured air. The base leg is proof
// only (the codec already separated the modes); the F leg pins
// the wave-43 mode-0 correction (5-octet data-key aux).
//
// Provenance: wave-39 joiner probes. The broken base seal
// (`~/hwscratch/w39/sniff_b1.txt` probe 0) carries a plaintext
// command octet ahead of the aux plus a network-key-style aux
// (`2d ...`, mode 1) on a link-key seal; the fixed F seal
// (`~/hwscratch/w39/sniff_f3.txt`) seals the command inside with a
// data-key-style aux (`06 ...`, mode 0). Key-identifier mode values
// follow Table 4-39 (0x00 data key, 0x01 network key).
#[test]
fn vector_aps_seal_shape_keyid_modes_05_3474_23_451_02() {
    // Broken base aux: 14 octets, network-key family. A link-key
    // seal check gated on `KeyIdMode::DataKey` refuses this shape —
    // the keyid defect is visible at the codec.
    let base_aux: &[u8] = &[
        0x2d, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xf2, 0x62, 0xff, 0xfe, 0xff, 0xfe, 0x85, 0x00,
    ];
    let (base, base_used) = AuxHeader::decode(base_aux).unwrap();
    assert_eq!(base_used, 14);
    assert_eq!(base.control.level, 5);
    assert_eq!(base.control.key_id, KeyIdMode::Index);
    assert!(base.control.extended_nonce);
    assert_eq!(base.frame_counter, 0);
    assert_ne!(base.key_id.mode(), KeyIdMode::DataKey);
    assert_eq!(base.key_id, KeyIdentifier::Index(0x00));

    // Fixed F aux: data-key family, counter 0, five octets — the
    // sixth octet (0xa5) is the first payload octet, never a key
    // sequence number (wave-43 mode-0 fix, 05-3474-23-4514-01).
    let fix_aux: &[u8] = &[0x06, 0x00, 0x00, 0x00, 0x00, 0xa5];
    let (fix, fix_used) = AuxHeader::decode(fix_aux).unwrap();
    assert_eq!(fix_used, 5);
    assert_eq!(fix.control.level, 6);
    assert_eq!(fix.control.key_id, KeyIdMode::DataKey);
    assert!(!fix.control.extended_nonce);
    assert_eq!(fix.frame_counter, 0);
    assert_eq!(fix.key_id, KeyIdentifier::DataKey);
    assert_eq!(fix_aux[fix_used], 0xa5);

    // The plaintext command octet ahead of the aux shifts every
    // downstream parse: decoding at the command octet (the base
    // bug) yields a different header than decoding at the true aux
    // start. Base APS tail on air: `21 00 | 06 | 2d 00 ...`.
    let aps_tail: &[u8] = &[
        0x21, 0x00, 0x06, 0x2d, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xf2, 0x62, 0xff, 0xfe, 0xff, 0xfe,
        0x85, 0x00,
    ];
    let (shifted, _) = AuxHeader::decode(&aps_tail[2..]).unwrap();
    assert_eq!(shifted.frame_counter, 0x2d);
    assert_eq!(
        (base, base_used),
        AuxHeader::decode(&aps_tail[3..]).unwrap()
    );
    assert_ne!(shifted.frame_counter, base.frame_counter);
}

// 05-3474-23-4312-01: counter-zero (UD0) handling proof from
// captured air (no behavior change — first-seen counter 0 is
// accepted; only a repeat is a replay).
//
// Provenance: the same wave-39 base probe aux as above
// (`~/hwscratch/w39/sniff_b1.txt`): its aux counter is 0, the
// order-free case (little- and big-endian counter encodings agree
// at zero, so no octet-order hypothesis is needed).
#[test]
fn vector_aux_counter_zero_first_accept_05_3474_23_4312_01() {
    let ud0_aux: &[u8] = &[
        0x2d, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xf2, 0x62, 0xff, 0xfe, 0xff, 0xfe, 0x85, 0x00,
    ];
    let (header, _) = AuxHeader::decode(ud0_aux).unwrap();
    assert_eq!(header.frame_counter, 0);

    let sender = u64::from_le_bytes([0xa0, 0xf2, 0x62, 0xff, 0xfe, 0xff, 0xfe, 0x85]);
    let mut rx = ReplayTable::<4>::new();
    assert!(rx.check(sender, header.frame_counter).is_ok());
    assert_eq!(rx.last(sender), Some(0));
    assert_eq!(rx.check(sender, 0), Err(SecError::Replay));
    assert!(rx.check(sender, 1).is_ok());

    // Order-free at zero: the nonce counter field is all zeros
    // either way the counter octets are laid out.
    let nonce = NwkNonce::from_header(&header).unwrap();
    assert_eq!(&nonce.bytes[8..12], &[0, 0, 0, 0]);
    assert_eq!(&nonce.bytes[8..12], &0u32.to_be_bytes());
}

// 05-3474-23-B11-01 (extended): the hash also covers the short
// 16-octet form. Input C0..CF (the B.4 short-form worked example,
// anchor p0550-L13551-L13565) must produce A7977E88BC0B61E8
// 210827109A228F2D.
#[test]
fn vector_mmo_short_form_worked_05_3474_23_b11_01() {
    let input = [
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE,
        0xCF,
    ];
    assert_eq!(
        mmo_hash_128(&input).unwrap(),
        [
            0xA7, 0x97, 0x7E, 0x88, 0xBC, 0x0B, 0x61, 0xE8, 0x21, 0x08, 0x27, 0x10, 0x9A, 0x22,
            0x8F, 0x2D
        ]
    );
}

// 05-3474-23-B14-01: keyed-hash worked example (128-bit key,
// anchor p0554-L13638-L13667). Key 4041..4F with the one-octet
// input C0 must hash the inner leg to 3C3D537529A7A9A03F66
// 9DCD886CB52C and finish at 4512807BF94CB3400F0E2C
// 25FB76E999 — the same construction the key hierarchy below
// applies with its own one-octet domain inputs.
#[test]
fn vector_hmac_mmo_worked_05_3474_23_b14_01() {
    let key = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
        0x4F,
    ];
    assert_eq!(
        hmac_mmo_128(&key, &[0xC0]).unwrap(),
        [
            0x45, 0x12, 0x80, 0x7B, 0xF9, 0x4C, 0xB3, 0x40, 0x0F, 0x0E, 0x2C, 0x25, 0xFB, 0x76,
            0xE9, 0x99
        ]
    );
}

// 05-3474-23-B14-01 (extended): one-octet key-agreement KDF check
// (anchor p0557-L13737-L13739). The agreement secret
// AE466B75309D5C2D715F7E4431DF047A under the domain input 0x01
// must produce 2547F3AF96391E1EBFF2A3B76D6A2929 — the same
// one-octet-input shape the link-key hierarchy uses.
#[test]
fn vector_hmac_mmo_kdf_shape_05_3474_23_b14_01() {
    let secret = [
        0xAE, 0x46, 0x6B, 0x75, 0x30, 0x9D, 0x5C, 0x2D, 0x71, 0x5F, 0x7E, 0x44, 0x31, 0xDF, 0x04,
        0x7A,
    ];
    assert_eq!(
        hmac_mmo_128(&secret, &[0x01]).unwrap(),
        [
            0x25, 0x47, 0xF3, 0xAF, 0x96, 0x39, 0x1E, 0x1E, 0xBF, 0xF2, 0xA3, 0xB7, 0x6D, 0x6A,
            0x29, 0x29
        ]
    );
}

// 05-3474-23-453-01: key-hierarchy derivation from the BDB worked
// link key 66B6900981E1EE3CA4206B6B861C02BB. The transport key
// (domain input 0x00) and the load key (0x02) are pinned below;
// the values were cross-checked against an independent Python
// model of the same clause before freezing. The data key is the
// link key itself.
#[test]
fn vector_key_hierarchy_from_worked_link_05_3474_23_453_01() {
    let link = [
        0x66, 0xB6, 0x90, 0x09, 0x81, 0xE1, 0xEE, 0x3C, 0xA4, 0x20, 0x6B, 0x6B, 0x86, 0x1C, 0x02,
        0xBB,
    ];
    assert_eq!(
        derive_key_transport_key(&link).unwrap(),
        [
            0x3C, 0x6C, 0xCA, 0x89, 0x77, 0xEB, 0x18, 0x9E, 0xFD, 0x16, 0x14, 0xC3, 0xE7, 0xF7,
            0x59, 0x89
        ]
    );
    assert_eq!(
        derive_key_load_key(&link).unwrap(),
        [
            0x11, 0x77, 0xA0, 0xEE, 0x26, 0x00, 0xD0, 0x02, 0x0D, 0xBA, 0x82, 0xD7, 0x04, 0x9F,
            0x53, 0xBC
        ]
    );
    assert_eq!(data_key_is_link_key(&link), &link);
}

// Production CCM* equivalence: the `ccm` module must open the genuine
// Ember frames and seal byte-identically to the test-local oracle
// (retired lab-capture key, interop pin only).
#[test]
fn prod_ccm_matches_oracle_on_ember_vectors() {
    for frame in [&EMBER_U1, &EMBER_B1] {
        let (nwk, aux, ct) = ember_parts(frame);
        let (header, _) = AuxHeader::decode_with_level(aux, 5).unwrap();
        let nonce = NwkNonce::from_header(&header).unwrap();
        let aad = [nwk, &restored_aux(aux, 5, &header)[..]].concat();
        let expect_pt = ccm_star_open(&EMBER_LAB_KEY, &nonce.bytes, &aad, ct)
            .expect("oracle opens genuine frame");
        // Production open agrees, byte for byte.
        let mut pt = [0u8; 64];
        let (ct_body, tag) = ct.split_at(ct.len() - CCM_TAG_LEN);
        let mut tag4 = [0u8; CCM_TAG_LEN];
        tag4.copy_from_slice(tag);
        let n = ccm_star_open_into(&EMBER_LAB_KEY, &nonce.bytes, &aad, ct_body, &tag4, &mut pt)
            .expect("prod opens genuine frame");
        assert_eq!(&pt[..n], &expect_pt[..]);
        // Production seal reproduces the oracle wire bytes exactly.
        let mut sealed = [0u8; 64];
        let m = ccm_star_seal_into(&EMBER_LAB_KEY, &nonce.bytes, &aad, &expect_pt, &mut sealed)
            .expect("prod seals");
        let oracle_wire = ccm_star_seal(&EMBER_LAB_KEY, &nonce.bytes, &aad, &expect_pt);
        assert_eq!(&sealed[..m], &oracle_wire[..]);
    }
}
