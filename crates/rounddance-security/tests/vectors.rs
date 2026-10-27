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

// 05-3474-23-451-01: DataKey mode, level 5, counter 0x12345678, seq 3.
// control 0x05 | counter LE | seq.
#[test]
fn vector_aux_data_key() {
    let header = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::DataKey, false).unwrap(),
        frame_counter: 0x1234_5678,
        ext_source: None,
        key_id: KeyIdentifier::Seq(0x03),
    };
    assert_eq!(header.header_len(), Some(6));
    let mut out = [0u8; MAX_AUX_LEN];
    let n = header.encode_into(&mut out).unwrap();
    assert_eq!(n, 6);
    assert_eq!(&out[..n], &[0x05, 0x78, 0x56, 0x34, 0x12, 0x03]);
    let (back, used) = AuxHeader::decode(&out[..n]).unwrap();
    assert_eq!((back, used), (header, n));
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
        key_id: KeyIdentifier::Seq(0),
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
    assert_eq!(mmo_hash_128(&[0u8; 32]).unwrap_err(), MmoError::TooLong);
}
