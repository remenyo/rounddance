//! Chapter 4 auxiliary header, security control, nonce, CCM legs, and
//! secured NWK/APS frame-shape coverage.
//!
//! Paraphrase-level pins of doc `05-3474-23` R23.2 chapter 4. All
//! wording here is paraphrase (D1); anchors below are document,
//! revision, clause-line numbers only.
//!
//! Gap ranges closed here (from `/tmp/opencode/coverage-B.json`):
//! outgoing secured-frame construction
//! (`p0422-L10145-L10147`); sender-cleared level octet
//! (`p0422-L10155`); CCM/decrypt/auth legs
//! (`p0423-L10190-L10192`, `p0423-L10194-L10198`, `p0423-L10200`);
//! secured APDU shape (`p0463-L11194-L11196`, `p0463-L11198-L11212`,
//! `p0463-L11214-L11217`); auxiliary-header format
//! (`p0479-L11428-L11435`); level table (`p0480-L11452`,
//! `p0480-L11459-L11460`); source address and sequence/parameter legs
//! (`p0481-L11463-L11466`, `p0481-L11470-L11479`).
//!
//! Machine tags (preferred cites; see `tools/coverage/README.md`):
//! @covers lines below name the implemented ranges, @verifies links
//! each requirement to its pinning test here.

// @covers doc=05-3474-23 rev=R23.2 clause=4.3 lines=p0422-L10145-L10147,p0422-L10155 req=05-3474-23-431-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.3 lines=p0423-L10190-L10192,p0423-L10194-L10198,p0423-L10200 req=05-3474-23-4522-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.4 lines=p0463-L11194-L11196,p0463-L11198-L11212,p0463-L11214-L11217 req=05-3474-23-451-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.5 lines=p0479-L11428-L11435 req=05-3474-23-451-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.5 lines=p0480-L11452,p0480-L11459-L11460 req=05-3474-23-451-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.5 lines=p0481-L11463-L11466,p0481-L11470-L11479 req=05-3474-23-4522-01
// @na doc=05-3474-23 lines=p0482-L11502-L11513 reason=hardware-rng-target-owned

use rounddance_security::{
    ccm::{open_into as ccm_open, seal_into as ccm_seal, CcmError, NONCE_LEN, TAG_LEN},
    AuxHeader, AuxReception, KeyIdMode, KeyIdentifier, NwkNonce, SecError, SecurityControl,
    MAX_AUX_LEN, UNSECURED_LEVEL,
};

// @verifies req=05-3474-23-451-01 test=crates/rounddance-security/tests/coverage_core_ch4_aux_nonce.rs::security_control_octet_packing
// Control-octet leg: the level is three bits, the key-identifier mode
// two bits, and the extended-nonce flag one bit; out-of-range levels
// are refused at construction, and restoring a base level keeps the
// other sub-fields.
#[test]
fn security_control_octet_packing() {
    // Level 5, network-key mode, extended nonce:
    // 5 | (1 << 3) | (1 << 5) = 0x2D.
    let control = SecurityControl::new(5, KeyIdMode::Index, true).unwrap();
    assert_eq!(control.as_octet(), 0x2D);

    // Data-key mode has no trailing octet; the level travels in the
    // low three bits either way.
    let bare = SecurityControl::new(6, KeyIdMode::DataKey, false).unwrap();
    assert_eq!(bare.as_octet(), 0x06);

    // Restoring the network base over a zeroed on-air octet keeps the
    // mode and nonce flag (incoming step-1 helper).
    let restored = bare.with_level(5).unwrap();
    assert_eq!(restored.as_octet(), 0x05);
    assert_eq!(restored.key_id, KeyIdMode::DataKey);
    assert!(!restored.extended_nonce);

    // Levels above three bits are refused both ways.
    assert!(SecurityControl::new(8, KeyIdMode::DataKey, false).is_none());
    assert!(bare.with_level(9).is_none());
    assert_eq!(
        AuxHeader::decode_with_level(&[0x28, 0, 0, 0, 0], 8),
        Err(SecError::BadKeyIdMode)
    );
}

// @verifies req=05-3474-23-451-01 test=crates/rounddance-security/tests/coverage_core_ch4_aux_nonce.rs::aux_all_modes_roundtrip
// Header-shape leg: every key-identifier mode encodes and decodes;
// the data-key shape carries no trailing octet while the network-key
// shape carries exactly one sequence-number octet.
#[test]
fn aux_all_modes_roundtrip() {
    // Outgoing secured-frame shape: header bytes sit between the
    // network header and the payload/MIC on air.
    let data = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::DataKey, false).unwrap(),
        frame_counter: 0x1234_5678,
        ext_source: None,
        key_id: KeyIdentifier::DataKey,
    };
    assert_eq!(data.header_len(), Some(5));
    let mut out = [0u8; MAX_AUX_LEN];
    let n = data.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], &[0x05, 0x78, 0x56, 0x34, 0x12]);
    assert_eq!(AuxHeader::decode(&out[..n]).unwrap(), (data, n));

    let index = AuxHeader {
        control: SecurityControl::new(1, KeyIdMode::Index, false).unwrap(),
        frame_counter: 0,
        ext_source: None,
        key_id: KeyIdentifier::Index(0x07),
    };
    assert_eq!(index.header_len(), Some(6));
    let m = index.encode_into(&mut out).unwrap();
    assert_eq!(&out[..m], &[0x09, 0x00, 0x00, 0x00, 0x00, 0x07]);
    assert_eq!(AuxHeader::decode(&out[..m]).unwrap(), (index, m));

    let source4 = AuxHeader {
        control: SecurityControl::new(3, KeyIdMode::Source4, false).unwrap(),
        frame_counter: 0xAABB_CCDD,
        ext_source: None,
        key_id: KeyIdentifier::Source4([0x11, 0x22, 0x33, 0x44], 0x09),
    };
    assert_eq!(source4.header_len(), Some(10));
    let k = source4.encode_into(&mut out).unwrap();
    assert_eq!(
        &out[..k],
        &[0x13, 0xDD, 0xCC, 0xBB, 0xAA, 0x11, 0x22, 0x33, 0x44, 0x09]
    );
    assert_eq!(AuxHeader::decode(&out[..k]).unwrap(), (source4, k));

    let source8 = AuxHeader {
        control: SecurityControl::new(2, KeyIdMode::Source8, true).unwrap(),
        frame_counter: 1,
        ext_source: Some([0xAA; 8]),
        key_id: KeyIdentifier::Source8([0xBB; 8], 0x02),
    };
    assert_eq!(source8.header_len(), Some(22));
    let j = source8.encode_into(&mut out).unwrap();
    assert_eq!(j, 22);
    assert_eq!(out[0], 0x3A);
    assert_eq!(AuxHeader::decode(&out[..j]).unwrap(), (source8, j));

    // Truncation at any length is a fallible error, never a panic.
    let full = [0x3Au8; 22];
    for len in 0..22 {
        assert!(AuxHeader::decode(&full[..len]).is_err());
    }
    // Flag/shape disagreement is refused at both ends.
    let bad = AuxHeader {
        control: SecurityControl::new(0, KeyIdMode::DataKey, true).unwrap(),
        frame_counter: 0,
        ext_source: None,
        key_id: KeyIdentifier::DataKey,
    };
    assert_eq!(bad.header_len(), None);
    assert!(bad.encode_into(&mut out).is_err());
    let mut tiny = [0u8; 1];
    assert_eq!(data.encode_into(&mut tiny), Err(SecError::TooSmall));
}

// @verifies req=05-3474-23-431-01 test=crates/rounddance-security/tests/coverage_core_ch4_aux_nonce.rs::aux_decode_with_level_restores_zeroed
// Sender-cleared-level leg: the sender zeroes the on-air level octet
// after protecting the frame, so the receiver restores its network
// base before any nonce or integrity work; raw decode still sees the
// zeroed octet.
#[test]
fn aux_decode_with_level_restores_zeroed() {
    let sent = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::Index, true).unwrap(),
        frame_counter: 0x0000_4004,
        ext_source: Some([0x5f, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04]),
        key_id: KeyIdentifier::Index(0x00),
    };
    let mut wire = [0u8; MAX_AUX_LEN];
    let n = sent.encode_into(&mut wire).unwrap();
    assert_eq!(n, 14);

    // Simulate the on-air zeroing: clear the level bits of octet 0.
    let mut on_air = wire;
    on_air[0] &= 0xF8;
    assert_eq!(on_air[0], 0x28);

    // Raw decode parses the zeroed level; the level-routed reception
    // would file this as plaintext, so NWK receivers must restore.
    let (raw, _) = AuxHeader::decode(&on_air[..n]).unwrap();
    assert_eq!(raw.control.level, 0);
    let (rx, used) = AuxReception::decode(&on_air[..n]).unwrap();
    assert!(rx.is_plaintext());
    assert_eq!(used, 1);

    let (header, used) = AuxHeader::decode_with_level(&on_air[..n], 5).unwrap();
    assert_eq!(used, 14);
    assert_eq!(header, sent);
    assert_eq!(header.control.as_octet(), 0x2D);
}

// @verifies req=05-3474-23-451-01 test=crates/rounddance-security/tests/coverage_core_ch4_aux_nonce.rs::aux_reception_routing_level0
// Reception-shape leg: a level-0 frame is exactly one control octet
// followed by plaintext — no counter, no key identifier, no tag —
// while secured levels take the full envelope.
#[test]
fn aux_reception_routing_level0() {
    for ctrl in [0x00u8, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38] {
        let buf = [ctrl, 0xAA, 0xBB];
        let (rx, used) = AuxReception::decode(&buf).unwrap();
        assert!(rx.is_plaintext());
        assert_eq!(used, 1);
        assert_eq!(rx.control().level, UNSECURED_LEVEL);
    }
    // Secured shape still routes the long way.
    let secured = [0x05u8, 0x78, 0x56, 0x34, 0x12, 0x03];
    let (rx, used) = AuxReception::decode(&secured).unwrap();
    assert!(!rx.is_plaintext());
    assert_eq!(used, 5);
    assert_eq!(secured[used], 0x03);
    assert_eq!(AuxReception::decode(&[]), Err(SecError::Truncated));
}

// @verifies req=05-3474-23-4522-01 test=crates/rounddance-security/tests/coverage_core_ch4_aux_nonce.rs::nwk_nonce_layout_binds_source_counter_control
// Nonce leg: the 13-octet nonce binds the extended source, the
// counter in protection order, and the effective control octet; with
// no source there is no nonce to build.
#[test]
fn nwk_nonce_layout_binds_source_counter_control() {
    let sender = [0x5fu8, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04];
    let header = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::Index, true).unwrap(),
        frame_counter: 0x0000_4004,
        ext_source: Some(sender),
        key_id: KeyIdentifier::Index(0x02),
    };
    let nonce = NwkNonce::from_header(&header).unwrap();
    let mut expect = [0u8; 13];
    expect[..8].copy_from_slice(&sender);
    expect[8..12].copy_from_slice(&0x0000_4004u32.to_le_bytes());
    expect[12] = 0x2D;
    assert_eq!(nonce.bytes, expect);

    // No extended source: no nonce to build.
    let nosrc = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::DataKey, false).unwrap(),
        frame_counter: 1,
        ext_source: None,
        key_id: KeyIdentifier::DataKey,
    };
    assert_eq!(NwkNonce::from_header(&nosrc), Err(SecError::Truncated));
}

// @verifies req=05-3474-23-4522-01 test=crates/rounddance-security/tests/coverage_core_ch4_aux_nonce.rs::ccm_seal_open_roundtrip_and_tamper
// CCM leg: the production seal/open pair round-trips over the nonce
// and authenticated bytes above; any tamper with ciphertext, tag, or
// associated bytes fails authentication and yields no plaintext.
#[test]
fn ccm_seal_open_roundtrip_and_tamper() {
    let key = [0x42u8; 16];
    let nonce = [0x07u8; NONCE_LEN];
    let aad: &[u8] = &[0x09, 0x12, 0x1d, 0x02];
    let pt = [0x04u8, 0x60, 0xAA, 0xBB, 0xCC];

    let mut sealed = [0u8; 32];
    let n = ccm_seal(&key, &nonce, aad, &pt, &mut sealed).unwrap();
    assert_eq!(n, pt.len() + TAG_LEN);
    let (ct, tag) = sealed[..n].split_at(pt.len());
    let mut tag4 = [0u8; TAG_LEN];
    tag4.copy_from_slice(tag);

    let mut back = [0u8; 5];
    assert_eq!(
        ccm_open(&key, &nonce, aad, ct, &tag4, &mut back),
        Ok(pt.len())
    );
    assert_eq!(&back, &pt);

    // Flipped ciphertext, tag, or associated bytes all fail closed.
    let mut bad_ct = [0u8; 5];
    bad_ct.copy_from_slice(ct);
    bad_ct[0] ^= 0x01;
    let mut out = [0u8; 5];
    assert_eq!(
        ccm_open(&key, &nonce, aad, &bad_ct, &tag4, &mut out),
        Err(CcmError::AuthFailed)
    );
    let mut bad_tag = tag4;
    bad_tag[0] ^= 0x01;
    assert_eq!(
        ccm_open(&key, &nonce, aad, ct, &bad_tag, &mut out),
        Err(CcmError::AuthFailed)
    );
    assert_eq!(
        ccm_open(&key, &nonce, &[0x00], ct, &tag4, &mut out),
        Err(CcmError::AuthFailed)
    );
    // Short buffers fail without partial writes.
    let mut tiny = [0u8; 2];
    assert_eq!(
        ccm_seal(&key, &nonce, aad, &pt, &mut tiny),
        Err(CcmError::TooSmall)
    );
    assert_eq!(
        ccm_open(&key, &nonce, aad, ct, &tag4, &mut tiny),
        Err(CcmError::TooSmall)
    );
}

// @verifies req=05-3474-23-451-01 test=crates/rounddance-security/tests/coverage_core_ch4_aux_nonce.rs::secured_apdu_aux_shape
// Secured-APDU leg: with security applied the auxiliary header sits
// between the APS header and the protected payload; the security bit
// marks its presence and the control octet selects the envelope.
#[test]
fn secured_apdu_aux_shape() {
    // Network-key APDU envelope: 6 octets (control + counter + one
    // sequence octet); the trailing octet names the key in use.
    let net = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::Index, false).unwrap(),
        frame_counter: 0x0102_0304,
        ext_source: None,
        key_id: KeyIdentifier::Index(0x09),
    };
    assert_eq!(net.header_len(), Some(6));
    let mut out = [0u8; MAX_AUX_LEN];
    let n = net.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], &[0x0d, 0x04, 0x03, 0x02, 0x01, 0x09]);

    // Link-key (data-key) APDU envelope: 5 octets, no trailing key
    // octet — the key is implicit, so the next octet is payload.
    let link = AuxHeader {
        control: SecurityControl::new(6, KeyIdMode::DataKey, false).unwrap(),
        frame_counter: 0x0102_0304,
        ext_source: None,
        key_id: KeyIdentifier::DataKey,
    };
    assert_eq!(link.header_len(), Some(5));
    let m = link.encode_into(&mut out).unwrap();
    assert_eq!(&out[..m], &[0x06, 0x04, 0x03, 0x02, 0x01]);
    // A trailing octet after a data-key header is payload, never a
    // sequence number: decoding stops at five octets.
    let with_payload = [0x06u8, 0x04, 0x03, 0x02, 0x01, 0xa5];
    let (back, used) = AuxHeader::decode(&with_payload).unwrap();
    assert_eq!((back, used), (link, 5));
    assert_eq!(with_payload[used], 0xa5);
}
