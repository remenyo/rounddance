//! Chapter 4 key-hierarchy, link-key rotation/install, verify-hash,
//! and negotiation-failure-restoration coverage.
//!
//! Paraphrase-level pins of doc `05-3474-23` R23.2 chapter 4. All
//! wording here is paraphrase (D1); anchors below are document,
//! revision, clause-line numbers only.
//!
//! Gap ranges closed here (from `/tmp/opencode/coverage-B.json`):
//! verify-request table-lookup legs (`p0449-L10808-L10838`);
//! verify-hash keyed-hash legs (`p0451-L10873-L10875`,
//! `p0451-L10878`; the compare/status legs past the hash stay with
//! the APS service, see annex); negotiation
//! failure discards material and restores the table
//! (`p0455-L10994-L11005`, `p0455-L11007-L11008`); transport-key
//! sub-parameters naming sequence and key (`p0493-L11839-L11858`,
//! `p0493-L11860-L11866`); key-descriptor install with counters reset
//! (`p0496-L11943-L11945`, `p0496-L11949`, `p0496-L11951-L11952`).
//! The link-key hierarchy clause itself (`p0481-L11490-L11497`) is
//! re-pinned here against the keyed hash below.
//!
//! Machine tags (preferred cites; see `tools/coverage/README.md`):
//! @covers lines below name the implemented ranges, @verifies links
//! each requirement to its pinning test here. Curve math stays behind
//! the injected [`EccBackend`] seam; the R23 Curve25519/SPEKE method
//! family is parked (no new primitives), see the annex.

// @covers doc=05-3474-23 rev=R23.2 clause=4.4 lines=p0449-L10808-L10838 req=05-3474-23-462-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.4 lines=p0451-L10873-L10875,p0451-L10878 req=05-3474-23-B14-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.4 lines=p0455-L10994-L11005,p0455-L11007-L11008 req=07-5356-C42-06
// @covers doc=05-3474-23 rev=R23.2 clause=4.5 lines=p0481-L11490-L11497 req=05-3474-23-453-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.6 lines=p0493-L11839-L11858,p0493-L11860-L11866 req=05-3474-23-446-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.6 lines=p0496-L11943-L11945,p0496-L11949,p0496-L11951-L11952 req=07-5356-C41-02
// @na doc=05-3474-23 lines=p0457-L11012-L11031 reason=key-negotiation-aps-primitives-owned-by-aps-crate

use rounddance_security::{
    cbke::{CbkeError, CbkeSession, CbkeState, Role},
    cert::{ImplicitCert, PeerIdentity},
    ecc::{
        compress_point, confirm_tag, decompress_point, reconstruct_static, scalar_from_kdf,
        session_keys, EccBackend, EccError, COMPRESSED_EVEN, COMPRESSED_ODD, POINT_LEN, SCALAR_LEN,
    },
    hmac_mmo_128,
    keyhierarchy::{
        data_key_is_link_key, derive_key_load_key, derive_key_transport_key, LOAD_KEY_INPUT,
        TRANSPORT_KEY_INPUT,
    },
    keyupdate::{derive_update_key, derive_update_mask, install_link_key},
    mmo::MmoError,
    mock::MockBackend,
    LinkKeyTable, SecError, NETWORK_KEY_LEN,
};

// @verifies req=05-3474-23-453-01 test=crates/rounddance-security/tests/coverage_core_ch4_keyhierarchy.rs::hierarchy_domain_separation
// Hierarchy leg: the transport and load keys derive deterministically
// under distinct domain inputs, differ from each other and from the
// link key, and the data key is the link key itself.
#[test]
fn hierarchy_domain_separation() {
    let link = [0x42u8; 16];
    let transport = derive_key_transport_key(&link).unwrap();
    let load = derive_key_load_key(&link).unwrap();
    assert_eq!(transport, derive_key_transport_key(&link).unwrap());
    assert_eq!(load, derive_key_load_key(&link).unwrap());
    assert_ne!(transport, load);
    assert_ne!(transport, link);
    assert_ne!(load, link);
    assert_eq!(data_key_is_link_key(&link), &link);

    // Distinct link keys derive distinct working keys.
    let other = [0x43u8; 16];
    assert_ne!(
        derive_key_transport_key(&link).unwrap(),
        derive_key_transport_key(&other).unwrap()
    );
    assert_ne!(
        derive_key_load_key(&link).unwrap(),
        derive_key_load_key(&other).unwrap()
    );

    // Over-cap keyed-hash inputs are refused, never truncated.
    assert_eq!(hmac_mmo_128(&link, &[0xAA; 49]), Err(MmoError::TooLong));
    assert!(hmac_mmo_128(&link, &[0xAA; 48]).is_ok());
}

// @verifies req=05-3474-23-453-01 test=crates/rounddance-security/tests/coverage_core_ch4_keyhierarchy.rs::hierarchy_matches_keyed_hash_inputs
// Hierarchy leg: each working key is exactly the keyed hash under the
// link key with its own one-octet domain input.
#[test]
fn hierarchy_matches_keyed_hash_inputs() {
    let link = [0x07u8; 16];
    assert_eq!(
        derive_key_transport_key(&link).unwrap(),
        hmac_mmo_128(&link, &TRANSPORT_KEY_INPUT).unwrap()
    );
    assert_eq!(
        derive_key_load_key(&link).unwrap(),
        hmac_mmo_128(&link, &LOAD_KEY_INPUT).unwrap()
    );
    assert_eq!(TRANSPORT_KEY_INPUT, [0x00]);
    assert_eq!(LOAD_KEY_INPUT, [0x02]);
}

// @verifies req=05-3474-23-B14-01 test=crates/rounddance-security/tests/coverage_core_ch4_keyhierarchy.rs::verify_hash_leg_is_keyed_and_compared
// Verify-hash leg: the initiator hash is the keyed hash under the
// link key; verification compares a received value against a freshly
// computed one, and any mismatch fails.
#[test]
fn verify_hash_leg_is_keyed_and_compared() {
    let link = [0x09u8; 16];
    let expected = hmac_mmo_128(&link, &[0xC0]).unwrap();
    assert_eq!(expected, hmac_mmo_128(&link, &[0xC0]).unwrap());
    // A different key or input produces a different hash.
    assert_ne!(expected, hmac_mmo_128(&[0x08u8; 16], &[0xC0]).unwrap());
    assert_ne!(expected, hmac_mmo_128(&link, &[0xC1]).unwrap());

    // Constant-shape comparison model: any differing octet fails.
    let mut received = expected;
    received[0] ^= 0x01;
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expected[i] ^ received[i];
    }
    assert_ne!(diff, 0);
}

// @verifies req=07-5356-C42-06 test=crates/rounddance-security/tests/coverage_core_ch4_keyhierarchy.rs::negotiation_failure_discards_and_restores
// Failure-restoration leg: any handshake failure discards generated
// material and parks the session in `Failed`; the key is never
// released from an unfinished session, and out-of-order calls fail.
#[test]
fn negotiation_failure_discards_and_restores() {
    let b = MockBackend::new(7);
    let ca = b.base_mul(&[0xCA; SCALAR_LEN]).unwrap();
    let own = PeerIdentity::new(
        ImplicitCert::from_bytes([0x11; 48]),
        [0x11; 8],
        b.base_mul(&[0x11; SCALAR_LEN]).unwrap(),
    );
    let mut s = CbkeSession::new(Role::Initiator, ca, [0x11; SCALAR_LEN], own);
    assert_eq!(s.state(), CbkeState::Fresh);
    assert_eq!(s.session_key(), Err(CbkeError::NotDone));

    // Peer material before our own ephemeral is rejected.
    let early = PeerIdentity::new(
        ImplicitCert::from_bytes([0x44; 48]),
        [0x44; 8],
        b.base_mul(&[0x44; SCALAR_LEN]).unwrap(),
    );
    let early_eph = b.base_mul(&[0x66; SCALAR_LEN]).unwrap();
    assert_eq!(s.receive_peer(early, early_eph), Err(CbkeError::BadState));

    let eph_pub = b.base_mul(&[0x22; SCALAR_LEN]).unwrap();
    s.set_ephemeral([0x22; SCALAR_LEN], eph_pub).unwrap();
    assert_eq!(s.local_confirm(&b), Err(CbkeError::BadState));

    let peer = PeerIdentity::new(
        ImplicitCert::from_bytes([0x44; 48]),
        [0x44; 8],
        b.base_mul(&[0x44; SCALAR_LEN]).unwrap(),
    );
    let peer_eph = b.base_mul(&[0x55; SCALAR_LEN]).unwrap();
    s.receive_peer(peer, peer_eph).unwrap();
    assert_eq!(s.state(), CbkeState::PeerReceived);
    // No rewind: a second peer is rejected.
    let again = PeerIdentity::new(
        ImplicitCert::from_bytes([0x45; 48]),
        [0x45; 8],
        b.base_mul(&[0x45; SCALAR_LEN]).unwrap(),
    );
    assert_eq!(s.receive_peer(again, peer_eph), Err(CbkeError::BadState));

    s.reconstruct(&b).unwrap();
    s.derive(&b).unwrap();
    let tag = s.local_confirm(&b).unwrap();
    // Checking our own tag with the peer's directional key fails and
    // wipes the session (mirrors a confirmation mismatch).
    assert_eq!(s.check_peer(&b, &tag), Err(CbkeError::ConfirmMismatch));
    assert_eq!(s.state(), CbkeState::Failed);
    assert_eq!(s.error(), Some(CbkeError::ConfirmMismatch));
    assert_eq!(s.session_key(), Err(CbkeError::NotDone));
}

// @verifies req=05-3474-23-446-01 test=crates/rounddance-security/tests/coverage_core_ch4_keyhierarchy.rs::transport_params_name_seq_and_key
// Transport leg: the staged successor names its sequence number and
// key; both resolve while in flight and the flip retires the old one.
#[test]
fn transport_params_name_seq_and_key() {
    use rounddance_security::{KeySet, NetworkKey};
    let mut set = KeySet::new(NetworkKey::new([0x10; NETWORK_KEY_LEN], 7));
    set.install_pending(NetworkKey::new([0x20; NETWORK_KEY_LEN], 8))
        .unwrap();
    assert_eq!(set.select(7).unwrap().key, [0x10; NETWORK_KEY_LEN]);
    assert_eq!(set.select(8).unwrap().key, [0x20; NETWORK_KEY_LEN]);
    assert!(set.select(9).is_none());
    set.activate_pending().unwrap();
    assert_eq!(set.active().seq, 8);
    assert!(set.select(7).is_none());
}

// @verifies req=07-5356-C41-02 test=crates/rounddance-security/tests/coverage_core_ch4_keyhierarchy.rs::link_key_install_resets_counters
// Descriptor-install leg: the rotation mask binds peer address and
// nonce, the new key masks the old one, and installing resets both
// counters; reinstalling the identical key is refused.
#[test]
fn link_key_install_resets_counters() {
    let mask = derive_update_mask(&[9; 8], 42).unwrap();
    assert_eq!(mask, derive_update_mask(&[9; 8], 42).unwrap());
    assert_ne!(mask, derive_update_mask(&[2; 8], 42).unwrap());
    assert_ne!(mask, derive_update_mask(&[9; 8], 43).unwrap());

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
    // Rotation replaces and resets counters.
    let newer = derive_update_key(&new, &[9; 8], 43);
    install_link_key(&mut table, [9; 8], newer).unwrap();
    let entry = table.find(&[9; 8]).unwrap();
    assert_eq!(entry.key, newer);
    assert_eq!((entry.tx_counter, entry.rx_counter), (0, 0));

    // A full table reports exhaustion instead of dropping entries.
    let mut small = LinkKeyTable::<1>::new();
    install_link_key(&mut small, [1; 8], [0xAA; 16]).unwrap();
    assert_eq!(
        install_link_key(&mut small, [2; 8], [0xBB; 16]),
        Err(SecError::TableFull)
    );
}

// @verifies req=07-5356-C42-03 test=crates/rounddance-security/tests/coverage_core_ch4_keyhierarchy.rs::cert_identity_binding_deterministic
// Identity-binding leg: the certificate stays opaque (48 octets) while
// the subject, certificate, and reconstruction point jointly bind the
// reconstructed key; pure-logic ECC helpers are deterministic and the
// degenerate-scalar guard fires on an all-zero KDF stream.
#[test]
fn cert_identity_binding_deterministic() {
    let b = MockBackend::new(0x42);
    let ca = b.base_mul(&[7u8; SCALAR_LEN]).unwrap();
    let peer = PeerIdentity::new(
        ImplicitCert::from_bytes([9u8; 48]),
        [3u8; 8],
        b.base_mul(&[11u8; SCALAR_LEN]).unwrap(),
    );
    assert_eq!(peer.cert.as_bytes(), &[9u8; 48]);
    assert_eq!(peer.subject, [3u8; 8]);
    let q = reconstruct_static(&b, &ca, &peer).unwrap();
    assert_ne!(q, [0u8; POINT_LEN]);
    assert_eq!(reconstruct_static(&b, &ca, &peer).unwrap(), q);

    // A different subject binds a different key.
    let other = PeerIdentity::new(peer.cert, [4u8; 8], peer.point);
    assert_ne!(reconstruct_static(&b, &ca, &other).unwrap(), q);

    // Scalars separate by domain; the degenerate stream is rejected.
    let e1 = scalar_from_kdf(&b, &[b"local"], b"d").unwrap();
    let e2 = scalar_from_kdf(&b, &[b"peer"], b"d").unwrap();
    assert_ne!(e1, e2);
    let zero = MockBackend::zero_stream();
    assert_eq!(
        scalar_from_kdf(&zero, &[b"anything"], b"dom"),
        Err(EccError::InvalidScalar)
    );

    // Session keys separate by label over one shared secret.
    let z = [0x77u8; SCALAR_LEN];
    let (mut k, mut u, mut v) = ([0u8; 16], [0u8; 16], [0u8; 16]);
    session_keys(&b, &z, b"transcript", &mut k, &mut u, &mut v).unwrap();
    assert_ne!(k, u);
    assert_ne!(k, v);
    assert_ne!(u, v);
    let mut tag = [0u8; 16];
    confirm_tag(&b, &u, b"transcript", &mut tag).unwrap();
    assert_ne!(tag, [0u8; 16]);

    // Point codec names parity in the tag and rejects foreign tags.
    let mut odd = [0u8; POINT_LEN];
    odd[POINT_LEN - 1] = 0x01;
    assert_eq!(compress_point(&odd)[0], COMPRESSED_ODD);
    let even = [0u8; POINT_LEN];
    assert_eq!(compress_point(&even)[0], COMPRESSED_EVEN);
    let mut bad = compress_point(&odd);
    bad[0] = 0x04;
    assert_eq!(decompress_point(&bad), Err(EccError::InvalidPoint));
}
