//! Wire vectors for the Smart Energy + metering clusters.
//!
//! Each test names the requirement ID it verifies. Byte strings are
//! hand-computed from the paraphrased layouts in doc `07-5123-08`
//! and doc `07-5356` — never copied from spec text (D1,
//! `SCOPE.md` §2). Corpus-mined IDs are reused verbatim;
//! repo-minted IDs are MINTED-pending-confirm.

use rounddance_security::{
    backend_host::HostBackend, EccBackend, ImplicitCert, LinkKeyTable, PeerIdentity,
};
use rounddance_security::{ecc::scalar_from_kdf, CbkeError};
use rounddance_zcl::cluster::ClusterDef;
use rounddance_zcl::*;

// ---- metering.rs ----------------------------------------------------

// 07-5123-08-1041-01/02 + 07-5123-08-1042-01/02: server store shape.
#[test]
fn vector_metering_store_defaults_07_5123_08_1042_01() {
    let store = metering::server_store().unwrap();
    assert_eq!(metering::CLUSTER_ID, 0x0702);
    assert_eq!(metering::REVISION, 2);
    assert_eq!(metering::scaled_summation(&store), 0);
    // Tables stay ascending for the discovery handler.
    let ids: Vec<u16> = metering::ServerDef
        .attributes()
        .iter()
        .map(|a| a.id)
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
    for table in [metering::SERVER_RX, metering::SERVER_TX] {
        let cmds: Vec<u8> = table.iter().map(|c| c.id).collect();
        let mut s = cmds.clone();
        s.sort_unstable();
        assert_eq!(cmds, s);
        let _ = cmds;
    }
}

// 07-5123-08-1042-03: multiplier/divisor scaling incl. zero guards.
#[test]
fn vector_metering_scaling_07_5123_08_1042_03() {
    assert_eq!(metering::scaled_value(52003, 1, 1000), 52);
    assert_eq!(metering::scaled_value(617, 2, 100), 12);
    assert_eq!(metering::scaled_value(u64::MAX, u64::MAX, 1), u64::MAX);
    // Zero divisor is unitary, never a trap; zero multiplier is zero.
    assert_eq!(metering::scaled_value(999, 3, 0), 2997);
    assert_eq!(metering::scaled_value(999, 0, 1000), 0);
}

// 07-5123-08-1042-04: formatting digit layout split.
#[test]
fn vector_metering_formatting_07_5123_08_1042_04() {
    assert_eq!(metering::split_formatting(0b0000_1010), (2, 1, false));
    assert_eq!(metering::split_formatting(0b1001_0011), (3, 2, true));
}

// 07-5123-08-1043-01: GetProfile request exact bytes.
#[test]
fn vector_get_profile_codec_07_5123_08_1043_01() {
    let req = metering::GetProfileRequest {
        channel: 0x00,
        end_time: 0x1234_5678,
        periods: 0x05,
    };
    let mut out = [0u8; 8];
    assert_eq!(metering::encode_get_profile(&req, &mut out), Ok(6));
    assert_eq!(&out[..6], &[0x00, 0x78, 0x56, 0x34, 0x12, 0x05]);
    assert_eq!(metering::decode_get_profile(&out[..6]).unwrap(), req);
    assert!(metering::decode_get_profile(&out[..5]).is_err());
    assert!(metering::decode_get_profile(&out[..7]).is_err());
}

// 07-5123-08-1043-02: profile backlog answers, errors, caps.
#[test]
fn vector_profile_answer_07_5123_08_1043_02() {
    let mut buf = metering::ProfileBuffer::new();
    let req = metering::GetProfileRequest {
        channel: 0,
        end_time: 0,
        periods: 8,
    };
    let mut out = [0u8; 64];
    // Empty backlog is NOT_FOUND, not a silent empty reply.
    assert_eq!(buf.answer(&req, &mut out), Err(ZclStatus::NotFound));
    // Undefined channel is a field error, not NOT_FOUND.
    let bad = metering::GetProfileRequest {
        channel: 0x09,
        end_time: 0,
        periods: 1,
    };
    assert_eq!(buf.answer(&bad, &mut out), Err(ZclStatus::InvalidField));
    buf.record(0x00aa_bb01, 1_000);
    buf.record(0x00cc_dd02, 1_900);
    let req2 = metering::GetProfileRequest {
        channel: 1,
        end_time: 0,
        periods: 8,
    };
    let n = buf.answer(&req2, &mut out).unwrap();
    // end time + success + period enum + count + 2 newest-first uint24s.
    assert_eq!(n, 7 + 6);
    assert_eq!(&out[..4], &1_900u32.to_le_bytes());
    assert_eq!(out[4], metering::PROFILE_STATUS_SUCCESS);
    assert_eq!(out[5], 3);
    assert_eq!(out[6], 2);
    assert_eq!(&out[7..10], &[0x02, 0xdd, 0xcc]);
    assert_eq!(&out[10..13], &[0x01, 0xbb, 0xaa]);
    // A request for zero periods is NOT_FOUND too.
    let zero = metering::GetProfileRequest {
        channel: 0,
        end_time: 0,
        periods: 0,
    };
    assert_eq!(buf.answer(&zero, &mut out), Err(ZclStatus::NotFound));
}

// 07-5123-08-1042-01: consumption accumulation saturates at 48 bits.
#[test]
fn vector_metering_consumption_saturates_07_5123_08_1042_01() {
    let mut store = metering::server_store().unwrap();
    let beh = metering::ServerBehavior::default();
    beh.add_consumption(&mut store, 0x0000_ffff_ffff_ffff);
    beh.add_consumption(&mut store, 0x10);
    assert_eq!(metering::scaled_summation(&store), 0x0000_ffff_ffff_ffff);
}

// ---- electrical.rs --------------------------------------------------

// 07-5123-08-491-01/02 + 07-5123-08-492-01: store shape, unitary scale.
#[test]
fn vector_electrical_store_07_5123_08_492_01() {
    assert_eq!(electrical::CLUSTER_ID, 0x0B04);
    let store = electrical::server_store().unwrap();
    assert_eq!(electrical::scaled_rms_voltage(&store), None);
    assert_eq!(electrical::scaled_rms_current(&store), None);
    assert_eq!(electrical::scaled_active_power(&store), None);
    let ids: Vec<u16> = electrical::ServerDef
        .attributes()
        .iter()
        .map(|a| a.id)
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
}

// 07-5123-08-492-02/03: scale pairs + unknown sentinels + sign rule.
#[test]
fn vector_electrical_scaling_07_5123_08_492_02() {
    assert_eq!(electrical::scaled_u64(2300, 1, 10), 230);
    assert_eq!(electrical::scaled_u64(100, 0, 0), 100);
    assert_eq!(electrical::scaled_i64(-500, 2, 0), -1000);
    let mut store = electrical::server_store().unwrap();
    use rounddance_zcl::types::Value;
    store
        .set_local(
            electrical::ATTR_RMS_VOLTAGE,
            Value::UInt {
                width: 2,
                v: 23_000,
            },
        )
        .unwrap();
    store
        .set_local(
            electrical::ATTR_AC_VOLTAGE_DIVISOR,
            Value::UInt { width: 2, v: 100 },
        )
        .unwrap();
    assert_eq!(electrical::scaled_rms_voltage(&store), Some(230));
}

// ---- price.rs -------------------------------------------------------

// 07-5123-08-1021-01..03: cluster id + label table + write refusal.
#[test]
fn vector_price_store_07_5123_08_1021_03() {
    assert_eq!(price::CLUSTER_ID, 0x0700);
    let store = price::server_store().unwrap();
    let (len, bytes) = price::tier_label(&store, 0).unwrap();
    assert_eq!(len, 6);
    assert_eq!(&bytes[..6], b"Tier 1");
    assert!(price::tier_label(&store, 8).is_none());
    // Tier labels are read-only: writes are refused, never applied.
    let mut store = store;
    let v = Value::OctetStr {
        len: 3,
        bytes: {
            let mut b = [0u8; MAX_STR_LEN];
            b[..3].copy_from_slice(b"Off");
            b
        },
    };
    assert_eq!(
        store.write(price::ATTR_TIER_LABEL_FIRST, v),
        Err(ZclStatus::ReadOnly)
    );
}

// 07-5123-08-1024-01: PublishPrice mandatory prefix exact bytes.
#[test]
fn vector_publish_price_codec_07_5123_08_1024_01() {
    let mut label = [0u8; price::MAX_LABEL];
    label[..5].copy_from_slice(b"TOU-1");
    let ev = price::PublishPrice {
        provider_id: 0x0A0B_0C0D,
        rate_len: 5,
        rate_label: label,
        issuer_event_id: 0x0000_0007,
        current_time: 0x65A1_B2C3,
        unit_of_measure: 0x00,
        currency: 0x0348,
        trailing_tier: 0x23,
        tiers_register: 0x21,
        start_time: 0,
        duration_min: 60,
        price: 12345,
    };
    assert_eq!(ev.price_tier(), 3);
    assert_eq!(ev.trailing_digit(), 2);
    let mut out = [0u8; 48];
    let n = price::encode_publish_price(&ev, &mut out).unwrap();
    assert_eq!(n, 33);
    assert_eq!(
        &out[..n],
        &[
            0x0D, 0x0C, 0x0B, 0x0A, 0x05, 0x54, 0x4F, 0x55, 0x2D, 0x31, 0x07, 0x00, 0x00, 0x00,
            0xC3, 0xB2, 0xA1, 0x65, 0x00, 0x48, 0x03, 0x23, 0x21, 0x00, 0x00, 0x00, 0x00, 0x3C,
            0x00, 0x39, 0x30, 0x00, 0x00,
        ][..]
    );
    let (back, tail) = price::decode_publish_price(&out[..n]).unwrap();
    assert_eq!(back, ev);
    assert_eq!(tail, 0);
    // Optional command tail is tolerated and reported, never parsed.
    let mut tailed = [0u8; 48];
    tailed[..n].copy_from_slice(&out[..n]);
    tailed[n] = 0xAA;
    tailed[n + 1] = 0xBB;
    let (back2, tail2) = price::decode_publish_price(&tailed[..n + 2]).unwrap();
    assert_eq!(back2, ev);
    assert_eq!(tail2, 2);
    assert!(price::decode_publish_price(&out[..n - 1]).is_err());
}

// 07-5123-08-1022-03 + 07-5123-08-1022-05: ack + tier-label codecs.
#[test]
fn vector_price_ack_tier_labels_07_5123_08_1022() {
    let mut out = [0u8; 16];
    assert_eq!(
        price::encode_price_ack(0x0A0B_0C0D, 7, 0x65A1_B2C3, 0x01, &mut out),
        Ok(13)
    );
    assert_eq!(
        &out[..13],
        &[0x0D, 0x0C, 0x0B, 0x0A, 0x07, 0x00, 0x00, 0x00, 0xC3, 0xB2, 0xA1, 0x65, 0x01]
    );
    assert_eq!(
        price::decode_price_ack(&out[..13]).unwrap(),
        (0x0A0B_0C0D, 7, 0x65A1_B2C3, 0x01)
    );
    // GetScheduledPrices: start + count.
    let (start, count) = price::decode_get_scheduled(&[0x10, 0x00, 0x00, 0x00, 0x03]).unwrap();
    assert_eq!((start, count), (0x10, 3));

    let mut label = [0u8; price::MAX_LABEL];
    label[..4].copy_from_slice(b"Peak");
    let entries = [price::TierLabelEntry {
        tier_id: 1,
        len: 4,
        label,
    }];
    let mut buf = [0u8; 64];
    let n = price::encode_publish_tier_labels(9, 8, 7, 0, 1, &entries, &mut buf).unwrap();
    assert_eq!(n, 15 + 2 + 4);
    let mut slot = [price::TierLabelEntry {
        tier_id: 0,
        len: 0,
        label: [0; price::MAX_LABEL],
    }; 4];
    let (p, i, t, idx, c) = price::decode_publish_tier_labels(&buf[..n], &mut slot).unwrap();
    assert_eq!((p, i, t, idx, c), (9, 8, 7, 0, 1));
    assert_eq!(slot[0].tier_id, 1);
    assert_eq!(&slot[0].label[..4], b"Peak");
}

// 07-5123-08-102-03 + 07-5123-08-1024-02: backlog + supersession.
#[test]
fn vector_price_table_supersession_07_5123_08_1024_02() {
    let mut table = price::PriceTable::new();
    assert!(table.is_empty());
    assert!(table.current(100).is_none());
    let base = price::PublishPrice {
        provider_id: 1,
        rate_len: 0,
        rate_label: [0; price::MAX_LABEL],
        issuer_event_id: 10,
        current_time: 0,
        unit_of_measure: 0,
        currency: 0x0348,
        trailing_tier: 0,
        tiers_register: 0,
        start_time: 100,
        duration_min: 60,
        price: 100,
    };
    table.insert(base);
    // Newer issuer wins the overlap.
    let mut newer = base;
    newer.issuer_event_id = 11;
    newer.price = 200;
    table.insert(newer);
    assert_eq!(table.len(), 1);
    assert_eq!(table.current(200).unwrap().price, 200);
    // Older issuer loses against the stored event.
    let mut older = base;
    older.issuer_event_id = 5;
    older.price = 50;
    table.insert(older);
    assert_eq!(table.len(), 1);
    assert_eq!(table.current(200).unwrap().price, 200);
    // Active-tail overlap shortens the predecessor to until-changed
    // instead of dropping it: a newer event starting mid-window.
    let mut table2 = price::PriceTable::new();
    table2.insert(base);
    let mut mid = base;
    mid.issuer_event_id = 11;
    mid.start_time = 200;
    mid.price = 300;
    table2.insert(mid);
    assert_eq!(table2.len(), 2);
    assert_eq!(
        table2.current(150).unwrap().duration_min,
        price::DURATION_UNTIL_CHANGED
    );
    assert_eq!(table2.current(250).unwrap().price, 300);
    // A non-overlapping future event coexists instead.
    let mut future = base;
    future.issuer_event_id = 12;
    future.start_time = 10_000;
    table.insert(future);
    assert_eq!(table.len(), 2);
    table.note_ack(1, 12);
    assert_eq!(table.last_ack(), Some((1, 12)));
}

// 07-5123-08-1024-01 (display): trailing-digit decimal split.
#[test]
fn vector_price_display_parts_07_5123_08_1024_01() {
    assert_eq!(price::display_parts(12345, 2), Some((123, 100)));
    assert_eq!(price::display_parts(7, 0), Some((7, 1)));
    assert_eq!(price::display_parts(7, 10), None);
}

// ---- keyest.rs ------------------------------------------------------

// 07-5123-08-1073-01/02 + 07-5123-08-1074-01: suite store + initiate codec.
#[test]
fn vector_keyest_initiate_codec_07_5123_08_1074_01() {
    assert_eq!(keyest::CLUSTER_ID, 0x0800);
    let store = keyest::server_store().unwrap();
    assert_eq!(
        store.get(keyest::ATTR_SUITE),
        Some(Value::Enum16(keyest::SUITE_1))
    );
    let msg = keyest::InitiateMsg {
        suite: keyest::SUITE_1,
        eph_time: 0x02,
        confirm_time: 0x03,
        cert: [0xA5; 48],
    };
    let mut out = [0u8; 64];
    assert_eq!(keyest::encode_initiate(&msg, &mut out), Ok(52));
    assert_eq!(&out[..4], &[0x01, 0x00, 0x02, 0x03]);
    assert_eq!(&out[4..52], &[0xA5; 48]);
    assert_eq!(keyest::decode_initiate(&out[..52]).unwrap(), msg);
    assert!(keyest::decode_initiate(&out[..51]).is_err());
    // Terminate exact bytes: status + wait + suite.
    let term = keyest::TerminateMsg {
        status: keyest::TERM_BAD_KEY_CONFIRM,
        wait_s: 0x0A,
        suite: keyest::SUITE_1,
    };
    let mut tb = [0u8; 8];
    assert_eq!(keyest::encode_terminate(&term, &mut tb), Ok(4));
    assert_eq!(&tb[..4], &[0x02, 0x0A, 0x01, 0x00]);
    assert_eq!(keyest::decode_terminate(&tb[..4]).unwrap(), term);
}

// Retry advice mapping (07-5123-08-1074-04 effect half).
#[test]
fn vector_keyest_retry_advice_07_5123_08_1074_04() {
    let wait = keyest::TerminateMsg {
        status: keyest::TERM_NO_RESOURCES,
        wait_s: 30,
        suite: keyest::SUITE_1,
    };
    assert_eq!(
        keyest::retry_advice(&wait),
        keyest::RetryAdvice::WaitThenRetry { wait_s: 30 }
    );
    let suite = keyest::TerminateMsg {
        status: keyest::TERM_UNSUPPORTED_SUITE,
        wait_s: 5,
        suite: 0x0002,
    };
    assert_eq!(
        keyest::retry_advice(&suite),
        keyest::RetryAdvice::TryOtherSuite {
            wait_s: 5,
            suite: 0x0002
        }
    );
    let give_up = keyest::TerminateMsg {
        status: keyest::TERM_BAD_KEY_CONFIRM,
        wait_s: 0,
        suite: 0,
    };
    assert_eq!(keyest::retry_advice(&give_up), keyest::RetryAdvice::GiveUp);
}

// Suite-2 wire shape + negotiation (07-5123-08-1073-02 suite bits,
// 07-5123-08-1074-01 initiate framing, 07-5356-22-C312-02 guards):
// the suite-2 bit is advertised, framed byte-exact, and negotiated
// with the same guards as suite 1. The suite-2 crypto core
// (credentials, curve, KDF labels) is residue: no in-repo anchor
// pins a suite-2 certificate/ephemeral size, so nothing here runs a
// suite-2 key derivation.
#[test]
fn vector_keyest_suite2_advertise_07_5123_08_1073_02() {
    assert_eq!(keyest::SUPPORTED_SUITE_MASK, 0x0003);
    assert_eq!(
        keyest::SUPPORTED_SUITE_MASK,
        keyest::SUITE_1 | keyest::SUITE_2
    );
    // Single-bit rule names the wire guard (multi-bit terminates).
    for good in [keyest::SUITE_1, keyest::SUITE_2, 0x0004, 0x8000] {
        assert!(keyest::is_single_suite_bit(good), "0x{good:04x}");
    }
    for bad in [0x0000, 0x0003, 0x00FF, 0xFFFF] {
        assert!(!keyest::is_single_suite_bit(bad), "0x{bad:04x}");
    }
    // Known bits are exactly the two declared suite bits.
    assert!(keyest::is_known_suite(keyest::SUITE_1));
    assert!(keyest::is_known_suite(keyest::SUITE_2));
    for unknown in [0x0000u16, 0x0003, 0x0004, 0x8000, 0xFFFF] {
        assert!(!keyest::is_known_suite(unknown), "0x{unknown:04x}");
    }
    // Advertisement: suite-1 store is unchanged, suite-2 advertises
    // its own bit; anything else is refused, never defaulted.
    let s1 = keyest::server_store().unwrap();
    let s1b = keyest::server_store_for_suite(keyest::SUITE_1).unwrap();
    assert_eq!(
        s1.get(keyest::ATTR_SUITE),
        Some(Value::Enum16(keyest::SUITE_1))
    );
    assert_eq!(
        s1b.get(keyest::ATTR_SUITE),
        Some(Value::Enum16(keyest::SUITE_1))
    );
    let s2 = keyest::server_store_for_suite(keyest::SUITE_2).unwrap();
    assert_eq!(
        s2.get(keyest::ATTR_SUITE),
        Some(Value::Enum16(keyest::SUITE_2))
    );
    for refused in [0x0000u16, 0x0003, 0x0004, 0xFFFF] {
        assert!(
            keyest::server_store_for_suite(refused).is_err(),
            "0x{refused:04x}"
        );
    }
}

// 07-5123-08-1074-01 + 07-5123-08-1074-04: suite-2 framing is
// byte-exact: the suite field carries the suite-2 bit, lengths are
// unchanged (2 + 1 + 1 + 48 initiate, 4 terminate).
#[test]
fn vector_keyest_suite2_framing_07_5123_08_1074_01() {
    let msg = keyest::InitiateMsg {
        suite: keyest::SUITE_2,
        eph_time: 0x02,
        confirm_time: 0x03,
        cert: [0xA5; 48],
    };
    let mut out = [0u8; 64];
    assert_eq!(keyest::encode_initiate(&msg, &mut out), Ok(52));
    assert_eq!(&out[..4], &[0x02, 0x00, 0x02, 0x03]);
    assert_eq!(&out[4..52], &[0xA5; 48]);
    assert_eq!(keyest::decode_initiate(&out[..52]).unwrap(), msg);
    assert!(keyest::decode_initiate(&out[..51]).is_err());
    assert!(keyest::decode_initiate(&out[..53]).is_err());
    // Terminate with a suite-2 mask: exact bytes + fallback advice.
    let term = keyest::TerminateMsg {
        status: keyest::TERM_UNSUPPORTED_SUITE,
        wait_s: 5,
        suite: keyest::SUITE_2,
    };
    let mut tb = [0u8; 8];
    assert_eq!(keyest::encode_terminate(&term, &mut tb), Ok(4));
    assert_eq!(&tb[..4], &[0x05, 0x05, 0x02, 0x00]);
    assert_eq!(keyest::decode_terminate(&tb[..4]).unwrap(), term);
    assert_eq!(
        keyest::retry_advice(&term),
        keyest::RetryAdvice::TryOtherSuite {
            wait_s: 5,
            suite: keyest::SUITE_2,
        }
    );
}

/// ECQV-consistent device provisioning (same construction as the
/// security-crate host vectors: full private key from the cert
/// binding, NOT the cert randomness).
fn provision(
    b: &HostBackend,
    ca_priv: &[u8; 32],
    cert_byte: u8,
    subj: u8,
    k_byte: u8,
) -> ([u8; 32], PeerIdentity) {
    let cert = ImplicitCert::from_bytes([cert_byte; 48]);
    let k = [k_byte; 32];
    let p = b.base_mul(&k).unwrap();
    let subj_arr = [subj; 8];
    let e = scalar_from_kdf(b, &[cert.as_bytes(), &subj_arr, &p], b"ecqv-reconstruct").unwrap();
    let w = b
        .scalar_add(&b.scalar_mul(&e, ca_priv).unwrap(), &k)
        .unwrap();
    (w, PeerIdentity::new(cert, subj_arr, p))
}

struct Pair {
    init: keyest::Exchange,
    resp: keyest::Exchange,
    backend: HostBackend,
}

fn make_pair() -> Pair {
    make_pair_suite(keyest::SUITE_1)
}

fn make_pair_suite(suite: u16) -> Pair {
    let b = HostBackend::new();
    let ca_priv = [0xC0u8; 32];
    let ca_pub = b.base_mul(&ca_priv).unwrap();
    let (w_i, id_i) = provision(&b, &ca_priv, 0xA1, 0x01, 0x11);
    let (w_r, id_r) = provision(&b, &ca_priv, 0xB2, 0x02, 0x33);
    let q_i = b.base_mul(&[0x22; 32]).unwrap();
    let q_r = b.base_mul(&[0x55; 32]).unwrap();
    let init = keyest::Exchange::begin(
        true,
        ca_pub,
        w_i,
        id_i,
        [0x22; 32],
        q_i,
        &[id_i, id_r],
        suite,
    )
    .unwrap();
    let resp = keyest::Exchange::begin(
        false,
        ca_pub,
        w_r,
        id_r,
        [0x55; 32],
        q_r,
        &[id_r, id_i],
        suite,
    )
    .unwrap();
    Pair {
        init,
        resp,
        backend: b,
    }
}

/// Drive the full 8-message handshake through the cluster layer.
fn drive_full(pair: &mut Pair) {
    let b = &pair.backend;
    // Initiate.
    let req = pair.init.initiate_request().unwrap();
    let mut wire = [0u8; 64];
    let n = keyest::encode_initiate(&req, &mut wire).unwrap();
    let rsp = pair
        .resp
        .on_initiate(b, &keyest::decode_initiate(&wire[..n]).unwrap())
        .unwrap();
    let mut wire2 = [0u8; 64];
    let m = keyest::encode_initiate(&rsp, &mut wire2).unwrap();
    pair.init
        .on_initiate_response(b, &keyest::decode_initiate(&wire2[..m]).unwrap())
        .unwrap();
    // Ephemeral.
    let qe_u = pair.init.ephemeral_request().unwrap();
    let qe_v = pair.resp.on_ephemeral_request(b, qe_u.as_slice()).unwrap();
    let mac_u = pair.init.on_ephemeral_response(b, qe_v.as_slice()).unwrap();
    // Confirm.
    let mac_v = pair.resp.on_confirm_request(b, &mac_u).unwrap();
    pair.init.on_confirm_response(b, &mac_v).unwrap();
}

// 07-5356-22-C312-01..08: full cluster-level handshake agrees.
#[test]
fn vector_keyest_handshake_transcript_07_5356_22_c312() {
    let mut pair = make_pair();
    drive_full(&mut pair);
    assert!(pair.init.is_done());
    assert!(pair.resp.is_done());
    assert_eq!(
        pair.init.session_key().unwrap(),
        pair.resp.session_key().unwrap()
    );
    // Trust-center update path: negotiated key installs under the peer.
    let mut table = LinkKeyTable::<4>::new();
    let receipt = keyest::install_negotiated_key(&mut table, &pair.resp, [0x01; 8]).unwrap();
    assert_eq!(receipt.key, pair.resp.session_key().unwrap());
    assert_eq!(table.find(&[0x01; 8]).unwrap().key, receipt.key);
    // Rotation re-keys without a new exchange.
    let rotated = keyest::rotate_link_key(&mut table, [0x01; 8], 1).unwrap();
    assert_ne!(rotated.key, receipt.key);
    assert_eq!(table.find(&[0x01; 8]).unwrap().key, rotated.key);
}

// Negative: a tampered MACV fails the handshake with BAD_KEY_CONFIRM.
#[test]
fn vector_keyest_mac_fail_terminates_07_5356_22_c312_08() {
    let mut pair = make_pair();
    let b = HostBackend::new();
    let req = pair.init.initiate_request().unwrap();
    let rsp = pair.resp.on_initiate(&b, &req).unwrap();
    pair.init.on_initiate_response(&b, &rsp).unwrap();
    let qe_u = pair.init.ephemeral_request().unwrap();
    let qe_v = pair.resp.on_ephemeral_request(&b, qe_u.as_slice()).unwrap();
    let mac_u = pair
        .init
        .on_ephemeral_response(&b, qe_v.as_slice())
        .unwrap();
    let mac_v = pair.resp.on_confirm_request(&b, &mac_u).unwrap();
    // Tamper one bit of the responder tag on the wire.
    let mut bad = mac_v;
    bad[0] ^= 0x01;
    assert_eq!(
        pair.init.on_confirm_response(&b, &bad),
        Err(keyest::ExchangeError::Terminated)
    );
    assert_eq!(
        pair.init.take_terminate().unwrap().status,
        keyest::TERM_BAD_KEY_CONFIRM
    );
    assert_eq!(pair.init.stage(), keyest::Stage::Failed);
    assert_eq!(pair.init.session_key(), Err(CbkeError::NotDone));
    // A failed exchange never releases a key into the table either.
    let mut table = LinkKeyTable::<4>::new();
    assert!(keyest::install_negotiated_key(&mut table, &pair.init, [0x01; 8]).is_err());
    assert!(table.is_empty());
}

// Initiation guards: suite and issuer failures terminate (corpus
// 07-5123-08-107-02/03/04 + 07-5356-22-C312-02/03).
#[test]
fn vector_keyest_initiate_guards_07_5356_22_c312_02() {
    let mut pair = make_pair();
    let b = HostBackend::new();
    // Multi-bit suite field: BAD_MESSAGE.
    let mut multi = pair.init.initiate_request().unwrap();
    multi.suite = 0x0003;
    assert_eq!(
        pair.resp.on_initiate(&b, &multi),
        Err(keyest::ExchangeError::Terminated)
    );
    assert_eq!(
        pair.resp.take_terminate().unwrap().status,
        keyest::TERM_BAD_MESSAGE
    );

    // Unknown suite bit: UNSUPPORTED_SUITE.
    let mut pair = make_pair();
    let mut other = pair.init.initiate_request().unwrap();
    other.suite = keyest::SUITE_2;
    assert_eq!(
        pair.resp.on_initiate(&b, &other),
        Err(keyest::ExchangeError::Terminated)
    );
    assert_eq!(
        pair.resp.take_terminate().unwrap().status,
        keyest::TERM_UNSUPPORTED_SUITE
    );

    // Unknown issuer: UNKNOWN_ISSUER, and on_terminate advises give-up.
    let mut pair = make_pair();
    let mut foreign = pair.init.initiate_request().unwrap();
    foreign.cert = [0xEE; 48];
    assert_eq!(
        pair.resp.on_initiate(&b, &foreign),
        Err(keyest::ExchangeError::Terminated)
    );
    let term = pair.resp.take_terminate().unwrap();
    assert_eq!(term.status, keyest::TERM_UNKNOWN_ISSUER);
    assert_eq!(pair.resp.on_terminate(&term), keyest::RetryAdvice::GiveUp);

    // Short ephemeral: BAD_MESSAGE.
    let mut pair = make_pair();
    let req = pair.init.initiate_request().unwrap();
    let rsp = pair.resp.on_initiate(&b, &req).unwrap();
    pair.init.on_initiate_response(&b, &rsp).unwrap();
    assert_eq!(
        pair.resp.on_ephemeral_request(&b, &[0u8; 22]),
        Err(keyest::ExchangeError::Terminated)
    );
    assert_eq!(
        pair.resp.take_terminate().unwrap().status,
        keyest::TERM_BAD_MESSAGE
    );
}

// Suite-2 negotiation (07-5123-08-107-02/03/04 +
// 07-5356-22-C312-02/03): a suite-2-configured pair accepts the
// suite-2 bit through initiation and rejects anything else with
// the same guard table as suite 1 — never a crypto run, only the
// negotiation half (suite-2 key derivation is residue).
#[test]
fn vector_keyest_suite2_negotiation_07_5356_22_c312_02() {
    let mut pair = make_pair_suite(keyest::SUITE_2);
    let b = HostBackend::new();
    // Acceptance: the suite-2 bit passes both initiation halves and
    // parks both sides at Initiated with the bit preserved.
    let req = pair.init.initiate_request().unwrap();
    assert_eq!(req.suite, keyest::SUITE_2);
    let rsp = pair.resp.on_initiate(&b, &req).unwrap();
    assert_eq!(rsp.suite, keyest::SUITE_2);
    pair.init.on_initiate_response(&b, &rsp).unwrap();
    assert_eq!(pair.init.stage(), keyest::Stage::Initiated);
    assert_eq!(pair.resp.stage(), keyest::Stage::Initiated);
    // The initiator still offers ephemeral framing after a
    // suite-2 initiation (framing half, not derivation).
    assert!(pair.init.ephemeral_request().is_ok());

    // Foreign single bit (suite 1): UNSUPPORTED_SUITE, and the
    // queued terminate carries our own suite-2 bit.
    let mut pair = make_pair_suite(keyest::SUITE_2);
    let mut foreign = pair.init.initiate_request().unwrap();
    foreign.suite = keyest::SUITE_1;
    assert_eq!(
        pair.resp.on_initiate(&b, &foreign),
        Err(keyest::ExchangeError::Terminated)
    );
    let term = pair.resp.take_terminate().unwrap();
    assert_eq!(term.status, keyest::TERM_UNSUPPORTED_SUITE);
    assert_eq!(term.suite, keyest::SUITE_2);

    // Multi-bit suite field: BAD_MESSAGE (same rule as suite 1).
    let mut pair = make_pair_suite(keyest::SUITE_2);
    let mut multi = pair.init.initiate_request().unwrap();
    multi.suite = keyest::SUITE_1 | keyest::SUITE_2;
    assert_eq!(
        pair.resp.on_initiate(&b, &multi),
        Err(keyest::ExchangeError::Terminated)
    );
    assert_eq!(
        pair.resp.take_terminate().unwrap().status,
        keyest::TERM_BAD_MESSAGE
    );

    // Zero suite field: BAD_MESSAGE, not unsupported.
    let mut pair = make_pair_suite(keyest::SUITE_2);
    let mut zero = pair.init.initiate_request().unwrap();
    zero.suite = 0x0000;
    assert_eq!(
        pair.resp.on_initiate(&b, &zero),
        Err(keyest::ExchangeError::Terminated)
    );
    assert_eq!(
        pair.resp.take_terminate().unwrap().status,
        keyest::TERM_BAD_MESSAGE
    );

    // Mirror: a suite-1 initiator rejects a suite-2 response with
    // UNSUPPORTED_SUITE (initiate-response half).
    let mut pair = make_pair_suite(keyest::SUITE_1);
    let req = pair.init.initiate_request().unwrap();
    let mut rsp2 = pair.resp.on_initiate(&b, &req).unwrap();
    rsp2.suite = keyest::SUITE_2;
    assert_eq!(
        pair.init.on_initiate_response(&b, &rsp2),
        Err(keyest::ExchangeError::Terminated)
    );
    assert_eq!(
        pair.init.take_terminate().unwrap().status,
        keyest::TERM_UNSUPPORTED_SUITE
    );
}

// Out-of-sequence messages terminate (07-5356-22-C312-06).
#[test]
fn vector_keyest_sequence_guard_07_5356_22_c312_06() {
    let mut pair = make_pair();
    let b = HostBackend::new();
    // Confirm before any initiation.
    assert_eq!(
        pair.resp.on_confirm_request(&b, &[0u8; 16]),
        Err(keyest::ExchangeError::Terminated)
    );
    assert_eq!(
        pair.resp.take_terminate().unwrap().status,
        keyest::TERM_BAD_MESSAGE
    );
    // Initiator cannot speak first with ephemeral material.
    let mut pair = make_pair();
    assert_eq!(
        pair.init.on_ephemeral_response(&b, &[0u8; 64]),
        Err(keyest::ExchangeError::Terminated)
    );
}

// Ephemeral length rule is exact (profile convention 1074-05).
#[test]
fn vector_keyest_ephemeral_length_07_5123_08_1074_05() {
    assert_eq!(keyest::EPH_LEN, 64);
    let mut pair = make_pair();
    let b = HostBackend::new();
    let req = pair.init.initiate_request().unwrap();
    let rsp = pair.resp.on_initiate(&b, &req).unwrap();
    pair.init.on_initiate_response(&b, &rsp).unwrap();
    let mut long = [0u8; 65];
    let qe = pair.init.ephemeral_request().unwrap();
    long[..64].copy_from_slice(qe.as_slice());
    assert_eq!(
        pair.resp.on_ephemeral_request(&b, &long),
        Err(keyest::ExchangeError::Terminated)
    );
}

// Ephemeral wire forms: the transmit preference only shapes our own
// flights (07-5123-08-1074-05 + 07-5356-22-C312-06/07).
#[test]
fn vector_keyest_compressed_forms_07_5123_08_1074_05() {
    use rounddance_security::decompress_point;

    fn as33(slice: &[u8]) -> [u8; 33] {
        let mut c = [0u8; 33];
        c.copy_from_slice(slice);
        c
    }

    let mut pair = make_pair();
    let b = HostBackend::new();
    // Default transmit is the expanded convention.
    assert!(!pair.init.tx_compressed());
    let req = pair.init.initiate_request().unwrap();
    let rsp = pair.resp.on_initiate(&b, &req).unwrap();
    pair.init.on_initiate_response(&b, &rsp).unwrap();
    let default = pair.init.ephemeral_request().unwrap();
    assert!(!default.is_compressed());
    assert_eq!(default.len(), keyest::EPH_LEN);
    assert_eq!(default.as_slice().len(), 64);
    // Preferred compressed transmit expands to the same point.
    pair.init.set_tx_compressed(true);
    assert!(pair.init.tx_compressed());
    let compressed = pair.init.ephemeral_request().unwrap();
    assert!(compressed.is_compressed());
    assert_eq!(compressed.len(), keyest::EPH_COMPRESSED_LEN);
    let expanded = match default {
        keyest::EphemeralPayload::Expanded(p) => p,
        keyest::EphemeralPayload::Compressed(_) => unreachable!(),
    };
    assert_eq!(
        decompress_point(&as33(compressed.as_slice())).unwrap(),
        expanded
    );
    // The responder accepts the compressed flight and answers in its
    // own (default expanded) form.
    let answer = pair
        .resp
        .on_ephemeral_request(&b, compressed.as_slice())
        .unwrap();
    assert!(!answer.is_compressed());
}

// Compressed ephemeral flights complete the handshake with the same
// session key as the expanded run: the transcript absorbs expanded
// points, so the wire form never splits the keys
// (07-5356-22-C312-06/07 + 07-5123-08-1074-05).
#[test]
fn vector_keyest_compressed_handshake_07_5356_22_c312() {
    let mut pair = make_pair();
    pair.init.set_tx_compressed(true);
    pair.resp.set_tx_compressed(true);
    drive_full(&mut pair);
    assert!(pair.init.is_done());
    assert!(pair.resp.is_done());
    assert_eq!(
        pair.init.session_key().unwrap(),
        pair.resp.session_key().unwrap()
    );
    // Mixed forms agree too, and match the expanded-only run.
    let mut mixed = make_pair();
    mixed.init.set_tx_compressed(true);
    drive_full(&mut mixed);
    assert_eq!(
        mixed.init.session_key().unwrap(),
        pair.init.session_key().unwrap()
    );
    let mut plain = make_pair();
    drive_full(&mut plain);
    assert_eq!(
        plain.init.session_key().unwrap(),
        pair.init.session_key().unwrap()
    );
}

// Malformed ephemeral payloads terminate with BAD_MESSAGE — never a
// silent wrong point and never a certificate defect
// (07-5123-08-1074-02 + 07-5356-22-C312-06/07).
#[test]
fn vector_keyest_compressed_rejection_07_5123_08_1074_02() {
    // Non-residue x = 2 with an even tag: well-formed length, no
    // curve point.
    let mut nonresidue = [0u8; 33];
    nonresidue[0] = 0x02;
    nonresidue[32] = 2;
    // Unknown tag over a valid x (taken from a live ephemeral).
    let mut pair = make_pair();
    let b = HostBackend::new();
    let req = pair.init.initiate_request().unwrap();
    let rsp = pair.resp.on_initiate(&b, &req).unwrap();
    pair.init.on_initiate_response(&b, &rsp).unwrap();
    let live = pair.init.ephemeral_request().unwrap();
    let mut badtag = [0u8; 33];
    badtag[0] = 0x04;
    badtag[1..].copy_from_slice(&live.as_slice()[..32]);

    for qe in [&nonresidue[..], &badtag[..], &[0u8; 32][..], &[0u8; 34][..]] {
        // Responder path.
        let mut pair = make_pair();
        let req = pair.init.initiate_request().unwrap();
        let rsp = pair.resp.on_initiate(&b, &req).unwrap();
        pair.init.on_initiate_response(&b, &rsp).unwrap();
        assert_eq!(
            pair.resp.on_ephemeral_request(&b, qe),
            Err(keyest::ExchangeError::Terminated)
        );
        assert_eq!(
            pair.resp.take_terminate().unwrap().status,
            keyest::TERM_BAD_MESSAGE
        );
        assert_eq!(pair.resp.stage(), keyest::Stage::Failed);
        // Initiator path.
        let mut pair = make_pair();
        let req = pair.init.initiate_request().unwrap();
        let rsp = pair.resp.on_initiate(&b, &req).unwrap();
        pair.init.on_initiate_response(&b, &rsp).unwrap();
        assert_eq!(
            pair.init.on_ephemeral_response(&b, qe),
            Err(keyest::ExchangeError::Terminated)
        );
        assert_eq!(
            pair.init.take_terminate().unwrap().status,
            keyest::TERM_BAD_MESSAGE
        );
        assert_eq!(pair.init.stage(), keyest::Stage::Failed);
    }
}

// ---- price.rs: block periods + block thresholds --------------------
// (wave-22 coverage expansion; corpus-mined 102-01/02/03 + 104-02
// reused, codec/table/store rows repo-minted MINTED-pending-confirm)

fn block_period_fixture() -> price::BlockPeriod {
    price::BlockPeriod {
        provider_id: 0x1122_3344,
        issuer_event_id: 0x0000_0010,
        start_time: 0x1000_0000,
        duration: 60,
        control: 0x01,
        duration_type: 0x20,
        tariff_type: 0x00,
        tariff_resolution: 0x00,
    }
}

// 07-5123-08-1025-01: PublishBlockPeriod 19-octet codec.
#[test]
fn vector_block_period_codec_07_5123_08_1025_01() {
    let ev = block_period_fixture();
    let mut out = [0u8; 20];
    assert_eq!(price::encode_publish_block_period(&ev, &mut out), Ok(19));
    assert_eq!(
        &out[..19],
        &[
            0x44, 0x33, 0x22, 0x11, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x3c, 0x00,
            0x00, 0x01, 0x20, 0x00, 0x00,
        ]
    );
    assert_eq!(price::decode_publish_block_period(&out[..19]).unwrap(), ev);
    assert!(ev.ack_required());
    assert!(!ev.repeating());
    assert_eq!(ev.timebase(), price::DUR_BASE_MINUTES);
    assert!(price::decode_publish_block_period(&out[..18]).is_err());
    assert!(price::decode_publish_block_period(&out[..20]).is_err());
    let mut wide = ev;
    wide.duration = price::BLOCK_DURATION_UNTIL_CHANGED + 1;
    assert!(price::encode_publish_block_period(&wide, &mut out).is_err());
}

// 07-5123-08-1023-01: Get Block Period(s) codec (5- and 6-octet).
#[test]
fn vector_get_block_periods_codec_07_5123_08_1023_01() {
    let req = price::decode_get_block_periods(&[0x00, 0x00, 0x00, 0x00, 0x02]).unwrap();
    assert_eq!(req.start_time, 0);
    assert_eq!(req.max_events, 2);
    assert_eq!(req.tariff_type, None);
    let req2 = price::decode_get_block_periods(&[0x78, 0x56, 0x34, 0x12, 0x00, 0x01]).unwrap();
    assert_eq!(req2.start_time, 0x1234_5678);
    assert_eq!(req2.max_events, 0);
    assert_eq!(req2.tariff_type, Some(0x01));
    assert!(price::decode_get_block_periods(&[0x00, 0x00, 0x00, 0x00]).is_err());
    assert!(price::decode_get_block_periods(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).is_err());
}

// 07-5123-08-1025-02 + 102-03: backlog supersession + cancel.
#[test]
fn vector_block_table_supersede_cancel_07_5123_08_1025_02() {
    let mut table = price::BlockTable::new();
    assert!(table.is_empty());
    let first = block_period_fixture();
    table.insert(first);
    assert_eq!(table.len(), 1);
    // Same window, older-or-equal issuer: newcomer loses.
    let mut stale = first;
    stale.issuer_event_id = 0x0000_0005;
    table.insert(stale);
    assert_eq!(table.len(), 1);
    // Same window, newer issuer: replaces.
    let mut newer = first;
    newer.issuer_event_id = 0x0000_0020;
    table.insert(newer);
    assert_eq!(table.len(), 1);
    let mut hits = [newer; price::MAX_BLOCK_PERIODS];
    let n = table.scheduled_since(0x1000_0000, 0, None, &mut hits);
    assert_eq!(n, 1);
    assert_eq!(hits[0].issuer_event_id, 0x0000_0020);
    // Cancel by provider + issuer removes it.
    let mut cancel = newer;
    cancel.start_time = price::BLOCK_START_CANCEL;
    table.insert(cancel);
    assert!(table.is_empty());
    // Mirror tracks the covering period.
    table.insert(newer);
    let mut beh = price::ServerBehavior::new();
    beh.blocks_mut().insert(newer);
    beh.refresh_block_mirror(0x1000_0000 + 100);
    assert_eq!(beh.block_mirror(), (0x1000_0000, 60, 0x20));
}

// 07-5123-08-1026-01: PublishBlockThresholds codec (tier/count nibbles).
#[test]
fn vector_block_thresholds_codec_07_5123_08_1026_01() {
    // Header (19) + set(tier 2, count 2) + 2x uint48.
    let wire: [u8; 19 + 1 + 12] = [
        0x44, 0x33, 0x22, 0x11, // provider
        0x07, 0x00, 0x00, 0x00, // issuer
        0x00, 0x00, 0x00, 0x10, // start
        0x55, 0x00, 0x00, 0x00, // tariff
        0x00, 0x01, 0x00, // index 0, total 1, per-tier control
        0x22, // tier 2, count 2
        0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, // 1000
        0x10, 0x27, 0x00, 0x00, 0x00, 0x00, // 10000
    ];
    let msg = price::decode_publish_block_thresholds(&wire).unwrap();
    assert_eq!(msg.provider_id, 0x1122_3344);
    assert_eq!(msg.issuer_tariff_id, 0x55);
    assert_eq!(msg.set_count, 1);
    assert_eq!(msg.sets[0].tier, 2);
    assert_eq!(msg.sets[0].count, 2);
    assert_eq!(msg.sets[0].values[0], 1000);
    assert_eq!(msg.sets[0].values[1], 10000);
    let mut out = [0u8; 64];
    assert_eq!(
        price::encode_publish_block_thresholds(&msg, &mut out),
        Ok(wire.len())
    );
    assert_eq!(&out[..wire.len()], &wire);
    // All-tiers control with a nonzero tier nibble is refused.
    let mut bad = wire;
    bad[18] = 0x01;
    assert!(price::decode_publish_block_thresholds(&bad).is_err());
    // Zero total / index past total refused.
    let mut bad2 = wire;
    bad2[17] = 0x00;
    assert!(price::decode_publish_block_thresholds(&bad2).is_err());
}

// 07-5123-08-102-02 + 104-02: tariff shape + scaled thresholds.
#[test]
fn vector_threshold_shape_and_scale_07_5123_08_102_02() {
    assert_eq!(price::threshold_count_for_tariff(true, 5), 0);
    assert_eq!(price::threshold_count_for_tariff(false, 0), 1);
    assert_eq!(price::threshold_count_for_tariff(false, 3), 3);
    assert_eq!(price::threshold_count_for_tariff(false, 15), 15);
    assert_eq!(price::threshold_count_for_tariff(false, 200), 15);
    assert_eq!(price::scaled_threshold(52003, 1, 1000), 52);
    assert_eq!(price::scaled_threshold(999, 3, 0), 2997);
    assert_eq!(price::scaled_threshold(999, 0, 1000), 0);
}

// 07-5123-08-1023-01/02: behavior serves block periods + thresholds,
// NOT_FOUND when empty.
#[test]
fn vector_block_serve_and_not_found_07_5123_08_1023() {
    use rounddance_zcl::behavior::{Behavior, Ctx, EventQueue};
    use rounddance_zcl::frame::{Direction, FrameControl, FrameType, Header};
    let mut store = price::server_store().unwrap();
    let mut eng = rounddance_zcl::ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = price::ServerBehavior::new();
    let header = Header {
        control: FrameControl {
            frame_type: FrameType::ClusterSpecific,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x60,
        command_id: price::CMD_GET_BLOCK_PERIODS,
    };
    // Empty backlog: NOT_FOUND for both queries.
    {
        let mut ctx = Ctx {
            store: &mut store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 0x1000_0000,
            peer_onoff: None,
            sender_ieee: None,
        };
        assert_eq!(
            <price::ServerBehavior as Behavior>::handle_cluster_command(
                &mut beh,
                &mut ctx,
                &header,
                price::CMD_GET_BLOCK_PERIODS,
                &[0x00, 0x00, 0x00, 0x00, 0x00]
            ),
            Err(rounddance_zcl::ZclStatus::NotFound)
        );
        assert_eq!(
            <price::ServerBehavior as Behavior>::handle_cluster_command(
                &mut beh,
                &mut ctx,
                &header,
                price::CMD_GET_BLOCK_THRESHOLDS,
                &[0x55, 0x00, 0x00, 0x00]
            ),
            Err(rounddance_zcl::ZclStatus::NotFound)
        );
    }
    // Load one period + one threshold set, then serve both.
    beh.blocks_mut().insert(block_period_fixture());
    let wire: [u8; 32] = [
        0x44, 0x33, 0x22, 0x11, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x55, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x22, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00,
        0x00, 0x00,
    ];
    let msg = price::decode_publish_block_thresholds(&wire).unwrap();
    beh.thresholds_insert(&msg);
    {
        let mut ctx = Ctx {
            store: &mut store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 0x1000_0000,
            peer_onoff: None,
            sender_ieee: None,
        };
        <price::ServerBehavior as Behavior>::handle_cluster_command(
            &mut beh,
            &mut ctx,
            &header,
            price::CMD_GET_BLOCK_PERIODS,
            &[0x00, 0x00, 0x00, 0x00, 0x00],
        )
        .unwrap();
        <price::ServerBehavior as Behavior>::handle_cluster_command(
            &mut beh,
            &mut ctx,
            &header,
            price::CMD_GET_BLOCK_THRESHOLDS,
            &[0x55, 0x00, 0x00, 0x00],
        )
        .unwrap();
    }
    // Two outbound answers: the 19-octet period + the threshold set.
    let mut kinds = Vec::new();
    while let Some(ev) = events.pop() {
        if let rounddance_zcl::AppEvent::OutboundCommand { cmd, len, .. } = ev {
            kinds.push((cmd, len));
        }
    }
    assert_eq!(
        kinds,
        vec![
            (price::CMD_PUBLISH_BLOCK_PERIOD, 19),
            (price::CMD_PUBLISH_BLOCK_THRESHOLDS, 32)
        ]
    );
}

// 07-5123-08-1023-02: threshold store keeps newest per tariff.
#[test]
fn vector_threshold_store_newest_wins_07_5123_08_1023_02() {
    let wire: [u8; 32] = [
        0x44, 0x33, 0x22, 0x11, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x55, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x22, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00,
        0x00, 0x00,
    ];
    let msg = price::decode_publish_block_thresholds(&wire).unwrap();
    let mut store = price::ThresholdStore::new();
    store.insert(&msg);
    assert_eq!(store.for_tariff(0x55).unwrap().issuer_event_id, 7);
    assert!(store.for_tariff(0x56).is_none());
    // Older-or-equal issuer for the same tariff loses.
    let mut older = msg;
    older.issuer_event_id = 3;
    store.insert(&older);
    assert_eq!(store.for_tariff(0x55).unwrap().issuer_event_id, 7);
    let mut newer = msg;
    newer.issuer_event_id = 9;
    store.insert(&newer);
    assert_eq!(store.for_tariff(0x55).unwrap().issuer_event_id, 9);
}
