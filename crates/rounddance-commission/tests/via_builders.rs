//! Relay-leg builder checks: the `*_via` constructors carry the same
//! NWK MSDU as the direct builders with only the MAC destination
//! changed (Trust Center -> router -> grandchild relay contract).
//!
//! @covers doc=05-3474-23 rev=R23.2 clause=3.6 lines=p0221-L5224 req=05-3474-23-3661-01
//! @covers doc=05-3474-23 rev=R23.2 clause=3.6 lines=p0221-L5224 req=05-3474-23-3661-02

use rounddance_commission::{
    build_secured_nwk_frame, build_secured_nwk_frame_via, build_transport_key_frame,
    build_transport_key_frame_via, ha_transport_key, SecuredNwkParams, TransportKeyParams,
    SECURED_FRAME_MAX, TRANSPORT_FRAME_LEN,
};

const TEST_NETKEY: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const TC: [u8; 8] = [0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
const JOINER: [u8; 8] = [0x6d, 0x49, 0x11, 0xfe, 0xff, 0x13, 0x8d, 0x34];

fn tkey_params(dst_short: u16) -> TransportKeyParams {
    TransportKeyParams {
        dst_pan: 0xC601,
        dst_short,
        dst_eui: JOINER,
        src_eui: TC,
        mac_seq: 0x5a,
        nwk_seq: 0x21,
        nwk_radius: 0x1e,
        aps_ctr: 0x51,
        auxctr: 0x0000_1000,
        seq_no: 0x00,
        netkey: TEST_NETKEY,
        transport_key: ha_transport_key().unwrap(),
    }
}

fn secured_params(dst_short: u16) -> SecuredNwkParams {
    SecuredNwkParams {
        dst_pan: 0xC601,
        dst_short,
        src_short: 0x0000,
        broadcast: false,
        src_eui: TC,
        mac_seq: 0x5a,
        nwk_seq: 0x21,
        nwk_radius: 0x1e,
        auxctr: 0x0000_2000,
        netkey: TEST_NETKEY,
    }
}

#[test]
fn transport_via_self_matches_direct_builder() {
    // Degenerate relay (MAC dst == NWK dst) is byte-identical to the
    // direct builder: same MSDU, same MAC.
    let p = tkey_params(0x0003);
    let mut direct = [0u8; TRANSPORT_FRAME_LEN];
    let mut via = [0u8; TRANSPORT_FRAME_LEN];
    let n = build_transport_key_frame(&p, &mut direct).unwrap();
    let m = build_transport_key_frame_via(&p, 0x0003, &mut via).unwrap();
    assert_eq!((n, m), (TRANSPORT_FRAME_LEN, TRANSPORT_FRAME_LEN));
    assert_eq!(direct, via);
}

#[test]
fn transport_via_router_differs_only_in_mac_dst() {
    // Relay leg to 0x0003 through 0x0002: only the MAC destination
    // octets (LE at [5..7]) change; the NWK MSDU is preserved so the
    // joiner's nonce/AAD open accepts either leg.
    let p = tkey_params(0x0003);
    let mut direct = [0u8; TRANSPORT_FRAME_LEN];
    let mut relay = [0u8; TRANSPORT_FRAME_LEN];
    build_transport_key_frame(&p, &mut direct).unwrap();
    build_transport_key_frame_via(&p, 0x0002, &mut relay).unwrap();
    assert_eq!(&relay[5..7], &0x0002u16.to_le_bytes());
    assert_eq!(&direct[5..7], &0x0003u16.to_le_bytes());
    assert_eq!(&relay[..5], &direct[..5]);
    assert_eq!(&relay[7..], &direct[7..]);
}

#[test]
fn transport_via_refuses_short_buffer() {
    let p = tkey_params(0x0003);
    let mut tiny = [0u8; TRANSPORT_FRAME_LEN - 1];
    assert!(build_transport_key_frame_via(&p, 0x0002, &mut tiny).is_err());
}

#[test]
fn secured_via_self_matches_direct_builder() {
    let pt = [0x00u8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07];
    let p = secured_params(0x0003);
    let mut direct = [0u8; SECURED_FRAME_MAX];
    let mut via = [0u8; SECURED_FRAME_MAX];
    let n = build_secured_nwk_frame(&pt, &p, &mut direct).unwrap();
    let m = build_secured_nwk_frame_via(&pt, &p, 0x0003, &mut via).unwrap();
    assert_eq!(n, m);
    assert_eq!(&direct[..n], &via[..m]);
}

#[test]
fn secured_via_router_differs_only_in_mac_dst() {
    let pt = [0x00u8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07];
    let p = secured_params(0x0003);
    let mut direct = [0u8; SECURED_FRAME_MAX];
    let mut relay = [0u8; SECURED_FRAME_MAX];
    let n = build_secured_nwk_frame(&pt, &p, &mut direct).unwrap();
    let m = build_secured_nwk_frame_via(&pt, &p, 0x0002, &mut relay).unwrap();
    assert_eq!(n, m);
    assert_eq!(&relay[5..7], &0x0002u16.to_le_bytes());
    assert_eq!(&direct[5..7], &0x0003u16.to_le_bytes());
    assert_eq!(&relay[..5], &direct[..5]);
    assert_eq!(&relay[7..n], &direct[7..n]);
}

#[test]
fn secured_via_broadcast_ignores_mac_dst() {
    // Broadcast delivery keeps the 41 88 / 0xFFFF MAC shape whatever
    // next hop is passed: there is no relay MAC choice to make.
    let pt = [0x00u8, 0x01];
    let mut p = secured_params(0xFFFD);
    p.broadcast = true;
    let mut a = [0u8; SECURED_FRAME_MAX];
    let mut b = [0u8; SECURED_FRAME_MAX];
    let n = build_secured_nwk_frame_via(&pt, &p, 0x0002, &mut a).unwrap();
    let m = build_secured_nwk_frame_via(&pt, &p, 0x0003, &mut b).unwrap();
    assert_eq!(n, m);
    assert_eq!(a[0], 0x41);
    assert_eq!(&a[..n], &b[..m]);
}

#[test]
fn secured_via_refuses_oversize_and_short_buffer() {
    let p = secured_params(0x0003);
    let big = [0u8; 97];
    let mut out = [0u8; SECURED_FRAME_MAX];
    assert!(build_secured_nwk_frame_via(&big, &p, 0x0002, &mut out).is_err());
    let pt = [0u8; 4];
    let mut tiny = [0u8; 10];
    assert!(build_secured_nwk_frame_via(&pt, &p, 0x0002, &mut tiny).is_err());
}
