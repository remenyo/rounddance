//! Scripted network-address conflict: a stray announce claims A's
//! address, A detects, decides, and re-announces under a fresh one.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `05-3474-23-36110-01` (detect + table scan),
//! `05-3474-23-36110-02` (router adopts), `05-3474-23-36110-03`
//! (report names the previous address), `05-3474-23-36110-04`
//! (re-announce act edge), `05-3474-23-24311-11` (announce shape),
//! `SCOPE.md` §8 (decision determinism).

use rounddance_aps::{DataDest, DataHeader, DeliveryMode, FrameControl};
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap as _, MacMgmtSap as _, TxOptions, TxRequest,
    TxStatus,
};
use rounddance_nwk::{build_data_header, decode as nwk_decode, DiscoverRoute, NldeDataRequest};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};
use rounddance_zdo::{
    decide_local_conflict, detect_local_conflict, first_table_conflict, reannounce,
    ConflictDecision, ConflictRole, DeviceAnnce, NeighborEntry, CLUSTER_DEVICE_ANNCE,
    MAX_NEIGHBORS,
};

const PAN: u16 = 0x1a2b;
const NODE_A: u16 = 0x0001;
const NODE_B: u16 = 0x0002;
const IEEE_A: u64 = 0x0200_0000_0000_0001;
const IEEE_B: u64 = 0x0200_0000_0000_0002;
const ZDP_PROFILE: u16 = 0x0000;
/// Announce destination: broadcast to receivers-on-when-idle.
const RX_ON_BROADCAST: u16 = 0xFFFD;

/// Wrap ZDP octets in an APS data APDU on the ZDO endpoint pair.
fn zdp_apdu(cluster: u16, counter: u8, zdp: &[u8]) -> Vec<u8> {
    let header = DataHeader {
        control: FrameControl {
            ack_request: false,
            ..FrameControl::data(DeliveryMode::Broadcast)
        },
        dest: DataDest::Broadcast { dst_endpoint: 0xFF },
        cluster_id: cluster,
        profile_id: ZDP_PROFILE,
        src_endpoint: 0x00,
        counter,
        ext: None,
    };
    let mut out = vec![0u8; header.header_len() + zdp.len()];
    let n = header.encode_into(zdp, &mut out).unwrap();
    out.truncate(n);
    out
}

/// Wrap an APDU in an NWK data NPDU from `src` to `dst`.
fn npdu(src: u16, dst: u16, apdu: &[u8]) -> Vec<u8> {
    let req = NldeDataRequest {
        dst_addr: dst,
        use_alias: false,
        alias_src: 0,
        alias_seq: 0,
        radius_param: 3,
        discover_route: DiscoverRoute::Suppress,
        generated_seq: 0x42,
        local_short_addr: src,
        max_depth: 5,
        associated: true,
    };
    let header = build_data_header(&req).unwrap();
    let mut out = vec![0u8; header.header_len() + apdu.len()];
    let n = header.encode_into(apdu, &mut out).unwrap();
    out.truncate(n);
    out
}

/// One medium trip: queue `frame` on a loopback radio and return the
/// delivered on-air copy.
fn trip(seed: u64, node: u16, dst: u16, frame: &[u8]) -> Vec<u8> {
    let mut radio = ScriptedRadio::new(Seed(seed), vec![ScriptAction::Deliver]);
    radio.reset(true);
    radio.set_channel(Channel::new(15).unwrap()).unwrap();
    radio.set_pan_id(PAN);
    radio.set_short_addr(node);
    radio
        .data_request(TxRequest {
            dst: MacAddress::short(PAN, dst),
            msdu: FramePayload::from_slice(frame).expect("fits one MSDU"),
            options: TxOptions::NONE,
        })
        .expect("queue has room");
    radio.run_until_idle(16);
    let confirm = radio.poll_confirm().expect("script always confirms");
    assert_eq!(confirm.status, TxStatus::Delivered);
    radio
        .poll_indication()
        .expect("delivery implies indication")
        .msdu
        .as_slice()
        .to_vec()
}

/// Decode one on-air frame back to its announce body.
fn hear_annce(air: &[u8]) -> DeviceAnnce {
    let npdu = nwk_decode(air).unwrap();
    let aps = rounddance_aps::decode_data(npdu.payload).unwrap();
    assert_eq!(aps.header.cluster_id, CLUSTER_DEVICE_ANNCE);
    DeviceAnnce::decode(aps.payload).unwrap()
}

// 05-3474-23-36110-01/02/03/04: B's stray announce claims A's
// address; A (router) detects the local conflict, confirms it
// against its neighbor page, adopts a fresh address with the
// previous one named for report, and re-announces under the new
// address — which raises no conflict at B.
#[test]
fn announce_conflict_router_adopts_and_reannounces() {
    // B strays onto A's address and announces it network-wide.
    let stray = DeviceAnnce {
        tsn: 0x40,
        nwk_addr: NODE_A,
        ieee: IEEE_B,
        capability: 0x8E,
    };
    let mut sbuf = [0u8; 16];
    let sn = stray.encode_into(&mut sbuf).unwrap();
    let air = trip(
        0xD101,
        NODE_B,
        RX_ON_BROADCAST,
        &npdu(
            NODE_B,
            RX_ON_BROADCAST,
            &zdp_apdu(CLUSTER_DEVICE_ANNCE, 0x50, &sbuf[..sn]),
        ),
    );
    let heard = hear_annce(&air);
    assert_eq!(heard, stray);

    // A detects: same network address, different long address.
    assert!(detect_local_conflict(
        NODE_A,
        IEEE_A,
        heard.nwk_addr,
        heard.ieee
    ));

    // A's neighbor page already binds A's address to the stranger:
    // the table scan confirms at row 1.
    let blank = NeighborEntry {
        ext_pan: 0,
        ieee: 0,
        nwk: 0,
        device_type: 0,
        rx_on_idle: false,
        relationship: 0,
        depth: 0,
        lqi: 0,
    };
    let mut entries = [blank; MAX_NEIGHBORS];
    entries[0] = NeighborEntry {
        nwk: NODE_B,
        ieee: IEEE_B,
        ..blank
    };
    entries[1] = NeighborEntry {
        nwk: NODE_A,
        ieee: IEEE_B,
        ..blank
    };
    assert_eq!(first_table_conflict(&entries[..2], NODE_A, IEEE_A), Some(1));

    // A is a router with a fresh sighting: adopt + report previous.
    let outcome = decide_local_conflict(ConflictRole::Router, NODE_A, false);
    assert_eq!(outcome.decision, ConflictDecision::AdoptNewAddress);
    assert_eq!(outcome.report_addr, Some(NODE_A));

    // Act edge: A re-announces under its replacement address (the
    // stochastic pick itself is caller-owned; the test fixes one).
    const NEW_A: u16 = 0x0007;
    let re = reannounce(0x41, NEW_A, IEEE_A, 0x8E);
    let mut rbuf = [0u8; 16];
    let rn = re.encode_into(&mut rbuf).unwrap();
    let re_air = trip(
        0xD102,
        NEW_A,
        RX_ON_BROADCAST,
        &npdu(
            NEW_A,
            RX_ON_BROADCAST,
            &zdp_apdu(CLUSTER_DEVICE_ANNCE, 0x51, &rbuf[..rn]),
        ),
    );
    let reheard = hear_annce(&re_air);
    assert_eq!(reheard.nwk_addr, NEW_A);
    assert_eq!(reheard.ieee, IEEE_A);
    // At B the re-announce claims nobody's address: no conflict.
    assert!(!detect_local_conflict(
        NODE_B,
        IEEE_B,
        reheard.nwk_addr,
        reheard.ieee
    ));
}
