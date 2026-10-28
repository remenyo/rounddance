//! Smart Energy loop over the scripted medium: a meter device and an
//! ESP-like client drive a full CBKE handshake on the key-
//! establishment cluster, install the negotiated link key at the
//! trust center, rotate it, then run price publish/ack and meter
//! report/profile reads — twice, with byte-identical traces.
//!
//! Requirement traceability (repo-minted unless noted,
//! MINTED-pending-confirm): `07-5356-22-C312-01..08` (CBKE flows,
//! corpus-mined), `07-5356-C41-02` (key update), `07-5123-08-102-03`
//! (price backlog, corpus-mined), `07-5123-08-1024-01/02` (publish +
//! supersession), `07-5123-08-1042-01` + `07-5123-08-1043-02`
//! (meter reading + profile), `SCOPE.md` §8 (decision determinism).

use rounddance_aps::{DataDest, DataHeader, DeliveryMode, FrameControl as ApsFrameControl};
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap as _, MacMgmtSap as _, TxOptions, TxRequest,
    TxStatus,
};
use rounddance_nwk::{build_data_header, decode as nwk_decode, DiscoverRoute, NldeDataRequest};
use rounddance_security::ecc::scalar_from_kdf;
use rounddance_security::{
    backend_host::HostBackend, EccBackend, ImplicitCert, LinkKeyTable, PeerIdentity,
};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};
use rounddance_zcl::behavior::{Ctx, EventQueue};
use rounddance_zcl::frame::{Direction, FrameControl, FrameType, Header};
use rounddance_zcl::{keyest, metering, price, ReportingEngine};

const PAN: u16 = 0x1a2b;
const NODE_METER: u16 = 0x0001;
const NODE_TC: u16 = 0x0002;
/// Smart Energy profile identifier on the APDUs here.
const SE_PROFILE: u16 = 0x0109;
const ENDPOINT: u8 = 0x01;

/// Wrap ZCL octets in an APS data APDU.
fn encoded_zcl_apdu(cluster: u16, counter: u8, zcl: &[u8]) -> Vec<u8> {
    let header = DataHeader {
        control: ApsFrameControl {
            ack_request: true,
            ..ApsFrameControl::data(DeliveryMode::Unicast)
        },
        dest: DataDest::Unicast {
            dst_endpoint: ENDPOINT,
        },
        cluster_id: cluster,
        profile_id: SE_PROFILE,
        src_endpoint: ENDPOINT,
        counter,
        ext: None,
    };
    let mut out = vec![0u8; header.header_len() + zcl.len()];
    let n = header.encode_into(zcl, &mut out).unwrap();
    out.truncate(n);
    out
}

/// Wrap an APDU in an NWK data NPDU from `src` to `dst`.
fn encoded_npdu(src: u16, dst: u16, apdu: &[u8]) -> Vec<u8> {
    let req = NldeDataRequest {
        dst_addr: dst,
        use_alias: false,
        alias_src: 0,
        alias_seq: 0,
        radius_param: 3,
        discover_route: DiscoverRoute::Enable,
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

/// One medium trip: queue `zcl` (full ZCL frame) from `src` to `dst`
/// on a fresh scripted radio and return the delivered ZCL octets.
fn trip(seed: u64, src: u16, dst: u16, cluster: u16, counter: u8, zcl: &[u8]) -> Vec<u8> {
    let apdu = encoded_zcl_apdu(cluster, counter, zcl);
    let npdu = encoded_npdu(src, dst, &apdu);
    let mut radio = ScriptedRadio::new(Seed(seed), vec![ScriptAction::Deliver]);
    radio.reset(true);
    radio.set_channel(Channel::new(15).unwrap()).unwrap();
    radio.set_pan_id(PAN);
    radio.set_short_addr(src);
    radio
        .data_request(TxRequest {
            dst: MacAddress::short(PAN, dst),
            msdu: FramePayload::from_slice(&npdu).expect("NPDU fits one MSDU"),
            options: TxOptions::ACK,
        })
        .expect("queue has room");
    radio.run_until_idle(16);
    let confirm = radio.poll_confirm().expect("script always confirms");
    assert_eq!(confirm.status, TxStatus::Delivered);
    let rx = radio
        .poll_indication()
        .expect("delivery implies indication");
    let on_air = rx.msdu.as_slice().to_vec();
    let parsed = nwk_decode(&on_air).unwrap();
    assert_eq!(parsed.header.dst_addr, dst);
    let aps = rounddance_aps::decode_data(parsed.payload).unwrap();
    assert_eq!(aps.header.cluster_id, cluster);
    aps.payload.to_vec()
}

/// Wrap a cluster command payload in a ZCL frame.
fn zcl_frame(tsn: u8, to_server: bool, cmd: u8, payload: &[u8]) -> Vec<u8> {
    let header = Header {
        control: FrameControl {
            frame_type: FrameType::ClusterSpecific,
            manufacturer_specific: false,
            direction: if to_server {
                Direction::ToServer
            } else {
                Direction::ToClient
            },
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn,
        command_id: cmd,
    };
    let mut out = vec![0u8; 8 + payload.len()];
    let n = header.encode_into(&mut out).unwrap();
    out[n..n + payload.len()].copy_from_slice(payload);
    out.truncate(n + payload.len());
    out
}

/// ECQV-consistent provisioning (same construction as the vector
/// tests: full private key from the certificate binding).
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

/// Run the whole SE loop once; returns the hex trace of every on-air
/// ZCL frame plus the closing key, price, and reading. With
/// `compressed`, both sides transmit the 33-octet ephemeral form;
/// otherwise both use the expanded convention.
fn run_loop(seed: u64, compressed: bool) -> (Vec<String>, [u8; 16], u32, u64) {
    let mut trace = Vec::new();
    let mut counter = 0u8;
    let mut tsn = 0x40u8;

    // Provision: trust-center keypair + meter keypair, ECQV-consistent.
    let backend = HostBackend::new();
    let ca_priv = [0xC0u8; 32];
    let ca_pub = backend.base_mul(&ca_priv).unwrap();
    let (w_meter, id_meter) = provision(&backend, &ca_priv, 0xA1, 0x01, 0x11);
    let (w_tc, id_tc) = provision(&backend, &ca_priv, 0xB2, 0x02, 0x33);
    let mut init = keyest::Exchange::begin(
        true,
        ca_pub,
        w_meter,
        id_meter,
        [0x22; 32],
        backend.base_mul(&[0x22; 32]).unwrap(),
        &[id_meter, id_tc],
        keyest::SUITE_1,
    )
    .unwrap();
    let mut resp = keyest::Exchange::begin(
        false,
        ca_pub,
        w_tc,
        id_tc,
        [0x55; 32],
        backend.base_mul(&[0x55; 32]).unwrap(),
        &[id_tc, id_meter],
        keyest::SUITE_1,
    )
    .unwrap();
    init.set_tx_compressed(compressed);
    resp.set_tx_compressed(compressed);

    // Macro-free trip helper: send a ZCL frame, record it, deliver it.
    let mut fly = |from: u16, to: u16, frame: Vec<u8>| -> Vec<u8> {
        trace.push(format!("{from:04x}>{to:04x}:{}", hex(&frame)));
        counter = counter.wrapping_add(1);
        trip(seed, from, to, keyest::CLUSTER_ID, counter, &frame)
    };

    // 1. Initiate.
    let req = init.initiate_request().unwrap();
    let mut body = [0u8; 64];
    let n = keyest::encode_initiate(&req, &mut body).unwrap();
    let air = fly(
        NODE_METER,
        NODE_TC,
        zcl_frame(tsn, true, keyest::CMD_INITIATE_REQ, &body[..n]),
    );
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    assert_eq!(h.command_id, keyest::CMD_INITIATE_REQ);
    let rsp = resp
        .on_initiate(&backend, &keyest::decode_initiate(p).unwrap())
        .unwrap();
    let m = keyest::encode_initiate(&rsp, &mut body).unwrap();
    let air = fly(
        NODE_TC,
        NODE_METER,
        zcl_frame(tsn, false, keyest::CMD_INITIATE_RSP, &body[..m]),
    );
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    assert_eq!(h.command_id, keyest::CMD_INITIATE_RSP);
    init.on_initiate_response(&backend, &keyest::decode_initiate(p).unwrap())
        .unwrap();

    // 2. Ephemeral.
    let qe_u = init.ephemeral_request().unwrap();
    let air = fly(
        NODE_METER,
        NODE_TC,
        zcl_frame(tsn, true, keyest::CMD_EPHEMERAL_REQ, qe_u.as_slice()),
    );
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    assert_eq!(h.command_id, keyest::CMD_EPHEMERAL_REQ);
    let qe_v = resp.on_ephemeral_request(&backend, p).unwrap();
    let air = fly(
        NODE_TC,
        NODE_METER,
        zcl_frame(tsn, false, keyest::CMD_EPHEMERAL_RSP, qe_v.as_slice()),
    );
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    assert_eq!(h.command_id, keyest::CMD_EPHEMERAL_RSP);
    let mac_u = init.on_ephemeral_response(&backend, p).unwrap();

    // 3. Confirm.
    let air = fly(
        NODE_METER,
        NODE_TC,
        zcl_frame(tsn, true, keyest::CMD_CONFIRM_REQ, &mac_u),
    );
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    assert_eq!(h.command_id, keyest::CMD_CONFIRM_REQ);
    let mac_v = resp.on_confirm_request(&backend, p).unwrap();
    let air = fly(
        NODE_TC,
        NODE_METER,
        zcl_frame(tsn, false, keyest::CMD_CONFIRM_RSP, &mac_v),
    );
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    assert_eq!(h.command_id, keyest::CMD_CONFIRM_RSP);
    init.on_confirm_response(&backend, p).unwrap();

    assert!(init.is_done() && resp.is_done());
    assert_eq!(init.session_key().unwrap(), resp.session_key().unwrap());

    // 4. Trust-center link-key update + rotation.
    let mut table = LinkKeyTable::<8>::new();
    let receipt = keyest::install_negotiated_key(&mut table, &resp, [0x01; 8]).unwrap();
    let rotated = keyest::rotate_link_key(&mut table, [0x01; 8], 1).unwrap();
    assert_ne!(rotated.key, receipt.key);
    let final_key = rotated.key;

    // 5. Price publish: TC serves GetCurrentPrice; meter acks.
    let mut price_store = price::server_store().unwrap();
    let mut price_beh = price::ServerBehavior::default();
    let mut label = [0u8; price::MAX_LABEL];
    label[..4].copy_from_slice(b"Peak");
    price_beh.table_mut().insert(price::PublishPrice {
        provider_id: 0x0A0B_0C0D,
        rate_len: 4,
        rate_label: label,
        issuer_event_id: 7,
        current_time: 1_000,
        unit_of_measure: 0,
        currency: 0x0348,
        trailing_tier: 0x23,
        tiers_register: 0x21,
        start_time: 0,
        duration_min: 60,
        price: 12345,
    });
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let req_frame = zcl_frame(tsn, true, price::CMD_GET_CURRENT_PRICE, &[0x01]);
    let air = {
        trace.push(format!(
            "{NODE_METER:04x}>{NODE_TC:04x}:{}",
            hex(&req_frame)
        ));
        counter = counter.wrapping_add(1);
        trip(
            seed,
            NODE_METER,
            NODE_TC,
            price::CLUSTER_ID,
            counter,
            &req_frame,
        )
    };
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    let mut ctx = Ctx {
        store: &mut price_store,
        reporting: &mut eng,
        events: &mut events,
        now_s: 100,
        peer_onoff: None,
        sender_ieee: None,
    };
    <price::ServerBehavior as rounddance_zcl::behavior::Behavior>::handle_cluster_command(
        &mut price_beh,
        &mut ctx,
        &h,
        h.command_id,
        p,
    )
    .unwrap();
    let outbound = match events.pop() {
        Some(rounddance_zcl::behavior::AppEvent::OutboundCommand {
            cmd, len, payload, ..
        }) => {
            assert_eq!(cmd, price::CMD_PUBLISH_PRICE);
            payload[..len as usize].to_vec()
        }
        other => panic!("expected publish, got {other:?}"),
    };
    let resp_frame = zcl_frame(tsn, false, price::CMD_PUBLISH_PRICE, &outbound);
    let air = {
        trace.push(format!(
            "{NODE_TC:04x}>{NODE_METER:04x}:{}",
            hex(&resp_frame)
        ));
        counter = counter.wrapping_add(1);
        trip(
            seed,
            NODE_TC,
            NODE_METER,
            price::CLUSTER_ID,
            counter,
            &resp_frame,
        )
    };
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    assert_eq!(h.command_id, price::CMD_PUBLISH_PRICE);
    let (got, _) = price::decode_publish_price(p).unwrap();
    assert_eq!(got.price, 12345);
    assert_eq!(got.issuer_event_id, 7);
    let final_price = got.price;

    // Meter acknowledges; TC records it.
    let mut ack = [0u8; 16];
    let an = price::encode_price_ack(0x0A0B_0C0D, 7, 1_010, 0x01, &mut ack).unwrap();
    let ack_frame = zcl_frame(tsn, true, price::CMD_PRICE_ACK, &ack[..an]);
    let air = {
        trace.push(format!(
            "{NODE_METER:04x}>{NODE_TC:04x}:{}",
            hex(&ack_frame)
        ));
        counter = counter.wrapping_add(1);
        trip(
            seed,
            NODE_METER,
            NODE_TC,
            price::CLUSTER_ID,
            counter,
            &ack_frame,
        )
    };
    let (h, p) = Header::decode(&air).unwrap();
    let mut events2 = EventQueue::new();
    let mut ctx2 = Ctx {
        store: &mut price_store,
        reporting: &mut eng,
        events: &mut events2,
        now_s: 1_010,
        peer_onoff: None,
        sender_ieee: None,
    };
    <price::ServerBehavior as rounddance_zcl::behavior::Behavior>::handle_cluster_command(
        &mut price_beh,
        &mut ctx2,
        &h,
        h.command_id,
        p,
    )
    .unwrap();
    assert_eq!(price_beh.table().last_ack(), Some((0x0A0B_0C0D, 7)));

    // 6. Meter reading + profile: report and GetProfile round-trip.
    let mut meter_store = metering::server_store().unwrap();
    let mut meter_beh = metering::ServerBehavior::default();
    meter_beh.add_consumption(&mut meter_store, 1_000_000);
    meter_beh.profile_mut().record(501, 1_900);
    meter_beh.profile_mut().record(502, 1_000);
    let mut preq = [0u8; 8];
    let pn = metering::encode_get_profile(
        &metering::GetProfileRequest {
            channel: 0,
            end_time: 0,
            periods: 8,
        },
        &mut preq,
    )
    .unwrap();
    let preq_frame = zcl_frame(tsn, true, metering::CMD_GET_PROFILE, &preq[..pn]);
    let air = {
        trace.push(format!(
            "{NODE_TC:04x}>{NODE_METER:04x}:{}",
            hex(&preq_frame)
        ));
        counter = counter.wrapping_add(1);
        trip(
            seed,
            NODE_TC,
            NODE_METER,
            metering::CLUSTER_ID,
            counter,
            &preq_frame,
        )
    };
    let (h, p) = Header::decode(&air).unwrap();
    let mut events3 = EventQueue::new();
    let mut eng3 = ReportingEngine::new();
    let mut ctx3 = Ctx {
        store: &mut meter_store,
        reporting: &mut eng3,
        events: &mut events3,
        now_s: 2_000,
        peer_onoff: None,
        sender_ieee: None,
    };
    <metering::ServerBehavior as rounddance_zcl::behavior::Behavior>::handle_cluster_command(
        &mut meter_beh,
        &mut ctx3,
        &h,
        h.command_id,
        p,
    )
    .unwrap();
    let profile_body = match events3.pop() {
        Some(rounddance_zcl::behavior::AppEvent::OutboundCommand {
            cmd, len, payload, ..
        }) => {
            assert_eq!(cmd, metering::CMD_GET_PROFILE_RESPONSE);
            payload[..len as usize].to_vec()
        }
        other => panic!("expected profile response, got {other:?}"),
    };
    let prsp_frame = zcl_frame(
        tsn,
        false,
        metering::CMD_GET_PROFILE_RESPONSE,
        &profile_body,
    );
    let air = {
        trace.push(format!(
            "{NODE_METER:04x}>{NODE_TC:04x}:{}",
            hex(&prsp_frame)
        ));
        counter = counter.wrapping_add(1);
        trip(
            seed,
            NODE_METER,
            NODE_TC,
            metering::CLUSTER_ID,
            counter,
            &prsp_frame,
        )
    };
    let (h, p) = Header::decode(&air).unwrap();
    assert_eq!(h.command_id, metering::CMD_GET_PROFILE_RESPONSE);
    assert_eq!(p[4], metering::PROFILE_STATUS_SUCCESS);
    assert_eq!(p[6], 2);
    let final_reading = metering::scaled_summation(&meter_store);

    (trace, final_key, final_price, final_reading)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// The full SE loop runs over the scripted medium and agrees.
#[test]
fn se_loop_meter_and_tc_agree() {
    let (trace, key, price, reading) = run_loop(0x5EED, false);
    assert!(!trace.is_empty());
    assert_ne!(key, [0u8; 16]);
    assert_eq!(price, 12345);
    assert_eq!(reading, 1_000_000);
}

// Decision determinism: the same seed replays byte-identically.
#[test]
fn se_loop_replays_deterministically() {
    let (t1, k1, p1, r1) = run_loop(0x5EED, false);
    let (t2, k2, p2, r2) = run_loop(0x5EED, false);
    assert_eq!(t1, t2);
    assert_eq!(k1, k2);
    assert_eq!(p1, p2);
    assert_eq!(r1, r2);
    // A different seed still drives the same application outcome.
    let (_, k3, p3, r3) = run_loop(0x5EEF, false);
    assert_eq!(k3, k1);
    assert_eq!(p3, p1);
    assert_eq!(r3, r1);
}

// A full CBKE run with both ephemeral flights compressed agrees on
// the same session key as the expanded run: the transcript absorbs
// expanded points, so the wire form never splits the keys
// (07-5123-08-1074-05 + 07-5356-22-C312-06/07). The on-air ephemeral
// frames are shorter, but everything after the handshake is
// identical.
#[test]
fn se_loop_compressed_ephemeral_agrees() {
    let (trace_c, key_c, price_c, reading_c) = run_loop(0x5EED, true);
    let (trace_e, key_e, _, _) = run_loop(0x5EED, false);
    assert!(!trace_c.is_empty());
    assert_eq!(key_c, key_e);
    assert_eq!(price_c, 12345);
    assert_eq!(reading_c, 1_000_000);
    // Only the two ephemeral frames differ on air.
    let diffs = trace_c
        .iter()
        .zip(trace_e.iter())
        .filter(|(a, b)| a != b)
        .count();
    assert_eq!(diffs, 2);
    assert_eq!(trace_c.len(), trace_e.len());
}

// The compressed run replays byte-identically too.
#[test]
fn se_loop_compressed_replays_deterministically() {
    let (t1, k1, _, _) = run_loop(0x5EED, true);
    let (t2, k2, _, _) = run_loop(0x5EED, true);
    assert_eq!(t1, t2);
    assert_eq!(k1, k2);
}
