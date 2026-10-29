//! Post-join application transactions over the scripted medium:
//! ZDO request/response correlation (Match_Desc + Bind + Mgmt_Lqi),
//! ZCL transaction flow (Read + Toggle + Default Response), and the
//! secured APS data path (counter-managed send, validated receive,
//! replay refused at both layers).
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `05-3474-23-24401-01` (ZDO correlation), `05-3474-23-24311-07` +
//! `05-3474-23-24427-01` (Match_Desc), `05-3474-23-24322-01/02` +
//! `05-3474-23-24432-01` (Bind), `05-3474-23-24332-01/02` (Mgmt_Lqi),
//! `07-5123-08-2413-02` (ZCL TSN match), `07-5123-08-2512-03`
//! (Default Response), `05-3474-23-22843-03/04` (secured APS data;
//! re-mint of wave-47 `22845-01/02`), `05-3474-23-22844-02` (APS ack
//! leg + captured-air t1/t2 vectors), `SCOPE.md` §8 (decision
//! determinism).

use rounddance_aps::{
    ack_for, parse_ack, ApsStatus, DataDest, DataHeader, DeliveryMode, FrameControl, RetrySession,
    RetryVerdict, SecureDataLink,
};
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap as _, MacMgmtSap as _, TxOptions, TxRequest,
    TxStatus,
};
use rounddance_nwk::{build_data_header, decode as nwk_decode, DiscoverRoute, NldeDataRequest};
use rounddance_security::{
    AuxHeader, FrameCounter, KeyIdMode, KeyIdentifier, KeySet, NetworkKey, ReplayTable,
    SecurityControl, NETWORK_KEY_LEN,
};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};
use rounddance_zcl::behavior::{Ctx, EventQueue};
use rounddance_zcl::frame::{Direction, FrameType, Header as ZclHeader};
use rounddance_zcl::{general, onoff, DispatchOutcome, Endpoint, ReportingEngine, ZclStatus};
use rounddance_zdo::{
    BindDstMode, BindEntry, BindManager, BindRsp, MatchDescReq, MatchDescRsp, MgmtLqiReq,
    MgmtLqiRsp, NeighborEntry, PendingTable, ZdpStatus, CLUSTER_BIND_REQ, CLUSTER_MATCH_DESC_REQ,
    CLUSTER_MGMT_LQI_REQ,
};

const PAN: u16 = 0x1a2b;
const NODE_A: u16 = 0x0001;
const NODE_B: u16 = 0x0002;
const IEEE_A: u64 = 0x0200_0000_0000_0001;
const IEEE_B: u64 = 0x0200_0000_0000_0002;
const ZDP_PROFILE: u16 = 0x0000;
const HA_PROFILE: u16 = 0x0104;
const APP_EP: u8 = 0x01;

/// Wrap ZDP octets in an APS data APDU on the ZDO endpoint pair.
fn zdp_apdu(cluster: u16, counter: u8, zdp: &[u8]) -> Vec<u8> {
    let header = DataHeader {
        control: FrameControl {
            ack_request: true,
            ..FrameControl::data(DeliveryMode::Unicast)
        },
        dest: DataDest::Unicast { dst_endpoint: 0x00 },
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

/// Wrap ZCL octets in an APS data APDU on the application endpoint pair.
fn zcl_apdu(cluster: u16, counter: u8, zcl: &[u8]) -> Vec<u8> {
    let header = DataHeader {
        control: FrameControl {
            ack_request: true,
            ..FrameControl::data(DeliveryMode::Unicast)
        },
        dest: DataDest::Unicast {
            dst_endpoint: APP_EP,
        },
        cluster_id: cluster,
        profile_id: HA_PROFILE,
        src_endpoint: APP_EP,
        counter,
        ext: None,
    };
    let mut out = vec![0u8; header.header_len() + zcl.len()];
    let n = header.encode_into(zcl, &mut out).unwrap();
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
            options: TxOptions::ACK,
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

// 05-3474-23-24401-01 + Match_Desc/Bind/Mgmt_Lqi pairs: A opens one
// transaction per request on (cluster, TSN); B answers each; every
// answer correlates back to its own request, and a stray duplicate
// answer correlates to nothing.
#[test]
fn zdo_match_bind_lqi_two_node() {
    let mut pending = PendingTable::<4>::new();
    let mut aps_counter: u8 = 0x20;

    // --- Match_Desc_req: A seeks an HA On/Off server. ---
    let (match_tsn, bind_tsn, lqi_tsn) = (0x51, 0x52, 0x53);
    pending.open(CLUSTER_MATCH_DESC_REQ, match_tsn).unwrap();
    let match_req = MatchDescReq {
        tsn: match_tsn,
        nwk_of_interest: 0xfffd,
        profile_id: HA_PROFILE,
        in_clusters: {
            let mut a = [0u16; 16];
            a[0] = onoff::CLUSTER_ID;
            a
        },
        in_len: 1,
        out_clusters: [0u16; 16],
        out_len: 0,
    };
    let mut mbuf = [0u8; 48];
    let mn = match_req.encode_into(&mut mbuf).unwrap();
    let sent = npdu(
        NODE_A,
        NODE_B,
        &zdp_apdu(CLUSTER_MATCH_DESC_REQ, aps_counter, &mbuf[..mn]),
    );
    aps_counter = aps_counter.wrapping_add(1);
    let air = trip(0xA701, NODE_A, NODE_B, &sent);
    assert_eq!(air, sent);

    // B decodes the request and answers with its application endpoint.
    let got = nwk_decode(&air).unwrap();
    let aps = rounddance_aps::decode_data(got.payload).unwrap();
    let seen_req = MatchDescReq::decode(aps.payload).unwrap();
    assert_eq!(seen_req.in_clusters[0], onoff::CLUSTER_ID);
    let match_rsp = MatchDescRsp {
        tsn: seen_req.tsn,
        status: ZdpStatus::Success,
        nwk_of_interest: NODE_B,
        endpoints: {
            let mut a = [0u8; 32];
            a[0] = APP_EP;
            a
        },
        ep_len: 1,
    };
    let mut mrbuf = [0u8; 40];
    let mrn = match_rsp.encode_into(&mut mrbuf).unwrap();
    let rsp_air = trip(
        0xA702,
        NODE_B,
        NODE_A,
        &npdu(
            NODE_B,
            NODE_A,
            &zdp_apdu(CLUSTER_MATCH_DESC_REQ | 0x8000, aps_counter, &mrbuf[..mrn]),
        ),
    );
    aps_counter = aps_counter.wrapping_add(1);
    let rsp_npdu = nwk_decode(&rsp_air).unwrap();
    let rsp_aps = rounddance_aps::decode_data(rsp_npdu.payload).unwrap();
    assert_eq!(
        pending.close(rsp_aps.header.cluster_id, rsp_aps.payload[0]),
        Some(CLUSTER_MATCH_DESC_REQ)
    );
    let seen_rsp = MatchDescRsp::decode(rsp_aps.payload).unwrap();
    assert_eq!(seen_rsp.ep_list(), &[APP_EP]);

    // --- Bind_req: A binds its On/Off client at B's endpoint. ---
    pending.open(CLUSTER_BIND_REQ, bind_tsn).unwrap();
    let bind_req = BindEntry {
        tsn: bind_tsn,
        src_ieee: IEEE_A,
        src_endpoint: APP_EP,
        cluster_id: onoff::CLUSTER_ID,
        dst: BindDstMode::Extended {
            dst_ieee: IEEE_B,
            dst_endpoint: APP_EP,
        },
    };
    let mut bbuf = [0u8; 32];
    let bn = bind_req.encode_into(&mut bbuf).unwrap();
    let bsent = npdu(
        NODE_A,
        NODE_B,
        &zdp_apdu(CLUSTER_BIND_REQ, aps_counter, &bbuf[..bn]),
    );
    aps_counter = aps_counter.wrapping_add(1);
    let bair = trip(0xA703, NODE_A, NODE_B, &bsent);
    let bgot = nwk_decode(&bair).unwrap();
    let baps = rounddance_aps::decode_data(bgot.payload).unwrap();
    let seen_bind = BindEntry::decode(baps.payload).unwrap();
    let mut binding = rounddance_aps::BindingTable::new();
    let mut group = rounddance_aps::GroupTable::new();
    let mut manager = BindManager::new(&mut binding, &mut group);
    let status = manager.bind(&seen_bind, IEEE_B);
    assert_eq!(status, ZdpStatus::Success);
    let bind_rsp = BindRsp {
        tsn: seen_bind.tsn,
        status,
    };
    let mut brbuf = [0u8; 4];
    let brn = bind_rsp.encode_into(&mut brbuf).unwrap();
    let br_air = trip(
        0xA704,
        NODE_B,
        NODE_A,
        &npdu(
            NODE_B,
            NODE_A,
            &zdp_apdu(CLUSTER_BIND_REQ | 0x8000, aps_counter, &brbuf[..brn]),
        ),
    );
    aps_counter = aps_counter.wrapping_add(1);
    let br_npdu = nwk_decode(&br_air).unwrap();
    let br_aps = rounddance_aps::decode_data(br_npdu.payload).unwrap();
    assert_eq!(
        pending.close(br_aps.header.cluster_id, br_aps.payload[0]),
        Some(CLUSTER_BIND_REQ)
    );
    assert_eq!(
        BindRsp::decode(br_aps.payload).unwrap().status,
        ZdpStatus::Success
    );

    // --- Mgmt_Lqi_req: A pages B's neighbor table. ---
    pending.open(CLUSTER_MGMT_LQI_REQ, lqi_tsn).unwrap();
    let lqi_req = MgmtLqiReq {
        tsn: lqi_tsn,
        start_index: 0,
    };
    let mut lbuf = [0u8; 4];
    let ln = lqi_req.encode_into(&mut lbuf).unwrap();
    let lsent = npdu(
        NODE_A,
        NODE_B,
        &zdp_apdu(CLUSTER_MGMT_LQI_REQ, aps_counter, &lbuf[..ln]),
    );
    let lair = trip(0xA705, NODE_A, NODE_B, &lsent);
    let lgot = nwk_decode(&lair).unwrap();
    let laps = rounddance_aps::decode_data(lgot.payload).unwrap();
    let seen_lqi = MgmtLqiReq::decode(laps.payload).unwrap();
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
    let mut entries = [blank; rounddance_zdo::MAX_NEIGHBORS];
    entries[0] = NeighborEntry {
        ext_pan: 0x0102_0304_0506_0708,
        ieee: IEEE_A,
        nwk: NODE_A,
        device_type: 2,
        rx_on_idle: false,
        relationship: 1,
        depth: 1,
        lqi: 180,
    };
    let lqi_rsp = MgmtLqiRsp {
        tsn: seen_lqi.tsn,
        status: ZdpStatus::Success,
        neighbor_count: 1,
        start_index: seen_lqi.start_index,
        entries,
        entry_len: 1,
    };
    let mut lrbuf = [0u8; 48];
    let lrn = lqi_rsp.encode_into(&mut lrbuf).unwrap();
    let lr_air = trip(
        0xA706,
        NODE_B,
        NODE_A,
        &npdu(
            NODE_B,
            NODE_A,
            &zdp_apdu(CLUSTER_MGMT_LQI_REQ | 0x8000, aps_counter, &lrbuf[..lrn]),
        ),
    );
    let lr_npdu = nwk_decode(&lr_air).unwrap();
    let lr_aps = rounddance_aps::decode_data(lr_npdu.payload).unwrap();
    assert_eq!(
        pending.close(lr_aps.header.cluster_id, lr_aps.payload[0]),
        Some(CLUSTER_MGMT_LQI_REQ)
    );
    let seen_lqi_rsp = MgmtLqiRsp::decode(lr_aps.payload).unwrap();
    assert_eq!(seen_lqi_rsp.entry_list()[0].ieee, IEEE_A);
    assert!(pending.is_empty());
    // A stray duplicate of the LQI answer no longer correlates.
    assert_eq!(
        pending.close(lr_aps.header.cluster_id, lr_aps.payload[0]),
        None
    );
}

// 07-5123-08-2413-02 + 07-5123-08-2512-03: A reads B's OnOff with a
// tracked TSN, toggles the live server, and gets a Default Response
// for an unknown command — every reply echoes its request's TSN.
#[test]
fn zcl_read_toggle_defaultrsp_two_node() {
    let mut alloc = rounddance_zcl::TsnAlloc::new(0x61);
    let mut pending = rounddance_zcl::PendingTable::<4>::new();
    let mut aps_counter: u8 = 0x30;

    // --- Read Attributes (OnOff) with TSN correlation. ---
    let read_tsn = alloc.take();
    pending
        .open(read_tsn, onoff::CLUSTER_ID, general::cmd::READ)
        .unwrap();
    let read_hdr = ZclHeader {
        control: rounddance_zcl::FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: read_tsn,
        command_id: general::cmd::READ,
    };
    let mut zcl = [0u8; 64];
    let hn = read_hdr.encode_into(&mut zcl).unwrap();
    let qn = general::encode_id_list(&[onoff::ATTR_ONOFF], &mut zcl[hn..]).unwrap();
    let sent = npdu(
        NODE_A,
        NODE_B,
        &zcl_apdu(onoff::CLUSTER_ID, aps_counter, &zcl[..hn + qn]),
    );
    aps_counter = aps_counter.wrapping_add(1);
    let air = trip(0xB101, NODE_A, NODE_B, &sent);
    assert_eq!(air, sent);

    // B dispatches the read against a live server (starts off).
    let got = nwk_decode(&air).unwrap();
    let aps = rounddance_aps::decode_data(got.payload).unwrap();
    let (req_hdr, req_body) = ZclHeader::decode(aps.payload).unwrap();
    let def = onoff::ServerDef;
    let mut endpoint = Endpoint::new();
    endpoint.add(&def).unwrap();
    let mut store = onoff::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = onoff::ServerBehavior;
    let mut ctx = Ctx {
        store: &mut store,
        reporting: &mut eng,
        events: &mut events,
        now_s: 0,
        peer_onoff: None,
        sender_ieee: None,
    };
    let mut zcl_out = [0u8; 128];
    let len = match rounddance_zcl::dispatch(
        &endpoint,
        Some(&mut beh),
        &mut ctx,
        &req_hdr,
        req_body,
        onoff::CLUSTER_ID,
        None,
        &[],
        &mut zcl_out,
    )
    .unwrap()
    {
        DispatchOutcome::Respond(n) => n,
        DispatchOutcome::Silent => panic!("read expects a reply"),
    };
    let rsp_air = trip(
        0xB102,
        NODE_B,
        NODE_A,
        &npdu(
            NODE_B,
            NODE_A,
            &zcl_apdu(onoff::CLUSTER_ID, aps_counter, &zcl_out[..len]),
        ),
    );
    aps_counter = aps_counter.wrapping_add(1);
    let rsp_npdu = nwk_decode(&rsp_air).unwrap();
    let rsp_aps = rounddance_aps::decode_data(rsp_npdu.payload).unwrap();
    let (rep_hdr, rep_body) = ZclHeader::decode(rsp_aps.payload).unwrap();
    assert!(rounddance_zcl::reply_direction_ok(&rep_hdr));
    let open = pending.close(&rep_hdr, rsp_aps.header.cluster_id).unwrap();
    assert_eq!(open.command, general::cmd::READ);
    let mut recs = [general::ReadRecord {
        id: 0,
        status: ZclStatus::Success,
        dtype: 0,
        value: rounddance_zcl::Value::NoData,
    }; 4];
    assert_eq!(general::decode_read_rsp(rep_body, &mut recs).unwrap(), 1);
    assert_eq!(recs[0].id, onoff::ATTR_ONOFF);
    assert_eq!(recs[0].value, rounddance_zcl::Value::Bool(false));

    // --- Toggle flips the live server; no reply is owed. ---
    let toggle_tsn = alloc.take();
    let mut tbuf = [0u8; 8];
    let tn = onoff::client::toggle(toggle_tsn, &mut tbuf).unwrap();
    let tsent = npdu(
        NODE_A,
        NODE_B,
        &zcl_apdu(onoff::CLUSTER_ID, aps_counter, &tbuf[..tn]),
    );
    let tair = trip(0xB103, NODE_A, NODE_B, &tsent);
    let tgot = nwk_decode(&tair).unwrap();
    let taps = rounddance_aps::decode_data(tgot.payload).unwrap();
    let (thdr, tbody) = ZclHeader::decode(taps.payload).unwrap();
    assert_eq!(thdr.tsn, toggle_tsn);
    {
        let mut ctx2 = Ctx {
            store: &mut store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 0,
            peer_onoff: None,
            sender_ieee: None,
        };
        match rounddance_zcl::dispatch(
            &endpoint,
            Some(&mut beh),
            &mut ctx2,
            &thdr,
            tbody,
            onoff::CLUSTER_ID,
            None,
            &[],
            &mut zcl_out,
        )
        .unwrap()
        {
            DispatchOutcome::Silent => {}
            DispatchOutcome::Respond(_) => panic!("toggle sends no reply"),
        }
    }
    assert!(onoff::onoff(&store));

    // --- Unknown command: B answers Default Response UNSUP_COMMAND. ---
    let bad_hdr = ZclHeader {
        control: rounddance_zcl::FrameControl {
            frame_type: FrameType::ClusterSpecific,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: alloc.take(),
        command_id: 0xff,
    };
    let mut bbuf = [0u8; 8];
    let bhn = bad_hdr.encode_into(&mut bbuf).unwrap();
    let bsent = npdu(
        NODE_A,
        NODE_B,
        &zcl_apdu(onoff::CLUSTER_ID, aps_counter, &bbuf[..bhn]),
    );
    let bair = trip(0xB104, NODE_A, NODE_B, &bsent);
    let bgot = nwk_decode(&bair).unwrap();
    let baps = rounddance_aps::decode_data(bgot.payload).unwrap();
    let (bhdr, bbody) = ZclHeader::decode(baps.payload).unwrap();
    let mut ctx3 = Ctx {
        store: &mut store,
        reporting: &mut eng,
        events: &mut events,
        now_s: 0,
        peer_onoff: None,
        sender_ieee: None,
    };
    let status = rounddance_zcl::dispatch(
        &endpoint,
        Some(&mut beh),
        &mut ctx3,
        &bhdr,
        bbody,
        onoff::CLUSTER_ID,
        None,
        &[],
        &mut zcl_out,
    )
    .expect_err("unknown command must fail");
    let mut drbuf = [0u8; 16];
    let drn = rounddance_zcl::build_default_response(&bhdr, status, true, &mut drbuf).unwrap();
    let dr_air = trip(
        0xB105,
        NODE_B,
        NODE_A,
        &npdu(
            NODE_B,
            NODE_A,
            &zcl_apdu(onoff::CLUSTER_ID, 0x3a, &drbuf[..drn]),
        ),
    );
    let dr_npdu = nwk_decode(&dr_air).unwrap();
    let dr_aps = rounddance_aps::decode_data(dr_npdu.payload).unwrap();
    let (dr_hdr, dr_body) = ZclHeader::decode(dr_aps.payload).unwrap();
    assert_eq!(dr_hdr.tsn, bhdr.tsn);
    let drsp = rounddance_zcl::transaction::decode_default_response(dr_body).unwrap();
    assert_eq!(drsp.cmd, 0xff);
    assert_eq!(drsp.status, rounddance_zcl::ZclStatus::UnsupCommand);
    assert!(pending.is_empty());
}

// 05-3474-23-22843-03/04: secured APS data end to end — A allocates
// a counter-managed secured header, the frame rides a secured NWK
// envelope, B validates both layers, and the captured replay is
// refused without delivering twice.
#[test]
fn secured_aps_data_two_node() {
    let keys = KeySet::new(NetworkKey::new([0x77; NETWORK_KEY_LEN], 1));
    let mut nwk_tx = FrameCounter::new(10, 4);
    let mut nwk_rx = ReplayTable::<8>::new();
    let mut aps_tx = SecureDataLink::new();
    let mut aps_rx = SecureDataLink::new();

    // A builds one secured Toggle-carrying data frame.
    let mut toggle = [0u8; 8];
    let tn = onoff::client::toggle(0x71, &mut toggle).unwrap();
    let (aps_hdr, expect) = aps_tx.send_header(
        DataDest::Unicast {
            dst_endpoint: APP_EP,
        },
        onoff::CLUSTER_ID,
        HA_PROFILE,
        APP_EP,
        true,
    );
    assert!(expect.is_some());
    let mut apdu = vec![0u8; aps_hdr.header_len() + tn];
    let an = aps_hdr.encode_into(&toggle[..tn], &mut apdu).unwrap();
    apdu.truncate(an);
    // NWK secured envelope around the APS APDU.
    let aux = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::Index, false).unwrap(),
        frame_counter: nwk_tx.take().unwrap(),
        ext_source: None,
        key_id: KeyIdentifier::Index(keys.active().seq),
    };
    let hlen = aux.header_len().unwrap();
    let mut secured = vec![0u8; hlen + apdu.len()];
    let wn = aux.encode_into(&mut secured).unwrap();
    secured[wn..].copy_from_slice(&apdu);
    let sent = npdu(NODE_A, NODE_B, &secured);

    let air = trip(0xC101, NODE_A, NODE_B, &sent);
    assert_eq!(air, sent);

    // B opens both layers: NWK aux (key + replay) then APS secured
    // (flag + duplicate) — and owes a unicast ack back.
    let got = nwk_decode(&air).unwrap();
    let (rx_aux, used) = AuxHeader::decode(got.payload).unwrap();
    let seq = match rx_aux.key_id {
        KeyIdentifier::Index(s) => s,
        _ => panic!("index keying only"),
    };
    assert!(keys.select(seq).is_some());
    nwk_rx.check(IEEE_A, rx_aux.frame_counter).unwrap();
    let decoded = rounddance_aps::decode_data(&got.payload[used..]).unwrap();
    let ack_back = aps_rx.accept(&decoded.header, NODE_A).unwrap();
    assert!(ack_back.is_some());
    assert!(decoded.header.control.security);
    assert_eq!(decoded.payload, &toggle[..tn]);
    // The ack B owes matches what A expects.
    let owed = ack_back.unwrap();
    assert!(aps_tx.note_ack(owed.cluster_id, owed.counter, owed.dst_endpoint));
    assert_eq!(aps_tx.pending_ack(), None);

    // Attacker replays the exact captured frame: the NWK replay guard
    // fires first, so nothing reaches the APS layer twice.
    let replay = nwk_decode(&air).unwrap();
    let (re_aux, _) = AuxHeader::decode(replay.payload).unwrap();
    assert!(nwk_rx.check(IEEE_A, re_aux.frame_counter).is_err());
    // Even past the NWK guard, the APS duplicate guard refuses it.
    let re_aps = rounddance_aps::decode_data(&replay.payload[used..]).unwrap();
    assert_eq!(
        aps_rx.accept(&re_aps.header, NODE_A),
        Err(rounddance_aps::ApsStatus::NoAck)
    );

    // The next fresh frame still advances on both layers.
    let (aps_hdr2, _) = aps_tx.send_header(
        DataDest::Unicast {
            dst_endpoint: APP_EP,
        },
        onoff::CLUSTER_ID,
        HA_PROFILE,
        APP_EP,
        true,
    );
    assert_eq!(aps_hdr2.counter, aps_hdr.counter.wrapping_add(1));
    let mut apdu2 = vec![0u8; aps_hdr2.header_len() + tn];
    let an2 = aps_hdr2.encode_into(&toggle[..tn], &mut apdu2).unwrap();
    apdu2.truncate(an2);
    let aux2 = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::Index, false).unwrap(),
        frame_counter: nwk_tx.take().unwrap(),
        ext_source: None,
        key_id: KeyIdentifier::Index(keys.active().seq),
    };
    let hlen2 = aux2.header_len().unwrap();
    let mut secured2 = vec![0u8; hlen2 + apdu2.len()];
    let wn2 = aux2.encode_into(&mut secured2).unwrap();
    secured2[wn2..].copy_from_slice(&apdu2);
    let air2 = trip(0xC102, NODE_A, NODE_B, &npdu(NODE_A, NODE_B, &secured2));
    let got2 = nwk_decode(&air2).unwrap();
    let (rx2, used2) = AuxHeader::decode(got2.payload).unwrap();
    nwk_rx.check(IEEE_A, rx2.frame_counter).unwrap();
    let dec2 = rounddance_aps::decode_data(&got2.payload[used2..]).unwrap();
    assert!(aps_rx.accept(&dec2.header, NODE_A).is_ok());
}

// 05-3474-23-22844-02 decision test over the medium, wave-47 t2 then
// t1 shape: A sends an ack-requested secured Toggle; B's data ack
// clears A's wait (acked -> success, TC 9/9 SUCCESS); a second send
// with B silent exhausts the retry cap to NO_ACK (no-ack -> retries
// -> failed, the t1 DELIVERY_FAILED) even though B received and owed
// the ack both times.
#[test]
fn aps_ack_leg_acked_vs_unacked_two_node() {
    let mut aps_a = SecureDataLink::new();
    let mut aps_b = SecureDataLink::new();
    let mut toggle = [0u8; 8];
    let tn = onoff::client::toggle(0x72, &mut toggle).unwrap();
    let send_toggle = |link: &mut SecureDataLink| {
        let (hdr, expect) = link.send_header(
            DataDest::Unicast {
                dst_endpoint: APP_EP,
            },
            onoff::CLUSTER_ID,
            HA_PROFILE,
            APP_EP,
            true,
        );
        let mut apdu = vec![0u8; hdr.header_len() + tn];
        let n = hdr.encode_into(&toggle[..tn], &mut apdu).unwrap();
        apdu.truncate(n);
        (apdu, expect.expect("unicast send expects an ack"))
    };

    // --- t2 shape: acked -> success. ---
    let (apdu, expect) = send_toggle(&mut aps_a);
    let air = trip(0xC201, NODE_A, NODE_B, &npdu(NODE_A, NODE_B, &apdu));
    let got = nwk_decode(&air).unwrap();
    let dec = rounddance_aps::decode_data(got.payload).unwrap();
    let owed = aps_b.accept(&dec.header, NODE_A).unwrap();
    assert!(owed.is_some());
    let ack_hdr = ack_for(&dec.header, HA_PROFILE).expect("request bit set: ack owed");
    assert_eq!(owed.unwrap().counter, ack_hdr.counter);
    let mut ack_wire = [0u8; 16];
    let an = ack_hdr.encode_into(&mut ack_wire).unwrap();
    let ack_air = trip(
        0xC202,
        NODE_B,
        NODE_A,
        &npdu(NODE_B, NODE_A, &ack_wire[..an]),
    );
    let back = nwk_decode(&ack_air).unwrap();
    let info = parse_ack(back.payload)
        .unwrap()
        .expect("data ack correlates");
    let mut session = RetrySession::new(expect, 0, 16);
    assert_eq!(session.poll_transmit(), RetryVerdict::Transmit);
    assert_eq!(session.on_ack(info), RetryVerdict::Acked);
    assert!(aps_a.note_ack(info.cluster_id, info.counter, info.src_endpoint));
    assert_eq!(aps_a.pending_ack(), None);

    // --- t1 shape: no ack -> retries -> Failed(NO_ACK). ---
    // B receives (and owes an ack) but stays silent on air.
    let (apdu2, expect2) = send_toggle(&mut aps_a);
    let air2 = trip(0xC203, NODE_A, NODE_B, &npdu(NODE_A, NODE_B, &apdu2));
    let got2 = nwk_decode(&air2).unwrap();
    let dec2 = rounddance_aps::decode_data(got2.payload).unwrap();
    assert!(aps_b.accept(&dec2.header, NODE_A).unwrap().is_some());
    assert!(ack_for(&dec2.header, HA_PROFILE).is_some());
    let mut silent = RetrySession::new(expect2, 0, 16);
    assert_eq!(silent.poll_transmit(), RetryVerdict::Transmit);
    let mut verdict = RetryVerdict::Waiting;
    let mut now = 16u64;
    while verdict == RetryVerdict::Waiting || verdict == RetryVerdict::Transmit {
        verdict = silent.on_tick(now);
        now += 16;
    }
    assert_eq!(verdict, RetryVerdict::Failed(ApsStatus::NoAck));
    assert_eq!(silent.attempts(), rounddance_aps::MAX_FRAME_RETRIES);
    // The unacked expectation is still outstanding on A.
    assert!(aps_a.pending_ack().is_some());
}

// SCOPE.md §8: the same seed + request bytes always yield identical
// traces and identical delivered octets across runs.
#[test]
fn app_transaction_replays_deterministically() {
    let req = MatchDescReq {
        tsn: 0x51,
        nwk_of_interest: 0xfffd,
        profile_id: HA_PROFILE,
        in_clusters: {
            let mut a = [0u16; 16];
            a[0] = onoff::CLUSTER_ID;
            a
        },
        in_len: 1,
        out_clusters: [0u16; 16],
        out_len: 0,
    };
    let mut mbuf = [0u8; 48];
    let mn = req.encode_into(&mut mbuf).unwrap();
    let sent = npdu(
        NODE_A,
        NODE_B,
        &zdp_apdu(CLUSTER_MATCH_DESC_REQ, 0x20, &mbuf[..mn]),
    );
    let run = |seed: u64| {
        let mut radio = ScriptedRadio::new(
            Seed(seed),
            vec![
                ScriptAction::Delay {
                    base_us: 320,
                    jitter_us: 100,
                },
                ScriptAction::Deliver,
            ],
        );
        radio.reset(true);
        radio.set_channel(Channel::new(15).unwrap()).unwrap();
        radio.set_pan_id(PAN);
        radio.set_short_addr(NODE_A);
        radio
            .data_request(TxRequest {
                dst: MacAddress::short(PAN, NODE_B),
                msdu: FramePayload::from_slice(&sent).expect("fits"),
                options: TxOptions::ACK,
            })
            .expect("room");
        radio.run_until_idle(16);
        let rx = radio
            .poll_indication()
            .expect("delivery")
            .msdu
            .as_slice()
            .to_vec();
        (radio.trace_lines().to_vec(), rx)
    };
    let (t1, r1) = run(0xA710);
    let (t2, r2) = run(0xA710);
    assert_eq!(t1, t2);
    assert_eq!(r1, r2);
    assert_eq!(r1, sent);
}
