//! IAS panel loop over the scripted medium: a zone sensor enrolls
//! against a panel (ACE server), trips into alarm with panel
//! fan-out, the panel arms, and a warning device sounds, preempts,
//! and expires — twice, with byte-identical traces.
//!
//! Requirement traceability (corpus-mined unless noted,
//! MINTED-pending-confirm): `07-5123-08-822-01/05/06`
//! (zone CIE gating + handshake), `07-5123-08-832-01/03/04`
//! (arm verdicts, mask query, panel fan-out + disarm reset),
//! `07-5123-08-833-01/02`, `07-5123-08-834-01` (codecs +
//! emitters), `07-5123-08-841-01`, `07-5123-08-842-01/03`
//! (warning codec, preemption, duty quantization),
//! `SCOPE.md` §8 (decision determinism).

use rounddance_aps::{DataDest, DataHeader, DeliveryMode, FrameControl as ApsFrameControl};
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap as _, MacMgmtSap as _, TxOptions, TxRequest,
    TxStatus,
};
use rounddance_nwk::{build_data_header, decode as nwk_decode, DiscoverRoute, NldeDataRequest};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};
use rounddance_zcl::behavior::{AppEvent, Behavior, Ctx, EventQueue};
use rounddance_zcl::frame::{Direction, FrameControl, FrameType, Header};
use rounddance_zcl::{ace, ias_zone, wd, ReportingEngine, Value};

const PAN: u16 = 0x1a2b;
const NODE_PANEL: u16 = 0x0001;
const NODE_SENSOR: u16 = 0x0002;
const NODE_SOUNDER: u16 = 0x0003;
/// Home-automation profile identifier on the APDUs here.
const HA_PROFILE: u16 = 0x0104;
const ENDPOINT: u8 = 0x01;
const CIE_IEEE: u64 = 0x0012_4b00_0000_0001;

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
        profile_id: HA_PROFILE,
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

/// One medium trip: queue `zcl` (full ZCL frame) from `src` to
/// `dst` on a fresh scripted radio and return the delivered ZCL
/// octets.
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

fn hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn drain(events: &mut EventQueue) -> Vec<AppEvent> {
    let mut out = Vec::new();
    while let Some(ev) = events.pop() {
        out.push(ev);
    }
    out
}

/// Run the whole IAS loop once; returns the hex trace of every
/// on-air ZCL frame plus the closing panel, zone, and warning
/// states.
fn run_loop(seed: u64) -> (Vec<String>, u8, u8, bool) {
    let mut trace = Vec::new();
    let mut counter = 0u8;
    let mut tsn = 0x30u8;

    let mut fly = |from: u16, to: u16, cluster: u16, frame: Vec<u8>| -> Vec<u8> {
        trace.push(format!("{from:04x}>{to:04x}:{}", hex(&frame)));
        counter = counter.wrapping_add(1);
        trip(seed, from, to, cluster, counter, &frame)
    };

    // Devices: panel ACE server, sensor zone server, sounder WD.
    let mut ace_beh = ace::ServerBehavior::new();
    let mut ace_store = ace::server_store().unwrap();
    let mut zone_beh = ias_zone::ServerBehavior::new();
    let mut zone_store = ias_zone::server_store(0x000d).unwrap();
    let mut wd_beh = wd::ServerBehavior::new();
    let mut wd_store = wd::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();

    // 1. Bind the CIE address on the sensor (write hook arms the gate).
    zone_store
        .set_local(
            ias_zone::ATTR_CIE_ADDRESS,
            Value::Eui64(CIE_IEEE.to_le_bytes()),
        )
        .unwrap();
    {
        let mut ctx = Ctx {
            store: &mut zone_store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 10,
            peer_onoff: None,
            sender_ieee: None,
        };
        <ias_zone::ServerBehavior as Behavior>::on_attribute_written(
            &mut zone_beh,
            &mut ctx,
            ias_zone::ATTR_CIE_ADDRESS,
        )
        .unwrap();
    }
    assert_eq!(zone_beh.stage(), ias_zone::EnrollStage::CieBound);
    drain(&mut events);

    // 2. Trip-to-pair: enroll request flies sensor -> panel.
    {
        let mut ctx = Ctx {
            store: &mut zone_store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 11,
            peer_onoff: None,
            sender_ieee: None,
        };
        zone_beh
            .trigger_enroll_request(&mut ctx, 0x1037, tsn)
            .unwrap();
    }
    tsn = tsn.wrapping_add(1);
    let enroll_ev = drain(&mut events);
    let (enroll_cmd, enroll_tsn, enroll_body) = enroll_ev
        .iter()
        .find_map(|ev| match ev {
            AppEvent::OutboundCommand {
                cluster,
                cmd,
                tsn,
                len,
                payload,
            } => {
                assert_eq!(*cluster, ias_zone::CLUSTER_ID);
                assert_eq!(*cmd, ias_zone::CMD_ENROLL_REQUEST);
                Some((*cmd, *tsn, payload[..*len as usize].to_vec()))
            }
            _ => None,
        })
        .expect("expected enroll request");
    let air = fly(
        NODE_SENSOR,
        NODE_PANEL,
        ias_zone::CLUSTER_ID,
        zcl_frame(enroll_tsn, true, enroll_cmd, &enroll_body),
    );
    let (h, p) = Header::decode(&air).unwrap();
    assert_eq!(h.command_id, ias_zone::CMD_ENROLL_REQUEST);
    assert_eq!(p.len(), 4);

    // 3. Panel enrolls the zone in its ACE table and answers success.
    ace_beh
        .enroll_zone(4, 0x000d, CIE_IEEE.to_le_bytes(), b"Door", false)
        .unwrap();
    let mut rsp = [0u8; 16];
    let rn = ias_zone::cie::enroll_response(tsn, ias_zone::ENROLL_SUCCESS, 4, &mut rsp).unwrap();
    tsn = tsn.wrapping_add(1);
    let air = fly(
        NODE_PANEL,
        NODE_SENSOR,
        ias_zone::CLUSTER_ID,
        rsp[..rn].to_vec(),
    );
    let (h, p) = Header::decode(&air).unwrap();
    assert_eq!(h.command_id, ias_zone::CMD_ENROLL_RESPONSE);
    {
        let mut ctx = Ctx {
            store: &mut zone_store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 12,
            peer_onoff: None,
            sender_ieee: Some(CIE_IEEE),
        };
        <ias_zone::ServerBehavior as Behavior>::handle_cluster_command(
            &mut zone_beh,
            &mut ctx,
            &h,
            h.command_id,
            p,
        )
        .unwrap();
    }
    assert_eq!(zone_beh.stage(), ias_zone::EnrollStage::Enrolled);
    drain(&mut events);

    // 4. Sensor trips: status notification flies sensor -> panel,
    // panel fans out Zone Status Changed.
    {
        let mut ctx = Ctx {
            store: &mut zone_store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 20,
            peer_onoff: None,
            sender_ieee: None,
        };
        zone_beh
            .set_status(&mut ctx, ias_zone::STATUS_ALARM1, tsn)
            .unwrap();
    }
    tsn = tsn.wrapping_add(1);
    let notify_ev = drain(&mut events);
    let notify_body = match notify_ev.last().unwrap() {
        AppEvent::OutboundCommand { len, payload, .. } => payload[..*len as usize].to_vec(),
        _ => panic!("expected notification"),
    };
    let air = fly(
        NODE_SENSOR,
        NODE_PANEL,
        ias_zone::CLUSTER_ID,
        zcl_frame(tsn, false, ias_zone::CMD_STATUS_NOTIFY, &notify_body),
    );
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    assert_eq!(h.command_id, ias_zone::CMD_STATUS_NOTIFY);
    let status = u16::from_le_bytes([p[0], p[1]]);
    ace_beh
        .report_zone_status(&mut events, tsn, 4, status, ace::AUDIBLE_DEFAULT)
        .unwrap();
    tsn = tsn.wrapping_add(1);
    let fanout = drain(&mut events);
    assert_eq!(fanout.len(), 1);

    // 5. Keypad arms all: Arm flies to the panel, verdict + panel
    // change come back.
    let mut arm_body = [0u8; 8];
    let an = ace::encode_arm(ace::ARM_ALL, b"", 0xff, &mut arm_body).unwrap();
    let air = fly(
        NODE_SENSOR,
        NODE_PANEL,
        ace::CLUSTER_ID,
        zcl_frame(tsn, true, ace::CMD_ARM, &arm_body[..an]),
    );
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    {
        let mut ctx = Ctx {
            store: &mut ace_store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 30,
            peer_onoff: None,
            sender_ieee: None,
        };
        <ace::ServerBehavior as Behavior>::handle_cluster_command(
            &mut ace_beh,
            &mut ctx,
            &h,
            h.command_id,
            p,
        )
        .unwrap();
    }
    assert_eq!(ace_beh.panel(), ace::PANEL_ARMED_AWAY);
    let arm_out = drain(&mut events);
    let arm_cmds: Vec<u8> = arm_out
        .iter()
        .filter_map(|ev| match ev {
            AppEvent::OutboundCommand { cmd, .. } => Some(*cmd),
            _ => None,
        })
        .collect();
    assert_eq!(
        arm_cmds,
        vec![ace::CMD_PANEL_STATUS_CHANGED, ace::CMD_ARM_RESPONSE]
    );

    // 6. Masked zone-status query from the keypad.
    let q = ace::ZoneStatusQuery {
        start: 0,
        max: 8,
        mask_flag: true,
        mask: 0x0001,
    };
    let mut qbody = [0u8; 5];
    ace::encode_zone_status_query(&q, &mut qbody).unwrap();
    let air = fly(
        NODE_SENSOR,
        NODE_PANEL,
        ace::CLUSTER_ID,
        zcl_frame(tsn, true, ace::CMD_GET_ZONE_STATUS, &qbody),
    );
    tsn = tsn.wrapping_add(1);
    let (h, p) = Header::decode(&air).unwrap();
    {
        let mut ctx = Ctx {
            store: &mut ace_store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 31,
            peer_onoff: None,
            sender_ieee: None,
        };
        <ace::ServerBehavior as Behavior>::handle_cluster_command(
            &mut ace_beh,
            &mut ctx,
            &h,
            h.command_id,
            p,
        )
        .unwrap();
    }
    let query_out = drain(&mut events);
    assert_eq!(query_out.len(), 1);

    // 7. Warning device: start warning flies panel -> sounder,
    // preempt once, squawk gated, expiry ticks out.
    let w = wd::StartWarning {
        mode: wd::WARN_BURGLAR,
        strobe: wd::STROBE_PARALLEL,
        siren: 0x02,
        duration_s: 120,
        duty: 44,
        level: 0x02,
    };
    let mut wbody = [0u8; 5];
    wd::encode_start_warning(&w, &mut wbody).unwrap();
    let air = fly(
        NODE_PANEL,
        NODE_SOUNDER,
        wd::CLUSTER_ID,
        zcl_frame(tsn, true, wd::CMD_START_WARNING, &wbody),
    );
    let (h, p) = Header::decode(&air).unwrap();
    {
        let mut ctx = Ctx {
            store: &mut wd_store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 40,
            peer_onoff: None,
            sender_ieee: None,
        };
        <wd::ServerBehavior as Behavior>::handle_cluster_command(
            &mut wd_beh,
            &mut ctx,
            &h,
            h.command_id,
            p,
        )
        .unwrap();
    }
    let active = wd_beh.active().unwrap();
    assert_eq!(active.mode, wd::WARN_BURGLAR);
    assert_eq!(active.duty, 40);
    drain(&mut events);
    // Fire preempts; squawk while live is ignored; clock runs out.
    let fire = wd::StartWarning {
        mode: wd::WARN_FIRE,
        strobe: wd::STROBE_NONE,
        siren: 0x03,
        duration_s: 10,
        duty: 0,
        level: 0x01,
    };
    wd::encode_start_warning(&fire, &mut wbody).unwrap();
    {
        let mut ctx = Ctx {
            store: &mut wd_store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 41,
            peer_onoff: None,
            sender_ieee: None,
        };
        <wd::ServerBehavior as Behavior>::handle_cluster_command(
            &mut wd_beh,
            &mut ctx,
            &h,
            wd::CMD_START_WARNING,
            &wbody,
        )
        .unwrap();
    }
    assert_eq!(wd_beh.active().unwrap().mode, wd::WARN_FIRE);
    {
        let mut ctx = Ctx {
            store: &mut wd_store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 42,
            peer_onoff: None,
            sender_ieee: None,
        };
        <wd::ServerBehavior as Behavior>::handle_cluster_command(
            &mut wd_beh,
            &mut ctx,
            &h,
            wd::CMD_SQUAWK,
            &[0xa0],
        )
        .unwrap();
    }
    assert_eq!(wd_beh.squawks(), 0);
    wd::tick_1s(&mut wd_beh, &mut events, 10);
    assert!(wd_beh.active().is_none());
    drain(&mut events);

    (
        trace,
        ace_beh.panel(),
        zone_beh.stage() as u8,
        wd_beh.active().is_none(),
    )
}

// Full panel loop runs twice with a byte-identical trace.
#[test]
fn ias_panel_loop_replays_identically() {
    let (t1, panel1, stage1, silent1) = run_loop(0x1a50);
    let (t2, panel2, stage2, silent2) = run_loop(0x1a50);
    assert_eq!(t1, t2);
    assert!(!t1.is_empty());
    assert_eq!(panel1, ace::PANEL_ARMED_AWAY);
    assert_eq!(panel1, panel2);
    assert_eq!(stage1, ias_zone::EnrollStage::Enrolled as u8);
    assert_eq!(stage1, stage2);
    assert!(silent1 && silent2);
}
