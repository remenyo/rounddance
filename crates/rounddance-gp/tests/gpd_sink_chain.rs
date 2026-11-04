//! GPD → sink chain: device commission + data hands off to NWK.
use rounddance_gp::{
    receive, AppId, CommissioningAnnouncement, CommissioningSession, GpError, GpKeySlots, GpReplay,
    GpdDevice, GpdId, Gpdf, SinkDecision, SinkTable, SinkTableEntry, TranslationTable,
    GPD_TOGGLE_CMD, MAX_GP_OPEN,
};

#[test]
fn gpd_commission_data_hands_off_to_nwk() {
    let mut gpd = GpdDevice::new_srcid(0x1234_5678);
    let mut buf = [0u8; 128];
    let n = gpd.build_commissioning(&mut buf).expect("commission");

    let keys = GpKeySlots::new();
    let mut session = CommissioningSession::new();
    let mut sinks: SinkTable<8> = SinkTable::new();
    let mut xl: TranslationTable<8> = TranslationTable::new();
    let mut replay: GpReplay<8> = GpReplay::new();
    let mut opened = [0u8; MAX_GP_OPEN];

    match receive(
        &buf[..n],
        &keys,
        true,
        &mut session,
        &mut sinks,
        &mut xl,
        &mut replay,
        &mut opened,
    ) {
        SinkDecision::AdmitCommissioning {
            gpd: gpd_key,
            endpoint,
            command,
        } => {
            assert_eq!(command, 0xE0);
            session.begin(CommissioningAnnouncement {
                app: AppId::SrcId,
                gpd: gpd_key,
                endpoint,
                pan_id_request: false,
                key_request: false,
                rx_after_tx: false,
                security_capable: false,
                key_present: false,
            });
            let seed = session.complete().expect("complete").expect("seed");
            xl.upsert(seed.materialize()).expect("translation");
            sinks
                .upsert(SinkTableEntry::new(AppId::SrcId, gpd_key))
                .expect("sink");
            gpd.mark_commissioned();
        }
        other => panic!("commission not admitted: {other:?}"),
    }

    let m = gpd
        .build_data(GPD_TOGGLE_CMD, &[0x01], &mut buf)
        .expect("data");
    match receive(
        &buf[..m],
        &keys,
        false,
        &mut session,
        &mut sinks,
        &mut xl,
        &mut replay,
        &mut opened,
    ) {
        SinkDecision::Handoff(h) => {
            assert_eq!(h.profile, 0x0104);
            // Default unidirectional seed translates any GPD command to
            // command 0x00 with verbatim payload copy.
            assert_eq!(h.command, 0x00);
            assert_eq!(&h.payload[..h.payload_len as usize], &[0x01]);
        }
        other => panic!("data not handed off: {other:?}"),
    }
    assert_eq!(gpd.data_sent, 1);
}

#[test]
fn gpd_bidir_loop_reply_then_success_commissions() {
    use rounddance_gp::{CommissioningReply, CommissioningState, ReplyOptions};
    let mut gpd = GpdDevice::new_srcid(0x2222_3333);
    let mut buf = [0u8; 128];
    let n = gpd
        .build_bidir_commissioning(&mut buf)
        .expect("bidir commission");
    let (dec, _) = Gpdf::decode(&buf[..n]).expect("decode bidir");
    assert!(dec.ext.expect("bidir has ext").rx_after_tx);
    assert!(!dec.fc.auto_commissioning);

    let keys = GpKeySlots::new();
    let mut session = CommissioningSession::new();
    let mut sinks: SinkTable<8> = SinkTable::new();
    let mut xl: TranslationTable<8> = TranslationTable::new();
    let mut replay: GpReplay<8> = GpReplay::new();
    let mut opened = [0u8; MAX_GP_OPEN];

    match receive(
        &buf[..n],
        &keys,
        true,
        &mut session,
        &mut sinks,
        &mut xl,
        &mut replay,
        &mut opened,
    ) {
        SinkDecision::AdmitCommissioning {
            gpd,
            endpoint,
            command,
        } => {
            assert_eq!(command, 0xE0);
            session.begin(CommissioningAnnouncement {
                app: AppId::SrcId,
                gpd,
                endpoint,
                pan_id_request: true,
                key_request: false,
                rx_after_tx: true,
                security_capable: true,
                key_present: false,
            });
            assert_eq!(session.complete_at(0), Err(GpError::BidirectionalPending));
            assert_eq!(session.state(), CommissioningState::AwaitingReply);
            session
                .stage_reply(CommissioningReply {
                    options: ReplyOptions {
                        pan_id_present: true,
                        key_present: false,
                        key_encrypted: false,
                        level: 0,
                        key_type: 0,
                    },
                    pan_id: Some(0x1A62),
                    key: None,
                    key_mic: None,
                    frame_counter: None,
                })
                .expect("stage");
            let mut rbuf = [0u8; CommissioningReply::MAX_LEN];
            let rn = session.build_reply(&mut rbuf).expect("reply bytes");
            let (reply, _) = CommissioningReply::decode(&rbuf[..rn]).expect("decode reply");
            assert_eq!(reply.pan_id, Some(0x1A62));
        }
        other => panic!("bidir commission not admitted: {other:?}"),
    }

    let m = gpd.build_success(&mut buf).expect("success");
    match receive(
        &buf[..m],
        &keys,
        false,
        &mut session,
        &mut sinks,
        &mut xl,
        &mut replay,
        &mut opened,
    ) {
        SinkDecision::Commissioned { gpd, endpoint } => {
            assert_eq!(gpd, 0x2222_3333);
            assert_eq!(endpoint, 0x00);
        }
        other => panic!("success did not commission: {other:?}"),
    }
    assert!(sinks.find(GpdId::SrcId(0x2222_3333)).is_some());

    let k = gpd
        .build_data(GPD_TOGGLE_CMD, &[0x01], &mut buf)
        .expect("data");
    match receive(
        &buf[..k],
        &keys,
        false,
        &mut session,
        &mut sinks,
        &mut xl,
        &mut replay,
        &mut opened,
    ) {
        SinkDecision::Handoff(h) => {
            assert_eq!(h.profile, 0x0104);
            assert_eq!(&h.payload[..h.payload_len as usize], &[0x01]);
        }
        other => panic!("paired data not handed off: {other:?}"),
    }
}
