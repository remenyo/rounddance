//! S3+H2 OTBR path over scripted RCP UART: form → join → secured
//! ZCL On/Off end to end, plus the negative legs (UART loss,
//! RCP-timeout recovery, desync→resync) and deterministic replay.
//!
//! Two [`OtbrNode`]s stand in for the two boards: each is an
//! [`RcpDriver`] (the S3 host stack side) wired through a byte pump
//! to an [`EmulatedRcp`] (the H2 firmware side). Radiated frames move
//! over a scripted test medium between the peers. No hardware, no
//! wall clock — the only timing is the drivers' injected clocks.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-RCP-10` (OTBR topology proof), `RD-RCP-06` (timeout/retry +
//! recovery), `RD-RCP-07` (desync→resync); reused corpus rows
//! `22-65816-030-91-0*` (join), `05-3474-23-32214-01` +
//! `05-3474-23-32215-01` (announce), `05-3474-23-446-01` +
//! `05-3474-23-4311-01` + `05-3474-23-4312-01` + `05-3474-23-451-01`
//! (APS security), `07-5123-08-383-01` (On effect), `SCOPE.md` §8
//! (decision determinism).

use rounddance_aps::{DataDest, DataHeader, DeliveryMode, FrameControl};
use rounddance_commission::{
    BaselineSteeringPolicy, BeaconSurveyEntry, ChannelMask, EccJoinKdf, InstallCode, JoinMethod,
    JoinPolicy, JoinerMachine, SteeringMachine, TrustCenter,
};
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap as _, MacMgmtSap as _, TxOptions, TxRequest,
    TxStatus,
};
use rounddance_nwk::{build_data_header, decode as nwk_decode, DiscoverRoute, NldeDataRequest};
use rounddance_rcp::{
    EmulatedRcp, HostSide, RcpDriver, RcpStats as RcpDriverStats, TraceEvent, CMD_TIMEOUT_US,
    MAX_RETRIES,
};
use rounddance_security::mock::MockBackend;
use rounddance_security::{
    AuxHeader, FrameCounter, KeyIdMode, KeyIdentifier, KeySet, NetworkKey, ReplayTable, SecError,
    SecurityControl, NETWORK_KEY_LEN,
};
use rounddance_zcl::behavior::{Ctx, EventQueue};
use rounddance_zcl::frame::Header;
use rounddance_zcl::{onoff, DispatchOutcome, Endpoint, ReportingEngine};
use rounddance_zdo::DeviceAnnce;

const PAN: u16 = 0x1a2b;
const COORD_SHORT: u16 = 0x0000;
const JOINER_SHORT: u16 = 0x0001;
const COORD_IEEE: u64 = 0x0200_0000_0000_0001;
const JOINER_IEEE: u64 = 0x0200_0000_0000_0002;
const HA_PROFILE: u16 = 0x0104;
const ENDPOINT: u8 = 0x01;

/// One emulated board: host driver + RCP firmware + the byte pump
/// between them (the scripted UART).
struct OtbrNode {
    driver: RcpDriver<HostSide>,
    peer: EmulatedRcp,
}

impl OtbrNode {
    fn new() -> Self {
        Self {
            driver: RcpDriver::new(HostSide::new()),
            peer: EmulatedRcp::new(),
        }
    }

    /// One link round-trip: driver → peer → driver.
    fn pump(&mut self) {
        let mut buf = [0u8; 512];
        let mut n = 0;
        while let Some(b) = self.driver.uart_mut().outbound.pop() {
            if n >= buf.len() {
                break;
            }
            buf[n] = b;
            n += 1;
        }
        self.peer.push_host_bytes(&buf[..n]);
        self.peer.poll();
        let m = self.peer.take_rcp_bytes(&mut buf);
        for b in &buf[..m] {
            assert!(self.driver.uart_mut().inbound.push(*b), "test FIFO fits");
        }
        self.driver.poll();
    }

    fn advance(&mut self, delta_us: u64) {
        self.driver.advance(delta_us);
    }

    /// Form this node: reset handshake, channel/PAN/address/power
    /// provisioning, and one energy scan.
    fn form(&mut self, short: u16, ieee: u64) {
        self.driver.reset(true);
        self.pump();
        assert!(self.driver.ready(), "reset handshake completes");
        self.driver.set_channel(Channel::new(15).unwrap()).unwrap();
        self.driver.set_pan_id(PAN);
        self.driver.set_short_addr(short);
        self.driver.set_extended_addr(ieee);
        self.driver.set_tx_power(10).unwrap();
        self.pump();
        let ch = Channel::new(15).unwrap();
        assert_eq!(
            self.driver.energy_scan(ch),
            Err(rounddance_mac_sap::MacError::NotReady)
        );
        self.pump();
        assert!(
            self.driver.energy_scan(ch).is_ok(),
            "split-phase scan completes"
        );
    }

    fn trace(&self) -> Vec<TraceEvent> {
        (0..self.driver.trace_len())
            .map(|i| self.driver.trace_at(i).unwrap())
            .collect()
    }
}

/// Move every radiated frame from `a`'s firmware to `b`'s RX queue,
/// pumping both ends around the transfer. The peer RX queue is
/// bounded: under retry storms it fills and sheds (counted on the
/// driver side as overruns), so the harness never asserts room here.
fn transfer(a: &mut OtbrNode, b: &mut OtbrNode) {
    a.pump();
    while let Some(tx) = a.peer.take_tx() {
        let _ = b
            .peer
            .queue_rx(&tx.psdu[..tx.len as usize], -50, 200, tx.inter_pan);
    }
    b.pump();
}

/// Queue one NPDU on `node` for `dst` and return the confirm status.
fn send_npdu(node: &mut OtbrNode, dst: u16, npdu: &[u8]) -> TxStatus {
    let h = node
        .driver
        .data_request(TxRequest {
            dst: MacAddress::short(PAN, dst),
            msdu: FramePayload::from_slice(npdu).expect("NPDU fits one MSDU"),
            options: TxOptions::ACK,
        })
        .expect("queue has room");
    node.pump();
    let c = node.driver.poll_confirm().expect("peer always confirms");
    assert_eq!(c.handle, h);
    c.status
}

/// Take one received NPDU from `node`.
fn recv_npdu(node: &mut OtbrNode) -> Vec<u8> {
    node.driver
        .poll_indication()
        .expect("delivery implies indication")
        .msdu
        .as_slice()
        .to_vec()
}

/// Wrap ZCL octets in an APS data APDU; `secure` sets the APS
/// security flag (the aux header is applied by the caller).
fn encoded_zcl_apdu(cluster: u16, counter: u8, secure: bool, zcl: &[u8]) -> Vec<u8> {
    let header = DataHeader {
        control: FrameControl {
            ack_request: true,
            security: secure,
            ..FrameControl::data(DeliveryMode::Unicast)
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

/// One secured application payload: auxiliary header followed by the
/// (sim-plaintext) payload, keyed + counted per the security crate.
fn secured_frame(
    keys: &KeySet,
    tx_counter: &mut FrameCounter,
    payload: &[u8],
) -> Result<Vec<u8>, SecError> {
    let header = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::DataKey, false).unwrap(),
        frame_counter: tx_counter.take()?,
        ext_source: None,
        key_id: KeyIdentifier::Seq(keys.active().seq),
    };
    let hlen = header.header_len().ok_or(SecError::BadKeyIdMode)?;
    let mut out = vec![0u8; hlen + payload.len()];
    let n = header.encode_into(&mut out)?;
    out[n..].copy_from_slice(payload);
    Ok(out)
}

/// Receive-side validation: key resolution + replay guard.
fn accept_frame(
    keys: &KeySet,
    rx: &mut ReplayTable<8>,
    src: u64,
    frame: &[u8],
) -> Result<Vec<u8>, SecError> {
    let (header, used) = AuxHeader::decode(frame)?;
    let seq = match header.key_id {
        KeyIdentifier::Seq(s) => s,
        _ => return Err(SecError::BadKeyIdMode),
    };
    let _key = keys.select(seq).ok_or(SecError::NotFound)?;
    rx.check(src, header.frame_counter)?;
    Ok(frame[used..].to_vec())
}

// RD-RCP-10: both boards form through the RCP handshake and agree on
// channel, PAN, addresses, power, and the energy baseline.
#[test]
fn rcp_form_provisions_both_ends() {
    let mut coord = OtbrNode::new();
    let mut joiner = OtbrNode::new();
    coord.form(COORD_SHORT, COORD_IEEE);
    joiner.form(JOINER_SHORT, JOINER_IEEE);
    for (node, short) in [(&coord, COORD_SHORT), (&joiner, JOINER_SHORT)] {
        assert!(node.driver.ready());
        assert_eq!(node.peer.channel(), Some(15));
        assert_eq!(node.peer.pan(), Some(PAN));
        assert_eq!(node.peer.short(), Some(short));
        assert_eq!(node.peer.tx_power_dbm(), 10);
        assert_eq!(node.driver.stats().drops, 0);
        assert_eq!(node.driver.stats().resyncs, 0);
    }
}

// Join over the OTBR path: steering survey + install-code key +
// Trust-Center admission run as stack logic, and the DeviceAnnce
// rides the scripted UART from joiner firmware to coordinator.
#[test]
fn rcp_join_announce_over_uart() {
    let mut coord = OtbrNode::new();
    let mut joiner = OtbrNode::new();
    coord.form(COORD_SHORT, COORD_IEEE);
    joiner.form(JOINER_SHORT, JOINER_IEEE);

    let mut tc = TrustCenter::new();
    tc.open();
    tc.set_allow_list(&[JOINER_IEEE]);

    let mut steering = SteeringMachine::new();
    steering
        .begin_scan(ChannelMask::from_list(&[15]).unwrap(), 3)
        .unwrap();
    steering
        .ingest(BeaconSurveyEntry {
            pan_id: PAN,
            channel: 15,
            lqi: 220,
            permit_joining: true,
            router_capacity: true,
            end_device_capacity: true,
            protocol_version: 2,
        })
        .unwrap();
    steering.finish_scan(&BaselineSteeringPolicy {
        min_lqi: 100,
        min_version: 2,
    });
    assert_eq!(
        steering.state(),
        rounddance_commission::SteeringState::CandidateSelected
    );

    let kdf = EccJoinKdf(MockBackend::new(0xC0));
    let mut wire = [0u8; 18];
    let n = InstallCode::with_crc(&[0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23], &mut wire)
        .unwrap();
    let code = InstallCode::from_slice(&wire[..n]).unwrap();
    let mut initial_key = [0u8; 16];
    TrustCenter::install_code_key(&kdf, &code, &JOINER_IEEE.to_be_bytes(), &mut initial_key)
        .unwrap();

    let policy = JoinPolicy {
        cbke_supported: false,
        cbke_required: false,
        interview_tc: true,
        parent_is_r20_earlier: false,
    };
    let mut joiner_machine = JoinerMachine::new(JoinMethod::InstallCode, policy);
    joiner_machine.on_candidate();
    joiner_machine.on_assoc_confirm(true);
    joiner_machine.on_key_transport(true);

    tc.admit(JOINER_IEEE, JOINER_SHORT, JoinMethod::InstallCode, 100)
        .unwrap();
    let stored = [0x00u8; 16];
    let attrs = tc
        .exchange_key(JOINER_IEEE, &initial_key, &stored, 0x04)
        .unwrap();
    assert_eq!(attrs, rounddance_commission::KeyAttributes::SYMMETRIC);
    tc.on_verify_confirm(JOINER_IEEE, true).unwrap();
    joiner_machine.on_verify_confirm(true, rounddance_commission::KeyAttributes::SYMMETRIC);
    assert_eq!(
        joiner_machine.state(),
        rounddance_commission::JoinerState::Announced
    );

    // The announcement rides the OTBR path as one RCP payload.
    let annce = joiner_machine.device_annce(0x0A, JOINER_SHORT, JOINER_IEEE);
    let mut frame = [0u8; DeviceAnnce::LEN];
    let flen = annce.encode_into(&mut frame).unwrap();
    assert_eq!(
        send_npdu(&mut joiner, COORD_SHORT, &frame[..flen]),
        TxStatus::Delivered
    );
    transfer(&mut joiner, &mut coord);
    let heard = DeviceAnnce::decode(&recv_npdu(&mut coord)).unwrap();
    assert_eq!(heard.nwk_addr, JOINER_SHORT);
    assert_eq!(heard.ieee, JOINER_IEEE);
}

// Secured ZCL On over the OTBR path: APS security flag + aux header
// + counter + replay guard, inside an NWK NPDU, applied to a live
// OnOff server. A captured replay is rejected.
#[test]
fn rcp_secured_zcl_on_over_uart() {
    let mut coord = OtbrNode::new();
    let mut joiner = OtbrNode::new();
    coord.form(COORD_SHORT, COORD_IEEE);
    joiner.form(JOINER_SHORT, JOINER_IEEE);

    let keys = KeySet::new(NetworkKey::new([0x77; NETWORK_KEY_LEN], 1));
    let mut tx_counter = FrameCounter::new(0, 4);
    let mut replay = ReplayTable::<8>::new();

    // Coordinator builds On → secures → APS (security on) → NWK.
    let mut zcl = [0u8; 16];
    let tsn = 0x61;
    let zlen = onoff::client::on(tsn, &mut zcl).unwrap();
    let secured = secured_frame(&keys, &mut tx_counter, &zcl[..zlen]).unwrap();
    let apdu = encoded_zcl_apdu(onoff::CLUSTER_ID, 0x09, true, &secured);
    let sent = encoded_npdu(COORD_SHORT, JOINER_SHORT, &apdu);
    assert_eq!(
        send_npdu(&mut coord, JOINER_SHORT, &sent),
        TxStatus::Delivered
    );
    transfer(&mut coord, &mut joiner);

    // Joiner validates every layer off the UART copy.
    let on_air = recv_npdu(&mut joiner);
    assert_eq!(on_air, sent, "UART path preserves every octet");
    let npdu = nwk_decode(&on_air).unwrap();
    assert_eq!(npdu.header.dst_addr, JOINER_SHORT);
    let aps = rounddance_aps::decode_data(npdu.payload).unwrap();
    assert!(
        aps.header.control.security,
        "APS security flag rides the RCP"
    );
    assert_eq!(aps.header.cluster_id, onoff::CLUSTER_ID);
    let payload = accept_frame(&keys, &mut replay, COORD_IEEE, aps.payload).unwrap();
    let (header, body) = Header::decode(&payload).unwrap();
    assert_eq!(header.tsn, tsn);
    assert_eq!(header.command_id, onoff::CMD_ON);

    // Applied to a live server that starts off.
    let def = onoff::ServerDef;
    let mut endpoint = Endpoint::new();
    endpoint.add(&def).unwrap();
    let mut store = onoff::server_store().unwrap();
    assert!(!onoff::onoff(&store));
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = onoff::ServerBehavior;
    let mut zcl_out = [0u8; 128];
    let mut ctx = Ctx {
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
        &mut ctx,
        &header,
        body,
        onoff::CLUSTER_ID,
        None,
        &[],
        &mut zcl_out,
    )
    .unwrap()
    {
        DispatchOutcome::Silent | DispatchOutcome::Respond(_) => {}
    }
    assert!(onoff::onoff(&store), "On flips the joined server");

    // The captured over-air bytes replayed by an attacker fail the
    // replay guard instead of toggling anything twice.
    assert!(accept_frame(&keys, &mut replay, COORD_IEEE, aps.payload).is_err());
}

// RD-RCP-06, leg 1: one lost UART confirm costs exactly one resend,
// then the transaction still delivers.
#[test]
fn rcp_uart_loss_costs_one_retry() {
    let mut coord = OtbrNode::new();
    coord.form(COORD_SHORT, COORD_IEEE);
    coord.peer.drop_confirms = 1;
    let h = coord
        .driver
        .data_request(TxRequest {
            dst: MacAddress::short(PAN, JOINER_SHORT),
            msdu: FramePayload::from_slice(&[0xAA]).unwrap(),
            options: TxOptions::ACK,
        })
        .unwrap();
    coord.pump();
    assert!(coord.driver.poll_confirm().is_none(), "first confirm lost");
    coord.advance(CMD_TIMEOUT_US);
    coord.pump(); // timeout fires, resend emitted
    coord.pump(); // resend delivered, confirm lands
    let c = coord.driver.poll_confirm().unwrap();
    assert_eq!((c.handle, c.status), (h, TxStatus::Delivered));
    assert_eq!(coord.driver.stats().tx_retries, 1);
    assert_eq!(coord.peer.stats.tx_received, 2, "peer saw both attempts");
}

// RD-RCP-06, leg 2: a fully deaf RCP fails the transaction after the
// budget — and the very next frame delivers once it heals.
#[test]
fn rcp_timeout_fails_then_heals() {
    let mut coord = OtbrNode::new();
    coord.form(COORD_SHORT, COORD_IEEE);
    coord.peer.drop_confirms = 255;
    coord
        .driver
        .data_request(TxRequest {
            dst: MacAddress::short(PAN, JOINER_SHORT),
            msdu: FramePayload::from_slice(&[1]).unwrap(),
            options: TxOptions::ACK,
        })
        .unwrap();
    coord.pump();
    for _ in 0..=MAX_RETRIES {
        coord.advance(CMD_TIMEOUT_US);
        coord.pump();
    }
    assert_eq!(coord.driver.poll_confirm().unwrap().status, TxStatus::NoAck);
    assert_eq!(coord.driver.stats().tx_failed, 1);
    coord.peer.drop_confirms = 0;
    coord
        .driver
        .data_request(TxRequest {
            dst: MacAddress::short(PAN, JOINER_SHORT),
            msdu: FramePayload::from_slice(&[2]).unwrap(),
            options: TxOptions::ACK,
        })
        .unwrap();
    coord.pump();
    assert_eq!(
        coord.driver.poll_confirm().unwrap().status,
        TxStatus::Delivered,
        "path recovers without a reset"
    );
}

// RD-RCP-07: framing garbage + CRC corruption trip the desync meter
// into a reset handshake; after the heal the stack resumes where it
// stood, and the whole run replays identically.
#[test]
fn rcp_desync_resync_and_replay() {
    fn disturbed_run() -> (Vec<TraceEvent>, Vec<TraceEvent>, RcpDriverStats) {
        let mut coord = OtbrNode::new();
        let mut joiner = OtbrNode::new();
        coord.form(COORD_SHORT, COORD_IEEE);
        joiner.form(JOINER_SHORT, JOINER_IEEE);
        coord.peer.corrupt_next = 255;
        coord.peer.garbage_next = 255;
        for _ in 0..4 {
            let _ = coord.driver.data_request(TxRequest {
                dst: MacAddress::short(PAN, JOINER_SHORT),
                msdu: FramePayload::from_slice(&[9, 9]).unwrap(),
                options: TxOptions::ACK,
            });
            coord.pump();
            coord.advance(CMD_TIMEOUT_US);
        }
        assert_eq!(coord.driver.stats().resyncs, 1, "meter trips once");
        coord.peer.corrupt_next = 0;
        coord.peer.garbage_next = 0;
        coord.peer.drop_confirms = 0;
        for _ in 0..6 {
            coord.pump();
            transfer(&mut coord, &mut joiner);
            // Shed the retry-storm backlog so the bounded peer RX
            // queue never fills mid-heal. The 10 ms steps trip the
            // 20 ms command timeout within two iterations, so
            // storm-era slots drain (fail or deliver) instead of
            // wedging the single flight.
            while joiner.driver.poll_indication().is_some() {}
            coord.advance(10_000);
        }
        assert!(coord.driver.ready(), "handshake re-completes");
        assert_eq!(coord.peer.channel(), Some(15), "cache replayed");
        // Shed stale confirms from the disturbed phase so the fresh
        // frame's confirm is unambiguous.
        while coord.driver.poll_confirm().is_some() {}
        // A fresh frame crosses the healed path intact.
        assert_eq!(
            send_npdu(&mut coord, JOINER_SHORT, &[0xCA, 0xFE]),
            TxStatus::Delivered
        );
        transfer(&mut coord, &mut joiner);
        assert_eq!(recv_npdu(&mut joiner), [0xCA, 0xFE]);
        (coord.trace(), joiner.trace(), coord.driver.stats())
    }

    let (ct1, jt1, s1) = disturbed_run();
    let (ct2, jt2, s2) = disturbed_run();
    assert_eq!(
        (ct1, jt1, s1),
        (ct2, jt2, s2),
        "disturbed run replays exactly"
    );
    assert!(s1.drops >= 4, "drops counted: {}", s1.drops);
    assert_eq!(s1.resyncs, 1, "one desync-triggered handshake");
    assert!(s1.resets >= 2, "form handshake + resync handshake");
}
