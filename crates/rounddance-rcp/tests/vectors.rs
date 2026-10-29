//! Wire goldens + scripted-exchange pins for the RCP path.
//!
//! The CRC below is recomputed by an independent bit-by-bit
//! implementation in this file (not by calling `crc16`), so the
//! goldens pin the on-air bytes against implementation drift rather
//! than echoing the unit under test.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-RCP-01` (framing), `RD-RCP-02` (CRC), `RD-RCP-03`/`RD-RCP-04`
//! (command/event classes).

use rounddance_mac_sap::{Channel, MacDataSap as _, MacMgmtSap as _, TxStatus};
use rounddance_rcp::cmd::{
    Command, Event, TxOutcome, E_POWER_CAPPED, K_ENERGY_SCAN, K_GET_VERSION, K_READY, K_RESET,
    K_SET_CHANNEL, K_SET_PROMISCUOUS, K_TX_CONFIRM, K_VERSION, MAX_PSDU,
};
use rounddance_rcp::frame::{Decoder, Outcome, MAX_RCP_PAYLOAD, SYNC};
use rounddance_rcp::{EmulatedRcp, HostSide, RcpDriver};

/// Independent CRC-16/CCITT (bit-by-bit, no table sharing with the
/// crate implementation).
fn reference_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for b in data {
        crc ^= (*b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

fn decode_one(wire: &[u8]) -> rounddance_rcp::Frame {
    let mut dec = Decoder::new();
    let mut out = None;
    for b in wire {
        if let Some(o) = dec.push_byte(*b) {
            assert!(out.is_none(), "exactly one outcome per golden");
            out = Some(o);
        }
    }
    match out {
        Some(Outcome::Frame(f)) => f,
        other => panic!("expected one frame, got {other:?}"),
    }
}

#[test]
fn golden_set_channel_bytes() {
    // SetChannel(15), seq 0x09: SYNC | LEN=5 | KIND | SEQ | 15 | CRC16-LE.
    let mut wire = [0u8; 16];
    let n = Command::SetChannel { channel: 15 }
        .encode(0x09, &mut wire)
        .unwrap();
    assert_eq!(n, 7);
    let body = [K_SET_CHANNEL, 0x09, 15];
    let crc = reference_crc16(&body);
    assert_eq!(
        wire[..n],
        [
            SYNC,
            5,
            K_SET_CHANNEL,
            0x09,
            15,
            (crc & 0xFF) as u8,
            (crc >> 8) as u8
        ]
    );
    let f = decode_one(&wire[..n]);
    assert_eq!(
        Command::decode(&f).unwrap(),
        Command::SetChannel { channel: 15 }
    );
}

#[test]
fn golden_reset_cold_and_ready() {
    let mut wire = [0u8; 16];
    let n = Command::Reset { cold: true }
        .encode(0x01, &mut wire)
        .unwrap();
    let crc = reference_crc16(&[K_RESET, 0x01, 0x01]);
    assert_eq!(
        wire[..n],
        [
            SYNC,
            5,
            K_RESET,
            0x01,
            0x01,
            (crc & 0xFF) as u8,
            (crc >> 8) as u8
        ]
    );
    let mut ev_wire = [0u8; 16];
    let m = Event::Ready { fw_version: 1 }
        .encode(0x00, &mut ev_wire)
        .unwrap();
    let ecrc = reference_crc16(&[K_READY, 0x00, 0x01]);
    assert_eq!(
        ev_wire[..m],
        [
            SYNC,
            5,
            K_READY,
            0x00,
            0x01,
            (ecrc & 0xFF) as u8,
            (ecrc >> 8) as u8
        ]
    );
}

#[test]
fn golden_tx_confirm_and_max_psdu_reject() {
    // TxConfirm{seq, Delivered} pins the confirm shape the driver matches.
    let mut wire = [0u8; 16];
    let n = Event::TxConfirm {
        seq: 0x41,
        status: TxOutcome::Delivered,
    }
    .encode(0x02, &mut wire)
    .unwrap();
    let crc = reference_crc16(&[K_TX_CONFIRM, 0x02, 0x41, 0x00]);
    assert_eq!(wire[0], SYNC);
    assert_eq!(wire[1], 6);
    assert_eq!(
        &wire[..n],
        &[
            SYNC,
            6,
            K_TX_CONFIRM,
            0x02,
            0x41,
            0x00,
            (crc & 0xFF) as u8,
            (crc >> 8) as u8
        ]
    );
    // A 128-octet PSDU never encodes (127 is the ceiling).
    let mut out = [0u8; 256];
    let big = [0xAAu8; MAX_PSDU + 1];
    let mut psdu = [0u8; MAX_PSDU];
    psdu.copy_from_slice(&big[..MAX_PSDU]);
    assert!(Command::TxFrame {
        inter_pan: false,
        len: (MAX_PSDU + 1) as u8,
        psdu,
    }
    .encode(0, &mut out)
    .is_err());
    // The frame layer itself refuses >128-octet payloads.
    assert!(rounddance_rcp::frame::encode(1, 0, &[0u8; MAX_RCP_PAYLOAD + 1], &mut out).is_err());
}

#[test]
fn golden_set_promiscuous_and_version() {
    // SetPromiscuous(false) = filtered + HW auto-ACK, seq 0x0A:
    // SYNC | LEN=5 | KIND | SEQ | 0x00 | CRC16-LE.
    let mut wire = [0u8; 16];
    let n = Command::SetPromiscuous { promiscuous: false }
        .encode(0x0A, &mut wire)
        .unwrap();
    assert_eq!(n, 7);
    let body = [K_SET_PROMISCUOUS, 0x0A, 0x00];
    let crc = reference_crc16(&body);
    assert_eq!(
        wire[..n],
        [
            SYNC,
            5,
            K_SET_PROMISCUOUS,
            0x0A,
            0x00,
            (crc & 0xFF) as u8,
            (crc >> 8) as u8
        ]
    );
    let f = decode_one(&wire[..n]);
    assert_eq!(
        Command::decode(&f).unwrap(),
        Command::SetPromiscuous { promiscuous: false }
    );
    // GetVersion carries an empty payload.
    let n = Command::GetVersion.encode(0x0B, &mut wire).unwrap();
    assert_eq!(n, 6);
    let gbody = [K_GET_VERSION, 0x0B];
    let gcrc = reference_crc16(&gbody);
    assert_eq!(
        wire[..n],
        [
            SYNC,
            4,
            K_GET_VERSION,
            0x0B,
            (gcrc & 0xFF) as u8,
            (gcrc >> 8) as u8
        ]
    );
    // Version event: [fw, proto, caps-LE, eui64].
    let eui = [0x74, 0x4D, 0xBD, 0xFF, 0xFE, 0x61, 0x7A, 0xFA];
    let mut vwire = [0u8; 32];
    let n = Event::Version {
        fw_version: 1,
        proto_version: 1,
        caps: 0x00FF,
        eui,
    }
    .encode(0x0C, &mut vwire)
    .unwrap();
    let mut vbody = [0u8; 15];
    vbody[0] = K_VERSION;
    vbody[1] = 0x0C;
    vbody[2] = 1;
    vbody[3] = 1;
    vbody[4] = 0xFF;
    vbody[5] = 0x00;
    vbody[6..14].copy_from_slice(&eui);
    let vcrc = reference_crc16(&vbody[..14]);
    assert_eq!(n, 18);
    assert_eq!(vwire[2], K_VERSION);
    assert_eq!(&vwire[n - 2..n], [(vcrc & 0xFF) as u8, (vcrc >> 8) as u8]);
    let f = decode_one(&vwire[..n]);
    assert_eq!(
        Event::decode(&f).unwrap(),
        Event::Version {
            fw_version: 1,
            proto_version: 1,
            caps: 0x00FF,
            eui,
        }
    );
}

#[test]
fn golden_garbage_prefix_drops_exactly_once() {
    // The peer's scripted desync prefix: noise, then a SYNC-led run
    // with an illegal LEN — exactly one BadLen drop, parser re-armed.
    let mut dec = Decoder::new();
    let mut drops = 0;
    for b in [0x00u8, 0xA5, 0x01, 0xFF] {
        if let Some(Outcome::Dropped(_)) = dec.push_byte(b) {
            drops += 1;
        }
    }
    assert_eq!(drops, 1);
    assert_eq!(dec.dropped(), 1);
    // And a clean scan command still parses right after.
    let mut wire = [0u8; 16];
    let n = Command::EnergyScan { channel: 26 }
        .encode(0x05, &mut wire)
        .unwrap();
    assert_eq!(wire[2], K_ENERGY_SCAN);
    let f = decode_one(&wire[..n]);
    assert_eq!(
        Command::decode(&f).unwrap(),
        Command::EnergyScan { channel: 26 }
    );
}

/// Full scripted exchange pin: reset → provision → TX → scan, with
/// the exact confirm/status/energy the sim path depends on.
#[test]
fn scripted_exchange_transcript() {
    let mut driver = RcpDriver::new(HostSide::new());
    let mut peer = EmulatedRcp::new();
    let mut buf = [0u8; 512];
    let mut pump = |driver: &mut RcpDriver<HostSide>, peer: &mut EmulatedRcp| {
        let mut n = 0;
        while let Some(b) = driver.uart_mut().outbound.pop() {
            if n >= buf.len() {
                break;
            }
            buf[n] = b;
            n += 1;
        }
        peer.push_host_bytes(&buf[..n]);
        peer.poll();
        let m = peer.take_rcp_bytes(&mut buf);
        for b in &buf[..m] {
            assert!(driver.uart_mut().inbound.push(*b));
        }
        driver.poll();
    };

    driver.reset(true);
    pump(&mut driver, &mut peer);
    assert!(driver.ready());
    driver.set_channel(Channel::new(15).unwrap()).unwrap();
    driver.set_pan_id(0x1a2b);
    driver.set_short_addr(0x0001);
    pump(&mut driver, &mut peer);
    assert_eq!(peer.stats.resets, 1);

    // Over-cap power is refused on the host AND would be refused by
    // the firmware; the in-policy value lands.
    assert!(driver.set_tx_power(20).is_err());
    driver.set_tx_power(10).unwrap();
    pump(&mut driver, &mut peer);
    assert_eq!(peer.tx_power_dbm(), 10);

    let h = driver
        .data_request(rounddance_mac_sap::TxRequest {
            dst: rounddance_mac_sap::MacAddress::short(0x1a2b, 0x0002),
            msdu: rounddance_mac_sap::FramePayload::from_slice(&[7, 7]).unwrap(),
            options: rounddance_mac_sap::TxOptions::ACK,
        })
        .unwrap();
    pump(&mut driver, &mut peer);
    let c = driver.poll_confirm().unwrap();
    assert_eq!((c.handle, c.status), (h, TxStatus::Delivered));

    let ch = Channel::new(15).unwrap();
    assert!(driver.energy_scan(ch).is_err());
    pump(&mut driver, &mut peer);
    assert_eq!(
        driver.energy_scan(ch).unwrap(),
        15u8.wrapping_mul(7).wrapping_add(11)
    );

    let s = driver.stats();
    assert_eq!(
        (s.tx_sent, s.tx_confirmed, s.drops, s.resyncs),
        (1, 1, 0, 0)
    );
    assert_eq!(peer.stats.tx_received, 1);
    assert_eq!(peer.stats.scans, 1);
    // Peer-side cap mirror, forced through the raw command path.
    let mut wire = [0u8; 32];
    let n = Command::SetTxPower { dbm: 20 }
        .encode(0x77, &mut wire)
        .unwrap();
    peer.push_host_bytes(&wire[..n]);
    peer.poll();
    assert_eq!(peer.tx_power_dbm(), 10, "firmware ignores hot requests");
    let m = peer.take_rcp_bytes(&mut buf);
    let f = decode_one(&buf[..m]);
    assert_eq!(
        Event::decode(&f).unwrap(),
        Event::Error {
            code: E_POWER_CAPPED
        }
    );
}
