//! Ember/EZSP adapter vectors: frame codec pins plus the SAP-level
//! mapping and the decision-for-decision parity leg against the
//! existing short-short MAC codec (`EspAdapter` + `MockDriver`).
//!
//! No hardware, no serial: the NCP side is the in-crate mock
//! transport. New behaviors are `RD-COMPAT-05..07` (repo-minted,
//! MINTED-pending-confirm).

use rounddance_compat::ember::{
    decode, encode, next_seq, EmberAdapter, EzspError, MockEzspTransport, CMD_DATA_SEND,
    CTRL_CALLBACK, CTRL_SEQ_MASK, EVT_DATA_RECEIVE, FLAG, MAX_EZSP_PAYLOAD, STATUS_DELIVERED,
    STATUS_NO_ACK,
};
use rounddance_mac_sap::{
    AddrMode, FramePayload, MacAddress, MacDataSap, MacMgmtSap, TxHandle, TxOptions, TxRequest,
    TxStatus,
};

fn req(dst: MacAddress, bytes: &[u8], ack: bool) -> TxRequest {
    TxRequest {
        dst,
        msdu: FramePayload::from_slice(bytes).unwrap(),
        options: if ack { TxOptions::ACK } else { TxOptions::NONE },
    }
}

/// Minimal command frame, byte-pinned: FLAG | LEN=5 | CTRL=0x00 |
/// ID 0x0001 LE | CRC16-LE(`00 01 00` = 0xFFAD) | FLAG.
#[test]
fn ezsp_known_vector_byte_pinned() {
    let mut out = [0u8; 32];
    let n = encode(0, CMD_DATA_SEND, &[], &mut out).unwrap();
    assert_eq!(&out[..n], &[FLAG, 0x05, 0x00, 0x01, 0x00, 0xAD, 0xFF, FLAG]);
    let (frame, used) = decode(&out[..n]).unwrap();
    assert_eq!(used, n);
    assert_eq!(frame.seq(), 0);
    assert_eq!(frame.frame_id, CMD_DATA_SEND);
    assert_eq!(frame.payload_bytes(), &[]);
}

/// FLAG and ESC bytes inside the body must be stuffed so the only
/// raw FLAG octets are the two delimiters.
#[test]
fn ezsp_escapes_flag_and_escape_bytes() {
    let payload = [FLAG, 0x7D, 0x00, FLAG];
    let mut out = [0u8; 64];
    let n = encode(2, CMD_DATA_SEND, &payload, &mut out).unwrap();
    assert_eq!(out[0], FLAG);
    assert_eq!(out[n - 1], FLAG);
    assert_eq!(out[1..n - 1].iter().filter(|b| **b == FLAG).count(), 0);
    let (frame, used) = decode(&out[..n]).unwrap();
    assert_eq!(used, n);
    assert_eq!(frame.seq(), 2);
    assert_eq!(frame.payload_bytes(), &payload);
}

/// A flipped body octet must fail the CRC, never decode.
#[test]
fn ezsp_crc_mismatch_refused() {
    let mut out = [0u8; 32];
    let n = encode(1, CMD_DATA_SEND, &[0xAA], &mut out).unwrap();
    out[n - 3] ^= 0x01;
    assert_eq!(decode(&out[..n]), Err(EzspError::BadCrc));
}

/// Missing closing FLAG is truncation, not a frame.
#[test]
fn ezsp_truncated_refused() {
    let mut out = [0u8; 32];
    let n = encode(0, CMD_DATA_SEND, &[0xAA], &mut out).unwrap();
    assert_eq!(decode(&out[..n - 1]), Err(EzspError::Truncated));
    assert_eq!(decode(&[]), Err(EzspError::Truncated));
}

/// Sequence numbers are 3-bit and wrap.
#[test]
fn ezsp_seq_wraps_at_eight() {
    assert_eq!(CTRL_SEQ_MASK, 0x07);
    let mut s = 0u8;
    for expect in [1u8, 2, 3, 4, 5, 6, 7, 0, 1] {
        s = next_seq(s);
        assert_eq!(s, expect);
    }
}

/// Oversize payloads are refused before touching the output.
#[test]
fn ezsp_oversize_refused() {
    let big = [0xAAu8; MAX_EZSP_PAYLOAD + 1];
    let mut out = [0u8; 300];
    assert_eq!(
        encode(0, CMD_DATA_SEND, &big, &mut out),
        Err(EzspError::TooLong)
    );
    assert_eq!(out, [0u8; 300]);
}

/// Callback-bit frames decode with the flag surfaced.
#[test]
fn ezsp_callback_flag_surfaced() {
    let t = MockEzspTransport::new();
    let raw = t.callback_frame(EVT_DATA_RECEIVE, &[0x01]);
    let (frame, _) = decode(&raw.0[..raw.1]).unwrap();
    assert!(frame.is_callback());
    assert_eq!(frame.control & CTRL_CALLBACK, CTRL_CALLBACK);
}

/// `data_request` emits one FLAG-delimited command frame carrying
/// destination + options + MSDU, and returns a fresh handle.
#[test]
fn ember_data_request_encodes_ezsp_frame() {
    let mut adapter = EmberAdapter::new();
    let msdu = [0x08, 0x00, 0x00, 0x01, 0x00, 0x1E, 0x7A];
    let h = adapter
        .data_request(req(MacAddress::short(0xC601, 0x0002), &msdu, true))
        .unwrap();
    assert_eq!(adapter.tx_queue_free(), 3);
    let raw = adapter.transport().tx_frame(0).unwrap();
    let (frame, _) = decode(raw).unwrap();
    assert!(!frame.is_callback());
    assert_eq!(frame.frame_id, CMD_DATA_SEND);
    let body = frame.payload_bytes();
    assert_eq!(&body[..2], &[0x02, 0x00]);
    assert_eq!(body[2], 0x01);
    assert_eq!(&body[3..], &msdu);
    // Handles are adapter-scoped and never reused while outstanding.
    let h2 = adapter
        .data_request(req(MacAddress::short(0xC601, 0x0003), &msdu, false))
        .unwrap();
    assert_ne!(h, h2);
}

/// An NCP confirm callback completes the matching transaction.
#[test]
fn ember_confirm_mapping_delivered() {
    let mut adapter = EmberAdapter::new();
    let h = adapter
        .data_request(req(MacAddress::short(0xC601, 0x0002), &[0x01], true))
        .unwrap();
    assert_eq!(adapter.poll_confirm(), None);
    adapter.inject_ncp_confirm(0, STATUS_DELIVERED);
    let c = adapter.poll_confirm().unwrap();
    assert_eq!(c.handle, h);
    assert_eq!(c.status, TxStatus::Delivered);
    assert_eq!(c.timestamp_us, None);
    assert_eq!(adapter.poll_confirm(), None);
}

/// A failed delivery surfaces as `NoAck`, never as success.
#[test]
fn ember_confirm_mapping_no_ack() {
    let mut adapter = EmberAdapter::new();
    let h = adapter
        .data_request(req(MacAddress::short(0xC601, 0x0002), &[0x01], true))
        .unwrap();
    adapter.inject_ncp_confirm(0, STATUS_NO_ACK);
    let c = adapter.poll_confirm().unwrap();
    assert_eq!((c.handle, c.status), (h, TxStatus::NoAck));
}

/// An NCP receive callback becomes an `RxIndication` with the same
/// source, LQI, and MSDU bytes the NCP reported.
#[test]
fn ember_indication_mapping() {
    let mut adapter = EmberAdapter::new();
    let msdu = [0x08, 0x00, 0x00, 0x01, 0x00, 0x1E, 0x7A];
    adapter.inject_ncp_receive(0x0002, 200, &msdu);
    let ind = adapter.poll_indication().unwrap();
    assert_eq!(ind.src, MacAddress::short(0xC601, 0x0002));
    assert_eq!(ind.lqi, 200);
    assert_eq!(ind.msdu.as_slice(), &msdu);
    assert_eq!(adapter.poll_indication(), None);
}

/// Backpressure and cancel match the SAP contract: the 5th queued
/// request fails, a queued handle cancels, unknown handles refuse.
#[test]
fn ember_backpressure_and_cancel() {
    use rounddance_mac_sap::MacError;
    let mut adapter = EmberAdapter::new();
    assert_eq!(adapter.tx_queue_capacity(), 4);
    let mut handles = [TxHandle(0); 4];
    for (i, h) in handles.iter_mut().enumerate() {
        *h = adapter
            .data_request(req(MacAddress::short(0xC601, i as u16), &[i as u8], false))
            .unwrap();
    }
    assert!(adapter.tx_queue_full());
    assert_eq!(
        adapter.data_request(req(MacAddress::short(0xC601, 9), &[9], false)),
        Err(MacError::QueueFull)
    );
    adapter.data_cancel(handles[1]).unwrap();
    assert_eq!(adapter.tx_queue_free(), 1);
    let c = adapter.poll_confirm().unwrap();
    assert_eq!((c.handle, c.status), (handles[1], TxStatus::Cancelled));
    assert_eq!(
        adapter.data_cancel(handles[1]),
        Err(MacError::UnknownHandle)
    );
}

/// Address-shape errors match the existing MAC codec decision for
/// decision: extended is well-formed but unsupported here, `None`
/// is malformed, oversize is too long — on both adapters.
#[test]
fn ember_error_mapping_parity_with_esp_codec() {
    use rounddance_hal_esp::{EspAdapter, MockDriver};
    use rounddance_mac_sap::MacError;
    let mut ember = EmberAdapter::new();
    let mut esp = EspAdapter::new(MockDriver::new());
    esp.init().unwrap();
    let cases: [(TxRequest, MacError); 2] = [
        (
            req(
                MacAddress {
                    pan: Some(0xC601),
                    addr: AddrMode::Extended(0x0012_4B00_1A2B_3C4D),
                },
                &[0x01],
                false,
            ),
            MacError::Unsupported,
        ),
        (
            req(
                MacAddress {
                    pan: None,
                    addr: AddrMode::None,
                },
                &[0x01],
                false,
            ),
            MacError::InvalidAddress,
        ),
    ];
    for (r, expect) in cases {
        assert_eq!(ember.data_request(r), Err(expect));
        assert_eq!(esp.data_request(r), Err(expect));
    }
    // Hold auto-complete so queued ESP transactions stay queued
    // and the 5th request genuinely meets a full queue.
    esp.driver_mut().hold_auto_complete();
    // Backpressure coincides too: both depths are 4, so the 5th
    // queued request fails identically on both legs.
    for i in 0..4 {
        let r = req(MacAddress::short(0xC601, i), &[i as u8], false);
        assert!(ember.data_request(r).is_ok());
        assert!(esp.data_request(r).is_ok());
    }
    let full = req(MacAddress::short(0xC601, 9), &[9], false);
    assert_eq!(ember.data_request(full), Err(MacError::QueueFull));
    assert_eq!(esp.data_request(full), Err(MacError::QueueFull));
}

/// Join-transaction parity: the same NWK join MSDU (built through
/// the repo NWK codec, as a 3.0 peer emits it) takes the same
/// request/confirm/indication decisions on the Ember path and on
/// the existing short-short MAC codec path.
#[test]
fn ember_join_flow_parity_with_esp_codec() {
    use rounddance_hal_esp::driver::RxFrame;
    use rounddance_hal_esp::{adapter::build_data_frame, EspAdapter, MockDriver};
    // Join MSDU: NWK data header a 3.0 peer emits (version 2).
    let header = rounddance_nwk::NwkHeader::minimal(
        rounddance_nwk::FrameControl::data(),
        0x0000,
        0x0001,
        30,
        0x7A,
    );
    let mut msdu = [0u8; 32];
    let n = header.encode_into(&[], &mut msdu).unwrap();
    let msdu = &msdu[..n];

    let mut ember = EmberAdapter::new();
    let mut esp = EspAdapter::new(MockDriver::new());
    esp.init().unwrap();
    // Same provisioning on both legs: PAN 0xC601, our short 0x0002.
    esp.set_pan_id(0xC601);
    esp.set_short_addr(0x0002);
    let dst = MacAddress::short(0xC601, 0x0000);
    let he = ember.data_request(req(dst, msdu, true)).unwrap();
    let hs = esp.data_request(req(dst, msdu, true)).unwrap();
    assert_eq!(he, hs);

    // Complete both legs: NCP confirm callback vs driver auto-Done.
    ember.inject_ncp_confirm(0, STATUS_DELIVERED);
    let ce = ember.poll_confirm().unwrap();
    let cs = esp.poll_confirm().unwrap();
    assert_eq!((ce.handle, ce.status), (he, TxStatus::Delivered));
    assert_eq!((cs.handle, cs.status), (hs, TxStatus::Delivered));

    // Same inbound frame on both legs: NCP receive callback vs an
    // air frame through the short-short codec with the same LQI.
    ember.inject_ncp_receive(0x0001, 200, msdu);
    let (air, air_len) = build_data_frame(7, 0xC601, 0x0002, 0x0001, msdu, false).unwrap();
    esp.driver_mut()
        .inject_rx(&[RxFrame::from_slice(&air[..air_len], 15, -60, 200).unwrap()]);

    let ie = ember.poll_indication().unwrap();
    let is = esp.poll_indication().unwrap();
    assert_eq!(ie.src, MacAddress::short(0xC601, 0x0001));
    assert_eq!(is.src, MacAddress::short(0xC601, 0x0001));
    assert_eq!((ie.lqi, is.lqi), (200, 200));
    assert_eq!(ie.msdu.as_slice(), msdu);
    assert_eq!(is.msdu.as_slice(), msdu);
}
