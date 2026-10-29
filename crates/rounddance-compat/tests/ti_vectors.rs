//! TI/Z-Stack-MT adapter vectors: frame codec pins plus the SAP-level
//! mapping and the decision-for-decision parity leg against the
//! existing short-short MAC codec (`EspAdapter` + `MockDriver`).
//!
//! No hardware, no serial: the NCP side is the in-crate mock
//! transport. New behaviors are `RD-COMPAT-08..10` (repo-minted,
//! MINTED-pending-confirm). `RD-COMPAT-05..07` (Ember half) stand
//! CONFIRMED via corpus sweep-41 (0 corrections / 0 REJECT).

use rounddance_compat::ti::{
    decode, encode, TiAdapter, CMD_DATA_SEND_C0, CMD_DATA_SEND_C1, EVT_DATA_RECEIVE_C0,
    EVT_DATA_RECEIVE_C1, MAX_MT_PAYLOAD, MT_TYPE_AREQ, MT_TYPE_MASK, MT_TYPE_SREQ, SOF,
    STATUS_DELIVERED, STATUS_NO_ACK,
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

/// Minimal command frame, byte-pinned: SOF | LEN=0 | CMD0 0x24 |
/// CMD1 0x01 | FCS (`00 ^ 24 ^ 01` = 0x25).
#[test]
fn mt_known_vector_byte_pinned() {
    let mut out = [0u8; 16];
    let n = encode(CMD_DATA_SEND_C0, CMD_DATA_SEND_C1, &[], &mut out).unwrap();
    assert_eq!(&out[..n], &[SOF, 0x00, 0x24, 0x01, 0x25]);
    let (frame, used) = decode(&out[..n]).unwrap();
    assert_eq!(used, n);
    assert_eq!(
        (frame.cmd0, frame.cmd1),
        (CMD_DATA_SEND_C0, CMD_DATA_SEND_C1)
    );
    assert_eq!(frame.payload_bytes(), &[]);
}

/// A flipped body octet must fail the FCS, never decode.
#[test]
fn mt_fcs_mismatch_refused() {
    use rounddance_compat::ti::MtError;
    let mut out = [0u8; 16];
    let n = encode(CMD_DATA_SEND_C0, CMD_DATA_SEND_C1, &[0xAA], &mut out).unwrap();
    out[n - 2] ^= 0x01;
    assert_eq!(decode(&out[..n]), Err(MtError::BadFcs));
}

/// A first octet other than SOF is refused before any length work.
#[test]
fn mt_bad_sof_refused() {
    use rounddance_compat::ti::MtError;
    assert_eq!(
        decode(&[0x00, 0x00, 0x24, 0x01, 0x25]),
        Err(MtError::BadSof)
    );
    assert_eq!(decode(&[]), Err(MtError::Truncated));
}

/// Missing FCS is truncation, not a frame; a LEN naming more bytes
/// than are present is truncation too.
#[test]
fn mt_truncated_refused() {
    use rounddance_compat::ti::MtError;
    let mut out = [0u8; 16];
    let n = encode(CMD_DATA_SEND_C0, CMD_DATA_SEND_C1, &[0xAA], &mut out).unwrap();
    assert_eq!(decode(&out[..n - 1]), Err(MtError::Truncated));
    // LEN claims 4 data octets, only 1 present.
    assert_eq!(
        decode(&[SOF, 0x04, 0x24, 0x01, 0xAA]),
        Err(MtError::Truncated)
    );
}

/// A LEN beyond the bounded data capacity is refused, never
/// allocated around.
#[test]
fn mt_bad_length_refused() {
    use rounddance_compat::ti::MtError;
    assert_eq!(
        decode(&[SOF, 0xFF, 0x24, 0x01, 0x00]),
        Err(MtError::BadLength)
    );
}

/// Oversize payloads are refused before touching the output.
#[test]
fn mt_oversize_refused() {
    use rounddance_compat::ti::MtError;
    let big = [0xAAu8; MAX_MT_PAYLOAD + 1];
    let mut out = [0u8; 160];
    assert_eq!(
        encode(CMD_DATA_SEND_C0, CMD_DATA_SEND_C1, &big, &mut out),
        Err(MtError::TooLong)
    );
    assert_eq!(out, [0u8; 160]);
}

/// Command-type bits ride in CMD0: host-to-NCP sends are SREQ, NCP
/// callbacks are AREQ — responses and callbacks never alias.
#[test]
fn mt_type_flags_surfaced() {
    assert_eq!(CMD_DATA_SEND_C0 & MT_TYPE_MASK, MT_TYPE_SREQ);
    assert_eq!(EVT_DATA_RECEIVE_C0 & MT_TYPE_MASK, MT_TYPE_AREQ);
    let t = rounddance_compat::ti::MockMtTransport::new();
    let raw = t.callback_frame(EVT_DATA_RECEIVE_C0, EVT_DATA_RECEIVE_C1, &[0x01]);
    let (frame, _) = decode(&raw.0[..raw.1]).unwrap();
    assert_eq!(frame.cmd_type(), MT_TYPE_AREQ);
}

/// `data_request` emits one SOF-delimited command frame carrying the
/// adapter-local token + destination + options + MSDU, and returns a
/// fresh handle.
#[test]
fn ti_data_request_encodes_mt_frame() {
    let mut adapter = TiAdapter::new();
    let msdu = [0x08, 0x00, 0x00, 0x01, 0x00, 0x1E, 0x7A];
    let h = adapter
        .data_request(req(MacAddress::short(0xC601, 0x0002), &msdu, true))
        .unwrap();
    assert_eq!(adapter.tx_queue_free(), 3);
    let raw = adapter.transport().tx_frame(0).unwrap();
    let (frame, _) = decode(raw).unwrap();
    assert_eq!(frame.cmd_type(), MT_TYPE_SREQ);
    assert_eq!(
        (frame.cmd0, frame.cmd1),
        (CMD_DATA_SEND_C0, CMD_DATA_SEND_C1)
    );
    let body = frame.payload_bytes();
    assert_eq!(&body[1..3], &[0x02, 0x00]);
    assert_eq!(body[3], 0x01);
    assert_eq!(&body[4..], &msdu);
    // Handles are adapter-scoped and never reused while outstanding.
    let h2 = adapter
        .data_request(req(MacAddress::short(0xC601, 0x0003), &msdu, false))
        .unwrap();
    assert_ne!(h, h2);
}

/// An NCP confirm callback completes the matching transaction.
#[test]
fn ti_confirm_mapping_delivered() {
    let mut adapter = TiAdapter::new();
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
fn ti_confirm_mapping_no_ack() {
    let mut adapter = TiAdapter::new();
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
fn ti_indication_mapping() {
    let mut adapter = TiAdapter::new();
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
fn ti_backpressure_and_cancel() {
    use rounddance_mac_sap::MacError;
    let mut adapter = TiAdapter::new();
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
fn ti_error_mapping_parity_with_esp_codec() {
    use rounddance_hal_esp::{EspAdapter, MockDriver};
    use rounddance_mac_sap::MacError;
    let mut ti = TiAdapter::new();
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
        assert_eq!(ti.data_request(r), Err(expect));
        assert_eq!(esp.data_request(r), Err(expect));
    }
    // Hold auto-complete so queued ESP transactions stay queued
    // and the 5th request genuinely meets a full queue.
    esp.driver_mut().hold_auto_complete();
    // Backpressure coincides too: both depths are 4, so the 5th
    // queued request fails identically on both legs.
    for i in 0..4 {
        let r = req(MacAddress::short(0xC601, i), &[i as u8], false);
        assert!(ti.data_request(r).is_ok());
        assert!(esp.data_request(r).is_ok());
    }
    let full = req(MacAddress::short(0xC601, 9), &[9], false);
    assert_eq!(ti.data_request(full), Err(MacError::QueueFull));
    assert_eq!(esp.data_request(full), Err(MacError::QueueFull));
}

/// Join-transaction parity: the same NWK join MSDU (built through
/// the repo NWK codec, as a 3.0 peer emits it) takes the same
/// request/confirm/indication decisions on the TI path and on
/// the existing short-short MAC codec path.
#[test]
fn ti_join_flow_parity_with_esp_codec() {
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

    let mut ti = TiAdapter::new();
    let mut esp = EspAdapter::new(MockDriver::new());
    esp.init().unwrap();
    // Same provisioning on both legs: PAN 0xC601, our short 0x0002.
    esp.set_pan_id(0xC601);
    esp.set_short_addr(0x0002);
    let dst = MacAddress::short(0xC601, 0x0000);
    let he = ti.data_request(req(dst, msdu, true)).unwrap();
    let hs = esp.data_request(req(dst, msdu, true)).unwrap();
    assert_eq!(he, hs);

    // Complete both legs: NCP confirm callback vs driver auto-Done.
    ti.inject_ncp_confirm(0, STATUS_DELIVERED);
    let ce = ti.poll_confirm().unwrap();
    let cs = esp.poll_confirm().unwrap();
    assert_eq!((ce.handle, ce.status), (he, TxStatus::Delivered));
    assert_eq!((cs.handle, cs.status), (hs, TxStatus::Delivered));

    // Same inbound frame on both legs: NCP receive callback vs an
    // air frame through the short-short codec with the same LQI.
    ti.inject_ncp_receive(0x0001, 200, msdu);
    let (air, air_len) = build_data_frame(7, 0xC601, 0x0002, 0x0001, msdu, false).unwrap();
    esp.driver_mut()
        .inject_rx(&[RxFrame::from_slice(&air[..air_len], 15, -60, 200).unwrap()]);

    let ie = ti.poll_indication().unwrap();
    let is = esp.poll_indication().unwrap();
    assert_eq!(ie.src, MacAddress::short(0xC601, 0x0001));
    assert_eq!(is.src, MacAddress::short(0xC601, 0x0001));
    assert_eq!((ie.lqi, is.lqi), (200, 200));
    assert_eq!(ie.msdu.as_slice(), msdu);
    assert_eq!(is.msdu.as_slice(), msdu);
}
