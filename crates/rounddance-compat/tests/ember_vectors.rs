//! Ember/EZSP adapter vectors: frame codec pins plus the SAP-level
//! mapping and the decision-for-decision parity leg against the
//! existing short-short MAC codec (`EspAdapter` + `MockDriver`).
//!
//! No hardware, no serial: the NCP side is the in-crate mock
//! transport. New behaviors are `RD-COMPAT-05..07` (repo-minted,
//! MINTED-pending-confirm).

use rounddance_compat::ember::{
    decode, encode, next_seq, EmberAdapter, EzspDecoder, EzspDropReason, EzspError, EzspOutcome,
    MockEzspTransport, CMD_DATA_SEND, CTRL_CALLBACK, CTRL_SEQ_MASK, EVT_DATA_RECEIVE, FLAG,
    MAX_ENCODED_FRAME, MAX_EZSP_PAYLOAD, STATUS_DELIVERED, STATUS_NO_ACK,
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

/// Feed every byte, collecting the non-silent outcomes.
fn pump_dec(dec: &mut EzspDecoder, bytes: &[u8]) -> Vec<EzspOutcome> {
    let mut out = Vec::new();
    for b in bytes {
        if let Some(o) = dec.push_byte(*b) {
            out.push(o);
        }
    }
    out
}

/// Streaming byte pin: FLAG | LEN=6 | CTRL=0x02 | ID 0x0001 LE |
/// stuffed FLAG (`7D 5E`) | CRC16-LE(`02 01 00 7E` = 0xC1C1) | FLAG.
/// The payload carries a FLAG-valued octet (only the two delimiting
/// FLAGs are raw — the body FLAG is stuffed) and the CRC is
/// hand-computed through the independent CRC-16/CCITT oracle
/// (`crc16(b"123456789") == 0x29B1` pins the oracle itself).
#[test]
fn ezsp_decoder_byte_pinned_vector() {
    let wire = [FLAG, 0x06, 0x02, 0x01, 0x00, 0x7D, 0x5E, 0xC1, 0xC1, FLAG];
    assert_eq!(
        rounddance_compat::ember::crc16(&[0x02, 0x01, 0x00, 0x7E]),
        0xC1C1
    );
    let mut dec = EzspDecoder::new();
    for b in &wire[..wire.len() - 1] {
        assert_eq!(dec.push_byte(*b), None);
    }
    let Some(EzspOutcome::Frame(frame)) = dec.push_byte(wire[wire.len() - 1]) else {
        panic!("pinned wire must decode");
    };
    assert_eq!(frame.control, 0x02);
    assert_eq!(frame.seq(), 2);
    assert!(!frame.is_callback());
    assert_eq!(frame.frame_id, CMD_DATA_SEND);
    assert_eq!(frame.payload_bytes(), &[0x7E]);
    assert_eq!(dec.dropped(), 0);
}

/// Split feeds reassemble to the same frame the one-shot `decode`
/// returns, however the bytes are chunked (length delimits, and the
/// stuffed body is re-validated byte-identically on close).
#[test]
fn ezsp_decoder_split_feed_reassembles() {
    let mut raw = [0u8; MAX_ENCODED_FRAME];
    let payload = [FLAG, 0x7D, 0x08, 0x00, 0x00, 0x01, 0x00, 0x1E, 0x7A];
    let n = encode(5, CMD_DATA_SEND, &payload, &mut raw).unwrap();
    let (want, used) = decode(&raw[..n]).unwrap();
    assert_eq!(used, n);
    for split in [1usize, 2, 5, 7, 9] {
        let mut dec = EzspDecoder::new();
        let mut frames = Vec::new();
        for chunk in raw[..n].chunks(split) {
            for o in pump_dec(&mut dec, chunk) {
                frames.push(o);
            }
        }
        assert_eq!(frames.len(), 1, "split {split}");
        let EzspOutcome::Frame(got) = frames[0] else {
            panic!("split {split} must yield a frame");
        };
        assert_eq!(got, want, "split {split}");
    }
}

/// Line noise ahead of FLAG is skipped silently; a LEN that disagrees
/// with the delimited body drops one run and re-arms, so the next
/// good frame still decodes and the desync meter resets.
#[test]
fn ezsp_decoder_resyncs_over_noise_and_bad_len() {
    let mut raw = [0u8; 32];
    let n = encode(1, CMD_DATA_SEND, &[0xAA], &mut raw).unwrap();
    let mut bad = [0u8; 32];
    bad[..n].copy_from_slice(&raw[..n]);
    bad[1] = bad[1].wrapping_add(1);
    assert_eq!(decode(&bad[..n]), Err(EzspError::BadLength));
    let mut dec = EzspDecoder::new();
    // Noise with no FLAG: silent.
    assert!(pump_dec(&mut dec, &[0x00, 0x55, 0x13]).is_empty());
    // LEN mismatch: one BadLength drop, then re-armed.
    assert_eq!(
        pump_dec(&mut dec, &bad[..n]),
        [EzspOutcome::Dropped(EzspDropReason::BadLength)]
    );
    assert_eq!(dec.dropped(), 1);
    assert_eq!(dec.consecutive_bad(), 1);
    // The good frame still decodes; the meter resets.
    let outcomes = pump_dec(&mut dec, &raw[..n]);
    assert_eq!(outcomes.len(), 1);
    let EzspOutcome::Frame(frame) = outcomes[0] else {
        panic!("good frame must decode after a drop");
    };
    assert_eq!(frame.payload_bytes(), &[0xAA]);
    assert_eq!(dec.consecutive_bad(), 0);
    assert_eq!(dec.dropped(), 1);
}

/// A flipped body octet fails the CRC: one `BadCrc` drop, counters
/// tick, and the stream re-arms for the next frame.
#[test]
fn ezsp_decoder_bad_crc_drops_and_rearms() {
    let mut raw = [0u8; 32];
    let n = encode(1, CMD_DATA_SEND, &[0xAA, 0x10], &mut raw).unwrap();
    let mut bad = [0u8; 32];
    bad[..n].copy_from_slice(&raw[..n]);
    bad[n - 3] ^= 0x01;
    assert_eq!(decode(&bad[..n]), Err(EzspError::BadCrc));
    let mut dec = EzspDecoder::new();
    assert_eq!(
        pump_dec(&mut dec, &bad[..n]),
        [EzspOutcome::Dropped(EzspDropReason::BadCrc)]
    );
    assert_eq!((dec.dropped(), dec.consecutive_bad()), (1, 1));
    let outcomes = pump_dec(&mut dec, &raw[..n]);
    assert!(matches!(outcomes[..], [EzspOutcome::Frame(_)]));
    assert_eq!(dec.consecutive_bad(), 0);
}

/// A dangling ESC just before the closing FLAG is a `BadEscape` drop
/// (same verdict the one-shot `decode` returns on the same bytes),
/// and the stream re-arms for the next frame.
#[test]
fn ezsp_decoder_dangling_escape_drops() {
    // Hand-built: LEN=5 names `CTRL ID CRC` but the last body octet
    // is an ESC with no following octet before the FLAG.
    let wire = [FLAG, 0x05, 0x00, 0x01, 0x00, 0xAD, 0x7D, FLAG];
    assert_eq!(decode(&wire), Err(EzspError::BadEscape));
    let mut dec = EzspDecoder::new();
    assert_eq!(
        pump_dec(&mut dec, &wire),
        [EzspOutcome::Dropped(EzspDropReason::BadEscape)]
    );
    assert_eq!((dec.dropped(), dec.consecutive_bad()), (1, 1));
    // Re-armed: a good frame decodes next.
    let mut raw = [0u8; 32];
    let n = encode(0, CMD_DATA_SEND, &[], &mut raw).unwrap();
    let outcomes = pump_dec(&mut dec, &raw[..n]);
    assert!(matches!(outcomes[..], [EzspOutcome::Frame(_)]));
    assert_eq!(dec.consecutive_bad(), 0);
}

/// A run with no closing FLAG inside the bounded buffer drops exactly
/// once: the overflow byte ends the run, the tail through the run's
/// FLAG is swallowed, and the next good frame decodes.
#[test]
fn ezsp_decoder_overflow_drops_once_and_rearms() {
    let mut raw = [0u8; 32];
    let n = encode(3, CMD_DATA_SEND, &[0x01], &mut raw).unwrap();
    // FLAG-led run of 299 non-FLAG octets closed by its own FLAG:
    // the overflow trips long before the closer arrives.
    let mut overlong = [0x55u8; 301];
    overlong[0] = FLAG;
    overlong[300] = FLAG;
    let mut dec = EzspDecoder::new();
    let outcomes = pump_dec(&mut dec, &overlong);
    assert_eq!(outcomes, [EzspOutcome::Dropped(EzspDropReason::BadLength)]);
    assert_eq!((dec.dropped(), dec.consecutive_bad()), (1, 1));
    let outcomes = pump_dec(&mut dec, &raw[..n]);
    assert!(matches!(outcomes[..], [EzspOutcome::Frame(_)]));
    assert_eq!((dec.dropped(), dec.consecutive_bad()), (1, 0));
}

/// Back-to-back frames on one feed decode in order with no drops.
#[test]
fn ezsp_decoder_back_to_back_frames() {
    let mut first = [0u8; 32];
    let n1 = encode(0, CMD_DATA_SEND, &[0x01], &mut first).unwrap();
    let mut second = [0u8; 32];
    let n2 = encode(1, CMD_DATA_SEND, &[0x02, 0x03], &mut second).unwrap();
    let mut wire = [0u8; 64];
    wire[..n1].copy_from_slice(&first[..n1]);
    wire[n1..n1 + n2].copy_from_slice(&second[..n2]);
    let mut dec = EzspDecoder::new();
    let outcomes = pump_dec(&mut dec, &wire[..n1 + n2]);
    assert_eq!(outcomes.len(), 2);
    let [EzspOutcome::Frame(a), EzspOutcome::Frame(b)] = outcomes[..] else {
        panic!("back-to-back frames must both decode");
    };
    assert_eq!((a.seq(), b.seq()), (0, 1));
    assert_eq!(a.payload_bytes(), &[0x01]);
    assert_eq!(b.payload_bytes(), &[0x02, 0x03]);
    assert_eq!(dec.dropped(), 0);
}
