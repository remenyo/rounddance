//! TI/Z-Stack-MT adapter vectors: frame codec pins plus the SAP-level
//! mapping and the decision-for-decision parity leg against the
//! existing short-short MAC codec (`EspAdapter` + `MockDriver`).
//!
//! No hardware, no serial: the NCP side is the in-crate mock
//! transport. New behaviors are `RD-COMPAT-08..10` (repo-minted,
//! MINTED-pending-confirm). `RD-COMPAT-05..07` (Ember half) stand
//! CONFIRMED via corpus sweep-41 (0 corrections / 0 REJECT).

use rounddance_compat::ti::{
    decode, encode, MtDecoder, MtDropReason, MtOutcome, TiAdapter, CMD_DATA_SEND_C0,
    CMD_DATA_SEND_C1, EVT_DATA_RECEIVE_C0, EVT_DATA_RECEIVE_C1, MAX_MT_PAYLOAD, MT_TYPE_AREQ,
    MT_TYPE_MASK, MT_TYPE_SREQ, SOF, STATUS_DELIVERED, STATUS_NO_ACK,
};
use rounddance_mac_sap::{
    AddrMode, FramePayload, MacAddress, MacDataSap, MacMgmtSap, TxHandle, TxOptions, TxRequest,
    TxStatus,
};

/// Feed every byte, collecting the non-silent outcomes.
fn pump(dec: &mut MtDecoder, bytes: &[u8]) -> Vec<MtOutcome> {
    let mut out = Vec::new();
    for b in bytes {
        if let Some(o) = dec.push_byte(*b) {
            out.push(o);
        }
    }
    out
}

/// Streaming byte pin: SOF | LEN=3 | 0x24 | 0x01 | AA 10 FE | FCS.
/// The data carries a SOF-valued octet (length, not flags, delimits)
/// and the FCS is hand-computed through the independent XOR-fold
/// oracle (`03 ^ 24 ^ 01 ^ AA ^ 10 ^ FE` = 0x62).
#[test]
fn mt_decoder_byte_pinned_vector() {
    let wire = [SOF, 0x03, 0x24, 0x01, 0xAA, 0x10, 0xFE, 0x62];
    assert_eq!(
        rounddance_compat::ti::fcs(0x03, 0x24, 0x01, &[0xAA, 0x10, 0xFE]),
        0x62
    );
    let mut dec = MtDecoder::new();
    for b in &wire[..wire.len() - 1] {
        assert_eq!(dec.push_byte(*b), None);
    }
    let Some(MtOutcome::Frame(frame)) = dec.push_byte(wire[wire.len() - 1]) else {
        panic!("pinned wire must decode");
    };
    assert_eq!((frame.cmd0, frame.cmd1), (0x24, 0x01));
    assert_eq!(frame.payload_bytes(), &[0xAA, 0x10, 0xFE]);
    assert_eq!(dec.dropped(), 0);
}

/// Split feeds reassemble to the same frame the one-shot `decode`
/// returns, however the bytes are chunked.
#[test]
fn mt_decoder_split_feed_reassembles() {
    let mut raw = [0u8; 160];
    let data = [0x08u8, 0x00, 0x00, 0x01, 0x00, 0x1E, 0x7A];
    let n = encode(CMD_DATA_SEND_C0, CMD_DATA_SEND_C1, &data, &mut raw).unwrap();
    let (want, used) = decode(&raw[..n]).unwrap();
    assert_eq!(used, n);
    for split in [1usize, 2, 4, 5, 7] {
        let mut dec = MtDecoder::new();
        let mut frames = Vec::new();
        for chunk in raw[..n].chunks(split) {
            for o in pump(&mut dec, chunk) {
                frames.push(o);
            }
        }
        assert_eq!(frames.len(), 1, "split {split}");
        let MtOutcome::Frame(got) = frames[0] else {
            panic!("split {split} must yield a frame");
        };
        assert_eq!(got, want, "split {split}");
    }
}

/// Line noise ahead of SOF is skipped silently; a bad LEN drops one
/// run and re-arms, so the next good frame still decodes and the
/// desync meter resets.
#[test]
fn mt_decoder_resyncs_over_noise_and_bad_len() {
    let mut raw = [0u8; 16];
    let n = encode(CMD_DATA_SEND_C0, CMD_DATA_SEND_C1, &[0xAA], &mut raw).unwrap();
    let mut dec = MtDecoder::new();
    // Noise with no SOF: silent.
    assert!(pump(&mut dec, &[0x00, 0x55, 0x13]).is_empty());
    // SOF naming 0xFF data octets: one BadLen drop, then re-armed.
    assert_eq!(
        pump(&mut dec, &[SOF, 0xFF]),
        [MtOutcome::Dropped(MtDropReason::BadLen(0xFF))]
    );
    assert_eq!(dec.dropped(), 1);
    assert_eq!(dec.consecutive_bad(), 1);
    // The good frame still decodes; the meter resets.
    let outcomes = pump(&mut dec, &raw[..n]);
    assert_eq!(outcomes.len(), 1);
    let MtOutcome::Frame(frame) = outcomes[0] else {
        panic!("good frame must decode after a drop");
    };
    assert_eq!(frame.payload_bytes(), &[0xAA]);
    assert_eq!(dec.consecutive_bad(), 0);
    assert_eq!(dec.dropped(), 1);
}

/// A flipped body octet fails the FCS: one `BadFcs` drop, counters
/// tick, and the stream re-arms for the next frame.
#[test]
fn mt_decoder_bad_fcs_drops_and_rearms() {
    let mut raw = [0u8; 16];
    let n = encode(CMD_DATA_SEND_C0, CMD_DATA_SEND_C1, &[0xAA, 0x10], &mut raw).unwrap();
    let mut bad = [0u8; 16];
    bad[..n].copy_from_slice(&raw[..n]);
    bad[4] ^= 0x01;
    let mut dec = MtDecoder::new();
    assert_eq!(
        pump(&mut dec, &bad[..n]),
        [MtOutcome::Dropped(MtDropReason::BadFcs)]
    );
    assert_eq!((dec.dropped(), dec.consecutive_bad()), (1, 1));
    let outcomes = pump(&mut dec, &raw[..n]);
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(outcomes[0], MtOutcome::Frame(_)));
    assert_eq!((dec.dropped(), dec.consecutive_bad()), (1, 0));
}

/// Two frames back-to-back decode in order with no drops.
#[test]
fn mt_decoder_back_to_back_frames() {
    let mut first = [0u8; 16];
    let mut second = [0u8; 16];
    let n1 = encode(CMD_DATA_SEND_C0, CMD_DATA_SEND_C1, &[], &mut first).unwrap();
    let n2 = encode(
        CMD_DATA_SEND_C0,
        CMD_DATA_SEND_C1,
        &[0x01, 0x02],
        &mut second,
    )
    .unwrap();
    let mut wire = [0u8; 32];
    wire[..n1].copy_from_slice(&first[..n1]);
    wire[n1..n1 + n2].copy_from_slice(&second[..n2]);
    let mut dec = MtDecoder::new();
    let outcomes = pump(&mut dec, &wire[..n1 + n2]);
    assert_eq!(outcomes.len(), 2);
    let [MtOutcome::Frame(a), MtOutcome::Frame(b)] = outcomes[..] else {
        panic!("both frames must decode in order");
    };
    assert_eq!(
        (a.payload_bytes(), b.payload_bytes()),
        (&[][..], &[0x01, 0x02][..])
    );
    assert_eq!(dec.dropped(), 0);
}

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

/// Streaming receive path, byte-pinned: SOF | LEN=5 | 0x44 | 0x82 |
/// `01 00 C8 08 00` (src 0x0001, LQI 200, MSDU `08 00`) | FCS
/// (`05 ^ 44 ^ 82 ^ 01 ^ 00 ^ C8 ^ 08 ^ 00` = 0x02, independent
/// python3 XOR-fold oracle). Fed whole through the byte ingress, the
/// indication surfaces with the same source, LQI, and MSDU the NCP
/// reported and no drop is counted.
#[test]
fn ti_stream_receive_byte_pinned_vector() {
    let wire = [SOF, 0x05, 0x44, 0x82, 0x01, 0x00, 0xC8, 0x08, 0x00, 0x02];
    let mut adapter = TiAdapter::new();
    adapter.push_rx_bytes(&wire);
    let ind = adapter.poll_indication().unwrap();
    assert_eq!(ind.src, MacAddress::short(0xC601, 0x0001));
    assert_eq!(ind.lqi, 200);
    assert_eq!(ind.msdu.as_slice(), &[0x08, 0x00]);
    assert_eq!(adapter.poll_indication(), None);
    assert_eq!(
        (adapter.stream_dropped(), adapter.stream_consecutive_bad()),
        (0, 0)
    );
    assert_eq!(adapter.rx_dropped(), 0);
}

/// Split feeds reassemble through the adapter: one confirm callback
/// (`FE 02 44 81 00 00 C7`, token 0 + DELIVERED) fed byte-by-byte
/// plus one receive callback fed in 3-byte chunks complete the same
/// request/confirm/indication decisions the queued-frame pump makes.
#[test]
fn ti_stream_receive_split_feed_delivers_confirm_and_indication() {
    let mut adapter = TiAdapter::new();
    let h = adapter
        .data_request(req(MacAddress::short(0xC601, 0x0002), &[0x01], true))
        .unwrap();
    let confirm = [SOF, 0x02, 0x44, 0x81, 0x00, 0x00, 0xC7];
    for b in &confirm {
        adapter.push_rx_bytes(&[*b]);
    }
    let c = adapter.poll_confirm().unwrap();
    assert_eq!((c.handle, c.status), (h, TxStatus::Delivered));
    let receive = [SOF, 0x05, 0x44, 0x82, 0x01, 0x00, 0xC8, 0x08, 0x00, 0x02];
    for chunk in receive.chunks(3) {
        adapter.push_rx_bytes(chunk);
    }
    let ind = adapter.poll_indication().unwrap();
    assert_eq!(ind.src, MacAddress::short(0xC601, 0x0001));
    assert_eq!(ind.msdu.as_slice(), &[0x08, 0x00]);
    assert_eq!(
        (adapter.stream_dropped(), adapter.stream_consecutive_bad()),
        (0, 0)
    );
    assert_eq!(adapter.rx_dropped(), 0);
}

/// A failed delivery streamed off the wire surfaces as `NoAck`:
/// `FE 02 44 81 00 01 C6` (token 0 + NO_ACK, FCS `02 ^ 44 ^ 81 ^
/// 00 ^ 01` = 0xC6 via the python3 oracle) completes the matching
/// transaction without success.
#[test]
fn ti_stream_receive_no_ack_maps_to_noack() {
    let mut adapter = TiAdapter::new();
    let h = adapter
        .data_request(req(MacAddress::short(0xC601, 0x0002), &[0x01], true))
        .unwrap();
    adapter.push_rx_bytes(&[SOF, 0x02, 0x44, 0x81, 0x00, 0x01, 0xC6]);
    let c = adapter.poll_confirm().unwrap();
    assert_eq!((c.handle, c.status), (h, TxStatus::NoAck));
    assert_eq!(adapter.rx_dropped(), 0);
}

/// Line noise, an oversize LEN, and a bad FCS drop through the byte
/// ingress exactly as the decoder reports them — then a good confirm
/// still completes its transaction and the desync meter resets.
#[test]
fn ti_stream_receive_resyncs_over_noise_bad_len_and_bad_fcs() {
    let mut adapter = TiAdapter::new();
    let h = adapter
        .data_request(req(MacAddress::short(0xC601, 0x0002), &[0x01], true))
        .unwrap();
    // Noise with no SOF: silent, no counters.
    adapter.push_rx_bytes(&[0x00, 0x55]);
    assert_eq!(
        (adapter.stream_dropped(), adapter.stream_consecutive_bad()),
        (0, 0)
    );
    // SOF naming 0xFF data octets: one BadLen drop, then re-armed.
    adapter.push_rx_bytes(&[SOF, 0xFF]);
    assert_eq!(
        (adapter.stream_dropped(), adapter.stream_consecutive_bad()),
        (1, 1)
    );
    // Confirm with a flipped data octet (FCS still 0xC7): BadFcs drop.
    adapter.push_rx_bytes(&[SOF, 0x02, 0x44, 0x81, 0x01, 0x00, 0xC7]);
    assert_eq!(
        (adapter.stream_dropped(), adapter.stream_consecutive_bad()),
        (2, 2)
    );
    // The good confirm still matches its slot; the meter resets.
    adapter.push_rx_bytes(&[SOF, 0x02, 0x44, 0x81, 0x00, 0x00, 0xC7]);
    let c = adapter.poll_confirm().unwrap();
    assert_eq!((c.handle, c.status), (h, TxStatus::Delivered));
    assert_eq!(
        (adapter.stream_dropped(), adapter.stream_consecutive_bad()),
        (2, 0)
    );
    assert_eq!(adapter.rx_dropped(), 2);
}

/// An FCS-clean frame with an unknown command (`FE 01 44 FF 00 BA`,
/// FCS `01 ^ 44 ^ FF ^ 00` = 0xBA via the python3 oracle) is
/// well-formed but unroutable: counted, never queued.
#[test]
fn ti_stream_receive_unknown_command_counts_dropped() {
    let mut adapter = TiAdapter::new();
    adapter.push_rx_bytes(&[SOF, 0x01, 0x44, 0xFF, 0x00, 0xBA]);
    assert_eq!(adapter.poll_confirm(), None);
    assert_eq!(adapter.poll_indication(), None);
    assert_eq!(
        (adapter.stream_dropped(), adapter.stream_consecutive_bad()),
        (0, 0)
    );
    assert_eq!(adapter.rx_dropped(), 1);
}

/// Backpressure parity with the queued-frame pump: the indication
/// queue holds 8, so the 9th streamed receive callback is counted,
/// never queued — and every queued indication drains in order.
#[test]
fn ti_stream_receive_full_indication_queue_counts_dropped() {
    let mut adapter = TiAdapter::new();
    let one = [SOF, 0x05, 0x44, 0x82, 0x01, 0x00, 0xC8, 0x08, 0x00, 0x02];
    let mut nine = [0u8; 90];
    for (i, slot) in nine.chunks_mut(10).enumerate() {
        slot.copy_from_slice(&one);
        let _ = i;
    }
    adapter.push_rx_bytes(&nine);
    for _ in 0..8 {
        let ind = adapter.poll_indication().unwrap();
        assert_eq!(ind.src, MacAddress::short(0xC601, 0x0001));
    }
    assert_eq!(adapter.poll_indication(), None);
    assert_eq!(adapter.rx_dropped(), 1);
}
