//! ASH link-control vectors: control-octet pins, full-frame
//! byte-pinned vectors, rejection legs, and the layering leg that
//! carries one EZSP frame body as an ASH DATA payload.
//!
//! No hardware, no serial: vectors are recorded byte pins computed
//! against the CRC-16/CCITT check (`crc16(b"123456789") == 0x29B1`).
//! New behavior is `RD-COMPAT-11` (repo-minted,
//! MINTED-pending-confirm).

use rounddance_compat::ash::{
    decode, decode_control, encode_ack, encode_data, encode_error, encode_nak, encode_rst,
    encode_rstack, next_num, pack_data_header, AshDecoder, AshDropReason, AshError, AshKind,
    AshOutcome, AshRxState, AshTxWindow, RxOutcome, ACK_BASE, ASH_TX_WINDOW, ERROR_CTRL,
    MAX_ASH_DATA, MAX_ENCODED_ASH, NAK_BASE, NUM_MASK, RSTACK_CTRL, RST_CTRL,
};
use rounddance_compat::ember::FLAG;

/// DATA frame, byte-pinned: FLAG | LEN=6 | CTRL=0x11 (frm=1, ack=2)
/// | EZSP-like body `00 01 00` | CRC16-LE(`11 00 01 00` = 0xDAE2)
/// | FLAG.
#[test]
fn ash_data_known_vector_byte_pinned() {
    let mut out = [0u8; 32];
    let n = encode_data(1, 2, false, &[0x00, 0x01, 0x00], &mut out).unwrap();
    assert_eq!(
        &out[..n],
        &[FLAG, 0x06, 0x11, 0x00, 0x01, 0x00, 0xE2, 0xDA, FLAG]
    );
    let (frame, used) = decode(&out[..n]).unwrap();
    assert_eq!(used, n);
    assert_eq!(
        frame.kind,
        AshKind::Data {
            frm_num: 1,
            ack_num: 2,
            re_tx: false
        }
    );
    assert_eq!(frame.payload_bytes(), &[0x00, 0x01, 0x00]);
}

/// ACK-only / NAK / RST frames, byte-pinned (empty bodies).
#[test]
fn ash_ack_nak_rst_vectors_byte_pinned() {
    let mut out = [0u8; 16];
    // ACK ack=3: CTRL=0x98, CRC16-LE(`98`) = 0xE341.
    let n = encode_ack(3, &mut out).unwrap();
    assert_eq!(&out[..n], &[FLAG, 0x03, 0x98, 0x41, 0xE3, FLAG]);
    let (frame, _) = decode(&out[..n]).unwrap();
    assert_eq!(frame.kind, AshKind::Ack { ack_num: 3 });
    assert_eq!(frame.payload_bytes(), &[]);
    // NAK ack=5: CTRL=0xA9, CRC16-LE(`A9`) = 0xC533.
    let n = encode_nak(5, &mut out).unwrap();
    assert_eq!(&out[..n], &[FLAG, 0x03, 0xA9, 0x33, 0xC5, FLAG]);
    let (frame, _) = decode(&out[..n]).unwrap();
    assert_eq!(frame.kind, AshKind::Nak { ack_num: 5 });
    // RST: CTRL=0xC0, CRC16-LE(`C0`) = 0x38BC.
    let n = encode_rst(&mut out).unwrap();
    assert_eq!(&out[..n], &[FLAG, 0x03, 0xC0, 0xBC, 0x38, FLAG]);
    let (frame, _) = decode(&out[..n]).unwrap();
    assert_eq!(frame.kind, AshKind::Rst);
}

/// RSTACK / ERROR frames, byte-pinned (two version/status octets).
#[test]
fn ash_rstack_error_vectors_byte_pinned() {
    let mut out = [0u8; 16];
    // RSTACK version=2 status=1: CRC16-LE(`C1 02 01`) = 0xAB18.
    let n = encode_rstack(2, 1, &mut out).unwrap();
    assert_eq!(&out[..n], &[FLAG, 0x05, 0xC1, 0x02, 0x01, 0x18, 0xAB, FLAG]);
    let (frame, _) = decode(&out[..n]).unwrap();
    assert_eq!(
        frame.kind,
        AshKind::Rstack {
            version: 2,
            status: 1
        }
    );
    // ERROR version=2 code=0x51: CRC16-LE(`C2 02 51`) = 0xA8BD.
    let n = encode_error(2, 0x51, &mut out).unwrap();
    assert_eq!(&out[..n], &[FLAG, 0x05, 0xC2, 0x02, 0x51, 0xBD, 0xA8, FLAG]);
    let (frame, _) = decode(&out[..n]).unwrap();
    assert_eq!(
        frame.kind,
        AshKind::Error {
            version: 2,
            code: 0x51
        }
    );
}

/// Retransmit flag plus FLAG-stuffing inside a DATA payload:
/// CTRL=0x47 (frm=7, ack=0, reTx), payload `7E` stuffed as `7D 5E`,
/// CRC16-LE(`47 7E`) = 0x160D.
#[test]
fn ash_retx_flag_and_stuffing_pinned() {
    let mut out = [0u8; 32];
    let n = encode_data(7, 0, true, &[FLAG], &mut out).unwrap();
    assert_eq!(&out[..n], &[FLAG, 0x04, 0x47, 0x7D, 0x5E, 0x0D, 0x16, FLAG]);
    let (frame, used) = decode(&out[..n]).unwrap();
    assert_eq!(used, n);
    assert_eq!(
        frame.kind,
        AshKind::Data {
            frm_num: 7,
            ack_num: 0,
            re_tx: true
        }
    );
    assert_eq!(frame.payload_bytes(), &[FLAG]);
}

/// Control-octet shapes decode to their kinds; unknown shapes
/// refuse with `BadControl` (never misread as another kind).
#[test]
fn ash_control_octet_shapes() {
    assert_eq!(NUM_MASK, 0x07);
    // DATA spans the whole bit7=0 half, reTx in bit 6.
    assert_eq!(
        decode_control(0x00),
        Ok(AshKind::Data {
            frm_num: 0,
            ack_num: 0,
            re_tx: false
        })
    );
    assert_eq!(
        decode_control(0x7F),
        Ok(AshKind::Data {
            frm_num: 7,
            ack_num: 7,
            re_tx: true
        })
    );
    assert_eq!(ACK_BASE, 0x80);
    assert_eq!(NAK_BASE, 0x81);
    assert_eq!(RST_CTRL, 0xC0);
    assert_eq!(RSTACK_CTRL, 0xC1);
    assert_eq!(ERROR_CTRL, 0xC2);
    // 0xC3 sets the control-half bits but names no frame: refused.
    assert_eq!(decode_control(0xC3), Err(AshError::BadControl));
    // ACK-pattern low bits 0b010..0b111 name no frame either.
    assert_eq!(decode_control(0x8A), Err(AshError::BadControl));
    assert_eq!(decode_control(0xBF), Err(AshError::BadControl));
}

/// Link numbers are 3-bit and wrap; out-of-range numbers never
/// encode (a header with `frm_num = 8` would alias `frm_num = 0`).
#[test]
fn ash_numbers_wrap_and_reject_overflow() {
    let mut n = 0u8;
    for expect in [1u8, 2, 3, 4, 5, 6, 7, 0, 1] {
        n = next_num(n);
        assert_eq!(n, expect);
    }
    assert_eq!(pack_data_header(7, 7, true), Ok(0x7F));
    assert_eq!(pack_data_header(8, 0, false), Err(AshError::BadNumber));
    assert_eq!(pack_data_header(0, 8, false), Err(AshError::BadNumber));
    let mut out = [0u8; 16];
    assert_eq!(encode_ack(8, &mut out), Err(AshError::BadNumber));
    assert_eq!(encode_nak(8, &mut out), Err(AshError::BadNumber));
    assert_eq!(out, [0u8; 16]);
}

/// Worst-case stuffing: a maximum payload of FLAG octets (with a
/// stuffable control octet) encodes without panicking, round-trips
/// exactly, and a short output refuses without a prefix.
#[test]
fn ash_max_stuffed_payload_round_trips() {
    use rounddance_compat::ash::MAX_ENCODED_ASH;
    let payload = [FLAG; MAX_ASH_DATA];
    let mut out = [0u8; MAX_ENCODED_ASH];
    // frm=6, ack=7, reTx gives control 0x7E: itself stuffed.
    let n = encode_data(6, 7, true, &payload, &mut out).unwrap();
    assert!(n <= MAX_ENCODED_ASH);
    let (frame, used) = decode(&out[..n]).unwrap();
    assert_eq!(used, n);
    assert_eq!(
        frame.kind,
        AshKind::Data {
            frm_num: 6,
            ack_num: 7,
            re_tx: true
        }
    );
    assert_eq!(frame.payload_bytes(), &payload);
    let mut short = [0u8; 10];
    let before = short;
    assert_eq!(
        encode_data(6, 7, true, &payload, &mut short),
        Err(AshError::BufferTooSmall)
    );
    assert_eq!(short, before);
}

/// A flipped body octet must fail the CRC, never decode.
#[test]
fn ash_crc_mismatch_refused() {
    let mut out = [0u8; 32];
    let n = encode_data(0, 0, false, &[0xAA], &mut out).unwrap();
    out[n - 3] ^= 0x01;
    assert_eq!(decode(&out[..n]), Err(AshError::BadCrc));
}

/// Missing closing FLAG is truncation, not a frame.
#[test]
fn ash_truncated_refused() {
    let mut out = [0u8; 32];
    let n = encode_data(0, 0, false, &[0xAA], &mut out).unwrap();
    assert_eq!(decode(&out[..n - 1]), Err(AshError::Truncated));
    assert_eq!(decode(&[]), Err(AshError::Truncated));
}

/// Oversize payloads are refused before touching the output; short
/// outputs refuse without a prefix.
#[test]
fn ash_oversize_and_short_output_refused() {
    let big = [0xAAu8; MAX_ASH_DATA + 1];
    let mut out = [0u8; 300];
    assert_eq!(
        encode_data(0, 0, false, &big, &mut out),
        Err(AshError::TooLong)
    );
    assert_eq!(out, [0u8; 300]);
    let mut tiny = [0u8; 5];
    assert_eq!(
        encode_data(0, 0, false, &[0x01, 0x02], &mut tiny),
        Err(AshError::BufferTooSmall)
    );
}

/// Control kinds police their body lengths: ACK/NAK/RST carry no
/// body, RSTACK/ERROR carry exactly two octets.
#[test]
fn ash_control_body_lengths_policed() {
    // Hand-built ACK (ack=0) with a one-octet trailer: the CRC is
    // valid but the kind forbids a body. CRC16-LE(`80 00`) = 0x0697.
    let frame = [FLAG, 0x04, 0x80, 0x00, 0x97, 0x06, FLAG];
    assert_eq!(decode(&frame).map(|_| ()), Err(AshError::BadLength));
    // Hand-built RSTACK with a one-octet body is short of the pair.
    // CRC16-LE(`C1 02`) = 0x1828.
    let frame = [FLAG, 0x04, 0xC1, 0x02, 0x28, 0x18, FLAG];
    assert_eq!(decode(&frame), Err(AshError::BadLength));
}

/// Layering leg: one EZSP command frame body rides as an ASH DATA
/// payload and survives both codecs, FLAG-stuffing included.
#[test]
fn ash_carries_ezsp_frame_body() {
    use rounddance_compat::ember::{crc16, decode as ezsp_decode, encode as ezsp_encode};
    use rounddance_compat::ember::{CMD_DATA_SEND, CTRL_SEQ_MASK};
    // EZSP command with a FLAG octet in its payload (exercises the
    // ASH-level stuffing of the reassembled unstuffed body).
    let mut ezsp_out = [0u8; 64];
    let ezsp_n = ezsp_encode(3, CMD_DATA_SEND, &[0xAA, FLAG], &mut ezsp_out).unwrap();
    let (ezsp, _) = ezsp_decode(&ezsp_out[..ezsp_n]).unwrap();
    assert_eq!(ezsp.seq(), 3 & CTRL_SEQ_MASK);
    // Reassemble the unstuffed EZSP body through public API only.
    let mut ezsp_body = [0u8; 1 + 2 + 128 + 2];
    ezsp_body[0] = ezsp.control;
    ezsp_body[1..3].copy_from_slice(&ezsp.frame_id.to_le_bytes());
    ezsp_body[3..3 + ezsp.payload_len as usize].copy_from_slice(ezsp.payload_bytes());
    let body_len = 3 + ezsp.payload_len as usize;
    let crc = crc16(&ezsp_body[..body_len]).to_le_bytes();
    ezsp_body[body_len..body_len + 2].copy_from_slice(&crc);
    let wire_body = &ezsp_body[..body_len + 2];
    assert!(wire_body.contains(&FLAG));

    let mut ash_out = [0u8; 300];
    let n = encode_data(2, 5, false, wire_body, &mut ash_out).unwrap();
    let (frame, used) = decode(&ash_out[..n]).unwrap();
    assert_eq!(used, n);
    assert_eq!(
        frame.kind,
        AshKind::Data {
            frm_num: 2,
            ack_num: 5,
            re_tx: false
        }
    );
    assert_eq!(frame.payload_bytes(), wire_body);
}

/// Feed every byte, collecting the non-silent outcomes.
fn pump_ash(dec: &mut AshDecoder, bytes: &[u8]) -> Vec<AshOutcome> {
    let mut out = Vec::new();
    for b in bytes {
        if let Some(o) = dec.push_byte(*b) {
            out.push(o);
        }
    }
    out
}

/// Streaming byte pin: FLAG | LEN=6 | CTRL=0x11 (frm=1, ack=2) |
/// `00 01 00` | CRC16-LE(`11 00 01 00` = 0xDAE2) | FLAG. The CRC is
/// hand-computed through the independent CRC-16/CCITT oracle
/// (`crc16(b"123456789") == 0x29B1` pins the oracle itself), and the
/// same bytes decode identically through one-shot `decode`.
#[test]
fn ash_decoder_byte_pinned_vector() {
    use rounddance_compat::ember::crc16;
    assert_eq!(crc16(b"123456789"), 0x29B1);
    assert_eq!(crc16(&[0x11, 0x00, 0x01, 0x00]), 0xDAE2);
    let wire = [FLAG, 0x06, 0x11, 0x00, 0x01, 0x00, 0xE2, 0xDA, FLAG];
    let (want, used) = decode(&wire).unwrap();
    assert_eq!(used, wire.len());
    let mut dec = AshDecoder::new();
    for b in &wire[..wire.len() - 1] {
        assert_eq!(dec.push_byte(*b), None);
    }
    let Some(AshOutcome::Frame(got)) = dec.push_byte(wire[wire.len() - 1]) else {
        panic!("pinned wire must decode");
    };
    assert_eq!(got, want);
    assert_eq!(
        got.kind,
        AshKind::Data {
            frm_num: 1,
            ack_num: 2,
            re_tx: false
        }
    );
    assert_eq!(got.payload_bytes(), &[0x00, 0x01, 0x00]);
    assert_eq!((dec.dropped(), dec.consecutive_bad()), (0, 0));
}

/// Split feeds reassemble to the same frame the one-shot `decode`
/// returns, however the bytes are chunked — with FLAG/ESC octets in
/// the payload so the stuffing path is exercised too.
#[test]
fn ash_decoder_split_feed_reassembles() {
    let mut raw = [0u8; MAX_ENCODED_ASH];
    let payload = [FLAG, 0x7D, 0x08, 0x00];
    let n = encode_data(3, 4, false, &payload, &mut raw).unwrap();
    let (want, used) = decode(&raw[..n]).unwrap();
    assert_eq!(used, n);
    for split in [1usize, 2, 5, 7, 9] {
        let mut dec = AshDecoder::new();
        let mut frames = Vec::new();
        for chunk in raw[..n].chunks(split) {
            for o in pump_ash(&mut dec, chunk) {
                frames.push(o);
            }
        }
        assert_eq!(frames.len(), 1, "split {split}");
        let AshOutcome::Frame(got) = frames[0] else {
            panic!("split {split} must yield a frame");
        };
        assert_eq!(got, want, "split {split}");
    }
}

/// Line noise ahead of FLAG is skipped silently; a LEN that disagrees
/// with the delimited body drops one run and re-arms, so the next
/// good frame still decodes and the desync meter resets.
#[test]
fn ash_decoder_resyncs_over_noise_and_bad_len() {
    let mut raw = [0u8; 32];
    let n = encode_data(1, 2, false, &[0xAA], &mut raw).unwrap();
    let mut bad = [0u8; 32];
    bad[..n].copy_from_slice(&raw[..n]);
    bad[1] = bad[1].wrapping_add(1);
    assert_eq!(decode(&bad[..n]), Err(AshError::BadLength));
    let mut dec = AshDecoder::new();
    // Noise with no FLAG: silent.
    assert!(pump_ash(&mut dec, &[0x00, 0x55, 0x13]).is_empty());
    // LEN mismatch: one BadLength drop, then re-armed.
    assert_eq!(
        pump_ash(&mut dec, &bad[..n]),
        [AshOutcome::Dropped(AshDropReason::BadLength)]
    );
    assert_eq!((dec.dropped(), dec.consecutive_bad()), (1, 1));
    // The good frame still decodes; the meter resets.
    let outcomes = pump_ash(&mut dec, &raw[..n]);
    assert_eq!(outcomes.len(), 1);
    let AshOutcome::Frame(frame) = outcomes[0] else {
        panic!("good frame must decode after a drop");
    };
    assert_eq!(frame.payload_bytes(), &[0xAA]);
    assert_eq!(dec.consecutive_bad(), 0);
    assert_eq!(dec.dropped(), 1);
}

/// A flipped body octet fails the CRC: one `BadCrc` drop, counters
/// tick, and the stream re-arms for the next frame.
#[test]
fn ash_decoder_bad_crc_drops_and_rearms() {
    let mut raw = [0u8; 32];
    let n = encode_data(1, 2, false, &[0xAA, 0x10], &mut raw).unwrap();
    let mut bad = [0u8; 32];
    bad[..n].copy_from_slice(&raw[..n]);
    bad[n - 3] ^= 0x01;
    assert_eq!(decode(&bad[..n]), Err(AshError::BadCrc));
    let mut dec = AshDecoder::new();
    assert_eq!(
        pump_ash(&mut dec, &bad[..n]),
        [AshOutcome::Dropped(AshDropReason::BadCrc)]
    );
    assert_eq!((dec.dropped(), dec.consecutive_bad()), (1, 1));
    let outcomes = pump_ash(&mut dec, &raw[..n]);
    assert!(matches!(outcomes[..], [AshOutcome::Frame(_)]));
    assert_eq!((dec.dropped(), dec.consecutive_bad()), (1, 0));
}

/// A dangling ESC just before the closing FLAG is a `BadEscape` drop
/// (same verdict the one-shot `decode` returns on the same bytes),
/// and the stream re-arms for the next frame.
#[test]
fn ash_decoder_dangling_escape_drops() {
    // Hand-built: ACK ack=3 (`0x98`) plus one body octet, closed by
    // an ESC with no following octet before the FLAG.
    let wire = [FLAG, 0x03, 0x98, 0x41, 0x7D, FLAG];
    assert_eq!(decode(&wire), Err(AshError::BadEscape));
    let mut dec = AshDecoder::new();
    assert_eq!(
        pump_ash(&mut dec, &wire),
        [AshOutcome::Dropped(AshDropReason::BadEscape)]
    );
    assert_eq!((dec.dropped(), dec.consecutive_bad()), (1, 1));
    // Re-armed: a good frame decodes next.
    let mut raw = [0u8; 32];
    let n = encode_ack(2, &mut raw).unwrap();
    let outcomes = pump_ash(&mut dec, &raw[..n]);
    assert!(matches!(outcomes[..], [AshOutcome::Frame(_)]));
    assert_eq!(dec.consecutive_bad(), 0);
}

/// A run with no closing FLAG inside the bounded buffer drops exactly
/// once: the overflow byte ends the run, the tail through the run's
/// FLAG is swallowed, and the next good frame decodes.
#[test]
fn ash_decoder_overflow_drops_once_and_rearms() {
    let mut raw = [0u8; 32];
    let n = encode_data(3, 1, false, &[0x01], &mut raw).unwrap();
    // FLAG-led run of non-FLAG octets longer than the bounded
    // buffer, closed by its own FLAG: the overflow trips long before
    // the closer arrives.
    let mut overlong = [0x55u8; MAX_ENCODED_ASH + 2];
    overlong[0] = FLAG;
    overlong[MAX_ENCODED_ASH + 1] = FLAG;
    let mut dec = AshDecoder::new();
    let outcomes = pump_ash(&mut dec, &overlong);
    assert_eq!(outcomes, [AshOutcome::Dropped(AshDropReason::BadLength)]);
    assert_eq!((dec.dropped(), dec.consecutive_bad()), (1, 1));
    let outcomes = pump_ash(&mut dec, &raw[..n]);
    assert!(matches!(outcomes[..], [AshOutcome::Frame(_)]));
    assert_eq!((dec.dropped(), dec.consecutive_bad()), (1, 0));
}

/// Back-to-back frames on one feed decode in order with no drops.
#[test]
fn ash_decoder_back_to_back_frames() {
    let mut first = [0u8; 32];
    let n1 = encode_data(0, 0, false, &[0x01], &mut first).unwrap();
    let mut second = [0u8; 32];
    let n2 = encode_data(1, 0, false, &[0x02, 0x03], &mut second).unwrap();
    let mut wire = [0u8; 64];
    wire[..n1].copy_from_slice(&first[..n1]);
    wire[n1..n1 + n2].copy_from_slice(&second[..n2]);
    let mut dec = AshDecoder::new();
    let outcomes = pump_ash(&mut dec, &wire[..n1 + n2]);
    assert_eq!(outcomes.len(), 2);
    let [AshOutcome::Frame(a), AshOutcome::Frame(b)] = outcomes[..] else {
        panic!("back-to-back frames must both decode");
    };
    assert_eq!(
        (a.kind, b.kind),
        (
            AshKind::Data {
                frm_num: 0,
                ack_num: 0,
                re_tx: false
            },
            AshKind::Data {
                frm_num: 1,
                ack_num: 0,
                re_tx: false
            },
        )
    );
    assert_eq!(a.payload_bytes(), &[0x01]);
    assert_eq!(b.payload_bytes(), &[0x02, 0x03]);
    assert_eq!(dec.dropped(), 0);
}

/// A CRC-clean frame with a control octet matching no known shape
/// (`7E 03 C3 DF 08 7E`, CRC `C3` = 0x08DF via the oracle) is
/// well-delimited but unroutable: one `BadControl` drop — the same
/// verdict one-shot `decode` returns — and the stream re-arms.
#[test]
fn ash_decoder_bad_control_drops_and_rearms() {
    use rounddance_compat::ember::crc16;
    assert_eq!(crc16(b"123456789"), 0x29B1);
    assert_eq!(crc16(&[0xC3]), 0x08DF);
    let wire = [FLAG, 0x03, 0xC3, 0xDF, 0x08, FLAG];
    assert_eq!(decode(&wire), Err(AshError::BadControl));
    let mut dec = AshDecoder::new();
    assert_eq!(
        pump_ash(&mut dec, &wire),
        [AshOutcome::Dropped(AshDropReason::BadControl)]
    );
    assert_eq!((dec.dropped(), dec.consecutive_bad()), (1, 1));
    // Re-armed: a good frame decodes next and resets the meter.
    let mut raw = [0u8; 32];
    let n = encode_ack(2, &mut raw).unwrap();
    let outcomes = pump_ash(&mut dec, &raw[..n]);
    let [AshOutcome::Frame(frame)] = outcomes[..] else {
        panic!("good frame must decode after a drop");
    };
    assert_eq!(frame.kind, AshKind::Ack { ack_num: 2 });
    assert_eq!((dec.dropped(), dec.consecutive_bad()), (1, 0));
}

/// Sender window: fresh numbers allocate in order, the window fills
/// at 7 outstanding (one number stays free of the 3-bit space), the
/// 8th allocation refuses (`None` backpressure), and a cumulative
/// ACK retires the covered run and reopens the window.
#[test]
fn ash_tx_window_allocate_ack_backpressure() {
    assert_eq!(ASH_TX_WINDOW, 7);
    let mut tx = AshTxWindow::new();
    assert!(tx.can_send());
    assert!(!tx.window_full());
    assert_eq!(tx.outstanding(), 0);
    for expect in 0..ASH_TX_WINDOW {
        assert_eq!(tx.try_allocate(), Some(expect));
    }
    assert!(tx.window_full());
    assert!(!tx.can_send());
    assert_eq!(tx.try_allocate(), None);
    assert_eq!(tx.outstanding(), ASH_TX_WINDOW);
    // Cumulative ACK through frame 2 retires frames 0, 1, 2.
    assert_eq!(tx.on_ack(2), Ok(3));
    assert_eq!(tx.outstanding(), 4);
    assert_eq!(tx.base(), 3);
    assert!(tx.can_send());
    assert!(!tx.window_full());
    // Freed slots hand out the next fresh numbers (wrap discipline).
    assert_eq!(tx.try_allocate(), Some(7));
    assert_eq!(tx.try_allocate(), Some(0));
    assert_eq!(tx.try_allocate(), Some(1));
    assert!(tx.window_full());
    // Duplicate ACK (names only retired frames) retires nothing.
    assert_eq!(tx.on_ack(2), Ok(0));
    assert_eq!(tx.outstanding(), 7);
    // Out-of-range ACK numbers never encode and never retire.
    assert_eq!(tx.on_ack(8), Err(AshError::BadNumber));
    assert_eq!(tx.outstanding(), 7);
}

/// NAK-triggered retransmit leg, end to end over the codec: fill the
/// window, ACK part of it, NAK the rest, then re-encode the
/// retransmit run with the retransmit flag set and decode it back.
#[test]
fn ash_nak_retransmit_run_round_trips_with_retx_flag() {
    let mut tx = AshTxWindow::new();
    let mut rx = AshRxState::new();
    // Send frames 0..=3 through the real encoder, receiver accepts
    // the first two in order (ack now 1, expects 2).
    let mut wire = [0u8; 64];
    for frm in 0..4u8 {
        assert_eq!(tx.try_allocate(), Some(frm));
        let ack = rx.ack_num();
        let n = encode_data(frm, ack, false, &[0x50 + frm], &mut wire).unwrap();
        let (frame, _) = decode(&wire[..n]).unwrap();
        let AshKind::Data {
            frm_num,
            ack_num: _,
            re_tx,
        } = frame.kind
        else {
            panic!("DATA frame expected");
        };
        assert!(!re_tx);
        if frm < 2 {
            assert_eq!(rx.on_data(frm_num), Ok(RxOutcome::Accept));
        }
    }
    assert_eq!(rx.ack_num(), 1);
    // Receiver sees frame 3 while still expecting 2: a gap, so it
    // NAKs with ack 1. The NAK frame itself round-trips the codec.
    assert_eq!(rx.on_data(3), Ok(RxOutcome::Gap));
    let mut nak_wire = [0u8; 16];
    let n = encode_nak(rx.ack_num(), &mut nak_wire).unwrap();
    let (nak, _) = decode(&nak_wire[..n]).unwrap();
    assert_eq!(nak.kind, AshKind::Nak { ack_num: 1 });
    // Sender files the NAK: frame 1 stays cumulatively acked (frames
    // 0, 1 retired), retransmit run starts at 2 over frames 2, 3.
    let decision = tx.on_nak(1).unwrap();
    assert!(decision.needed());
    assert_eq!(decision.start_frm, 2);
    assert_eq!(decision.count, 2);
    assert_eq!(tx.outstanding(), 2);
    // Re-encode the run with the retransmit flag: both decode back
    // with `re_tx` set and the receiver accepts frame 2 in order.
    for k in 0..decision.count {
        let frm = (decision.start_frm + k) & NUM_MASK;
        let n = encode_data(frm, 0, true, &[0x50 + frm], &mut wire).unwrap();
        let (frame, _) = decode(&wire[..n]).unwrap();
        assert_eq!(
            frame.kind,
            AshKind::Data {
                frm_num: frm,
                ack_num: 0,
                re_tx: true
            }
        );
        if k == 0 {
            assert_eq!(rx.on_data(frm), Ok(RxOutcome::Accept));
        }
    }
    assert_eq!(rx.ack_num(), 2);
    // NAK with nothing outstanding reports an empty run (no work).
    let mut idle = AshTxWindow::new();
    let decision = idle.on_nak(0).unwrap();
    assert!(!decision.needed());
    assert_eq!(decision.count, 0);
    assert_eq!(idle.on_nak(8), Err(AshError::BadNumber));
}

/// Receiver legs: in-order accept advances, a repeat of the newest
/// accepted frame re-acknowledges without advancing, a gap holds the
/// ack number for the NAK, and out-of-range numbers refuse.
#[test]
fn ash_rx_accept_duplicate_gap_legs() {
    let mut rx = AshRxState::new();
    assert_eq!(rx.expected(), 0);
    assert_eq!(rx.ack_num(), 0);
    assert_eq!(rx.on_data(0), Ok(RxOutcome::Accept));
    assert_eq!(rx.expected(), 1);
    assert_eq!(rx.ack_num(), 0);
    // Repeat of frame 0 (retransmission before frame 1 arrives):
    // duplicate, cursors hold.
    assert_eq!(rx.on_data(0), Ok(RxOutcome::Duplicate));
    assert_eq!(rx.expected(), 1);
    assert_eq!(rx.on_data(2), Ok(RxOutcome::Gap));
    assert_eq!(rx.ack_num(), 0);
    assert_eq!(rx.on_data(1), Ok(RxOutcome::Accept));
    assert_eq!(rx.ack_num(), 1);
    assert_eq!(rx.expected(), 2);
    // Wrap: accept through 7 then 0 in order.
    for frm in 2..8u8 {
        assert_eq!(rx.on_data(frm), Ok(RxOutcome::Accept));
    }
    assert_eq!(rx.ack_num(), 7);
    assert_eq!(rx.on_data(0), Ok(RxOutcome::Accept));
    assert_eq!(rx.ack_num(), 0);
    assert_eq!(rx.on_data(8), Err(AshError::BadNumber));
    rx.reset();
    assert_eq!(rx.expected(), 0);
    assert_eq!(rx.ack_num(), 0);
}

/// ACK-only frames drive the sender window through the real codec:
/// the ack number decoded off the wire retires the matching run.
#[test]
fn ash_ack_frame_drives_tx_window_off_wire() {
    let mut tx = AshTxWindow::new();
    for frm in 0..3u8 {
        assert_eq!(tx.try_allocate(), Some(frm));
    }
    let mut wire = [0u8; 16];
    let n = encode_ack(1, &mut wire).unwrap();
    let (frame, _) = decode(&wire[..n]).unwrap();
    let AshKind::Ack { ack_num } = frame.kind else {
        panic!("ACK frame expected");
    };
    assert_eq!(tx.on_ack(ack_num), Ok(2));
    assert_eq!(tx.outstanding(), 1);
    assert_eq!(tx.retransmit_pending().start_frm, 2);
}

/// Sender reset: the link-reset primitive clears window state on the
/// sender side (mirrors [`AshRxState::reset`] on the receiver side),
/// so numbering restarts at zero with no frame owed.
#[test]
fn ash_tx_window_reset_clears_link_state() {
    let mut tx = AshTxWindow::new();
    for frm in 0..3u8 {
        assert_eq!(tx.try_allocate(), Some(frm));
    }
    assert_eq!(tx.on_ack(0), Ok(1));
    assert_eq!(tx.outstanding(), 2);
    tx.reset();
    assert_eq!(tx.outstanding(), 0);
    assert_eq!(tx.base(), 0);
    assert_eq!(tx.next_frm(), 0);
    assert!(tx.can_send());
    assert!(!tx.window_full());
    assert!(!tx.retransmit_pending().needed());
    assert_eq!(tx.try_allocate(), Some(0));
    // Reset on a fresh window is a safe no-op.
    let mut fresh = AshTxWindow::new();
    fresh.reset();
    assert_eq!(fresh.try_allocate(), Some(0));
}

/// Full-window wrap loopback through the streaming decoder: all
/// seven outstanding frames cross the real wire byte-by-byte, the
/// receiver accepts them in order, one cumulative ACK retires the
/// whole window, fresh numbers wrap past 7 to 0, and the
/// link-reset primitive restarts both sides. No timers, no
/// bring-up sequencing — direct delivery only.
#[test]
fn ash_full_window_wrap_loopback_through_decoder() {
    let mut tx = AshTxWindow::new();
    let mut rx = AshRxState::new();
    let mut dec = AshDecoder::new();
    // Fill the whole window: frames 0..=6, one-octet payloads.
    let mut wires = [[0u8; 32]; ASH_TX_WINDOW as usize];
    let mut lens = [0usize; ASH_TX_WINDOW as usize];
    for frm in 0..ASH_TX_WINDOW {
        assert_eq!(tx.try_allocate(), Some(frm));
        lens[frm as usize] = encode_data(frm, 0, false, &[0x40 + frm], &mut wires[frm as usize])
            .expect("window payload must encode");
    }
    assert!(tx.window_full());
    assert_eq!(tx.try_allocate(), None);
    // Stream every frame through the decoder; each outcome is
    // cross-checked against one-shot `decode` before the receiver
    // files the frame number.
    for frm in 0..ASH_TX_WINDOW {
        let wire = &wires[frm as usize][..lens[frm as usize]];
        let (want, used) = decode(wire).expect("window frame must decode");
        assert_eq!(used, wire.len());
        let outcomes = pump_ash(&mut dec, wire);
        assert_eq!(outcomes.len(), 1, "frame {frm} must yield one outcome");
        let AshOutcome::Frame(got) = outcomes[0] else {
            panic!("frame {frm} must decode through the stream");
        };
        assert_eq!(got, want);
        let AshKind::Data {
            frm_num,
            re_tx: false,
            ..
        } = got.kind
        else {
            panic!("frame {frm} must be fresh DATA");
        };
        assert_eq!(frm_num, frm);
        assert_eq!(rx.on_data(frm_num), Ok(RxOutcome::Accept));
        assert_eq!(got.payload_bytes(), &[0x40 + frm]);
    }
    assert_eq!(rx.ack_num(), 6);
    assert_eq!(rx.expected(), 7);
    // One cumulative ACK(6) off the real wire retires all seven.
    let mut ack_wire = [0u8; 16];
    let n = encode_ack(rx.ack_num(), &mut ack_wire).expect("ACK must encode");
    let (ack, _) = decode(&ack_wire[..n]).expect("ACK must decode");
    let AshKind::Ack { ack_num } = ack.kind else {
        panic!("ACK frame expected");
    };
    assert_eq!(tx.on_ack(ack_num), Ok(7));
    assert_eq!(tx.outstanding(), 0);
    assert!(!tx.retransmit_pending().needed());
    assert_eq!((dec.dropped(), dec.consecutive_bad()), (0, 0));
    // Wrap: fresh allocation continues past 7 back to 0.
    assert_eq!(tx.try_allocate(), Some(7));
    assert_eq!(tx.try_allocate(), Some(0));
    // Link-reset primitive restarts both sides at zero.
    tx.reset();
    rx.reset();
    assert_eq!(tx.outstanding(), 0);
    assert_eq!((tx.base(), tx.next_frm()), (0, 0));
    assert!(tx.can_send());
    assert_eq!(tx.try_allocate(), Some(0));
    assert_eq!((rx.expected(), rx.ack_num()), (0, 0));
}
