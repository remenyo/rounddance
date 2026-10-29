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
    encode_rstack, next_num, pack_data_header, AshError, AshKind, ACK_BASE, ERROR_CTRL,
    MAX_ASH_DATA, NAK_BASE, NUM_MASK, RSTACK_CTRL, RST_CTRL,
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
