//! Conformance: envelope round-trip over the reference transports.
//!
//! Requirement: every binding carries the v0 envelope losslessly —
//! encode on one end, frame, byte-stream, decode on the other —
//! including the empty and maximum-size payloads.

use rounddance_ifc::{
    envelope::{Envelope, Payload, FLAG_WANTS_CONFIRM},
    frame::{encode_frame, FrameDecoder, MAX_STUFFED},
    ids::*,
    transport::{MemLink, Side},
    IFC_MAX_PAYLOAD,
};

fn sample(seq: u16, payload: &[u8]) -> Envelope {
    Envelope {
        version: 0,
        if_id: IF_MAC_DRIVER,
        op: 0x10,
        seq,
        flags: FLAG_WANTS_CONFIRM,
        payload: Payload::from_slice(payload).unwrap(),
    }
}

/// Drive one envelope through encode -> frame -> decode -> compare.
fn wire_roundtrip(e: &Envelope) {
    let mut cbor = [0u8; 600];
    let n = e.encode(&mut cbor).unwrap();
    let mut wire = [0u8; MAX_STUFFED];
    let m = encode_frame(&cbor[..n], &mut wire).unwrap();
    let mut d = FrameDecoder::new();
    let mut got = None;
    for &b in &wire[..m] {
        if let Some(k) = d.push(b).unwrap() {
            got = Some(k);
        }
    }
    assert!(got.is_some(), "frame never completed");
    assert_eq!(Envelope::decode(d.body()).unwrap(), *e);
}

#[test]
fn envelope_round_trips_over_framed_bytes() {
    wire_roundtrip(&sample(1, b"hello"));
    wire_roundtrip(&sample(0xFFFF, &[]));
    let max = [0x5Au8; IFC_MAX_PAYLOAD];
    wire_roundtrip(&sample(42, &max));
}

#[test]
fn mem_transport_delivers_both_directions_in_order() {
    let mut link = MemLink::new();
    let a = sample(1, b"a-to-b");
    let b = sample(2, b"b-to-a");
    link.send(Side::A, a).unwrap();
    link.send(Side::B, b).unwrap();
    assert_eq!(link.recv(Side::B), Some(a));
    assert_eq!(link.recv(Side::A), Some(b));
    assert_eq!(link.recv(Side::A), None);
    assert_eq!(link.recv(Side::B), None);
}

#[test]
fn every_interface_id_survives_the_envelope() {
    for if_id in [
        IF_LINK,
        IF_MAC_DRIVER,
        IF_NWK,
        IF_APS,
        IF_ZDO,
        IF_SECURITY,
        IF_ZCL_ENGINE,
        IF_COMMISSION,
        IF_SIM_MEDIA,
        IF_MGMT_AGENT,
    ] {
        let e = Envelope {
            version: 0,
            if_id,
            op: 0xFF,
            seq: 7,
            flags: 0,
            payload: Payload::from_slice(&[if_id]).unwrap(),
        };
        wire_roundtrip(&e);
    }
}
