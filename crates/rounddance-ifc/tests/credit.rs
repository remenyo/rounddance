//! Conformance: credit exhaustion is explicit backpressure.
//!
//! Requirement: when the bounded send queue is full, `send` fails
//! with `QueueFull` (never blocks, never grows); draining one slot
//! admits exactly one more send. Mirrors the `MacDataSap`
//! `tx_queue_free` / `QueueFull` contract from `mac-sap-alignment.md`.

use rounddance_ifc::{
    credit::Credits,
    envelope::{Envelope, Payload},
    ids::IF_NWK,
    transport::{MemLink, Side, MEM_QUEUE},
    IfcError,
};

fn msg(seq: u16) -> Envelope {
    Envelope {
        version: 0,
        if_id: IF_NWK,
        op: 0x01,
        seq,
        flags: 0,
        payload: Payload::from_slice(&[0xAA]).unwrap(),
    }
}

#[test]
fn full_queue_rejects_and_single_drain_admits_single_send() {
    let mut link = MemLink::new();
    for i in 0..MEM_QUEUE {
        link.send(Side::A, msg(i as u16)).unwrap();
    }
    assert_eq!(link.depth(Side::B), MEM_QUEUE);
    assert_eq!(link.send(Side::A, msg(99)), Err(IfcError::QueueFull));

    // Drain exactly one: exactly one send fits again.
    assert_eq!(link.recv(Side::B), Some(msg(0)));
    link.send(Side::A, msg(100)).unwrap();
    assert_eq!(link.send(Side::A, msg(101)), Err(IfcError::QueueFull));
}

#[test]
fn credit_window_models_the_same_contract() {
    let mut c = Credits::<MEM_QUEUE>::new();
    assert_eq!(c.free(), MEM_QUEUE);
    for _ in 0..MEM_QUEUE {
        c.take().unwrap();
    }
    assert!(c.full());
    assert_eq!(c.take(), Err(IfcError::QueueFull));
    c.give();
    assert!(!c.full());
    c.take().unwrap();
}

#[test]
fn closed_link_rejects_sends_but_drains() {
    let mut link = MemLink::new();
    link.send(Side::A, msg(1)).unwrap();
    link.close();
    assert!(link.is_closed());
    assert_eq!(link.send(Side::A, msg(2)), Err(IfcError::Closed));
    // Pending traffic still drains after close (orderly shutdown).
    assert_eq!(link.recv(Side::B), Some(msg(1)));
}
