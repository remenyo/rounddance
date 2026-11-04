//! IFC envelope: wrap an operation payload in the versioned
//! interface envelope and unwrap it. Covers the boundary every
//! split (MAC driver, core, sim, management agent) speaks.
//!
//! Run: `cargo run -p rounddance --example ifc_envelope`

use rounddance::ifc::envelope::{Envelope, Payload};
use rounddance::ifc::{ids, IFC_VERSION};

fn main() {
    let env = Envelope {
        version: IFC_VERSION,
        if_id: ids::IF_NWK,
        op: 0x01,
        seq: 0x1234,
        flags: 0x01,
        payload: Payload::from_slice(&[0xaa, 0xbb]).expect("fits"),
    };
    let mut buf = [0u8; 64];
    let n = env.encode(&mut buf).expect("fits");
    println!("ENVELOPE ({n} B): {:02x?}", &buf[..n]);

    let back = Envelope::decode(&buf[..n]).expect("decodes");
    assert_eq!(back.if_id, ids::IF_NWK);
    assert_eq!(back.seq, 0x1234);
    println!(
        "ROUNDTRIP if={:#04x} op={:#04x} seq={:#06x}",
        back.if_id, back.op, back.seq
    );
}
