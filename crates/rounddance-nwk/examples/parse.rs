//! Parse and rebuild one NWK data frame: decode the on-air octets,
//! print the header fields, re-encode, and assert byte-identity.
//!
//! Run: `cargo run -p rounddance-nwk --example parse`

use rounddance_nwk::{decode, FrameControl, NwkHeader};

fn main() {
    // Minimal unicast data NPDU as it appears on air (discovery suppressed).
    let wire: &[u8] = &[0x08, 0x00, 0x34, 0x12, 0x00, 0x00, 0x0a, 0x07, 0xde, 0xad];
    let back = decode(wire).expect("decodes");
    println!(
        "dst={:#06x} src={:#06x} radius={} seq={} payload={:02x?}",
        back.header.dst_addr,
        back.header.src_addr,
        back.header.radius,
        back.header.seq,
        back.payload
    );

    let rebuilt = NwkHeader::minimal(FrameControl::data(), 0x1234, 0x0000, 0x0a, 0x07);
    let mut buf = [0u8; 32];
    let n = rebuilt.encode_into(&[0xde, 0xad], &mut buf).expect("fits");
    assert_eq!(&buf[..n], wire);
    println!("ROUNDTRIP {n} bytes identical");
}
