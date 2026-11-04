//! NWK data header: encode a minimal unicast header plus payload,
//! then decode it back. Covers the Fig. 3-4 header order (frame
//! control, addresses, radius, sequence) with presence-flag
//! consistency enforced on encode.
//!
//! Run: `cargo run -p rounddance --example nwk_frame`

use rounddance::nwk::{decode, FrameControl, NwkHeader};

fn main() {
    let header = NwkHeader::minimal(FrameControl::data(), 0x0001, 0x0000, 30, 7);
    let payload = [0xde, 0xad, 0xbe, 0xef];
    let mut buf = [0u8; 32];
    let n = header.encode_into(&payload, &mut buf).expect("fits");
    println!("NPDU ({n} B): {:02x?}", &buf[..n]);

    let back = decode(&buf[..n]).expect("decodes");
    assert_eq!(back.header.dst_addr, 0x0001);
    assert_eq!(back.header.src_addr, 0x0000);
    assert_eq!(back.header.seq, 7);
    assert_eq!(back.payload, &payload);
    println!(
        "ROUNDTRIP dst={:#06x} src={:#06x} seq={} payload={:02x?}",
        back.header.dst_addr, back.header.src_addr, back.header.seq, back.payload
    );
}
