//! ZDO node descriptor: build a router descriptor, set its logical
//! type, encode the 14 octets, and decode them back. Covers the
//! descriptor at the heart of Node_Desc_req/rsp discovery.
//!
//! Run: `cargo run -p rounddance --example zdo_descriptors`

use rounddance::zdo::desc::{LogicalType, NodeDescriptor, NODE_DESCRIPTOR_LEN};

fn main() {
    let mut desc = NodeDescriptor {
        flags0: 0x00,
        aps_flags: 0x00,
        freq_band: 0x08,
        mac_cap: 0x8c,
        mfr_code: 0x0000,
        max_buf: 82,
        max_in_transfer: 82,
        server_mask: 0x0000,
        max_out_transfer: 82,
        desc_cap: 0x00,
    };
    desc.set_logical_type(LogicalType::Router);
    assert_eq!(desc.logical_type().unwrap(), LogicalType::Router);

    let mut buf = [0u8; NODE_DESCRIPTOR_LEN];
    let n = desc.encode_into(&mut buf).expect("fits");
    assert_eq!(n, NODE_DESCRIPTOR_LEN);
    println!("DESC ({n} B): {:02x?}", &buf[..n]);

    let back = NodeDescriptor::decode(&buf).expect("decodes");
    assert_eq!(back.logical_type().unwrap(), LogicalType::Router);
    assert_eq!(back.mac_cap, 0x8c);
    println!(
        "ROUNDTRIP logical={:?} mac_cap={:#04x}",
        back.logical_type().unwrap(),
        back.mac_cap
    );
}
