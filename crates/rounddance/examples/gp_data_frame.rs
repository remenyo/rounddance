//! Green Power data frame: encode a minimal unsecured SrcId frame
//! and decode it back. Covers the GPDF wire shape proxies forward.
//!
//! Run: `cargo run -p rounddance --example gp_data_frame`

use rounddance::gp::frame::{FrameType, GpdId, Gpdf, GpdfBody, NwkFrameControl};

fn main() {
    let frame = Gpdf {
        fc: NwkFrameControl {
            frame_type: FrameType::Data,
            auto_commissioning: false,
            ext_present: false,
        },
        ext: None,
        id: Some(GpdId::SrcId(0x1234_5678)),
        frame_counter: None,
        body: GpdfBody::LpedOpaque(&[0x20, 0x01]),
        mic: None,
    };
    let mut buf = [0u8; 16];
    let n = frame.encode_into(&mut buf).expect("fits");
    println!("GPDF ({n} B): {:02x?}", &buf[..n]);

    let (back, used) = Gpdf::decode(&buf[..n]).expect("decodes");
    assert_eq!(used, n);
    assert_eq!(back.id, Some(GpdId::SrcId(0x1234_5678)));
    println!("ROUNDTRIP id={:?} len={used}", back.id.unwrap());
}
