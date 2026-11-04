//! ZCL foundation frame: encode a global Read Attributes header and
//! decode it back. Covers the header/payload split every ZCL
//! exchange rides on.
//!
//! Run: `cargo run -p rounddance --example zcl_frame`

use rounddance::zcl::frame::{Direction, FrameControl, FrameType, Header};

fn main() {
    let header = Header {
        control: FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x0a,
        command_id: 0x00,
    };
    let mut buf = [0u8; 8];
    let n = header.encode_into(&mut buf).expect("fits");
    println!("ZCL header ({n} B): {:02x?}", &buf[..n]);

    let (back, rest) = Header::decode(&buf[..n]).expect("decodes");
    assert_eq!(back.tsn, 0x0a);
    assert_eq!(back.command_id, 0x00);
    assert!(rest.is_empty());
    println!(
        "ROUNDTRIP tsn={:#04x} cmd={:#04x}",
        back.tsn, back.command_id
    );
}
