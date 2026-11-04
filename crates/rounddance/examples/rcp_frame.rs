//! RCP frame: encode a command frame and stream it byte-by-byte
//! through the resyncing decoder. Covers the S3↔H2 UART path framing
//! (SYNC/LEN/KIND/SEQ/CRC16) including noise-skip hardening.
//!
//! Run: `cargo run -p rounddance --example rcp_frame`

use rounddance::rcp::{frame::encode, Decoder, Outcome};

fn main() {
    let mut wire = [0u8; 16];
    let n = encode(0x09, 0x2a, &[0x01], &mut wire).expect("fits");
    println!("RCP ({n} B): {:02x?}", &wire[..n]);

    let mut decoder = Decoder::new();
    // Line noise before the frame must not wedge the parser.
    let mut seen = None;
    for &b in &[0xff, 0x00, 0x7f] {
        assert!(decoder.push_byte(b).is_none());
    }
    for &b in &wire[..n] {
        if let Some(out) = decoder.push_byte(b) {
            seen = Some(out);
        }
    }
    match seen.expect("a frame comes out") {
        Outcome::Frame(f) => {
            assert_eq!(f.kind, 0x09);
            assert_eq!(f.seq, 0x2a);
            assert_eq!(f.payload_bytes(), &[0x01]);
            println!(
                "DECODED kind={:#04x} seq={:#04x} payload={:02x?}",
                f.kind,
                f.seq,
                f.payload_bytes()
            );
        }
        Outcome::Dropped(reason) => panic!("unexpected drop: {reason:?}"),
    }
}
