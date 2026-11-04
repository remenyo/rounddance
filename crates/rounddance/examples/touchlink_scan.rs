//! Touchlink frame: build a scan-request-shaped inter-PAN frame and
//! decode it back. Covers the transaction-bound codec the Touchlink
//! commissioning exchange is built from.
//!
//! Run: `cargo run -p rounddance --example touchlink_scan`

use rounddance::commission::TouchlinkFrame;

const SCAN_REQUEST: u8 = 0x00;

fn main() {
    let frame = TouchlinkFrame::new(0x0102_0304, SCAN_REQUEST, &[0x01, 0x02]).expect("fits");
    let mut buf = [0u8; 16];
    let n = frame.encode_into(&mut buf).expect("fits");
    println!("TOUCHLINK ({n} B): {:02x?}", &buf[..n]);

    let back = TouchlinkFrame::decode(&buf[..n]).expect("decodes");
    assert_eq!(back.transaction, 0x0102_0304);
    assert_eq!(back.command, SCAN_REQUEST);
    println!(
        "ROUNDTRIP transaction={:#010x} command={:#04x}",
        back.transaction, back.command
    );
}
