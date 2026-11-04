//! Inspector: dissect a genuine over-the-air coordinator beacon
//! (permit-open C601, captured on the lab bench) into its decode
//! tree. Covers the offline half of the packet inspector.
//!
//! Run: `cargo run -p rounddance --example inspect_beacon`

use rounddance::inspect::chain::dissect;

const BEACON: [u8; 26] = [
    0x00, 0x80, 0x00, 0x01, 0xc6, 0x00, 0x00, 0xff, 0xcf, 0x00, 0x00, 0x00, 0x22, 0x8c, 0x43, 0x36,
    0x4a, 0x4f, 0x49, 0x4e, 0x30, 0x31, 0xff, 0xff, 0xff, 0x00,
];

fn main() {
    let tree = dissect(&BEACON).expect("beacon dissects");
    println!("DISSECTED ok");
    println!("{tree:?}");
}
