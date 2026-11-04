//! MAC beacon-request: build one the way a joining device solicits
//! beacons, then parse it back. Covers the MAC command leg every
//! join starts with.
//!
//! Run: `cargo run -p rounddance --example mac_beacon_req`

use rounddance::hal_esp::mac_cmd::{build_beacon_req, parse_beacon_req};

fn main() {
    let mut buf = [0u8; 8];
    let n = build_beacon_req(0x01, &mut buf).expect("fits");
    println!("BEACON-REQ bytes: {:02x?}", &buf[..n]);

    let req = parse_beacon_req(&buf[..n]).expect("parses");
    assert_eq!(req.seq, 0x01);
    println!("PARSED seq={:#04x}", req.seq);

    assert!(parse_beacon_req(&buf[..n - 1]).is_none());
    println!("TRUNCATED refused, as it should be");
}
