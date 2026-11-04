//! Seal-then-open through the facade: builds the same CCM\* envelope
//! the stack radiates (13-byte nonce over EUI + frame counter, header
//! AAD, 4-byte integrity tag), opens it under the right key, then
//! shows the integrity check refusing the wrong key.
//!
//! Run: `cargo run -p rounddance --example sealed_frame`

use rounddance::security::{ccm_star_open_into, ccm_star_seal_into, CCM_TAG_LEN};

const NETKEY: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const SRC_EUI: [u8; 8] = [0xa4, 0x97, 0x85, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
const AUXCTR: u32 = 0x0000_2000;

fn nonce() -> [u8; 13] {
    let mut n = [0u8; 13];
    n[..8].copy_from_slice(&SRC_EUI);
    n[8..12].copy_from_slice(&AUXCTR.to_le_bytes());
    n[12] = 0x2d;
    n
}

fn main() {
    let aad = [0x08, 0x02, 0x01, 0x00, 0x00, 0x00, 0x1e];
    let pt = [0x01, 0x01, 0x06, 0x00, 0x08, 0x02, 0x00, 0x02];
    let mut sealed = [0u8; 12];
    let n = ccm_star_seal_into(&NETKEY, &nonce(), &aad, &pt, &mut sealed).expect("seal fits");
    assert_eq!(n, pt.len() + CCM_TAG_LEN);
    println!("SEALED={}", hex_of(&sealed[..n]));

    let (ct, tag) = sealed[..n].split_at(pt.len());
    let mut tag4 = [0u8; CCM_TAG_LEN];
    tag4.copy_from_slice(tag);
    let mut open = [0u8; 8];
    let m = ccm_star_open_into(&NETKEY, &nonce(), &aad, ct, &tag4, &mut open)
        .expect("opens under the right key");
    assert_eq!(&open[..m], &pt);
    println!("OPENED ok ({m} bytes match)");

    let mut wrong = NETKEY;
    wrong[0] ^= 0x01;
    match ccm_star_open_into(&wrong, &nonce(), &aad, ct, &tag4, &mut open) {
        Ok(_) => println!("WRONG-KEY opened (BUG)"),
        Err(e) => println!("WRONG-KEY refused ({e:?}), as it should"),
    }
}

fn hex_of(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0x0f) as usize] as char);
    }
    s
}
