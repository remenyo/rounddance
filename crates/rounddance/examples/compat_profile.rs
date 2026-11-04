//! Compat admission: a 3.0-profile peer passes the NWK version,
//! key-method, and security-level gates in one call — while a
//! PRO-profile value on a closed network is refused with a typed
//! error, never silently downgraded.
//!
//! Run: `cargo run -p rounddance --example compat_profile`

use rounddance::compat::negotiate::{admit_30_peer, KeyPolicy};
use rounddance::compat::profile::{CompatPeer, BASELINE_SEC_LEVEL};

fn main() {
    let peer = CompatPeer::profile_30();
    let (method, level) = admit_30_peer(
        &peer,
        false,
        &KeyPolicy::ALLOW_SYMMETRIC,
        BASELINE_SEC_LEVEL,
    )
    .expect("3.0 peer admitted");
    println!("ADMITTED method={method:?} level={level}");

    let pro = CompatPeer::profile_pro();
    match admit_30_peer(
        &pro,
        false,
        &KeyPolicy::STRICT_NEGOTIATION,
        BASELINE_SEC_LEVEL,
    ) {
        Ok(_) => println!("PRO-AS-30 admitted (unexpected here)"),
        Err(e) => println!("PRO-AS-30 refused ({e:?}), no silent downgrade"),
    }
}
