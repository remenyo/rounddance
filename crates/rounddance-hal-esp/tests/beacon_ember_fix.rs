//! Beacon Ember-scan-consistency pin (w87-beaconfix).
//!
//! Rung-3 root cause (`~/hwscratch/w87-rung3/SUMMARY.md` §2): our beacons
//! mixed nonbeacon-network markers (BO=15) with beaconed-network fields
//! (SO=0, TxOffset=000000); Ember scan parsers drop them deterministically.
//! This test pins the corrected wire shape: superframe `0xCFFF`
//! (BO=15/SO=15 + permit) and beacon-payload TxOffset `FFFFFF`.

use rounddance_hal_esp::app;
use rounddance_hal_esp::mac_cmd::{self, BEACON_LEN, SUPERFRAME_ASSOC_PERMIT};

#[test]
fn beacon_is_ember_scan_consistent() {
    assert_eq!(
        SUPERFRAME_ASSOC_PERMIT, 0xCFFF,
        "superframe must be BO=15/SO=15 + permit (Ember-scan-consistency)"
    );
    let mut out = [0u8; 32];
    let n = mac_cmd::build_beacon(
        0x5a,
        app::APP_PAN,
        app::COORD_SHORT,
        SUPERFRAME_ASSOC_PERMIT,
        &app::EXT_PAN_ID,
        &mut out,
    )
    .unwrap();
    assert_eq!(n, BEACON_LEN);
    // Superframe LE on the wire: FF CF.
    assert_eq!(
        [out[7], out[8]],
        [0xff, 0xcf],
        "wire superframe must be 0xCFFF"
    );
    // Beacon-payload TxOffset (3 octets after ext-PAN) must be FFFFFF.
    assert_eq!(
        [out[22], out[23], out[24]],
        [0xff, 0xff, 0xff],
        "TxOffset must be FFFFFF (nonbeacon-network marker)"
    );
    // Update id stays 0x00.
    assert_eq!(out[25], 0x00);
    // Permit bit still set.
    assert_eq!(u16::from_le_bytes([out[7], out[8]]) & 0x8000, 0x8000);
}
