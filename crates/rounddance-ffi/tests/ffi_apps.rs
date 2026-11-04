//! C-ABI join/toggle/poll surface over the live ESP apps.
//!
//! Exercises the exact firmware path head-side: coordinator builds a
//! sealed Toggle (fresh TSN per intent); the keyed joiner classifies
//! and answers it (lamp flips); the coordinator verifies the Default
//! Response. Mirrors `coord_radiate.rs` but through the C boundary.

use rounddance_ffi::apps_ffi as apps;

const KEY: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

fn keyed_joiner() -> *mut apps::RdJoiner {
    use rounddance_commission::{build_transport_key_frame, ha_transport_key, TransportKeyParams};
    use rounddance_hal_esp::app::TC_EUI_WIRE;
    const JW: [u8; 8] = [0xa4, 0x97, 0x85, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
    const TCW: [u8; 8] = [0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
    unsafe {
        let mut j: *mut apps::RdJoiner = std::ptr::null_mut();
        assert_eq!(apps::rd_joiner_create(&mut j), 0);
        assert!(!j.is_null());
        // Survey → elect (two sightings: the N-sighting gate) →
        // assoc-rsp adopts the short, exactly like the fw path.
        assert_eq!(apps::rd_joiner_begin_scan(j), 0);
        for _ in 0..2 {
            assert_eq!(
                apps::rd_joiner_ingest_beacon(j, 0xC601, 15, 200, -40, 1, 1, 1),
                0
            );
        }
        let mut pan = 0u16;
        assert_eq!(apps::rd_joiner_finish_scan(j, &mut pan), 0);
        assert_eq!(pan, 0xC601);
        let mut rsp = [0u8; 25];
        rsp[..5].copy_from_slice(&[0x63, 0xcc, 0x02, 0x01, 0xc6]);
        rsp[5..13].copy_from_slice(&JW);
        rsp[13..21].copy_from_slice(&TC_EUI_WIRE);
        rsp[21..25].copy_from_slice(&[0x02, 0x02, 0x00, 0x00]);
        let mut short = 0u16;
        assert_eq!(
            apps::rd_joiner_on_mac(j, rsp.as_ptr(), rsp.len(), 15, -40, 200, &mut short),
            0
        );
        assert_eq!(short, 0x0002);
        // Key the joiner through a synthetic transport (same shape
        // the NCP delivers on air; built with the commission crate
        // exactly like `coord_radiate.rs`).
        let tkey = ha_transport_key().unwrap();
        let tp = TransportKeyParams {
            dst_pan: 0xC601,
            dst_short: 0x0002,
            dst_eui: JW,
            src_eui: TCW,
            mac_seq: 0x5a,
            nwk_seq: 0x21,
            nwk_radius: 0x1e,
            aps_ctr: 0x51,
            auxctr: 0x0000_0FFF,
            seq_no: 0x00,
            netkey: KEY,
            transport_key: tkey,
        };
        let mut tf = [0u8; 128];
        let tn = build_transport_key_frame(&tp, &mut tf).unwrap();
        // Transport frames carry a 9-byte MAC header on the fw path.
        let mut kind = 0u32;
        let mut a = 0u32;
        let mut b = 0u32;
        assert_eq!(
            apps::rd_joiner_feed(j, tf.as_ptr().add(9), tn - 9, &mut kind, &mut a, &mut b),
            0
        );
        assert_eq!(kind, 2, "transport accepted");
        j
    }
}

#[test]
fn ffi_apps_toggle_roundtrip_flips_lamp_once() {
    unsafe {
        let mut c: *mut apps::RdCoord = std::ptr::null_mut();
        assert_eq!(apps::rd_coord_create(&mut c), 0);
        let j = keyed_joiner();
        // Lamp starts off.
        let mut lamp = 9u32;
        assert_eq!(apps::rd_joiner_lamp(j, &mut lamp), 0);
        assert_eq!(lamp, 0);
        // Coordinator builds one toggle (new TSN per intent).
        let mut tog = [0u8; 160];
        let mut tlen = 0usize;
        assert_eq!(
            apps::rd_coord_build_toggle(c, KEY.as_ptr(), tog.as_mut_ptr(), tog.len(), &mut tlen),
            0
        );
        assert!(tlen > 0);
        // Joiner classifies (Data) then answers; lamp flips.
        let (mut kind, mut a, mut b) = (0u32, 0u32, 0u32);
        // Toggle frames carry the 9-byte MAC header; classification
        // takes the MSDU (same split as the fw poll_indication path).
        assert_eq!(
            apps::rd_joiner_feed(j, tog.as_ptr().add(9), tlen - 9, &mut kind, &mut a, &mut b),
            0
        );
        assert_eq!((kind, a, b), (1, 0x0006, 0x0104));
        let mut ans = [0u8; 160];
        let mut alen = 0usize;
        assert_eq!(
            apps::rd_joiner_answer(
                j,
                tog.as_ptr().add(9),
                tlen - 9,
                ans.as_mut_ptr(),
                ans.len(),
                &mut alen
            ),
            0
        );
        assert!(alen > 0);
        assert_eq!(apps::rd_joiner_lamp(j, &mut lamp), 0);
        assert_eq!(lamp, 1);
        // Coordinator verifies the answer.
        let mut ok = 0u32;
        assert_eq!(
            apps::rd_coord_verify_defrsp(
                c,
                KEY.as_ptr(),
                0,
                ans.as_ptr().add(9),
                alen - 9,
                &mut ok
            ),
            0
        );
        assert_eq!(ok, 1);
        // Duplicate delivery classifies as replay (kind 0), never
        // re-answered: the firewall holds through the C boundary too.
        assert_eq!(
            apps::rd_joiner_feed(j, tog.as_ptr().add(9), tlen - 9, &mut kind, &mut a, &mut b),
            0
        );
        assert_eq!(kind, 0);
        apps::rd_joiner_destroy(j);
        apps::rd_coord_destroy(c);
    }
}
