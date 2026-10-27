//! ESP adapter TX shape: the exact on-air bytes a rounddance NWK frame
//! produces through [`EspAdapter`](rounddance_hal_esp::EspAdapter).
//!
//! This runs on the host over [`MockDriver`](rounddance_hal_esp::MockDriver)
//! (same code path as `cargo test -p rounddance-hal-esp`). The on-target
//! firmware binary differs ONLY in the driver: construct
//! `EspAdapter::new(EspIdfDriver::new())` (with the `esp` cargo feature,
//! `riscv32imac-esp-espidf` target) and prepend the board sequence that
//! this example cannot do on host:
//!
//! ```ignore
//! // Board code (Xiao C6): onboard ceramic antenna select.
//! PinDriver::output(peripherals.pins.gpio3)?.set_low()?;
//! PinDriver::output(peripherals.pins.gpio14)?.set_low()?;
//! // NVS-first init + radio bring-up lives in `EspIdfDriver::init`
//! // (erase-on-version-mismatch, then `esp_ieee802154_enable`).
//! ```
//!
//! Everything below — NWK encode pinned to the frozen vector, MAC
//! framing with Len+2, TX-DONE confirm — is byte-identical on device
//! (proven OTA by the wave-15 spike: 37/37 sniffer hits).

use rounddance_hal_esp::{EspAdapter, MockDriver};
use rounddance_mac_sap::{MacAddress, MacDataSap, MacMgmtSap, TxOptions, TxRequest, TxStatus};
use rounddance_nwk::{DiscoverRoute, FrameControl, NwkHeader};

// Frozen NWK wire octets (repo vector, minimal data unicast) — the same
// bytes the spike radiated.
const NWK_FROZEN: [u8; 10] = [0x48, 0x00, 0x34, 0x12, 0x00, 0x00, 0x0A, 0x5C, 0xDE, 0xAD];

fn main() {
    // 1. NWK frame through the repo codec, pinned to the frozen vector.
    let control = FrameControl {
        discover_route: DiscoverRoute::Enable,
        ..FrameControl::data()
    };
    let header = NwkHeader::minimal(control, 0x1234, 0x0000, 10, 0x5C);
    let mut nwk = [0u8; 32];
    let n = header
        .encode_into(&[0xDE, 0xAD], &mut nwk)
        .expect("nwk encode");
    assert_eq!(n, NWK_FROZEN.len());
    assert_eq!(nwk[..n], NWK_FROZEN);

    // 2. Over the ESP adapter (mock driver on host). Provisioning
    // before init programs the driver in NVS-first order on device.
    let mut sap = EspAdapter::new(MockDriver::new());
    sap.set_pan_id(0x1234);
    sap.set_short_addr(0x0001);
    sap.init().expect("adapter init");
    let req = TxRequest {
        dst: MacAddress::short(0x1234, 0xFFFF),
        msdu: rounddance_mac_sap::FramePayload::from_slice(&nwk[..n]).unwrap(),
        options: TxOptions::NONE,
    };
    let handle = sap.data_request(req).expect("data request");

    // 3. Pump to the TX-DONE confirm and show the air bytes.
    let confirm = sap.poll_confirm().expect("tx confirm");
    assert_eq!(confirm.handle, handle);
    assert_eq!(confirm.status, TxStatus::Delivered);
    let air = sap.driver().tx_frame(0).expect("recorded air frame");
    print!("ESP-TX air({}B):", air.len());
    for b in air {
        print!(" {b:02x}");
    }
    println!("\nESP-TX confirm: handle={} status=Delivered", handle.0);
}
