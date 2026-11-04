//! Guest adapter leg: `EspAdapter` over `WasmDriver<MockHost>`.
//!
//! The same MAC SAP behavior the C6 `MockDriver` legs prove, now
//! routed through the host-call seam: provisioning call-through,
//! TX confirms (Delivered / NoAck / ChannelBusy), RX indication
//! routing, energy scan, and NotReady gating before init.
use rounddance_hal_esp::driver::RxFrame;
use rounddance_hal_esp::{Driver, EspAdapter, MockDriver, TxEvent, TxFail};
use rounddance_hal_wasm::{MockHost, WasmDriver};
use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap, MacMgmtSap, TxOptions, TxRequest, TxStatus,
};

fn adapter() -> EspAdapter<WasmDriver<MockHost>> {
    EspAdapter::new(WasmDriver::new(MockHost::new()))
}

#[test]
fn guest_provisioning_reaches_the_host() {
    let mut a = adapter();
    // Before init the SAP refuses (adapter contract, unchanged).
    assert!(a
        .data_request(TxRequest {
            dst: MacAddress::short(0xC601, 0x0001),
            msdu: FramePayload::from_slice(&[0x01]).unwrap(),
            options: TxOptions::ACK,
        })
        .is_err());
    a.set_pan_id(0xC601);
    a.set_short_addr(0x0000);
    a.set_extended_addr(0x1122_3344_5566_7788);
    a.set_tx_power(10).unwrap();
    a.init().unwrap();
    a.set_channel(Channel::new(15).unwrap()).unwrap();
    let (pan, short) = a.driver().host().driver().last_addrs().unwrap();
    assert_eq!((pan, short), (0xC601, 0x0000));
    assert_eq!(a.driver().host().driver().last_channel(), Some(15));
    assert_eq!(a.driver().host().driver().last_power(), Some(10));
}

#[test]
fn guest_tx_confirm_maps_host_events() {
    let mut a = adapter();
    a.init().unwrap();
    let req = |b: &[u8]| TxRequest {
        dst: MacAddress::short(0xC601, 0x0001),
        msdu: FramePayload::from_slice(b).unwrap(),
        options: TxOptions::ACK,
    };
    a.data_request(req(&[0xAA])).unwrap();
    assert_eq!(a.poll_confirm().unwrap().status, TxStatus::Delivered);

    a.driver_mut()
        .host_mut()
        .script_events(&[TxEvent::Failed(TxFail::NoAck)]);
    a.data_request(req(&[0xBB])).unwrap();
    assert_eq!(a.poll_confirm().unwrap().status, TxStatus::NoAck);

    a.driver_mut()
        .host_mut()
        .script_events(&[TxEvent::Failed(TxFail::CcaBusy)]);
    a.data_request(req(&[0xCC])).unwrap();
    assert_eq!(a.poll_confirm().unwrap().status, TxStatus::ChannelBusy);
}

#[test]
fn guest_rx_indication_routes_to_pan_queue() {
    let mut a = adapter();
    a.set_pan_id(0xC601);
    a.set_short_addr(0x0001);
    a.init().unwrap();
    // One short-short intra-PAN air frame for our PAN.
    let mut air = [0u8; 17];
    air[0] = 15; // Len+2: 9-byte MHR + 4-byte MSDU + 2 FCS octets
    air[1] = 0x41;
    air[2] = 0x88;
    air[3] = 0x01;
    air[4..6].copy_from_slice(&0xC601u16.to_le_bytes());
    air[6..8].copy_from_slice(&0x0001u16.to_le_bytes());
    air[8..10].copy_from_slice(&0x0000u16.to_le_bytes());
    air[10..14].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let frame = RxFrame::from_slice(&air, 15, -40, 200).unwrap();
    a.driver_mut().host_mut().inject_rx(&[frame]);
    let ind = a.poll_indication().unwrap();
    assert_eq!(ind.msdu.as_slice(), &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn guest_energy_scan_uses_canned_host_value() {
    let mut a = adapter();
    a.init().unwrap();
    a.driver_mut().host_mut().set_ed(-70, false);
    let ch = Channel::new(15).unwrap();
    assert_eq!(a.energy_scan(ch).unwrap(), -70i8 as u8);
    a.driver_mut().host_mut().set_ed(-70, true);
    assert!(a.energy_scan(ch).is_err());
}

#[test]
fn guest_driver_passthrough_matches_mock() {
    // WasmDriver<MockHost> behaves exactly like MockDriver behind
    // the same seam (universality: no guest-specific semantics).
    let mut w = WasmDriver::new(MockHost::new());
    let mut m = MockDriver::new();
    assert!(!Driver::is_ready(&w));
    assert!(!Driver::is_ready(&m));
    w.init().unwrap();
    m.init().unwrap();
    assert!(Driver::is_ready(&w));
    w.set_channel(20).unwrap();
    m.set_channel(20).unwrap();
    assert_eq!(w.host().driver().last_channel(), m.last_channel());
}
