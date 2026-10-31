//! Adapter behavior over [`MockDriver`]: queueing, failure mapping,
//! cap enforcement, and the inter-PAN path — the same logic the
//! on-target driver inherits through the [`Driver`] seam.
//!
//! Requirement traceability: `RD-HAL-ESP-*` (repo-minted,
//! MINTED-pending-confirm); inter-PAN legs additionally exercise
//! `22-65816-030-121-03` + `122-02` (repo-minted,
//! MINTED-pending-confirm).

use rounddance_hal_esp::{
    adapter::{build_data_frame, build_inter_pan_frame},
    driver::{DriverError, RxFrame, TxEvent, TxFail},
    EspAdapter, EspError, MockDriver, MAX_TX_POWER_DBM,
};
use rounddance_mac_sap::{
    Channel, FramePayload, HasCapabilities, MacAddress, MacDataSap, MacError, MacInterPanSap,
    MacMgmtSap, TxOptions, TxRequest, TxStatus,
};

fn msdu(bytes: &[u8]) -> FramePayload {
    FramePayload::from_slice(bytes).unwrap()
}

fn adapter() -> EspAdapter<MockDriver> {
    let mut a = EspAdapter::new(MockDriver::new());
    a.set_pan_id(0x1234);
    a.set_short_addr(0x0001);
    a.init().unwrap();
    a
}

fn pan_request(dst: u16, payload: &[u8], options: TxOptions) -> TxRequest {
    TxRequest {
        dst: MacAddress::short(0x1234, dst),
        msdu: msdu(payload),
        options,
    }
}

#[test]
fn crate_name_is_non_empty() {
    assert!(!rounddance_hal_esp::name().is_empty());
}

#[test]
fn init_programs_filtering_defaults() {
    let mut a = EspAdapter::new(MockDriver::new());
    a.init().unwrap();
    let d = a.driver();
    // Driver default is promiscuous TRUE: the adapter must explicitly
    // enable filtering, start RX-when-idle, and program power/channel.
    assert_eq!(d.promiscuous(), Some(false));
    assert_eq!(d.start_rx_calls(), 1);
    assert_eq!(d.last_power(), Some(MAX_TX_POWER_DBM));
    assert_eq!(d.last_channel(), Some(15));
    assert_eq!(d.last_addrs(), Some((0xFFFF, 0xFFFF)));
}

#[test]
fn init_applies_pre_provisioned_addrs() {
    let mut a = EspAdapter::new(MockDriver::new());
    a.set_pan_id(0x1234);
    a.set_short_addr(0x0001);
    a.init().unwrap();
    assert_eq!(a.driver().last_addrs(), Some((0x1234, 0x0001)));
}

#[test]
fn init_failure_surfaces_and_stays_down() {
    let mut a = EspAdapter::new(MockDriver::new().with_failing_init());
    assert_eq!(a.init(), Err(EspError::Driver(DriverError::HwFault)));
    let req = pan_request(0xFFFF, &[0xDE, 0xAD], TxOptions::NONE);
    assert_eq!(a.data_request(req), Err(MacError::NotReady));
}

#[test]
fn request_before_init_is_not_ready() {
    let mut a = EspAdapter::new(MockDriver::new());
    let req = pan_request(0xFFFF, &[1], TxOptions::NONE);
    assert_eq!(a.data_request(req), Err(MacError::NotReady));
    assert_eq!(
        a.energy_scan(Channel::new(15).unwrap()),
        Err(MacError::NotReady)
    );
    assert_eq!(
        a.interpan_request(Channel::new(15).unwrap(), &msdu(&[1])),
        Err(MacError::NotReady)
    );
    assert_eq!(
        a.set_channel(Channel::new(15).unwrap()),
        Err(MacError::NotReady)
    );
}

#[test]
fn data_request_builds_len_plus_two_frame() {
    let mut a = adapter();
    let req = pan_request(0xFFFF, &[0xDE, 0xAD], TxOptions::NONE);
    let h = a.data_request(req).unwrap();
    // Len+2: MHR(9) + MSDU(2) + FCS(2) = 13; short-short intra-PAN,
    // seq 0, broadcast dst, our src.
    assert_eq!(
        a.driver().tx_frame(0),
        Some([13, 0x41, 0x88, 0x00, 0x34, 0x12, 0xFF, 0xFF, 0x01, 0x00, 0xDE, 0xAD].as_slice())
    );
    let c = a.poll_confirm().unwrap();
    assert_eq!(c.handle, h);
    assert_eq!(c.status, TxStatus::Delivered);
    assert_eq!(c.timestamp_us, None);
}

#[test]
fn ack_option_sets_ar_bit() {
    let mut a = adapter();
    let req = pan_request(0x0000, &[0x01], TxOptions::ACK);
    a.data_request(req).unwrap();
    assert_eq!(a.driver().tx_frame(0).unwrap()[1], 0x61);
}

#[test]
fn cca_fail_maps_channel_busy() {
    let mut a = adapter();
    a.driver_mut()
        .script_events(&[TxEvent::Failed(TxFail::CcaBusy)]);
    let h = a
        .data_request(pan_request(0xFFFF, &[1], TxOptions::ACK))
        .unwrap();
    let c = a.poll_confirm().unwrap();
    assert_eq!((c.handle, c.status), (h, TxStatus::ChannelBusy));
}

#[test]
fn noack_maps_noack() {
    let mut a = adapter();
    a.driver_mut()
        .script_events(&[TxEvent::Failed(TxFail::NoAck)]);
    let h = a
        .data_request(pan_request(0xFFFF, &[1], TxOptions::ACK))
        .unwrap();
    let c = a.poll_confirm().unwrap();
    assert_eq!((c.handle, c.status), (h, TxStatus::NoAck));
}

#[test]
fn other_driver_failures_report_not_delivered() {
    for fail in [
        TxFail::Aborted,
        TxFail::CoexReject,
        TxFail::Security,
        TxFail::InvalidAck,
    ] {
        let mut a = adapter();
        a.driver_mut().script_events(&[TxEvent::Failed(fail)]);
        let h = a
            .data_request(pan_request(0xFFFF, &[1], TxOptions::ACK))
            .unwrap();
        let c = a.poll_confirm().unwrap();
        assert_eq!((c.handle, c.status), (h, TxStatus::NoAck), "fail={fail:?}");
    }
}

#[test]
fn power_cap_enforced_before_driver() {
    let mut a = adapter();
    assert_eq!(a.driver().last_power(), Some(10));
    // One dBm over the cap is rejected; the driver never sees it.
    assert_eq!(
        a.set_tx_power(MAX_TX_POWER_DBM + 1),
        Err(EspError::PowerCapExceeded {
            requested: MAX_TX_POWER_DBM + 1
        })
    );
    assert_eq!(a.driver().last_power(), Some(10));
    assert_eq!(a.tx_power(), 10);
    // At and below the cap go through.
    a.set_tx_power(MAX_TX_POWER_DBM).unwrap();
    a.set_tx_power(-12).unwrap();
    assert_eq!(a.driver().last_power(), Some(-12));
    assert_eq!(a.tx_power(), -12);
}

#[test]
fn queue_full_backpressure_then_ordered_confirms() {
    let mut a = adapter();
    a.driver_mut().hold_auto_complete();
    assert_eq!(a.tx_queue_capacity(), 4);
    let mut handles = Vec::new();
    for i in 0..4 {
        let h = a
            .data_request(pan_request(0x0000, &[i], TxOptions::NONE))
            .unwrap();
        handles.push(h);
    }
    assert!(a.tx_queue_full());
    assert_eq!(a.tx_queue_free(), 0);
    let over = pan_request(0x0000, &[9], TxOptions::NONE);
    assert_eq!(a.data_request(over), Err(MacError::QueueFull));
    // Drain: the single-flight driver completes one per pump.
    a.driver_mut()
        .script_events(&[TxEvent::Done, TxEvent::Done, TxEvent::Done, TxEvent::Done]);
    for h in handles {
        let c = a.poll_confirm().unwrap();
        assert_eq!((c.handle, c.status), (h, TxStatus::Delivered));
    }
    assert!(a.poll_confirm().is_none());
    assert_eq!(a.tx_queue_free(), 4);
}

#[test]
fn submit_busy_stays_queued_then_flushes() {
    let mut a = adapter();
    a.driver_mut().hold_auto_complete();
    a.driver_mut().script_submit(&[Err(DriverError::Busy)]);
    let h = a
        .data_request(pan_request(0x0000, &[7], TxOptions::NONE))
        .unwrap();
    // Submit refused (single-flight race): still queued, no confirm;
    // Busy is normal backpressure, not a counted fault.
    assert!(a.poll_confirm().is_none());
    assert_eq!(a.tx_queue_free(), 3);
    assert_eq!(a.submit_faults(), 0);
    // Next pump retries and succeeds.
    a.driver_mut().script_submit(&[Ok(())]);
    a.driver_mut().script_events(&[TxEvent::Done]);
    let c = a.poll_confirm().unwrap();
    assert_eq!((c.handle, c.status), (h, TxStatus::Delivered));
}

#[test]
fn submit_fault_stays_queued_and_counted() {
    let mut a = adapter();
    let h1 = a
        .data_request(pan_request(0x0000, &[1], TxOptions::NONE))
        .unwrap();
    let c = a.poll_confirm().unwrap();
    assert_eq!((c.handle, c.status), (h1, TxStatus::Delivered));
    // Fault injection: the next submit fails persistently.
    a.driver_mut().hold_auto_complete();
    a.driver_mut().script_submit(&[Err(DriverError::HwFault)]);
    let h2 = a
        .data_request(pan_request(0x0000, &[2], TxOptions::NONE))
        .unwrap();
    // Still queued (visible backpressure), counted, no confirm lost.
    assert_eq!(a.submit_faults(), 1);
    assert_eq!(a.tx_queue_free(), 3);
    // The fault clears: a later pump submits (script exhausted means
    // the mock accepts), then the scripted done completes it.
    assert!(a.poll_confirm().is_none());
    a.driver_mut().script_events(&[TxEvent::Done]);
    let c = a.poll_confirm().unwrap();
    assert_eq!((c.handle, c.status), (h2, TxStatus::Delivered));
}

#[test]
fn cancel_revokes_queued_with_cancelled() {
    let mut a = adapter();
    a.driver_mut().hold_auto_complete();
    // Keep the driver busy so the request stays queued, never in-air.
    a.driver_mut().script_submit(&[Err(DriverError::Busy)]);
    let h = a
        .data_request(pan_request(0x0000, &[7], TxOptions::NONE))
        .unwrap();
    a.data_cancel(h).unwrap();
    let c = a.poll_confirm().unwrap();
    assert_eq!((c.handle, c.status), (h, TxStatus::Cancelled));
    assert_eq!(a.data_cancel(h), Err(MacError::UnknownHandle));
}

#[test]
fn cancel_air_submitted_runs_to_completion() {
    let mut a = adapter();
    let h = a
        .data_request(pan_request(0x0000, &[7], TxOptions::NONE))
        .unwrap();
    // Already submitted to the single-flight driver: cancel is a no-op
    // success; the transaction completes normally.
    a.data_cancel(h).unwrap();
    let c = a.poll_confirm().unwrap();
    assert_eq!((c.handle, c.status), (h, TxStatus::Delivered));
}

#[test]
fn interpan_path_tunes_channel_and_confirms() {
    let mut a = adapter();
    let ch = Channel::new(20).unwrap();
    let h = a.interpan_request(ch, &msdu(&[0xAA, 0xBB])).unwrap();
    assert_eq!(a.driver().last_channel(), Some(20));
    // Len+2 inter-PAN broadcast: MHR(11) + MSDU(2) + FCS(2) = 15.
    let air = a.driver().tx_frame(0).unwrap();
    assert_eq!(
        air,
        [15, 0x01, 0x88, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x34, 0x12, 0x01, 0x00, 0xAA, 0xBB]
            .as_slice()
    );
    let c = a.poll_interpan_confirm().unwrap();
    assert_eq!((c.handle, c.status), (h, TxStatus::Delivered));
    // One inter-PAN slot: a second request backpressures.
    a.driver_mut().hold_auto_complete();
    let _ = a.interpan_request(ch, &msdu(&[1])).unwrap();
    assert_eq!(
        a.interpan_request(ch, &msdu(&[2])),
        Err(MacError::QueueFull)
    );
}

#[test]
fn interpan_indication_carries_channel_and_bytes() {
    let mut a = adapter();
    let (frame, len) = build_inter_pan_frame(3, 0x1234, 0x0002, &[0xAA]).unwrap();
    let rx = RxFrame::from_slice(&frame[..len], 20, -60, 200).unwrap();
    a.driver_mut().inject_rx(&[rx]);
    let ind = a.poll_interpan_indication().unwrap();
    assert_eq!(ind.channel.number(), 20);
    assert_eq!(ind.msdu.as_slice(), [0xAA]);
}

#[test]
fn rx_pan_indication_parses_src_and_payload() {
    let mut a = adapter();
    // Air frame from 0x0002 to us on our PAN (built by our own builder).
    let mut frame = [0u8; 32];
    let (built, len) = build_data_frame(9, 0x1234, 0x0001, 0x0002, &[0xDE, 0xAD], false).unwrap();
    frame[..len].copy_from_slice(&built[..len]);
    let rx = RxFrame::from_slice(&frame[..len], 15, -55, 210).unwrap();
    a.driver_mut().inject_rx(&[rx]);
    let ind = a.poll_indication().unwrap();
    assert_eq!(ind.src, MacAddress::short(0x1234, 0x0002));
    assert_eq!(ind.msdu.as_slice(), [0xDE, 0xAD]);
    assert_eq!(ind.lqi, 210);
}

/// Per-frame attribution: consecutive frames with wildly different
/// meters must each keep their own (wave-27: the old most-recent
/// getters smeared one frame's meters onto the next — flat LQI 10/11
/// on every beacon while RSSI swung floor-to-strong). Two beacons from
/// the same sender, injected back-to-back with distinct (channel,
/// RSSI, LQI), surface with exactly their own meters in order.
#[test]
fn rx_meters_are_per_frame_not_stale() {
    let mut a = adapter();
    // Two valid PAN frames addressed to us (0x0001 on PAN 0x1234).
    let (first, first_len) = build_data_frame(9, 0x1234, 0x0001, 0x0002, &[0x01], false).unwrap();
    let (second, second_len) = build_data_frame(9, 0x1234, 0x0001, 0x0002, &[0x02], false).unwrap();
    // Wave-27 bench shape: flat LQI, swinging RSSI — plus a second
    // frame with totally different meters to catch any smearing.
    let rx_first = RxFrame::from_slice(&first[..first_len], 15, -28, 10).unwrap();
    let rx_second = RxFrame::from_slice(&second[..second_len], 20, -61, 200).unwrap();
    a.driver_mut().inject_rx(&[rx_first, rx_second]);
    let ind_first = a.poll_indication().unwrap();
    assert_eq!(ind_first.msdu.as_slice(), [0x01]);
    assert_eq!(ind_first.lqi, 10);
    let ind_second = a.poll_indication().unwrap();
    assert_eq!(ind_second.msdu.as_slice(), [0x02]);
    assert_eq!(ind_second.lqi, 200);
    // The second frame's LQI must not leak backwards either: replay the
    // same pair reversed and each frame still carries its own meters.
    let mut b = adapter();
    b.driver_mut().inject_rx(&[rx_second, rx_first]);
    assert_eq!(b.poll_indication().unwrap().lqi, 200);
    assert_eq!(b.poll_indication().unwrap().lqi, 10);
}

#[test]
fn foreign_pan_routes_to_interpan() {
    let mut a = adapter();
    let (built, len) = build_data_frame(9, 0x9999, 0x0001, 0x0002, &[0xEE], false).unwrap();
    let rx = RxFrame::from_slice(&built[..len], 15, -70, 150).unwrap();
    a.driver_mut().inject_rx(&[rx]);
    assert!(a.poll_indication().is_none());
    let ind = a.poll_interpan_indication().unwrap();
    assert_eq!(ind.channel.number(), 15);
    assert_eq!(ind.msdu.as_slice(), [0xEE]);
}

#[test]
fn extended_dst_unsupported_and_none_invalid() {
    use rounddance_mac_sap::{AddrMode, ExtAddr};
    let mut a = adapter();
    let ext_req = TxRequest {
        dst: MacAddress {
            pan: Some(0x1234),
            addr: AddrMode::Extended(0x0012_4B00_1234_5678 as ExtAddr),
        },
        msdu: msdu(&[1]),
        options: TxOptions::NONE,
    };
    assert_eq!(a.data_request(ext_req), Err(MacError::Unsupported));
    let none_req = TxRequest {
        dst: MacAddress {
            pan: None,
            addr: AddrMode::None,
        },
        msdu: msdu(&[1]),
        options: TxOptions::NONE,
    };
    assert_eq!(a.data_request(none_req), Err(MacError::InvalidAddress));
}

#[test]
fn ed_scan_delegates_and_maps_sign() {
    let mut a = adapter();
    a.driver_mut().set_ed(-70, false);
    // SAP reports u8 energy (higher = more); -70 dBm wraps per cast.
    assert_eq!(a.energy_scan(Channel::new(15).unwrap()), Ok(-70i8 as u8));
    a.driver_mut().set_ed(0, true);
    assert_eq!(
        a.energy_scan(Channel::new(15).unwrap()),
        Err(MacError::RadioFault)
    );
}

#[test]
fn reset_cold_drops_state_and_stays_down_until_init() {
    let mut a = adapter();
    a.driver_mut().hold_auto_complete();
    let _ = a
        .data_request(pan_request(0x0000, &[1], TxOptions::NONE))
        .unwrap();
    a.reset(true);
    assert!(a.poll_confirm().is_none());
    let req = pan_request(0x0000, &[1], TxOptions::NONE);
    assert_eq!(a.data_request(req), Err(MacError::NotReady));
    a.init().unwrap();
    a.data_request(pan_request(0x0000, &[1], TxOptions::NONE))
        .unwrap();
}

#[test]
fn warm_reset_keeps_provisioning() {
    let mut a = adapter();
    a.reset(false);
    // Still up (no deinit), provisioning intact: requests flow.
    a.data_request(pan_request(0x0000, &[1], TxOptions::NONE))
        .unwrap();
}

#[test]
fn capabilities_report_hardware_truthfully() {
    let a = adapter();
    let c = a.capabilities();
    assert!(c.hw_auto_ack);
    assert!(c.hw_csma_ca);
    assert!(!c.hw_retries);
    assert!(c.energy_scan);
    assert!(!c.frame_timestamping);
    assert!(c.promiscuous_mode);
}

#[test]
fn frame_builders_reject_oversize() {
    let big = [0xAAu8; 117];
    assert!(build_data_frame(0, 0x1234, 1, 2, &big, false).is_err());
    assert!(build_inter_pan_frame(0, 0x1234, 1, &big).is_err());
    let max = [0xAAu8; 116];
    let (f, n) = build_data_frame(0, 0x1234, 1, 2, &max, false).unwrap();
    assert_eq!(f[0], 127);
    assert_eq!(n, 126);
}

/// Phase 1 leg 1a (auto-pending primitives): coordinator mode +
/// Zigbee pending mode + short-table management program the driver,
/// and read back through the mock recording.
#[test]
fn coordinator_pending_primitives_program_driver() {
    use rounddance_hal_esp::driver::PendingMode;
    let mut a = adapter();
    a.set_coordinator(true).unwrap();
    a.set_pending_mode(PendingMode::Zigbee).unwrap();
    a.pending_short_add(0x0002).unwrap();
    a.pending_short_add(0x0003).unwrap();
    a.pending_short_clear(0x0002).unwrap();
    let d = a.driver();
    assert_eq!(d.coordinator(), Some(true));
    assert_eq!(d.pending_mode(), Some(PendingMode::Zigbee));
    assert_eq!(d.pending_shorts(), &[0x0003]);
    a.pending_shorts_reset().unwrap();
    assert_eq!(a.driver().pending_shorts(), &[]);
}
