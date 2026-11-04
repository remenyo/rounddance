//! Guest-export verification: the real `rd_guest_radio_selftest`
//! path runs against stub host imports defined right here (same C
//! ABI the native runner implements), proving the exact guest code
//! that will execute on-device.

use rounddance_hal_wasm::rd_guest_radio_selftest;
use std::sync::{
    atomic::{AtomicI32, AtomicUsize, Ordering},
    Mutex,
};

static INIT_CALLS: AtomicUsize = AtomicUsize::new(0);
static TX_FRAMES: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
static CANNED_ED: AtomicI32 = AtomicI32::new(-60);

#[unsafe(no_mangle)]
pub extern "C" fn rd_host_init() -> i32 {
    INIT_CALLS.fetch_add(1, Ordering::SeqCst);
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn rd_host_deinit() -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn rd_host_is_ready() -> i32 {
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn rd_host_set_channel(_channel: u32) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn rd_host_set_tx_power(_dbm: i32) -> i32 {
    0
}
/// Test host provisioning: records nothing, checks nothing.
///
/// # Safety
///
/// The caller must pass a readable 8-byte `eui` (the guest passes a
/// live array); this stub ignores it, so any aligned pointer is fine.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rd_host_set_addrs(_pan: u32, _short: u32, _eui: *const u8) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn rd_host_set_promiscuous(_enable: u32) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn rd_host_start_rx() -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn rd_host_set_coordinator(_enable: u32) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn rd_host_set_pending_mode(_mode: u32) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn rd_host_pending_short_add(_short: u32) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn rd_host_pending_short_clear(_short: u32) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn rd_host_pending_shorts_reset() -> i32 {
    0
}
/// Test host transmit: copies the frame bytes into the log.
///
/// # Safety
///
/// The caller must pass `len` readable bytes at `frame` (the guest
/// passes a live TX buffer of exactly that length).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rd_host_transmit(frame: *const u8, len: u32) -> i32 {
    let bytes = unsafe { core::slice::from_raw_parts(frame, len as usize) };
    TX_FRAMES.lock().unwrap().push(bytes.to_vec());
    0
}
/// Test host TX report: always reports Done.
///
/// # Safety
///
/// The caller must pass a writable `i32` slot (the guest passes a
/// live stack slot).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rd_host_poll_tx(out_event: *mut i32) -> i32 {
    unsafe {
        *out_event = 1; // Done
    }
    1
}
/// Test host RX: the queue is always empty here.
///
/// # Safety
///
/// Safe to call with any arguments; nothing is dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rd_host_poll_rx(_frame_out: *mut u8, _cap: u32, _meta: *mut i32) -> i32 {
    0 // nothing queued
}
/// Test host energy scan: reports the canned value.
///
/// # Safety
///
/// The caller must pass a writable `i32` slot (the guest passes a
/// live stack slot).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rd_host_energy_scan(_channel: u32, out_dbm: *mut i32) -> i32 {
    unsafe {
        *out_dbm = CANNED_ED.load(Ordering::SeqCst);
    }
    0
}

#[test]
fn guest_selftest_passes_over_stub_host() {
    TX_FRAMES.lock().unwrap().clear();
    INIT_CALLS.store(0, Ordering::SeqCst);
    assert_eq!(rd_guest_radio_selftest(), 0);
    assert_eq!(INIT_CALLS.load(Ordering::SeqCst), 1);
    let frames = TX_FRAMES.lock().unwrap();
    assert_eq!(frames.len(), 1);
    // Len+2 frame: length octet counts header + MSDU + 2 FCS octets.
    assert_eq!(frames[0][0] as usize, frames[0].len() + 1);
    assert_eq!(&frames[0][1..4], &[0x03, 0x08, 0xFF]);
}
