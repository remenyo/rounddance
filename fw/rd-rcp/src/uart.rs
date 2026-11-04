//! RCP-wire UART backend (IDF UART driver, 460800 8N1 raw).
//!
//! `unsafe` is confined here (crate `#![deny(unsafe_code)]`, module
//! `#![allow(unsafe_code)]`): every block states why the call is
//! sound — live driver-owned UART number, caller-provided buffers
//! that outlive the call, scalar error codes only.

#![allow(unsafe_code)]

use crate::ffi;
use core::sync::atomic::{AtomicI32, Ordering};

/// RCP wire rate in baud (pinned by `docs/otbr/protocol.md`).
pub const RCP_BAUD: i32 = 460_800;
/// `esp_err_t` success (`esp_err.h` `ESP_OK`).
const ESP_OK: i32 = 0;

/// The engine's single RCP UART number (set once by [`init`]).
static UART_NUM: AtomicI32 = AtomicI32::new(1);

/// Install + configure the RCP UART: 460800 8N1, no flow control,
/// no event queue, 2K RX ring. Console stays on USB_SERIAL_JTAG —
/// this UART carries RCP frames only.
pub fn init(uart_num: i32, rx_pin: i32, tx_pin: i32) {
    let cfg = ffi::UartConfig {
        baud_rate: RCP_BAUD,
        data_bits: 3,
        parity: 0,
        stop_bits: 1,
        flow_ctrl: 0,
        rx_flow_ctrl_thresh: 0,
        source_clk: 0,
    };
    // SAFETY: scalar FFI on a live UART number; `cfg` outlives the
    // call; return codes map to panics (a misconfigured wire wedges
    // framing, so boot fails loudly instead).
    unsafe {
        assert_eq!(
            ffi::uart_param_config(uart_num, &cfg),
            ESP_OK,
            "uart_param_config"
        );
        assert_eq!(
            ffi::_uart_set_pin6(
                uart_num,
                tx_pin,
                rx_pin,
                ffi::UART_PIN_NO_CHANGE,
                ffi::UART_PIN_NO_CHANGE,
                ffi::UART_PIN_NO_CHANGE,
                ffi::UART_PIN_NO_CHANGE
            ),
            ESP_OK,
            "uart_set_pin"
        );
        assert_eq!(
            ffi::uart_driver_install(uart_num, 2048, 1024, 0, core::ptr::null_mut(), 0),
            ESP_OK,
            "uart_driver_install"
        );
        ffi::uart_flush_input(uart_num);
    }
    UART_NUM.store(uart_num, Ordering::SeqCst);
}

/// Read up to `out.len()` bytes without blocking; returns bytes read
/// (negative driver errors clamp to zero — the framing layer drops
/// nothing it never received).
pub fn read(uart_num: i32, out: &mut [u8]) -> usize {
    // SAFETY: `out` is a live exclusive borrow for the call; length
    // is exact; a zero tick budget never blocks.
    unsafe {
        let n = ffi::uart_read_bytes(uart_num, out.as_mut_ptr(), out.len() as u32, 0);
        n.max(0) as usize
    }
}

/// Write all of `bytes` on the engine UART (blocking, bounded —
/// callers pass one RCP frame, at most 134 octets).
pub fn write_all(bytes: &[u8]) {
    let uart_num = UART_NUM.load(Ordering::SeqCst);
    // SAFETY: `bytes` outlives the blocking write; the UART number
    // is the engine's live one (installed by `init` before `run`
    // serves the wire).
    unsafe {
        ffi::uart_write_bytes(uart_num, bytes.as_ptr(), bytes.len());
    }
}
