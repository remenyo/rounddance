//! Minimal IDF FFI the RCP engine needs beyond `esp-idf-sys` 0.38:
//! the UART driver (`driver/uart.h`) plus `esp_read_mac`
//! (`esp_mac.h`). Same confinement as `rounddance-hal-esp`'s `ffi`:
//! declarations only, each citing its header; all call sites live in
//! [`crate::uart`] or carry their own `SAFETY` comment.

#![allow(unsafe_code)]

/// UART configuration (`driver/uart.h` `uart_config_t`).
#[repr(C)]
pub struct UartConfig {
    /// Baud rate (460800 for the RCP wire).
    pub baud_rate: i32,
    /// Word length (`UART_DATA_8_BITS` = 3).
    pub data_bits: i32,
    /// Parity (`UART_PARITY_DISABLE` = 0).
    pub parity: i32,
    /// Stop bits (`UART_STOP_BITS_1` = 1).
    pub stop_bits: i32,
    /// Flow control (`UART_HW_FLOWCTRL_DISABLE` = 0).
    pub flow_ctrl: i32,
    /// RX flow threshold (unused without flow control).
    pub rx_flow_ctrl_thresh: u8,
    /// RX glitch-filter width in ns, 0 = disabled (`driver/uart.h`
    /// `rx_glitch_filt_thresh`; IDF v6.1 field — omitting it shifts
    /// `source_clk` out of place and the driver reads garbage).
    pub rx_glitch_filt_thresh: u32,
    /// Clock source (`UART_SCLK_DEFAULT` = 0; S31 pins XTAL, see
    /// `Board::uart_sclk`).
    pub source_clk: i32,
    /// Driver flags bitfield (`allow_pd`/`backup_before_sleep`).
    /// Must be present and zero: without it the driver reads past
    /// the struct (IDF v6.1 `uart_config_t` layout).
    pub flags: u32,
}

/// `UART_PIN_NO_CHANGE` (`driver/uart.h`): leave a pin unassigned.
pub const UART_PIN_NO_CHANGE: i32 = -1;

unsafe extern "C" {
    /// Install the UART driver (`driver/uart.h`).
    pub fn uart_driver_install(
        uart_num: i32,
        rx_buffer_size: i32,
        tx_buffer_size: i32,
        queue_size: i32,
        queue_handle: *mut *mut core::ffi::c_void,
        intr_alloc_flags: i32,
    ) -> i32;
    /// Configure baud/word/parity/stop/flow (`driver/uart.h`).
    pub fn uart_param_config(uart_num: i32, config: *const UartConfig) -> i32;
    /// Route TX/RX pins (`driver/uart.h` `uart_set_pin` is a
    /// variadic macro in IDF v6.1; `_uart_set_pin4` is a header
    /// `static inline`, so this binds the real 6-arg symbol with
    /// DTR/DSR unassigned (-1). There is no linkable `uart_set_pin`.
    pub fn _uart_set_pin6(
        uart_num: i32,
        tx_io_num: i32,
        rx_io_num: i32,
        rts_io_num: i32,
        cts_io_num: i32,
        dtr_io_num: i32,
        dsr_io_num: i32,
    ) -> i32;
    /// Non-blocking when `ticks_to_wait` is 0 (`driver/uart.h`).
    pub fn uart_read_bytes(uart_num: i32, buf: *mut u8, length: u32, ticks_to_wait: u32) -> i32;
    /// Queue bytes for transmission (`driver/uart.h`).
    pub fn uart_write_bytes(uart_num: i32, src: *const u8, size: usize) -> i32;
    /// Drop pending RX bytes (`driver/uart.h`).
    pub fn uart_flush_input(uart_num: i32) -> i32;
    /// Factory base MAC (`esp_mac.h`; type 5 = `ESP_MAC_BASE`).
    pub fn esp_read_mac(mac: *mut u8, type_: u32) -> i32;
}

/// Read the factory base MAC into `out` (synchronous scalar FFI;
/// the out-param borrows a live stack slot for the call only).
/// Returns the IDF status code (`0` = `ESP_OK`).
pub fn read_base_mac(out: &mut [u8; 6]) -> i32 {
    // SAFETY: as documented above; `esp_mac.h` contract.
    unsafe { esp_read_mac(out.as_mut_ptr(), 5) }
}
