//! [`EspIdfDriver`]: the [`Driver`] over the real IDF 15.4 driver.
//!
//! NVS-init-first, single-flight TX, ISR-flag-only events with a bounded
//! RX mailbox copy (the proven C-leg pattern: `memcpy` + flag +
//! `receive_handle_done`, never log/lock in the callback). All `unsafe`
//! in this crate lives here and in [`crate::ffi`], each block justified.

use crate::driver::{Driver, DriverError, PendingMode, RxFrame, TxEvent, TxFail, MAX_AIR_FRAME};
use crate::ffi::{self, tx_err};
use core::sync::atomic::{AtomicBool, AtomicI8, AtomicU32, AtomicU8, AtomicUsize, Ordering};

/// `esp_err_t` success (IDF `ESP_OK`).
const ESP_OK: i32 = 0;
/// `esp_err_t` for bad arguments (`ESP_ERR_INVALID_ARG`, `esp_err.h`).
const ESP_ERR_INVALID_ARG: i32 = 0x102;
/// NVS "no free pages" (`nvs_flash.h`): erase + retry.
const NVS_NO_FREE_PAGES: i32 = 0x1108;
/// NVS "new version found" (`nvs_flash.h`): erase + retry.
const NVS_NEW_VERSION: i32 = 0x1109;
/// ED scan dwell in driver time units (`energy_detect` arg).
const ED_DWELL: u32 = 8;
/// ED scan wait budget in 1 ms ticks.
const ED_WAIT_TICKS: u32 = 500;

// ---- ISR-side state: flags and bounded copies only -------------------

/// TX completed (set by `transmit_done`).
static TX_DONE: AtomicBool = AtomicBool::new(false);
/// TX failed (set by `transmit_failed`).
static TX_FAILED: AtomicBool = AtomicBool::new(false);
/// Failure code at the moment of failure (`tx_err::*`).
static TX_FAIL_CODE: AtomicU32 = AtomicU32::new(tx_err::NONE);
/// ED scan result ready.
static ED_READY: AtomicBool = AtomicBool::new(false);
/// ED scan result in dBm.
static ED_VALUE: AtomicI8 = AtomicI8::new(0);
/// RX mailbox state: 0 = empty, 1 = full, 2 = draining (reader-owned).
static RX_STATE: AtomicU8 = AtomicU8::new(0);
/// RX mailbox bytes (writer: ISR only, while state == empty).
static mut RX_BUF: [u8; MAX_AIR_FRAME] = [0; MAX_AIR_FRAME];
/// Live length of `RX_BUF`.
static RX_LEN: AtomicUsize = AtomicUsize::new(0);
/// Snapshot RSSI / LQI / channel for the mailed frame. Every field is
/// per-frame: the ISR fills all three from the callback's `frame_info`
/// pointer (primary) or the FCS-replaced frame tail (fallback) — never
/// from a most-recent getter, so consecutive frames cannot smear each
/// other's meters.
static RX_RSSI: AtomicI8 = AtomicI8::new(0);
static RX_LQI: AtomicU8 = AtomicU8::new(0);
static RX_CH: AtomicU8 = AtomicU8::new(15);
/// Frames metered from the tail because `frame_info` arrived null.
/// Diagnostics only (a healthy driver never sends null here).
static RX_INFO_NULL: AtomicU32 = AtomicU32::new(0);
/// Frames dropped because the mailbox was still full.
static RX_OVERRUN: AtomicU32 = AtomicU32::new(0);
/// Current channel (task-side cache, mirrored to `RX_CH` for the ISR).
static CURRENT_CH: AtomicU8 = AtomicU8::new(15);

/// Driver event hook: TX-DONE. Signature matches the header's
/// `transmit_done` extern (`esp_ieee802154.h` §"callbacks").
///
/// The header names the ACK buffer explicitly: `receive_handle_done`
/// takes "the frame ... or ack frame from `esp_ieee802154_transmit_done`".
/// The driver parks every received ACK in one of its RX-buffer slots
/// (`IEEE802154_RX_BUFFER_STAT_IS_FREE(false)` in the driver's own
/// `ieee802154_transmit_done`) and only frees the slot on
/// `receive_handle_done`. Never releasing it leaks one slot per
/// ACK-requesting transmission until the pool refuses further ACKs
/// (reported as NO_ACK) and its buffer accounting degrades — the
/// exact subsystem whose abort path asserts in b007. Release first,
/// then report Done, so the slot is free before any next submit.
///
/// SAFETY: atomic flag store only — no logging, no locks, no allocation;
/// the `handle_done` call follows the same ISR contract as the
/// receive path (driver-owned pointer, exactly once).
#[no_mangle]
pub extern "C" fn esp_ieee802154_transmit_done(_frame: *const u8, ack: *const u8, _info: *mut u8) {
    if !ack.is_null() {
        // SAFETY: driver-owned ACK buffer from this callback; release
        // exactly once per the header contract (see above).
        unsafe {
            ffi::esp_ieee802154_receive_handle_done(ack);
        }
    }
    TX_DONE.store(true, Ordering::Release);
}

/// Driver event hook: TX-failed. Signature matches the header's
/// `transmit_failed` extern; `error` is a `tx_err::*` value.
///
/// SAFETY: two atomic stores only (code first, flag second — the pump
/// reads the flag first with `Acquire`, so the code is always fresh).
#[no_mangle]
pub extern "C" fn esp_ieee802154_transmit_failed(_frame: *const u8, error: u32) {
    TX_FAIL_CODE.store(error, Ordering::Relaxed);
    TX_FAILED.store(true, Ordering::Release);
}

/// Driver event hook: frame received. Copies the frame into the
/// mailbox, snapshots per-frame RSSI/LQI/channel, releases the driver
/// buffer, sets the flag — the proven C-leg sequence, bounded and
/// lock-free.
///
/// Metering contract (`esp_ieee802154.h` §"reception",
/// `esp_ieee802154_types.h` `frame_info_t`): the `info` pointer carries
/// this frame's channel/RSSI/LQI, and the hardware-verified FCS is
/// REPLACED by the frame's RSSI and LQI octets, so a Len+2 frame reads
/// `[Len][Len-2 payload bytes][RSSI][LQI]`. Meters come from `info`
/// first and the frame tail second — never from the most-recent
/// getters, which proved stale on air.
///
/// HARDWARE NOTE (wave-27 field evidence): on the C6 units under test
/// the LQI meter reads flat 9–11 on links that decode ~100% (nRF grades
/// the same air 252/255; tail-RSSI a rock-stable −28 dBm while the
/// stale getter swung −59…−102 dBm frame to frame). The flat LQI is a
/// metering quirk of this hardware/firmware, not a link verdict — no
/// admission policy may treat a C6 LQI reading as link quality. See
/// `rounddance-commission::LinkEvidencePolicy`.
///
/// SAFETY: (1) null-checked; (2) the copy is bounded to `MAX_AIR_FRAME`
/// bytes into a static buffer the ISR alone writes, and only while the
/// mailbox is empty — task code touches `RX_BUF` only after swapping
/// state to draining, a state the ISR never writes in; (3) `info` is
/// either null (tail fallback) or points at one driver-owned
/// `EspFrameInfo` valid for the callback duration (header contract),
/// read with a plain copy while still in the callback; (4)
/// `receive_handle_done` is called exactly once per non-null frame with
/// the driver's own pointer; (5) no logging, locks, or allocation.
#[no_mangle]
pub extern "C" fn esp_ieee802154_receive_done(frame: *mut u8, info: *mut ffi::EspFrameInfo) {
    if frame.is_null() {
        return;
    }
    if RX_STATE.load(Ordering::Acquire) != 0 {
        // SAFETY: same call contract as below; the frame is dropped but
        // the driver buffer MUST still be released or the RX pool
        // exhausts. Overrun is counted for diagnostics.
        unsafe {
            ffi::esp_ieee802154_receive_handle_done(frame as *const u8);
        }
        RX_OVERRUN.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // SAFETY: `frame` is non-null and points at `len + 1` driver-owned
    // bytes (Len+2 convention, C-leg verified); the copy is clamped to
    // the mailbox; this is the single writer while state == empty.
    // `addr_of_mut!` creates no reference, so no `static_mut_refs`.
    let total = unsafe {
        let len = (*frame) as usize;
        let full = len.saturating_add(1);
        let total = full.min(MAX_AIR_FRAME);
        let dst = core::ptr::addr_of_mut!(RX_BUF).cast::<u8>();
        core::ptr::copy_nonoverlapping(frame, dst, total);
        // Per-frame meters: the callback's own info struct first.
        if let Some(meters) = info.as_ref() {
            RX_CH.store(meters.channel, Ordering::Relaxed);
            RX_RSSI.store(meters.rssi, Ordering::Relaxed);
            RX_LQI.store(meters.lqi, Ordering::Relaxed);
        } else {
            // Driver sent no info (never observed): fall back to the
            // FCS-replaced tail — `[..][RSSI][LQI]` at the frame's own
            // end — and the task-side channel cache. Counted so a sick
            // driver shows up in diagnostics instead of silently
            // degrading attribution. The read stays inside the mailbox
            // clamp (driver RX buffers are max-size; a corrupt length
            // past the clamp yields no meters rather than an OOB read —
            // the frame itself will fail parsing downstream anyway).
            RX_INFO_NULL.fetch_add(1, Ordering::Relaxed);
            if full >= 2 && full <= MAX_AIR_FRAME {
                let tail = core::slice::from_raw_parts(frame as *const u8, full);
                RX_RSSI.store(tail[full - 2] as i8, Ordering::Relaxed);
                RX_LQI.store(tail[full - 1], Ordering::Relaxed);
            }
            RX_CH.store(CURRENT_CH.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        total
    };
    RX_LEN.store(total, Ordering::Relaxed);
    RX_STATE.store(1, Ordering::Release);
    // SAFETY: exactly-once release of the driver's buffer, same
    // contract as above.
    unsafe {
        ffi::esp_ieee802154_receive_handle_done(frame as *const u8);
    }
}

/// Driver event hook: RX-failed. Exists to satisfy the driver; nothing
/// to do.
///
/// SAFETY: empty body — trivially sound.
#[no_mangle]
pub extern "C" fn esp_ieee802154_receive_failed(_error: u16) {}

/// Driver event hook: ED scan complete.
///
/// SAFETY: two atomic stores only (value first, flag second).
#[no_mangle]
pub extern "C" fn esp_ieee802154_energy_detect_done(power: i8) {
    ED_VALUE.store(power, Ordering::Relaxed);
    ED_READY.store(true, Ordering::Release);
}

/// Map an `esp_err_t` to the seam error.
fn check(rc: i32) -> Result<(), DriverError> {
    if rc == ESP_OK {
        Ok(())
    } else if rc == ESP_ERR_INVALID_ARG {
        Err(DriverError::InvalidParam)
    } else {
        Err(DriverError::HwFault)
    }
}

fn map_tx_fail(code: u32) -> TxFail {
    match code {
        tx_err::CCA_BUSY => TxFail::CcaBusy,
        tx_err::NO_ACK => TxFail::NoAck,
        tx_err::INVALID_ACK => TxFail::InvalidAck,
        tx_err::COEXIST => TxFail::CoexReject,
        tx_err::SECURITY => TxFail::Security,
        tx_err::ABORT | tx_err::NONE => TxFail::Aborted,
        // Future driver revisions may add variants: fail safe (the
        // frame was not delivered) rather than fail closed.
        _ => TxFail::Aborted,
    }
}

/// The [`Driver`] over the real IDF 15.4 driver (C6/H2/C5/S31 — the
/// application-level driver API is identical).
///
/// Construct with [`EspIdfDriver::new`], then drive via the [`Driver`]
/// trait (normally through [`EspAdapter`](crate::adapter::EspAdapter),
/// never directly from application code).
pub struct EspIdfDriver {
    inited: bool,
    tx_in_flight: bool,
}

impl EspIdfDriver {
    /// Uninitialised driver (radio down until `init`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inited: false,
            tx_in_flight: false,
        }
    }

    /// RX-mailbox overruns (frames dropped with the mailbox full).
    /// Diagnostics only.
    #[must_use]
    pub fn rx_overruns() -> u32 {
        RX_OVERRUN.load(Ordering::Relaxed)
    }

    /// Frames metered from the frame tail because the driver's
    /// `frame_info` pointer arrived null. Diagnostics only — a healthy
    /// driver always passes info, so any nonzero count here is a
    /// firmware bug report, not a tuning knob.
    #[must_use]
    pub fn rx_info_fallbacks() -> u32 {
        RX_INFO_NULL.load(Ordering::Relaxed)
    }
}

impl Default for EspIdfDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl Driver for EspIdfDriver {
    fn is_ready(&self) -> bool {
        self.inited
    }

    fn init(&mut self) -> Result<(), DriverError> {
        // NVS FIRST: radio calibration data lives there (wave-2b hard
        // constraint). SAFETY: NVS init/erase take no pointers; return
        // codes handled below. `link_patches` must run once per image.
        unsafe {
            esp_idf_sys::link_patches();
            let rc = esp_idf_sys::nvs_flash_init();
            if rc == NVS_NO_FREE_PAGES || rc == NVS_NEW_VERSION {
                esp_idf_sys::nvs_flash_erase();
                let rc = esp_idf_sys::nvs_flash_init();
                if rc != ESP_OK {
                    return Err(DriverError::HwFault);
                }
            } else if rc != ESP_OK {
                return Err(DriverError::HwFault);
            }
            // SAFETY: no-arg FFI, return code checked (see `ffi` for
            // per-symbol signature justification).
            check(ffi::esp_ieee802154_enable())?;
        }
        self.inited = true;
        self.tx_in_flight = false;
        Ok(())
    }

    fn deinit(&mut self) -> Result<(), DriverError> {
        // SAFETY: no-arg FFI, return code checked.
        unsafe {
            check(ffi::esp_ieee802154_disable())?;
        }
        self.inited = false;
        self.tx_in_flight = false;
        Ok(())
    }

    fn set_channel(&mut self, channel: u8) -> Result<(), DriverError> {
        if !self.inited {
            return Err(DriverError::NotReady);
        }
        // SAFETY: byte-arg FFI, return code checked.
        unsafe {
            check(ffi::esp_ieee802154_set_channel(channel))?;
        }
        CURRENT_CH.store(channel, Ordering::Relaxed);
        Ok(())
    }

    fn set_tx_power(&mut self, dbm: i8) -> Result<(), DriverError> {
        if !self.inited {
            return Err(DriverError::NotReady);
        }
        // SAFETY: byte-arg FFI, return code checked. The standing
        // +10 dBm cap is enforced by the adapter before this point.
        unsafe {
            check(ffi::esp_ieee802154_set_txpower(dbm))?;
        }
        Ok(())
    }

    fn set_addrs(&mut self, pan: u16, short: u16, ext: &[u8; 8]) -> Result<(), DriverError> {
        if !self.inited {
            return Err(DriverError::NotReady);
        }
        // SAFETY: scalar FFI calls, codes checked; the extended-address
        // pointer borrows `ext` for the call duration only (the driver
        // copies synchronously — see `ffi`).
        unsafe {
            check(ffi::esp_ieee802154_set_panid(pan))?;
            check(ffi::esp_ieee802154_set_short_address(short))?;
            check(ffi::esp_ieee802154_set_extended_address(ext.as_ptr()))?;
        }
        Ok(())
    }

    fn set_promiscuous(&mut self, enable: bool) -> Result<(), DriverError> {
        if !self.inited {
            return Err(DriverError::NotReady);
        }
        // SAFETY: bool-arg FFI, return code checked.
        unsafe {
            check(ffi::esp_ieee802154_set_promiscuous(enable))?;
            check(ffi::esp_ieee802154_set_rx_when_idle(true))?;
        }
        Ok(())
    }

    fn start_rx(&mut self) -> Result<(), DriverError> {
        if !self.inited {
            return Err(DriverError::NotReady);
        }
        // SAFETY: no-arg FFI, return code checked.
        unsafe {
            check(ffi::esp_ieee802154_receive())?;
        }
        Ok(())
    }

    fn set_coordinator(&mut self, enable: bool) -> Result<(), DriverError> {
        if !self.inited {
            return Err(DriverError::NotReady);
        }
        // SAFETY: bool-arg FFI, return code checked.
        unsafe {
            check(ffi::esp_ieee802154_set_coordinator(enable))?;
        }
        Ok(())
    }

    fn set_pending_mode(&mut self, mode: PendingMode) -> Result<(), DriverError> {
        if !self.inited {
            return Err(DriverError::NotReady);
        }
        let ffi_mode = match mode {
            PendingMode::Disable => ffi::PendingMode::Disable,
            PendingMode::Enable => ffi::PendingMode::Enable,
            PendingMode::Enhanced => ffi::PendingMode::Enhanced,
            PendingMode::Zigbee => ffi::PendingMode::Zigbee,
        };
        // SAFETY: enum passed by value (repr u32, order checked
        // against the header in `ffi`), code checked.
        unsafe {
            check(ffi::esp_ieee802154_set_pending_mode(ffi_mode))?;
        }
        Ok(())
    }

    fn pending_short_add(&mut self, short: u16) -> Result<(), DriverError> {
        if !self.inited {
            return Err(DriverError::NotReady);
        }
        // SAFETY: the driver copies the 2 address octets synchronously
        // (header §"frame pending"); LE wire order on both sides.
        let le = short.to_le_bytes();
        unsafe {
            check(ffi::esp_ieee802154_add_pending_addr(le.as_ptr(), true))?;
        }
        Ok(())
    }

    fn pending_short_clear(&mut self, short: u16) -> Result<(), DriverError> {
        if !self.inited {
            return Err(DriverError::NotReady);
        }
        // SAFETY: as for `pending_short_add`.
        let le = short.to_le_bytes();
        unsafe {
            check(ffi::esp_ieee802154_clear_pending_addr(le.as_ptr(), true))?;
        }
        Ok(())
    }

    fn pending_shorts_reset(&mut self) -> Result<(), DriverError> {
        if !self.inited {
            return Err(DriverError::NotReady);
        }
        // SAFETY: bool-arg FFI, return code checked.
        unsafe {
            check(ffi::esp_ieee802154_reset_pending_table(true))?;
        }
        Ok(())
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), DriverError> {
        if !self.inited {
            return Err(DriverError::NotReady);
        }
        if self.tx_in_flight {
            return Err(DriverError::Busy);
        }
        if frame.is_empty() || frame.len() > MAX_AIR_FRAME {
            return Err(DriverError::InvalidParam);
        }
        // SAFETY: the borrowed frame outlives this call; the driver
        // copies what it needs before returning (single-flight, and the
        // DONE/FAILED hooks only echo the pointer as an identifier).
        // CCA-gated (`true`): unacked inter-PAN still benefits from
        // carrier sense; ACKed frames need it for CSMA-CA.
        unsafe {
            check(ffi::esp_ieee802154_transmit(frame.as_ptr(), true))?;
        }
        self.tx_in_flight = true;
        Ok(())
    }

    fn poll_tx(&mut self) -> Option<TxEvent> {
        if TX_DONE.load(Ordering::Acquire) {
            TX_DONE.store(false, Ordering::Relaxed);
            self.tx_in_flight = false;
            return Some(TxEvent::Done);
        }
        if TX_FAILED.load(Ordering::Acquire) {
            TX_FAILED.store(false, Ordering::Relaxed);
            self.tx_in_flight = false;
            let code = TX_FAIL_CODE.load(Ordering::Relaxed);
            return Some(TxEvent::Failed(map_tx_fail(code)));
        }
        None
    }

    fn poll_rx(&mut self) -> Option<RxFrame> {
        // Claim the mailbox: full -> draining. The ISR never writes
        // while draining, so the copy below cannot tear.
        if RX_STATE.load(Ordering::Acquire) != 1 {
            return None;
        }
        if RX_STATE
            .compare_exchange(1, 2, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }
        // SAFETY: state is draining — the ISR (sole writer) will not
        // touch `RX_BUF` until it observes empty again, which only this
        // path sets after the copy. Single reader by adapter contract
        // (`poll_rx` is never called from ISR context). `addr_of!`
        // creates no reference, so no `static_mut_refs`.
        let frame = unsafe {
            let len = RX_LEN.load(Ordering::Relaxed).min(MAX_AIR_FRAME);
            let mut bytes = [0u8; MAX_AIR_FRAME];
            let src = core::ptr::addr_of!(RX_BUF).cast::<u8>();
            core::ptr::copy_nonoverlapping(src, bytes.as_mut_ptr(), len);
            let frame = RxFrame {
                bytes,
                len,
                channel: RX_CH.load(Ordering::Relaxed),
                rssi: RX_RSSI.load(Ordering::Relaxed),
                lqi: RX_LQI.load(Ordering::Relaxed),
            };
            RX_STATE.store(0, Ordering::Release);
            frame
        };
        Some(frame)
    }

    fn energy_scan(&mut self, channel: u8) -> Result<i8, DriverError> {
        if !self.inited {
            return Err(DriverError::NotReady);
        }
        if !(11..=26).contains(&channel) {
            return Err(DriverError::InvalidParam);
        }
        self.set_channel(channel)?;
        ED_READY.store(false, Ordering::Relaxed);
        // SAFETY: scalar-arg FFI, return code checked.
        unsafe {
            check(ffi::esp_ieee802154_energy_detect(ED_DWELL))?;
        }
        // Bounded wait for the async ED-done event (1 ms ticks).
        // SAFETY: `vTaskDelay` takes a tick count, no pointers.
        for _ in 0..ED_WAIT_TICKS {
            if ED_READY.load(Ordering::Acquire) {
                return Ok(ED_VALUE.load(Ordering::Relaxed));
            }
            unsafe {
                esp_idf_sys::vTaskDelay(1);
            }
        }
        Err(DriverError::HwFault)
    }
}
