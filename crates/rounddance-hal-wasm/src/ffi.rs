//! Guest imports: the WASM side of the host-call ABI.
//!
//! Each function below is imported from the native runner (`host/`
//! `rd_wasm_host.h` states the C side). Integers cross as `i32`/`u32`
//! (WASM MVP types); byte buffers cross as guest-memory pointer +
//! length pairs that the host resolves through its runtime's memory
//! API. Return convention: `0` = ok (or "none", for the poll legs);
//! negative = `-(DriverError as i32)` with the discriminant mapping
//! in [`FfiHost`].
//!
//! `unsafe` confinement: this is the crate's single
//! `#![allow(unsafe_code)]` module (crate root keeps
//! `#![deny(unsafe_code)]`, the `rounddance-browser` precedent).
//! Every foreign call carries a `SAFETY` comment. Guest-owned buffers
//! passed down live in guest frames/arrays for exactly the call
//! duration; the host must never retain the pointers (the C header
//! states the same rule for the runner side).
//!
//! Requirement `RD-WASM-RT-02` (MINTED-pending-confirm).
#![allow(unsafe_code)]

use crate::host::HostOps;
use rounddance_hal_esp::driver::MAX_AIR_FRAME;
use rounddance_hal_esp::{DriverError, PendingMode, RxFrame, TxEvent, TxFail};

/// `0` return: success (or "queue empty" on the poll legs).
const HOST_OK: i32 = 0;

/// TX-event codes on the host→guest leg.
const EV_DONE: i32 = 1;
const EV_CCA_BUSY: i32 = 2;
const EV_NOACK: i32 = 3;
const EV_ABORTED: i32 = 4;
const EV_COEX_REJECT: i32 = 5;
const EV_SECURITY: i32 = 6;
const EV_INVALID_ACK: i32 = 7;

/// Inverse of the on-wire error mapping (host→guest): -1 NotReady,
/// -2 Busy, -3 HwFault, -4 Unsupported, -5 InvalidParam; anything else
/// is a hardware fault, never silent success.
const fn err_from_code(v: i32) -> DriverError {
    match v {
        -1 => DriverError::NotReady,
        -2 => DriverError::Busy,
        -3 => DriverError::HwFault,
        -4 => DriverError::Unsupported,
        _ => DriverError::HwFault,
    }
}

#[link(wasm_import_module = "host")]
unsafe extern "C" {
    fn rd_host_init() -> i32;
    fn rd_host_deinit() -> i32;
    fn rd_host_is_ready() -> i32;
    fn rd_host_set_channel(channel: u32) -> i32;
    fn rd_host_set_tx_power(dbm: i32) -> i32;
    fn rd_host_set_addrs(pan: u32, short: u32, eui: *const u8) -> i32;
    fn rd_host_set_promiscuous(enable: u32) -> i32;
    fn rd_host_start_rx() -> i32;
    fn rd_host_set_coordinator(enable: u32) -> i32;
    fn rd_host_set_pending_mode(mode: u32) -> i32;
    fn rd_host_pending_short_add(short: u32) -> i32;
    fn rd_host_pending_short_clear(short: u32) -> i32;
    fn rd_host_pending_shorts_reset() -> i32;
    fn rd_host_transmit(frame: *const u8, len: u32) -> i32;
    fn rd_host_poll_tx(out_event: *mut i32) -> i32;
    fn rd_host_poll_rx(frame_out: *mut u8, cap: u32, meta: *mut i32) -> i32;
    fn rd_host_energy_scan(channel: u32, out_dbm: *mut i32) -> i32;
}

/// [`HostOps`] over the real guest imports (the on-device path).
///
/// Constructing is side-effect free; every method is one host call.
#[derive(Clone, Copy, Debug, Default)]
pub struct FfiHost;

impl FfiHost {
    /// New host handle (no radio effect until `init`).
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

fn ev_from_code(v: i32) -> Option<TxEvent> {
    match v {
        EV_DONE => Some(TxEvent::Done),
        EV_CCA_BUSY => Some(TxEvent::Failed(TxFail::CcaBusy)),
        EV_NOACK => Some(TxEvent::Failed(TxFail::NoAck)),
        EV_ABORTED => Some(TxEvent::Failed(TxFail::Aborted)),
        EV_COEX_REJECT => Some(TxEvent::Failed(TxFail::CoexReject)),
        EV_SECURITY => Some(TxEvent::Failed(TxFail::Security)),
        EV_INVALID_ACK => Some(TxEvent::Failed(TxFail::InvalidAck)),
        _ => None,
    }
}

impl HostOps for FfiHost {
    fn is_ready(&self) -> bool {
        // SAFETY: pure query, no buffers cross the boundary.
        unsafe { rd_host_is_ready() != 0 }
    }

    fn init(&mut self) -> Result<(), DriverError> {
        // SAFETY: no buffers cross; return code maps 1:1.
        let rc = unsafe { rd_host_init() };
        if rc == HOST_OK {
            Ok(())
        } else {
            Err(err_from_code(rc))
        }
    }

    fn deinit(&mut self) -> Result<(), DriverError> {
        // SAFETY: as for `init`.
        let rc = unsafe { rd_host_deinit() };
        if rc == HOST_OK {
            Ok(())
        } else {
            Err(err_from_code(rc))
        }
    }

    fn set_channel(&mut self, channel: u8) -> Result<(), DriverError> {
        // SAFETY: scalar-only call; the adapter range-checks 11–26.
        let rc = unsafe { rd_host_set_channel(u32::from(channel)) };
        if rc == HOST_OK {
            Ok(())
        } else {
            Err(err_from_code(rc))
        }
    }

    fn set_tx_power(&mut self, dbm: i8) -> Result<(), DriverError> {
        // SAFETY: scalar-only call; the adapter caps before calling.
        let rc = unsafe { rd_host_set_tx_power(i32::from(dbm)) };
        if rc == HOST_OK {
            Ok(())
        } else {
            Err(err_from_code(rc))
        }
    }

    fn set_addrs(&mut self, pan: u16, short: u16, ext: &[u8; 8]) -> Result<(), DriverError> {
        // SAFETY: `ext` borrows a live caller array for the call only;
        // the host must copy, never retain (C header states this too).
        let rc = unsafe { rd_host_set_addrs(u32::from(pan), u32::from(short), ext.as_ptr()) };
        if rc == HOST_OK {
            Ok(())
        } else {
            Err(err_from_code(rc))
        }
    }

    fn set_promiscuous(&mut self, enable: bool) -> Result<(), DriverError> {
        // SAFETY: scalar-only call.
        let rc = unsafe { rd_host_set_promiscuous(u32::from(enable)) };
        if rc == HOST_OK {
            Ok(())
        } else {
            Err(err_from_code(rc))
        }
    }

    fn start_rx(&mut self) -> Result<(), DriverError> {
        // SAFETY: scalar-only call.
        let rc = unsafe { rd_host_start_rx() };
        if rc == HOST_OK {
            Ok(())
        } else {
            Err(err_from_code(rc))
        }
    }

    fn set_coordinator(&mut self, enable: bool) -> Result<(), DriverError> {
        // SAFETY: scalar-only call.
        let rc = unsafe { rd_host_set_coordinator(u32::from(enable)) };
        if rc == HOST_OK {
            Ok(())
        } else {
            Err(err_from_code(rc))
        }
    }

    fn set_pending_mode(&mut self, mode: PendingMode) -> Result<(), DriverError> {
        // SAFETY: scalar-only call; discriminants are the shared
        // `PendingMode` order both sides program against.
        let rc = unsafe { rd_host_set_pending_mode(mode as u32) };
        if rc == HOST_OK {
            Ok(())
        } else {
            Err(err_from_code(rc))
        }
    }

    fn pending_short_add(&mut self, short: u16) -> Result<(), DriverError> {
        // SAFETY: scalar-only call.
        let rc = unsafe { rd_host_pending_short_add(u32::from(short)) };
        if rc == HOST_OK {
            Ok(())
        } else {
            Err(err_from_code(rc))
        }
    }

    fn pending_short_clear(&mut self, short: u16) -> Result<(), DriverError> {
        // SAFETY: scalar-only call.
        let rc = unsafe { rd_host_pending_short_clear(u32::from(short)) };
        if rc == HOST_OK {
            Ok(())
        } else {
            Err(err_from_code(rc))
        }
    }

    fn pending_shorts_reset(&mut self) -> Result<(), DriverError> {
        // SAFETY: scalar-only call.
        let rc = unsafe { rd_host_pending_shorts_reset() };
        if rc == HOST_OK {
            Ok(())
        } else {
            Err(err_from_code(rc))
        }
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), DriverError> {
        if frame.is_empty() || frame.len() > MAX_AIR_FRAME {
            return Err(DriverError::InvalidParam);
        }
        // SAFETY: `frame` borrows a live caller slice for the call
        // only; the host must copy before returning (single-flight
        // submit, same contract as the native driver).
        let rc = unsafe { rd_host_transmit(frame.as_ptr(), frame.len() as u32) };
        if rc == HOST_OK {
            Ok(())
        } else {
            Err(err_from_code(rc))
        }
    }

    fn poll_tx(&mut self) -> Option<TxEvent> {
        let mut ev: i32 = 0;
        // SAFETY: `ev` is a live stack slot for the call only.
        let rc = unsafe { rd_host_poll_tx(&mut ev) };
        if rc == 1 {
            ev_from_code(ev)
        } else {
            None
        }
    }

    fn poll_rx(&mut self) -> Option<RxFrame> {
        let mut buf = [0u8; MAX_AIR_FRAME];
        let mut meta = [0i32; 4];
        // SAFETY: both arrays are live stack slots for the call only;
        // `cap` bounds the host write; a short or overlong report is
        // rejected below, never trusted.
        let n = unsafe { rd_host_poll_rx(buf.as_mut_ptr(), buf.len() as u32, meta.as_mut_ptr()) };
        if n <= 0 {
            return None;
        }
        let len = n as usize;
        if len > buf.len() {
            return None;
        }
        let mut bytes = [0u8; MAX_AIR_FRAME];
        bytes[..len].copy_from_slice(&buf[..len]);
        Some(RxFrame {
            bytes,
            len,
            channel: meta[0] as u8,
            rssi: meta[1] as i8,
            lqi: meta[2] as u8,
        })
    }

    fn energy_scan(&mut self, channel: u8) -> Result<i8, DriverError> {
        let mut dbm: i32 = 0;
        // SAFETY: `dbm` is a live stack slot for the call only.
        let rc = unsafe { rd_host_energy_scan(u32::from(channel), &mut dbm) };
        if rc == HOST_OK {
            Ok(dbm as i8)
        } else {
            Err(err_from_code(rc))
        }
    }
}
