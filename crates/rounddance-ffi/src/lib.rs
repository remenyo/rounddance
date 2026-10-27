//! C ABI over the first complete host transaction.
//!
//! Same scenario as the host leg and the browser bundle
//! ([`rounddance_hal_host::scenario::run_first_transaction`]:
//! coordinator formation → install-code join → Trust-Center verify →
//! secured ZCL On → timer-gated attribute report), exposed through a
//! stable C ABI so C and C++ harnesses can drive it and assert
//! decision-match against the native digest.
//!
//! ## Shape
//!
//! * Opaque context handle: [`ffi::rd_create`] runs the transaction
//!   to completion and stores the outcome; [`ffi::rd_destroy`]
//!   releases it. No context state is shared across handles.
//! * Getters return one decision each through length-tagged out
//!   params. Strings (trace lines) cross as **nul-free** byte spans:
//!   [`ffi::rd_trace_line`] writes raw bytes with no terminator and
//!   reports the full length separately.
//! * Every function returns an [`RD_OK`]-family status code; a null
//!   handle or out-pointer is a status, never UB.
//!
//! ## Panic policy
//!
//! Every boundary function wraps its body in
//! [`std::panic::catch_unwind`](std::panic::catch_unwind) and maps a
//! caught panic to [`RD_ERR_PANIC`]. Under `panic = "abort"` builds
//! the process terminates at the boundary instead of returning —
//! still FFI-safe (no unwind crosses into C), just fatal. Either
//! way no Rust panic unwinds into C/C++ callers.
//!
//! ## `unsafe` confinement
//!
//! Protocol crates carry `#![forbid(unsafe_code)]`. This crate is a
//! boundary adapter in the hal-esp sense (not a protocol crate): the
//! crate root keeps `#![deny(unsafe_code)]`, and the ONLY allowance
//! is the [`ffi`] module, where each `unsafe` block dereferences a
//! caller-provided pointer after a null check, with a `SAFETY`
//! comment naming the invariant. No protocol logic lives here.
//!
//! ## `no_std` note
//!
//! Not `no_std`: the scenario path runs on the `std`-based
//! host backends (loopback radio, timer, store), exactly like the
//! browser bundle crate. The `unsafe` surface and the nul-free,
//! bounded-buffer discipline are kept `no_std`-shaped so a future
//! `no_std` scenario could reuse this boundary pattern.
//!
//! Requirement traceability: `REQUIREMENTS.md` wave-21 section
//! (`RD-FFI-*`, repo-minted, MINTED-pending-confirm).
#![deny(unsafe_code)]

use rounddance_hal_host::scenario::TransactionOutcome;

/// C ABI version. Bump on any signature or semantic change.
pub const API_VERSION: u32 = 1;

/// Success.
pub const RD_OK: i32 = 0;
/// Null handle or null out-pointer argument.
pub const RD_ERR_NULL: i32 = 1;
/// Allocation of the context failed.
pub const RD_ERR_OOM: i32 = 2;
/// Trace-line index out of range.
pub const RD_ERR_RANGE: i32 = 3;
/// Caller buffer too small for the trace line (partial bytes were
/// still written; `out_len` carries the full length so the caller
/// can retry with a bigger buffer).
pub const RD_ERR_SMALL: i32 = 4;
/// The scenario panicked (caught at the boundary).
pub const RD_ERR_PANIC: i32 = 5;

/// Opaque transaction context. Constructed only via
/// [`ffi::rd_create`]; the outcome is the completed first
/// transaction (decisions + trace).
pub struct RdContext {
    outcome: TransactionOutcome,
}

/// Crate identifier.
#[must_use]
pub fn name() -> &'static str {
    "rounddance-ffi"
}

/// Stable-name C ABI for the transaction boundary (see the
/// crate-level `unsafe` confinement note).
pub mod ffi {
    #![allow(unsafe_code)]
    use super::{
        RdContext, API_VERSION, RD_ERR_NULL, RD_ERR_PANIC, RD_ERR_RANGE, RD_ERR_SMALL, RD_OK,
    };
    use rounddance_hal_host::scenario::{run_first_transaction, ScenarioConfig};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    /// ABI version (no context needed).
    #[unsafe(no_mangle)]
    pub extern "C" fn rd_api_version() -> u32 {
        API_VERSION
    }

    /// Run the first transaction to completion and store the outcome
    /// in a new context. `*out` receives the handle on [`RD_OK`].
    ///
    /// # Safety
    ///
    /// `ctx` must be a live handle from `rd_create` (or null,
    /// where documented); every out-pointer must point to
    /// caller-owned writable memory of the documented size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_create(out: *mut *mut RdContext) -> i32 {
        if out.is_null() {
            return RD_ERR_NULL;
        }
        match catch_unwind(|| {
            let outcome = run_first_transaction(ScenarioConfig::first_transaction());
            Box::new(RdContext { outcome })
        }) {
            Ok(ctx) => {
                // SAFETY: `out` is non-null (checked above) and points
                // to caller-owned writable memory for one pointer.
                unsafe {
                    *out = Box::into_raw(ctx);
                }
                RD_OK
            }
            Err(_) => RD_ERR_PANIC,
        }
    }

    /// Release a context created by [`rd_create`]. Null-tolerant
    /// (no-op returning nothing, like `free(NULL)`).
    ///
    /// # Safety
    ///
    /// `ctx` must be a live handle from `rd_create` (or null,
    /// where documented); every out-pointer must point to
    /// caller-owned writable memory of the documented size.
    /// Null is a documented no-op.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_destroy(ctx: *mut RdContext) {
        if ctx.is_null() {
            return;
        }
        let _ = catch_unwind(|| {
            // SAFETY: non-null (checked); every non-null handle comes
            // from `Box::into_raw` in `rd_create` and is destroyed at
            // most once by contract (mirrors `free` ownership).
            unsafe {
                drop(Box::from_raw(ctx));
            }
        });
    }

    /// Read one `u32` decision field out of the context.
    fn get_u32(ctx: *const RdContext, out: *mut u32, pick: impl FnOnce(&RdContext) -> u32) -> i32 {
        if ctx.is_null() || out.is_null() {
            return RD_ERR_NULL;
        }
        // `AssertUnwindSafe`: a panic here would be caught and mapped
        // to `RD_ERR_PANIC`; the closure only reads caller memory and
        // holds no lock or invariant that a panic could corrupt.
        match catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: both pointers are non-null (checked); `ctx`
            // points to a live `rd_create` outcome (caller contract),
            // `out` to caller-owned writable memory for one `u32`.
            // The closure only reads.
            unsafe { pick(&*ctx) }
        })) {
            Ok(v) => {
                // SAFETY: `out` non-null, caller-owned, one `u32`.
                unsafe {
                    *out = v;
                }
                RD_OK
            }
            Err(_) => RD_ERR_PANIC,
        }
    }

    /// High 32 bits of the decision digest.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live handle from `rd_create` (or null,
    /// where documented); every out-pointer must point to
    /// caller-owned writable memory of the documented size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_digest_hi(ctx: *const RdContext, out: *mut u32) -> i32 {
        get_u32(ctx, out, |c| (c.outcome.decisions.digest >> 32) as u32)
    }

    /// Low 32 bits of the decision digest.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live handle from `rd_create` (or null,
    /// where documented); every out-pointer must point to
    /// caller-owned writable memory of the documented size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_digest_lo(ctx: *const RdContext, out: *mut u32) -> i32 {
        get_u32(ctx, out, |c| c.outcome.decisions.digest as u32)
    }

    /// Coordinator formed the network (`formed`), as 0/1.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live handle from `rd_create` (or null,
    /// where documented); every out-pointer must point to
    /// caller-owned writable memory of the documented size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_formed(ctx: *const RdContext, out: *mut u32) -> i32 {
        get_u32(ctx, out, |c| u32::from(c.outcome.decisions.formed))
    }

    /// Trust Center verified the joiner (`tc_verified`), as 0/1.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live handle from `rd_create` (or null,
    /// where documented); every out-pointer must point to
    /// caller-owned writable memory of the documented size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_tc_verified(ctx: *const RdContext, out: *mut u32) -> i32 {
        get_u32(ctx, out, |c| u32::from(c.outcome.decisions.tc_verified))
    }

    /// Joiner completed admission (`joiner_joined`), as 0/1.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live handle from `rd_create` (or null,
    /// where documented); every out-pointer must point to
    /// caller-owned writable memory of the documented size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_joiner_joined(ctx: *const RdContext, out: *mut u32) -> i32 {
        get_u32(ctx, out, |c| u32::from(c.outcome.decisions.joiner_joined))
    }

    /// Device OnOff server state after the secured On, as 0/1.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live handle from `rd_create` (or null,
    /// where documented); every out-pointer must point to
    /// caller-owned writable memory of the documented size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_server_onoff(ctx: *const RdContext, out: *mut u32) -> i32 {
        get_u32(ctx, out, |c| u32::from(c.outcome.decisions.server_onoff))
    }

    /// Coordinator-decoded reported value (`reported_onoff`), as 0/1.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live handle from `rd_create` (or null,
    /// where documented); every out-pointer must point to
    /// caller-owned writable memory of the documented size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_reported_onoff(ctx: *const RdContext, out: *mut u32) -> i32 {
        get_u32(ctx, out, |c| u32::from(c.outcome.decisions.reported_onoff))
    }

    /// APS security bit seen on both secured frames, as 0/1.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live handle from `rd_create` (or null,
    /// where documented); every out-pointer must point to
    /// caller-owned writable memory of the documented size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_aps_security_on(ctx: *const RdContext, out: *mut u32) -> i32 {
        get_u32(ctx, out, |c| u32::from(c.outcome.decisions.aps_security_on))
    }

    /// Outgoing counter used for the ZCL On command.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live handle from `rd_create` (or null,
    /// where documented); every out-pointer must point to
    /// caller-owned writable memory of the documented size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_cmd_counter(ctx: *const RdContext, out: *mut u32) -> i32 {
        get_u32(ctx, out, |c| c.outcome.decisions.cmd_counter)
    }

    /// Outgoing counter used for the attribute report.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live handle from `rd_create` (or null,
    /// where documented); every out-pointer must point to
    /// caller-owned writable memory of the documented size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_report_counter(ctx: *const RdContext, out: *mut u32) -> i32 {
        get_u32(ctx, out, |c| c.outcome.decisions.report_counter)
    }

    /// Resume mark after the simulated reboot.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live handle from `rd_create` (or null,
    /// where documented); every out-pointer must point to
    /// caller-owned writable memory of the documented size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_resume_next(ctx: *const RdContext, out: *mut u32) -> i32 {
        get_u32(ctx, out, |c| c.outcome.decisions.resume_next)
    }

    /// ZCL transaction number used end to end.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live handle from `rd_create` (or null,
    /// where documented); every out-pointer must point to
    /// caller-owned writable memory of the documented size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_tsn(ctx: *const RdContext, out: *mut u32) -> i32 {
        get_u32(ctx, out, |c| u32::from(c.outcome.decisions.tsn))
    }

    /// Number of trace lines the run emitted.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live handle from `rd_create` (or null,
    /// where documented); every out-pointer must point to
    /// caller-owned writable memory of the documented size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_trace_lines(ctx: *const RdContext, out: *mut u32) -> i32 {
        get_u32(ctx, out, |c| {
            u32::try_from(c.outcome.trace.len()).unwrap_or(u32::MAX)
        })
    }

    /// Fetch trace line `index` as nul-free bytes: up to `buf_len`
    /// bytes are written with NO terminator, and `*out_len` always
    /// receives the full line length. Returns [`RD_ERR_SMALL`] when
    /// the buffer truncated the line.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live handle from `rd_create` (or null,
    /// where documented); every out-pointer must point to
    /// caller-owned writable memory of the documented size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_trace_line(
        ctx: *const RdContext,
        index: u32,
        buf: *mut u8,
        buf_len: usize,
        out_len: *mut usize,
    ) -> i32 {
        if ctx.is_null() || buf.is_null() || out_len.is_null() {
            return RD_ERR_NULL;
        }
        let result = catch_unwind(|| {
            // SAFETY: non-null (checked); `ctx` is a live `rd_create`
            // outcome, `buf`/`out_len` are caller-owned writable for
            // `buf_len` bytes / one `usize`. Read-only on `ctx`.
            unsafe {
                let c = &*ctx;
                let line = c.outcome.trace.get(index as usize).ok_or(RD_ERR_RANGE)?;
                let bytes = line.as_bytes();
                *out_len = bytes.len();
                let n = bytes.len().min(buf_len);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n);
                if n < bytes.len() {
                    return Err(RD_ERR_SMALL);
                }
                Ok(())
            }
        });
        match result {
            Ok(Ok(())) => RD_OK,
            Ok(Err(code)) => code,
            Err(_) => RD_ERR_PANIC,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_name_is_non_empty() {
        assert!(!name().is_empty());
    }
}
