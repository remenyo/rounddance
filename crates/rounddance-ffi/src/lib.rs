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

use rounddance_hal_esp::app::{CoordinatorApp, JoinerApp};
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
/// Verification / answer refused at the stack gate (bad frame,
/// replay, wrong cluster, bad status): the frame was counted,
/// never acted on.
pub const RD_ERR_VERIFY: i32 = 6;

/// Opaque coordinator context (owns a [`CoordinatorApp`]).
/// Opaque to C callers; nameable from Rust (integration tests).
pub struct RdCoord {
    app: CoordinatorApp,
}

/// Opaque joiner context (owns a [`JoinerApp`] over a leaked
/// zero-sized server definition — leaking a ZST allocates nothing,
/// so there is nothing to free on destroy).
/// Opaque to C callers; nameable from Rust (integration tests).
pub struct RdJoiner {
    app: JoinerApp<'static>,
}

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

/// Stable-name C ABI over the live ESP apps (join/toggle/poll).
/// Same `unsafe` confinement, panic policy, and status discipline
/// as [`ffi`]: null handles/pointers are statuses, never UB; panics
/// are caught at the boundary. A context that returns
/// [`RD_ERR_PANIC`] must be destroyed (its app may be half-mutated).
///
/// Outcome codes (`*out_kind`): 0 ignored/firewalled, 1 data
/// (`*out_a` = cluster, `*out_b` = profile), 2 transport accepted
/// (`*out_a` = aux counter), 3 node-descriptor request (`*out_a` =
/// source short, `*out_b` = `tsn << 16 | subject`), 4 NWK command
/// (`*out_a` = command id). The coordinator poll uses the same
/// codes, except 2 = announce (`*out_a` = short) and 3 = ZDO
/// response (`*out_a` = cluster, `*out_b` = `tsn << 8 | status`,
/// `0xFF` when absent).
pub mod apps_ffi {
    #![allow(unsafe_code)]
    pub use super::{RdCoord, RdJoiner};
    use super::{RD_ERR_NULL, RD_ERR_PANIC, RD_ERR_SMALL, RD_ERR_VERIFY, RD_OK};
    use rounddance_hal_esp::app::{
        AppError, CoordinatorApp, JoinerApp, JoinerNwkOutcome, NullLog, NwkRxOutcome,
    };
    use rounddance_security::{KeySet, NetworkKey};
    use rounddance_zcl::onoff;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn map_app_err(e: AppError) -> i32 {
        match e {
            AppError::BufferTooSmall => RD_ERR_SMALL,
            _ => RD_ERR_VERIFY,
        }
    }

    /// Create a coordinator context. `*out` receives the handle.
    ///
    /// # Safety
    ///
    /// `out` must point to caller-owned writable memory for one pointer.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_coord_create(out: *mut *mut RdCoord) -> i32 {
        if out.is_null() {
            return RD_ERR_NULL;
        }
        match catch_unwind(|| {
            Box::new(RdCoord {
                app: CoordinatorApp::new(),
            })
        }) {
            Ok(ctx) => {
                // SAFETY: `out` is non-null (checked) and caller-owned.
                unsafe {
                    *out = Box::into_raw(ctx);
                }
                RD_OK
            }
            Err(_) => RD_ERR_PANIC,
        }
    }

    /// Release a coordinator context. Null-tolerant.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live `rd_coord_create` handle or null.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_coord_destroy(ctx: *mut RdCoord) {
        if !ctx.is_null() {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                // SAFETY: live handle by contract; drops the box.
                unsafe {
                    drop(Box::from_raw(ctx));
                }
            }));
        }
    }

    /// Build one secured ZCL Toggle request (fresh TSN per call = new
    /// intent; a confirm-lost retry must REUSE bytes, never rebuild).
    /// `*out_n` receives the frame length (MAC + NWK-secured).
    ///
    /// # Safety
    ///
    /// `ctx` must be live; `key` must point to 16 readable bytes;
    /// `out` must be caller-owned writable for `out_len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_coord_build_toggle(
        ctx: *mut RdCoord,
        key: *const u8,
        out: *mut u8,
        out_len: usize,
        out_n: *mut usize,
    ) -> i32 {
        if ctx.is_null() || key.is_null() || out.is_null() || out_n.is_null() {
            return RD_ERR_NULL;
        }
        match catch_unwind(|| {
            // SAFETY: non-null (checked); `ctx` live, `key` 16
            // readable bytes, `out` writable for `out_len`.
            unsafe {
                let c = &mut *ctx;
                let mut k = [0u8; 16];
                std::ptr::copy_nonoverlapping(key, k.as_mut_ptr(), 16);
                let buf = std::slice::from_raw_parts_mut(out, out_len);
                let mut log = NullLog;
                c.app.new_toggle();
                match c.app.build_toggle_request(&mut log, &k, buf) {
                    Ok(n) => {
                        *out_n = n;
                        RD_OK
                    }
                    Err(e) => map_app_err(e),
                }
            }
        }) {
            Ok(code) => code,
            Err(_) => RD_ERR_PANIC,
        }
    }

    /// Verify a secured Default Response against the run key (`seq` =
    /// key sequence). `*out_ok` is 1 on verified toggle-success.
    ///
    /// # Safety
    ///
    /// `ctx` must be live; `key` 16 readable bytes; `msdu` readable
    /// for `msdu_len`; `out_ok` caller-owned writable.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_coord_verify_defrsp(
        ctx: *mut RdCoord,
        key: *const u8,
        seq: u8,
        msdu: *const u8,
        msdu_len: usize,
        out_ok: *mut u32,
    ) -> i32 {
        if ctx.is_null() || key.is_null() || msdu.is_null() || out_ok.is_null() {
            return RD_ERR_NULL;
        }
        match catch_unwind(|| {
            // SAFETY: non-null (checked) with the documented sizes.
            unsafe {
                let c = &mut *ctx;
                let mut k = [0u8; 16];
                std::ptr::copy_nonoverlapping(key, k.as_mut_ptr(), 16);
                let frame = std::slice::from_raw_parts(msdu, msdu_len);
                let keys = KeySet::new(NetworkKey::new(k, seq));
                let mut log = NullLog;
                *out_ok = 0;
                match c.app.verify_defrsp(&mut log, &keys, frame) {
                    Ok(true) => {
                        *out_ok = 1;
                        RD_OK
                    }
                    Ok(false) => RD_ERR_VERIFY,
                    Err(e) => map_app_err(e),
                }
            }
        }) {
            Ok(code) => code,
            Err(_) => RD_ERR_PANIC,
        }
    }

    /// Classify one inbound NWK frame on the coordinator (poll path).
    ///
    /// # Safety
    ///
    /// `ctx` must be live; `key` 16 readable bytes; `msdu` readable
    /// for `msdu_len`; out-pointers caller-owned writable.
    #[unsafe(no_mangle)]
    #[allow(clippy::too_many_arguments)]
    pub unsafe extern "C" fn rd_coord_poll(
        ctx: *mut RdCoord,
        key: *const u8,
        seq: u8,
        msdu: *const u8,
        msdu_len: usize,
        now_ms: u64,
        out_kind: *mut u32,
        out_a: *mut u32,
        out_b: *mut u32,
    ) -> i32 {
        if ctx.is_null()
            || key.is_null()
            || msdu.is_null()
            || out_kind.is_null()
            || out_a.is_null()
            || out_b.is_null()
        {
            return RD_ERR_NULL;
        }
        match catch_unwind(|| {
            // SAFETY: non-null (checked) with the documented sizes.
            unsafe {
                let c = &mut *ctx;
                let mut k = [0u8; 16];
                std::ptr::copy_nonoverlapping(key, k.as_mut_ptr(), 16);
                let frame = std::slice::from_raw_parts(msdu, msdu_len);
                let keys = KeySet::new(NetworkKey::new(k, seq));
                let (kind, a, b) = match c.app.on_nwk_data(frame, &keys, now_ms) {
                    NwkRxOutcome::Ignored(_) => (0, 0, 0),
                    NwkRxOutcome::Data { cluster, profile } => {
                        (1, u32::from(cluster), u32::from(profile))
                    }
                    NwkRxOutcome::Annce { short, .. } => (2, u32::from(short), 0),
                    NwkRxOutcome::ZdoResponse {
                        cluster,
                        tsn,
                        status,
                        ..
                    } => (
                        3,
                        u32::from(cluster),
                        (u32::from(tsn) << 8) | u32::from(status.unwrap_or(0xFF)),
                    ),
                    NwkRxOutcome::NwkCommand { id } => (4, u32::from(id), 0),
                };
                *out_kind = kind;
                *out_a = a;
                *out_b = b;
                RD_OK
            }
        }) {
            Ok(code) => code,
            Err(_) => RD_ERR_PANIC,
        }
    }

    /// Create a joiner context (lamp off, unkeyed).
    ///
    /// # Safety
    ///
    /// `out` must point to caller-owned writable memory for one pointer.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_joiner_create(out: *mut *mut RdJoiner) -> i32 {
        if out.is_null() {
            return RD_ERR_NULL;
        }
        match catch_unwind(AssertUnwindSafe(|| {
            // The server definition is zero-sized: leaking the box
            // allocates nothing and gives the app a `&'static`
            // reference, so there is nothing to free on destroy.
            let def: &'static onoff::ServerDef = Box::leak(Box::new(onoff::ServerDef));
            JoinerApp::new(def).map(|app| Box::new(RdJoiner { app }))
        })) {
            Ok(Ok(ctx)) => {
                // SAFETY: `out` is non-null (checked) and caller-owned.
                unsafe {
                    *out = Box::into_raw(ctx);
                }
                RD_OK
            }
            Ok(Err(_)) => RD_ERR_VERIFY,
            Err(_) => RD_ERR_PANIC,
        }
    }

    /// Open the scan window (surveys the app's lab channel).
    ///
    /// # Safety
    ///
    /// `ctx` must be live.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_joiner_begin_scan(ctx: *mut RdJoiner) -> i32 {
        if ctx.is_null() {
            return RD_ERR_NULL;
        }
        match catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: non-null (checked); `ctx` live.
            unsafe {
                let c = &mut *ctx;
                let mut log = NullLog;
                match c.app.begin_scan(&mut log) {
                    Ok(()) => RD_OK,
                    Err(e) => map_app_err(e),
                }
            }
        })) {
            Ok(code) => code,
            Err(_) => RD_ERR_PANIC,
        }
    }

    /// Ingest one beacon row (permit flag + capacities decide
    /// admission; channel/RSSI/LQI rank candidates).
    ///
    /// # Safety
    ///
    /// `ctx` must be live.
    #[unsafe(no_mangle)]
    #[allow(clippy::too_many_arguments)]
    pub unsafe extern "C" fn rd_joiner_ingest_beacon(
        ctx: *mut RdJoiner,
        pan: u16,
        channel: u8,
        lqi: u8,
        rssi: i8,
        permit: u8,
        router_capacity: u8,
        end_device_capacity: u8,
    ) -> i32 {
        if ctx.is_null() {
            return RD_ERR_NULL;
        }
        match catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: non-null (checked); `ctx` live.
            unsafe {
                use rounddance_commission::BeaconSurveyEntry;
                let c = &mut *ctx;
                let entry = BeaconSurveyEntry {
                    pan_id: pan,
                    channel,
                    lqi,
                    rssi,
                    permit_joining: permit != 0,
                    router_capacity: router_capacity != 0,
                    end_device_capacity: end_device_capacity != 0,
                    protocol_version: 2,
                };
                match c.app.ingest_beacon(entry) {
                    Ok(()) => RD_OK,
                    Err(_) => RD_ERR_VERIFY,
                }
            }
        })) {
            Ok(code) => code,
            Err(_) => RD_ERR_PANIC,
        }
    }

    /// Close the scan window: `*out_pan` is the elected PAN, or
    /// `0xFFFF` when nothing was electable.
    ///
    /// # Safety
    ///
    /// `ctx` must be live; `out_pan` caller-owned writable.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_joiner_finish_scan(ctx: *mut RdJoiner, out_pan: *mut u16) -> i32 {
        if ctx.is_null() || out_pan.is_null() {
            return RD_ERR_NULL;
        }
        match catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: non-null (checked) with the documented sizes.
            unsafe {
                let c = &mut *ctx;
                let mut log = NullLog;
                *out_pan = c.app.finish_scan(&mut log).unwrap_or(0xFFFF);
                RD_OK
            }
        })) {
            Ok(code) => code,
            Err(_) => RD_ERR_PANIC,
        }
    }

    /// Feed one inbound MAC PSDU (beacons feed the survey,
    /// association responses adopt the short). `*out_short` is the
    /// adopted short, or `0xFFFF` when none is held.
    ///
    /// # Safety
    ///
    /// `ctx` must be live; `psdu` readable for `psdu_len`;
    /// `out_short` caller-owned writable.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_joiner_on_mac(
        ctx: *mut RdJoiner,
        psdu: *const u8,
        psdu_len: usize,
        channel: u8,
        rssi: i8,
        lqi: u8,
        out_short: *mut u16,
    ) -> i32 {
        if ctx.is_null() || psdu.is_null() || out_short.is_null() {
            return RD_ERR_NULL;
        }
        match catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: non-null (checked) with the documented sizes.
            unsafe {
                let c = &mut *ctx;
                let frame = std::slice::from_raw_parts(psdu, psdu_len);
                let mut log = NullLog;
                let _ = c.app.on_mac_psdu(&mut log, frame, channel, rssi, lqi);
                *out_short = c.app.assoc_short().unwrap_or(0xFFFF);
                RD_OK
            }
        })) {
            Ok(code) => code,
            Err(_) => RD_ERR_PANIC,
        }
    }

    /// Release a joiner context. Null-tolerant.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live `rd_joiner_create` handle or null.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_joiner_destroy(ctx: *mut RdJoiner) {
        if !ctx.is_null() {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                // SAFETY: live handle by contract; drops the box.
                unsafe {
                    drop(Box::from_raw(ctx));
                }
            }));
        }
    }

    /// Classify one inbound NWK frame on the joiner (poll path).
    ///
    /// # Safety
    ///
    /// `ctx` must be live; `msdu` readable for `msdu_len`;
    /// out-pointers caller-owned writable.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_joiner_feed(
        ctx: *mut RdJoiner,
        msdu: *const u8,
        msdu_len: usize,
        out_kind: *mut u32,
        out_a: *mut u32,
        out_b: *mut u32,
    ) -> i32 {
        if ctx.is_null()
            || msdu.is_null()
            || out_kind.is_null()
            || out_a.is_null()
            || out_b.is_null()
        {
            return RD_ERR_NULL;
        }
        match catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: non-null (checked) with the documented sizes.
            unsafe {
                let c = &mut *ctx;
                let frame = std::slice::from_raw_parts(msdu, msdu_len);
                let (kind, a, b) = match c.app.on_nwk_joiner(frame) {
                    JoinerNwkOutcome::Ignored(_) => (0, 0, 0),
                    JoinerNwkOutcome::Data { cluster, profile } => {
                        (1, u32::from(cluster), u32::from(profile))
                    }
                    JoinerNwkOutcome::TransportAccepted { auxctr } => (2, auxctr, 0),
                    JoinerNwkOutcome::NodeDescReq {
                        src_short,
                        tsn,
                        subject,
                    } => (
                        3,
                        u32::from(src_short),
                        (u32::from(tsn) << 16) | u32::from(subject),
                    ),
                    JoinerNwkOutcome::NwkCommand { id } => (4, u32::from(id), 0),
                };
                *out_kind = kind;
                *out_a = a;
                *out_b = b;
                RD_OK
            }
        })) {
            Ok(code) => code,
            Err(_) => RD_ERR_PANIC,
        }
    }

    /// Answer an already-classified Toggle request (`answer_toggle`
    /// path: no replay re-check, same-TSN duplicates re-seal without
    /// re-flipping). `*out_n` receives the DefRsp frame length.
    ///
    /// # Safety
    ///
    /// `ctx` must be live; `msdu` readable for `msdu_len`; `out`
    /// caller-owned writable for `out_len`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_joiner_answer(
        ctx: *mut RdJoiner,
        msdu: *const u8,
        msdu_len: usize,
        out: *mut u8,
        out_len: usize,
        out_n: *mut usize,
    ) -> i32 {
        if ctx.is_null() || msdu.is_null() || out.is_null() || out_n.is_null() {
            return RD_ERR_NULL;
        }
        match catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: non-null (checked) with the documented sizes.
            unsafe {
                let c = &mut *ctx;
                let frame = std::slice::from_raw_parts(msdu, msdu_len);
                let buf = std::slice::from_raw_parts_mut(out, out_len);
                let mut log = NullLog;
                match c.app.answer_toggle(&mut log, frame, buf) {
                    Ok(n) => {
                        *out_n = n;
                        RD_OK
                    }
                    Err(e) => map_app_err(e),
                }
            }
        })) {
            Ok(code) => code,
            Err(_) => RD_ERR_PANIC,
        }
    }

    /// Lamp state: `*out` is 1 when on. Never fails on a live handle.
    ///
    /// # Safety
    ///
    /// `ctx` must be a live `rd_joiner_create` handle; `out`
    /// caller-owned writable.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rd_joiner_lamp(ctx: *const RdJoiner, out: *mut u32) -> i32 {
        if ctx.is_null() || out.is_null() {
            return RD_ERR_NULL;
        }
        match catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: non-null (checked); read-only on `ctx`.
            unsafe {
                *out = u32::from((*ctx).app.lamp());
                RD_OK
            }
        })) {
            Ok(code) => code,
            Err(_) => RD_ERR_PANIC,
        }
    }
}
