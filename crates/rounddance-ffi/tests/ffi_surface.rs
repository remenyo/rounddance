//! FFI boundary tests: drive the exported `extern "C"` surface
//! through raw pointers (as a C caller would) and assert
//! decision-match against the native scenario.

use rounddance_ffi::ffi;
use rounddance_hal_host::scenario::{run_first_transaction, ScenarioConfig};

fn get(
    ctx: *const rounddance_ffi::RdContext,
    f: unsafe extern "C" fn(*const rounddance_ffi::RdContext, *mut u32) -> i32,
) -> u32 {
    let mut v = 0u32;
    // SAFETY: `ctx` is a live handle from `rd_create` (or null in the
    // null tests, where the call must return RD_ERR_NULL without
    // touching memory); `&mut v` is owned writable for one `u32`.
    let rc = unsafe { f(ctx, &mut v) };
    assert_eq!(rc, rounddance_ffi::RD_OK);
    v
}

#[test]
fn ffi_decisions_match_native() {
    let mut ctx: *mut rounddance_ffi::RdContext = std::ptr::null_mut();
    // SAFETY: `&mut ctx` is owned writable for one pointer.
    let rc = unsafe { ffi::rd_create(&mut ctx) };
    assert_eq!(rc, rounddance_ffi::RD_OK);
    assert!(!ctx.is_null());

    let native = run_first_transaction(ScenarioConfig::first_transaction());
    let d = &native.decisions;
    assert_eq!(get(ctx, ffi::rd_digest_hi), (d.digest >> 32) as u32);
    assert_eq!(get(ctx, ffi::rd_digest_lo), d.digest as u32);
    assert_eq!(get(ctx, ffi::rd_formed), u32::from(d.formed));
    assert_eq!(get(ctx, ffi::rd_tc_verified), u32::from(d.tc_verified));
    assert_eq!(get(ctx, ffi::rd_joiner_joined), u32::from(d.joiner_joined));
    assert_eq!(get(ctx, ffi::rd_server_onoff), u32::from(d.server_onoff));
    assert_eq!(
        get(ctx, ffi::rd_reported_onoff),
        u32::from(d.reported_onoff)
    );
    assert_eq!(
        get(ctx, ffi::rd_aps_security_on),
        u32::from(d.aps_security_on)
    );
    assert_eq!(get(ctx, ffi::rd_cmd_counter), d.cmd_counter);
    assert_eq!(get(ctx, ffi::rd_report_counter), d.report_counter);
    assert_eq!(get(ctx, ffi::rd_resume_next), d.resume_next);
    assert_eq!(get(ctx, ffi::rd_tsn), u32::from(d.tsn));
    assert_eq!(get(ctx, ffi::rd_trace_lines), native.trace.len() as u32);

    // Trace lines round-trip byte-exact through the nul-free getter.
    let mut buf = vec![0u8; 4096];
    let mut total = 0usize;
    for (i, want) in native.trace.iter().enumerate() {
        let mut len = 0usize;
        // SAFETY: live handle; `buf` owned writable; `len` owned.
        let rc =
            unsafe { ffi::rd_trace_line(ctx, i as u32, buf.as_mut_ptr(), buf.len(), &mut len) };
        assert_eq!(rc, rounddance_ffi::RD_OK);
        assert_eq!(len, want.len());
        assert_eq!(&buf[..len], want.as_bytes());
        total += len;
    }
    assert!(total > 0, "trace must be non-empty");

    // SAFETY: handle from `rd_create`, destroyed exactly once.
    unsafe {
        ffi::rd_destroy(ctx);
    }
}

#[test]
fn ffi_null_and_range_errors_are_statuses() {
    let mut v = 0u32;
    // SAFETY: null handle / null out-pointer must return RD_ERR_NULL
    // without dereferencing.
    unsafe {
        assert_eq!(
            ffi::rd_digest_hi(std::ptr::null(), &mut v),
            rounddance_ffi::RD_ERR_NULL
        );
        assert_eq!(
            ffi::rd_digest_hi(std::ptr::null(), std::ptr::null_mut()),
            rounddance_ffi::RD_ERR_NULL
        );
        assert_eq!(
            ffi::rd_create(std::ptr::null_mut()),
            rounddance_ffi::RD_ERR_NULL
        );
        ffi::rd_destroy(std::ptr::null_mut());
    }

    let mut ctx: *mut rounddance_ffi::RdContext = std::ptr::null_mut();
    // SAFETY: as above; valid out-pointer.
    let rc = unsafe { ffi::rd_create(&mut ctx) };
    assert_eq!(rc, rounddance_ffi::RD_OK);
    // SAFETY: live handle with a valid out-pointer must report NULL.
    unsafe {
        assert_eq!(
            ffi::rd_cmd_counter(ctx, std::ptr::null_mut()),
            rounddance_ffi::RD_ERR_NULL
        );
    }

    // Out-of-range trace index is RD_ERR_RANGE.
    let mut buf = [0u8; 16];
    let mut len = 0usize;
    // SAFETY: live handle; owned buffers.
    let rc = unsafe { ffi::rd_trace_line(ctx, u32::MAX, buf.as_mut_ptr(), buf.len(), &mut len) };
    assert_eq!(rc, rounddance_ffi::RD_ERR_RANGE);

    // Small buffer writes the prefix and reports RD_ERR_SMALL with the
    // full length for retry sizing.
    let mut lines = 0u32;
    // SAFETY: live handle; owned out.
    assert_eq!(
        unsafe { ffi::rd_trace_lines(ctx, &mut lines) },
        rounddance_ffi::RD_OK
    );
    assert!(lines > 0);
    // SAFETY: live handle; owned buffers; 1-byte buffer must truncate.
    let rc = unsafe { ffi::rd_trace_line(ctx, 0, buf.as_mut_ptr(), 1, &mut len) };
    assert_eq!(rc, rounddance_ffi::RD_ERR_SMALL);
    assert!(len > 1);

    // SAFETY: handle destroyed exactly once.
    unsafe {
        ffi::rd_destroy(ctx);
    }
}
