//! Decision pin: the browser bundle's getters must return exactly
//! the native first-transaction decisions (digest pinned from the
//! wave-15 host run). Any stack change that moves these values must
//! update the pin, `harness/browser/index.html`, and
//! `harness/browser/expected.txt` together.

use rounddance_browser::exports::{
    rd_aps_security_on, rd_cmd_counter, rd_digest_hi, rd_digest_lo, rd_formed, rd_joiner_joined,
    rd_report_counter, rd_reported_onoff, rd_resume_next, rd_server_onoff, rd_tc_verified,
    rd_trace_lines, rd_tsn,
};

/// Native-pinned digest of the canonical first transaction.
const PIN_DIGEST: u64 = 0x3ea31047e1933c90;

#[test]
fn browser_getters_match_native_pin() {
    let digest = (u64::from(rd_digest_hi()) << 32) | u64::from(rd_digest_lo());
    assert_eq!(digest, PIN_DIGEST, "digest moved — see module docs");
    assert_eq!(rd_formed(), 1);
    assert_eq!(rd_tc_verified(), 1);
    assert_eq!(rd_joiner_joined(), 1);
    assert_eq!(rd_server_onoff(), 1);
    assert_eq!(rd_reported_onoff(), 1);
    assert_eq!(rd_aps_security_on(), 1);
    assert_eq!(rd_cmd_counter(), 1024);
    assert_eq!(rd_report_counter(), 1025);
    assert_eq!(rd_resume_next(), 1024);
    assert_eq!(rd_tsn(), 0x64);
    assert_eq!(rd_trace_lines(), 35);
}
