//! Per-run worker lease IDs: deterministic derivation, no calls.
//!
//! Live capture leases serial ports through the lab arbitrator (one
//! owner per port). The offline wave keeps the plumbing only: a run
//! stamps a lease ID derived purely from its inputs
//! (`worker`, `tag`, `channel`, run sequence) with FNV-1a 64, so
//! replays of the same inputs reproduce the same ID and distinct
//! runs never collide by construction of distinct inputs. No
//! arbitrator calls, no hardware, no network — the live worker
//! replaces this stub with a real lease without changing the report
//! shape (the ID is already a field).
//!
//! `no_std` + `#![forbid(unsafe_code)]`, no allocator: everything is
//! caller buffers and by-value integers.

/// FNV-1a 64 offset basis.
const FNV_OFFSET: u64 = 0xcbf29ce484222325;
/// FNV-1a 64 prime.
const FNV_PRIME: u64 = 0x100000001b3;

const fn mix(mut h: u64, b: u8) -> u64 {
    h ^= b as u64;
    h.wrapping_mul(FNV_PRIME)
}

/// Derive the lease ID for one offline run.
///
/// Pure function of (`worker`, `tag`, `channel`, `seq`): same inputs
/// always yield the same ID, so a replay reproduces the live run's
/// stamp. Field-separated with `0xff` (never valid UTF-8
/// continuation confusion: the separator byte cannot appear in the
/// UTF-8 encodings mixed here) so `("ab", "c")` and `("a", "bc")`
/// never alias.
#[must_use]
pub fn lease_id_for_run(worker: &str, tag: &str, channel: u8, seq: u32) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in worker.as_bytes() {
        h = mix(h, b);
    }
    h = mix(h, 0xff);
    for &b in tag.as_bytes() {
        h = mix(h, b);
    }
    h = mix(h, 0xff);
    h = mix(h, channel);
    for &b in &seq.to_le_bytes() {
        h = mix(h, b);
    }
    h
}

/// Lowercase hex rendering of a lease ID into a caller buffer (no
/// allocator): 16 ASCII hex chars, most-significant nibble first.
pub fn lease_id_hex(id: u64, out: &mut [u8; 16]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut i = 0;
    while i < 16 {
        out[i] = HEX[((id >> (60 - 4 * i)) & 0x0f) as usize];
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_input_sensitive() {
        let a = lease_id_for_run("w1-offline", "ch25", 25, 0);
        assert_eq!(a, lease_id_for_run("w1-offline", "ch25", 25, 0));
        assert_ne!(a, lease_id_for_run("w1-offline", "ch25", 20, 0));
        assert_ne!(a, lease_id_for_run("w1-offline", "ch20", 25, 0));
        assert_ne!(a, lease_id_for_run("w1-offline", "ch25", 25, 1));
        assert_ne!(a, lease_id_for_run("other-worker", "ch25", 25, 0));
        // Separator blocks cross-field aliasing.
        assert_ne!(
            lease_id_for_run("ab", "c", 25, 0),
            lease_id_for_run("a", "bc", 25, 0)
        );
    }

    #[test]
    fn hex_rendering_is_16_lowercase_nibbles() {
        let mut out = [0u8; 16];
        lease_id_hex(0x0123456789abcdef, &mut out);
        assert_eq!(&out, b"0123456789abcdef");
        let mut zero = [0u8; 16];
        lease_id_hex(0, &mut zero);
        assert_eq!(&zero, b"0000000000000000");
        let mut max = [0u8; 16];
        lease_id_hex(u64::MAX, &mut max);
        assert_eq!(&max, b"ffffffffffffffff");
    }
}
