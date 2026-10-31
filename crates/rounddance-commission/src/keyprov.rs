//! Build-time network-key provisioning (Phase 4 hardening: the fixed
//! lab test key must not be the only option).
//!
//! `RD_NETKEY_HEX` carries 32 lowercase-or-uppercase hex digits
//! (16 bytes, MSB first) baked in at firmware build time. This module
//! only parses + validates; the firmware wires `option_env!` around
//! it (see `fw/rd-coord`), so unset means the explicit lab default
//! with a build warning — never a silent mistype.
//!
//! `no_std` + `forbid(unsafe_code)`: byte arithmetic only.

/// Why a `RD_NETKEY_HEX` value was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetkeyHexError {
    /// Not exactly 32 hex digits (no `0x` prefix allowed).
    Len,
    /// Non-hex digit at the given byte index.
    Digit(usize),
}

/// Parse 32 hex digits into a 16-byte network key (MSB first).
///
/// # Errors
///
/// [`NetkeyHexError::Len`] when `s` is not exactly 32 digits;
/// [`NetkeyHexError::Digit`] naming the first bad index otherwise.
pub fn netkey_from_hex(s: &str) -> Result<[u8; 16], NetkeyHexError> {
    let b = s.as_bytes();
    if b.len() != 32 {
        return Err(NetkeyHexError::Len);
    }
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        let hi = hex_val(b[2 * i], 2 * i)?;
        let lo = hex_val(b[2 * i + 1], 2 * i + 1)?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Ok(out)
}

fn hex_val(c: u8, idx: usize) -> Result<u8, NetkeyHexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(NetkeyHexError::Digit(idx)),
    }
}

/// Const-eval twin for `option_env!` wiring in firmware: same grammar,
/// panics (compile error) on any refusal instead of returning it.
pub const fn parse_hex_netkey(s: &str) -> [u8; 16] {
    let b = s.as_bytes();
    assert!(b.len() == 32, "RD_NETKEY_HEX must be exactly 32 hex digits");
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = (hex_nibble(b[2 * i]) << 4) | hex_nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn hex_nibble(c: u8) -> u8 {
    assert!(
        (c >= b'0' && c <= b'9') || (c >= b'a' && c <= b'f') || (c >= b'A' && c <= b'F'),
        "RD_NETKEY_HEX holds only [0-9a-fA-F], no 0x prefix"
    );
    if c >= b'a' {
        c - b'a' + 10
    } else if c >= b'A' {
        c - b'A' + 10
    } else {
        c - b'0'
    }
}
