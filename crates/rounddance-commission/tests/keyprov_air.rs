//! Phase 4: build-time network-key provisioning pins (head-side).
//! Synthetic vectors only — no lab key material in repo tests.
use rounddance_commission::{netkey_from_hex, parse_hex_netkey, NetkeyHexError};

#[test]
fn parses_lower_upper_and_rejects() {
    assert_eq!(
        netkey_from_hex("000102030405060708090a0b0c0d0e0f"),
        Ok([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f
        ])
    );
    assert_eq!(
        netkey_from_hex("DEADBEEFCAFEBABE0123456789ABCDEF"),
        Ok([
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef
        ])
    );
    assert_eq!(netkey_from_hex(""), Err(NetkeyHexError::Len));
    assert_eq!(
        netkey_from_hex("000102030405060708090a0b0c0d0e0"),
        Err(NetkeyHexError::Len)
    );
    assert_eq!(
        netkey_from_hex("000102030405060708090a0b0c0d0e0f00"),
        Err(NetkeyHexError::Len)
    );
    assert_eq!(
        netkey_from_hex("zz0102030405060708090a0b0c0d0e0f"),
        Err(NetkeyHexError::Digit(0))
    );
    assert_eq!(
        netkey_from_hex("000102030405060708090a0b0c0d0e0g"),
        Err(NetkeyHexError::Digit(31))
    );
    assert_eq!(
        netkey_from_hex("0x000102030405060708090a0b0c0d0e0f"),
        Err(NetkeyHexError::Len)
    );
    // Const-eval twin agrees with the runtime parser (fw uses the const
    // one inside `option_env!`, same grammar or compile failure).
    assert_eq!(
        parse_hex_netkey("000102030405060708090a0b0c0d0e0f"),
        netkey_from_hex("000102030405060708090a0b0c0d0e0f").unwrap()
    );
    assert_eq!(
        parse_hex_netkey("DEADBEEFCAFEBABE0123456789ABCDEF"),
        netkey_from_hex("deadbeefcafebabe0123456789abcdef").unwrap()
    );
}
