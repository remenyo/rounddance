//! Generic NWK-secured data frame builder (Phase 1 response legs).
//!
//! Unlike [`crate::transport`] (NWK-open + APS-sealed transport-key
//! delivery), normal post-join traffic is NWK-secured with the network
//! key and APS-open: 9-octet MAC data header, 8-octet NWK data header
//! (no extended addresses, no source route), 14-octet NWK auxiliary
//! header (control `0x28` on air: level zeroed, key-id mode 1 =
//! network-key Index, extended nonce set), then the CCM* tail
//! (caller-built APS plaintext + MIC-32) sealed under the network key.
//! Nonce (13): source EUI (as on air, LE) + aux counter LE + restored
//! control `0x2D`; AAD = NWK header + restored aux (key sequence
//! included — the w97 AAD lesson).
//!
//! `no_std` + `forbid(unsafe_code)`: caller buffers, lengths checked
//! before any indexing. The network key passed in is the
//! coordinator's deployment-owned key; tests use synthetic keys.
//! Frame-counter management stays with the caller (one counter space
//! per sender per key); this builder only encodes `auxctr`.

use rounddance_nwk::{FrameControl, NwkHeader};
use rounddance_security::{
    ccm_star_seal_into, AuxHeader, CcmError, KeyIdMode, KeyIdentifier, SecError, SecurityControl,
    CCM_NONCE_LEN,
};

/// Largest APS plaintext this builder seals (covers a ZDO request
/// with margin; longer payloads are a later leg).
pub const SECURED_PT_MAX: usize = 96;
/// Full secured MAC PSDU length bound: 9 MAC + 8 NWK + 14 aux +
/// 96 plaintext + 4 MIC.
pub const SECURED_FRAME_MAX: usize = 131;
/// Restored NWK security-control level (base level 5; the sender
/// zeroes the on-air level bits, the receiver restores).
pub const SECURED_LEVEL: u8 = 5;
/// Network-key sequence carried in the auxiliary header.
pub const SECURED_SEQ_NO: u8 = 0x00;

/// Parameters for one NWK-secured data frame.
#[derive(Clone, Copy, Debug)]
pub struct SecuredNwkParams {
    /// Destination PAN.
    pub dst_pan: u16,
    /// Destination short.
    pub dst_short: u16,
    /// Coordinator source short (normally 0x0000).
    pub src_short: u16,
    /// Source long address, as on air (LSB-first wire order).
    pub src_eui: [u8; 8],
    /// MAC sequence octet.
    pub mac_seq: u8,
    /// NWK sequence octet.
    pub nwk_seq: u8,
    /// NWK hop budget.
    pub nwk_radius: u8,
    /// Auxiliary frame counter (anti-replay; strictly monotonic per key).
    pub auxctr: u32,
    /// Network key to seal under (deployment-owned).
    pub netkey: [u8; 16],
}

/// Failure building the secured frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecuredError {
    /// Caller buffer holds fewer than the encoded frame, or the APS
    /// plaintext exceeds [`SECURED_PT_MAX`] octets.
    TooSmall,
    /// Auxiliary header inconsistent (shape refusal, never sent).
    Aux(SecError),
    /// NWK header encode refusal.
    Nwk,
    /// CCM* seal refusal.
    Seal(CcmError),
}

/// Build one NWK-secured data frame carrying `aps_pt` (already-built
/// APS frame: header + payload) into `out`; returns bytes written.
///
/// # Errors
///
/// [`SecuredError::TooSmall`] when `out` is short or `aps_pt` exceeds
/// [`SECURED_PT_MAX`]; the aux/NWK/seal arms on inconsistent inputs
/// (never partially written).
pub fn build_secured_nwk_frame(
    aps_pt: &[u8],
    p: &SecuredNwkParams,
    out: &mut [u8],
) -> Result<usize, SecuredError> {
    if aps_pt.len() > SECURED_PT_MAX {
        return Err(SecuredError::TooSmall);
    }
    let total = 9 + 8 + 14 + aps_pt.len() + 4;
    if out.len() < total {
        return Err(SecuredError::TooSmall);
    }
    // Restored aux (AAD + nonce): control 0x2D, counter LE, src EUI.
    let aux_restored = AuxHeader {
        control: SecurityControl::new(SECURED_LEVEL, KeyIdMode::Index, true)
            .ok_or(SecuredError::Aux(SecError::BadKeyIdMode))?,
        frame_counter: p.auxctr,
        ext_source: Some(p.src_eui),
        key_id: KeyIdentifier::Index(SECURED_SEQ_NO),
    };
    let mut rbuf = [0u8; 14];
    let rlen = aux_restored
        .encode_into(&mut rbuf)
        .map_err(SecuredError::Aux)?;
    debug_assert_eq!(rlen, 14);
    // NWK header (data, secured, no extended addresses).
    let nwk = NwkHeader {
        control: FrameControl {
            frame_type: rounddance_nwk::FrameType::Data,
            protocol_version: rounddance_nwk::NWKC_PROTOCOL_VERSION,
            discover_route: rounddance_nwk::DiscoverRoute::Suppress,
            multicast: false,
            security: true,
            source_route: false,
            dst_ieee: false,
            src_ieee: false,
            end_device_initiator: false,
        },
        dst_addr: p.dst_short,
        src_addr: p.src_short,
        radius: p.nwk_radius,
        seq: p.nwk_seq,
        dst_ieee: None,
        src_ieee: None,
        source_route: None,
    };
    let mut hdr_buf = [0u8; 8];
    let hlen = nwk
        .encode_into(&[], &mut hdr_buf)
        .map_err(|_| SecuredError::Nwk)?;
    debug_assert_eq!(hlen, 8);
    // On-air aux (level zeroed) + seal.
    let aux_open = AuxHeader {
        control: SecurityControl::new(0, KeyIdMode::Index, true)
            .ok_or(SecuredError::Aux(SecError::BadKeyIdMode))?,
        frame_counter: p.auxctr,
        ext_source: Some(p.src_eui),
        key_id: KeyIdentifier::Index(SECURED_SEQ_NO),
    };
    let mut aux_buf = [0u8; 14];
    let alen = aux_open
        .encode_into(&mut aux_buf)
        .map_err(SecuredError::Aux)?;
    debug_assert_eq!(alen, 14);
    let mut aad = [0u8; 22];
    aad[..8].copy_from_slice(&hdr_buf);
    aad[8..22].copy_from_slice(&rbuf[..rlen]);
    let mut nonce = [0u8; CCM_NONCE_LEN];
    nonce[..8].copy_from_slice(&p.src_eui);
    nonce[8..12].copy_from_slice(&p.auxctr.to_le_bytes());
    nonce[12] = 0x2d;
    let tail_at = 9 + 8 + 14;
    let sealed_len = ccm_star_seal_into(&p.netkey, &nonce, &aad, aps_pt, &mut out[tail_at..])
        .map_err(SecuredError::Seal)?;
    // MAC data header: `61 88`, intra-PAN short/short.
    out[0] = 0x61;
    out[1] = 0x88;
    out[2] = p.mac_seq;
    out[3..5].copy_from_slice(&p.dst_pan.to_le_bytes());
    out[5..7].copy_from_slice(&p.dst_short.to_le_bytes());
    out[7..9].copy_from_slice(&p.src_short.to_le_bytes());
    out[9..17].copy_from_slice(&hdr_buf);
    out[17..31].copy_from_slice(&aux_buf);
    Ok(9 + 8 + 14 + sealed_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rounddance_security::{ccm_star_open_into, CCM_TAG_LEN};

    const KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];

    fn params() -> SecuredNwkParams {
        SecuredNwkParams {
            dst_pan: 0xC601,
            dst_short: 0x0002,
            src_short: 0x0000,
            src_eui: [0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0],
            mac_seq: 0x5a,
            nwk_seq: 0x21,
            nwk_radius: 0x1e,
            auxctr: 0x0000_2000,
            netkey: KEY,
        }
    }

    #[test]
    fn roundtrip_opens_with_network_key() {
        let pt = [
            0x00u8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07, 0x0a, 0x02, 0x00,
        ];
        let mut out = [0u8; SECURED_FRAME_MAX];
        let n = build_secured_nwk_frame(&pt, &params(), &mut out).unwrap();
        assert_eq!(n, 9 + 8 + 14 + pt.len() + CCM_TAG_LEN);
        assert_eq!(
            &out[..9],
            &[0x61, 0x88, 0x5a, 0x01, 0xc6, 0x02, 0x00, 0x00, 0x00]
        );
        assert_eq!(out[17], 0x28);
        assert_eq!(out[30], 0x00);
        let ct_end = n - CCM_TAG_LEN;
        let mut tag = [0u8; CCM_TAG_LEN];
        tag.copy_from_slice(&out[ct_end..n]);
        let mut aad = [0u8; 22];
        aad[..8].copy_from_slice(&out[9..17]);
        aad[8] = 0x2d;
        aad[9..13].copy_from_slice(&out[18..22]);
        aad[13..21].copy_from_slice(&params().src_eui);
        aad[21] = 0x00;
        let mut nonce = [0u8; 13];
        nonce[..8].copy_from_slice(&params().src_eui);
        nonce[8..12].copy_from_slice(&0x0000_2000u32.to_le_bytes());
        nonce[12] = 0x2d;
        let mut back = [0u8; 96];
        let m = ccm_star_open_into(&KEY, &nonce, &aad, &out[31..ct_end], &tag, &mut back).unwrap();
        assert_eq!(&back[..m], &pt);
    }

    #[test]
    fn rejects_oversize_and_short_buffers() {
        let big = [0u8; SECURED_PT_MAX + 1];
        let mut out = [0u8; SECURED_FRAME_MAX];
        assert_eq!(
            build_secured_nwk_frame(&big, &params(), &mut out),
            Err(SecuredError::TooSmall)
        );
        let mut tiny = [0u8; 16];
        assert_eq!(
            build_secured_nwk_frame(&[0x00], &params(), &mut tiny),
            Err(SecuredError::TooSmall)
        );
    }
}
