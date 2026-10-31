//! Trust-Center network-key transport frame builder (proactive leg).
//!
//! Builds the exact on-air shape a real Ember NCP answers with the
//! network key to (w93 MG21 reference: `NETWORK_UP` after the
//! equivalent frame): 9-octet MAC data header, 8-octet unsecured
//! NWK data header, 2-octet APS command header, 13-octet auxiliary
//! header (control `0x30` on air: level zeroed, key-id bits 2 =
//! key-transport key, extended nonce set), then the 39-octet CCM*
//! tail (35-octet plaintext + MIC-32) sealed under the key-transport
//! key derived from the preconfigured link key.
//!
//! Plaintext (35 octets): `05 01 <network-key:16> <seq 0x00>
//! <dst joiner-EUI:8> <src TC-EUI:8>` — transport-key command,
//! network key type, per the w45 offline open (all five A-frames).
//! Nonce (13): source EUI (as on air, LE) + aux counter LE +
//! restored control `0x35`; AAD = APS header + restored aux.
//!
//! `no_std` + `forbid(unsafe_code)`: caller buffers, lengths checked
//! before any indexing. The network key passed in is the
//! coordinator's own lab key (deployment-owned); test vectors use a
//! distinct synthetic key.

use rounddance_nwk::{FrameControl, NwkHeader};
use rounddance_security::{
    ccm_star_seal_into, derive_key_transport_key, AuxHeader, CcmError, KeyIdMode, KeyIdentifier,
    SecError, SecurityControl, CCM_NONCE_LEN,
};

/// Well-known HA preconfigured link key (`"ZigBeeAlliance09"`):
/// public default, never a secret. Joiners provisioned with it
/// derive the same key-transport key and open our delivery.
pub const HA_LINK_KEY: [u8; 16] = [
    0x5A, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6C, 0x6C, 0x69, 0x61, 0x6E, 0x63, 0x65, 0x30, 0x39,
];

/// Starting auxiliary frame counter for transport delivery.
/// Fresh key per deployment makes reboot reuse harmless; production
/// must persist the counter (NVM) and randomize the network key.
pub const TRANSPORT_AUX_BASE: u32 = 0x0000_1000;

/// Full transport-key MAC PSDU length: 9 MAC + 8 NWK + 2 APS + 13
/// aux + 35 plaintext + 4 MIC.
pub const TRANSPORT_FRAME_LEN: usize = 71;

/// Sealed tail length: 35-octet plaintext + MIC-32.
pub const TRANSPORT_TAIL_LEN: usize = 39;

/// Transport-key command id (`0x05`) and network-key key type
/// (`0x01`): the pair the joiner waits on.
pub const TRANSPORT_CMD: u8 = 0x05;
/// Network key type octet inside the transport-key command.
pub const TRANSPORT_KEY_TYPE_NETWORK: u8 = 0x01;

/// Parameters for one Trust-Center→joiner transport-key frame.
#[derive(Clone, Copy, Debug)]
pub struct TransportKeyParams {
    /// Destination PAN + assigned joiner short.
    pub dst_pan: u16,
    /// Destination short (assigned at association).
    pub dst_short: u16,
    /// Destination joiner long address, as on air (LSB-first).
    pub dst_eui: [u8; 8],
    /// Source coordinator (Trust Center) long address, as on air
    /// (LSB-first).
    pub src_eui: [u8; 8],
    /// MAC sequence octet.
    pub mac_seq: u8,
    /// NWK sequence octet.
    pub nwk_seq: u8,
    /// NWK hop budget.
    pub nwk_radius: u8,
    /// APS frame counter octet.
    pub aps_ctr: u8,
    /// Auxiliary frame counter (anti-replay; strictly monotonic per key).
    pub auxctr: u32,
    /// Key sequence octet carried in the plaintext (0x00 = initial key).
    pub seq_no: u8,
    /// Coordinator's network key to deliver (deployment-owned).
    pub netkey: [u8; 16],
    /// Key-transport key (from [`derive_key_transport_key`]).
    pub transport_key: [u8; 16],
}

/// Failure building the transport-key frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// Caller buffer holds fewer than [`TRANSPORT_FRAME_LEN`] octets.
    TooSmall,
    /// Auxiliary header inconsistent (shape refusal, never sent).
    Aux(SecError),
    /// NWK header encode refusal.
    Nwk,
    /// CCM* seal refusal.
    Seal(CcmError),
}

/// Derive the key-transport key for the HA preconfigured link key.
pub fn ha_transport_key() -> Result<[u8; 16], SecError> {
    derive_key_transport_key(&HA_LINK_KEY).map_err(|_| SecError::BadKeyIdMode)
}

/// Build one Trust-Center→joiner transport-key frame into `out` (71
/// octets); returns bytes written.
///
/// # Errors
///
/// [`TransportError::TooSmall`] when `out` is short; the aux/NWK/seal
/// arms on inconsistent inputs (never partially written).
pub fn build_transport_key_frame(
    p: &TransportKeyParams,
    out: &mut [u8],
) -> Result<usize, TransportError> {
    if out.len() < TRANSPORT_FRAME_LEN {
        return Err(TransportError::TooSmall);
    }
    // Plaintext (35): cmd, key type, key, seq, dst EUI, src EUI.
    let mut pt = [0u8; 35];
    pt[0] = TRANSPORT_CMD;
    pt[1] = TRANSPORT_KEY_TYPE_NETWORK;
    pt[2..18].copy_from_slice(&p.netkey);
    pt[18] = p.seq_no;
    pt[19..27].copy_from_slice(&p.dst_eui);
    pt[27..35].copy_from_slice(&p.src_eui);
    // Restored aux (AAD + nonce): control 0x35, counter LE, src EUI.
    let restored = [
        0x35,
        p.auxctr as u8,
        (p.auxctr >> 8) as u8,
        (p.auxctr >> 16) as u8,
        (p.auxctr >> 24) as u8,
    ];
    let mut aux_restored = [0u8; 13];
    aux_restored[0] = restored[0];
    aux_restored[1..5].copy_from_slice(&restored[1..]);
    aux_restored[5..13].copy_from_slice(&p.src_eui);
    let aps_hdr = [0x21u8, p.aps_ctr];
    let mut aad = [0u8; 15];
    aad[..2].copy_from_slice(&aps_hdr);
    aad[2..].copy_from_slice(&aux_restored);
    let mut nonce = [0u8; CCM_NONCE_LEN];
    nonce[..8].copy_from_slice(&p.src_eui);
    nonce[8..12].copy_from_slice(&p.auxctr.to_le_bytes());
    nonce[12] = 0x35;
    // Seal into the tail region.
    let mut tail = [0u8; TRANSPORT_TAIL_LEN];
    ccm_star_seal_into(&p.transport_key, &nonce, &aad, &pt, &mut tail)
        .map_err(TransportError::Seal)?;
    // Assemble APS payload: header + on-air aux + sealed tail.
    let mut aps = [0u8; 54];
    aps[..2].copy_from_slice(&aps_hdr);
    let aux = AuxHeader {
        control: SecurityControl::new(0, KeyIdMode::Source4, true)
            .ok_or(TransportError::Aux(SecError::BadKeyIdMode))?,
        frame_counter: p.auxctr,
        ext_source: Some(p.src_eui),
        key_id: KeyIdentifier::TransportKey,
    };
    let aux_len = aux
        .encode_into(&mut aps[2..15])
        .map_err(TransportError::Aux)?;
    debug_assert_eq!(aux_len, 13);
    aps[15..].copy_from_slice(&tail);
    // NWK header + payload.
    let nwk = NwkHeader::minimal(
        FrameControl::data(),
        p.dst_short,
        0x0000,
        p.nwk_radius,
        p.nwk_seq,
    );
    let nwk_total = nwk
        .encode_into(&aps, &mut out[9..9 + 8 + aps.len()])
        .map_err(|_| TransportError::Nwk)?;
    debug_assert_eq!(nwk_total, 8 + aps.len());
    // MAC data header: FC 61 88 (no ack/security, intra-PAN
    // short/short), seq, PAN, dst short, src short 0x0000.
    out[0] = 0x61;
    out[1] = 0x88;
    out[2] = p.mac_seq;
    out[3..5].copy_from_slice(&p.dst_pan.to_le_bytes());
    out[5..7].copy_from_slice(&p.dst_short.to_le_bytes());
    out[7..9].copy_from_slice(&0x0000u16.to_le_bytes());
    Ok(9 + nwk_total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_NETKEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    // EUIs as on air (LSB-first wire order), matching the MG21
    // reference capture (aux source + plaintext EUIs).
    const TC: [u8; 8] = [0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0];
    const JOINER: [u8; 8] = [0x6d, 0x49, 0x11, 0xfe, 0xff, 0x13, 0x8d, 0x34];

    fn params() -> TransportKeyParams {
        TransportKeyParams {
            dst_pan: 0xC601,
            dst_short: 0x0002,
            dst_eui: JOINER,
            src_eui: TC,
            mac_seq: 0x5a,
            nwk_seq: 0x21,
            nwk_radius: 0x1e,
            aps_ctr: 0x51,
            auxctr: TRANSPORT_AUX_BASE,
            seq_no: 0x00,
            netkey: TEST_NETKEY,
            transport_key: ha_transport_key().unwrap(),
        }
    }

    #[test]
    fn ha_transport_key_matches_python_model() {
        // Independent Python HMAC-MMO gives 4bab0f17… for the HA key.
        assert_eq!(
            ha_transport_key().unwrap(),
            [
                0x4b, 0xab, 0x0f, 0x17, 0x3e, 0x14, 0x34, 0xa2, 0xd5, 0x72, 0xe1, 0xc1, 0xef, 0x47,
                0x87, 0x82
            ]
        );
    }

    #[test]
    fn golden_frame_matches_python_model() {
        // Byte-exact 71-octet frame from the independent Python CCM*
        // model (fixed test key/EUIs/counters above). No secrets: HA
        // public default + synthetic key + lab identifiers.
        let expect: [u8; TRANSPORT_FRAME_LEN] = [
            0x61, 0x88, 0x5a, 0x01, 0xc6, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x1e, 0x21, 0x21, 0x51, 0x30, 0x00, 0x10, 0x00, 0x00, 0x68, 0x7f, 0x86, 0xfe,
            0xff, 0x62, 0xf2, 0xa0, 0x94, 0x9a, 0xfa, 0x9e, 0x00, 0xc9, 0x95, 0x9d, 0x83, 0x7c,
            0x81, 0xfb, 0xda, 0x96, 0x09, 0x7f, 0x45, 0x29, 0xd7, 0xf0, 0x55, 0xfb, 0x7b, 0x4b,
            0xf3, 0x55, 0x9f, 0x03, 0x94, 0x2e, 0x7a, 0x86, 0xc5, 0xe8, 0x44, 0xd7, 0x47, 0xb0,
            0xc4,
        ];
        let mut out = [0u8; TRANSPORT_FRAME_LEN];
        let n = build_transport_key_frame(&params(), &mut out).unwrap();
        assert_eq!(n, TRANSPORT_FRAME_LEN);
        assert_eq!(out, expect);
    }

    #[test]
    fn rejects_short_buffer() {
        let mut tiny = [0u8; 16];
        assert_eq!(
            build_transport_key_frame(&params(), &mut tiny),
            Err(TransportError::TooSmall)
        );
    }

    fn expected_plaintext(p: &TransportKeyParams) -> [u8; 35] {
        let mut pt = [0u8; 35];
        pt[0] = TRANSPORT_CMD;
        pt[1] = TRANSPORT_KEY_TYPE_NETWORK;
        pt[2..18].copy_from_slice(&p.netkey);
        pt[18] = p.seq_no;
        pt[19..27].copy_from_slice(&p.dst_eui);
        pt[27..35].copy_from_slice(&p.src_eui);
        pt
    }

    fn nonce_aad_from_frame(frame: &[u8; TRANSPORT_FRAME_LEN]) -> ([u8; 13], [u8; 15]) {
        let mut nonce = [0u8; CCM_NONCE_LEN];
        nonce[..8].copy_from_slice(&frame[24..32]);
        nonce[8..12].copy_from_slice(&frame[20..24]);
        nonce[12] = 0x35;
        let mut aad = [0u8; 15];
        aad[..2].copy_from_slice(&frame[17..19]);
        aad[2] = 0x35;
        aad[3..7].copy_from_slice(&frame[20..24]);
        aad[7..15].copy_from_slice(&frame[24..32]);
        (nonce, aad)
    }

    #[test]
    fn rejects_truncated_buffers_and_accepts_exact_fit() {
        // 0- and 70-octet buffers refuse; 71-octet exact fit succeeds;
        // oversize succeeds returning 71 with slack untouched. Short
        // refusal writes nothing (builder checks length first).
        let p = params();
        let mut zero = [0u8; 0];
        assert_eq!(
            build_transport_key_frame(&p, &mut zero),
            Err(TransportError::TooSmall)
        );
        let mut short70 = [0xAAu8; 70];
        assert_eq!(
            build_transport_key_frame(&p, &mut short70),
            Err(TransportError::TooSmall)
        );
        assert_eq!(short70, [0xAAu8; 70]);
        let mut exact = [0u8; TRANSPORT_FRAME_LEN];
        assert_eq!(
            build_transport_key_frame(&p, &mut exact),
            Ok(TRANSPORT_FRAME_LEN)
        );
        let mut oversize = [0x55u8; TRANSPORT_FRAME_LEN + 8];
        assert_eq!(
            build_transport_key_frame(&p, &mut oversize),
            Ok(TRANSPORT_FRAME_LEN)
        );
        assert_eq!(&oversize[..TRANSPORT_FRAME_LEN], &exact[..]);
        assert_eq!(&oversize[TRANSPORT_FRAME_LEN..], &[0x55u8; 8]);
    }

    #[test]
    fn ha_transport_key_is_deterministic() {
        // Same HA default input twice gives the same key-transport key.
        let a = ha_transport_key().unwrap();
        let b = ha_transport_key().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn auxctr_boundaries_encode_verbatim_and_roundtrip() {
        // Builder owns no counter state: it encodes the given auxctr
        // verbatim LE both on air and in the CCM* nonce. It never
        // increments or wraps; 0xFFFFFFFF does NOT wrap to 0 inside the
        // builder (caller owns monotonicity/persistence). Pin both
        // extremes: they build, differ on air/in tail, and both open.
        use rounddance_security::ccm_star_open_into;
        let mut frame_zero = [0u8; TRANSPORT_FRAME_LEN];
        let mut p_zero = params();
        p_zero.auxctr = 0x0000_0000;
        assert_eq!(
            build_transport_key_frame(&p_zero, &mut frame_zero),
            Ok(TRANSPORT_FRAME_LEN)
        );
        assert_eq!(&frame_zero[20..24], &0u32.to_le_bytes());
        let mut frame_max = [0u8; TRANSPORT_FRAME_LEN];
        let mut p_max = params();
        p_max.auxctr = 0xFFFF_FFFF;
        assert_eq!(
            build_transport_key_frame(&p_max, &mut frame_max),
            Ok(TRANSPORT_FRAME_LEN)
        );
        assert_eq!(&frame_max[20..24], &0xFFFF_FFFFu32.to_le_bytes());
        // Distinct counters give distinct on-air tails.
        assert_ne!(&frame_zero[32..], &frame_max[32..]);
        // Both tails open to the exact plaintext with their own nonce.
        for (frame, p) in [(&frame_zero, &p_zero), (&frame_max, &p_max)] {
            let (nonce, aad) = nonce_aad_from_frame(frame);
            // Nonce mirrors the LE counter verbatim + control 0x35.
            assert_eq!(&nonce[8..12], &p.auxctr.to_le_bytes());
            assert_eq!(nonce[12], 0x35);
            let (ct, tag) = frame[32..].split_at(35);
            let mut tag4 = [0u8; 4];
            tag4.copy_from_slice(&tag[..4]);
            let mut pt = [0u8; 35];
            assert_eq!(
                ccm_star_open_into(&p.transport_key, &nonce, &aad, ct, &tag4, &mut pt),
                Ok(35)
            );
            assert_eq!(pt, expected_plaintext(p));
        }
    }

    #[test]
    fn wrong_transport_key_fails_and_zeroes() {
        // Open with any key other than the sealing key-transport key
        // must fail with AuthFailed and zero the output buffer.
        use rounddance_security::ccm_star_open_into;
        let p = params();
        let mut frame = [0u8; TRANSPORT_FRAME_LEN];
        build_transport_key_frame(&p, &mut frame).unwrap();
        let (nonce, aad) = nonce_aad_from_frame(&frame);
        let (ct, tag) = frame[32..].split_at(35);
        let mut tag4 = [0u8; 4];
        tag4.copy_from_slice(&tag[..4]);
        let mut wrong = p.transport_key;
        wrong[0] ^= 0x01;
        let mut out = [0xAAu8; 35];
        assert_eq!(
            ccm_star_open_into(&wrong, &nonce, &aad, ct, &tag4, &mut out),
            Err(CcmError::AuthFailed)
        );
        assert_eq!(out, [0u8; 35]);
    }

    #[test]
    fn tampered_tail_ciphertext_rejected() {
        // Flip the first sealed-tail octet (encrypts cmd 0x05): the
        // receiver rebuilding nonce/AAD from untampered aux still fails.
        use rounddance_security::ccm_star_open_into;
        let p = params();
        let mut frame = [0u8; TRANSPORT_FRAME_LEN];
        build_transport_key_frame(&p, &mut frame).unwrap();
        let (nonce, aad) = nonce_aad_from_frame(&frame);
        let mut bad_ct = [0u8; 35];
        bad_ct.copy_from_slice(&frame[32..67]);
        bad_ct[0] ^= 0x01;
        let mut tag4 = [0u8; 4];
        tag4.copy_from_slice(&frame[67..71]);
        let mut out = [0xAAu8; 35];
        assert_eq!(
            ccm_star_open_into(&p.transport_key, &nonce, &aad, &bad_ct, &tag4, &mut out),
            Err(CcmError::AuthFailed)
        );
        assert_eq!(out, [0u8; 35]);
        // Flip the last ciphertext octet (covers src-EUI region) too.
        let mut bad_last = [0u8; 35];
        bad_last.copy_from_slice(&frame[32..67]);
        bad_last[34] ^= 0x80;
        let mut out2 = [0xAAu8; 35];
        assert_eq!(
            ccm_star_open_into(&p.transport_key, &nonce, &aad, &bad_last, &tag4, &mut out2),
            Err(CcmError::AuthFailed)
        );
        assert_eq!(out2, [0u8; 35]);
    }

    #[test]
    fn tampered_aux_counter_rejected() {
        // Flip one on-air aux-counter octet: the receiver derives nonce
        // and AAD from the tampered counter, so open of the untampered
        // tail must fail (covers counter integrity, not just secrecy).
        use rounddance_security::ccm_star_open_into;
        let p = params();
        let mut frame = [0u8; TRANSPORT_FRAME_LEN];
        build_transport_key_frame(&p, &mut frame).unwrap();
        let mut bad = frame;
        bad[21] ^= 0x01;
        let (bad_nonce, bad_aad) = nonce_aad_from_frame(&bad);
        let (ct, tag) = bad[32..].split_at(35);
        let mut tag4 = [0u8; 4];
        tag4.copy_from_slice(&tag[..4]);
        let mut out = [0xAAu8; 35];
        assert_eq!(
            ccm_star_open_into(&p.transport_key, &bad_nonce, &bad_aad, ct, &tag4, &mut out),
            Err(CcmError::AuthFailed)
        );
        assert_eq!(out, [0u8; 35]);
    }

    #[test]
    fn tampered_eui_nonce_rejected() {
        // Flip one on-air aux-source (EUI) octet: the receiver derives
        // the CCM* nonce from the tampered EUI, so open must fail.
        use rounddance_security::ccm_star_open_into;
        let p = params();
        let mut frame = [0u8; TRANSPORT_FRAME_LEN];
        build_transport_key_frame(&p, &mut frame).unwrap();
        let mut bad = frame;
        bad[25] ^= 0x01;
        let (bad_nonce, bad_aad) = nonce_aad_from_frame(&bad);
        let (ct, tag) = bad[32..].split_at(35);
        let mut tag4 = [0u8; 4];
        tag4.copy_from_slice(&tag[..4]);
        let mut out = [0xAAu8; 35];
        assert_eq!(
            ccm_star_open_into(&p.transport_key, &bad_nonce, &bad_aad, ct, &tag4, &mut out),
            Err(CcmError::AuthFailed)
        );
        assert_eq!(out, [0u8; 35]);
    }

    #[test]
    fn truncated_tag_rejected() {
        // A 70-octet frame (one tag octet missing) already refuses at
        // build; a 38-octet tail (35 ct + 3 tag) cannot authenticate:
        // any guess for the missing octet fails and the sealer needs 39.
        use rounddance_security::{ccm_star_open_into, ccm_star_seal_into};
        let p = params();
        let mut frame = [0u8; TRANSPORT_FRAME_LEN];
        build_transport_key_frame(&p, &mut frame).unwrap();
        assert_eq!(frame[32..].len(), TRANSPORT_TAIL_LEN);
        // First 38 octets of the tail (35 ct + 3 tag).
        let truncated = &frame[32..32 + 38];
        assert_eq!(truncated.len(), 38);
        let (ct, tag3) = truncated.split_at(35);
        assert_eq!(tag3.len(), 3);
        // Guessing the missing tag octet must still fail.
        let (nonce, aad) = nonce_aad_from_frame(&frame);
        let mut guessed = [0u8; 4];
        guessed[..3].copy_from_slice(tag3);
        guessed[3] = frame[70] ^ 0x01;
        // Ensure the guess is actually wrong (flip if it collided).
        if guessed[3] == frame[70] {
            guessed[3] ^= 0x01;
        }
        let mut out = [0xAAu8; 35];
        assert_eq!(
            ccm_star_open_into(&p.transport_key, &nonce, &aad, ct, &guessed, &mut out),
            Err(CcmError::AuthFailed)
        );
        assert_eq!(out, [0u8; 35]);
        // Sealing the 35-octet plaintext needs 39 octets; 38 refuses.
        let pt = expected_plaintext(&p);
        let mut short = [0u8; 38];
        assert_eq!(
            ccm_star_seal_into(&p.transport_key, &nonce, &aad, &pt, &mut short),
            Err(CcmError::TooSmall)
        );
    }
}
