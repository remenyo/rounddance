//! 802.15.4 MAC header layer for the RCP path.
//!
//! The v0 RCP wire carried SAP MSDUs verbatim and left every header
//! decision to out-of-band lore (`docs/otbr/protocol.md` v0
//! non-goals). This module closes that gap on the host side: the
//! driver builds short-short intra-PAN data headers and
//! broadcast inter-PAN headers around each MSDU before handing the
//! complete PSDU to the RCP (`Command::TxFrame` proxy), and parses
//! received PSDUs back into sources plus MSDUs on the way up.
//!
//! Shapes mirror
//! `rounddance-hal-esp`'s [`adapter`](https://github.com/remenyo/rounddance)
//! builders octet-for-octet, minus the leading length octet: the RCP
//! UART framing already delimits transfers, so the length prefix only
//! exists on air (the firmware adds `Len+2` and the trailing FCS when
//! it radiates, and strips/checks them on receive). Layer order on
//! the wire is therefore `MHR | MSDU`, where the MHR is:
//!
//! * data: `FC0 FC1 seq pan-LE dst-LE src-LE` (9 octets, `FC0 =
//!   0x41`, plus the AR bit when ACK is requested; `FC1 = 0x88`);
//! * inter-PAN: `FC0=0x01 FC1=0x88 seq 0xFFFF 0xFFFF src-pan-LE
//!   src-LE` (11 octets, unacknowledged broadcast).
//!
//! Anything that parses as neither shape is not a data frame: the
//! driver surfaces it verbatim on the MAC-command queue (beacons,
//! association traffic, polls) for the upper layer to classify —
//! firmware stays a dumb pipe and never classifies.
//!
//! Accounting (requirement `RD-RCP-17`): every builder refuses an
//! MSDU over [`MAX_MSDU_LEN`]
//! (116) and any header + MSDU + 2-octet FCS combination over the
//! 127-octet PSDU ceiling, as [`MacError::FrameTooLong`] — never a
//! truncation. An 11-octet inter-PAN header therefore caps its MSDU
//! at 114 octets, not 116.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-RCP-17` (MAC header build/parse + accounting).

use rounddance_mac_sap::{AddrMode, Channel, MacAddress, MacError, PanId, ShortAddr, MAX_MSDU_LEN};

/// Data-frame MAC header length in octets (`FC0 FC1 seq pan dst src`).
pub const MHR_DATA: usize = 9;
/// Inter-PAN MAC header length in octets (`FC0 FC1 seq dst-pan
/// dst src-pan src`).
pub const MHR_INTERPAN: usize = 11;
/// Trailing hardware-FCS length the air frame carries (added and
/// checked by the firmware, never present in an RCP PSDU).
pub const FCS_LEN: usize = 2;
/// Largest PSDU (MHR + MSDU) the RCP path carries.
pub const MAX_MAC_PSDU: usize = 127;

/// First-frame-control octet of our short-short data shape (AR bit
/// clear; OR with [`FC0_ACK_BIT`] when ACK is requested).
pub const FC0_DATA: u8 = 0x41;
/// ACK-request bit inside `FC0`.
pub const FC0_ACK_BIT: u8 = 0x20;
/// Second frame-control octet shared by both shapes.
pub const FC1_SHORT_SHORT: u8 = 0x88;
/// First-frame-control octet of the inter-PAN broadcast shape.
pub const FC0_INTER_PAN: u8 = 0x01;

/// Enforce the SAP-vs-PSDU accounting: `msdu_len` must fit the SAP
/// bound and `mhr + msdu_len + FCS` must fit the PSDU ceiling.
fn check_accounting(mhr: usize, msdu_len: usize) -> Result<(), MacError> {
    if msdu_len > MAX_MSDU_LEN {
        return Err(MacError::FrameTooLong);
    }
    if mhr + msdu_len + FCS_LEN > MAX_MAC_PSDU {
        return Err(MacError::FrameTooLong);
    }
    Ok(())
}

/// Build a short-short intra-PAN data PSDU into `out`.
///
/// Layout: `FC0 FC1 seq pan-LE dst-LE src-LE msdu`. `FC0` carries
/// the AR bit exactly when `ack` is set.
///
/// # Errors
///
/// [`MacError::FrameTooLong`] when the accounting rule fails (see
/// the module docs).
pub fn build_data_psdu(
    seq: u8,
    pan: PanId,
    dst: ShortAddr,
    src: ShortAddr,
    msdu: &[u8],
    ack: bool,
    out: &mut [u8; MAX_MAC_PSDU],
) -> Result<usize, MacError> {
    check_accounting(MHR_DATA, msdu.len())?;
    out[0] = if ack {
        FC0_DATA | FC0_ACK_BIT
    } else {
        FC0_DATA
    };
    out[1] = FC1_SHORT_SHORT;
    out[2] = seq;
    out[3..5].copy_from_slice(&pan.to_le_bytes());
    out[5..7].copy_from_slice(&dst.to_le_bytes());
    out[7..9].copy_from_slice(&src.to_le_bytes());
    out[MHR_DATA..MHR_DATA + msdu.len()].copy_from_slice(msdu);
    Ok(MHR_DATA + msdu.len())
}

/// Build an inter-PAN broadcast PSDU into `out`.
///
/// Layout: `0x01 0x88 seq 0xFFFF 0xFFFF src-pan-LE src-LE msdu`,
/// unacknowledged (no AR bit exists on this shape).
///
/// # Errors
///
/// [`MacError::FrameTooLong`] when the accounting rule fails (note
/// the 114-octet effective MSDU cap documented above).
pub fn build_inter_pan_psdu(
    seq: u8,
    src_pan: PanId,
    src: ShortAddr,
    msdu: &[u8],
    out: &mut [u8; MAX_MAC_PSDU],
) -> Result<usize, MacError> {
    check_accounting(MHR_INTERPAN, msdu.len())?;
    out[0] = FC0_INTER_PAN;
    out[1] = FC1_SHORT_SHORT;
    out[2] = seq;
    out[3..5].copy_from_slice(&0xFFFFu16.to_le_bytes());
    out[5..7].copy_from_slice(&0xFFFFu16.to_le_bytes());
    out[7..9].copy_from_slice(&src_pan.to_le_bytes());
    out[9..11].copy_from_slice(&src.to_le_bytes());
    out[MHR_INTERPAN..MHR_INTERPAN + msdu.len()].copy_from_slice(msdu);
    Ok(MHR_INTERPAN + msdu.len())
}

/// Parsed short-short data frame: source plus the MSDU bounds into
/// the PSDU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedData {
    /// Source address (short in our PAN context).
    pub src: MacAddress,
    /// Destination PAN the frame was addressed to.
    pub dst_pan: PanId,
    /// MSDU start offset into the PSDU.
    pub msdu_start: usize,
    /// MSDU end offset into the PSDU (exclusive).
    pub msdu_end: usize,
}

/// Parsed inter-PAN frame: MSDU bounds into the PSDU (the arrival
/// channel is attached by the caller from provisioning or the
/// channel-tagged event).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedInterPan {
    /// MSDU start offset into the PSDU.
    pub msdu_start: usize,
    /// MSDU end offset into the PSDU (exclusive).
    pub msdu_end: usize,
}

/// Parse our short-short intra-PAN shape; anything else is `None`
/// (the caller routes those to the MAC-command queue or the
/// inter-PAN path — never silently drops).
#[must_use]
pub fn parse_data_psdu(psdu: &[u8]) -> Option<ParsedData> {
    if psdu.len() < MHR_DATA {
        return None;
    }
    if psdu[0] != FC0_DATA && psdu[0] != (FC0_DATA | FC0_ACK_BIT) {
        return None;
    }
    if psdu[1] != FC1_SHORT_SHORT {
        return None;
    }
    let msdu_start = MHR_DATA;
    let msdu_end = psdu.len();
    if msdu_end - msdu_start > MAX_MSDU_LEN {
        return None;
    }
    let pan = u16::from_le_bytes([psdu[3], psdu[4]]);
    let src = u16::from_le_bytes([psdu[7], psdu[8]]);
    Some(ParsedData {
        src: MacAddress {
            pan: Some(pan),
            addr: AddrMode::Short(src),
        },
        dst_pan: pan,
        msdu_start,
        msdu_end,
    })
}

/// Parse our inter-PAN broadcast shape; anything else is `None`.
#[must_use]
pub fn parse_inter_pan_psdu(psdu: &[u8]) -> Option<ParsedInterPan> {
    if psdu.len() < MHR_INTERPAN {
        return None;
    }
    if psdu[0] != FC0_INTER_PAN || psdu[1] != FC1_SHORT_SHORT {
        return None;
    }
    let msdu_start = MHR_INTERPAN;
    let msdu_end = psdu.len();
    if msdu_end - msdu_start > MAX_MSDU_LEN {
        return None;
    }
    Some(ParsedInterPan {
        msdu_start,
        msdu_end,
    })
}

/// Arrival channel type-check helper: a raw octet is a legal 802.15.4
/// channel exactly when [`Channel::new`] accepts it.
#[must_use]
pub fn legal_channel(channel: u8) -> bool {
    Channel::new(channel).is_ok()
}

/// Association-response short latch (SHORT-SNOOP): inspect one
/// inbound PSDU and report the assigned short when it is the current
/// long-long assoc-rsp shape (`0x63cc`, 25 octets) naming `pan` +
/// `ext` (wire order) with a success status. Anything else —
/// wrong length, foreign FCF, wrong PAN/EUI, denied status, the
/// `0xFFFF` unassigned sentinel, or an already-latched `current` —
/// yields `None` (never a latch).
///
/// Both the scripted peer ([`crate::peer`]) and the real RCP
/// firmware share this function, so the air proof and the sim agree
/// on exactly which bytes latch.
#[must_use]
pub fn snoop_assoc_short(
    pan: Option<PanId>,
    ext: Option<u64>,
    psdu: &[u8],
    current: Option<u16>,
) -> Option<u16> {
    let pan = pan?;
    let ext = ext?;
    if psdu.len() != 25 {
        return None;
    }
    let fcf = u16::from_le_bytes([psdu[0], psdu[1]]);
    if fcf & 0x07 != 0x03 {
        return None;
    }
    if (fcf >> 10) & 0x03 != 0x03 || (fcf >> 14) & 0x03 != 0x03 {
        return None;
    }
    if u16::from_le_bytes([psdu[3], psdu[4]]) != pan {
        return None;
    }
    let mut dst = [0u8; 8];
    dst.copy_from_slice(&psdu[5..13]);
    if u64::from_le_bytes(dst) != ext {
        return None;
    }
    if psdu[21] != 0x02 || psdu[24] != 0x00 {
        return None;
    }
    let short = u16::from_le_bytes([psdu[22], psdu[23]]);
    if short != 0xFFFF && Some(short) != current {
        Some(short)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_round_trip_with_and_without_ack() {
        let msdu = [0xDE, 0xAD, 0xBE, 0xEF];
        for ack in [false, true] {
            let mut out = [0u8; MAX_MAC_PSDU];
            let n = build_data_psdu(0x42, 0x1a2b, 0x0002, 0x0000, &msdu, ack, &mut out).unwrap();
            assert_eq!(n, MHR_DATA + msdu.len());
            assert_eq!(out[0], if ack { 0x61 } else { 0x41 });
            assert_eq!(out[1], 0x88);
            assert_eq!(out[2], 0x42);
            assert_eq!(&out[3..5], &0x1a2bu16.to_le_bytes());
            assert_eq!(&out[5..7], &0x0002u16.to_le_bytes());
            assert_eq!(&out[7..9], &0x0000u16.to_le_bytes());
            assert_eq!(&out[9..n], &msdu);
            let p = parse_data_psdu(&out[..n]).unwrap();
            assert_eq!(
                p.src,
                MacAddress {
                    pan: Some(0x1a2b),
                    addr: AddrMode::Short(0x0000),
                }
            );
            assert_eq!(p.dst_pan, 0x1a2b);
            assert_eq!(&out[p.msdu_start..p.msdu_end], &msdu);
        }
        // The inter-PAN shape never aliases the data shape.
        let mut ip = [0u8; MAX_MAC_PSDU];
        let m = build_inter_pan_psdu(0x01, 0x1a2b, 0x0000, &msdu, &mut ip).unwrap();
        assert_eq!(m, MHR_INTERPAN + msdu.len());
        assert!(parse_data_psdu(&ip[..m]).is_none());
        let q = parse_inter_pan_psdu(&ip[..m]).unwrap();
        assert_eq!(&ip[q.msdu_start..q.msdu_end], &msdu);
        assert!(parse_inter_pan_psdu(&[0x01, 0x88][..]).is_none());
    }

    #[test]
    fn snoop_latches_only_our_success_response() {
        fn rsp(pan: u16, ext: u64, short: u16, status: u8) -> [u8; 25] {
            let mut psdu = [0u8; 25];
            psdu[0..2].copy_from_slice(&0xCC63u16.to_le_bytes());
            psdu[2] = 0x55;
            psdu[3..5].copy_from_slice(&pan.to_le_bytes());
            psdu[5..13].copy_from_slice(&ext.to_le_bytes());
            psdu[13..21].copy_from_slice(&[0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0]);
            psdu[21] = 0x02;
            psdu[22..24].copy_from_slice(&short.to_le_bytes());
            psdu[24] = status;
            psdu
        }
        const EXT: u64 = 0x0200_0000_0000_0002;
        // Success naming us latches; nothing else does.
        assert_eq!(
            snoop_assoc_short(
                Some(0x1a2b),
                Some(EXT),
                &rsp(0x1a2b, EXT, 0x0001, 0x00),
                None
            ),
            Some(0x0001)
        );
        assert_eq!(
            snoop_assoc_short(
                Some(0x1a2b),
                Some(EXT),
                &rsp(0x9999, EXT, 0x0001, 0x00),
                None
            ),
            None,
            "wrong PAN ignored"
        );
        assert_eq!(
            snoop_assoc_short(
                Some(0x1a2b),
                Some(EXT),
                &rsp(0x1a2b, 0x0200_0000_0000_0003, 0x0001, 0x00),
                None
            ),
            None,
            "foreign EUI ignored"
        );
        assert_eq!(
            snoop_assoc_short(
                Some(0x1a2b),
                Some(EXT),
                &rsp(0x1a2b, EXT, 0x0001, 0x02),
                None
            ),
            None,
            "denied status ignored"
        );
        assert_eq!(
            snoop_assoc_short(
                Some(0x1a2b),
                Some(EXT),
                &rsp(0x1a2b, EXT, 0xFFFF, 0x00),
                None
            ),
            None,
            "unassigned sentinel ignored"
        );
        assert_eq!(
            snoop_assoc_short(
                Some(0x1a2b),
                Some(EXT),
                &rsp(0x1a2b, EXT, 0x0001, 0x00),
                Some(0x0001)
            ),
            None,
            "already latched is not a new latch"
        );
        assert_eq!(
            snoop_assoc_short(None, Some(EXT), &rsp(0x1a2b, EXT, 1, 0), None),
            None
        );
        assert_eq!(
            snoop_assoc_short(Some(0x1a2b), Some(EXT), &[0x41, 0x88, 0x00], None),
            None,
            "short frames never latch"
        );
    }

    #[test]
    fn accounting_refuses_oversize_before_air() {
        let mut out = [0u8; MAX_MAC_PSDU];
        // SAP bound: 117 > 116 refused on both shapes.
        let big = [0xAAu8; MAX_MSDU_LEN + 1];
        assert_eq!(
            build_data_psdu(0, 1, 2, 3, &big, false, &mut out),
            Err(MacError::FrameTooLong)
        );
        assert_eq!(
            build_inter_pan_psdu(0, 1, 2, &big, &mut out),
            Err(MacError::FrameTooLong)
        );
        // PSDU ceiling: 11 + 116 + 2 = 129 > 127 refused even though
        // the MSDU alone fits the SAP bound.
        let full = [0xBBu8; MAX_MSDU_LEN];
        assert_eq!(
            build_inter_pan_psdu(0, 1, 2, &full, &mut out),
            Err(MacError::FrameTooLong)
        );
        // ... while a 114-octet inter-PAN MSDU (11 + 114 + 2 = 127)
        // still fits, and a 116-octet data MSDU (9 + 116 + 2 = 127)
        // is exactly the ceiling.
        let ok_ip = [0xCCu8; 114];
        assert_eq!(
            build_inter_pan_psdu(0, 1, 2, &ok_ip, &mut out).unwrap(),
            MHR_INTERPAN + 114
        );
        let ok_data = [0xDDu8; MAX_MSDU_LEN];
        assert_eq!(
            build_data_psdu(0, 1, 2, 3, &ok_data, false, &mut out).unwrap(),
            MHR_DATA + MAX_MSDU_LEN
        );
        // Oversize air frames never parse as data (they route to the
        // MAC queue instead).
        let mut fat = [0u8; MAX_MAC_PSDU];
        fat[0] = FC0_DATA;
        fat[1] = FC1_SHORT_SHORT;
        assert!(parse_data_psdu(&fat[..]).is_none());
    }

    #[test]
    fn foreign_shapes_do_not_parse_as_ours() {
        // Command/beacon FC0 values are not our data shape.
        assert!(parse_data_psdu(&[0x23, 0xC8, 0x00, 0x01, 0xC6, 0x00, 0x00, 0xFF, 0xFF]).is_none());
        assert!(parse_data_psdu(&[0x00, 0x80, 0x5A]).is_none());
        assert!(parse_inter_pan_psdu(&[0x41, 0x88, 0x00]).is_none());
        assert!(!legal_channel(10));
        assert!(legal_channel(11) && legal_channel(26));
        assert!(!legal_channel(27));
    }
}
