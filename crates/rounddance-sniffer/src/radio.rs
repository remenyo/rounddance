//! Radio-header DLT for pcap-out: channel/RSSI/LQI the 195 writer drops.
//!
//! The inspector's [`pcap`](rounddance_inspect::pcap) writer emits
//! classic pcap with link type 195 (bare 802.15.4, FCS already
//! stripped) — that writer is untouched. Captures that need the
//! radio metadata use this variant: classic pcap with link type
//! [`LINKTYPE_SNIFFER_RADIO`] (DLT `USER0`, 147 — a sniffer-local
//! assignment, documented here, carrying no Wireshark-decodability
//! claim) where every packet payload is a 4-octet header plus the
//! bare frame:
//!
//! ```text
//! byte 0: header version ([`RADIO_VERSION`], currently 1)
//! byte 1: 802.15.4 channel (11..=26 on live captures)
//! byte 2: RSSI in dBm as raw two's-complement octets (kept honest:
//!         positive sniffer quirks stay in the file, downstream
//!         consumers file them as unknown per the capture seam)
//! byte 3: LQI (0..=255, radio-defined)
//! bytes 4..: bare 802.15.4 frame (MAC header onward, no FCS)
//! ```
//!
//! `no_std` + `#![forbid(unsafe_code)]`, no allocator, panic-free:
//! encoding is total, decoding validates version and length and
//! returns `None` otherwise.

/// Classic-pcap link type of the radio-header variant (DLT `USER0`).
pub const LINKTYPE_SNIFFER_RADIO: u32 = 147;
/// Radio header version written by [`encode_header`].
pub const RADIO_VERSION: u8 = 1;
/// Radio header length in octets.
pub const RADIO_HDR_LEN: usize = 4;

/// Decoded radio header fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RadioFields {
    /// 802.15.4 channel the frame arrived on.
    pub channel: u8,
    /// Raw RSSI reading in dBm (honest bytes: quirks included).
    pub rssi: i8,
    /// Link quality indicator (radio-defined).
    pub lqi: u8,
}

/// Encode one radio header (total function over all inputs).
#[must_use]
pub const fn encode_header(channel: u8, rssi: i8, lqi: u8) -> [u8; RADIO_HDR_LEN] {
    [RADIO_VERSION, channel, rssi as u8, lqi]
}

/// Decode and validate one radio header: `None` on short input or a
/// version mismatch (never a panic, never a guess).
#[must_use]
pub fn decode_header(hdr: &[u8]) -> Option<RadioFields> {
    if hdr.len() < RADIO_HDR_LEN || hdr[0] != RADIO_VERSION {
        return None;
    }
    Some(RadioFields {
        channel: hdr[1],
        rssi: hdr[2] as i8,
        lqi: hdr[3],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips_all_octets() {
        for ch in [11u8, 20, 25, 26] {
            for rssi in [i8::MIN, -104, -1, 0, 103, 111, i8::MAX] {
                for lqi in [0u8, 88, 255] {
                    let hdr = encode_header(ch, rssi, lqi);
                    assert_eq!(hdr.len(), RADIO_HDR_LEN);
                    let back = decode_header(&hdr).expect("self-made header");
                    assert_eq!(
                        back,
                        RadioFields {
                            channel: ch,
                            rssi,
                            lqi,
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn decode_refuses_short_and_versioned() {
        assert_eq!(decode_header(&[]), None);
        assert_eq!(decode_header(&[1, 25, 0]), None);
        assert_eq!(decode_header(&[2, 25, 0, 0]), None);
        // Trailing payload octets are fine (header is a prefix).
        assert_eq!(
            decode_header(&[1, 25, 0x98, 255, 0x03, 0x08]),
            Some(RadioFields {
                channel: 25,
                rssi: -104,
                lqi: 255,
            })
        );
    }
}
