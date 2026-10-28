//! Listener / sender traits: the inspector's seam to live radios.
//!
//! The traits are `no_std`-clean seams only — this wave ships NO live
//! drivers. A future 802.15.4 sniffer or dongle backend implements
//! [`Listener`] (frames in) and/or [`Sender`] (frames out); the dissector
//! chain and session engine never touch hardware types.

/// One captured 802.15.4 frame with radio metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Captured<'a> {
    /// 802.15.4 channel the frame arrived on (11–26).
    pub channel: u8,
    /// Received signal strength in dBm.
    pub rssi: i8,
    /// Link quality indicator (0–255, radio-defined).
    pub lqi: u8,
    /// Raw on-air octets: MAC header onward, FCS already stripped.
    pub payload: &'a [u8],
}

/// Frame source: poll a sniffer, dongle, or replay file.
pub trait Listener {
    /// Failure type of the backend.
    type Error;
    /// Return the next captured frame, or `Ok(None)` when no frame is
    /// available right now. The payload borrows `buf` as scratch.
    fn next_frame<'b>(&mut self, buf: &'b mut [u8]) -> Result<Option<Captured<'b>>, Self::Error>;
}

/// Frame sink: transmit raw 802.15.4 frames (MAC header onward).
pub trait Sender {
    /// Failure type of the backend.
    type Error;
    /// Transmit `frame` on `channel`. Implementations enforce their own
    /// regulatory caps (duty cycle, TX power); the trait passes the
    /// request through unchanged.
    fn send(&mut self, channel: u8, frame: &[u8]) -> Result<(), Self::Error>;
}
