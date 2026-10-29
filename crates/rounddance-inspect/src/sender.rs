//! Loopback sender: the offline [`Sender`](crate::capture::Sender)
//! implementation.
//!
//! The dissector chain and session engine never touch hardware types;
//! this loopback closes the other half of that seam for tests and
//! offline bring-up. [`LoopbackSender`] records every transmitted
//! frame in bounded fixed buffers (no allocator, `no_std`-clean) and
//! replays them back through the
//! [`Listener`](crate::capture::Listener) seam in FIFO order, so an
//! encode → transmit → receive → decode round trip exercises the
//! identical decision path as a capture. A drained loopback feeds the
//! [`pcap`](crate::pcap) writer, so crafted frames stay
//! Wireshark-inspectable.

use crate::capture::{Captured, Listener, Sender};

/// Frames retained by one loopback.
pub const LOOPBACK_CAPACITY: usize = 8;
/// Largest single frame the loopback retains (802.15.4 PSDU maximum
/// is 127 octets; headroom covers overlong negative tests).
pub const LOOPBACK_FRAME_MAX: usize = 256;

/// Loopback failure (bounded, typed, never panics).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopbackError {
    /// Frame exceeds [`LOOPBACK_FRAME_MAX`]: never queued.
    TooLong,
    /// Queue already holds [`LOOPBACK_CAPACITY`] frames: the frame is
    /// refused and the saturating drop counter advances.
    Full,
    /// Receive buffer smaller than the queued head frame: the frame
    /// stays queued.
    SmallBuffer,
}

/// Offline frame sink + source: records [`Sender`] transmissions and
/// replays them as a [`Listener`] in FIFO order.
#[derive(Clone, Debug)]
pub struct LoopbackSender {
    channels: [u8; LOOPBACK_CAPACITY],
    lens: [usize; LOOPBACK_CAPACITY],
    frames: [[u8; LOOPBACK_FRAME_MAX]; LOOPBACK_CAPACITY],
    head: usize,
    pending: usize,
    /// Accepted transmissions.
    pub sends: u32,
    /// Refused transmissions (queue full).
    pub drops: u32,
}

impl LoopbackSender {
    /// Empty loopback.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            channels: [0; LOOPBACK_CAPACITY],
            lens: [0; LOOPBACK_CAPACITY],
            frames: [[0; LOOPBACK_FRAME_MAX]; LOOPBACK_CAPACITY],
            head: 0,
            pending: 0,
            sends: 0,
            drops: 0,
        }
    }

    /// Frames currently queued.
    #[must_use]
    pub const fn pending(&self) -> usize {
        self.pending
    }

    /// Accepted transmissions so far.
    #[must_use]
    pub const fn sends(&self) -> u32 {
        self.sends
    }

    /// Refused transmissions so far (queue full).
    #[must_use]
    pub const fn drops(&self) -> u32 {
        self.drops
    }

    /// Inspect one queued frame by FIFO position (`None` past the
    /// queued prefix). Returns the transmit channel plus bytes.
    #[must_use]
    pub fn queued(&self, pos: usize) -> Option<(u8, &[u8])> {
        if pos >= self.pending {
            return None;
        }
        let i = (self.head + pos) % LOOPBACK_CAPACITY;
        Some((self.channels[i], &self.frames[i][..self.lens[i]]))
    }
}

impl Default for LoopbackSender {
    fn default() -> Self {
        Self::new()
    }
}

impl Sender for LoopbackSender {
    type Error = LoopbackError;

    fn send(&mut self, channel: u8, frame: &[u8]) -> Result<(), Self::Error> {
        if frame.len() > LOOPBACK_FRAME_MAX {
            return Err(LoopbackError::TooLong);
        }
        if self.pending >= LOOPBACK_CAPACITY {
            self.drops = self.drops.saturating_add(1);
            return Err(LoopbackError::Full);
        }
        let i = (self.head + self.pending) % LOOPBACK_CAPACITY;
        self.frames[i][..frame.len()].copy_from_slice(frame);
        self.lens[i] = frame.len();
        self.channels[i] = channel;
        self.pending += 1;
        self.sends = self.sends.saturating_add(1);
        Ok(())
    }
}

impl Listener for LoopbackSender {
    type Error = LoopbackError;

    fn next_frame<'b>(&mut self, buf: &'b mut [u8]) -> Result<Option<Captured<'b>>, Self::Error> {
        if self.pending == 0 {
            return Ok(None);
        }
        let i = self.head;
        if buf.len() < self.lens[i] {
            return Err(LoopbackError::SmallBuffer);
        }
        buf[..self.lens[i]].copy_from_slice(&self.frames[i][..self.lens[i]]);
        let channel = self.channels[i];
        let len = self.lens[i];
        self.head = (self.head + 1) % LOOPBACK_CAPACITY;
        self.pending -= 1;
        Ok(Some(Captured {
            channel,
            rssi: 0,
            lqi: 0,
            payload: &buf[..len],
        }))
    }
}
