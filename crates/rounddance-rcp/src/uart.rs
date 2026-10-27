//! UART seam: the byte transport the driver runs on.
//!
//! [`Uart`] is the only hardware boundary in this crate: two calls,
//! no locks, no callbacks. The S3 firmware will implement it over its
//! UART peripheral; every host/sim use runs on [`HostSide`], a pair of
//! fixed-capacity FIFOs with fallible (never blocking, never growing)
//! writes — D5 bounded + fallible, `SCOPE.md` §2.

use crate::RcpError;

/// Byte transport both directions: the driver writes command frames,
/// the RCP's response/event bytes wait to be read.
pub trait Uart {
    /// Queue `bytes` toward the RCP, or [`RcpError::UartFull`] when
    /// the FIFO has no room (backpressure, never silent loss).
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), RcpError>;

    /// Take the oldest inbound byte, if any (poll-based, like the
    /// MAC SAP above it — no callbacks, no locks).
    fn read_byte(&mut self) -> Option<u8>;
}

/// Fixed-capacity byte FIFO, `const`-constructible, no heap.
#[derive(Clone, Debug)]
pub struct LoopPipe<const N: usize> {
    buf: [u8; N],
    head: usize,
    len: usize,
}

impl<const N: usize> LoopPipe<N> {
    /// Empty pipe.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0; N],
            head: 0,
            len: 0,
        }
    }

    /// Queued octets right now.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True when no octet is queued.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True when no further octet fits.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len >= N
    }

    /// Push one octet; `false` when full (byte refused, never dropped
    /// silently by the caller contract).
    pub fn push(&mut self, byte: u8) -> bool {
        if self.is_full() {
            return false;
        }
        let idx = (self.head + self.len) % N;
        self.buf[idx] = byte;
        self.len += 1;
        true
    }

    /// Pop the oldest octet, if any.
    pub fn pop(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        let byte = self.buf[self.head];
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(byte)
    }

    /// Push all of `bytes`; on the first refusal the pushed prefix
    /// stays queued and the remainder is reported.
    pub fn push_slice(&mut self, bytes: &[u8]) -> Result<(), usize> {
        for (i, b) in bytes.iter().enumerate() {
            if !self.push(*b) {
                return Err(i);
            }
        }
        Ok(())
    }
}

/// Bytes in flight one direction of a scripted link.
pub const LINK_BYTES: usize = 2048;

/// Host end of a scripted UART: the driver writes `outbound` (the
/// test harness carries those octets to the peer) and reads
/// `inbound` (octets the harness collected from the peer).
#[derive(Clone, Debug)]
pub struct HostSide {
    /// Octets the driver emitted, awaiting delivery to the RCP.
    pub outbound: LoopPipe<LINK_BYTES>,
    /// Octets arrived from the RCP, awaiting [`Uart::read_byte`].
    pub inbound: LoopPipe<LINK_BYTES>,
}

impl HostSide {
    /// Both directions empty.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            outbound: LoopPipe::new(),
            inbound: LoopPipe::new(),
        }
    }
}

impl<const N: usize> Default for LoopPipe<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for HostSide {
    fn default() -> Self {
        Self::new()
    }
}

impl Uart for HostSide {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), RcpError> {
        self.outbound
            .push_slice(bytes)
            .map_err(|_| RcpError::UartFull)?;
        Ok(())
    }

    fn read_byte(&mut self) -> Option<u8> {
        self.inbound.pop()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_fifo_and_full() {
        let mut p = LoopPipe::<4>::new();
        assert!(p.is_empty());
        assert!(p.push_slice(&[1, 2, 3]).is_ok());
        assert_eq!(p.len(), 3);
        assert_eq!([p.pop(), p.pop(), p.pop()], [Some(1), Some(2), Some(3)]);
        assert_eq!(p.pop(), None);
        assert!(p.push_slice(&[1, 2, 3, 4]).is_ok());
        assert!(p.is_full());
        assert!(!p.push(5), "full pipe refuses, never overwrites");
        assert_eq!(p.len(), 4);
    }

    #[test]
    fn host_side_seam() {
        let mut u = HostSide::new();
        u.write_bytes(&[0xA5, 0x04]).unwrap();
        assert_eq!(u.outbound.len(), 2);
        assert_eq!(u.read_byte(), None);
        u.inbound.push(0x80);
        assert_eq!(u.read_byte(), Some(0x80));
    }
}
