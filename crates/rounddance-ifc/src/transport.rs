//! Reference in-memory transport: message queues, no I/O.
//!
//! [`MemPair::new`] yields two linked [`MemEnd`]s: whatever end A
//! sends, end B receives, and vice versa. Queues are bounded
//! ([`MEM_QUEUE`] deep per direction); a full queue surfaces
//! [`IfcError::QueueFull`] — the same backpressure verbs as a real
//! binding, minus the byte stream. Byte-level framing is covered by
//! [`crate::frame`] unit tests plus the `serial_pair` integration
//! test over a real pty.

use crate::{envelope::Envelope, IfcError};

/// Per-direction queue depth.
pub const MEM_QUEUE: usize = 8;

/// One message slot.
type Slot = Option<Envelope>;

/// Shared queues behind both ends (single-threaded reference only —
/// NOT `Sync`; the conformance tests drive both ends by hand, which
/// is exactly the deterministic interleaving a real binding must
/// also survive).
#[derive(Debug)]
struct Queues {
    a_to_b: [Slot; MEM_QUEUE],
    b_to_a: [Slot; MEM_QUEUE],
    a_len: usize,
    b_len: usize,
    closed: bool,
}

/// The pair IS the transport; sides are selected per call.
#[derive(Debug)]
pub struct MemLink {
    inner: Queues,
}

/// Which side of a [`MemLink`] acts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// First endpoint.
    A,
    /// Second endpoint.
    B,
}

impl MemLink {
    /// Fresh queues.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: Queues {
                a_to_b: [None, None, None, None, None, None, None, None],
                b_to_a: [None, None, None, None, None, None, None, None],
                a_len: 0,
                b_len: 0,
                closed: false,
            },
        }
    }

    fn inbox(&mut self, side: Side) -> &mut [Slot; MEM_QUEUE] {
        match side {
            Side::A => &mut self.inner.b_to_a,
            Side::B => &mut self.inner.a_to_b,
        }
    }

    fn inbox_len(&self, side: Side) -> usize {
        match side {
            Side::A => self.inner.b_len,
            Side::B => self.inner.a_len,
        }
    }

    fn inbox_len_mut(&mut self, side: Side) -> &mut usize {
        match side {
            Side::A => &mut self.inner.b_len,
            Side::B => &mut self.inner.a_len,
        }
    }

    /// Send from `side` to the peer. [`IfcError::QueueFull`] on
    /// backpressure, [`IfcError::Closed`] after [`MemLink::close`].
    pub fn send(&mut self, side: Side, msg: Envelope) -> Result<(), IfcError> {
        if self.inner.closed {
            return Err(IfcError::Closed);
        }
        let peer = match side {
            Side::A => Side::B,
            Side::B => Side::A,
        };
        let len = self.inbox_len(peer);
        if len >= MEM_QUEUE {
            return Err(IfcError::QueueFull);
        }
        self.inbox(peer)[len] = Some(msg);
        *self.inbox_len_mut(peer) += 1;
        Ok(())
    }

    /// Take the oldest message addressed to `side`, if any.
    pub fn recv(&mut self, side: Side) -> Option<Envelope> {
        let len = self.inbox_len(side);
        if len == 0 {
            return None;
        }
        let q = self.inbox(side);
        let first = q[0].take();
        q.rotate_left(1);
        *self.inbox_len_mut(side) -= 1;
        first
    }

    /// Pending inbound depth for `side` (backpressure readout).
    #[must_use]
    pub fn depth(&self, side: Side) -> usize {
        self.inbox_len(side)
    }

    /// Orderly shutdown: sends fail, pending receives still drain.
    pub fn close(&mut self) {
        self.inner.closed = true;
    }

    /// True after [`MemLink::close`].
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.inner.closed
    }

    /// Reopen after [`MemLink::close`] (reconnect path); queues keep
    /// whatever was never drained — the handshake `RESUME` seq decides
    /// what the peer must replay.
    pub fn reopen(&mut self) {
        self.inner.closed = false;
    }
}

impl Default for MemLink {
    fn default() -> Self {
        Self::new()
    }
}
