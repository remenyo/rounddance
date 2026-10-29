//! Post-join ZCL transaction layer: sequence allocation, reply
//! correlation, and Default Response generation.
//!
//! Paraphrase-level model of doc `07-5123-08` §2.4.1.3 (the
//! transaction sequence chains requests to replies, anchor
//! p0061-L2398-L2404) and §2.5.12.2 (when the Default Response is
//! generated, anchors p0080-L2995-L3000 + p0081-L3001-L3016). The
//! triage rule itself lives in [`crate::dispatch::should_default_respond`];
//! this module owns the per-endpoint pending set plus the reply bytes.
//! All wording here is paraphrase (D1).
//!
//! Requirement IDs below: `07-5123-08-2413-01` + `07-5123-08-2412-02`
//! (corpus-mined, sequence copy + reply disable-bit, reused via
//! [`Header::reply_to`](crate::frame::Header::reply_to)),
//! `07-5123-08-2512-01/02` (corpus-mined, triage reused), plus
//! repo-minted `07-5123-08-<clause>-<seq>` rows MINTED-pending-confirm.

use crate::dispatch::should_default_respond;
use crate::frame::{Direction, Header};
use crate::general::{cmd::DEFAULT_RSP, DefaultRsp};
use crate::{Error, ZclStatus};

/// Wrapping transaction-sequence allocator: each request takes the
/// next octet, so in-flight reuse only happens after 256 requests.
///
/// Requirement `07-5123-08-2413-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TsnAlloc {
    next: u8,
}

impl TsnAlloc {
    /// New allocator starting at `start` (boot: `0x00`).
    #[must_use]
    pub const fn new(start: u8) -> Self {
        Self { next: start }
    }

    /// Take the next sequence number.
    pub fn take(&mut self) -> u8 {
        let tsn = self.next;
        self.next = self.next.wrapping_add(1);
        tsn
    }

    /// Sequence number the next [`take`](Self::take) returns.
    #[must_use]
    pub const fn peek(&self) -> u8 {
        self.next
    }
}

/// One open request awaiting its reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    /// Sequence the reply must echo.
    pub tsn: u8,
    /// Cluster the reply must arrive on.
    pub cluster: u16,
    /// Command the request sent (kept for diagnostics only).
    pub command: u8,
}

/// Why a transaction could not open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxnError {
    /// The same sequence is already open on this endpoint.
    Duplicate,
    /// No free slot in the table.
    TableFull,
}

/// Bounded table of open ZCL transactions: replies correlate by
/// echoed sequence plus cluster, never by either alone.
///
/// Requirement `07-5123-08-2413-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug)]
pub struct PendingTable<const N: usize> {
    entries: [Option<Pending>; N],
    len: usize,
}

impl<const N: usize> Default for PendingTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PendingTable<N> {
    /// Empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            len: 0,
        }
    }

    /// Open a transaction for an outgoing request frame. A duplicate
    /// sequence on the same endpoint is refused rather than aliased.
    pub fn open(&mut self, tsn: u8, cluster: u16, command: u8) -> Result<(), TxnError> {
        let mut i = 0;
        while i < N {
            if self.entries[i]
                == Some(Pending {
                    tsn,
                    cluster,
                    command,
                })
            {
                return Err(TxnError::Duplicate);
            }
            // Same sequence with any cluster/command still collides:
            // the reply keys on the sequence first.
            if matches!(self.entries[i], Some(p) if p.tsn == tsn) {
                return Err(TxnError::Duplicate);
            }
            i += 1;
        }
        let mut slot = 0;
        while slot < N {
            if self.entries[slot].is_none() {
                self.entries[slot] = Some(Pending {
                    tsn,
                    cluster,
                    command,
                });
                self.len += 1;
                return Ok(());
            }
            slot += 1;
        }
        Err(TxnError::TableFull)
    }

    /// Close the transaction matching an incoming reply header +
    /// cluster. Returns the open entry, or `None` for a stray,
    /// replayed, or already-closed sequence. Spontaneous
    /// server-to-client frames (reports) carry no open entry and stay
    /// `None`: the caller handles them, never this table.
    pub fn close(&mut self, header: &Header, cluster: u16) -> Option<Pending> {
        let mut i = 0;
        while i < N {
            if let Some(p) = self.entries[i] {
                if p.tsn == header.tsn && p.cluster == cluster {
                    self.entries[i] = None;
                    self.len -= 1;
                    return Some(p);
                }
            }
            i += 1;
        }
        None
    }

    /// Open transactions currently held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the table holds nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Whether an incoming frame travels toward the client side (the only
/// direction a reply to a client request may take).
///
/// Requirement `07-5123-08-2412-01` (corpus-mined, direction bit
/// reused).
#[must_use]
pub const fn reply_direction_ok(header: &Header) -> bool {
    matches!(header.control.direction, Direction::ToClient)
}

/// Largest Default Response frame this builder emits (worst-case
/// header + 2-octet body).
pub const MAX_DEFAULT_RSP_LEN: usize = 7;

/// Encode the Default Response for one dispatch outcome into `out`:
/// the reply header echoes the request sequence with the direction
/// flipped, and the body echoes the failed command plus its status.
/// Returns `None` (no bytes written) exactly when the triage rule
/// stays silent; errors answer even with the disable bit set.
///
/// Requirement `07-5123-08-2512-03` (MINTED-pending-confirm; triage
/// `07-5123-08-2512-01/02` corpus-mined and reused).
pub fn build_default_response(
    header: &Header,
    status: ZclStatus,
    is_unicast: bool,
    out: &mut [u8],
) -> Option<usize> {
    if !should_default_respond(header, is_unicast, false, !status.is_success()) {
        return None;
    }
    let reply = Header::reply_to(header, DEFAULT_RSP);
    let hn = reply.encode_into(out).ok()?;
    let body = DefaultRsp {
        cmd: header.command_id,
        status,
    };
    let bn = body.encode_into(&mut out[hn..]).ok()?;
    Some(hn + bn)
}

/// Decode one Default Response frame, returning the echoed command
/// plus its status.
pub fn decode_default_response(buf: &[u8]) -> Result<DefaultRsp, Error> {
    DefaultRsp::decode(buf)
}
