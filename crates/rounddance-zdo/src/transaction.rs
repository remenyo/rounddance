//! Post-join ZDP transaction tracker: request/response correlation
//! by transaction sequence plus cluster.
//!
//! Paraphrase-level model of the device-profile transaction rule: a
//! request carries a one-octet transaction sequence that the matching
//! response echoes, and the response rides the request cluster with
//! the response bit set ([`crate::cluster::response_cluster`]).
//! Commands that carry no response (`Device_annce`) never open a
//! transaction. All wording here is paraphrase (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped), MINTED-pending-confirm.

use crate::cluster::{response_cluster, CLUSTER_DEVICE_ANNCE};

/// One open request: the cluster it went out on plus its sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    /// Request cluster the transaction opened on.
    pub req_cluster: u16,
    /// Transaction sequence echoed by the response.
    pub tsn: u8,
}

/// Why a transaction could not open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxnError {
    /// The command carries no response, so nothing can correlate to.
    NoResponse,
    /// The same cluster + sequence is already open.
    Duplicate,
    /// No free slot in the table.
    TableFull,
}

/// Bounded table of open ZDP transactions (caller-owned TSN
/// allocation; wrap-around reuse is safe once the old entry closes).
///
/// Requirement `05-3474-23-24401-01` (MINTED-pending-confirm).
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

    /// Open a transaction for a request on `req_cluster` with sequence
    /// `tsn`. Refuses response-less commands, duplicates, and a full
    /// table instead of aliasing or growing.
    pub fn open(&mut self, req_cluster: u16, tsn: u8) -> Result<(), TxnError> {
        if response_cluster(req_cluster).is_none() {
            return Err(TxnError::NoResponse);
        }
        let mut i = 0;
        while i < N {
            if self.entries[i] == Some(Pending { req_cluster, tsn }) {
                return Err(TxnError::Duplicate);
            }
            i += 1;
        }
        let mut slot = 0;
        while slot < N {
            if self.entries[slot].is_none() {
                self.entries[slot] = Some(Pending { req_cluster, tsn });
                self.len += 1;
                return Ok(());
            }
            slot += 1;
        }
        Err(TxnError::TableFull)
    }

    /// Close the transaction matching an incoming response cluster +
    /// sequence. Returns the request cluster the response correlates
    /// to, or `None` when the cluster has no response bit, names no
    /// known request, or matches no open entry (stray, replayed, or
    /// already-closed responses never correlate).
    pub fn close(&mut self, rsp_cluster: u16, tsn: u8) -> Option<u16> {
        let mut i = 0;
        while i < N {
            if let Some(p) = self.entries[i] {
                if response_cluster(p.req_cluster) == Some(rsp_cluster) && p.tsn == tsn {
                    self.entries[i] = None;
                    self.len -= 1;
                    return Some(p.req_cluster);
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

/// Whether a request cluster may open a transaction (every command
/// except the response-less announce).
///
/// Requirement `05-3474-23-24401-01` (MINTED-pending-confirm).
#[must_use]
pub const fn transaction_expected(req_cluster: u16) -> bool {
    req_cluster != CLUSTER_DEVICE_ANNCE && response_cluster(req_cluster).is_some()
}
