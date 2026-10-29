//! Secured APS data send/receive path: per-originator counter
//! management over the frame codec.
//!
//! Paraphrase-level model of doc `05-3474-23` R23.2 §2.2.5.1.1.5 (the
//! security flag marks a secured data frame), §2.2.5.1.7 (the APS
//! counter is the per-originator sequence), §2.2.5.2.3.1 (the data
//! acknowledgement echoes cluster/profile/counter with swapped
//! endpoints), §2.2.8.4.2 (duplicate rejection on source + counter),
//! §2.2.8.4.3 (acknowledgements are sent only for ack-requested
//! unicast frames), and §2.2.8.4.4 (acknowledgement correlation on
//! cluster + counter + endpoint, bounded wait with retransmit cap and
//! a NO_ACK confirm). Payload ciphering itself stays a radio/HAL
//! assist (wave-2b contract); this layer owns the flag, the counters,
//! the ack frames, and the receive checks, so what goes out secured
//! must validate on receipt and unsecured or replayed frames must be
//! refused. All wording here is paraphrase; citations name document,
//! revision, and clause only (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are repo-minted
//! (`05-3474-23-<clause>-<seq>`, dots stripped), MINTED-pending-confirm.
//! (`05-3474-23-22843-03/04` re-mint the wave-47 `22845-01/02` rows,
//! rejected by confirmation sweep 28 as duplicates of the anchored
//! batch-18 fragmentation entries; see wave-48 section.)

use crate::frame::{
    decode_ack, AckAddr, AckHeader, DataDest, DataHeader, DeliveryMode, Error as ApsError,
    FrameControl, FrameType,
};
use crate::retry::{AckExpect, AckInfo, DupRejectTable};
use crate::status::ApsStatus;

/// One secured APS data endpoint: allocates the outgoing counter,
/// tracks the acknowledgement expectation for unicast sends, and
/// rejects unsecured or replayed receives.
///
/// Requirement `05-3474-23-22843-03` (MINTED-pending-confirm;
/// re-mints wave-47 `05-3474-23-22845-01`).
#[derive(Debug)]
pub struct SecureDataLink {
    /// Next outgoing APS counter (wraps; in-flight reuse is the
    /// caller's ack-wait concern, as in [`crate::retry::RetrySession`]).
    tx_counter: u8,
    /// Source + counter pairs already delivered upward.
    dup: DupRejectTable,
    /// Outstanding unicast acknowledgement expectation, if any.
    pending: Option<AckExpect>,
}

impl SecureDataLink {
    /// New link: counter starts at `0x00`, no duplicates seen, no
    /// acknowledgement outstanding.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tx_counter: 0,
            dup: DupRejectTable::new(),
            pending: None,
        }
    }

    /// Next outgoing counter without advancing (test seam).
    #[must_use]
    pub const fn peek_counter(&self) -> u8 {
        self.tx_counter
    }

    /// Build the header for one secured outgoing data frame: the
    /// security flag is set, the counter is taken and advanced, and a
    /// unicast send records its acknowledgement expectation
    /// (broadcast/group sends record none: they carry no ack).
    ///
    /// Requirement `05-3474-23-22843-03` (MINTED-pending-confirm).
    pub fn send_header(
        &mut self,
        dest: DataDest,
        cluster_id: u16,
        profile_id: u16,
        src_endpoint: u8,
        ack_request: bool,
    ) -> (DataHeader, Option<AckExpect>) {
        let counter = self.tx_counter;
        self.tx_counter = self.tx_counter.wrapping_add(1);
        let expect = match dest {
            DataDest::Unicast { dst_endpoint } => Some(AckExpect {
                cluster_id,
                counter,
                dst_endpoint,
            }),
            _ => None,
        };
        self.pending = expect;
        let header = DataHeader {
            control: FrameControl {
                frame_type: FrameType::Data,
                delivery_mode: dest.delivery_mode(),
                ack_format: false,
                security: true,
                ack_request: ack_request && matches!(dest.delivery_mode(), DeliveryMode::Unicast),
                ext_header: false,
            },
            dest,
            cluster_id,
            profile_id,
            src_endpoint,
            counter,
            ext: None,
        };
        (header, expect)
    }

    /// Outstanding unicast acknowledgement expectation, if any.
    #[must_use]
    pub const fn pending_ack(&self) -> Option<AckExpect> {
        self.pending
    }

    /// Note one incoming acknowledgement: a matching unicast ack
    /// clears the expectation and reports success; anything else
    /// leaves it outstanding.
    ///
    /// Requirement `05-3474-23-22843-03` (MINTED-pending-confirm).
    pub fn note_ack(&mut self, cluster_id: u16, counter: u8, src_endpoint: u8) -> bool {
        match self.pending {
            Some(expect) if expect.matches(cluster_id, counter, src_endpoint) => {
                self.pending = None;
                true
            }
            _ => false,
        }
    }

    /// Accept one incoming secured data header from source `src`:
    /// refuses frames without the security flag, delivers each
    /// source + counter pair upward exactly once (replays report
    /// `NoAck`-family refusal via `ApsStatus::NoAck` so the caller
    /// keeps waiting rather than delivering twice), and returns the
    /// acknowledgement expectation the caller owes back for unicast
    /// frames (`None` for broadcast/group).
    ///
    /// Requirement `05-3474-23-22843-04` (MINTED-pending-confirm;
    /// re-mints wave-47 `05-3474-23-22845-02`).
    pub fn accept(
        &mut self,
        header: &DataHeader,
        src: u16,
    ) -> Result<Option<AckExpect>, ApsStatus> {
        if !header.control.security {
            return Err(ApsStatus::Unsecured);
        }
        if header.control.frame_type != FrameType::Data {
            return Err(ApsStatus::IllegalRequest);
        }
        if self.dup.observe(src, header.counter) {
            return Err(ApsStatus::NoAck);
        }
        Ok(match header.dest {
            DataDest::Unicast { .. } | DataDest::Broadcast { .. } => Some(AckExpect {
                cluster_id: header.cluster_id,
                counter: header.counter,
                dst_endpoint: header.src_endpoint,
            }),
            DataDest::Group { .. } => None,
        })
    }
}

impl Default for SecureDataLink {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the data acknowledgement owed for one received data header:
/// returns `Some` only when the frame requests it (ack-request bit
/// set) and is unicast — broadcast/group frames are never
/// acknowledged — with the addressing fields echoed (endpoints
/// swapped, cluster/profile/counter copied) and the ack-request bit
/// clear on the ack itself.
///
/// Requirement `05-3474-23-22844-02` (MINTED-pending-confirm).
#[must_use]
pub fn ack_for(header: &DataHeader, profile_id: u16) -> Option<AckHeader> {
    if !header.control.ack_request {
        return None;
    }
    let dst_endpoint = match header.dest {
        DataDest::Unicast { dst_endpoint } => dst_endpoint,
        _ => return None,
    };
    Some(AckHeader {
        control: FrameControl::ack_for_data(),
        addr: Some(AckAddr {
            dst_endpoint: header.src_endpoint,
            cluster_id: header.cluster_id,
            profile_id,
            src_endpoint: dst_endpoint,
        }),
        counter: header.counter,
        ext: None,
    })
}

/// Parse one received acknowledgement APDU into the correlation
/// triple (cluster, counter, source endpoint) the sender matches
/// against its outstanding expectation. Malformed or non-ack frames
/// are refused with the codec error; command acknowledgements (no
/// addressing fields) carry nothing to correlate and report `None`.
///
/// Requirement `05-3474-23-22844-02` (MINTED-pending-confirm).
pub fn parse_ack(buf: &[u8]) -> Result<Option<AckInfo>, ApsError> {
    let decoded = decode_ack(buf)?;
    Ok(decoded.header.addr.map(|addr| AckInfo {
        cluster_id: addr.cluster_id,
        counter: decoded.header.counter,
        src_endpoint: addr.src_endpoint,
    }))
}
