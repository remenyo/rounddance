//! Metering sampled data (cluster 0x0702): StartSampling /
//! GetSampledData command codecs plus the bounded sampling-session
//! engine and its single-answer retrieval.
//!
//! Paraphrase-level model of doc `07-5123-08` §10.4.3.3.1.8/9 (client
//! StartSampling / GetSampledData: session setup, cancellation, and
//! windowed retrieval) and §10.4.2.3.1.8/14 (server
//! GetSampledDataResponse / StartSamplingResponse: session id plus
//! the chronological sample series). All wording here is paraphrase
//! (D1).
//!
//! Requirement IDs below are repo-minted (`07-5123-08-1047-*`, dots
//! stripped), MINTED-pending-confirm.
//!
//! The engine captures through explicit `push` calls (live
//! measurement stays a caller input, like every behavior here); the
//! caller-second clock only opens sessions and filters windows, so
//! replay stays deterministic.

use crate::{Error, ZclStatus};

/// Client generated (server receives): StartSampling (open or cancel
/// a sampling session).
///
/// Requirement `07-5123-08-1047-01` (MINTED-pending-confirm).
pub const CMD_START_SAMPLING: u8 = 0x07;
/// Client generated (server receives): GetSampledData (windowed read
/// of one session).
///
/// Requirement `07-5123-08-1047-02` (MINTED-pending-confirm).
pub const CMD_GET_SAMPLED_DATA: u8 = 0x08;
/// Server generated: GetSampledDataResponse (session header plus the
/// chronological sample series).
///
/// Requirement `07-5123-08-1047-02` (MINTED-pending-confirm).
pub const CMD_GET_SAMPLED_DATA_RESPONSE: u8 = 0x07;
/// Server generated: StartSamplingResponse (allocated session id, or
/// the failure sentinel when no session is free).
///
/// Requirement `07-5123-08-1047-01` (MINTED-pending-confirm).
pub const CMD_START_SAMPLING_RESPONSE: u8 = 0x0D;

/// Sample type: delivered-consumption deltas.
///
/// Requirement `07-5123-08-1047-03` (MINTED-pending-confirm).
pub const SAMPLE_DELIVERED: u8 = 0x00;
/// Sample type: received-consumption deltas.
pub const SAMPLE_RECEIVED: u8 = 0x01;
/// Sample type: reactive-delivered deltas.
pub const SAMPLE_REACTIVE_DELIVERED: u8 = 0x02;
/// Sample type: reactive-received deltas.
pub const SAMPLE_REACTIVE_RECEIVED: u8 = 0x03;
/// Sample type: instantaneous-demand snapshots (signed 24-bit
/// carrier; all other types are unsigned 24-bit deltas).
pub const SAMPLE_DEMAND: u8 = 0x04;

/// Sample value marking an invalid sample.
///
/// Requirement `07-5123-08-1047-03` (MINTED-pending-confirm).
pub const SAMPLE_INVALID: u32 = 0x00FF_FFFF;
/// Start time cancelling the session filed under the same issuer.
///
/// Requirement `07-5123-08-1047-01` (MINTED-pending-confirm).
pub const START_CANCEL: u32 = 0xFFFF_FFFF;
/// Session id answering "no session free" (never allocated).
///
/// Requirement `07-5123-08-1047-01` (MINTED-pending-confirm).
pub const SAMPLE_ID_NONE: u16 = 0xFFFF;
/// Session id reserved for the profile back-door (never allocated
/// here).
///
/// Requirement `07-5123-08-1047-01` (MINTED-pending-confirm).
pub const SAMPLE_ID_RESERVED: u16 = 0x0000;

/// Largest concurrent sampling sessions (bounded; a further open
/// answers the failure sentinel, never grows).
///
/// Requirement `07-5123-08-1047-04` (MINTED-pending-confirm).
pub const MAX_SESSIONS: usize = 2;
/// Largest samples kept per session (bounds one response: the 11
/// header octets plus 16 samples fit the 64-octet reply path).
///
/// Requirement `07-5123-08-1047-04` (MINTED-pending-confirm).
pub const MAX_SAMPLES_PER_SESSION: usize = 16;
/// Largest samples carried in one GetSampledDataResponse decode.
///
/// Requirement `07-5123-08-1047-02` (MINTED-pending-confirm).
pub const MAX_SAMPLES_PER_RESPONSE: usize = 16;

/// Whether a sample-type value names captured data here.
#[must_use]
pub const fn sample_type_known(sample_type: u8) -> bool {
    sample_type <= SAMPLE_DEMAND
}

/// StartSampling request: session setup or cancellation.
///
/// Requirement `07-5123-08-1047-01` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartSampling {
    /// Commodity-provider sequence (stale values are ignored, never
    /// applied; equal-or-older never opens a session).
    pub issuer: u32,
    /// First capture time (0 opens at once, `START_CANCEL` closes the
    /// issuer's session).
    pub start: u32,
    /// Which quantity to capture (`SAMPLE_*`).
    pub sample_type: u8,
    /// Seconds between captures.
    pub interval_s: u16,
    /// Captures to keep (capped at `MAX_SAMPLES_PER_SESSION`).
    pub max_samples: u16,
}

/// Decode a StartSampling body: exactly 13 octets.
pub fn decode_start_sampling(buf: &[u8]) -> Result<StartSampling, Error> {
    if buf.len() != 13 {
        return Err(Error::Truncated);
    }
    Ok(StartSampling {
        issuer: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        start: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        sample_type: buf[8],
        interval_s: u16::from_le_bytes([buf[9], buf[10]]),
        max_samples: u16::from_le_bytes([buf[11], buf[12]]),
    })
}

/// Encode a StartSampling body into `out` (13 octets).
pub fn encode_start_sampling(req: &StartSampling, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 13 {
        return Err(Error::BufferTooSmall);
    }
    out[..4].copy_from_slice(&req.issuer.to_le_bytes());
    out[4..8].copy_from_slice(&req.start.to_le_bytes());
    out[8] = req.sample_type;
    out[9..11].copy_from_slice(&req.interval_s.to_le_bytes());
    out[11..13].copy_from_slice(&req.max_samples.to_le_bytes());
    Ok(13)
}

/// Encode a StartSamplingResponse body (one session id) into `out`.
pub fn encode_start_response(sample_id: u16, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 2 {
        return Err(Error::BufferTooSmall);
    }
    out[..2].copy_from_slice(&sample_id.to_le_bytes());
    Ok(2)
}

/// Decode a StartSamplingResponse body: exactly 2 octets.
pub fn decode_start_response(buf: &[u8]) -> Result<u16, Error> {
    if buf.len() != 2 {
        return Err(Error::Truncated);
    }
    Ok(u16::from_le_bytes([buf[0], buf[1]]))
}

/// GetSampledData request: windowed read of one session.
///
/// Requirement `07-5123-08-1047-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetSampledData {
    /// Session to read (allocated by StartSamplingResponse).
    pub sample_id: u16,
    /// Earliest sample stamp to return (inclusive).
    pub earliest: u32,
    /// Required sample type (must match the session).
    pub sample_type: u8,
    /// Samples wanted (capped at the session size).
    pub count: u16,
}

/// Decode a GetSampledData body: exactly 9 octets.
pub fn decode_get_sampled_data(buf: &[u8]) -> Result<GetSampledData, Error> {
    if buf.len() != 9 {
        return Err(Error::Truncated);
    }
    Ok(GetSampledData {
        sample_id: u16::from_le_bytes([buf[0], buf[1]]),
        earliest: u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]),
        sample_type: buf[6],
        count: u16::from_le_bytes([buf[7], buf[8]]),
    })
}

/// Encode a GetSampledData body into `out` (9 octets).
pub fn encode_get_sampled_data(req: &GetSampledData, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 9 {
        return Err(Error::BufferTooSmall);
    }
    out[..2].copy_from_slice(&req.sample_id.to_le_bytes());
    out[2..6].copy_from_slice(&req.earliest.to_le_bytes());
    out[6] = req.sample_type;
    out[7..9].copy_from_slice(&req.count.to_le_bytes());
    Ok(9)
}

/// Fixed GetSampledDataResponse header length (id + start + type +
/// interval + count).
pub const SAMPLED_DATA_HEADER_LEN: usize = 11;

/// Encode a GetSampledDataResponse body (header plus the 24-bit
/// sample series) into `out`.
pub fn encode_sampled_data_response(
    sample_id: u16,
    start: u32,
    sample_type: u8,
    interval_s: u16,
    samples: &[u32],
    out: &mut [u8],
) -> Result<usize, Error> {
    if samples.len() > MAX_SAMPLES_PER_RESPONSE {
        return Err(Error::InvalidValue(samples.len() as u8));
    }
    let need = SAMPLED_DATA_HEADER_LEN + 3 * samples.len();
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    out[..2].copy_from_slice(&sample_id.to_le_bytes());
    out[2..6].copy_from_slice(&start.to_le_bytes());
    out[6] = sample_type;
    out[7..9].copy_from_slice(&interval_s.to_le_bytes());
    out[9..11].copy_from_slice(&(samples.len() as u16).to_le_bytes());
    let mut i = 0;
    while i < samples.len() {
        let raw = (samples[i] & 0x00FF_FFFF).to_le_bytes();
        out[11 + 3 * i..14 + 3 * i].copy_from_slice(&raw[..3]);
        i += 1;
    }
    Ok(need)
}

/// Decoded GetSampledDataResponse body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedSampledData {
    /// Session this answers.
    pub sample_id: u16,
    /// Stamp of the first returned sample.
    pub start: u32,
    /// Sample type carried.
    pub sample_type: u8,
    /// Seconds between captures.
    pub interval_s: u16,
    /// Sample values (24-bit significant).
    pub samples: [u32; MAX_SAMPLES_PER_RESPONSE],
    /// Significant samples.
    pub count: u8,
}

impl DecodedSampledData {
    /// Sample slice.
    #[must_use]
    pub const fn sample_values(&self) -> &[u32] {
        self.samples.split_at(self.count as usize).0
    }
}

/// Decode a GetSampledDataResponse body.
pub fn decode_sampled_data_response(buf: &[u8]) -> Result<DecodedSampledData, Error> {
    if buf.len() < SAMPLED_DATA_HEADER_LEN {
        return Err(Error::Truncated);
    }
    let tail = buf.len() - SAMPLED_DATA_HEADER_LEN;
    if !tail.is_multiple_of(3) {
        return Err(Error::MalformedList);
    }
    let count = tail / 3;
    if count > MAX_SAMPLES_PER_RESPONSE {
        return Err(Error::InvalidValue(count as u8));
    }
    let declared = u16::from_le_bytes([buf[9], buf[10]]) as usize;
    if declared != count {
        return Err(Error::MalformedList);
    }
    let mut samples = [0u32; MAX_SAMPLES_PER_RESPONSE];
    let mut i = 0;
    while i < count {
        let b = &buf[11 + 3 * i..14 + 3 * i];
        samples[i] = u32::from_le_bytes([b[0], b[1], b[2], 0]);
        i += 1;
    }
    Ok(DecodedSampledData {
        sample_id: u16::from_le_bytes([buf[0], buf[1]]),
        start: u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]),
        sample_type: buf[6],
        interval_s: u16::from_le_bytes([buf[7], buf[8]]),
        samples,
        count: count as u8,
    })
}

/// One sampling session: configuration plus the chronological
/// capture log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SampleSession {
    id: u16,
    issuer: u32,
    sample_type: u8,
    interval_s: u16,
    max: u8,
    start: u32,
    stamps: [u32; MAX_SAMPLES_PER_SESSION],
    values: [u32; MAX_SAMPLES_PER_SESSION],
    len: u8,
    open: bool,
}

impl SampleSession {
    /// Session identifier.
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// Configured sample type.
    #[must_use]
    pub const fn sample_type(&self) -> u8 {
        self.sample_type
    }

    /// Captured sample count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// No samples captured yet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Session still accepting captures.
    #[must_use]
    pub const fn open(&self) -> bool {
        self.open
    }

    /// Session start stamp.
    #[must_use]
    pub const fn start(&self) -> u32 {
        self.start
    }
}

/// Bounded sampling-session engine: open/cancel/push/query with
/// issuer serialisation.
///
/// Requirement `07-5123-08-1047-04` (MINTED-pending-confirm): stale
/// issuers are ignored, cancellations free the issuer's session, a
/// full engine answers the failure sentinel, and retrieval returns
/// the single matching window or `NOT_FOUND`.
#[derive(Clone, Copy, Debug)]
pub struct SampleEngine {
    sessions: [Option<SampleSession>; MAX_SESSIONS],
    len: u8,
    next_id: u16,
    last_issuer: u32,
    seen_issuer: bool,
}

impl Default for SampleEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Session-open verdict: either the allocated id or a typed reason
/// the behavior maps onto its reply path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenVerdict {
    /// Session allocated (id usable in GetSampledData).
    Opened(u16),
    /// Stale issuer: ignored, no reply.
    Stale,
    /// Cancelled the issuer's session: no reply.
    Cancelled,
    /// No free session slot: answer the failure sentinel.
    Full,
    /// Unusable request (unknown type, zero interval, zero count):
    /// answer `InvalidField`.
    Unusable,
}

impl SampleEngine {
    /// Empty engine; first allocated session takes id 1.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sessions: [None; MAX_SESSIONS],
            len: 0,
            next_id: 1,
            last_issuer: 0,
            seen_issuer: false,
        }
    }

    /// Live session count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// No sessions held.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Look a session up by id.
    pub fn session(&self, id: u16) -> Option<&SampleSession> {
        let mut i = 0;
        while i < self.len as usize {
            if let Some(s) = self.sessions[i] {
                if s.id == id {
                    return self.sessions[i].as_ref();
                }
            }
            i += 1;
        }
        None
    }

    /// Open, cancel, or refuse one StartSampling request.
    pub fn open(&mut self, req: &StartSampling, now: u32) -> OpenVerdict {
        if req.start == START_CANCEL {
            let mut i = 0;
            while i < self.len as usize {
                if let Some(s) = self.sessions[i] {
                    if s.issuer == req.issuer {
                        self.sessions[i] = self.sessions[self.len as usize - 1];
                        self.sessions[self.len as usize - 1] = None;
                        self.len -= 1;
                        return OpenVerdict::Cancelled;
                    }
                }
                i += 1;
            }
            // Cancelling an unknown session is still a cancel.
            return OpenVerdict::Cancelled;
        }
        if self.seen_issuer && req.issuer <= self.last_issuer {
            return OpenVerdict::Stale;
        }
        if !sample_type_known(req.sample_type) || req.interval_s == 0 || req.max_samples == 0 {
            return OpenVerdict::Unusable;
        }
        if self.len as usize >= MAX_SESSIONS {
            self.last_issuer = req.issuer;
            self.seen_issuer = true;
            return OpenVerdict::Full;
        }
        let mut id = self.next_id;
        // Skip the reserved and failure sentinels on wrap.
        if id == SAMPLE_ID_RESERVED || id == SAMPLE_ID_NONE {
            id = id.wrapping_add(1);
        }
        if id == SAMPLE_ID_RESERVED || id == SAMPLE_ID_NONE {
            id = id.wrapping_add(1);
        }
        self.next_id = id.wrapping_add(1);
        if self.next_id == SAMPLE_ID_RESERVED || self.next_id == SAMPLE_ID_NONE {
            self.next_id = self.next_id.wrapping_add(1);
        }
        let cap = (req.max_samples as usize).min(MAX_SAMPLES_PER_SESSION) as u8;
        self.sessions[self.len as usize] = Some(SampleSession {
            id,
            issuer: req.issuer,
            sample_type: req.sample_type,
            interval_s: req.interval_s,
            max: cap,
            start: req.start,
            stamps: [0u32; MAX_SAMPLES_PER_SESSION],
            values: [0u32; MAX_SAMPLES_PER_SESSION],
            len: 0,
            open: req.start == 0 || req.start <= now,
        });
        self.len += 1;
        self.last_issuer = req.issuer;
        self.seen_issuer = true;
        OpenVerdict::Opened(id)
    }

    /// Open sessions whose start time arrived; returns the count
    /// opened (the behavior fans out state events from this).
    pub fn tick(&mut self, now: u32) -> u8 {
        let mut n = 0;
        let mut i = 0;
        while i < self.len as usize {
            if let Some(mut s) = self.sessions[i] {
                if !s.open && s.start != START_CANCEL && now >= s.start {
                    s.open = true;
                    self.sessions[i] = Some(s);
                    n += 1;
                }
            }
            i += 1;
        }
        n
    }

    /// Capture one sample into an open session that still has room;
    /// full or unopened sessions (and unknown ids) refuse quietly so
    /// measurement overruns never disturb the protocol path.
    pub fn push(&mut self, id: u16, value: u32, now: u32) -> bool {
        let mut i = 0;
        while i < self.len as usize {
            if let Some(mut s) = self.sessions[i] {
                if s.id == id {
                    if !s.open || s.len as usize >= s.max as usize {
                        return false;
                    }
                    s.stamps[s.len as usize] = now;
                    s.values[s.len as usize] = value & 0x00FF_FFFF;
                    s.len += 1;
                    if s.len >= s.max {
                        s.open = false;
                    }
                    self.sessions[i] = Some(s);
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    /// Read the window of one session into `out` (chronological,
    /// oldest first): unknown ids and empty windows answer
    /// `NOT_FOUND`, type mismatches answer `InvalidField`, and wider
    /// requests are capped at the session size.
    pub fn query(
        &self,
        req: &GetSampledData,
        out: &mut [u32; MAX_SAMPLES_PER_RESPONSE],
    ) -> Result<(u32, u8, u16, u8), ZclStatus> {
        let s = self.session(req.sample_id).ok_or(ZclStatus::NotFound)?;
        if req.sample_type != s.sample_type {
            return Err(ZclStatus::InvalidField);
        }
        let want = (req.count as usize).min(s.max as usize);
        let mut n = 0usize;
        let mut first = 0u32;
        let mut first_set = false;
        let mut i = 0;
        while i < s.len as usize && n < want && n < MAX_SAMPLES_PER_RESPONSE {
            if s.stamps[i] >= req.earliest {
                if !first_set {
                    first = s.stamps[i];
                    first_set = true;
                }
                out[n] = s.values[i];
                n += 1;
            }
            i += 1;
        }
        if n == 0 {
            return Err(ZclStatus::NotFound);
        }
        Ok((first, s.sample_type, s.interval_s, n as u8))
    }
}
