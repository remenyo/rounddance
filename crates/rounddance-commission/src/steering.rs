//! Network steering: beacon survey structures and join-decision machine.
//!
//! Paraphrase-level model of doc `22-65816-030` BDB v3.1 §9 + §9.1
//! (steering families, discovery scan, suitability via the discovery
//! table; anchors p0059-L1261-L1268 + p0060-L1280-L1296) and doc
//! `05-3474-23` R23.2 §3.6.1.6.1 (discovery procedure; anchor
//! p0222-L5278) with §3.6.1.3 (beacon processing; anchor p0249-L5842).
//! All wording here is paraphrase (D1, `SCOPE.md` §2).
//!
//! Requirement IDs: corpus-mined `22-65816-030-91-01`; repo-minted
//! `05-3474-23-3613-*` / `05-3474-23-36161-*` (dots stripped),
//! MINTED-pending-confirm.
//!
//! The survey records what the discovery scan heard; the application
//! owns suitability (this crate only ranks acceptable candidates).

/// Largest discovery table this crate keeps (declared budget; longer
/// over-air lists are truncated scan-side, never grown here).
///
/// Requirement `22-65816-030-91-01` (discovery table carries the
/// suitability inputs).
pub const MAX_SURVEY_ENTRIES: usize = 16;

/// One heard beacon: the discovery-table row the application judges.
///
/// Requirement `05-3474-23-3613-01` (beacon processing feeds
/// discovery; anchor p0249-L5842).
///
/// Every row is one FCS-passing decode: presence in the table IS the
/// decode evidence (the radio only delivers frames that pass the
/// hardware check). `rssi`/`lqi` are that frame's own meters, filled by
/// whoever heard it (on ESP: the HAL's per-frame snapshot, `frame_info`
/// first, frame tail second).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconSurveyEntry {
    /// PAN identifier heard.
    pub pan_id: u16,
    /// Channel the beacon arrived on.
    pub channel: u8,
    /// Link quality 0–255 of the heard frame (ranks candidates;
    /// NEVER an absolute gate on flat-metering hardware — see
    /// [`LinkEvidencePolicy`]).
    pub lqi: u8,
    /// RSSI in dBm of the heard frame (sanity-gates admission; see
    /// [`LinkEvidencePolicy`]).
    pub rssi: i8,
    /// Whether the beacon advertises joining permitted.
    pub permit_joining: bool,
    /// Whether a router child would have room.
    pub router_capacity: bool,
    /// Whether an end-device child would have room.
    pub end_device_capacity: bool,
    /// Protocol version heard (join rules may gate on it).
    pub protocol_version: u8,
}

/// Survey failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurveyError {
    /// Discovery table is full (declared budget exhausted).
    TableFull,
    /// Channel outside 11–26.
    BadChannel,
    /// Operation not allowed in the current machine state.
    BadState,
}

/// Bounded discovery table: joinable-network rows only are ingested by
/// the machine; storage itself just holds rows.
///
/// Requirement `22-65816-030-91-01`.
#[derive(Debug, Clone)]
pub struct SurveyTable {
    entries: [Option<BeaconSurveyEntry>; MAX_SURVEY_ENTRIES],
    len: usize,
}

impl SurveyTable {
    /// Empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_SURVEY_ENTRIES],
            len: 0,
        }
    }

    /// Rows held.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether no rows are held.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Insert a row; a full table reports `TableFull`, never grows.
    pub fn add(&mut self, entry: BeaconSurveyEntry) -> Result<(), SurveyError> {
        if !(11..=26).contains(&entry.channel) {
            return Err(SurveyError::BadChannel);
        }
        if self.len >= MAX_SURVEY_ENTRIES {
            return Err(SurveyError::TableFull);
        }
        match self.entries.iter_mut().find(|e| e.is_none()) {
            Some(slot) => {
                *slot = Some(entry);
                self.len += 1;
                Ok(())
            }
            None => Err(SurveyError::TableFull),
        }
    }

    /// Iterate held rows in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &BeaconSurveyEntry> {
        self.entries.iter().filter_map(|e| e.as_ref())
    }

    /// Drop all rows (next scan starts clean).
    pub fn clear(&mut self) {
        self.entries = [None; MAX_SURVEY_ENTRIES];
        self.len = 0;
    }
}

impl Default for SurveyTable {
    fn default() -> Self {
        Self::new()
    }
}

/// What the steering scan asks the MAC to look for.
///
/// Requirement `22-65816-030-91-01`: the scan asks only for
/// join-permitted networks with end-device room; a bad scan fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryScan {
    /// Channels to scan.
    pub channels: crate::formation::ChannelMask,
    /// Scan duration exponent.
    pub scan_duration: u8,
    /// Always true: only join-permitted beacons are wanted.
    pub join_permitted_only: bool,
    /// Always true: networks must have end-device room.
    pub require_end_device_capacity: bool,
}

impl DiscoveryScan {
    /// Build a scan over `channels`.
    #[must_use]
    pub const fn new(channels: crate::formation::ChannelMask, scan_duration: u8) -> Self {
        Self {
            channels,
            scan_duration,
            join_permitted_only: true,
            require_end_device_capacity: true,
        }
    }
}

/// Application suitability gate: the stack discovers, the application
/// judges (`22-65816-030-91-01`: suitability is read from the
/// discovery table by the application).
pub trait SteeringPolicy {
    /// Whether this candidate may be joined (permit flag, capacity,
    /// link margin, version policy — all application-owned).
    fn acceptable(&self, entry: &BeaconSurveyEntry) -> bool;
}

/// Baseline gate: join-permitted, end-device room, minimum link
/// quality. Tests and simple apps with honest meters use this
/// directly. NOT for C6 field units: their LQI meter reads flat 9–11
/// on links that decode ~100% (wave-27), so any absolute `min_lqi`
/// there is unpassable — use [`LinkEvidencePolicy`] instead.
#[derive(Debug, Clone, Copy)]
pub struct BaselineSteeringPolicy {
    /// Minimum link quality admitted.
    pub min_lqi: u8,
    /// Minimum protocol version admitted.
    pub min_version: u8,
}

impl SteeringPolicy for BaselineSteeringPolicy {
    fn acceptable(&self, entry: &BeaconSurveyEntry) -> bool {
        entry.permit_joining
            && entry.end_device_capacity
            && entry.lqi >= self.min_lqi
            && entry.protocol_version >= self.min_version
    }
}

/// Hardware-grounded suitability: decode success + RSSI sanity +
/// optional LQI floor. The default admission for field apps.
///
/// Admission is evidence, not a quality number:
/// * **Decode success** — table presence means one FCS-passing decode
///   of this beacon (the radio delivers nothing else). No counter is
///   claimed: one frame is one frame.
/// * **RSSI sanity** — the heard frame's RSSI must clear `min_rssi`.
///   The default (−90 dBm) sits 11 dB above the measured C6 noise floor
///   (ED −101 dBm, ch15, wave-2b audit) and far below every
///   field-observed successful decode (tail-RSSI −28/−29 dBm on the
///   bench link, wave-27): it rejects only pathologically weak beacons
///   while admitting everything the hardware can actually decode.
/// * **LQI is ranking-only by default** — highest LQI still wins the
///   candidate race (ties break to the lower PAN), but no absolute LQI
///   value gates admission (`lqi_floor: None`). Rationale: the C6 LQI
///   meter is flat 9–11 on ~100%-decode links (wave-27: same air grades
///   252/255 on the nRF) — an absolute floor would either be unpassable
///   (like the old `min_lqi = 100`) or pretend a number means something
///   it does not. Set `lqi_floor: Some` only on radios whose LQI meter
///   is calibrated, and document the calibration next to the value.
///
/// Requirement `22-65816-030-91-01` (suitability is read from the
/// discovery table by the application): this policy IS that
/// application-side reading for field hardware.
#[derive(Debug, Clone, Copy)]
pub struct LinkEvidencePolicy {
    /// Minimum protocol version admitted.
    pub min_version: u8,
    /// Minimum per-frame RSSI (dBm) admitted.
    pub min_rssi: i8,
    /// Optional absolute LQI floor. `None` (default) disables the LQI
    /// gate entirely — the honest setting for flat-metering units.
    pub lqi_floor: Option<u8>,
}

impl LinkEvidencePolicy {
    /// Field default: version 2+, RSSI sanity at −90 dBm, no LQI gate.
    /// Admits the wave-27 bench link (flat LQI 10–11, RSSI −28 dBm)
    /// that the old absolute gate rejected.
    #[must_use]
    pub const fn field_default() -> Self {
        Self {
            min_version: 2,
            min_rssi: -90,
            lqi_floor: None,
        }
    }
}

impl Default for LinkEvidencePolicy {
    fn default() -> Self {
        Self::field_default()
    }
}

impl SteeringPolicy for LinkEvidencePolicy {
    fn acceptable(&self, entry: &BeaconSurveyEntry) -> bool {
        entry.permit_joining
            && entry.end_device_capacity
            && entry.protocol_version >= self.min_version
            && entry.rssi >= self.min_rssi
            && self.lqi_floor.is_none_or(|floor| entry.lqi >= floor)
    }
}

/// Steering sequencing: scan, survey, rank, decide.
///
/// Requirements `22-65816-030-91-01` (off-network search-and-join
/// family; bad scan fails; application owns suitability) and
/// `05-3474-23-36161-01` (discovery procedure admits only the
/// scan the application configured; anchor p0222-L5278).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SteeringState {
    /// Created; no scan running.
    Idle,
    /// Discovery scan outstanding.
    Scanning,
    /// Scan done; a candidate was selected (see
    /// [`SteeringMachine::candidate`]).
    CandidateSelected,
    /// Scan done; nothing acceptable was heard.
    NoSuitableNetwork,
    /// Terminal failure (bad scan; see [`SteeringMachine::error`]).
    Failed,
}

/// Join-decision driver over a [`SurveyTable`].
pub struct SteeringMachine {
    state: SteeringState,
    survey: SurveyTable,
    candidate: Option<BeaconSurveyEntry>,
    scan_failed: bool,
}

impl SteeringMachine {
    /// Create idle with an empty survey.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: SteeringState::Idle,
            survey: SurveyTable::new(),
            candidate: None,
            scan_failed: false,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> SteeringState {
        self.state
    }

    /// Selected candidate (valid in `CandidateSelected`).
    #[must_use]
    pub const fn candidate(&self) -> Option<BeaconSurveyEntry> {
        self.candidate
    }

    /// Survey rows (read-only; the application judges suitability).
    #[must_use]
    pub const fn survey(&self) -> &SurveyTable {
        &self.survey
    }

    /// Whether the last scan failed.
    #[must_use]
    pub const fn scan_failed(&self) -> bool {
        self.scan_failed
    }

    /// Open the discovery scan: clears the table and enters
    /// `Scanning`. Returns the scan the MAC should run.
    pub fn begin_scan(
        &mut self,
        channels: crate::formation::ChannelMask,
        scan_duration: u8,
    ) -> Result<DiscoveryScan, SurveyError> {
        if self.state == SteeringState::Scanning {
            return Err(SurveyError::BadState);
        }
        self.survey.clear();
        self.candidate = None;
        self.scan_failed = false;
        self.state = SteeringState::Scanning;
        Ok(DiscoveryScan::new(channels, scan_duration))
    }

    /// Ingest one heard beacon while scanning. Rows that do not offer
    /// joining are still recorded (the application may judge them for
    /// diagnostics); selection filters later.
    pub fn ingest(&mut self, entry: BeaconSurveyEntry) -> Result<(), SurveyError> {
        if self.state != SteeringState::Scanning {
            return Err(SurveyError::BadState);
        }
        self.survey.add(entry)
    }

    /// Report a failed scan: the procedure fails
    /// (`22-65816-030-91-01`).
    pub fn on_scan_failed(&mut self) {
        if self.state == SteeringState::Scanning {
            self.state = SteeringState::Failed;
            self.scan_failed = true;
        }
    }

    /// Close the scan: rank acceptable rows by link quality (highest
    /// first, ties broken by lower PAN) and select the winner; with no
    /// acceptable row the machine parks in `NoSuitableNetwork` (the
    /// application may rescan with different channels).
    pub fn finish_scan<P: SteeringPolicy>(&mut self, policy: &P) {
        if self.state != SteeringState::Scanning {
            return;
        }
        let mut best: Option<BeaconSurveyEntry> = None;
        for entry in self.survey.iter() {
            if !policy.acceptable(entry) {
                continue;
            }
            let wins = match best {
                None => true,
                Some(b) => entry.lqi > b.lqi || (entry.lqi == b.lqi && entry.pan_id < b.pan_id),
            };
            if wins {
                best = Some(*entry);
            }
        }
        match best {
            Some(entry) => {
                self.candidate = Some(entry);
                self.state = SteeringState::CandidateSelected;
            }
            None => self.state = SteeringState::NoSuitableNetwork,
        }
    }
}

impl Default for SteeringMachine {
    fn default() -> Self {
        Self::new()
    }
}
