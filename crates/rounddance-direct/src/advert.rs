//! Direct BLE advertisement extension as data.
//!
//! Paraphrase-level model of doc `20-27688-041` §7.6.2–7.6.3
//! (connectable advertisements carrying the Direct extension
//! records: version, flags, PAN identifier, network address,
//! all-ones sentinels when unjoined, refreshed on state change),
//! §6.2.2 (provisioning-timeout advertisement quieting), and
//! §7.5.1 (link-drop advertisement resume).
//!
//! Requirement IDs: `20-27688-041-76-01` (advertisement records),
//! `20-27688-041-62-01` (provisioning timeout),
//! `20-27688-041-62-02` (awareness check), `20-27688-041-75-01`
//! (virtual-link capacity back-pressure on advertisements).

/// Advertisement failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvError {
    /// Input is not a Direct extension record.
    BadRecord,
    /// Caller buffer too small.
    BufferTooSmall,
}

/// Extension version carried in the low nibble
/// (`20-27688-041-76-01`).
pub const ADV_EXTENSION_VERSION: u8 = 0x1;
/// Sentinel for PAN/address fields while unjoined (all-ones).
pub const ADV_UNJOINED_SENTINEL: u16 = 0xFFFF;
/// AD type for service-data records carrying the extension.
pub const ADV_AD_TYPE_SERVICE_DATA: u8 = 0x16;
/// 16-bit UUID of the commissioning service in advertisements.
pub const ADV_COMMISSIONING_UUID16: u16 = 0xFFF7;
/// Full extension record length: AD length + type + UUID +
/// version/flags + PAN + address (`20-27688-041-76-01`).
pub const ADV_RECORD_LEN: usize = 9;

/// Direct extension to the BLE advertisement, Table 24
/// (`20-27688-041-76-01`): version nibble, capability/status
/// flags (tunnel-service support, permit-join state), PAN
/// identifier, and network address — PAN/address read all-ones
/// while unjoined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvExtension {
    /// Tunnel-service support flag.
    pub tunnel_supported: bool,
    /// Permit-joining status flag (forced clear while
    /// unjoined).
    pub permit_join: bool,
    /// PAN identifier (`0xFFFF` while unjoined).
    pub pan_id: u16,
    /// Network address (`0xFFFF` while unjoined).
    pub nwk_addr: u16,
}

impl AdvExtension {
    /// Factory-new record: unjoined sentinels, no flags.
    #[must_use]
    pub fn factory_new() -> Self {
        Self {
            tunnel_supported: false,
            permit_join: false,
            pan_id: ADV_UNJOINED_SENTINEL,
            nwk_addr: ADV_UNJOINED_SENTINEL,
        }
    }

    /// Whether the record shows a joined network.
    #[must_use]
    pub fn joined(&self) -> bool {
        self.pan_id != ADV_UNJOINED_SENTINEL
    }

    /// Encode the 9-octet record into `out` (little-endian
    /// fields); returns the written length.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, AdvError> {
        if out.len() < ADV_RECORD_LEN {
            return Err(AdvError::BufferTooSmall);
        }
        // Flags ride the high nibble (Table 24 bit numbers are
        // octet-relative: bit 4 = nibble bit 0, bit 5 = nibble
        // bit 1).
        let mut flags: u8 = 0;
        if self.tunnel_supported {
            flags |= 1 << 0;
        }
        if self.permit_join && self.joined() {
            flags |= 1 << 1;
        }
        out[0] = 0x08;
        out[1] = ADV_AD_TYPE_SERVICE_DATA;
        out[2..4].copy_from_slice(&ADV_COMMISSIONING_UUID16.to_le_bytes());
        out[4] = ADV_EXTENSION_VERSION | (flags << 4);
        out[5..7].copy_from_slice(&self.pan_id.to_le_bytes());
        out[7..9].copy_from_slice(&self.nwk_addr.to_le_bytes());
        Ok(ADV_RECORD_LEN)
    }

    /// Decode a 9-octet record.
    pub fn decode(input: &[u8]) -> Result<Self, AdvError> {
        if input.len() < ADV_RECORD_LEN
            || input[0] != 0x08
            || input[1] != ADV_AD_TYPE_SERVICE_DATA
            || u16::from_le_bytes([input[2], input[3]]) != ADV_COMMISSIONING_UUID16
            || input[4] & 0x0F != ADV_EXTENSION_VERSION
        {
            return Err(AdvError::BadRecord);
        }
        let flags = input[4] >> 4;
        Ok(Self {
            tunnel_supported: flags & (1 << 0) != 0,
            permit_join: flags & (1 << 1) != 0,
            pan_id: u16::from_le_bytes([input[5], input[6]]),
            nwk_addr: u16::from_le_bytes([input[7], input[8]]),
        })
    }
}

/// Advertisement-policy states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvPolicyState {
    /// Connectable advertisements carry the extension.
    Advertising,
    /// Provisioning timeout elapsed: extension dropped until
    /// power-cycle or user interaction (`20-27688-041-62-01`).
    Quiet,
    /// Link table full: extension removed while manufacturer
    /// advertisements may continue (`20-27688-041-75-01`).
    Suspended,
}

/// Advertisement policy machine on an injected tick clock (one
/// tick = one second).
#[derive(Debug, Clone, Copy)]
pub struct AdvPolicy {
    state: AdvPolicyState,
    /// Provisioning timeout in seconds (at least sixty,
    /// `20-27688-041-62-01`); manufacturer-defined.
    timeout_s: u32,
    elapsed_s: u32,
    provisioned: bool,
}

impl AdvPolicy {
    /// Minimum provisioning timeout (sixty seconds).
    pub const MIN_TIMEOUT_S: u32 = 60;

    /// New policy: advertising, unprovisioned, clock at zero.
    /// Timeouts below the sixty-second minimum are rejected
    /// (`None`).
    #[must_use]
    pub fn new(timeout_s: u32) -> Option<Self> {
        if timeout_s < Self::MIN_TIMEOUT_S {
            return None;
        }
        Some(Self {
            state: AdvPolicyState::Advertising,
            timeout_s,
            elapsed_s: 0,
            provisioned: false,
        })
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> AdvPolicyState {
        self.state
    }

    /// Whether the extension is currently advertised.
    #[must_use]
    pub fn extension_visible(&self) -> bool {
        self.state == AdvPolicyState::Advertising
    }

    /// Commissioning completed: stop the provisioning clock
    /// (network members keep advertising per §7.6.2 while link
    /// capacity allows).
    pub fn mark_provisioned(&mut self) {
        self.provisioned = true;
    }

    /// Leaving the network returns to open-to-provision
    /// advertising (`20-27688-041-62-02`).
    pub fn mark_unprovisioned(&mut self) {
        self.provisioned = false;
        self.elapsed_s = 0;
        self.state = AdvPolicyState::Advertising;
    }

    /// User interaction or power-cycle resumes advertising
    /// after a provisioning-timeout quiet
    /// (`20-27688-041-62-01`).
    pub fn user_resume(&mut self) {
        self.elapsed_s = 0;
        if self.state == AdvPolicyState::Quiet {
            self.state = AdvPolicyState::Advertising;
        }
    }

    /// Virtual-link table filled to capacity: drop the
    /// extension (`20-27688-041-75-01`).
    pub fn suspend(&mut self) {
        self.state = AdvPolicyState::Suspended;
    }

    /// Links freed or dropped: resume advertisements
    /// (`20-27688-041-75-01`).
    pub fn resume_links(&mut self) {
        if self.state == AdvPolicyState::Suspended {
            self.state = AdvPolicyState::Advertising;
        }
    }

    /// Advance one second: an unprovisioned device with no
    /// session drops the extension after the provisioning
    /// timeout (`20-27688-041-62-01`). `session_live` reports
    /// whether any BLE session is up (a live session holds
    /// the clock).
    pub fn tick_1s(&mut self, session_live: bool) {
        if self.provisioned || session_live {
            return;
        }
        if self.state != AdvPolicyState::Advertising {
            return;
        }
        self.elapsed_s = self.elapsed_s.saturating_add(1);
        if self.elapsed_s >= self.timeout_s {
            self.state = AdvPolicyState::Quiet;
        }
    }
}
