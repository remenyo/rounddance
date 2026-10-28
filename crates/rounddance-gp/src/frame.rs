//! GPDF frame codec: NWK frame control, extended control, GPD
//! addressing, security frame counter, command payload, MIC.
//!
//! Paraphrase-level model of doc `14-0563-19` §A.1.4 (frame formats;
//! anchors p0039-L737-L746, p0040-L750-L773, p0041-L778-L807,
//! p0042-L813-L836, p0043-L844-L873, p0044-L875-L889) and §A.1.5.1
//! (cGP ingress filtering; anchors p0044-L897-L909). All wording here
//! is paraphrase (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are corpus-mined `14-0563-19-*`.

/// Green Power cluster endpoint on infrastructure devices.
///
/// Requirement `14-0563-19-A11-01`.
pub const GP_ENDPOINT: u8 = 0xF2;

/// Protocol-version sub-field value carried in every GPDF.
///
/// Requirement `14-0563-19-A141-*` (frame-control layout).
pub const PROTOCOL_VERSION: u8 = 0x3;

/// Length of the on-air security frame counter (octets).
///
/// Requirement `14-0563-19-A141-*` (counter/MIC geometry).
pub const FRAME_COUNTER_LEN: usize = 4;

/// Length of the on-air message integrity code (octets).
///
/// Requirement `14-0563-19-A141-*` (counter/MIC geometry).
pub const COUNT_MIC_LEN: usize = 4;

/// Largest GPDF this codec will encode or decode (octets, bounded).
pub const MAX_GPDF: usize = 128;

/// Largest GPD command payload this codec carries (octets, bounded).
pub const MAX_GPD_PAYLOAD: usize = 64;

/// Frame-type sub-field values, bits 0–1 of the NWK frame control.
///
/// Requirement `14-0563-19-A141-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameType {
    /// `0b00`: data frame.
    Data,
    /// `0b01`: maintenance frame.
    Maintenance,
}

impl FrameType {
    /// Decode the 2-bit value; reserved patterns are rejected.
    ///
    /// Requirement `14-0563-19-A141-01`.
    pub const fn from_bits(bits: u8) -> Result<Self, GpError> {
        match bits & 0x03 {
            0x00 => Ok(Self::Data),
            0x01 => Ok(Self::Maintenance),
            v => Err(GpError::ReservedFrameType(v)),
        }
    }

    /// 2-bit wire value.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::Data => 0x00,
            Self::Maintenance => 0x01,
        }
    }
}

/// Application-identifier sub-field values, bits 0–2 of the extended
/// NWK frame control.
///
/// Requirement `14-0563-19-A141-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppId {
    /// `0b000`: GPD identified by 32-bit source identifier.
    SrcId,
    /// `0b001`: LPED application (recognized, opaque body here).
    Lped,
    /// `0b010`: GPD identified by IEEE address plus endpoint.
    Ieee,
}

impl AppId {
    /// Decode the 3-bit value; anything else is foreign and dropped.
    ///
    /// Requirement `14-0563-19-A141-01`.
    pub const fn from_bits(bits: u8) -> Result<Self, GpError> {
        match bits & 0x07 {
            0x00 => Ok(Self::SrcId),
            0x01 => Ok(Self::Lped),
            0x02 => Ok(Self::Ieee),
            v => Err(GpError::ForeignAppId(v)),
        }
    }

    /// 3-bit wire value.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::SrcId => 0x00,
            Self::Lped => 0x01,
            Self::Ieee => 0x02,
        }
    }
}

/// Security-level sub-field values, bits 3–4 of the extended control
/// (GP application identifiers).
///
/// Requirement `14-0563-19-A152-03` (level gating).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireSecurityLevel {
    /// `0b00`: no security; no counter or MIC on air.
    None,
    /// `0b10`: 4-octet counter plus 4-octet MIC.
    MicOnly,
    /// `0b11`: encrypted payload plus counter plus MIC.
    Encrypted,
}

impl WireSecurityLevel {
    /// Decode the 2-bit value; the reserved pattern is rejected.
    ///
    /// Requirement `14-0563-19-A152-03`.
    pub const fn from_bits(bits: u8) -> Result<Self, GpError> {
        match (bits >> 3) & 0x03 {
            0x00 => Ok(Self::None),
            0x02 => Ok(Self::MicOnly),
            0x03 => Ok(Self::Encrypted),
            v => Err(GpError::ReservedSecurityLevel(v)),
        }
    }

    /// 2-bit wire value (already shifted to bits 3–4).
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::None => 0x00,
            Self::MicOnly => 0x02 << 3,
            Self::Encrypted => 0x03 << 3,
        }
    }

    /// True when counter + MIC travel on air.
    #[must_use]
    pub const fn protected(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Typed failure for GPDF codec and ingress-filter operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpError {
    /// Caller buffer too small for the encoding.
    TooSmall,
    /// Input truncated: not enough octets for the declared fields.
    Truncated,
    /// Frame-type bits name no implemented frame.
    ReservedFrameType(u8),
    /// Protocol-version sub-field is not the specified value.
    BadVersion(u8),
    /// Application identifier is outside the handled set.
    ForeignAppId(u8),
    /// Security-level bits name no implemented level.
    ReservedSecurityLevel(u8),
    /// Extended control missing where the frame shape requires it.
    MissingExtControl,
    /// Extended control present where the frame shape forbids it.
    ForbiddenExtControl,
    /// Source identifier or IEEE address outside the usable range.
    BadIdentifier,
    /// Command payload exceeds the bounded codec budget.
    PayloadTooLarge,
    /// Proxy-originated frame arriving on a GPD-side ingress path.
    ProxyOriginated,
    /// Both receive-after-transmit and auto-commissioning asserted.
    ConflictingFlags,
    /// Commissioning-range command under no/low security.
    UnsecuredCommissioning,
    /// Maintenance-range command identifier rejected.
    BadMaintenanceCommand,
    /// Frame failed the proxy/sink security or freshness gate.
    SecurityFailed,
    /// No table entry covers this GPD.
    NoTableEntry,
    /// Table or queue has no free slot.
    TableFull,
    /// No entry matches this lookup.
    NotFound,
    /// Operation not allowed in the current machine state.
    BadState,
    /// Bidirectional completion needs the follow-up reply path.
    BidirectionalPending,
    /// Bidirectional reply window elapsed with no Success frame.
    ReplyTimeout,
    /// Success (or reply-targeted) frame names a GPD the session is
    /// not waiting on.
    TransactionMismatch,
    /// GPD asked for a key without opening a receive window, or
    /// without the security capability the request needs.
    PeerIncapable,
}

/// NWK frame control octet (Figure 6 geometry).
///
/// Requirement `14-0563-19-A141-*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NwkFrameControl {
    /// Data vs maintenance.
    pub frame_type: FrameType,
    /// Auto-commissioning sub-field.
    pub auto_commissioning: bool,
    /// Extension-present sub-field.
    pub ext_present: bool,
}

impl NwkFrameControl {
    /// Decode one octet; reserved types and wrong versions rejected.
    ///
    /// Requirement `14-0563-19-A141-01`.
    pub const fn decode(byte: u8) -> Result<Self, GpError> {
        let frame_type = match FrameType::from_bits(byte) {
            Ok(t) => t,
            Err(e) => return Err(e),
        };
        let version = (byte >> 2) & 0x0F;
        if version != PROTOCOL_VERSION {
            return Err(GpError::BadVersion(version));
        }
        Ok(Self {
            frame_type,
            auto_commissioning: byte & 0x40 != 0,
            ext_present: byte & 0x80 != 0,
        })
    }

    /// Encode one octet.
    #[must_use]
    pub const fn encode(self) -> u8 {
        self.frame_type.bits()
            | (PROTOCOL_VERSION << 2)
            | ((self.auto_commissioning as u8) << 6)
            | ((self.ext_present as u8) << 7)
    }
}

/// Extended NWK frame control octet (Figures 7–8 geometry, GP/LPED
/// application identifiers).
///
/// Requirement `14-0563-19-A141-*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtFrameControl {
    /// Which identity scheme the frame uses.
    pub app_id: AppId,
    /// Protection level (GP identifiers only).
    pub level: WireSecurityLevel,
    /// Key-type wire bit (GP identifiers only).
    pub key_bit: bool,
    /// Receive-after-transmit request (GP identifiers only).
    pub rx_after_tx: bool,
    /// Sender side: clear = GPD, set = proxy (GP identifiers only).
    pub direction_proxy: bool,
}

impl ExtFrameControl {
    /// GPD-side data frame defaults: SrcId identity, no security,
    /// no receive window, GPD-originated.
    ///
    /// Requirement `14-0563-19-A141-03` (direction defaults clear).
    #[must_use]
    pub const fn gpd_data() -> Self {
        Self {
            app_id: AppId::SrcId,
            level: WireSecurityLevel::None,
            key_bit: false,
            rx_after_tx: false,
            direction_proxy: false,
        }
    }

    /// Decode one octet.
    ///
    /// Requirement `14-0563-19-A141-01`.
    pub const fn decode(byte: u8) -> Result<Self, GpError> {
        let app_id = match AppId::from_bits(byte) {
            Ok(a) => a,
            Err(e) => return Err(e),
        };
        if matches!(app_id, AppId::Lped) {
            // LPED redefines bits 3–7; this layer keeps the body
            // opaque and only records recognition.
            return Ok(Self {
                app_id,
                level: WireSecurityLevel::None,
                key_bit: false,
                rx_after_tx: false,
                direction_proxy: false,
            });
        }
        let level = match WireSecurityLevel::from_bits(byte) {
            Ok(l) => l,
            Err(e) => return Err(e),
        };
        Ok(Self {
            app_id,
            level,
            key_bit: byte & 0x20 != 0,
            rx_after_tx: byte & 0x40 != 0,
            direction_proxy: byte & 0x80 != 0,
        })
    }

    /// Encode one octet.
    #[must_use]
    pub const fn encode(self) -> u8 {
        if matches!(self.app_id, AppId::Lped) {
            return self.app_id.bits();
        }
        self.app_id.bits()
            | self.level.bits()
            | ((self.key_bit as u8) << 5)
            | ((self.rx_after_tx as u8) << 6)
            | ((self.direction_proxy as u8) << 7)
    }
}

/// GPD identity carried beside a GPDF.
///
/// Requirement `14-0563-19-A162-01` (stable unique identity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpdId {
    /// 32-bit source identifier (`0x00000000` unspecified and
    /// `0xFFFFFFFF` all are never valid frame identities).
    SrcId(u32),
    /// IEEE address plus endpoint (endpoint travels only for this
    /// identity scheme).
    Ieee {
        /// 64-bit address, little-endian on air.
        addr: [u8; 8],
        /// GPD endpoint jointly identifying the logical device.
        endpoint: u8,
    },
}

/// True when every octet is zero (const-compatible comparison).
const fn is_zero_addr(addr: [u8; 8]) -> bool {
    let mut i = 0;
    while i < 8 {
        if addr[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// True when every octet is `0xFF` (const-compatible comparison).
const fn is_all_ff_addr(addr: [u8; 8]) -> bool {
    let mut i = 0;
    while i < 8 {
        if addr[i] != 0xFF {
            return false;
        }
        i += 1;
    }
    true
}

impl GpdId {
    /// Reject the reserved none/all source identifiers.
    ///
    /// Requirement `14-0563-19-A162-01`.
    pub const fn check(self) -> Result<Self, GpError> {
        match self {
            Self::SrcId(id) => {
                if id == 0x0000_0000 || id >= 0xFFFF_FFF9 {
                    return Err(GpError::BadIdentifier);
                }
                Ok(self)
            }
            Self::Ieee { addr, .. } => {
                if is_zero_addr(addr) || is_all_ff_addr(addr) {
                    return Err(GpError::BadIdentifier);
                }
                Ok(self)
            }
        }
    }

    /// Canonical 64-bit table key: source identifier zero-extended,
    /// IEEE address little-endian-decoded.
    #[must_use]
    pub const fn table_key(self) -> u64 {
        match self {
            Self::SrcId(id) => id as u64,
            Self::Ieee { addr, .. } => u64::from_le_bytes(addr),
        }
    }
}

/// GPDF body: parsed GP command section or opaque LPED bytes.
///
/// Requirement `14-0563-19-A141-*` (payload geometry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpdfBody<'a> {
    /// Command identifier plus command payload; MIC travels
    /// separately so security processing can cover exactly this.
    Gp {
        /// Command identifier.
        command: u8,
        /// Command payload bytes (borrowed).
        payload: &'a [u8],
    },
    /// LPED body kept opaque by this layer.
    LpedOpaque(&'a [u8]),
}

/// Decoded Green Power device frame (zero-copy over the input).
///
/// All multi-octet fields are little-endian on air.
///
/// Requirement `14-0563-19-A11-02`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gpdf<'a> {
    /// NWK frame control.
    pub fc: NwkFrameControl,
    /// Extended control (`None` exactly when the extension sub-field
    /// is clear).
    pub ext: Option<ExtFrameControl>,
    /// GPD identity (absent for maintenance frames).
    pub id: Option<GpdId>,
    /// Security frame counter (`Some` exactly when the level puts
    /// counter + MIC on air).
    pub frame_counter: Option<u32>,
    /// Command section.
    pub body: GpdfBody<'a>,
    /// Message integrity code (`Some` exactly when protected).
    pub mic: Option<[u8; 4]>,
}

impl<'a> Gpdf<'a> {
    /// Wire length of this frame in octets.
    pub const fn encoded_len(&self) -> usize {
        let mut len = 1; // NWK frame control
        if self.ext.is_some() {
            len += 1;
        }
        match self.id {
            Some(GpdId::SrcId(_)) => len += 4,
            Some(GpdId::Ieee { .. }) => len += 9,
            None => {}
        }
        if self.frame_counter.is_some() {
            len += FRAME_COUNTER_LEN;
        }
        match self.body {
            GpdfBody::Gp { payload, .. } => len += 1 + payload.len(),
            GpdfBody::LpedOpaque(raw) => len += raw.len(),
        }
        if self.mic.is_some() {
            len += COUNT_MIC_LEN;
        }
        len
    }

    /// Encode into the caller buffer; returns octets written.
    ///
    /// Requirement `14-0563-19-A11-02` (little-endian throughout).
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, GpError> {
        let need = self.encoded_len();
        if out.len() < need {
            return Err(GpError::TooSmall);
        }
        // Shape guards mirror the decode rules so a constructed
        // frame can never violate them.
        self.check_shape()?;
        let mut at = 0;
        out[at] = self.fc.encode();
        at += 1;
        if let Some(ext) = self.ext {
            out[at] = ext.encode();
            at += 1;
        }
        match self.id {
            Some(GpdId::SrcId(id)) => {
                out[at..at + 4].copy_from_slice(&id.to_le_bytes());
                at += 4;
            }
            Some(GpdId::Ieee { addr, endpoint }) => {
                out[at..at + 8].copy_from_slice(&addr);
                at += 8;
                out[at] = endpoint;
                at += 1;
            }
            None => {}
        }
        if let Some(counter) = self.frame_counter {
            out[at..at + 4].copy_from_slice(&counter.to_le_bytes());
            at += 4;
        }
        match self.body {
            GpdfBody::Gp { command, payload } => {
                if payload.len() > MAX_GPD_PAYLOAD {
                    return Err(GpError::PayloadTooLarge);
                }
                out[at] = command;
                at += 1;
                out[at..at + payload.len()].copy_from_slice(payload);
                at += payload.len();
            }
            GpdfBody::LpedOpaque(raw) => {
                out[at..at + raw.len()].copy_from_slice(raw);
                at += raw.len();
            }
        }
        if let Some(mic) = self.mic {
            out[at..at + 4].copy_from_slice(&mic);
            at += 4;
        }
        Ok(at)
    }

    /// Decode one frame; returns the frame plus octets consumed.
    ///
    /// Requirement `14-0563-19-A141-*`.
    pub fn decode(buf: &'a [u8]) -> Result<(Self, usize), GpError> {
        if buf.is_empty() {
            return Err(GpError::Truncated);
        }
        let fc = NwkFrameControl::decode(buf[0])?;
        let mut at = 1;
        let ext = if fc.ext_present {
            if buf.len() < at + 1 {
                return Err(GpError::Truncated);
            }
            let e = ExtFrameControl::decode(buf[at])?;
            at += 1;
            Some(e)
        } else {
            None
        };
        // Maintenance frames travel bare: no identity, no endpoint,
        // no security fields, no extension.
        //
        // Requirement `14-0563-19-A141-04`.
        if matches!(fc.frame_type, FrameType::Maintenance) {
            if fc.ext_present {
                return Err(GpError::ForbiddenExtControl);
            }
            if buf.len() < at + 1 {
                return Err(GpError::Truncated);
            }
            let command = buf[at];
            at += 1;
            let body = GpdfBody::Gp {
                command,
                payload: &buf[at..],
            };
            let frame = Self {
                fc,
                ext,
                id: None,
                frame_counter: None,
                body,
                mic: None,
            };
            let used = buf.len();
            return Ok((frame, used));
        }
        // Data frames: identity follows the application identifier.
        let app = ext.map_or(AppId::SrcId, |e| e.app_id);
        if matches!(app, AppId::Lped) {
            let frame = Self {
                fc,
                ext,
                id: None,
                frame_counter: None,
                body: GpdfBody::LpedOpaque(&buf[at..]),
                mic: None,
            };
            let used = buf.len();
            return Ok((frame, used));
        }
        let id = match app {
            AppId::SrcId => {
                if buf.len() < at + 4 {
                    return Err(GpError::Truncated);
                }
                let mut raw = [0u8; 4];
                raw.copy_from_slice(&buf[at..at + 4]);
                at += 4;
                GpdId::SrcId(u32::from_le_bytes(raw)).check()?
            }
            AppId::Ieee => {
                if buf.len() < at + 9 {
                    return Err(GpError::Truncated);
                }
                let mut addr = [0u8; 8];
                addr.copy_from_slice(&buf[at..at + 8]);
                at += 8;
                let endpoint = buf[at];
                at += 1;
                GpdId::Ieee { addr, endpoint }.check()?
            }
            AppId::Lped => unreachable!(),
        };
        let level = ext.map_or(WireSecurityLevel::None, |e| e.level);
        let frame_counter = if level.protected() {
            if buf.len() < at + FRAME_COUNTER_LEN {
                return Err(GpError::Truncated);
            }
            let mut raw = [0u8; 4];
            raw.copy_from_slice(&buf[at..at + 4]);
            at += 4;
            Some(u32::from_le_bytes(raw))
        } else {
            None
        };
        if buf.len() < at + 1 {
            return Err(GpError::Truncated);
        }
        let command = buf[at];
        at += 1;
        // Protected frames end with the 4-octet MIC; the remainder
        // between command section and MIC is the command payload.
        let (payload, mic) = if level.protected() {
            if buf.len() < at + COUNT_MIC_LEN {
                return Err(GpError::Truncated);
            }
            let split = buf.len() - COUNT_MIC_LEN;
            if split < at {
                return Err(GpError::Truncated);
            }
            let mut tag = [0u8; 4];
            tag.copy_from_slice(&buf[split..]);
            (&buf[at..split], Some(tag))
        } else {
            (&buf[at..], None)
        };
        if payload.len() > MAX_GPD_PAYLOAD {
            return Err(GpError::PayloadTooLarge);
        }
        let frame = Self {
            fc,
            ext,
            id: Some(id),
            frame_counter,
            body: GpdfBody::Gp { command, payload },
            mic,
        };
        frame.check_shape()?;
        let used = buf.len();
        Ok((frame, used))
    }

    /// Internal shape cross-check shared by encode and decode.
    fn check_shape(&self) -> Result<(), GpError> {
        let is_maint = matches!(self.fc.frame_type, FrameType::Maintenance);
        if is_maint {
            if self.ext.is_some() {
                return Err(GpError::ForbiddenExtControl);
            }
            if self.id.is_some() || self.frame_counter.is_some() || self.mic.is_some() {
                return Err(GpError::ForbiddenExtControl);
            }
            return Ok(());
        }
        match self.id {
            None => {
                // Only LPED data frames may omit the identity.
                let lped = self.ext.is_some_and(|e| matches!(e.app_id, AppId::Lped));
                if !lped {
                    return Err(GpError::MissingExtControl);
                }
            }
            Some(id) => {
                id.check()?;
            }
        }
        let level = self.ext.map_or(WireSecurityLevel::None, |e| e.level);
        if level.protected() {
            if self.frame_counter.is_none() || self.mic.is_none() {
                return Err(GpError::Truncated);
            }
        } else if self.frame_counter.is_some() || self.mic.is_some() {
            return Err(GpError::ForbiddenExtControl);
        }
        Ok(())
    }

    /// GPD-side and infrastructure ingress pre-filter: foreign frame
    /// shapes, proxy-originated direction, and the
    /// receive-after-transmit/auto-commissioning combination are
    /// silently dropped by the caller on `Err`.
    ///
    /// Requirements `14-0563-19-A141-01`, `-A141-02`, `-A141-03`,
    /// `-A152-03`.
    pub fn ingress_check(&self) -> Result<(), GpError> {
        if let Some(ext) = self.ext {
            if !matches!(ext.app_id, AppId::SrcId | AppId::Ieee) {
                // LPED is recognized but handled on its own path;
                // this filter only governs GP identities.
                return Ok(());
            }
            if ext.direction_proxy {
                return Err(GpError::ProxyOriginated);
            }
            if ext.rx_after_tx && self.fc.auto_commissioning {
                return Err(GpError::ConflictingFlags);
            }
        }
        // Commissioning-range command identifiers under no security
        // are dropped before any table lookup.
        if let GpdfBody::Gp { command, .. } = self.body {
            let commissioning_range = (0xF0..=0xFF).contains(&command);
            if commissioning_range && !matches!(self.fc.frame_type, FrameType::Maintenance) {
                let level = self.ext.map_or(WireSecurityLevel::None, |e| e.level);
                if matches!(level, WireSecurityLevel::None) {
                    return Err(GpError::UnsecuredCommissioning);
                }
            }
            if matches!(self.fc.frame_type, FrameType::Maintenance)
                && (0xF0..=0xFF).contains(&command)
            {
                return Err(GpError::BadMaintenanceCommand);
            }
        }
        Ok(())
    }
}
