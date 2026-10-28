//! Bidirectional commissioning reply path: reply codecs plus the
//! GPD-side request/response command shapes that frame the exchange.
//!
//! Paraphrase-level model of doc `14-0563-19` §A.1.7.3 (exchange
//! rules; anchors p0069-L1921-L1934), §A.1.7.3.1 (basic-only
//! instruction; anchor p0070-L1941-L1945), §A.1.7.4 (channel
//! configuration; anchors p0071-L1983-L2023), §A.1.7.5 (key
//! configuration; anchors p0072-L2025-L2042), §A.4.2.1.2 (reply
//! command; anchors p0258-L7204-L7215, p0259-L7227-L7250),
//! §A.4.2.1.4 (channel request; anchors p0259-L7259-L7270) and
//! §A.4.2.1.5 (channel configuration; anchors p0260-L7275-L7292).
//! All wording here is paraphrase (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are repo-minted
//! (`14-0563-19-<clause>-<seq>`, dots stripped),
//! MINTED-pending-confirm.

use crate::frame::GpError;

/// GPD Commissioning command identifier.
///
/// Requirement `14-0563-19-A4211-01`.
pub const CMD_COMMISSIONING: u8 = 0xE0;

/// GPD Decommissioning command identifier (no payload).
///
/// Requirement `14-0563-19-A4211-01`.
pub const CMD_DECOMMISSIONING: u8 = 0xE1;

/// GPD Success command identifier (no payload).
///
/// Requirement `14-0563-19-A4211-01`.
pub const CMD_SUCCESS: u8 = 0xE2;

/// GPD Channel Request command identifier.
///
/// Requirement `14-0563-19-A4214-01`.
pub const CMD_CHANNEL_REQUEST: u8 = 0xE3;

/// GPD Commissioning Reply command identifier.
///
/// Requirement `14-0563-19-A4212-01`.
pub const CMD_COMMISSIONING_REPLY: u8 = 0xF0;

/// GPD Channel Configuration command identifier.
///
/// Requirement `14-0563-19-A4215-01`.
pub const CMD_CHANNEL_CONFIG: u8 = 0xF3;

/// True for the payloadless commissioning commands (Success and
/// Decommissioning): any payload octet is a malformed frame.
///
/// Requirement `14-0563-19-A4211-01`.
#[must_use]
pub const fn is_payloadless_commissioning(command: u8) -> bool {
    command == CMD_SUCCESS || command == CMD_DECOMMISSIONING
}

/// Options octet of the Commissioning Reply command: presence flags
/// plus the agreed protection level and key type.
///
/// Requirement `14-0563-19-A4212-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyOptions {
    /// PAN identifier field present.
    pub pan_id_present: bool,
    /// Security-key field present.
    pub key_present: bool,
    /// Key travels protected (MIC + frame counter also present).
    pub key_encrypted: bool,
    /// Agreed protection level (2-bit value).
    pub level: u8,
    /// Key type (3-bit value).
    pub key_type: u8,
}

impl ReplyOptions {
    /// Decode one octet; out-of-range level/key-type values rejected.
    ///
    /// Requirement `14-0563-19-A4212-01`.
    pub const fn decode(byte: u8) -> Result<Self, GpError> {
        let level = (byte >> 3) & 0x03;
        let key_type = (byte >> 5) & 0x07;
        if level == 0x01 {
            return Err(GpError::ReservedSecurityLevel(0x01));
        }
        Ok(Self {
            pan_id_present: byte & 0x01 != 0,
            key_present: byte & 0x02 != 0,
            key_encrypted: byte & 0x04 != 0,
            level,
            key_type,
        })
    }

    /// Encode one octet.
    #[must_use]
    pub const fn encode(self) -> u8 {
        (self.pan_id_present as u8)
            | ((self.key_present as u8) << 1)
            | ((self.key_encrypted as u8) << 2)
            | ((self.level & 0x03) << 3)
            | ((self.key_type & 0x07) << 5)
    }

    /// Shape gate: level zero carries no key material, so the key
    /// flags must be clear; anything else contradicts the options.
    ///
    /// Requirement `14-0563-19-A4212-01`.
    pub const fn check_shape(self) -> Result<Self, GpError> {
        if self.level == 0 && (self.key_present || self.key_encrypted || self.key_type != 0) {
            return Err(GpError::UnsecuredCommissioning);
        }
        Ok(self)
    }
}

/// Commissioning Reply payload: options plus the requested network
/// parameters (PAN identifier and/or security key).
///
/// Wire order is options, then PAN identifier (little-endian), then
/// the key, then the key MIC, then the frame counter that protected
/// the key.
///
/// Requirement `14-0563-19-A4212-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommissioningReply {
    /// Presence flags + agreed level/key type.
    pub options: ReplyOptions,
    /// Operational PAN identifier (present exactly when flagged).
    pub pan_id: Option<u16>,
    /// Security key, clear or protected (present exactly when flagged).
    pub key: Option<[u8; 16]>,
    /// MIC over the protected key (present exactly when the key
    /// travels protected).
    pub key_mic: Option<[u8; 4]>,
    /// Frame counter that protected the key (present exactly when the
    /// key travels protected under a nonzero level).
    pub frame_counter: Option<u32>,
}

impl CommissioningReply {
    /// Largest reply payload in octets (1 + 2 + 16 + 4 + 4).
    pub const MAX_LEN: usize = 27;

    /// Wire length of this reply in octets.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        let mut len = 1;
        if self.pan_id.is_some() {
            len += 2;
        }
        if self.key.is_some() {
            len += 16;
        }
        if self.key_mic.is_some() {
            len += 4;
        }
        if self.frame_counter.is_some() {
            len += 4;
        }
        len
    }

    /// Encode into the caller buffer; returns octets written.
    ///
    /// Requirement `14-0563-19-A4212-01`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, GpError> {
        self.check_shape()?;
        let need = self.encoded_len();
        if out.len() < need {
            return Err(GpError::TooSmall);
        }
        let mut at = 0;
        out[at] = self.options.encode();
        at += 1;
        if let Some(pan) = self.pan_id {
            out[at..at + 2].copy_from_slice(&pan.to_le_bytes());
            at += 2;
        }
        if let Some(key) = self.key {
            out[at..at + 16].copy_from_slice(&key);
            at += 16;
        }
        if let Some(mic) = self.key_mic {
            out[at..at + 4].copy_from_slice(&mic);
            at += 4;
        }
        if let Some(counter) = self.frame_counter {
            out[at..at + 4].copy_from_slice(&counter.to_le_bytes());
            at += 4;
        }
        Ok(at)
    }

    /// Decode one reply payload; returns the reply plus octets
    /// consumed. Trailing octets are left to the caller.
    ///
    /// Requirement `14-0563-19-A4212-01`.
    pub fn decode(input: &[u8]) -> Result<(Self, usize), GpError> {
        if input.is_empty() {
            return Err(GpError::Truncated);
        }
        let options = ReplyOptions::decode(input[0])?.check_shape()?;
        let mut at = 1;
        let pan_id = if options.pan_id_present {
            if input.len() < at + 2 {
                return Err(GpError::Truncated);
            }
            let v = u16::from_le_bytes([input[at], input[at + 1]]);
            at += 2;
            Some(v)
        } else {
            None
        };
        let key = if options.key_present {
            if input.len() < at + 16 {
                return Err(GpError::Truncated);
            }
            let mut k = [0u8; 16];
            k.copy_from_slice(&input[at..at + 16]);
            at += 16;
            Some(k)
        } else {
            None
        };
        let protected = options.key_present && options.key_encrypted && options.level != 0;
        let key_mic = if protected {
            if input.len() < at + 4 {
                return Err(GpError::Truncated);
            }
            let mut m = [0u8; 4];
            m.copy_from_slice(&input[at..at + 4]);
            at += 4;
            Some(m)
        } else {
            None
        };
        let frame_counter = if protected {
            if input.len() < at + 4 {
                return Err(GpError::Truncated);
            }
            let v = u32::from_le_bytes([input[at], input[at + 1], input[at + 2], input[at + 3]]);
            at += 4;
            Some(v)
        } else {
            None
        };
        let reply = Self {
            options,
            pan_id,
            key,
            key_mic,
            frame_counter,
        };
        reply.check_shape()?;
        Ok((reply, at))
    }

    /// Presence/shape gate: flags and fields must agree, and a
    /// protected key needs a nonzero level.
    ///
    /// Requirement `14-0563-19-A4212-01`.
    pub const fn check_shape(&self) -> Result<(), GpError> {
        if let Err(e) = self.options.check_shape() {
            return Err(e);
        }
        if self.options.pan_id_present != self.pan_id.is_some() {
            return Err(GpError::Truncated);
        }
        if self.options.key_present != self.key.is_some() {
            return Err(GpError::Truncated);
        }
        let protected = self.options.key_present && self.options.key_encrypted;
        if protected && self.options.level == 0 {
            return Err(GpError::UnsecuredCommissioning);
        }
        if (self.key_mic.is_some() != protected) || (self.frame_counter.is_some() != protected) {
            return Err(GpError::Truncated);
        }
        Ok(())
    }
}

/// Channel Configuration payload: one octet naming the operational
/// channel plus whether the sender only supports basic operation.
///
/// Requirement `14-0563-19-A4215-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelConfig {
    /// Operational channel, 11..=26.
    pub channel: u8,
    /// Set when the sender only supports basic operation.
    pub basic: bool,
}

impl ChannelConfig {
    /// Decode one octet: every nibble names a channel 11..=26, so
    /// every octet is a valid configuration.
    ///
    /// Requirement `14-0563-19-A4215-01`.
    #[must_use]
    pub const fn decode(byte: u8) -> Self {
        Self {
            channel: 11 + (byte & 0x0F),
            basic: byte & 0x10 != 0,
        }
    }

    /// Encode one octet.
    ///
    /// Requirement `14-0563-19-A4215-01`.
    pub const fn encode(self) -> Result<u8, GpError> {
        if self.channel < 11 || self.channel > 26 {
            return Err(GpError::BadIdentifier);
        }
        Ok((self.channel - 11) | ((self.basic as u8) << 4))
    }
}

/// Channel Request payload: one octet naming the receive channel for
/// the next two attempts (nibbles encode channel minus eleven).
///
/// Requirement `14-0563-19-A4214-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelRequest {
    /// Receive channel for the next attempt, 11..=26.
    pub rx_next: u8,
    /// Receive channel for the second next attempt, 11..=26.
    pub rx_second: u8,
}

impl ChannelRequest {
    /// Decode one octet: both nibbles name channels 11..=26, so
    /// every octet is a valid request.
    ///
    /// Requirement `14-0563-19-A4214-01`.
    #[must_use]
    pub const fn decode(byte: u8) -> Self {
        Self {
            rx_next: 11 + (byte & 0x0F),
            rx_second: 11 + ((byte >> 4) & 0x0F),
        }
    }

    /// Encode one octet.
    ///
    /// Requirement `14-0563-19-A4214-01`.
    pub const fn encode(self) -> Result<u8, GpError> {
        if self.rx_next < 11 || self.rx_next > 26 || self.rx_second < 11 || self.rx_second > 26 {
            return Err(GpError::BadIdentifier);
        }
        Ok((self.rx_next - 11) | ((self.rx_second - 11) << 4))
    }
}
