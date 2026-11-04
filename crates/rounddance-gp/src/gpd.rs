//! Green Power Device (GPD): energy-harvest transmit role.
//!
//! The crate so far models only network-side infrastructure
//! (proxy/sink/receive/reply). This module is the missing device
//! side the universal-library audit flagged: a self-powered GPD that
//! commissions (auto-commissioning / Commissioning command) and then
//! emits data commands (e.g. toggle) as GPDFs a proxy/sink can
//! receive. No receiver, no Rx-after-Tx window, no key storage here:
//! unsecured commissioning + unsecured data first (the harvest-class
//! baseline), with a monotonic frame counter slot for secured levels
//! when the deployment provisions one.
//!
//! Paraphrase-level model of doc `14-0563-19` §A.1.6 GPD behavior +
//! §A.1.4 frame formats; no spec text (D1, `SCOPE.md` §2).
//! Requirement IDs: corpus-mined `14-0563-19-A141-*` (frame layout),
//! `-A162-01` (identity), `-A152-03` (level gating); repo-minted
//! `14-0563-19-A16GPD-01..03` (MINTED-pending-confirm).

use crate::frame::{
    AppId, ExtFrameControl, FrameType, GpError, GpdId, Gpdf, GpdfBody, NwkFrameControl,
    WireSecurityLevel, MAX_GPDF,
};
use crate::reply::CMD_COMMISSIONING;

/// Generic GPD toggle/data command identifier used by the universal
/// library demo leg (On/Off-class payload carried opaquely; the sink
/// translation table maps it).
pub const GPD_TOGGLE_CMD: u8 = 0x20;

/// GPD lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpdState {
    /// Fresh from harvest: must commission before data.
    Uncommissioned,
    /// Commissioning frame emitted, awaiting infrastructure learn.
    Commissioning,
    /// Learned by a proxy/sink: data frames accepted.
    Commissioned,
}

/// Energy-harvest Green Power Device: identity + monotonic counter +
/// commission/data frame builder. The caller moves the bytes onto the
/// radio (or the sim medium); this machine never reads a clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpdDevice {
    id: GpdId,
    state: GpdState,
    /// Monotonic frame counter for secured levels; also numbers
    /// unsecured data intents locally (never rewound).
    counter: u32,
    /// Data frames emitted (lifetime counter).
    pub data_sent: u32,
}

impl GpdDevice {
    /// New GPD with a 32-bit source identifier.
    #[must_use]
    pub const fn new_srcid(src_id: u32) -> Self {
        Self {
            id: GpdId::SrcId(src_id),
            state: GpdState::Uncommissioned,
            counter: 0,
            data_sent: 0,
        }
    }

    /// New GPD with an IEEE address + endpoint.
    #[must_use]
    pub const fn new_ieee(addr: [u8; 8], endpoint: u8) -> Self {
        Self {
            id: GpdId::Ieee { addr, endpoint },
            state: GpdState::Uncommissioned,
            counter: 0,
            data_sent: 0,
        }
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(self) -> GpdState {
        self.state
    }

    /// Device identity.
    #[must_use]
    pub const fn id(self) -> GpdId {
        self.id
    }

    /// Build the commissioning frame (auto-commissioning set,
    /// Commissioning command `0xE0`, unsecured) into `out`.
    /// Advances to `Commissioning`.
    ///
    /// Requirement `14-0563-19-A16GPD-01` (MINTED-pending-confirm).
    pub fn build_commissioning(&mut self, out: &mut [u8]) -> Result<usize, GpError> {
        let app_id = match self.id {
            GpdId::SrcId(_) => AppId::SrcId,
            GpdId::Ieee { .. } => AppId::Ieee,
            // GpdId is non-exhaustive-proofed by construction; the
            // check below refuses reserved identities anyway.
        };
        self.id.check()?;
        let frame = Gpdf {
            fc: NwkFrameControl {
                frame_type: FrameType::Data,
                auto_commissioning: true,
                ext_present: true,
            },
            ext: Some(ExtFrameControl {
                app_id,
                level: WireSecurityLevel::None,
                key_bit: false,
                rx_after_tx: false,
                direction_proxy: false,
            }),
            id: Some(self.id),
            frame_counter: None,
            body: GpdfBody::Gp {
                command: CMD_COMMISSIONING,
                payload: &[],
            },
            mic: None,
        };
        frame.ingress_check()?;
        let n = frame.encode_into(out)?;
        self.state = GpdState::Commissioning;
        Ok(n)
    }

    /// Mark the device learned by infrastructure (proxy/sink paired
    /// the commissioning frame). Data path opens.
    ///
    /// Requirement `14-0563-19-A16GPD-02` (MINTED-pending-confirm).
    pub fn mark_commissioned(&mut self) {
        if self.state == GpdState::Commissioning || self.state == GpdState::Uncommissioned {
            self.state = GpdState::Commissioned;
        }
    }

    /// Build one unsecured data frame (`command` + `payload`) into
    /// `out`. Requires `Commissioned`. Bumps the local counter and
    /// `data_sent`.
    ///
    /// Requirement `14-0563-19-A16GPD-03` (MINTED-pending-confirm).
    pub fn build_data(
        &mut self,
        command: u8,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, GpError> {
        if self.state != GpdState::Commissioned {
            return Err(GpError::BadState);
        }
        if command >= 0xF0 {
            // Commissioning-range identifiers are not data commands
            // on the unsecured data path.
            return Err(GpError::UnsecuredCommissioning);
        }
        let app_id = match self.id {
            GpdId::SrcId(_) => AppId::SrcId,
            GpdId::Ieee { .. } => AppId::Ieee,
        };
        self.id.check()?;
        let frame = Gpdf {
            fc: NwkFrameControl {
                frame_type: FrameType::Data,
                auto_commissioning: false,
                ext_present: true,
            },
            ext: Some(ExtFrameControl {
                app_id,
                level: WireSecurityLevel::None,
                key_bit: false,
                rx_after_tx: false,
                direction_proxy: false,
            }),
            id: Some(self.id),
            frame_counter: None,
            body: GpdfBody::Gp { command, payload },
            mic: None,
        };
        frame.ingress_check()?;
        let n = frame.encode_into(out)?;
        self.counter = self.counter.wrapping_add(1);
        self.data_sent += 1;
        Ok(n)
    }

    /// Build the bidirectional commissioning frame (Commissioning
    /// command `0xE0`, receive-after-transmit set, unsecured) into
    /// `out`. The device opens a short receive window after
    /// transmitting, inside which the sink serves its reply; the
    /// device closes the exchange with [`build_success`](Self::build_success).
    /// Auto-commissioning stays clear (the ingress rule drops frames
    /// asserting both flags). Advances to `Commissioning`.
    ///
    /// Requirement `14-0563-19-A16GPD-04` (MINTED-pending-confirm).
    pub fn build_bidir_commissioning(&mut self, out: &mut [u8]) -> Result<usize, GpError> {
        let app_id = match self.id {
            GpdId::SrcId(_) => AppId::SrcId,
            GpdId::Ieee { .. } => AppId::Ieee,
        };
        self.id.check()?;
        let frame = Gpdf {
            fc: NwkFrameControl {
                frame_type: FrameType::Data,
                auto_commissioning: false,
                ext_present: true,
            },
            ext: Some(ExtFrameControl {
                app_id,
                level: WireSecurityLevel::None,
                key_bit: false,
                rx_after_tx: true,
                direction_proxy: false,
            }),
            id: Some(self.id),
            frame_counter: None,
            body: GpdfBody::Gp {
                command: CMD_COMMISSIONING,
                payload: &[],
            },
            mic: None,
        };
        frame.ingress_check()?;
        let n = frame.encode_into(out)?;
        self.state = GpdState::Commissioning;
        Ok(n)
    }

    /// Build the GPD Success frame (payloadless command `0xE2`) into
    /// `out`: the device-side close of a bidirectional commissioning
    /// exchange after the sink serves its reply inside the receive
    /// window. Requires `Commissioning` (the reply was received);
    /// completes the device to `Commissioned`.
    ///
    /// Requirement `14-0563-19-A16GPD-02` (MINTED-pending-confirm).
    pub fn build_success(&mut self, out: &mut [u8]) -> Result<usize, GpError> {
        use crate::reply::CMD_SUCCESS;
        if self.state != GpdState::Commissioning {
            return Err(GpError::BadState);
        }
        let app_id = match self.id {
            GpdId::SrcId(_) => AppId::SrcId,
            GpdId::Ieee { .. } => AppId::Ieee,
        };
        self.id.check()?;
        let frame = Gpdf {
            fc: NwkFrameControl {
                frame_type: FrameType::Data,
                auto_commissioning: false,
                ext_present: true,
            },
            ext: Some(ExtFrameControl {
                app_id,
                level: WireSecurityLevel::None,
                key_bit: false,
                rx_after_tx: false,
                direction_proxy: false,
            }),
            id: Some(self.id),
            frame_counter: None,
            body: GpdfBody::Gp {
                command: CMD_SUCCESS,
                payload: &[],
            },
            mic: None,
        };
        frame.ingress_check()?;
        let n = frame.encode_into(out)?;
        self.state = GpdState::Commissioned;
        Ok(n)
    }

    /// Largest GPDF this device can emit (bounded budgetPin).
    #[must_use]
    pub const fn max_frame_len() -> usize {
        MAX_GPDF
    }
}
