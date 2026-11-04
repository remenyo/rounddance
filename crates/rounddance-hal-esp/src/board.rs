//! Board bindings: target selection for S31 coordinator vs C6 roles.
//!
//! The 15.4 driver application API is identical across C6/H2/C5/S31
//! (see `lib.rs` target scope; S31 `SOC_IEEE802154_SUPPORTED=1` per
//! `soc/esp32s31/include/soc/soc_caps.h:136`, same value as C6
//! `soc/esp32c6/include/soc/soc_caps.h:39`). Only board code differs:
//! IDF target string, antenna-GPIO handling, and which provisioned
//! identity boots which role. This module owns those deltas so
//! `CoordinatorApp` / `JoinerApp` / `RouterDevice` stay
//! target-agnostic `no_std`.
//!
//! Paraphrase-level model; no spec text (D1, `SCOPE.md` §2).

use crate::app::{eui_from_mac, AppRole};

/// Supported ESP targets for the universal library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspTarget {
    /// ESP32-C6: standalone coordinator, router, or end device.
    C6,
    /// ESP32-S31 (S3-family + 15.4): standalone coordinator.
    /// IDF target `esp32s31` (`idf.py --preview set-target esp32s31`).
    S31,
    /// ESP32-H2: minimal-radio experiment.
    H2,
    /// ESP32-C5: 15.4-capable, same driver API.
    C5,
}

impl EspTarget {
    /// IDF target string for `sdkconfig.defaults` / flash profile.
    #[must_use]
    pub const fn idf_target(self) -> &'static str {
        match self {
            Self::C6 => "esp32c6",
            Self::S31 => "esp32s31",
            Self::H2 => "esp32h2",
            Self::C5 => "esp32c5",
        }
    }

    /// Whether this target drives the Xiao-C6 ceramic-antenna select
    /// (GPIO3 LOW + GPIO14 LOW). Only C6 Xiao boards need it; S31
    /// boards must NOT drive those pins (different RF front end).
    #[must_use]
    pub const fn needs_xiao_c6_antenna_select(self) -> bool {
        matches!(self, Self::C6)
    }

    /// Whether this target may boot the standalone coordinator image.
    /// C6 (proven) and S31 (port target) are admitted; H2/C5 share the
    /// driver API but are not coordinator products in this tree.
    #[must_use]
    pub const fn supports_standalone_coordinator(self) -> bool {
        matches!(self, Self::C6 | Self::S31)
    }
}

/// Provisioned board identity: which base MAC boots which role on
/// this unit. Replaces the two-hardcoded-MAC lab gate
/// (`role_from_mac` over `COORD_BASE_MAC`/`JOINER_BASE_MAC`) with an
/// explicit provisioning record so any S31 or C6 unit — not just the
/// two lab C6s — can be a coordinator, router, or end device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoardIdentity {
    /// Factory base MAC of this unit (`esp_read_mac(ESP_MAC_BASE)`).
    pub base_mac: [u8; 6],
    /// Base MAC provisioned as the coordinator for this network.
    /// `None` = this build never boots coordinator (router/end-device
    /// only).
    pub coordinator_mac: Option<[u8; 6]>,
    /// Base MAC provisioned as the primary joiner/end-device for this
    /// network. `None` = no dedicated joiner slot.
    pub joiner_mac: Option<[u8; 6]>,
}

impl BoardIdentity {
    /// Role for this unit under this provisioning. Coordinator wins
    /// over joiner on exact-match collision (misprovisioning is a
    /// build/deploy error, surfaced as coordinator rather than silent
    /// refuse).
    #[must_use]
    pub fn role(&self) -> Option<AppRole> {
        if let Some(cm) = self.coordinator_mac {
            if self.base_mac == cm {
                return Some(AppRole::Coordinator);
            }
        }
        if let Some(jm) = self.joiner_mac {
            if self.base_mac == jm {
                return Some(AppRole::Joiner);
            }
        }
        None
    }

    /// 8-octet EUI derived from this unit's base MAC (`ff:fe` rule).
    #[must_use]
    pub fn eui(&self) -> [u8; 8] {
        eui_from_mac(&self.base_mac)
    }
}

/// Full board configuration for one firmware image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoardConfig {
    /// Silicon target.
    pub target: EspTarget,
    /// Provisioned identity (role selection).
    pub identity: BoardIdentity,
    /// 802.15.4 channel 11–26.
    pub channel: u8,
    /// PAN identifier.
    pub pan: u16,
}

impl BoardConfig {
    /// S31 standalone coordinator configuration. No antenna-GPIO
    /// handling (S31 front end differs from Xiao C6); role comes from
    /// provisioning, not from the two lab-C6 MAC constants.
    #[must_use]
    pub const fn s31_coordinator(coordinator_mac: [u8; 6], pan: u16, channel: u8) -> Self {
        Self {
            target: EspTarget::S31,
            identity: BoardIdentity {
                base_mac: coordinator_mac,
                coordinator_mac: Some(coordinator_mac),
                joiner_mac: None,
            },
            channel,
            pan,
        }
    }

    /// C6 router configuration (joins as router, then forwards).
    #[must_use]
    pub const fn c6_router(base_mac: [u8; 6], pan: u16, channel: u8) -> Self {
        Self {
            target: EspTarget::C6,
            identity: BoardIdentity {
                base_mac,
                coordinator_mac: None,
                joiner_mac: None,
            },
            channel,
            pan,
        }
    }

    /// C6 end-device configuration (joins, hosts On/Off, polls).
    #[must_use]
    pub const fn c6_end_device(
        base_mac: [u8; 6],
        joiner_mac: [u8; 6],
        pan: u16,
        channel: u8,
    ) -> Self {
        Self {
            target: EspTarget::C6,
            identity: BoardIdentity {
                base_mac,
                coordinator_mac: None,
                joiner_mac: Some(joiner_mac),
            },
            channel,
            pan,
        }
    }
}
