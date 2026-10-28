//! Peer profiles: what a 3.0-profile vs 4.0 device looks like on the
//! wire for the fields this stack gates on.

/// NWK protocol-version sub-field value shared by the 3.0 profile and
/// the R23.2 core on every Zigbee-stack frame.
///
/// Requirement `05-3474-23-331-02` (corpus-mined, Fig. 3-5).
pub const NWK_VERSION_SHARED_30_40: u8 = 0x02;

/// Green-Power protocol-version sub-field value on both sides.
pub const GP_VERSION_SHARED_30_40: u8 = 0x03;

/// Security level this stack transmits for secured traffic
/// (encrypted payload + 32-bit integrity code), understood by 3.0
/// and 4.0 peers alike.
pub const BASELINE_SEC_LEVEL: u8 = 5;

/// Maximum security level value (3-bit field).
pub const MAX_SEC_LEVEL: u8 = 7;

/// Stack-profile value the PRO profile carries in the discovery
/// stack-profile field (doc `22-65816-030` v3.1 body, pp 16–103;
/// same value the R23.2 discovery filter expects, see requirement
/// `05-3474-23-3615-01`). PRO-legacy, 3.0-profile, and 4.0 devices
/// all beacon this value; the profile tag ([`StackProfile`]) comes
/// from key capabilities and commissioning posture, never from this
/// field alone.
pub const PRO_STACK_PROFILE: u8 = 0x02;

/// Stack profile of a peer, as inferred from its beacons and
/// commissioning capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackProfile {
    /// 3.0-profile peer: shared NWK version, symmetric key paths only.
    Profile30,
    /// 4.0 (R23.2-era) peer: shared NWK version, negotiation capable.
    Profile40,
    /// PRO-legacy peer (doc `22-65816-030` v3.1): shared NWK version,
    /// symmetric key paths only. Best-effort only — see the PRO
    /// boundary in [`crate::negotiate`].
    Pro,
}

impl StackProfile {
    /// NWK protocol version this profile transmits.
    #[must_use]
    pub const fn nwk_version(self) -> u8 {
        NWK_VERSION_SHARED_30_40
    }

    /// Whether this profile speaks the authenticated-negotiation key
    /// path (`22-65816-030-57-01` family). 3.0-profile peers do not;
    /// they join over the preconfigured or install-code paths.
    #[must_use]
    pub const fn supports_key_negotiation(self) -> bool {
        match self {
            Self::Profile30 => false,
            Self::Profile40 => true,
            Self::Pro => false,
        }
    }
}

/// Key-establishment methods, as a bitmask so a peer can advertise a
/// set. Bit assignments are local to this crate.
pub mod method_mask {
    /// Well-known preconfigured link key.
    pub const PRECONFIGURED: u8 = 0x01;
    /// Install-code-derived link key (`22-65816-030-56-03`).
    pub const INSTALL_CODE: u8 = 0x02;
    /// Authenticated negotiation (`22-65816-030-57-01`).
    pub const NEGOTIATION: u8 = 0x04;
}

/// Observed peer descriptor driving negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompatPeer {
    /// Profile inferred for the peer.
    pub profile: StackProfile,
    /// NWK protocol version heard (beacon / frame control).
    pub nwk_version: u8,
    /// Key methods the peer offers ([`method_mask`] bits).
    pub key_methods: u8,
    /// Highest security level the peer receives.
    pub max_sec_level: u8,
}

impl CompatPeer {
    /// Describe a 3.0-profile peer: shared NWK version, symmetric
    /// methods only, baseline security level.
    #[must_use]
    pub const fn profile_30() -> Self {
        Self {
            profile: StackProfile::Profile30,
            nwk_version: NWK_VERSION_SHARED_30_40,
            key_methods: method_mask::PRECONFIGURED | method_mask::INSTALL_CODE,
            max_sec_level: BASELINE_SEC_LEVEL,
        }
    }

    /// Describe a PRO-legacy peer: shared NWK version, shared
    /// stack-profile value, symmetric methods only, baseline
    /// security level. Best-effort only — see the PRO boundary in
    /// [`crate::negotiate`].
    #[must_use]
    pub const fn profile_pro() -> Self {
        Self {
            profile: StackProfile::Pro,
            nwk_version: NWK_VERSION_SHARED_30_40,
            key_methods: method_mask::PRECONFIGURED | method_mask::INSTALL_CODE,
            max_sec_level: BASELINE_SEC_LEVEL,
        }
    }

    /// Describe a 4.0 peer: shared NWK version, all methods.
    #[must_use]
    pub const fn profile_40() -> Self {
        Self {
            profile: StackProfile::Profile40,
            nwk_version: NWK_VERSION_SHARED_30_40,
            key_methods: method_mask::PRECONFIGURED
                | method_mask::INSTALL_CODE
                | method_mask::NEGOTIATION,
            max_sec_level: MAX_SEC_LEVEL,
        }
    }
}
