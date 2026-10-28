//! Admission and negotiation gates: every 3.0/4.0 wire delta that
//! needs a decision funnels through here, and every refusal is typed
//! so a downgrade can never happen silently.

use crate::profile::{
    method_mask, CompatPeer, StackProfile, BASELINE_SEC_LEVEL, GP_VERSION_SHARED_30_40,
    MAX_SEC_LEVEL, NWK_VERSION_SHARED_30_40, PRO_STACK_PROFILE,
};

/// Compatibility failure: the peer cannot be admitted without
/// lowering the posture, so no traffic flows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompatError {
    /// NWK protocol version is not the shared 3.0/4.0 value.
    UnsupportedNwkVersion(u8),
    /// Green-Power protocol version is not the shared value.
    UnsupportedGpVersion(u8),
    /// Agreeing with the peer would drop below the floor.
    SecurityDowngradeRefused {
        /// Application-mandated minimum security level.
        floor: u8,
        /// Highest level the peer can receive.
        offered: u8,
    },
    /// No key-establishment method is common to both sides (or the
    /// only common methods are forbidden by policy).
    NoCommonKeyMethod,
    /// Discovery stack-profile field is not the PRO value, or the
    /// peer's profile tag is not the PRO-legacy one the best-effort
    /// path serves.
    UnsupportedStackProfile(u8),
    /// The candidate network is closed to joining; no key decision
    /// is taken for a closed network.
    JoiningClosed,
}

impl core::fmt::Display for CompatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedNwkVersion(v) => write!(f, "unsupported NWK version {v}"),
            Self::UnsupportedGpVersion(v) => write!(f, "unsupported GP version {v}"),
            Self::SecurityDowngradeRefused { floor, offered } => write!(
                f,
                "security downgrade refused (floor {floor}, peer offers {offered})"
            ),
            Self::NoCommonKeyMethod => write!(f, "no common key-establishment method"),
            Self::UnsupportedStackProfile(p) => write!(f, "unsupported stack profile {p}"),
            Self::JoiningClosed => write!(f, "candidate network is closed to joining"),
        }
    }
}

impl core::error::Error for CompatError {}

/// Admit a heard NWK protocol version. Accepts exactly the value the
/// 3.0 profile and the R23.2 core share; anything else is refused so
/// an unknown frame shape never enters the pipeline.
///
/// Requirement `05-3474-23-331-02` (corpus-mined, Fig. 3-5).
///
/// The admitted value is shared, so it names no profile by itself:
/// profile is inferred from key capabilities, not the version.
pub const fn admit_nwk_version(version: u8) -> Result<(), CompatError> {
    match version {
        NWK_VERSION_SHARED_30_40 => Ok(()),
        v => Err(CompatError::UnsupportedNwkVersion(v)),
    }
}

/// Admit a heard Green-Power protocol version: exactly the shared
/// value, mirroring the GPDF codec's own gate.
pub const fn admit_gp_version(version: u8) -> Result<(), CompatError> {
    match version {
        GP_VERSION_SHARED_30_40 => Ok(()),
        v => Err(CompatError::UnsupportedGpVersion(v)),
    }
}

/// Admit a Touchlink scan-response sub-device version: any value is
/// carried verbatim (application version, not a stack gate).
#[must_use]
pub const fn admit_touchlink_sub_version(_version: u8) -> bool {
    true
}

/// A 3.0 ZCL reader tolerates any ClusterRevision at or above the tip
/// it knows: unknown attributes and commands are ignored by the
/// reader, so a higher revision never breaks receipt.
#[must_use]
pub const fn tolerates_cluster_revision(_our_revision: u16, _peer_known_tip: u16) -> bool {
    true
}

/// ZCL reserved frame-control bits need no negotiation: they are
/// zeroed on transmit and ignored on receipt on both sides.
///
/// Requirement `07-5123-08-231-02` + `07-5123-08-232-01`
/// (corpus-mined).
#[must_use]
pub const fn zcl_reserved_bits_need_no_negotiation() -> bool {
    true
}

/// Agree a security level with a peer: the lower of the two maxima,
/// refused when it would land below the application floor.
///
/// The floor defaults to [`BASELINE_SEC_LEVEL`]; callers securing
/// infrastructure traffic pass a higher one. Refusal is typed
/// ([`CompatError::SecurityDowngradeRefused`]), never a quiet
/// fall-through to a weaker level.
pub const fn agree_security_level(our_max: u8, peer_max: u8, floor: u8) -> Result<u8, CompatError> {
    let agreed = if our_max < peer_max {
        our_max
    } else {
        peer_max
    };
    if agreed > MAX_SEC_LEVEL {
        return Err(CompatError::SecurityDowngradeRefused {
            floor,
            offered: peer_max,
        });
    }
    if agreed < floor {
        return Err(CompatError::SecurityDowngradeRefused {
            floor,
            offered: peer_max,
        });
    }
    Ok(agreed)
}

/// Key method selected for one peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedMethod {
    /// Well-known preconfigured link key.
    Preconfigured,
    /// Install-code-derived link key.
    InstallCode,
    /// Authenticated negotiation.
    Negotiation,
}

/// Application policy for key-establishment fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPolicy {
    /// When false, a peer without negotiation support is refused
    /// instead of falling back to a symmetric path (mandatory-CBKE
    /// posture). When true, the strongest common symmetric path is
    /// selected and returned so the caller can log it.
    pub allow_symmetric_fallback: bool,
}

impl KeyPolicy {
    /// Strict posture: negotiation or nothing.
    pub const STRICT_NEGOTIATION: Self = Self {
        allow_symmetric_fallback: false,
    };
    /// Interop posture: fall back to install-code, then preconfigured.
    pub const ALLOW_SYMMETRIC: Self = Self {
        allow_symmetric_fallback: true,
    };
}

/// Select the key-establishment method for a peer: prefer
/// negotiation when both sides speak it, else the strongest common
/// symmetric method when policy allows, else refuse.
///
/// Preference order on fallback is install-code before preconfigured
/// (a device-specific secret before a well-known one).
pub fn select_key_method(
    peer: &CompatPeer,
    we_offer_negotiation: bool,
    policy: &KeyPolicy,
) -> Result<SelectedMethod, CompatError> {
    let peer = peer.key_methods;
    if we_offer_negotiation && peer & method_mask::NEGOTIATION != 0 {
        return Ok(SelectedMethod::Negotiation);
    }
    if policy.allow_symmetric_fallback {
        if peer & method_mask::INSTALL_CODE != 0 {
            return Ok(SelectedMethod::InstallCode);
        }
        if peer & method_mask::PRECONFIGURED != 0 {
            return Ok(SelectedMethod::Preconfigured);
        }
    }
    Err(CompatError::NoCommonKeyMethod)
}

/// Highest key-transport index common to both sides (bounded scan;
/// empty offer means no common index).
#[must_use]
pub fn highest_common_key_index(offered: &[u8], ours: &[u8]) -> Option<u8> {
    let mut best: Option<u8> = None;
    for &o in offered {
        for &m in ours {
            if o == m && best.map(|b| o > b).unwrap_or(true) {
                best = Some(o);
            }
        }
    }
    best
}

/// Full 3.0-profile admission: NWK version gate, key-method
/// selection, and security-level agreement in one call, so a join
/// path cannot skip a gate.
pub fn admit_30_peer(
    peer: &CompatPeer,
    we_offer_negotiation: bool,
    key_policy: &KeyPolicy,
    floor: u8,
) -> Result<(SelectedMethod, u8), CompatError> {
    admit_nwk_version(peer.nwk_version)?;
    let method = select_key_method(peer, we_offer_negotiation, key_policy)?;
    let level = agree_security_level(BASELINE_SEC_LEVEL, peer.max_sec_level, floor)?;
    Ok((method, level))
}

// PRO best-effort boundary (doc `22-65816-030` v3.1).
//
// What this path covers: recognition of a PRO-legacy peer (shared
// NWK version 2 + PRO stack-profile value + symmetric-only key
// capabilities), one typed accept/refuse decision per candidate
// network (`admit_pro_peer`), and the version-gate extension that
// keeps unknown versions out of the join machine. The decision is
// zero-alloc and infallible in resources: it touches only the
// caller's descriptor and returns a value, so there is no
// allocator budget to declare.
//
// What it does NOT cover (explicit non-goals, full PRO
// commissioning stays out): BDB formation/steering procedures,
// Trust-Center PRO policies, PRO install-code policy tables, and
// any translation of PRO commissioning frames. A PRO-legacy peer
// admitted here joins over the same symmetric exchange the 3.0
// path already proves; anything PRO-specific beyond admission is
// refused with a typed error, never silently downgraded.

/// Admit a heard discovery stack-profile value on the PRO
/// best-effort path: exactly [`PRO_STACK_PROFILE`], the value the
/// PRO profile, the 3.0 profile, and the R23.2 core all beacon
/// (version-gate extension: the shared value is now explicitly
/// recognized as the PRO value instead of merely tolerated).
///
/// Requirement `RD-PRO-02` (repo-minted, MINTED-pending-confirm).
pub const fn admit_pro_stack_profile(profile: u8) -> Result<(), CompatError> {
    match profile {
        PRO_STACK_PROFILE => Ok(()),
        p => Err(CompatError::UnsupportedStackProfile(p)),
    }
}

/// Full PRO-legacy admission in one call: NWK version gate, PRO
/// stack-profile gate (raw field + profile tag), joining-permission
/// gate, key-method selection, and security-level agreement, in
/// that order, so a candidate network cannot skip a gate and no
/// key decision is ever taken for a closed network.
///
/// Requirement `RD-PRO-01` (admission) + `RD-PRO-03` (typed
/// accept/refuse matrix, repo-minted, MINTED-pending-confirm).
/// Version-gate extension is `RD-PRO-04`: the shared version-2
/// recognition from `admit_nwk_version` now explicitly covers PRO
/// beacons via this bundle.
pub fn admit_pro_peer(
    peer: &CompatPeer,
    stack_profile_field: u8,
    joining_permitted: bool,
    we_offer_negotiation: bool,
    key_policy: &KeyPolicy,
    floor: u8,
) -> Result<(SelectedMethod, u8), CompatError> {
    admit_nwk_version(peer.nwk_version)?;
    admit_pro_stack_profile(stack_profile_field)?;
    if peer.profile != StackProfile::Pro {
        return Err(CompatError::UnsupportedStackProfile(stack_profile_field));
    }
    if !joining_permitted {
        return Err(CompatError::JoiningClosed);
    }
    let method = select_key_method(peer, we_offer_negotiation, key_policy)?;
    let level = agree_security_level(BASELINE_SEC_LEVEL, peer.max_sec_level, floor)?;
    Ok((method, level))
}
