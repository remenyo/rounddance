//! Implicit-certificate types for ECQV/CBKE foundations.
//!
//! Paraphrase-level model of doc `07-5356` SE 1.4a §5 (CBKE with
//! CA-signed implicit certificates): per the ECQV verdict, CBKE peers
//! carry CA-signed implicit certificates, NOT X.509 — no X.509 parsing
//! exists or is wanted on this path. All wording here is paraphrase
//! (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are repo-minted (`07-5356-<clause>-<seq>`,
//! dots stripped), MINTED-pending-confirm, with line anchors from the
//! private corpus (`text/smart-energy-07-5356-22/p*.txt`, trailing spec
//! line numbers): CBKE concept p0149-L3853-L3857 + p0167-L4302-L4306,
//! 48-octet certificate layout p0169-L4365-L4368 with field anchors
//! L4370-L4374.
//!
//! The 48-octet certificate is kept opaque here: the core never parses
//! fields out of it. Identity binding travels in [`PeerIdentity`],
//! where the subject EUI-64, the certificate octets, and the
//! reconstruction point are explicit separate fields, and the
//! CA-signature check happens implicitly through successful key
//! reconstruction plus MAC confirmation (the ECQV property).
//!
//! Wire mapping note: on the wire the certificate carries a 22-octet
//! reconstruction value plus an 8-octet subject plus issuer and profile
//! data (anchors above); the core's 64-octet point is the EXPANDED
//! form the backend operates on. Recovering the expanded point from
//! the 22-octet wire value is a profile/backend responsibility (PSA on
//! ESP, `p256` on host), not core logic — the core only records that
//! the carried point and the certificate travel together.

use crate::ecc::POINT_LEN;

/// Implicit-certificate length in octets (CA-signed ECQV material).
///
/// Requirement `07-5356-C4224-01`.
pub const IMPLICIT_CERT_LEN: usize = 48;

/// Opaque 48-octet CA-signed implicit certificate.
///
/// Requirement `07-5356-C4224-01`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImplicitCert(pub [u8; IMPLICIT_CERT_LEN]);

impl ImplicitCert {
    /// Wrap raw octets (e.g. received in a certificate-exchange
    /// command). No validation happens here: trust is established by
    /// reconstruction + MAC confirmation, never by parsing.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; IMPLICIT_CERT_LEN]) -> Self {
        Self(bytes)
    }

    /// Raw octets.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; IMPLICIT_CERT_LEN] {
        &self.0
    }
}

/// Everything needed to reconstruct one peer's static public key: the
/// certificate, the subject it names, and the reconstruction point
/// carried with the certificate material.
///
/// Requirement `07-5356-C4224-02`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    /// CA-signed implicit certificate.
    pub cert: ImplicitCert,
    /// Subject long address (EUI-64, little-endian octets).
    pub subject: [u8; 8],
    /// Reconstruction point (uncompressed x||y).
    pub point: [u8; POINT_LEN],
}

impl PeerIdentity {
    /// Bundle the three fields; all are required, none is inferred.
    #[must_use]
    pub const fn new(cert: ImplicitCert, subject: [u8; 8], point: [u8; POINT_LEN]) -> Self {
        Self {
            cert,
            subject,
            point,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_is_opaque_48_octets() {
        let bytes = [0x5Au8; IMPLICIT_CERT_LEN];
        let cert = ImplicitCert::from_bytes(bytes);
        assert_eq!(cert.as_bytes(), &bytes);
        let peer = PeerIdentity::new(cert, [1; 8], [2; POINT_LEN]);
        assert_eq!(peer.subject, [1; 8]);
        assert_eq!(peer.point, [2; POINT_LEN]);
    }
}
