//! CBKE handshake orchestration: explicit state machine over an
//! injected [`EccBackend`](crate::ecc::EccBackend).
//!
//! Paraphrase-level model of the doc `07-5356` SE 1.4a §5 key-establishment
//! flow (certificate exchange, static-key reconstruction, shared-secret
//! agreement, MACU/MACV confirmation). All wording here is paraphrase
//! (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below are repo-minted (`07-5356-<clause>-<seq>`,
//! dots stripped), MINTED-pending-confirm, with line anchors from the
//! private corpus: CBKE flow (anchor p0167-L4302-L4306), key
//! confirmation including the failure status (anchors p0168-L4323-L4325
//! + p0167-L4278).
//!
//! # Transcript
//!
//! The session accumulates a bounded transcript — CA key, then both
//! identities and both ephemeral points in canonical role order
//! (initiator first) — totalling at most [`TRANSCRIPT_MAX`] octets. Session and
//! confirmation keys derive from the shared secret bound to this
//! transcript, and the MACU/MACV tags authenticate it, so any
//! transcript disagreement fails the handshake instead of installing
//! a mismatched key.

use crate::cert::PeerIdentity;
use crate::ecc::{
    confirm_tag, mqv_agree, reconstruct_static, scalar_from_kdf, session_keys, EccBackend,
    EccError, MAC_LEN, POINT_LEN, SCALAR_LEN,
};

/// Largest handshake transcript in octets (fixed bound, never grown):
/// CA key (64) plus both sides' certificate (48) + subject (8) +
/// reconstruction point (64) + ephemeral point (64).
pub const TRANSCRIPT_MAX: usize = 512;

/// Domain label for the initiator confirmation key.
pub const CONFIRM_LABEL_U: u8 = 1;
/// Domain label for the responder confirmation key.
pub const CONFIRM_LABEL_V: u8 = 2;
/// Domain label for the link key (see [`session_keys`](crate::ecc::session_keys)).
pub const SESSION_KEY_LABEL: u8 = 0;

/// Role in the handshake: who confirms first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Initiator: sends the first confirmation tag (MACU) and checks
    /// the responder's tag (MACV).
    Initiator,
    /// Responder: checks MACU, then answers with MACV.
    Responder,
}

/// Handshake progress. Transitions only move forward; any failure
/// parks the session in `Failed` and wipes key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CbkeState {
    /// Created; no peer material yet.
    Fresh,
    /// Peer identity + ephemeral received, not yet reconstructed.
    PeerReceived,
    /// Peer static key reconstructed.
    Reconstructed,
    /// Shared secret + session/MAC keys derived.
    Derived,
    /// Local confirmation tag emitted, peer tag not yet checked.
    ConfirmSent,
    /// Peer tag verified, local tag not yet emitted.
    PeerVerified,
    /// Both halves done; `session_key()` is releasable.
    Done,
    /// Terminal failure (see [`CbkeSession::error`]).
    Failed,
}

/// Handshake failures: explicit, fallible, no panics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CbkeError {
    /// Operation not allowed in the current state.
    BadState,
    /// ECC backend failure.
    Ecc(EccError),
    /// Peer confirmation tag did not verify.
    ConfirmMismatch,
    /// Refusing to release a key from an unfinished session.
    NotDone,
    /// Transcript would exceed [`TRANSCRIPT_MAX`].
    TranscriptOverflow,
}

/// One side of a CBKE handshake.
///
/// Requirement `07-5356-C42-06`.
pub struct CbkeSession {
    role: Role,
    state: CbkeState,
    error: Option<CbkeError>,
    ca_pub: [u8; POINT_LEN],
    local_static: [u8; SCALAR_LEN],
    own: PeerIdentity,
    local_eph_priv: Option<[u8; SCALAR_LEN]>,
    local_eph_pub: Option<[u8; POINT_LEN]>,
    peer: Option<PeerIdentity>,
    peer_eph: Option<[u8; POINT_LEN]>,
    peer_static: Option<[u8; POINT_LEN]>,
    link_key: [u8; 16],
    mac_u: [u8; 16],
    mac_v: [u8; 16],
    transcript: [u8; TRANSCRIPT_MAX],
    transcript_len: usize,
}

impl CbkeSession {
    /// Create a session: role, CA public key, our static private key,
    /// and our own identity (certificate material). Absorbs the CA key
    /// as transcript prefix; exchanged material is absorbed later in
    /// canonical role order so both sides build the IDENTICAL
    /// transcript (direction comes from which confirmation key each
    /// side uses, never from transcript bytes).
    ///
    /// `local_static` is the device's full private key matching its
    /// implicit certificate (provisioned together with the cert: the
    /// private scalar behind the peer-reconstructed public key), NOT
    /// the certificate randomness. The peer side reproduces the
    /// matching public key through [`CbkeSession::reconstruct`]; MQV
    /// agreement only holds when both sides are provisioned this way.
    ///
    /// Requirement `07-5356-C42-06`.
    #[must_use]
    pub fn new(
        role: Role,
        ca_pub: [u8; POINT_LEN],
        local_static: [u8; SCALAR_LEN],
        own: PeerIdentity,
    ) -> Self {
        let mut session = Self {
            role,
            state: CbkeState::Fresh,
            error: None,
            ca_pub,
            local_static,
            own,
            local_eph_priv: None,
            local_eph_pub: None,
            peer: None,
            peer_eph: None,
            peer_static: None,
            link_key: [0u8; 16],
            mac_u: [0u8; 16],
            mac_v: [0u8; 16],
            transcript: [0u8; TRANSCRIPT_MAX],
            transcript_len: 0,
        };
        // Infallible: 64 octets always fit.
        let _ = session.absorb(&ca_pub);
        session
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> CbkeState {
        self.state
    }

    /// Role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Terminal failure detail, if any.
    #[must_use]
    pub const fn error(&self) -> Option<CbkeError> {
        self.error
    }

    /// Release the negotiated link key. Only callable in `Done`.
    pub fn session_key(&self) -> Result<[u8; 16], CbkeError> {
        if self.state == CbkeState::Done {
            Ok(self.link_key)
        } else {
            Err(CbkeError::NotDone)
        }
    }

    fn fail(&mut self, err: CbkeError) {
        self.state = CbkeState::Failed;
        self.error = Some(err);
        self.link_key = [0u8; 16];
        self.mac_u = [0u8; 16];
        self.mac_v = [0u8; 16];
    }

    fn absorb(&mut self, bytes: &[u8]) -> Result<(), CbkeError> {
        if self.transcript_len + bytes.len() > TRANSCRIPT_MAX {
            return Err(CbkeError::TranscriptOverflow);
        }
        self.transcript[self.transcript_len..self.transcript_len + bytes.len()]
            .copy_from_slice(bytes);
        self.transcript_len += bytes.len();
        Ok(())
    }

    fn transcript_bytes(&self) -> &[u8] {
        &self.transcript[..self.transcript_len]
    }

    fn require(&self, want: CbkeState) -> Result<(), CbkeError> {
        if self.state == want {
            Ok(())
        } else {
            Err(CbkeError::BadState)
        }
    }

    /// Install our ephemeral key pair (generated by the caller through
    /// its RNG + backend `base_mul`). Stored, not yet absorbed: the
    /// transcript absorbs ephemeral material in canonical role order
    /// once the peer arrives, so both sides match exactly.
    ///
    /// Requirement `07-5356-C42-06`.
    pub fn set_ephemeral(
        &mut self,
        priv_key: [u8; SCALAR_LEN],
        pub_key: [u8; POINT_LEN],
    ) -> Result<(), CbkeError> {
        self.require(CbkeState::Fresh)?;
        if self.local_eph_priv.is_some() {
            return Err(CbkeError::BadState);
        }
        self.local_eph_priv = Some(priv_key);
        self.local_eph_pub = Some(pub_key);
        Ok(())
    }

    /// Absorb one side's material in transcript order: certificate
    /// octets, subject, reconstruction point, ephemeral point.
    fn absorb_side(&mut self, id: &PeerIdentity, eph: &[u8; POINT_LEN]) -> Result<(), CbkeError> {
        let parts: [&[u8]; 4] = [id.cert.as_bytes(), &id.subject, &id.point, eph];
        for p in parts {
            self.absorb(p)?;
        }
        Ok(())
    }

    /// Receive the peer's identity + ephemeral point (Fresh only, and
    /// only after `set_ephemeral`). Absorbs both sides' material in
    /// canonical role order — initiator first — so initiator and
    /// responder build byte-identical transcripts.
    ///
    /// Requirement `07-5356-C42-06`.
    pub fn receive_peer(
        &mut self,
        peer: PeerIdentity,
        peer_eph: [u8; POINT_LEN],
    ) -> Result<(), CbkeError> {
        self.require(CbkeState::Fresh)?;
        let local_eph = self.local_eph_pub.ok_or(CbkeError::BadState)?;
        let own = self.own;
        let outcome = match self.role {
            Role::Initiator => self
                .absorb_side(&own, &local_eph)
                .and_then(|()| self.absorb_side(&peer, &peer_eph)),
            Role::Responder => self
                .absorb_side(&peer, &peer_eph)
                .and_then(|()| self.absorb_side(&own, &local_eph)),
        };
        if let Err(e) = outcome {
            self.fail(e);
            return Err(e);
        }
        self.peer = Some(peer);
        self.peer_eph = Some(peer_eph);
        self.state = CbkeState::PeerReceived;
        Ok(())
    }

    /// Reconstruct the peer's static public key from its certificate
    /// material (SEC4-style pure logic over the backend).
    ///
    /// Requirement `07-5356-C42-06`.
    pub fn reconstruct<B: EccBackend>(
        &mut self,
        backend: &B,
    ) -> Result<[u8; POINT_LEN], CbkeError> {
        self.require(CbkeState::PeerReceived)?;
        let peer = self.peer.expect("state implies peer present");
        match reconstruct_static(backend, &self.ca_pub, &peer) {
            Ok(q) => {
                self.peer_static = Some(q);
                self.state = CbkeState::Reconstructed;
                Ok(q)
            }
            Err(e) => {
                self.fail(CbkeError::Ecc(e));
                Err(CbkeError::Ecc(e))
            }
        }
    }

    /// Combine ephemeral + static material MQV-style, derive the
    /// session link key and both confirmation keys.
    ///
    /// Requirement `07-5356-C42-06`.
    pub fn derive<B: EccBackend>(&mut self, backend: &B) -> Result<(), CbkeError> {
        self.require(CbkeState::Reconstructed)?;
        let outcome = (|| {
            let peer_static = self.peer_static.expect("state implies static present");
            let peer_eph = self.peer_eph.expect("state implies eph present");
            let local_eph = self.local_eph_priv.expect("eph set before peer");
            let local_pub = self.local_eph_pub.expect("eph set before peer");
            let peer = self.peer.expect("state implies peer present");
            // Implicit-signature scalars bind each side's certificate
            // material to its ephemeral point. Both scalars derive from
            // SHARED material only, in canonical role order, so both
            // handshake sides compute identical values: the initiator's
            // scalar from the initiator's identity + ephemeral, the
            // responder's from the responder's.
            let (own_id, own_eph_pub, peer_id, peer_eph_pub) =
                (&self.own, &local_pub, &peer, &peer_eph);
            let (init_id, init_eph, resp_id, resp_eph) = match self.role {
                Role::Initiator => (own_id, own_eph_pub, peer_id, peer_eph_pub),
                Role::Responder => (peer_id, peer_eph_pub, own_id, own_eph_pub),
            };
            let e_init = scalar_from_kdf(
                backend,
                &[
                    init_id.cert.as_bytes(),
                    &init_id.subject,
                    &init_id.point,
                    init_eph,
                ],
                b"cbke-sig-init",
            )?;
            let e_resp = scalar_from_kdf(
                backend,
                &[
                    resp_id.cert.as_bytes(),
                    &resp_id.subject,
                    &resp_id.point,
                    resp_eph,
                ],
                b"cbke-sig-resp",
            )?;
            let (e_local, e_peer) = match self.role {
                Role::Initiator => (&e_init, &e_resp),
                Role::Responder => (&e_resp, &e_init),
            };
            let z = mqv_agree(
                backend,
                &self.local_static,
                &local_eph,
                &peer_static,
                &peer_eph,
                e_local,
                e_peer,
            )?;
            let mut link = [0u8; 16];
            let mut u = [0u8; 16];
            let mut v = [0u8; 16];
            session_keys(
                backend,
                &z,
                self.transcript_bytes(),
                &mut link,
                &mut u,
                &mut v,
            )?;
            Ok((link, u, v))
        })();
        match outcome {
            Ok((link, u, v)) => {
                self.link_key = link;
                self.mac_u = u;
                self.mac_v = v;
                self.state = CbkeState::Derived;
                Ok(())
            }
            Err(e) => {
                self.fail(CbkeError::Ecc(e));
                Err(CbkeError::Ecc(e))
            }
        }
    }

    /// Emit our confirmation tag: initiators MAC with `mac_u`
    /// (MACU), responders with `mac_v` (MACV). Callable once the keys
    /// exist (`Derived`) or after the peer tag already verified
    /// (`PeerVerified`, which then completes the handshake).
    ///
    /// Requirement `07-5356-C42-06`.
    pub fn local_confirm<B: EccBackend>(
        &mut self,
        backend: &B,
    ) -> Result<[u8; MAC_LEN], CbkeError> {
        if self.state != CbkeState::Derived && self.state != CbkeState::PeerVerified {
            return Err(CbkeError::BadState);
        }
        let finishing = self.state == CbkeState::PeerVerified;
        let key = match self.role {
            Role::Initiator => self.mac_u,
            Role::Responder => self.mac_v,
        };
        let mut tag = [0u8; MAC_LEN];
        match confirm_tag(backend, &key, self.transcript_bytes(), &mut tag) {
            Ok(()) => {
                self.state = if finishing {
                    CbkeState::Done
                } else {
                    CbkeState::ConfirmSent
                };
                Ok(tag)
            }
            Err(e) => {
                self.fail(CbkeError::Ecc(e));
                Err(CbkeError::Ecc(e))
            }
        }
    }

    /// Check the peer's confirmation tag (the key we did NOT use
    /// above). Callable after the keys exist, whether or not our own
    /// tag went out first: from `ConfirmSent` success completes the
    /// handshake, from `Derived` it records peer verification and our
    /// tag still has to go out. Mismatch fails the session and wipes
    /// key material either way.
    ///
    /// Requirement `07-5356-C42-06`.
    pub fn check_peer<B: EccBackend>(
        &mut self,
        backend: &B,
        peer_tag: &[u8; MAC_LEN],
    ) -> Result<(), CbkeError> {
        if self.state != CbkeState::ConfirmSent && self.state != CbkeState::Derived {
            return Err(CbkeError::BadState);
        }
        let finishing = self.state == CbkeState::ConfirmSent;
        let key = match self.role {
            Role::Initiator => self.mac_v,
            Role::Responder => self.mac_u,
        };
        let mut expect = [0u8; MAC_LEN];
        if confirm_tag(backend, &key, self.transcript_bytes(), &mut expect).is_err() {
            self.fail(CbkeError::Ecc(EccError::BackendFault));
            return Err(CbkeError::Ecc(EccError::BackendFault));
        }
        // Constant-shape comparison (no early exit on content).
        let mut diff = 0u8;
        for i in 0..MAC_LEN {
            diff |= expect[i] ^ peer_tag[i];
        }
        if diff == 0 {
            self.state = if finishing {
                CbkeState::Done
            } else {
                CbkeState::PeerVerified
            };
            Ok(())
        } else {
            self.fail(CbkeError::ConfirmMismatch);
            Err(CbkeError::ConfirmMismatch)
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::cert::ImplicitCert;
    use crate::mock::MockBackend;

    pub fn peer(id: u8) -> (PeerIdentity, [u8; POINT_LEN]) {
        let b = MockBackend::new(3);
        (
            PeerIdentity::new(
                ImplicitCert::from_bytes([id; crate::cert::IMPLICIT_CERT_LEN]),
                [id; 8],
                b.base_mul(&[id; SCALAR_LEN]).unwrap(),
            ),
            b.base_mul(&[id.wrapping_add(1); SCALAR_LEN]).unwrap(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::peer;
    use super::*;
    use crate::mock::MockBackend;

    #[test]
    fn full_mock_handshake_single_side() {
        // One side driven through every state on the mock backend.
        // MOCK provenance: pins state flow + determinism, not interop
        // (mock ECDH is not cross-side symmetric; host test covers
        // two-side agreement).
        let b = MockBackend::new(7);
        let ca = b.base_mul(&[0xCA; SCALAR_LEN]).unwrap();
        let (own, _) = peer(0x11);
        let mut s = CbkeSession::new(Role::Initiator, ca, [0x11; SCALAR_LEN], own);
        assert_eq!(s.state(), CbkeState::Fresh);
        assert_eq!(s.session_key(), Err(CbkeError::NotDone));
        // Peer before ephemeral is rejected (canonical order needs
        // both sides' ephemeral material).
        let (p_early, pe_early) = peer(0x44);
        assert_eq!(s.receive_peer(p_early, pe_early), Err(CbkeError::BadState));
        let eph_pub = b.base_mul(&[0x22; SCALAR_LEN]).unwrap();
        s.set_ephemeral([0x22; SCALAR_LEN], eph_pub).unwrap();
        // Out-of-order calls are rejected, not panics.
        assert_eq!(s.local_confirm(&b), Err(CbkeError::BadState));
        let (p, pe) = peer(0x44);
        s.receive_peer(p, pe).unwrap();
        assert_eq!(s.state(), CbkeState::PeerReceived);
        // Second peer is rejected (no rewind).
        let (p2, pe2) = peer(0x45);
        assert_eq!(s.receive_peer(p2, pe2), Err(CbkeError::BadState));
        s.reconstruct(&b).unwrap();
        s.derive(&b).unwrap();
        let tag = s.local_confirm(&b).unwrap();
        // Self-check with the WRONG directional key fails and wipes.
        assert_eq!(s.check_peer(&b, &tag), Err(CbkeError::ConfirmMismatch));
        assert_eq!(s.state(), CbkeState::Failed);
        assert_eq!(s.session_key(), Err(CbkeError::NotDone));
    }

    #[test]
    fn responder_role_uses_mac_v_first() {
        let b = MockBackend::new(7);
        let ca = b.base_mul(&[0xCA; SCALAR_LEN]).unwrap();
        let (own_r, _) = peer(0x33);
        let mut r = CbkeSession::new(Role::Responder, ca, [0x33; SCALAR_LEN], own_r);
        let eph_pub = b.base_mul(&[0x55; SCALAR_LEN]).unwrap();
        r.set_ephemeral([0x55; SCALAR_LEN], eph_pub).unwrap();
        let (p, pe) = peer(0x44);
        r.receive_peer(p, pe).unwrap();
        r.reconstruct(&b).unwrap();
        r.derive(&b).unwrap();
        // Different sides (role byte, static, ephemeral all differ)
        // must not collide on confirmation tags.
        let tag_r = r.local_confirm(&b).unwrap();
        let (own_i, _) = peer(0x11);
        let mut i = CbkeSession::new(Role::Initiator, ca, [0x11; SCALAR_LEN], own_i);
        i.set_ephemeral([0x22; SCALAR_LEN], eph_pub).unwrap();
        let (p, pe) = peer(0x44);
        i.receive_peer(p, pe).unwrap();
        i.reconstruct(&b).unwrap();
        i.derive(&b).unwrap();
        let tag_i = i.local_confirm(&b).unwrap();
        assert_ne!(tag_r, tag_i);
    }
}
