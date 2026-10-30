//! Key Establishment cluster (0x0800): suite negotiation, command
//! codecs, and the initiate/ephemeral/confirm/terminate exchange
//! machine wired to the [`rounddance_security`] CBKE core.
//!
//! Paraphrase-level model of doc `07-5123-08` §10.7 (negotiation
//! anchor p0849-L19328-L19336, revision p0849-L19337-L19339, cluster
//! id p0849-L19341, information set p0850-L19350-L19360, server
//! received table p0850-L19361-L19365, initiate payload
//! p0851-L19369-L19381, initiate guards p0851-L19382-L19401,
//! acceptance p0852-L19402-L19409, ephemeral request
//! p0852-L19410-L19426, confirm request p0852-L19427-L19435 +
//! p0853-L19436-L19447, terminate p0853-L19448-L19461 with effect
//! p0854-L19462-L19472, generated table p0855-L24-L27, ephemeral
//! sizes p0865-L19821) plus the doc `07-5356` SE 1.4a §C.3.1 flows
//! (`07-5356-22-C311-01/02`, `-C312-01..10` corpus-mined and reused;
//! suite-2-only field validation collapses to `UNSUPPORTED_SUITE`
//! here because this build holds no suite-2 credentials, and the
//! leave-the-network consequence of `C311-01` is app policy above
//! this layer).
//! All wording here is paraphrase (D1).
//!
//! Requirement IDs below are repo-minted (`07-5123-08-<clause>-<seq>`,
//! dots stripped), MINTED-pending-confirm.
//!
//! # Profile conventions (rounddance, not spec algorithms)
//!
//! * The negotiated suite bit is `SUITE_1` or `SUITE_2` (see
//!   [`SUPPORTED_SUITE_MASK`]); only single-bit suite fields naming
//!   our configured bit are accepted, everything else terminates per
//!   the guard table. The wire shape below (command framing,
//!   negotiation guards, attribute advertisement) is pinned for both
//!   bits; the suite-2 cryptographic core — credential sizes beyond
//!   the 48-octet opaque certificate form, curve choice, KDF labels —
//!   is residue, not implemented here: no in-repo anchor
//!   (`07-5123-08-1073-*` family, `07-5356-22-C311/C312` rows)
//!   pins a suite-2 primitive, and this profile does not invent one.
//! * Certificates on the wire are the 48-octet opaque implicit form
//!   for either suite bit (no in-repo anchor pins a distinct suite-2
//!   size, so none is carried here);
//!   ephemeral points are accepted in BOTH wire forms — the 33-octet
//!   compressed encoding (parity tag + x, `y` recovered on receipt)
//!   and the 64-octet expanded convention — while transmit uses the
//!   locally preferred form (`Exchange::set_tx_compressed`, default
//!   expanded). The CBKE parameter table carries the ephemeral keys
//!   as point-compressed values (anchor p0865-L19821); the expanded
//!   form stays supported as the profile's long-standing convention.
//! * The receiver binds the peer identity to the sender address by
//!   matching the received certificate against locally installed
//!   same-suite certificates (the enforceable form of the
//!   issuer-comparison rule with opaque certificates here).

use crate::attrs::{access, AttrDef, AttrStore, ATTR_CLUSTER_REVISION};
use crate::cluster::{ClusterDef, ClusterRole, CmdDef};
use crate::types::{DataType, Value};
use crate::{Error, ZclStatus};
use rounddance_security::{
    compress_point, derive_update_key, install_link_key, CbkeError, CbkeSession, CbkeState,
    EccBackend, EccError, LinkKeyTable, PeerIdentity, SecError, COMPRESSED_LEN, IMPLICIT_CERT_LEN,
    MAC_LEN, POINT_LEN, SCALAR_LEN,
};

/// Cluster identifier.
///
/// Requirement `07-5123-08-1073-01` (MINTED-pending-confirm).
pub const CLUSTER_ID: u16 = 0x0800;
/// Implemented specification revision.
///
/// Requirement `07-5123-08-1073-02` (MINTED-pending-confirm).
pub const REVISION: u16 = 2;

/// KeyEstablishmentSuite attribute.
pub const ATTR_SUITE: u16 = 0x0000;
/// Suite bit implemented here (Crypto Suite 1 shape).
pub const SUITE_1: u16 = 0x0001;
/// Suite bit with wire-shape + negotiation implemented here; the
/// cryptographic core is residue (see the module docs).
pub const SUITE_2: u16 = 0x0002;
/// Known suite bits: the union of the declared `SUITE_*` bits.
///
/// Requirement `07-5123-08-1073-02` (MINTED-pending-confirm).
pub const SUPPORTED_SUITE_MASK: u16 = SUITE_1 | SUITE_2;

/// Whether `suite` names exactly one suite bit (zero and multi-bit
/// fields are malformed on the wire and terminate with
/// [`TERM_BAD_MESSAGE`]).
///
/// Requirement `07-5123-08-1073-02` (MINTED-pending-confirm).
#[must_use]
pub const fn is_single_suite_bit(suite: u16) -> bool {
    suite != 0 && suite.count_ones() == 1
}

/// Whether `suite` names one of the declared suite bits
/// ([`SUITE_1`], [`SUITE_2`]).
///
/// Requirement `07-5123-08-1073-02` (MINTED-pending-confirm).
#[must_use]
pub const fn is_known_suite(suite: u16) -> bool {
    suite == SUITE_1 || suite == SUITE_2
}

/// Server received: Initiate Key Establishment Request.
pub const CMD_INITIATE_REQ: u8 = 0x00;
/// Server received: Ephemeral Data Request.
pub const CMD_EPHEMERAL_REQ: u8 = 0x01;
/// Server received: Confirm Key Data Request.
pub const CMD_CONFIRM_REQ: u8 = 0x02;
/// Both sides: Terminate Key Establishment.
pub const CMD_TERMINATE: u8 = 0x03;
/// Client generated (= server received as response): Initiate Response.
pub const CMD_INITIATE_RSP: u8 = 0x00;
/// Ephemeral Data Response.
pub const CMD_EPHEMERAL_RSP: u8 = 0x01;
/// Confirm Key Data Response.
pub const CMD_CONFIRM_RSP: u8 = 0x02;

/// Terminate: partner certificate issuer unknown here.
pub const TERM_UNKNOWN_ISSUER: u8 = 0x01;
/// Terminate: key confirmation failed.
pub const TERM_BAD_KEY_CONFIRM: u8 = 0x02;
/// Terminate: bad message / out of sequence / bad length.
pub const TERM_BAD_MESSAGE: u8 = 0x03;
/// Terminate: no resources to continue.
pub const TERM_NO_RESOURCES: u8 = 0x04;
/// Terminate: suite not supported.
pub const TERM_UNSUPPORTED_SUITE: u8 = 0x05;
/// Terminate: certificate fields invalid.
pub const TERM_INVALID_CERTIFICATE: u8 = 0x06;

/// Largest generate-time hint accepted (0xFF is out of range).
pub const MAX_GENERATE_TIME: u8 = 0xFE;
/// Wire ephemeral length for the expanded point form (x || y).
///
/// Requirement `07-5123-08-1074-05` (MINTED-pending-confirm).
pub const EPH_LEN: usize = POINT_LEN;
/// Wire ephemeral length for the compressed point form
/// (parity tag || x).
///
/// Requirement `07-5123-08-1074-05` (MINTED-pending-confirm).
pub const EPH_COMPRESSED_LEN: usize = COMPRESSED_LEN;
/// Largest provisioned-peer table in one exchange.
pub const MAX_PEERS: usize = 4;

/// Server attribute table.
pub static SERVER_ATTRS: &[AttrDef] = &[
    AttrDef {
        id: ATTR_SUITE,
        datatype: DataType::Enum16.as_u8(),
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: ATTR_CLUSTER_REVISION,
        datatype: DataType::UInt(2).as_u8(),
        access: access::READ,
        reportable: false,
    },
];

/// Server received commands, ascending.
pub static SERVER_RX: &[CmdDef] = &[
    CmdDef {
        id: CMD_INITIATE_REQ,
        name: "initiate-req",
    },
    CmdDef {
        id: CMD_EPHEMERAL_REQ,
        name: "ephemeral-req",
    },
    CmdDef {
        id: CMD_CONFIRM_REQ,
        name: "confirm-req",
    },
    CmdDef {
        id: CMD_TERMINATE,
        name: "terminate",
    },
];

/// Server generated commands, ascending.
pub static SERVER_TX: &[CmdDef] = &[
    CmdDef {
        id: CMD_INITIATE_RSP,
        name: "initiate-rsp",
    },
    CmdDef {
        id: CMD_EPHEMERAL_RSP,
        name: "ephemeral-rsp",
    },
    CmdDef {
        id: CMD_CONFIRM_RSP,
        name: "confirm-rsp",
    },
    CmdDef {
        id: CMD_TERMINATE,
        name: "terminate",
    },
];

/// Server definition.
pub struct ServerDef;
impl ClusterDef for ServerDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "keyest-server"
    }
    fn revision(&self) -> u16 {
        REVISION
    }
    fn role(&self) -> ClusterRole {
        ClusterRole::Server
    }
    fn attributes(&self) -> &'static [AttrDef] {
        SERVER_ATTRS
    }
    fn received_commands(&self) -> &'static [CmdDef] {
        SERVER_RX
    }
    fn generated_commands(&self) -> &'static [CmdDef] {
        SERVER_TX
    }
}

/// Client definition (mirrored command sets).
pub struct ClientDef;
impl ClusterDef for ClientDef {
    fn cluster_id(&self) -> u16 {
        CLUSTER_ID
    }
    fn name(&self) -> &'static str {
        "keyest-client"
    }
    fn revision(&self) -> u16 {
        REVISION
    }
    fn role(&self) -> ClusterRole {
        ClusterRole::Client
    }
    fn attributes(&self) -> &'static [AttrDef] {
        SERVER_ATTRS
    }
    fn received_commands(&self) -> &'static [CmdDef] {
        SERVER_TX
    }
    fn generated_commands(&self) -> &'static [CmdDef] {
        SERVER_RX
    }
}

/// Build a fresh suite attribute store advertising `SUITE_1`.
///
/// Requirement `07-5123-08-1073-02` (MINTED-pending-confirm).
pub fn server_store() -> Result<AttrStore, Error> {
    server_store_for_suite(SUITE_1)
}

/// Build a fresh suite attribute store advertising `suite`: one of
/// the declared suite bits ([`SUITE_1`], [`SUITE_2`]). Anything else
/// — zero, multi-bit, or an unknown bit — is refused, never
/// defaulted.
///
/// Requirement `07-5123-08-1073-02` (MINTED-pending-confirm).
pub fn server_store_for_suite(suite: u16) -> Result<AttrStore, Error> {
    if !is_single_suite_bit(suite) || !is_known_suite(suite) {
        return Err(Error::InvalidValue(0));
    }
    let mut store = AttrStore::new(None);
    store.add(SERVER_ATTRS[0], Value::Enum16(suite))?;
    store.add_globals(REVISION)?;
    Ok(store)
}

/// Decoded Initiate (request or response) body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitiateMsg {
    /// Negotiated suite (single bit).
    pub suite: u16,
    /// Peer ephemeral-generation hint.
    pub eph_time: u8,
    /// Peer confirm-generation hint.
    pub confirm_time: u8,
    /// Implicit certificate octets (48-octet opaque form, either suite).
    pub cert: [u8; IMPLICIT_CERT_LEN],
}

/// Decode an Initiate body: 2 + 1 + 1 + 48 octets.
///
/// Requirement `07-5123-08-1074-01` (MINTED-pending-confirm).
pub fn decode_initiate(buf: &[u8]) -> Result<InitiateMsg, Error> {
    if buf.len() != 4 + IMPLICIT_CERT_LEN {
        return Err(Error::Truncated);
    }
    let mut cert = [0u8; IMPLICIT_CERT_LEN];
    cert.copy_from_slice(&buf[4..]);
    Ok(InitiateMsg {
        suite: u16::from_le_bytes([buf[0], buf[1]]),
        eph_time: buf[2],
        confirm_time: buf[3],
        cert,
    })
}

/// Encode an Initiate body.
pub fn encode_initiate(msg: &InitiateMsg, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 4 + IMPLICIT_CERT_LEN {
        return Err(Error::BufferTooSmall);
    }
    out[0..2].copy_from_slice(&msg.suite.to_le_bytes());
    out[2] = msg.eph_time;
    out[3] = msg.confirm_time;
    out[4..4 + IMPLICIT_CERT_LEN].copy_from_slice(&msg.cert);
    Ok(4 + IMPLICIT_CERT_LEN)
}

/// Decoded Terminate body.
///
/// Requirement `07-5123-08-1074-04` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminateMsg {
    /// Status code (`TERM_*`).
    pub status: u8,
    /// Wait hint in seconds before retrying.
    pub wait_s: u8,
    /// Sender suite mask.
    pub suite: u16,
}

/// Decode a Terminate body (1 + 1 + 2 octets).
pub fn decode_terminate(buf: &[u8]) -> Result<TerminateMsg, Error> {
    if buf.len() != 4 {
        return Err(Error::Truncated);
    }
    Ok(TerminateMsg {
        status: buf[0],
        wait_s: buf[1],
        suite: u16::from_le_bytes([buf[2], buf[3]]),
    })
}

/// Encode a Terminate body.
pub fn encode_terminate(msg: &TerminateMsg, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 4 {
        return Err(Error::BufferTooSmall);
    }
    out[0] = msg.status;
    out[1] = msg.wait_s;
    out[2..4].copy_from_slice(&msg.suite.to_le_bytes());
    Ok(4)
}

/// Retry advice after a received Terminate.
///
/// Requirement `07-5123-08-1074-04` (MINTED-pending-confirm, effect
/// half of the terminate rules).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryAdvice {
    /// Wait `wait_s` seconds, then may retry the same peer.
    WaitThenRetry {
        /// Minimum wait in seconds.
        wait_s: u8,
    },
    /// Try another mutually supported suite after waiting.
    TryOtherSuite {
        /// Minimum wait in seconds.
        wait_s: u8,
        /// Partner suite mask.
        suite: u16,
    },
    /// Do not retry: another attempt is unlikely to succeed.
    GiveUp,
}

/// Map a received terminate status onto retry advice.
#[must_use]
pub const fn retry_advice(msg: &TerminateMsg) -> RetryAdvice {
    match msg.status {
        TERM_BAD_MESSAGE | TERM_NO_RESOURCES => RetryAdvice::WaitThenRetry { wait_s: msg.wait_s },
        TERM_UNSUPPORTED_SUITE => RetryAdvice::TryOtherSuite {
            wait_s: msg.wait_s,
            suite: msg.suite,
        },
        _ => RetryAdvice::GiveUp,
    }
}

/// An ephemeral point in either accepted wire form.
///
/// Requirement `07-5123-08-1074-05` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EphemeralPayload {
    /// 64-octet expanded convention (x || y).
    Expanded([u8; EPH_LEN]),
    /// 33-octet compressed encoding (parity tag || x).
    Compressed([u8; EPH_COMPRESSED_LEN]),
}

impl EphemeralPayload {
    /// Wire bytes of this payload.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Expanded(p) => &p[..],
            Self::Compressed(p) => &p[..],
        }
    }

    /// Wire length: [`EPH_LEN`] or [`EPH_COMPRESSED_LEN`].
    #[must_use]
    pub const fn len(&self) -> usize {
        match self {
            Self::Expanded(_) => EPH_LEN,
            Self::Compressed(_) => EPH_COMPRESSED_LEN,
        }
    }

    /// Whether this payload uses the compressed encoding.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        matches!(self, Self::Compressed(_))
    }

    /// Whether this payload carries no bytes: never true — both wire
    /// forms are fixed non-zero lengths (exists for the `len`/`is_empty`
    /// pair convention).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

/// Expand a received ephemeral payload to the 64-octet form the
/// crypto session consumes: expanded bytes pass through, compressed
/// bytes recover `y` through the backend. Anything else — wrong
/// length, unknown tag, `x >= p`, non-residue `x` — reports the
/// terminate status the caller must fail with (a malformed ephemeral
/// field is a bad message, never a certificate defect).
fn decode_peer<B: EccBackend>(backend: &B, qe: &[u8]) -> Result<[u8; POINT_LEN], u8> {
    if qe.len() == EPH_LEN {
        let mut point = [0u8; POINT_LEN];
        point.copy_from_slice(qe);
        return Ok(point);
    }
    if qe.len() == EPH_COMPRESSED_LEN {
        let mut compressed = [0u8; COMPRESSED_LEN];
        compressed.copy_from_slice(qe);
        return backend
            .point_decompress(&compressed)
            .map_err(|_| TERM_BAD_MESSAGE);
    }
    Err(TERM_BAD_MESSAGE)
}

/// Exchange-level failures (wire-visible as Terminate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExchangeError {
    /// No exchange is active with this peer (sequence violation).
    NoExchange,
    /// Wrong message for the current stage (sequence violation).
    OutOfSequence,
    /// Crypto core failure (mapped to a terminate status).
    Core(CbkeError),
    /// Outgoing terminate was produced (see [`Exchange::take_terminate`]).
    Terminated,
}

/// One side of a 0x0800 key-establishment exchange: the cluster
/// framing around a [`CbkeSession`].
///
/// Requirement `07-5356-22-C312-06` (corpus-mined: out-of-sequence
/// messages terminate) drives every `Err` path below into a pending
/// outgoing Terminate retrievable with [`Exchange::take_terminate`].
pub struct Exchange {
    session: CbkeSession,
    initiator: bool,
    stage: Stage,
    suite: u16,
    own: PeerIdentity,
    peers: [Option<PeerIdentity>; MAX_PEERS],
    pending_peer: Option<PeerIdentity>,
    own_eph_pub: Option<[u8; POINT_LEN]>,
    tx_compressed: bool,
    pending_term: Option<TerminateMsg>,
    failed: bool,
}

/// Cluster-visible stage (mirrors the crypto session, plus the
/// pre-crypto initiation step).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Created; our ephemeral is installed, no peer yet.
    Fresh,
    /// Initiation accepted (responder) or sent (initiator).
    Initiated,
    /// Ephemeral material exchanged; keys derived.
    KeysDerived,
    /// Our confirmation sent (initiator) or peer confirmed.
    Confirming,
    /// Both confirmations done; session key releasable.
    Done,
    /// Terminal failure.
    Failed,
}

impl Exchange {
    /// Create one side: installs our ephemeral pair into the crypto
    /// session and advertises `suite`. `own` is our full provisioned
    /// identity; `peers` are the installed same-suite certificates we
    /// accept (issuer-equivalence by membership).
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        initiator: bool,
        ca_pub: [u8; POINT_LEN],
        local_static: [u8; SCALAR_LEN],
        own: PeerIdentity,
        eph_priv: [u8; SCALAR_LEN],
        eph_pub: [u8; POINT_LEN],
        peers: &[PeerIdentity],
        suite: u16,
    ) -> Result<Self, CbkeError> {
        let role = if initiator {
            rounddance_security::Role::Initiator
        } else {
            rounddance_security::Role::Responder
        };
        let mut session = CbkeSession::new(role, ca_pub, local_static, own);
        session.set_ephemeral(eph_priv, eph_pub)?;
        let mut table = [None; MAX_PEERS];
        let mut i = 0;
        while i < peers.len().min(MAX_PEERS) {
            table[i] = Some(peers[i]);
            i += 1;
        }
        Ok(Self {
            session,
            initiator,
            stage: Stage::Fresh,
            suite,
            own,
            peers: table,
            pending_peer: None,
            own_eph_pub: Some(eph_pub),
            tx_compressed: false,
            pending_term: None,
            failed: false,
        })
    }

    /// Prefer the compressed encoding on transmit. The default is the
    /// expanded convention; either choice is always accepted on
    /// receipt, so this only shapes our own flights.
    ///
    /// Requirement `07-5123-08-1074-05` (MINTED-pending-confirm).
    pub fn set_tx_compressed(&mut self, compressed: bool) {
        self.tx_compressed = compressed;
    }

    /// Whether transmit currently prefers the compressed encoding.
    #[must_use]
    pub const fn tx_compressed(&self) -> bool {
        self.tx_compressed
    }

    /// Our ephemeral payload in the preferred transmit form.
    fn own_payload(&self) -> Result<EphemeralPayload, ExchangeError> {
        let eph = self.own_eph_pub.ok_or(ExchangeError::NoExchange)?;
        if self.tx_compressed {
            Ok(EphemeralPayload::Compressed(compress_point(&eph)))
        } else {
            Ok(EphemeralPayload::Expanded(eph))
        }
    }

    /// Current stage.
    #[must_use]
    pub const fn stage(&self) -> Stage {
        self.stage
    }

    /// Take a pending outgoing Terminate, if the last call queued one.
    #[must_use]
    pub fn take_terminate(&mut self) -> Option<TerminateMsg> {
        self.pending_term.take()
    }

    /// Whether the handshake completed (session key releasable).
    #[must_use]
    pub const fn is_done(&self) -> bool {
        matches!(self.stage, Stage::Done)
    }

    fn fail(&mut self, status: u8, core: Option<CbkeError>) -> ExchangeError {
        self.stage = Stage::Failed;
        self.failed = true;
        self.pending_term = Some(TerminateMsg {
            status,
            wait_s: 0,
            suite: self.suite,
        });
        let _ = core;
        ExchangeError::Terminated
    }

    /// Validate an incoming suite field: exactly our bit, nothing else.
    /// A foreign single bit terminates with `UNSUPPORTED_SUITE`;
    /// zero and multi-bit fields terminate with `BAD_MESSAGE`.
    fn check_suite(&self, suite: u16) -> Result<(), TerminateMsg> {
        if suite != self.suite {
            if is_single_suite_bit(suite) {
                return Err(TerminateMsg {
                    status: TERM_UNSUPPORTED_SUITE,
                    wait_s: 0,
                    suite: self.suite,
                });
            }
            return Err(TerminateMsg {
                status: TERM_BAD_MESSAGE,
                wait_s: 0,
                suite: self.suite,
            });
        }
        Ok(())
    }

    /// Find the installed peer matching `cert` (issuer-equivalence by
    /// membership in the same-suite table).
    fn find_peer(&self, cert: &[u8; IMPLICIT_CERT_LEN]) -> Option<PeerIdentity> {
        let mut i = 0;
        while i < MAX_PEERS {
            if let Some(p) = self.peers[i] {
                if p.cert.as_bytes() == cert {
                    return Some(p);
                }
            }
            i += 1;
        }
        None
    }

    /// Build the outgoing Initiate body (initiator only).
    pub fn initiate_request(&self) -> Result<InitiateMsg, ExchangeError> {
        if !self.initiator || self.stage != Stage::Fresh || self.failed {
            return Err(ExchangeError::NoExchange);
        }
        let own = self.session_own();
        Ok(InitiateMsg {
            suite: self.suite,
            eph_time: 2,
            confirm_time: 2,
            cert: *own.cert.as_bytes(),
        })
    }

    fn session_own(&self) -> PeerIdentity {
        self.own
    }

    /// Handle an incoming Initiate Request (responder only):
    /// validates suite/times/certificate, remembers the peer, and
    /// returns our Initiate Response body.
    ///
    /// Requirements `07-5123-08-107-02/03/04` (corpus-mined guards)
    /// + `07-5356-22-C312-01..05` (corpus-mined initiation flow).
    pub fn on_initiate<B: EccBackend>(
        &mut self,
        _backend: &B,
        msg: &InitiateMsg,
    ) -> Result<InitiateMsg, ExchangeError> {
        if self.initiator || self.stage != Stage::Fresh || self.failed {
            return Err(ExchangeError::NoExchange);
        }
        if let Err(term) = self.check_suite(msg.suite) {
            self.pending_term = Some(term);
            self.stage = Stage::Failed;
            self.failed = true;
            return Err(ExchangeError::Terminated);
        }
        if msg.eph_time > MAX_GENERATE_TIME || msg.confirm_time > MAX_GENERATE_TIME {
            return Err(self.fail(TERM_BAD_MESSAGE, None));
        }
        let Some(peer) = self.find_peer(&msg.cert) else {
            return Err(self.fail(TERM_UNKNOWN_ISSUER, None));
        };
        self.pending_peer = Some(peer);
        self.stage = Stage::Initiated;
        let own = self.session_own();
        Ok(InitiateMsg {
            suite: self.suite,
            eph_time: 2,
            confirm_time: 2,
            cert: *own.cert.as_bytes(),
        })
    }

    /// Handle an incoming Initiate Response (initiator only):
    /// validates and remembers the responder, ready for the
    /// ephemeral step.
    pub fn on_initiate_response<B: EccBackend>(
        &mut self,
        _backend: &B,
        msg: &InitiateMsg,
    ) -> Result<(), ExchangeError> {
        if !self.initiator || self.stage != Stage::Fresh || self.failed {
            return Err(ExchangeError::NoExchange);
        }
        if let Err(term) = self.check_suite(msg.suite) {
            self.pending_term = Some(term);
            self.stage = Stage::Failed;
            self.failed = true;
            return Err(ExchangeError::Terminated);
        }
        let Some(peer) = self.find_peer(&msg.cert) else {
            return Err(self.fail(TERM_UNKNOWN_ISSUER, None));
        };
        self.pending_peer = Some(peer);
        self.stage = Stage::Initiated;
        Ok(())
    }

    /// Outgoing ephemeral payload in the preferred transmit form
    /// (expanded by default; compressed after
    /// [`Exchange::set_tx_compressed`]).
    pub fn ephemeral_request(&self) -> Result<EphemeralPayload, ExchangeError> {
        if self.stage != Stage::Initiated || self.failed {
            return Err(ExchangeError::OutOfSequence);
        }
        self.own_payload()
    }

    /// Handle an incoming Ephemeral Data Request (responder): checks
    /// form and sequence, drives reconstruction + derivation, and
    /// returns our Ephemeral Data Response payload in the preferred
    /// transmit form.
    ///
    /// Requirements `07-5123-08-1074-02/05` (MINTED-pending-confirm) +
    /// `07-5356-22-C312-06/07` (corpus-mined sequence + length rules).
    pub fn on_ephemeral_request<B: EccBackend>(
        &mut self,
        backend: &B,
        qe: &[u8],
    ) -> Result<EphemeralPayload, ExchangeError> {
        if self.initiator || self.stage != Stage::Initiated || self.failed {
            return Err(self.fail(TERM_BAD_MESSAGE, None));
        }
        let peer_eph = match decode_peer(backend, qe) {
            Ok(point) => point,
            Err(status) => return Err(self.fail(status, None)),
        };
        let peer = self.pending_peer.ok_or(ExchangeError::NoExchange)?;
        if let Err(e) = self.session.receive_peer(peer, peer_eph) {
            return Err(self.fail(TERM_BAD_MESSAGE, Some(e)));
        }
        if let Err(e) = self.session.reconstruct(backend) {
            let status = match e {
                CbkeError::Ecc(EccError::InvalidPoint | EccError::InvalidScalar) => {
                    TERM_INVALID_CERTIFICATE
                }
                _ => TERM_NO_RESOURCES,
            };
            return Err(self.fail(status, Some(e)));
        }
        if let Err(e) = self.session.derive(backend) {
            return Err(self.fail(TERM_NO_RESOURCES, Some(e)));
        }
        self.stage = Stage::KeysDerived;
        self.own_payload()
    }

    /// Handle an incoming Ephemeral Data Response (initiator):
    /// completes reconstruction + derivation and returns our
    /// confirmation tag (MACU) for the Confirm Request. Accepts
    /// either ephemeral wire form.
    pub fn on_ephemeral_response<B: EccBackend>(
        &mut self,
        backend: &B,
        qe: &[u8],
    ) -> Result<[u8; MAC_LEN], ExchangeError> {
        if !self.initiator || self.stage != Stage::Initiated || self.failed {
            return Err(self.fail(TERM_BAD_MESSAGE, None));
        }
        let peer_eph = match decode_peer(backend, qe) {
            Ok(point) => point,
            Err(status) => return Err(self.fail(status, None)),
        };
        let peer = self.pending_peer.ok_or(ExchangeError::NoExchange)?;
        if let Err(e) = self.session.receive_peer(peer, peer_eph) {
            return Err(self.fail(TERM_BAD_MESSAGE, Some(e)));
        }
        if let Err(e) = self.session.reconstruct(backend) {
            let status = match e {
                CbkeError::Ecc(EccError::InvalidPoint | EccError::InvalidScalar) => {
                    TERM_INVALID_CERTIFICATE
                }
                _ => TERM_NO_RESOURCES,
            };
            return Err(self.fail(status, Some(e)));
        }
        if let Err(e) = self.session.derive(backend) {
            return Err(self.fail(TERM_NO_RESOURCES, Some(e)));
        }
        self.stage = Stage::KeysDerived;
        match self.session.local_confirm(backend) {
            Ok(tag) => {
                self.stage = Stage::Confirming;
                Ok(tag)
            }
            Err(e) => Err(self.fail(TERM_NO_RESOURCES, Some(e))),
        }
    }

    /// Handle an incoming Confirm Request (responder): verifies MACU
    /// and returns MACV. A mismatch terminates with BAD_KEY_CONFIRM.
    ///
    /// Requirements `07-5123-08-1074-03` (MINTED-pending-confirm) +
    /// `07-5356-22-C312-08` (corpus-mined confirmation rule).
    pub fn on_confirm_request<B: EccBackend>(
        &mut self,
        backend: &B,
        mac: &[u8],
    ) -> Result<[u8; MAC_LEN], ExchangeError> {
        if self.initiator || self.stage != Stage::KeysDerived || self.failed {
            return Err(self.fail(TERM_BAD_MESSAGE, None));
        }
        if mac.len() != MAC_LEN {
            return Err(self.fail(TERM_BAD_MESSAGE, None));
        }
        let mut tag = [0u8; MAC_LEN];
        tag.copy_from_slice(mac);
        match self.session.check_peer(backend, &tag) {
            Ok(()) => {}
            Err(CbkeError::ConfirmMismatch) => {
                return Err(self.fail(TERM_BAD_KEY_CONFIRM, None));
            }
            Err(e) => return Err(self.fail(TERM_NO_RESOURCES, Some(e))),
        }
        match self.session.local_confirm(backend) {
            Ok(answer) => {
                self.stage = Stage::Done;
                Ok(answer)
            }
            Err(e) => Err(self.fail(TERM_NO_RESOURCES, Some(e))),
        }
    }

    /// Handle an incoming Confirm Response (initiator): verifies MACV
    /// and completes the handshake. A mismatch terminates.
    pub fn on_confirm_response<B: EccBackend>(
        &mut self,
        backend: &B,
        mac: &[u8],
    ) -> Result<(), ExchangeError> {
        if !self.initiator || self.stage != Stage::Confirming || self.failed {
            return Err(self.fail(TERM_BAD_MESSAGE, None));
        }
        if mac.len() != MAC_LEN {
            return Err(self.fail(TERM_BAD_MESSAGE, None));
        }
        let mut tag = [0u8; MAC_LEN];
        tag.copy_from_slice(mac);
        match self.session.check_peer(backend, &tag) {
            Ok(()) => {
                self.stage = Stage::Done;
                Ok(())
            }
            Err(CbkeError::ConfirmMismatch) => Err(self.fail(TERM_BAD_KEY_CONFIRM, None)),
            Err(e) => Err(self.fail(TERM_NO_RESOURCES, Some(e))),
        }
    }

    /// Handle an incoming Terminate: parks the session as failed and
    /// reports retry advice. Never answers a terminate with another
    /// terminate.
    pub fn on_terminate(&mut self, msg: &TerminateMsg) -> RetryAdvice {
        self.stage = Stage::Failed;
        self.failed = true;
        self.pending_term = None;
        retry_advice(msg)
    }

    /// Release the negotiated session key (only when done).
    pub fn session_key(&self) -> Result<[u8; 16], CbkeError> {
        if self.stage != Stage::Done {
            return Err(CbkeError::NotDone);
        }
        if self.session.state() != CbkeState::Done {
            return Err(CbkeError::NotDone);
        }
        self.session.session_key()
    }
}

/// Trust-center link-key update record: the negotiated key installed
/// under the peer address, plus the rotation nonce for the next turn.
///
/// Requirement `07-5356-C41-02` (MINTED-pending-confirm).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyUpdateReceipt {
    /// Peer long address the key was installed under.
    pub ieee: [u8; 8],
    /// Installed key (the CBKE session key on first update).
    pub key: [u8; 16],
}

/// Install the negotiated session key into the trust-center table
/// for `ieee`: the CBKE completion step that replaces the bootstrap
/// key with the public-key-derived link key.
///
/// Requirement `07-5356-C41-02` (MINTED-pending-confirm).
pub fn install_negotiated_key<const N: usize>(
    table: &mut LinkKeyTable<N>,
    exchange: &Exchange,
    ieee: [u8; 8],
) -> Result<KeyUpdateReceipt, SecError> {
    let key = exchange.session_key().map_err(|_| SecError::NotFound)?;
    install_link_key(table, ieee, key)?;
    Ok(KeyUpdateReceipt { ieee, key })
}

/// Rotate an installed link key under a fresh nonce (MMO-masked),
/// for post-CBKE re-keying without a full new exchange.
///
/// Requirement `07-5356-C41-02` (MINTED-pending-confirm).
pub fn rotate_link_key<const N: usize>(
    table: &mut LinkKeyTable<N>,
    ieee: [u8; 8],
    nonce: u32,
) -> Result<KeyUpdateReceipt, SecError> {
    let old = table.find(&ieee).ok_or(SecError::NotFound)?.key;
    let key = derive_update_key(&old, &ieee, nonce);
    install_link_key(table, ieee, key)?;
    Ok(KeyUpdateReceipt { ieee, key })
}

/// Map a dispatcher outcome onto a ZCL status for cluster-command
/// failures that carry no terminate of their own.
#[must_use]
pub const fn exchange_status(err: ExchangeError) -> ZclStatus {
    match err {
        ExchangeError::NoExchange | ExchangeError::OutOfSequence => ZclStatus::UnsupCommand,
        ExchangeError::Core(_) | ExchangeError::Terminated => ZclStatus::Failure,
    }
}
