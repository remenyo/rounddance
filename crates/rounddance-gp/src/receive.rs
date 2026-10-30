//! Sink intake: the unified sink-side receive path for GPDFs.
//!
//! The sink is the mains-powered device that consumes GPDFs: it
//! verifies or decrypts counter-protected frames under slotted keys,
//! drops replays through a counter window, admits frames against the
//! sink table (SrcId/IEEE pairing plus commissioning-mode handling),
//! and hands accepted commands to the network layer as routing
//! records. [`receive`] wires the existing machines
//! ([`Gpdf::decode`](crate::frame::Gpdf),
//! [`GpReplay`](crate::security::GpReplay),
//! [`SinkTable`](crate::sink::SinkTable),
//! [`TranslationTable`](crate::sink::TranslationTable),
//! [`CommissioningSession`](crate::commissioning::CommissioningSession))
//! into that single intake so callers never re-derive the order:
//! decode, ingress filter, secured open, freshness, Success
//! completion, table admission, then route.
//!
//! Paraphrase-level model of doc `14-0563-19` §A.1.5.3 (security
//! operation), §A.3.6.2 (sink operation), §A.3.6.2.2 (translation
//! table), §A.1.5.2 (level gating). All wording here is paraphrase
//! (D1, `SCOPE.md` §2).
//!
//! Requirement IDs below: corpus-mined `14-0563-19-*` plus
//! repo-minted `RD-GP-*` (MINTED-pending-confirm).

use crate::commissioning::{is_commissioning_command, CommissioningSession, CommissioningState};
use crate::frame::{AppId, GpError, GpdId, Gpdf, GpdfBody, WireSecurityLevel, MAX_GPD_PAYLOAD};
use crate::reply::{CMD_COMMISSIONING, CMD_SUCCESS};
use crate::security::{GpNonce, GpReplay};
use crate::sink::{
    PayloadMode, SinkTable, SinkTableEntry, TranslationTable, MAX_TRANSLATION_PAYLOAD,
};
use rounddance_security::encrypt_block_aes128;

/// Largest verified command section the opener hands back: one
/// command octet plus the codec payload budget.
///
/// Requirement `RD-GP-01`.
pub const MAX_GP_OPEN: usize = MAX_GPD_PAYLOAD + 1;

/// Maximum GP key slots, indexed by the wire key-bit value (one slot
/// for the group-key class, one for the individual-key class).
///
/// Requirement `RD-GP-01`.
pub const MAX_GP_SLOTS: usize = 2;

/// One loaded GP key: raw octets plus the wire key-bit value the lab
/// provisioned it under. Never rendered.
///
/// Requirement `RD-GP-01`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpKeySlot {
    /// Raw 128-bit key octets.
    pub key: [u8; 16],
    /// Key-bit value this slot answers.
    pub key_bit: bool,
}

/// Operator-loaded GP key material for the sink intake: the opener
/// resolves strictly by the wire key-bit, so a protected frame naming
/// an unloaded class never opens, even when the other class slot is
/// loaded.
///
/// Requirement `RD-GP-01`.
#[derive(Debug)]
pub struct GpKeySlots {
    slots: [Option<GpKeySlot>; MAX_GP_SLOTS],
}

impl GpKeySlots {
    /// Empty slots: no key material.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_GP_SLOTS],
        }
    }

    /// Load (or replace by key-bit value) one GP key.
    pub fn set(&mut self, key: [u8; 16], key_bit: bool) {
        if let Some(slot) = self
            .slots
            .iter_mut()
            .find(|s| matches!(s, Some(e) if e.key_bit == key_bit))
        {
            *slot = Some(GpKeySlot { key, key_bit });
            return;
        }
        if let Some(slot) = self.slots.iter_mut().find(|s| s.is_none()) {
            *slot = Some(GpKeySlot { key, key_bit });
        }
    }

    /// Key octets for the slot provisioned under `key_bit`, if loaded.
    #[must_use]
    pub fn get(&self, key_bit: bool) -> Option<[u8; 16]> {
        self.slots
            .iter()
            .filter_map(|s| *s)
            .find(|s| s.key_bit == key_bit)
            .map(|s| s.key)
    }

    /// Number of loaded slots.
    #[must_use]
    pub const fn len(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < MAX_GP_SLOTS {
            if self.slots[i].is_some() {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// True when no key is loaded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for GpKeySlots {
    fn default() -> Self {
        Self::new()
    }
}

/// Open one counter-protected GPDF against the slotted keys.
///
/// The GPDF carries its own header in the clear; only the command
/// section is integrity-checked (counter-plus-MIC level) or
/// decrypted-then-checked (encrypted level), following the same CCM*
/// wire shape as the inspector's offline opener: the GP nonce binds
/// the GPD identity to the frame counter, the associated data covers
/// the header (frame control, extended control, the identity word the
/// protection covers — source identifier, or the endpoint octet for
/// IEEE identities — plus the counter), and the trailing integrity
/// word is 4 octets. The key resolves strictly by the wire key-bit;
/// every integrity failure yields [`GpError::SecurityFailed`]. A
/// failure leaves no usable output: the caller must ignore `out`.
///
/// Unprotected, LPED, maintenance, and proxy-originated frames carry
/// no envelope this opener consumes and are refused.
///
/// Requirement `RD-GP-01` (reuses the `decrypt::open_gp` wire
/// semantics inside this `no_std` crate).
pub fn open_secured(
    slots: &GpKeySlots,
    gpdf_bytes: &[u8],
    out: &mut [u8],
) -> Result<usize, GpError> {
    let (gpdf, _) = Gpdf::decode(gpdf_bytes)?;
    let ext = gpdf.ext.ok_or(GpError::MissingExtControl)?;
    if matches!(ext.app_id, AppId::Lped) {
        return Err(GpError::ForeignAppId(AppId::Lped.bits()));
    }
    if ext.direction_proxy {
        return Err(GpError::ProxyOriginated);
    }
    let protected = match ext.level {
        WireSecurityLevel::None => return Err(GpError::BadState),
        WireSecurityLevel::MicOnly => false,
        WireSecurityLevel::Encrypted => true,
    };
    let counter = gpdf.frame_counter.ok_or(GpError::Truncated)?;
    let key = slots.get(ext.key_bit).ok_or(GpError::SecurityFailed)?;
    // Nonce address half: the repeated source identifier, or the GPD
    // IEEE address — always the incoming shape here.
    let addr = match gpdf.id.ok_or(GpError::MissingExtControl)? {
        GpdId::SrcId(id) => GpNonce::incoming_srcid_addr(id),
        GpdId::Ieee { addr, .. } => GpNonce::ieee_addr(addr),
    };
    let nonce = GpNonce::build(addr, counter, false);
    // Associated-data header: frame control, extended control, the
    // identity word the protection covers, then the counter. The wire
    // header length differs from the associated-data length for IEEE
    // identities (the address travels on air but only the endpoint
    // enters the integrity computation).
    let mut aad = [0u8; 10];
    let mut aad_len = 2;
    aad[0] = gpdf.fc.encode();
    aad[1] = ext.encode();
    let hdr_len = match gpdf.id {
        Some(GpdId::SrcId(id)) => {
            aad[aad_len..aad_len + 4].copy_from_slice(&id.to_le_bytes());
            aad_len += 4;
            2 + 4 + 4
        }
        Some(GpdId::Ieee { endpoint, .. }) => {
            aad[aad_len] = endpoint;
            aad_len += 1;
            2 + 9 + 4
        }
        None => return Err(GpError::MissingExtControl),
    };
    aad[aad_len..aad_len + 4].copy_from_slice(&counter.to_le_bytes());
    aad_len += 4;
    let aad = &aad[..aad_len];
    if !matches!(gpdf.body, GpdfBody::Gp { .. }) {
        return Err(GpError::ForeignAppId(AppId::Lped.bits()));
    }
    let section_len = gpdf_bytes
        .len()
        .checked_sub(hdr_len + 4)
        .ok_or(GpError::Truncated)?;
    let section = gpdf_bytes
        .get(hdr_len..gpdf_bytes.len() - 4)
        .ok_or(GpError::Truncated)?;
    if section.is_empty() || out.len() < section_len {
        return Err(GpError::TooSmall);
    }
    if protected {
        // Encrypted level: counter-mode decrypt (counter from 1),
        // then verify over the decrypted section.
        ctr_crypt(&key, &nonce.bytes, section, &mut out[..section_len]);
        let ok = gp_verify(
            &key,
            &nonce.bytes,
            aad,
            &[],
            &out[..section_len],
            &gpdf_bytes[gpdf_bytes.len() - 4..],
        );
        if ok {
            Ok(section_len)
        } else {
            Err(GpError::SecurityFailed)
        }
    } else {
        // Counter-plus-MIC level: the section travels in the clear;
        // verify it, then hand it back for the command leg.
        let ok = gp_verify(
            &key,
            &nonce.bytes,
            aad,
            section,
            &[],
            &gpdf_bytes[gpdf_bytes.len() - 4..],
        );
        if ok {
            out[..section_len].copy_from_slice(section);
            Ok(section_len)
        } else {
            Err(GpError::SecurityFailed)
        }
    }
}

/// Counter-mode crypt (decrypt == encrypt): keystream block `i`
/// covers section octets `16*(i-1)..`, starting at counter 1.
fn ctr_crypt(key: &[u8; 16], nonce13: &[u8; 13], input: &[u8], out: &mut [u8]) {
    let mut ctr: u32 = 1;
    for (chunk, dst) in input.chunks(16).zip(out.chunks_mut(16)) {
        let ks = keystream(key, nonce13, ctr);
        ctr = ctr.wrapping_add(1);
        for (i, b) in chunk.iter().enumerate() {
            dst[i] = b ^ ks[i];
        }
    }
}

fn keystream(key: &[u8; 16], nonce13: &[u8; 13], ctr: u32) -> [u8; 16] {
    let mut blk = [0u8; 16];
    blk[0] = 0x01;
    blk[1..14].copy_from_slice(nonce13);
    blk[14..16].copy_from_slice(&(ctr as u16).to_be_bytes());
    encrypt_block_aes128(key, &blk)
}

/// Verify one GP trailing integrity word: B0 (flags for a 4-octet
/// word with associated data, the GP nonce, message length), then the
/// length-prefixed associated data plus the `extra` prefix of the
/// message section, then the message itself, each padded separately
/// to the block edge. `extra` is the cleartext command section for
/// the counter-plus-MIC level (already part of the associated data
/// there) and empty for the encrypted level (its section arrives as
/// the message).
fn gp_verify(
    key: &[u8; 16],
    nonce13: &[u8; 13],
    aad: &[u8],
    extra: &[u8],
    msg: &[u8],
    tag: &[u8],
) -> bool {
    if tag.len() != 4 {
        return false;
    }
    let mut b0 = [0u8; 16];
    b0[0] = 0x40 | 0x08 | 0x01;
    b0[1..14].copy_from_slice(nonce13);
    b0[14..16].copy_from_slice(&(msg.len() as u16).to_be_bytes());
    let mut mac = CbcMac::new(key, &b0);
    // Associated-data section: 2-octet length over the GP header
    // plus the cleartext command prefix (counter-plus-MIC level),
    // padded to the block edge.
    let aad_len = aad.len().checked_add(extra.len());
    let Some(aad_len) = aad_len else {
        return false;
    };
    if aad_len > 0 {
        mac.push(key, &(aad_len as u16).to_be_bytes());
        mac.push(key, aad);
        mac.push(key, extra);
        mac.pad(key);
    }
    mac.push(key, msg);
    mac.pad(key);
    let x = mac.finish();
    let s0 = keystream(key, nonce13, 0);
    let mut diff = 0u8;
    for i in 0..4 {
        diff |= x[i] ^ s0[i] ^ tag[i];
    }
    diff == 0
}

/// Streaming CBC-MAC over block-cipher calls: `push` buffers a
/// trailing partial block, `pad` zero-fills and absorbs it, so
/// separately-padded sections stay separate.
struct CbcMac {
    x: [u8; 16],
    buf: [u8; 16],
    used: usize,
}

impl CbcMac {
    fn new(key: &[u8; 16], b0: &[u8; 16]) -> Self {
        Self {
            x: encrypt_block_aes128(key, b0),
            buf: [0u8; 16],
            used: 0,
        }
    }

    fn push(&mut self, key: &[u8; 16], bytes: &[u8]) {
        for &b in bytes {
            self.buf[self.used] = b;
            self.used += 1;
            if self.used == 16 {
                absorb(key, &mut self.x, &self.buf);
                self.used = 0;
            }
        }
    }

    fn pad(&mut self, key: &[u8; 16]) {
        if self.used > 0 {
            for b in self.buf.iter_mut().skip(self.used) {
                *b = 0;
            }
            absorb(key, &mut self.x, &self.buf);
            self.used = 0;
        }
    }

    fn finish(self) -> [u8; 16] {
        debug_assert_eq!(self.used, 0);
        self.x
    }
}

fn absorb(key: &[u8; 16], x: &mut [u8; 16], blk: &[u8; 16]) {
    let mut mix = [0u8; 16];
    for i in 0..16 {
        mix[i] = x[i] ^ blk[i];
    }
    *x = encrypt_block_aes128(key, &mix);
}

/// Where the network layer must route an accepted command.
///
/// Requirement `RD-GP-04`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NwkRoute {
    /// Re-emit the GPD command to the paired group address.
    Groupcast(u16),
    /// Deliver the translated command to the paired local endpoints.
    PairedEndpoints,
}

/// Route-to-NWK handoff record: everything the network layer needs
/// to carry one accepted sink command onward.
///
/// Requirement `RD-GP-04`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NwkHandoff {
    /// Canonical GPD key.
    pub gpd: u64,
    /// Endpoint scope (`0x00` for SrcId identities, the GPD endpoint
    /// for IEEE identities).
    pub endpoint: u8,
    /// Target profile identifier.
    pub profile: u16,
    /// Target cluster identifier (`0xFFFF` = the triggering cluster,
    /// per the translation convention).
    pub cluster: u16,
    /// Target command identifier (the GPD command for groupcast).
    pub command: u8,
    /// Payload bytes (template, copied trigger payload, or the raw
    /// GPD command payload for groupcast).
    pub payload: [u8; MAX_TRANSLATION_PAYLOAD],
    /// Valid payload bytes.
    pub payload_len: u8,
    /// Where the record routes.
    pub route: NwkRoute,
}

impl NwkHandoff {
    /// Payload slice.
    #[must_use]
    pub const fn payload_bytes(&self) -> &[u8] {
        self.payload.split_at(self.payload_len as usize).0
    }
}

/// Sink intake decision for one GPDF.
///
/// Requirement `RD-GP-02`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkDecision {
    /// Frame dropped with the recorded reason.
    Drop(GpError),
    /// Secured commissioning-range frame from an unpaired GPD while
    /// the commissioning mode is open: the caller drives the
    /// commissioning session from here.
    AdmitCommissioning {
        /// Canonical GPD key.
        gpd: u64,
        /// Endpoint scope.
        endpoint: u8,
        /// Commissioning-range command identifier.
        command: u8,
    },
    /// Accepted command with its route-to-NWK record.
    Handoff(NwkHandoff),
    /// The GPD's Success frame completed a parked bidirectional
    /// session: the sink-table entry and the default translation
    /// installed, the GPD is paired.
    Commissioned {
        /// Canonical GPD key.
        gpd: u64,
        /// Endpoint scope.
        endpoint: u8,
    },
}

/// Sink admission set for the commissioning mode: the GPD
/// commissioning announcement plus the reply-path command range. The
/// announcement (`0xE0`) sits below the level-gated range the ingress
/// filter enforces, so the intake names it here explicitly.
///
/// Requirement `RD-GP-03`.
const fn admits_for_commissioning(command: u8) -> bool {
    command == CMD_COMMISSIONING || is_commissioning_command(command)
}

/// Sink endpoint scope for one identity: SrcId identities are
/// endpoint-agnostic (`0x00`, matching the proxy notification
/// convention); IEEE identities carry their GPD endpoint.
const fn endpoint_of(id: GpdId) -> u8 {
    match id {
        GpdId::SrcId(_) => 0x00,
        GpdId::Ieee { endpoint, .. } => endpoint,
    }
}

/// Accept one GPDF through the full sink intake: decode, ingress
/// filter, secured open, counter-window dedup, Success completion,
/// sink-table admission (SrcId/IEEE pairing plus
/// commissioning-mode handling), then translation or group fan-out
/// mapped to a route-to-NWK handoff record.
///
/// The caller supplies the slotted keys, the commissioning-mode flag,
/// the parked commissioning session, the sink and translation tables,
/// the per-GPD replay window, and a scratch buffer for the verified
/// command section. Every fallible path returns a [`SinkDecision`];
/// nothing allocates.
///
/// Ordering mirrors [`BasicProxy::process`](crate::proxy::BasicProxy):
/// the ingress filter runs before any table lookup, so
/// commissioning-range frames under no security drop even while the
/// mode is open, and proxy-originated frames never enter the sink.
///
/// Caller-clock contract: this intake takes no timestamp, so the
/// caller ticks the parked session against its own clock before
/// calling — otherwise a Success arriving past the reply window
/// would still complete instead of timing out.
///
/// Requirements `RD-GP-02`, `RD-GP-03`, `RD-GP-05`
/// (`14-0563-19-A36-05` dedup, `-A36-06` sink admission,
/// `-A36-07` translation, `-A152-03` level gating).
#[allow(clippy::too_many_arguments)]
pub fn receive<const ST: usize, const TT: usize, const RN: usize>(
    gpdf_bytes: &[u8],
    keys: &GpKeySlots,
    commissioning_open: bool,
    session: &mut CommissioningSession,
    sink_table: &mut SinkTable<ST>,
    translations: &mut TranslationTable<TT>,
    replay: &mut GpReplay<RN>,
    opened: &mut [u8; MAX_GP_OPEN],
) -> SinkDecision {
    let (frame, _) = match Gpdf::decode(gpdf_bytes) {
        Ok(f) => f,
        Err(e) => return SinkDecision::Drop(e),
    };
    if let Err(e) = frame.ingress_check() {
        return SinkDecision::Drop(e);
    }
    if matches!(frame.body, GpdfBody::LpedOpaque(_)) {
        return SinkDecision::Drop(GpError::ForeignAppId(AppId::Lped.bits()));
    }
    let id = match frame.id {
        Some(id) => id,
        None => return SinkDecision::Drop(GpError::NoTableEntry),
    };
    // Resolve the command section: protected frames open against
    // the slotted keys, unprotected frames carry it in the clear.
    // The verified section borrows the caller scratch buffer for
    // protected frames, the input for unprotected ones.
    let opened_section: &[u8];
    let (command, payload): (u8, &[u8]) = if frame.ext.is_some_and(|e| e.level.protected()) {
        let n = match open_secured(keys, gpdf_bytes, opened) {
            Ok(n) => n,
            Err(e) => return SinkDecision::Drop(e),
        };
        opened_section = &opened[..n];
        (opened_section[0], &opened_section[1..])
    } else {
        match frame.body {
            GpdfBody::Gp { command, payload } => (command, payload),
            GpdfBody::LpedOpaque(_) => {
                return SinkDecision::Drop(GpError::ForeignAppId(AppId::Lped.bits()));
            }
        }
    };
    // Counter-window dedup: the counter must strictly advance per
    // GPD; replays drop before any table or session work.
    let counter = frame.frame_counter;
    if let Some(c) = counter {
        if replay.check(id.table_key(), c).is_err() {
            return SinkDecision::Drop(GpError::SecurityFailed);
        }
    }
    let endpoint = endpoint_of(id);
    // Success completion: a parked bidirectional session consumes
    // the matching Success frame, installs the pairing (sink-table
    // entry plus the default translation), and commissions.
    if command == CMD_SUCCESS && session.state() == CommissioningState::AwaitingReply {
        let seed = match session.note_success(id.table_key(), endpoint) {
            Ok(seed) => seed,
            Err(e) => return SinkDecision::Drop(e),
        };
        let app = match id {
            GpdId::SrcId(_) => AppId::SrcId,
            GpdId::Ieee { .. } => AppId::Ieee,
        };
        let mut entry = SinkTableEntry::new(app, id.table_key());
        entry.endpoint = endpoint;
        if let Some(ext) = frame.ext {
            entry.level = ext.level;
            entry.key_bit = ext.key_bit;
        }
        if let Some(c) = counter {
            entry.counter = c;
        }
        if sink_table.upsert(entry).is_err() {
            return SinkDecision::Drop(GpError::TableFull);
        }
        if let Some(seed) = seed {
            if translations.upsert(seed.materialize()).is_err() {
                return SinkDecision::Drop(GpError::TableFull);
            }
        }
        return SinkDecision::Commissioned {
            gpd: id.table_key(),
            endpoint,
        };
    }
    // Sink-table admission with SrcId/IEEE pairing.
    let entry = match sink_table.find_mut(id) {
        Some(e) => e,
        None => {
            // Unpaired GPDs admit only the commissioning
            // announcement set while the commissioning mode is open;
            // the caller drives the session from the admission. The
            // reply-path range arrives secured (the ingress filter
            // refused it unprotected); the announcement itself is
            // the mode-gated trust decision.
            if commissioning_open && admits_for_commissioning(command) {
                return SinkDecision::AdmitCommissioning {
                    gpd: id.table_key(),
                    endpoint,
                    command,
                };
            }
            return SinkDecision::Drop(GpError::NoTableEntry);
        }
    };
    let wire = frame
        .ext
        .map_or((WireSecurityLevel::None, false), |e| (e.level, e.key_bit));
    if entry.level != wire.0 || entry.key_bit != wire.1 {
        return SinkDecision::Drop(GpError::SecurityFailed);
    }
    if let Some(c) = counter {
        entry.counter = c;
    }
    // Group-bound entries hand a groupcast route to NWK before any
    // translation work.
    if entry.group_forward && entry.group_count > 0 {
        let group = entry.groups[0];
        let take = payload.len().min(MAX_TRANSLATION_PAYLOAD);
        let mut handoff = NwkHandoff {
            gpd: id.table_key(),
            endpoint,
            profile: 0x0104,
            cluster: 0xFFFF,
            command,
            payload: [0u8; MAX_TRANSLATION_PAYLOAD],
            payload_len: take as u8,
            route: NwkRoute::Groupcast(group),
        };
        handoff.payload[..take].copy_from_slice(&payload[..take]);
        return SinkDecision::Handoff(handoff);
    }
    // Translation: 8-bit vector contact matching takes no contact
    // state from the GPDF envelope here, so the neutral contact
    // applies (contact-gated entries stay the app layer's opt-in).
    let Some(t) = translations.lookup(id, command, 0) else {
        return SinkDecision::Drop(GpError::NotFound);
    };
    let mut handoff = NwkHandoff {
        gpd: id.table_key(),
        endpoint,
        profile: t.profile,
        cluster: t.cluster,
        command: t.command,
        payload: [0u8; MAX_TRANSLATION_PAYLOAD],
        payload_len: 0,
        route: NwkRoute::PairedEndpoints,
    };
    match t.payload_mode {
        PayloadMode::None | PayloadMode::Parsed => {}
        PayloadMode::Fixed => {
            let n = t.payload_len as usize;
            handoff.payload[..n].copy_from_slice(&t.payload[..n]);
            handoff.payload_len = t.payload_len;
        }
        PayloadMode::VerbatimCopy => {
            let n = payload.len().min(MAX_TRANSLATION_PAYLOAD);
            handoff.payload[..n].copy_from_slice(&payload[..n]);
            handoff.payload_len = n as u8;
        }
    }
    SinkDecision::Handoff(handoff)
}
