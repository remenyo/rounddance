//! NWK decryptor: lab-key-gated integrity-checked open of secured
//! NWK payloads.
//!
//! The session [`KeySlots`](crate::keys::KeySlots) record which lab
//! keys the operator loaded; this module turns a slotted key into a
//! verified plaintext. It never decrypts without a slotted key, it
//! resolves the key strictly by the auxiliary header's key sequence
//! number, and every open is integrity-checked (wrong key, wrong
//! counter, or any mutated octet fails the check and yields `None`).
//!
//! Construction (offline-analysis shape of the on-air protection):
//! the secured NWK frame arrives with the auxiliary level bits
//! zeroed, so the receiver restores the network-base level before
//! any nonce or integrity work; the nonce binds the extended source,
//! the frame counter, and the restored control octet; the associated
//! data covers the NWK header plus the restored auxiliary header;
//! the trailing integrity word is 4 octets. The block cipher comes
//! from [`rounddance_security`]; this module adds only the bounded,
//! allocation-free open around it. Payload protection itself stays a
//! radio assist in production — this path exists so captured frames
//! can be analyzed offline against lab keys.

use crate::keys::KeySlots;
use rounddance_security::classical::{AuxHeader, KeyIdentifier, NwkNonce};
use rounddance_security::encrypt_block_aes128;

/// Network-base protection level restored into the zeroed on-air aux
/// control octet before nonce / integrity work (protected payload +
/// 32-bit integrity word).
pub const NWK_BASE_LEVEL: u8 = 5;

/// Integrity-word length in octets for [`NWK_BASE_LEVEL`].
pub const MIC_LEN: usize = 4;

/// Largest NWK payload (aux header + ciphertext) this decryptor
/// opens: an 802.15.4 frame never exceeds 127 octets, so a secured
/// NWK payload always fits with margin.
pub const MAX_SECURED_PAYLOAD: usize = 127;

/// Open one secured NWK payload against the loaded lab keys.
///
/// `nwk_header` is the raw NWK header octets (associated data),
/// `nwk_payload` starts at the auxiliary header, and the verified
/// plaintext is written to `out`. Returns the plaintext length on a
/// verified open, `None` whenever no slotted key matches or the
/// integrity check fails. A `None` leaves no usable output: the
/// caller must ignore `out` (it may hold unverified candidate
/// bytes).
pub fn open_nwk(
    keys: &KeySlots,
    nwk_header: &[u8],
    nwk_payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    if !keys.has_key() {
        return None;
    }
    let (aux, aux_len) = AuxHeader::decode_with_level(nwk_payload, NWK_BASE_LEVEL).ok()?;
    // NWK names a network key: exactly one trailing sequence octet.
    // Any other key-identifier shape is refused, never tried.
    let seq = match aux.key_id {
        KeyIdentifier::Index(s) => s,
        _ => return None,
    };
    let key = keys.key_by_seq(seq)?;
    let nonce = NwkNonce::from_header(&aux).ok()?;
    let aux_bytes = nwk_payload.get(..aux_len)?;
    let ct = nwk_payload.get(aux_len..)?;
    if ct.len() < MIC_LEN {
        return None;
    }
    let pt_len = ct.len() - MIC_LEN;
    if out.len() < pt_len {
        return None;
    }
    // Associated data: NWK header plus the auxiliary header with the
    // restored control octet written back over the zeroed on-air one.
    let restored = aux.control.as_octet();
    let (ct_body, _tag) = ct.split_at(pt_len);
    ctr_crypt(&key, &nonce.bytes, ct_body, &mut out[..pt_len]);
    let ok = verify(
        &key,
        &nonce.bytes,
        nwk_header,
        aux_bytes,
        restored,
        &out[..pt_len],
        &ct[pt_len..],
    );
    if ok {
        Some(pt_len)
    } else {
        None
    }
}

/// Counter-mode crypt (decrypt == encrypt): keystream block `i`
/// covers payload octets `16*(i-1)..`, starting at counter 1.
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

/// Verify the trailing integrity word over the candidate plaintext:
/// B0 (flags for a 4-octet word with associated data, nonce,
/// message length), then the length-prefixed associated data and the
/// plaintext, each padded separately to the block edge.
#[allow(clippy::too_many_arguments)]
fn verify(
    key: &[u8; 16],
    nonce13: &[u8; 13],
    nwk_header: &[u8],
    aux_bytes: &[u8],
    restored_control: u8,
    pt: &[u8],
    tag: &[u8],
) -> bool {
    if tag.len() != MIC_LEN {
        return false;
    }
    let mut b0 = [0u8; 16];
    b0[0] = 0x40 | 0x08 | 0x01;
    b0[1..14].copy_from_slice(nonce13);
    b0[14..16].copy_from_slice(&(pt.len() as u16).to_be_bytes());
    let mut mac = CbcMac::new(key, &b0);
    // Associated-data section: 2-octet length over the header plus
    // the restored auxiliary header, padded to the block edge.
    let aad_len = nwk_header.len().checked_add(aux_bytes.len());
    let Some(aad_len) = aad_len else {
        return false;
    };
    if aad_len > 0 {
        mac.push(key, &(aad_len as u16).to_be_bytes());
        mac.push(key, nwk_header);
        // First aux octet on air carries the zeroed level; the
        // integrity computation ran over the restored octet.
        if let Some((_on_air, rest)) = aux_bytes.split_first() {
            mac.push(key, &[restored_control]);
            mac.push(key, rest);
        }
        mac.pad(key);
    }
    mac.push(key, pt);
    mac.pad(key);
    let x = mac.finish();
    let s0 = keystream(key, nonce13, 0);
    for i in 0..MIC_LEN {
        if x[i] ^ s0[i] != tag[i] {
            return false;
        }
    }
    true
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

/// Largest verified GP command section (identifier + payload) the
/// opener writes: one command octet plus the codec payload budget.
pub const MAX_GP_OPEN: usize = rounddance_gp::frame::MAX_GPD_PAYLOAD + 1;

/// Open one counter-protected GPDF against the loaded lab GP keys.
///
/// The GPDF carries its own header in the clear (frame control,
/// extended control, GPD identity, frame counter); only the command
/// section is integrity-checked (counter-plus-MIC level) or
/// decrypted-then-checked (encrypted level), following the same
/// CCM* wire shape as [`open_nwk`] with the GP nonce and the GP
/// header as associated data. The key resolves strictly by the
/// wire key-bit — no slotted key for that class means no open, and
/// every integrity failure yields `None`. A `None` leaves no usable
/// output: the caller must ignore `out`. Proxy-originated frames
/// take the outgoing nonce shape the captures never show and are
/// refused here; LPED and maintenance frames carry no GP security
/// envelope and are refused alike.
///
/// Returns the verified command-section length (command identifier
/// first) on a verified open.
pub fn open_gp(keys: &KeySlots, gpdf_bytes: &[u8], out: &mut [u8]) -> Option<usize> {
    use rounddance_gp::frame::{AppId, Gpdf, GpdfBody, WireSecurityLevel};
    use rounddance_gp::security::GpNonce;
    let (gpdf, _) = Gpdf::decode(gpdf_bytes).ok()?;
    let ext = gpdf.ext?;
    if matches!(ext.app_id, AppId::Lped) {
        return None;
    }
    if ext.direction_proxy {
        return None;
    }
    let protected = match ext.level {
        WireSecurityLevel::None => return None,
        WireSecurityLevel::MicOnly => false,
        WireSecurityLevel::Encrypted => true,
    };
    let counter = gpdf.frame_counter?;
    let key = keys.gp_key_by_bit(ext.key_bit)?;
    // Nonce address half: the repeated source identifier, or the
    // GPD IEEE address — always the incoming shape here.
    let addr = match gpdf.id? {
        rounddance_gp::frame::GpdId::SrcId(id) => GpNonce::incoming_srcid_addr(id),
        rounddance_gp::frame::GpdId::Ieee { addr, .. } => GpNonce::ieee_addr(addr),
    };
    let nonce = GpNonce::build(addr, counter, false);
    // Associated-data header: frame control, extended control, the
    // identity word the protection covers (source identifier, or
    // the endpoint octet for IEEE identities), then the counter.
    // The wire header length differs from the associated-data
    // length for IEEE identities (the address travels on air but
    // only the endpoint enters the integrity computation).
    let mut aad = [0u8; 10];
    let mut aad_len = 2;
    aad[0] = gpdf.fc.encode();
    aad[1] = ext.encode();
    let hdr_len = match gpdf.id {
        Some(rounddance_gp::frame::GpdId::SrcId(id)) => {
            aad[aad_len..aad_len + 4].copy_from_slice(&id.to_le_bytes());
            aad_len += 4;
            2 + 4 + 4
        }
        Some(rounddance_gp::frame::GpdId::Ieee { endpoint, .. }) => {
            aad[aad_len] = endpoint;
            aad_len += 1;
            2 + 9 + 4
        }
        None => return None,
    };
    aad[aad_len..aad_len + 4].copy_from_slice(&counter.to_le_bytes());
    aad_len += 4;
    let aad = &aad[..aad_len];
    // Command section: cleartext under the counter-plus-MIC level,
    // ciphertext under the encrypted level.
    if !matches!(gpdf.body, GpdfBody::Gp { .. }) {
        return None;
    }
    let section_len = gpdf_bytes.len().checked_sub(hdr_len + 4)?;
    let section = gpdf_bytes.get(hdr_len..gpdf_bytes.len() - 4)?;
    if section.is_empty() || out.len() < section_len {
        return None;
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
            Some(section_len)
        } else {
            None
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
            Some(section_len)
        } else {
            None
        }
    }
}

/// Verify one GP trailing integrity word: B0 (flags for a 4-octet
/// word with associated data, the GP nonce, message length), then
/// the length-prefixed associated data plus the `extra` prefix of
/// the message section, then the message itself, each padded
/// separately to the block edge. `extra` is the cleartext command
/// section for the counter-plus-MIC level (already part of the
/// associated data there) and empty for the encrypted level (its
/// section arrives as the message).
fn gp_verify(
    key: &[u8; 16],
    nonce13: &[u8; 13],
    aad: &[u8],
    extra: &[u8],
    msg: &[u8],
    tag: &[u8],
) -> bool {
    if tag.len() != MIC_LEN {
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
    for i in 0..MIC_LEN {
        if x[i] ^ s0[i] != tag[i] {
            return false;
        }
    }
    true
}
