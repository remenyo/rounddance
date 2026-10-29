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
