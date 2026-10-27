//! Bounded fuzz: auxiliary-header codec round-trip, counter
//! monotonicity under random walks, and malformed-input rejection.
//! No panics on any input; no allocation beyond fixed test buffers.

use rounddance_security::*;

/// Deterministic xorshift64 (no allocation, no external RNG).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn bytes(&mut self, out: &mut [u8]) {
        let mut i = 0;
        while i < out.len() {
            let v = self.next().to_le_bytes();
            let take = (out.len() - i).min(8);
            out[i..i + take].copy_from_slice(&v[..take]);
            i += take;
        }
    }
}

fn random_header(rng: &mut Rng) -> AuxHeader {
    let mode = match rng.next() % 4 {
        0 => KeyIdMode::DataKey,
        1 => KeyIdMode::Index,
        2 => KeyIdMode::Source4,
        _ => KeyIdMode::Source8,
    };
    let extended = rng.next().is_multiple_of(2);
    let mut ctr = [0u8; 4];
    rng.bytes(&mut ctr);
    let mut s8 = [0u8; 8];
    rng.bytes(&mut s8);
    let mut s4 = [0u8; 4];
    rng.bytes(&mut s4);
    let mut idx = [0u8; 1];
    rng.bytes(&mut idx);
    AuxHeader {
        control: SecurityControl::new((rng.next() % 8) as u8, mode, extended).unwrap(),
        frame_counter: u32::from_le_bytes(ctr),
        ext_source: extended.then_some(s8),
        key_id: match mode {
            KeyIdMode::DataKey => KeyIdentifier::Seq(idx[0]),
            KeyIdMode::Index => KeyIdentifier::Index(idx[0]),
            KeyIdMode::Source4 => KeyIdentifier::Source4(s4, idx[0]),
            KeyIdMode::Source8 => KeyIdentifier::Source8(s8, idx[0]),
        },
    }
}

// 05-3474-23-451-01: 8k random headers round-trip exactly.
#[test]
fn fuzz_aux_header_roundtrip() {
    let mut rng = Rng(0x5EED_0001);
    for _ in 0..8000 {
        let header = random_header(&mut rng);
        let mut out = [0u8; MAX_AUX_LEN];
        let n = header.encode_into(&mut out).expect("random header encodes");
        let (back, used) = AuxHeader::decode(&out[..n]).expect("random header decodes");
        assert_eq!(back, header);
        assert_eq!(used, n);
    }
}

// 05-3474-23-451-01: arbitrary octets never panic the decoder; every
// accepted short input still re-encodes to the same length.
#[test]
fn fuzz_malformed_never_panics() {
    let mut rng = Rng(0xDEAD_0002);
    let mut buf = [0u8; 32];
    for _ in 0..8000 {
        rng.bytes(&mut buf);
        let len = (rng.next() % 33) as usize;
        if let Ok((header, used)) = AuxHeader::decode(&buf[..len]) {
            let mut out = [0u8; MAX_AUX_LEN];
            if let Ok(n) = header.encode_into(&mut out) {
                assert_eq!(n, used);
            }
        }
    }
}

// 05-3474-23-4311-01 + 05-3474-23-4312-01: random counter walks stay strictly increasing
// per source; replays of any earlier value always fail.
#[test]
fn fuzz_counter_monotonicity() {
    let mut rng = Rng(0xC0FF_EE03);
    let mut tx = FrameCounter::new(0, 16);
    let mut rx = ReplayTable::<8>::new();
    let mut seen: [(u64, u32); 8] = [(0, 0); 8];
    let mut seen_len = 0usize;
    for _ in 0..8000 {
        let addr = rng.next() % 8;
        // Fresh transmit value.
        let c = tx.take().expect("far from exhaustion in 8k takes");
        // Interleave occasional replays of recorded values.
        if seen_len > 0 && rng.next().is_multiple_of(5) {
            let (a, v) = seen[(rng.next() as usize) % seen_len];
            assert_eq!(rx.check(a, v), Err(SecError::Replay));
        }
        rx.check(addr, c).expect("fresh counter advances");
        if seen_len < seen.len() {
            seen[seen_len] = (addr, c);
            seen_len += 1;
        }
    }
    // Watermark tripped long ago; checkpoint accepts current peek.
    assert!(tx.needs_persist());
    tx.mark_persisted(tx.peek()).unwrap();
    assert!(!tx.needs_persist());
}
