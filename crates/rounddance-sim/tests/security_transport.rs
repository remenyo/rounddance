//! Secured APS payload transport: auxiliary-header framing, transmit
//! key selection, receive-side counter validation, and replay-attack
//! rejection across the scripted medium.
//!
//! Payload encryption itself stays a radio/HAL assist (wave-2b
//! contract); this layer owns key selection, nonces/counters, and the
//! auxiliary header, so the sim pins exactly that: what goes out must
//! validate on receipt, and captured bytes replayed by an attacker
//! must be rejected.
//!
//! Requirement traceability: `05-3474-23-446-01` (key rotation +
//! selection), `05-3474-23-4311-01` (outgoing counter), `05-3474-23-4312-01`
//! (replay guard), `05-3474-23-451-01` (aux codec), `05-3474-23-434-01`
//! (NVM checkpoint/resume).

use rounddance_mac_sap::{
    Channel, FramePayload, MacAddress, MacDataSap, MacMgmtSap, TxOptions, TxRequest, TxStatus,
};
use rounddance_nwk::{build_data_header, decode as nwk_decode, DiscoverRoute, NldeDataRequest};
use rounddance_security::{
    AuxHeader, FrameCounter, KeyIdMode, KeyIdentifier, KeySet, NetworkKey, NvmStore,
    PersistedState, RamStore, ReplayTable, SecError, SecurityControl, NETWORK_KEY_LEN,
};
use rounddance_sim::{ScriptAction, ScriptedRadio, Seed};

const PAN: u16 = 0x1a2b;
const NODE_A: u16 = 0x0001;
const NODE_B: u16 = 0x0002;
const IEEE_B: u64 = 0x0200_0000_0000_0002;

/// One secured application payload: auxiliary header octets followed
/// by the (sim-plaintext) payload. Key selection comes from `keys`,
/// the nonce from `tx_counter`.
fn secured_frame(
    keys: &KeySet,
    tx_counter: &mut FrameCounter,
    payload: &[u8],
) -> Result<Vec<u8>, SecError> {
    let header = AuxHeader {
        control: SecurityControl::new(5, KeyIdMode::Index, false).unwrap(),
        frame_counter: tx_counter.take()?,
        ext_source: None,
        key_id: KeyIdentifier::Index(keys.active().seq),
    };
    let hlen = header.header_len().ok_or(SecError::BadKeyIdMode)?;
    let mut out = vec![0u8; hlen + payload.len()];
    let n = header.encode_into(&mut out)?;
    out[n..].copy_from_slice(payload);
    Ok(out)
}

/// Receive-side validation: decode the header, resolve the key, and
/// enforce replay protection.
fn accept_frame(
    keys: &KeySet,
    rx: &mut ReplayTable<8>,
    src: u64,
    frame: &[u8],
) -> Result<Vec<u8>, SecError> {
    let (header, used) = AuxHeader::decode(frame)?;
    let seq = match header.key_id {
        KeyIdentifier::Index(s) => s,
        _ => return Err(SecError::BadKeyIdMode),
    };
    let _key = keys.select(seq).ok_or(SecError::NotFound)?;
    rx.check(src, header.frame_counter)?;
    Ok(frame[used..].to_vec())
}

fn encoded_npdu(dst: u16, secured: &[u8]) -> Vec<u8> {
    let req = NldeDataRequest {
        dst_addr: dst,
        use_alias: false,
        alias_src: 0,
        alias_seq: 0,
        radius_param: 3,
        discover_route: DiscoverRoute::Enable,
        generated_seq: 0x42,
        local_short_addr: NODE_A,
        max_depth: 5,
        associated: true,
    };
    let header = build_data_header(&req).unwrap();
    let mut out = vec![0u8; header.header_len() + secured.len()];
    let n = header.encode_into(secured, &mut out).unwrap();
    out.truncate(n);
    out
}

fn loopback_deliver(seed: u64, npdu: &[u8]) -> Vec<u8> {
    let mut radio = ScriptedRadio::new(
        Seed(seed),
        vec![ScriptAction::Delay {
            base_us: 320,
            jitter_us: 100,
        }],
    );
    radio.reset(true);
    radio.set_channel(Channel::new(15).unwrap()).unwrap();
    radio.set_pan_id(PAN);
    radio.set_short_addr(NODE_A);
    let req = TxRequest {
        dst: MacAddress::short(PAN, NODE_B),
        msdu: FramePayload::from_slice(npdu).expect("NPDU fits one MSDU"),
        options: TxOptions::ACK,
    };
    radio.data_request(req).expect("queue has room");
    radio.run_until_idle(16);
    let confirm = radio.poll_confirm().expect("script always confirms");
    assert_eq!(confirm.status, TxStatus::Delivered);
    radio
        .poll_indication()
        .expect("delivery implies indication")
        .msdu
        .as_slice()
        .to_vec()
}

// 05-3474-23-446-01 + 05-3474-23-4311-01 + 05-3474-23-4312-01 + 05-3474-23-451-01: secured frame end to end — A secures with
// the active key and a fresh counter, B validates key + counter and
// recovers the payload; the medium preserves every octet.
#[test]
fn secured_frame_end_to_end_two_node() {
    let keys = KeySet::new(NetworkKey::new([0x77; NETWORK_KEY_LEN], 1));
    let mut tx = FrameCounter::new(0, 4);
    let mut rx = ReplayTable::<8>::new();

    let secured = secured_frame(&keys, &mut tx, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
    let received = loopback_deliver(0x5EC0, &encoded_npdu(NODE_B, &secured));
    assert_eq!(received, encoded_npdu(NODE_B, &secured));

    let npdu = nwk_decode(&received).unwrap();
    assert_eq!(npdu.header.dst_addr, NODE_B);
    let payload = accept_frame(&keys, &mut rx, IEEE_B, npdu.payload).unwrap();
    assert_eq!(payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

// 05-3474-23-4312-01: replay attack — captured bytes replayed by an
// attacker are rejected; a forged lower counter is rejected; the next
// fresh counter still advances.
#[test]
fn replay_attack_rejected_fresh_advances() {
    let keys = KeySet::new(NetworkKey::new([0x77; NETWORK_KEY_LEN], 1));
    let mut tx = FrameCounter::new(41, 4);
    let mut rx = ReplayTable::<8>::new();

    let first = secured_frame(&keys, &mut tx, b"cmd-on").unwrap();
    let captured = loopback_deliver(0xBEEF, &encoded_npdu(NODE_B, &first));
    let npdu = nwk_decode(&captured).unwrap();
    accept_frame(&keys, &mut rx, IEEE_B, npdu.payload).unwrap();

    // Attacker replays the exact captured NPDU payload.
    let replay = nwk_decode(&captured).unwrap();
    assert_eq!(
        accept_frame(&keys, &mut rx, IEEE_B, replay.payload),
        Err(SecError::Replay)
    );
    // Forged lower counter with the same key also fails.
    let mut forged = first.clone();
    forged[1..5].copy_from_slice(&7u32.to_le_bytes());
    assert_eq!(
        accept_frame(&keys, &mut rx, IEEE_B, &forged),
        Err(SecError::Replay)
    );
    // The legitimate next frame still advances.
    let second = secured_frame(&keys, &mut tx, b"cmd-off").unwrap();
    let payload = accept_frame(&keys, &mut rx, IEEE_B, &second).unwrap();
    assert_eq!(payload, b"cmd-off");
}

// 05-3474-23-446-01 + 05-3474-23-434-01: rotation across the medium — frames secured
// under the old sequence keep validating while staged, then the new
// sequence takes over after activation; NVM checkpoint/resume keeps
// counters monotonic across the rotation.
#[test]
fn key_rotation_and_counter_persist_across_reboot() {
    let mut keys = KeySet::new(NetworkKey::new([0x11; NETWORK_KEY_LEN], 1));
    let mut store = RamStore::new();
    let mut tx = FrameCounter::new(900, 4);
    let mut rx = ReplayTable::<8>::new();

    keys.install_pending(NetworkKey::new([0x22; NETWORK_KEY_LEN], 2))
        .unwrap();
    // Old-sequence frame in flight validates while the new key stages.
    let in_flight = secured_frame(&keys, &mut tx, b"old").unwrap();
    let payload = accept_frame(&keys, &mut rx, IEEE_B, &in_flight).unwrap();
    assert_eq!(payload, b"old");

    keys.activate_pending().unwrap();
    let rotated = secured_frame(&keys, &mut tx, b"new").unwrap();
    assert_eq!(rotated[5], 2, "new sequence rides the wire");
    let payload = accept_frame(&keys, &mut rx, IEEE_B, &rotated).unwrap();
    assert_eq!(payload, b"new");
    // Old sequence no longer resolves after activation (key lookup
    // runs before the replay check, so this is NotFound, not Replay).
    assert_eq!(
        accept_frame(&keys, &mut rx, IEEE_B, &in_flight),
        Err(SecError::NotFound)
    );

    // Checkpoint + simulated reboot: resume skips the rollback stride.
    store.save_outgoing(tx.peek()).unwrap();
    let saved: PersistedState = store.load().unwrap();
    let mut tx2 = FrameCounter::new(0, 4);
    tx2.resume(saved.resume_next());
    assert!(tx2.peek() > tx.peek());
    let after = secured_frame(&keys, &mut tx2, b"post-reboot").unwrap();
    let payload = accept_frame(&keys, &mut rx, IEEE_B, &after).unwrap();
    assert_eq!(payload, b"post-reboot");
}
