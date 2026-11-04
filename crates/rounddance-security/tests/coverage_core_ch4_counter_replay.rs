//! Chapter 4 outgoing/incoming counter, replay-guard, NVM-persistence,
//! two-key rotation, and per-peer link-key counter coverage.
//!
//! Paraphrase-level pins of doc `05-3474-23` R23.2 chapter 4. All
//! wording here is paraphrase (D1); anchors below are document,
//! revision, clause-line numbers only.
//!
//! Gap ranges closed here (from `/tmp/opencode/coverage-B.json`):
//! outgoing steps and counter/key failure
//! (`p0421-L10103-L10105`, `p0421-L10107-L10108`,
//! `p0421-L10110-L10118`, `p0421-L10125-L10141`,
//! `p0421-L10143-L10144`); incoming steps, key lookup, and replay
//! rejection (`p0422-L10145-L10147`, `p0422-L10149-L10151`,
//! `p0422-L10153`, `p0422-L10155`, `p0422-L10165`,
//! `p0422-L10167-L10189`); incoming store, memory bound, and newer-key
//! activation (`p0423-L10202-L10209`, `p0423-L10212-L10215`);
//! counter persistence across resets
//! (`p0425-L10230-L10231`, `p0425-L10237-L10244`); counter-usage
//! guidance and two-key storage (`p0426-L10245-L10265`); switch-key
//! goal (`p0446-L10760-L10761`); AIB key-table persistence legs
//! (`p0478-L11416-L11427`); two-key rotation procedure
//! (`p0494-L11867-L11890`, `p0494-L11892-L11899`).
//!
//! Machine tags (preferred cites; see `tools/coverage/README.md`):
//! @covers lines below name the implemented ranges, @verifies links
//! each requirement to its pinning test here.
//!
//! Note: the incoming rule that rejects a received counter already at
//! the top of the range is a caller-side pipeline check owned by the
//! NWK incoming path; [`ReplayTable`] accepts any strictly advancing
//! value (see the `@deferred` tag below and the annex).

// @covers doc=05-3474-23 rev=R23.2 clause=4.3 lines=p0421-L10103-L10105,p0421-L10107-L10108 req=05-3474-23-4311-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.3 lines=p0421-L10110-L10118,p0421-L10125-L10141,p0421-L10143-L10144 req=05-3474-23-4311-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.3 lines=p0422-L10145-L10147,p0422-L10149-L10151,p0422-L10153 req=05-3474-23-4311-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.3 lines=p0422-L10155,p0422-L10165,p0422-L10167-L10189 req=05-3474-23-4312-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.3 lines=p0423-L10202-L10209,p0423-L10212-L10215 req=05-3474-23-4312-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.3 lines=p0425-L10230-L10231,p0425-L10237-L10244 req=05-3474-23-434-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.3 lines=p0426-L10245-L10265 req=05-3474-23-434-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.4 lines=p0446-L10760-L10761 req=05-3474-23-446-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.4 lines=p0478-L11416-L11427 req=05-3474-23-462-01
// @covers doc=05-3474-23 rev=R23.2 clause=4.6 lines=p0494-L11867-L11890,p0494-L11892-L11899 req=05-3474-23-446-01
// @na doc=05-3474-23 lines=p0424-L10222-L10224,p0424-L10226-L10229 reason=nib-attributes-owned-by-nwk-crate
// @na doc=05-3474-23 lines=p0424-L2,p0425-L4,p0435-L16,p0466-L8,p0468-L8,p0469-L1,p0469-L4,p0470-L16,p0471-L8,p0476-L16,p0477-L16,p0479-L7,p0481-L1,p0504-L128 reason=table-figure-fragment-no-standalone-normative-behavior
// @deferred doc=05-3474-23 lines=p0422-L10162-L10163 reason=caller-side-max-reject-needs-classical-edit
// @deferred doc=05-3474-23 lines=p0510-L12336-L12337,p0510-L12339-L12347,p0510-L12349-L12363,p0511-L12366-L12374,p0511-L12376-L12378,p0511-L12380-L12397,p0511-L12399,p0511-L12401-L12404,p0512-L12405-L12414,p0512-L12416-L12442 reason=challenge-state-machine-needs-new-module-plus-hookup

use rounddance_security::{
    store::{NvmStore, PersistedState, RamStore, StoreError, COUNTER_STRIDE},
    FrameCounter, KeySet, LinkKeyEntry, LinkKeyTable, NetworkKey, ReplayTable, SecError,
    NETWORK_KEY_LEN,
};

// @verifies req=05-3474-23-4311-01 test=crates/rounddance-security/tests/coverage_core_ch4_counter_replay.rs::outgoing_counter_monotonic_then_exhausts
// Outgoing leg: the counter hands out successive values, never wraps,
// and reports exhaustion so the management layer rotates the key
// instead of reusing a counter value.
#[test]
fn outgoing_counter_monotonic_then_exhausts() {
    let mut tx = FrameCounter::new(41, 4);
    assert_eq!(tx.peek(), 41);
    assert_eq!(tx.take().unwrap(), 41);
    assert_eq!(tx.take().unwrap(), 42);
    assert_eq!(tx.peek(), 43);

    // Top-of-range edge: the last usable value is handed out once,
    // then the counter stops instead of wrapping.
    let mut edge = FrameCounter::new(u32::MAX - 1, 1);
    assert_eq!(edge.take().unwrap(), u32::MAX - 1);
    assert_eq!(edge.take(), Err(SecError::CounterExhausted));
    assert_eq!(edge.take(), Err(SecError::CounterExhausted));
    assert_eq!(edge.peek(), u32::MAX);
}

// @verifies req=05-3474-23-4311-01 test=crates/rounddance-security/tests/coverage_core_ch4_counter_replay.rs::outgoing_watermark_and_resume_never_repeat
// Outgoing leg: the persistence watermark fires only after enough new
// values, checkpoints only move forward, and resume never replays a
// value handed out before a reboot.
#[test]
fn outgoing_watermark_and_resume_never_repeat() {
    let mut tx = FrameCounter::new(0, 4);
    assert!(!tx.needs_persist());
    tx.take().unwrap();
    tx.take().unwrap();
    assert!(!tx.needs_persist());
    tx.take().unwrap();
    tx.take().unwrap();
    assert!(tx.needs_persist());

    // Checkpointing the current mark clears the watermark; a mark from
    // the future is a caller bug and is refused.
    tx.mark_persisted(4).unwrap();
    assert!(!tx.needs_persist());
    assert_eq!(tx.mark_persisted(99), Err(SecError::BadPersisted));

    // Resume applies the rollback stride on top of the persisted mark.
    let mut rebooted = FrameCounter::new(0, 4);
    rebooted.resume(PersistedState { outgoing_next: 100 }.resume_next());
    assert_eq!(rebooted.peek(), 100 + COUNTER_STRIDE);
    assert_eq!(rebooted.take().unwrap(), 100 + COUNTER_STRIDE);
}

// @verifies req=05-3474-23-434-01 test=crates/rounddance-security/tests/coverage_core_ch4_counter_replay.rs::nvm_store_monotonic_blank_and_faults
// NVM leg: the RAM backend keeps the same monotonic API used by the
// persistence hook; a blank image reads as factory state, backwards
// saves are rejected, and injected write faults surface as I/O errors.
#[test]
fn nvm_store_monotonic_blank_and_faults() {
    let mut store = RamStore::new();
    assert_eq!(store.load().unwrap(), PersistedState::blank());
    assert_eq!(store.writes(), 0);

    store.save_outgoing(1024).unwrap();
    assert_eq!(store.load().unwrap().outgoing_next, 1024);
    assert_eq!(store.writes(), 1);

    // Backwards save is rejected and the stored mark is unchanged.
    assert_eq!(store.save_outgoing(100), Err(StoreError::Corrupt));
    assert_eq!(store.load().unwrap().outgoing_next, 1024);

    // One-shot write fault surfaces without touching the mark.
    store.arm_failure();
    assert_eq!(store.save_outgoing(2048), Err(StoreError::Io));
    assert_eq!(store.writes(), 1);
    assert_eq!(store.load().unwrap().outgoing_next, 1024);
}

// @verifies req=05-3474-23-434-01 test=crates/rounddance-security/tests/coverage_core_ch4_counter_replay.rs::nvm_resume_stride_saturates_at_top
// NVM leg: resume adds the stride and saturates at the top of the
// range instead of wrapping.
#[test]
fn nvm_resume_stride_saturates_at_top() {
    let mid = PersistedState {
        outgoing_next: 2048,
    };
    assert_eq!(mid.resume_next(), 2048 + COUNTER_STRIDE);
    let top = PersistedState {
        outgoing_next: u32::MAX,
    };
    assert_eq!(top.resume_next(), u32::MAX);
}

// @verifies req=05-3474-23-4312-01 test=crates/rounddance-security/tests/coverage_core_ch4_counter_replay.rs::incoming_replay_accepts_first_advance_only
// Incoming leg: the first frame from a new source is accepted at any
// counter value (including zero); only a non-advancing counter from a
// known source is a replay or duplicate.
#[test]
fn incoming_replay_accepts_first_advance_only() {
    let mut rx = ReplayTable::<4>::new();
    assert!(rx.is_empty());
    assert_eq!(rx.len(), 0);

    rx.check(0x1111, 7).unwrap();
    assert_eq!(rx.last(0x1111), Some(7));
    assert_eq!(rx.check(0x1111, 7), Err(SecError::Replay));
    assert_eq!(rx.check(0x1111, 3), Err(SecError::Replay));
    rx.check(0x1111, 8).unwrap();

    // Other sources are tracked independently; counter zero from a new
    // source is a legitimate first frame, not a replay.
    rx.check(0x2222, 0).unwrap();
    assert_eq!(rx.last(0x2222), Some(0));
    assert_eq!(rx.check(0x2222, 0), Err(SecError::Replay));
    assert_eq!(rx.len(), 2);
}

// @verifies req=05-3474-23-4312-01 test=crates/rounddance-security/tests/coverage_core_ch4_counter_replay.rs::incoming_table_bounded_evicts_stalest
// Incoming leg: neighbor state is bounded; when full, the stalest
// (smallest-counter) entry is evicted, and a zero-size table rejects.
#[test]
fn incoming_table_bounded_evicts_stalest() {
    let mut t = ReplayTable::<2>::new();
    t.check(1, 10).unwrap();
    t.check(2, 20).unwrap();
    t.check(3, 30).unwrap();
    assert!(t.last(1).is_none());
    assert_eq!(t.last(2), Some(20));
    assert_eq!(t.last(3), Some(30));

    let mut zero = ReplayTable::<0>::new();
    assert_eq!(zero.check(9, 0), Err(SecError::TableFull));
}

// @verifies req=05-3474-23-4312-01 test=crates/rounddance-security/tests/coverage_core_ch4_counter_replay.rs::rejoin_forgets_source_to_restart_counter_space
// Incoming leg: forgetting a source restarts its counter space, which
// is what lets a (re)joining device with a legitimately reset counter
// be heard again after its key is refreshed.
#[test]
fn rejoin_forgets_source_to_restart_counter_space() {
    let mut rx = ReplayTable::<4>::new();
    rx.check(0x1111, 5).unwrap();
    assert_eq!(rx.check(0x1111, 5), Err(SecError::Replay));
    rx.remove(0x1111);
    assert_eq!(rx.last(0x1111), None);
    rx.check(0x1111, 0).unwrap();
    assert_eq!(rx.len(), 1);
    // Forgetting an unknown source is a silent no-op.
    rx.remove(0x9999);
    assert_eq!(rx.len(), 1);
}

// @verifies req=05-3474-23-446-01 test=crates/rounddance-security/tests/coverage_core_ch4_counter_replay.rs::switch_key_two_phase_rotation
// Switch-key / rotation leg: two-phase rotation keeps both keys
// resolvable while in flight, then flips traffic to the successor in
// one step; a duplicate install and a flip with nothing staged fail.
#[test]
fn switch_key_two_phase_rotation() {
    let mut set = KeySet::new(NetworkKey::new([0x10; NETWORK_KEY_LEN], 4));
    assert_eq!(set.active().seq, 4);
    assert!(set.pending().is_none());
    assert_eq!(set.activate_pending(), Err(SecError::NotFound));

    // Installing the identical key is refused.
    assert_eq!(
        set.install_pending(NetworkKey::new([0x10; NETWORK_KEY_LEN], 4)),
        Err(SecError::DuplicateKey)
    );
    set.install_pending(NetworkKey::new([0x20; NETWORK_KEY_LEN], 5))
        .unwrap();

    // Frames in flight on either key resolve during staging.
    assert_eq!(set.select(4).unwrap().key, [0x10; NETWORK_KEY_LEN]);
    assert_eq!(set.select(5).unwrap().key, [0x20; NETWORK_KEY_LEN]);
    assert!(set.select(6).is_none());

    set.activate_pending().unwrap();
    assert_eq!(set.active().seq, 5);
    assert!(set.pending().is_none());
    // The retired key no longer resolves after the flip.
    assert!(set.select(4).is_none());
    assert_eq!(set.select(5).unwrap().key, [0x20; NETWORK_KEY_LEN]);
}

// @verifies req=05-3474-23-462-01 test=crates/rounddance-security/tests/coverage_core_ch4_counter_replay.rs::link_key_table_lookup_and_per_peer_counters
// AIB key-table leg: the bounded trust-center table inserts, finds,
// replaces, and removes by long address; per-peer counters give each
// link the same monotonicity and replay protection as network keys.
#[test]
fn link_key_table_lookup_and_per_peer_counters() {
    let mut table = LinkKeyTable::<2>::new();
    assert!(table.is_empty());
    assert_eq!(table.len(), 0);

    table
        .insert(LinkKeyEntry::new([0x01; 8], [0xAA; NETWORK_KEY_LEN]))
        .unwrap();
    table
        .insert(LinkKeyEntry::new([0x02; 8], [0xBB; NETWORK_KEY_LEN]))
        .unwrap();
    assert_eq!(table.len(), 2);
    assert!(table
        .insert(LinkKeyEntry::new([0x03; 8], [0xCC; NETWORK_KEY_LEN]))
        .is_err());
    // Unknown long address resolves to nothing.
    assert!(table.find(&[0x09; 8]).is_none());

    // Transmit counters advance monotonically per peer.
    let entry = table.find_mut(&[0x01; 8]).unwrap();
    assert_eq!(entry.tx_take().unwrap(), 0);
    assert_eq!(entry.tx_take().unwrap(), 1);

    // Receive counters accept the first value, then only advances.
    entry.rx_check(9).unwrap();
    assert_eq!(entry.rx_check(9), Err(SecError::Replay));
    assert_eq!(entry.rx_check(4), Err(SecError::Replay));
    entry.rx_check(10).unwrap();

    // Removal drops the entry; removing again reports absence.
    table.remove(&[0x02; 8]).unwrap();
    assert!(table.find(&[0x02; 8]).is_none());
    assert_eq!(table.remove(&[0x02; 8]), Err(SecError::NotFound));
}

// @verifies req=05-3474-23-462-01 test=crates/rounddance-security/tests/coverage_core_ch4_counter_replay.rs::link_key_tx_counter_exhausts
// AIB key-table leg: a transmit counter at the top of the range stops
// instead of wrapping, forcing a key refresh for that peer.
#[test]
fn link_key_tx_counter_exhausts() {
    let mut entry = LinkKeyEntry::new([0x07; 8], [0x55; NETWORK_KEY_LEN]);
    entry.tx_counter = u32::MAX - 1;
    assert_eq!(entry.tx_take().unwrap(), u32::MAX - 1);
    assert_eq!(entry.tx_take(), Err(SecError::CounterExhausted));
}
