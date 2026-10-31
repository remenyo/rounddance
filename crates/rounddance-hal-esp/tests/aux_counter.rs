//! Phase 4: NVM-backed auxiliary frame counter (anti-replay across
//! reboots) — head-side contract pins.
//!
//! A coordinator reboot restarts a RAM-only counter at its base while
//! live peers still hold the pre-reboot high-water in their replay
//! tables: every post-reboot frame then misclassifies as replay and
//! the join wedges until the peer reboots too (observed class after
//! B-008 crash-reboots). The fix persists a chunk high-water in NVS;
//! this file pins the chunk arithmetic the firmware depends on.
use rounddance_hal_esp::app::{AuxCounter, AUX_CHUNK};

#[test]
fn fresh_counter_starts_at_base_and_reports_first_chunk() {
    let mut c = AuxCounter::fresh(0x1000);
    // Persist-before-use: the base chunk is due before the first
    // sealed frame goes on air, so a crash before any write still
    // resumes above it.
    assert_eq!(c.poll_checkpoint(), Some(0x1000 / AUX_CHUNK));
    assert_eq!(c.poll_checkpoint(), None);
    assert_eq!(c.take(), 0x1000);
    // Same chunk: nothing new to persist.
    assert_eq!(c.poll_checkpoint(), None);
}

#[test]
fn checkpoint_fires_exactly_on_chunk_crossing() {
    let mut c = AuxCounter::fresh(0);
    assert_eq!(c.poll_checkpoint(), Some(0));
    // Burn the rest of chunk 0 (values 0..=62): nothing new to report.
    for v in 0..63u32 {
        assert_eq!(c.take(), v);
    }
    assert_eq!(c.poll_checkpoint(), None);
    // Last value of chunk 0: taking it moves `next` into chunk 1,
    // so the crossing report fires immediately (persist-before-use:
    // chunk 1 is due before any of its values radiate).
    assert_eq!(c.take(), 63);
    assert_eq!(c.poll_checkpoint(), Some(1));
    assert_eq!(c.poll_checkpoint(), None);
    assert_eq!(c.take(), 64);
    assert_eq!(c.poll_checkpoint(), None);
}

#[test]
fn resume_skips_persisted_range_monotonically() {
    // Crash after persisting chunk 65 (values up through 0x107F may
    // have radiated): resume restarts at 0x1080, strictly above every
    // used value, so a rejoining peer holding 0x1041 advances instead
    // of replay-refusing a restarted 0x1000.
    let mut c = AuxCounter::resume(Some(65), 0x1000);
    assert_eq!(c.take(), 0x1080);
    // 0x1080 strictly exceeds a peer high-water of 0x1041, so a
    // rejoining peer holding 0x1041 advances instead of
    // replay-refusing a restarted 0x1000.
    assert_eq!(c.poll_checkpoint(), Some(0x1080 / AUX_CHUNK));
    assert_eq!(c.poll_checkpoint(), None);
}

#[test]
fn base_floor_holds_when_nvs_lags_behind() {
    // Stale NVS (chunk 3) with a higher lab base: the base wins so a
    // fresh image never rewinds below its deployment floor.
    let mut c = AuxCounter::resume(Some(3), 0x1000);
    assert_eq!(c.take(), 0x1000);
    // First poll reports the base chunk (persist-before-use).
    assert_eq!(c.poll_checkpoint(), Some(0x1000 / AUX_CHUNK));
}

#[test]
fn counter_saturates_instead_of_wrapping() {
    // At the top of the space the counter sticks (loud outage) rather
    // than wrapping to 0 (silent replay-acceptance).
    let mut c = AuxCounter::resume(Some(u32::MAX), 0);
    assert_eq!(c.take(), u32::MAX);
    assert_eq!(c.take(), u32::MAX);
    assert_eq!(c.poll_checkpoint(), Some(u32::MAX / AUX_CHUNK));
}
