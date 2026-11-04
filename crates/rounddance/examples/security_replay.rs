//! Security replay window: a strict-advance counter table accepts
//! fresh frames, refuses exact replays, and forgets nothing while
//! running. Covers the anti-replay half of every secured frame.
//!
//! Run: `cargo run -p rounddance --example security_replay`

use rounddance::security::ReplayTable;

const TC: u64 = 0xa0f262fffe867f68;

fn main() {
    let mut table = ReplayTable::<8>::new();
    table.check(TC, 0x1000).expect("first frame accepted");
    table.check(TC, 0x1001).expect("advanced frame accepted");
    assert_eq!(table.last(TC), Some(0x1001));

    match table.check(TC, 0x1001) {
        Ok(()) => println!("REPLAY accepted (BUG)"),
        Err(e) => println!("REPLAY refused ({e:?}), as it must be"),
    }
    match table.check(TC, 0x0fff) {
        Ok(()) => println!("REWIND accepted (BUG)"),
        Err(e) => println!("REWIND refused ({e:?}), as it must be"),
    }

    table.remove(TC);
    assert_eq!(table.last(TC), None);
    println!("FORGET ok (rejoin restarts the counter space)");
}
