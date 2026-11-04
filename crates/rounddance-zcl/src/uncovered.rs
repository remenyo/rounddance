//! Previously uncovered document models: ERL Interface device,
//! Daily Schedule cluster, Occupancy Sensing cluster, Linky
//! Metering extension, Device Type Library registry, and the
//! Aliro Reader bridge.
//!
//! NOTE for the lib.rs hookup (main agent merges this to avoid
//! `mod` conflicts): add exactly one line to
//! `crates/rounddance-zcl/src/lib.rs` in the module block:
//!
//! ```text
//! pub mod uncovered;
//! ```
//!
//! and reach the new models as `uncovered::erl`,
//! `uncovered::dailysched`, `uncovered::occupancy`,
//! `uncovered::linky`, `uncovered::devtype`, and
//! `uncovered::aliro`.

#[path = "aliro.rs"]
pub mod aliro;
#[path = "dailysched.rs"]
pub mod dailysched;
#[path = "devtype.rs"]
pub mod devtype;
#[path = "erl.rs"]
pub mod erl;
#[path = "linky.rs"]
pub mod linky;
#[path = "occupancy.rs"]
pub mod occupancy;
