//! Discovery handlers: attribute and command enumeration over a
//! cluster definition plus its live store.
//!
//! Paraphrase-level model of doc `07-5123-08` §2.5.13.3 (response
//! lists ascending from the start identifier, capped by the maximum,
//! anchor p0082-L3040-L3046), §2.5.14.1.2 (completion flag, anchor
//! p0083-L3062-L3064), and §2.5.18.3 (ordered command lists, anchor
//! p0090-L3304-L3307). All wording here is paraphrase (D1).
//!
//! Requirement IDs `07-5123-08-2513-01`/`2514-01`/`2518-01`
//! (repo-minted, MINTED-pending-confirm).

use crate::attrs::AttrStore;
use crate::cluster::ClusterDef;
use crate::frame::Header;
use crate::general::{DiscoverAttrs, DiscoverCmds};

/// Answer attribute discovery from the live store: ascending
/// identifier/type pairs starting at `req.start`, at most `req.max`
/// (and at most `out.len()`). Returns the count written and whether
/// the store holds no further identifiers.
///
/// Manufacturer-specific discovery over standard-only definitions
/// yields an empty complete page.
pub fn handle_discover_attrs(
    store: &AttrStore,
    req: DiscoverAttrs,
    manufacturer_specific: bool,
    out: &mut [(u16, u8)],
) -> (usize, bool) {
    if manufacturer_specific {
        return (0, true);
    }
    let cap = (req.max as usize).min(out.len());
    let mut idx = store.lower_bound(req.start);
    let mut n = 0;
    while n < cap {
        match store.nth(idx) {
            Some(pair) => {
                out[n] = pair;
                n += 1;
                idx += 1;
            }
            None => break,
        }
    }
    let complete = store.nth(idx).is_none();
    (n, complete)
}

/// Answer command discovery from the definition tables: the received
/// set for direction bit 0 (commands the server processes), the
/// generated set for direction bit 1. Ascending, capped, with the
/// completion flag.
pub fn handle_discover_cmds(
    def: &dyn ClusterDef,
    header: &Header,
    req: DiscoverCmds,
    out: &mut [u8],
) -> (usize, bool) {
    let table = if header.control.direction.bit() == 0 {
        def.received_commands()
    } else {
        def.generated_commands()
    };
    let cap = (req.max as usize).min(out.len());
    let mut n = 0;
    let mut pending = false;
    let mut i = 0;
    while i < table.len() {
        if table[i].id >= req.start {
            if n < cap {
                out[n] = table[i].id;
                n += 1;
            } else {
                pending = true;
            }
        }
        i += 1;
    }
    (n, !pending)
}
