//! Offline btsnoop ingest (`std` only).
//!
//! Reads the btsnoop container (`btsnoop\0` magic, version, datalink
//! header, then per-record headers) as written by the lab `btmon`
//! captures. Record payloads are raw HCI packets without the H4
//! type octet; the flags discriminate host-to-controller commands
//! (2), controller-to-host events (3), ACL data sent (4), and ACL
//! data received (5). Every other flag value is monitor control
//! (index add/remove, MGMT commands/events, open/close, system
//! notes) and is skipped — only HCI records are returned.
//!
//! Record timestamps ride along opaquely (`ts_raw`): the file clock
//! is not Unix time and the inspector does no time math.

use std::io::{self, Read};

pub use crate::ble::{FLAGS_ACL_RX, FLAGS_ACL_TX, FLAGS_HCI_CMD, FLAGS_HCI_EVT};

/// One ingested HCI record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HciRecord {
    /// btsnoop flags (2 = HCI command, 3 = HCI event, 4 = ACL
    /// sent, 5 = ACL received).
    pub flags: u32,
    /// Opaque file clock (not Unix time; carried, never computed on).
    pub ts_raw: u64,
    /// Raw HCI packet octets (no H4 type byte).
    pub data: Vec<u8>,
}

/// Ingest failure.
#[derive(Debug)]
pub enum IngestError {
    /// Underlying IO failure.
    Io(io::Error),
    /// Magic is not btsnoop.
    BadMagic,
    /// Record runs past the end of the input.
    Truncated,
}

impl From<io::Error> for IngestError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn u64be(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Monitor-control flags carry no HCI: index notes, MGMT traffic,
/// open/close, and system notes. Anything outside 2..=5 skips.
fn is_hci(flags: u32) -> bool {
    matches!(
        flags,
        FLAGS_HCI_CMD | FLAGS_HCI_EVT | FLAGS_ACL_TX | FLAGS_ACL_RX
    )
}

/// Read one btsnoop recording from `r`, returning HCI records only.
pub fn read_all<R: Read>(r: &mut R) -> Result<Vec<HciRecord>, IngestError> {
    let mut buf = Vec::new();
    r.read_to_end(&mut buf)?;
    if buf.len() < 16 || &buf[..8] != b"btsnoop\0" {
        return Err(IngestError::BadMagic);
    }
    let mut out = Vec::new();
    let mut pos = 16;
    while pos < buf.len() {
        if buf.len() < pos + 24 {
            return Err(IngestError::Truncated);
        }
        let (orig, incl, flags) = (
            u32be(&buf[pos..pos + 4]) as usize,
            u32be(&buf[pos + 4..pos + 8]) as usize,
            u32be(&buf[pos + 8..pos + 12]),
        );
        let _ = orig;
        let ts = u64be(&buf[pos + 16..pos + 24]);
        pos += 24;
        if buf.len() < pos + incl {
            return Err(IngestError::Truncated);
        }
        if is_hci(flags) {
            out.push(HciRecord {
                flags,
                ts_raw: ts,
                data: buf[pos..pos + incl].to_vec(),
            });
        }
        pos += incl;
    }
    Ok(out)
}
