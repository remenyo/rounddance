//! Offline pcap / pcapng ingest (`std` only).
//!
//! Reads classic pcap (global header + per-packet records, any DLT —
//! the inspector expects `LINKTYPE_IEEE802_15_4` 195 but records the
//! link type per file for the report) and minimal pcapng (Section
//! Header + Interface Description + Enhanced Packet blocks; other block
//! kinds are skipped by length). Writing is pcap-only: pcapng ingest
//! is read-only at scaffold scope.

use std::io::{self, Read, Write};

/// Classic pcap magic (microsecond, little-endian).
pub const PCAP_MAGIC_LE: u32 = 0xa1b2c3d4;
/// Classic pcap magic (microsecond, big-endian on air).
pub const PCAP_MAGIC_BE: u32 = 0xd4c3b2a1;
/// pcapng section-header magic (little-endian).
pub const PCAPNG_MAGIC_LE: u32 = 0x0a0d0d0a;
/// 802.15.4 link type (no FCS).
pub const LINKTYPE_IEEE802_15_4: u32 = 195;

/// pcapng block types we consume or skip.
const PB_SHB: u32 = 0x0A0D0D0A;
const PB_IDB: u32 = 0x00000001;
const PB_EPB: u32 = 0x00000006;

/// One ingested packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// Capture timestamp in microseconds since the Unix epoch.
    pub ts_us: u64,
    /// Link type of the recording (pcap global header / IDB linktype).
    pub linktype: u32,
    /// Raw packet octets.
    pub data: Vec<u8>,
}

/// Ingest failure.
#[derive(Debug)]
pub enum IngestError {
    /// Underlying IO failure.
    Io(io::Error),
    /// Magic not recognized as pcap or pcapng.
    BadMagic(u32),
    /// Unsupported pcap version.
    BadVersion(u16, u16),
    /// Record runs past the end of the input.
    Truncated,
    /// pcapng block length invalid.
    BadBlockLen(u32),
}

impl From<io::Error> for IngestError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

fn u16le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Read one pcap/pcapng recording from `r` (auto-detected by magic).
pub fn read_all<R: Read>(r: &mut R) -> Result<Vec<Packet>, IngestError> {
    let mut buf = Vec::new();
    r.read_to_end(&mut buf)?;
    if buf.len() < 4 {
        return Err(IngestError::Truncated);
    }
    let magic_le = u32le(&buf[0..4]);
    if magic_le == PCAPNG_MAGIC_LE {
        return read_pcapng(&buf);
    }
    read_pcap(&buf)
}

fn read_pcap(buf: &[u8]) -> Result<Vec<Packet>, IngestError> {
    if buf.len() < 24 {
        return Err(IngestError::Truncated);
    }
    let le = u32le(&buf[0..4]) == PCAP_MAGIC_LE;
    let magic = if le {
        u32le(&buf[0..4])
    } else {
        u32be(&buf[0..4])
    };
    if magic != PCAP_MAGIC_LE {
        return Err(IngestError::BadMagic(magic));
    }
    let rd16 = |b: &[u8]| {
        if le {
            u16le(b)
        } else {
            u16::from_be_bytes([b[0], b[1]])
        }
    };
    let rd32 = |b: &[u8]| if le { u32le(b) } else { u32be(b) };
    let (major, minor) = (rd16(&buf[4..6]), rd16(&buf[6..8]));
    if major != 2 || minor != 4 {
        return Err(IngestError::BadVersion(major, minor));
    }
    let linktype = rd32(&buf[20..24]);
    let mut out = Vec::new();
    let mut pos = 24;
    while pos < buf.len() {
        if buf.len() < pos + 16 {
            return Err(IngestError::Truncated);
        }
        let (ts_sec, ts_sub) = (
            u64::from(rd32(&buf[pos..pos + 4])),
            u64::from(rd32(&buf[pos + 4..pos + 8])),
        );
        let (incl, _orig) = (
            rd32(&buf[pos + 8..pos + 12]) as usize,
            rd32(&buf[pos + 12..pos + 16]),
        );
        pos += 16;
        if buf.len() < pos + incl {
            return Err(IngestError::Truncated);
        }
        // pcap timestamps are µs by definition of the accepted magics.
        out.push(Packet {
            ts_us: ts_sec * 1_000_000 + ts_sub,
            linktype,
            data: buf[pos..pos + incl].to_vec(),
        });
        pos += incl;
    }
    Ok(out)
}

fn read_pcapng(buf: &[u8]) -> Result<Vec<Packet>, IngestError> {
    let mut out = Vec::new();
    let mut pos = 0;
    let mut linktype = LINKTYPE_IEEE802_15_4;
    while pos < buf.len() {
        if buf.len() < pos + 12 {
            return Err(IngestError::Truncated);
        }
        let (kind, total) = (
            u32le(&buf[pos..pos + 4]),
            u32le(&buf[pos + 4..pos + 8]) as usize,
        );
        if total < 12 || buf.len() < pos + total {
            return Err(IngestError::Truncated);
        }
        if u32le(&buf[pos + total - 4..pos + total]) as usize != total {
            return Err(IngestError::BadBlockLen(total as u32));
        }
        match kind {
            PB_SHB => {}
            PB_IDB => {
                if total >= 20 {
                    linktype = u16le(&buf[pos + 8..pos + 10]) as u32;
                }
            }
            PB_EPB => {
                if total < 32 {
                    return Err(IngestError::Truncated);
                }
                let ts = (u64::from(u32le(&buf[pos + 16..pos + 20])) << 32)
                    | u64::from(u32le(&buf[pos + 12..pos + 16]));
                let cap = u32le(&buf[pos + 20..pos + 24]) as usize;
                if total < 28 + cap {
                    return Err(IngestError::Truncated);
                }
                // pcapng default resolution is µs unless an if_tsresol
                // option says otherwise; scaffold scope assumes µs.
                out.push(Packet {
                    ts_us: ts,
                    linktype,
                    data: buf[pos + 28..pos + 28 + cap].to_vec(),
                });
            }
            _ => {}
        }
        pos += total;
    }
    Ok(out)
}

/// Write packets as classic pcap (µs, LE) with the given link type.
pub fn write_pcap<W: Write>(w: &mut W, linktype: u32, packets: &[Packet]) -> io::Result<()> {
    w.write_all(&PCAP_MAGIC_LE.to_le_bytes())?;
    w.write_all(&2u16.to_le_bytes())?;
    w.write_all(&4u16.to_le_bytes())?;
    w.write_all(&0u32.to_le_bytes())?;
    w.write_all(&0u32.to_le_bytes())?;
    w.write_all(&262144u32.to_le_bytes())?;
    w.write_all(&linktype.to_le_bytes())?;
    for p in packets {
        w.write_all(&((p.ts_us / 1_000_000) as u32).to_le_bytes())?;
        w.write_all(&((p.ts_us % 1_000_000) as u32).to_le_bytes())?;
        w.write_all(&(p.data.len() as u32).to_le_bytes())?;
        w.write_all(&(p.data.len() as u32).to_le_bytes())?;
        w.write_all(&p.data)?;
    }
    Ok(())
}
