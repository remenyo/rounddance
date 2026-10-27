//! Device inventory: typed records from `esp-inventory.md` plus live discovery.
//!
//! The pinned map is the authority for port -> chip assignments. Live
//! discovery only lists which `/dev` nodes exist right now and who holds
//! them; `esptool` probes run on request only (never as a side effect).

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// ESP chip kinds present in the lab (plus non-ESP nodes we must not touch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Chip {
    C5,
    S3,
    H2,
    C6,
    S31,
    /// Nordic nRF 802.15.4 sniffer (ACM0/ACM1) — owned by the sniffer worker.
    NordicSniffer,
    /// Sonoff MG24 / MG21 (USB0/USB1) — not ESP flash targets.
    Sonoff,
}

impl fmt::Display for Chip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Chip::C5 => "ESP32-C5",
            Chip::S3 => "ESP32-S3",
            Chip::H2 => "ESP32-H2",
            Chip::C6 => "ESP32-C6",
            Chip::S31 => "ESP32-S31",
            Chip::NordicSniffer => "nRF-sniffer",
            Chip::Sonoff => "Sonoff",
        };
        f.write_str(s)
    }
}

/// What a device can do (from `chip-id` features + datasheets).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Capabilities {
    pub wifi: bool,
    pub ieee802154: bool,
    pub bluetooth_le: bool,
    pub flash_mb: u32,
    pub psram: bool,
}

/// One pinned lab device.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeviceInfo {
    /// Serial port, e.g. `/dev/ttyACM7`.
    pub port: String,
    pub chip: Chip,
    pub mac: String,
    /// Lab role, e.g. `wifi-node`, `hal-audit-spare`, `sniffer-shell`.
    pub role: String,
    pub caps: Capabilities,
}

fn caps(
    wifi: bool,
    ieee802154: bool,
    bluetooth_le: bool,
    flash_mb: u32,
    psram: bool,
) -> Capabilities {
    Capabilities {
        wifi,
        ieee802154,
        bluetooth_le,
        flash_mb,
        psram,
    }
}

/// Pinned inventory from `hardware-meta/esp-inventory.md` (probed 2026-10-27).
///
/// MACs are lowercase hex with colons, matching `esptool chip-id` output.
pub fn known_inventory() -> Vec<DeviceInfo> {
    vec![
        DeviceInfo {
            port: "/dev/ttyACM2".into(),
            chip: Chip::C5,
            mac: "30:ed:a0:e4:1a:30".into(),
            role: "wifi-node".into(),
            caps: caps(true, true, true, 8, true),
        },
        DeviceInfo {
            port: "/dev/ttyACM3".into(),
            chip: Chip::S3,
            mac: "cc:8d:a2:29:a4:6c".into(),
            role: "wifi-node".into(),
            caps: caps(true, false, true, 8, true),
        },
        DeviceInfo {
            port: "/dev/ttyACM4".into(),
            chip: Chip::H2,
            mac: "74:4d:bd:61:7a:fa".into(),
            role: "radio-only".into(),
            caps: caps(false, true, true, 2, false),
        },
        DeviceInfo {
            port: "/dev/ttyACM5".into(),
            chip: Chip::S3,
            mac: "48:ca:43:06:14:dc".into(),
            role: "wifi-node".into(),
            caps: caps(true, false, true, 8, true),
        },
        DeviceInfo {
            port: "/dev/ttyACM6".into(),
            chip: Chip::H2,
            mac: "74:4d:bd:61:7d:1c".into(),
            role: "radio-only".into(),
            caps: caps(false, true, true, 2, false),
        },
        DeviceInfo {
            port: "/dev/ttyACM7".into(),
            chip: Chip::C6,
            mac: "a0:f2:62:86:7f:68".into(),
            role: "wifi-node".into(),
            caps: caps(true, true, true, 4, false),
        },
        DeviceInfo {
            port: "/dev/ttyACM8".into(),
            chip: Chip::C6,
            mac: "a0:f2:62:85:97:a4".into(),
            role: "wifi-node".into(),
            caps: caps(true, true, true, 4, false),
        },
        DeviceInfo {
            port: "/dev/ttyACM9".into(),
            chip: Chip::C6,
            mac: "a0:f2:62:86:e5:10".into(),
            role: "wifi-node".into(),
            caps: caps(true, true, true, 4, false),
        },
        DeviceInfo {
            port: "/dev/ttyUSB2".into(),
            chip: Chip::S31,
            mac: "30:ed:a0:f3:ce:94".into(),
            role: "wasm-isolation".into(),
            caps: caps(true, true, true, 16, false),
        },
        // Non-ESP nodes: listed so workers know they exist and stay off them.
        DeviceInfo {
            port: "/dev/ttyACM0".into(),
            chip: Chip::NordicSniffer,
            mac: "".into(),
            role: "sniffer-shell".into(),
            caps: caps(false, true, false, 0, false),
        },
        DeviceInfo {
            port: "/dev/ttyACM1".into(),
            chip: Chip::NordicSniffer,
            mac: "".into(),
            role: "sniffer-shell".into(),
            caps: caps(false, true, false, 0, false),
        },
        DeviceInfo {
            port: "/dev/ttyUSB0".into(),
            chip: Chip::Sonoff,
            mac: "".into(),
            role: "sonoff-mg24".into(),
            caps: caps(false, true, false, 0, false),
        },
        DeviceInfo {
            port: "/dev/ttyUSB1".into(),
            chip: Chip::Sonoff,
            mac: "".into(),
            role: "sonoff-mg21".into(),
            caps: caps(false, true, false, 0, false),
        },
    ]
}

/// Look up the pinned record for a port.
pub fn lookup(port: &str) -> Option<DeviceInfo> {
    known_inventory().into_iter().find(|d| d.port == port)
}

/// Live discovery: which `/dev/ttyACM*` / `/dev/ttyUSB*` nodes exist now.
///
/// Pure directory listing — opens no ports, probes nothing.
pub fn discover_ports(dev_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dev_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("ttyACM") || name.starts_with("ttyUSB") {
            out.push(entry.path());
        }
    }
    out.sort();
    Ok(out)
}

/// PIDs currently holding `port` open (via `/proc/<pid>/fd` scan).
///
/// Empty means no local process holds it. This is advisory: a port can be
/// opened between this check and use — always `reserve` through the lease
/// manager before touching hardware.
pub fn port_holders(port: &str) -> Vec<u32> {
    let mut holders = Vec::new();
    // No /proc (non-Linux): cannot scan; report none.
    let Ok(procs) = fs::read_dir("/proc") else {
        return holders;
    };
    for proc in procs.flatten() {
        let pid: u32 = match proc.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let fd_dir = format!("/proc/{pid}/fd");
        for fd in fs::read_dir(&fd_dir).into_iter().flatten().flatten() {
            if let Ok(target) = fs::read_link(fd.path()) {
                if target.to_string_lossy() == port {
                    holders.push(pid);
                    break;
                }
            }
        }
    }
    holders.sort_unstable();
    holders.dedup();
    holders
}

/// Run `esptool --port <port> chip-id` and return its stdout.
///
/// ON REQUEST ONLY — never call from discovery or lease paths.
pub fn probe_chip(port: &str) -> io::Result<String> {
    let out = std::process::Command::new("esptool")
        .args(["--port", port, "chip-id"])
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_inventory_has_nine_esp_nodes() {
        let esp = known_inventory()
            .into_iter()
            .filter(|d| {
                matches!(
                    d.chip,
                    Chip::C5 | Chip::S3 | Chip::H2 | Chip::C6 | Chip::S31
                )
            })
            .count();
        assert_eq!(esp, 9);
    }

    #[test]
    fn lookup_finds_pinned_ports() {
        let d = lookup("/dev/ttyACM7").expect("ACM7 pinned");
        assert_eq!(d.chip, Chip::C6);
        assert!(d.caps.ieee802154);
    }

    #[test]
    fn live_discovery_lists_only_serial_nodes() {
        let dir = std::env::temp_dir().join("arb-inv-test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for n in ["ttyACM7", "ttyUSB0", "ttyS0", "null"] {
            fs::write(dir.join(n), b"").unwrap();
        }
        let ports = discover_ports(&dir).unwrap();
        let names: Vec<_> = ports
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["ttyACM7".to_string(), "ttyUSB0".to_string()]);
        fs::remove_dir_all(&dir).unwrap();
    }
}
