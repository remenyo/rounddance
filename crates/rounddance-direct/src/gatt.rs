//! Direct GATT service model as data.
//!
//! Paraphrase-level model of doc `20-27688-041` §6.5 (security
//! service) and §7.7.2.1–7.7.2.3 (commissioning service). A BLE shim
//! (NimBLE on ESP, a host harness on Pi) instantiates these
//! descriptors; this crate never touches a controller.
//!
//! Requirement IDs: `20-27688-041-65-01` (security-service shape),
//! `20-27688-041-772-01` (commissioning-service discipline).

/// 128-bit UUID in wire (big-endian text) order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uuid128(pub [u8; 16]);

impl Uuid128 {
    /// Parse `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (either case).
    /// Returns `None` on any malformed input — no panics.
    #[must_use]
    pub fn parse(text: &[u8]) -> Option<Self> {
        const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
        let mut out = [0u8; 16];
        let mut ti = 0usize;
        let mut oi = 0usize;
        for (gi, g) in GROUPS.iter().enumerate() {
            for _ in 0..*g {
                if ti + 1 >= text.len() {
                    return None;
                }
                let hi = hex_val(text[ti])?;
                let lo = hex_val(text[ti + 1])?;
                ti += 2;
                out[oi] = (hi << 4) | lo;
                oi += 1;
            }
            if gi < 4 {
                if ti >= text.len() || text[ti] != b'-' {
                    return None;
                }
                ti += 1;
            }
        }
        if ti != text.len() {
            return None;
        }
        Some(Self(out))
    }

    /// Lowercase hyphenated text form into `out` (needs 36 octets).
    /// Returns the written length or 0 when `out` is too small.
    #[must_use]
    pub fn format_into(&self, out: &mut [u8]) -> usize {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
        if out.len() < 36 {
            return 0;
        }
        let mut oi = 0usize;
        let mut si = 0usize;
        for (gi, g) in GROUPS.iter().enumerate() {
            for _ in 0..*g / 2 {
                let b = self.0[si];
                si += 1;
                out[oi] = HEX[(b >> 4) as usize];
                out[oi + 1] = HEX[(b & 0xF) as usize];
                oi += 2;
            }
            if gi < 4 {
                out[oi] = b'-';
                oi += 1;
            }
        }
        oi
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// BLE procedures a characteristic supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharProps {
    /// ATT Read Request.
    pub read: bool,
    /// ATT Write Request.
    pub write: bool,
    /// Notifications (client-subscribed).
    pub notify: bool,
    /// Indications (acknowledged).
    pub indicate: bool,
}

/// Direct authorization level gating a characteristic.
///
/// Requirement `20-27688-041-63-01` (session access control).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthLevel {
    /// No session needed (status reads excepted).
    Open,
    /// Any provisioning session with an unprovisioned peer.
    Provisioning,
    /// Basic-level authorization session.
    Basic,
    /// Admin-level authorization session.
    Admin,
}

/// One GATT characteristic descriptor (data only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharDesc {
    /// Short name (ASCII, for logs).
    pub name: &'static str,
    /// 128-bit characteristic UUID.
    pub uuid: Uuid128,
    /// Supported BLE procedures.
    pub props: CharProps,
    /// Minimum session level while the device is unprovisioned.
    pub auth: AuthLevel,
    /// Minimum session level once the device is provisioned
    /// (Table 26 authorization column).
    pub auth_provisioned: AuthLevel,
    /// Mandatory (`true`) or optional (`false`) on the device.
    pub mandatory: bool,
}

/// One GATT service descriptor (data only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceDesc {
    /// Short name (ASCII, for logs).
    pub name: &'static str,
    /// Service UUID.
    pub uuid: Uuid128,
    /// Exactly-one-instance services (`true`) per the clauses below.
    pub single_instance: bool,
    /// Mandatory (`true`) or optional (`false`) on the device.
    pub mandatory: bool,
    /// Characteristic set.
    pub chars: &'static [CharDesc],
}

const fn uuid(bytes: [u8; 16]) -> Uuid128 {
    Uuid128(bytes)
}

/// Security service UUID, §6.5 (`20-27688-041-65-01`):
/// `29144AF4-0000-4481-BFE9-6D0299B429E3`.
pub const SECURITY_SERVICE_UUID: Uuid128 = uuid([
    0x29, 0x14, 0x4A, 0xF4, 0x00, 0x00, 0x44, 0x81, 0xBF, 0xE9, 0x6D, 0x02, 0x99, 0xB4, 0x29, 0xE3,
]);

/// Commissioning service UUID: assigned 16-bit `0xFFF7` expanded
/// through the Bluetooth Base UUID (§7.7.2.1,
/// `20-27688-041-772-01`).
pub const COMMISSIONING_SERVICE_UUID: Uuid128 = uuid([
    0x00, 0x00, 0xFF, 0xF7, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
]);

const AUTH_BASE: [u8; 16] = [
    0x29, 0x14, 0x4A, 0xF4, 0x00, 0x00, 0x44, 0x81, 0xBF, 0xE9, 0x6D, 0x02, 0x99, 0xB4, 0x29, 0xE3,
];

const fn auth_char(lo: u8) -> Uuid128 {
    let mut b = AUTH_BASE;
    b[5] = lo;
    Uuid128(b)
}

const COMM_BASE: [u8; 16] = [
    0x70, 0x72, 0x37, 0x7D, 0x00, 0x00, 0x42, 0x1C, 0xB1, 0x63, 0x49, 0x1C, 0x27, 0x33, 0x3A, 0x61,
];

const fn comm_char(lo: u8) -> Uuid128 {
    let mut b = COMM_BASE;
    b[5] = lo;
    Uuid128(b)
}

const WRITE_INDICATE: CharProps = CharProps {
    read: false,
    write: true,
    notify: false,
    indicate: true,
};
const WRITE_ONLY: CharProps = CharProps {
    read: false,
    write: true,
    notify: false,
    indicate: false,
};

/// Security-service Authenticate characteristics, Table 5
/// (`20-27688-041-65-01`, `20-27688-041-65-02`): one per
/// establishment method, Write Request + Indication, strict
/// sequence, no BLE-layer authentication requirement.
pub const SECURITY_CHARS: [CharDesc; 3] = [
    CharDesc {
        name: "Authenticate-SPEKE-MM0",
        uuid: auth_char(0x01),
        props: WRITE_INDICATE,
        auth: AuthLevel::Open,
        auth_provisioned: AuthLevel::Open,
        mandatory: false,
    },
    CharDesc {
        name: "Authenticate-SPEKE-SHA",
        uuid: auth_char(0x02),
        props: WRITE_INDICATE,
        auth: AuthLevel::Open,
        auth_provisioned: AuthLevel::Open,
        mandatory: false,
    },
    CharDesc {
        name: "Authenticate-ECDHE-PSK",
        uuid: auth_char(0x03),
        props: WRITE_INDICATE,
        auth: AuthLevel::Open,
        auth_provisioned: AuthLevel::Open,
        mandatory: false,
    },
];

/// Commissioning-service characteristics, Table 26
/// (`20-27688-041-772-01`): Form/Join/Permit/Leave write-only,
/// Status read+notify, Manage Joiners write-only (optional),
/// Identify write+read uint16, Finding&Binding write-only
/// (optional).
pub const COMMISSIONING_CHARS: [CharDesc; 8] = [
    CharDesc {
        name: "FormNetwork",
        uuid: comm_char(0x01),
        props: WRITE_ONLY,
        auth: AuthLevel::Provisioning,
        auth_provisioned: AuthLevel::Admin,
        mandatory: true,
    },
    CharDesc {
        name: "JoinNetwork",
        uuid: comm_char(0x02),
        props: WRITE_ONLY,
        auth: AuthLevel::Provisioning,
        auth_provisioned: AuthLevel::Admin,
        mandatory: true,
    },
    CharDesc {
        name: "PermitJoining",
        uuid: comm_char(0x03),
        props: WRITE_ONLY,
        auth: AuthLevel::Provisioning,
        auth_provisioned: AuthLevel::Admin,
        mandatory: true,
    },
    CharDesc {
        name: "LeaveNetwork",
        uuid: comm_char(0x04),
        props: WRITE_ONLY,
        auth: AuthLevel::Provisioning,
        auth_provisioned: AuthLevel::Admin,
        mandatory: true,
    },
    CharDesc {
        name: "CommissioningStatus",
        uuid: comm_char(0x05),
        props: CharProps {
            read: true,
            write: false,
            notify: true,
            indicate: false,
        },
        auth: AuthLevel::Open,
        auth_provisioned: AuthLevel::Open,
        mandatory: true,
    },
    CharDesc {
        name: "ManageJoiners",
        uuid: comm_char(0x06),
        props: WRITE_ONLY,
        auth: AuthLevel::Admin,
        auth_provisioned: AuthLevel::Admin,
        mandatory: false,
    },
    CharDesc {
        name: "Identify",
        uuid: comm_char(0x07),
        props: CharProps {
            read: true,
            write: true,
            notify: false,
            indicate: false,
        },
        auth: AuthLevel::Provisioning,
        auth_provisioned: AuthLevel::Basic,
        mandatory: true,
    },
    CharDesc {
        name: "FindingBinding",
        uuid: comm_char(0x08),
        props: WRITE_ONLY,
        auth: AuthLevel::Basic,
        auth_provisioned: AuthLevel::Basic,
        mandatory: false,
    },
];

/// Both Direct services in descriptor form.
pub const DIRECT_SERVICES: [ServiceDesc; 2] = [
    ServiceDesc {
        name: "DirectSecurity",
        uuid: SECURITY_SERVICE_UUID,
        single_instance: true,
        mandatory: true,
        chars: &SECURITY_CHARS,
    },
    ServiceDesc {
        name: "DirectCommissioning",
        uuid: COMMISSIONING_SERVICE_UUID,
        single_instance: true,
        mandatory: true,
        chars: &COMMISSIONING_CHARS,
    },
];

/// ATT application error for insufficient authorization, §6.4.7.4
/// (`20-27688-041-63-01`): the receiver ignores the request and,
/// for Read/Write Requests, answers with this error code.
pub const APP_ERROR_INSUFFICIENT_AUTH: u8 = 0x80;

/// Authorization check for one characteristic access.
///
/// Requirement `20-27688-041-63-01` (provisioned devices restrict
/// commissioning characteristics to session holders, status reads
/// excepted): returns `Ok(())` when `held` meets the
/// characteristic's level, else the ATT application error above.
pub fn authorize(desc: &CharDesc, held: AuthLevel, provisioned: bool) -> Result<(), u8> {
    let need = if provisioned {
        desc.auth_provisioned
    } else {
        desc.auth
    };
    if held >= need {
        Ok(())
    } else {
        Err(APP_ERROR_INSUFFICIENT_AUTH)
    }
}
