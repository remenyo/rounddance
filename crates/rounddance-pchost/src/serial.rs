//! Real POSIX serial backend: `SerialUart` implements
//! [`Uart`] over `/dev/ttyUSBx` (or any POSIX
//! serial node) at 460800 baud, 8N1, raw — the RCP wire rate pinned
//! in `docs/otbr/topology.md`.
//!
//! Host-only (`std`, unix): opening configures the port with
//! `termios2` + `BOTHER` for the exact 460800 rate (no nearest-baud
//! fallback — a misconfigured rate wedges framing, so it fails
//! loudly instead), non-blocking I/O, and no modem hangup on open.
//! DTR controls the board reset strap: [`SerialUart::pulse_dtr`]
//! drops DTR for one reset hold so an RCP unit in download-park
//! reboots into its firmware without `esptool` (the documented
//! fallback stays `esptool.py --chip …` DTR/RTS or the BOOT+EN
//! strap).
//!
//! `unsafe` is confined to this module (the crate is a host tool,
//! same standing as `lab-arbitrator`; protocol crates keep
//! `forbid(unsafe_code)`). Every block carries a `SAFETY` comment.
//!
//! Requirement traceability (repo-minted, MINTED-pending-confirm):
//! `RD-RCP-NCP-05` (real UART backend).

#![allow(unsafe_code)]

use rounddance_rcp::{RcpError, Uart};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::OpenOptionsExt as _;

/// RCP wire rate in baud (pinned by `docs/otbr/topology.md`).
pub const RCP_BAUD: u32 = 460_800;
/// DTR reset-hold length in milliseconds.
pub const DTR_HOLD_MS: u64 = 150;

/// Serial-port errors (errno captured at the failing call).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerialError {
    /// `open(2)` failed.
    Open(i32),
    /// `tcgetattr` / `ioctl(TCSETS2)` / `tcsetattr` failed.
    Config(i32),
    /// `read` / `write` / `ioctl(TIOCMBIS/BIC)` failed.
    Io(i32),
    /// Path did not fit the bounded slot.
    PathTooLong,
    /// Requested baud is not the RCP wire rate.
    BadBaud(u32),
}

impl core::fmt::Display for SerialError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Open(e) => write!(f, "serial open failed (errno {e})"),
            Self::Config(e) => write!(f, "serial configure failed (errno {e})"),
            Self::Io(e) => write!(f, "serial I/O failed (errno {e})"),
            Self::PathTooLong => f.write_str("serial path too long"),
            Self::BadBaud(b) => write!(f, "serial baud {b} is not the RCP rate {RCP_BAUD}"),
        }
    }
}

impl std::error::Error for SerialError {}

/// A real serial port speaking the RCP framing.
pub struct SerialUart {
    file: std::fs::File,
    read_buf: [u8; 256],
    read_pos: usize,
    read_len: usize,
}

impl SerialUart {
    /// Open `path` at exactly [`RCP_BAUD`] baud, 8N1, raw,
    /// non-blocking reads. Any other `baud` is refused (a wrong rate
    /// wedges framing silently; refusing is the honest failure).
    pub fn open(path: &str, baud: u32) -> Result<Self, SerialError> {
        if baud != RCP_BAUD {
            return Err(SerialError::BadBaud(baud));
        }
        if path.len() > 107 {
            return Err(SerialError::PathTooLong);
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| SerialError::Open(e.raw_os_error().unwrap_or(libc::EIO)))?;
        let uart = Self {
            file,
            read_buf: [0; 256],
            read_pos: 0,
            read_len: 0,
        };
        uart.configure()?;
        Ok(uart)
    }

    fn fd(&self) -> libc::c_int {
        self.file.as_raw_fd()
    }

    fn configure(&self) -> Result<(), SerialError> {
        // SAFETY: fd is a live open serial node owned by `self.file`;
        // termios2 is a plain-old-data struct we fully overwrite via
        // the TCGETS2 read below before use; the ioctl writes it back
        // with only baud/flags/controls changed. No aliasing: the
        // kernel copies the struct in and out.
        unsafe {
            let mut t: libc::termios2 = core::mem::zeroed();
            if libc::ioctl(self.fd(), libc::TCGETS2 as _, &mut t) != 0 {
                return Err(SerialError::Config(errno()));
            }
            t.c_iflag &= !(libc::IGNBRK
                | libc::BRKINT
                | libc::IGNPAR
                | libc::PARMRK
                | libc::INPCK
                | libc::ISTRIP
                | libc::INLCR
                | libc::IGNCR
                | libc::ICRNL
                | libc::IXON);
            t.c_oflag &= !libc::OPOST;
            t.c_cflag &= !(libc::CSIZE | libc::PARENB | libc::CSTOPB | libc::CRTSCTS);
            t.c_cflag |= libc::CS8 | libc::CREAD | libc::CLOCAL | libc::BOTHER;
            t.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
            t.c_cc[libc::VMIN] = 0;
            t.c_cc[libc::VTIME] = 0;
            t.c_ispeed = RCP_BAUD;
            t.c_ospeed = RCP_BAUD;
            if libc::ioctl(self.fd(), libc::TCSETS2 as _, &t) != 0 {
                return Err(SerialError::Config(errno()));
            }
            // Flush stale line noise from a previous session so the
            // first handshake starts clean.
            libc::tcflush(self.fd(), libc::TCIOFLUSH);
        }
        Ok(())
    }

    /// Assert (`true`) or clear (`false`) DTR on the port.
    pub fn set_dtr(&self, assert: bool) -> Result<(), SerialError> {
        // SAFETY: fd is live; TIOCMBIS/BIC take an `int` by pointer
        // that the kernel reads once. No allocation, no aliasing.
        unsafe {
            let mut bit: libc::c_int = libc::TIOCM_DTR;
            let req = if assert {
                libc::TIOCMBIS
            } else {
                libc::TIOCMBIC
            };
            if libc::ioctl(self.fd(), req as _, &mut bit) != 0 {
                return Err(SerialError::Io(errno()));
            }
        }
        Ok(())
    }

    /// Drop DTR for [`DTR_HOLD_MS`], then re-assert: reboots an RCP
    /// unit whose EN strap follows DTR into its firmware without
    /// touching BOOT selection. No-op error policy: the caller logs
    /// and falls back to `esptool` on failure.
    pub fn pulse_dtr(&self) -> Result<(), SerialError> {
        self.set_dtr(false)?;
        std::thread::sleep(std::time::Duration::from_millis(DTR_HOLD_MS));
        self.set_dtr(true)
    }
}

impl Uart for SerialUart {
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), RcpError> {
        use std::io::Write as _;
        // SAFETY-free path: `File::write` handles EINTR internally
        // per std's contract; `WouldBlock` on our O_NONBLOCK fd is
        // backpressure, mapped to `UartFull` (never silent loss).
        let mut written = 0;
        while written < bytes.len() {
            match self.file.write(&bytes[written..]) {
                Ok(0) => return Err(RcpError::UartFull),
                Ok(n) => written += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(RcpError::UartFull);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(RcpError::UartFull),
            }
        }
        Ok(())
    }

    fn read_byte(&mut self) -> Option<u8> {
        use std::io::Read as _;
        if self.read_pos >= self.read_len {
            match self.file.read(&mut self.read_buf) {
                Ok(0) | Err(_) => return None,
                Ok(n) => {
                    self.read_pos = 0;
                    self.read_len = n;
                }
            }
        }
        let b = self.read_buf[self.read_pos];
        self.read_pos += 1;
        Some(b)
    }
}

fn errno() -> libc::c_int {
    // SAFETY: `__errno_location` returns a thread-local pointer the
    // libc owns; reading the int is the documented errno contract.
    unsafe { *libc::__errno_location() }
}
