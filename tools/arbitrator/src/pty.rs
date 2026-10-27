//! PTY helpers for hardware-free integration tests.
//!
//! A pty pair stands in for a serial port: the test writes on the
//! controller side and the code under test reads the replica path, or vice
//! versa. Production code paths take plain `Read`/`Write`/path arguments,
//! so loopback tests exercise the real capture logic with zero hardware.
//!
//! SAFETY: `openpty` fills two fds on success; both are owned from that
//! point (closed exactly once via `File::from_raw_fd`). The replica name
//! is read from `/proc/self/fd` before our replica copy closes; the open
//! controller keeps the path valid afterwards.

use std::fs::File;
use std::io;
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;

/// One side of a pty pair: the controller `File` plus the replica path.
/// Open the replica with read+write (`OpenOptions`) for bidirectional use;
/// plain `File::open` is read-only and writes will fail with EBADF.
pub struct PtyPair {
    pub controller: File,
    pub replica_path: PathBuf,
}

/// Open a new pty pair.
pub fn open_pty_pair() -> io::Result<PtyPair> {
    let mut controller_fd = -1;
    let mut replica_fd = -1;
    // SAFETY: openpty writes both fds on return 0; see module docs.
    let rc = unsafe {
        libc::openpty(
            &mut controller_fd,
            &mut replica_fd,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // Raw mode on the replica so the pair behaves like a serial port
    // (no canonical line buffering, no NL translation).
    // SAFETY: fds are open; termios calls only touch our own replica fd.
    unsafe {
        let mut tio: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(replica_fd, &mut tio) == 0 {
            libc::cfmakeraw(&mut tio);
            libc::tcsetattr(replica_fd, libc::TCSANOW, &tio);
        }
    }
    // Replica name via /proc/self/fd (robust where ptsname() fails).
    let replica_path: PathBuf = {
        let link = format!("/proc/self/fd/{replica_fd}");
        match std::fs::read_link(&link) {
            Ok(p) => p,
            Err(e) => {
                // SAFETY: fds are open and uniquely owned; close both.
                unsafe {
                    let _ = File::from_raw_fd(controller_fd);
                    let _ = File::from_raw_fd(replica_fd);
                }
                return Err(e);
            }
        }
    };
    // SAFETY: replica fd is open and owned; close our copy via File drop.
    // The controller keeps the pair alive, so the path stays valid.
    unsafe {
        let _ = File::from_raw_fd(replica_fd);
    }
    // SAFETY: controller_fd is open and transferred exactly once.
    let controller = unsafe { File::from_raw_fd(controller_fd) };
    Ok(PtyPair {
        controller,
        replica_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn pty_loopback_both_directions() {
        let mut pair = open_pty_pair().unwrap();
        // Controller -> replica.
        pair.controller.write_all(b"ping").unwrap();
        let mut replica = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pair.replica_path)
            .unwrap();
        let mut buf = [0u8; 4];
        replica.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        // Replica -> controller.
        replica.write_all(b"pong").unwrap();
        let mut back = [0u8; 4];
        pair.controller.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"pong");
    }
}
