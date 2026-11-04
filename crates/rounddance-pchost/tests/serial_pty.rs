//! Serial backend proof over a real OS serial pair (pty).
//!
//! `SerialUart` opens the replica end at the pinned 460800 8N1 raw
//! rate; RCP bytes written on the controller fd decode on the
//! `SerialUart` side and vice versa — the same shape as
//! `rounddance-ifc`'s `serial_pair` conformance. DTR is attempted
//! but not asserted (pty slaves may refuse modem ioctls; real
//! hardware is the DTR leg, exercised by the `rd-pchost` runbook).

use rounddance_pchost::serial::{SerialUart, RCP_BAUD};
use rounddance_rcp::{frame, Command, Event, HostSide, Uart};
use std::ffi::CStr;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;

/// Open a pty pair; return (controller File, replica path). The
/// controller end is non-blocking (fcntl), so tests poll it.
fn open_pty_pair() -> (std::fs::File, String) {
    let mut ctl: libc::c_int = -1;
    let mut rep: libc::c_int = -1;
    // SAFETY: openpty fills both fds on success; checked below.
    let rc = unsafe {
        libc::openpty(
            &mut ctl,
            &mut rep,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0, "openpty failed");
    assert!(ctl >= 0 && rep >= 0);
    // SAFETY: fd is live; close the replica fd — `SerialUart` opens
    // the same node by path below (like a real /dev/ttyUSBx).
    unsafe {
        libc::close(rep);
    }
    // Reentrant slave name (libc::ptsname uses a static buffer and
    // races when tests run in parallel threads).
    let mut name = [0 as libc::c_char; 64];
    // SAFETY: `name` is a live exclusive buffer of known length.
    let rc = unsafe { libc::ptsname_r(ctl, name.as_mut_ptr(), name.len()) };
    assert_eq!(rc, 0, "ptsname_r failed");
    // SAFETY: ptsname_r NUL-terminated `name` on success.
    let path = unsafe { CStr::from_ptr(name.as_ptr()).to_string_lossy().into_owned() };
    // SAFETY: fd is open and uniquely owned; the File closes it.
    let ctl_file = unsafe { std::fs::File::from_raw_fd(ctl) };
    // SAFETY: F_GETFL/F_SETFL on a live fd with O_NONBLOCK OR'd in;
    // no aliasing (we own the fd).
    unsafe {
        use std::os::fd::AsRawFd as _;
        let flags = libc::fcntl(ctl_file.as_raw_fd(), libc::F_GETFL);
        assert!(flags >= 0, "fcntl F_GETFL failed");
        assert_eq!(
            libc::fcntl(
                ctl_file.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK
            ),
            0,
            "fcntl F_SETFL failed"
        );
    }
    (ctl_file, path)
}

#[test]
fn serial_uart_crosses_pty_both_ways() {
    let (mut ctl, path) = open_pty_pair();
    let mut uart = SerialUart::open(&path, RCP_BAUD).expect("pty opens at RCP rate");

    // Controller -> SerialUart: a framed command decodes byte-wise.
    let mut wire = [0u8; 64];
    let n = Command::SetChannel { channel: 15 }
        .encode(0x09, &mut wire)
        .unwrap();
    ctl.write_all(&wire[..n]).expect("pty write");
    ctl.flush().expect("pty flush");
    let mut dec = frame::Decoder::new();
    let mut seen = None;
    for _ in 0..10_000 {
        if let Some(b) = uart.read_byte() {
            if let Some(o) = dec.push_byte(b) {
                seen = Some(o);
                break;
            }
        } else {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    match seen {
        Some(frame::Outcome::Frame(f)) => {
            assert_eq!(
                &Command::decode(&f).unwrap(),
                &Command::SetChannel { channel: 15 }
            );
        }
        other => panic!("expected frame, got {other:?}"),
    }

    // SerialUart -> controller: an event frame arrives intact.
    let mut ev_wire = [0u8; 64];
    let m = Event::Ready { fw_version: 1 }
        .encode(0x00, &mut ev_wire)
        .unwrap();
    // Feed the event bytes through a HostSide peer model the same
    // way the driver would emit them, then re-emit via SerialUart.
    let mut host = HostSide::new();
    host.write_bytes(&ev_wire[..m]).unwrap();
    while let Some(b) = host.outbound.pop() {
        uart.write_bytes(&[b]).unwrap();
    }
    let mut got = [0u8; 64];
    let mut total = 0;
    for _ in 0..10_000 {
        let mut one = [0u8; 1];
        match ctl.read(&mut one) {
            Ok(1) => {
                got[total] = one[0];
                total += 1;
                if total >= m {
                    break;
                }
            }
            _ => std::thread::sleep(std::time::Duration::from_millis(1)),
        }
    }
    assert_eq!(total, m, "event frame crossed the pty");
    assert_eq!(&got[..m], &ev_wire[..m]);

    // DTR must not panic; pty slaves may refuse the ioctl (then the
    // error is reported, never hidden).
    let _ = uart.set_dtr(true);
    let _ = uart.set_dtr(false);
}

#[test]
fn serial_uart_refuses_wrong_baud() {
    let (_ctl, path) = open_pty_pair();
    assert!(SerialUart::open(&path, 115_200).is_err());
    assert!(SerialUart::open(&path, 0).is_err());
}
