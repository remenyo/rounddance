//! Conformance: the same envelope over a real serial pair (pty).
//!
//! Requirement: the framed byte stream from `frame.rs` crosses a true
//! OS serial pair — bytes written on the controller fd decode on the
//! replica fd — so framing bugs that a `Vec` loopback would hide
//! (partial reads, escape handling across read boundaries) fail here.
//! Uses `libc::openpty` + raw mode; no hardware, no network.

use rounddance_ifc::{
    envelope::{Envelope, Payload},
    frame::{encode_frame, FrameDecoder, MAX_STUFFED},
    ids::IF_MGMT_AGENT,
};
use std::io::{Read, Write};
use std::os::fd::FromRawFd;

fn sample(seq: u16, payload: &[u8]) -> Envelope {
    Envelope {
        version: 0,
        if_id: IF_MGMT_AGENT,
        op: 0x20,
        seq,
        flags: 0,
        payload: Payload::from_slice(payload).unwrap(),
    }
}

/// Open a pty pair, both ends in raw mode with a 2 s read timeout.
fn open_raw_pair() -> (std::fs::File, std::fs::File) {
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
    for &fd in &[ctl, rep] {
        // SAFETY: fd is a live pty end we just opened.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(fd, &mut t), 0);
            libc::cfmakeraw(&mut t);
            // Byte-at-a-time reads with a 2 s timeout (VTIME in 0.1 s).
            t.c_cc[libc::VMIN] = 0;
            t.c_cc[libc::VTIME] = 20;
            assert_eq!(libc::tcsetattr(fd, libc::TCSANOW, &t), 0);
        }
    }
    // SAFETY: fds are open and uniquely owned; each File closes one.
    unsafe {
        (
            std::fs::File::from_raw_fd(ctl),
            std::fs::File::from_raw_fd(rep),
        )
    }
}

/// Push bytes from `reader` into `decoder` until one frame completes.
fn read_one_frame(reader: &mut std::fs::File, decoder: &mut FrameDecoder) -> usize {
    let mut byte = [0u8; 1];
    for _ in 0..10_000 {
        let n = reader.read(&mut byte).expect("pty read");
        assert!(n > 0, "pty read timed out before frame completed");
        if let Some(k) = decoder.push(byte[0]).expect("frame decode") {
            return k;
        }
    }
    panic!("frame never completed after 10k bytes");
}

#[test]
fn framed_envelope_crosses_pty_both_ways() {
    let (mut ctl, mut rep) = open_raw_pair();

    // Controller -> replica, one byte per read on the far end.
    let out = sample(11, b"over-the-wire");
    let mut cbor = [0u8; 600];
    let n = out.encode(&mut cbor).unwrap();
    let mut wire = [0u8; MAX_STUFFED];
    let m = encode_frame(&cbor[..n], &mut wire).unwrap();
    ctl.write_all(&wire[..m]).expect("pty write");
    let mut dec = FrameDecoder::new();
    read_one_frame(&mut rep, &mut dec);
    assert_eq!(Envelope::decode(dec.body()).unwrap(), out);

    // Replica -> controller.
    let back = sample(12, b"ack-path");
    let n = back.encode(&mut cbor).unwrap();
    let m = encode_frame(&cbor[..n], &mut wire).unwrap();
    rep.write_all(&wire[..m]).expect("pty write");
    let mut dec2 = FrameDecoder::new();
    read_one_frame(&mut ctl, &mut dec2);
    assert_eq!(Envelope::decode(dec2.body()).unwrap(), back);
}

#[test]
fn pty_resyncs_after_line_noise() {
    let (mut ctl, mut rep) = open_raw_pair();
    // Inject raw noise (including stray flags/escapes), then a frame.
    ctl.write_all(&[0x00, 0x7E, 0x7D, 0xFF, 0x7E])
        .expect("pty write");
    let out = sample(13, b"after-noise");
    let mut cbor = [0u8; 600];
    let n = out.encode(&mut cbor).unwrap();
    let mut wire = [0u8; MAX_STUFFED];
    let m = encode_frame(&cbor[..n], &mut wire).unwrap();
    ctl.write_all(&wire[..m]).expect("pty write");

    // Drain: noise frames error out, the real frame completes.
    let mut dec = FrameDecoder::new();
    let mut byte = [0u8; 1];
    let mut found = false;
    for _ in 0..10_000 {
        let n = rep.read(&mut byte).expect("pty read");
        assert!(n > 0, "timed out waiting for post-noise frame");
        match dec.push(byte[0]) {
            Ok(Some(_)) => {
                found = true;
                break;
            }
            Ok(None) => {}
            Err(_) => {}
        }
    }
    assert!(found, "no frame decoded after noise");
    assert_eq!(Envelope::decode(dec.body()).unwrap(), out);
}
