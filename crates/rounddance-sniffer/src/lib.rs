//! Offline 802.15.4 sniffer (wave 1): file input → dissect → report.
//!
//! This crate is a thin host-side app over the
//! [`rounddance-inspect`](rounddance_inspect) dissector chain — it
//! owns no codecs and changes no dissectors. Every capture mode
//! funnels through one of two paths that share the same dissect and
//! fold legs:
//!
//! * [`run::run_listener`] — any
//!   [`Listener`](rounddance_inspect::capture::Listener) backend
//!   (offline: [`ReplayListener`](rounddance_inspect::sniffer::ReplayListener)
//!   over a saved `sniff_*.txt` feed; live backends later);
//! * [`run::run_packets`] — classic pcap / pcapng file input via
//!   [`pcap`](rounddance_inspect::pcap) (the w82 ch25/ch20 captures
//!   are the golden inputs).
//!
//! Both legs dissect with
//! [`dissect_with_keys`](rounddance_inspect::chain::dissect_with_keys),
//! attach radio metadata, and fold into one
//! [`SessionEngine`](rounddance_inspect::session::SessionEngine).
//! [`run::run_stream`] replays raw wire bytes through the
//! [`Ingest`](rounddance_inspect::stream::Ingest) byte pipe so the
//! live == replay invariant (Listener path vs streamed path produce
//! byte-identical trees and sessions) is testable offline.
//! [`run::run_radio_packets`] replays radio-header pcap records, so a
//! live run's radio pcap re-ingested with the same tag/lease/keys
//! renders byte-identical reports (live == file conformance).
//!
//! Outputs: per-frame text/JSON reports plus the session v2 snapshot
//! ([`session_to_json_v2`](rounddance_inspect::report::session_to_json_v2),
//! v1 bytes frozen as its prefix), and pcap-out in two link types —
//! the untouched 195 writer and the radio-header variant ([`radio`]).
//! Per-run worker lease IDs are pure derivations ([`lease`]): no
//! arbitrator calls from the library. Live capture ([`live`]) opens
//! the lab nRF sniffer over serial (passive RX only, channel-gated,
//! Drop parks the hardware); the `rd-sniff` binary holds the real
//! arbitrator port lease around the run.
//!
//! The decode path (dissect + fold) is the `no_std` +
//! `#![forbid(unsafe_code)]` core of `rounddance-inspect`; the
//! [`lease`] and [`radio`] modules keep that discipline here, while
//! [`run`], [`live`], and the `rd-sniff` binary are host-side (`std`)
//! file and serial IO (the raw termios driver, which needs `unsafe`,
//! lives in the binary — the library stays `forbid(unsafe_code)`).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub mod lease;
pub mod radio;

#[cfg(feature = "std")]
pub mod live;

#[cfg(feature = "std")]
pub mod run;
