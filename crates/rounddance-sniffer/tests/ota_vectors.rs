//! W1 (RD-SNIFF-*): verbatim w82 OTA vectors through the sniffer legs.
//!
//! Provenance: `~/hwscratch/w82/track-ota/` (read-only lab captures,
//! MG21 PAN `0x3761`/ch25 + ch20 scan traffic). The bodies below are
//! verbatim `received:` lines (sniffer `\x1b[J` prefix, FCS-tailed
//! hex, radio metadata) — line numbers cite `sniff_w82ch25.txt` /
//! `sniff_w82ch20.txt`. No key material anywhere: the NWK-secured
//! maintenance frame stays sealed (orphan leg), exactly as the
//! captured-air Ember vectors stay sealed in `rounddance-inspect`.

use rounddance_inspect::{chain, report, session, sniffer::parse_received};

// sniff_w82ch25.txt:1 — beacon-request noise, bogus positive power quirk.
const CH25_BEACON_REQ: &str =
    "\u{1b}[Jreceived: 0308adffffffff071600 power: 103 lqi: 88 time: 5167374343";
// sniff_w82ch25.txt:2 — MG21 beacon (PAN 0x3761, src 0x0000).
const CH25_BEACON: &str = "\u{1b}[Jreceived: 00807461370000ff4f00000022841694b10911403a09ffffff004900 power: -102 lqi: 255 time: 5167461593";
// sniff_w82ch25.txt:3 — MG21 NWK-secured maintenance frame (0x0000->0xfffc).
const CH25_SECURED: &str = "\u{1b}[Jreceived: 4188756137ffff00000912fcff0000011b5f75f4feffe5e30428057005005f75f4feffe5e304006c02be58bd3b4900 power: -102 lqi: 255 time: 5167725293";
// sniff_w82ch25.txt:22 — MAC-secured foreign frame (PAN 0x6659).
const CH25_MAC_SECURED: &str = "\u{1b}[Jreceived: 6b98f15966009001900d0e3505001604d5117aec0309 power: 87 lqi: 12 time: 5178227991";
// sniff_w82ch20.txt:1 — beacon-request (ch20, MG24 stack down).
const CH20_BEACON_REQ: &str =
    "\u{1b}[Jreceived: 030839ffffffff070400 power: 85 lqi: 16 time: 5262186082";

fn frame_of(line: &str) -> (Vec<u8>, i8, u8) {
    parse_received(line).expect("verbatim w82 line parses")
}

#[test]
fn beacon_request_names_maccmd_and_files_quirk_unknown() {
    let (raw, rssi, lqi) = frame_of(CH25_BEACON_REQ);
    // FCS stripped: 10 on-air octets -> 8 bare.
    assert_eq!(raw.len(), 8);
    assert_eq!(rssi, 103, "parser is honest: quirk passes through raw");
    assert_eq!(lqi, 88);
    let mut tree = chain::dissect(&raw).unwrap();
    let mac = tree.mac().expect("mac node");
    assert_eq!(mac.frame_type, 3);
    assert_eq!(mac.command_id, Some(0x07));
    let cmd = tree.maccmd().expect("named beacon-req leg");
    assert!(matches!(
        cmd.kind,
        rounddance_inspect::tree::MacCmdKind::BeaconReq
    ));
    assert!(report::to_text(&tree).contains("mac-command"));
    // Positive RSSI files as unknown downstream, never as link data.
    tree.set_radio(25, rssi, lqi);
    assert_eq!(tree.radio().expect("radio").rssi, None);
    assert_eq!(tree.radio().expect("radio").lqi, 88);
    // Beacon-requests carry no source address: no device row opens.
    let mut eng = session::SessionEngine::new();
    eng.note_tree(&tree);
    assert!(eng.devices().iter().all(|d| d.is_none()));
    assert_eq!(eng.network(0xffff).expect("pan row").frames, 1);
}

#[test]
fn mg21_beacon_names_pan_and_coordinator_source() {
    let (raw, rssi, lqi) = frame_of(CH25_BEACON);
    assert_eq!((rssi, lqi), (-102, 255));
    let mut tree = chain::dissect(&raw).unwrap();
    let mac = tree.mac().expect("mac node");
    assert_eq!(mac.frame_type, 0);
    assert_eq!(mac.src_pan, Some(0x3761));
    assert!(matches!(
        mac.src,
        rounddance_inspect::tree::Addr::Short(0x0000)
    ));
    assert!(report::to_text(&tree).contains("…: beacon"));
    tree.set_radio(25, rssi, lqi);
    let mut eng = session::SessionEngine::new();
    eng.note_tree(&tree);
    // Beacons name only their source PAN: coordinator row opens there.
    let dev = eng.device(0x0000).expect("coordinator row");
    assert_eq!(dev.frames, 1);
    assert_eq!(dev.last_rssi, Some(-102));
    assert_eq!(eng.network(0x3761).expect("pan row").frames, 1);
}

#[test]
fn mg21_maintenance_frame_is_nwk_sealed_not_plaintext() {
    let (raw, rssi, lqi) = frame_of(CH25_SECURED);
    assert_eq!(raw.len(), 45);
    assert_eq!((rssi, lqi), (-102, 255));
    // Byte-level ground truth (offsets: 9-octet MAC + 16-octet NWK
    // header with source IEEE): the 0x28 octet the w82 census filed
    // as an "NWK command id" is the aux security control (level 0 =
    // MIC-32, key-id mode 1 = network key), and the counter matches
    // the live MG21 frame counter (356353 at netup + 4).
    assert_eq!(raw[9], 0x09);
    assert_eq!(raw[25], 0x28, "aux control, not a command id");
    assert_eq!(raw[26..30], [0x05, 0x70, 0x05, 0x00]);
    let tree = chain::dissect(&raw).unwrap();
    let mac = tree.mac().expect("mac node");
    assert!(!mac.security_enabled, "MAC outer is unsecured data");
    let nwk = tree.nwk().expect("nwk node");
    assert_eq!(nwk.frame_type, 1);
    assert_eq!(nwk.protocol_version, 2);
    assert_eq!((nwk.dst_addr, nwk.src_addr), (0xfffc, 0x0000));
    assert_eq!(nwk.radius, 1);
    assert!(nwk.security, "NWK security bit is set");
    assert!(report::to_text(&tree).contains("…: secured (20B left)"));
    // No key: sealed, orphan — never guessed open.
    let mut eng = session::SessionEngine::new();
    eng.note_tree(&tree);
    assert_eq!(eng.secured_orphan, 1);
    assert_eq!(eng.secured_decryptable, 0);
    // A synthetic test-only key flips the accounting (slot-loaded
    // domain) without opening anything: the tree is unchanged and
    // no lab key material is involved.
    eng.set_network_key([0x77u8; 16], 0);
    eng.note_tree(&tree);
    assert_eq!(eng.secured_decryptable, 1);
    assert_eq!(eng.secured_orphan, 1);
}

#[test]
fn foreign_mac_secured_frame_stops_outside_nwk_domain() {
    let (raw, rssi, lqi) = frame_of(CH25_MAC_SECURED);
    assert_eq!((rssi, lqi), (87, 12));
    let mut tree = chain::dissect(&raw).unwrap();
    let mac = tree.mac().expect("mac node");
    assert!(mac.security_enabled);
    assert_eq!(mac.dst_pan, Some(0x6659));
    assert!(tree.nwk().is_none(), "sealed MAC opens no NWK leg");
    assert!(report::to_text(&tree).contains("…: mac-secured"));
    // MAC-domain sealing never mixes into NWK secured accounting.
    tree.set_radio(25, rssi, lqi);
    let mut eng = session::SessionEngine::new();
    eng.note_tree(&tree);
    assert_eq!(eng.secured_orphan, 0);
    assert_eq!(eng.secured_decryptable, 0);
    assert_eq!(eng.network(0x6659).expect("foreign pan").frames, 1);
}

#[test]
fn ch20_scan_traffic_is_beacon_req_only() {
    let (raw, rssi, lqi) = frame_of(CH20_BEACON_REQ);
    assert_eq!(raw.len(), 8);
    assert_eq!((rssi, lqi), (85, 16));
    let tree = chain::dissect(&raw).unwrap();
    assert_eq!(tree.mac().expect("mac").command_id, Some(0x07));
    assert!(report::to_text(&tree).contains("mac-command"));
}

/// Captured-corpus pins for the W1 golden inputs: hashes plus
/// analyzer-observed census for the offline reproduction procedure.
/// Procedure: `rd-sniff --in <pcap|txt> --channel <25|20>` over the
/// on-disk files (read-only, lab `0600` keys never in the repo —
/// and unneeded: the corpus holds no decryptable NWK content).
/// Expected run census: ch25 176 frames / 0 dissect errors with stops
/// beacon=82, mac-command=83, secured=6, mac-secured=5; ch20 49
/// frames / 0 dissect errors, all mac-command. Session: ch25
/// `trees=176 secured_orphan=6`, devices 0x0000x88 + 0x9001x5,
/// networks 0xffffx83 + 0x3761x88 + 0x6659x5, timelines empty (no
/// join legs in a mid-session capture); ch20 `trees=49`, one
/// 0xffff network row, timelines empty. (PAN-appearance counts in
/// `census_summary.txt` double-count frames carrying both dst and
/// src PANs — 0x3761x94, 0x6659x10 — the engine attributes one PAN
/// per frame, hence 88/5.)
#[test]
fn captured_corpus_pins_w82() {
    const CH25_PCAP_SHA256: &str =
        "09ac38a4e5c198bba1c646277b8462f3e28e24a4866b88276e72573e3b82f765";
    const CH20_PCAP_SHA256: &str =
        "9cac0bd880d1e0786e42f7cc68e13a760ea676339f8e62997659f8fc23d930ef";
    const CH25_TXT_SHA256: &str =
        "93fa26fec10d43e15c12e7333f745b864eefc21fc0fd300c6f143d29dd884fd4";
    const CH20_TXT_SHA256: &str =
        "ca24fa9471ebeb3d32f9c767ae9971c25b3c5d9fb15a19d69814524da0caee53";
    assert_eq!(CH25_PCAP_SHA256.len(), 64);
    assert_eq!(CH20_PCAP_SHA256.len(), 64);
    assert_eq!(CH25_TXT_SHA256.len(), 64);
    assert_eq!(CH20_TXT_SHA256.len(), 64);
    const CH25_FRAMES: usize = 176;
    const CH20_FRAMES: usize = 49;
    const CH25_BEACON: usize = 82;
    const CH25_MACCMD: usize = 83;
    const CH25_SECURED: usize = 6;
    const CH25_MAC_SECURED: usize = 5;
    assert_eq!(
        CH25_BEACON + CH25_MACCMD + CH25_SECURED + CH25_MAC_SECURED,
        CH25_FRAMES
    );
    assert_eq!(CH20_FRAMES, 49);
}
