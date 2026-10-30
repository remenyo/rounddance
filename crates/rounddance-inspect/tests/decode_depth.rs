//! Wave-50 leftover reproductions: every carried wave-49 item must fail
//! on the pre-fix dissector before it is closed.
//!
//! Provenance: quirk octets are verbatim wave-49 live frames
//! (`~/hwscratch/w49/r1k.frames.log` f611, 76 octets, bogus-positive
//! rssi +126 — the INS-LIVE-02 class); the ZDO and session legs are
//! codec-built shapes of the live-confirmed classes (analyzer
//! `~/hwscratch/w49/analyze49.py`: `zdo/annce`, `zdo/lqi-rsp`,
//! `nwk/rejoin-req`, ...). The GPDF octets are verbatim wave-51 lane-1
//! air frames (`~/hwscratch/w51/lane1_*.pcap`, linktype 230, GAP-5:
//! every GPDF stops `unknown` — L 84/84, K 84, H2 28). No key material
//! anywhere.

use rounddance_inspect::{chain, report, session, tree};

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn note_reasons(t: &tree::DecodeTree) -> Vec<&'static str> {
    t.layers()
        .iter()
        .flatten()
        .filter_map(|l| match l {
            tree::Layer::Note(n) => Some(n.reason),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Garbage secured-stop quirk x2 (r1 f611 / r2 f293): depth mac+note with
// stop `secured` — a MAC-level sealed outer filed under the NWK-level
// stop name, so keyed-run accounting mixes it with netkey-domain
// misses (the two transport outers).
// ---------------------------------------------------------------------------

/// Verbatim r1 f611: len-76 garbage that parses as a MAC-secured data
/// frame (bogus-positive rssi +126 in the capture log).
const QUIRK_R1_F611: &str = "09d858ffffffff01416619cbc0d79a874215f0010000ffffffffffc676b0cf407e55d2a895b74e83257c801b42721e080b1a1ea1603f46df1109bf8f5664cb498836037b4e476714d5cbd1c8";

#[test]
fn repro_garbage_mac_secured_stop_is_ambiguous() {
    let tree = chain::dissect(&hex(QUIRK_R1_F611)).unwrap();
    let m = tree.mac().expect("mac node");
    assert!(m.security_enabled, "quirk outer is MAC-sealed");
    assert!(tree.nwk().is_none(), "no NWK header under a MAC seal");
    // Required: the stop names the MAC layer, not the NWK key domain.
    assert_eq!(note_reasons(&tree), vec!["mac-secured"]);
}

// ---------------------------------------------------------------------------
// INS-DEC-02: a verified-open tree folded into an engine with no loaded
// key still counts `secured_orphan` — session accounting doesn't see
// tree legs (keyed runs: decryptable 0 / orphan 54-95 despite 47-95
// verified opens).
// ---------------------------------------------------------------------------

/// Minimal synthetic seal/open: MAC + secured NWK data sealing a tiny
/// APS payload under a test-only key (never a lab key).
fn sealed_frame(key: &[u8; 16]) -> Vec<u8> {
    use rounddance_security::encrypt_block_aes128;
    let ext = [0x5fu8, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04];
    let ctr = 0x0000_4004u32;
    let pt = [0x00u8, 0x02, 0x06, 0x00, 0x04, 0x01, 0x01, 0x07];
    let mut aux = vec![0x28u8];
    aux.extend_from_slice(&ctr.to_le_bytes());
    aux.extend_from_slice(&ext);
    aux.push(0);
    let mut nonce = [0u8; 13];
    nonce[..8].copy_from_slice(&ext);
    nonce[8..12].copy_from_slice(&ctr.to_le_bytes());
    nonce[12] = 0x2d;
    let mut fc = rounddance_nwk::frame::FrameControl::data();
    fc.security = true;
    let nwk = rounddance_nwk::frame::NwkHeader::minimal(fc, 0x5678, 0x1234, 30, 0x09);
    let mut nwk_buf = [0u8; 64];
    let nn = nwk.encode_into(&[], &mut nwk_buf).unwrap();
    let mut aad = nwk_buf[..nn].to_vec();
    aad.push(0x2d);
    aad.extend_from_slice(&aux[1..]);
    let ks = |c: u32| -> [u8; 16] {
        let mut blk = [0u8; 16];
        blk[0] = 0x01;
        blk[1..14].copy_from_slice(&nonce);
        blk[14..16].copy_from_slice(&(c as u16).to_be_bytes());
        encrypt_block_aes128(key, &blk)
    };
    let mut ct = vec![0u8; pt.len()];
    for (i, chunk) in pt.chunks(16).enumerate() {
        let k = ks(1 + i as u32);
        for (j, b) in chunk.iter().enumerate() {
            ct[i * 16 + j] = b ^ k[j];
        }
    }
    let mut b0 = [0u8; 16];
    b0[0] = 0x40 | 0x08 | 0x01;
    b0[1..14].copy_from_slice(&nonce);
    b0[14..16].copy_from_slice(&(pt.len() as u16).to_be_bytes());
    let mut mac_in = Vec::new();
    mac_in.extend_from_slice(&(aad.len() as u16).to_be_bytes());
    mac_in.extend_from_slice(&aad);
    while mac_in.len() % 16 != 0 {
        mac_in.push(0);
    }
    mac_in.extend_from_slice(&pt);
    while mac_in.len() % 16 != 0 {
        mac_in.push(0);
    }
    let mut x = encrypt_block_aes128(key, &b0);
    for blk in mac_in.chunks(16) {
        let mut mix = [0u8; 16];
        for (i, b) in blk.iter().enumerate() {
            mix[i] = x[i] ^ b;
        }
        x = encrypt_block_aes128(key, &mix);
    }
    let s0 = ks(0);
    for i in 0..4 {
        ct.push(x[i] ^ s0[i]);
    }
    let mut frame = vec![0x41, 0x88, 0x5a];
    frame.extend_from_slice(&0x3761u16.to_le_bytes());
    frame.extend_from_slice(&0x5678u16.to_le_bytes());
    frame.extend_from_slice(&0x1234u16.to_le_bytes());
    frame.extend_from_slice(&nwk_buf[..nn]);
    frame.extend_from_slice(&aux);
    frame.extend_from_slice(&ct);
    frame
}

#[test]
fn repro_verified_open_tree_counts_decryptable_without_engine_key() {
    let key = [0x77u8; 16];
    let frame = sealed_frame(&key);
    // Keys reach the dissector only (as in the keyed-glue path); the
    // session engine itself never loads one.
    let mut ks = rounddance_inspect::keys::KeySlots::new();
    ks.set_network_key(key, 0);
    let tree = chain::dissect_with_keys(&frame, &ks).unwrap();
    assert_eq!(note_reasons(&tree)[0], "decrypted");
    let mut eng = session::SessionEngine::new();
    assert_eq!(eng.keys().loaded(), 0, "engine holds no key");
    eng.note_tree(&tree);
    // Required: the verified-open leg counts as decryptable even
    // though no key slot is loaded in the engine.
    assert_eq!(eng.secured_decryptable, 1);
    assert_eq!(eng.secured_orphan, 0);
}

// ---------------------------------------------------------------------------
// INS-DEC-01: a decrypted (here: plain-built) ZDO payload — APS profile
// 0x0000, cluster 0x8031 — is fed to the ZCL dissector instead of a ZDO
// one (`zcl: ... profile=0x0000 cluster=0x8031 unknown cmd`, 4/run).
// ---------------------------------------------------------------------------

/// Wrap an APS data payload (profile 0x0000) in NWK + MAC.
fn wrap_aps_data(profile: u16, cluster: u16, payload: &[u8]) -> Vec<u8> {
    let aps = rounddance_aps::frame::DataHeader {
        control: rounddance_aps::frame::FrameControl::data(
            rounddance_aps::frame::DeliveryMode::Unicast,
        ),
        dest: rounddance_aps::frame::DataDest::Unicast { dst_endpoint: 0 },
        cluster_id: cluster,
        profile_id: profile,
        src_endpoint: 0,
        counter: 0x02,
        ext: None,
    };
    let mut aps_buf = [0u8; 64];
    let an = aps.encode_into(payload, &mut aps_buf).unwrap();
    let nwk = rounddance_nwk::frame::NwkHeader::minimal(
        rounddance_nwk::frame::FrameControl::data(),
        0x0000,
        0x56cb,
        1,
        0x65,
    );
    let mut nwk_buf = [0u8; 128];
    let nn = nwk.encode_into(&aps_buf[..an], &mut nwk_buf).unwrap();
    let mut frame = vec![0x41, 0x88, 0x61];
    frame.extend_from_slice(&0x3761u16.to_le_bytes());
    frame.extend_from_slice(&0x0000u16.to_le_bytes());
    frame.extend_from_slice(&0x56cbu16.to_le_bytes());
    frame.extend_from_slice(&nwk_buf[..nn]);
    frame
}

#[test]
fn repro_zdo_payload_never_reaches_zcl() {
    // Live class: Mgmt-LQI response (tsn 0x01, status 0x00, one entry).
    // The leading tsn byte doubles as a plausible ZCL frame-control
    // octet on the pre-fix path (type 1, server->client off) — exactly
    // the live misparse (`zcl: ... cluster=0x8031 unknown cmd`).
    let body = [0x01u8, 0x00, 0x01, 0x00, 0x01, 0x10, 0x69, 0x00, 0x01];
    let tree = wrap_aps_data(0x0000, 0x8031, &body);
    let tree = chain::dissect(&tree).unwrap();
    // Required: profile 0x0000 never produces a ZCL node.
    assert!(tree.zcl().is_none(), "ZDO must not misparse as ZCL");
    let z = tree.zdo().expect("zdo envelope");
    assert_eq!(z.cluster_id, 0x8031);
    assert!(z.is_response);
    assert_eq!(z.tsn, 0x01);
    assert_eq!(z.status, Some(0x00));
    assert_eq!(note_reasons(&tree), Vec::<&'static str>::new());
    let text = report::to_text(&tree);
    assert!(text.contains("zdo:"));
    assert!(text.contains("cluster=0x8031"));
    assert!(text.contains("status=0x00"));
    let json = report::to_json(&tree);
    assert!(json.contains("\"zdo\""));
    assert!(json.contains("\"cluster\":32817"));
}

// ---------------------------------------------------------------------------
// RD-INSPECT-24: NWK command payloads named (gap-4a).
// ---------------------------------------------------------------------------

/// Wrap one NWK command payload in a MAC frame (unsecured).
fn wrap_nwk_command(pt: &[u8], dst: u16, src: u16) -> Vec<u8> {
    let nwk = rounddance_nwk::frame::NwkHeader::minimal(
        rounddance_nwk::frame::FrameControl::command(),
        dst,
        src,
        1,
        0x44,
    );
    assert!(nwk.control.frame_type == rounddance_nwk::frame::FrameType::Command);
    let mut nwk_buf = [0u8; 128];
    let nn = nwk.encode_into(pt, &mut nwk_buf).unwrap();
    let mut frame = vec![0x41, 0x88, 0x60];
    frame.extend_from_slice(&0x3761u16.to_le_bytes());
    frame.extend_from_slice(&dst.to_le_bytes());
    frame.extend_from_slice(&src.to_le_bytes());
    frame.extend_from_slice(&nwk_buf[..nn]);
    frame
}

#[test]
fn nwk_command_legs_name_every_live_shape() {
    use tree::NwkCmdKind as K;
    // Live census (w49 r1/r2/r1b secured + unsecured probes): every
    // (id, len) pair the captures carry.
    let cases: &[(&[u8], u8, K)] = &[
        (&[0x06, 0x8c], 0x06, K::RejoinRequest { capabilities: 0x8c }),
        (
            &[0x07, 0xcb, 0x56, 0x00],
            0x07,
            K::RejoinResponse {
                short_addr: 0x56cb,
                status: 0x00,
            },
        ),
        (&[0x04, 0x00], 0x04, K::Leave { options: 0x00 }),
        (
            &[0x0b, 0x08, 0x00],
            0x0b,
            K::TimeoutRequest {
                arg0: 0x08,
                arg1: 0x00,
            },
        ),
        (
            &[0x0c, 0x00, 0x03],
            0x0c,
            K::TimeoutResponse {
                arg0: 0x00,
                arg1: 0x03,
            },
        ),
    ];
    for (pt, id, kind) in cases {
        let tree = chain::dissect(&wrap_nwk_command(pt, 0x0000, 0x56cb)).unwrap();
        let n = tree.nwk().expect("nwk node");
        assert_eq!(n.frame_type, 1);
        let c = tree.nwkcmd().expect("command leg");
        assert_eq!(c.command_id, *id);
        assert_eq!(c.kind, *kind, "payload {pt:02x?}");
        assert_eq!(c.payload_len, pt.len() as u16);
        // Stop taxonomy never moves for a named leg.
        assert_eq!(note_reasons(&tree), vec!["trailing"]);
        assert!(tree.aps().is_none());
        let text = report::to_text(&tree);
        assert!(text.contains("nwkcmd:"), "payload {pt:02x?}");
    }
    // Link-status via the repo codec: empty list and one entry (both
    // live lengths).
    let mut ls0 = [0u8; 16];
    let l0 = rounddance_nwk::commands::LinkStatus::new(
        rounddance_nwk::commands::LinkStatusOptions {
            first_frame: true,
            last_frame: true,
        },
        &[],
    )
    .unwrap();
    let n0 = l0.encode_into(&mut ls0).unwrap();
    let t0 = chain::dissect(&wrap_nwk_command(&ls0[..n0], 0xfffc, 0x0000)).unwrap();
    assert_eq!(
        t0.nwkcmd().expect("link-status leg").kind,
        K::LinkStatus {
            entries: 0,
            first_neighbor: 0xffff,
        }
    );
    let e = rounddance_nwk::commands::LinkStatusEntry::new(0x6910, 3, 2).unwrap();
    let mut ls1 = [0u8; 16];
    let l1 = rounddance_nwk::commands::LinkStatus::new(
        rounddance_nwk::commands::LinkStatusOptions {
            first_frame: true,
            last_frame: true,
        },
        &[e],
    )
    .unwrap();
    let n1 = l1.encode_into(&mut ls1).unwrap();
    let t1 = chain::dissect(&wrap_nwk_command(&ls1[..n1], 0xfffc, 0x0000)).unwrap();
    assert_eq!(
        t1.nwkcmd().expect("link-status leg").kind,
        K::LinkStatus {
            entries: 1,
            first_neighbor: 0x6910,
        }
    );
    let json = report::to_json(&t1);
    assert!(json.contains("\"nwkcmd\""));
    assert!(json.contains("\"kind\":\"link-status\""));
    // Unmodeled identifier: named `Unknown`, never a guess, same stop.
    let tu = chain::dissect(&wrap_nwk_command(&[0x03, 0xaa], 0x0000, 0x56cb)).unwrap();
    assert_eq!(tu.nwkcmd().expect("unknown leg").kind, K::Unknown);
    assert_eq!(note_reasons(&tu), vec!["trailing"]);
    // Empty command payload: typed refusal path, still `trailing`.
    let te = chain::dissect(&wrap_nwk_command(&[], 0x0000, 0x56cb)).unwrap();
    assert!(te.nwkcmd().is_none());
    assert_eq!(note_reasons(&te), vec!["trailing"]);
}

// ---------------------------------------------------------------------------
// Wave-70 lane 1: NWK network-status (0x03) named. Fixed 4-octet shape
// (status code + LE destination short), length-gated like the
// rejoin/timeout names: no repo codec covers it, so any other length
// stays `Unknown`.
// ---------------------------------------------------------------------------

#[test]
fn nwk_network_status_leg_names_fixed_shape() {
    use tree::NwkCmdKind as K;
    // Status 0x0d (address conflict) against 0x1234.
    let pt = [0x03u8, 0x0d, 0x34, 0x12];
    let tree = chain::dissect(&wrap_nwk_command(&pt, 0x0000, 0x56cb)).unwrap();
    let c = tree.nwkcmd().expect("network-status leg");
    assert_eq!(c.command_id, 0x03);
    assert_eq!(
        c.kind,
        K::NetworkStatus {
            status: 0x0d,
            dst_addr: 0x1234
        }
    );
    assert_eq!(c.payload_len, 4);
    // Stop taxonomy never moves for a named leg.
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
    assert!(tree.aps().is_none());
    let text = report::to_text(&tree);
    assert!(text.contains("nwkcmd:"), "named leg renders: {text}");
    assert!(text.contains("net-status"), "leg kind renders: {text}");
    let json = report::to_json(&tree);
    assert!(json.contains("\"nwkcmd\""), "json leg renders");
    assert!(
        json.contains("\"kind\":\"net-status\""),
        "json kind renders: {json}"
    );
    // Route chatter never opens a session timeline.
    assert!(session::classify_tree(&tree).is_none());
    // Wrong lengths stay `Unknown` under the same stop.
    for bad in [
        &[0x03u8, 0x0d, 0x34][..],
        &[0x03u8, 0x0d, 0x34, 0x12, 0x00][..],
    ] {
        let t = chain::dissect(&wrap_nwk_command(bad, 0x0000, 0x56cb)).unwrap();
        assert_eq!(t.nwkcmd().expect("unknown leg").kind, K::Unknown);
        assert_eq!(note_reasons(&t), vec!["trailing"]);
    }
}

// ---------------------------------------------------------------------------
// Wave-73 lane 2: NWK route record (0x05) named. Relay count + LE relay
// list; the declared count must exactly cover the trailing octets
// (no repo codec covers it), so a count/length mismatch stays
// `Unknown` — the wave-70 network-status length-gate discipline.
// ---------------------------------------------------------------------------

#[test]
fn nwk_route_record_leg_names_relay_list() {
    use tree::NwkCmdKind as K;
    // Two relays: 0x6910 then 0x1234.
    let pt = [0x05u8, 0x02, 0x10, 0x69, 0x34, 0x12];
    let tree = chain::dissect(&wrap_nwk_command(&pt, 0x0000, 0x56cb)).unwrap();
    let c = tree.nwkcmd().expect("route-record leg");
    assert_eq!(c.command_id, 0x05);
    assert_eq!(
        c.kind,
        K::RouteRecord {
            relays: 2,
            first_relay: 0x6910
        }
    );
    assert_eq!(c.payload_len, 6);
    // Stop taxonomy never moves for a named leg.
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
    assert!(tree.aps().is_none());
    let text = report::to_text(&tree);
    assert!(text.contains("nwkcmd:"), "named leg renders: {text}");
    assert!(text.contains("route-rec"), "leg kind renders: {text}");
    let json = report::to_json(&tree);
    assert!(json.contains("\"nwkcmd\""), "json leg renders");
    assert!(
        json.contains("\"kind\":\"route-rec\""),
        "json kind renders: {json}"
    );
    // Route chatter never opens a session timeline.
    assert!(session::classify_tree(&tree).is_none());
    // Empty relay list names the leg with no first hop.
    let empty = chain::dissect(&wrap_nwk_command(&[0x05u8, 0x00], 0x0000, 0x56cb)).unwrap();
    assert_eq!(
        empty.nwkcmd().expect("empty route-record leg").kind,
        K::RouteRecord {
            relays: 0,
            first_relay: 0xffff
        }
    );
    assert_eq!(note_reasons(&empty), vec!["trailing"]);
    // Count/length mismatches stay `Unknown` under the same stop.
    for bad in [
        &[0x05u8][..],
        &[0x05u8, 0x02, 0x10, 0x69][..],
        &[0x05u8, 0x01, 0x10, 0x69, 0x34, 0x12][..],
        &[0x05u8, 0x03, 0x10, 0x69, 0x34, 0x12][..],
    ] {
        let t = chain::dissect(&wrap_nwk_command(bad, 0x0000, 0x56cb)).unwrap();
        assert_eq!(t.nwkcmd().expect("unknown leg").kind, K::Unknown);
        assert_eq!(note_reasons(&t), vec!["trailing"]);
    }
}

// ---------------------------------------------------------------------------
// Wave-74 lane 2: NWK network report (0x09) named. Options count
// (bits 0-4) + 8-octet EPID + LE PAN-ID conflict list; the declared
// count must exactly cover the trailing octets past the EPID, and
// only report-id 0 (PAN-ID conflict) names the leg (no repo codec
// covers it) — the wave-73 route-record count-gate discipline, with
// reserved report ids staying `Unknown`, never a guess.
// ---------------------------------------------------------------------------

#[test]
fn nwk_network_report_leg_names_conflict_list() {
    use tree::NwkCmdKind as K;
    // EPID 01..08, two conflicting PAN IDs: 0x1234 then 0x5678.
    let pt = [
        0x09u8, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x34, 0x12, 0x78, 0x56,
    ];
    let tree = chain::dissect(&wrap_nwk_command(&pt, 0x0000, 0x56cb)).unwrap();
    let c = tree.nwkcmd().expect("network-report leg");
    assert_eq!(c.command_id, 0x09);
    assert_eq!(
        c.kind,
        K::NetworkReport {
            reports: 2,
            first_pan: 0x1234
        }
    );
    assert_eq!(c.payload_len, 14);
    // Stop taxonomy never moves for a named leg.
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
    assert!(tree.aps().is_none());
    let text = report::to_text(&tree);
    assert!(text.contains("nwkcmd:"), "named leg renders: {text}");
    assert!(text.contains("net-report"), "leg kind renders: {text}");
    let json = report::to_json(&tree);
    assert!(json.contains("\"nwkcmd\""), "json leg renders");
    assert!(
        json.contains("\"kind\":\"net-report\""),
        "json kind renders: {json}"
    );
    // Route chatter never opens a session timeline.
    assert!(session::classify_tree(&tree).is_none());
    // Empty conflict list names the leg with no first PAN ID.
    let empty = [0x09u8, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let empty = chain::dissect(&wrap_nwk_command(&empty, 0x0000, 0x56cb)).unwrap();
    assert_eq!(
        empty.nwkcmd().expect("empty network-report leg").kind,
        K::NetworkReport {
            reports: 0,
            first_pan: 0xffff
        }
    );
    assert_eq!(note_reasons(&empty), vec!["trailing"]);
    // Count/length mismatches, short frames, and reserved report
    // ids stay `Unknown` under the same stop.
    let short = [0x09u8, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let over = [
        0x09u8, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x34, 0x12, 0x78, 0x56,
    ];
    let reserved = [0x09u8, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    for bad in [&[0x09u8][..], &short[..], &over[..], &reserved[..]] {
        let t = chain::dissect(&wrap_nwk_command(bad, 0x0000, 0x56cb)).unwrap();
        assert_eq!(t.nwkcmd().expect("unknown leg").kind, K::Unknown);
        assert_eq!(note_reasons(&t), vec!["trailing"]);
    }
}

// ---------------------------------------------------------------------------
// Wave-75 lane 2: NWK network update (0x0a) named. Options count
// (bits 0-4) + 8-octet EPID + update-id octet + LE new-PAN-ID list;
// the declared count must exactly cover the trailing octets past
// the update-id octet, and only update-command-id 0 (PAN-ID
// update) names the leg (no repo codec covers it) — the wave-74
// network-report count-gate discipline, with reserved command
// ids staying `Unknown`, never a guess.
// ---------------------------------------------------------------------------

#[test]
fn nwk_network_update_leg_names_new_pan() {
    use tree::NwkCmdKind as K;
    // EPID 01..08, update id 0x07, one new PAN ID: 0x1234.
    let pt = [
        0x0au8, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x07, 0x34, 0x12,
    ];
    let tree = chain::dissect(&wrap_nwk_command(&pt, 0x0000, 0x56cb)).unwrap();
    let c = tree.nwkcmd().expect("network-update leg");
    assert_eq!(c.command_id, 0x0a);
    assert_eq!(
        c.kind,
        K::NetworkUpdate {
            updates: 1,
            first_pan: 0x1234
        }
    );
    assert_eq!(c.payload_len, 13);
    // Stop taxonomy never moves for a named leg.
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
    assert!(tree.aps().is_none());
    let text = report::to_text(&tree);
    assert!(text.contains("nwkcmd:"), "named leg renders: {text}");
    assert!(text.contains("net-update"), "leg kind renders: {text}");
    let json = report::to_json(&tree);
    assert!(json.contains("\"nwkcmd\""), "json leg renders");
    assert!(
        json.contains("\"kind\":\"net-update\""),
        "json kind renders: {json}"
    );
    // Update chatter never opens a session timeline.
    assert!(session::classify_tree(&tree).is_none());
    // Empty update list names the leg with no first PAN ID.
    let empty = [
        0x0au8, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x07,
    ];
    let empty = chain::dissect(&wrap_nwk_command(&empty, 0x0000, 0x56cb)).unwrap();
    assert_eq!(
        empty.nwkcmd().expect("empty network-update leg").kind,
        K::NetworkUpdate {
            updates: 0,
            first_pan: 0xffff
        }
    );
    assert_eq!(note_reasons(&empty), vec!["trailing"]);
    // Count/length mismatches, short frames, and reserved update
    // ids stay `Unknown` under the same stop.
    let short = [0x0au8, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let over = [
        0x0au8, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x07, 0x34, 0x12,
    ];
    let reserved = [
        0x0au8, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x07,
    ];
    for bad in [&[0x0au8][..], &short[..], &over[..], &reserved[..]] {
        let t = chain::dissect(&wrap_nwk_command(bad, 0x0000, 0x56cb)).unwrap();
        assert_eq!(t.nwkcmd().expect("unknown leg").kind, K::Unknown);
        assert_eq!(note_reasons(&t), vec!["trailing"]);
    }
}

// ---------------------------------------------------------------------------
// RD-INSPECT-25: MAC command payloads named (gap-4b).
// ---------------------------------------------------------------------------

#[test]
fn mac_command_legs_name_every_live_shape() {
    use tree::MacCmdKind as K;
    // Verbatim wave-48 live octets (pinned by RD-INSPECT-19): beacon
    // request, association request, data-request poll, association
    // response.
    let cases: &[(&str, u8, K)] = &[
        ("030816ffffffff07", 0x07, K::BeaconReq),
        (
            "23c84261370000ffffa0f262fffefffe85018c",
            0x01,
            K::AssocReq { capabilities: 0x8c },
        ),
        ("23c84161370000ffffa0f262fffefffe8504", 0x04, K::DataReq),
        (
            "63ccfc6137a0f262fffefffe855f75f4feffe5e30402ffff02",
            0x02,
            K::AssocResp {
                short_addr: 0xffff,
                status: 0x02,
            },
        ),
    ];
    for (raw, cmd, kind) in cases {
        let tree = chain::dissect(&hex(raw)).unwrap();
        let m = tree.nwkcmd();
        assert!(m.is_none(), "no NWK leg on a MAC command frame");
        let c = tree.maccmd().expect("command leg");
        assert_eq!(c.command_id, *cmd, "frame {raw}");
        assert_eq!(c.kind, *kind, "frame {raw}");
        // Stop taxonomy never moves for a named leg.
        assert_eq!(note_reasons(&tree), vec!["mac-command"], "frame {raw}");
    }
    // Verbatim wave-49 orphan + coordinator realignment (r2 f74/f76):
    // the R3 shapes the gap left unnamed.
    let orphan = chain::dissect(&hex("23c843ffffffffffffa0f262fffefffe8506")).unwrap();
    assert_eq!(orphan.maccmd().expect("orphan leg").kind, K::Orphan);
    assert_eq!(note_reasons(&orphan), vec!["mac-command"]);
    let realign = chain::dissect(&hex(
        "23cc5effffa0f262fffefffe8561375f75f4feffe5e3040861370000191069",
    ))
    .unwrap();
    let r = realign.maccmd().expect("realign leg");
    assert_eq!(
        r.kind,
        K::CoordRealign {
            pan: 0x3761,
            coord: 0x0000,
            channel: 25,
            short_addr: 0x6910,
        }
    );
    let text = report::to_text(&realign);
    assert!(text.contains("maccmd:"));
    assert!(text.contains("realign pan=0x3761"));
    assert!(text.contains("short=0x6910"));
    let json = report::to_json(&realign);
    assert!(json.contains("\"maccmd\""));
    assert!(json.contains("\"kind\":\"realign\""));
    // Wrong length on a named id, and an unmodeled id: no layer, the
    // historical stop stands alone.
    let short = chain::dissect(&hex("23c84261370000ffffa0f262fffefffe8501")).unwrap();
    assert!(short.maccmd().is_none(), "dangling assoc-req earns no leg");
    assert_eq!(note_reasons(&short), vec!["mac-command"]);
}

// ---------------------------------------------------------------------------
// RD-INSPECT-26: ZDO envelope (INS-DEC-01 follow-through).
// ---------------------------------------------------------------------------

#[test]
fn zdo_envelope_names_requests_and_responses() {
    // Device-announce class: request direction, no status octet.
    let annce = chain::dissect(&wrap_aps_data(
        0x0000,
        0x0013,
        &[
            0x09, 0xcb, 0x56, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x8c,
        ],
    ))
    .unwrap();
    let z = annce.zdo().expect("zdo leg");
    assert_eq!(z.cluster_id, 0x0013);
    assert!(!z.is_response);
    assert_eq!(z.tsn, 0x09);
    assert_eq!(z.status, None);
    assert!(annce.zcl().is_none());
    // One-octet response: status stays unknown rather than guessed.
    let short = chain::dissect(&wrap_aps_data(0x0000, 0x8031, &[0x05])).unwrap();
    let z = short.zdo().expect("zdo leg");
    assert!(z.is_response);
    assert_eq!(z.status, None);
    // Empty body: no leg, the historical `unknown` stop stands.
    let empty = chain::dissect(&wrap_aps_data(0x0000, 0x8031, &[])).unwrap();
    assert!(empty.zdo().is_none());
    assert_eq!(note_reasons(&empty), vec!["unknown"]);
    // HA profile still reaches ZCL: the routing only diverts 0x0000.
    let ha = wrap_aps_data(0x0104, 0x0006, &[0x00, 0x42, 0x00, 0x00, 0x00]);
    let ha = chain::dissect(&ha).unwrap();
    assert!(ha.zcl().is_some());
    assert!(ha.zdo().is_none());
    // APS-broadcast to endpoint 0x00 (the live Device-annce class:
    // NWK broadcast + APS broadcast mode + ZDO endpoint) stays a
    // typed codec refusal, never a layer: the APS codec cites
    // `05-3474-23-22511-07/08` for refusing broadcast-to-ZDO, so the
    // chain files `unknown` instead of guessing a profile leg.
    let mut bcast = wrap_aps_data(0x0000, 0x0013, &[0x09, 0x00]);
    // Flip the wrapped APS header to broadcast delivery mode
    // (mode bits `10`). Layout: MAC(9) + NWK(8) + APS fc at offset 17.
    bcast[17] = 0x08;
    let bcast = chain::dissect(&bcast).unwrap();
    assert!(bcast.aps().is_none(), "broadcast-to-ZDO refused");
    assert!(bcast.zdo().is_none());
    assert!(bcast.zcl().is_none());
    assert_eq!(note_reasons(&bcast), vec!["unknown"]);
}

// ---------------------------------------------------------------------------
// RD-INSPECT-28: `mac-secured` stop (garbage quirk follow-through).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Wave-51 Touchlink gaps (G1/G2/G3): every inter-PAN shape below is a
// verbatim wave-50 captured frame (`~/hwscratch/w50/c20.pcap`, ch20
// run — the channel whose scan-response transaction bytes parsed as
// a version-5 "NWK" header with full APS/ZCL legs pre-fix).
// Provenance: scan-req f24, scan-rsp f25, start order f129,
// start-rsp f130, join order f131, join-rsp f132. The orders carry
// captured-air wrapped-key ciphertext only (openable solely with
// the lab keys, never embedded); no key bytes anywhere.
// ---------------------------------------------------------------------------

/// c20 f24: scan request, tid 0x3eaa2114 (base + ch20).
const TL_SCAN_REQ: &str = "018800ffffffffffff687f1421aa3e000583";
/// c20 f25: scan response — the pre-fix hallucination shape.
const TL_SCAN_RSP: &str =
    "018800ffffffffffffa4971421aa3e010505831080b12f7688000000000000000000000000ffff0000";
/// c20 f129: network-start order (wrapped-key ciphertext inside).
const TL_START_REQ: &str = "018829ffffffffffff687f0920aa3e1001020304050607080f8322636873a7bb2a189a53708c607bd00f2b1a0100010008000200ff7f0b000c00aaaaaaaaaaaaaaaa0000";
/// c20 f130: network-start response.
const TL_START_RSP: &str = "018829ffffffffffffa4970920aa3e11000102030405060708000f2b1a";
/// c20 f131: network-join order (wrapped-key ciphertext inside).
const TL_JOIN_REQ: &str = "01882bffffffffffff687f0b20aa3e1201020304050607080f626bbe70430702d7b59e95c6524ef953030f2b1a0200010008000200ff7f0b000c00";
/// c20 f132: network-join response.
const TL_JOIN_RSP: &str = "01882bffffffffffffa4970b20aa3e1300";
/// c20 f9: NWK broadcast data — shares the broadcast destination
/// but rides a joined PAN, so it must still reach NWK.
const NWK_BCAST_DATA: &str =
    "4188646437ffff00000912fcff000001d56d4911feff138d3428489000006d4911feff138d340085d855c81933";

/// G1: an inter-PAN MAC outer never enters the NWK dissector.
/// Pre-fix the scan response below dissected as a full
/// `mac+nwk+aps+zcl` tree with an invalid NWK version (5); the
/// scan request stopped `mac+unknown`. Both now file MAC +
/// Touchlink beside the `interpan` stop, with no NWK/APS/ZCL leg.
#[test]
fn repro_inter_pan_never_enters_nwk() {
    for raw in [TL_SCAN_REQ, TL_SCAN_RSP] {
        let tree = chain::dissect(&hex(raw)).unwrap();
        let m = tree.mac().expect("mac node");
        assert_eq!(m.frame_type, 1);
        assert!(!m.security_enabled);
        assert!(tree.touchlink().is_some(), "touchlink leg on {raw}");
        assert!(tree.nwk().is_none(), "no NWK leg on {raw}");
        assert!(tree.aps().is_none(), "no APS leg on {raw}");
        assert!(tree.zcl().is_none(), "no ZCL leg on {raw}");
        assert_eq!(note_reasons(&tree), vec!["interpan"]);
        assert_eq!(tree.len(), 3);
    }
    // Gate boundary: a broadcast-destination data frame on a joined
    // PAN (destination broadcast, PAN real) still routes to NWK —
    // the gate keys on all three PAN/address fields, not the
    // destination alone.
    let bcast = chain::dissect(&hex(NWK_BCAST_DATA)).unwrap();
    assert!(bcast.touchlink().is_none());
    assert!(bcast.nwk().is_some());
}

/// G2: the Touchlink envelope names transaction, command, and the
/// body shape for all six live commands; session attribution still
/// flows from the MAC source with zero secured accounting.
#[test]
fn touchlink_envelope_names_all_six_live_shapes() {
    let scan_req = chain::dissect(&hex(TL_SCAN_REQ)).unwrap();
    let t = scan_req.touchlink().expect("scan-req leg");
    assert_eq!(t.tid, 0x3eaa2114);
    assert_eq!(t.command_id, 0x00);
    assert_eq!(
        t.kind,
        tree::TouchlinkKind::ScanReq {
            zigbee_info: 0x05,
            touchlink_info: 0x83,
        }
    );
    assert_eq!(t.payload_len, 7);

    let scan_rsp = chain::dissect(&hex(TL_SCAN_RSP)).unwrap();
    let t = scan_rsp.touchlink().expect("scan-rsp leg");
    assert_eq!(t.tid, 0x3eaa2114);
    assert_eq!(t.command_id, 0x01);
    assert_eq!(t.kind, tree::TouchlinkKind::ScanRsp { key_mask: 0x8010 });
    assert_eq!(t.payload_len, 30);

    let start_req = chain::dissect(&hex(TL_START_REQ)).unwrap();
    let t = start_req.touchlink().expect("start-req leg");
    assert_eq!(t.tid, 0x3eaa2009);
    assert_eq!(t.command_id, 0x10);
    assert_eq!(t.kind, tree::TouchlinkKind::StartReq { key_index: 0x0f });
    assert_eq!(t.payload_len, 57);

    let start_rsp = chain::dissect(&hex(TL_START_RSP)).unwrap();
    let t = start_rsp.touchlink().expect("start-rsp leg");
    assert_eq!(t.tid, 0x3eaa2009);
    assert_eq!(t.command_id, 0x11);
    assert_eq!(t.kind, tree::TouchlinkKind::StartRsp { status: 0x00 });
    assert_eq!(t.payload_len, 18);

    let join_req = chain::dissect(&hex(TL_JOIN_REQ)).unwrap();
    let t = join_req.touchlink().expect("join-req leg");
    assert_eq!(t.tid, 0x3eaa200b);
    assert_eq!(t.command_id, 0x12);
    assert_eq!(t.kind, tree::TouchlinkKind::JoinReq { key_index: 0x0f });
    assert_eq!(t.payload_len, 48);

    let join_rsp = chain::dissect(&hex(TL_JOIN_RSP)).unwrap();
    let t = join_rsp.touchlink().expect("join-rsp leg");
    assert_eq!(t.tid, 0x3eaa200b);
    assert_eq!(t.command_id, 0x13);
    assert_eq!(t.kind, tree::TouchlinkKind::JoinRsp { status: 0x00 });
    assert_eq!(t.payload_len, 6);

    // Reports name the leg in both renderings; the order bodies
    // render as lengths only (wrapped keys never rendered).
    let text = report::to_text(&scan_rsp);
    assert!(text.contains("touchlink:"));
    assert!(text.contains("scan-rsp"));
    assert!(text.contains("key_mask=0x8010"));
    let json = report::to_json(&start_req);
    assert!(json.contains("\"touchlink\":{\"tid\":"));
    assert!(json.contains("\"kind\":\"start-req\""));
    assert!(json.contains("\"key_index\":15"));

    // Session attribution: MAC source row under the broadcast PAN,
    // no secured accounting (inter-PAN is never NWK-secured).
    let mut eng = session::SessionEngine::new();
    eng.note_tree(&scan_req);
    let dev = eng.device(0x7f68).expect("initiator row");
    assert_eq!(dev.frames, 1);
    assert_eq!(dev.secured, 0);
    let net = eng.network(0xffff).expect("broadcast PAN row");
    assert_eq!(net.frames, 1);
    assert_eq!(net.secured, 0);
    assert_eq!(eng.secured_decryptable, 0);
    assert_eq!(eng.secured_orphan, 0);

    // Edges: a sub-transaction MSDU keeps the stop with no leg; a
    // named command at a wrong length refuses the same way; an
    // unmodeled command files `Unknown` with its identifier.
    let mut short_msdu = hex(TL_SCAN_REQ);
    short_msdu.truncate(11 + 4);
    let short = chain::dissect(&short_msdu).unwrap();
    assert!(short.touchlink().is_none());
    assert_eq!(note_reasons(&short), vec!["interpan"]);
    let mut wrong_len = hex(TL_SCAN_REQ);
    wrong_len.push(0x00);
    let wrong = chain::dissect(&wrong_len).unwrap();
    assert!(wrong.touchlink().is_none());
    assert_eq!(note_reasons(&wrong), vec!["interpan"]);
    let mut unknown_cmd = hex(TL_SCAN_REQ);
    unknown_cmd[11 + 4] = 0x02;
    let unknown = chain::dissect(&unknown_cmd).unwrap();
    let t = unknown.touchlink().expect("unknown-cmd leg");
    assert_eq!(t.command_id, 0x02);
    assert_eq!(t.kind, tree::TouchlinkKind::Unknown);
    assert_eq!(note_reasons(&unknown), vec!["interpan"]);
}

/// G3: the NWK version guard refuses alien versions before any
/// header field is trusted. Pre-fix the crafted frame below filed
/// an NWK leg with version 5 (the ch20 hallucination's first
/// header byte); now the chain stops `mac+unknown` with no NWK
/// leg. The Green-Power value refuses the same way (no GP leg is
/// modeled); the stack version still decodes.
#[test]
fn repro_nwk_version_guard_refuses_ver5() {
    // MAC data on a joined PAN (never the inter-PAN gate) + NWK
    // data header with version 5, then a 2-octet payload.
    let ver5 = hex("4188016137ffff34121400341256781e090000");
    let tree = chain::dissect(&ver5).unwrap();
    assert!(tree.nwk().is_none(), "no NWK leg under version 5");
    assert_eq!(note_reasons(&tree), vec!["unknown"]);
    // Version 3 (Green-Power value): contract evolution in wave 52
    // (RD-INSPECT-32) — the GP leg is now modeled, and these very
    // bytes are a well-formed unsecured GPDF (data, SrcId
    // `0x56123400`, command `0x78`), so the chain names MAC + GP
    // beside `trailing` instead of refusing. Version 5 above still
    // stops `unknown`: no leg exists for it.
    let ver3 = hex("4188016137ffff34120c00341256781e090000");
    let tree3 = chain::dissect(&ver3).unwrap();
    assert!(tree3.nwk().is_none());
    let g3 = tree3.gp().expect("version-3 GP leg");
    assert_eq!(g3.src_id, 0x5612_3400);
    assert_eq!(g3.command_id, Some(0x78));
    assert_eq!(note_reasons(&tree3), vec!["trailing"]);
    // Control: version 2 on the same bytes decodes normally.
    let ver2 = hex("4188016137ffff34120800341256781e090000");
    let ok = chain::dissect(&ver2).unwrap();
    let n = ok.nwk().expect("version-2 NWK leg");
    assert_eq!(n.protocol_version, 2);
}

#[test]
fn mac_secured_stop_stays_out_of_session_secured_counts() {
    let tree = chain::dissect(&hex(QUIRK_R1_F611)).unwrap();
    assert_eq!(note_reasons(&tree), vec!["mac-secured"]);
    let mut eng = session::SessionEngine::new();
    eng.note_tree(&tree);
    assert_eq!(eng.secured_decryptable, 0);
    assert_eq!(eng.secured_orphan, 0, "MAC seal is not a NWK key miss");
    let text = report::to_text(&tree);
    assert!(text.contains("mac-secured"));
    let json = report::to_json(&tree);
    assert!(json.contains("\"reason\":\"mac-secured\""));
}

// ---------------------------------------------------------------------------
// GAP-5 (wave-51 lane 1): Green-Power device frames stop `unknown` —
// no GP leg exists (L 84/84, K 84, H2 28). Both repros compile against
// the HEAD API only (`len` + stop reasons) and must FAIL pre-fix.
// ---------------------------------------------------------------------------

/// Verbatim w51 L data frame: short-dst-only MAC outer + unsecured
/// GPDF data (`20 01`, SrcId `0x517f6811`).
const GPDF_DATA_UNSECURED: &str = "01080f6137ffff8c0011687f512001";

/// Verbatim w51 L data frame: counter-protected GPDF data
/// (`ext 0x30`, counter `0x0f`, `20 01` + MIC), no key slotted.
const GPDF_DATA_MIC_ONLY: &str = "01080c6137ffff8c3011687f510f00000020017a871adc";

#[test]
fn repro_gpdf_data_stops_unknown_without_leg() {
    let tree = chain::dissect(&hex(GPDF_DATA_UNSECURED)).unwrap();
    assert!(tree.mac().is_some(), "MAC outer decodes");
    assert!(tree.nwk().is_none(), "GPDF is not a stack NWK frame");
    // Required: a named GP leg beside a terminal stop, not `unknown`.
    assert_eq!(tree.len(), 3, "MAC + GP leg + stop note");
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
}

#[test]
fn repro_gpdf_secured_stops_secured_not_unknown() {
    let tree = chain::dissect(&hex(GPDF_DATA_MIC_ONLY)).unwrap();
    assert!(tree.mac().is_some(), "MAC outer decodes");
    assert!(tree.nwk().is_none(), "GPDF is not a stack NWK frame");
    // Required: the counter-protected shape files the key-domain
    // stop (`secured`), never the catch-all `unknown`.
    assert_eq!(tree.len(), 3, "MAC + GP leg + stop note");
    assert_eq!(note_reasons(&tree), vec!["secured"]);
}

// ---------------------------------------------------------------------------
// GAP-5 closure (wave 52, RD-INSPECT-32/33): Green-Power decode leg.
// Provenance: every verbatim octet string below is a genuine w51
// lane-1 air frame (`~/hwscratch/w51/lane1_*.pcap`, linktype 230);
// the sealed round trips use a synthetic test-only key, never lab
// key material (wave-49 precedent). One behavior per test.
// ---------------------------------------------------------------------------

/// Synthetic GP test-only key (committed; lab keys stay local-only).
const GP_TEST_KEY: [u8; 16] = [0x5au8; 16];

/// Incoming-nonce bytes for a source-identifier GPD: the identifier
/// repeated, the counter, the fixed control octet.
fn gp_test_nonce(srcid: u32, ctr: u32) -> [u8; 13] {
    let id = srcid.to_le_bytes();
    let c = ctr.to_le_bytes();
    [
        id[0], id[1], id[2], id[3], id[0], id[1], id[2], id[3], c[0], c[1], c[2], c[3], 0x05,
    ]
}

fn gp_test_ks(key: &[u8; 16], nonce: &[u8; 13], ctr: u32) -> [u8; 16] {
    use rounddance_security::encrypt_block_aes128;
    let mut blk = [0u8; 16];
    blk[0] = 0x01;
    blk[1..14].copy_from_slice(nonce);
    blk[14..16].copy_from_slice(&(ctr as u16).to_be_bytes());
    encrypt_block_aes128(key, &blk)
}

/// CCM* integrity word over (`aad_extra`, `msg`) with flags 0x49
/// (associated data present, 4-octet word, 2-octet length).
fn gp_test_tag(key: &[u8; 16], nonce: &[u8; 13], aad_extra: &[u8], msg: &[u8]) -> [u8; 4] {
    use rounddance_security::encrypt_block_aes128;
    let mut b0 = [0u8; 16];
    b0[0] = 0x40 | 0x08 | 0x01;
    b0[1..14].copy_from_slice(nonce);
    b0[14..16].copy_from_slice(&(msg.len() as u16).to_be_bytes());
    let mut mac_in = Vec::new();
    mac_in.extend_from_slice(&(aad_extra.len() as u16).to_be_bytes());
    mac_in.extend_from_slice(aad_extra);
    while mac_in.len() % 16 != 0 {
        mac_in.push(0);
    }
    mac_in.extend_from_slice(msg);
    while mac_in.len() % 16 != 0 {
        mac_in.push(0);
    }
    let mut x = encrypt_block_aes128(key, &b0);
    for blk in mac_in.chunks(16) {
        let mut mix = [0u8; 16];
        for (i, b) in blk.iter().enumerate() {
            mix[i] = x[i] ^ b;
        }
        x = encrypt_block_aes128(key, &mix);
    }
    let s0 = gp_test_ks(key, nonce, 0);
    [x[0] ^ s0[0], x[1] ^ s0[1], x[2] ^ s0[2], x[3] ^ s0[3]]
}

/// Counter-mode seal of one command section (counter from 1).
fn gp_test_ct(key: &[u8; 16], nonce: &[u8; 13], section: &[u8]) -> Vec<u8> {
    let mut ct = vec![0u8; section.len()];
    for (i, chunk) in section.chunks(16).enumerate() {
        let k = gp_test_ks(key, nonce, 1 + i as u32);
        for (j, b) in chunk.iter().enumerate() {
            ct[i * 16 + j] = b ^ k[j];
        }
    }
    ct
}

/// MAC short-dst-only outer (the GPD-originated shape on air) around
/// one GPDF payload.
fn gp_wrap(msdu: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x01u8, 0x08, 0x5a, 0x61, 0x37, 0xff, 0xff];
    frame.extend_from_slice(msdu);
    frame
}

#[test]
fn gp_data_leg_names_frame_control_and_addressing() {
    // Verbatim w51 L: unsecured data `20 01`, SrcId `0x517f6811`.
    let tree = chain::dissect(&hex(GPDF_DATA_UNSECURED)).unwrap();
    assert_eq!(tree.len(), 3, "MAC + GP + stop note");
    let m = tree.mac().expect("mac node");
    assert_eq!(m.frame_type, 1);
    assert!(!m.security_enabled);
    let g = tree.gp().expect("gp node");
    assert_eq!(g.frame_type, 0);
    assert!(!g.auto_commissioning);
    assert_eq!(g.app_id, 0);
    assert_eq!(g.level, 0);
    assert!(!g.key_bit);
    assert!(!g.rx_after_tx);
    assert!(!g.direction_proxy);
    assert_eq!(g.src_id, 0x517f_6811);
    assert_eq!(g.ieee, None);
    assert_eq!(g.frame_counter, None);
    assert_eq!(g.command_id, Some(0x20));
    assert_eq!(g.kind, tree::GpKind::Data);
    assert_eq!(g.payload_len, 1);
    assert!(!g.secured);
    assert!(tree.nwk().is_none());
    assert!(tree.aps().is_none());
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
    let text = report::to_text(&tree);
    assert!(text.contains("gp: data"), "report names the leg:\n{text}");
    assert!(text.contains("cmd=0x20"));
    let json = report::to_json(&tree);
    assert!(json.contains("\"gp\":{"), "json names the leg: {json}");
    assert!(json.contains("\"cmd\":32"));
    // Session: nothing secured, one network row, no device row (the
    // short-dst-only outer carries no source address).
    let mut eng = session::SessionEngine::new();
    eng.note_tree(&tree);
    assert_eq!(eng.secured_decryptable, 0);
    assert_eq!(eng.secured_orphan, 0);
    let net = eng.network(0x3761).expect("PAN row");
    assert_eq!(net.frames, 1);
    assert_eq!(net.secured, 0);
}

#[test]
fn gp_commissioning_leg_names_long_and_compact() {
    // Verbatim w51 L: unsecured commissioning, 23-octet body.
    let long = hex("0108006137ffff8c0011687f51e002c3b26ee456f3ef39194b39b5d6b9b4fac9f80a000000");
    let tree = chain::dissect(&long).unwrap();
    let g = tree.gp().expect("gp node");
    assert_eq!(g.command_id, Some(0xe0));
    assert_eq!(g.kind, tree::GpKind::Commissioning);
    assert_eq!(g.payload_len, 23);
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
    // Verbatim w51 L: compact 2-octet commissioning body `02 43`.
    let short = hex("0108066137ffff8c0014687f51e00243");
    let tree2 = chain::dissect(&short).unwrap();
    let g2 = tree2.gp().expect("gp node");
    assert_eq!(g2.command_id, Some(0xe0));
    assert_eq!(g2.kind, tree::GpKind::Commissioning);
    assert_eq!(g2.payload_len, 2);
    assert_eq!(g2.src_id, 0x517f_6814);
    assert_eq!(note_reasons(&tree2), vec!["trailing"]);
}

#[test]
fn gp_bidirectional_request_leg_names_rx_after_tx() {
    // Verbatim w51 B8: commissioning with the receive-after-transmit
    // request set (the bidirectional-reply window ask), 7-octet body.
    let tree = chain::dissect(&hex("0108006137ffff8c4016687f51e002f3320a000000")).unwrap();
    let g = tree.gp().expect("gp node");
    assert!(g.rx_after_tx, "reply-window request bit");
    assert!(!g.direction_proxy);
    assert_eq!(g.level, 0);
    assert_eq!(g.command_id, Some(0xe0));
    assert_eq!(g.kind, tree::GpKind::Commissioning);
    assert_eq!(g.payload_len, 7);
    assert!(!g.secured);
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
    let text = report::to_text(&tree);
    assert!(
        text.contains("rx-after-tx"),
        "report flags the ask:\n{text}"
    );
}

#[test]
fn gp_secured_mic_only_names_command_beside_secured_stop() {
    // Verbatim w51 L: counter-protected data (`ext 0x30`, key-bit
    // class, counter `0x0f`), no key slotted.
    let tree = chain::dissect(&hex(GPDF_DATA_MIC_ONLY)).unwrap();
    assert_eq!(tree.len(), 3, "MAC + GP + stop note");
    let g = tree.gp().expect("gp node");
    assert_eq!(g.level, 2);
    assert!(g.key_bit);
    assert_eq!(g.frame_counter, Some(0x0f));
    // The command travels in the clear under the counter-plus-MIC
    // level, so the leg is named even while sealed.
    assert_eq!(g.command_id, Some(0x20));
    assert_eq!(g.kind, tree::GpKind::Data);
    assert_eq!(g.payload_len, 1);
    assert!(g.secured);
    assert_eq!(note_reasons(&tree), vec!["secured"]);
    // Session: one secured orphan, no device row (no source on air).
    let mut eng = session::SessionEngine::new();
    eng.note_tree(&tree);
    assert_eq!(eng.secured_decryptable, 0);
    assert_eq!(eng.secured_orphan, 1);
    // Verbatim w51 H2: counter-protected decommissioning, empty body.
    let decomm = chain::dissect(&hex("01081cffffffff8c3012687f5124000000e1acd6a5bd")).unwrap();
    let d = decomm.gp().expect("gp node");
    assert_eq!(d.command_id, Some(0xe1));
    assert_eq!(d.kind, tree::GpKind::Decommissioning);
    assert_eq!(d.payload_len, 0);
    assert_eq!(note_reasons(&decomm), vec!["secured"]);
    // Verbatim w51 L: counter-protected 23-octet commissioning.
    let comm = chain::dissect(&hex("0108276137ffff8c3011687f5115000000e002c3b26ee456f3ef39194b39b5d6b9b4fac9f815000000b96abe58")).unwrap();
    let c = comm.gp().expect("gp node");
    assert_eq!(c.command_id, Some(0xe0));
    assert_eq!(c.kind, tree::GpKind::Commissioning);
    assert_eq!(c.payload_len, 23);
    assert_eq!(c.frame_counter, Some(0x15));
    assert_eq!(note_reasons(&comm), vec!["secured"]);
}

#[test]
fn gp_encrypted_seals_command_without_key() {
    // Verbatim w51 L: encrypted section — the command identifier is
    // ciphertext, so no command is named while sealed.
    let tree = chain::dissect(&hex("0108126137ffff8c3811687f5113000000518b52aeb021fe")).unwrap();
    assert_eq!(tree.len(), 3, "MAC + GP + stop note");
    let g = tree.gp().expect("gp node");
    assert_eq!(g.level, 3);
    assert!(g.key_bit);
    assert_eq!(g.frame_counter, Some(0x13));
    assert_eq!(g.command_id, None);
    assert_eq!(g.kind, tree::GpKind::EncryptedSealed);
    assert_eq!(g.payload_len, 0);
    assert!(g.secured);
    assert_eq!(note_reasons(&tree), vec!["secured"]);
    let mut eng = session::SessionEngine::new();
    eng.note_tree(&tree);
    assert_eq!(eng.secured_decryptable, 0);
    assert_eq!(eng.secured_orphan, 1);
}

#[test]
fn gp_decrypt_opens_with_slotted_key_and_stops_without() {
    // Synthetic counter-protected data under the test-only key:
    // header 8c 30 <srcid 0x517f6811> <ctr 7> + section 20 01 + MIC.
    let srcid = 0x517f_6811u32;
    let ctr = 7u32;
    let section = [0x20u8, 0x01];
    let mut header = vec![0x8cu8, 0x30];
    header.extend_from_slice(&srcid.to_le_bytes());
    header.extend_from_slice(&ctr.to_le_bytes());
    let nonce = gp_test_nonce(srcid, ctr);
    let mut aad_extra = header.clone();
    aad_extra.extend_from_slice(&section);
    let tag = gp_test_tag(&GP_TEST_KEY, &nonce, &aad_extra, &[]);
    let mut msdu = header.clone();
    msdu.extend_from_slice(&section);
    msdu.extend_from_slice(&tag);
    let frame = gp_wrap(&msdu);
    // Slotted key-bit class: verified open, command leg, `decrypted`.
    let mut eng = session::SessionEngine::new();
    eng.set_gp_key(GP_TEST_KEY, true);
    let open = chain::dissect_with_keys(&frame, eng.keys()).unwrap();
    assert_eq!(open.len(), 3, "MAC + GP + stop note");
    let g = open.gp().expect("gp node past the open");
    assert_eq!(g.command_id, Some(0x20));
    assert_eq!(g.kind, tree::GpKind::Data);
    assert_eq!(note_reasons(&open), vec!["decrypted"]);
    eng.note_tree(&open);
    assert_eq!(eng.secured_decryptable, 1);
    assert_eq!(eng.secured_orphan, 0);
    // No key: identical bytes stop sealed.
    let shut = chain::dissect(&frame).unwrap();
    assert_eq!(note_reasons(&shut), vec!["secured"]);
    assert_eq!(shut.gp().expect("gp node").command_id, Some(0x20));
    // Wrong key-bit class, wrong key bytes, and any mutated octet:
    // never opens without the slotted key.
    let mut wrong_bit = session::SessionEngine::new();
    wrong_bit.set_gp_key(GP_TEST_KEY, false);
    assert_eq!(
        note_reasons(&chain::dissect_with_keys(&frame, wrong_bit.keys()).unwrap()),
        vec!["secured"]
    );
    let mut wrong_key = session::SessionEngine::new();
    wrong_key.set_gp_key([0x11u8; 16], true);
    assert_eq!(
        note_reasons(&chain::dissect_with_keys(&frame, wrong_key.keys()).unwrap()),
        vec!["secured"]
    );
    for flip in [msdu.len() + 6, msdu.len() + 3, 9] {
        let mut bad = frame.clone();
        bad[flip] ^= 0x01;
        assert_eq!(
            note_reasons(&chain::dissect_with_keys(&bad, eng.keys()).unwrap()),
            vec!["secured"],
            "mutation at {flip} must fail integrity"
        );
    }
    // Session per-domain gating: a GP-sealed tree folded into an
    // engine holding only an NWK slot still files orphan (NWK slots
    // never cover GP legs).
    let mut nwk_only = session::SessionEngine::new();
    nwk_only.set_network_key([0x77u8; 16], 0);
    nwk_only.note_tree(&shut);
    assert_eq!(nwk_only.secured_decryptable, 0);
    assert_eq!(nwk_only.secured_orphan, 1);
}

#[test]
fn gp_encrypted_decrypt_reveals_command_with_slotted_key() {
    // Synthetic encrypted commissioning under the test-only key:
    // section e0 02 sealed with CTR, header-only AAD.
    let srcid = 0x517f_6814u32;
    let ctr = 0x21u32;
    let section = [0xe0u8, 0x02];
    let mut header = vec![0x8cu8, 0x38];
    header.extend_from_slice(&srcid.to_le_bytes());
    header.extend_from_slice(&ctr.to_le_bytes());
    let nonce = gp_test_nonce(srcid, ctr);
    let ct = gp_test_ct(&GP_TEST_KEY, &nonce, &section);
    let tag = gp_test_tag(&GP_TEST_KEY, &nonce, &header, &section);
    let mut msdu = header;
    msdu.extend_from_slice(&ct);
    msdu.extend_from_slice(&tag);
    let frame = gp_wrap(&msdu);
    // Sealed: no command named.
    let shut = chain::dissect(&frame).unwrap();
    let s = shut.gp().expect("gp node");
    assert_eq!(s.kind, tree::GpKind::EncryptedSealed);
    assert_eq!(s.command_id, None);
    assert_eq!(note_reasons(&shut), vec!["secured"]);
    // Slotted: verified open reveals the commissioning envelope.
    let mut eng = session::SessionEngine::new();
    eng.set_gp_key(GP_TEST_KEY, true);
    let open = chain::dissect_with_keys(&frame, eng.keys()).unwrap();
    let g = open.gp().expect("gp node past the open");
    assert_eq!(g.command_id, Some(0xe0));
    assert_eq!(g.kind, tree::GpKind::Commissioning);
    assert_eq!(g.payload_len, 1);
    assert_eq!(note_reasons(&open), vec!["decrypted"]);
}

// ---------------------------------------------------------------------------
// Wave-76 lane 2: APS transport-key (0x05) command leg. APS command
// frames are the last stack layer with no named sub-leg: MAC earns
// `maccmd`, NWK earns `nwkcmd`, ZDO/ZCL/GP/Touchlink all name their
// envelope, while APS commands stop at an anonymous `trailing` note.
// The transport-key command is the highest-value single variant: it is
// the frame the Trust-Center-first join turns on, and the corpus
// permits it APS-plain on initial joining, so keyed dissect exposes it
// in cleartext. Reserved key types and every other command identifier
// stay `Unknown` for future waves.
// ---------------------------------------------------------------------------

/// Wrap an APS command body (key type + descriptor; the header command
/// octet rides the codec) in NWK + MAC.
fn wrap_aps_command(cmd_id: u8, body: &[u8]) -> Vec<u8> {
    let aps = rounddance_aps::frame::CommandHeader {
        control: rounddance_aps::frame::FrameControl::command(),
        counter: 0x51,
        command_id: cmd_id,
    };
    let mut aps_buf = [0u8; 128];
    let an = aps.encode_into(body, &mut aps_buf).unwrap();
    let nwk = rounddance_nwk::frame::NwkHeader::minimal(
        rounddance_nwk::frame::FrameControl::data(),
        0x0000,
        0x56cb,
        1,
        0x65,
    );
    let mut nwk_buf = [0u8; 256];
    let nn = nwk.encode_into(&aps_buf[..an], &mut nwk_buf).unwrap();
    let mut frame = vec![0x41, 0x88, 0x61];
    frame.extend_from_slice(&0x3761u16.to_le_bytes());
    frame.extend_from_slice(&0x0000u16.to_le_bytes());
    frame.extend_from_slice(&0x56cbu16.to_le_bytes());
    frame.extend_from_slice(&nwk_buf[..nn]);
    frame
}

#[test]
fn aps_transport_key_leg_names_key_type() {
    use tree::ApsCmdKind as K;
    // Network-key descriptor: type 0x01 + 16-octet key (test-only
    // placeholder, never rendered) + seq 0x00 + dst/src EUIs = 35
    // octets past the command octet (spec Fig 4-10; w45 battery
    // plaintext pin).
    let mut net = vec![0x01u8];
    net.extend_from_slice(&[0xAAu8; 16]);
    net.push(0x00);
    net.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    net.extend_from_slice(&[0x5f, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04]);
    let tree = chain::dissect(&wrap_aps_command(0x05, &net)).unwrap();
    let a = tree.apscmd().expect("transport-key leg");
    assert_eq!(a.command_id, 0x05);
    assert_eq!(a.kind, K::TransportKey { key_type: 0x01 });
    assert_eq!(a.payload_len, 35);
    // The APS envelope still files the command identifier; no ZCL
    // rides a command frame.
    assert_eq!(tree.aps().expect("aps envelope").command_id, Some(0x05));
    assert!(tree.zcl().is_none());
    // Stop taxonomy never moves for a named leg.
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
    let text = report::to_text(&tree);
    assert!(text.contains("apscmd:"), "named leg renders: {text}");
    assert!(text.contains("transport-key"), "leg kind renders: {text}");
    assert!(
        text.contains("keytype=0x01"),
        "key type renders, key bytes never do: {text}"
    );
    let json = report::to_json(&tree);
    assert!(json.contains("\"apscmd\""), "json leg renders: {json}");
    assert!(
        json.contains("\"kind\":\"transport-key\""),
        "json kind renders: {json}"
    );
    assert!(json.contains("\"key_type\":1"), "json key type: {json}");
    // The session timeline keys transport-key envelopes (the
    // pre-existing `TransportKey` event arm reads the APS command
    // identifier, unchanged by this leg).
    assert_eq!(
        session::classify_tree(&tree),
        Some(session::TimelineEvent::TransportKey)
    );
    // Trust-Center-link minimum shape (type 0x04 + 32 fixed octets)
    // and the same shape with trailing TLVs both name the leg.
    let mut tc = vec![0x04u8];
    tc.extend_from_slice(&[0xBBu8; 32]);
    let tc_tlv = [&tc[..], &[0x00, 0x02, 0xAA, 0xBB][..]].concat();
    for body in [&tc[..], &tc_tlv[..]] {
        let t = chain::dissect(&wrap_aps_command(0x05, body)).unwrap();
        assert_eq!(
            t.apscmd().expect("tc-link leg").kind,
            K::TransportKey { key_type: 0x04 }
        );
        assert_eq!(note_reasons(&t), vec!["trailing"]);
        assert_eq!(
            session::classify_tree(&t),
            Some(session::TimelineEvent::TransportKey)
        );
    }
    // Application-link minimum shape (type 0x03 + 25 fixed octets).
    let mut app = vec![0x03u8];
    app.extend_from_slice(&[0xCCu8; 25]);
    let app = chain::dissect(&wrap_aps_command(0x05, &app)).unwrap();
    assert_eq!(
        app.apscmd().expect("app-link leg").kind,
        K::TransportKey { key_type: 0x03 }
    );
    assert_eq!(
        session::classify_tree(&app),
        Some(session::TimelineEvent::TransportKey)
    );
    // Short network descriptor (33 body octets, one past the type
    // short of the 34-octet shape), a reserved key type, a short
    // update-device 0x06 prefix, and the next command identifier
    // (remove-device 0x07, a future wave's leg) all file `Unknown`
    // under the same stop; a lone command octet (empty body) refuses
    // the leg outright.
    let short = net[..33].to_vec();
    let reserved = [&[0x00u8][..], &net[1..]].concat();
    assert_eq!(short.len(), 33);
    let ud = [0xCCu8; 11];
    let short_ud = &ud[..10];
    // The timeline arm reads the APS envelope command identifier, so
    // short/reserved 0x05 bodies still key `TransportKey` while the
    // other command identifiers key nothing (update-device 0x06
    // names its own leg since wave-78 — see the wave-78 test).
    for (cmd, body, event) in [
        (
            0x05u8,
            &short[..],
            Some(session::TimelineEvent::TransportKey),
        ),
        (
            0x05u8,
            &reserved[..],
            Some(session::TimelineEvent::TransportKey),
        ),
        (0x06u8, short_ud, None),
        (0x07u8, &ud[..], None),
    ] {
        let t = chain::dissect(&wrap_aps_command(cmd, body)).unwrap();
        assert_eq!(t.apscmd().expect("unknown leg").kind, K::Unknown);
        assert_eq!(note_reasons(&t), vec!["trailing"]);
        assert_eq!(session::classify_tree(&t), event);
    }
    // A lone command octet (empty body) refuses the leg outright but
    // keeps the same stop.
    let lone = chain::dissect(&wrap_aps_command(0x05, &[])).unwrap();
    assert!(lone.apscmd().is_none());
    assert_eq!(note_reasons(&lone), vec!["trailing"]);
    // A truncated APDU (no command octet at all) never reaches the
    // leg: the APS refusal keeps the `unknown` stop.
    let mut clipped = wrap_aps_command(0x05, &net);
    clipped.truncate(clipped.len() - (net.len() + 1));
    let t = chain::dissect(&clipped).unwrap();
    assert!(t.aps().is_none());
    assert!(t.apscmd().is_none());
    assert_eq!(note_reasons(&t), vec!["unknown"]);
}

// ---------------------------------------------------------------------------
// Wave-78 track-inspect: APS update-device (0x06) command leg. The next
// unnamed APS command id after wave-76's transport-key (0x05): spec Table
// 4-31 assigns 0x06 to UPDATE_DEVICE, and the wave-76 test pins it as a
// future leg (`Unknown`). Wire shape is spec Fig 4-13: an 8-octet device
// address + a 2-octet device short address + a 1-octet status with
// optional R23 JoinerTLVs after it — an 11-octet fixed body prefix with
// trailing TLVs admitted (the transport-key fixed-prefix minima
// precedent). The 8-octet EUI stays in the capture (the network-report
// EPID precedent); the node carries status + short only. Status values
// (Table 4-14, 0x00-0x03 assigned, 0x04-0x07 reserved) are never
// validated — the network-status precedent.
// ---------------------------------------------------------------------------

#[test]
fn aps_update_device_leg_names_status_and_short() {
    use tree::ApsCmdKind as K;
    // Status 0x01 (unsecured join) for short 0x1234, EUI 01..08:
    // synthetic identifiers, never key material, never rendered.
    let mut body = vec![0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    body.extend_from_slice(&0x1234u16.to_le_bytes());
    body.push(0x01);
    assert_eq!(body.len(), 11);
    let tree = chain::dissect(&wrap_aps_command(0x06, &body)).unwrap();
    let a = tree.apscmd().expect("update-device leg");
    assert_eq!(a.command_id, 0x06);
    assert_eq!(
        a.kind,
        K::UpdateDevice {
            status: 0x01,
            short_addr: 0x1234
        }
    );
    assert_eq!(a.payload_len, 12);
    // The APS envelope still files the command identifier; no ZCL
    // rides a command frame.
    assert_eq!(tree.aps().expect("aps envelope").command_id, Some(0x06));
    assert!(tree.zcl().is_none());
    // Stop taxonomy never moves for a named leg.
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
    let text = report::to_text(&tree);
    assert!(text.contains("apscmd:"), "named leg renders: {text}");
    assert!(text.contains("update-device"), "leg kind renders: {text}");
    assert!(text.contains("status=0x01"), "status renders: {text}");
    assert!(text.contains("short=0x1234"), "short renders: {text}");
    let json = report::to_json(&tree);
    assert!(json.contains("\"apscmd\""), "json leg renders: {json}");
    assert!(
        json.contains("\"kind\":\"update-device\""),
        "json kind renders: {json}"
    );
    assert!(json.contains("\"status\":1"), "json status: {json}");
    assert!(json.contains("\"short\":4660"), "json short: {json}");
    // The 8-octet EUI stays in the capture, never in the node.
    assert!(
        !json.contains("578437695752307201"),
        "EUI never rendered: {json}"
    );
    // Update chatter never opens a session timeline.
    assert_eq!(session::classify_tree(&tree), None);
    // R23 JoinerTLVs tail admitted: same prefix + 4 TLV octets.
    let tlv = [&body[..], &[0x00u8, 0x02, 0xAA, 0xBB][..]].concat();
    let t = chain::dissect(&wrap_aps_command(0x06, &tlv)).unwrap();
    assert_eq!(
        t.apscmd().expect("tlv leg").kind,
        K::UpdateDevice {
            status: 0x01,
            short_addr: 0x1234
        }
    );
    assert_eq!(t.apscmd().expect("tlv leg").payload_len, 16);
    assert_eq!(note_reasons(&t), vec!["trailing"]);
    assert_eq!(session::classify_tree(&t), None);
    // A reserved status still names the shape (status semantics are
    // the stack's, never validated — the network-status precedent).
    let mut reserved = body.clone();
    reserved[10] = 0x05;
    let r = chain::dissect(&wrap_aps_command(0x06, &reserved)).unwrap();
    assert_eq!(
        r.apscmd().expect("reserved-status leg").kind,
        K::UpdateDevice {
            status: 0x05,
            short_addr: 0x1234
        }
    );
    assert_eq!(note_reasons(&r), vec!["trailing"]);
    assert_eq!(session::classify_tree(&r), None);
    // A short 0x06 prefix and reserved command identifiers stay
    // `Unknown` under the same stop with no timeline event.
    let short = &body[..10];
    for (cmd, b) in [(0x06u8, short), (0x01u8, &body[..]), (0x07u8, &body[..])] {
        let t = chain::dissect(&wrap_aps_command(cmd, b)).unwrap();
        assert_eq!(t.apscmd().expect("unknown leg").kind, K::Unknown);
        assert_eq!(note_reasons(&t), vec!["trailing"]);
        assert_eq!(session::classify_tree(&t), None);
    }
    // A lone command octet (empty body) refuses the leg outright but
    // keeps the same stop.
    let lone = chain::dissect(&wrap_aps_command(0x06, &[])).unwrap();
    assert!(lone.apscmd().is_none());
    assert_eq!(note_reasons(&lone), vec!["trailing"]);
}

// ---------------------------------------------------------------------------
// Wave-79 track-inspect: APS remove-device (0x07) command leg. The next
// unnamed APS command id after wave-78's update-device (0x06): spec Table
// 4-31 assigns 0x07 to REMOVE_DEVICE, and the wave-78 test pins it as a
// future leg (`Unknown`). Wire shape is the device address alone — an
// 8-octet EUI with no short, no status, and no JoinerTLV tail — so the
// gate is an exact 8-octet body (9-octet payload with the command
// octet). The EUI stays in the capture (the network-report EPID and
// update-device EUI precedents); the node carries no address bytes,
// never rendered in either report leg.
// ---------------------------------------------------------------------------

#[test]
fn aps_remove_device_leg_names_eui_shape() {
    use tree::ApsCmdKind as K;
    // Synthetic EUI 01..08: identifier bytes only, never key material,
    // never rendered.
    let body = vec![0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    assert_eq!(body.len(), 8);
    let tree = chain::dissect(&wrap_aps_command(0x07, &body)).unwrap();
    let a = tree.apscmd().expect("remove-device leg");
    assert_eq!(a.command_id, 0x07);
    assert_eq!(a.kind, K::RemoveDevice);
    assert_eq!(a.payload_len, 9);
    // The APS envelope still files the command identifier; no ZCL
    // rides a command frame.
    assert_eq!(tree.aps().expect("aps envelope").command_id, Some(0x07));
    assert!(tree.zcl().is_none());
    // Stop taxonomy never moves for a named leg.
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
    let text = report::to_text(&tree);
    assert!(text.contains("apscmd:"), "named leg renders: {text}");
    assert!(text.contains("remove-device"), "leg kind renders: {text}");
    let json = report::to_json(&tree);
    assert!(json.contains("\"apscmd\""), "json leg renders: {json}");
    assert!(
        json.contains("\"kind\":\"remove-device\""),
        "json kind renders: {json}"
    );
    assert!(json.contains("\"cmd\":7"), "json command id: {json}");
    // The 8-octet EUI stays in the capture, never in the node.
    assert!(
        !json.contains("578437695752307201"),
        "EUI never rendered: {json}"
    );
    assert!(
        !text.contains("578437695752307201"),
        "EUI never rendered: {text}"
    );
    // Remove chatter never opens a session timeline.
    assert_eq!(session::classify_tree(&tree), None);
    // Exact gate: short (7) and long (9, trailing octet) bodies stay
    // `Unknown` under the same stop with no timeline event, as do
    // reserved command identifiers at the named length and the next
    // command identifier (request-key 0x08, a future wave's leg).
    let short = &body[..7];
    let long = [&body[..], &[0xAAu8][..]].concat();
    assert_eq!(long.len(), 9);
    for (cmd, b) in [
        (0x07u8, short),
        (0x07u8, &long[..]),
        (0x01u8, &body[..]),
        (0x08u8, &[0x01u8][..]),
    ] {
        let t = chain::dissect(&wrap_aps_command(cmd, b)).unwrap();
        assert_eq!(t.apscmd().expect("unknown leg").kind, K::Unknown);
        assert_eq!(note_reasons(&t), vec!["trailing"]);
        assert_eq!(session::classify_tree(&t), None);
    }
    // A lone command octet (empty body) refuses the leg outright but
    // keeps the same stop.
    let lone = chain::dissect(&wrap_aps_command(0x07, &[])).unwrap();
    assert!(lone.apscmd().is_none());
    assert_eq!(note_reasons(&lone), vec!["trailing"]);
}

// ---------------------------------------------------------------------------
// Wave-80 track-inspect: APS request-key (0x08) command leg. The next
// unnamed APS command id after wave-79's remove-device (0x07): spec Table
// 4-31 assigns 0x08 to REQUEST_KEY, and the wave-79 test pins it as a
// future leg (`Unknown`). Wire shape is a 1-octet key type plus the
// 8-octet partner device address alone — a fixed 9-octet body (10-octet
// payload with the command octet), so the gate is exact. The partner EUI
// stays in the capture (the network-report EPID and update/remove-device
// EUI precedents); the node carries the key type alone (the transport-key
// key-type precedent). Key-type values are the stack's, never validated
// here (the update-device status precedent — the length is fixed, so no
// structural gate needs the type); no key material rides this command, so
// no key bytes can ever render.
// ---------------------------------------------------------------------------

#[test]
fn aps_request_key_leg_names_key_type() {
    use tree::ApsCmdKind as K;
    // Synthetic: key type 0x01 + EUI 01..08: identifier bytes only,
    // never key material, never rendered.
    let mut body = vec![0x01u8];
    body.extend_from_slice(&[0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    assert_eq!(body.len(), 9);
    let tree = chain::dissect(&wrap_aps_command(0x08, &body)).unwrap();
    let a = tree.apscmd().expect("request-key leg");
    assert_eq!(a.command_id, 0x08);
    assert_eq!(a.kind, K::RequestKey { key_type: 0x01 });
    assert_eq!(a.payload_len, 10);
    // The APS envelope still files the command identifier; no ZCL
    // rides a command frame.
    assert_eq!(tree.aps().expect("aps envelope").command_id, Some(0x08));
    assert!(tree.zcl().is_none());
    // Stop taxonomy never moves for a named leg.
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
    let text = report::to_text(&tree);
    assert!(text.contains("apscmd:"), "named leg renders: {text}");
    assert!(text.contains("request-key"), "leg kind renders: {text}");
    assert!(
        text.contains("keytype=0x01"),
        "key type renders, partner EUI never does: {text}"
    );
    let json = report::to_json(&tree);
    assert!(json.contains("\"apscmd\""), "json leg renders: {json}");
    assert!(
        json.contains("\"kind\":\"request-key\""),
        "json kind renders: {json}"
    );
    assert!(json.contains("\"cmd\":8"), "json command id: {json}");
    assert!(json.contains("\"key_type\":1"), "json key type: {json}");
    // The 8-octet partner EUI stays in the capture, never in the node.
    assert!(
        !json.contains("578437695752307201"),
        "EUI never rendered: {json}"
    );
    assert!(
        !text.contains("578437695752307201"),
        "EUI never rendered: {text}"
    );
    // Request chatter never opens a session timeline.
    assert_eq!(session::classify_tree(&tree), None);
    // Key-type values are never validated: a type outside the
    // transport-key named set still names the shape (the reserved-status
    // precedent of the update-device leg).
    let mut other = body.clone();
    other[0] = 0x02;
    let o = chain::dissect(&wrap_aps_command(0x08, &other)).unwrap();
    assert_eq!(
        o.apscmd().expect("unvalidated-type leg").kind,
        K::RequestKey { key_type: 0x02 }
    );
    assert_eq!(note_reasons(&o), vec!["trailing"]);
    assert_eq!(session::classify_tree(&o), None);
    // Exact gate: short (8) and long (10, trailing octet) bodies stay
    // `Unknown` under the same stop with no timeline event, as do
    // reserved command identifiers at the named length and the next
    // named command identifier (switch-key 0x09, now its own wave-81
    // leg at its exact 1-octet gate — a 1-octet body is no longer
    // `Unknown` there — plus reserved 0x0A and tunnel 0x0E, future
    // legs still `Unknown`).
    let short = &body[..8];
    let long = [&body[..], &[0xAAu8][..]].concat();
    assert_eq!(long.len(), 10);
    for (cmd, b) in [
        (0x08u8, short),
        (0x08u8, &long[..]),
        (0x01u8, &body[..]),
        (0x0Au8, &[0x00u8][..]),
        (0x0Eu8, &[0x00u8][..]),
    ] {
        let t = chain::dissect(&wrap_aps_command(cmd, b)).unwrap();
        assert_eq!(t.apscmd().expect("unknown leg").kind, K::Unknown);
        assert_eq!(note_reasons(&t), vec!["trailing"]);
        assert_eq!(session::classify_tree(&t), None);
    }
    // A lone command octet (empty body) refuses the leg outright but
    // keeps the same stop.
    let lone = chain::dissect(&wrap_aps_command(0x08, &[])).unwrap();
    assert!(lone.apscmd().is_none());
    assert_eq!(note_reasons(&lone), vec!["trailing"]);
}

// ---------------------------------------------------------------------------
// Wave-81 track-inspect: APS switch-key (0x09) command leg. The next
// unnamed APS command id after wave-80's request-key (0x08): spec Table
// 4-31 assigns 0x09 to SWITCH_KEY, and the wave-80 test pins it as a
// future leg (`Unknown`). Wire shape is the new-network-key sequence
// number alone — a fixed 1-octet body (2-octet payload with the command
// octet), so the gate is exact. No addresses and no key material ride
// this command; the node carries the sequence number alone (the
// update-device status / request-key key-type precedent). Sequence
// values are the stack's, never validated here (the update-device
// status precedent — the length is fixed, so no structural gate needs
// the value).
// ---------------------------------------------------------------------------

#[test]
fn aps_switch_key_leg_names_seq() {
    use tree::ApsCmdKind as K;
    // Synthetic: sequence number 0x02 alone: a sequence octet only,
    // never an address, never key material, never rendered as bytes.
    let body = [0x02u8];
    let tree = chain::dissect(&wrap_aps_command(0x09, &body)).unwrap();
    let a = tree.apscmd().expect("switch-key leg");
    assert_eq!(a.command_id, 0x09);
    assert_eq!(a.kind, K::SwitchKey { key_seq: 0x02 });
    assert_eq!(a.payload_len, 2);
    // The APS envelope still files the command identifier; no ZCL
    // rides a command frame.
    assert_eq!(tree.aps().expect("aps envelope").command_id, Some(0x09));
    assert!(tree.zcl().is_none());
    // Stop taxonomy never moves for a named leg.
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
    let text = report::to_text(&tree);
    assert!(text.contains("apscmd:"), "named leg renders: {text}");
    assert!(text.contains("switch-key"), "leg kind renders: {text}");
    assert!(text.contains("seq=0x02"), "sequence number renders: {text}");
    let json = report::to_json(&tree);
    assert!(json.contains("\"apscmd\""), "json leg renders: {json}");
    assert!(
        json.contains("\"kind\":\"switch-key\""),
        "json kind renders: {json}"
    );
    assert!(json.contains("\"cmd\":9"), "json command id: {json}");
    assert!(json.contains("\"key_seq\":2"), "json sequence: {json}");
    // Switch chatter never opens a session timeline.
    assert_eq!(session::classify_tree(&tree), None);
    // Sequence values are never validated: an all-ones sequence still
    // names the shape (the reserved-status precedent of the
    // update-device leg).
    let other = chain::dissect(&wrap_aps_command(0x09, &[0xFFu8])).unwrap();
    assert_eq!(
        other.apscmd().expect("unvalidated-seq leg").kind,
        K::SwitchKey { key_seq: 0xFF }
    );
    assert_eq!(note_reasons(&other), vec!["trailing"]);
    assert_eq!(session::classify_tree(&other), None);
    // Exact gate: long (2, trailing octet) bodies stay `Unknown`
    // under the same stop with no timeline event, as do reserved
    // command identifiers at the named length and the next named
    // command identifier (tunnel 0x0E, a future wave's leg).
    let long = [&body[..], &[0xAAu8][..]].concat();
    assert_eq!(long.len(), 2);
    for (cmd, b) in [
        (0x09u8, &long[..]),
        (0x0Au8, &body[..]),
        (0x0Eu8, &body[..]),
    ] {
        let t = chain::dissect(&wrap_aps_command(cmd, b)).unwrap();
        assert_eq!(t.apscmd().expect("unknown leg").kind, K::Unknown);
        assert_eq!(note_reasons(&t), vec!["trailing"]);
        assert_eq!(session::classify_tree(&t), None);
    }
    // A lone command octet (empty body) refuses the leg outright but
    // keeps the same stop.
    let lone = chain::dissect(&wrap_aps_command(0x09, &[])).unwrap();
    assert!(lone.apscmd().is_none());
    assert_eq!(note_reasons(&lone), vec!["trailing"]);
}

// ---------------------------------------------------------------------------
// Wave-82 track-inspect: APS tunnel (0x0E) command leg. The next
// unnamed APS command id after wave-81's switch-key (0x09): spec Table
// 4-31 assigns 0x0E to TUNNEL, and the wave-81 test pins it as a
// future leg (`Unknown`). Wire shape is the destination address plus
// the tunneled frame: an 8-octet EUI prefix with at least one tunneled
// octet after it, so the gate is a 9-octet body minimum with the tail
// admitted unparsed (the update-device fixed-prefix minima precedent).
// The EUI and the tunneled bytes stay in the capture, never in the
// node (the remove-device EUI precedent); the node is fieldless and
// carries nothing renderable. No key material rides this command.
// ---------------------------------------------------------------------------

#[test]
fn aps_tunnel_leg_names_eui_prefix() {
    use tree::ApsCmdKind as K;
    // Destination EUI 01..08 plus one tunneled octet: synthetic
    // identifiers, never key material, never rendered.
    let body = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xAA];
    assert_eq!(body.len(), 9);
    let tree = chain::dissect(&wrap_aps_command(0x0E, &body)).unwrap();
    let a = tree.apscmd().expect("tunnel leg");
    assert_eq!(a.command_id, 0x0E);
    assert_eq!(a.kind, K::Tunnel);
    assert_eq!(a.payload_len, 10);
    // The APS envelope still files the command identifier; no ZCL
    // rides a command frame.
    assert_eq!(tree.aps().expect("aps envelope").command_id, Some(0x0E));
    assert!(tree.zcl().is_none());
    // Stop taxonomy never moves for a named leg.
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
    let text = report::to_text(&tree);
    assert!(text.contains("apscmd:"), "named leg renders: {text}");
    assert!(text.contains("tunnel"), "leg kind renders: {text}");
    let json = report::to_json(&tree);
    assert!(json.contains("\"apscmd\""), "json leg renders: {json}");
    assert!(
        json.contains("\"kind\":\"tunnel\""),
        "json kind renders: {json}"
    );
    assert!(json.contains("\"cmd\":14"), "json command id: {json}");
    // The EUI stays in the capture, never in the node.
    assert!(
        !json.contains("578437695752307201"),
        "EUI never rendered: {json}"
    );
    assert!(
        !text.contains("578437695752307201"),
        "EUI never rendered: {text}"
    );
    // Tunnel chatter never opens a session timeline.
    assert_eq!(session::classify_tree(&tree), None);
    // Longer tunneled tails still name the shape (minimum gate, the
    // update-device TLV-tail precedent).
    let long = [&body[..], &[0xBBu8, 0xCC][..]].concat();
    assert_eq!(long.len(), 11);
    let t = chain::dissect(&wrap_aps_command(0x0E, &long)).unwrap();
    assert_eq!(t.apscmd().expect("long-tail leg").kind, K::Tunnel);
    assert_eq!(note_reasons(&t), vec!["trailing"]);
    assert_eq!(session::classify_tree(&t), None);
    // Exact minimum: EUI alone (8) and shorter prefixes stay
    // `Unknown` under the same stop with no timeline event, as do
    // reserved command identifiers at the named length and the next
    // command identifier (0x0F, a future wave's leg).
    let eui_only = &body[..8];
    let short = &body[..7];
    for (cmd, b) in [
        (0x0Eu8, eui_only),
        (0x0Eu8, short),
        (0x0Au8, &body[..]),
        (0x0Fu8, &body[..]),
    ] {
        let t = chain::dissect(&wrap_aps_command(cmd, b)).unwrap();
        assert_eq!(t.apscmd().expect("unknown leg").kind, K::Unknown);
        assert_eq!(note_reasons(&t), vec!["trailing"]);
        assert_eq!(session::classify_tree(&t), None);
    }
    // A lone command octet (empty body) refuses the leg outright but
    // keeps the same stop.
    let lone = chain::dissect(&wrap_aps_command(0x0E, &[])).unwrap();
    assert!(lone.apscmd().is_none());
    assert_eq!(note_reasons(&lone), vec!["trailing"]);
}

// ---------------------------------------------------------------------------
// Wave-83 track-inspect: APS verify-key (0x0F) command leg. The next
// unnamed APS command id after wave-82's tunnel (0x0E): spec Table
// 4-31 assigns 0x0F to VERIFY_KEY, and the wave-82 test pins it as a
// future leg (`Unknown`). Wire shape is the key type plus the source
// address plus the initiator hash: a 1-octet type, an 8-octet EUI,
// and a 16-octet hash with no TLV tail, so the gate is an exact
// 25-octet body (26-octet payload with the command octet) — the
// request-key exact-gate precedent. The source EUI and the hash stay
// in the capture, never in the node (the remove-device EUI precedent
// for the address, the transport-key sealed-key precedent for the
// hash — a key-derived verifier, never rendered); the node carries the
// key type alone (the request-key key-type precedent). Key-type values
// are never validated (the update-device status precedent — the fixed
// length needs no type gate, and the hash is never checked here).
// ---------------------------------------------------------------------------

#[test]
fn aps_verify_key_leg_names_key_type() {
    use tree::ApsCmdKind as K;
    // Key type 0x04 plus source EUI 01..08 plus a 16-octet synthetic
    // hash: identifiers and opaque bytes only, never key material,
    // never rendered.
    let mut body = vec![0x04u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    body.extend_from_slice(&[0xAAu8; 16]);
    assert_eq!(body.len(), 25);
    let tree = chain::dissect(&wrap_aps_command(0x0F, &body)).unwrap();
    let a = tree.apscmd().expect("verify-key leg");
    assert_eq!(a.command_id, 0x0F);
    assert_eq!(a.kind, K::VerifyKey { key_type: 0x04 });
    assert_eq!(a.payload_len, 26);
    // The APS envelope still files the command identifier; no ZCL
    // rides a command frame.
    assert_eq!(tree.aps().expect("aps envelope").command_id, Some(0x0F));
    assert!(tree.zcl().is_none());
    // Stop taxonomy never moves for a named leg.
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
    let text = report::to_text(&tree);
    assert!(text.contains("apscmd:"), "named leg renders: {text}");
    assert!(text.contains("verify-key"), "leg kind renders: {text}");
    assert!(
        text.contains("keytype=0x04"),
        "key type renders, EUI/hash bytes never do: {text}"
    );
    let json = report::to_json(&tree);
    assert!(json.contains("\"apscmd\""), "json leg renders: {json}");
    assert!(
        json.contains("\"kind\":\"verify-key\""),
        "json kind renders: {json}"
    );
    assert!(json.contains("\"cmd\":15"), "json command id: {json}");
    assert!(json.contains("\"key_type\":4"), "json key type: {json}");
    // The 8-octet source EUI stays in the capture, never in the node.
    assert!(
        !json.contains("578437695752307201"),
        "EUI never rendered: {json}"
    );
    assert!(
        !text.contains("578437695752307201"),
        "EUI never rendered: {text}"
    );
    // Verify chatter never opens a session timeline.
    assert_eq!(session::classify_tree(&tree), None);
    // Key-type values are never validated: a type outside the
    // transport-key named set still names the shape (the reserved-status
    // precedent of the update-device leg).
    let mut other = body.clone();
    other[0] = 0x02;
    let o = chain::dissect(&wrap_aps_command(0x0F, &other)).unwrap();
    assert_eq!(
        o.apscmd().expect("unvalidated-type leg").kind,
        K::VerifyKey { key_type: 0x02 }
    );
    assert_eq!(note_reasons(&o), vec!["trailing"]);
    assert_eq!(session::classify_tree(&o), None);
    // Exact gate: short (24) and long (26, trailing octet) bodies stay
    // `Unknown` under the same stop with no timeline event, as do
    // reserved command identifiers at the named length and the next
    // named command identifier (confirm-key 0x10, a future wave's leg).
    let short = &body[..24];
    let long = [&body[..], &[0xBBu8][..]].concat();
    assert_eq!(long.len(), 26);
    for (cmd, b) in [
        (0x0Fu8, short),
        (0x0Fu8, &long[..]),
        (0x01u8, &body[..]),
        (0x0Au8, &body[..]),
        (0x10u8, &body[..]),
    ] {
        let t = chain::dissect(&wrap_aps_command(cmd, b)).unwrap();
        assert_eq!(t.apscmd().expect("unknown leg").kind, K::Unknown);
        assert_eq!(note_reasons(&t), vec!["trailing"]);
        assert_eq!(session::classify_tree(&t), None);
    }
    // A lone command octet (empty body) refuses the leg outright but
    // keeps the same stop.
    let lone = chain::dissect(&wrap_aps_command(0x0F, &[])).unwrap();
    assert!(lone.apscmd().is_none());
    assert_eq!(note_reasons(&lone), vec!["trailing"]);
}

// ---------------------------------------------------------------------------
// Wave-85: APS confirm-key (0x10) named. Status + key type over the
// spec-fixed shape; the destination EUI stays in the capture, never
// in the node. Values are never validated; there is no key material
// in this command at all.
// ---------------------------------------------------------------------------

#[test]
fn aps_confirm_key_leg_names_status_key_type() {
    use tree::ApsCmdKind as K;
    // Status 0x00 plus key type 0x04 plus destination EUI 01..08: the
    // fixed 10-octet body (status + type + address, no TLV tail).
    let body = vec![0x00u8, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    assert_eq!(body.len(), 10);
    let tree = chain::dissect(&wrap_aps_command(0x10, &body)).unwrap();
    let a = tree.apscmd().expect("confirm-key leg");
    assert_eq!(a.command_id, 0x10);
    assert_eq!(
        a.kind,
        K::ConfirmKey {
            status: 0x00,
            key_type: 0x04
        }
    );
    assert_eq!(a.payload_len, 11);
    // The APS envelope still files the command identifier; no ZCL
    // rides a command frame.
    assert_eq!(tree.aps().expect("aps envelope").command_id, Some(0x10));
    assert!(tree.zcl().is_none());
    // Stop taxonomy never moves for a named leg.
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
    let text = report::to_text(&tree);
    assert!(text.contains("apscmd:"), "named leg renders: {text}");
    assert!(text.contains("confirm-key"), "leg kind renders: {text}");
    assert!(
        text.contains("status=0x00"),
        "status renders, EUI bytes never do: {text}"
    );
    assert!(
        text.contains("keytype=0x04"),
        "key type renders, EUI bytes never do: {text}"
    );
    let json = report::to_json(&tree);
    assert!(json.contains("\"apscmd\""), "json leg renders: {json}");
    assert!(
        json.contains("\"kind\":\"confirm-key\""),
        "json kind renders: {json}"
    );
    assert!(json.contains("\"cmd\":16"), "json command id: {json}");
    assert!(json.contains("\"status\":0"), "json status: {json}");
    assert!(json.contains("\"key_type\":4"), "json key type: {json}");
    // The 8-octet destination EUI stays in the capture, never in the
    // node.
    assert!(
        !json.contains("578437695752307201"),
        "EUI never rendered: {json}"
    );
    assert!(
        !text.contains("578437695752307201"),
        "EUI never rendered: {text}"
    );
    // Confirm chatter never opens a session timeline.
    assert_eq!(session::classify_tree(&tree), None);
    // Values are never validated: an out-of-range status plus a type
    // outside the transport-key named set still names the shape (the
    // reserved-status precedent of the update-device leg).
    let mut other = body.clone();
    other[0] = 0x07;
    other[1] = 0x02;
    let o = chain::dissect(&wrap_aps_command(0x10, &other)).unwrap();
    assert_eq!(
        o.apscmd().expect("unvalidated-value leg").kind,
        K::ConfirmKey {
            status: 0x07,
            key_type: 0x02
        }
    );
    assert_eq!(note_reasons(&o), vec!["trailing"]);
    assert_eq!(session::classify_tree(&o), None);
    // Exact gate: short (9) and long (11, trailing octet) bodies stay
    // `Unknown` under the same stop with no timeline event, as do
    // reserved command identifiers at the named length and the next
    // named command identifier (relay-downstream 0x11, a future
    // wave's leg).
    let short = &body[..9];
    let long = [&body[..], &[0xBBu8][..]].concat();
    assert_eq!(long.len(), 11);
    for (cmd, b) in [
        (0x10u8, short),
        (0x10u8, &long[..]),
        (0x01u8, &body[..]),
        (0x0Au8, &body[..]),
        (0x11u8, &body[..]),
    ] {
        let t = chain::dissect(&wrap_aps_command(cmd, b)).unwrap();
        assert_eq!(t.apscmd().expect("unknown leg").kind, K::Unknown);
        assert_eq!(note_reasons(&t), vec!["trailing"]);
        assert_eq!(session::classify_tree(&t), None);
    }
    // A lone command octet (empty body) refuses the leg outright but
    // keeps the same stop.
    let lone = chain::dissect(&wrap_aps_command(0x10, &[])).unwrap();
    assert!(lone.apscmd().is_none());
    assert_eq!(note_reasons(&lone), vec!["trailing"]);
}

// ---------------------------------------------------------------------------
// Wave-86: APS relay-downstream (0x11) named. One or more Zigbee core
// TLVs (tag + length + value of length + 1) with at least one Relay
// Message TLV (tag 0: 8-octet destination EUI + >=1 relayed octet).
// The EUI and the relayed bytes stay in the capture, never in the
// node; unknown tags ride in any order. Anything else stays
// `Unknown` under the same stop.
// ---------------------------------------------------------------------------

#[test]
fn aps_relay_downstream_leg_names_tlv_minima() {
    use tree::ApsCmdKind as K;
    // Relay Message TLV: tag 0x00, length 0x08 (value 9 = EUI
    // 01..08 + one relayed octet 0xAA). Single-TLV body, 11 octets.
    let body = vec![
        0x00u8, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xAA,
    ];
    assert_eq!(body.len(), 11);
    let tree = chain::dissect(&wrap_aps_command(0x11, &body)).unwrap();
    let a = tree.apscmd().expect("relay-downstream leg");
    assert_eq!(a.command_id, 0x11);
    assert_eq!(a.kind, K::RelayDownstream);
    assert_eq!(a.payload_len, 12);
    // The APS envelope still files the command identifier; no ZCL
    // rides a command frame.
    assert_eq!(tree.aps().expect("aps envelope").command_id, Some(0x11));
    assert!(tree.zcl().is_none());
    // Stop taxonomy never moves for a named leg.
    assert_eq!(note_reasons(&tree), vec!["trailing"]);
    let text = report::to_text(&tree);
    assert!(text.contains("apscmd:"), "named leg renders: {text}");
    assert!(
        text.contains("relay-downstream"),
        "leg kind renders: {text}"
    );
    let json = report::to_json(&tree);
    assert!(json.contains("\"apscmd\""), "json leg renders: {json}");
    assert!(
        json.contains("\"kind\":\"relay-downstream\""),
        "json kind renders: {json}"
    );
    assert!(json.contains("\"cmd\":17"), "json command id: {json}");
    // The 8-octet destination EUI stays in the capture, never in the
    // node; the relayed byte is never rendered either.
    assert!(
        !json.contains("578437695752307201"),
        "EUI never rendered: {json}"
    );
    assert!(
        !text.contains("578437695752307201"),
        "EUI never rendered: {text}"
    );
    // Relay chatter never opens a session timeline.
    assert_eq!(session::classify_tree(&tree), None);
    // TLV order never matters and unknown tags ride along: the relay
    // TLV second after a global tag still names the shape.
    let mut reordered = vec![0x40u8, 0x00, 0xBB];
    reordered.extend_from_slice(&body);
    let r = chain::dissect(&wrap_aps_command(0x11, &reordered)).unwrap();
    assert_eq!(r.apscmd().expect("reordered leg").kind, K::RelayDownstream);
    assert_eq!(note_reasons(&r), vec!["trailing"]);
    assert_eq!(session::classify_tree(&r), None);
    // A longer relay value (multi-octet relayed message) still names
    // the shape: the value minimum admits longer values.
    let long_body = vec![
        0x00u8, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xAA, 0xCC,
    ];
    let l = chain::dissect(&wrap_aps_command(0x11, &long_body)).unwrap();
    assert_eq!(l.apscmd().expect("long-value leg").kind, K::RelayDownstream);
    assert_eq!(note_reasons(&l), vec!["trailing"]);
    assert_eq!(session::classify_tree(&l), None);
    // Misses stay `Unknown` under the same stop with no timeline
    // event: truncated value (length promises 9, only 8 present),
    // short relay value (length 7: EUI alone, no relayed octet),
    // trailing garbage past a complete TLV, a body with no tag-0
    // TLV, reserved identifiers at the relay shape, the confirm-key
    // fixed shape under 0x11, and the next command identifier
    // (relay-upstream 0x12, a future wave's leg).
    let truncated = &reordered[3..13];
    assert_eq!(truncated.len(), 10);
    let short = [0x00u8, 0x07, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut garbage = body.clone();
    garbage.push(0xFF);
    let no_tag0 = [0x01u8, 0x00, 0xBB];
    let confirm_shaped = [0x00u8, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    for (cmd, b) in [
        (0x11u8, truncated),
        (0x11u8, &short[..]),
        (0x11u8, &garbage[..]),
        (0x11u8, &no_tag0[..]),
        (0x11u8, &confirm_shaped[..]),
        (0x01u8, &body[..]),
        (0x0Au8, &body[..]),
        (0x12u8, &body[..]),
    ] {
        let t = chain::dissect(&wrap_aps_command(cmd, b)).unwrap();
        assert_eq!(t.apscmd().expect("unknown leg").kind, K::Unknown);
        assert_eq!(note_reasons(&t), vec!["trailing"]);
        assert_eq!(session::classify_tree(&t), None);
    }
    // A lone command octet (empty body) refuses the leg outright but
    // keeps the same stop.
    let lone = chain::dissect(&wrap_aps_command(0x11, &[])).unwrap();
    assert!(lone.apscmd().is_none());
    assert_eq!(note_reasons(&lone), vec!["trailing"]);
}
