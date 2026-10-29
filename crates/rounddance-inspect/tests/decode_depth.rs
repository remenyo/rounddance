//! Wave-50 leftover reproductions: every carried wave-49 item must fail
//! on the pre-fix dissector before it is closed.
//!
//! Provenance: quirk octets are verbatim wave-49 live frames
//! (`~/hwscratch/w49/r1k.frames.log` f611, 76 octets, bogus-positive
//! rssi +126 — the INS-LIVE-02 class); the ZDO and session legs are
//! codec-built shapes of the live-confirmed classes (analyzer
//! `~/hwscratch/w49/analyze49.py`: `zdo/annce`, `zdo/lqi-rsp`,
//! `nwk/rejoin-req`, ...). No key material anywhere.

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
    // Version 3 (Green-Power value): same refusal, no leg.
    let ver3 = hex("4188016137ffff34120c00341256781e090000");
    let tree3 = chain::dissect(&ver3).unwrap();
    assert!(tree3.nwk().is_none());
    assert_eq!(note_reasons(&tree3), vec!["unknown"]);
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
