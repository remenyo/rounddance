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
