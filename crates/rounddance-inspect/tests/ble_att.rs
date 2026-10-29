//! Wave-53 BLE/ATT decode leg: the inspector gains a BLE leg.
//!
//! Provenance: HCI/ATT octets are verbatim wave-52 BLE captures
//! (`~/hwscratch/w52/hci_runA1-7f68.btsnoop`, read-only; plaintext
//! protocol PDUs — no key material is involved anywhere on this
//! leg). Longer commissioning write values and wrapped keys stay
//! length-named only, exactly like the Touchlink wrapped-key rule.
//! Analyzer: `python3 analyze53_ble.py` in `~/hwscratch/w53/`
//! (CENSUS PASS: 387/387 ACL payloads parse as HCI+ACL+L2CAP+ATT;
//! MTU {256, 517}; the exact 13-UUID Direct set).
//!
//! Reproduce-then-fix: every `repro_*` test below fails on the
//! pre-fix dissector (no BLE leg at all), then passes with the leg.

use rounddance_inspect::{ble, btsnoop, chain, report, session, tree};

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
// RD-INSPECT-34: HCI event/ACL framing + ATT opcodes (MTU exchange,
// write/notify handle decode). Failing-first: no BLE entry point.
// ---------------------------------------------------------------------------

/// Verbatim HCI command (host->controller): LE Set Random Address.
const HCI_CMD: &str = "052006083bf005c428";
/// Verbatim HCI event (controller->host): Command Complete.
const HCI_EVT: &str = "0e0401052000";
/// Verbatim ACL TX: ATT Exchange MTU Request, client RX MTU 517.
const ACL_MTU_REQ: &str = "4000070003000400020502";
/// Verbatim ACL RX: ATT Exchange MTU Response, server RX MTU 256.
const ACL_MTU_RSP: &str = "4020070003000400030001";
/// Verbatim ACL RX: ATT Error Response (write 0x001c, code 0x80).
const ACL_ERR80: &str = "402009000500040001121c0080";

#[test]
fn repro_hci_records_have_no_ble_leg() {
    // Required: HCI framing names kind + opcode/event, ACL names
    // the connection handle; command/event records file no ATT leg.
    let cmd = chain::dissect_ble(btsnoop::FLAGS_HCI_CMD, &hex(HCI_CMD)).unwrap();
    let h = cmd.hci().expect("hci node");
    assert_eq!(h.kind, tree::HciKind::Command);
    assert_eq!(h.opcode, Some(0x2005));
    assert!(cmd.att().is_none());

    let evt = chain::dissect_ble(btsnoop::FLAGS_HCI_EVT, &hex(HCI_EVT)).unwrap();
    let e = evt.hci().expect("hci node");
    assert_eq!(e.kind, tree::HciKind::Event);
    assert_eq!(e.event, Some(0x0e));
    assert!(evt.att().is_none());
}

#[test]
fn hci_acl_mtu_exchange_names_mtu_values() {
    let req = chain::dissect_ble(btsnoop::FLAGS_ACL_TX, &hex(ACL_MTU_REQ)).unwrap();
    let h = req.hci().expect("hci node");
    assert_eq!(h.kind, tree::HciKind::AclTx);
    assert_eq!(h.conn_handle, Some(0x0040));
    let a = req.att().expect("att node");
    assert_eq!(a.opcode, 0x02);
    assert_eq!(a.mtu, Some(517));
    assert_eq!(note_reasons(&req), Vec::<&str>::new());

    let rsp = chain::dissect_ble(btsnoop::FLAGS_ACL_RX, &hex(ACL_MTU_RSP)).unwrap();
    let a = rsp.att().expect("att node");
    assert_eq!(a.opcode, 0x03);
    assert_eq!(a.mtu, Some(256));

    let text = report::to_text(&rsp);
    assert!(text.contains("hci:"));
    assert!(text.contains("att:"));
    assert!(text.contains("mtu=256"));
    let json = report::to_json(&rsp);
    assert!(json.contains("\"att\""));
    assert!(json.contains("\"mtu\":256"));
}

#[test]
fn att_error_response_names_request_and_code() {
    let t = chain::dissect_ble(btsnoop::FLAGS_ACL_RX, &hex(ACL_ERR80)).unwrap();
    let a = t.att().expect("att node");
    assert_eq!(a.opcode, 0x01);
    assert_eq!(a.req_opcode, Some(0x12));
    assert_eq!(a.handle, Some(0x001c));
    // 0x80 is the Direct insufficient-authorization application
    // error: filed as a code, never interpreted as a TLV here.
    assert_eq!(a.error, Some(0x80));
}

#[test]
fn hci_framing_failures_are_typed() {
    assert_eq!(chain::dissect_ble(2, &[]), Err(tree::TreeError::Empty));
    assert_eq!(
        chain::dissect_ble(2, &[0x05]),
        Err(tree::TreeError::BleTruncated)
    );
    assert_eq!(
        chain::dissect_ble(9, &[0x00]),
        Err(tree::TreeError::BleMalformed)
    );
    // Non-ATT L2CAP CID (0x0005 signalling): HCI leg stands, the
    // remainder files `ble-unknown` with no ATT leg.
    let sig = hex("400008000400050001000400");
    let t = chain::dissect_ble(btsnoop::FLAGS_ACL_TX, &sig).unwrap();
    assert!(t.hci().is_some());
    assert!(t.att().is_none());
    assert_eq!(note_reasons(&t), vec!["ble-unknown"]);
    // Unknown ATT opcode still names its octet, never a guess.
    let unk = hex("4000050001000400ff");
    let t = chain::dissect_ble(btsnoop::FLAGS_ACL_TX, &unk).unwrap();
    let a = t.att().expect("att node");
    assert_eq!(a.opcode, 0xff);
    assert_eq!(a.kind, tree::AttKind::Unknown);
}

// ---------------------------------------------------------------------------
// RD-INSPECT-35: Direct service/char attribution by UUID + Direct PDU
// envelope naming (decode-only, no crypto; TLV bodies never rendered).
// ---------------------------------------------------------------------------

/// Verbatim ACL RX: Read By Group Response naming both Direct
/// services (Security 0x000e-0x0017, Commissioning 0x0018+).
const ACL_GRP_RSP: &str = "40202e002a00040011140e001700e329b499026de9bf81440000f44a14291800fffffb349b5f8000008000100000f7ff0000";
/// Verbatim ACL RX: Read By Type Response naming all 11 Direct
/// characteristics (3 security + 8 commissioning).
const ACL_TYP_RSP: &str = "4020ed00e900040009150f00281000e329b499026de9bf81440100f44a14291200281300e329b499026de9bf81440200f44a14291500281600e329b499026de9bf81440300f44a14291900081a00613a33271c4963b11c4201007d3772701b00081c00613a33271c4963b11c4202007d3772701d00081e00613a33271c4963b11c4203007d3772701f00082000613a33271c4963b11c4204007d3772702100122200613a33271c4963b11c4205007d3772702400082500613a33271c4963b11c4206007d37727026000a2700613a33271c4963b11c4207007d3772702800082900613a33271c4963b11c4208007d377270";
/// Verbatim ACL TX: Write Request to handle 0x001c carrying the
/// 27-octet Direct TLV sequence (6 TLVs, first tag 0x00).
const ACL_WRITE27: &str =
    "400022001e000400121c000008000000000000000201022b1a02010f05010106020100070102";
/// Verbatim ACL RX: Handle Value Notification on 0x0022 carrying a
/// Direct Status Code TLV (domain 0x00 GENERAL, success).
const ACL_NOTIFY: &str = "40200b00070004001b22000e020000";

#[test]
fn repro_discovery_without_direct_attribution() {
    // Required: discovery responses carrying Direct UUIDs earn a
    // Direct leg; both services named, no NWK/APS/ZCL legs ever.
    let t = chain::dissect_ble(btsnoop::FLAGS_ACL_RX, &hex(ACL_GRP_RSP)).unwrap();
    assert!(t.nwk().is_none() && t.aps().is_none() && t.zcl().is_none());
    let d = t.direct().expect("direct node");
    assert_eq!(d.kind, tree::DirectKind::Discovery);
    assert_eq!(d.services, 0x03, "security + commissioning seen");
    assert_eq!(d.entries, 2);
}

#[test]
fn direct_discovery_names_all_eleven_characteristics() {
    let t = chain::dissect_ble(btsnoop::FLAGS_ACL_RX, &hex(ACL_TYP_RSP)).unwrap();
    let d = t.direct().expect("direct node");
    assert_eq!(d.kind, tree::DirectKind::Discovery);
    assert_eq!(d.sec_chars, 0x07, "all three auth chars");
    assert_eq!(d.comm_chars, 0xff, "all eight commissioning chars");
    assert_eq!(d.entries, 11);
    assert_eq!(d.services, 0x00, "char discovery names no service");
    // Non-Direct discovery (16-bit generic services) earns no leg.
    let generic = hex("400012000e00040011060e00170000181800ffff0118");
    let g = chain::dissect_ble(btsnoop::FLAGS_ACL_RX, &generic).unwrap();
    assert!(g.att().is_some());
    assert!(g.direct().is_none());
    assert_eq!(note_reasons(&g), Vec::<&str>::new());
}

#[test]
fn direct_status_notify_names_domain_and_code() {
    let t = chain::dissect_ble(btsnoop::FLAGS_ACL_RX, &hex(ACL_NOTIFY)).unwrap();
    let a = t.att().expect("att node");
    assert_eq!(a.opcode, 0x1b);
    assert_eq!(a.handle, Some(0x0022));
    let d = t.direct().expect("direct node");
    assert_eq!(d.kind, tree::DirectKind::Status);
    assert_eq!(d.domain, 0x00);
    assert_eq!(d.code, 0x00);
    // Form-network success notify from the same capture class.
    let form = hex("40200b00070004001b22000e020100");
    let f = chain::dissect_ble(btsnoop::FLAGS_ACL_RX, &form).unwrap();
    let fd = f.direct().expect("direct node");
    assert_eq!((fd.domain, fd.code), (0x01, 0x00));
    // A non-status notify value earns no Direct leg.
    let other = hex("40200a00060004001b2200aabbcc");
    let o = chain::dissect_ble(btsnoop::FLAGS_ACL_RX, &other).unwrap();
    assert!(o.att().is_some());
    assert!(o.direct().is_none());
    let text = report::to_text(&t);
    assert!(text.contains("direct:"));
    assert!(text.contains("status"));
    let json = report::to_json(&t);
    assert!(json.contains("\"direct\""));
}

#[test]
fn direct_write_envelope_names_tlvs_without_bodies() {
    let t = chain::dissect_ble(btsnoop::FLAGS_ACL_TX, &hex(ACL_WRITE27)).unwrap();
    let a = t.att().expect("att node");
    assert_eq!(a.opcode, 0x12);
    assert_eq!(a.handle, Some(0x001c));
    assert_eq!(a.payload_len, 27);
    let d = t.direct().expect("direct node");
    assert_eq!(d.kind, tree::DirectKind::Envelope);
    assert_eq!(d.entries, 6, "six TLVs in the JoinNetwork value");
    assert_eq!(d.first_tag, 0x00);
    assert_eq!(d.payload_len, 27);
    // TLV bodies (which may carry key material) are never rendered.
    let text = report::to_text(&t);
    assert!(!text.contains("2b1a"));
    assert!(!report::to_json(&t).contains("2b1a"));
    // A short CCC write (`02 00`) is one bare TLV, not a Direct
    // envelope: ATT leg only, no Direct leg.
    let ccc = hex("40000900050004001209000200");
    let c = chain::dissect_ble(btsnoop::FLAGS_ACL_TX, &ccc).unwrap();
    assert!(c.att().is_some());
    assert!(c.direct().is_none());
}

#[test]
fn ble_trees_fold_without_device_attribution() {
    // BLE trees carry no 15.4 addresses: session counts the tree
    // under PAN 0 with no device row and zero secured accounting.
    let mut eng = session::SessionEngine::new();
    let t = chain::dissect_ble(btsnoop::FLAGS_ACL_RX, &hex(ACL_NOTIFY)).unwrap();
    eng.note_tree(&t);
    eng.note_tree(&t);
    assert_eq!(eng.trees, 2);
    assert!(eng.devices().iter().all(|d| d.is_none()));
    assert_eq!(eng.secured_decryptable, 0);
    assert_eq!(eng.secured_orphan, 0);
    let net = eng.network(0).expect("PAN 0 row");
    assert_eq!(net.frames, 2);
}

// ---------------------------------------------------------------------------
// RD-INSPECT-36: btsnoop ingest + w52 regression goldens (hashes and
// metadata in-repo; captures stay read-only under `~/hwscratch/w52`).
// ---------------------------------------------------------------------------

#[test]
fn btsnoop_ingest_reads_hci_records_and_skips_control() {
    // Hand-built btsnoop: magic + version/datalink, one system note
    // (skipped), one HCI command, one HCI event, one ACL.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"btsnoop\0");
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&2001u32.to_be_bytes());
    let rec = |flags: u32, pkt: &[u8], out: &mut Vec<u8>| {
        out.extend_from_slice(&(pkt.len() as u32).to_be_bytes());
        out.extend_from_slice(&(pkt.len() as u32).to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0i64.to_be_bytes());
        out.extend_from_slice(pkt);
    };
    rec(0xFFFF000C, b"note-skipped", &mut buf);
    rec(btsnoop::FLAGS_HCI_CMD, &hex(HCI_CMD), &mut buf);
    rec(btsnoop::FLAGS_HCI_EVT, &hex(HCI_EVT), &mut buf);
    rec(btsnoop::FLAGS_ACL_RX, &hex(ACL_MTU_RSP)[..], &mut buf);
    let pkts = btsnoop::read_all(&mut &buf[..]).unwrap();
    assert_eq!(pkts.len(), 3);
    assert_eq!(pkts[0].flags, btsnoop::FLAGS_HCI_CMD);
    assert_eq!(pkts[2].data, hex(ACL_MTU_RSP));
    // Every ACL record dissects with no errors.
    for p in &pkts {
        let _ = chain::dissect_ble(p.flags, &p.data).unwrap();
    }
    // Bad magic and truncation are typed, never panics.
    assert!(btsnoop::read_all(&mut &b"nope"[..]).is_err());
    assert!(btsnoop::read_all(&mut &buf[..buf.len() - 3]).is_err());
}

#[test]
fn ble_truncation_prefixes_are_typed_and_panic_free() {
    // Every truncation prefix of every verbatim vector dissects to
    // a sub-tree or a typed error — never a panic. Full-length
    // inputs decode (pinned above); shorter ones refuse or stop.
    let vectors: &[(u32, &str)] = &[
        (btsnoop::FLAGS_HCI_CMD, HCI_CMD),
        (btsnoop::FLAGS_HCI_EVT, HCI_EVT),
        (btsnoop::FLAGS_ACL_TX, ACL_MTU_REQ),
        (btsnoop::FLAGS_ACL_RX, ACL_MTU_RSP),
        (btsnoop::FLAGS_ACL_RX, ACL_ERR80),
        (btsnoop::FLAGS_ACL_RX, ACL_GRP_RSP),
        (btsnoop::FLAGS_ACL_RX, ACL_TYP_RSP),
        (btsnoop::FLAGS_ACL_TX, ACL_WRITE27),
        (btsnoop::FLAGS_ACL_RX, ACL_NOTIFY),
    ];
    for (flags, v) in vectors {
        let full = hex(v);
        for len in 0..full.len() {
            let r = chain::dissect_ble(*flags, &full[..len]);
            match r {
                Ok(tree) => {
                    assert!(!tree.is_empty());
                    let _ = report::to_text(&tree);
                    let _ = report::to_json(&tree);
                    let mut eng = session::SessionEngine::new();
                    eng.note_tree(&tree);
                }
                Err(e) => assert!(matches!(
                    e,
                    tree::TreeError::Empty
                        | tree::TreeError::BleTruncated
                        | tree::TreeError::BleMalformed
                )),
            }
        }
        // Full length always decodes (golden shape).
        assert!(chain::dissect_ble(*flags, &full).is_ok());
    }
}

#[test]
fn direct_envelope_refusals_stay_undecided() {
    // Reserved-tag values, bad domains, and short statuses earn no
    // Direct leg — the ATT leg still stands with no stop.
    let att_write = |value: &str| {
        let mut rec = hex("4000070003000400120900");
        let v = hex(value);
        rec[4] = (3 + v.len()) as u8;
        rec[2] = (7 + v.len()) as u8;
        rec.extend_from_slice(&v);
        rec
    };
    // Reserved first tag: refused.
    let t = chain::dissect_ble(btsnoop::FLAGS_ACL_TX, &att_write("1000")).unwrap();
    assert!(t.att().is_some());
    assert!(t.direct().is_none());
    // Undefined status domain: refused.
    let bad = hex("40200b00070004001b22000e020801");
    let b = chain::dissect_ble(btsnoop::FLAGS_ACL_RX, &bad).unwrap();
    assert!(b.att().is_some());
    assert!(b.direct().is_none());
    // Truncated status (3 value bytes): refused.
    let short = hex("40200a00060004001b22000e0200");
    let s = chain::dissect_ble(btsnoop::FLAGS_ACL_RX, &short).unwrap();
    assert!(s.att().is_some());
    assert!(s.direct().is_none());
}

#[test]
fn ble_hci_layer_reuses_direct_uuid_tables() {
    // The attribution source is the `rounddance-direct` GATT model,
    // not a parallel constant table in the inspector.
    assert_eq!(rounddance_direct::gatt::SECURITY_CHARS.len(), 3);
    assert_eq!(rounddance_direct::gatt::COMMISSIONING_CHARS.len(), 8);
    assert_eq!(ble::DIRECT_UUID_COUNT, 13);
}
