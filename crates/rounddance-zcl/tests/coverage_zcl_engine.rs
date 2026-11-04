//! Coverage vectors for the ZCL foundation/engine (doc `07-5123-08`,
//! chapter 2): frame header, data-type codec, attribute store,
//! general command codecs, reporting engine, discovery handlers,
//! dispatch triage, transaction table, and status mapping.
//!
//! Each test names the requirement ID it verifies. Byte strings are
//! hand-computed from the paraphrased layouts in
//! `rounddance_zcl::{frame, types, attrs, general, reporting,
//! discovery, dispatch, transaction, status}` — never copied from
//! spec text (D1, `SCOPE.md` §2). Corpus-mined IDs are reused
//! verbatim; repo-minted IDs are MINTED-pending-confirm.
//!
//! Anchor cites below are extraction line anchors
//! (`pNNNN-Lxxx`) into the corpus mirror of doc `07-5123-08`.

use rounddance_zcl::attrs::{access, AttrDef, AttrStore, ATTR_CLUSTER_REVISION};
use rounddance_zcl::behavior::{Ctx, EventQueue};
use rounddance_zcl::cluster::{find_generated, find_received, ClusterDef, ClusterRole, CmdDef};
use rounddance_zcl::discovery::{handle_discover_attrs, handle_discover_cmds};
use rounddance_zcl::dispatch::{check_manufacturer, should_default_respond, Endpoint};
use rounddance_zcl::frame::{Direction, FrameControl, FrameType, Header};
use rounddance_zcl::general::{
    self, CfgStatus, DefaultRsp, DiscoverAttrs, DiscoverCmds, ReadCfgQuery, ReadRecord,
    ReportCfgRecord, ReportRecord, WriteRecord, WriteStatus,
};
use rounddance_zcl::reporting::{change_qualifies, QueryAnswer, ReportSlot, ReportingEngine};
use rounddance_zcl::transaction::{
    build_default_response, decode_default_response, reply_direction_ok, PendingTable, TsnAlloc,
    TxnError,
};
use rounddance_zcl::types::{DataType, Value, MAX_STR_LEN};
use rounddance_zcl::{Error, ZclStatus};

fn to_server(disable: bool, cmd: u8) -> Header {
    Header {
        control: FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: disable,
        },
        manufacturer_code: None,
        tsn: 3,
        command_id: cmd,
    }
}

// ---- frame (anchor p0062-L2431-L2432, p0057-L2273-L2274) ------------

// 07-5123-08-2411-02: frame-control bit positions.
#[test]
fn vector_frame_control_roundtrip_07_5123_08_2411_02() {
    let control = FrameControl {
        frame_type: FrameType::ClusterSpecific,
        manufacturer_specific: true,
        direction: Direction::ToClient,
        disable_default_response: true,
    };
    let byte = control.encode();
    assert_eq!(byte & 0x03, 0x01);
    assert_ne!(byte & 0x04, 0);
    assert_ne!(byte & 0x08, 0);
    assert_ne!(byte & 0x10, 0);
    let back = FrameControl::decode(byte).unwrap();
    assert_eq!(back.frame_type, FrameType::ClusterSpecific);
    assert!(back.manufacturer_specific);
    assert_eq!(back.direction, Direction::ToClient);
    assert!(back.disable_default_response);
    assert!(FrameControl::decode(0x06).is_err());
}

// 07-5123-08-24111-01: header manufacturer presence mismatch.
#[test]
fn vector_header_presence_mismatch_07_5123_08_24111_01() {
    let hdr = Header {
        control: FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: Some(0x1234),
        tsn: 9,
        command_id: 0x00,
    };
    let mut buf = [0u8; Header::MAX_LEN];
    assert_eq!(hdr.encode_into(&mut buf), Err(Error::PresenceMismatch));
    // Manufacturer-specific without a code is the mirror fault.
    let hdr2 = Header {
        control: FrameControl {
            manufacturer_specific: true,
            ..hdr.control
        },
        manufacturer_code: None,
        ..hdr
    };
    assert_eq!(hdr2.encode_into(&mut buf), Err(Error::PresenceMismatch));
    // Truncated wire is refused, never panicked on.
    assert!(Header::decode(&[0x00]).is_err());
    assert!(Header::decode(&[0x04]).is_err());
}

// 07-5123-08-2413-01: reply header flips direction, keeps TSN.
#[test]
fn vector_reply_header_direction_07_5123_08_2413_01() {
    let req = to_server(false, general::cmd::READ);
    let rsp = Header::reply_to(&req, general::cmd::READ_RSP);
    assert_eq!(rsp.control.direction, Direction::ToClient);
    assert_eq!(rsp.tsn, req.tsn);
    assert_eq!(rsp.command_id, general::cmd::READ_RSP);
    // Replying to a ToClient frame flips back to ToServer.
    let back = Header::reply_to(&rsp, general::cmd::DEFAULT_RSP);
    assert_eq!(back.control.direction, Direction::ToServer);
}

// 07-5123-08-2412-01: reply-direction gate for Default Responses.
#[test]
fn vector_reply_direction_gate_07_5123_08_2412_01() {
    // Incoming requests travel toward the server ...
    assert!(!reply_direction_ok(&to_server(false, general::cmd::READ)));
    // ... while replies travel toward the client.
    let rsp = Header::reply_to(
        &to_server(false, general::cmd::READ),
        general::cmd::READ_RSP,
    );
    assert!(reply_direction_ok(&rsp));
}

// ---- data types (anchors p0068-L2596-L2615, §2.6.2) -----------------

// 07-5123-08-262-01: codable scalar set round-trips.
#[test]
fn vector_scalar_codec_set_07_5123_08_262_01() {
    let mut buf = [0u8; 16];
    let v = Value::UInt {
        width: 4,
        v: 0xdead_beef,
    };
    let n = v.encode_into(&mut buf).unwrap();
    assert_eq!(n, 4);
    let (back, used) = Value::decode(DataType::UInt(4), &buf[..n]).unwrap();
    assert_eq!(used, 4);
    assert_eq!(back, v);
    // Signed and boolean extremes.
    let neg = Value::Int { width: 2, v: -1 };
    let n = neg.encode_into(&mut buf).unwrap();
    let (back, _) = Value::decode(DataType::Int(2), &buf[..n]).unwrap();
    assert_eq!(back, neg);
    assert!(Value::Bool(true).encode_into(&mut buf).is_ok());
    // Out-of-range booleans are refused on decode.
    assert!(Value::decode(DataType::Bool, &[0x02]).is_err());
}

// 07-5123-08-262-02: strings are length-capped, never grown.
#[test]
fn vector_string_cap_07_5123_08_262_02() {
    let mut bytes = [0x41u8; MAX_STR_LEN];
    bytes[0] = 0x5a;
    let v = Value::CharStr {
        len: MAX_STR_LEN as u8,
        bytes,
    };
    let mut buf = [0u8; MAX_STR_LEN + 1];
    let n = v.encode_into(&mut buf).unwrap();
    assert_eq!(n, MAX_STR_LEN + 1);
    let (back, used) = Value::decode(DataType::CharStr, &buf[..n]).unwrap();
    assert_eq!((used, back), (n, v));
    // Over-long declared length is refused.
    assert!(Value::decode(DataType::CharStr, &[0xff, 0x41]).is_err());
}

// 07-5123-08-262-03: unknown/unsupported types are typed errors.
#[test]
fn vector_type_errors_07_5123_08_262_03() {
    assert_eq!(DataType::from_u8(0xfe), Err(Error::UnknownDatatype(0xfe)));
    // Composite types are recognized but not carried.
    assert!(matches!(
        Value::decode(DataType::Composite(0x51), &[0x00]),
        Err(Error::UnsupportedType(0x51))
    ));
    assert!(Value::NoData.encode_into(&mut [0u8; 8]).is_ok());
}

// ---- attribute store (anchors p0058-L2309-L2318, p0067-L2561) -------

fn attr_def(id: u16, datatype: u8, acc: u8) -> AttrDef {
    AttrDef {
        id,
        datatype,
        access: acc,
        reportable: false,
    }
}

// 07-5123-08-2344-01: access classes gate writes.
#[test]
fn vector_attr_access_gates_07_5123_08_2344_01() {
    let mut store = AttrStore::new(None);
    store
        .add(
            attr_def(0x0000, DataType::Bool.as_u8(), access::READ),
            Value::Bool(false),
        )
        .unwrap();
    // Read-only attributes refuse writes with ReadOnly ...
    assert_eq!(
        store.write(0x0000, Value::Bool(true)),
        Err(ZclStatus::ReadOnly)
    );
    // ... and local (behavior-side) updates bypass the gate.
    store.set_local(0x0000, Value::Bool(true)).unwrap();
    assert_eq!(store.get(0x0000), Some(Value::Bool(true)));
    // Type mismatch on a readable attribute reports the type fault.
    store
        .add(
            attr_def(
                0x0001,
                DataType::UInt(1).as_u8(),
                access::READ | access::WRITE,
            ),
            Value::UInt { width: 1, v: 0 },
        )
        .unwrap();
    assert_eq!(
        store.write(0x0001, Value::Bool(true)),
        Err(ZclStatus::InvalidDataType)
    );
}

// 07-5123-08-253-01: duplicate/overflow/unknown attribute guards.
#[test]
fn vector_attr_registry_guards_07_5123_08_253_01() {
    let mut store = AttrStore::new(None);
    store
        .add(
            attr_def(
                0x0001,
                DataType::UInt(1).as_u8(),
                access::READ | access::WRITE,
            ),
            Value::UInt { width: 1, v: 0 },
        )
        .unwrap();
    assert_eq!(
        store.add(
            attr_def(0x0001, DataType::UInt(1).as_u8(), access::READ),
            Value::UInt { width: 1, v: 0 }
        ),
        Err(Error::DuplicateAttribute)
    );
    assert_eq!(
        store.write(0x00ff, Value::UInt { width: 1, v: 0 }),
        Err(ZclStatus::UnsupportedAttribute)
    );
    assert_eq!(store.definition(0x00ff), None);
    // Globals ride along with the revision.
    store.add_globals(3).unwrap();
    assert!(store.definition(ATTR_CLUSTER_REVISION).is_some());
}

// ---- general command codecs (§2.5.1-§2.5.11) ------------------------

#[test]
fn vector_id_list_codec_07_5123_08_25_02() {
    let mut buf = [0u8; 8];
    let n = general::encode_id_list(&[0x0000, 0x0001, 0xfffd], &mut buf).unwrap();
    assert_eq!(n, 6);
    let mut out = [0u16; 4];
    let m = general::decode_id_list(&buf[..n], &mut out).unwrap();
    assert_eq!(&out[..m], &[0x0000, 0x0001, 0xfffd]);
    // Odd-length bodies are malformed lists.
    let mut tiny = [0u16; 4];
    assert_eq!(
        general::decode_id_list(&buf[..5], &mut tiny),
        Err(Error::MalformedList)
    );
    // Overflow is refused, never truncated silently.
    let mut one = [0u16; 1];
    assert!(general::decode_id_list(&buf[..n], &mut one).is_err());
}

#[test]
fn vector_write_roundtrip_07_5123_08_253_01() {
    // Write On/Off = 1: id + type + LE value.
    let wire: &[u8] = &[0x00, 0x00, 0x10, 0x01];
    let mut recs = [WriteRecord {
        id: 0,
        dtype: 0,
        value: Value::NoData,
    }; 2];
    assert_eq!(general::decode_write(wire, &mut recs).unwrap(), 1);
    assert_eq!(recs[0].id, 0x0000);
    assert_eq!(recs[0].value, Value::Bool(true));
    // All-success write response compacts to one octet.
    let mut out = [0u8; 8];
    let ok = [WriteStatus {
        status: ZclStatus::Success,
        id: None,
    }];
    assert_eq!(general::encode_write_rsp(&ok, &mut out).unwrap(), 1);
    assert_eq!(out[0], 0x00);
    // Mixed outcomes list every failure with its identifier;
    // bare-success records are omitted from the mixed form.
    let mixed = [
        WriteStatus {
            status: ZclStatus::Success,
            id: None,
        },
        WriteStatus {
            status: ZclStatus::ReadOnly,
            id: Some(0x0000),
        },
    ];
    let n = general::encode_write_rsp(&mixed, &mut out).unwrap();
    assert_eq!(&out[..n], &[0x88, 0x00, 0x00]);
    let mut back = [WriteStatus {
        status: ZclStatus::Success,
        id: None,
    }; 2];
    assert_eq!(general::decode_write_rsp(&out[..n], &mut back).unwrap(), 1);
    assert_eq!(back[0], mixed[1]);
}

#[test]
fn vector_report_codec_07_5123_08_2511_01() {
    let mut bytes = [0u8; MAX_STR_LEN];
    bytes[0] = 0x41;
    let rec = ReportRecord {
        id: 0x0000,
        dtype: DataType::CharStr.as_u8(),
        value: Value::CharStr { len: 1, bytes },
    };
    let mut buf = [0u8; 40];
    let n = general::encode_report(&[rec], &mut buf).unwrap();
    let mut out = [ReportRecord {
        id: 0,
        dtype: 0,
        value: Value::NoData,
    }; 2];
    let m = general::decode_report(&buf[..n], &mut out).unwrap();
    assert_eq!(m, 1);
    assert_eq!(out[0].id, 0x0000);
    assert_eq!(out[0].value, rec.value);
    assert!(general::decode_report(&buf[..2], &mut out).is_err());
}

#[test]
fn vector_config_report_codec_07_5123_08_257_01() {
    // Discrete record: no change field on the wire.
    let wire: &[u8] = &[0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x3c, 0x00];
    let mut recs = [ReportCfgRecord {
        direction: 0xff,
        id: 0,
        dtype: 0,
        min: 0,
        max: 0,
        change: None,
        timeout: 0,
    }; 2];
    assert_eq!(general::decode_config_report(wire, &mut recs).unwrap(), 1);
    assert_eq!((recs[0].min, recs[0].max, recs[0].change), (1, 60, None));
    // Analog record carries its change threshold.
    let analog: &[u8] = &[0x00, 0x01, 0x00, 0x21, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00];
    assert_eq!(general::decode_config_report(analog, &mut recs).unwrap(), 1);
    assert_eq!(recs[0].change, Some(Value::UInt { width: 2, v: 10 }));
    let mut buf = [0u8; 32];
    let n = general::encode_config_report(&recs[..1], &mut buf).unwrap();
    assert_eq!(&buf[..n], analog);
    // Response records round-trip with per-record status.
    let rsp = [CfgStatus {
        status: ZclStatus::Success,
        direction: None,
        id: None,
    }];
    let n2 = general::encode_config_report_rsp(&rsp, &mut buf).unwrap();
    assert_eq!(n2, 1);
    let mut out2 = [CfgStatus {
        status: ZclStatus::Failure,
        direction: None,
        id: None,
    }; 2];
    let m2 = general::decode_config_report_rsp(&buf[..n2], &mut out2).unwrap();
    assert_eq!((m2, out2[0].status), (1, ZclStatus::Success));
}

#[test]
fn vector_read_report_cfg_codec_07_5123_08_25_10_01() {
    let wire: &[u8] = &[0x00, 0x00, 0x00];
    let mut out = [ReadCfgQuery {
        direction: 0xff,
        id: 0,
    }; 2];
    let m = general::decode_read_report_cfg(wire, &mut out).unwrap();
    assert_eq!((m, out[0].id), (1, 0x0000));
    let rec = ReadRecord {
        id: 0x0001,
        status: ZclStatus::Success,
        dtype: DataType::UInt(1).as_u8(),
        value: Value::UInt { width: 1, v: 9 },
    };
    let mut rbuf = [0u8; 16];
    let n = general::encode_read_rsp(&[rec], &mut rbuf).unwrap();
    let mut rout = [ReadRecord {
        id: 0,
        status: ZclStatus::Failure,
        dtype: 0,
        value: Value::NoData,
    }; 2];
    let m2 = general::decode_read_rsp(&rbuf[..n], &mut rout).unwrap();
    assert_eq!(
        (m2, rout[0].status, rout[0].id),
        (1, ZclStatus::Success, 0x0001)
    );
    assert_eq!(rout[0].value, rec.value);
}

// 07-5123-08-2512-01: Default Response encode/decode + triage.
#[test]
fn vector_default_response_triage_07_5123_08_2512_01() {
    let rsp = DefaultRsp {
        cmd: general::cmd::READ,
        status: ZclStatus::Success,
    };
    let mut buf = [0u8; 8];
    let n = rsp.encode_into(&mut buf).unwrap();
    assert_eq!(n, 2);
    let back = DefaultRsp::decode(&buf[..n]).unwrap();
    assert_eq!(
        (back.cmd, back.status),
        (general::cmd::READ, ZclStatus::Success)
    );
    assert!(DefaultRsp::decode(&buf[..1]).is_err());
    // Triage: unicast errors answer unless the frame disables them;
    // an already-replied exchange stays silent.
    let plain = to_server(false, general::cmd::READ);
    let muted = to_server(true, general::cmd::READ);
    assert!(should_default_respond(&plain, true, false, true));
    assert!(!should_default_respond(&muted, true, false, false));
    assert!(should_default_respond(&muted, true, false, true));
    // An enabled unicast frame still answers success (the disable
    // bit, not the outcome, gates the response); a replied one never
    // echoes, and broadcasts/Default Responses never echo.
    assert!(should_default_respond(&plain, true, false, false));
    assert!(!should_default_respond(&plain, true, true, false));
    assert!(!should_default_respond(&plain, true, true, true));
    // Broadcasts and Default Responses never echo.
    assert!(!should_default_respond(&plain, false, false, true));
    let is_rsp = to_server(false, general::cmd::DEFAULT_RSP);
    assert!(!should_default_respond(&is_rsp, true, false, true));
}

// ---- discovery (§2.5.13/§2.5.14/§2.5.18, anchors p0081-p0090) -------

struct FakeDef;
static FAKE_ATTRS: &[AttrDef] = &[
    AttrDef {
        id: 0x0000,
        datatype: 0x10,
        access: access::READ,
        reportable: false,
    },
    AttrDef {
        id: 0x0001,
        datatype: 0x10,
        access: access::READ,
        reportable: false,
    },
];
impl ClusterDef for FakeDef {
    fn cluster_id(&self) -> u16 {
        0x0006
    }
    fn name(&self) -> &'static str {
        "fake"
    }
    fn revision(&self) -> u16 {
        1
    }
    fn role(&self) -> ClusterRole {
        ClusterRole::Server
    }
    fn attributes(&self) -> &'static [AttrDef] {
        FAKE_ATTRS
    }
    fn received_commands(&self) -> &'static [CmdDef] {
        &[CmdDef {
            id: 0x00,
            name: "a",
        }]
    }
    fn generated_commands(&self) -> &'static [CmdDef] {
        &[CmdDef {
            id: 0x01,
            name: "b",
        }]
    }
}

#[test]
fn vector_discover_paging_07_5123_08_2513_01() {
    let mut store = AttrStore::new(None);
    for a in FakeDef.attributes() {
        store.add(*a, Value::Bool(false)).unwrap();
    }
    let req = DiscoverAttrs {
        start: 0x0000,
        max: 8,
    };
    let mut out = [(0u16, 0u8); 4];
    let (n, complete) = handle_discover_attrs(&store, req, false, &mut out);
    assert_eq!((n, complete), (2, true));
    // Paging from the second identifier yields one record.
    let req2 = DiscoverAttrs {
        start: 0x0001,
        max: 8,
    };
    let (n2, complete2) = handle_discover_attrs(&store, req2, false, &mut out);
    assert_eq!((n2, complete2), (1, true));
    // Manufacturer-specific discovery over standard definitions is
    // an empty complete page.
    let (n3, complete3) = handle_discover_attrs(&store, req, true, &mut out);
    assert_eq!((n3, complete3), (0, true));
    // Command discovery follows the frame direction.
    let hdr = to_server(false, general::cmd::DISCOVER_CMDS_RX);
    let creq = DiscoverCmds {
        start: 0x00,
        max: 8,
    };
    let mut cout = [0u8; 4];
    let (cn, ccomplete) = handle_discover_cmds(&FakeDef, &hdr, creq, &mut cout);
    assert_eq!((cn, ccomplete, cout[0]), (1, true, 0x00));
    assert!(find_received(&FakeDef, 0x00).is_some());
    assert!(find_generated(&FakeDef, 0x01).is_some());
    assert!(find_received(&FakeDef, 0x01).is_none());
}

// ---- dispatch (§2.3.2.1/§2.3.3/§2.5.12.2) ----------------------------

#[test]
fn vector_dispatch_gates_07_5123_08_233_01() {
    let mfr = Header {
        control: FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: true,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: Some(0x10ab),
        tsn: 1,
        command_id: general::cmd::READ,
    };
    assert!(check_manufacturer(&mfr, &[0x10ab]).is_ok());
    assert_eq!(
        check_manufacturer(&mfr, &[0x10cd]),
        Err(ZclStatus::UnsupCommand)
    );
    // Endpoint registry: unknown clusters miss (callers answer
    // UnsupportedCluster per 07-5123-08-2512-01).
    let mut ep = Endpoint::new();
    ep.add(&FakeDef).unwrap();
    assert!(ep.find(0x0006).is_some());
    assert!(ep.find(0x0703).is_none());
}

// ---- reporting (§2.5.7.1.5-1.7) -------------------------------------

#[test]
fn vector_reporting_change_gates_07_5123_08_257_02() {
    let slot = ReportSlot {
        attr: 0x0000,
        min_s: 1,
        max_s: 10,
        change: Value::UInt { width: 1, v: 5 },
        last_value: Value::UInt { width: 1, v: 10 },
        last_at_s: 0,
    };
    // Discrete change of any size qualifies ...
    assert!(change_qualifies(
        slot,
        Value::Bool(false),
        Value::Bool(true)
    ));
    // ... while analog changes need the configured delta ...
    assert!(!change_qualifies(
        slot,
        Value::UInt { width: 1, v: 10 },
        Value::UInt { width: 1, v: 12 }
    ));
    assert!(change_qualifies(
        slot,
        Value::UInt { width: 1, v: 10 },
        Value::UInt { width: 1, v: 15 }
    ));
    // ... and identical values never qualify.
    assert!(!change_qualifies(
        slot,
        Value::UInt { width: 1, v: 10 },
        Value::UInt { width: 1, v: 10 }
    ));
}

#[test]
fn vector_reporting_lifecycle_07_5123_08_257_03() {
    let mut store = AttrStore::new(None);
    store
        .add(
            AttrDef {
                id: 0x0001,
                datatype: DataType::UInt(2).as_u8(),
                access: access::READ | access::REPORT,
                reportable: true,
            },
            Value::UInt { width: 2, v: 100 },
        )
        .unwrap();
    store.add_globals(1).unwrap();
    let mut eng = ReportingEngine::new();
    assert!(eng.is_empty());
    let rec = ReportCfgRecord {
        direction: 0x00,
        id: 0x0001,
        dtype: DataType::UInt(2).as_u8(),
        min: 0,
        max: 10,
        change: Some(Value::UInt { width: 2, v: 10 }),
        timeout: 0,
    };
    assert!(eng.configure(&store, &rec, 0).is_success());
    assert_eq!(eng.len(), 1);
    // Unknown attributes are refused with a typed status.
    let bad = ReportCfgRecord { id: 0x00ff, ..rec };
    assert_eq!(
        eng.configure(&store, &bad, 0),
        ZclStatus::UnsupportedAttribute
    );
    // Query answers the live configuration.
    match eng.query(&store, 0x00, 0x0001) {
        QueryAnswer::Send { min_s, max_s, .. } => assert_eq!((min_s, max_s), (0, 10)),
        QueryAnswer::Bare { .. } | QueryAnswer::Timeout { .. } => panic!("expected live config"),
    }
    // Below-threshold moves stay silent; past-threshold moves go due.
    let mut due = [0u16; 4];
    store
        .set_local(0x0001, Value::UInt { width: 2, v: 105 })
        .unwrap();
    assert_eq!(eng.tick(&store, 1, &mut due), 0);
    store
        .set_local(0x0001, Value::UInt { width: 2, v: 115 })
        .unwrap();
    assert_eq!(eng.tick(&store, 2, &mut due), 1);
}

// ---- transaction (§2.4.1.3) ------------------------------------------

#[test]
fn vector_transaction_table_07_5123_08_2413_02() {
    let mut alloc = TsnAlloc::new(0xfe);
    assert_eq!(alloc.take(), 0xfe);
    assert_eq!(alloc.take(), 0xff);
    assert_eq!(alloc.peek(), 0x00);
    let mut table = PendingTable::<4>::new();
    assert!(table.is_empty());
    table.open(0x01, 0x0006, 0x00).unwrap();
    assert_eq!(table.len(), 1);
    // Duplicate opens collide on the sequence.
    assert_eq!(table.open(0x01, 0x0006, 0x00), Err(TxnError::Duplicate));
    let hdr = Header {
        control: FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: false,
            direction: Direction::ToClient,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x01,
        command_id: general::cmd::DEFAULT_RSP,
    };
    assert!(table.close(&hdr, 0x0006).is_some());
    assert!(table.is_empty());
    // Default Response build/decode round-trips the status; the body
    // follows the three-octet reply header.
    let req = to_server(false, general::cmd::READ);
    let mut buf = [0u8; 16];
    let n = build_default_response(&req, ZclStatus::Success, true, &mut buf).unwrap();
    let (_, body) = Header::decode(&buf[..n]).unwrap();
    let back = decode_default_response(body).unwrap();
    assert_eq!(
        (back.cmd, back.status),
        (general::cmd::READ, ZclStatus::Success)
    );
    // Silence rules produce no bytes (broadcast success here).
    assert_eq!(
        build_default_response(&req, ZclStatus::Success, false, &mut buf),
        None
    );
}

// ---- status (§2.6.3 Table 2-12) -------------------------------------

#[test]
fn vector_status_mapping_07_5123_08_263_01() {
    assert_eq!(ZclStatus::from_u8(0x00), ZclStatus::Success);
    assert_eq!(ZclStatus::from_u8(0x81), ZclStatus::UnsupCommand);
    assert_eq!(ZclStatus::from_u8(0x86), ZclStatus::UnsupportedAttribute);
    assert_eq!(ZclStatus::from_u8(0x88), ZclStatus::ReadOnly);
    assert_eq!(ZclStatus::from_u8(0xc3), ZclStatus::UnsupportedCluster);
    // Deprecated manufacturer/general variants collapse to
    // UnsupCommand on receipt, never surface distinctly.
    assert_eq!(ZclStatus::from_u8(0x82), ZclStatus::UnsupCommand);
    assert_eq!(ZclStatus::from_u8(0x83), ZclStatus::UnsupCommand);
    assert_eq!(ZclStatus::from_u8(0x84), ZclStatus::UnsupCommand);
    // Duplicate-entry maps to SUCCESS on receipt.
    assert_eq!(ZclStatus::from_u8(0x8a), ZclStatus::Success);
    // Unknown values survive verbatim for forward compatibility.
    assert_eq!(ZclStatus::from_u8(0xa0), ZclStatus::Other(0xa0));
    assert_eq!(ZclStatus::Success.as_u8(), 0x00);
    assert_eq!(ZclStatus::UnsupportedCluster.as_u8(), 0xc3);
}

// ---- dispatch integration: Context plumbing --------------------------

#[test]
fn vector_ctx_plumbing_07_5123_08_23_01() {
    let mut store = AttrStore::new(None);
    store
        .add(
            attr_def(0x0000, DataType::Bool.as_u8(), access::READ),
            Value::Bool(true),
        )
        .unwrap();
    let mut reporting = ReportingEngine::new();
    let mut events = EventQueue::new();
    let ctx = Ctx {
        store: &mut store,
        reporting: &mut reporting,
        events: &mut events,
        now_s: 1234,
        peer_onoff: Some(true),
        sender_ieee: Some(0x0012_4b00_1a2b_3c4d),
    };
    assert_eq!(ctx.now_s, 1234);
    assert_eq!(ctx.peer_onoff, Some(true));
    assert_eq!(ctx.sender_ieee, Some(0x0012_4b00_1a2b_3c4d));
    assert_eq!(ctx.store.get(0x0000), Some(Value::Bool(true)));
}
