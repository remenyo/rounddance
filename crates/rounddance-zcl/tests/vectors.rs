//! Hand-computed wire vectors for the ZCL engine + first clusters.
//!
//! Each test names the requirement ID it verifies. Byte strings below
//! are hand-computed from the paraphrased layouts in doc `07-5123-08`
//! — never copied from spec text (D1, `SCOPE.md` §2). Corpus-mined
//! IDs are reused verbatim; engine-gap IDs are repo-minted,
//! MINTED-pending-confirm.

use rounddance_zcl::behavior::{AppEvent, EventQueue};
use rounddance_zcl::cluster::ClusterDef;
use rounddance_zcl::*;
use rounddance_zcl::{general, ias_zone, level, onoff};

// ---- frame.rs: header codec -------------------------------------------

// 07-5123-08-2411-02: frame-control bit layout; reserved bits 5-7
// zeroed on transmit, ignored on receipt (with 231-02 / 232-01).
#[test]
fn vector_frame_control_bits_07_5123_08_2411_02() {
    let ctl = FrameControl {
        frame_type: FrameType::ClusterSpecific,
        manufacturer_specific: true,
        direction: Direction::ToClient,
        disable_default_response: true,
    };
    assert_eq!(ctl.encode(), 0x01 | 0x04 | 0x08 | 0x10);
    // Reserved bits set on the wire are ignored on receipt.
    let back = FrameControl::decode(0x01 | 0x04 | 0x08 | 0x10 | 0xe0).unwrap();
    assert_eq!(back, ctl);
    assert_eq!(
        FrameControl::decode(0x00).unwrap().frame_type,
        FrameType::Global
    );
    assert!(FrameType::from_bits(0x02).is_err());
    assert!(FrameType::from_bits(0x03).is_err());
}

// 07-5123-08-24111-01: manufacturer code present exactly when flagged.
#[test]
fn vector_header_manuf_presence_07_5123_08_24111_01() {
    let h = Header {
        control: FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: true,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: Some(0x1234),
        tsn: 0x51,
        command_id: 0x00,
    };
    let mut out = [0u8; 8];
    let n = h.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], &[0x04, 0x34, 0x12, 0x51, 0x00]);
    let (back, payload) = Header::decode(&out[..n]).unwrap();
    assert_eq!(back, h);
    assert!(payload.is_empty());
    // Flag/code mismatch is a fallible error, never a bad frame.
    let bad = Header {
        control: FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: Some(0x1234),
        tsn: 0,
        command_id: 0,
    };
    assert!(bad.encode_into(&mut out).is_err());
    // Truncated manufacturer code.
    assert!(Header::decode(&[0x04, 0x34]).is_err());
}

// 07-5123-08-2413-01 + 07-5123-08-2412-02: replies copy the sequence,
// flip direction, and set the disable bit.
#[test]
fn vector_reply_header_07_5123_08_2413_01() {
    let req = Header {
        control: FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x7a,
        command_id: general::cmd::READ,
    };
    let rsp = Header::reply_to(&req, general::cmd::READ_RSP);
    assert_eq!(rsp.tsn, 0x7a);
    assert_eq!(rsp.control.direction, Direction::ToClient);
    assert!(rsp.control.disable_default_response);
    let mut out = [0u8; 8];
    let n = rsp.encode_into(&mut out).unwrap();
    assert_eq!(&out[..n], &[0x18, 0x7a, general::cmd::READ_RSP]);
}

// ---- types.rs: data-type codec ----------------------------------------

// 07-5123-08-262-01: wire type identifiers.
#[test]
fn vector_datatype_ids_07_5123_08_262_01() {
    assert_eq!(DataType::from_u8(0x00).unwrap(), DataType::NoData);
    assert_eq!(DataType::from_u8(0x10).unwrap(), DataType::Bool);
    assert_eq!(DataType::from_u8(0x19).unwrap(), DataType::Map(2));
    assert_eq!(DataType::from_u8(0x21).unwrap(), DataType::UInt(2));
    assert_eq!(DataType::from_u8(0x29).unwrap(), DataType::Int(2));
    assert_eq!(DataType::from_u8(0x30).unwrap(), DataType::Enum8);
    assert_eq!(DataType::from_u8(0x42).unwrap(), DataType::CharStr);
    assert_eq!(DataType::from_u8(0x48).unwrap(), DataType::Array);
    assert_eq!(DataType::from_u8(0xe2).unwrap(), DataType::Time(0xe2));
    assert_eq!(DataType::from_u8(0xf0).unwrap(), DataType::Eui64);
    assert!(DataType::from_u8(0x07).is_err());
    assert!(DataType::from_u8(0x45).is_err());
}

// 07-5123-08-262-02: scalar bodies, little-endian first.
#[test]
fn vector_scalar_bodies_07_5123_08_262_02() {
    let mut out = [0u8; 16];
    let v = Value::UInt {
        width: 2,
        v: 0x1234,
    };
    assert_eq!(v.encode_into(&mut out).unwrap(), 2);
    assert_eq!(&out[..2], &[0x34, 0x12]);
    let (back, used) = Value::decode(DataType::UInt(2), &out[..2]).unwrap();
    assert_eq!((back, used), (v, 2));
    let neg = Value::Int { width: 1, v: -5 };
    assert_eq!(neg.encode_into(&mut out).unwrap(), 1);
    assert_eq!(out[0], 0xfb);
    let (back, _) = Value::decode(DataType::Int(1), &out[..1]).unwrap();
    assert_eq!(back, neg);
    assert_eq!(Value::Bool(true).encode_into(&mut out).unwrap(), 1);
    assert_eq!(out[0], 0x01);
    // Boolean admits only 0x00/0x01 (plus Non-Value handling by the
    // attribute layer, never on this path).
    assert!(Value::decode(DataType::Bool, &[0x02]).is_err());
    // i24 sign extension.
    let (v24, _) = Value::decode(DataType::Int(3), &[0xff, 0xff, 0xff]).unwrap();
    assert_eq!(v24, Value::Int { width: 3, v: -1 });
}

// 07-5123-08-262-03: strings (short + long) and packed scalar arrays.
#[test]
fn vector_strings_arrays_07_5123_08_262_03() {
    let mut out = [0u8; 40];
    let s = Value::CharStr {
        len: 2,
        bytes: {
            let mut b = [0u8; MAX_STR_LEN];
            b[0] = b'h';
            b[1] = b'i';
            b
        },
    };
    assert_eq!(s.encode_into(&mut out).unwrap(), 3);
    assert_eq!(&out[..3], &[0x02, b'h', b'i']);
    let (back, used) = Value::decode(DataType::CharStr, &out[..3]).unwrap();
    assert_eq!((back, used), (s, 3));
    // 0xff length is the invalid marker, never data.
    assert!(Value::decode(DataType::CharStr, &[0xff, b'h']).is_err());
    // Packed uint8 array [1, 2]: tag + LE count + bodies.
    let wire: &[u8] = &[0x20, 0x02, 0x00, 0x01, 0x02];
    let (arr, used) = Value::decode(DataType::Array, wire).unwrap();
    assert_eq!(used, 5);
    let mut rt = [0u8; 8];
    assert_eq!(arr.encode_into(&mut rt).unwrap(), 5);
    assert_eq!(&rt[..5], wire);
    // Nested/variable element tags are refused, not misread.
    assert!(Value::decode(DataType::Array, &[0x42, 0x01, 0x00, 0x41]).is_err());
    // Oversize arrays are rejected fallibly.
    assert!(Value::decode(DataType::Array, &[0x20, 0x11, 0x00]).is_err());
}

// 07-5123-08-2343-01: defaults resolve to Non-Value, else zero.
#[test]
fn vector_type_defaults_07_5123_08_2343_01() {
    assert_eq!(
        Value::default_for(DataType::UInt(2)),
        Some(Value::UInt {
            width: 2,
            v: 0xffff
        })
    );
    assert_eq!(
        Value::default_for(DataType::Int(1)),
        Some(Value::Int { width: 1, v: -128 })
    );
    assert_eq!(Value::default_for(DataType::Bool), Some(Value::Bool(false)));
    assert_eq!(
        Value::default_for(DataType::Map(2)),
        Some(Value::Map {
            width: 2,
            bytes: [0; 8]
        })
    );
    assert!(Value::default_for(DataType::Composite(0x4c)).is_none());
}

// ---- status.rs --------------------------------------------------------

// 07-5123-08-263-01: deprecated values map on receipt, never emit.
#[test]
fn vector_status_remap_07_5123_08_263_01() {
    assert_eq!(ZclStatus::from_u8(0x82), ZclStatus::UnsupCommand);
    assert_eq!(ZclStatus::from_u8(0x83), ZclStatus::UnsupCommand);
    assert_eq!(ZclStatus::from_u8(0x84), ZclStatus::UnsupCommand);
    assert_eq!(ZclStatus::from_u8(0x8a), ZclStatus::Success);
    assert_eq!(ZclStatus::from_u8(0x8f), ZclStatus::NotAuthorized);
    assert_eq!(ZclStatus::UnsupCommand.as_u8(), 0x81);
    assert_eq!(ZclStatus::Success.as_u8(), 0x00);
    assert_eq!(ZclStatus::from_u8(0x86), ZclStatus::UnsupportedAttribute);
}

// ---- attrs.rs ---------------------------------------------------------

// 07-5123-08-253-01: write validation order; 2345-01: globals present.
#[test]
fn vector_attr_store_guards_07_5123_08_253_01() {
    let mut store = onoff::server_store().unwrap();
    // Mandatory global present with the cluster revision.
    assert_eq!(
        store.get(ATTR_CLUSTER_REVISION),
        Some(Value::UInt { width: 2, v: 2 })
    );
    // Unknown identifier.
    assert_eq!(
        store.write(0x1234, Value::Bool(true)),
        Err(ZclStatus::UnsupportedAttribute)
    );
    // Wrong wire type.
    assert_eq!(
        store.write(onoff::ATTR_ONOFF, Value::UInt { width: 1, v: 1 }),
        Err(ZclStatus::InvalidDataType)
    );
    // Read-only attribute.
    assert_eq!(
        store.write(onoff::ATTR_ONOFF, Value::Bool(true)),
        Err(ZclStatus::ReadOnly)
    );
    // Writable attribute commits.
    assert!(store
        .write(onoff::ATTR_ONTIME, Value::UInt { width: 2, v: 30 })
        .is_ok());
    assert_eq!(
        store.get(onoff::ATTR_ONTIME),
        Some(Value::UInt { width: 2, v: 30 })
    );
    // Duplicate registration refused.
    assert!(store
        .add(
            AttrDef {
                id: onoff::ATTR_ONTIME,
                datatype: DataType::UInt(2).as_u8(),
                access: access::READ,
                reportable: false,
            },
            Value::UInt { width: 2, v: 0 }
        )
        .is_err());
}

// ---- general.rs -------------------------------------------------------

// 07-5123-08-25-02: command identifiers; 251-01: read request shape.
#[test]
fn vector_general_ids_and_read_07_5123_08_25_02() {
    assert_eq!(general::cmd::READ, 0x00);
    assert_eq!(general::cmd::READ_RSP, 0x01);
    assert_eq!(general::cmd::WRITE, 0x02);
    assert_eq!(general::cmd::WRITE_NO_RSP, 0x05);
    assert_eq!(general::cmd::CONFIG_REPORT, 0x06);
    assert_eq!(general::cmd::REPORT, 0x0a);
    assert_eq!(general::cmd::DEFAULT_RSP, 0x0b);
    assert_eq!(general::cmd::DISCOVER_ATTRS, 0x0c);
    assert_eq!(general::cmd::DISCOVER_ATTRS_RSP, 0x0d);
    assert_eq!(general::cmd::DISCOVER_CMDS_RX, 0x11);
    assert_eq!(general::cmd::DISCOVER_CMDS_TX_RSP, 0x14);
    let mut out = [0u8; 8];
    assert_eq!(general::encode_id_list(&[0x0000], &mut out).unwrap(), 2);
    assert_eq!(&out[..2], &[0x00, 0x00]);
    let mut ids = [0u16; 4];
    assert_eq!(general::decode_id_list(&out[..2], &mut ids).unwrap(), 1);
    assert_eq!(ids[0], 0x0000);
}

// 07-5123-08-252-01: response records echo + gate type/value.
#[test]
fn vector_read_rsp_records_07_5123_08_252_01() {
    let records = [
        general::ReadRecord {
            id: 0x0000,
            status: ZclStatus::Success,
            dtype: DataType::Bool.as_u8(),
            value: Value::Bool(true),
        },
        general::ReadRecord {
            id: 0x0001,
            status: ZclStatus::UnsupportedAttribute,
            dtype: 0,
            value: Value::NoData,
        },
    ];
    let mut out = [0u8; 16];
    let n = general::encode_read_rsp(&records, &mut out).unwrap();
    assert_eq!(&out[..n], &[0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00, 0x86]);
    let mut back = [general::ReadRecord {
        id: 0,
        status: ZclStatus::Success,
        dtype: 0,
        value: Value::NoData,
    }; 4];
    assert_eq!(general::decode_read_rsp(&out[..n], &mut back).unwrap(), 2);
    assert_eq!(back[0], records[0]);
    assert_eq!(back[1].status, ZclStatus::UnsupportedAttribute);
}

// 07-5123-08-253-02: all-success write response compacts to bare SUCCESS.
#[test]
fn vector_write_rsp_compact_07_5123_08_253_02() {
    let mut out = [0u8; 8];
    // Write OnTime = 30: id + type + LE value.
    let wire: &[u8] = &[0x01, 0x40, 0x21, 0x1e, 0x00];
    let mut recs = [general::WriteRecord {
        id: 0,
        dtype: 0,
        value: Value::NoData,
    }; 4];
    assert_eq!(general::decode_write(wire, &mut recs).unwrap(), 1);
    assert_eq!(recs[0].id, 0x4001);
    assert_eq!(recs[0].value, Value::UInt { width: 2, v: 30 });
    let ok = [general::WriteStatus {
        status: ZclStatus::Success,
        id: None,
    }];
    assert_eq!(general::encode_write_rsp(&ok, &mut out).unwrap(), 1);
    assert_eq!(out[0], 0x00);
    let fail = [
        general::WriteStatus {
            status: ZclStatus::Success,
            id: None,
        },
        general::WriteStatus {
            status: ZclStatus::ReadOnly,
            id: Some(0x0000),
        },
    ];
    let n = general::encode_write_rsp(&fail, &mut out).unwrap();
    assert_eq!(&out[..n], &[0x88, 0x00, 0x00]);
}

// 07-5123-08-257-01/03: configure-reporting records; change omitted
// for discrete types, present for analog.
#[test]
fn vector_config_report_shapes_07_5123_08_257_01() {
    // Discrete (OnOff bool): no change field.
    let wire: &[u8] = &[0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x3c, 0x00];
    let mut recs = [general::ReportCfgRecord {
        direction: 0,
        id: 0,
        dtype: 0,
        min: 0,
        max: 0,
        change: None,
        timeout: 0,
    }; 4];
    assert_eq!(general::decode_config_report(wire, &mut recs).unwrap(), 1);
    assert_eq!(recs[0].min, 1);
    assert_eq!(recs[0].max, 60);
    assert_eq!(recs[0].change, None);
    let mut out = [0u8; 16];
    assert_eq!(
        general::encode_config_report(&recs[..1], &mut out).unwrap(),
        8
    );
    assert_eq!(&out[..8], wire);
    // Analog (OnTime uint16): change threshold travels inline.
    let awire: &[u8] = &[0x00, 0x01, 0x40, 0x21, 0x05, 0x00, 0x00, 0x01, 0x0a, 0x00];
    assert_eq!(general::decode_config_report(awire, &mut recs).unwrap(), 1);
    assert_eq!(recs[0].change, Some(Value::UInt { width: 2, v: 10 }));
    // Receive direction carries only the timeout.
    let twire: &[u8] = &[0x01, 0x00, 0x00, 0x2c, 0x01];
    assert_eq!(general::decode_config_report(twire, &mut recs).unwrap(), 1);
    assert_eq!(recs[0].timeout, 300);
}

// 07-5123-08-2511-01: report records; 2512-01: default response body.
#[test]
fn vector_report_and_default_rsp_07_5123_08_2511_01() {
    let records = [general::ReportRecord {
        id: 0x0000,
        dtype: DataType::Bool.as_u8(),
        value: Value::Bool(true),
    }];
    let mut out = [0u8; 16];
    let n = general::encode_report(&records, &mut out).unwrap();
    assert_eq!(&out[..n], &[0x00, 0x00, 0x10, 0x01]);
    let rsp = general::DefaultRsp {
        cmd: onoff::CMD_TOGGLE,
        status: ZclStatus::Success,
    };
    assert_eq!(rsp.encode_into(&mut out).unwrap(), 2);
    assert_eq!(&out[..2], &[0x02, 0x00]);
    assert_eq!(general::DefaultRsp::decode(&out[..2]).unwrap(), rsp);
}

// 07-5123-08-2513-01/2514-01: discover attributes round trip.
#[test]
fn vector_discover_attrs_07_5123_08_2513_01() {
    let req = general::DiscoverAttrs {
        start: 0x4001,
        max: 0xff,
    };
    let mut out = [0u8; 8];
    assert_eq!(req.encode_into(&mut out).unwrap(), 3);
    assert_eq!(&out[..3], &[0x01, 0x40, 0xff]);
    assert_eq!(general::DiscoverAttrs::decode(&out[..3]).unwrap(), req);
    let records = [(0x4001u16, 0x21u8), (0x4002, 0x21)];
    let n = general::encode_discover_attrs_rsp(&records, true, &mut out).unwrap();
    assert_eq!(&out[..n], &[0x01, 0x01, 0x40, 0x21, 0x02, 0x40, 0x21]);
    let mut back = [(0u16, 0u8); 4];
    assert_eq!(
        general::decode_discover_attrs_rsp(&out[..n], &mut back).unwrap(),
        (true, 2)
    );
    assert_eq!(back[0], (0x4001, 0x21));
}

// 07-5123-08-2518-01: discover commands round trip.
#[test]
fn vector_discover_cmds_07_5123_08_2518_01() {
    let req = general::DiscoverCmds {
        start: 0x02,
        max: 0xff,
    };
    let mut out = [0u8; 8];
    assert_eq!(req.encode_into(&mut out).unwrap(), 2);
    assert_eq!(&out[..2], &[0x02, 0xff]);
    let ids = [0x02u8, 0x40, 0x41, 0x42];
    let n = general::encode_discover_cmds_rsp(&ids, true, &mut out).unwrap();
    assert_eq!(&out[..n], &[0x01, 0x02, 0x40, 0x41, 0x42]);
    let mut back = [0u8; 8];
    assert_eq!(
        general::decode_discover_cmds_rsp(&out[..n], &mut back).unwrap(),
        (true, 4)
    );
    assert_eq!(&back[..4], &ids);
}

// ---- reporting.rs -----------------------------------------------------

// 07-5123-08-257-02/04 + 2511-02: configure, tick, disable, restore.
#[test]
fn vector_reporting_lifecycle_07_5123_08_257_02() {
    let mut store = onoff::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut recs = [general::ReportCfgRecord {
        direction: 0,
        id: 0,
        dtype: 0,
        min: 0,
        max: 0,
        change: None,
        timeout: 0,
    }; 4];
    // Configure OnOff: min 5 s, max 60 s.
    let wire: &[u8] = &[0x00, 0x00, 0x00, 0x10, 0x05, 0x00, 0x3c, 0x00];
    general::decode_config_report(wire, &mut recs).unwrap();
    assert!(eng.configure(&store, &recs[0], 1000).is_success());
    // No change yet: nothing due before the ceiling.
    let mut due = [0u16; 4];
    assert_eq!(eng.tick(&store, 1059, &mut due), 0);
    // Ceiling reached at +60 s: one periodic report.
    assert_eq!(eng.tick(&store, 1060, &mut due), 1);
    assert_eq!(due[0], onoff::ATTR_ONOFF);
    // Discrete change after the floor: immediate report.
    store
        .set_local(onoff::ATTR_ONOFF, Value::Bool(true))
        .unwrap();
    assert_eq!(eng.tick(&store, 1061, &mut due), 0);
    assert_eq!(eng.tick(&store, 1065, &mut due), 1);
    // Disable encoding drops the slot.
    let dwire: &[u8] = &[0x00, 0x00, 0x00, 0x10, 0x05, 0x00, 0xff, 0xff];
    general::decode_config_report(dwire, &mut recs).unwrap();
    assert!(eng.configure(&store, &recs[0], 2000).is_success());
    assert!(eng.is_empty());
    // Unknown attribute + wrong type + unreportable rejections.
    let bad: &[u8] = &[0x00, 0x34, 0x12, 0x10, 0x00, 0x00, 0x3c, 0x00];
    general::decode_config_report(bad, &mut recs).unwrap();
    assert_eq!(
        eng.configure(&store, &recs[0], 2000),
        ZclStatus::UnsupportedAttribute
    );
    let wrong: &[u8] = &[0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x3c, 0x00, 0x01, 0x00];
    general::decode_config_report(wrong, &mut recs).unwrap();
    assert_eq!(
        eng.configure(&store, &recs[0], 2000),
        ZclStatus::InvalidDataType
    );
    let unrep: &[u8] = &[0x00, 0x01, 0x40, 0x21, 0x00, 0x00, 0x3c, 0x00, 0x01, 0x00];
    general::decode_config_report(unrep, &mut recs).unwrap();
    assert_eq!(
        eng.configure(&store, &recs[0], 2000),
        ZclStatus::UnreportableAttribute
    );
}

// 07-5123-08-257-03: analog thresholds are sign-insensitive magnitudes.
#[test]
fn vector_analog_threshold_07_5123_08_257_03() {
    let mut store = onoff::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut recs = [general::ReportCfgRecord {
        direction: 0,
        id: 0,
        dtype: 0,
        min: 0,
        max: 0,
        change: None,
        timeout: 0,
    }; 4];
    // OnTime is not reportable in our table; use a scratch reportable
    // analog attribute instead.
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
    let wire: &[u8] = &[0x00, 0x01, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00];
    general::decode_config_report(wire, &mut recs).unwrap();
    assert!(eng.configure(&store, &recs[0], 0).is_success());
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

// 07-5123-08-25-10-01: query statuses distinguish the four cases.
#[test]
fn vector_report_cfg_query_07_5123_08_25_10_01() {
    let store = onoff::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    // Absent attribute.
    assert_eq!(
        eng.query(&store, 0x00, 0x1234),
        QueryAnswer::Bare {
            status: ZclStatus::UnsupportedAttribute
        }
    );
    // Present but not reportable.
    assert_eq!(
        eng.query(&store, 0x00, onoff::ATTR_ONTIME),
        QueryAnswer::Bare {
            status: ZclStatus::UnreportableAttribute
        }
    );
    // Reportable but unconfigured.
    assert_eq!(
        eng.query(&store, 0x00, onoff::ATTR_ONOFF),
        QueryAnswer::Bare {
            status: ZclStatus::NotFound
        }
    );
    // Configured: SUCCESS shape with live values.
    let mut recs = [general::ReportCfgRecord {
        direction: 0,
        id: 0,
        dtype: 0,
        min: 0,
        max: 0,
        change: None,
        timeout: 0,
    }; 2];
    general::decode_config_report(&[0x00, 0x00, 0x00, 0x10, 0x05, 0x00, 0x3c, 0x00], &mut recs)
        .unwrap();
    eng.configure(&store, &recs[0], 0);
    match eng.query(&store, 0x00, onoff::ATTR_ONOFF) {
        QueryAnswer::Send {
            min_s,
            max_s,
            dtype,
            ..
        } => {
            assert_eq!((min_s, max_s), (5, 60));
            assert_eq!(dtype, DataType::Bool.as_u8());
        }
        other => panic!("expected Send, got {other:?}"),
    }
}

// ---- onoff.rs ---------------------------------------------------------

// 07-5123-08-381-01 + 382-01: identity, revision, attribute table.
#[test]
fn vector_onoff_definition_07_5123_08_381_01() {
    let def = onoff::ServerDef;
    assert_eq!(def.cluster_id(), 0x0006);
    assert_eq!(def.revision(), 2);
    assert_eq!(def.role(), ClusterRole::Server);
    assert!(def.is_reportable(onoff::ATTR_ONOFF));
    assert!(!def.is_reportable(onoff::ATTR_ONTIME));
    let rx: Vec<u8> = def.received_commands().iter().map(|c| c.id).collect();
    assert_eq!(rx, vec![0x00, 0x01, 0x02, 0x40, 0x41, 0x42]);
    assert!(def.generated_commands().is_empty());
    let client = onoff::ClientDef;
    assert_eq!(client.role(), ClusterRole::Client);
    assert!(client.attributes().is_empty());
}

// 07-5123-08-383-01: Off/On/Toggle effects incl. timer coupling.
#[test]
fn vector_onoff_basic_effects_07_5123_08_383_01() {
    let mut store = onoff::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = onoff::ServerBehavior;
    let run = |beh: &mut onoff::ServerBehavior,
               store: &mut AttrStore,
               eng: &mut ReportingEngine,
               events: &mut EventQueue,
               cmd: u8,
               payload: &[u8]| {
        beh.handle_cluster_command(
            &mut Ctx {
                store,
                reporting: eng,
                events,
                now_s: 0,
                peer_onoff: None,
                sender_ieee: None,
            },
            &Header {
                control: FrameControl {
                    frame_type: FrameType::ClusterSpecific,
                    manufacturer_specific: false,
                    direction: Direction::ToServer,
                    disable_default_response: false,
                },
                manufacturer_code: None,
                tsn: 0x01,
                command_id: cmd,
            },
            cmd,
            payload,
        )
        .unwrap()
    };
    run(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        onoff::CMD_ON,
        &[],
    );
    assert!(onoff::onoff(&store));
    run(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        onoff::CMD_TOGGLE,
        &[],
    );
    assert!(!onoff::onoff(&store));
    assert_eq!(
        store.get(onoff::ATTR_ONTIME),
        Some(Value::UInt { width: 2, v: 0 })
    );
    run(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        onoff::CMD_TOGGLE,
        &[],
    );
    assert!(onoff::onoff(&store));
    run(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        onoff::CMD_OFF,
        &[],
    );
    assert!(!onoff::onoff(&store));
    // Payload-bearing basics reject trailing octets.
    assert!(beh
        .handle_cluster_command(
            &mut Ctx {
                store: &mut store,
                reporting: &mut eng,
                events: &mut events,
                now_s: 0,
                peer_onoff: None,
                sender_ieee: None,
            },
            &Header {
                control: FrameControl {
                    frame_type: FrameType::ClusterSpecific,
                    manufacturer_specific: false,
                    direction: Direction::ToServer,
                    disable_default_response: false,
                },
                manufacturer_code: None,
                tsn: 0x01,
                command_id: onoff::CMD_ON,
            },
            onoff::CMD_ON,
            &[0x00],
        )
        .is_err());
}

// 07-5123-08-383-04: Timed Off validation, guard window, countdown.
#[test]
fn vector_onoff_timed_off_07_5123_08_383_04() {
    let mut store = onoff::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = onoff::ServerBehavior;
    macro_rules! ctx {
        () => {
            Ctx {
                store: &mut store,
                reporting: &mut eng,
                events: &mut events,
                now_s: 0,
                peer_onoff: None,
                sender_ieee: None,
            }
        };
    }
    let hdr = Header {
        control: FrameControl {
            frame_type: FrameType::ClusterSpecific,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x02,
        command_id: onoff::CMD_ON_TIMED_OFF,
    };
    // 0xffff fields are out of range.
    assert!(beh
        .handle_cluster_command(
            &mut ctx!(),
            &hdr,
            onoff::CMD_ON_TIMED_OFF,
            &[0x00, 0xff, 0xff, 0x00, 0x00]
        )
        .is_err());
    // On 100 + wait 50: guarded on.
    beh.handle_cluster_command(
        &mut ctx!(),
        &hdr,
        onoff::CMD_ON_TIMED_OFF,
        &[0x00, 0x64, 0x00, 0x32, 0x00],
    )
    .unwrap();
    assert!(onoff::onoff(&store));
    assert_eq!(
        store.get(onoff::ATTR_ONTIME),
        Some(Value::UInt { width: 2, v: 100 })
    );
    // Countdown turns off at zero.
    let mut i = 0;
    while i < 100 {
        onoff::tick_100ms(&mut store, &mut events);
        i += 1;
    }
    assert!(!onoff::onoff(&store));
    assert_eq!(
        store.get(onoff::ATTR_ONTIME),
        Some(Value::UInt { width: 2, v: 0 })
    );
    // Accept-only-when-on discards while off.
    beh.handle_cluster_command(
        &mut ctx!(),
        &hdr,
        onoff::CMD_ON_TIMED_OFF,
        &[0x01, 0x0a, 0x00, 0x0a, 0x00],
    )
    .unwrap();
    assert!(!onoff::onoff(&store));
    // Startup modes resolve through previous state.
    onoff::apply_startup(&mut store, false).unwrap();
    // Default StartUpOnOff is previous-value: stays off.
    assert!(!onoff::onoff(&store));
    store
        .set_local(onoff::ATTR_STARTUP, Value::Enum8(onoff::STARTUP_TOGGLE))
        .unwrap();
    onoff::apply_startup(&mut store, false).unwrap();
    assert!(onoff::onoff(&store));
}

// 07-5123-08-383-02/03: effect + recall-scene paths; client encoding.
#[test]
fn vector_onoff_scene_paths_07_5123_08_383_02() {
    let mut out = [0u8; 16];
    // Client Toggle frame: cluster-specific, to-server, TSN, 0x02.
    assert_eq!(onoff::client::toggle(0x33, &mut out).unwrap(), 3);
    assert_eq!(&out[..3], &[0x01, 0x33, 0x02]);
    assert_eq!(onoff::client::off(0x34, &mut out).unwrap(), 3);
    assert_eq!(&out[..3], &[0x01, 0x34, 0x00]);
    assert_eq!(
        onoff::client::off_with_effect(0x35, onoff::EFFECT_DYING_LIGHT, 0x00, &mut out).unwrap(),
        5
    );
    assert_eq!(&out[..5], &[0x01, 0x35, 0x40, 0x01, 0x00]);
    let mut store = onoff::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = onoff::ServerBehavior;
    let hdr = Header {
        control: FrameControl {
            frame_type: FrameType::ClusterSpecific,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x03,
        command_id: onoff::CMD_OFF_EFFECT,
    };
    // Reserved effect identifiers are refused.
    assert!(beh
        .handle_cluster_command(
            &mut Ctx {
                store: &mut store,
                reporting: &mut eng,
                events: &mut events,
                now_s: 0,
                peer_onoff: None,
                sender_ieee: None,
            },
            &hdr,
            onoff::CMD_OFF_EFFECT,
            &[0x02, 0x00]
        )
        .is_err());
}

// ---- level.rs ---------------------------------------------------------

// 07-5123-08-3101-01 + 3102-01: identity, revision, table.
#[test]
fn vector_level_definition_07_5123_08_3101_01() {
    let def = level::ServerDef;
    assert_eq!(def.cluster_id(), 0x0008);
    assert_eq!(def.revision(), 3);
    let rx: Vec<u8> = def.received_commands().iter().map(|c| c.id).collect();
    assert_eq!(rx, vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    assert!(def.is_reportable(level::ATTR_CURRENT_LEVEL));
}

// 07-5123-08-3102-03/04 + 425-01: level application, envelope guard,
// ExecuteIfOff gating, with-On/Off coupling requests.
#[test]
fn vector_level_basics_07_5123_08_3102_03() {
    let mut store = level::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = level::ServerBehavior::new();
    let run = |beh: &mut level::ServerBehavior,
               store: &mut AttrStore,
               eng: &mut ReportingEngine,
               events: &mut EventQueue,
               cmd: u8,
               payload: &[u8],
               peer: Option<bool>| {
        beh.handle_cluster_command(
            &mut Ctx {
                store,
                reporting: eng,
                events,
                now_s: 0,
                peer_onoff: peer,
                sender_ieee: None,
            },
            &Header {
                control: FrameControl {
                    frame_type: FrameType::ClusterSpecific,
                    manufacturer_specific: false,
                    direction: Direction::ToServer,
                    disable_default_response: false,
                },
                manufacturer_code: None,
                tsn: 0x04,
                command_id: cmd,
            },
            cmd,
            payload,
        )
    };
    // Move to level 100 over 10 (1/10 s), no options pair.
    run(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        level::CMD_MOVE_TO_LEVEL,
        &[100, 10, 0],
        None,
    )
    .unwrap();
    assert_eq!(
        store.get(level::ATTR_CURRENT_LEVEL),
        Some(Value::UInt { width: 1, v: 100 })
    );
    assert!(beh.take_onoff_request().is_none());
    // With-On/Off twin requests the sibling on.
    run(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        level::CMD_MOVE_TO_LEVEL_ONOFF,
        &[200, 0, 0],
        Some(false),
    )
    .unwrap();
    assert_eq!(beh.take_onoff_request(), Some(true));
    // Envelope guard: MinLevel clamps writes (425-01).
    store
        .set_local(level::ATTR_MIN_LEVEL, Value::UInt { width: 1, v: 10 })
        .unwrap();
    store
        .set_local(level::ATTR_MAX_LEVEL, Value::UInt { width: 1, v: 200 })
        .unwrap();
    assert!(run(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        level::CMD_MOVE_TO_LEVEL,
        &[9, 0, 0],
        None
    )
    .is_err());
    // ExecuteIfOff gate: without-On/Off command ignored while off.
    assert!(run(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        level::CMD_MOVE_TO_LEVEL,
        &[50, 0, 0],
        Some(false)
    )
    .is_ok());
    assert_eq!(
        store.get(level::ATTR_CURRENT_LEVEL),
        Some(Value::UInt { width: 1, v: 200 })
    );
    // Step down clamps at the minimum.
    run(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        level::CMD_STEP_ONOFF,
        &[1, 250, 0, 0],
        None,
    )
    .unwrap();
    assert_eq!(
        store.get(level::ATTR_CURRENT_LEVEL),
        Some(Value::UInt { width: 1, v: 10 })
    );
    assert_eq!(beh.take_onoff_request(), Some(false));
    // Bad direction fields are refused.
    assert!(run(
        &mut beh,
        &mut store,
        &mut eng,
        &mut events,
        level::CMD_MOVE,
        &[0x02, 0xff],
        None
    )
    .is_err());
    // Client encoding: Move to Level with options pair.
    let mut out = [0u8; 16];
    let n =
        level::client::move_to_level(0x44, false, 100, 10, Some((0x01, 0x01)), &mut out).unwrap();
    assert_eq!(&out[..n], &[0x01, 0x44, 0x00, 100, 10, 0, 0x01, 0x01]);
}

// ---- ias_zone.rs ------------------------------------------------------

// 07-5123-08-821-01 + 822-10: identity, notification geometry.
#[test]
fn vector_ias_definition_07_5123_08_821_01() {
    let def = ias_zone::ServerDef;
    assert_eq!(def.cluster_id(), 0x0500);
    assert_eq!(def.revision(), 2);
    let rx: Vec<u8> = def.received_commands().iter().map(|c| c.id).collect();
    assert_eq!(rx, vec![0x00, 0x01, 0x02]);
    let tx: Vec<u8> = def.generated_commands().iter().map(|c| c.id).collect();
    assert_eq!(tx, vec![0x00, 0x01]);
    assert!(def.is_reportable(ias_zone::ATTR_ZONE_STATUS));
}

// 07-5123-08-822-01/05/06/07: enrollment handshake + gating + lockdown.
#[test]
fn vector_ias_enrollment_07_5123_08_822_06() {
    let mut store = ias_zone::server_store(0x000d).unwrap();
    assert_eq!(
        store.get(ias_zone::ATTR_ZONE_STATE),
        Some(Value::Enum8(0x00))
    );
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = ias_zone::ServerBehavior::new();
    let cie: u64 = 0x0012_4b00_1122_3344;
    // CIE writes its address through the protocol path: the write
    // hook binds the server.
    let mut addr = [0u8; 8];
    addr.copy_from_slice(&cie.to_le_bytes());
    store
        .set_local(ias_zone::ATTR_CIE_ADDRESS, Value::Eui64(addr))
        .unwrap();
    {
        let mut ctx = Ctx {
            store: &mut store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 0,
            peer_onoff: None,
            sender_ieee: None,
        };
        beh.on_attribute_written(&mut ctx, ias_zone::ATTR_CIE_ADDRESS)
            .unwrap();
        // Enroll request trigger emits zone type + manufacturer code.
        beh.trigger_enroll_request(&mut ctx, 0x1234, 0x10).unwrap();
    }
    // Hook bound (CieBound) then the trigger parked (EnrollPending).
    assert_eq!(beh.stage(), ias_zone::EnrollStage::EnrollPending);
    // Drain the StateChanged(CieBound) then the enroll request.
    match events.pop().unwrap() {
        AppEvent::StateChanged { to, .. } => {
            assert_eq!(to, ias_zone::EnrollStage::CieBound as u8);
        }
        other => panic!("expected bind event, got {other:?}"),
    }
    match events.pop().unwrap() {
        AppEvent::OutboundCommand {
            cluster,
            cmd,
            payload,
            len,
            ..
        } => {
            assert_eq!((cluster, cmd, len), (0x0500, 0x01, 4));
            assert_eq!(&payload[..4], &[0x0d, 0x00, 0x34, 0x12]);
        }
        other => panic!("expected enroll request, got {other:?}"),
    }
    // Foreign sender refused once bound (822-01).
    let hdr = Header {
        control: FrameControl {
            frame_type: FrameType::ClusterSpecific,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x11,
        command_id: ias_zone::CMD_ENROLL_RESPONSE,
    };
    {
        let mut ctx = Ctx {
            store: &mut store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 0,
            peer_onoff: None,
            sender_ieee: Some(0xdead_beef_0000_0001),
        };
        assert_eq!(
            beh.handle_cluster_command(
                &mut ctx,
                &hdr,
                ias_zone::CMD_ENROLL_RESPONSE,
                &[0x00, 0x05]
            )
            .unwrap_err(),
            ZclStatus::NotAuthorized
        );
    }
    // CIE enroll response completes the handshake (822-06).
    {
        let mut ctx = Ctx {
            store: &mut store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 0,
            peer_onoff: None,
            sender_ieee: Some(cie),
        };
        beh.handle_cluster_command(&mut ctx, &hdr, ias_zone::CMD_ENROLL_RESPONSE, &[0x00, 0x05])
            .unwrap();
    }
    assert_eq!(beh.stage(), ias_zone::EnrollStage::Enrolled);
    assert_eq!(
        store.get(ias_zone::ATTR_ZONE_ID),
        Some(Value::UInt { width: 1, v: 5 })
    );
    assert_eq!(
        store.get(ias_zone::ATTR_ZONE_STATE),
        Some(Value::Enum8(0x01))
    );
    // Bind lockdown: strangers refused, CIE allowed (822-07).
    assert!(ias_zone::ServerBehavior::check_bind(&store, beh.stage(), 0x9999).is_err());
    assert!(ias_zone::ServerBehavior::check_bind(&store, beh.stage(), cie).is_ok());
}

// 07-5123-08-822-08/09/10: mode signaling, test timer, notification flow.
#[test]
fn vector_ias_modes_notify_07_5123_08_822_08() {
    let mut store = ias_zone::server_store(0x0028).unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = ias_zone::ServerBehavior::new();
    let hdr = Header {
        control: FrameControl {
            frame_type: FrameType::ClusterSpecific,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x20,
        command_id: ias_zone::CMD_TEST_MODE,
    };
    // Test mode for 10 s: sensitivity stored, test bit announced.
    {
        let mut ctx = Ctx {
            store: &mut store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 100,
            peer_onoff: None,
            sender_ieee: None,
        };
        beh.handle_cluster_command(&mut ctx, &hdr, ias_zone::CMD_TEST_MODE, &[10, 0x02])
            .unwrap();
    }
    assert_eq!(
        store.get(ias_zone::ATTR_CUR_SENS_LEVEL),
        Some(Value::UInt { width: 1, v: 2 })
    );
    assert_ne!(ias_zone::zone_status(&store) & ias_zone::STATUS_TEST, 0);
    // Entry pushes the attribute change first, then the notification.
    match events.pop().unwrap() {
        AppEvent::AttributeChanged { cluster, attr } => {
            assert_eq!((cluster, attr), (0x0500, 0x0002));
        }
        other => panic!("expected attr event, got {other:?}"),
    }
    match events.pop().unwrap() {
        AppEvent::OutboundCommand {
            cmd, payload, len, ..
        } => {
            assert_eq!((cmd, len), (0x00, 6));
            // Geometry: status LE + zeroed extended + zone id + delay.
            assert_eq!(payload[2], 0x00);
            assert_eq!(payload[3], 0xff);
        }
        other => panic!("expected notify, got {other:?}"),
    }
    // Alarm bit set: notification carries the live status.
    {
        let mut ctx = Ctx {
            store: &mut store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 100,
            peer_onoff: None,
            sender_ieee: None,
        };
        beh.set_status(
            &mut ctx,
            ias_zone::STATUS_ALARM1 | ias_zone::STATUS_TEST,
            0x21,
        )
        .unwrap();
    }
    match events.pop().unwrap() {
        AppEvent::AttributeChanged { cluster, attr } => {
            assert_eq!((cluster, attr), (0x0500, 0x0002));
        }
        other => panic!("expected attr event, got {other:?}"),
    }
    match events.pop().unwrap() {
        AppEvent::OutboundCommand { payload, .. } => {
            assert_eq!(&payload[..2], &[0x01, 0x01]);
        }
        other => panic!("expected notify, got {other:?}"),
    }
    // Timer expiry restores normal mode with test-bit-cleared notify.
    ias_zone::tick_1s(&mut beh, &mut store, &mut events, 0x22, 110, 10);
    assert_eq!(ias_zone::zone_status(&store) & ias_zone::STATUS_TEST, 0);
    match events.pop().unwrap() {
        AppEvent::OutboundCommand { cmd, payload, .. } => {
            assert_eq!(cmd, 0x00);
            assert_eq!(&payload[..2], &[0x01, 0x00]);
            assert_eq!(payload[2], 0x00);
        }
        other => panic!("expected expiry notify, got {other:?}"),
    }
    // NormalOp entry retains the alarm bit, clears test, notifies.
    {
        let mut ctx = Ctx {
            store: &mut store,
            reporting: &mut eng,
            events: &mut events,
            now_s: 120,
            peer_onoff: None,
            sender_ieee: None,
        };
        let normal = Header {
            control: FrameControl {
                frame_type: FrameType::ClusterSpecific,
                manufacturer_specific: false,
                direction: Direction::ToServer,
                disable_default_response: false,
            },
            manufacturer_code: None,
            tsn: 0x23,
            command_id: ias_zone::CMD_NORMAL_OP,
        };
        beh.handle_cluster_command(&mut ctx, &normal, ias_zone::CMD_NORMAL_OP, &[])
            .unwrap();
    }
    assert_eq!(ias_zone::zone_status(&store) & ias_zone::STATUS_TEST, 0);
    assert_ne!(ias_zone::zone_status(&store) & ias_zone::STATUS_ALARM1, 0);
    assert!(matches!(
        events.pop().unwrap(),
        AppEvent::AttributeChanged {
            cluster: 0x0500,
            attr: 0x0002
        }
    ));
    match events.pop().unwrap() {
        AppEvent::OutboundCommand { payload, .. } => {
            assert_eq!(&payload[..4], &[0x01, 0x00, 0x00, 0xff]);
        }
        other => panic!("expected normal-mode notify, got {other:?}"),
    }
    // CIE builders encode server-to-client frames.
    let mut out = [0u8; 16];
    let n = ias_zone::cie::enroll_response(0x30, 0x00, 0x05, &mut out).unwrap();
    assert_eq!(&out[..n], &[0x09, 0x30, 0x00, 0x00, 0x05]);
}

// 07-5123-08-2512-01: Default Response triage (unicast, disable bit,
// never answering a Default Response).
#[test]
fn vector_default_response_triage_07_5123_08_2512_01() {
    let mk = |cmd: u8, disable: bool| Header {
        control: FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: disable,
        },
        manufacturer_code: None,
        tsn: 0x01,
        command_id: cmd,
    };
    // Errors answer even with the disable bit set.
    assert!(should_default_respond(
        &mk(general::cmd::READ, true),
        true,
        false,
        true
    ));
    // Success stays silent with the disable bit set.
    assert!(!should_default_respond(
        &mk(general::cmd::READ, true),
        true,
        false,
        false
    ));
    // Broadcast errors stay silent.
    assert!(!should_default_respond(
        &mk(general::cmd::READ, false),
        false,
        false,
        true
    ));
    // A Default Response is never answered.
    assert!(!should_default_respond(
        &mk(general::cmd::DEFAULT_RSP, false),
        true,
        false,
        true
    ));
    // A command-specific reply suppresses the fallback.
    assert!(!should_default_respond(
        &mk(general::cmd::READ, false),
        true,
        true,
        false
    ));
}

// 07-5123-08-233-01: unrecognized manufacturer codes are not executed.
#[test]
fn vector_manufacturer_gate_07_5123_08_233_01() {
    let h = Header {
        control: FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: true,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: Some(0x9999),
        tsn: 0x01,
        command_id: general::cmd::READ,
    };
    assert_eq!(
        check_manufacturer(&h, &[0x1234]),
        Err(ZclStatus::UnsupCommand)
    );
    let known = Header {
        manufacturer_code: Some(0x1234),
        ..h
    };
    assert!(check_manufacturer(&known, &[0x1234]).is_ok());
    let plain = Header {
        control: FrameControl {
            manufacturer_specific: false,
            ..h.control
        },
        manufacturer_code: None,
        ..h
    };
    assert!(check_manufacturer(&plain, &[]).is_ok());
}

// Dispatch integration: a global Read over the On/Off server answers;
// discovery pages walk the live store; cluster-specific Toggle flips.
#[test]
fn vector_dispatch_integration_onoff() {
    let def = onoff::ServerDef;
    let mut endpoint = Endpoint::new();
    endpoint.add(&def).unwrap();
    let mut store = onoff::server_store().unwrap();
    let mut eng = ReportingEngine::new();
    let mut events = EventQueue::new();
    let mut beh = onoff::ServerBehavior;
    let mut out = [0u8; 128];
    // Read OnOff (starts off).
    let read = Header {
        control: FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x40,
        command_id: general::cmd::READ,
    };
    let mut ctx = Ctx {
        store: &mut store,
        reporting: &mut eng,
        events: &mut events,
        now_s: 0,
        peer_onoff: None,
        sender_ieee: None,
    };
    match dispatch(
        &endpoint,
        None,
        &mut ctx,
        &read,
        &[0x00, 0x00],
        0x0006,
        None,
        &[],
        &mut out,
    )
    .unwrap()
    {
        DispatchOutcome::Respond(n) => {
            assert_eq!(
                &out[..n],
                &[
                    0x18,
                    0x40,
                    general::cmd::READ_RSP,
                    0x00,
                    0x00,
                    0x00,
                    0x10,
                    0x00
                ]
            );
        }
        DispatchOutcome::Silent => panic!("read must answer"),
    }
    // Cluster-specific Toggle flips the attribute.
    let tog = Header {
        control: FrameControl {
            frame_type: FrameType::ClusterSpecific,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x41,
        command_id: onoff::CMD_TOGGLE,
    };
    let mut ctx = Ctx {
        store: &mut store,
        reporting: &mut eng,
        events: &mut events,
        now_s: 0,
        peer_onoff: None,
        sender_ieee: None,
    };
    match dispatch(
        &endpoint,
        Some(&mut beh),
        &mut ctx,
        &tog,
        &[],
        0x0006,
        None,
        &[],
        &mut out,
    )
    .unwrap()
    {
        DispatchOutcome::Silent => {}
        DispatchOutcome::Respond(_) => panic!("toggle sends no reply"),
    }
    assert!(onoff::onoff(&store));
    // Unknown cluster maps to the documented failure status.
    let mut ctx = Ctx {
        store: &mut store,
        reporting: &mut eng,
        events: &mut events,
        now_s: 0,
        peer_onoff: None,
        sender_ieee: None,
    };
    assert_eq!(
        dispatch(
            &endpoint,
            None,
            &mut ctx,
            &read,
            &[0x00, 0x00],
            0x1234,
            None,
            &[],
            &mut out
        )
        .unwrap_err(),
        ZclStatus::Failure
    );
    // Attribute discovery walks all six instance attributes.
    let disc = Header {
        control: FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x42,
        command_id: general::cmd::DISCOVER_ATTRS,
    };
    let mut ctx = Ctx {
        store: &mut store,
        reporting: &mut eng,
        events: &mut events,
        now_s: 0,
        peer_onoff: None,
        sender_ieee: None,
    };
    match dispatch(
        &endpoint,
        None,
        &mut ctx,
        &disc,
        &[0x00, 0x00, 0xff],
        0x0006,
        None,
        &[],
        &mut out,
    )
    .unwrap()
    {
        DispatchOutcome::Respond(n) => {
            assert_eq!(
                &out[..n],
                &[
                    0x18,
                    0x42,
                    general::cmd::DISCOVER_ATTRS_RSP,
                    0x01,
                    0x00,
                    0x00,
                    0x10,
                    0x00,
                    0x40,
                    0x10,
                    0x01,
                    0x40,
                    0x21,
                    0x02,
                    0x40,
                    0x21,
                    0x03,
                    0x40,
                    0x30,
                    0xfd,
                    0xff,
                    0x21,
                ]
            );
        }
        DispatchOutcome::Silent => panic!("discovery must answer"),
    }
    // Command discovery lists the six received commands.
    let dc = Header {
        control: FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x43,
        command_id: general::cmd::DISCOVER_CMDS_RX,
    };
    let mut ctx = Ctx {
        store: &mut store,
        reporting: &mut eng,
        events: &mut events,
        now_s: 0,
        peer_onoff: None,
        sender_ieee: None,
    };
    match dispatch(
        &endpoint,
        None,
        &mut ctx,
        &dc,
        &[0x00, 0xff],
        0x0006,
        None,
        &[],
        &mut out,
    )
    .unwrap()
    {
        DispatchOutcome::Respond(n) => {
            assert_eq!(
                &out[..n],
                &[
                    0x18,
                    0x43,
                    general::cmd::DISCOVER_CMDS_RX_RSP,
                    0x01,
                    0x00,
                    0x01,
                    0x02,
                    0x40,
                    0x41,
                    0x42
                ]
            );
        }
        DispatchOutcome::Silent => panic!("discovery must answer"),
    }
    // 07-5123-08-251-02/252-02: a two-attribute read into an
    // 11-octet buffer keeps the fitting record and shrinks the
    // overflowing one to INSUFFICIENT_SPACE.
    let mut tiny = [0u8; 11];
    let mut ctx = Ctx {
        store: &mut store,
        reporting: &mut eng,
        events: &mut events,
        now_s: 0,
        peer_onoff: None,
        sender_ieee: None,
    };
    match dispatch(
        &endpoint,
        None,
        &mut ctx,
        &read,
        &[0x00, 0x00, 0x01, 0x40],
        0x0006,
        None,
        &[],
        &mut tiny,
    )
    .unwrap()
    {
        DispatchOutcome::Respond(n) => {
            assert_eq!(
                &tiny[..n],
                &[
                    0x18,
                    0x40,
                    general::cmd::READ_RSP,
                    0x00,
                    0x00,
                    0x00,
                    0x10,
                    0x01,
                    0x01,
                    0x40,
                    0x89,
                ]
            );
        }
        DispatchOutcome::Silent => panic!("read must answer"),
    }
    // Configure reporting on OnOff succeeds bare.
    let cr = Header {
        control: FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn: 0x44,
        command_id: general::cmd::CONFIG_REPORT,
    };
    let mut ctx = Ctx {
        store: &mut store,
        reporting: &mut eng,
        events: &mut events,
        now_s: 0,
        peer_onoff: None,
        sender_ieee: None,
    };
    match dispatch(
        &endpoint,
        None,
        &mut ctx,
        &cr,
        &[0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x3c, 0x00],
        0x0006,
        None,
        &[],
        &mut out,
    )
    .unwrap()
    {
        DispatchOutcome::Respond(n) => {
            assert_eq!(
                &out[..n],
                &[0x18, 0x44, general::cmd::CONFIG_REPORT_RSP, 0x00]
            );
        }
        DispatchOutcome::Silent => panic!("config reporting must answer"),
    }
}
