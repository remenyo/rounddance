//! ZCL transaction layer: sequence allocation, reply correlation,
//! Default Response generation, and the Read/On-Off flows that ride
//! on top.
//!
//! Requirement traceability (repo-minted unless noted,
//! MINTED-pending-confirm): `07-5123-08-2413-02` (allocation +
//! matching), `07-5123-08-2512-03` (Default Response builder;
//! triage `07-5123-08-2512-01/02` corpus-mined and reused),
//! `07-5123-08-252-01` (corpus-mined Read Response shape reused),
//! `07-5123-08-383-01` (Toggle effect reused).

use rounddance_zcl::frame::{Direction, FrameControl, FrameType, Header};
use rounddance_zcl::transaction::{
    build_default_response, reply_direction_ok, PendingTable, TsnAlloc,
};
use rounddance_zcl::{general, onoff, ZclStatus};

// 07-5123-08-2413-02: allocator hands out sequential sequences and
// wraps without repeating the in-flight set.
#[test]
fn tsn_allocator_sequences_and_wraps() {
    let mut alloc = TsnAlloc::new(0x00);
    assert_eq!(alloc.peek(), 0x00);
    assert_eq!(alloc.take(), 0x00);
    assert_eq!(alloc.take(), 0x01);
    assert_eq!(alloc.peek(), 0x02);
    let mut edge = TsnAlloc::new(0xff);
    assert_eq!(edge.take(), 0xff);
    assert_eq!(edge.take(), 0x00);
}

// 07-5123-08-2413-02: replies correlate by echoed sequence + cluster;
// reports (no open entry), stray sequences, and wrong clusters stay
// uncorrelated; the same sequence cannot open twice.
#[test]
fn pending_table_matches_tsn_and_cluster() {
    let mut table = PendingTable::<4>::new();
    assert!(table.is_empty());
    table
        .open(0x61, onoff::CLUSTER_ID, onoff::CMD_TOGGLE)
        .unwrap();
    // Same sequence, any cluster/command: refused.
    assert!(table.open(0x61, 0x0008, 0x00).is_err());
    // Wrong sequence or wrong cluster: no correlation.
    let header = |tsn: u8| Header {
        control: FrameControl {
            frame_type: FrameType::ClusterSpecific,
            manufacturer_specific: false,
            direction: Direction::ToClient,
            disable_default_response: true,
        },
        manufacturer_code: None,
        tsn,
        command_id: general::cmd::REPORT,
    };
    assert!(table.close(&header(0x62), onoff::CLUSTER_ID).is_none());
    assert!(table.close(&header(0x61), 0x0008).is_none());
    // Echoed reply closes and returns the open entry.
    let pending = table.close(&header(0x61), onoff::CLUSTER_ID).unwrap();
    assert_eq!(pending.cluster, onoff::CLUSTER_ID);
    assert!(table.is_empty());
    // Replayed reply after close: uncorrelated.
    assert!(table.close(&header(0x61), onoff::CLUSTER_ID).is_none());
    // Full table refuses instead of growing.
    let mut one = PendingTable::<1>::new();
    one.open(0x01, onoff::CLUSTER_ID, onoff::CMD_TOGGLE)
        .unwrap();
    assert!(one
        .open(0x02, onoff::CLUSTER_ID, onoff::CMD_TOGGLE)
        .is_err());
}

// 07-5123-08-2412-01: only client-bound frames count as the reply
// direction.
#[test]
fn reply_direction_gate() {
    let to_client = Header {
        control: FrameControl {
            frame_type: FrameType::Global,
            manufacturer_specific: false,
            direction: Direction::ToClient,
            disable_default_response: true,
        },
        manufacturer_code: None,
        tsn: 0x01,
        command_id: general::cmd::READ_RSP,
    };
    assert!(reply_direction_ok(&to_client));
    let to_server = Header {
        control: FrameControl {
            direction: Direction::ToServer,
            ..to_client.control
        },
        ..to_client
    };
    assert!(!reply_direction_ok(&to_server));
}

// 07-5123-08-2512-03: the builder echoes sequence + command with the
// direction flipped; success answers only when the disable bit is
// clear, errors always answer, and a Default Response is never
// answered.
#[test]
fn default_response_builder_triage() {
    let request = |disable: bool, cmd: u8| Header {
        control: FrameControl {
            frame_type: FrameType::ClusterSpecific,
            manufacturer_specific: false,
            direction: Direction::ToServer,
            disable_default_response: disable,
        },
        manufacturer_code: None,
        tsn: 0x42,
        command_id: cmd,
    };
    let mut out = [0u8; 16];
    // Success without the disable bit: answered.
    let n = build_default_response(
        &request(false, onoff::CMD_TOGGLE),
        ZclStatus::Success,
        true,
        &mut out,
    )
    .unwrap();
    let (reply, body) = Header::decode(&out[..n]).unwrap();
    assert_eq!(reply.tsn, 0x42);
    assert_eq!(reply.command_id, general::cmd::DEFAULT_RSP);
    assert_eq!(reply.control.direction, Direction::ToClient);
    assert!(reply.control.disable_default_response);
    let rsp = rounddance_zcl::transaction::decode_default_response(body).unwrap();
    assert_eq!(rsp.cmd, onoff::CMD_TOGGLE);
    assert_eq!(rsp.status, ZclStatus::Success);
    // Success with the disable bit: silent.
    assert_eq!(
        build_default_response(
            &request(true, onoff::CMD_TOGGLE),
            ZclStatus::Success,
            true,
            &mut out
        ),
        None
    );
    // Error with the disable bit: still answered.
    let n = build_default_response(
        &request(true, onoff::CMD_TOGGLE),
        ZclStatus::UnsupCommand,
        true,
        &mut out,
    )
    .unwrap();
    let (_, body) = Header::decode(&out[..n]).unwrap();
    let rsp = rounddance_zcl::transaction::decode_default_response(body).unwrap();
    assert_eq!(rsp.status, ZclStatus::UnsupCommand);
    // Broadcast errors stay silent.
    assert_eq!(
        build_default_response(
            &request(false, onoff::CMD_TOGGLE),
            ZclStatus::UnsupCommand,
            false,
            &mut out
        ),
        None
    );
    // A Default Response is never answered, even on error.
    assert_eq!(
        build_default_response(
            &request(false, general::cmd::DEFAULT_RSP),
            ZclStatus::Failure,
            true,
            &mut out
        ),
        None
    );
}

// 07-5123-08-252-01 + 07-5123-08-383-01: Read Response and On/Off
// command wire shapes the transaction layer carries.
#[test]
fn read_and_toggle_wire_shapes() {
    // Read Attributes request is an id list.
    let ids = [onoff::ATTR_ONOFF, 0x4001];
    let mut qbuf = [0u8; 8];
    let qn = general::encode_id_list(&ids, &mut qbuf).unwrap();
    assert_eq!(&qbuf[..qn], &[0x00, 0x00, 0x01, 0x40]);
    // Read Response carries the echoed id + status + typed value.
    let recs = [general::ReadRecord {
        id: onoff::ATTR_ONOFF,
        status: ZclStatus::Success,
        dtype: rounddance_zcl::DataType::Bool.as_u8(),
        value: rounddance_zcl::Value::Bool(true),
    }];
    let mut rbuf = [0u8; 16];
    let rn = general::encode_read_rsp(&recs, &mut rbuf).unwrap();
    let mut back = [general::ReadRecord {
        id: 0,
        status: ZclStatus::Success,
        dtype: 0,
        value: rounddance_zcl::Value::NoData,
    }; 4];
    assert_eq!(general::decode_read_rsp(&rbuf[..rn], &mut back).unwrap(), 1);
    assert_eq!(back[0].id, onoff::ATTR_ONOFF);
    assert_eq!(back[0].value, rounddance_zcl::Value::Bool(true));
    // Toggle command shape is unchanged under the transaction layer.
    let mut tbuf = [0u8; 8];
    let tn = onoff::client::toggle(0x61, &mut tbuf).unwrap();
    assert_eq!(&tbuf[..tn], &[0x01, 0x61, onoff::CMD_TOGGLE]);
}
