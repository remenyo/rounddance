//! Command dispatch: global-command execution plus
//! cluster-specific routing with Default Response triage.
//!
//! Paraphrase-level model of doc `07-5123-08` §2.5.12.2 (when the
//! Default Response is generated, anchors p0080-L2995-L3000 +
//! p0081-L3001-L3016), §2.3.3 (unrecognized manufacturer codes are
//! not executed, anchor p0057-L2273-L2274), and §2.3.2.1
//! (broadcast-endpoint fan-out, anchor p0056-L2250). All wording is
//! paraphrase (D1).
//!
//! Requirement IDs: `07-5123-08-2512-01` (corpus corpus-mined shape,
//! MINTED-pending-confirm for the unknown-cluster mapping),
//! `07-5123-08-233-01` + `07-5123-08-2321-01` corpus-mined and reused.

use crate::attrs::AttrStore;
use crate::behavior::{Behavior, Ctx};
use crate::cluster::{ClusterDef, ClusterRole};
use crate::discovery::{handle_discover_attrs, handle_discover_cmds};
use crate::frame::{Direction, FrameType, Header};
use crate::general::{
    self, CfgStatus, ReadCfgQuery, ReadRecord, ReportCfgRecord, WriteRecord, WriteStatus,
    MAX_RECORDS,
};
use crate::reporting::QueryAnswer;
use crate::{Error, ZclStatus};

/// Largest ZCL payload (header excluded) this dispatcher emits.
pub const MAX_ZCL_PAYLOAD: usize = 128;
/// Largest cluster population one endpoint registry holds.
pub const MAX_ENDPOINT_CLUSTERS: usize = 8;

/// Static registry of the cluster sides implemented on one endpoint.
pub struct Endpoint<'a> {
    defs: [&'a dyn ClusterDef; MAX_ENDPOINT_CLUSTERS],
    len: u8,
}

impl<'a> Default for Endpoint<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Endpoint<'a> {
    /// Empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            defs: [NO_DEF; MAX_ENDPOINT_CLUSTERS],
            len: 0,
        }
    }

    /// Register one cluster side.
    pub fn add(&mut self, def: &'a dyn ClusterDef) -> Result<(), Error> {
        if self.len as usize >= MAX_ENDPOINT_CLUSTERS {
            return Err(Error::TooManyClusters);
        }
        self.defs[self.len as usize] = def;
        self.len += 1;
        Ok(())
    }

    /// Find the local side for `cluster_id`, if implemented.
    #[must_use]
    pub fn find(&self, cluster_id: u16) -> Option<&'a dyn ClusterDef> {
        let mut i = 0;
        while i < self.len as usize {
            if self.defs[i].cluster_id() == cluster_id {
                return Some(self.defs[i]);
            }
            i += 1;
        }
        None
    }
}

const NO_DEF: &dyn ClusterDef = &NoDef;
struct NoDef;
impl ClusterDef for NoDef {
    fn cluster_id(&self) -> u16 {
        0xffff
    }
    fn name(&self) -> &'static str {
        "none"
    }
    fn revision(&self) -> u16 {
        0
    }
    fn role(&self) -> ClusterRole {
        ClusterRole::Server
    }
    fn attributes(&self) -> &'static [crate::attrs::AttrDef] {
        &[]
    }
    fn received_commands(&self) -> &'static [crate::cluster::CmdDef] {
        &[]
    }
    fn generated_commands(&self) -> &'static [crate::cluster::CmdDef] {
        &[]
    }
}

/// Gate a manufacturer-specific frame: codes outside the known set
/// are not executed.
///
/// Requirement `07-5123-08-233-01` (corpus-mined).
pub fn check_manufacturer(header: &Header, known: &[u16]) -> Result<(), ZclStatus> {
    if !header.control.manufacturer_specific {
        return Ok(());
    }
    match header.manufacturer_code {
        Some(code) if known.contains(&code) => Ok(()),
        _ => Err(ZclStatus::UnsupCommand),
    }
}

/// Whether the Default Response rules emit a response for this
/// outcome: unicast only, never answering a Default Response, honoring
/// the disable bit (errors still answer when it is set).
///
/// Requirement `07-5123-08-2512-01` (MINTED-pending-confirm).
#[must_use]
pub const fn should_default_respond(
    header: &Header,
    is_unicast: bool,
    replied: bool,
    is_error: bool,
) -> bool {
    if !is_unicast {
        return false;
    }
    if header.command_id == general::cmd::DEFAULT_RSP {
        return false;
    }
    if replied {
        return false;
    }
    if header.control.disable_default_response {
        return is_error;
    }
    true
}

/// Outcome of one dispatch step.
#[derive(Debug)]
pub enum DispatchOutcome {
    /// A command-specific response was written into the caller buffer
    /// (`len` significant octets, header included).
    Respond(usize),
    /// Nothing to send (fire-and-forget path, or a handled report).
    Silent,
}

/// Execute one received frame against an endpoint.
///
/// `behavior` must be the runtime state for `cluster_id` when the
/// frame is cluster-specific, else `None`. Responses are encoded into
/// `out` (header + body). Errors return the status for Default
/// Response triage via [`should_default_respond`]; the caller owns
/// the unicast/broadcast knowledge.
///
/// Requirement `07-5123-08-2321-01` (corpus-mined): broadcast delivery
/// fans out per cluster — the caller iterates its endpoints and calls
/// this once per matching side with `is_unicast = false`.
#[allow(clippy::too_many_arguments)]
pub fn dispatch(
    endpoint: &Endpoint<'_>,
    behavior: Option<&mut dyn Behavior>,
    ctx: &mut Ctx<'_>,
    header: &Header,
    payload: &[u8],
    cluster_id: u16,
    sender_ieee: Option<u64>,
    known_manufacturers: &[u16],
    out: &mut [u8],
) -> Result<DispatchOutcome, ZclStatus> {
    check_manufacturer(header, known_manufacturers)?;
    ctx.sender_ieee = sender_ieee;
    let def = endpoint.find(cluster_id).ok_or(ZclStatus::Failure)?;
    match header.control.frame_type {
        FrameType::Global => {
            let mut behavior = behavior;
            dispatch_global(def, &mut behavior, ctx, header, payload, cluster_id, out)
        }
        FrameType::ClusterSpecific => {
            dispatch_cluster(def, behavior, ctx, header, payload, cluster_id, out)
        }
    }
}

fn dispatch_cluster(
    def: &dyn ClusterDef,
    behavior: Option<&mut dyn Behavior>,
    ctx: &mut Ctx<'_>,
    header: &Header,
    payload: &[u8],
    cluster_id: u16,
    out: &mut [u8],
) -> Result<DispatchOutcome, ZclStatus> {
    // Role/direction agreement: servers take client-to-server frames
    // against their received set; clients take server-to-client frames
    // against their generated set.
    let (want_dir, table) = match def.role() {
        ClusterRole::Server => (Direction::ToServer, def.received_commands()),
        ClusterRole::Client => (Direction::ToClient, def.generated_commands()),
    };
    if header.control.direction != want_dir {
        return Err(ZclStatus::UnsupCommand);
    }
    if !table.iter().any(|c| c.id == header.command_id) {
        return Err(ZclStatus::UnsupCommand);
    }
    let behavior = behavior.ok_or(ZclStatus::Failure)?;
    if behavior.cluster_id() != cluster_id {
        return Err(ZclStatus::Failure);
    }
    let outcome = behavior.handle_cluster_command(ctx, header, header.command_id, payload)?;
    match outcome.reply_cmd {
        None => Ok(DispatchOutcome::Silent),
        Some(cmd) => {
            // `reply_to` preserves the cluster-specific frame type.
            let reply = Header::reply_to(header, cmd);
            let hn = reply.encode_into(out).map_err(|_| ZclStatus::Failure)?;
            let body = &outcome.reply_body[..outcome.reply_len as usize];
            if out.len() - hn < body.len() {
                return Err(ZclStatus::InsufficientSpace);
            }
            out[hn..hn + body.len()].copy_from_slice(body);
            Ok(DispatchOutcome::Respond(hn + body.len()))
        }
    }
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
fn dispatch_global(
    def: &dyn ClusterDef,
    behavior: &mut Option<&mut dyn Behavior>,
    ctx: &mut Ctx<'_>,
    header: &Header,
    payload: &[u8],
    cluster_id: u16,
    out: &mut [u8],
) -> Result<DispatchOutcome, ZclStatus> {
    // Only server sides host attribute state here; a global command
    // arriving for a client side has nothing to act on. Server-side
    // discover/read/write support is the minimum cluster behavior of
    // `07-5123-08-25-01` (corpus-mined).
    if def.role() != ClusterRole::Server {
        return Err(ZclStatus::UnsupCommand);
    }
    match header.command_id {
        general::cmd::READ => {
            let mut ids = [0u16; MAX_RECORDS];
            let n = general::decode_id_list(payload, &mut ids).map_err(map_codec)?;
            let mut records = [ReadRecord {
                id: 0,
                status: ZclStatus::Success,
                dtype: 0,
                value: crate::types::Value::NoData,
            }; MAX_RECORDS];
            let mut i = 0;
            while i < n {
                records[i] = read_one(ctx.store, ids[i]);
                i += 1;
            }
            let reply = Header::reply_to(header, general::cmd::READ_RSP);
            let hn = reply.encode_into(out).map_err(|_| ZclStatus::Failure)?;
            // Fit rule: the first record that overflows is shrunk to
            // its 3-octet INSUFFICIENT_SPACE form and the scan ends;
            // if even that does not fit, trailing records drop until
            // the frame goes out as assembled so far.
            //
            // Requirements `07-5123-08-251-02` + `07-5123-08-252-02`
            // (corpus-mined).
            let mut kept = n;
            loop {
                match general::encode_read_rsp(&records[..kept], &mut out[hn..]) {
                    Ok(bn) => return Ok(DispatchOutcome::Respond(hn + bn)),
                    Err(Error::BufferTooSmall) if kept > 0 => {
                        let last = &mut records[kept - 1];
                        if last.status.is_success() {
                            last.status = ZclStatus::InsufficientSpace;
                            last.dtype = 0;
                            last.value = crate::types::Value::NoData;
                        } else {
                            kept -= 1;
                        }
                    }
                    Err(_) => return Err(ZclStatus::InsufficientSpace),
                }
            }
        }
        general::cmd::WRITE | general::cmd::WRITE_UNDIVIDED => {
            let mut recs = [WriteRecord {
                id: 0,
                dtype: 0,
                value: crate::types::Value::NoData,
            }; MAX_RECORDS];
            let n = general::decode_write(payload, &mut recs).map_err(map_codec)?;
            // Undivided writes validate everything before changing
            // anything; plain writes apply record by record.
            let undivided = header.command_id == general::cmd::WRITE_UNDIVIDED;
            let mut statuses = [WriteStatus {
                status: ZclStatus::Success,
                id: None,
            }; MAX_RECORDS];
            if undivided {
                let mut i = 0;
                while i < n {
                    statuses[i] = probe_write(ctx.store, &recs[i]);
                    i += 1;
                }
                if statuses[..n].iter().any(|s| !s.status.is_success()) {
                    return write_rsp(header, &statuses[..n], out);
                }
            }
            let mut i = 0;
            while i < n {
                statuses[i] = apply_write(behavior, ctx, cluster_id, &recs[i]);
                i += 1;
            }
            write_rsp(header, &statuses[..n], out)
        }
        general::cmd::WRITE_NO_RSP => {
            let mut recs = [WriteRecord {
                id: 0,
                dtype: 0,
                value: crate::types::Value::NoData,
            }; MAX_RECORDS];
            let n = general::decode_write(payload, &mut recs).map_err(map_codec)?;
            // Fire-and-forget: valid records apply, the rest are
            // silently skipped, and no reply of any kind is emitted.
            //
            // Requirement `07-5123-08-256-01` (corpus-mined).
            let mut i = 0;
            while i < n {
                let _ = apply_write(behavior, ctx, cluster_id, &recs[i]);
                i += 1;
            }
            Ok(DispatchOutcome::Silent)
        }
        general::cmd::CONFIG_REPORT => {
            let mut recs = [ReportCfgRecord {
                direction: 0,
                id: 0,
                dtype: 0,
                min: 0,
                max: 0,
                change: None,
                timeout: 0,
            }; MAX_RECORDS];
            let n = general::decode_config_report(payload, &mut recs).map_err(map_codec)?;
            let mut statuses = [CfgStatus {
                status: ZclStatus::Success,
                direction: None,
                id: None,
            }; MAX_RECORDS];
            let mut i = 0;
            while i < n {
                statuses[i] = apply_report_cfg(ctx, &recs[i]);
                i += 1;
            }
            let reply = Header::reply_to(header, general::cmd::CONFIG_REPORT_RSP);
            let hn = reply.encode_into(out).map_err(|_| ZclStatus::Failure)?;
            let bn = general::encode_config_report_rsp(&statuses[..n], &mut out[hn..])
                .map_err(|_| ZclStatus::InsufficientSpace)?;
            Ok(DispatchOutcome::Respond(hn + bn))
        }
        general::cmd::READ_REPORT_CFG => {
            let mut queries = [ReadCfgQuery {
                direction: 0,
                id: 0,
            }; MAX_RECORDS];
            let n = general::decode_read_report_cfg(payload, &mut queries).map_err(map_codec)?;
            // Response records are variable-length; encode incrementally.
            let reply = Header::reply_to(header, general::cmd::READ_REPORT_CFG_RSP);
            let mut off = reply.encode_into(out).map_err(|_| ZclStatus::Failure)?;
            let mut i = 0;
            while i < n {
                off += encode_query_answer(ctx, &queries[i], &mut out[off..])
                    .map_err(|_| ZclStatus::InsufficientSpace)?;
                i += 1;
            }
            Ok(DispatchOutcome::Respond(off))
        }
        general::cmd::REPORT => {
            // Reports carry values, not commands: accept and drop (the
            // client-side application reads them via its own codec).
            let mut recs = [general::ReportRecord {
                id: 0,
                dtype: 0,
                value: crate::types::Value::NoData,
            }; MAX_RECORDS];
            general::decode_report(payload, &mut recs).map_err(map_codec)?;
            Ok(DispatchOutcome::Silent)
        }
        general::cmd::DISCOVER_ATTRS => {
            let req = general::DiscoverAttrs::decode(payload).map_err(map_codec)?;
            let mut records = [(0u16, 0u8); MAX_RECORDS];
            let (n, complete) = handle_discover_attrs(
                ctx.store,
                req,
                header.control.manufacturer_specific,
                &mut records,
            );
            let reply = Header::reply_to(header, general::cmd::DISCOVER_ATTRS_RSP);
            let hn = reply.encode_into(out).map_err(|_| ZclStatus::Failure)?;
            let bn = general::encode_discover_attrs_rsp(&records[..n], complete, &mut out[hn..])
                .map_err(|_| ZclStatus::InsufficientSpace)?;
            Ok(DispatchOutcome::Respond(hn + bn))
        }
        general::cmd::DISCOVER_CMDS_RX | general::cmd::DISCOVER_CMDS_TX => {
            let req = general::DiscoverCmds::decode(payload).map_err(map_codec)?;
            let mut ids = [0u8; MAX_RECORDS];
            let (n, complete) = handle_discover_cmds(def, header, req, &mut ids);
            let rsp_cmd = if header.command_id == general::cmd::DISCOVER_CMDS_RX {
                general::cmd::DISCOVER_CMDS_RX_RSP
            } else {
                general::cmd::DISCOVER_CMDS_TX_RSP
            };
            let reply = Header::reply_to(header, rsp_cmd);
            let hn = reply.encode_into(out).map_err(|_| ZclStatus::Failure)?;
            let bn = general::encode_discover_cmds_rsp(&ids[..n], complete, &mut out[hn..])
                .map_err(|_| ZclStatus::InsufficientSpace)?;
            Ok(DispatchOutcome::Respond(hn + bn))
        }
        _ => Err(ZclStatus::UnsupCommand),
    }
}

fn read_one(store: &AttrStore, id: u16) -> ReadRecord {
    match store.get(id) {
        None => ReadRecord {
            id,
            status: ZclStatus::UnsupportedAttribute,
            dtype: 0,
            value: crate::types::Value::NoData,
        },
        Some(value) => {
            let def = store.definition(id).unwrap();
            if !def.readable() {
                // Write-only-class attributes are not readable here;
                // report authorization failure without a value.
                return ReadRecord {
                    id,
                    status: ZclStatus::NotAuthorized,
                    dtype: 0,
                    value: crate::types::Value::NoData,
                };
            }
            ReadRecord {
                id,
                status: ZclStatus::Success,
                dtype: def.datatype,
                value,
            }
        }
    }
}

fn probe_write(store: &AttrStore, rec: &WriteRecord) -> WriteStatus {
    let fail = |status| WriteStatus {
        status,
        id: Some(rec.id),
    };
    let def = match store.definition(rec.id) {
        Some(d) => d,
        None => return fail(ZclStatus::UnsupportedAttribute),
    };
    if rec.dtype != def.datatype {
        return fail(ZclStatus::InvalidDataType);
    }
    if !def.writable() {
        return fail(ZclStatus::ReadOnly);
    }
    WriteStatus {
        status: ZclStatus::Success,
        id: None,
    }
}

fn apply_write(
    behavior: &mut Option<&mut dyn Behavior>,
    ctx: &mut Ctx<'_>,
    cluster_id: u16,
    rec: &WriteRecord,
) -> WriteStatus {
    let fail = |status| WriteStatus {
        status,
        id: Some(rec.id),
    };
    match ctx.store.write(rec.id, rec.value) {
        Ok(()) => {
            ctx.events
                .push(crate::behavior::AppEvent::AttributeChanged {
                    cluster: cluster_id,
                    attr: rec.id,
                });
            // Write-triggered behavior flows (IAS enrollment) observe
            // the commit here; hook failures are diagnostics only —
            // the attribute value already stands.
            if let Some(b) = behavior.as_mut() {
                let _ = b.on_attribute_written(ctx, rec.id);
            }
            WriteStatus {
                status: ZclStatus::Success,
                id: None,
            }
        }
        Err(status) => fail(status),
    }
}

fn write_rsp(
    header: &Header,
    statuses: &[WriteStatus],
    out: &mut [u8],
) -> Result<DispatchOutcome, ZclStatus> {
    let reply = Header::reply_to(header, general::cmd::WRITE_RSP);
    let hn = reply.encode_into(out).map_err(|_| ZclStatus::Failure)?;
    let bn = general::encode_write_rsp(statuses, &mut out[hn..])
        .map_err(|_| ZclStatus::InsufficientSpace)?;
    Ok(DispatchOutcome::Respond(hn + bn))
}

fn apply_report_cfg(ctx: &mut Ctx<'_>, rec: &ReportCfgRecord) -> CfgStatus {
    let fail = |status| CfgStatus {
        status,
        direction: Some(rec.direction),
        id: Some(rec.id),
    };
    let status = if rec.direction == 0x00 {
        ctx.reporting.configure(ctx.store, rec, ctx.now_s)
    } else if rec.direction == 0x01 {
        ctx.reporting.configure_timeout(ctx.store, rec)
    } else {
        return fail(ZclStatus::InvalidField);
    };
    if status.is_success() {
        CfgStatus {
            status,
            direction: None,
            id: None,
        }
    } else {
        fail(status)
    }
}

fn encode_query_answer(
    ctx: &Ctx<'_>,
    query: &ReadCfgQuery,
    out: &mut [u8],
) -> Result<usize, crate::Error> {
    if query.direction != 0x00 && query.direction != 0x01 {
        return Err(Error::InvalidValue(query.direction));
    }
    match ctx.reporting.query(ctx.store, query.direction, query.id) {
        QueryAnswer::Bare { status } => {
            if out.len() < 4 {
                return Err(Error::BufferTooSmall);
            }
            out[0] = status.as_u8();
            out[1] = query.direction;
            out[2..4].copy_from_slice(&query.id.to_le_bytes());
            Ok(4)
        }
        QueryAnswer::Send {
            dtype,
            min_s,
            max_s,
            change,
        } => {
            let dtype_t = crate::types::DataType::from_u8(dtype)?;
            let need = 4
                + 1
                + 2
                + 2
                + if dtype_t.is_analog() {
                    change.encoded_len()
                } else {
                    0
                };
            if out.len() < need {
                return Err(Error::BufferTooSmall);
            }
            out[0] = ZclStatus::Success.as_u8();
            out[1] = query.direction;
            out[2..4].copy_from_slice(&query.id.to_le_bytes());
            out[4] = dtype;
            out[5..7].copy_from_slice(&min_s.to_le_bytes());
            out[7..9].copy_from_slice(&max_s.to_le_bytes());
            let mut off = 9;
            if dtype_t.is_analog() {
                off += change.encode_into(&mut out[off..])?;
            }
            Ok(off)
        }
        QueryAnswer::Timeout { timeout_s } => {
            if out.len() < 6 {
                return Err(Error::BufferTooSmall);
            }
            out[0] = ZclStatus::Success.as_u8();
            out[1] = query.direction;
            out[2..4].copy_from_slice(&query.id.to_le_bytes());
            out[4..6].copy_from_slice(&timeout_s.to_le_bytes());
            Ok(6)
        }
    }
}

/// Map codec fallibility onto command statuses: truncation and
/// malformed lists read as MALFORMED_COMMAND; semantic rejections
/// pass through.
fn map_codec(err: Error) -> ZclStatus {
    match err {
        Error::Truncated | Error::MalformedList => ZclStatus::MalformedCommand,
        Error::TooManyRecords => ZclStatus::InsufficientSpace,
        Error::UnknownDatatype(_) | Error::UnsupportedType(_) => ZclStatus::InvalidField,
        Error::InvalidValue(_) => ZclStatus::InvalidField,
        _ => ZclStatus::Failure,
    }
}
