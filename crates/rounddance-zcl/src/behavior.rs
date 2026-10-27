//! BEHAVIOR layer: state machines plus application callbacks.
//!
//! The top of the 3-level ZCL architecture (engine / definitions /
//! behavior). The engine owns frames, types, stores, and reporting;
//! definitions own static tables; behaviors own *state transitions*
//! and talk to the application through a bounded [`EventQueue`].
//!
//! # Extension contract (adding a full-behavior cluster)
//!
//! A new cluster ships three pieces:
//!
//! 1. A `&'static` [`ClusterDef`](crate::cluster::ClusterDef) table
//!    (identifier, revision, attributes ascending, both command sets
//!    ascending). The discovery handlers and dispatcher consume it
//!    with no further wiring.
//! 2. A `Behavior` implementation holding the cluster's runtime
//!    state (e.g. enrollment stage, test-mode timer, level target).
//!    All time enters through explicit `tick_*` methods taking
//!    caller seconds — behaviors never read a clock, so sim replay
//!    stays deterministic.
//! 3. Vectors exercising every command effect plus discovery and
//!    reporting integration, each citing its requirement ID.
//!
//! Enrollment-style flows (multi-step handshakes with a peer address
//! gate, like IAS trip-to-pair) are expressible as plain state enums
//! advanced inside [`Behavior::handle_cluster_command`]; the stub
//! test at the bottom of this module proves the shape with a minimal
//! three-stage enrollment machine driving the real [`Ctx`].
//!
//! Requirement `07-5123-08-822-03` family (corpus-mined) constrains
//! the IAS instance of this pattern; the trait itself is
//! architecture, not specification.

use crate::attrs::AttrStore;
use crate::frame::Header;
use crate::reporting::ReportingEngine;
use crate::{Error, ZclStatus};

/// Largest queued application callback backlog. Full queues drop new
/// events (counted) rather than growing or blocking the protocol path.
pub const MAX_EVENTS: usize = 16;
/// Largest outbound cluster-command payload carried in an event.
pub const MAX_EVENT_PAYLOAD: usize = 64;

/// Application-visible callback produced by a behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppEvent {
    /// An attribute value changed through command handling.
    AttributeChanged {
        /// Owning cluster.
        cluster: u16,
        /// Changed attribute.
        attr: u16,
    },
    /// The behavior emitted a cluster-specific command for the peer
    /// (e.g. a zone status notification or an enroll request).
    OutboundCommand {
        /// Owning cluster.
        cluster: u16,
        /// Command identifier.
        cmd: u8,
        /// Transaction number to use.
        tsn: u8,
        /// Payload length significant in `payload`.
        len: u8,
        /// Command payload octets.
        payload: [u8; MAX_EVENT_PAYLOAD],
    },
    /// A behavior state machine moved stage (enrollment, test mode…).
    StateChanged {
        /// Owning cluster.
        cluster: u16,
        /// Previous stage code (cluster-defined).
        from: u8,
        /// New stage code (cluster-defined).
        to: u8,
    },
}

/// Bounded application-callback queue shared with behaviors through
/// [`Ctx`]. Pushes beyond capacity are dropped and counted.
#[derive(Clone, Debug)]
pub struct EventQueue {
    events: [Option<AppEvent>; MAX_EVENTS],
    len: u8,
    /// Dropped-event counter (diagnostics; never a protocol input).
    pub dropped: u32,
}

impl Default for EventQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl EventQueue {
    /// Empty queue.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: [None; MAX_EVENTS],
            len: 0,
            dropped: 0,
        }
    }

    /// Queued event count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// No events queued.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Push an event, dropping (and counting) on overflow.
    pub fn push(&mut self, ev: AppEvent) {
        if self.len as usize >= MAX_EVENTS {
            self.dropped += 1;
            return;
        }
        self.events[self.len as usize] = Some(ev);
        self.len += 1;
    }

    /// Drain one event (FIFO).
    pub fn pop(&mut self) -> Option<AppEvent> {
        if self.len == 0 {
            return None;
        }
        let ev = self.events[0];
        let mut i = 0;
        while i + 1 < self.len as usize {
            self.events[i] = self.events[i + 1];
            i += 1;
        }
        self.events[self.len as usize - 1] = None;
        self.len -= 1;
        ev
    }
}

/// Handler context handed to every behavior invocation.
pub struct Ctx<'a> {
    /// Live attribute values for the cluster instance.
    pub store: &'a mut AttrStore,
    /// Reporting engine shared by the endpoint.
    pub reporting: &'a mut ReportingEngine,
    /// Application callback sink.
    pub events: &'a mut EventQueue,
    /// Caller seconds (sim virtual time or host clock snapshot).
    pub now_s: u64,
    /// On/Off server value on the same endpoint, when that cluster
    /// is implemented alongside (level-coupling input; `None` when
    /// absent). Behaviors must treat `None` as "no coupling".
    pub peer_onoff: Option<bool>,
    /// IEEE address of the frame sender, when the lower layers know
    /// it (`None` in unit tests). Address-gated behaviors (IAS Zone)
    /// refuse commands from unexpected senders.
    pub sender_ieee: Option<u64>,
}

/// Outcome of one cluster-specific command handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandleOutcome {
    /// Optional immediate reply payload (cluster-specific response
    /// command body; the dispatcher wraps it in the reply header).
    /// `None` means "no command-specific reply" — the dispatcher
    /// falls back to Default Response rules.
    pub reply_cmd: Option<u8>,
    /// Significant length in `reply_body`.
    pub reply_len: u8,
    /// Reply body octets.
    pub reply_body: [u8; MAX_EVENT_PAYLOAD],
}

impl HandleOutcome {
    /// No command-specific reply; Default Response rules apply.
    #[must_use]
    pub const fn no_reply() -> Self {
        Self {
            reply_cmd: None,
            reply_len: 0,
            reply_body: [0; MAX_EVENT_PAYLOAD],
        }
    }

    /// Reply with command `cmd` and body `body`.
    pub fn reply(cmd: u8, body: &[u8]) -> Result<Self, Error> {
        if body.len() > MAX_EVENT_PAYLOAD {
            return Err(Error::BufferTooSmall);
        }
        let mut reply_body = [0u8; MAX_EVENT_PAYLOAD];
        reply_body[..body.len()].copy_from_slice(body);
        #[allow(clippy::cast_possible_truncation)]
        let reply_len = body.len() as u8;
        Ok(Self {
            reply_cmd: Some(cmd),
            reply_len,
            reply_body,
        })
    }
}

/// Runtime behavior of one cluster instance: state machine plus
/// application callbacks.
///
/// Implementations must be total over their `received_commands` set:
/// known commands apply their effects and update `ctx` (store,
/// events); unknown commands return `Err(ZclStatus::UnsupCommand)`
/// so the dispatcher emits the correct Default Response. Payload
/// truncation or malformed fields return
/// `Err(ZclStatus::MalformedCommand)`, never panic.
pub trait Behavior {
    /// Owning cluster identifier.
    fn cluster_id(&self) -> u16;

    /// Handle one received cluster-specific command. `header` is the
    /// decoded frame header (direction already checked by the
    /// dispatcher); `payload` is the command body.
    fn handle_cluster_command(
        &mut self,
        ctx: &mut Ctx<'_>,
        header: &Header,
        command_id: u8,
        payload: &[u8],
    ) -> Result<HandleOutcome, ZclStatus>;

    /// Post-write hook fired by the dispatcher after a general Write
    /// Attributes record commits. Default: ignore. Behaviors with
    /// write-triggered flows (IAS CIE-address enrollment) override it.
    fn on_attribute_written(&mut self, _ctx: &mut Ctx<'_>, _attr: u16) -> Result<(), ZclStatus> {
        Ok(())
    }
}

#[cfg(test)]
mod stub_tests {
    use super::*;
    use crate::attrs::{access, AttrDef};
    use crate::cluster::{ClusterDef, ClusterRole, CmdDef};
    use crate::frame::{Direction, FrameControl, FrameType};
    use crate::types::DataType;

    /// Minimal three-stage enrollment stub proving IAS-style flows
    /// are expressible through `Behavior`: idle → requested →
    /// enrolled, gated on a single peer-address match.
    struct EnrollStub {
        stage: u8,
        peer: u64,
    }

    struct EnrollStubDef;
    impl ClusterDef for EnrollStubDef {
        fn cluster_id(&self) -> u16 {
            0xfff0
        }
        fn name(&self) -> &'static str {
            "enroll-stub"
        }
        fn revision(&self) -> u16 {
            1
        }
        fn role(&self) -> ClusterRole {
            ClusterRole::Server
        }
        fn attributes(&self) -> &'static [AttrDef] {
            &[]
        }
        fn received_commands(&self) -> &'static [CmdDef] {
            &[CmdDef {
                id: 0x00,
                name: "enroll-response",
            }]
        }
        fn generated_commands(&self) -> &'static [CmdDef] {
            &[CmdDef {
                id: 0x01,
                name: "enroll-request",
            }]
        }
    }

    impl Behavior for EnrollStub {
        fn cluster_id(&self) -> u16 {
            0xfff0
        }

        fn handle_cluster_command(
            &mut self,
            ctx: &mut Ctx<'_>,
            _header: &Header,
            command_id: u8,
            payload: &[u8],
        ) -> Result<HandleOutcome, ZclStatus> {
            if command_id != 0x00 {
                return Err(ZclStatus::UnsupCommand);
            }
            if payload.len() < 9 {
                return Err(ZclStatus::MalformedCommand);
            }
            let mut addr = [0u8; 8];
            addr.copy_from_slice(&payload[..8]);
            let peer = u64::from_le_bytes(addr);
            if peer != self.peer {
                return Err(ZclStatus::NotAuthorized);
            }
            let from = self.stage;
            // Response code 0x00 advances; anything else resets.
            self.stage = if payload[8] == 0x00 { 2 } else { 0 };
            ctx.events.push(AppEvent::StateChanged {
                cluster: 0xfff0,
                from,
                to: self.stage,
            });
            Ok(HandleOutcome::no_reply())
        }
    }

    fn hdr() -> Header {
        Header {
            control: FrameControl {
                frame_type: FrameType::ClusterSpecific,
                manufacturer_specific: false,
                direction: Direction::ToServer,
                disable_default_response: false,
            },
            manufacturer_code: None,
            tsn: 0x07,
            command_id: 0x00,
        }
    }

    #[test]
    fn enrollment_stub_flow_is_expressible() {
        let _ = EnrollStubDef;
        let _ = DataType::Bool;
        let _ = access::READ;
        let mut store = AttrStore::new(None);
        let mut reporting = ReportingEngine::new();
        let mut events = EventQueue::new();
        let mut stub = EnrollStub {
            stage: 1,
            peer: 0x0102_0304_0506_0708,
        };
        let mut payload = [0u8; 9];
        payload[..8].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        payload[8] = 0x00;
        let outcome = stub
            .handle_cluster_command(
                &mut Ctx {
                    store: &mut store,
                    reporting: &mut reporting,
                    events: &mut events,
                    now_s: 0,
                    peer_onoff: None,
                    sender_ieee: None,
                },
                &hdr(),
                0x00,
                &payload,
            )
            .unwrap();
        assert_eq!(outcome, HandleOutcome::no_reply());
        assert_eq!(stub.stage, 2);
        assert_eq!(
            events.pop(),
            Some(AppEvent::StateChanged {
                cluster: 0xfff0,
                from: 1,
                to: 2,
            })
        );
        // Wrong peer is refused without a stage move.
        payload[..8].copy_from_slice(&0xdead_beef_cafe_f00du64.to_le_bytes());
        let err = stub
            .handle_cluster_command(
                &mut Ctx {
                    store: &mut store,
                    reporting: &mut reporting,
                    events: &mut events,
                    now_s: 0,
                    peer_onoff: None,
                    sender_ieee: None,
                },
                &hdr(),
                0x00,
                &payload,
            )
            .unwrap_err();
        assert_eq!(err, ZclStatus::NotAuthorized);
        assert_eq!(stub.stage, 2);
        assert!(events.is_empty());
    }
}
