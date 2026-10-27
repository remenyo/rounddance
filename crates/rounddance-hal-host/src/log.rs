//! Structured host log: module-attributed events with device,
//! run-id, state-transition, and transaction fields.
//!
//! Every event carries `module / device / run_id` plus a payload
//! describing a state transition, a transaction phase, or a note.
//! The scenario in [`crate::scenario`] logs the full transaction
//! through this sink; the checked-in `sample_trace.txt` is its
//! rendered output, so any behavioral drift fails the test.

/// What happened: a state transition, a transaction phase, or a
/// free-form note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// `module` moved `from` → `to` on `device`.
    StateTransition {
        /// State name before the step.
        from: &'static str,
        /// State name after the step.
        to: &'static str,
    },
    /// Phase `phase` of transaction `id` (e.g. `"zcl-on"` /
    /// `"aps-secure-tx"`).
    Transaction {
        /// Transaction identifier (e.g. the ZCL TSN).
        id: u64,
        /// Phase name within the transaction.
        phase: &'static str,
    },
    /// Free-form note (never a state or transaction — those have
    /// their own variants so greps stay reliable).
    Note {
        /// Short note text.
        msg: String,
    },
}

/// One structured log event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEvent {
    /// Monotonic sequence number within this log.
    pub seq: u64,
    /// Tick-clock time in microseconds (never wall time, so replays agree).
    pub time_us: u64,
    /// Owning protocol module (e.g. `"commission"`, `"zcl"`, `"hal-host"`).
    pub module: &'static str,
    /// Device the event belongs to (short address; `0xFFFF` = medium/host).
    pub device: u16,
    /// Run id (the scenario seed doubles as run id).
    pub run_id: u64,
    /// What happened.
    pub kind: EventKind,
}

impl LogEvent {
    /// Render one trace line.
    #[must_use]
    pub fn line(&self) -> String {
        match &self.kind {
            EventKind::StateTransition { from, to } => format!(
                "t={} seq={} run={:#x} mod={} dev={:#06x} transition {from}->{to}",
                self.time_us, self.seq, self.run_id, self.module, self.device,
            ),
            EventKind::Transaction { id, phase } => format!(
                "t={} seq={} run={:#x} mod={} dev={:#06x} txn={id:#x} phase={phase}",
                self.time_us, self.seq, self.run_id, self.module, self.device,
            ),
            EventKind::Note { msg } => format!(
                "t={} seq={} run={:#x} mod={} dev={:#06x} note {msg}",
                self.time_us, self.seq, self.run_id, self.module, self.device,
            ),
        }
    }
}

/// In-memory structured log (native + WASM).
///
/// Bounded: past [`HostLog::MAX_EVENTS`] the oldest events are
/// dropped (counter kept so sequence numbers stay gapless and the
/// drop itself stays visible via [`HostLog::dropped`]).
#[derive(Clone, Debug, Default)]
pub struct HostLog {
    events: Vec<LogEvent>,
    dropped: u64,
    next_seq: u64,
}

impl HostLog {
    /// Ring bound (oldest-first drop past this many events).
    pub const MAX_EVENTS: usize = 8192;

    /// Empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of events retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// True when no event is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Events dropped past the bound.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Record an event; returns its sequence number.
    pub fn event(
        &mut self,
        time_us: u64,
        module: &'static str,
        device: u16,
        run_id: u64,
        kind: EventKind,
    ) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        if self.events.len() >= Self::MAX_EVENTS {
            self.events.remove(0);
            self.dropped += 1;
        }
        self.events.push(LogEvent {
            seq,
            time_us,
            module,
            device,
            run_id,
            kind,
        });
        seq
    }

    /// Convenience: log a state transition.
    pub fn transition(
        &mut self,
        time_us: u64,
        module: &'static str,
        device: u16,
        run_id: u64,
        from: &'static str,
        to: &'static str,
    ) -> u64 {
        self.event(
            time_us,
            module,
            device,
            run_id,
            EventKind::StateTransition { from, to },
        )
    }

    /// Convenience: log a transaction phase.
    pub fn txn(
        &mut self,
        time_us: u64,
        module: &'static str,
        device: u16,
        run_id: u64,
        id: u64,
        phase: &'static str,
    ) -> u64 {
        self.event(
            time_us,
            module,
            device,
            run_id,
            EventKind::Transaction { id, phase },
        )
    }

    /// Retained events, oldest first.
    #[must_use]
    pub fn events(&self) -> &[LogEvent] {
        &self.events
    }

    /// Rendered trace lines, oldest first.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        self.events.iter().map(LogEvent::line).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_carry_module_device_run_transition_txn() {
        let mut log = HostLog::new();
        assert!(log.is_empty());
        log.transition(10, "commission", 0x0001, 0xabc, "joining", "joined");
        log.txn(20, "zcl", 0x0001, 0xabc, 0x61, "report-rx");
        let lines = log.lines();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("mod=commission"));
        assert!(lines[0].contains("dev=0x0001"));
        assert!(lines[0].contains("run=0xabc"));
        assert!(lines[0].contains("transition joining->joined"));
        assert!(lines[1].contains("txn=0x61 phase=report-rx"));
        assert_eq!(log.dropped(), 0);
    }
}
