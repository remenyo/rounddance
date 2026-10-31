//! [`MockDriver`]: scriptable [`Driver`] for host tests and WASM.
//!
//! No hardware, no IDF: scripted TX outcomes, an RX FIFO, a canned ED
//! value, and full recording of everything the adapter programmed
//! (channels, power, addresses, air frames). `no_std`-clean (fixed
//! rings, no heap) so the same mock runs under
//! `wasm32-unknown-unknown`.

use crate::driver::{Driver, DriverError, PendingMode, RxFrame, TxEvent, MAX_AIR_FRAME};

/// Scripted TX-submit outcomes consumed in order (`Ok` = accepted).
const SCRIPT_DEPTH: usize = 8;
/// Queued TX events consumed in order by `poll_tx`.
const EVENT_DEPTH: usize = 8;
/// Injected RX frames consumed in order by `poll_rx`.
const RX_DEPTH: usize = 8;
/// Recorded transmitted air frames.
const TX_LOG_DEPTH: usize = 8;
/// Recorded channel-programming calls.
const CH_LOG_DEPTH: usize = 8;
/// Recorded source-matching (pending) table entries.
const PENDING_TABLE_DEPTH: usize = 8;

/// Scriptable [`Driver`]: the adapter's host-side double.
///
/// Unscripted behavior is permissive (accept TX, report `Done` on the
/// next pump, empty RX, ED returns the canned value) so happy-path
/// tests need no setup; fault-injection legs script exact sequences.
#[derive(Clone, Copy, Debug)]
pub struct MockDriver {
    ready: bool,
    fail_init: bool,
    // Scripts.
    submit_script: [Option<Result<(), DriverError>>; SCRIPT_DEPTH],
    submit_len: usize,
    submit_pos: usize,
    events: [Option<TxEvent>; EVENT_DEPTH],
    events_len: usize,
    events_pos: usize,
    rx_fifo: [Option<RxFrame>; RX_DEPTH],
    rx_len: usize,
    rx_pos: usize,
    ed_dbm: i8,
    fail_ed: bool,
    // Recordings.
    last_channel: Option<u8>,
    channel_sets: [u8; CH_LOG_DEPTH],
    channel_sets_len: usize,
    last_power: Option<i8>,
    power_sets: u32,
    last_addrs: Option<(u16, u16)>,
    promiscuous: Option<bool>,
    start_rx_calls: u32,
    coordinator: Option<bool>,
    pending_mode: Option<PendingMode>,
    pending_shorts: [u16; PENDING_TABLE_DEPTH],
    pending_shorts_len: usize,
    tx_log: [[u8; MAX_AIR_FRAME]; TX_LOG_DEPTH],
    tx_lens: [usize; TX_LOG_DEPTH],
    tx_count: usize,
    auto_done: bool,
    pending_auto: u32,
    /// Single-flight driver state: events only fire while a submit is
    /// outstanding (a scripted event installed before the submit waits
    /// for it — the pump polls completions before submitting).
    in_flight: bool,
}

impl MockDriver {
    /// Permissive mock: init succeeds, TX auto-completes `Done`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ready: false,
            fail_init: false,
            submit_script: [None; SCRIPT_DEPTH],
            submit_len: 0,
            submit_pos: 0,
            events: [None; EVENT_DEPTH],
            events_len: 0,
            events_pos: 0,
            rx_fifo: [None; RX_DEPTH],
            rx_len: 0,
            rx_pos: 0,
            ed_dbm: -80,
            fail_ed: false,
            last_channel: None,
            channel_sets: [0; CH_LOG_DEPTH],
            channel_sets_len: 0,
            last_power: None,
            power_sets: 0,
            last_addrs: None,
            promiscuous: None,
            start_rx_calls: 0,
            coordinator: None,
            pending_mode: None,
            pending_shorts: [0u16; PENDING_TABLE_DEPTH],
            pending_shorts_len: 0,
            tx_log: [[0u8; MAX_AIR_FRAME]; TX_LOG_DEPTH],
            tx_lens: [0; TX_LOG_DEPTH],
            tx_count: 0,
            auto_done: true,
            pending_auto: 0,
            in_flight: false,
        }
    }

    /// Next `init` fails with [`DriverError::HwFault`].
    #[must_use]
    pub fn with_failing_init(mut self) -> Self {
        self.fail_init = true;
        self
    }

    /// Script the next `transmit` submit outcomes in order.
    pub fn script_submit(&mut self, outcomes: &[Result<(), DriverError>]) {
        let n = outcomes.len().min(SCRIPT_DEPTH);
        for (i, o) in outcomes.iter().take(n).enumerate() {
            self.submit_script[i] = Some(*o);
        }
        self.submit_len = n;
        self.submit_pos = 0;
    }

    /// Script the next `poll_tx` events in order.
    pub fn script_events(&mut self, events: &[TxEvent]) {
        let n = events.len().min(EVENT_DEPTH);
        for (i, e) in events.iter().take(n).enumerate() {
            self.events[i] = Some(*e);
        }
        self.events_len = n;
        self.events_pos = 0;
        self.auto_done = false;
    }

    /// Disable TX auto-complete (poll_tx yields only scripted events).
    pub fn hold_auto_complete(&mut self) {
        self.auto_done = false;
    }

    /// Inject RX frames, drained in order by `poll_rx`.
    pub fn inject_rx(&mut self, frames: &[RxFrame]) {
        let n = frames.len().min(RX_DEPTH);
        for (i, f) in frames.iter().take(n).enumerate() {
            self.rx_fifo[i] = Some(*f);
        }
        self.rx_len = n;
        self.rx_pos = 0;
    }

    /// Set the canned energy-scan result; `fail` makes scans error.
    pub fn set_ed(&mut self, dbm: i8, fail: bool) {
        self.ed_dbm = dbm;
        self.fail_ed = fail;
    }

    /// Last programmed channel, if any.
    #[must_use]
    pub fn last_channel(&self) -> Option<u8> {
        self.last_channel
    }

    /// Number of channel-programming calls.
    #[must_use]
    pub fn channel_sets(&self) -> usize {
        self.channel_sets_len
    }

    /// Last programmed TX power, if any.
    #[must_use]
    pub fn last_power(&self) -> Option<i8> {
        self.last_power
    }

    /// Number of TX-power programming calls.
    #[must_use]
    pub fn power_sets(&self) -> u32 {
        self.power_sets
    }

    /// Last programmed (pan, short), if any.
    #[must_use]
    pub fn last_addrs(&self) -> Option<(u16, u16)> {
        self.last_addrs
    }

    /// Last programmed promiscuous mode, if any.
    #[must_use]
    pub fn promiscuous(&self) -> Option<bool> {
        self.promiscuous
    }

    /// Number of receiver-start calls.
    #[must_use]
    pub fn start_rx_calls(&self) -> u32 {
        self.start_rx_calls
    }

    /// Last programmed coordinator mode, if any.
    #[must_use]
    pub fn coordinator(&self) -> Option<bool> {
        self.coordinator
    }

    /// Last programmed auto frame-pending mode, if any.
    #[must_use]
    pub fn pending_mode(&self) -> Option<PendingMode> {
        self.pending_mode
    }

    /// Current recorded source-matching (pending) short table.
    #[must_use]
    pub fn pending_shorts(&self) -> &[u16] {
        &self.pending_shorts[..self.pending_shorts_len]
    }

    /// Number of transmitted air frames recorded.
    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.tx_count
    }

    /// Recorded transmitted air frame `i`.
    #[must_use]
    pub fn tx_frame(&self, i: usize) -> Option<&[u8]> {
        if i < self.tx_count.min(TX_LOG_DEPTH) {
            Some(&self.tx_log[i][..self.tx_lens[i]])
        } else {
            None
        }
    }
}

impl Default for MockDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl Driver for MockDriver {
    fn is_ready(&self) -> bool {
        self.ready
    }

    fn init(&mut self) -> Result<(), DriverError> {
        if self.fail_init {
            return Err(DriverError::HwFault);
        }
        self.ready = true;
        Ok(())
    }

    fn deinit(&mut self) -> Result<(), DriverError> {
        self.ready = false;
        Ok(())
    }

    fn set_channel(&mut self, channel: u8) -> Result<(), DriverError> {
        if !self.ready {
            return Err(DriverError::NotReady);
        }
        if !(11..=26).contains(&channel) {
            return Err(DriverError::InvalidParam);
        }
        self.last_channel = Some(channel);
        if self.channel_sets_len < CH_LOG_DEPTH {
            self.channel_sets[self.channel_sets_len] = channel;
            self.channel_sets_len += 1;
        }
        Ok(())
    }

    fn set_tx_power(&mut self, dbm: i8) -> Result<(), DriverError> {
        if !self.ready {
            return Err(DriverError::NotReady);
        }
        self.last_power = Some(dbm);
        self.power_sets += 1;
        Ok(())
    }

    fn set_addrs(&mut self, pan: u16, short: u16, _ext: &[u8; 8]) -> Result<(), DriverError> {
        if !self.ready {
            return Err(DriverError::NotReady);
        }
        self.last_addrs = Some((pan, short));
        Ok(())
    }

    fn set_promiscuous(&mut self, enable: bool) -> Result<(), DriverError> {
        if !self.ready {
            return Err(DriverError::NotReady);
        }
        self.promiscuous = Some(enable);
        Ok(())
    }

    fn start_rx(&mut self) -> Result<(), DriverError> {
        if !self.ready {
            return Err(DriverError::NotReady);
        }
        self.start_rx_calls += 1;
        Ok(())
    }

    fn set_coordinator(&mut self, enable: bool) -> Result<(), DriverError> {
        if !self.ready {
            return Err(DriverError::NotReady);
        }
        self.coordinator = Some(enable);
        Ok(())
    }

    fn set_pending_mode(&mut self, mode: PendingMode) -> Result<(), DriverError> {
        if !self.ready {
            return Err(DriverError::NotReady);
        }
        self.pending_mode = Some(mode);
        Ok(())
    }

    fn pending_short_add(&mut self, short: u16) -> Result<(), DriverError> {
        if !self.ready {
            return Err(DriverError::NotReady);
        }
        if self.pending_shorts[..self.pending_shorts_len].contains(&short) {
            return Ok(());
        }
        if self.pending_shorts_len >= PENDING_TABLE_DEPTH {
            // Mirrors the real driver's NO_MEM (mapped to HwFault).
            return Err(DriverError::HwFault);
        }
        self.pending_shorts[self.pending_shorts_len] = short;
        self.pending_shorts_len += 1;
        Ok(())
    }

    fn pending_short_clear(&mut self, short: u16) -> Result<(), DriverError> {
        if !self.ready {
            return Err(DriverError::NotReady);
        }
        if let Some(pos) = self.pending_shorts[..self.pending_shorts_len]
            .iter()
            .position(|s| *s == short)
        {
            self.pending_shorts.copy_within(pos + 1.., pos);
            self.pending_shorts_len -= 1;
        }
        Ok(())
    }

    fn pending_shorts_reset(&mut self) -> Result<(), DriverError> {
        if !self.ready {
            return Err(DriverError::NotReady);
        }
        self.pending_shorts_len = 0;
        Ok(())
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), DriverError> {
        if !self.ready {
            return Err(DriverError::NotReady);
        }
        if self.submit_pos < self.submit_len {
            let out = self.submit_script[self.submit_pos].expect("scripted submit");
            self.submit_pos += 1;
            if out.is_ok() {
                self.record_tx(frame);
            }
            return out;
        }
        if frame.is_empty() || frame.len() > MAX_AIR_FRAME {
            return Err(DriverError::InvalidParam);
        }
        self.record_tx(frame);
        Ok(())
    }

    fn poll_tx(&mut self) -> Option<TxEvent> {
        // Single-flight: nothing outstanding, nothing to report.
        if !self.in_flight {
            return None;
        }
        if self.events_pos < self.events_len {
            let ev = self.events[self.events_pos].expect("scripted event");
            self.events_pos += 1;
            self.in_flight = false;
            return Some(ev);
        }
        // Permissive default: every accepted submit completes Done on a
        // later pump (one Done per submit).
        if self.auto_done && self.pending_auto > 0 {
            self.pending_auto -= 1;
            self.in_flight = false;
            return Some(TxEvent::Done);
        }
        None
    }

    fn poll_rx(&mut self) -> Option<RxFrame> {
        if self.rx_pos < self.rx_len {
            let f = self.rx_fifo[self.rx_pos].expect("injected rx");
            self.rx_pos += 1;
            return Some(f);
        }
        None
    }

    fn energy_scan(&mut self, channel: u8) -> Result<i8, DriverError> {
        if !self.ready {
            return Err(DriverError::NotReady);
        }
        if !(11..=26).contains(&channel) {
            return Err(DriverError::InvalidParam);
        }
        if self.fail_ed {
            return Err(DriverError::HwFault);
        }
        Ok(self.ed_dbm)
    }
}

impl MockDriver {
    /// Record a transmitted frame and arm its auto-complete.
    /// Marks the driver busy (single-flight) until the event is polled.
    fn record_tx(&mut self, frame: &[u8]) {
        if self.tx_count < TX_LOG_DEPTH {
            self.tx_log[self.tx_count][..frame.len()].copy_from_slice(frame);
            self.tx_lens[self.tx_count] = frame.len();
        }
        self.tx_count += 1;
        self.in_flight = true;
        if self.auto_done {
            self.pending_auto += 1;
        }
    }
}
