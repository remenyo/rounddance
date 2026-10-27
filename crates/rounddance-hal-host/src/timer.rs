//! Host timer backend: bounded deadline queue driven by an explicit
//! tick clock.
//!
//! The stack never blocks: callers [`HostTimer::schedule`] deadlines
//! against [`crate::HostClock`] time and drain firings with
//! [`HostTimer::poll_due`]. Capacity is fixed at provisioning (D5:
//! never resized mid-transaction); overflow is a typed error, never
//! silent growth.

/// Timer failures: backpressure only, never allocator state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerError {
    /// Deadline table is full (backpressure signal).
    Full,
    /// Unknown timer id.
    UnknownId,
}

impl core::fmt::Display for TimerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Full => f.write_str("timer table full"),
            Self::UnknownId => f.write_str("unknown timer id"),
        }
    }
}

impl std::error::Error for TimerError {}

/// One armed deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Deadline {
    id: u64,
    fire_at_us: u64,
}

/// Bounded host timer queue.
///
/// Deadlines fire in time order; ties break by id so replays agree
/// across native and WASM.
#[derive(Clone, Debug)]
pub struct HostTimer {
    deadlines: Vec<Deadline>,
    capacity: usize,
}

impl HostTimer {
    /// Fixed deadline-table depth (preallocated, never resized — D5).
    pub const DEFAULT_CAPACITY: usize = 16;

    /// Empty timer queue with [`HostTimer::DEFAULT_CAPACITY`] slots.
    #[must_use]
    pub fn new() -> Self {
        Self {
            deadlines: Vec::with_capacity(Self::DEFAULT_CAPACITY),
            capacity: Self::DEFAULT_CAPACITY,
        }
    }

    /// Number of armed deadlines.
    #[must_use]
    pub fn armed(&self) -> usize {
        self.deadlines.len()
    }

    /// True when no deadline is armed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.deadlines.is_empty()
    }

    /// Arm timer `id` to fire at absolute `fire_at_us`.
    ///
    /// # Errors
    ///
    /// [`TimerError::Full`] when the table holds `capacity` deadlines.
    pub fn schedule(&mut self, id: u64, fire_at_us: u64) -> Result<(), TimerError> {
        if self.deadlines.len() >= self.capacity {
            return Err(TimerError::Full);
        }
        self.deadlines.push(Deadline { id, fire_at_us });
        Ok(())
    }

    /// Arm timer `id` to fire `delay_us` after `now_us`.
    ///
    /// # Errors
    ///
    /// [`TimerError::Full`] when the table is full.
    pub fn schedule_in(&mut self, id: u64, now_us: u64, delay_us: u64) -> Result<(), TimerError> {
        self.schedule(id, now_us.saturating_add(delay_us))
    }

    /// Cancel timer `id`.
    ///
    /// # Errors
    ///
    /// [`TimerError::UnknownId`] when `id` is not armed.
    pub fn cancel(&mut self, id: u64) -> Result<(), TimerError> {
        let Some(pos) = self.deadlines.iter().position(|d| d.id == id) else {
            return Err(TimerError::UnknownId);
        };
        self.deadlines.remove(pos);
        Ok(())
    }

    /// Drain every deadline with `fire_at_us <= now_us`, in
    /// (time, id) order.
    pub fn poll_due(&mut self, now_us: u64) -> Vec<u64> {
        let mut due: Vec<(u64, u64)> = self
            .deadlines
            .iter()
            .filter(|d| d.fire_at_us <= now_us)
            .map(|d| (d.fire_at_us, d.id))
            .collect();
        due.sort_unstable();
        self.deadlines.retain(|d| d.fire_at_us > now_us);
        due.into_iter().map(|(_, id)| id).collect()
    }
}

impl Default for HostTimer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_in_time_order_with_id_tiebreak() {
        let mut t = HostTimer::new();
        t.schedule(9, 300).unwrap();
        t.schedule(3, 100).unwrap();
        t.schedule(7, 100).unwrap();
        assert_eq!(t.poll_due(99), Vec::<u64>::new());
        assert_eq!(t.poll_due(100), vec![3, 7]);
        assert_eq!(t.poll_due(300), vec![9]);
        assert!(t.is_empty());
    }

    #[test]
    fn full_is_an_error_cancel_frees() {
        let mut t = HostTimer::new();
        for id in 0..HostTimer::DEFAULT_CAPACITY as u64 {
            t.schedule(id, id * 10).unwrap();
        }
        assert_eq!(t.schedule(999, 0), Err(TimerError::Full));
        t.cancel(0).unwrap();
        t.schedule(999, 0).unwrap();
        assert_eq!(t.cancel(4242), Err(TimerError::UnknownId));
    }
}
