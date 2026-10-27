//! Exclusive port leases: acquire / heartbeat / release / queue / expire.
//!
//! State persists to a JSON file so a crashed worker's leases are found on
//! reload — and stale ones expire on load (crash recovery). Every mutating
//! operation sweeps expired leases first, so expiry needs no background task.
//!
//! Contended ports get a FIFO queue: a failed `acquire` records the waiter
//! and returns its position; when the holder releases (or expires), the head
//! waiter is next but must still call `acquire` (leases are never granted
//! silently — the waiter re-checks ownership at acquire time).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A waiter queued for a contended port.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Waiter {
    pub owner: String,
    pub purpose: String,
    pub queued_epoch: u64,
}

/// An exclusive lease on one serial port.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Lease {
    pub port: String,
    pub owner: String,
    pub purpose: String,
    pub acquired_epoch: u64,
    pub expires_epoch: u64,
}

impl Lease {
    pub fn expired(&self, now_epoch: u64) -> bool {
        now_epoch >= self.expires_epoch
    }

    pub fn remaining(&self, now_epoch: u64) -> Duration {
        Duration::from_secs(self.expires_epoch.saturating_sub(now_epoch))
    }
}

/// Lease manager errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseError {
    /// Port is held; waiter recorded at this queue position (0-based).
    Contended { holder: String, position: usize },
    /// Port is quarantined; nobody may acquire until cleared.
    Quarantined { reason: String },
    /// No live lease on this port.
    NotHeld,
    /// Lease exists but belongs to someone else.
    NotOwner { holder: String },
    /// State file I/O or JSON failure.
    Store(String),
}

impl fmt::Display for LeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LeaseError::Contended { holder, position } => {
                write!(f, "port held by {holder}; queued at position {position}")
            }
            LeaseError::Quarantined { reason } => {
                write!(f, "port quarantined: {reason}")
            }
            LeaseError::NotHeld => write!(f, "no live lease on this port"),
            LeaseError::NotOwner { holder } => {
                write!(f, "lease held by {holder}, not you")
            }
            LeaseError::Store(e) => write!(f, "lease store: {e}"),
        }
    }
}

impl std::error::Error for LeaseError {}

/// Warn-before-expiry horizon for `status`: leases with less than
/// this TTL are surfaced as expiring instead of vanishing silently
/// at expiry (the silent-expiry fix).
pub const EXPIRY_WARN_SECS: u64 = 300;

/// Time source. Production uses the wall clock; tests use [`ManualClock`].
pub trait Clock {
    fn now_epoch(&self) -> u64;
}

/// Wall-clock time source.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_epoch(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Controllable time source for tests.
#[derive(Debug, Clone, Copy)]
pub struct ManualClock {
    pub now: u64,
}

impl Clock for ManualClock {
    fn now_epoch(&self) -> u64 {
        self.now
    }
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Store {
    #[serde(default)]
    leases: HashMap<String, Lease>,
    #[serde(default)]
    queues: HashMap<String, VecDeque<Waiter>>,
    #[serde(default)]
    quarantine: HashMap<String, String>,
}

/// Exclusive-lease manager backed by a JSON state file.
pub struct LeaseManager<C: Clock = SystemClock> {
    path: PathBuf,
    store: Store,
    clock: C,
}

impl LeaseManager<SystemClock> {
    /// Load state from `path` (missing file = empty state). Stale leases
    /// expire during load — this is the crash-recovery path.
    pub fn load(path: &Path) -> Result<Self, LeaseError> {
        Self::load_with_clock(path, SystemClock)
    }
}

impl<C: Clock> LeaseManager<C> {
    /// Load with an explicit clock (used by tests).
    pub fn load_with_clock(path: &Path, clock: C) -> Result<Self, LeaseError> {
        let mut mgr = Self {
            path: path.to_path_buf(),
            store: Store::default(),
            clock,
        };
        mgr.read_file()?;
        mgr.sweep();
        // Best-effort: persist the swept state so a crash loop converges.
        let _ = mgr.save();
        Ok(mgr)
    }

    fn read_file(&mut self) -> Result<(), LeaseError> {
        let raw = match fs::read(&self.path) {
            Ok(b) if !b.is_empty() => b,
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(LeaseError::Store(e.to_string())),
        };
        self.store = serde_json::from_slice(&raw).map_err(|e| LeaseError::Store(e.to_string()))?;
        Ok(())
    }

    /// Persist current state.
    pub fn save(&self) -> Result<(), LeaseError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| LeaseError::Store(e.to_string()))?;
            }
        }
        let raw =
            serde_json::to_vec_pretty(&self.store).map_err(|e| LeaseError::Store(e.to_string()))?;
        // Atomic-ish: write temp, then rename.
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, raw).map_err(|e| LeaseError::Store(e.to_string()))?;
        fs::rename(&tmp, &self.path).map_err(|e| LeaseError::Store(e.to_string()))?;
        Ok(())
    }

    fn now(&self) -> u64 {
        self.clock.now_epoch()
    }

    /// Waiters older than this are dropped: a crashed waiter must not hold
    /// the head slot forever and block the queue behind it.
    pub const WAITER_TTL_SECS: u64 = 3600;

    /// Drop expired leases and stale waiters.
    pub fn sweep(&mut self) {
        let now = self.now();
        self.store.leases.retain(|_, l| !l.expired(now));
        let ttl = Self::WAITER_TTL_SECS;
        for queue in self.store.queues.values_mut() {
            queue.retain(|w| now.saturating_sub(w.queued_epoch) < ttl);
        }
        self.store.queues.retain(|_, q| !q.is_empty());
    }

    /// Acquire an exclusive lease. On contention the caller is queued and
    /// [`LeaseError::Contended`] carries the queue position.
    pub fn acquire(
        &mut self,
        port: &str,
        owner: &str,
        purpose: &str,
        timeout: Duration,
    ) -> Result<Lease, LeaseError> {
        self.sweep();
        let now = self.now();
        if let Some(reason) = self.store.quarantine.get(port).cloned() {
            return Err(LeaseError::Quarantined { reason });
        }
        if let Some(holder) = self.store.leases.get(port).map(|l| l.owner.clone()) {
            let position = {
                let queue = self.store.queues.entry(port.to_string()).or_default();
                if !queue.iter().any(|w| w.owner == owner) {
                    queue.push_back(Waiter {
                        owner: owner.to_string(),
                        purpose: purpose.to_string(),
                        queued_epoch: now,
                    });
                }
                queue.iter().position(|w| w.owner == owner).unwrap_or(0)
            };
            self.save()?;
            return Err(LeaseError::Contended { holder, position });
        }
        // If a queue exists (holder expired), only the head may take it.
        let head_owner = self
            .store
            .queues
            .get(port)
            .and_then(|q| q.front())
            .map(|w| w.owner.clone());
        if let Some(head) = head_owner {
            if head != owner {
                let position = {
                    let queue = self.store.queues.entry(port.to_string()).or_default();
                    if !queue.iter().any(|w| w.owner == owner) {
                        queue.push_back(Waiter {
                            owner: owner.to_string(),
                            purpose: purpose.to_string(),
                            queued_epoch: now,
                        });
                    }
                    queue.iter().position(|w| w.owner == owner).unwrap_or(0)
                };
                self.save()?;
                return Err(LeaseError::Contended {
                    holder: head,
                    position,
                });
            }
            if let Some(queue) = self.store.queues.get_mut(port) {
                queue.retain(|w| w.owner != owner);
            }
        }
        let lease = Lease {
            port: port.to_string(),
            owner: owner.to_string(),
            purpose: purpose.to_string(),
            acquired_epoch: now,
            expires_epoch: now.saturating_add(timeout.as_secs().max(1)),
        };
        self.store.leases.insert(port.to_string(), lease.clone());
        self.save()?;
        Ok(lease)
    }

    /// Extend your own lease by `extra` from now.
    pub fn renew(&mut self, port: &str, owner: &str, extra: Duration) -> Result<Lease, LeaseError> {
        self.sweep();
        let now = self.now();
        match self.store.leases.get_mut(port) {
            None => Err(LeaseError::NotHeld),
            Some(l) if l.owner != owner => Err(LeaseError::NotOwner {
                holder: l.owner.clone(),
            }),
            Some(l) => {
                l.expires_epoch = now.saturating_add(extra.as_secs().max(1));
                let out = l.clone();
                self.save()?;
                Ok(out)
            }
        }
    }

    /// Release your own lease. Returns the head waiter (if any) so the
    /// caller can notify them; they must still `acquire`.
    pub fn release(&mut self, port: &str, owner: &str) -> Result<Option<Waiter>, LeaseError> {
        self.sweep();
        match self.store.leases.get(port) {
            None => return Err(LeaseError::NotHeld),
            Some(l) if l.owner != owner => {
                return Err(LeaseError::NotOwner {
                    holder: l.owner.clone(),
                })
            }
            Some(_) => {}
        }
        self.store.leases.remove(port);
        // Peek, don't pop: the head waiter must still `acquire` (which
        // removes them from the queue on success). Popping here would
        // promote the *second* waiter to head and lock the first one out.
        let next = self.store.queues.get(port).and_then(|q| q.front()).cloned();
        self.save()?;
        Ok(next)
    }

    /// Drop any lease on `port` regardless of owner (stuck/crashed worker).
    /// Returns the removed lease, if any.
    pub fn force_expire(&mut self, port: &str) -> Result<Option<Lease>, LeaseError> {
        self.sweep();
        let removed = self.store.leases.remove(port);
        self.save()?;
        Ok(removed)
    }

    /// Quarantine a device that failed restore-verify. Clears any live lease
    /// and blocks future acquires until [`LeaseManager::clear_quarantine`].
    pub fn quarantine(&mut self, port: &str, reason: &str) -> Result<(), LeaseError> {
        self.sweep();
        self.store.leases.remove(port);
        self.store
            .quarantine
            .insert(port.to_string(), reason.to_string());
        self.save()
    }

    /// Clear a quarantine entry. Returns true if one existed.
    pub fn clear_quarantine(&mut self, port: &str) -> Result<bool, LeaseError> {
        let removed = self.store.quarantine.remove(port).is_some();
        self.save()?;
        Ok(removed)
    }

    /// Live leases expiring within `warn`, soonest first, each
    /// with its remaining TTL. Visibility half of the
    /// silent-expiry fix: already-expired leases are swept (they
    /// are gone, not expiring), and everything returned here is
    /// still renewable via [`LeaseManager::renew`].
    pub fn expiring_soon(&mut self, warn: Duration) -> Vec<(Lease, Duration)> {
        self.sweep();
        let now = self.now();
        let mut out: Vec<(Lease, Duration)> = self
            .store
            .leases
            .values()
            .filter(|l| !l.expired(now) && l.remaining(now) <= warn)
            .map(|l| (l.clone(), l.remaining(now)))
            .collect();
        out.sort_by_key(|(_, ttl)| *ttl);
        out
    }

    /// Live lease on `port`, if any.
    pub fn lease(&mut self, port: &str) -> Option<Lease> {
        self.sweep();
        self.store.leases.get(port).cloned()
    }

    /// All live leases.
    pub fn all_leases(&mut self) -> Vec<Lease> {
        self.sweep();
        self.store.leases.values().cloned().collect()
    }

    /// Queue depth per contended port.
    pub fn queue_depths(&self) -> HashMap<String, usize> {
        self.store
            .queues
            .iter()
            .map(|(p, q)| (p.clone(), q.len()))
            .collect()
    }

    /// Quarantined ports and reasons.
    pub fn quarantined(&self) -> HashMap<String, String> {
        self.store.quarantine.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    fn tmp() -> PathBuf {
        let n = N.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("arb-lease-test-{n}-{}.json", std::process::id()))
    }

    fn mgr_at(path: &Path, now: u64) -> LeaseManager<ManualClock> {
        LeaseManager::load_with_clock(path, ManualClock { now }).unwrap()
    }

    #[test]
    fn acquire_release_roundtrip() {
        let p = tmp();
        let mut m = mgr_at(&p, 1000);
        let l = m
            .acquire("/dev/ttyACM7", "w1", "flash", Duration::from_secs(60))
            .unwrap();
        assert_eq!(l.owner, "w1");
        assert_eq!(l.expires_epoch, 1060);
        assert!(m.release("/dev/ttyACM7", "w1").unwrap().is_none());
        assert!(m.lease("/dev/ttyACM7").is_none());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn contention_queues_fifo() {
        let p = tmp();
        let mut m = mgr_at(&p, 1000);
        m.acquire("/dev/ttyACM7", "w1", "flash", Duration::from_secs(60))
            .unwrap();
        let e2 = m
            .acquire("/dev/ttyACM7", "w2", "test", Duration::from_secs(60))
            .unwrap_err();
        assert_eq!(
            e2,
            LeaseError::Contended {
                holder: "w1".into(),
                position: 0
            }
        );
        let e3 = m
            .acquire("/dev/ttyACM7", "w3", "test", Duration::from_secs(60))
            .unwrap_err();
        assert_eq!(
            e3,
            LeaseError::Contended {
                holder: "w1".into(),
                position: 1
            }
        );
        // Release names the head waiter; head may now acquire.
        let next = m.release("/dev/ttyACM7", "w1").unwrap().expect("waiter");
        assert_eq!(next.owner, "w2");
        let l = m
            .acquire("/dev/ttyACM7", "w2", "test", Duration::from_secs(60))
            .unwrap();
        assert_eq!(l.owner, "w2");
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn expiry_frees_port_without_release() {
        let p = tmp();
        let mut m = mgr_at(&p, 1000);
        m.acquire("/dev/ttyACM7", "w1", "flash", Duration::from_secs(10))
            .unwrap();
        m.clock.now = 1011; // past expiry
        assert!(m.lease("/dev/ttyACM7").is_none());
        // Another worker can take it now.
        let l = m
            .acquire("/dev/ttyACM7", "w2", "flash", Duration::from_secs(10))
            .unwrap();
        assert_eq!(l.owner, "w2");
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn stale_leases_expire_on_load_crash_recovery() {
        let p = tmp();
        {
            let mut m = mgr_at(&p, 1000);
            m.acquire("/dev/ttyACM7", "crashed", "flash", Duration::from_secs(30))
                .unwrap();
        }
        // "Restart" after the lease went stale: load expires it.
        let mut m2 = LeaseManager::load_with_clock(&p, ManualClock { now: 2000 }).unwrap();
        assert!(m2.lease("/dev/ttyACM7").is_none());
        let l = m2
            .acquire("/dev/ttyACM7", "w2", "x", Duration::from_secs(30))
            .unwrap();
        assert_eq!(l.owner, "w2");
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn persist_recover_keeps_live_leases_and_queues() {
        let p = tmp();
        {
            let mut m = mgr_at(&p, 1000);
            m.acquire("/dev/ttyACM7", "w1", "flash", Duration::from_secs(3600))
                .unwrap();
            let _ = m.acquire("/dev/ttyACM7", "w2", "test", Duration::from_secs(60));
        }
        let mut m2 = LeaseManager::load_with_clock(&p, ManualClock { now: 1100 }).unwrap();
        assert_eq!(m2.lease("/dev/ttyACM7").unwrap().owner, "w1");
        assert_eq!(m2.queue_depths().get("/dev/ttyACM7"), Some(&1));
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn renew_rejects_non_owner_and_extends() {
        let p = tmp();
        let mut m = mgr_at(&p, 1000);
        m.acquire("/dev/ttyACM7", "w1", "flash", Duration::from_secs(60))
            .unwrap();
        assert_eq!(
            m.renew("/dev/ttyACM7", "w2", Duration::from_secs(60))
                .unwrap_err(),
            LeaseError::NotOwner {
                holder: "w1".into()
            }
        );
        m.clock.now = 1010;
        let l = m
            .renew("/dev/ttyACM7", "w1", Duration::from_secs(120))
            .unwrap();
        assert_eq!(l.expires_epoch, 1130);
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn force_expire_and_quarantine_paths() {
        let p = tmp();
        let mut m = mgr_at(&p, 1000);
        m.acquire("/dev/ttyACM7", "stuck", "flash", Duration::from_secs(3600))
            .unwrap();
        let removed = m.force_expire("/dev/ttyACM7").unwrap().expect("lease");
        assert_eq!(removed.owner, "stuck");
        m.quarantine("/dev/ttyACM7", "restore-verify failed")
            .unwrap();
        let e = m
            .acquire("/dev/ttyACM7", "w1", "x", Duration::from_secs(60))
            .unwrap_err();
        assert!(matches!(e, LeaseError::Quarantined { .. }));
        assert!(m.clear_quarantine("/dev/ttyACM7").unwrap());
        m.acquire("/dev/ttyACM7", "w1", "x", Duration::from_secs(60))
            .unwrap();
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn expiry_is_visible_and_renewable() {
        let p = tmp();
        let mut m = mgr_at(&p, 1000);
        m.acquire("/dev/ttyACM7", "w1", "flash", Duration::from_secs(1800))
            .unwrap();
        // Fresh 30-minute lease: nothing within the warn horizon.
        assert!(m.expiring_soon(Duration::from_secs(300)).is_empty());
        // Near expiry the lease is visible with its TTL instead of
        // vanishing silently.
        m.clock.now = 1000 + 1800 - 120;
        let soon = m.expiring_soon(Duration::from_secs(300));
        assert_eq!(soon.len(), 1);
        assert_eq!(soon[0].0.owner, "w1");
        assert_eq!(soon[0].1, Duration::from_secs(120));
        // Renewable back to a healthy TTL, then invisible again.
        m.renew("/dev/ttyACM7", "w1", Duration::from_secs(1800))
            .unwrap();
        assert!(m.expiring_soon(Duration::from_secs(300)).is_empty());
        assert_eq!(
            m.lease("/dev/ttyACM7").unwrap().remaining(m.clock.now),
            Duration::from_secs(1800)
        );
        let _ = fs::remove_file(&p);
    }
}
