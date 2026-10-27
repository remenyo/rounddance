//! Host persistent-store backend: in-memory KV plus a native-only
//! file-backed store that plugs the security-crate NVM seam.
//!
//! [`HostStore`] is the deterministic store (memory map, works on
//! native and WASM). [`FileStore`] persists each key as one file
//! under a directory for live Pi tooling (native only). Both also
//! implement [`rounddance_security::NvmStore`], so the protocol
//! frame-counter checkpoint/resume rule (`05-3474-23-434-01`) runs
//! against a real host backend instead of [`rounddance_security::RamStore`].

use rounddance_security::{NvmStore, PersistedState, StoreError};
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::path::{Path, PathBuf};

/// Host store failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvError {
    /// Key not present.
    NotFound,
    /// Backend refused the write.
    Io(String),
}

impl core::fmt::Display for KvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => f.write_str("key not found"),
            Self::Io(e) => write!(f, "store I/O: {e}"),
        }
    }
}

impl std::error::Error for KvError {}

/// In-memory host KV store (deterministic; native + WASM).
///
/// Also implements [`NvmStore`] over the fixed key
/// `zigbee/outgoing-counter` so protocol code can checkpoint frame
/// counters through it.
#[derive(Clone, Debug, Default)]
pub struct HostStore {
    map: HashMap<String, Vec<u8>>,
}

/// NVM counter key inside [`HostStore`].
pub const OUTGOING_COUNTER_KEY: &str = "zigbee/outgoing-counter";

impl HostStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Write `value` under `key`.
    pub fn put(&mut self, key: &str, value: &[u8]) {
        self.map.insert(key.to_string(), value.to_vec());
    }

    /// Read the value under `key`.
    ///
    /// # Errors
    ///
    /// [`KvError::NotFound`] when `key` was never written.
    pub fn get(&self, key: &str) -> Result<Vec<u8>, KvError> {
        self.map.get(key).cloned().ok_or(KvError::NotFound)
    }

    /// Number of keys held (budget accounting hook).
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when no key is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn load_counter(&self) -> Result<PersistedState, StoreError> {
        match self.map.get(OUTGOING_COUNTER_KEY) {
            None => Ok(PersistedState::blank()),
            Some(raw) => {
                if raw.len() != 4 {
                    return Err(StoreError::Corrupt);
                }
                let mut b = [0u8; 4];
                b.copy_from_slice(raw);
                Ok(PersistedState {
                    outgoing_next: u32::from_le_bytes(b),
                })
            }
        }
    }
}

impl NvmStore for HostStore {
    fn load(&self) -> Result<PersistedState, StoreError> {
        self.load_counter()
    }

    fn save_outgoing(&mut self, next: u32) -> Result<(), StoreError> {
        if next < self.load_counter()?.outgoing_next {
            return Err(StoreError::Io);
        }
        self.put(OUTGOING_COUNTER_KEY, &next.to_le_bytes());
        Ok(())
    }
}

/// File-backed host KV store (live Pi tooling, native only).
///
/// Each key maps to one file under `dir` (URL-safe file names are
/// the caller's job; the scenario uses fixed key names). Also
/// implements [`NvmStore`] over the same counter key.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug)]
pub struct FileStore {
    dir: PathBuf,
}

#[cfg(not(target_arch = "wasm32"))]
impl FileStore {
    /// Store rooted at `dir` (created on first write).
    #[must_use]
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    fn path(&self, key: &str) -> PathBuf {
        self.dir.join(key.replace('/', "_"))
    }

    /// Write `value` under `key`.
    ///
    /// # Errors
    ///
    /// [`KvError::Io`] on filesystem failures.
    pub fn put(&mut self, key: &str, value: &[u8]) -> Result<(), KvError> {
        std::fs::create_dir_all(&self.dir).map_err(|e| KvError::Io(e.to_string()))?;
        std::fs::write(self.path(key), value).map_err(|e| KvError::Io(e.to_string()))
    }

    /// Read the value under `key`.
    ///
    /// # Errors
    ///
    /// [`KvError::NotFound`] when absent, [`KvError::Io`] on
    /// filesystem failures.
    pub fn get(&self, key: &str) -> Result<Vec<u8>, KvError> {
        std::fs::read(self.path(key)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                KvError::NotFound
            } else {
                KvError::Io(e.to_string())
            }
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl NvmStore for FileStore {
    fn load(&self) -> Result<PersistedState, StoreError> {
        match self.get(OUTGOING_COUNTER_KEY) {
            Err(KvError::NotFound) => Ok(PersistedState::blank()),
            Err(KvError::Io(_)) => Err(StoreError::Io),
            Ok(raw) => {
                if raw.len() != 4 {
                    return Err(StoreError::Corrupt);
                }
                let mut b = [0u8; 4];
                b.copy_from_slice(&raw);
                Ok(PersistedState {
                    outgoing_next: u32::from_le_bytes(b),
                })
            }
        }
    }

    fn save_outgoing(&mut self, next: u32) -> Result<(), StoreError> {
        if next < self.load()?.outgoing_next {
            return Err(StoreError::Io);
        }
        self.put(OUTGOING_COUNTER_KEY, &next.to_le_bytes())
            .map_err(|_| StoreError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_put_get_roundtrip() {
        let mut s = HostStore::new();
        assert!(s.is_empty());
        assert_eq!(s.get("k"), Err(KvError::NotFound));
        s.put("k", b"v");
        assert_eq!(s.get("k").unwrap(), b"v");
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn mem_nvm_checkpoint_resume_monotonic() {
        let mut s = HostStore::new();
        assert_eq!(s.load().unwrap(), PersistedState::blank());
        s.save_outgoing(900).unwrap();
        assert_eq!(s.load().unwrap().outgoing_next, 900);
        // Backwards saves are rejected (rollback guard).
        assert_eq!(s.save_outgoing(899), Err(StoreError::Io));
        let resumed = s.load().unwrap().resume_next();
        assert!(resumed > 900);
    }

    #[test]
    fn mem_nvm_corrupt_image_rejected() {
        let mut s = HostStore::new();
        s.put(OUTGOING_COUNTER_KEY, b"too-long-image");
        assert_eq!(s.load(), Err(StoreError::Corrupt));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn file_store_roundtrip_in_tmp() {
        let dir = std::env::temp_dir().join(format!(
            "rounddance-hoststore-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut s = FileStore::new(&dir);
        assert_eq!(s.get("k"), Err(KvError::NotFound));
        s.put("k", b"v").unwrap();
        assert_eq!(s.get("k").unwrap(), b"v");
        s.save_outgoing(41).unwrap();
        assert_eq!(s.load().unwrap().outgoing_next, 41);
        std::fs::remove_dir_all(&dir).ok();
    }
}
