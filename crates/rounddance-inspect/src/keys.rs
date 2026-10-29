//! Lab-key slots: which key material the engine holds for reporting.
//!
//! The inspector never decrypts — the reused NWK codec does not
//! surface the security aux header (frame counter, key sequence), so
//! there is nothing to build a nonce from. The slots exist so a
//! session can report, per secured frame, whether lab key material
//! was loaded at the time: `decryptable` means "a key slot was
//! loaded, take this capture to a keyed decryptor", not "decrypted
//! here". Loading a key is an explicit operator action; the slots
//! hold raw key octets and are never rendered by [`crate::report`].

/// Maximum NWK key slots (active + alternate, e.g. during rotation).
pub const MAX_NWK_KEYS: usize = 2;

/// Maximum GP key slots, indexed by the GPDF key-bit value (one slot
/// for the group-key class, one for the individual-key class).
pub const MAX_GP_KEYS: usize = 2;

/// One loaded GP key: raw octets plus the wire key-bit value the lab
/// provisioned it under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpKeySlot {
    /// Raw 128-bit key octets. Never rendered.
    pub key: [u8; 16],
    /// Key-bit value this slot answers (`false` group class,
    /// `true` individual class).
    pub key_bit: bool,
}

/// One loaded NWK key: raw octets plus the key sequence number the
/// lab provisioned it under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeySlot {
    /// Raw 128-bit key octets. Never rendered.
    pub key: [u8; 16],
    /// Key sequence number (lab provisioning label).
    pub seq: u8,
}

/// Operator-loaded key material for decryptability reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeySlots {
    slots: [Option<KeySlot>; MAX_NWK_KEYS],
    /// Number of `set_network_key` calls (rotation count).
    pub loads: u32,
    gp_slots: [Option<GpKeySlot>; MAX_GP_KEYS],
    /// Number of `set_gp_key` calls (rotation count).
    pub gp_loads: u32,
}

impl Default for KeySlots {
    fn default() -> Self {
        Self::new()
    }
}

impl KeySlots {
    /// Empty slots: no key material.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_NWK_KEYS],
            loads: 0,
            gp_slots: [None; MAX_GP_KEYS],
            gp_loads: 0,
        }
    }

    /// Load (or replace by sequence number) one NWK key. A full table
    /// evicts the stalest-loaded slot (index 0); loads are counted
    /// with saturation.
    pub fn set_network_key(&mut self, key: [u8; 16], seq: u8) {
        self.loads = self.loads.saturating_add(1);
        if let Some(slot) = self
            .slots
            .iter_mut()
            .find(|s| matches!(s, Some(e) if e.seq == seq))
        {
            *slot = Some(KeySlot { key, seq });
            return;
        }
        if let Some(slot) = self.slots.iter_mut().find(|s| s.is_none()) {
            *slot = Some(KeySlot { key, seq });
            return;
        }
        self.slots[0] = Some(KeySlot { key, seq });
    }

    /// Drop every loaded key.
    pub fn clear(&mut self) {
        self.slots = [None; MAX_NWK_KEYS];
        self.gp_slots = [None; MAX_GP_KEYS];
    }

    /// Load (or replace by key-bit value) one GP key. A full table
    /// evicts the stalest-loaded slot (index 0); loads are counted
    /// with saturation.
    pub fn set_gp_key(&mut self, key: [u8; 16], key_bit: bool) {
        self.gp_loads = self.gp_loads.saturating_add(1);
        if let Some(slot) = self
            .gp_slots
            .iter_mut()
            .find(|s| matches!(s, Some(e) if e.key_bit == key_bit))
        {
            *slot = Some(GpKeySlot { key, key_bit });
            return;
        }
        if let Some(slot) = self.gp_slots.iter_mut().find(|s| s.is_none()) {
            *slot = Some(GpKeySlot { key, key_bit });
            return;
        }
        self.gp_slots[0] = Some(GpKeySlot { key, key_bit });
    }

    /// Drop every loaded GP key; NWK slots are untouched.
    pub fn clear_gp_keys(&mut self) {
        self.gp_slots = [None; MAX_GP_KEYS];
    }

    /// Number of loaded GP slots.
    #[must_use]
    pub fn gp_loaded(&self) -> usize {
        self.gp_slots.iter().filter(|s| s.is_some()).count()
    }

    /// Whether any GP key is loaded (counter-protected GPDFs seen
    /// from here on count as decryptable-offline; a verified-open
    /// tree leg counts decryptable regardless — see
    /// [`crate::session`]).
    #[must_use]
    pub fn has_gp_key(&self) -> bool {
        self.gp_slots.iter().any(|s| s.is_some())
    }

    /// Key octets for the slot provisioned under `key_bit`, if
    /// loaded. The GP decryptor resolves strictly by the wire
    /// key-bit: a protected frame naming an unloaded class never
    /// decrypts, even when the other class slot is loaded.
    #[must_use]
    pub fn gp_key_by_bit(&self, key_bit: bool) -> Option<[u8; 16]> {
        self.gp_slots
            .iter()
            .filter_map(|s| *s)
            .find(|s| s.key_bit == key_bit)
            .map(|s| s.key)
    }

    /// Number of loaded NWK slots.
    #[must_use]
    pub fn loaded(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// Whether any NWK key is loaded (secured frames seen from here
    /// on count as decryptable-offline; a verified-open tree leg
    /// counts decryptable regardless — see [`crate::session`]).
    #[must_use]
    pub fn has_key(&self) -> bool {
        self.slots.iter().any(|s| s.is_some())
    }

    /// Key octets for the slot provisioned under `seq`, if loaded.
    /// The decryptor resolves strictly by sequence number: a secured
    /// frame naming an unloaded sequence never decrypts, even when
    /// other slots are loaded.
    #[must_use]
    pub fn key_by_seq(&self, seq: u8) -> Option<[u8; 16]> {
        self.slots
            .iter()
            .filter_map(|s| *s)
            .find(|s| s.seq == seq)
            .map(|s| s.key)
    }

    /// Rebuild slot state from a saved snapshot (see
    /// [`crate::report::session_from_json`]): the first `loaded`
    /// slots hold zeroed placeholder octets — never rendered, never
    /// key material, only the loaded-slot count survives the JSON
    /// snapshot — and the rotation counter restarts at `loads`.
    #[must_use]
    pub fn restore(loaded: usize, loads: u32) -> Self {
        let n = loaded.min(MAX_NWK_KEYS);
        let mut slots = [None; MAX_NWK_KEYS];
        let mut i = 0;
        while i < n {
            slots[i] = Some(KeySlot {
                key: [0u8; 16],
                seq: i as u8,
            });
            i += 1;
        }
        // GP slots are live-only state (like radio readings, never
        // snapshot state): a restore restarts with no GP key
        // material, and the schema stays at v1.
        Self {
            slots,
            loads,
            gp_slots: [None; MAX_GP_KEYS],
            gp_loads: 0,
        }
    }
}
