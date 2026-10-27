//! Raw 15.4 driver declarations missing from `esp-idf-sys` 0.38.
//!
//! `esp-idf-sys` 0.38 does not ship bindings for the 802.15.4 driver
//! header. Every item below is declared here with its exact C signature
//! and a cross-reference to the IDF v6.1 header it comes from. All
//! declarations are private to the crate; [`super::esp::EspIdfDriver`]
//! is the only caller, and every call site carries its own `SAFETY`
//! justification. Safe wrappers are impossible at this layer (FFI is
//! inherently unsafe) — the safety argument lives per item + per call.
//!
//! Header: `components/ieee802154/include/esp_ieee802154.h` (and
//! `esp_ieee802154_types.h` for the TX-error enum).

// The driver entry points take plain C types only, so the declarations
// need no IDF struct bindings. WHY-SAFE (whole module): declaring an
// `extern "C"` symbol is sound when the signature matches the C
// definition; each signature below was checked against the cited header
// section, and the spike binary proved the set links and behaves on
// real C6 hardware (10/10 TX-DONE OTA-verified).

unsafe extern "C" {
    /// `esp_err_t esp_ieee802154_enable(void)` — header §"basic",
    /// `enable`/`disable` pair. WHY-SAFE: no args, returns `esp_err_t`.
    pub(crate) fn esp_ieee802154_enable() -> i32;
    /// `esp_err_t esp_ieee802154_disable(void)` — header §"basic".
    /// WHY-SAFE: no args, returns `esp_err_t`.
    pub(crate) fn esp_ieee802154_disable() -> i32;
    /// `esp_err_t esp_ieee802154_set_channel(uint8_t channel)` —
    /// header §"channel". WHY-SAFE: single byte arg by value.
    pub(crate) fn esp_ieee802154_set_channel(channel: u8) -> i32;
    /// `esp_err_t esp_ieee802154_set_txpower(int8_t power)` — header
    /// §"power". WHY-SAFE: single signed-byte arg by value.
    pub(crate) fn esp_ieee802154_set_txpower(power: i8) -> i32;
    /// `esp_err_t esp_ieee802154_set_panid(uint16_t panid)` — header
    /// §"addressing". WHY-SAFE: single half-word arg by value.
    pub(crate) fn esp_ieee802154_set_panid(panid: u16) -> i32;
    /// `esp_err_t esp_ieee802154_set_short_address(uint16_t
    /// short_address)` — header §"addressing". WHY-SAFE: as above.
    pub(crate) fn esp_ieee802154_set_short_address(short_address: u16) -> i32;
    /// `esp_err_t esp_ieee802154_set_extended_address(const uint8_t
    /// *ext_addr)` — header §"addressing"; 8 octets, caller-retained.
    /// WHY-SAFE: the driver copies the address synchronously during the
    /// call (proven by the C leg + spike); the pointer only needs to be
    /// valid for the call duration, which the wrapper guarantees with a
    /// borrowed `[u8; 8]`.
    pub(crate) fn esp_ieee802154_set_extended_address(ext_addr: *const u8) -> i32;
    /// `esp_err_t esp_ieee802154_set_promiscuous(bool enable)` —
    /// header §"promiscuous". WHY-SAFE: C99 `_Bool` is one byte, and
    /// Rust `bool` matches it; arg by value.
    pub(crate) fn esp_ieee802154_set_promiscuous(enable: bool) -> i32;
    /// `esp_err_t esp_ieee802154_set_rx_when_idle(bool enable)` —
    /// header §"reception". WHY-SAFE: bool by value, as above.
    pub(crate) fn esp_ieee802154_set_rx_when_idle(enable: bool) -> i32;
    /// `esp_err_t esp_ieee802154_receive(void)` — header §"reception";
    /// enters receive state. WHY-SAFE: no args.
    pub(crate) fn esp_ieee802154_receive() -> i32;
    /// `esp_err_t esp_ieee802154_transmit(const uint8_t *frame, bool
    /// cca)` — header §"transmission"; `frame[0]` is the Len+2 length,
    /// the buffer must outlive the submit call (the driver copies what
    /// it needs before returning). WHY-SAFE: the wrapper passes a
    /// borrowed slice that outlives the call; the driver never retains
    /// the pointer past return (single-flight + DONE/FAILED callbacks
    /// carry the same pointer back only as an identifier).
    pub(crate) fn esp_ieee802154_transmit(frame: *const u8, cca: bool) -> i32;
    /// `esp_err_t esp_ieee802154_energy_detect(uint32_t duration)` —
    /// header §"energy detection"; result arrives via
    /// `esp_ieee802154_energy_detect_done`. WHY-SAFE: scalar arg.
    pub(crate) fn esp_ieee802154_energy_detect(duration: u32) -> i32;
    /// `int8_t esp_ieee802154_get_recent_rssi(void)` — header
    /// §"reception info"; RSSI of the most recently received frame.
    /// WHY-SAFE: no args, returns a signed byte by value. Called from
    /// the RX callback (ISR) so the reading belongs to this frame.
    pub(crate) fn esp_ieee802154_get_recent_rssi() -> i8;
    /// `uint8_t esp_ieee802154_get_recent_lqi(void)` — header
    /// §"reception info"; LQI of the most recently received frame.
    /// WHY-SAFE: as above.
    pub(crate) fn esp_ieee802154_get_recent_lqi() -> u8;
    /// `esp_err_t esp_ieee802154_receive_handle_done(const uint8_t
    /// *frame)` — header §"reception"; releases a driver RX buffer
    /// (or a DONE-path ACK buffer). MUST be called exactly once per
    /// received frame or the RX pool exhausts. WHY-SAFE: the wrapper
    /// calls it exactly once per `receive_done` / written-ACK pointer,
    /// with the pointer the driver itself handed us.
    pub(crate) fn esp_ieee802154_receive_handle_done(frame: *const u8) -> i32;
}

/// TX-error values (`esp_ieee802154_tx_error_t`,
/// `esp_ieee802154_types.h`): the `transmit_failed` callback reports
/// one of these. Kept as `u32` constants (not a Rust enum) so a future
/// driver revision adding variants cannot change our layout — unknown
/// values map to [`TxFail::Aborted`](crate::driver::TxFail).
pub(crate) mod tx_err {
    /// `ESP_IEEE802154_TX_ERR_NONE` — no error.
    pub(crate) const NONE: u32 = 0;
    /// `ESP_IEEE802154_TX_ERR_CCA_BUSY` — medium busy.
    pub(crate) const CCA_BUSY: u32 = 1;
    /// `ESP_IEEE802154_TX_ERR_ABORT` — transmit aborted.
    pub(crate) const ABORT: u32 = 2;
    /// `ESP_IEEE802154_TX_ERR_NO_ACK` — no ACK within budget.
    pub(crate) const NO_ACK: u32 = 3;
    /// `ESP_IEEE802154_TX_ERR_INVALID_ACK` — bad ACK frame.
    pub(crate) const INVALID_ACK: u32 = 4;
    /// `ESP_IEEE802154_TX_ERR_COEXIST` — rejected by coexistence.
    pub(crate) const COEXIST: u32 = 5;
    /// `ESP_IEEE802154_TX_ERR_SECURITY` — bad security config.
    pub(crate) const SECURITY: u32 = 6;
}
