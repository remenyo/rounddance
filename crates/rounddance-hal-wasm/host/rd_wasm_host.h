/* rd_wasm_host.h — native runner contract for the rounddance WASM guest.
 *
 * The guest (crates/rounddance-hal-wasm, built for wasm32-unknown-unknown)
 * imports exactly these functions; the runner implements them against the
 * IDF C 15.4 driver (which carries S31 SoC support). No WASI, no strings,
 * no allocator handshake: integers and guest-memory pointer+length pairs
 * only. Buffers live in guest linear memory; resolve them with the
 * runtime's memory API (wasm3: m3_GetMemory; WAMR:
 * wasm_runtime_addr_app_to_native) and NEVER retain the pointers.
 *
 * Conventions (mirroring rounddance-hal-esp adapter invariants):
 * - Return 0 on success. Negative returns are -(DriverError): -1 NotReady,
 *   -2 Busy (transmit while one is in flight), -3 HwFault, -4 Unsupported,
 *   -5 InvalidParam.
 * - Transmit is single-flight: at most one frame is outstanding. Its fate
 *   is reported once via rd_host_poll_tx, never by callback.
 * - RX frames are pumped: each poll hands out one frame AND releases the
 *   driver buffer (receive_handle_done analogue). Per-frame meters
 *   (channel/RSSI/LQI) travel with the frame — never the most-recent
 *   getters, which proved stale on air (C6 metering quirk).
 * - init() runs nvs_flash_init (with erase-on-version-mismatch) BEFORE
 *   esp_ieee802154_enable, programs filtering ON (promiscuous OFF),
 *   rx_when_idle ON, and starts the receiver. Calibration lives in NVS.
 * - ISR discipline: callbacks are ISR-context — set flags, copy bounded
 *   bytes, never log or lock. Pump in task context.
 * - MAX_AIR_FRAME is 128 (1 length octet + up to 127 PSDU octets).
 * - Poll legs: rd_host_poll_tx writes one event code to *out_event and
 *   returns 1, or returns 0 when the queue is empty. rd_host_poll_rx
 *   writes one frame and its 4 meta words [len, channel, rssi, lqi] and
 *   returns the byte count, or 0 when the queue is empty.
 * - Event codes for *out_event: 1 Done, 2 CcaBusy, 3 NoAck, 4 Aborted,
 *   5 CoexReject, 6 Security, 7 InvalidAck. Unknown codes are HwFaults
 *   on the guest side, never silent success.
 * - PendingMode values match rounddance PendingMode order
 *   (0 Disable, 1 Enable, 2 Enhanced, 3 Zigbee).
 * - ext/eui arguments are 8 little-endian bytes in guest memory.
 */
#ifndef ROUNDANCE_WASM_HOST_H
#define ROUNDANCE_WASM_HOST_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t rd_host_init(void);
int32_t rd_host_deinit(void);
int32_t rd_host_is_ready(void);
int32_t rd_host_set_channel(uint32_t channel);
int32_t rd_host_set_tx_power(int32_t dbm);
int32_t rd_host_set_addrs(uint32_t pan_id, uint32_t short_addr, const uint8_t eui[8]);
int32_t rd_host_set_promiscuous(uint32_t enable);
int32_t rd_host_start_rx(void);
int32_t rd_host_set_coordinator(uint32_t enable);
int32_t rd_host_set_pending_mode(uint32_t mode);
int32_t rd_host_pending_short_add(uint32_t short_addr);
int32_t rd_host_pending_short_clear(uint32_t short_addr);
int32_t rd_host_pending_shorts_reset(void);
int32_t rd_host_transmit(const uint8_t *frame, uint32_t len);
int32_t rd_host_poll_tx(int32_t *out_event);
int32_t rd_host_poll_rx(uint8_t *frame_out, uint32_t cap, int32_t *meta /*[len,channel,rssi,lqi]*/);
int32_t rd_host_energy_scan(uint32_t channel, int32_t *out_dbm);

#ifdef __cplusplus
}
#endif

#endif /* ROUNDANCE_WASM_HOST_H */
