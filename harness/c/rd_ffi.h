/* rounddance C ABI — first complete host transaction.
 *
 * Same scenario as the host leg and the browser bundle (coordinator
 * formation → install-code join → Trust-Center verify → secured ZCL
 * On → timer-gated attribute report). The C harness drives the
 * staticlib through this header and asserts decision-match against
 * the native digest pinned in expected.txt.
 *
 * Conventions (mirror the Rust docs in crates/rounddance-ffi):
 * - Opaque handle: rd_create runs the transaction to completion.
 * - Every function returns an RD_* status; null arguments are a
 *   status, never UB.
 * - Trace lines are NUL-FREE byte spans: rd_trace_line writes raw
 *   bytes with no terminator; *out_len always gets the full length.
 * - C++ compatible: extern "C" guards, void params, fixed-width
 *   stdint types only.
 */
#ifndef ROUNDDANCE_FFI_H
#define ROUNDDANCE_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RD_OK 0
#define RD_ERR_NULL 1
#define RD_ERR_OOM 2
#define RD_ERR_RANGE 3
#define RD_ERR_SMALL 4
#define RD_ERR_PANIC 5
#define RD_ERR_VERIFY 6

#define RD_API_VERSION 1u

typedef struct rd_context rd_context_t;

uint32_t rd_api_version(void);
int32_t rd_create(rd_context_t **out);
void rd_destroy(rd_context_t *ctx);

int32_t rd_digest_hi(rd_context_t const *ctx, uint32_t *out);
int32_t rd_digest_lo(rd_context_t const *ctx, uint32_t *out);
int32_t rd_formed(rd_context_t const *ctx, uint32_t *out);
int32_t rd_tc_verified(rd_context_t const *ctx, uint32_t *out);
int32_t rd_joiner_joined(rd_context_t const *ctx, uint32_t *out);
int32_t rd_server_onoff(rd_context_t const *ctx, uint32_t *out);
int32_t rd_reported_onoff(rd_context_t const *ctx, uint32_t *out);
int32_t rd_aps_security_on(rd_context_t const *ctx, uint32_t *out);
int32_t rd_cmd_counter(rd_context_t const *ctx, uint32_t *out);
int32_t rd_report_counter(rd_context_t const *ctx, uint32_t *out);
int32_t rd_resume_next(rd_context_t const *ctx, uint32_t *out);
int32_t rd_tsn(rd_context_t const *ctx, uint32_t *out);
int32_t rd_trace_lines(rd_context_t const *ctx, uint32_t *out);
int32_t rd_trace_line(rd_context_t const *ctx, uint32_t index,
                      uint8_t *buf, size_t buf_len, size_t *out_len);

/* Live ESP apps: join/toggle/poll surface (crates/rounddance-ffi
 * apps_ffi). Outcome codes (*out_kind): 0 ignored/firewalled,
 * 1 data (a=cluster, b=profile), 2 transport accepted (a=auxctr),
 * 3 node-desc request (a=src short, b=tsn<<16|subject), 4 NWK command
 * (a=id). Coordinator poll uses the same codes, except 2 = announce
 * (a=short) and 3 = ZDO response (a=cluster, b=tsn<<8|status).
 */
typedef struct rd_coord rd_coord_t;
typedef struct rd_joiner rd_joiner_t;

int32_t rd_coord_create(rd_coord_t **out);
void rd_coord_destroy(rd_coord_t *ctx);
/* Build one Toggle (fresh TSN per call); *out_n = frame length. */
int32_t rd_coord_build_toggle(rd_coord_t *ctx, uint8_t const key[16],
                              uint8_t *out, size_t out_len,
                              size_t *out_n);
/* Verify a DefRsp; *out_ok = 1 on verified toggle-success. */
int32_t rd_coord_verify_defrsp(rd_coord_t *ctx, uint8_t const key[16],
                               uint8_t seq, uint8_t const *msdu,
                               size_t msdu_len, uint32_t *out_ok);
/* Classify one inbound NWK frame on the coordinator. */
int32_t rd_coord_poll(rd_coord_t *ctx, uint8_t const key[16], uint8_t seq,
                      uint8_t const *msdu, size_t msdu_len, uint64_t now_ms,
                      uint32_t *out_kind, uint32_t *out_a,
                      uint32_t *out_b);

int32_t rd_joiner_create(rd_joiner_t **out);
void rd_joiner_destroy(rd_joiner_t *ctx);
int32_t rd_joiner_begin_scan(rd_joiner_t *ctx);
int32_t rd_joiner_ingest_beacon(rd_joiner_t *ctx, uint16_t pan,
                                uint8_t channel, uint8_t lqi, int8_t rssi,
                                uint8_t permit, uint8_t router_capacity,
                                uint8_t end_device_capacity);
int32_t rd_joiner_finish_scan(rd_joiner_t *ctx, uint16_t *out_pan);
int32_t rd_joiner_on_mac(rd_joiner_t *ctx, uint8_t const *psdu,
                         size_t psdu_len, uint8_t channel, int8_t rssi,
                         uint8_t lqi, uint16_t *out_short);
/* Classify one inbound NWK frame on the joiner. */
int32_t rd_joiner_feed(rd_joiner_t *ctx, uint8_t const *msdu,
                       size_t msdu_len, uint32_t *out_kind,
                       uint32_t *out_a, uint32_t *out_b);
/* Answer an already-classified Toggle; *out_n = DefRsp length. */
int32_t rd_joiner_answer(rd_joiner_t *ctx, uint8_t const *msdu,
                         size_t msdu_len, uint8_t *out, size_t out_len,
                         size_t *out_n);
int32_t rd_joiner_lamp(rd_joiner_t const *ctx, uint32_t *out);

#ifdef __cplusplus
}
#endif

#endif /* ROUNDDANCE_FFI_H */
