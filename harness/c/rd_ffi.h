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

#ifdef __cplusplus
}
#endif

#endif /* ROUNDDANCE_FFI_H */
