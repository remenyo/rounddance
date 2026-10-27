/* C harness: drive the rounddance staticlib through the first
 * transaction and assert decision-match against the pinned native
 * values (see expected.txt — captured from a live native run).
 *
 * Build: gcc -std=c11 -Wall -Wextra -Werror -O2 txn.c
 *        librounddance_ffi.a -lpthread -ldl -lm
 */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "rd_ffi.h"

/* Pinned from the live native run (tools/c-check.sh re-verifies the
 * digest against a fresh native run every time). */
#define WANT_DIGEST_HI 1050873927u /* 0x3ea31047 */
#define WANT_DIGEST_LO 3784522896u /* 0xe1933c90 */
#define WANT_CMD_COUNTER 1024u
#define WANT_REPORT_COUNTER 1025u
#define WANT_RESUME_NEXT 1024u
#define WANT_TSN 100u /* 0x64 */
#define WANT_TRACE_LINES 35u

static int fails = 0;

#define CHECK_FIELD(getter, want)                                          \
    do {                                                                   \
        uint32_t v = 0;                                                    \
        if (getter(ctx, &v) != RD_OK) {                                    \
            printf("FAIL " #getter ": status != RD_OK\n");                 \
            fails++;                                                       \
        } else if (v != (want)) {                                          \
            printf("FAIL " #getter ": got %" PRIu32 ", want %" PRIu32 "\n", \
                   v, (uint32_t)(want));                                   \
            fails++;                                                       \
        } else {                                                           \
            printf(#getter "=%" PRIu32 "\n", v);                           \
        }                                                                  \
    } while (0)

int main(void) {
    if (rd_api_version() != RD_API_VERSION) {
        printf("FAIL api_version: got %" PRIu32 "\n", rd_api_version());
        return 1;
    }
    printf("api_version=%" PRIu32 "\n", rd_api_version());

    rd_context_t *ctx = 0;
    if (rd_create(&ctx) != RD_OK || ctx == 0) {
        printf("FAIL rd_create\n");
        return 1;
    }

    CHECK_FIELD(rd_digest_hi, WANT_DIGEST_HI);
    CHECK_FIELD(rd_digest_lo, WANT_DIGEST_LO);
    CHECK_FIELD(rd_formed, 1u);
    CHECK_FIELD(rd_tc_verified, 1u);
    CHECK_FIELD(rd_joiner_joined, 1u);
    CHECK_FIELD(rd_server_onoff, 1u);
    CHECK_FIELD(rd_reported_onoff, 1u);
    CHECK_FIELD(rd_aps_security_on, 1u);
    CHECK_FIELD(rd_cmd_counter, WANT_CMD_COUNTER);
    CHECK_FIELD(rd_report_counter, WANT_REPORT_COUNTER);
    CHECK_FIELD(rd_resume_next, WANT_RESUME_NEXT);
    CHECK_FIELD(rd_tsn, WANT_TSN);
    CHECK_FIELD(rd_trace_lines, WANT_TRACE_LINES);

    /* Pull every trace line through the nul-free getter: exact length
     * round-trip plus a byte total so truncation would fail loudly. */
    {
        uint32_t n = 0;
        uint8_t buf[4096];
        size_t total = 0;
        int rc = rd_trace_lines(ctx, &n);
        if (rc != RD_OK || n != WANT_TRACE_LINES) {
            printf("FAIL trace_lines fetch: rc=%d n=%" PRIu32 "\n", rc, n);
            fails++;
        } else {
            for (uint32_t i = 0; i < n; i++) {
                size_t len = 0;
                rc = rd_trace_line(ctx, i, buf, sizeof buf, &len);
                if (rc != RD_OK) {
                    printf("FAIL trace_line %" PRIu32 ": rc=%d\n", i, rc);
                    fails++;
                    break;
                }
                if (len == 0 || len >= sizeof buf) {
                    printf("FAIL trace_line %" PRIu32 ": len=%zu\n", i, len);
                    fails++;
                    break;
                }
                total += len;
            }
            printf("trace_bytes=%zu\n", total);
            if (total == 0) {
                printf("FAIL trace_bytes == 0\n");
                fails++;
            }
        }
    }

    rd_destroy(ctx);

    if (fails != 0) {
        printf("C-MISMATCH: %d field(s) failed\n", fails);
        return 1;
    }
    printf("C-DECISION-MATCH: digest 0x%08x%08x, trace_lines=%u\n",
           WANT_DIGEST_HI, WANT_DIGEST_LO, WANT_TRACE_LINES);
    return 0;
}
