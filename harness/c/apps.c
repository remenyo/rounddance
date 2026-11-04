/* C harness: drive the live-app C ABI (join/toggle/poll) through the
 * staticlib and assert the air-proven exchange end to end:
 * keyed joiner + built toggle + classified Data + lamp on + verified
 * DefRsp + duplicate firewalled.
 *
 * Build: gcc -std=c11 -Wall -Wextra -Werror -O2 apps.c
 *        librounddance_ffi.a -lpthread -ldl -lm
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rd_ffi.h"

static int fails = 0;

#define CHECK_OK(call)                                                     \
    do {                                                                   \
        int32_t rc = (call);                                               \
        if (rc != RD_OK) {                                                 \
            printf("FAIL " #call ": rc=%d\n", rc);                         \
            fails++;                                                       \
        }                                                                  \
    } while (0)

#define CHECK_EQ(got, want)                                                \
    do {                                                                   \
        if ((got) != (want)) {                                             \
            printf("FAIL %s: got %u, want %u\n", #got,                      \
                   (unsigned)(got), (unsigned)(want));                      \
            fails++;                                                       \
        }                                                                  \
    } while (0)

static const uint8_t KEY[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
static const uint8_t JW[8] = { 0xa4, 0x97, 0x85, 0xfe, 0xff, 0x62, 0xf2, 0xa0 };
static const uint8_t TCW[8] = { 0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0 };

/* Pinned synthetic transport frame (MAC + NWK, auxctr 0x0FFF — one
 * below the coordinator base so the first toggle strictly advances;
 * captured from a live Rust run, same builder as coord_radiate). */
static const uint8_t TRANSPORT[71] = {
    0x61, 0x88, 0x5a, 0x01, 0xc6, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x1e, 0x21, 0x21, 0x51, 0x30, 0xff, 0x0f,
    0x00, 0x00, 0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0, 0x1c,
    0xc3, 0x23, 0x24, 0x30, 0xa8, 0xf3, 0x7b, 0xa2, 0x0b, 0x67, 0xd5,
    0xb3, 0x4f, 0xd0, 0x2d, 0x9d, 0xfd, 0x71, 0x27, 0xda, 0x9f, 0x45,
    0x4e, 0x30, 0xaa, 0xf5, 0x03, 0x0a, 0x2e, 0xfb, 0x93, 0x01, 0x7d,
    0x94, 0x7d, 0x2e, 0x78, 0x0c,
};

int main(void) {
    if (rd_api_version() != RD_API_VERSION) {
        printf("FAIL api_version\n");
        return 1;
    }

    rd_coord_t *c = 0;
    rd_joiner_t *j = 0;
    CHECK_OK(rd_coord_create(&c));
    CHECK_OK(rd_joiner_create(&j));
    if (fails != 0) {
        return 1;
    }

    /* Survey -> elect (two sightings) -> assoc adopts 0x0002. */
    uint16_t pan = 0;
    uint16_t short_addr = 0xffff;
    CHECK_OK(rd_joiner_begin_scan(j));
    CHECK_OK(rd_joiner_ingest_beacon(j, 0xc601, 15, 200, -40, 1, 1, 1));
    CHECK_OK(rd_joiner_ingest_beacon(j, 0xc601, 15, 200, -40, 1, 1, 1));
    CHECK_OK(rd_joiner_finish_scan(j, &pan));
    CHECK_EQ(pan, 0xc601u);

    uint8_t rsp[25];
    rsp[0] = 0x63;
    rsp[1] = 0xcc;
    rsp[2] = 0x02;
    rsp[3] = 0x01;
    rsp[4] = 0xc6;
    memcpy(&rsp[5], JW, 8);
    memcpy(&rsp[13], TCW, 8);
    rsp[21] = 0x02;
    rsp[22] = 0x02;
    rsp[23] = 0x00;
    rsp[24] = 0x00;
    CHECK_OK(rd_joiner_on_mac(j, rsp, sizeof rsp, 15, -40, 200, &short_addr));
    CHECK_EQ(short_addr, 0x0002u);

    /* Key via transport (MSDU = frame minus 9-byte MAC header). */
    {
        uint32_t kind = 0, a = 0, b = 0;
        CHECK_OK(rd_joiner_feed(j, &TRANSPORT[9], sizeof TRANSPORT - 9,
                                &kind, &a, &b));
        CHECK_EQ(kind, 2u);
        CHECK_EQ(a, 0x00000fffu);
    }

    /* Toggle roundtrip. */
    uint8_t tog[160];
    size_t tog_n = 0;
    CHECK_OK(rd_coord_build_toggle(c, KEY, tog, sizeof tog, &tog_n));
    if (tog_n == 0 || tog_n > sizeof tog) {
        printf("FAIL toggle length %zu\n", tog_n);
        fails++;
    }

    {
        uint32_t kind = 0, a = 0, b = 0;
        CHECK_OK(rd_joiner_feed(j, &tog[9], tog_n - 9, &kind, &a, &b));
        CHECK_EQ(kind, 1u);
        CHECK_EQ(a, 0x0006u);
        CHECK_EQ(b, 0x0104u);
    }

    uint8_t ans[160];
    size_t ans_n = 0;
    CHECK_OK(rd_joiner_answer(j, &tog[9], tog_n - 9, ans, sizeof ans, &ans_n));
    if (ans_n == 0 || ans_n > sizeof ans) {
        printf("FAIL answer length %zu\n", ans_n);
        fails++;
    }

    {
        uint32_t lamp = 0;
        CHECK_OK(rd_joiner_lamp(j, &lamp));
        CHECK_EQ(lamp, 1u);
    }

    {
        uint32_t ok = 0;
        CHECK_OK(rd_coord_verify_defrsp(c, KEY, 0, &ans[9], ans_n - 9, &ok));
        CHECK_EQ(ok, 1u);
    }

    /* Duplicate delivery is firewalled, never re-answered. */
    {
        uint32_t kind = 9, a = 9, b = 9;
        CHECK_OK(rd_joiner_feed(j, &tog[9], tog_n - 9, &kind, &a, &b));
        CHECK_EQ(kind, 0u);
    }

    rd_joiner_destroy(j);
    rd_coord_destroy(c);

    if (fails != 0) {
        printf("C-APPS-MISMATCH: %d check(s) failed\n", fails);
        return 1;
    }
    printf("C-APPS-MATCH: lamp=1 defrsp=1 dup-firewalled\n");
    return 0;
}
