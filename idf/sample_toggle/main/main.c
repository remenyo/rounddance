/* rd_toggle_sample: the air-proven join/toggle exchange, driven from C
 * on-device through the rounddance IDF component. Same pinned vectors
 * as harness/c/apps.c; verdict goes to the monitor log.
 */
#include <string.h>

#include "esp_log.h"
#include "rd_ffi.h"

static const char *TAG = "rd_toggle";

static const uint8_t KEY[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
static const uint8_t JW[8] = { 0xa4, 0x97, 0x85, 0xfe, 0xff, 0x62, 0xf2, 0xa0 };
static const uint8_t TCW[8] = { 0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0 };

/* Pinned synthetic transport frame (MAC + NWK, auxctr 0x0FFF). */
static const uint8_t TRANSPORT[71] = {
    0x61, 0x88, 0x5a, 0x01, 0xc6, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x1e, 0x21, 0x21, 0x51, 0x30, 0xff, 0x0f,
    0x00, 0x00, 0x68, 0x7f, 0x86, 0xfe, 0xff, 0x62, 0xf2, 0xa0, 0x1c,
    0xc3, 0x23, 0x24, 0x30, 0xa8, 0xf3, 0x7b, 0xa2, 0x0b, 0x67, 0xd5,
    0xb3, 0x4f, 0xd0, 0x2d, 0x9d, 0xfd, 0x71, 0x27, 0xda, 0x9f, 0x45,
    0x4e, 0x30, 0xaa, 0xf5, 0x03, 0x0a, 0x2e, 0xfb, 0x93, 0x01, 0x7d,
    0x94, 0x7d, 0x2e, 0x78, 0x0c,
};

#define CHECK_OK(call)                             \
    do {                                           \
        if ((call) != RD_OK) {                     \
            ESP_LOGE(TAG, "FAIL %s rc=%d", #call, (int)(call)); \
            goto fail;                             \
        }                                          \
    } while (0)

void app_main(void) {
    ESP_LOGI(TAG, "api_version=%u", rd_api_version());

    rd_coord_t *c = 0;
    rd_joiner_t *j = 0;
    CHECK_OK(rd_coord_create(&c));
    CHECK_OK(rd_joiner_create(&j));

    uint16_t pan = 0, short_addr = 0xffff;
    CHECK_OK(rd_joiner_begin_scan(j));
    CHECK_OK(rd_joiner_ingest_beacon(j, 0xc601, 15, 200, -40, 1, 1, 1));
    CHECK_OK(rd_joiner_ingest_beacon(j, 0xc601, 15, 200, -40, 1, 1, 1));
    CHECK_OK(rd_joiner_finish_scan(j, &pan));
    if (pan != 0xc601) {
        ESP_LOGE(TAG, "FAIL elect: pan=%04x", pan);
        goto fail;
    }

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
    if (short_addr != 0x0002) {
        ESP_LOGE(TAG, "FAIL assoc: short=%04x", short_addr);
        goto fail;
    }

    uint32_t kind = 0, a = 0, b = 0;
    CHECK_OK(rd_joiner_feed(j, &TRANSPORT[9], sizeof TRANSPORT - 9,
                            &kind, &a, &b));
    if (kind != 2 || a != 0x00000fffu) {
        ESP_LOGE(TAG, "FAIL transport: kind=%u a=%u", (unsigned)kind, (unsigned)a);
        goto fail;
    }

    uint8_t tog[160];
    size_t tog_n = 0;
    CHECK_OK(rd_coord_build_toggle(c, KEY, tog, sizeof tog, &tog_n));

    kind = a = b = 0;
    CHECK_OK(rd_joiner_feed(j, &tog[9], tog_n - 9, &kind, &a, &b));
    if (kind != 1 || a != 0x0006u || b != 0x0104u) {
        ESP_LOGE(TAG, "FAIL toggle data: %u %u %u", (unsigned)kind,
                 (unsigned)a, (unsigned)b);
        goto fail;
    }

    uint8_t ans[160];
    size_t ans_n = 0;
    CHECK_OK(rd_joiner_answer(j, &tog[9], tog_n - 9, ans, sizeof ans, &ans_n));

    uint32_t lamp = 0;
    CHECK_OK(rd_joiner_lamp(j, &lamp));
    if (lamp != 1) {
        ESP_LOGE(TAG, "FAIL lamp=%u", (unsigned)lamp);
        goto fail;
    }

    uint32_t ok = 0;
    CHECK_OK(rd_coord_verify_defrsp(c, KEY, 0, &ans[9], ans_n - 9, &ok));
    if (ok != 1) {
        ESP_LOGE(TAG, "FAIL defrsp ok=%u", (unsigned)ok);
        goto fail;
    }

    kind = 9;
    CHECK_OK(rd_joiner_feed(j, &tog[9], tog_n - 9, &kind, &a, &b));
    if (kind != 0) {
        ESP_LOGE(TAG, "FAIL dup not firewalled: kind=%u", (unsigned)kind);
        goto fail;
    }

    rd_joiner_destroy(j);
    rd_coord_destroy(c);
    ESP_LOGI(TAG, "RD-TOGGLE-MATCH: lamp=1 defrsp=1 dup-firewalled");
    return;

fail:
    rd_joiner_destroy(j);
    rd_coord_destroy(c);
    ESP_LOGE(TAG, "RD-TOGGLE-MISMATCH");
}
