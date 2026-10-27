// C++ harness: same transaction, same asserts as txn.c, compiled
// as C++ to prove the C ABI header and linkage are C++-clean.
//
// Build: g++ -std=c++17 -Wall -Wextra -Werror -O2 txn.cpp
//        librounddance_ffi.a -lpthread -ldl -lm
#include <cstdint>
#include <cstdio>

#include "rd_ffi.h"

// Pinned from the live native run (tools/c-check.sh re-verifies the
// digest against a fresh native run every time).
namespace {
constexpr std::uint32_t kWantDigestHi = 1050873927u; // 0x3ea31047
constexpr std::uint32_t kWantDigestLo = 3784522896u; // 0xe1933c90
constexpr std::uint32_t kWantCmdCounter = 1024u;
constexpr std::uint32_t kWantReportCounter = 1025u;
constexpr std::uint32_t kWantResumeNext = 1024u;
constexpr std::uint32_t kWantTsn = 100u; // 0x64
constexpr std::uint32_t kWantTraceLines = 35u;

int g_fails = 0;

using Getter = int32_t (*)(rd_context_t const*, std::uint32_t*);

void check_field(rd_context_t* ctx, char const* name, Getter getter,
                 std::uint32_t want) {
    std::uint32_t v = 0;
    if (getter(ctx, &v) != RD_OK) {
        std::printf("FAIL %s: status != RD_OK\n", name);
        ++g_fails;
    } else if (v != want) {
        std::printf("FAIL %s: got %u, want %u\n", name, v, want);
        ++g_fails;
    } else {
        std::printf("%s=%u\n", name, v);
    }
}
} // namespace

int main() {
    if (rd_api_version() != RD_API_VERSION) {
        std::printf("FAIL api_version: got %u\n", rd_api_version());
        return 1;
    }
    std::printf("api_version=%u\n", rd_api_version());

    rd_context_t* ctx = nullptr;
    if (rd_create(&ctx) != RD_OK || ctx == nullptr) {
        std::printf("FAIL rd_create\n");
        return 1;
    }

    check_field(ctx, "rd_digest_hi", &rd_digest_hi, kWantDigestHi);
    check_field(ctx, "rd_digest_lo", &rd_digest_lo, kWantDigestLo);
    check_field(ctx, "rd_formed", &rd_formed, 1u);
    check_field(ctx, "rd_tc_verified", &rd_tc_verified, 1u);
    check_field(ctx, "rd_joiner_joined", &rd_joiner_joined, 1u);
    check_field(ctx, "rd_server_onoff", &rd_server_onoff, 1u);
    check_field(ctx, "rd_reported_onoff", &rd_reported_onoff, 1u);
    check_field(ctx, "rd_aps_security_on", &rd_aps_security_on, 1u);
    check_field(ctx, "rd_cmd_counter", &rd_cmd_counter, kWantCmdCounter);
    check_field(ctx, "rd_report_counter", &rd_report_counter,
                kWantReportCounter);
    check_field(ctx, "rd_resume_next", &rd_resume_next, kWantResumeNext);
    check_field(ctx, "rd_tsn", &rd_tsn, kWantTsn);
    check_field(ctx, "rd_trace_lines", &rd_trace_lines, kWantTraceLines);

    // Pull every trace line through the nul-free getter.
    {
        std::uint32_t n = 0;
        std::uint8_t buf[4096];
        std::size_t total = 0;
        int rc = rd_trace_lines(ctx, &n);
        if (rc != RD_OK || n != kWantTraceLines) {
            std::printf("FAIL trace_lines fetch: rc=%d n=%u\n", rc, n);
            ++g_fails;
        } else {
            for (std::uint32_t i = 0; i < n; ++i) {
                std::size_t len = 0;
                rc = rd_trace_line(ctx, i, buf, sizeof buf, &len);
                if (rc != RD_OK) {
                    std::printf("FAIL trace_line %u: rc=%d\n", i, rc);
                    ++g_fails;
                    break;
                }
                if (len == 0 || len >= sizeof buf) {
                    std::printf("FAIL trace_line %u: len=%zu\n", i, len);
                    ++g_fails;
                    break;
                }
                total += len;
            }
            std::printf("trace_bytes=%zu\n", total);
            if (total == 0) {
                std::printf("FAIL trace_bytes == 0\n");
                ++g_fails;
            }
        }
    }

    rd_destroy(ctx);

    if (g_fails != 0) {
        std::printf("CPP-MISMATCH: %d field(s) failed\n", g_fails);
        return 1;
    }
    std::printf("CPP-DECISION-MATCH: digest 0x%08x%08x, trace_lines=%u\n",
                kWantDigestHi, kWantDigestLo, kWantTraceLines);
    return 0;
}
