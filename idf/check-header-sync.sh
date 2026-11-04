#!/bin/bash
# Header-sync check: the IDF wrapper component must expose the exact
# same C ABI as the host harness. Fails on any drift between
# harness/c/rd_ffi.h and idf/components/rounddance/include/rd_ffi.h.
#
# Usage: idf/check-header-sync.sh
set -euo pipefail
cd "$(dirname "$0")/.."

if diff -u harness/c/rd_ffi.h idf/components/rounddance/include/rd_ffi.h; then
    echo "HEADER-SYNC: idf wrapper header == harness/c/rd_ffi.h"
else
    echo "HEADER-SYNC-MISMATCH: copy harness/c/rd_ffi.h over" >&2
    exit 1
fi
