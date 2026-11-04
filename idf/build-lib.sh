#!/bin/bash
# Build the rounddance C-ABI staticlib for the ESP target and place it
# where the idf/components/rounddance wrapper expects it.
# Requires: cargo +esp toolchain, IDF exported (provides $IDF_PATH).
# Usage: idf/build-lib.sh  (run from anywhere)
set -euo pipefail
: "${IDF_PATH:?export IDF (provides \$IDF_PATH) before running}"
cd "$(dirname "$0")/.."
bash -c '. "$IDF_PATH"/export.sh >/dev/null 2>&1; cargo +esp build -p rounddance-ffi --release --target riscv32imac-esp-espidf --config "unstable.build-std=[\"std\",\"panic_abort\"]" --config "build.rustflags=[\"--cfg\", \"espidf_time64\"]"'
mkdir -p idf/components/rounddance/lib/riscv32imac-esp-espidf
cp target/riscv32imac-esp-espidf/release/librounddance_ffi.a \
   idf/components/rounddance/lib/riscv32imac-esp-espidf/
ls -l idf/components/rounddance/lib/riscv32imac-esp-espidf/
